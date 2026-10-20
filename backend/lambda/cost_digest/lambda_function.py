"""cost_digest — ENC-TSK-R24 (ENC-PLN-100 C1.7, BRD FR-2, rulings A4/A13).

Daily cost digest producer. Runs once a day (EventBridge cron 15 13 * * ? * UTC), makes at
most THREE Cost Explorer calls (ruling A13 -- CE bills per request), reads a handful of
CloudWatch metrics, and writes a compact JSON digest to the governance bucket:

    s3://jreese-net/governance/cost-digest/latest.json        (overwritten daily)
    s3://jreese-net/governance/cost-digest/YYYY-MM-DD.json    (immutable daily history)

Consumers (ENC-TSK-R32 connection_health) read the TOP-LEVEL fields only:

    date, prior_day_date, prior_day_spend, median_7d, regression, top_deltas,
    feed_publisher_invocations, invalidation_paths_mtd, invalidation_free_tier,
    jreese_net_bytes{current,noncurrent}, devops_agentcli_compute_bytes{current,noncurrent},
    tracker_rru_wcu{rru,wcu}, generated_at, ce_calls

CE call budget (hard cap CE_MAX_CALLS = 3, enforced by _CostExplorerBudget, pagination
included -- a NextPageToken follow-up consumes budget like any other call):

    1. DAILY  UnblendedCost, [today-8, today)                       -> prior day + 7-day baseline
    2. DAILY  UnblendedCost+UsageQuantity grouped by USAGE_TYPE,
              [min(first-of-month, today-8), today)                 -> top usage-type deltas AND the
                                                                       CloudFront Invalidations MTD
                                                                       (no extra API call)
    (3. is reserved for a NextPageToken follow-up of call 2; if more pages remain the digest is
        marked ce_truncated and the remainder is dropped rather than spending a 4th call.)

Every CloudWatch/S3-size section is best-effort: a failure there becomes a null field plus a
`warnings` entry, never a missing digest. A Cost Explorer failure raises (Lambda error alarm).

Weekly persistent-cost compliance scan (ENC-TSK-R38, BRD FR-37) -- REPORT ONLY, no new schedule
and no new resource (cost class C1). On Mondays (UTC weekday 0) or when the invocation event is
{"compliance_scan": true}, a `compliance` object is added to the digest (latest.json AND the dated
key; absent on every other day). It is NOT one of the top-level fields consumers read. Four
read-only sections, each isolated (a failure becomes {"error": ...} plus a `warnings` entry, never
a raise), each list capped at 50 entries with the full count alongside:

    s3_noncurrent_expiration  Enceladus-owned buckets (name prefix enceladus-/devops-/jreese-net/
                              support-lambda-artifacts) whose versioning is Enabled or Suspended and
                              that have no ENABLED lifecycle rule with NoncurrentVersionExpiration.
                              Never-versioned buckets have no noncurrent versions and are only counted.
    log_group_retention       /aws/lambda/enceladus-*, /aws/lambda/devops-*, /aws/codebuild/enceladus*
                              log groups with no retentionInDays (scan cap 1000).
    ecr_lifecycle             ECR repositories with no lifecycle policy.
    metric_dimensions         custom namespaces with > 50 distinct dimension sets (unbounded-dimension
                              candidates; list_metrics page-capped, `truncated` flags a lower bound).

A wall-clock budget (COMPLIANCE_BUDGET_SECONDS, split across the sections) keeps the scan inside the
Lambda timeout; a section that runs out reports `partial: true`.
"""
from __future__ import annotations

import json
import logging
import os
import re
import statistics
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

CE_MAX_CALLS = 3  # ruling A13: <= 3 Cost Explorer calls per invocation
CE_REGION = "us-east-1"  # Cost Explorer is a global service served from us-east-1
BASELINE_DAYS = 7
REGRESSION_MULTIPLIER = 1.2
TOP_DELTAS = 5
INVALIDATION_FREE_TIER = 1000  # CloudFront free tier: 1,000 invalidation paths / month

DIGEST_BUCKET = os.environ.get("COST_DIGEST_BUCKET", "jreese-net")
DIGEST_PREFIX = os.environ.get("COST_DIGEST_PREFIX", "governance/cost-digest/")
DIGEST_S3_REGION = os.environ.get("COST_DIGEST_S3_REGION", "us-west-1")
WORKLOAD_REGION = os.environ.get("AWS_REGION", "us-west-2")  # Lambda + DynamoDB metrics live here
FEED_PUBLISHER_FUNCTION = os.environ.get("FEED_PUBLISHER_FUNCTION", "devops-feed-publisher")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
JREESE_NET_BUCKET = os.environ.get("JREESE_NET_BUCKET", "jreese-net")
JREESE_NET_BUCKET_REGION = os.environ.get("JREESE_NET_BUCKET_REGION", "us-west-1")
COMPUTE_BUCKET = os.environ.get("COMPUTE_BUCKET", "devops-agentcli-compute")
COMPUTE_BUCKET_REGION = os.environ.get("COMPUTE_BUCKET_REGION", "us-west-2")
# AWS/S3 BucketSizeBytes only publishes the StorageType dims that exist for a bucket. Standard
# storage is the current-class series; any additional comma-separated dims named here are summed
# into `noncurrent` when (and only when) CloudWatch actually returns data for them, else null.
CURRENT_STORAGE_TYPE = "StandardStorage"
NONCURRENT_STORAGE_TYPES = [
    s.strip()
    for s in os.environ.get("NONCURRENT_STORAGE_TYPES", "NoncurrentVersionStorage").split(",")
    if s.strip()
]

_INVALIDATION_RE = re.compile(r"invalidation", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Cost Explorer (call-budgeted)
# ---------------------------------------------------------------------------
class CostExplorerBudgetExhausted(Exception):
    """Raised when a further CE request would exceed CE_MAX_CALLS."""


class _CostExplorerBudget:
    """Wraps a CE client; every get_cost_and_usage request (incl. pagination) is counted."""

    def __init__(self, client: Any, max_calls: int = CE_MAX_CALLS) -> None:
        self._client = client
        self.max_calls = max_calls
        self.calls = 0
        self.truncated = False

    def get_cost_and_usage(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Return ResultsByTime across pages; stops (truncated=True) rather than exceed budget."""
        results: List[Dict[str, Any]] = []
        token: Optional[str] = None
        while True:
            if self.calls >= self.max_calls:
                if token:
                    self.truncated = True
                    return results
                raise CostExplorerBudgetExhausted(f"CE budget of {self.max_calls} calls exhausted")
            req = dict(kwargs)
            if token:
                req["NextPageToken"] = token
            self.calls += 1
            resp = self._client.get_cost_and_usage(**req)
            results.extend(resp.get("ResultsByTime", []))
            token = resp.get("NextPageToken")
            if not token:
                return results


def _amount(metrics: Dict[str, Any], name: str) -> float:
    try:
        return float((metrics.get(name) or {}).get("Amount", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def daily_totals(results: List[Dict[str, Any]]) -> Dict[str, float]:
    """{YYYY-MM-DD: UnblendedCost} from an ungrouped DAILY CE response."""
    out: Dict[str, float] = {}
    for row in results:
        start = (row.get("TimePeriod") or {}).get("Start")
        if start:
            out[start] = out.get(start, 0.0) + _amount(row.get("Total") or {}, "UnblendedCost")
    return out


def usage_matrix(
    results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Tuple[float, float]]]:
    """{usage_type: {YYYY-MM-DD: (cost, usage_quantity)}} from a DAILY USAGE_TYPE-grouped response."""
    out: Dict[str, Dict[str, Tuple[float, float]]] = {}
    for row in results:
        start = (row.get("TimePeriod") or {}).get("Start")
        if not start:
            continue
        for group in row.get("Groups", []):
            keys = group.get("Keys") or []
            if not keys:
                continue
            metrics = group.get("Metrics") or {}
            cost, qty = out.setdefault(keys[0], {}).get(start, (0.0, 0.0))
            out[keys[0]][start] = (
                cost + _amount(metrics, "UnblendedCost"),
                qty + _amount(metrics, "UsageQuantity"),
            )
    return out


def compute_spend(
    totals: Dict[str, float], prior_day: date
) -> Tuple[Optional[float], Optional[float], bool]:
    """(prior_day_spend, median_7d, regression). Baseline = the 7 days BEFORE the prior day."""
    prior = totals.get(prior_day.isoformat())
    baseline = [
        totals[d.isoformat()]
        for d in (prior_day - timedelta(days=i) for i in range(1, BASELINE_DAYS + 1))
        if d.isoformat() in totals
    ]
    median = statistics.median(baseline) if baseline else None
    regression = bool(prior is not None and median is not None and prior > REGRESSION_MULTIPLIER * median)
    return (
        None if prior is None else round(prior, 4),
        None if median is None else round(median, 4),
        regression,
    )


def compute_top_deltas(
    matrix: Dict[str, Dict[str, Tuple[float, float]]], prior_day: date, limit: int = TOP_DELTAS
) -> List[Dict[str, Any]]:
    """Top usage-type cost deltas: prior day vs the mean of the 7 days before it (largest |delta|)."""
    prior_key = prior_day.isoformat()
    baseline_keys = [(prior_day - timedelta(days=i)).isoformat() for i in range(1, BASELINE_DAYS + 1)]
    rows: List[Dict[str, Any]] = []
    for usage_type, by_day in matrix.items():
        prior_cost = by_day.get(prior_key, (0.0, 0.0))[0]
        mean = sum(by_day.get(k, (0.0, 0.0))[0] for k in baseline_keys) / BASELINE_DAYS
        delta = prior_cost - mean
        if abs(delta) < 1e-9:
            continue
        rows.append(
            {
                "usage_type": usage_type,
                "prior_day": round(prior_cost, 4),
                "mean_7d": round(mean, 4),
                "delta": round(delta, 4),
            }
        )
    rows.sort(key=lambda r: (-abs(r["delta"]), r["usage_type"]))
    return rows[:limit]


def invalidation_paths_mtd(
    matrix: Dict[str, Dict[str, Tuple[float, float]]], month_start: date, prior_day: date
) -> int:
    """CloudFront invalidation paths month-to-date (through the prior day) from CE UsageQuantity."""
    total = 0.0
    lo, hi = month_start.isoformat(), prior_day.isoformat()
    for usage_type, by_day in matrix.items():
        if not _INVALIDATION_RE.search(usage_type):
            continue
        total += sum(qty for day, (_, qty) in by_day.items() if lo <= day <= hi)
    return int(round(total))


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------
def _metric_query(
    qid: str, namespace: str, metric: str, dims: Dict[str, str], stat: str, period: int = 86400
) -> Dict[str, Any]:
    return {
        "Id": qid,
        "MetricStat": {
            "Metric": {
                "Namespace": namespace,
                "MetricName": metric,
                "Dimensions": [{"Name": k, "Value": v} for k, v in dims.items()],
            },
            "Period": period,
            "Stat": stat,
        },
        "ReturnData": True,
    }


def _get_metric_values(
    client: Any, queries: List[Dict[str, Any]], start: datetime, end: datetime
) -> Dict[str, List[float]]:
    """{query_id: [values newest-first]}; a metric with no datapoints maps to []."""
    out: Dict[str, List[float]] = {q["Id"]: [] for q in queries}
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {
            "MetricDataQueries": queries,
            "StartTime": start,
            "EndTime": end,
            "ScanBy": "TimestampDescending",
        }
        if token:
            kwargs["NextToken"] = token
        resp = client.get_metric_data(**kwargs)
        for result in resp.get("MetricDataResults", []):
            out.setdefault(result.get("Id"), []).extend(result.get("Values", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _sum_or_none(values: List[float]) -> Optional[float]:
    return sum(values) if values else None


def collect_workload_metrics(
    cw: Any, prior_start: datetime, today_start: datetime
) -> Dict[str, Any]:
    """Prior-day feed-publisher invocations + tracker consumed RRU/WCU (workload region)."""
    queries = [
        _metric_query("feed", "AWS/Lambda", "Invocations", {"FunctionName": FEED_PUBLISHER_FUNCTION}, "Sum"),
        _metric_query("rru", "AWS/DynamoDB", "ConsumedReadCapacityUnits", {"TableName": TRACKER_TABLE}, "Sum"),
        _metric_query("wcu", "AWS/DynamoDB", "ConsumedWriteCapacityUnits", {"TableName": TRACKER_TABLE}, "Sum"),
    ]
    vals = _get_metric_values(cw, queries, prior_start, today_start)
    feed = _sum_or_none(vals["feed"])
    rru, wcu = _sum_or_none(vals["rru"]), _sum_or_none(vals["wcu"])
    return {
        "feed_publisher_invocations": None if feed is None else int(round(feed)),
        "tracker_rru_wcu": {
            "rru": None if rru is None else round(rru, 2),
            "wcu": None if wcu is None else round(wcu, 2),
        },
    }


def collect_bucket_bytes(cw: Any, bucket: str, today_start: datetime) -> Dict[str, Optional[int]]:
    """Latest daily BucketSizeBytes {current, noncurrent}. S3 storage metrics land once a day
    (lagging), so look back 3 days and take the newest datapoint per series."""
    def q(qid: str, storage_type: str) -> Dict[str, Any]:
        return _metric_query(
            qid, "AWS/S3", "BucketSizeBytes",
            {"BucketName": bucket, "StorageType": storage_type}, "Average",
        )

    queries = [q("cur", CURRENT_STORAGE_TYPE)] + [q(f"nc{i}", st) for i, st in enumerate(NONCURRENT_STORAGE_TYPES)]
    vals = _get_metric_values(cw, queries, today_start - timedelta(days=3), today_start)
    current = vals["cur"][0] if vals["cur"] else None
    nc = [vals[f"nc{i}"][0] for i in range(len(NONCURRENT_STORAGE_TYPES)) if vals.get(f"nc{i}")]
    return {
        "current": None if current is None else int(round(current)),
        "noncurrent": int(round(sum(nc))) if nc else None,
    }


# ---------------------------------------------------------------------------
# Weekly persistent-cost compliance scan (ENC-TSK-R38, BRD FR-37) -- REPORT ONLY, never mutates
# ---------------------------------------------------------------------------
COMPLIANCE_WEEKDAY = 0  # Monday (datetime.weekday(), UTC)
COMPLIANCE_LIST_CAP = 50
COMPLIANCE_LOG_GROUP_SCAN_CAP = 1000
COMPLIANCE_ECR_SCAN_CAP = 500
COMPLIANCE_METRIC_PAGE_CAP = 10  # list_metrics pages (<= 500 metrics each) per namespace
COMPLIANCE_DIMENSION_SET_LIMIT = 50
COMPLIANCE_BUDGET_SECONDS = float(os.environ.get("COMPLIANCE_BUDGET_SECONDS", "75"))
COMPLIANCE_ITEM_ERROR_SAMPLES = 5
COMPLIANCE_BUCKET_PREFIXES = ("enceladus-", "devops-", "jreese-net", "support-lambda-artifacts")
COMPLIANCE_LOG_GROUP_PREFIXES = ("/aws/lambda/enceladus-", "/aws/lambda/devops-", "/aws/codebuild/enceladus")
COMPLIANCE_METRIC_NAMESPACES = [
    s.strip()
    for s in os.environ.get(
        "COMPLIANCE_METRIC_NAMESPACES",
        "Enceladus/Prod,Enceladus/Docstore,Enceladus/SnapStart,Enceladus/OpenSearch,"
        "Enceladus/Synthetic,Enceladus/GraphHealth,EnceladusBackup",
    ).split(",")
    if s.strip()
]

ClientFor = Callable[[str, str], Any]  # (service, region) -> boto3 client


class _Deadline:
    def __init__(self, seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._end = clock() + seconds

    def expired(self) -> bool:
        return self._clock() >= self._end


def compliance_due(now: datetime, event: Any) -> Optional[str]:
    """Return the trigger ("event" | "weekly") when a compliance scan should run, else None."""
    if isinstance(event, dict) and event.get("compliance_scan") is True:
        return "event"
    if now.weekday() == COMPLIANCE_WEEKDAY:
        return "weekly"
    return None


def _error_code(exc: BaseException) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return str(resp.get("Error", {}).get("Code", ""))
    return ""


def _describe_error(exc: BaseException) -> str:
    code = _error_code(exc)
    return f"{type(exc).__name__}{':' + code if code else ''}"


def _capped(names: List[Any]) -> Dict[str, Any]:
    return {
        "entries": names[:COMPLIANCE_LIST_CAP],
        "entries_truncated": len(names) > COMPLIANCE_LIST_CAP,
    }


def _has_noncurrent_expiration(rules: List[Dict[str, Any]]) -> bool:
    return any(r.get("Status") == "Enabled" and r.get("NoncurrentVersionExpiration") for r in rules or [])


def scan_s3_noncurrent_expiration(client_for: ClientFor, deadline: _Deadline) -> Dict[str, Any]:
    s3 = client_for("s3", DIGEST_S3_REGION)
    owned = sorted(
        (b["Name"], b.get("BucketRegion"))
        for b in s3.list_buckets().get("Buckets", [])
        if str(b.get("Name", "")).startswith(COMPLIANCE_BUCKET_PREFIXES)
    )
    versioned = unversioned = item_errors = 0
    partial = False
    noncompliant: List[Dict[str, Any]] = []
    error_samples: List[str] = []
    for name, region in owned:
        if deadline.expired():
            partial = True
            break
        bucket_client = client_for("s3", region) if region else s3
        try:
            status = bucket_client.get_bucket_versioning(Bucket=name).get("Status")
            if status not in ("Enabled", "Suspended"):
                unversioned += 1  # never versioned -> no noncurrent versions to expire
                continue
            versioned += 1
            try:
                rules = bucket_client.get_bucket_lifecycle_configuration(Bucket=name).get("Rules", [])
            except Exception as exc:  # noqa: BLE001
                if _error_code(exc) != "NoSuchLifecycleConfiguration":
                    raise
                rules = []
            if not _has_noncurrent_expiration(rules):
                noncompliant.append({"bucket": name, "versioning": status, "lifecycle_rules": len(rules)})
        except Exception as exc:  # noqa: BLE001 -- one unreadable bucket must not lose the section
            item_errors += 1
            if len(error_samples) < COMPLIANCE_ITEM_ERROR_SAMPLES:
                error_samples.append(f"{name}: {_describe_error(exc)}")
    out: Dict[str, Any] = {
        "checked": versioned + unversioned,
        "versioned": versioned,
        "unversioned": unversioned,
        "noncompliant": len(noncompliant),
        **_capped(noncompliant),
        "item_errors": item_errors,
        "partial": partial,
    }
    if error_samples:
        out["item_error_samples"] = error_samples
    return out


def scan_log_group_retention(client_for: ClientFor, deadline: _Deadline) -> Dict[str, Any]:
    logs = client_for("logs", WORKLOAD_REGION)
    checked = 0
    scan_capped = partial = False
    missing: List[str] = []
    for prefix in COMPLIANCE_LOG_GROUP_PREFIXES:
        token: Optional[str] = None
        while True:
            if deadline.expired():
                partial = True
                break
            kwargs: Dict[str, Any] = {"logGroupNamePrefix": prefix}
            if token:
                kwargs["nextToken"] = token
            resp = logs.describe_log_groups(**kwargs)
            for group in resp.get("logGroups", []):
                if checked >= COMPLIANCE_LOG_GROUP_SCAN_CAP:
                    scan_capped = True
                    break
                checked += 1
                if group.get("retentionInDays") is None:
                    missing.append(group["logGroupName"])
            token = resp.get("nextToken")
            if scan_capped or not token:
                break
        if scan_capped or partial:
            break
    return {
        "region": WORKLOAD_REGION,
        "checked": checked,
        "noncompliant": len(missing),
        **_capped(missing),
        "scan_capped": scan_capped,
        "partial": partial,
    }


def scan_ecr_lifecycle(client_for: ClientFor, deadline: _Deadline) -> Dict[str, Any]:
    ecr = client_for("ecr", WORKLOAD_REGION)
    checked = item_errors = 0
    scan_capped = partial = False
    missing: List[str] = []
    error_samples: List[str] = []
    token: Optional[str] = None
    while not (scan_capped or partial):
        if deadline.expired():
            partial = True
            break
        kwargs: Dict[str, Any] = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.describe_repositories(**kwargs)
        for repo in resp.get("repositories", []):
            if checked >= COMPLIANCE_ECR_SCAN_CAP:
                scan_capped = True
                break
            checked += 1
            name = repo["repositoryName"]
            try:
                ecr.get_lifecycle_policy(repositoryName=name)
            except Exception as exc:  # noqa: BLE001
                if _error_code(exc) == "LifecyclePolicyNotFoundException":
                    missing.append(name)
                else:
                    item_errors += 1
                    if len(error_samples) < COMPLIANCE_ITEM_ERROR_SAMPLES:
                        error_samples.append(f"{name}: {_describe_error(exc)}")
        token = resp.get("nextToken")
        if not token:
            break
    out: Dict[str, Any] = {
        "region": WORKLOAD_REGION,
        "checked": checked,
        "noncompliant": len(missing),
        **_capped(missing),
        "item_errors": item_errors,
        "scan_capped": scan_capped,
        "partial": partial,
    }
    if error_samples:
        out["item_error_samples"] = error_samples
    return out


def scan_metric_dimensions(client_for: ClientFor, deadline: _Deadline) -> Dict[str, Any]:
    cw = client_for("cloudwatch", WORKLOAD_REGION)
    checked = item_errors = 0
    partial = False
    candidates: List[Dict[str, Any]] = []
    error_samples: List[str] = []
    for namespace in COMPLIANCE_METRIC_NAMESPACES:
        if deadline.expired():
            partial = True
            break
        try:
            dim_sets: set = set()
            metrics = pages = 0
            truncated = False
            token: Optional[str] = None
            while True:
                kwargs: Dict[str, Any] = {"Namespace": namespace}
                if token:
                    kwargs["NextToken"] = token
                resp = cw.list_metrics(**kwargs)
                pages += 1
                for metric in resp.get("Metrics", []):
                    metrics += 1
                    dim_sets.add(tuple(sorted((d["Name"], d["Value"]) for d in metric.get("Dimensions", []))))
                token = resp.get("NextToken")
                if not token:
                    break
                if pages >= COMPLIANCE_METRIC_PAGE_CAP:
                    truncated = True  # distinct count below is a lower bound
                    break
        except Exception as exc:  # noqa: BLE001
            item_errors += 1
            if len(error_samples) < COMPLIANCE_ITEM_ERROR_SAMPLES:
                error_samples.append(f"{namespace}: {_describe_error(exc)}")
            continue
        checked += 1
        if len(dim_sets) > COMPLIANCE_DIMENSION_SET_LIMIT:
            candidates.append({
                "namespace": namespace,
                "distinct_dimension_sets": len(dim_sets),
                "metrics": metrics,
                "truncated": truncated,
            })
    candidates.sort(key=lambda c: (-c["distinct_dimension_sets"], c["namespace"]))
    out: Dict[str, Any] = {
        "region": WORKLOAD_REGION,
        "dimension_set_limit": COMPLIANCE_DIMENSION_SET_LIMIT,
        "checked": checked,
        "noncompliant": len(candidates),
        **_capped(candidates),
        "item_errors": item_errors,
        "partial": partial,
    }
    if error_samples:
        out["item_error_samples"] = error_samples
    return out


COMPLIANCE_SECTIONS: List[Tuple[str, Callable[[ClientFor, _Deadline], Dict[str, Any]]]] = [
    ("s3_noncurrent_expiration", scan_s3_noncurrent_expiration),
    ("log_group_retention", scan_log_group_retention),
    ("ecr_lifecycle", scan_ecr_lifecycle),
    ("metric_dimensions", scan_metric_dimensions),
]


def collect_compliance(
    client_for: ClientFor,
    trigger: str,
    budget_seconds: float = COMPLIANCE_BUDGET_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    """Run every section in isolation; a failing section yields {"error": ...}, never a raise."""
    compliance: Dict[str, Any] = {"mode": "report_only", "trigger": trigger}
    share = budget_seconds / len(COMPLIANCE_SECTIONS)
    for key, fn in COMPLIANCE_SECTIONS:
        try:
            compliance[key] = fn(client_for, _Deadline(share, clock))
        except Exception as exc:  # noqa: BLE001
            compliance[key] = {"error": f"{_describe_error(exc)}: {str(exc)[:200]}"}
            LOGGER.warning(json.dumps({"event": "cost_digest_compliance_section_failed", "section": key, "error": str(exc)}))
    return compliance


# ---------------------------------------------------------------------------
# Digest assembly
# ---------------------------------------------------------------------------
def build_digest(
    ce: _CostExplorerBudget,
    cw_for_region: Callable[[str], Any],
    now: datetime,
    client_for: Optional[ClientFor] = None,
    event: Any = None,
) -> Dict[str, Any]:
    today = now.date()
    prior_day = today - timedelta(days=1)
    # MTD is "through the prior day": on the 1st this is the whole previous month.
    month_start = prior_day.replace(day=1)
    window_start = today - timedelta(days=BASELINE_DAYS + 1)  # 8 days ending at the prior day

    # CE call 1 -- daily totals
    totals = daily_totals(
        ce.get_cost_and_usage(
            TimePeriod={"Start": window_start.isoformat(), "End": today.isoformat()},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
        )
    )
    prior_spend, median_7d, regression = compute_spend(totals, prior_day)

    # CE call 2 (+ at most one pagination follow-up) -- usage types; also feeds invalidation MTD
    usage_start = min(month_start, window_start)
    matrix = usage_matrix(
        ce.get_cost_and_usage(
            TimePeriod={"Start": usage_start.isoformat(), "End": today.isoformat()},
            Granularity="DAILY",
            Metrics=["UnblendedCost", "UsageQuantity"],
            GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
        )
    )

    warnings: List[str] = []
    today_start = datetime(today.year, today.month, today.day, tzinfo=timezone.utc)
    prior_start = today_start - timedelta(days=1)

    digest: Dict[str, Any] = {
        "date": today.isoformat(),
        "prior_day_date": prior_day.isoformat(),
        "prior_day_spend": prior_spend,
        "median_7d": median_7d,
        "regression": regression,
        "top_deltas": compute_top_deltas(matrix, prior_day),
        "feed_publisher_invocations": None,
        "invalidation_paths_mtd": invalidation_paths_mtd(matrix, month_start, prior_day),
        "invalidation_free_tier": INVALIDATION_FREE_TIER,
        "jreese_net_bytes": {"current": None, "noncurrent": None},
        "devops_agentcli_compute_bytes": {"current": None, "noncurrent": None},
        "tracker_rru_wcu": {"rru": None, "wcu": None},
    }

    def _best_effort(label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 -- a metric hiccup must not lose the CE digest
            warnings.append(f"{label}: {type(exc).__name__}")
            LOGGER.warning(json.dumps({"event": "cost_digest_section_failed", "section": label, "error": str(exc)}))

    _best_effort("workload_metrics", lambda: digest.update(
        collect_workload_metrics(cw_for_region(WORKLOAD_REGION), prior_start, today_start)))
    _best_effort("jreese_net_bytes", lambda: digest.update(
        jreese_net_bytes=collect_bucket_bytes(cw_for_region(JREESE_NET_BUCKET_REGION), JREESE_NET_BUCKET, today_start)))
    _best_effort("devops_agentcli_compute_bytes", lambda: digest.update(
        devops_agentcli_compute_bytes=collect_bucket_bytes(cw_for_region(COMPUTE_BUCKET_REGION), COMPUTE_BUCKET, today_start)))

    # CloudWatch AWS/S3 BucketSizeBytes has no noncurrent-version StorageType (StandardStorage
    # already includes noncurrent versions), so `noncurrent` is null unless a configured dim
    # returns data. Say so explicitly instead of leaving a silent null.
    for field in ("jreese_net_bytes", "devops_agentcli_compute_bytes"):
        if digest[field]["current"] is not None and digest[field]["noncurrent"] is None:
            warnings.append(f"{field}.noncurrent: null -- CloudWatch AWS/S3 has no noncurrent storage type")

    # ENC-TSK-R38: weekly report-only compliance scan (Mondays UTC or event {"compliance_scan": true}).
    trigger = compliance_due(now, event) if client_for is not None else None
    if trigger and client_for is not None:
        scan_client_for = client_for
        _best_effort("compliance", lambda: digest.update(compliance=collect_compliance(scan_client_for, trigger)))
        for key, section in digest.get("compliance", {}).items():
            if isinstance(section, dict) and "error" in section:
                warnings.append(f"compliance.{key}: {str(section['error']).split(':', 1)[0]}")

    if ce.truncated:
        warnings.append("ce_truncated: usage-type pagination dropped to honor the 3-call budget")
    digest["generated_at"] = now.isoformat().replace("+00:00", "Z")
    digest["ce_calls"] = ce.calls
    if warnings:
        digest["warnings"] = warnings
    return digest


def digest_keys(digest_date: str) -> List[str]:
    """Dated (immutable history) key first, then latest -- latest only moves once history is safe."""
    return [f"{DIGEST_PREFIX}{digest_date}.json", f"{DIGEST_PREFIX}latest.json"]


def publish_digest(s3: Any, digest: Dict[str, Any]) -> List[str]:
    body = json.dumps(digest, separators=(",", ":"), sort_keys=False).encode("utf-8")
    keys = digest_keys(digest["date"])
    for key in keys:
        s3.put_object(Bucket=DIGEST_BUCKET, Key=key, Body=body, ContentType="application/json")
    return keys


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def lambda_handler(event: Any, context: Any) -> Dict[str, Any]:
    event = event if isinstance(event, dict) else {}
    now = _utcnow()
    LOGGER.info(json.dumps({"event": "cost_digest_start", "dry_run": bool(event.get("dry_run"))}))

    ce = _CostExplorerBudget(boto3.client("ce", region_name=CE_REGION))
    cw_clients: Dict[str, Any] = {}

    def cw_for_region(region: str) -> Any:
        if region not in cw_clients:
            cw_clients[region] = boto3.client("cloudwatch", region_name=region)
        return cw_clients[region]

    clients: Dict[Tuple[str, str], Any] = {}

    def client_for(service: str, region: str) -> Any:
        if service == "cloudwatch":
            return cw_for_region(region)
        if (service, region) not in clients:
            clients[(service, region)] = boto3.client(service, region_name=region)
        return clients[(service, region)]

    digest = build_digest(ce, cw_for_region, now, client_for=client_for, event=event)
    if event.get("dry_run"):
        keys: List[str] = []
    else:
        keys = publish_digest(boto3.client("s3", region_name=DIGEST_S3_REGION), digest)
    LOGGER.info(json.dumps({
        "event": "cost_digest_complete",
        "date": digest["date"],
        "ce_calls": digest["ce_calls"],
        "regression": digest["regression"],
        "compliance": digest.get("compliance", {}).get("trigger"),
        "keys": keys,
        "warnings": digest.get("warnings", []),
    }))
    return {
        "date": digest["date"],
        "ce_calls": digest["ce_calls"],
        "regression": digest["regression"],
        "compliance_scanned": "compliance" in digest,
        "keys": keys,
    }


# EventBridge target convention parity.
handler = lambda_handler
