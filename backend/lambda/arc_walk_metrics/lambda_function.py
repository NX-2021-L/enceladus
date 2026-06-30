"""arc_walk_metrics/lambda_function.py — Universal Arc-Walker telemetry + convergence probe
(ENC-TSK-H86 / ENC-FTR-111 Phase 1, T5).

Read-only, EventBridge-scheduled Lambda that surfaces the Universal Arc-Walker's operational
signals to the ENC-TSK-B66 observability dashboard as CloudWatch metrics (DOC-078C57FC1BE6 §10,
feature AC-6). It NEVER mutates a record — it scans the tracker table and publishes metrics only.

Three signals, exactly matching ENC-TSK-B66's arc-walk dashboard AC:

  1. ConvergenceBacklog / ConvergenceGatesShort — the read-only CONVERGENCE PROBE. Counts records
     currently sitting one or more *mechanical* gates short of where the walker could place them
     (DOC-078C57FC1BE6 §10 "convergence telemetry"). Quantifies the ceremony the walker eliminates
     and validates value independent of whether the mutating walk flag is enabled. A record latched
     `auto_walk_opt_out` is parked by design, so it is excluded from the backlog (the walker could
     NOT place it) and reported separately.

  2. ArcWalkAutoAdvances (dimension GateClass) — auto-advance counts by gate_class, derived from the
     governed [ARC-WALKER][AUTO-ADVANCE] Artifact-Genesis history entries the H85 walk loop writes.

  3. OptOutLatchEvents / OptOutClearEvents / OptOutLatchedRecords — opt_out latch/clear telemetry,
     derived from the [ARC-WALKER][OPT-OUT-LATCH|OPT-OUT-SET|OPT-OUT-CLEAR] history markers
     (H83 auto-latch + H86 explicit set/clear) and the live auto_walk_opt_out field.

Phase-1 mechanical-leg eligibility mirrors tracker_mutation._arc_walk_next_candidate + the
Lifecycle Service ruling O-2 (deploy-init auto-walks only on ci_triggered projects). The matrix
basis is DOC-B5B807D7C2CE (transition_type_matrix v1); gate_class taxonomy DOC-078C57FC1BE6 §3.

Environment variables:
  TRACKER_TABLE        default: devops-project-tracker  (governed records — the scan source)
  PROJECTS_TABLE       default: projects                (per-project deploy_policy, ruling O-2)
  CLOUDWATCH_NAMESPACE default: Enceladus/ArcWalk
  DYNAMODB_REGION      default: us-west-2
  PROJECT_ID           default: enceladus               (CloudWatch ProjectId dimension)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/ArcWalk")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")

# ---------------------------------------------------------------------------
# Phase-1 mechanical-leg model — mirror of tracker_mutation._arc_walk_next_candidate + ruling O-2.
# Kept self-contained (this Lambda is read-only and standalone, like graph_health_metrics) with an
# explicit cross-reference so a matrix change is a one-line, reviewable update here.
# ---------------------------------------------------------------------------
DEPLOY_ARC_TYPES = frozenset({"github_pr_deploy", "lambda_deploy", "web_deploy"})
DEPLOY_POLICY_CI_TRIGGERED = "ci_triggered"
DEFAULT_DEPLOY_POLICY = DEPLOY_POLICY_CI_TRIGGERED
GATE_CLASS_MECHANICAL = "mechanical"

# Bounded so a malformed record can never spin the convergence walk (mirror of _ARC_WALK_MAX_STEPS).
_MAX_WALK_STEPS = 8


def _mechanical_next(transition_type: str, status: str, deploy_policy: str) -> Optional[str]:
    """The single forward status a Phase-1 MECHANICAL gate would place this record at, or None.

    Phase-1 mechanical legs (DOC-078C57FC1BE6 §3.1 / §11):
      - <deploy-arc>|merged-main -> deploy-init   (ruling O-2: ci_triggered projects only)
      - code_only|merged-main    -> closed        (reuses stored commit_sha + GitHub compare)
    """
    tt = (transition_type or "github_pr_deploy").strip().lower()
    cur = (status or "").strip().lower()
    pol = (deploy_policy or DEFAULT_DEPLOY_POLICY).strip().lower()
    if cur == "merged-main":
        if tt == "code_only":
            return "closed"
        if tt in DEPLOY_ARC_TYPES and pol == DEPLOY_POLICY_CI_TRIGGERED:
            return "deploy-init"
    return None


def convergence_distance(transition_type: str, status: str, deploy_policy: str,
                         opt_out: bool) -> int:
    """How many consecutive MECHANICAL gates this record is short of its walker-reachable state.

    A record latched `auto_walk_opt_out` is parked by design (the walker can never advance it), so
    its distance is 0 — it is NOT part of the convergence backlog. Otherwise simulate the forward
    mechanical walk and count the gates. Phase-1 yields 0 or 1; the loop is forward-compatible with
    later mechanical legs and bounded against malformed cycles."""
    if opt_out:
        return 0
    cur = (status or "").strip().lower()
    steps = 0
    for _ in range(_MAX_WALK_STEPS):
        nxt = _mechanical_next(transition_type, cur, deploy_policy)
        if nxt is None:
            break
        steps += 1
        cur = nxt
    return steps


# ---------------------------------------------------------------------------
# History parsing — governed Artifact-Genesis markers written by the walk loop / opt_out paths.
# ---------------------------------------------------------------------------
def parse_history_arc_walk_counts(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Count arc-walk telemetry events from a record's history entries.

    Returns {"auto_advances_by_gate_class": {gate_class: n, ...}, "opt_out_latch": n,
    "opt_out_clear": n}. Recognized markers (descriptions written by tracker_mutation):
      - "[ARC-WALKER][AUTO-ADVANCE] ... (gate_class=<c>, ...)"   (H85 walk loop)
      - "[ARC-WALKER][OPT-OUT-LATCH]" / "[ARC-WALKER][OPT-OUT-SET]"  (H83 auto-latch / H86 explicit set)
      - "[ARC-WALKER][OPT-OUT-CLEAR]"                            (H86 explicit clear)
    """
    by_class: Dict[str, int] = {}
    latch = 0
    clear = 0
    for entry in history or []:
        desc = ""
        if isinstance(entry, dict):
            desc = str(entry.get("description", "") or "")
        if "[ARC-WALKER][AUTO-ADVANCE]" in desc:
            gc = _extract_gate_class(desc) or "unknown"
            by_class[gc] = by_class.get(gc, 0) + 1
        elif "[ARC-WALKER][OPT-OUT-LATCH]" in desc or "[ARC-WALKER][OPT-OUT-SET]" in desc:
            latch += 1
        elif "[ARC-WALKER][OPT-OUT-CLEAR]" in desc:
            clear += 1
    return {"auto_advances_by_gate_class": by_class, "opt_out_latch": latch, "opt_out_clear": clear}


def _extract_gate_class(description: str) -> Optional[str]:
    """Pull gate_class=<c> out of an [ARC-WALKER][AUTO-ADVANCE] history description."""
    marker = "gate_class="
    idx = description.find(marker)
    if idx < 0:
        return None
    tail = description[idx + len(marker):]
    # value ends at the next comma, close-paren, or whitespace.
    end = len(tail)
    for ch in (",", ")", " "):
        pos = tail.find(ch)
        if pos != -1:
            end = min(end, pos)
    val = tail[:end].strip()
    return val or None


# ---------------------------------------------------------------------------
# Aggregation — pure function over deserialized records (testable without AWS).
# ---------------------------------------------------------------------------
def aggregate(records: Iterable[Dict[str, Any]], deploy_policy_for) -> Dict[str, Any]:
    """Aggregate the three arc-walk dashboard signals over deserialized records.

    `records`: dicts with keys record_type, status, transition_type, checkout_transition_type,
    auto_walk_opt_out, project_id, history. `deploy_policy_for`: callable(project_id) -> policy str.
    """
    backlog_records = 0
    gates_short = 0
    opt_out_latched_records = 0
    auto_advances_by_gate_class: Dict[str, int] = {}
    opt_out_latch_events = 0
    opt_out_clear_events = 0
    tasks_scanned = 0
    records_scanned = 0

    for rec in records:
        records_scanned += 1
        opt_out = bool(rec.get("auto_walk_opt_out", False))
        if opt_out:
            opt_out_latched_records += 1

        counts = parse_history_arc_walk_counts(rec.get("history") or [])
        for gc, n in counts["auto_advances_by_gate_class"].items():
            auto_advances_by_gate_class[gc] = auto_advances_by_gate_class.get(gc, 0) + n
        opt_out_latch_events += counts["opt_out_latch"]
        opt_out_clear_events += counts["opt_out_clear"]

        if (rec.get("record_type") or "").strip().lower() != "task":
            continue
        tasks_scanned += 1
        # Pin to the checkout-stamped transition_type when present (matrix-version integrity, B07/B08).
        tt = rec.get("checkout_transition_type") or rec.get("transition_type") or "github_pr_deploy"
        policy = deploy_policy_for(rec.get("project_id") or PROJECT_ID)
        dist = convergence_distance(tt, rec.get("status") or "", policy, opt_out)
        if dist > 0:
            backlog_records += 1
            gates_short += dist

    return {
        "convergence_backlog_records": backlog_records,
        "convergence_gates_short": gates_short,
        "opt_out_latched_records": opt_out_latched_records,
        "auto_advances_by_gate_class": auto_advances_by_gate_class,
        "opt_out_latch_events": opt_out_latch_events,
        "opt_out_clear_events": opt_out_clear_events,
        "tasks_scanned": tasks_scanned,
        "records_scanned": records_scanned,
    }


def build_metric_data(agg: Dict[str, Any], project_id: str, now: datetime) -> List[Dict[str, Any]]:
    """Translate an aggregate into CloudWatch MetricData (read-only; published by the handler)."""
    base_dims = [{"Name": "ProjectId", "Value": project_id}]
    data: List[Dict[str, Any]] = [
        {"MetricName": "ConvergenceBacklog", "Value": float(agg["convergence_backlog_records"]),
         "Unit": "Count", "Timestamp": now, "Dimensions": base_dims},
        {"MetricName": "ConvergenceGatesShort", "Value": float(agg["convergence_gates_short"]),
         "Unit": "Count", "Timestamp": now, "Dimensions": base_dims},
        {"MetricName": "OptOutLatchedRecords", "Value": float(agg["opt_out_latched_records"]),
         "Unit": "Count", "Timestamp": now, "Dimensions": base_dims},
        {"MetricName": "OptOutLatchEvents", "Value": float(agg["opt_out_latch_events"]),
         "Unit": "Count", "Timestamp": now, "Dimensions": base_dims},
        {"MetricName": "OptOutClearEvents", "Value": float(agg["opt_out_clear_events"]),
         "Unit": "Count", "Timestamp": now, "Dimensions": base_dims},
    ]
    for gate_class, count in sorted(agg["auto_advances_by_gate_class"].items()):
        data.append({
            "MetricName": "ArcWalkAutoAdvances", "Value": float(count), "Unit": "Count",
            "Timestamp": now,
            "Dimensions": base_dims + [{"Name": "GateClass", "Value": gate_class}],
        })
    return data


# ---------------------------------------------------------------------------
# AWS plumbing (lazy clients; mirrors graph_health_metrics structure).
# ---------------------------------------------------------------------------
_ddb = None
_cw = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_cw():
    global _cw
    if _cw is None:
        _cw = boto3.client("cloudwatch", region_name=DYNAMODB_REGION)
    return _cw


def _deser_records(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Project the raw DynamoDB items to the minimal fields the aggregate needs."""
    out: List[Dict[str, Any]] = []
    for it in items:
        history: List[Dict[str, Any]] = []
        for h in (it.get("history", {}) or {}).get("L", []):
            m = h.get("M") or {}
            history.append({"description": (m.get("description", {}) or {}).get("S", "")})
        opt_out_attr = it.get("auto_walk_opt_out", {}) or {}
        out.append({
            "record_type": (it.get("record_type", {}) or {}).get("S", ""),
            "status": (it.get("status", {}) or {}).get("S", ""),
            "transition_type": (it.get("transition_type", {}) or {}).get("S", ""),
            "checkout_transition_type": (it.get("checkout_transition_type", {}) or {}).get("S", ""),
            "auto_walk_opt_out": bool(opt_out_attr.get("BOOL", False)),
            "project_id": (it.get("project_id", {}) or {}).get("S", ""),
            "history": history,
        })
    return out


def _scan_tracker() -> List[Dict[str, Any]]:
    ddb = _get_ddb()
    items: List[Dict[str, Any]] = []
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(
        TableName=TRACKER_TABLE,
        ProjectionExpression="project_id, record_type, #s, transition_type, "
                             "checkout_transition_type, auto_walk_opt_out, history",
        ExpressionAttributeNames={"#s": "status"},
    ):
        items.extend(page.get("Items", []))
    return items


class _DeployPolicyResolver:
    """Cache per-project deploy_policy (ruling O-2). Missing/unknown -> ci_triggered default,
    matching lifecycle_service._get_project_deploy_policy fail-open semantics."""

    def __init__(self) -> None:
        self._cache: Dict[str, str] = {}

    def __call__(self, project_id: str) -> str:
        pid = (project_id or "").strip()
        if not pid:
            return DEFAULT_DEPLOY_POLICY
        if pid in self._cache:
            return self._cache[pid]
        policy = DEFAULT_DEPLOY_POLICY
        try:
            resp = _get_ddb().get_item(
                TableName=PROJECTS_TABLE,
                Key={"project_id": {"S": pid}},
                ProjectionExpression="deploy_policy",
            )
            val = ((resp.get("Item") or {}).get("deploy_policy", {}) or {}).get("S", "").strip().lower()
            if val in (DEPLOY_POLICY_CI_TRIGGERED, "manual"):
                policy = val
        except Exception:  # noqa: BLE001
            logger.warning("[H86] deploy_policy read failed for '%s'; default '%s'",
                           pid, DEFAULT_DEPLOY_POLICY, exc_info=True)
        self._cache[pid] = policy
        return policy


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:  # noqa: ANN001
    """Compute the arc-walk convergence probe + telemetry counts and publish to CloudWatch."""
    logger.info("[START] arc-walk metrics — table=%s namespace=%s", TRACKER_TABLE, CLOUDWATCH_NAMESPACE)
    try:
        items = _scan_tracker()
        records = _deser_records(items)
        agg = aggregate(records, _DeployPolicyResolver())
        now = datetime.now(timezone.utc)
        metric_data = build_metric_data(agg, PROJECT_ID, now)

        cw = _get_cw()
        for i in range(0, len(metric_data), 20):  # CloudWatch cap: 20 datapoints per call
            cw.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=metric_data[i:i + 20])

        logger.info(
            "[SUCCESS] arc-walk metrics published: backlog=%d gates_short=%d opt_out_latched=%d "
            "auto_advances=%s (records_scanned=%d)",
            agg["convergence_backlog_records"], agg["convergence_gates_short"],
            agg["opt_out_latched_records"], agg["auto_advances_by_gate_class"],
            agg["records_scanned"],
        )
        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True, "namespace": CLOUDWATCH_NAMESPACE,
                "metrics_published": len(metric_data), **agg,
            }),
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("[ERROR] arc-walk metrics failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"success": False, "error": str(exc)})}
