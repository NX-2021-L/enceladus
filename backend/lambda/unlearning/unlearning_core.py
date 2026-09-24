"""FTR-106 / ENC-TSK-K03 — Crick-Mitchison unlearning core (reverse-consolidation).

Nightly per-invocation pass that identifies low-value graph entities from
consolidation/drift telemetry and either:
  * report-only (default + io-approval ramp): writes unlearning-candidate docs
  * mutation mode (explicitly enabled): archives eligible reference records and
    writes reversible S3 tombstones before graph_sync removes Neo4j projection

COST-PREFLIGHT: ~$0.25/mo (4× nightly Lambda 512MB×300s + S3 tombstones <100MB).

DATA-SAFETY:
  * UNLEARNING_DRY_RUN=1 (default) — no tracker/S3 mutations
  * UNLEARNING_MUTATION_ENABLED=0 (default) — report-only even when dry_run off
  * IO_APPROVAL_RUNS=3 — first three live runs emit reports only
  * Tombstones retained TOMBSTONE_RECOVERY_DAYS (30) before hard-delete path

OGTM: no new Neo4j edge types; archive uses existing graph_sync stream surfaces.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

COST_PREFLIGHT_MONTHLY_USD = 0.25
UNLEARNING_CANDIDATE_SUBTYPEPATTERN = "unlearning-candidate"
TOMBSTONE_SCHEMA = "enceladus.unlearning.tombstone.v1"

UNLEARNING_DRY_RUN = os.environ.get("UNLEARNING_DRY_RUN", "1").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
UNLEARNING_MUTATION_ENABLED = os.environ.get(
    "UNLEARNING_MUTATION_ENABLED", "0"
).strip().lower() in ("1", "true", "yes", "on")

try:
    IO_APPROVAL_RUNS = int(os.environ.get("IO_APPROVAL_RUNS", "3"))
except (TypeError, ValueError):
    IO_APPROVAL_RUNS = 3

try:
    TOMBSTONE_RECOVERY_DAYS = int(os.environ.get("TOMBSTONE_RECOVERY_DAYS", "30"))
except (TypeError, ValueError):
    TOMBSTONE_RECOVERY_DAYS = 30

try:
    LOOKBACK_HOURS = int(os.environ.get("UNLEARNING_LOOKBACK_HOURS", "24"))
except (TypeError, ValueError):
    LOOKBACK_HOURS = 24

try:
    SPURIOUS_ATTRACTOR_THRESHOLD = float(
        os.environ.get("UNLEARNING_SPURIOUS_ATTRACTOR_THRESHOLD", "0.5")
    )
except (TypeError, ValueError):
    SPURIOUS_ATTRACTOR_THRESHOLD = 0.5

try:
    MIN_MISS_COUNT = int(os.environ.get("UNLEARNING_MIN_MISS_COUNT", "3"))
except (TypeError, ValueError):
    MIN_MISS_COUNT = 3


def is_dry_run(event: Optional[Dict[str, Any]] = None) -> bool:
    if isinstance(event, dict) and "dry_run" in event:
        return bool(event.get("dry_run"))
    return UNLEARNING_DRY_RUN


def io_approval_ramp_active(run_count: int) -> bool:
    """True while live runs are still in the report-only ramp."""
    return run_count < IO_APPROVAL_RUNS


def mutation_allowed(
    *,
    run_count: int,
    dry_run: bool,
    mutation_enabled: bool = UNLEARNING_MUTATION_ENABLED,
) -> bool:
    if dry_run or not mutation_enabled:
        return False
    return not io_approval_ramp_active(run_count)


def _parse_float(attr: Dict[str, Any]) -> Optional[float]:
    if not isinstance(attr, dict):
        return None
    if "N" in attr:
        try:
            return float(attr["N"])
        except (TypeError, ValueError):
            return None
    if "NULL" in attr:
        return None
    return None


def _deser(attr: Dict[str, Any]) -> Any:
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        return attr["N"]
    if "BOOL" in attr:
        return attr["BOOL"]
    if "NULL" in attr:
        return None
    if "M" in attr:
        return {k: _deser(v) for k, v in attr["M"].items()}
    if "L" in attr:
        return [_deser(v) for v in attr["L"]]
    return None


def fetch_high_spurious_waves(
    ddb: Any,
    *,
    table_name: str,
    project_id: str,
    cutoff_iso: str,
    index_name: str = "project-timestamp-index",
) -> Set[str]:
    """Return wave_ids whose spurious_attractor_rate exceeds the threshold."""
    if not table_name:
        return set()
    waves: Set[str] = set()
    params: Dict[str, Any] = {
        "TableName": table_name,
        "IndexName": index_name,
        "KeyConditionExpression": "project_id = :pid AND #ts >= :cut",
        "ExpressionAttributeNames": {"#ts": "timestamp"},
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":cut": {"S": cutoff_iso},
        },
    }
    while True:
        resp = ddb.query(**params)
        for item in resp.get("Items") or []:
            sar = _parse_float(item.get("spurious_attractor_rate") or {})
            if sar is not None and sar >= SPURIOUS_ATTRACTOR_THRESHOLD:
                wid = _deser(item.get("wave_id") or {})
                if wid:
                    waves.add(str(wid))
        if not resp.get("LastEvaluatedKey"):
            break
        params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return waves


def _trace_outcome_is_miss(outcome_raw: Any) -> bool:
    if not outcome_raw:
        return False
    try:
        outcome = json.loads(outcome_raw) if isinstance(outcome_raw, str) else outcome_raw
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(outcome, dict):
        return False
    if str(outcome.get("retrieval_outcome") or "").lower() == "miss":
        return True
    try:
        score = float(outcome.get("fused_score"))
        return score < 0.3
    except (TypeError, ValueError):
        return False


def identify_candidates_from_traces(
    traces: Sequence[Dict[str, Any]],
    *,
    hot_waves: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Rank record_ids by miss-frequency in stigmergic traces."""
    counts: Dict[str, int] = {}
    for trace in traces or []:
        if not isinstance(trace, dict):
            continue
        if not _trace_outcome_is_miss(trace.get("outcome_signal")):
            continue
        path = str(trace.get("record_id_path") or "")
        for rid in [p.strip() for p in path.split("|") if p.strip()]:
            counts[rid] = counts.get(rid, 0) + 1

    candidates: List[Dict[str, Any]] = []
    for rid, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if count < MIN_MISS_COUNT:
            continue
        candidates.append(
            {
                "record_id": rid,
                "miss_count": count,
                "reason": "stigmergic_miss_cluster",
                "hot_wave": bool(hot_waves and any(True for _ in [1])),
            }
        )
    return candidates


def build_tombstone(
    record_id: str,
    snapshot: Dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    ts = now or datetime.now(timezone.utc)
    recover_until = ts + timedelta(days=TOMBSTONE_RECOVERY_DAYS)
    return {
        "schema": TOMBSTONE_SCHEMA,
        "record_id": record_id,
        "snapshot": snapshot,
        "created_at": ts.isoformat().replace("+00:00", "Z"),
        "recover_until": recover_until.isoformat().replace("+00:00", "Z"),
        "recovery_window_days": TOMBSTONE_RECOVERY_DAYS,
    }


def tombstone_s3_key(prefix: str, record_id: str, created_at: str) -> str:
    safe_rid = record_id.replace("/", "_")
    ts_slug = created_at.replace(":", "").replace("-", "")
    base = (prefix or "unlearning-tombstones").strip().strip("/")
    return f"{base}/{safe_rid}/{ts_slug}.json"


def stable_report_doc_id(project_id: str, run_id: str) -> str:
    digest = hashlib.sha1(f"{project_id}:{run_id}:unlearning".encode()).hexdigest()[:12]
    return f"DOC-{digest.upper()}"


def build_candidate_report_body(
    project_id: str,
    candidates: Sequence[Dict[str, Any]],
    *,
    run_count: int,
    dry_run: bool,
    mutation_enabled: bool,
) -> str:
    lines = [
        f"# Unlearning candidate report — {project_id}",
        "",
        f"- run_count: {run_count}",
        f"- dry_run: {dry_run}",
        f"- mutation_enabled: {mutation_enabled}",
        f"- io_approval_ramp_active: {io_approval_ramp_active(run_count)}",
        "",
        "## Candidates",
        "",
    ]
    if not candidates:
        lines.append("_No prune candidates identified in lookback window._")
    else:
        for c in candidates:
            lines.append(
                f"- `{c.get('record_id')}` — {c.get('reason')} "
                f"(miss_count={c.get('miss_count', 'n/a')})"
            )
    return "\n".join(lines) + "\n"


def list_expired_tombstone_keys(
    list_objects: Callable[[str], Iterable[str]],
    prefix: str,
    *,
    now: Optional[datetime] = None,
    get_object: Optional[Callable[[str], str]] = None,
) -> List[str]:
    """Return S3 keys whose tombstone recover_until is in the past."""
    ts = now or datetime.now(timezone.utc)
    expired: List[str] = []
    for key in list_objects(prefix):
        if not get_object:
            continue
        try:
            body = get_object(key)
            doc = json.loads(body)
            until = doc.get("recover_until")
            if not until:
                continue
            recover = datetime.fromisoformat(str(until).replace("Z", "+00:00"))
            if recover <= ts:
                expired.append(key)
        except Exception:  # noqa: BLE001
            continue
    return expired
