"""ENC-FTR-109 / ENC-TSK-K05 — Stigmergic exploration trace emission.

Per-event telemetry records for retrieval and graph-traversal activity. Writes
are fire-and-forget DynamoDB ``put_item`` calls (PAY_PER_REQUEST); when the
table env var is unset the emitter degrades to a structured CloudWatch line.

Telemetry-only: this module never mutates retrieval ranking, graph weights, or
any governed record. Exploration-weighting is a future io decision informed by
accumulated traces.

OGTM (ENC-FTR-066): traces land in DynamoDB only — no new Neo4j edge type.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

from drift_telemetry import to_ddb_item

STIGMERGIC_TRACE_SCHEMA = "enceladus.stigmergic.trace.v1"
TRACE_TTL_DAYS = 90


def _iso_timestamp(ts: Optional[datetime] = None) -> str:
    when = ts or datetime.now(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_trace_record(
    *,
    project_id: str,
    session_id: str,
    event_type: str,
    record_id_path: Sequence[str],
    outcome_signal: Dict[str, Any],
    timestamp: Optional[str] = None,
    trace_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build one stigmergic trace record with a 90-day TTL."""
    if not project_id:
        raise ValueError("build_trace_record requires project_id")
    if event_type not in {"retrieval", "traversal"}:
        raise ValueError("event_type must be 'retrieval' or 'traversal'")
    when = now or datetime.now(timezone.utc)
    expires_at = int((when + timedelta(days=TRACE_TTL_DAYS)).timestamp())
    path = [str(rid).strip() for rid in record_id_path if str(rid).strip()]
    return {
        "schema": STIGMERGIC_TRACE_SCHEMA,
        "trace_id": trace_id or uuid.uuid4().hex,
        "project_id": project_id,
        "session_id": str(session_id or "unassigned"),
        "event_type": event_type,
        "record_id_path": "|".join(path),
        "timestamp": timestamp or _iso_timestamp(when),
        "outcome_signal": json.dumps(outcome_signal, sort_keys=True, default=str),
        "expires_at": expires_at,
    }


def emit_stigmergic_trace(
    ddb_client: Any,
    table_name: str,
    record: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist one trace via ``put_item``. Client is injected for unit tests."""
    if not table_name:
        raise ValueError("emit_stigmergic_trace requires a table_name")
    ddb_client.put_item(TableName=table_name, Item=to_ddb_item(record))
    return record


def record_id_path_from_graph_result(result: Dict[str, Any]) -> List[str]:
    """Extract a stable record-id path from a graphsearch handler result."""
    seen: set[str] = set()
    ordered: List[str] = []

    def _add(rid: Any) -> None:
        token = str(rid or "").strip()
        if token and token not in seen:
            seen.add(token)
            ordered.append(token)

    pathway = result.get("pathway") or {}
    for rid in pathway.get("node_sequence") or []:
        _add(rid)

    for node in result.get("nodes") or []:
        if isinstance(node, dict):
            _add(node.get("record_id"))

    for path in result.get("paths") or []:
        if not isinstance(path, dict):
            continue
        for rid in path.get("node_ids") or path.get("nodes") or []:
            _add(rid)

    return ordered
