"""tracker_ops.py — Tracker record creation, status updates, history append, snapshots.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Sequence

from botocore.exceptions import ClientError

from config import PROJECTS_TABLE, TRACKER_TABLE, _DEFAULT_STATUS, _SEGMENT_TO_TYPE, logger
from serialization import _deserialize, _now_z, _serialize
from aws_clients import _get_ddb
from project_utils import _build_record_id, _key_for_record_id, _next_tracker_sequence

__all__ = [
    "_append_tracker_history",
    "_classify_related",
    "_collect_tracker_snapshots",
    "_create_tracker_record_auto",
    "_normalize_string_list",
    "_related_records_mutated",
    "_requires_related_record_mutation_guard",
    "_resolve_project_id_for_prefix",
    "_set_tracker_status",
    "_tracker_record_snapshot",
]

def _classify_related(related_ids: Sequence[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rid in related_ids:
        ridu = str(rid).strip().upper()
        parts = ridu.split("-")
        if len(parts) < 3:
            continue
        segment = parts[1]
        rtype = _SEGMENT_TO_TYPE.get(segment)
        if not rtype:
            continue
        field = f"related_{rtype}_ids"
        out.setdefault(field, []).append(ridu)
    return out


def _normalize_string_list(value: Any, field_name: str) -> List[str]:
    """Normalize a string/list[str] into non-empty trimmed strings."""
    if value is None:
        return []
    if isinstance(value, str):
        source = [value]
    elif isinstance(value, list):
        source = value
    else:
        raise ValueError(f"{field_name} must be a string or list of strings")

    out: List[str] = []
    for entry in source:
        if not isinstance(entry, str):
            raise ValueError(f"{field_name} must contain only strings")
        stripped = entry.strip()
        if stripped:
            out.append(stripped)
    return out


def _create_tracker_record_auto(
    project_id: str,
    prefix: str,
    record_type: str,
    title: str,
    description: str,
    priority: str,
    assigned_to: str,
    related_ids: Optional[List[str]] = None,
    status: Optional[str] = None,
    success_metrics: Optional[List[str]] = None,
    acceptance_criteria: Optional[List[str]] = None,
    severity: Optional[str] = None,
    hypothesis: Optional[str] = None,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> str:
    normalized_acceptance_criteria = _normalize_string_list(
        acceptance_criteria,
        "acceptance_criteria",
    )
    if record_type == "task" and not normalized_acceptance_criteria:
        raise ValueError(
            "Task creation requires acceptance_criteria with at least one non-empty criterion"
        )

    ddb = _get_ddb()
    now = _now_z()
    for _ in range(5):
        seq = _next_tracker_sequence(project_id, record_type)
        record_id = _build_record_id(prefix, record_type, seq)
        item: Dict[str, Any] = {
            "project_id": project_id,
            "record_id": f"{record_type}#{record_id}",
            "record_type": record_type,
            "item_id": record_id,
            "title": title,
            "description": description,
            "priority": priority,
            "assigned_to": assigned_to,
            "status": status or _DEFAULT_STATUS[record_type],
            "created_at": now,
            "updated_at": now,
            "sync_version": 1,
            "last_update_note": "Created via coordination API",
            "history": [
                {
                    "timestamp": now,
                    "status": "created",
                    "description": f"Created via coordination API: {title}",
                }
            ],
        }
        if related_ids:
            item.update(_classify_related(related_ids))
        if record_type == "feature":
            item["owners"] = [assigned_to]
            if success_metrics:
                item["success_metrics"] = success_metrics
        if record_type == "task":
            item["acceptance_criteria"] = normalized_acceptance_criteria
        if record_type == "issue":
            if severity:
                item["severity"] = severity
            if hypothesis:
                item["hypothesis"] = hypothesis

        try:
            ddb.put_item(
                TableName=TRACKER_TABLE,
                Item={k: _serialize(v) for k, v in item.items()},
                ConditionExpression="attribute_not_exists(record_id)",
            )
            return record_id
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            raise

    raise RuntimeError("Failed allocating tracker record id after retries")


def _append_tracker_history(
    record_id: str,
    status: str,
    note: str,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> None:
    _ = governance_hash, coordination_request_id, dispatch_id, provider
    project_id, _record_type, sk = _key_for_record_id(record_id)
    ddb = _get_ddb()
    now = _now_z()
    entry = [{"timestamp": now, "status": status, "description": note[:1000]}]
    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
        UpdateExpression=(
            "SET updated_at = :ts, last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "#history = list_append(if_not_exists(#history, :empty), :entry)"
        ),
        ExpressionAttributeNames={"#history": "history"},
        ExpressionAttributeValues={
            ":ts": _serialize(now),
            ":note": _serialize(note[:1000]),
            ":zero": _serialize(0),
            ":one": _serialize(1),
            ":empty": _serialize([]),
            ":entry": _serialize(entry),
        },
    )


def _set_tracker_status(
    record_id: str,
    new_status: str,
    note: str,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> None:
    _ = governance_hash, coordination_request_id, dispatch_id, provider
    project_id, _record_type, sk = _key_for_record_id(record_id)
    ddb = _get_ddb()
    now = _now_z()
    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
        UpdateExpression=(
            "SET #status = :new_status, updated_at = :ts, last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":new_status": _serialize(new_status),
            ":ts": _serialize(now),
            ":note": _serialize(note[:1000]),
            ":zero": _serialize(0),
            ":one": _serialize(1),
        },
    )
    _append_tracker_history(
        record_id,
        "worklog",
        note,
        governance_hash=governance_hash,
        coordination_request_id=coordination_request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )


def _resolve_project_id_for_prefix(prefix: str) -> Optional[str]:
    normalized_prefix = str(prefix or "").strip().upper()
    if not normalized_prefix:
        return None

    for project_id, data in _project_cache.items():
        if str(data.get("prefix") or "").upper() == normalized_prefix:
            return str(project_id)

    ddb = _get_ddb()
    scan = ddb.scan(
        TableName=PROJECTS_TABLE,
        ProjectionExpression="project_id, #pfx",
        ExpressionAttributeNames={"#pfx": "prefix"},
    )
    items = scan.get("Items", [])
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, #pfx",
            ExpressionAttributeNames={"#pfx": "prefix"},
            ExclusiveStartKey=scan["LastEvaluatedKey"],
        )
        items.extend(scan.get("Items", []))

    for raw in items:
        row = _deserialize(raw)
        project_id = str(row.get("project_id") or "").strip()
        project_prefix = str(row.get("prefix") or "").strip().upper()
        if project_id and project_prefix:
            _project_cache[project_id] = {"prefix": project_prefix}
        if project_prefix == normalized_prefix:
            return project_id or None

    return None


def _tracker_record_snapshot(record_id: str) -> Optional[Dict[str, Any]]:
    normalized_id = str(record_id or "").strip().upper()
    parts = normalized_id.split("-")
    if len(parts) != 3:
        return None

    prefix, segment, _num = parts
    segment_alias = "TSK" if segment == "TASK" else segment
    record_type = _SEGMENT_TO_TYPE.get(segment_alias)
    if not record_type:
        return None

    project_id = _resolve_project_id_for_prefix(prefix)
    if not project_id:
        return None

    sk = f"{record_type}#{normalized_id}"

    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=TRACKER_TABLE,
            Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed reading tracker snapshot for %s: %s", record_id, exc)
        return None

    item = resp.get("Item")
    if not item:
        return None

    plain = _deserialize(item)
    history = plain.get("history")
    sync_version_raw = plain.get("sync_version")
    try:
        sync_version = int(sync_version_raw)
    except (TypeError, ValueError):
        sync_version = 0

    return {
        "status": str(plain.get("status") or ""),
        "updated_at": str(plain.get("updated_at") or ""),
        "sync_version": sync_version,
        "history_len": len(history) if isinstance(history, list) else 0,
    }


def _collect_tracker_snapshots(record_ids: Sequence[str]) -> Dict[str, Optional[Dict[str, Any]]]:
    snapshots: Dict[str, Optional[Dict[str, Any]]] = {}
    seen: set[str] = set()
    for raw_id in record_ids:
        record_id = str(raw_id or "").strip().upper()
        if not record_id or record_id in seen:
            continue
        seen.add(record_id)
        snapshots[record_id] = _tracker_record_snapshot(record_id)
    return snapshots


def _related_records_mutated(
    before: Dict[str, Optional[Dict[str, Any]]],
    after: Dict[str, Optional[Dict[str, Any]]],
) -> Tuple[bool, List[str]]:
    changed_ids: List[str] = []
    for record_id in sorted(set(before.keys()) | set(after.keys())):
        if before.get(record_id) != after.get(record_id):
            changed_ids.append(record_id)
    return bool(changed_ids), changed_ids


def _requires_related_record_mutation_guard(request: Dict[str, Any], execution_mode: str) -> bool:
    if execution_mode not in {"codex_app_server", "codex_full_auto"}:
        return False

    related = [str(item).strip() for item in (request.get("related_record_ids") or []) if str(item).strip()]
    if not related:
        return False

    constraints = request.get("constraints")
    if not isinstance(constraints, dict):
        constraints = {}

    require_guard = constraints.get("require_related_record_mutation")
    if isinstance(require_guard, bool):
        return require_guard

    allow_noop_success = constraints.get("allow_noop_success")
    if isinstance(allow_noop_success, bool) and allow_noop_success:
        return False

    return True


