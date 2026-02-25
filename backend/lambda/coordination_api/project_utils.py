"""project_utils.py — Project metadata loading, tracker ID sequences, record key building.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from botocore.exceptions import BotoCoreError, ClientError

from config import PROJECTS_TABLE, TRACKER_TABLE, _SEGMENT_TO_TYPE, _TYPE_TO_SEGMENT
from serialization import _deserialize, _serialize
from aws_clients import _get_ddb

__all__ = [
    "ProjectMeta",
    "_ENCELADUS_MCP_SERVER_MODULE",
    "_MCP_RESOURCE_CACHE",
    "_PROJECT_CACHE_TTL",
    "_build_record_id",
    "_key_for_record_id",
    "_load_project_meta",
    "_next_tracker_sequence",
    "_project_cache",
    "_project_cache_at",
]

# ---------------------------------------------------------------------------
# Project metadata cache / ID helpers
# ---------------------------------------------------------------------------

_project_cache: Dict[str, Dict[str, Any]] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0
_ENCELADUS_MCP_SERVER_MODULE = None
_MCP_RESOURCE_CACHE: Dict[str, str] = {}
_TRACKER_COUNTER_PREFIX = "counter#"


@dataclass
class ProjectMeta:
    project_id: str
    prefix: str


def _load_project_meta(project_id: str) -> ProjectMeta:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now

    if project_id in _project_cache:
        cached = _project_cache[project_id]
        return ProjectMeta(project_id=project_id, prefix=cached["prefix"])

    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": _serialize(project_id)},
            ConsistentRead=True,
            ProjectionExpression="project_id, #pfx",
            ExpressionAttributeNames={"#pfx": "prefix"},
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed reading projects table: {exc}") from exc

    item = resp.get("Item")
    if not item:
        raise ValueError(f"Project '{project_id}' is not registered")

    plain = _deserialize(item)
    prefix = str(plain.get("prefix") or "").upper()
    if not re.fullmatch(r"[A-Z]{3}", prefix):
        raise ValueError(f"Project '{project_id}' has invalid prefix '{prefix}'")

    _project_cache[project_id] = {"prefix": prefix}
    return ProjectMeta(project_id=project_id, prefix=prefix)


def _next_tracker_sequence(project_id: str, record_type: str) -> int:
    def _max_existing_tracker_sequence() -> int:
        max_num = 0
        kwargs: Dict[str, Any] = {
            "TableName": TRACKER_TABLE,
            "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :rtype_prefix)",
            "ExpressionAttributeValues": {
                ":pid": _serialize(project_id),
                ":rtype_prefix": _serialize(f"{record_type}#"),
            },
            "ProjectionExpression": "item_id",
            "ConsistentRead": True,
        }
        while True:
            query_resp = ddb.query(**kwargs)
            for raw in query_resp.get("Items", []):
                iid = _deserialize(raw).get("item_id", "")
                parts = iid.split("-")
                if len(parts) < 3:
                    continue
                try:
                    n = int(parts[-1])
                except ValueError:
                    continue
                if n > max_num:
                    max_num = n
            last_key = query_resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return max_num

    ddb = _get_ddb()
    counter_key = {
        "project_id": _serialize(project_id),
        "record_id": _serialize(f"{_TRACKER_COUNTER_PREFIX}{record_type}"),
    }
    seed_num = 0

    try:
        counter_item = ddb.get_item(
            TableName=TRACKER_TABLE,
            Key=counter_key,
            ConsistentRead=True,
        ).get("Item")
        if not counter_item:
            seed_num = _max_existing_tracker_sequence()

        update_resp = ddb.update_item(
            TableName=TRACKER_TABLE,
            Key=counter_key,
            UpdateExpression=(
                "SET next_num = if_not_exists(next_num, :seed) + :one, "
                "record_type = if_not_exists(record_type, :counter_type), "
                "item_id = if_not_exists(item_id, :counter_item_id)"
            ),
            ExpressionAttributeValues={
                ":seed": _serialize(seed_num),
                ":one": _serialize(1),
                ":counter_type": _serialize("counter"),
                ":counter_item_id": _serialize(f"COUNTER-{record_type.upper()}"),
            },
            ReturnValues="UPDATED_NEW",
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed allocating tracker sequence: {exc}") from exc

    attrs = update_resp.get("Attributes", {})
    try:
        return int(attrs.get("next_num", {}).get("N", str(seed_num + 1)))
    except (TypeError, ValueError):
        return seed_num + 1


def _build_record_id(prefix: str, record_type: str, seq: int) -> str:
    return f"{prefix}-{_TYPE_TO_SEGMENT[record_type]}-{seq:03d}"


def _key_for_record_id(record_id: str) -> Tuple[str, str, str]:
    parts = record_id.upper().split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid record ID: {record_id}")

    prefix, segment, _ = parts
    record_type = _SEGMENT_TO_TYPE.get(segment)
    if not record_type:
        raise ValueError(f"Unsupported record ID segment '{segment}'")

    # Resolve project by prefix from cache (or table scan fallback).
    for project_id, data in _project_cache.items():
        if data.get("prefix") == prefix:
            return project_id, record_type, f"{record_type}#{record_id.upper()}"

    # Slow fallback if prefix cache does not include this project yet.
    ddb = _get_ddb()
    scan = ddb.scan(TableName=PROJECTS_TABLE, ProjectionExpression="project_id, #pfx", ExpressionAttributeNames={"#pfx": "prefix"})
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
        pid = row.get("project_id")
        pfx = str(row.get("prefix") or "").upper()
        if pid and pfx:
            _project_cache[pid] = {"prefix": pfx}
        if pfx == prefix:
            return pid, record_type, f"{record_type}#{record_id.upper()}"

    raise ValueError(f"Unknown project prefix in record ID '{record_id}'")

