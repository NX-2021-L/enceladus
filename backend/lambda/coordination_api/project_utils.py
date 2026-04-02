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


_BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _b36_to_str(v: int) -> str:
    r = []
    for _ in range(3):
        r.append(_BASE36_CHARS[v % 36])
        v //= 36
    return "".join(reversed(r))

def _str_to_b36(s: str) -> int:
    result = 0
    for ch in s:
        idx = _BASE36_CHARS.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid base-36 character {ch!r}")
        result = result * 36 + idx
    return result

def _is_legacy_pattern(s: str) -> bool:
    if s.isdigit():
        return True
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        num = int(s[1:])
        if 1 <= num <= 99:
            return True
    return False

_EXT_B36_TO_COUNTER: dict = {}
_EXT_COUNTER_TO_B36: list = []

def _init_ext_tables():
    idx = 0
    for v in range(46656):
        s = _b36_to_str(v)
        if not _is_legacy_pattern(s):
            _EXT_COUNTER_TO_B36.append(v)
            _EXT_B36_TO_COUNTER[v] = 3574 + idx
            idx += 1

_init_ext_tables()


def _encode_base36(n: int) -> str:
    """Encode a non-negative integer into a 3-char sequence (ENC-FTR-056)."""
    if n < 0:
        raise ValueError(f"Counter must be >= 0, got {n}")
    if n > 46655:
        raise ValueError(f"Base-36 capacity exhausted at counter {n}.")
    if n <= 999:
        return str(n).zfill(3)
    offset = n - 1000
    letter_index = offset // 99
    number = (offset % 99) + 1
    if letter_index <= 25:
        return chr(65 + letter_index) + str(number).zfill(2)
    ext_idx = n - 3574
    return _b36_to_str(_EXT_COUNTER_TO_B36[ext_idx])


def _decode_base36(s: str) -> int:
    """Decode a sequence string back into an integer (ENC-FTR-056)."""
    if not s:
        raise ValueError("Empty sequence")
    s = s.upper()
    if s.isdigit():
        return int(s)
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        letter_index = ord(s[0]) - 65
        number = int(s[1:])
        if 0 <= letter_index <= 25 and 1 <= number <= 99:
            return 1000 + (letter_index * 99) + (number - 1)
    try:
        b36_val = _str_to_b36(s)
    except ValueError:
        raise ValueError(f"Invalid sequence: {s!r}")
    counter = _EXT_B36_TO_COUNTER.get(b36_val)
    if counter is not None:
        return counter
    raise ValueError(f"Invalid sequence: {s!r}")


def _format_sequence(counter: int) -> str:
    """Encode an integer counter into a 3-char record ID sequence (ENC-FTR-056).

    Now uses base-36 encoding. Counter starts at 1.
    """
    if counter < 1:
        raise ValueError(f"Counter must be >= 1, got {counter}")
    return _encode_base36(counter)


def _parse_sequence(seq: str) -> int:
    """Decode a record ID sequence back into an integer counter (ENC-FTR-056).

    Delegates to _decode_base36 which handles all legacy formats.
    """
    return _decode_base36(seq)


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
                    n = _parse_sequence(parts[-1])
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
    return f"{prefix}-{_TYPE_TO_SEGMENT[record_type]}-{_format_sequence(seq)}"


def _key_for_record_id(record_id: str) -> Tuple[str, str, str]:
    parts = record_id.upper().split("-")
    if len(parts) < 3 or len(parts) > 4:
        raise ValueError(f"Invalid record ID: {record_id}")

    prefix, segment = parts[0], parts[1]
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

