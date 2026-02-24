"""persistence.py — Coordination request DynamoDB persistence helpers.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError

from config import COORDINATION_TABLE, _TRANSITIONS
from serialization import _deserialize, _emit_structured_observability, _now_z, _serialize, _unix_now
from aws_clients import _get_ddb

__all__ = [
    "_append_state_transition",
    "_get_request",
    "_put_request",
    "_redact_request",
    "_request_key",
    "_update_request",
]

# ---------------------------------------------------------------------------
# Coordination request persistence helpers
# ---------------------------------------------------------------------------


def _request_key(request_id: str) -> Dict[str, Any]:
    return {"request_id": _serialize(request_id)}


def _append_state_transition(
    request: Dict[str, Any],
    next_state: str,
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    prev = request.get("state")
    if prev not in _TRANSITIONS:
        raise ValueError(f"Unknown current state '{prev}'")
    if next_state not in _TRANSITIONS[prev]:
        raise ValueError(f"Invalid state transition {prev} -> {next_state}")

    now = _now_z()
    transition = {
        "timestamp": now,
        "from": prev,
        "to": next_state,
        "reason": reason,
    }
    if extra:
        transition["meta"] = extra

    history = list(request.get("state_history") or [])
    history.append(transition)

    request["state"] = next_state
    request["state_history"] = history
    request["updated_at"] = now
    request["updated_epoch"] = _unix_now()
    request["sync_version"] = int(request.get("sync_version", 0)) + 1
    transition_meta = extra or {}
    _emit_structured_observability(
        component="coordination_api",
        event="state_transition",
        request_id=str(request.get("request_id") or ""),
        dispatch_id=str(transition_meta.get("dispatch_id") or ""),
        tool_name="state.transition",
        latency_ms=0,
        error_code=str(transition_meta.get("error_code") or transition_meta.get("failure_class") or ""),
        extra={
            "from_state": prev,
            "to_state": next_state,
            "reason": reason,
        },
    )
    return request


def _get_request(request_id: str) -> Optional[Dict[str, Any]]:
    ddb = _get_ddb()
    resp = ddb.get_item(TableName=COORDINATION_TABLE, Key=_request_key(request_id), ConsistentRead=True)
    raw = resp.get("Item")
    if not raw:
        return None
    return _deserialize(raw)


def _put_request(item: Dict[str, Any]) -> None:
    ddb = _get_ddb()
    ddb.put_item(
        TableName=COORDINATION_TABLE,
        Item={k: _serialize(v) for k, v in item.items()},
        ConditionExpression="attribute_not_exists(request_id)",
    )


def _update_request(item: Dict[str, Any]) -> None:
    ddb = _get_ddb()
    ddb.put_item(TableName=COORDINATION_TABLE, Item={k: _serialize(v) for k, v in item.items()})


def _redact_request(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    out.pop("callback_token", None)
    return out


