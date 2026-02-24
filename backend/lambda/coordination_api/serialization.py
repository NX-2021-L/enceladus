"""serialization.py — DynamoDB serialization/deserialization, timestamps, CloudWatch observability.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from config import logger
from aws_clients import _get_logs

__all__ = [
    "_classify_mcp_error",
    "_deserialize",
    "_deserializer",
    "_emit_cloudwatch_json",
    "_emit_structured_observability",
    "_fetch_log_stream_token",
    "_now_z",
    "_serialize",
    "_serializer",
    "_unix_now",
]

# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

_deserializer = TypeDeserializer()
_serializer = TypeSerializer()


def _serialize(value: Any) -> Dict[str, Any]:
    return _serializer.serialize(value)


def _deserialize(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _deserializer.deserialize(v) for k, v in raw.items()}


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_now() -> int:
    return int(time.time())


def _fetch_log_stream_token(log_group: str, stream_name: str) -> Optional[str]:
    try:
        resp = _get_logs().describe_log_streams(
            logGroupName=log_group,
            logStreamNamePrefix=stream_name,
            limit=1,
        )
    except Exception:
        return None
    streams = resp.get("logStreams") or []
    if not streams:
        return None
    return streams[0].get("uploadSequenceToken")


def _emit_cloudwatch_json(log_group: str, payload: Dict[str, Any], stream_name: str = "coordination-audit") -> None:
    if not log_group:
        return
    logs = _get_logs()
    key = (log_group, stream_name)

    try:
        logs.create_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            return
    except Exception:
        return

    try:
        logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            return
    except Exception:
        return

    event = {
        "timestamp": int(time.time() * 1000),
        "message": json.dumps(payload, sort_keys=True, default=str),
    }
    kwargs: Dict[str, Any] = {
        "logGroupName": log_group,
        "logStreamName": stream_name,
        "logEvents": [event],
    }
    token = _cloudwatch_sequence_tokens.get(key)
    if token:
        kwargs["sequenceToken"] = token

    try:
        resp = logs.put_log_events(**kwargs)
        _cloudwatch_sequence_tokens[key] = resp.get("nextSequenceToken", "")
        return
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"InvalidSequenceTokenException", "DataAlreadyAcceptedException"}:
            return
    except Exception:
        return

    retry_token = _fetch_log_stream_token(log_group, stream_name)
    retry_kwargs: Dict[str, Any] = {
        "logGroupName": log_group,
        "logStreamName": stream_name,
        "logEvents": [event],
    }
    if retry_token:
        retry_kwargs["sequenceToken"] = retry_token
    try:
        resp = logs.put_log_events(**retry_kwargs)
        _cloudwatch_sequence_tokens[key] = resp.get("nextSequenceToken", "")
    except Exception:
        return


def _emit_structured_observability(
    *,
    component: str,
    event: str,
    request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    latency_ms: Optional[int] = None,
    error_code: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    mirror_log_group: Optional[str] = None,
) -> None:
    payload: Dict[str, Any] = {
        "timestamp": _now_z(),
        "component": component,
        "event": event,
        "request_id": str(request_id or ""),
        "dispatch_id": str(dispatch_id or ""),
        "tool_name": str(tool_name or ""),
        "latency_ms": int(max(0, latency_ms or 0)),
        "error_code": str(error_code or ""),
    }
    if extra:
        payload.update(extra)
    logger.info("[OBSERVABILITY] %s", json.dumps(payload, sort_keys=True, default=str))
    if mirror_log_group:
        _emit_cloudwatch_json(mirror_log_group, payload, stream_name="structured-observability")


def _classify_mcp_error(exc: Exception) -> str:
    msg = str(exc).lower()
    if "governance_stale" in msg or "stale" in msg:
        return "governance_stale"
    if "missing governance_hash" in msg:
        return "governance_hash_missing"
    if "not found" in msg:
        return "record_not_found"
    if "timeout" in msg:
        return "mcp_timeout"
    return "mcp_tool_error"


