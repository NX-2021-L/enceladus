"""http_utils.py — HTTP response building, body parsing, path/method extraction.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import logging
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

from config import CORS_ORIGIN

__all__ = [
    "_cors_headers",
    "_error",
    "_json_body",
    "_path_method",
    "_response",
]

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": (
            "Accept, Authorization, Content-Type, Cookie, X-Coordination-Callback-Token, "
            "X-Coordination-Internal-Key"
        ),
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, payload: Any) -> Dict[str, Any]:
    def _json_default(obj: Any) -> Any:
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(payload, default=_json_default),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict[str, Any]:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code == 409:
            code = "CONFLICT"
        elif status_code == 429:
            code = "RATE_LIMITED"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500 or code in {"TIMEOUT", "UPSTREAM_ERROR", "DEBOUNCE_ACTIVE"}))
    details = dict(extra)
    body: Dict[str, Any] = {
        "success": False,
        # legacy field retained for backwards compatibility
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    body.update(details)
    return _response(status_code, body)


def _json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("body")
    if raw in (None, ""):
        return {}

    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode("utf-8")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON body: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("JSON body must be an object")
    return parsed


def _path_method(event: Dict[str, Any]) -> Tuple[str, str]:
    method = (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod") or "").upper()
    path = event.get("rawPath") or event.get("path") or "/"
    return method, path


