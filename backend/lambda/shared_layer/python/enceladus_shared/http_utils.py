"""enceladus_shared.http_utils — HTTP response helpers with CORS.

Standard response envelope and error formatting used by all Enceladus
API Lambda functions.

Part of ENC-TSK-525: Extract shared Lambda layer.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

CORS_ORIGIN = "https://jreese.net"
CORS_HEADERS = {
    "Access-Control-Allow-Origin": CORS_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type,Authorization,Cookie",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Credentials": "true",
}


def _response(status_code: int, body: Any) -> Dict[str, Any]:
    """Build a standard API Gateway response with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            **CORS_HEADERS,
        },
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict[str, Any]:
    """Build a standard error response.

    Args:
        status_code: HTTP status code.
        message: Human-readable error message.
        **extra: Additional fields merged into the response payload.
    """
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
    }
    if extra:
        payload.update(extra)
    return _response(status_code, payload)


def _parse_body(event: Dict[str, Any]) -> Any:
    """Parse JSON body from API Gateway event (handles base64)."""
    import base64

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _path_method(event: Dict[str, Any]) -> tuple:
    """Extract HTTP method and path from API Gateway v2 event."""
    rc = event.get("requestContext") or {}
    http = rc.get("http") or {}
    method = (http.get("method") or event.get("httpMethod") or "GET").upper()
    path = http.get("path") or event.get("rawPath") or event.get("path") or "/"
    return method, path
