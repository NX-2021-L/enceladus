"""coordination_api/lambda_function.py — Entry point.

Thin entry point that imports all domain modules and exposes lambda_handler.
This file maintains backward compatibility with tests that import
functions via `lambda_function.<name>`.

Part of coordination_api modularization (ENC-TSK-527).

Routes (API Gateway HTTP API):
    POST    /api/v1/coordination/requests
    GET     /api/v1/coordination/requests/{requestId}
    POST    /api/v1/coordination/requests/{requestId}/dispatch
    POST    /api/v1/coordination/requests/{requestId}/callback
    GET     /api/v1/coordination/capabilities
    OPTIONS /api/v1/coordination/*
"""

from __future__ import annotations

import logging
import re  # noqa: F811 — used by lambda_handler
import urllib.error  # noqa: F401 — test compatibility (patch.object targets)
import urllib.request  # noqa: F401 — test compatibility (patch.object targets)
from typing import Any, Dict  # noqa: F401

# Re-export all names from domain modules for backward compatibility.
# Tests rely on `lambda_function.<name>` being accessible.
from config import *  # noqa: F401,F403
from serialization import *  # noqa: F401,F403
from aws_clients import *  # noqa: F401,F403
from auth import *  # noqa: F401,F403
from http_utils import *  # noqa: F401,F403
from project_utils import *  # noqa: F401,F403
from mcp_integration import *  # noqa: F401,F403
from tracker_ops import *  # noqa: F401,F403
from decomposition import *  # noqa: F401,F403
from intake_dedup import *  # noqa: F401,F403
from persistence import *  # noqa: F401,F403
from dispatch_ssm import *  # noqa: F401,F403
from lifecycle import *  # noqa: F401,F403
from handlers import *  # noqa: F401,F403

logger = logging.getLogger("coordination_api")

# ---------------------------------------------------------------------------
# Main Lambda handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    # --- v0.3: EventBridge callback ingestion ---
    # EventBridge events have 'source' and 'detail-type' at top level.
    event_source = event.get("source") or ""
    detail_type = event.get("detail-type") or ""
    if (
        event_source == CALLBACK_EVENT_SOURCE
        and detail_type == CALLBACK_EVENT_DETAIL_TYPE
    ):
        logger.info("[INFO] EventBridge callback event received")
        return _handle_eventbridge_callback(event)

    # --- v0.3: SQS callback ingestion ---
    # SQS events have 'Records' with 'eventSource' = 'aws:sqs'.
    records = event.get("Records")
    if isinstance(records, list) and records:
        first_source = (records[0].get("eventSource") or "")
        if first_source == "aws:sqs":
            logger.info("[INFO] SQS callback batch received (%d records)", len(records))
            return _handle_sqs_callback(event)

    # --- Standard API Gateway HTTP routing ---
    method, path = _path_method(event)

    if method == "OPTIONS":
        return _response(200, {"success": True})

    logger.info("[INFO] route method=%s path=%s", method, path)

    # GET /api/v1/coordination/capabilities is intentionally public.
    if method == "GET" and path == "/api/v1/coordination/capabilities":
        return _handle_capabilities()

    # POST /api/v1/coordination/requests/{requestId}/callback
    # Callback auth is enforced via per-request callback token.
    match_callback = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)/callback", path)
    if method == "POST" and match_callback:
        request_id = match_callback.group(1)
        return _handle_callback(event, request_id)

    # Auth all other routes.
    claims, auth_err = _authenticate(event)
    if auth_err:
        return auth_err

    # GET/POST /api/v1/coordination/mcp
    # Auth required (Cognito cookie or X-Coordination-Internal-Key).
    if method in {"GET", "POST"} and path == COORDINATION_MCP_HTTP_PATH:
        return _handle_mcp_http(event, claims or {})

    # POST /api/v1/coordination/requests
    if method == "POST" and path == "/api/v1/coordination/requests":
        return _handle_create_request(event, claims or {})

    # GET /api/v1/coordination/requests/{requestId}
    match_get = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)", path)
    if method == "GET" and match_get:
        request_id = match_get.group(1)
        return _handle_get_request(request_id)

    # POST /api/v1/coordination/requests/{requestId}/dispatch
    match_dispatch = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)/dispatch", path)
    if method == "POST" and match_dispatch:
        request_id = match_dispatch.group(1)
        return _handle_dispatch_request(event, request_id)

    return _error(404, f"Unsupported route: {method} {path}")
