"""coordination_monitor_api/lambda_function.py

Read-only Lambda API for Enceladus Coordination Monitor UI.

Routes (via API Gateway proxy):
    GET     /api/v1/coordination/monitor
    OPTIONS /api/v1/coordination/monitor*

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header.
    Validates the JWT using Cognito JWKS (RS256, cached module-level).

Environment variables:
    COGNITO_USER_POOL_ID      default: ""
    COGNITO_CLIENT_ID         default: ""
    COORDINATION_TABLE        default: coordination-requests
    DYNAMODB_REGION           default: us-west-2
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = "https://jreese.net"

DEFAULT_LIMIT = 50
MAX_LIMIT = 200

REDACTED_FIELDS = {"callback_token"}

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

_ddb = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Auth (same Cognito pattern as feed_query Lambda)
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache

    if not COGNITO_USER_POOL_ID:
        raise ValueError("COGNITO_USER_POOL_ID not set")

    region = COGNITO_USER_POOL_ID.split("_")[0]
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())

    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data["kid"]
        if _JWT_AVAILABLE:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))
        else:
            new_cache[kid] = key_data
    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    if not _JWT_AVAILABLE:
        raise ValueError("JWT library not available in Lambda package")
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise ValueError(f"Invalid token header: {exc}") from exc

    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg != "RS256":
        raise ValueError(f"Unexpected token algorithm: {alg}")

    keys = _get_jwks()
    pub_key = keys.get(kid)
    if pub_key is None:
        raise ValueError("Token key ID not found in JWKS")

    try:
        return jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc


def _extract_token(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("enceladus_id_token="):
            return part[len("enceladus_id_token="):]

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        for part in event_cookies:
            if isinstance(part, str) and part.startswith("enceladus_id_token="):
                return part[len("enceladus_id_token="):]
    return None


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str) -> Dict[str, Any]:
    return _response(status_code, {"success": False, "error": message})


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _ddb_str(item: Dict[str, Any], key: str, default: str = "") -> str:
    val = item.get(key)
    if val is None:
        return default
    return val.get("S", default)


def _ddb_num(item: Dict[str, Any], key: str, default: int = 0) -> int:
    val = item.get(key)
    if val is None:
        return default
    try:
        return int(val.get("N", default))
    except (ValueError, TypeError):
        return default


def _ddb_list(item: Dict[str, Any], key: str) -> List[str]:
    val = item.get(key)
    if val is None:
        return []
    if "L" in val:
        return [e.get("S", "") for e in val["L"] if "S" in e]
    if "SS" in val:
        return list(val["SS"])
    return []


def _ddb_map(item: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
    val = item.get(key)
    if val is None:
        return None
    if "M" in val:
        return _deserialize_map(val["M"])
    return None


def _ddb_list_of_maps(item: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    val = item.get(key)
    if val is None:
        return []
    if "L" in val:
        result = []
        for e in val["L"]:
            if "M" in e:
                result.append(_deserialize_map(e["M"]))
        return result
    return []


def _deserialize_map(m: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in m.items():
        if "S" in v:
            out[k] = v["S"]
        elif "N" in v:
            try:
                out[k] = int(v["N"])
            except ValueError:
                out[k] = float(v["N"])
        elif "BOOL" in v:
            out[k] = v["BOOL"]
        elif "NULL" in v:
            out[k] = None
        elif "L" in v:
            out[k] = [_deserialize_value(e) for e in v["L"]]
        elif "M" in v:
            out[k] = _deserialize_map(v["M"])
        elif "SS" in v:
            out[k] = list(v["SS"])
        else:
            out[k] = str(v)
    return out


def _deserialize_value(v: Dict[str, Any]) -> Any:
    if "S" in v:
        return v["S"]
    if "N" in v:
        try:
            return int(v["N"])
        except ValueError:
            return float(v["N"])
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "L" in v:
        return [_deserialize_value(e) for e in v["L"]]
    if "M" in v:
        return _deserialize_map(v["M"])
    if "SS" in v:
        return list(v["SS"])
    return str(v)


# ---------------------------------------------------------------------------
# Request transformation
# ---------------------------------------------------------------------------


def _transform_request(item: Dict[str, Any]) -> Dict[str, Any]:
    """Transform a raw DynamoDB item into the monitor API response shape."""
    request_id = _ddb_str(item, "request_id")
    state_history = _ddb_list_of_maps(item, "state_history")
    dispatch_plan = _ddb_map(item, "dispatch_plan")

    dispatch_summary = None
    if dispatch_plan:
        dispatches = dispatch_plan.get("dispatches", [])
        dispatch_summary = {
            "plan_id": dispatch_plan.get("plan_id", ""),
            "dispatches_count": len(dispatches) if isinstance(dispatches, list) else 0,
            "strategy": dispatch_plan.get("strategy"),
        }

    result = _ddb_map(item, "result")

    out: Dict[str, Any] = {
        "request_id": request_id,
        "project_id": _ddb_str(item, "project_id"),
        "initiative_title": _ddb_str(item, "initiative_title"),
        "state": _ddb_str(item, "state"),
        "execution_mode": _ddb_str(item, "execution_mode") or None,
        "outcomes": _ddb_list(item, "outcomes"),
        "constraints": _ddb_map(item, "constraints"),
        "requestor_session_id": _ddb_str(item, "requestor_session_id") or None,
        "related_record_ids": _ddb_list(item, "related_record_ids"),
        "created_at": _ddb_str(item, "created_at"),
        "updated_at": _ddb_str(item, "updated_at"),
        "dispatch_plan": dispatch_summary,
        "state_history": state_history,
        "state_history_count": len(state_history),
        "dispatch_attempts": _ddb_num(item, "dispatch_attempts"),
        "provider_preferences": _ddb_map(item, "provider_preferences"),
    }

    if result:
        out["result"] = result

    # Redact sensitive fields
    for field in REDACTED_FIELDS:
        out.pop(field, None)

    return out


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _handle_monitor(event: Dict[str, Any]) -> Dict[str, Any]:
    """GET /api/v1/coordination/monitor — list coordination requests."""
    qs = event.get("queryStringParameters") or {}

    # Parse limit
    try:
        limit = min(int(qs.get("limit", DEFAULT_LIMIT)), MAX_LIMIT)
    except (ValueError, TypeError):
        limit = DEFAULT_LIMIT

    state_filter = qs.get("state", "").strip() or None
    project_filter = qs.get("project_id", "").strip() or None

    ddb = _get_ddb()

    try:
        items: List[Dict[str, Any]] = []
        scan_kwargs: Dict[str, Any] = {"TableName": COORDINATION_TABLE}

        # Build filter expression
        filters = []
        expr_values: Dict[str, Any] = {}

        if state_filter:
            filters.append("#st = :state_val")
            expr_values[":state_val"] = {"S": state_filter}
            scan_kwargs.setdefault("ExpressionAttributeNames", {})["#st"] = "state"

        if project_filter:
            filters.append("project_id = :pid")
            expr_values[":pid"] = {"S": project_filter}

        if filters:
            scan_kwargs["FilterExpression"] = " AND ".join(filters)
            scan_kwargs["ExpressionAttributeValues"] = expr_values

        paginator = ddb.get_paginator("scan")
        for page in paginator.paginate(**scan_kwargs):
            for item in page.get("Items", []):
                items.append(item)

    except (BotoCoreError, ClientError) as exc:
        logger.exception("DynamoDB scan failed")
        return _error(500, f"Failed reading coordination requests: {exc}")

    # Transform and sort by updated_at descending
    requests = [_transform_request(item) for item in items]
    requests.sort(key=lambda r: r.get("updated_at") or "", reverse=True)

    # Apply limit after sort
    requests = requests[:limit]

    return _response(200, {
        "success": True,
        "generated_at": _now_z(),
        "requests": requests,
        "count": len(requests),
    })


def _handle_detail(request_id: str) -> Dict[str, Any]:
    """GET /api/v1/coordination/monitor/{requestId} — single request detail."""
    ddb = _get_ddb()

    try:
        result = ddb.get_item(
            TableName=COORDINATION_TABLE,
            Key={"request_id": {"S": request_id}},
        )
    except (BotoCoreError, ClientError) as exc:
        logger.exception("DynamoDB get_item failed")
        return _error(500, f"Failed reading coordination request: {exc}")

    item = result.get("Item")
    if not item:
        return _error(404, f"Request '{request_id}' not found")

    request = _transform_request(item)

    # Include full dispatch_plan (not summary) for detail view
    full_dispatch_plan = _ddb_map(item, "dispatch_plan")
    if full_dispatch_plan:
        request["dispatch_plan"] = full_dispatch_plan

    # Include mcp diagnostics if present
    mcp_data = _ddb_map(item, "mcp")
    if mcp_data:
        request["mcp"] = mcp_data

    return _response(200, {"success": True, "request": request})


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

import re as _re

def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod")
              or "GET").upper()
    path = (event.get("requestContext", {}).get("http", {}).get("path")
            or event.get("path")
            or "/")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    logger.info("[INFO] route method=%s path=%s", method, path)

    # Auth
    token = _extract_token(event)
    if not token:
        return _error(401, "Authentication required. No session cookie found.")

    try:
        _verify_token(token)
    except ValueError as exc:
        return _error(401, str(exc))

    # Route: GET /api/v1/coordination/monitor
    if method == "GET" and path.rstrip("/") == "/api/v1/coordination/monitor":
        return _handle_monitor(event)

    # Route: GET /api/v1/coordination/monitor/{requestId}
    detail_match = _re.fullmatch(r"/api/v1/coordination/monitor/([A-Za-z0-9\-]+)", path)
    if method == "GET" and detail_match:
        return _handle_detail(detail_match.group(1))

    return _error(404, f"Unsupported route: {method} {path}")
