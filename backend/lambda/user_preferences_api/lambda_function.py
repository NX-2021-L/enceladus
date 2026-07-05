"""user_preferences_api/lambda_function.py

Lambda API handler for per-user preferences (ENC-TSK-L25 / ENC-FTR-127 AC-10/16/17).
Serves saved searches, recently-viewed history, and free-form prefs, keyed on the
caller's Cognito sub, so ui-v2 can persist them cross-session and cross-device.

Routes (via API Gateway proxy):
    GET /api/v1/user/preferences  — Return the caller's preferences record
    PUT /api/v1/user/preferences  — Replace the caller's preferences record
    OPTIONS /api/v1/user/preferences — CORS preflight

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header (Cognito JWT).
    No internal-key path — this is a purely per-user, human-session surface.

Payload schema (locked, DOC-77D6C714867E §15h):
    {
      "saved_searches": [{"name": str, "query": str, "filters": {...}, "sort": str}],
      "recently_viewed": {"<feed_type>": [{"record_id": str, "project_id": str, "viewed_at": str}]},
      "prefs": {...}
    }

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    USER_PREFERENCES_TABLE default: user-preferences
    DYNAMODB_REGION        default: us-west-2
    CORS_ORIGIN            default: https://jreese.net

Related: ENC-FTR-127, ENC-TSK-L25
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001 — ENC-ISS-198 class: shared-layer ABI mismatch
    import logging as _l07_logging
    _l07_logging.getLogger(__name__).exception(
        "PyJWT import failed at module load — Cognito auth will be disabled "
        "(ENC-ISS-198: usually a shared-layer .so ABI mismatch with the function runtime)"
    )
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USER_PREFERENCES_TABLE = os.environ.get("USER_PREFERENCES_TABLE", "user-preferences")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")

MAX_SAVED_SEARCHES = 50
MAX_RECENTLY_VIEWED_PER_TYPE = 50
MAX_PAYLOAD_BYTES = 200_000  # generous cap; a single DDB item tops out at 400KB

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_ddb = None
_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


# ---------------------------------------------------------------------------
# CORS + response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _ok(body: Any) -> Dict:
    if isinstance(body, dict) and "success" not in body:
        body["success"] = True
    return _response(200, body)


def _error(status_code: int, message: str, **extra: Any) -> Dict:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        code = {400: "INVALID_INPUT", 401: "PERMISSION_DENIED", 404: "NOT_FOUND"}.get(
            status_code, "INTERNAL_ERROR" if status_code >= 500 else "INTERNAL_ERROR"
        )
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code, "message": message,
            "retryable": status_code >= 500,
            "details": dict(extra),
        },
    }
    return _response(status_code, payload)


# ---------------------------------------------------------------------------
# Auth (Cognito JWT cookie only — no internal-key path, same JWKS pattern as
# changelog_api / deploy_intake)
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache

    region = COGNITO_USER_POOL_ID.split("_")[0]
    url = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())

    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data["kid"]
        new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data)) if _JWT_AVAILABLE else key_data
    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    if not _JWT_AVAILABLE:
        raise ValueError("JWT library not available in Lambda package")
    header = jwt.get_unverified_header(token)
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
            token, pub_key, algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID, options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc


def _extract_token(event: Dict) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_parts: List[str] = []
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(p.strip() for p in cookie_header.split(";") if p.strip())
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(p.strip() for p in event_cookies if isinstance(p, str) and p.strip())
    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict) -> Tuple[Optional[Dict[str, Any]], Optional[Dict]]:
    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("Auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Payload validation (locked schema, DOC-77D6C714867E §15h)
# ---------------------------------------------------------------------------


def _validate_preferences_payload(body: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(body, dict):
        return None, "Request body must be a JSON object."

    saved_searches = body.get("saved_searches", [])
    if not isinstance(saved_searches, list):
        return None, "saved_searches must be an array."
    if len(saved_searches) > MAX_SAVED_SEARCHES:
        return None, f"saved_searches exceeds the maximum of {MAX_SAVED_SEARCHES} entries."
    for i, entry in enumerate(saved_searches):
        if not isinstance(entry, dict) or not str(entry.get("name", "")).strip():
            return None, f"saved_searches[{i}] must be an object with a non-empty 'name'."

    recently_viewed = body.get("recently_viewed", {})
    if not isinstance(recently_viewed, dict):
        return None, "recently_viewed must be an object keyed by feed_type."
    for feed_type, entries in recently_viewed.items():
        if not isinstance(entries, list):
            return None, f"recently_viewed[{feed_type!r}] must be an array."
        if len(entries) > MAX_RECENTLY_VIEWED_PER_TYPE:
            return None, (
                f"recently_viewed[{feed_type!r}] exceeds the maximum of "
                f"{MAX_RECENTLY_VIEWED_PER_TYPE} entries."
            )
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict) or not str(entry.get("record_id", "")).strip():
                return None, f"recently_viewed[{feed_type!r}][{i}] must have a non-empty record_id."

    prefs = body.get("prefs", {})
    if not isinstance(prefs, dict):
        return None, "prefs must be an object."

    return {
        "saved_searches": saved_searches,
        "recently_viewed": recently_viewed,
        "prefs": prefs,
    }, None


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

_DEFAULT_PREFERENCES = {"saved_searches": [], "recently_viewed": {}, "prefs": {}}


def _handle_get(sub: str) -> Dict:
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=USER_PREFERENCES_TABLE,
            Key={"sub": {"S": sub}},
            ConsistentRead=True,
        )
    except (ClientError, BotoCoreError) as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    item = resp.get("Item")
    if item is None:
        return _ok(dict(_DEFAULT_PREFERENCES))

    return _ok({
        "saved_searches": json.loads(item.get("saved_searches", {}).get("S", "[]")),
        "recently_viewed": json.loads(item.get("recently_viewed", {}).get("S", "{}")),
        "prefs": json.loads(item.get("prefs", {}).get("S", "{}")),
        "updated_at": item.get("updated_at", {}).get("S", ""),
    })


def _handle_put(sub: str, raw_body: str) -> Dict:
    if raw_body and len(raw_body.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        return _error(400, f"Payload exceeds the maximum of {MAX_PAYLOAD_BYTES} bytes.")

    try:
        parsed = json.loads(raw_body or "{}")
    except (ValueError, TypeError):
        return _error(400, "Invalid JSON body.")

    validated, err = _validate_preferences_payload(parsed)
    if err:
        return _error(400, err)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ddb = _get_ddb()
    try:
        ddb.put_item(
            TableName=USER_PREFERENCES_TABLE,
            Item={
                "sub": {"S": sub},
                "saved_searches": {"S": json.dumps(validated["saved_searches"])},
                "recently_viewed": {"S": json.dumps(validated["recently_viewed"])},
                "prefs": {"S": json.dumps(validated["prefs"])},
                "updated_at": {"S": now},
            },
        )
    except (ClientError, BotoCoreError) as exc:
        logger.error("put_item failed: %s", exc)
        return _error(500, "Database write failed.")

    return _ok({**validated, "updated_at": now})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    ).upper()
    path = event.get("rawPath") or event.get("path") or ""

    logger.info("user_preferences_api: %s %s", method, path)

    if method == "OPTIONS":
        return _response(204, "")

    if method not in ("GET", "PUT"):
        return _error(405, f"Method {method} not allowed.")

    claims, auth_error = _authenticate(event)
    if auth_error:
        return auth_error

    sub = str(claims.get("sub", "")).strip()
    if not sub:
        return _error(401, "Token missing 'sub' claim.")

    try:
        if method == "GET":
            return _handle_get(sub)
        return _handle_put(sub, event.get("body") or "{}")
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error: %s", exc, exc_info=True)
        return _error(500, "Internal service error")
