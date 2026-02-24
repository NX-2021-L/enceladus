"""auth_refresh/lambda_function.py

Lambda endpoint for refreshing Cognito tokens using a refresh_token cookie.

Route (via API Gateway proxy):
    POST /api/v1/auth/refresh
    OPTIONS /api/v1/auth/refresh  (CORS preflight)

Auth:
    Reads the `enceladus_refresh_token` cookie from the Cookie header.
    Calls Cognito InitiateAuth with REFRESH_TOKEN_AUTH flow.
    Returns new id_token as an HttpOnly cookie + session timestamp cookie.

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    COGNITO_REGION         default: us-east-1

CORS:
    Allows https://jreese.net only. Returns CORS headers on every response.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COGNITO_REGION = os.environ.get("COGNITO_REGION", "us-east-1")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
CORS_ORIGIN = "https://jreese.net"
ID_TOKEN_MAX_AGE = 3600       # 1 hour
SESSION_COOKIE_MAX_AGE = 3600  # 1 hour

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Cognito client (module-level for container reuse)
# ---------------------------------------------------------------------------

_cognito = None


def _get_cognito():
    global _cognito
    if _cognito is None:
        _cognito = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    return _cognito


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------

def _iter_cookie_pairs(event: Dict) -> list[str]:
    """Return normalized cookie key=value entries from headers and API Gateway v2 cookies."""
    pairs: list[str] = []

    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part and "=" in part:
                pairs.append(part)

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        for item in event_cookies:
            if isinstance(item, str) and "=" in item:
                pairs.append(item.strip())
    elif isinstance(event_cookies, str) and "=" in event_cookies:
        pairs.append(event_cookies.strip())

    return pairs


def _extract_refresh_token(event: Dict) -> Optional[str]:
    """Extract enceladus_refresh_token from either Cookie header or event.cookies."""
    for pair in _iter_cookie_pairs(event):
        if not pair.startswith("enceladus_refresh_token="):
            continue
        raw = pair[len("enceladus_refresh_token="):]
        return unquote(raw)
    return None


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any, extra_headers: Optional[Dict] = None) -> Dict:
    headers = {**_cors_headers(), "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str) -> Dict:
    return _response(status_code, {"success": False, "error": message})


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

def _refresh_tokens(refresh_token: str) -> Dict[str, str]:
    """Call Cognito InitiateAuth with REFRESH_TOKEN_AUTH.

    Returns dict with 'id_token' and 'access_token' on success.
    Raises ValueError on failure.
    """
    cognito = _get_cognito()
    try:
        resp = cognito.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
            },
            ClientId=COGNITO_CLIENT_ID,
        )
    except cognito.exceptions.NotAuthorizedException as exc:
        raise ValueError(f"Refresh token rejected: {exc}") from exc
    except (BotoCoreError, ClientError) as exc:
        raise ValueError(f"Cognito API error: {exc}") from exc

    result = resp.get("AuthenticationResult") or {}
    id_token = result.get("IdToken")
    if not id_token:
        raise ValueError("No id_token in Cognito response")

    return {
        "id_token": id_token,
        "access_token": result.get("AccessToken", ""),
    }


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )

    # CORS preflight
    if method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": _cors_headers(),
            "body": "",
        }

    if method != "POST":
        return _error(405, "Method not allowed. Use POST.")

    logger.info("auth refresh request")

    # --- Extract refresh token cookie ---
    refresh_token = _extract_refresh_token(event)
    if not refresh_token:
        logger.info("no refresh token cookie found")
        return _error(401, "No refresh token. Please sign in again.")

    # --- Exchange refresh token for new id_token ---
    try:
        tokens = _refresh_tokens(refresh_token)
    except ValueError as exc:
        logger.warning("refresh failed: %s", exc)
        return _error(401, "refresh_failed")

    # --- Build response with new cookies ---
    id_token = tokens["id_token"]
    now_ms = str(int(time.time() * 1000))

    # Set two cookies: new id_token (HttpOnly) and session timestamp (JS-readable)
    set_cookie_id = (
        f"enceladus_id_token={id_token}; "
        f"Path=/; Secure; HttpOnly; SameSite=None; Max-Age={ID_TOKEN_MAX_AGE}"
    )
    set_cookie_session = (
        f"enceladus_session_at={now_ms}; "
        f"Path=/enceladus; Secure; SameSite=None; Max-Age={SESSION_COOKIE_MAX_AGE}"
    )

    logger.info("refresh succeeded, new id_token issued")

    # API Gateway HTTP API v2 (payload format 2.0) uses the `cookies` field
    # to return multiple Set-Cookie headers in a single response.
    return {
        "statusCode": 200,
        "headers": {
            **_cors_headers(),
            "Content-Type": "application/json",
        },
        "cookies": [set_cookie_id, set_cookie_session],
        "body": json.dumps({
            "success": True,
            "expires_in": ID_TOKEN_MAX_AGE,
        }),
    }
