"""auth_refresh/lambda_function.py

Lambda endpoint for refreshing Cognito tokens and vending GitHub App tokens.

Routes (via API Gateway proxy):
    POST /api/v1/auth/refresh          — Cognito token refresh
    GET  /api/v1/auth/github-token     — GitHub App installation access token
    OPTIONS /api/v1/auth/*             (CORS preflight)

Auth (POST /refresh):
    Reads the `enceladus_refresh_token` cookie from the Cookie header.
    Calls Cognito InitiateAuth with REFRESH_TOKEN_AUTH flow.
    Returns new id_token as an HttpOnly cookie + session timestamp cookie.

Auth (GET /github-token):
    Requires valid Cognito session cookie (enceladus_id_token).
    Returns a short-lived GitHub App installation access token for
    direct api.github.com reads (read:deployments, actions scopes).

Environment variables:
    COGNITO_USER_POOL_ID        us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID           6q607dk3liirhtecgps7hifmlk
    COGNITO_REGION              default: us-east-1
    GITHUB_APP_ID               GitHub App numeric ID
    GITHUB_INSTALLATION_ID      Installation ID for NX-2021-L org
    GITHUB_PRIVATE_KEY_SECRET   Secrets Manager secret name (default: devops/github-app/private-key)

CORS:
    Allows https://jreese.net only. Returns CORS headers on every response.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError

try:
    import jwt
    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COGNITO_REGION = os.environ.get("COGNITO_REGION", "us-east-1")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
CORS_ORIGIN = "https://jreese.net"
ID_TOKEN_MAX_AGE = 3600       # 1 hour
SESSION_COOKIE_MAX_AGE = 3600  # 1 hour
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_INSTALLATION_ID = os.environ.get("GITHUB_INSTALLATION_ID", "")
GITHUB_PRIVATE_KEY_SECRET = os.environ.get("GITHUB_PRIVATE_KEY_SECRET", "devops/github-app/private-key")
GITHUB_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Cognito client (module-level for container reuse)
# ---------------------------------------------------------------------------

_cognito = None
_secretsmanager = None


def _get_cognito():
    global _cognito
    if _cognito is None:
        _cognito = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    return _cognito


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client("secretsmanager", region_name=COGNITO_REGION)
    return _secretsmanager


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
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
# GitHub App token vending
# ---------------------------------------------------------------------------

_private_key_cache: Optional[str] = None
_private_key_fetched_at: float = 0.0
_PRIVATE_KEY_TTL: float = 3600.0


def _get_github_private_key() -> str:
    global _private_key_cache, _private_key_fetched_at
    now = time.time()
    if _private_key_cache and (now - _private_key_fetched_at) < _PRIVATE_KEY_TTL:
        return _private_key_cache
    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=GITHUB_PRIVATE_KEY_SECRET)
    _private_key_cache = resp["SecretString"]
    _private_key_fetched_at = now
    return _private_key_cache


def _generate_app_jwt() -> str:
    if not _JWT_AVAILABLE:
        raise ValueError("PyJWT library not available in Lambda package")
    if not GITHUB_APP_ID:
        raise ValueError("GITHUB_APP_ID not configured")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + (9 * 60), "iss": int(GITHUB_APP_ID)}
    return jwt.encode(payload, _get_github_private_key(), algorithm="RS256")


def _get_installation_token() -> str:
    if not GITHUB_INSTALLATION_ID:
        raise ValueError("GITHUB_INSTALLATION_ID not configured")
    app_jwt = _generate_app_jwt()
    url = f"{GITHUB_API_BASE}/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {app_jwt}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data["token"]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.error("GitHub token exchange failed: %s %s", exc.code, body)
        raise ValueError(f"GitHub token exchange failed ({exc.code})") from exc


def _extract_id_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header or event.cookies."""
    for pair in _iter_cookie_pairs(event):
        if pair.startswith("enceladus_id_token="):
            return pair[len("enceladus_id_token="):]
    return None


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
# GitHub token handler
# ---------------------------------------------------------------------------

def _handle_github_token(event: Dict) -> Dict:
    id_token = _extract_id_token(event)
    if not id_token:
        return _error(401, "Not authenticated. Sign in first.")

    try:
        gh_token = _get_installation_token()
    except ValueError as exc:
        logger.error("github token vend failed: %s", exc)
        return _error(502, "GitHub token unavailable")

    logger.info("github installation token vended")
    return _response(200, {"token": gh_token, "expires_in": 3600})


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

    path = (
        (event.get("requestContext") or {}).get("http", {}).get("path")
        or event.get("path", "")
    )

    if method == "GET" and path.rstrip("/").endswith("/github-token"):
        return _handle_github_token(event)

    if method != "POST":
        return _error(405, "Method not allowed.")

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
