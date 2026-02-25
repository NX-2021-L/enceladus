"""github_integration/lambda_function.py — GitHub Integration API for Enceladus

Lambda API that proxies GitHub issue operations through a registered GitHub App.
Authenticates to GitHub using RS256 JWT → installation access token flow.

Routes (via API Gateway proxy):
    POST   /api/v1/github/issues        — create a GitHub issue
    OPTIONS /api/v1/github/*             — CORS preflight

Auth:
    Reads `enceladus_id_token` cookie from Cookie header.
    Validates JWT using Cognito JWKS (RS256, cached module-level).
    Optional service-to-service auth via X-Coordination-Internal-Key.

Environment variables:
    COGNITO_USER_POOL_ID        us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID           6q607dk3liirhtecgps7hifmlk
    GITHUB_APP_ID               GitHub App numeric ID
    GITHUB_INSTALLATION_ID      Installation ID for NX-2021-L org
    GITHUB_PRIVATE_KEY_SECRET   Secrets Manager secret name (default: devops/github-app/private-key)
    DYNAMODB_REGION             default: us-west-2
    COORDINATION_INTERNAL_API_KEY  (service auth key)

Part of ENC-FTR-021 Phase 2 (ENC-TSK-575).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

import boto3
from botocore.config import Config

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_INSTALLATION_ID = os.environ.get("GITHUB_INSTALLATION_ID", "")
GITHUB_PRIVATE_KEY_SECRET = os.environ.get(
    "GITHUB_PRIVATE_KEY_SECRET", "devops/github-app/private-key"
)
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
CORS_ORIGIN = "https://jreese.net"
GITHUB_API_BASE = "https://api.github.com"

# Allowed owner/repo pairs for issue creation (safety guardrail)
ALLOWED_REPOS = os.environ.get("ALLOWED_REPOS", "NX-2021-L/enceladus").split(",")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS client singletons
# ---------------------------------------------------------------------------

_secretsmanager = None


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


# ---------------------------------------------------------------------------
# GitHub App private key cache
# ---------------------------------------------------------------------------

_private_key_cache: Optional[str] = None
_private_key_fetched_at: float = 0.0
_PRIVATE_KEY_TTL: float = 3600.0  # re-fetch from Secrets Manager every hour


def _get_github_private_key() -> str:
    """Fetch GitHub App private key from Secrets Manager (cached)."""
    global _private_key_cache, _private_key_fetched_at
    now = time.time()
    if _private_key_cache and (now - _private_key_fetched_at) < _PRIVATE_KEY_TTL:
        return _private_key_cache

    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=GITHUB_PRIVATE_KEY_SECRET)
    _private_key_cache = resp["SecretString"]
    _private_key_fetched_at = now
    return _private_key_cache


# ---------------------------------------------------------------------------
# GitHub App JWT and installation token
# ---------------------------------------------------------------------------


def _generate_app_jwt() -> str:
    """Generate a short-lived RS256 JWT for the GitHub App.

    GitHub requires:
    - iat: issued at (max 60s in the past)
    - exp: expiration (max 10 minutes from iat)
    - iss: GitHub App ID
    """
    if not _JWT_AVAILABLE:
        raise ValueError("PyJWT library not available")
    if not GITHUB_APP_ID:
        raise ValueError("GITHUB_APP_ID environment variable not set")

    now = int(time.time())
    payload = {
        "iat": now - 60,  # allow for clock skew
        "exp": now + (9 * 60),  # 9 minutes (under 10-min max)
        "iss": int(GITHUB_APP_ID),
    }
    private_key = _get_github_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token() -> str:
    """Exchange App JWT for an installation access token.

    POST /app/installations/{installation_id}/access_tokens
    Returns a token valid for 1 hour.
    """
    if not GITHUB_INSTALLATION_ID:
        raise ValueError("GITHUB_INSTALLATION_ID environment variable not set")

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
        logger.error("GitHub installation token exchange failed: %s %s", exc.code, body)
        raise ValueError(f"GitHub token exchange failed ({exc.code}): {body}") from exc


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------


def _github_create_issue(
    owner: str,
    repo: str,
    title: str,
    body: str,
    labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a GitHub issue via REST API using installation token."""
    token = _get_installation_token()
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues"

    payload: Dict[str, Any] = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels

    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        logger.error("GitHub issue creation failed: %s %s", exc.code, body_text)
        raise ValueError(
            f"GitHub issue creation failed ({exc.code}): {body_text}"
        ) from exc


# ---------------------------------------------------------------------------
# Cognito JWT auth (same pattern as tracker_mutation / document_api)
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL: float = 3600.0


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
    pub_key = _get_jwks().get(kid)
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
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    cookie_parts: List[str] = []
    if cookie_header:
        cookie_parts.extend(
            part.strip() for part in cookie_header.split(";") if part.strip()
        )
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(
            part.strip() for part in event_cookies
            if isinstance(part, str) and part.strip()
        )
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())
    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Authenticate request. Returns (claims, None) or (None, error_response)."""
    headers = event.get("headers") or {}
    if COORDINATION_INTERNAL_API_KEY:
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key == COORDINATION_INTERNAL_API_KEY:
            return {"auth_mode": "internal-key", "sub": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in.")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"success": False, "error": message}
    if extra:
        payload.update(extra)
    return _response(status_code, payload)


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


def _parse_body(event: Dict) -> Optional[Dict]:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _path_method(event: Dict) -> Tuple[str, str]:
    rc = event.get("requestContext") or {}
    http = rc.get("http") or {}
    method = (http.get("method") or event.get("httpMethod") or "GET").upper()
    path = http.get("path") or event.get("rawPath") or event.get("path") or "/"
    return method, path


# ---------------------------------------------------------------------------
# POST /api/v1/github/issues — Create Issue
# ---------------------------------------------------------------------------


def _handle_create_issue(event: Dict, claims: Dict) -> Dict:
    """Create a GitHub issue from Enceladus record data."""
    body = _parse_body(event)
    if not body:
        return _error(400, "Invalid JSON body.")

    # Required fields
    owner = str(body.get("owner", "")).strip()
    repo = str(body.get("repo", "")).strip()
    title = str(body.get("title", "")).strip()

    if not owner or not repo:
        return _error(400, "Fields 'owner' and 'repo' are required.")
    if not title:
        return _error(400, "Field 'title' is required.")

    # Safety: only allow configured repos
    full_repo = f"{owner}/{repo}"
    if full_repo not in ALLOWED_REPOS:
        return _error(
            403,
            f"Repository '{full_repo}' is not in the allowed list.",
            allowed_repos=ALLOWED_REPOS,
        )

    # Optional fields
    issue_body = str(body.get("body", "")).strip()
    labels = body.get("labels", [])
    if not isinstance(labels, list):
        return _error(400, "'labels' must be an array of strings.")
    labels = [str(l).strip() for l in labels if str(l).strip()]

    # Enceladus metadata for traceability
    record_id = str(body.get("record_id", "")).strip()
    project_id = str(body.get("project_id", "")).strip()

    # Append Enceladus footer to issue body
    footer_parts = []
    if record_id:
        footer_parts.append(f"**Enceladus Record**: `{record_id}`")
    if project_id:
        footer_parts.append(f"**Project**: `{project_id}`")

    if footer_parts:
        footer = "\n\n---\n_Created from Enceladus_\n" + "\n".join(footer_parts)
        issue_body = (issue_body + footer) if issue_body else footer.lstrip("\n")

    # Create the issue
    try:
        result = _github_create_issue(owner, repo, title, issue_body, labels or None)
    except ValueError as exc:
        return _error(502, f"GitHub API error: {exc}")
    except Exception as exc:
        logger.error("Unexpected error creating GitHub issue: %s", exc)
        return _error(500, "Internal error creating GitHub issue.")

    issue_url = result.get("html_url", "")
    issue_number = result.get("number", 0)

    logger.info(
        "GitHub issue created: %s#%d record_id=%s user=%s",
        full_repo, issue_number, record_id,
        claims.get("email") or claims.get("sub", "unknown"),
    )

    return _response(201, {
        "success": True,
        "issue_url": issue_url,
        "issue_number": issue_number,
        "repo": full_repo,
        "title": result.get("title", title),
        "record_id": record_id,
    })


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict, context: Any) -> Dict:
    method, path = _path_method(event)

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # Authenticate
    claims, auth_err = _authenticate(event)
    if auth_err:
        return auth_err

    # Route
    if method == "POST" and "/github/issues" in path:
        return _handle_create_issue(event, claims)
    else:
        return _error(404, f"Route not found: {method} {path}")
