"""enceladus_shared.auth — Cognito JWT authentication for Enceladus Lambdas.

Reads `enceladus_id_token` from Cookie header / API Gateway cookies array,
validates RS256 JWT using the Cognito User Pool JWKS endpoint, and optionally
supports service-to-service auth via an internal API key header.

Requires environment variables:
    COGNITO_USER_POOL_ID   — e.g. us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      — e.g. 6q607dk3liirhtecgps7hifmlk

Optional:
    COORDINATION_INTERNAL_API_KEY — enables X-Coordination-Internal-Key header auth
    COORDINATION_INTERNAL_API_KEY_PREVIOUS — optional rollover key accepted during rotation
    COORDINATION_INTERNAL_API_KEYS — optional comma-separated allowlist (active + rollover)

Part of ENC-TSK-525: Extract shared Lambda layer.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:
    _JWT_AVAILABLE = False

logger = logging.getLogger(__name__)


def _normalize_api_keys(*raw_values: str) -> tuple[str, ...]:
    """Return deduplicated, non-empty key values from scalar/csv env sources."""
    keys: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not raw:
            continue
        for part in str(raw).split(","):
            key = part.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return tuple(keys)

# ---------------------------------------------------------------------------
# Configuration (read from env; callers may override at import time)
# ---------------------------------------------------------------------------

COGNITO_USER_POOL_ID: str = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID: str = os.environ.get("COGNITO_CLIENT_ID", "")
INTERNAL_API_KEY: str = os.environ.get(
    "COORDINATION_INTERNAL_API_KEY",
    os.environ.get("DOCUMENT_API_INTERNAL_API_KEY", ""),
)
INTERNAL_API_KEY_PREVIOUS: str = os.environ.get(
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    os.environ.get("DOCUMENT_API_INTERNAL_API_KEY_PREVIOUS", ""),
)
INTERNAL_API_KEYS: tuple[str, ...] = _normalize_api_keys(
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("DOCUMENT_API_INTERNAL_API_KEYS", ""),
    INTERNAL_API_KEY,
    INTERNAL_API_KEY_PREVIOUS,
)

# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL: float = 3600.0


def _extract_token(event: Dict[str, Any]) -> Optional[str]:
    """Extract enceladus_id_token from cookies (headers or API GW v2 array)."""
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
            part.strip()
            for part in event_cookies
            if isinstance(part, str) and part.strip()
        )
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return part[len("enceladus_id_token=") :]
    return None


def _get_jwks() -> Dict[str, Any]:
    """Fetch (and cache) Cognito User Pool JWKS."""
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
        if not _JWT_AVAILABLE:
            new_cache[kid] = key_data
        else:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))

    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    """Verify a Cognito JWT (RS256). Returns decoded claims dict."""
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

    key = _get_jwks().get(kid)
    if key is None:
        raise ValueError("Token key ID not found in JWKS")

    try:
        return jwt.decode(
            token,
            key,
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


def _authenticate(
    event: Dict[str, Any],
    *,
    error_fn=None,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Authenticate request via cookie JWT or internal API key.

    Returns (claims, None) on success or (None, error_response) on failure.

    Args:
        event: API Gateway event dict.
        error_fn: Optional callable(status_code, message) -> response dict.
                  If not provided, returns a plain dict with statusCode/body.
    """
    if error_fn is None:
        error_fn = _default_error

    # Internal key auth path for trusted orchestrators / smoke tests.
    if INTERNAL_API_KEYS:
        headers = event.get("headers") or {}
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key in INTERNAL_API_KEYS:
            return {"auth_mode": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        return None, error_fn(401, "Authentication required. Please sign in.")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        return None, error_fn(401, str(exc))


def _default_error(status_code: int, message: str) -> Dict[str, Any]:
    """Fallback error response builder."""
    import json as _json

    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": _json.dumps({"success": False, "error": message}),
    }
