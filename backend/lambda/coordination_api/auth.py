"""auth.py — JWT authentication, Cognito token verification, CORS headers.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:
    _JWT_AVAILABLE = False

try:
    import certifi

    _CERT_BUNDLE = certifi.where()
except Exception:
    _CERT_BUNDLE = None

from config import COGNITO_CLIENT_ID, COGNITO_USER_POOL_ID, COORDINATION_INTERNAL_API_KEY
from http_utils import _error

__all__ = [
    "_JWKS_TTL",
    "_authenticate",
    "_extract_token",
    "_get_jwks",
    "_verify_token",
]

# ---------------------------------------------------------------------------
# Auth (same Cognito cookie validation pattern as existing Enceladus Lambdas)
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0


def _extract_token(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    cookie_parts: List[str] = []
    if cookie_header:
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if isinstance(part, str) and part.strip())
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return part[len("enceladus_id_token=") :]
    return None


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
        if not _JWT_AVAILABLE:
            new_cache[kid] = key_data
        else:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))

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


def _authenticate(event: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    # Optional internal auth path for trusted orchestrators / smoke tests.
    if COORDINATION_INTERNAL_API_KEY:
        headers = event.get("headers") or {}
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key == COORDINATION_INTERNAL_API_KEY:
            return {"auth_mode": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in.")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        return None, _error(401, str(exc))


