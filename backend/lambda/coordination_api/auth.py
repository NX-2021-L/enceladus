"""auth.py — JWT authentication, Cognito token verification, CORS headers.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import hmac
import logging
import os
import pathlib
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001 — also catches RuntimeError/OSError from cffi backend ABI mismatch
    # ENC-ISS-198 / ENC-TSK-D22: log the import failure so operators can
    # diagnose PyJWT/cryptography ABI mismatches in CloudWatch instead of
    # chasing the downstream HTTP 401 "JWT library not available in Lambda
    # package" message. Historical incidents in this failure class:
    # ENC-ISS-041, ENC-ISS-044, ENC-ISS-198. logger is not yet defined at
    # module-load time, so use logging.getLogger(__name__) directly.
    import logging as _enc_iss_198_logging
    _enc_iss_198_logging.getLogger(__name__).exception(
        "PyJWT import failed at module load — Cognito auth will be disabled "
        "(ENC-ISS-198: usually a shared-layer .so ABI mismatch with the function runtime)"
    )
    _JWT_AVAILABLE = False

try:
    import certifi

    _CERT_BUNDLE = certifi.where()
except Exception:
    _CERT_BUNDLE = None

from config import COGNITO_CLIENT_ID, COGNITO_USER_POOL_ID, COORDINATION_INTERNAL_API_KEYS
from http_utils import _error

__all__ = [
    "_CERT_BUNDLE",
    "_JWT_AVAILABLE",
    "_JWKS_TTL",
    "_authenticate",
    "_extract_token",
    "_get_jwks",
    "_jwks_cache",
    "_jwks_fetched_at",
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
    auth_header = (
        headers.get("authorization")
        or headers.get("Authorization")
        or ""
    )
    if isinstance(auth_header, str):
        parts = auth_header.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()

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
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc

    expected_issuer = ""
    if COGNITO_USER_POOL_ID:
        region = COGNITO_USER_POOL_ID.split("_", 1)[0]
        expected_issuer = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}"
    token_issuer = str(claims.get("iss") or "").strip()
    if expected_issuer and token_issuer and not hmac.compare_digest(token_issuer, expected_issuer):
        raise ValueError("Token issuer mismatch.")

    expected_client_id = str(COGNITO_CLIENT_ID or "").strip()
    if expected_client_id:
        token_use = str(claims.get("token_use") or "").strip().lower()
        aud = str(claims.get("aud") or "").strip()
        client_id = str(claims.get("client_id") or "").strip()
        if token_use == "id":
            if not hmac.compare_digest(aud, expected_client_id):
                raise ValueError("Token audience mismatch.")
        elif token_use == "access":
            if not hmac.compare_digest(client_id, expected_client_id):
                raise ValueError("Token client_id mismatch.")
        elif not (
            (aud and hmac.compare_digest(aud, expected_client_id))
            or (client_id and hmac.compare_digest(client_id, expected_client_id))
        ):
            raise ValueError("Token client mismatch.")

    return claims


def _authenticate(event: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    # Optional internal auth path for trusted orchestrators / smoke tests.
    if COORDINATION_INTERNAL_API_KEYS:
        headers = event.get("headers") or {}
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key in COORDINATION_INTERNAL_API_KEYS:
            return {"auth_mode": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in.")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        return None, _error(401, str(exc))
