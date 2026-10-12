"""enceladus_shared/hub_exchange.py

DVP-TSK-A17 (DVP-PLN-013 E4-W2.8, ruling E4-R14): hub token exchange.

The shells that embed the escalation inbox authenticate against different
identity providers (vagamod: Keycloak; coach: the auth.thepup.io Cognito pool;
think: the io-graph Cognito pool). The hub's decide only understands the
enceladus Cognito human session. This module generalizes io's D-F05 ruling:
an ID token from an ALLOW-LISTED issuer is exchanged for a short-lived (<= 15
min) hub principal bound to io's allow-listed identity, carrying the source
issuer, auth_time and acr. coordination_api (exchange, list, decide) and the
escalation-decision authorizer accept that principal through
``Authorization: HubExchange <token>`` and re-verify it on every request.

FTR-121 invariants are kept by construction:
  * human only      - only ID tokens (never access / client-credentials /
                      service-account tokens) are exchangeable, and a machine
                      email domain is refused;
  * allow-list      - the email must be on the SAME approver allow-list the
                      Cognito path uses (the caller passes its loader);
  * no MCP path     - the hub principal is accepted only on the human hub
                      routes; coordination_api never honours it elsewhere.

Everything fails CLOSED: an empty / unparsable issuer config, a missing secret
or a missing JWT library means nothing can be exchanged or accepted.

Environment (never hand-created; declared in 02-compute.yaml):
    HUB_EXCHANGE_ISSUERS     JSON [{"name","iss","jwks_uri","audiences":[...]}]
    COORDINATION_INTERNAL_API_KEY           HMAC key source (derived: HMAC-SHA256(key, b"enceladus-hub-exchange-v1"))
    COORDINATION_INTERNAL_API_KEY_PREVIOUS  optional rotation-window key (verify only)
    HUB_EXCHANGE_SECRET_ARN  OPTIONAL override: Secrets Manager ARN of an explicit HMAC key
    HUB_SHELL_ORIGINS        comma list of allowed shell origins (CORS)
    HUB_EXCHANGE_TTL_SECONDS optional, clamped to [60, 900]
    ESCALATION_MACHINE_EMAIL_DOMAINS  shared with the Cognito human gate
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Set

try:  # PyJWT is in the shared layer; absence disables the feature (fail closed).
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001
    jwt = None  # type: ignore[assignment]
    RSAAlgorithm = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False

logger = logging.getLogger(__name__)

HUB_SCHEME = "HubExchange"
HUB_KIND = "hub_exchange"
HUB_AUTH_MODE = "hub_exchange"
MAX_TTL_SECONDS = 900
_MIN_TTL_SECONDS = 60
_JWKS_TTL_SECONDS = 600
_SECRET_TTL_SECONDS = 300
_CLOCK_LEEWAY_SECONDS = 30
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}$")


class HubExchangeError(Exception):
    """Refusal with a deliberately generic public message (no detail leak).

    ``reason`` is for logs only and is never returned to a caller.
    """

    def __init__(self, status: int, public_message: str, reason: str = "") -> None:
        super().__init__(reason or public_message)
        self.status = status
        self.public_message = public_message
        self.reason = reason


def _deny_auth(reason: str) -> HubExchangeError:
    return HubExchangeError(401, "Authentication failed.", reason)


def _deny_identity(reason: str) -> HubExchangeError:
    return HubExchangeError(403, "Identity is not permitted.", reason)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_issuers() -> List[Dict[str, Any]]:
    """Parse HUB_EXCHANGE_ISSUERS. Invalid entries are dropped; errors -> []."""
    raw = os.environ.get("HUB_EXCHANGE_ISSUERS", "") or ""
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except ValueError:
        logger.error("HUB_EXCHANGE_ISSUERS is not valid JSON (fail-closed, no issuers)")
        return []
    if not isinstance(parsed, list):
        return []
    out: List[Dict[str, Any]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        iss = str(entry.get("iss") or "").strip()
        jwks_uri = str(entry.get("jwks_uri") or "").strip()
        name = str(entry.get("name") or "").strip().lower()
        auds = entry.get("audiences")
        if isinstance(auds, str):
            auds = [auds]
        auds = [str(a).strip() for a in (auds or []) if str(a).strip()]
        if not (iss.startswith("https://") and jwks_uri.startswith("https://")
                and _NAME_RE.match(name) and auds):
            logger.error("HUB_EXCHANGE_ISSUERS entry rejected (name=%r)", name)
            continue
        out.append({"name": name, "iss": iss, "jwks_uri": jwks_uri, "audiences": auds})
    return out


def shell_origins(extra: Optional[Set[str]] = None) -> Set[str]:
    """Allowed shell origins from HUB_SHELL_ORIGINS (https only) plus ``extra``."""
    out: Set[str] = set()
    for part in (os.environ.get("HUB_SHELL_ORIGINS", "") or "").split(","):
        origin = part.strip().rstrip("/")
        if origin.startswith("https://"):
            out.add(origin)
    for item in extra or set():
        item = str(item or "").strip().rstrip("/")
        if item:
            out.add(item)
    return out


def cors_origin(headers: Optional[Mapping[str, Any]], extra: Optional[Set[str]] = None) -> Optional[str]:
    """The request Origin if (and only if) it is an allowed shell origin."""
    origin = _header(headers, "origin").strip().rstrip("/")
    if origin and origin in shell_origins(extra):
        return origin
    return None


def _ttl_seconds() -> int:
    try:
        ttl = int(os.environ.get("HUB_EXCHANGE_TTL_SECONDS", str(MAX_TTL_SECONDS)) or MAX_TTL_SECONDS)
    except ValueError:
        ttl = MAX_TTL_SECONDS
    return max(_MIN_TTL_SECONDS, min(MAX_TTL_SECONDS, ttl))


def _machine_domains() -> Set[str]:
    raw = os.environ.get("ESCALATION_MACHINE_EMAIL_DOMAINS", "enceladus.internal")
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def _header(headers: Optional[Mapping[str, Any]], name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value or "")
    return ""


# ---------------------------------------------------------------------------
# HMAC secret + hub token
# ---------------------------------------------------------------------------

_secret_cache: Dict[str, Any] = {"value": None, "fetched_at": 0.0}

# E4-R20: the signing key is DERIVED from the coordination internal API key (no Secrets Manager
# resource to create): HMAC-SHA256(key=COORDINATION_INTERNAL_API_KEY, msg=_KEY_CONTEXT).
_KEY_CONTEXT = b"enceladus-hub-exchange-v1"


def _unavailable(reason: str) -> HubExchangeError:
    return HubExchangeError(503, "Hub exchange is unavailable.", reason)


def _derive_key(raw: str) -> bytes:
    return hmac.new(raw.encode("utf-8"), _KEY_CONTEXT, hashlib.sha256).digest()


def _fetch_secret() -> str:
    """Optional override (HUB_EXCHANGE_SECRET_ARN): an explicit HMAC key from Secrets Manager."""
    import boto3  # local import: keeps module import cheap and test-patchable

    arn = os.environ.get("HUB_EXCHANGE_SECRET_ARN", "").strip()
    if not arn:
        raise _unavailable("HUB_EXCHANGE_SECRET_ARN unset")
    client = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION"))
    text = client.get_secret_value(SecretId=arn).get("SecretString") or ""
    try:  # CFN GenerateSecretString template form: {"hmac_key": "..."}
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            text = str(parsed.get("hmac_key") or parsed.get("key") or "")
    except ValueError:
        pass
    return text


def _override_key() -> Optional[bytes]:
    if not os.environ.get("HUB_EXCHANGE_SECRET_ARN", "").strip():
        return None
    now = time.time()
    cached = _secret_cache.get("value")
    if cached and (now - float(_secret_cache.get("fetched_at") or 0.0)) < _SECRET_TTL_SECONDS:
        return cached
    try:
        secret = _fetch_secret()
    except HubExchangeError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed on any secret error
        raise _unavailable(f"secret fetch failed: {exc}") from exc
    if len(secret) < 32:
        raise _unavailable("signing secret missing or too short")
    key = secret.encode("utf-8")
    _secret_cache.update({"value": key, "fetched_at": now})
    return key


def _signing_keys() -> List[bytes]:
    """[current, previous?]: sign with the first, verify against all. Fails CLOSED (503) without a key."""
    override = _override_key()
    if override is not None:
        return [override]
    current = (os.environ.get("COORDINATION_INTERNAL_API_KEY") or "").strip()
    if not current:
        raise _unavailable("COORDINATION_INTERNAL_API_KEY unset")
    keys = [_derive_key(current)]
    previous = (os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS") or "").strip()
    if previous and previous != current:
        keys.append(_derive_key(previous))
    return keys


def _signing_key() -> bytes:
    return _signing_keys()[0]


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


_HUB_HEADER = _b64e(json.dumps({"alg": "HS256", "typ": "HUBX"}, separators=(",", ":"), sort_keys=True).encode())


def _sign(signing_input: str, key: Optional[bytes] = None) -> str:
    return _b64e(hmac.new(key or _signing_key(), signing_input.encode("ascii"), hashlib.sha256).digest())


def mint_hub_token(*, sub: str, email: str, src_iss: str, src_name: str, auth_time: int,
                   acr: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Mint the short-lived hub principal. Returns {hub_token, expires_at, ...}."""
    iat = int(now if now is not None else time.time())
    exp = iat + _ttl_seconds()
    claims = {
        "sub": sub, "email": email, "src_iss": src_iss, "src_name": src_name,
        "auth_time": int(auth_time), "acr": acr, "iat": iat, "exp": exp,
        "kind": HUB_KIND, "jti": uuid.uuid4().hex,
    }
    payload = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{_HUB_HEADER}.{payload}"
    return {"hub_token": f"{signing_input}.{_sign(signing_input)}", "expires_at": exp, "claims": claims}


def verify_hub_token(token: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Verify HMAC + exp + issuer-still-allow-listed. Raises HubExchangeError."""
    current = int(now if now is not None else time.time())
    parts = str(token or "").split(".")
    if len(parts) != 3 or not all(parts):
        raise _deny_auth("hub token malformed")
    header_b64, payload_b64, sig = parts
    if header_b64 != _HUB_HEADER:  # exact alg pin: no alg=none / alg confusion
        raise _deny_auth("hub token header mismatch")
    signing_input = f"{header_b64}.{payload_b64}"
    # current key first, then the rotation-window previous key (E4-R20); missing key -> 503 deny
    if not any([hmac.compare_digest(_sign(signing_input, key), sig) for key in _signing_keys()]):
        raise _deny_auth("hub token signature mismatch")
    try:
        claims = json.loads(_b64d(payload_b64))
    except Exception as exc:  # noqa: BLE001
        raise _deny_auth("hub token payload unreadable") from exc
    if not isinstance(claims, dict) or claims.get("kind") != HUB_KIND:
        raise _deny_auth("hub token kind mismatch")
    try:
        iat, exp = int(claims["iat"]), int(claims["exp"])
        int(claims["auth_time"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _deny_auth("hub token timing claims invalid") from exc
    if exp <= current:
        raise _deny_auth("hub token expired")
    if iat > current + _CLOCK_LEEWAY_SECONDS or exp - iat > MAX_TTL_SECONDS:
        raise _deny_auth("hub token lifetime invalid")
    email = str(claims.get("email") or "").strip().lower()
    if not _is_human_email(email) or not claims.get("sub"):
        raise _deny_identity("hub token identity invalid")
    if not any(i["iss"] == claims.get("src_iss") and i["name"] == claims.get("src_name")
               for i in load_issuers()):
        raise _deny_auth("hub token issuer no longer allow-listed")
    claims["email"] = email
    return claims


def extract_hub_token(headers: Optional[Mapping[str, Any]]) -> Optional[str]:
    """The token of an ``Authorization: HubExchange <token>`` header, else None.

    Returns "" when the scheme is HubExchange but no token follows (so callers
    refuse rather than fall through to another auth path).
    """
    parts = _header(headers, "authorization").strip().split(None, 1)
    if parts and parts[0].lower() == HUB_SCHEME.lower():
        return parts[1].strip() if len(parts) == 2 else ""
    return None


def principal_claims(hub_claims: Dict[str, Any]) -> Dict[str, Any]:
    """Claims shape handed to the escalation handlers for a verified hub token."""
    name = str(hub_claims.get("src_name") or "")
    return {
        "auth_mode": HUB_AUTH_MODE, "kind": HUB_KIND, "token_use": "id",
        "sub": hub_claims.get("sub"), "email": hub_claims.get("email"),
        "auth_time": int(hub_claims["auth_time"]), "acr": hub_claims.get("acr") or "",
        "hub_source_issuer": hub_claims.get("src_iss"), "hub_source_name": name,
        "auth_method": f"hub_exchange:{name}", "iat": int(hub_claims["iat"]),
        "exp": int(hub_claims["exp"]),
    }


def is_human_hub_principal(claims: Optional[Dict[str, Any]]) -> bool:
    """True only for claims produced by principal_claims() for a human identity."""
    claims = claims or {}
    if claims.get("auth_mode") != HUB_AUTH_MODE or claims.get("kind") != HUB_KIND:
        return False
    if str(claims.get("token_use") or "") != "id":
        return False
    if not str(claims.get("auth_method") or "").startswith("hub_exchange:"):
        return False
    return _is_human_email(str(claims.get("email") or "").strip().lower())


def _is_human_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    return email.rsplit("@", 1)[1] not in _machine_domains()


# ---------------------------------------------------------------------------
# Source-token verification (JWKS)
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Dict[str, Any]] = {}


def _fetch_jwks(uri: str) -> Dict[str, Any]:
    if not uri.startswith("https://"):
        raise ValueError("jwks_uri must be https")
    req = urllib.request.Request(uri, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - https only, allow-listed
        return json.loads(resp.read().decode("utf-8"))


def _signing_jwk(uri: str, kid: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    for attempt in (0, 1):
        entry = _jwks_cache.get(uri)
        stale = entry is None or (now - float(entry["fetched_at"])) > _JWKS_TTL_SECONDS
        if attempt == 1 or stale:  # attempt 1: kid miss -> one forced refresh
            if attempt == 1 and entry is not None and (now - float(entry["fetched_at"])) < 10:
                return None  # refetch throttle: do not let bad kids hammer the issuer
            jwks = _fetch_jwks(uri)
            entry = {"fetched_at": now, "keys": {k.get("kid"): k for k in jwks.get("keys", [])}}
            _jwks_cache[uri] = entry
        key = entry["keys"].get(kid) if entry else None
        if key is not None:
            return key
    return None


def verify_source_token(id_token: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Verify an ID token against the issuer allow-list. Returns {issuer, claims}."""
    if not _JWT_AVAILABLE:
        raise HubExchangeError(503, "Hub exchange is unavailable.", "PyJWT unavailable")
    issuers = load_issuers()
    if not issuers or not isinstance(id_token, str) or id_token.count(".") != 2:
        raise _deny_auth("no issuers configured or token malformed")
    try:
        unverified = jwt.decode(id_token, options={"verify_signature": False})
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:  # noqa: BLE001
        raise _deny_auth("token unreadable") from exc
    issuer = next((i for i in issuers if i["iss"] == unverified.get("iss")), None)
    if issuer is None:
        raise _deny_auth("issuer not allow-listed")
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise _deny_auth("unexpected algorithm or missing kid")
    try:
        jwk = _signing_jwk(issuer["jwks_uri"], str(header["kid"]))
    except Exception as exc:  # noqa: BLE001
        raise _deny_auth(f"jwks fetch failed: {exc}") from exc
    if jwk is None:
        raise _deny_auth("signing key not found")
    try:
        key = RSAAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(
            id_token, key, algorithms=["RS256"], audience=issuer["audiences"], issuer=issuer["iss"],
            leeway=_CLOCK_LEEWAY_SECONDS, options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as exc:  # noqa: BLE001 - expired, bad signature, wrong aud/iss
        raise _deny_auth(f"token verification failed: {type(exc).__name__}") from exc
    _require_human_id_token(claims)
    return {"issuer": issuer, "claims": claims}


def _require_human_id_token(claims: Dict[str, Any]) -> None:
    """Refuse every machine / non-ID token shape (client-credentials, access...)."""
    if "token_use" in claims and str(claims["token_use"]).lower() != "id":
        raise _deny_auth("token_use is not id")
    if "typ" in claims and str(claims["typ"]).lower() != "id":
        raise _deny_auth("typ is not ID")
    if claims.get("client_id") and not claims.get("aud"):
        raise _deny_auth("machine client shape")
    if str(claims.get("gty") or "").lower() == "client-credentials" or claims.get("clientId"):
        raise _deny_auth("client-credentials shape")
    if str(claims.get("preferred_username") or "").lower().startswith("service-account-"):
        raise _deny_auth("service account shape")
    if claims.get("email_verified") in (False, "false", "False"):
        raise _deny_identity("email not verified")


# ---------------------------------------------------------------------------
# Exchange
# ---------------------------------------------------------------------------


def exchange(id_token: str, allowlist_loader: Callable[[], Set[str]],
             now: Optional[int] = None) -> Dict[str, Any]:
    """Exchange an allow-listed-issuer ID token for a hub principal.

    ``allowlist_loader`` is the caller's own approver-allow-list loader (the
    SAME S3 document the Cognito path uses; it fails closed to an empty set).
    """
    current = int(now if now is not None else time.time())
    verified = verify_source_token(id_token, now=current)
    issuer, claims = verified["issuer"], verified["claims"]
    email = str(claims.get("email") or "").strip().lower()
    if not _is_human_email(email):
        raise _deny_identity("email absent or machine domain")
    if email not in (allowlist_loader() or set()):
        raise _deny_identity("identity not on approver allow-list")
    try:
        auth_time = int(claims["auth_time"])
    except (KeyError, TypeError, ValueError) as exc:
        # No iat fallback: iat >= auth_time would make a stale login look fresh.
        raise _deny_auth("source token carries no auth_time") from exc
    if auth_time > current + _CLOCK_LEEWAY_SECONDS:
        raise _deny_auth("auth_time in the future")
    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise _deny_auth("source token carries no sub")
    acr = str(claims.get("acr") or "")
    minted = mint_hub_token(sub=sub, email=email, src_iss=issuer["iss"], src_name=issuer["name"],
                            auth_time=auth_time, acr=acr, now=current)
    return {"hub_token": minted["hub_token"], "expires_at": minted["expires_at"],
            "auth_time": auth_time, "acr": acr, "issuer": issuer["name"]}
