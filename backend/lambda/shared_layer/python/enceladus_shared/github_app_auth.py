"""enceladus_shared.github_app_auth — GitHub App JWT + installation-token auth.

Centralizes GitHub App authentication for the Enceladus Lambdas that call
the GitHub REST API using App-installation credentials and carry the shared
layer (checkout_service, deploy_decide, auth_refresh). Before ENC-TSK-O07
each of these carried its own copy of ``_generate_app_jwt()`` /
``_get_installation_token()`` (some cached, some minted fresh on every call,
with drifting defaults) — this module is the single hardened implementation
they now import.

NOT migrated: github_integration. It still carries its own local
``_generate_app_jwt()`` / ``_get_installation_token()`` deliberately.
``enceladus_shared`` only reaches a Lambda via an attached Lambda layer, and
the live ``devops-github-integration`` function has zero layers attached —
it is Gen2-managed with no CFN resource in this repo, and the Gen2 build
workflow (.github/workflows/_build.yml) does not vendor this package into
its artifact. Importing this module there today would fail at cold start
with ``Runtime.ImportModuleError: No module named 'enceladus_shared'`` on
every invocation (the ENC-ISS-566 crash-loop class). Migrating
github_integration requires attaching the shared layer (or vendoring the
package into its build) first — that is out of scope for ENC-TSK-O07.

Hardened semantics (mirrors ENC-TSK-O03 / ENC-ISS-621 C4):
    - Installation-token cache expiry is derived from the mint response's
      ``expires_at`` field (ISO 8601), not an assumed now+3600 — falling
      back to now+3600 only when the field is absent or unparseable. A 300s
      refresh buffer is applied before that expiry.
    - ``github_request()`` re-mints the installation token and retries the
      call ONCE when the API returns 401/403 — but only when the token
      currently in use is at least 60s old (the "age floor"). A 401/403 on a
      token minted <60s ago is a genuine authorization problem, not
      staleness, so it is surfaced immediately instead of looping. At most
      one re-mint happens per call, ever.
    - Every failed GitHub call logs one ``github_validation_fail`` line
      (endpoint, status, msg, token_age_s, repo, sha). Every successful mint
      logs the token's ``expires_at`` and the sorted KEYS of the returned
      ``permissions`` object (never the values).

Callers own their own environment variables (``GITHUB_APP_ID``,
``GITHUB_INSTALLATION_ID``, ``GITHUB_PRIVATE_KEY_SECRET``, region, API base)
and build a ``GitHubAppConfig`` once at module load, preserving whatever
per-lambda defaults they already had. This module reads no environment
variables and performs no I/O at import time.

Part of ENC-TSK-O07: extract shared enceladus_shared.github_app_auth
(ENC-ISS-621 C4).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

try:
    import jwt

    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001 — mirrors enceladus_shared.auth's ENC-ISS-198 handling
    # ENC-ISS-198 / ENC-TSK-D22: log the import failure so operators can
    # diagnose PyJWT/cryptography ABI mismatches in CloudWatch instead of
    # chasing the downstream "JWT library not available" message. logger is
    # not yet defined at module-load time, so use logging.getLogger directly.
    import logging as _enc_iss_198_logging

    _enc_iss_198_logging.getLogger(__name__).exception(
        "PyJWT import failed at module load — GitHub App auth will be disabled "
        "(ENC-ISS-198: usually a shared-layer .so ABI mismatch with the function runtime)"
    )
    _JWT_AVAILABLE = False

from enceladus_shared.aws_clients import _get_secretsmanager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tunables (ENC-TSK-O03 hardened semantics)
# ---------------------------------------------------------------------------

_REFRESH_BUFFER_S: float = 300.0  # re-mint this long before the parsed expiry
_REMINT_AGE_FLOOR_S: float = 60.0  # only re-mint-and-retry on 401/403 past this token age
_FALLBACK_TOKEN_TTL_S: float = 3600.0  # used when expires_at is missing/unparseable
_PRIVATE_KEY_TTL_S: float = 3600.0  # re-fetch private key from Secrets Manager every hour
_JWT_CLOCK_SKEW_S: int = 60
_JWT_TTL_S: int = 9 * 60  # 9 minutes, under GitHub's 10-minute max


@dataclass(frozen=True)
class GitHubAppConfig:
    """Per-lambda GitHub App identity + endpoint configuration.

    Each Lambda builds one of these from its own environment variables
    (preserving that Lambda's own defaults) and passes it to every call —
    this module does not read environment variables itself.
    """

    app_id: str
    installation_id: str
    private_key_secret: str
    region: Optional[str] = None
    api_base: str = "https://api.github.com"


# ---------------------------------------------------------------------------
# Private key cache (keyed by secret name, so multiple configs can share it)
# ---------------------------------------------------------------------------

_private_key_cache: Dict[str, Tuple[str, float]] = {}


def _get_private_key(config: GitHubAppConfig) -> str:
    """Fetch (and cache) the App's private key from Secrets Manager."""
    now = time.time()
    cached = _private_key_cache.get(config.private_key_secret)
    if cached and (now - cached[1]) < _PRIVATE_KEY_TTL_S:
        return cached[0]
    sm = _get_secretsmanager(config.region)
    resp = sm.get_secret_value(SecretId=config.private_key_secret)
    key = resp["SecretString"]
    _private_key_cache[config.private_key_secret] = (key, now)
    return key


# ---------------------------------------------------------------------------
# App JWT
# ---------------------------------------------------------------------------


def generate_app_jwt(config: GitHubAppConfig) -> str:
    """Generate a short-lived RS256 JWT for the GitHub App."""
    if not _JWT_AVAILABLE:
        raise ValueError("PyJWT library not available — cannot generate GitHub App JWT")
    if not config.app_id:
        raise ValueError("GITHUB_APP_ID not configured")
    now = int(time.time())
    payload = {
        "iat": now - _JWT_CLOCK_SKEW_S,
        "exp": now + _JWT_TTL_S,
        "iss": str(config.app_id),
    }
    private_key = _get_private_key(config)
    return jwt.encode(payload, private_key, algorithm="RS256")


# ---------------------------------------------------------------------------
# Installation token cache + mint (ENC-TSK-O03 hardened expiry)
# ---------------------------------------------------------------------------

_token_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}


def _parse_expires_at(raw: Optional[str]) -> float:
    """Parse a GitHub ``expires_at`` (ISO 8601) into an epoch float.

    Falls back to now + _FALLBACK_TOKEN_TTL_S when absent or unparseable.
    """
    if raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            pass
    return time.time() + _FALLBACK_TOKEN_TTL_S


def _mint_installation_token(config: GitHubAppConfig) -> Dict[str, Any]:
    """Exchange an App JWT for a fresh installation access token.

    Logs the token's expires_at and the sorted permission KEYS (never
    values) on every successful mint.
    """
    if not config.installation_id:
        raise ValueError("GITHUB_INSTALLATION_ID not configured")

    app_jwt = generate_app_jwt(config)
    url = f"{config.api_base}/app/installations/{config.installation_id}/access_tokens"
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
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.error("GitHub installation token exchange failed: %s %s", exc.code, body)
        raise ValueError(f"GitHub token exchange failed ({exc.code}): {body}") from exc

    expires_at_raw = data.get("expires_at")
    permissions = data.get("permissions") or {}
    logger.info(
        "github_app_token_minted expires_at=%s permission_keys=%s",
        expires_at_raw or "<unset>",
        sorted(permissions.keys()),
    )
    now = time.time()
    return {
        "token": data["token"],
        "minted_at": now,
        "expires_at_epoch": _parse_expires_at(expires_at_raw),
    }


def _cache_key(config: GitHubAppConfig) -> Tuple[str, str]:
    return (config.app_id, config.installation_id)


def _get_token_entry(config: GitHubAppConfig, *, force_refresh: bool = False) -> Dict[str, Any]:
    """Return the cached token entry, minting a fresh one when stale/forced."""
    key = _cache_key(config)
    now = time.time()
    entry = _token_cache.get(key)
    if (
        not force_refresh
        and entry is not None
        and now < (entry["expires_at_epoch"] - _REFRESH_BUFFER_S)
    ):
        return entry
    entry = _mint_installation_token(config)
    _token_cache[key] = entry
    return entry


def get_installation_token(config: GitHubAppConfig, *, force_refresh: bool = False) -> str:
    """Get a cached GitHub App installation token, refreshing when near expiry."""
    return _get_token_entry(config, force_refresh=force_refresh)["token"]


# ---------------------------------------------------------------------------
# GitHub REST calls with 401/403 re-mint-and-retry (ENC-TSK-O03 / ENC-ISS-621 C4)
# ---------------------------------------------------------------------------


def _log_validation_fail(
    endpoint: str,
    status: int,
    msg: str,
    token_age_s: float,
    repo: Optional[str],
    sha: Optional[str],
) -> None:
    logger.warning(
        "github_validation_fail endpoint=%s status=%s msg=%s token_age_s=%.1f repo=%s sha=%s",
        endpoint,
        status,
        msg,
        token_age_s,
        repo or "",
        sha or "",
    )


def _extract_message(body: Any) -> str:
    if isinstance(body, dict):
        return str(body.get("message", body))[:300]
    return str(body)[:300]


def _do_request(
    method: str,
    url: str,
    *,
    token: str,
    timeout: float,
    body: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Any]:
    headers: Dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, TypeError):
            payload = {"error": raw.decode("utf-8", errors="replace")}
        return exc.code, payload
    except Exception as exc:  # noqa: BLE001 — network/timeout errors surfaced as 503
        return 503, {"error": str(exc)}


def github_request(
    config: GitHubAppConfig,
    method: str,
    path: str,
    *,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 10,
    extra_headers: Optional[Dict[str, str]] = None,
    repo: Optional[str] = None,
    sha: Optional[str] = None,
) -> Tuple[int, Any]:
    """Call the GitHub REST API with installation-token auth.

    On a 401/403, re-mints the installation token and retries ONCE — but
    only if the token in use is at least ``_REMINT_AGE_FLOOR_S`` seconds
    old (a fresh token failing auth is not a staleness problem, and retrying
    it would loop pointlessly). At most one re-mint happens per call, ever.

    Returns (status_code, parsed_body). Network/timeout errors surface as a
    synthetic 503 rather than raising, matching the pre-extraction behavior
    of the lambdas' own GitHub request helpers.
    """
    url = f"{config.api_base}{path}"
    entry = _get_token_entry(config)
    status, resp_body = _do_request(
        method, url, token=entry["token"], timeout=timeout, body=body, extra_headers=extra_headers
    )

    if status in (401, 403):
        token_age_s = time.time() - entry["minted_at"]
        _log_validation_fail(path, status, _extract_message(resp_body), token_age_s, repo, sha)
        if token_age_s >= _REMINT_AGE_FLOOR_S:
            entry = _get_token_entry(config, force_refresh=True)
            status, resp_body = _do_request(
                method,
                url,
                token=entry["token"],
                timeout=timeout,
                body=body,
                extra_headers=extra_headers,
            )
            if status in (401, 403):
                token_age_s = time.time() - entry["minted_at"]
                _log_validation_fail(
                    path, status, _extract_message(resp_body), token_age_s, repo, sha
                )

    return status, resp_body
