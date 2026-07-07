"""checkout_service/lambda_function.py

Checkout Service Lambda — sole authorized caller for task status transitions and worklog appends.

Provides a complete lifecycle gate API for Enceladus tracker tasks, including:
  - Atomic checkout + advance to in-progress
  - Token-gated status advancement (CAI → coding-complete, CCI → committed)
  - Worklog appends (checkout required)
  - Commit SHA validation via GitHub API
  - PR merge validation via GitHub API
  - CCI token validation endpoint (consumed by GitHub Actions pr-commit-gate)
  - Auto-checkout EventBridge handler

Routes (via API Gateway proxy):
    POST   /api/v1/checkout/{project}/task/{task_id}/checkout          — Check out + in-progress
    DELETE /api/v1/checkout/{project}/task/{task_id}/checkout          — Release checkout
    POST   /api/v1/checkout/{project}/task/{task_id}/advance           — Advance status
    POST   /api/v1/checkout/{project}/task/{task_id}/log               — Append worklog
    GET    /api/v1/checkout/{project}/task/{task_id}/status            — Checkout + task state
    GET    /api/v1/checkout/validate/commit-complete/{cci_id}          — Validate CCI token
    OPTIONS /api/v1/checkout/*                                         — CORS preflight

Auth:
    Same JWT cookie auth as all Enceladus Lambdas (enceladus_id_token).
    Optional service-to-service auth via X-Coordination-Internal-Key.
    Auto-checkout handler: invoked by EventBridge (no HTTP auth required).

Environment variables:
    TRACKER_API_BASE              default: https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker (direct APIGW, avoids Cloudflare 1010)
    COORDINATION_INTERNAL_API_KEY  internal key for calling tracker API
    COORDINATION_INTERNAL_API_KEYS CSV of accepted internal keys (multi-key support)
    CHECKOUT_SERVICE_KEY          secret this service presents to tracker_mutation (X-Checkout-Service-Key)
    GITHUB_APP_ID                 GitHub App numeric ID (ENC-TSK-B26)
    GITHUB_INSTALLATION_ID        GitHub App installation ID for NX-2021-L org
    GITHUB_PRIVATE_KEY_SECRET     Secrets Manager secret name for App private key (default: devops/github-app/enceladus-private-key)
    CHECKOUT_TOKENS_TABLE         DynamoDB table for token storage (default: enceladus-checkout-tokens)
    CHECKOUT_TOKENS_REGION        AWS region for token table (default: us-west-2)
    AGENT_SESSIONS_TABLE          agent-sessions store for the SCI gate (default: agent-sessions)
    COGNITO_USER_POOL_ID          us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID             6q607dk3liirhtecgps7hifmlk
    CORS_ORIGIN                   default: https://jreese.net
    TOKEN_TTL_DAYS                token expiry in days (default: 90)
    COMPONENTS_TABLE              component registry DynamoDB table (default: component-registry)
    DOCUMENT_API_BASE             document API base URL (defaults from TRACKER_API_BASE sibling)
    CHECKOUT_ASSISTANT_KEY        secret key for checkout-service-assistant auto-remediation
    COORDINATION_API_BASE         base URL for coordination API (default: https://jreese.net/api/v1/coordination)

Related: ENC-FTR-037, ENC-ISS-092, ENC-FTR-041, ENC-ISS-106, ENC-ISS-172

ENC-ISS-092: Added ``transition_type`` field support. Tasks may now declare one of four
lifecycle arcs (github_pr_deploy, web_deploy, code_only, no_code) that determine which
target_status values are allowed and what evidence each gate requires. The default
``github_pr_deploy`` arc is fully backward compatible — tasks without the field behave
identically to before.

ENC-FTR-041: Added component registry enforcement. Tasks must declare ``components``
(list of component_ids from component-registry table) before agent-initiated advances.
The checkout service enforces that task.transition_type is at least as strict as the
most restrictive component's artifact policy. Legacy component policy values are
normalized to the v3 enum code|external_deploy|documentation at read time. Added
``lambda_deploy`` task transition_type arc (same as web_deploy but uses
lambda_deploy_evidence at deploy-success). Added checkout-service-assistant inline
auto-remediation: after 3 consecutive deploy-success failures, the assistant infers
the intended component policy if safe to do so.

ENC-ISS-106: Added subtask lifecycle gate. Parent tasks (those with non-empty
subtask_ids) cannot advance from coding-complete onward unless all direct children
have reached at least the target status. Children at 'closed' satisfy any stage.
The gate only applies to agent-initiated advances through the checkout service;
PWA user_initiated transitions bypass this gate (same as component enforcement).

ENC-ISS-172 / ENC-TSK-C15: Added component registry pre-validation to checkout.task.
_handle_checkout() now validates task.transition_type against the component registry
BEFORE writing the checkout lock, status mutation, or CAI token. If any registered
component enforces a stricter minimum transition_type than the task declares, checkout
is rejected with a 400 error. This surfaces incompatibilities at the earliest possible
enforcement point, before transition_type becomes immutable per ENC-FTR-060.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple
import urllib.parse
import urllib.request
import urllib.error
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

from transition_type_matrix import (
    MATRIX_VERSION,
    MATRIX_DOCUMENT_ID,
    ALLOWED_TRANSITIONS_BY_TYPE as _MATRIX_ALLOWED_TRANSITIONS,
    STRICTNESS_RANK as _MATRIX_STRICTNESS_RANK,
    VALID_TRANSITION_TYPES as _MATRIX_VALID_TYPES,
    GITHUB_PR_TYPES as _MATRIX_GITHUB_PR_TYPES,
    DEPLOY_SUCCESS_EVIDENCE,
    CLOSED_EVIDENCE,
    get_deploy_success_gate,
    get_closed_gate,
    uses_github_pr as _matrix_uses_github_pr,
)

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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TRACKER_API_BASE = os.environ.get("TRACKER_API_BASE", "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker").rstrip("/")
CHECKOUT_SERVICE_KEY = os.environ.get("CHECKOUT_SERVICE_KEY", "")
# ENC-TSK-B26: GitHub App installation tokens replace static PAT
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_INSTALLATION_ID = os.environ.get("GITHUB_INSTALLATION_ID", "")
GITHUB_PRIVATE_KEY_SECRET = os.environ.get(
    "GITHUB_PRIVATE_KEY_SECRET", "devops/github-app/enceladus-private-key"
)
CHECKOUT_TOKENS_TABLE = os.environ.get("CHECKOUT_TOKENS_TABLE", "enceladus-checkout-tokens")
CHECKOUT_TOKENS_REGION = os.environ.get("CHECKOUT_TOKENS_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
TOKEN_TTL_DAYS = int(os.environ.get("TOKEN_TTL_DAYS", "90"))
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
# ENC-FTR-041: Component registry enforcement
COMPONENTS_TABLE = os.environ.get("COMPONENTS_TABLE", "component-registry")
CHECKOUT_ASSISTANT_KEY = os.environ.get("CHECKOUT_ASSISTANT_KEY", "")
COORDINATION_API_BASE = os.environ.get(
    "COORDINATION_API_BASE", "https://jreese.net/api/v1/coordination"
)
DOCUMENT_API_BASE = os.environ.get(
    "DOCUMENT_API_BASE",
    TRACKER_API_BASE.rsplit("/", 1)[0] + "/documents",
).rstrip("/")
# ENC-ISS-441 / ENC-TSK-J93: agent-sessions store (ENC-FTR-117 / ENC-TSK-I37)
# read by the SCI enforcement gate for the grandfather-epoch check and the
# last_activity_at heartbeat touch (J83 pattern).
AGENT_SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")

GITHUB_API_BASE = "https://api.github.com"

# ---------------------------------------------------------------------------
# Internal API key normalization
# ---------------------------------------------------------------------------

def _normalize_api_keys(*raw_values: str) -> tuple:
    """Return deduplicated, non-empty key values from scalar/csv env sources."""
    keys: list = []
    seen: set = set()
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


_INTERNAL_API_KEYS: tuple = _normalize_api_keys(
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEY", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", ""),
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", ""),
    os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEY", ""),
)

# Primary key for outbound calls to tracker API
_PRIMARY_INTERNAL_KEY = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "")
    or (list(_INTERNAL_API_KEYS)[0] if _INTERNAL_API_KEYS else "")
)

# ---------------------------------------------------------------------------
# DynamoDB client for checkout token storage
# ---------------------------------------------------------------------------
_ddb = boto3.client("dynamodb", region_name=CHECKOUT_TOKENS_REGION)

# ---------------------------------------------------------------------------
# GitHub App installation token (ENC-TSK-B26)
# Replaces static GITHUB_TOKEN PAT with runtime token generation from
# GitHub App private key stored in Secrets Manager.
# ---------------------------------------------------------------------------
_sm_client = None
_private_key_cache: Optional[str] = None
_private_key_fetched_at: float = 0.0
_PRIVATE_KEY_TTL: float = 3600.0  # re-fetch private key from SM every hour

_installation_token_cache: Optional[str] = None
_installation_token_expires_at: float = 0.0

# ENC-TSK-C68 / ENC-ISS-183: cached set of 'owner/repo' full names accessible to
# the GitHub App installation. Used by _validate_commit to self-diagnose
# installation-scope 404s (repo missing from installation scope vs. commit
# genuinely not found). Short TTL so a grant via the org admin UI is picked up
# without a Lambda cold restart.
_installation_repos_cache: Optional[set] = None
_installation_repos_expires_at: float = 0.0
_INSTALLATION_REPOS_TTL: float = 300.0


def _get_secretsmanager():
    global _sm_client
    if _sm_client is None:
        _sm_client = boto3.client("secretsmanager", region_name=CHECKOUT_TOKENS_REGION)
    return _sm_client


def _get_github_private_key() -> str:
    """Fetch GitHub App private key from Secrets Manager (cached with TTL)."""
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
    """Generate a short-lived RS256 JWT for the GitHub App."""
    if not _JWT_AVAILABLE:
        raise ValueError("PyJWT library not available — cannot generate GitHub App JWT")
    if not GITHUB_APP_ID:
        raise ValueError("GITHUB_APP_ID environment variable not set")
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (9 * 60),
        "iss": str(GITHUB_APP_ID),
    }
    private_key = _get_github_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token() -> str:
    """Get a cached GitHub App installation token, refreshing when near expiry."""
    global _installation_token_cache, _installation_token_expires_at
    now = time.time()
    # Refresh with 5-minute buffer before the 1-hour expiry
    if _installation_token_cache and now < (_installation_token_expires_at - 300):
        return _installation_token_cache

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
            _installation_token_cache = data["token"]
            # GitHub installation tokens expire in 1 hour
            _installation_token_expires_at = now + 3600
            return _installation_token_cache
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.error("GitHub installation token exchange failed: %s %s", exc.code, body)
        raise ValueError(f"GitHub token exchange failed ({exc.code}): {body}") from exc


def _get_github_token() -> Optional[str]:
    """Return a valid GitHub token for API calls, or None if unconfigured."""
    if not GITHUB_APP_ID or not GITHUB_INSTALLATION_ID:
        logger.warning("GitHub App not configured — API calls will be unauthenticated")
        return None
    try:
        return _get_installation_token()
    except Exception as exc:
        logger.error("Failed to obtain GitHub installation token: %s", exc)
        return None


# ---------------------------------------------------------------------------
# CORS helpers
# ---------------------------------------------------------------------------

def _cors_headers(origin: str = CORS_ORIGIN) -> dict:
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": (
            "Content-Type,Authorization,Cookie,X-Coordination-Internal-Key,"
            "X-Checkout-Service-Key"
        ),
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status: int, body: Any, extra_headers: Optional[dict] = None) -> dict:
    headers = {**_cors_headers(), "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body) if not isinstance(body, str) else body,
    }


# ---------------------------------------------------------------------------
# ENC-TSK-H49 / ENC-ISS-142: machine-readable failure classification.
# Every blocked-transition envelope carries a `failure_classification` and a
# `recommended_next_actions` array so agents can escalate with concrete operator
# actions instead of guessing. Consumed by the agents.md "Escalation Protocol".
# ---------------------------------------------------------------------------
FAILURE_CLASSIFICATIONS = (
    "transient",
    "deterministic-governance",
    "external-dependency",
    "human-override-required",
)

# Map known error codes to a canonical classification. Codes not listed fall
# back by HTTP status family (see _failure_classification).
_CLASSIFICATION_BY_CODE = {
    "INVALID_INPUT": "deterministic-governance",
    "CONFLICT": "deterministic-governance",
    "NOT_FOUND": "deterministic-governance",
    "RESERVED_FIELD": "deterministic-governance",
    "component_lifecycle_blocked": "deterministic-governance",
    "GATE_CONDITION_UNMET": "deterministic-governance",
    "PERMISSION_DENIED": "human-override-required",
    "component_not_approved": "human-override-required",
    "component_rejected": "human-override-required",
    "COMPONENT_MISCONFIGURED": "human-override-required",
    "INTERNAL_ERROR": "transient",
}

_RECOMMENDED_NEXT_ACTIONS = {
    "deterministic-governance": [
        "Re-run tracker.validation_rules(record_id, target_status, provider) for the exact required evidence and allowed next statuses.",
        "Correct the governed inputs (set components/transition_type before checkout; supply the missing transition_evidence; satisfy the subtask gate), then retry once.",
        "If the block persists, escalate per the agents.md Escalation Protocol (L2) -- never reshape governed state to bypass the gate.",
    ],
    "human-override-required": [
        "This action is outside agent authority. Surface to io: use the PWA user_initiated (Cognito) path, or have io approve/remediate the component.",
        "Do not retry against the Cognito/authority guard.",
        "Escalate per the agents.md Escalation Protocol (L2/L3) with the exact failing operation and a proposed operator action.",
    ],
    "external-dependency": [
        "The failure originates from an external dependency (e.g. GitHub API, Cognito). Check the upstream service status.",
        "Retry after recovery within the bounded retry budget (3 attempts; 1s/4s/16s backoff).",
        "If it persists, escalate per the agents.md Escalation Protocol (L2).",
    ],
    "transient": [
        "Transient/internal error. Retry with exponential backoff (3 attempts; 1s/4s/16s).",
        "If it persists after the retry budget, escalate per the agents.md Escalation Protocol.",
    ],
}


def _failure_classification(
    code: Optional[str], status: int, override: Optional[str]
) -> str:
    """Classify a blocked-transition failure (ENC-TSK-H49). An explicit override
    wins (e.g. call sites that know a failure is an external dependency); else map
    by error code; else fall back by HTTP status family."""
    if override in FAILURE_CLASSIFICATIONS:
        return override
    if code in _CLASSIFICATION_BY_CODE:
        return _CLASSIFICATION_BY_CODE[code]
    return "transient" if status >= 500 else "deterministic-governance"


def _error(
    status: int,
    message: str,
    *,
    code: Optional[str] = None,
    retryable: Optional[bool] = None,
    details: Optional[Dict[str, Any]] = None,
    failure_classification: Optional[str] = None,
) -> dict:
    details = dict(details or {})
    if not code:
        if status == 400:
            code = "INVALID_INPUT"
        elif status == 401:
            code = "PERMISSION_DENIED"
        elif status == 403:
            code = "PERMISSION_DENIED"
        elif status == 404:
            code = "NOT_FOUND"
        elif status == 409:
            code = "CONFLICT"
        elif status == 422:
            code = "INVALID_INPUT"
        elif status >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    if retryable is None:
        retryable = status >= 500
    classification = _failure_classification(code, status, failure_classification)
    recommended_next_actions = _RECOMMENDED_NEXT_ACTIONS.get(classification, [])
    body: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "failure_classification": classification,
            "recommended_next_actions": recommended_next_actions,
            "details": details,
        },
    }
    body.update(details)
    return _response(status, body)


# ---------------------------------------------------------------------------
# Auth: JWT + internal key
# ---------------------------------------------------------------------------

_jwks_cache: Optional[dict] = None
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

def _get_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    region = COGNITO_USER_POOL_ID.split("_")[0] if "_" in COGNITO_USER_POOL_ID else "us-east-1"
    jwks_url = (
        f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )
    req = urllib.request.Request(jwks_url, headers={"User-Agent": "checkout-service/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        _jwks_cache = json.loads(resp.read())
        _jwks_fetched_at = now
    return _jwks_cache


def _validate_jwt(token: str) -> Tuple[bool, Optional[dict]]:
    if not _JWT_AVAILABLE:
        return False, None
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        jwks = _get_jwks()
        key_data = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
        if not key_data:
            return False, None
        public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            options={"verify_exp": True},
        )
        return True, claims
    except Exception as exc:
        logger.debug("JWT validation failed: %s", exc)
        return False, None


def _extract_jwt_cookie(headers: dict) -> Optional[str]:
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    for part in cookie_header.split(";"):
        name, _, value = part.strip().partition("=")
        if name.strip() == "enceladus_id_token":
            return value.strip()
    return None


def _is_authenticated(event: dict) -> bool:
    """Return True if request carries valid JWT cookie or valid internal key."""
    headers = event.get("headers") or {}

    # Internal service key (multi-key)
    for header_name in ("x-coordination-internal-key", "X-Coordination-Internal-Key"):
        presented = headers.get(header_name, "")
        if presented and _INTERNAL_API_KEYS and presented in _INTERNAL_API_KEYS:
            return True

    # JWT cookie
    token = _extract_jwt_cookie(headers)
    if token:
        ok, _ = _validate_jwt(token)
        if ok:
            return True

    return False


# ---------------------------------------------------------------------------
# Tracker API calls
# ---------------------------------------------------------------------------

def _tracker_request(
    method: str,
    path: str,
    payload: Optional[dict] = None,
) -> Tuple[int, dict]:
    """Make an HTTP request to the tracker API. Returns (status_code, body_dict)."""
    url = f"{TRACKER_API_BASE}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    headers: dict = {
        "Content-Type": "application/json",
        "X-Coordination-Internal-Key": _PRIMARY_INTERNAL_KEY,
    }
    if CHECKOUT_SERVICE_KEY:
        headers["X-Checkout-Service-Key"] = CHECKOUT_SERVICE_KEY

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, body
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            body = {"error": str(exc)}
        return exc.code, body
    except Exception as exc:
        logger.error("Tracker API request failed (%s %s): %s", method, path, exc)
        return 503, {"error": f"Tracker API unavailable: {exc}"}


def _document_api_request(method: str, path: str) -> Tuple[int, dict]:
    """Make a read-only request to document API using the coordination internal key."""
    url = f"{DOCUMENT_API_BASE}{path}"
    headers: dict = {
        "Content-Type": "application/json",
        "X-Coordination-Internal-Key": _PRIMARY_INTERNAL_KEY,
    }
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            return resp.status, body
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            body = {"error": str(exc)}
        return exc.code, body
    except Exception as exc:
        logger.error("Document API request failed (%s %s): %s", method, path, exc)
        return 503, {"error": f"Document API unavailable: {exc}"}


def _get_task(project_id: str, task_id: str) -> Tuple[int, dict]:
    status, body = _tracker_request("GET", f"/{project_id}/task/{task_id}")
    # tracker_mutation GET now returns {"success": true, "record": {...}}.
    # Preserve backward compatibility with older flat payloads.
    if status == 200 and isinstance(body, dict) and isinstance(body.get("record"), dict):
        return status, body["record"]
    return status, body


def _set_task_field(
    project_id: str,
    task_id: str,
    field: str,
    value: Any,
    provider: Optional[str] = None,
    transition_evidence: Optional[dict] = None,
    governance_hash: Optional[str] = None,
) -> Tuple[int, dict]:
    payload: dict = {"field": field, "value": value}
    if provider:
        payload["provider"] = provider
    if transition_evidence:
        payload["transition_evidence"] = transition_evidence
    if governance_hash:
        payload["governance_hash"] = governance_hash
    return _tracker_request("PATCH", f"/{project_id}/task/{task_id}", payload)


def _checkout_task(project_id: str, task_id: str, provider: str) -> Tuple[int, dict]:
    return _tracker_request(
        "POST",
        f"/{project_id}/task/{task_id}/checkout",
        {"provider": provider},
    )


def _release_task(project_id: str, task_id: str) -> Tuple[int, dict]:
    return _tracker_request("DELETE", f"/{project_id}/task/{task_id}/checkout", {})


def _log_task(
    project_id: str,
    task_id: str,
    description: str,
    provider: Optional[str] = None,
    governance_hash: Optional[str] = None,
) -> Tuple[int, dict]:
    payload: dict = {"description": description}
    if provider:
        payload["provider"] = provider
    if governance_hash:
        payload["governance_hash"] = governance_hash
    return _tracker_request("POST", f"/{project_id}/task/{task_id}/log", payload)


# ---------------------------------------------------------------------------
# Plan tracker API helpers (ENC-FTR-058 Phase 2)
# ---------------------------------------------------------------------------

def _get_plan(project_id: str, plan_id: str) -> Tuple[int, dict]:
    status, body = _tracker_request("GET", f"/{project_id}/plan/{plan_id}")
    if status == 200 and isinstance(body, dict) and isinstance(body.get("record"), dict):
        return status, body["record"]
    return status, body


def _set_plan_field(
    project_id: str,
    plan_id: str,
    field: str,
    value: Any,
    provider: Optional[str] = None,
    transition_evidence: Optional[dict] = None,
    governance_hash: Optional[str] = None,
) -> Tuple[int, dict]:
    payload: dict = {"field": field, "value": value}
    if provider:
        payload["provider"] = provider
    if transition_evidence:
        payload["transition_evidence"] = transition_evidence
    if governance_hash:
        payload["governance_hash"] = governance_hash
    return _tracker_request("PATCH", f"/{project_id}/plan/{plan_id}", payload)


def _checkout_plan(project_id: str, plan_id: str, provider: str) -> Tuple[int, dict]:
    return _tracker_request(
        "POST",
        f"/{project_id}/plan/{plan_id}/checkout",
        {"provider": provider},
    )


def _release_plan(project_id: str, plan_id: str) -> Tuple[int, dict]:
    return _tracker_request("DELETE", f"/{project_id}/plan/{plan_id}/checkout", {})


def _log_plan(
    project_id: str,
    plan_id: str,
    description: str,
    provider: Optional[str] = None,
    governance_hash: Optional[str] = None,
) -> Tuple[int, dict]:
    payload: dict = {"description": description}
    if provider:
        payload["provider"] = provider
    if governance_hash:
        payload["governance_hash"] = governance_hash
    return _tracker_request("POST", f"/{project_id}/plan/{plan_id}/log", payload)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_request(path: str) -> Tuple[int, dict]:
    url = f"{GITHUB_API_BASE}{path}"
    headers = {"User-Agent": "checkout-service/1.0", "Accept": "application/vnd.github+json"}
    token = _get_github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            body = {"error": str(exc)}
        return exc.code, body
    except Exception as exc:
        return 503, {"error": str(exc)}


def _list_installation_repos() -> set:
    """Return a cached set of 'owner/repo' full names accessible to the
    installation, or an empty set on any error.

    ENC-TSK-C68 / ENC-ISS-183: used by _validate_commit to distinguish an
    installation-scope 404 from a missing-commit 404. Paginates through
    /installation/repositories up to 20 pages (2000 repos). Cached for
    _INSTALLATION_REPOS_TTL seconds so we do not hammer GitHub on every
    failing commit validation. Cache is populated lazily on first call after
    expiry; a probe failure returns an empty set so the caller falls back to
    the generic 'commit not found' error rather than masking a real problem
    with a misleading installation-scope message.
    """
    global _installation_repos_cache, _installation_repos_expires_at
    now = time.time()
    if _installation_repos_cache is not None and now < _installation_repos_expires_at:
        return _installation_repos_cache

    try:
        token = _get_installation_token()
    except Exception as exc:
        logger.warning(
            "[ENC-ISS-183] Could not mint installation token for repo scope probe: %s", exc
        )
        return set()

    accessible: set = set()
    page = 1
    while page <= 20:
        url = f"{GITHUB_API_BASE}/installation/repositories?per_page=100&page={page}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "checkout-service/1.0",
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            logger.warning(
                "[ENC-ISS-183] Failed to list installation repos at page=%d: %s", page, exc
            )
            return set()

        repos = data.get("repositories") or []
        for r in repos:
            full = r.get("full_name")
            if full:
                accessible.add(full)
        total = int(data.get("total_count") or 0)
        if not repos or len(accessible) >= total:
            break
        page += 1

    _installation_repos_cache = accessible
    _installation_repos_expires_at = now + _INSTALLATION_REPOS_TTL
    return accessible


def _validate_commit(owner: str, repo: str, commit_sha: str) -> Tuple[bool, str]:
    """Verify commit SHA exists on GitHub. Returns (valid, reason).

    ENC-TSK-C68 / ENC-ISS-183: on a 404 response, probe the GitHub App
    installation's accessible-repositories list to distinguish between:

      1. the commit genuinely not existing in the repo, and
      2. the installation not having access to the repo at all (which GitHub
         surfaces as a bare 404 on /repos/{owner}/{repo}/commits/{sha}).

    When the repo is not in the installation scope, return a descriptive
    self-correcting error pointing at the installation management URL so
    operators do not re-live the original Blocker A confusion where every
    devops-project task stalled at coding-complete with the ambiguous
    "Commit <sha> not found in NX-2021-L/devops" message.
    """
    status, body = _github_request(f"/repos/{owner}/{repo}/commits/{commit_sha}")
    if status == 200:
        return True, ""
    if status == 404:
        full_name = f"{owner}/{repo}"
        accessible = _list_installation_repos()
        if accessible and full_name not in accessible:
            installation_id = GITHUB_INSTALLATION_ID or "<unset>"
            manage_url = (
                f"https://github.com/organizations/{owner}/settings/installations/{installation_id}"
                if installation_id and installation_id != "<unset>"
                else f"https://github.com/organizations/{owner}/settings/installations"
            )
            return False, (
                f"GitHub App 'enceladus-integration' (installation {installation_id}) does not "
                f"have access to {full_name}. The commit {commit_sha} may exist but is not "
                f"visible to the App. Grant access at {manage_url} (Organization Owner required), "
                f"then retry. Currently accessible: {sorted(accessible)}."
            )
        return False, f"Commit {commit_sha} not found in {owner}/{repo}"
    return False, f"GitHub API returned {status}: {body.get('message', 'unknown error')}"


def _validate_pr_merged(
    owner: str, repo: str, pr_id: int, merged_at: str
) -> Tuple[bool, str]:
    """Verify PR is merged and merged_at matches. Returns (valid, reason)."""
    status, body = _github_request(f"/repos/{owner}/{repo}/pulls/{pr_id}")
    if status == 404:
        return False, f"PR #{pr_id} not found in {owner}/{repo}"
    if status != 200:
        return False, f"GitHub API returned {status}: {body.get('message', 'unknown')}"

    api_merged_at = body.get("merged_at")
    if not api_merged_at:
        return False, f"PR #{pr_id} is not merged (merged_at is null)"

    # Normalize timestamps to compare (truncate to minute precision to allow format differences)
    try:
        api_dt = datetime.fromisoformat(api_merged_at.replace("Z", "+00:00"))
        given_dt = datetime.fromisoformat(merged_at.replace("Z", "+00:00"))
        diff_seconds = abs((api_dt - given_dt).total_seconds())
        if diff_seconds > 60:
            return False, (
                f"merged_at mismatch: provided={merged_at}, "
                f"github={api_merged_at} (diff={diff_seconds:.0f}s)"
            )
    except ValueError as exc:
        return False, f"Invalid merged_at timestamp format: {exc}"

    return True, ""


# ---------------------------------------------------------------------------
# Project repo resolution (DVP-ISS-082)
# ---------------------------------------------------------------------------

def _parse_github_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse owner and repo from a GitHub URL like https://github.com/OWNER/REPO."""
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', url)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _resolve_github_repo(project_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the GitHub owner/repo for a project from the projects table.

    Checks the project's ``repo`` field first. If absent and the project has a
    ``parent``, checks the parent (one level only to avoid deep recursion).

    Returns (owner, repo) or (None, None) if unresolvable.
    """
    try:
        resp = _ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="repo, parent",
        )
        item = resp.get("Item")
        if not item:
            return None, None

        repo_url = item.get("repo", {}).get("S", "")
        if repo_url:
            return _parse_github_url(repo_url)

        # Walk up to parent (one level)
        parent_id = item.get("parent", {}).get("S", "")
        if parent_id:
            try:
                resp2 = _ddb.get_item(
                    TableName=PROJECTS_TABLE,
                    Key={"project_id": {"S": parent_id}},
                    ProjectionExpression="repo",
                )
                item2 = resp2.get("Item")
                if item2:
                    repo_url2 = item2.get("repo", {}).get("S", "")
                    if repo_url2:
                        return _parse_github_url(repo_url2)
            except Exception as exc:
                logger.warning("Failed to look up parent project '%s': %s", parent_id, exc)

        # Check children: if this project is a parent of another project that has a repo
        # (e.g., devops is parent of enceladus)
        try:
            scan_resp = _ddb.scan(
                TableName=PROJECTS_TABLE,
                FilterExpression="parent = :pid",
                ExpressionAttributeValues={":pid": {"S": project_id}},
                ProjectionExpression="repo",
            )
            for child in scan_resp.get("Items", []):
                child_repo = child.get("repo", {}).get("S", "")
                if child_repo:
                    return _parse_github_url(child_repo)
        except Exception as exc:
            logger.warning("Failed to scan child projects for '%s': %s", project_id, exc)

        return None, None
    except Exception as exc:
        logger.warning("Failed to resolve GitHub repo for project '%s': %s", project_id, exc)
        return None, None


# ---------------------------------------------------------------------------
# Token management (DynamoDB)
# ---------------------------------------------------------------------------

def _generate_token(token_type: str) -> str:
    """Generate a CAI or CCI token: CAI-{uuid4_hex} or CCI-{uuid4_hex}."""
    return f"{token_type}-{uuid.uuid4().hex}"


def _store_token(
    token_id: str,
    token_type: str,
    task_id: str,
    project_id: str,
) -> None:
    """Store a token → task mapping in DynamoDB for lookup by GitHub Actions."""
    ttl = int(time.time()) + TOKEN_TTL_DAYS * 86400
    try:
        _ddb.put_item(
            TableName=CHECKOUT_TOKENS_TABLE,
            Item={
                "pk": {"S": token_id},
                "token_type": {"S": token_type},
                "task_id": {"S": task_id},
                "project_id": {"S": project_id},
                "created_at": {"S": datetime.now(timezone.utc).isoformat()},
                "ttl": {"N": str(ttl)},
            },
        )
    except ClientError as exc:
        logger.warning("Failed to store token %s: %s", token_id, exc)


def _lookup_token(token_id: str) -> Optional[dict]:
    """Look up a token record. Returns dict or None if not found."""
    try:
        resp = _ddb.get_item(
            TableName=CHECKOUT_TOKENS_TABLE,
            Key={"pk": {"S": token_id}},
        )
        item = resp.get("Item")
        if not item:
            return None
        return {
            "token_id": item["pk"]["S"],
            "token_type": item.get("token_type", {}).get("S"),
            "task_id": item.get("task_id", {}).get("S"),
            "project_id": item.get("project_id", {}).get("S"),
            "created_at": item.get("created_at", {}).get("S"),
        }
    except ClientError as exc:
        logger.warning("Token lookup failed for %s: %s", token_id, exc)
        return None


def _delete_token(token_id: str) -> None:
    """Remove a token from the lookup table (called on deploy-success)."""
    try:
        _ddb.delete_item(
            TableName=CHECKOUT_TOKENS_TABLE,
            Key={"pk": {"S": token_id}},
        )
    except ClientError as exc:
        logger.debug("Token delete failed for %s: %s", token_id, exc)


# ---------------------------------------------------------------------------
# SCI enforcement gate (ENC-ISS-441 Phase 3 / ENC-TSK-J93)
#
# Agent-origin mutations — requests presenting a minted ENC-SES-NNN id as the
# acting identity — must carry a valid Session Claim ID (`sci` in the request
# body). SCI tokens are minted by coordination_api agent.claim (ENC-TSK-J92)
# into CHECKOUT_TOKENS_TABLE alongside CAI/CCI tokens. Non-agent identities
# (github, system:arc-walker, PWA/Cognito users, coordination_dispatch, ...)
# are out of gate scope and pass through unchanged.
# ---------------------------------------------------------------------------

# ENC-ISS-441 Ph3 ship date; sessions created before this instant are
# grandfathered and mutate without an SCI. Deliberately a module-level
# constant, NOT an env var — out-of-band env vars get stripped by full-env
# deploys (PLN-047 / ENC-LSN-053 Sev1 class).
SCI_ENFORCEMENT_EPOCH = "2026-07-02T12:00:00Z"

# ENC-ISS-441 / ENC-TSK-J96: terminal-state retirement nudge (part 3 of the io-designed
# session retirement lifecycle). Injected verbatim into terminal-state success envelopes;
# the acting agent either retires its session autonomously (scope exhausted) or surfaces
# the prompt to io. Exact io-specified text from the ENC-ISS-441 worklog.
RETIREMENT_PROMPT = (
    "Prompt the user if this session can now be retired, or retire the session if it "
    "is certain that the full scope of the current session assignment is complete."
)


def _with_retirement_prompt(envelope: dict, new_status: str, terminal_statuses=("closed",)) -> dict:
    """Inject the ENC-TSK-J96 retirement nudge when a record lands in a final state."""
    if new_status in terminal_statuses:
        envelope["retirement_prompt"] = RETIREMENT_PROMPT
    return envelope

# J92 token shape: pk = "SCI-{uuid4_hex}"
_SCI_TOKEN_RE = re.compile(r"^SCI-[0-9a-f]{32}$")
# I37 minted session ids: ENC-SES-NNN (base-36, uppercase)
_AGENT_SESSION_ID_RE = re.compile(r"^ENC-SES-[0-9A-Z]+$")


def _touch_if_agent_session(provider: Any) -> None:
    """ENC-TSK-L35: best-effort session heartbeat/updated_at bump for a
    session-requiring call whose provider is a minted ENC-SES id.

    Unlike ``_validate_sci_gate`` this performs NO enforcement — it never
    rejects the request and never validates an SCI. It exists so that plan
    checkout/advance/log (which do not run the SCI enforcement gate today)
    still bump the acting session's own updated_at, matching the AC that a
    session record's updated-time bumps on every session-requiring call. Task
    handlers do not need this helper: their SCI gate call already performs the
    (now gate-entry-ordered) touch.
    """
    provider_id = str(provider or "").strip()
    if _AGENT_SESSION_ID_RE.match(provider_id):
        _touch_session_activity(provider_id)

_SCI_REMEDIATION = (
    "Obtain a Session Claim ID via coordination agent.claim (register->claim "
    "handshake, ENC-FTR-117 / ENC-ISS-441) and pass it as 'sci' on this request."
)


def _sci_error(failure_mode: str, message: str) -> dict:
    """Build the 403 rejection envelope for an SCI gate failure (ENC-ISS-441)."""
    logger.warning("[ERROR] SCI gate rejection (%s): %s", failure_mode, message)
    return _error(
        403,
        f"{message} {_SCI_REMEDIATION}",
        code="SCI_REQUIRED",
        details={
            "sci_failure_mode": failure_mode,
            "remediation": _SCI_REMEDIATION,
        },
    )


def _lookup_sci(sci_id: str) -> Optional[dict]:
    """Look up the FULL SCI token item (J92 shape).

    Dedicated helper: _lookup_token returns the partial CAI/CCI dict contract
    consumed by the GitHub Actions gate — extending it would risk those
    callers, so the SCI gate reads the item directly (ENC-TSK-J93).
    """
    try:
        resp = _ddb.get_item(
            TableName=CHECKOUT_TOKENS_TABLE,
            Key={"pk": {"S": sci_id}},
        )
    except ClientError as exc:
        logger.warning("SCI token lookup failed for %s: %s", sci_id, exc)
        return None
    item = resp.get("Item")
    if not item:
        return None
    ttl_raw = item.get("ttl", {}).get("N")
    try:
        ttl_val = int(float(ttl_raw)) if ttl_raw is not None else 0
    except (TypeError, ValueError):
        ttl_val = 0
    return {
        "token_id": item.get("pk", {}).get("S", ""),
        "token_type": item.get("token_type", {}).get("S", ""),
        "session_id": item.get("session_id", {}).get("S", ""),
        "agent_type_id": item.get("agent_type_id", {}).get("S", ""),
        "issued_at": item.get("issued_at", {}).get("S", ""),
        "revoked": bool(item.get("revoked", {}).get("BOOL", False)),
        "ttl": ttl_val,
    }


def _get_agent_session(session_id: str) -> Optional[dict]:
    """Fetch an agent-session record (ENC-FTR-117 store; key session_id)."""
    try:
        resp = _ddb.get_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
        )
    except ClientError as exc:
        logger.warning("Agent-session lookup failed for %s: %s", session_id, exc)
        return None
    item = resp.get("Item")
    if not item:
        return None
    return {
        "session_id": item.get("session_id", {}).get("S", ""),
        "created_at": item.get("created_at", {}).get("S", ""),
        "status": item.get("status", {}).get("S", ""),
    }


def _touch_session_activity(session_id: str) -> None:
    """Refresh the session's last_activity_at + updated_at heartbeat (J83 pattern,
    extended by ENC-TSK-L35 to also stamp ``updated_at`` so the SES record's
    updated-time bumps on every session-requiring call, matching the
    updated_at convention every other tracker record type already exposes).

    Conditional on the session still being live (allocated/claimed); a retired
    or vanished session is a silent no-op — the touch must NEVER fail the
    mutation it rides on (ENC-ISS-441 / ENC-TSK-J93).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        _ddb.update_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
            UpdateExpression="SET last_activity_at = :now, updated_at = :now",
            ConditionExpression=(
                "attribute_exists(session_id) AND (#st = :allocated OR #st = :claimed)"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":now": {"S": now},
                ":allocated": {"S": "allocated"},
                ":claimed": {"S": "claimed"},
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "[INFO] last_activity_at touch skipped for %s (session not live)",
                session_id,
            )
        else:
            logger.warning(
                "[ERROR] last_activity_at touch failed for %s (continuing): %s",
                session_id, exc,
            )
    except Exception as exc:  # noqa: BLE001 — touch is best-effort by contract
        logger.warning(
            "[ERROR] last_activity_at touch failed for %s (continuing): %s",
            session_id, exc,
        )


def _validate_sci_gate(session_id: str, sci: Any) -> Optional[dict]:
    """SCI enforcement gate (ENC-ISS-441 Phase 3 / ENC-TSK-J93).

    Callers invoke this only when ``session_id`` matches _AGENT_SESSION_ID_RE.
    Returns None when the mutation may proceed (grandfathered session or valid
    SCI), else the 403 rejection response naming the specific failure mode.

    ENC-TSK-L35: the session heartbeat (last_activity_at / updated_at) is
    touched unconditionally for every call that reaches this gate — BEFORE the
    grandfather-epoch short-circuit below — so the SES record's updated-time
    bumps on every session-requiring call, not only post-epoch SCI-validated
    ones. (Previously grandfathered sessions were never touched here.)
    """
    # Step 1: the session must exist — a fabricated ENC-SES id must not bypass
    # the gate (fail closed).
    session = _get_agent_session(session_id)
    if session is None:
        return _sci_error(
            "unknown_session",
            f"Agent session '{session_id}' is not a registered session; "
            "mutation rejected (fail-closed).",
        )

    # ENC-TSK-L35: bump the session's own heartbeat/updated_at now, before any
    # further gating, so every session-requiring call is reflected on the SES
    # record regardless of SCI outcome below.
    _touch_session_activity(session_id)

    # Step 2: grandfather epoch gate — sessions created before the Phase 3
    # ship instant pass without an SCI (skip token validation entirely).
    # created_at uses the shared "%Y-%m-%dT%H:%M:%SZ" format, so lexicographic
    # comparison is a correct chronological compare (see agent_id_alloc).
    created_at = str(session.get("created_at") or "").strip()
    if created_at and created_at < SCI_ENFORCEMENT_EPOCH:
        return None

    # Step 3: token validation.
    sci_id = str(sci or "").strip()
    if not sci_id:
        return _sci_error(
            "missing_sci",
            f"Agent session '{session_id}' presented no Session Claim ID (sci); "
            "agent-origin mutations require a valid SCI.",
        )
    if not _SCI_TOKEN_RE.match(sci_id):
        return _sci_error(
            "unknown_sci",
            f"'{sci_id}' is not a valid Session Claim ID "
            "(expected format SCI-{32 hex chars}).",
        )
    token = _lookup_sci(sci_id)
    if token is None:
        return _sci_error(
            "unknown_sci",
            f"Session Claim ID '{sci_id}' is not recognized.",
        )
    if token.get("token_type") != "SCI":
        return _sci_error(
            "wrong_token_type",
            f"Token '{sci_id}' has token_type '{token.get('token_type')}'; "
            "only SCI tokens authorize agent-origin mutations.",
        )
    if token.get("revoked"):
        return _sci_error(
            "revoked_sci",
            f"Session Claim ID '{sci_id}' has been revoked.",
        )
    # DynamoDB native TTL deletion may lag, so also enforce expiry here.
    if int(token.get("ttl") or 0) <= int(time.time()):
        return _sci_error(
            "expired_sci",
            f"Session Claim ID '{sci_id}' has expired.",
        )
    if token.get("session_id") != session_id:
        return _sci_error(
            "session_mismatch",
            f"Session Claim ID '{sci_id}' is bound to session "
            f"'{token.get('session_id')}', not '{session_id}'.",
        )

    # Valid SCI. The heartbeat/updated_at touch already ran at gate entry
    # (ENC-TSK-L35), so no further touch is needed here.
    return None


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_checkout(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../checkout — Atomic checkout + advance to in-progress.

    ENC-TSK-F41 / DOC-546B896390EA §5: every successful invocation of this
    handler increments the task record's server-side checkout_count field by 1.
    The increment is performed atomically by the tracker_mutation Lambda as part
    of the same DynamoDB UpdateExpression that stamps active_agent_session=True
    (see tracker_mutation._handle_update_field, field=active_agent_session,
    checking_out=True branch — appends "ADD checkout_count :one"). This keeps
    the counter colocated with the state transition and removes race-windows
    between checkout and counter bump.

    The checkout_count field is server-side only; tracker.set / tracker.create
    reject direct client writes with HTTP 400 RESERVED_FIELD. Callers must
    treat checkout_count as read-only. It feeds the FTR-076 v2 IMPLEMENTS edge
    immutability gate (designed->development requires checkout_count >= 1).
    """
    provider = (body.get("active_agent_session_id") or "").strip()
    if not provider:
        return _validation_error(
            400,
            "active_agent_session_id is required in request body",
            task_id=task_id,
            target_status="in-progress",
            required_fields=["active_agent_session_id"],
            example_fix=_example_checkout_fix(task_id),
        )

    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate. Agent-origin checkouts
    # (provider is a minted ENC-SES id) must present a valid Session Claim ID
    # BEFORE any state is written (checkout lock, status mutation, CAI token).
    # Non-agent providers (github, coordination_dispatch, PWA users, ...) are
    # out of gate scope and pass through unchanged.
    if _AGENT_SESSION_ID_RE.match(provider):
        sci_err = _validate_sci_gate(provider, body.get("sci"))
        if sci_err:
            return sci_err

    coordination_request_id = body.get("coordination_request_id", "")

    # ENC-TSK-C15 / ENC-ISS-172: Component registry pre-validation.
    # Validate transition_type against component registry BEFORE writing any
    # state (checkout lock, status mutation, CAI token). This surfaces
    # incompatibilities at the earliest enforcement point, before
    # transition_type becomes immutable per ENC-FTR-060.
    pre_status, pre_task = _get_task(project_id, task_id)
    if pre_status != 200:
        return _error(pre_status, pre_task.get("error", f"Task not found: {task_id}"))

    pre_components = pre_task.get("components") or []

    # F42: Opacity model gate (ENC-FTR-076 §7) — runs BEFORE transition_type
    # strictness so OPAQUE components cannot leak existence via 400 mismatch errors.
    if pre_components:
        lifecycle_map = _get_components_lifecycle(pre_components)
        for cid in pre_components:
            entry = lifecycle_map.get(str(cid))
            if not entry:
                continue
            ls = entry.get("lifecycle_status", "")
            if ls in _OPAQUE_LIFECYCLE_STATUSES:
                return _error(404, f"Component '{cid}' not found")
            if ls in _BLOCKED_LIFECYCLE_STATUSES:
                return _validation_error(
                    400,
                    f"Component {cid} is not available for checkout (status: {ls})",
                    task_id=task_id,
                    target_status="in-progress",
                    provider=provider,
                    extra_details={
                        "code": "component_lifecycle_blocked",
                        "component_id": cid,
                        "lifecycle_status": ls,
                    },
                )

    if pre_components:
        pre_transition_type = (pre_task.get("transition_type") or "github_pr_deploy").strip().lower()
        try:
            required_type = _get_required_transition_type(pre_components)
        except ComponentMisconfiguredError as exc:
            return _component_misconfigured_response(exc)
        if required_type is not None:
            task_rank = STRICTNESS_RANK.get(pre_transition_type, 99)
            required_rank = _COMPONENT_POLICY_TASK_MAX_RANK.get(required_type, -1)
            if not _task_transition_satisfies_component_requirement(pre_transition_type, required_type):
                # Identify the specific conflicting component for the error message.
                # F50/AC-3: read required_transition_type, not the legacy transition_type.
                conflicting_component = None
                for cid in pre_components:
                    try:
                        resp = _ddb.get_item(
                            TableName=COMPONENTS_TABLE,
                            Key={"component_id": {"S": str(cid)}},
                        )
                        item = resp.get("Item")
                        if not item:
                            continue
                        raw_comp_type = (
                            item.get("required_transition_type", {}).get("S") or ""
                        ).strip()
                        if not raw_comp_type:
                            # Should be unreachable after _get_required_transition_type
                            # succeeded for this component; skip defensively.
                            continue
                        comp_type = _normalize_component_required_transition_type(raw_comp_type, item)
                        if not _task_transition_satisfies_component_requirement(pre_transition_type, comp_type):
                            conflicting_component = cid
                            break
                    except Exception:
                        continue
                return _validation_error(
                    400,
                    (
                        f"Task transition_type '{pre_transition_type}' (rank {task_rank}) cannot satisfy "
                        f"component required_transition_type '{required_type}' (max task rank {required_rank}) "
                        f"enforced by component '{conflicting_component or pre_components[0]}'. Update "
                        "task.transition_type to a lifecycle arc that produces the required artifact class "
                        "before checking out."
                    ),
                    task_id=task_id,
                    target_status="in-progress",
                    transition_type=pre_transition_type,
                    provider=provider,
                    component_required_transition_type=required_type,
                    extra_details={
                        "task_transition_type": pre_transition_type,
                        "conflicting_component": conflicting_component or pre_components[0],
                        "components": pre_components,
                    },
                    example_fix={
                        "tool": "tracker_set",
                        "arguments": {
                            "record_id": task_id,
                            "field": "transition_type",
                            "value": _recommended_task_transition_for_component_policy(required_type),
                            "governance_hash": "<governance_hash>",
                        },
                    },
                )

    # Step 1: Check out the task (sets active_agent_session=True)
    status, result = _checkout_task(project_id, task_id, provider)
    if status not in (200, 201):
        return _validation_error(
            status,
            result.get("error", f"Checkout failed (HTTP {status})"),
            task_id=task_id,
            target_status="in-progress",
            required_fields=["active_agent_session_id"],
            extra_details={"tracker_response": result},
            example_fix=_example_checkout_fix(task_id),
        )

    # Step 2: Advance status to in-progress
    status2, result2 = _set_task_field(
        project_id, task_id, "status", "in-progress",
        provider=provider,
        governance_hash=result.get("governance_hash"),
    )
    if status2 not in (200, 201):
        # Checkout succeeded but status advance failed — warn but still return success
        logger.warning(
            "Checkout OK for %s/%s but status advance failed: %s", project_id, task_id, result2
        )

    # Step 3: Return current task state
    _, task = _get_task(project_id, task_id)

    # ENC-TSK-B08: Stamp transition_type at checkout time for integrity checking.
    # If the transition_type is later mutated between checkout and advance, the
    # advance will be rejected as a governance integrity violation.
    checkout_transition_type = (task.get("transition_type") or "github_pr_deploy").strip().lower()
    _set_task_field(
        project_id, task_id, "checkout_transition_type", checkout_transition_type,
        provider=provider,
    )

    # ENC-TSK-F41: observe checkout_count on the returned record — this value
    # reflects the atomic increment that tracker_mutation performed as part of
    # the successful checkout UpdateExpression (see tracker_mutation._handle_update_field
    # field=active_agent_session branch). Surface it on the response so callers
    # can verify the FTR-076 v2 counter advanced, and log an observability line
    # so operators can trace counter progression without a second read.
    try:
        checkout_count_val = int(task.get("checkout_count", 0) or 0)
    except (TypeError, ValueError):
        checkout_count_val = 0
    logger.info(
        "checkout.task success project=%s task=%s provider=%s checkout_count=%s",
        project_id, task_id, provider, checkout_count_val,
    )

    return _response(200, {
        "success": True,
        "task": task,
        "checked_out_by": provider,
        "checked_out_at": datetime.now(timezone.utc).isoformat(),
        "coordination_request_id": coordination_request_id or None,
        "checkout_transition_type": checkout_transition_type,
        "checkout_count": checkout_count_val,
    })


def _handle_release(project_id: str, task_id: str, body: dict) -> dict:
    """DELETE .../checkout — Release checkout."""
    status, result = _release_task(project_id, task_id)
    if status not in (200, 201):
        return _error(status, result.get("error", f"Release failed (HTTP {status})"))
    return _response(200, {"success": True, "task_id": task_id})


# ---------------------------------------------------------------------------
# ENC-ISS-092: Transition type lifecycle arcs
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ENC-FTR-059: Transition type constants sourced from canonical matrix v{MATRIX_VERSION}
# Source: transition_type_matrix.py (DOC-B5B807D7C2CE)
# ---------------------------------------------------------------------------
_GITHUB_PR_TYPES = _MATRIX_GITHUB_PR_TYPES
ALLOWED_TRANSITIONS_BY_TYPE: dict = _MATRIX_ALLOWED_TRANSITIONS
VALID_TRANSITION_TYPES: set = _MATRIX_VALID_TYPES

STRICTNESS_RANK: dict = _MATRIX_STRICTNESS_RANK

_TRANSITION_TYPE_SUMMARY: Dict[str, str] = {
    "github_pr_deploy": "Full PR workflow with GitHub Actions deploy evidence.",
    "lambda_deploy": "PR workflow with Lambda update evidence at deploy-success.",
    "web_deploy": "PR workflow with HTTP verification evidence at deploy-success.",
    "code_only": "PR workflow with no deploy stages; close with code_on_main_evidence.",
    "no_code": "No GitHub lifecycle; close with a non-empty no_code_evidence note.",
}

# ---------------------------------------------------------------------------
# ENC-FTR-058 Phase 2: Plan lifecycle constants
# ---------------------------------------------------------------------------

PLAN_ALLOWED_TRANSITIONS: Dict[str, list] = {
    "drafted": ["started"],
    "started": ["complete", "incomplete"],
    "incomplete": ["started"],
}

PLAN_TERMINAL_STATUSES: frozenset = frozenset({
    "closed", "completed", "complete", "archived", "deprecated", "production",
})

_COMMIT_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "commit_sha": {
            "type": "string",
            "format": "40-char lowercase or uppercase hex SHA",
            "description": "Git commit SHA to validate against the configured GitHub repo.",
        },
    },
    "example": {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
}

_MERGED_MAIN_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "pr_id": {
            "type": "integer",
            "description": "GitHub pull request number already merged to main.",
        },
        "merged_at": {
            "type": "string",
            "format": "ISO 8601 datetime with T separator",
            "description": "Exact merged_at timestamp returned by the GitHub API.",
        },
    },
    "example": {
        "pr_id": 123,
        "merged_at": "2026-03-08T22:45:00Z",
    },
}

_DEPLOY_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "source": "GET /repos/{owner}/{repo}/actions/jobs/{job_id}",
    "required_fields": {
        "id": {
            "type": "integer",
            "description": "GitHub Actions job ID.",
        },
        "name": {
            "type": "string",
            "description": "GitHub Actions job name from the Jobs API response.",
        },
        "run_id": {
            "type": "integer",
            "description": "Workflow run ID that owns the job.",
        },
        "head_sha": {
            "type": "string",
            "format": "40-char lowercase hex SHA",
            "description": "Commit SHA the deploy job executed against.",
        },
        "status": {
            "type": "enum",
            "allowed_values": ["completed"],
            "description": "Job status must be completed before it can be accepted as deploy evidence.",
        },
        "conclusion": {
            "type": "enum",
            "allowed_values": ["success"],
            "description": "Only successful GitHub Actions jobs qualify as deploy evidence.",
        },
        "started_at": {
            "type": "string",
            "format": "ISO 8601 datetime with T separator",
            "description": "UTC job start timestamp from the Jobs API response.",
        },
        "completed_at": {
            "type": "string",
            "format": "ISO 8601 datetime with T separator",
            "description": "UTC job completion timestamp from the Jobs API response.",
        },
    },
    "example": {
        "id": 12345678,
        "name": "Deploy checkout service",
        "run_id": 22549608910,
        "head_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-03-01T18:20:00Z",
        "completed_at": "2026-03-01T18:21:57Z",
    },
}

_WEB_DEPLOY_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "url": {
            "type": "string",
            "format": "HTTPS URL",
            "description": "Public URL that was verified after the deploy completed.",
        },
        "http_status": {
            "type": "integer",
            "allowed_values": [200],
            "description": "HTTP status from the verification request.",
        },
        "checked_at": {
            "type": "string",
            "format": "ISO 8601 datetime with T separator",
            "description": "UTC timestamp when the verification request was performed.",
        },
    },
    "optional_fields": {
        "cloudfront_invalidation_id": {
            "type": "string",
            "description": "Optional CloudFront invalidation ID for the release.",
        },
        "response_time_ms": {
            "type": "integer",
            "description": "Optional latency measurement for the verification request.",
        },
    },
    "example": {
        "url": "https://jreese.net/enceladus",
        "http_status": 200,
        "checked_at": "2026-03-08T22:45:00Z",
    },
}

_LAMBDA_DEPLOY_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "function_name": {
            "type": "string",
            "description": "Lambda function name that was updated.",
        },
        "version": {
            "type": "string",
            "description": "Published or live version identifier after the deploy.",
        },
        "updated_at": {
            "type": "string",
            "format": "ISO 8601 datetime with T separator",
            "description": "UTC timestamp when the Lambda update completed.",
        },
        "status": {
            "type": "enum",
            "allowed_values": ["Success"],
            "description": "Deployment status string required by the lambda_deploy gate.",
        },
    },
    "example": {
        "function_name": "devops-tracker-mutation-api",
        "version": "42",
        "updated_at": "2026-03-08T22:45:00Z",
        "status": "Success",
    },
}

_LIVE_VALIDATION_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "live_validation_evidence": {
            "type": "string",
            "format": "non-empty string",
            "description": "Describe how the deployed change was confirmed live, ideally with the SPEC-ID or URL checked.",
        },
    },
    "example": {
        "live_validation_evidence": "SPEC-20260308T224500 verified via Cognito-authenticated PWA smoke test.",
    },
}

_CODE_ON_MAIN_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "commit_sha": {
            "type": "string",
            "format": "40-char lowercase or uppercase hex SHA",
            "description": "Commit that must already be reachable from main.",
        },
    },
    "example": {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
}

_NO_CODE_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "no_code_evidence": {
            "type": "string",
            "format": "non-empty string",
            "description": "Human-readable audit note describing what changed and how it was verified.",
        },
    },
    "example": {
        "no_code_evidence": "Updated governance metadata and confirmed the new rules are visible to agents.",
    },
}

_EXTERNAL_DEPLOY_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "comp_external_id": {
            "type": "string",
            "format": "non-empty string",
            "description": "Stable identifier retrieved from the external system for the live component resource.",
        },
        "retrieval_steps": {
            "type": "string",
            "format": "non-empty string, minimum 20 characters",
            "description": "Concrete steps a future operator can follow to re-retrieve comp_external_id.",
        },
    },
    "example": {
        "external_deploy_evidence": {
            "comp_external_id": "90df28c1",
            "retrieval_steps": "Open the external console, select the production resource, and copy its instance identifier from the details panel.",
        }
    },
}

_DOCUMENTATION_EVIDENCE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required_fields": {
        "documentation_evidence": {
            "type": "array[string]",
            "format": "non-empty DOC-* identifiers",
            "description": "At least one DOC id must resolve to an extant document and be novel or fresh at close.",
        },
    },
    "close_gate": {
        "fresh_window_minutes": 15,
        "novel": "not referenced by another closed task's documentation_evidence",
        "fresh": "document.updated_at is within 15 minutes of the close attempt",
    },
    "example": {"documentation_evidence": ["DOC-EDEFF7CD0BD5"]},
}


def _ordered_transition_types() -> list[str]:
    return sorted(VALID_TRANSITION_TYPES, key=lambda name: (STRICTNESS_RANK.get(name, 99), name))


def _strictness_rank_table() -> list[Dict[str, Any]]:
    return [
        {
            "transition_type": name,
            "rank": STRICTNESS_RANK[name],
            "summary": _TRANSITION_TYPE_SUMMARY.get(name, ""),
        }
        for name in _ordered_transition_types()
    ]


def _required_evidence_schema(transition_type: str, target_status: str) -> Optional[Dict[str, Any]]:
    if target_status == "committed":
        return _COMMIT_EVIDENCE_SCHEMA
    if target_status == "merged-main":
        return _MERGED_MAIN_EVIDENCE_SCHEMA
    if target_status == "deploy-success":
        if transition_type == "web_deploy":
            return _WEB_DEPLOY_EVIDENCE_SCHEMA
        if transition_type == "lambda_deploy":
            return _LAMBDA_DEPLOY_EVIDENCE_SCHEMA
        return _DEPLOY_EVIDENCE_SCHEMA
    if target_status == "closed":
        if transition_type in ("github_pr_deploy", "web_deploy", "lambda_deploy"):
            return _LIVE_VALIDATION_EVIDENCE_SCHEMA
        if transition_type == "code_only":
            return _CODE_ON_MAIN_EVIDENCE_SCHEMA
        if transition_type == "no_code":
            return _NO_CODE_EVIDENCE_SCHEMA
    return None


def _example_checkout_fix(task_id: str) -> list[Dict[str, Any]]:
    return [
        {
            "tool": "tracker_set",
            "arguments": {
                "record_id": task_id,
                "field": "components",
                "value": [
                    "comp-checkout-service",
                    "comp-tracker-mutation",
                    "comp-coordination-api",
                ],
                "governance_hash": "<governance_hash>",
            },
        },
        {
            "tool": "tracker_set",
            "arguments": {
                "record_id": task_id,
                "field": "transition_type",
                "value": "github_pr_deploy",
                "governance_hash": "<governance_hash>",
            },
        },
        {
            "tool": "checkout_task",
            "arguments": {
                "record_id": task_id,
                "active_agent_session_id": "<agent-session-id>",
                "governance_hash": "<governance_hash>",
            },
        },
    ]


def _example_advance_fix(
    task_id: str,
    target_status: str,
    provider: str,
    transition_type: str,
) -> Dict[str, Any]:
    args: Dict[str, Any] = {
        "record_id": task_id,
        "target_status": target_status,
        "provider": provider or "<provider>",
        "governance_hash": "<governance_hash>",
    }
    schema = _required_evidence_schema(transition_type, target_status)
    if schema and schema.get("example"):
        args["transition_evidence"] = schema["example"]
    return {"tool": "advance_task_status", "arguments": args}


def _validation_error(
    status: int,
    message: str,
    *,
    task_id: str = "",
    current_status: str = "",
    target_status: str = "",
    transition_type: str = "",
    provider: str = "",
    required_fields: Optional[list[str]] = None,
    component_required_transition_type: str = "",
    extra_details: Optional[Dict[str, Any]] = None,
    example_fix: Optional[Any] = None,
) -> dict:
    details: Dict[str, Any] = {
        "task_id": task_id or None,
        "current_status": current_status or None,
        "target_status": target_status or None,
        "transition_type": transition_type or None,
        "allowed_transition_types": _ordered_transition_types(),
        "strictness_rank": _strictness_rank_table(),
    }
    if transition_type:
        details["valid_next_statuses"] = ALLOWED_TRANSITIONS_BY_TYPE.get(transition_type, [])
    schema = _required_evidence_schema(transition_type or "github_pr_deploy", target_status)
    if schema is not None:
        details["required_evidence_schema"] = schema
    if required_fields:
        details["required_fields"] = required_fields
    if component_required_transition_type:
        details["component_required_transition_type"] = component_required_transition_type
    if example_fix is None and task_id and target_status:
        example_fix = _example_advance_fix(
            task_id,
            target_status,
            provider or "<provider>",
            transition_type or "github_pr_deploy",
        )
    if example_fix is not None:
        details["example_fix"] = example_fix
    if extra_details:
        details.update(extra_details)
    clean_details = {
        key: value
        for key, value in details.items()
        if value not in (None, "", [], {})
    }
    return _error(status, message, details=clean_details)

#: ENC-ISS-106: Numeric rank for lifecycle stages. Used to enforce that parent tasks
#: cannot advance past a stage until all children have reached that stage.
#: Higher rank = further along the lifecycle.
STATUS_RANK: dict = {
    "open": 0,
    "in-progress": 1,
    "coding-complete": 2,
    "committed": 3,
    "pr": 4,
    "merged-main": 5,
    "deploy-init": 6,
    "deploy-success": 7,
    "closed": 8,
    # ENC-TSK-I07 (Dedup P3): `superseded` is an alternate terminal state (soft
    # duplicate collapse, DOC-DF651F07D5C2 §7). Same rank as `closed` so a
    # superseded child satisfies any subtask gate and a superseded task is
    # treated as furthest-along/terminal (non-advanceable).
    "superseded": 8,
}

#: ENC-ISS-106: Minimum status rank at which the subtask gate activates.
#: Statuses below this threshold (open, in-progress) are not gated because
#: a parent must be checked out (in-progress) before it can orchestrate children.
_SUBTASK_GATE_MIN_RANK: int = STATUS_RANK["coding-complete"]  # 2


def _validate_web_deploy_evidence(evidence: dict) -> Tuple[bool, str]:
    """Validate web_deploy_evidence structure for deploy-success (ENC-ISS-092).

    Does NOT re-fetch the URL — agent provides evidence, Lambda validates shape.
    Required fields: url (HTTPS), http_status (== 200), checked_at (ISO 8601 with T).
    Optional: cloudfront_invalidation_id, response_time_ms.
    """
    url = (evidence.get("url") or "").strip()
    if not url:
        return False, "web_deploy_evidence.url is required"
    if not url.startswith("https://"):
        return False, f"web_deploy_evidence.url must start with https://, got: '{url}'"

    http_status = evidence.get("http_status")
    if http_status is None:
        return False, "web_deploy_evidence.http_status is required"
    if http_status != 200:
        return False, f"web_deploy_evidence.http_status must be 200, got: {http_status}"

    checked_at = (evidence.get("checked_at") or "").strip()
    if not checked_at:
        return False, "web_deploy_evidence.checked_at is required"
    if "T" not in checked_at:
        return False, (
            f"web_deploy_evidence.checked_at must be ISO 8601 with 'T' separator, "
            f"got: '{checked_at}'"
        )
    try:
        datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError as exc:
        return False, f"web_deploy_evidence.checked_at is not a valid ISO 8601 timestamp: {exc}"

    return True, ""


def _validate_github_actions_deploy_evidence(evidence: dict) -> Tuple[bool, str]:
    """Validate GitHub Actions Jobs API deploy evidence for github_pr_deploy tasks."""
    if not evidence:
        return False, "transition_evidence.deploy_evidence is required"
    if not isinstance(evidence, dict):
        return False, "transition_evidence.deploy_evidence must be a JSON object"

    required_fields = [
        "id",
        "name",
        "run_id",
        "head_sha",
        "status",
        "conclusion",
        "started_at",
        "completed_at",
    ]
    missing = [field for field in required_fields if not evidence.get(field)]
    if missing:
        return False, f"deploy_evidence missing required fields: {missing}"

    head_sha = str(evidence.get("head_sha") or "").strip()
    if not re.match(r"^[0-9a-f]{40}$", head_sha.lower()):
        return False, (
            "deploy_evidence.head_sha must be a 40-char hex SHA, "
            f"got: '{evidence.get('head_sha')}'"
        )

    status = str(evidence.get("status") or "").strip().lower()
    if status != "completed":
        return False, (
            "deploy_evidence.status must be 'completed', "
            f"got: '{evidence.get('status')}'"
        )

    conclusion = str(evidence.get("conclusion") or "").strip().lower()
    if conclusion != "success":
        return False, (
            "deploy_evidence.conclusion must be 'success', "
            f"got: '{evidence.get('conclusion')}'"
        )

    for field_name in ("started_at", "completed_at"):
        field_value = str(evidence.get(field_name) or "").strip()
        if "T" not in field_value:
            return False, (
                f"deploy_evidence.{field_name} must be ISO 8601 with 'T' separator, "
                f"got: '{field_value}'"
            )
        try:
            datetime.fromisoformat(field_value.replace("Z", "+00:00"))
        except ValueError as exc:
            return False, (
                f"deploy_evidence.{field_name} is not a valid ISO 8601 timestamp: {exc}"
            )

    return True, ""


def _validate_lambda_deploy_evidence(evidence: dict) -> Tuple[bool, str]:
    """Validate lambda_deploy_evidence structure for deploy-success (ENC-FTR-041).

    Required fields: function_name (str), version (str), updated_at (ISO 8601 with T),
    status (must equal 'Success').
    """
    function_name = (evidence.get("function_name") or "").strip()
    if not function_name:
        return False, "lambda_deploy_evidence.function_name is required"

    version = (evidence.get("version") or "").strip()
    if not version:
        return False, "lambda_deploy_evidence.version is required"

    updated_at = (evidence.get("updated_at") or "").strip()
    if not updated_at:
        return False, "lambda_deploy_evidence.updated_at is required"
    if "T" not in updated_at:
        return False, (
            f"lambda_deploy_evidence.updated_at must be ISO 8601 with 'T' separator, "
            f"got: '{updated_at}'"
        )
    try:
        datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        return False, f"lambda_deploy_evidence.updated_at is not a valid ISO 8601 timestamp: {exc}"

    status = (evidence.get("status") or "").strip()
    if not status:
        return False, "lambda_deploy_evidence.status is required"
    if status != "Success":
        return False, f"lambda_deploy_evidence.status must be 'Success', got: '{status}'"

    return True, ""


def _validate_code_on_main_evidence(
    owner: str, repo: str, evidence: dict
) -> Tuple[bool, str]:
    """Validate code_on_main_evidence for closed (code_only arc, ENC-ISS-092).

    Calls GitHub compare API to verify commit_sha is an ancestor of main.
    Sets evidence["github_verified"] = True on success.
    """
    commit_sha = (evidence.get("commit_sha") or "").strip()
    if not commit_sha:
        return False, "code_on_main_evidence.commit_sha is required"
    if not re.match(r'^[0-9a-f]{40}$', commit_sha.lower()):
        return False, (
            f"code_on_main_evidence.commit_sha must be a 40-char hex string, "
            f"got: '{commit_sha}'"
        )

    # Call GitHub compare API: {sha}...main (base=sha, head=main)
    # ENC-ISS-161: status "ahead" means main has commits sha doesn't = sha is an ancestor.
    # status "identical" means sha IS main HEAD. Both are valid.
    compare_path = f"/repos/{owner}/{repo}/compare/{commit_sha}...main"
    status, body = _github_request(compare_path)
    if status == 404:
        return False, (
            f"GitHub compare returned 404 — commit '{commit_sha}' or repo "
            f"'{owner}/{repo}' not found"
        )
    if status != 200:
        return False, (
            f"GitHub compare API returned {status}: "
            f"{body.get('message', 'unknown error')}"
        )

    compare_status = body.get("status", "")
    if compare_status not in ("ahead", "identical"):
        return False, (
            f"Commit '{commit_sha}' is not on main "
            f"(GitHub compare status: '{compare_status}'). "
            "Commit must be an ancestor of main (status 'ahead' or 'identical')."
        )

    # Stamp verification flag for audit trail
    evidence["github_verified"] = True
    return True, ""


def _validate_external_deploy_evidence(evidence: Any) -> Tuple[bool, str]:
    if not evidence or not isinstance(evidence, dict):
        return False, "transition_evidence.external_deploy_evidence must be a JSON object"
    comp_external_id = evidence.get("comp_external_id")
    if not isinstance(comp_external_id, str) or not comp_external_id.strip():
        return False, "external_deploy_evidence.comp_external_id is required and must be a non-empty string"
    retrieval_steps = evidence.get("retrieval_steps")
    if not isinstance(retrieval_steps, str) or not retrieval_steps.strip():
        return False, "external_deploy_evidence.retrieval_steps is required and must be a non-empty string"
    if len(retrieval_steps.strip()) < 20:
        return False, "external_deploy_evidence.retrieval_steps must be at least 20 characters"
    evidence["comp_external_id"] = comp_external_id.strip()
    evidence["retrieval_steps"] = retrieval_steps.strip()
    return True, ""


_DOC_ID_RE = re.compile(r"^DOC-[0-9A-F]+$")
_DOCUMENTATION_FRESH_WINDOW_SECONDS = 15 * 60


def _parse_documentation_evidence(raw: Any) -> Tuple[list[str], Optional[str]]:
    if not isinstance(raw, list) or not raw:
        return [], "documentation_evidence must be a non-empty array of DOC-* strings"
    doc_ids: list[str] = []
    for value in raw:
        if not isinstance(value, str) or not value.strip():
            return [], "documentation_evidence entries must be non-empty strings"
        doc_id = value.strip().upper()
        if not _DOC_ID_RE.match(doc_id):
            return [], f"documentation_evidence entry '{value}' must match DOC-*"
        doc_ids.append(doc_id)
    return doc_ids, None


def _parse_jsonish_evidence(raw: Any) -> Any:
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
    return raw


def _extract_documentation_evidence_doc_ids(record: Dict[str, Any]) -> set[str]:
    doc_ids: set[str] = set()
    candidates = [
        record.get("documentation_evidence"),
        record.get("transition_evidence"),
    ]
    for candidate in candidates:
        parsed = _parse_jsonish_evidence(candidate)
        if isinstance(parsed, dict):
            parsed = parsed.get("documentation_evidence")
        if isinstance(parsed, list):
            ids, err = _parse_documentation_evidence(parsed)
            if not err:
                doc_ids.update(ids)
    return doc_ids


def _closed_documentation_evidence_doc_ids(project_id: str, current_task_id: str) -> set[str]:
    used: set[str] = set()
    cursor = ""
    for _ in range(25):
        path = f"/{project_id}?type=task&status=closed&page_size=200"
        if cursor:
            path += "&next_cursor=" + urllib.parse.quote(cursor, safe="")
        status, body = _tracker_request("GET", path)
        if status != 200:
            raise RuntimeError(body.get("error", f"tracker list failed with HTTP {status}"))
        for record in body.get("records") or body.get("items") or []:
            if not isinstance(record, dict):
                continue
            rid = str(record.get("id") or record.get("record_id") or record.get("task_id") or "").strip()
            if rid == current_task_id:
                continue
            used.update(_extract_documentation_evidence_doc_ids(record))
        cursor = str(body.get("next_cursor") or "").strip()
        if not cursor:
            break
    return used


def _get_document_metadata(doc_id: str) -> Tuple[int, Dict[str, Any]]:
    status, body = _document_api_request("GET", f"/{doc_id}")
    if status != 200:
        return status, body
    if isinstance(body.get("document"), dict):
        return status, body["document"]
    return status, body if isinstance(body, dict) else {}


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_documentation_close_evidence(
    *,
    project_id: str,
    task_id: str,
    evidence: Any,
    now: Optional[datetime] = None,
) -> Tuple[bool, str, Dict[str, Any], list[str]]:
    doc_ids, err = _parse_documentation_evidence(evidence)
    if err:
        return False, err, {"required_evidence_schema": _DOCUMENTATION_EVIDENCE_SCHEMA}, []

    now_dt = now or datetime.now(timezone.utc)
    try:
        previously_used = _closed_documentation_evidence_doc_ids(project_id, task_id)
    except Exception as exc:
        return (
            False,
            f"documentation_evidence novelty check failed: {exc}",
            {"policy": "P7 novelty-or-freshness close gate"},
            doc_ids,
        )

    details: Dict[str, Any] = {
        "policy": "P7 documentation close gate: at least one DOC id must be novel or fresh.",
        "fresh_window_minutes": 15,
        "doc_results": [],
    }
    qualifying: list[str] = []
    non_qualifying: list[str] = []
    for doc_id in doc_ids:
        status, doc = _get_document_metadata(doc_id)
        if status != 200:
            details["doc_results"].append({
                "document_id": doc_id,
                "qualifies": False,
                "reason": f"document lookup returned HTTP {status}",
            })
            non_qualifying.append(doc_id)
            continue
        updated_at = _parse_iso_datetime(doc.get("updated_at"))
        is_fresh = (
            updated_at is not None
            and 0 <= (now_dt - updated_at).total_seconds() <= _DOCUMENTATION_FRESH_WINDOW_SECONDS
        )
        is_novel = doc_id not in previously_used
        qualifies = is_novel or is_fresh
        if qualifies:
            qualifying.append(doc_id)
        else:
            non_qualifying.append(doc_id)
        details["doc_results"].append({
            "document_id": doc_id,
            "qualifies": qualifies,
            "novel": is_novel,
            "fresh": is_fresh,
            "updated_at": doc.get("updated_at", ""),
        })

    details["qualifying_doc_ids"] = qualifying
    details["non_qualifying_doc_ids"] = non_qualifying
    if not qualifying:
        return (
            False,
            "documentation_evidence close gate failed: at least one DOC id must be novel or fresh.",
            details,
            doc_ids,
        )
    return True, "", details, doc_ids


# ---------------------------------------------------------------------------
# ENC-FTR-059: Matrix-driven deploy-success validator registry
# Maps transition_type → validator function for deploy-success evidence.
# A new transition_type that reuses an existing evidence shape just references
# the same validator — no new code needed.
# ---------------------------------------------------------------------------
_DEPLOY_SUCCESS_VALIDATORS: Dict[str, Any] = {
    "github_pr_deploy": _validate_github_actions_deploy_evidence,
    "lambda_deploy": _validate_lambda_deploy_evidence,
    "web_deploy": _validate_web_deploy_evidence,
}


# ---------------------------------------------------------------------------
# ENC-ISS-106: Subtask lifecycle gate
# ---------------------------------------------------------------------------


def _validate_subtask_gate(
    project_id: str,
    task_id: str,
    task: dict,
    target_status: str,
) -> Optional[dict]:
    """Enforce that parent tasks cannot advance lifecycle stages unless all
    direct children have reached at least that stage.

    Returns ``None`` if validation passes (or gate does not apply).
    Returns an ``_error()`` response dict if validation fails.

    Gate applies from coding-complete onward. Skipped for:
      - Tasks with empty/missing subtask_ids (not a parent task)
      - Target statuses below the gate threshold (open, in-progress)

    Children with shortened arcs (e.g. no_code at 'closed') are handled
    correctly because 'closed' has rank 8, which satisfies any target rank.
    """
    subtask_ids = task.get("subtask_ids") or []
    if not subtask_ids:
        return None

    target_rank = STATUS_RANK.get(target_status)
    if target_rank is None or target_rank < _SUBTASK_GATE_MIN_RANK:
        return None

    lagging: list = []
    for child_id in subtask_ids:
        child_id = str(child_id).strip()
        if not child_id:
            continue
        child_status_code, child_task = _get_task(project_id, child_id)
        if child_status_code != 200:
            lagging.append((child_id, "not_found"))
            continue
        child_current = (child_task.get("status") or "unknown").strip().lower()
        child_rank = STATUS_RANK.get(child_current, -1)
        if child_rank < target_rank:
            lagging.append((child_id, child_current))

    if not lagging:
        return None

    detail_lines = [f"  - {cid} ({cstatus})" for cid, cstatus in lagging[:20]]
    if len(lagging) > 20:
        detail_lines.append(f"  ... and {len(lagging) - 20} more")
    return _validation_error(
        400,
        (
            f"Cannot advance {task_id} to '{target_status}': "
            f"{len(lagging)} child task(s) have not reached this stage "
            f"(ENC-ISS-106):\n"
            + "\n".join(detail_lines)
            + f"\nAdvance all child tasks to '{target_status}' or beyond "
            f"before advancing the parent."
        ),
        task_id=task_id,
        current_status=(task.get("status") or "").strip().lower(),
        target_status=target_status,
        transition_type=(task.get("transition_type") or "github_pr_deploy").strip().lower(),
        extra_details={
            "lagging_subtasks": [
                {"task_id": cid, "status": cstatus}
                for cid, cstatus in lagging
            ],
        },
    )


# ---------------------------------------------------------------------------
# ENC-FTR-041: Component registry enforcement helpers
# DOC-157A790F9E8B v3: component.required_transition_type is now the component
# policy enum {code, external_deploy, documentation}. Task.transition_type keeps
# the existing lifecycle-arc enum in transition_type_matrix.py. This layer maps
# legacy component rows at read time, then checks whether the task arc can
# produce the artifact class required by the component policy.
# ---------------------------------------------------------------------------

_COMPONENT_REQUIRED_TRANSITION_TYPES = frozenset({
    "code",
    "external_deploy",
    "documentation",
})
_LEGACY_COMPONENT_REQUIRED_TRANSITION_TYPE_MAP = {
    "github_pr_deploy": "code",
    "lambda_deploy": "code",
    "web_deploy": "code",
    "code_only": "code",
    "data_only": "code",
}
_COMPONENT_POLICY_TASK_MAX_RANK = {
    # Code components may use any code-producing lifecycle arc, including
    # code_only. no_code remains too weak because it produces no repo artifact.
    "code": STRICTNESS_RANK["code_only"],
    # External deploy components need a deploy-success stage for P6 evidence.
    "external_deploy": STRICTNESS_RANK["web_deploy"],
    # Documentation components are satisfied by any task arc, but receive the
    # P7 doc-evidence close gate below when the policy is present.
    "documentation": STRICTNESS_RANK["no_code"],
}
_COMPONENT_POLICY_ORDER = {
    name: rank for name, rank in sorted(
        _COMPONENT_POLICY_TASK_MAX_RANK.items(),
        key=lambda item: (item[1], item[0]),
    )
}


def _component_looks_documentation_authored(item: Dict[str, Any]) -> bool:
    address_class = (item.get("component_address_class", {}).get("S") or "").strip().lower()
    component_class = (item.get("component_class", {}).get("S") or "").strip().lower()
    address = (item.get("component_address", {}).get("S") or "").strip().lower()
    repo_dir = (item.get("component_repo_dir", {}).get("S") or "").strip().lower()
    return (
        address_class == "meta"
        or component_class == "meta"
        or address.startswith("meta:")
        or repo_dir.startswith("meta:")
    )


def _normalize_component_required_transition_type(raw_value: str, item: Optional[Dict[str, Any]] = None) -> str:
    value = (raw_value or "").strip().lower()
    if value in _COMPONENT_REQUIRED_TRANSITION_TYPES:
        return value
    if value == "no_code":
        return "documentation" if _component_looks_documentation_authored(item or {}) else "code"
    return _LEGACY_COMPONENT_REQUIRED_TRANSITION_TYPE_MAP.get(value, "")


def _task_transition_satisfies_component_requirement(
    task_transition_type: str,
    required_policy: str,
) -> bool:
    task_rank = STRICTNESS_RANK.get(task_transition_type, 99)
    return task_rank <= _COMPONENT_POLICY_TASK_MAX_RANK.get(required_policy, -1)


def _recommended_task_transition_for_component_policy(required_policy: str) -> str:
    if required_policy == "external_deploy":
        return "github_pr_deploy"
    if required_policy == "documentation":
        return "no_code"
    return "code_only"


class ComponentMisconfiguredError(Exception):
    """Raised when a component record is missing `required_transition_type`
    or carries an invalid enum value.

    F50/AC-3 and F50/AC-4: the previous silent-default behavior
    (``github_pr_deploy`` when ``transition_type`` was absent) is replaced
    with a first-class invariant violation surfaced through the standard
    ``api.error_envelope`` contract. Callers should translate this
    exception into an HTTP 500 response via
    :func:`_component_misconfigured_response`.
    """

    def __init__(
        self,
        component_id: str,
        *,
        reason: str = "missing",
        bad_value: Optional[str] = None,
    ) -> None:
        self.component_id = component_id
        self.reason = reason  # "missing" or "invalid_value"
        self.bad_value = bad_value
        if reason == "invalid_value":
            message = (
                f"Component '{component_id}' has invalid required_transition_type="
                f"'{bad_value}'; expected one of code|external_deploy|documentation "
                "or a recognized legacy value for read-time migration. Contact platform admin."
            )
        else:
            message = (
                f"Component '{component_id}' is missing required_transition_type; "
                "this is an invariant violation. Contact platform admin."
            )
        super().__init__(message)


def _component_misconfigured_response(exc: ComponentMisconfiguredError) -> dict:
    """Translate :class:`ComponentMisconfiguredError` into the standard
    ``api.error_envelope`` shape (ENC-TSK-D56).

    The envelope carries component_id, remediation_url, and remediation
    guidance sufficient for an agent to self-correct on the next attempt
    without additional tool calls (F50/AC-4).
    """
    remediation_url = f"https://jreese.net/components/{exc.component_id}"
    details: Dict[str, Any] = {
        "component_id": exc.component_id,
        "reason": exc.reason,
        "remediation_url": remediation_url,
        "remediation_guidance": (
            "Set the component's `required_transition_type` in the registry "
            "(DynamoDB enceladus-component-registry) via the PWA /components "
            "edit surface or via a product-lead terminal update-item. V3 valid "
            "values: code|external_deploy|documentation. "
            "After the field is populated, retry the checkout."
        ),
        "rule_citation": (
            "ENC-TSK-L77 / DOC-157A790F9E8B (v3 component hardening)"
        ),
    }
    if exc.bad_value is not None:
        details["invalid_value"] = exc.bad_value
    return _error(
        500,
        str(exc),
        code="COMPONENT_MISCONFIGURED",
        retryable=False,
        details=details,
    )


# F42: Opacity model (ENC-FTR-076 §7). Mirrors coordination_api constants.
_OPAQUE_LIFECYCLE_STATUSES = frozenset({"archived"})
_BLOCKED_LIFECYCLE_STATUSES = frozenset({"proposed", "deprecated"})


def _get_required_transition_type(component_ids: list) -> Optional[str]:
    """Return the most restrictive v3 component policy across component IDs.

    DOC-157A790F9E8B / ENC-TSK-L77: reads the governed
    ``required_transition_type`` field and normalizes legacy component enum
    values at read time. Missing values still fail loud; the compatibility path
    is for existing populated rows, not silent fallback.

    Missing components (component_id absent from the registry entirely)
    continue to fail-open with a WARNING log, preserving the ENC-FTR-041
    behavior for unknown IDs so a stale task.components entry does not hard
    block every downstream call.

    Returns None when ``component_ids`` is empty.
    """
    if not component_ids:
        return None
    min_rank = 99
    required: Optional[str] = None
    for cid in component_ids:
        try:
            resp = _ddb.get_item(
                TableName=COMPONENTS_TABLE,
                Key={"component_id": {"S": str(cid)}},
            )
            item = resp.get("Item")
            if not item:
                logger.warning(
                    "[FTR-041] Component '%s' not found in registry; skipping enforcement", cid
                )
                continue
            required_attr = item.get("required_transition_type") or {}
            raw_comp_type = (required_attr.get("S") or "").strip()
            if not raw_comp_type:
                logger.error(
                    "[F50/AC-3] Component '%s' is missing required_transition_type "
                    "in the registry (see DOC-157A790F9E8B for governance contract)",
                    cid,
                )
                raise ComponentMisconfiguredError(cid, reason="missing")
            comp_type = _normalize_component_required_transition_type(raw_comp_type, item)
            if comp_type not in _COMPONENT_REQUIRED_TRANSITION_TYPES:
                logger.error(
                    "[F50/AC-3] Component '%s' has invalid required_transition_type='%s' "
                    "(not in v3 enum and not a recognized legacy value)",
                    cid, raw_comp_type,
                )
                raise ComponentMisconfiguredError(
                    cid, reason="invalid_value", bad_value=raw_comp_type
                )
            rank = _COMPONENT_POLICY_TASK_MAX_RANK[comp_type]
            if rank < min_rank:
                min_rank = rank
                required = comp_type
        except ComponentMisconfiguredError:
            raise
        except Exception as exc:
            logger.error("[FTR-041] Failed to fetch component '%s': %s", cid, exc)
    return required


def _get_component_required_transition_types(component_ids: list) -> set[str]:
    """Return all normalized v3 component policies present on the task."""
    policies: set[str] = set()
    if not component_ids:
        return policies
    for cid in component_ids:
        try:
            resp = _ddb.get_item(
                TableName=COMPONENTS_TABLE,
                Key={"component_id": {"S": str(cid)}},
            )
            item = resp.get("Item")
            if not item:
                continue
            required_attr = item.get("required_transition_type") or {}
            raw_comp_type = (required_attr.get("S") or "").strip()
            if not raw_comp_type:
                raise ComponentMisconfiguredError(cid, reason="missing")
            comp_type = _normalize_component_required_transition_type(raw_comp_type, item)
            if comp_type not in _COMPONENT_REQUIRED_TRANSITION_TYPES:
                raise ComponentMisconfiguredError(
                    cid, reason="invalid_value", bad_value=raw_comp_type
                )
            policies.add(comp_type)
        except ComponentMisconfiguredError:
            raise
        except Exception as exc:
            logger.error("[FTR-041] Failed to fetch component '%s': %s", cid, exc)
    return policies


def _get_components_lifecycle(component_ids: list) -> Dict[str, Dict[str, str]]:
    """Fetch per-component lifecycle metadata for the FTR-076 / E10 gate.

    Returns a dict keyed by component_id with sub-dicts containing
    `lifecycle_status` and (when present) `rejection_reason`. Components
    not found in the registry are omitted (matching the fail-open posture
    of `_get_required_transition_type` for missing-component cases).
    Components without a `lifecycle_status` attribute (pre-FTR-076 records
    that escaped the E12 backfill) are reported as `lifecycle_status='active'`
    so the gate treats them as the historical default.
    """
    out: Dict[str, Dict[str, str]] = {}
    if not component_ids:
        return out
    for cid in component_ids:
        try:
            resp = _ddb.get_item(
                TableName=COMPONENTS_TABLE,
                Key={"component_id": {"S": str(cid)}},
            )
            item = resp.get("Item")
            if not item:
                logger.warning(
                    "[FTR-076] Component '%s' not found in registry; skipping lifecycle gate", cid
                )
                continue
            ls = item.get("lifecycle_status", {}).get("S", "active")
            entry: Dict[str, str] = {"lifecycle_status": ls}
            rr = item.get("rejection_reason", {}).get("S", "")
            if rr:
                entry["rejection_reason"] = rr
            out[str(cid)] = entry
        except Exception as exc:
            logger.error("[FTR-076] Failed to fetch component '%s' lifecycle: %s", cid, exc)
    return out


def _get_component_transition_type(component_id: str) -> str:
    """Fetch the current v3 component policy for assistant compatibility."""
    try:
        resp = _ddb.get_item(
            TableName=COMPONENTS_TABLE,
            Key={"component_id": {"S": str(component_id)}},
        )
        item = resp.get("Item") or {}
        raw = (
            item.get("required_transition_type", {}).get("S")
            or item.get("transition_type", {}).get("S")
            or "code"
        )
        return _normalize_component_required_transition_type(raw, item) or "code"
    except Exception as exc:
        logger.error("[ASSISTANT] Failed to fetch component '%s': %s", component_id, exc)
        return "code"


def _update_component_transition_type_via_api(
    component_id: str, new_type: str, reason: str
) -> None:
    """Update a component's transition_type via coordination API (assistant path)."""
    url = f"{COORDINATION_API_BASE.rstrip('/')}/components/{component_id}"
    payload = json.dumps({
        "transition_type": new_type,
        "required_transition_type": new_type,
        "assistant_reason": reason,
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Content-Type": "application/json",
            "X-Checkout-Assistant-Key": CHECKOUT_ASSISTANT_KEY,
            "X-Coordination-Internal-Key": _PRIMARY_INTERNAL_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
            logger.info(
                "[ASSISTANT] Updated component '%s' to '%s': %s",
                component_id, new_type, body.get("success"),
            )
    except Exception as exc:
        logger.error(
            "[ASSISTANT] Failed to update component '%s' to '%s': %s",
            component_id, new_type, exc,
        )


def _increment_failure_count(
    project_id: str, task_id: str, task: dict, gate: str, provider: str
) -> int:
    """Increment advance_failure_count on task record; reset counter when gate changes.

    Returns the new failure count.
    """
    current_gate = (task.get("advance_failure_gate") or "").strip()
    current_count = int(task.get("advance_failure_count") or 0)
    if current_gate != gate:
        new_count = 1
    else:
        new_count = current_count + 1
    _set_task_field(
        project_id, task_id, "advance_failure_count", new_count,
        provider=provider or "checkout-service-assistant",
    )
    _set_task_field(
        project_id, task_id, "advance_failure_gate", gate,
        provider=provider or "checkout-service-assistant",
    )
    return new_count


def _invoke_assistant(
    task_id: str, task: dict, failed_gate: str, evidence: dict
) -> None:
    """Analyze failure pattern and auto-remediate component transition_type (ENC-FTR-041).

    Only loosens (never tightens) a component's transition_type. Infers the intended
    deploy method from the evidence the caller is providing but failing to match.
    Non-blocking — logs outcomes and returns; caller still returns 400 to the agent.
    """
    components = task.get("components") or []
    if not components:
        logger.info("[ASSISTANT] No components on task %s; cannot auto-remediate", task_id)
        return

    has_gha = bool(evidence.get("deploy_evidence"))
    has_web = bool(evidence.get("web_deploy_evidence"))
    has_lambda = bool(evidence.get("lambda_deploy_evidence"))

    if not (has_gha or has_web or has_lambda):
        logger.info(
            "[ASSISTANT] No usable evidence on task %s; cannot infer intended type", task_id
        )
        return

    inferred_type = "code" if (has_gha or has_web or has_lambda) else None
    if not inferred_type:
        return

    for cid in components:
        current = _get_component_transition_type(cid)
        current_rank = _COMPONENT_POLICY_TASK_MAX_RANK.get(current, 0)
        inferred_rank = _COMPONENT_POLICY_TASK_MAX_RANK.get(inferred_type, 0)
        if inferred_rank >= current_rank:
            logger.info(
                "[ASSISTANT] NOT loosening component '%s' (inferred=%s rank=%d >= current=%s rank=%d)",
                cid, inferred_type, inferred_rank, current, current_rank,
            )
            continue
        _update_component_transition_type_via_api(
            cid, inferred_type,
            reason=(
                f"Auto-remediated by checkout-service-assistant after 3 consecutive "
                f"failed {failed_gate} attempts on task {task_id}. "
                f"Inferred type '{inferred_type}' from evidence shape."
            ),
        )
        logger.info(
            "[ASSISTANT] Updated component '%s': %s → %s", cid, current, inferred_type
        )


def _handle_advance(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../advance — Advance status with gate validation + token issuance."""
    target_status = (body.get("target_status") or "").strip().lower()
    provider = (body.get("provider") or "").strip()
    transition_evidence = body.get("transition_evidence") or {}
    governance_hash = body.get("governance_hash")

    if not target_status:
        return _validation_error(
            400,
            "target_status is required",
            task_id=task_id,
            required_fields=["target_status"],
            example_fix={
                "tool": "advance_task_status",
                "arguments": {
                    "record_id": task_id,
                    "target_status": "coding-complete",
                    "provider": provider or "<provider>",
                    "governance_hash": "<governance_hash>",
                },
            },
        )

    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate. `provider` is the acting
    # agent-session identity on advance (must equal the checked-out session id
    # downstream); when it is a minted ENC-SES id the request must carry a valid
    # Session Claim ID BEFORE any gate evaluation or state mutation. PWA
    # user_initiated / Cognito paths present non-ENC-SES identities and pass.
    if _AGENT_SESSION_ID_RE.match(provider):
        sci_err = _validate_sci_gate(provider, body.get("sci"))
        if sci_err:
            return sci_err

    # --- Fetch current task to validate checkout state and transition_type ---
    status, task = _get_task(project_id, task_id)
    if status != 200:
        return _error(status, task.get("error", f"Task not found: {task_id}"))

    current_status = (task.get("status") or "").lower()
    active_session = task.get("active_agent_session", False)
    session_id = task.get("active_agent_session_id", "")

    if target_status != "in-progress" and not provider:
        return _validation_error(
            400,
            "provider is required for advance requests after checkout.",
            task_id=task_id,
            current_status=current_status,
            target_status=target_status,
            transition_type=(task.get("transition_type") or "github_pr_deploy").strip().lower(),
            required_fields=["provider"],
        )

    # --- ENC-ISS-092: Resolve transition_type and validate allowed statuses ---
    transition_type = (task.get("transition_type") or "github_pr_deploy").strip().lower()
    if transition_type not in VALID_TRANSITION_TYPES:
        # Unknown value — safe default preserves backward compatibility
        logger.warning(
            "Unknown transition_type '%s' on task %s; defaulting to github_pr_deploy",
            transition_type, task_id,
        )
        transition_type = "github_pr_deploy"

    # --- ENC-TSK-B08: Transition type integrity check ---
    # If transition_type was stamped at checkout, verify it hasn't been mutated.
    checkout_tt = (task.get("checkout_transition_type") or "").strip().lower()
    if checkout_tt and checkout_tt != transition_type:
        logger.warning(
            "GOVERNANCE INTEGRITY VIOLATION: task %s transition_type mutated "
            "from '%s' (at checkout) to '%s' (current)",
            task_id, checkout_tt, transition_type,
        )
        return _validation_error(
            409,
            (
                f"Governance integrity violation: task transition_type was '{checkout_tt}' "
                f"at checkout but is now '{transition_type}'. The transition_type field "
                "must not be mutated between checkout and advance. Release and re-checkout "
                "with the correct transition_type."
            ),
            task_id=task_id,
            current_status=current_status,
            target_status=target_status,
            transition_type=transition_type,
            provider=provider or session_id,
            extra_details={
                "checkout_transition_type": checkout_tt,
                "current_transition_type": transition_type,
            },
        )

    if target_status != "in-progress":
        # in-progress is handled by checkout below; all other statuses are arc-gated
        allowed = ALLOWED_TRANSITIONS_BY_TYPE.get(transition_type, [])
        if target_status not in allowed:
            return _validation_error(
                400,
                (
                    f"Status '{target_status}' is not allowed for transition_type "
                    f"'{transition_type}'. Allowed: {allowed}"
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
            )

    uses_github_pr = transition_type in _GITHUB_PR_TYPES

    # --- ENC-FTR-041: Component registry enforcement ---
    # If task has no components and this is an agent-initiated request, block the advance.
    # Human operators via the PWA UI (user_initiated=true) bypass this check to allow
    # closing legacy tasks that pre-date the component registry.
    components = task.get("components") or []
    component_required_policies: set[str] = set()
    is_user_initiated = bool(body.get("user_initiated", False))
    if not components and not is_user_initiated:
        return _validation_error(
            400,
            (
                "task.components is required for agent-initiated advances (ENC-FTR-041). "
                "Set task.components via tracker_set before checkout, or use the PWA UI "
                "to advance this task (Cognito user_initiated=true path bypasses this check)."
            ),
            task_id=task_id,
            current_status=current_status,
            target_status=target_status,
            transition_type=transition_type,
            provider=provider or session_id,
            required_fields=["components"],
            example_fix=_example_checkout_fix(task_id),
        )
    # --- ENC-FTR-076 / ENC-TSK-E10: Component lifecycle_status gate ---
    # Block agent-initiated advances when any task component is in
    # `proposed` or `rejected` state. PWA users (user_initiated=true) bypass
    # this gate so io can still close legacy tasks against unapproved
    # components if needed. `approved` is a transient state that should not
    # be observed at advance time (it flips to `active` atomically inside
    # the same DynamoDB transaction in coordination_api E09); if observed,
    # we treat it as `active` and log a warning for ops visibility.
    if components and not is_user_initiated:
        lifecycle_map = _get_components_lifecycle(components)
        proposed_ids: list = []
        rejected_entries: list = []
        for cid in components:
            entry = lifecycle_map.get(str(cid))
            if not entry:
                continue
            ls = entry.get("lifecycle_status", "active")
            if ls == "proposed":
                proposed_ids.append(str(cid))
            elif ls == "rejected":
                rejected_entries.append({
                    "component_id": str(cid),
                    "rejection_reason": entry.get("rejection_reason", ""),
                })
            elif ls == "approved":
                logger.warning(
                    "[FTR-076] Component '%s' observed in lifecycle_status=approved at advance time; "
                    "expected approved -> active to be atomic. Treating as active.", cid,
                )

        if proposed_ids:
            return _validation_error(
                400,
                (
                    f"Component(s) {proposed_ids} are pending coordination-lead approval "
                    f"(lifecycle_status='proposed'). Wait for io to approve via the PWA "
                    f"Components page, or escalate."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={
                    "code": "component_not_approved",
                    "component_ids": proposed_ids,
                    "guidance": "Pending coordination lead approval. Wait for io to approve via PWA or escalate.",
                },
            )
        if rejected_entries:
            primary = rejected_entries[0]
            return _validation_error(
                400,
                (
                    f"Component '{primary['component_id']}' has been rejected "
                    f"(lifecycle_status='rejected'). Reason: {primary['rejection_reason'] or '(no reason recorded)'}. "
                    "Choose a different component or escalate to coord lead."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={
                    "code": "component_rejected",
                    "rejected_components": rejected_entries,
                },
            )

    if components:
        try:
            required_type = _get_required_transition_type(components)
        except ComponentMisconfiguredError as exc:
            return _component_misconfigured_response(exc)
        if required_type is not None:
            component_required_policies = {required_type}
            task_rank = STRICTNESS_RANK.get(transition_type, 99)
            required_rank = _COMPONENT_POLICY_TASK_MAX_RANK.get(required_type, -1)
            if not _task_transition_satisfies_component_requirement(transition_type, required_type):
                return _validation_error(
                    400,
                    (
                        f"Task transition_type '{transition_type}' (rank {task_rank}) cannot satisfy "
                        f"component required_transition_type '{required_type}' (max task rank {required_rank}) "
                        "enforced by the component registry (ENC-FTR-041). Update task.transition_type "
                        "to a lifecycle arc that produces the required artifact class, or fix the "
                        "component registration."
                    ),
                    task_id=task_id,
                    current_status=current_status,
                    target_status=target_status,
                    transition_type=transition_type,
                    provider=provider or session_id,
                    component_required_transition_type=required_type,
                    extra_details={"components": components},
                    example_fix=[
                        {
                            "tool": "tracker_set",
                            "arguments": {
                                "record_id": task_id,
                                "field": "transition_type",
                                "value": _recommended_task_transition_for_component_policy(required_type),
                                "governance_hash": "<governance_hash>",
                            },
                        },
                        _example_advance_fix(
                            task_id,
                            target_status,
                            provider or session_id or "<provider>",
                            _recommended_task_transition_for_component_policy(required_type),
                        ),
                    ],
                )

    # --- ENC-ISS-106: Subtask lifecycle gate ---
    # Parent tasks (those with subtask_ids) cannot advance from coding-complete
    # onward unless all direct children have reached at least that same stage.
    # Children with shortened arcs (no_code at 'closed') satisfy any stage.
    if target_status != "in-progress":
        subtask_error = _validate_subtask_gate(
            project_id, task_id, task, target_status,
        )
        if subtask_error is not None:
            return subtask_error

    # --- Per-status gate logic ---
    response_extras: dict = {}

    if target_status == "in-progress":
        # Delegate to checkout handler (checkout + advance)
        return _handle_checkout(project_id, task_id, body)

    elif target_status == "coding-complete":
        if not active_session:
            return _validation_error(
                409,
                "Task must be checked out to advance to coding-complete. Use checkout endpoint first.",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                example_fix=_example_checkout_fix(task_id),
            )
        if uses_github_pr:
            # Generate + store Commit Approval ID (skipped for no_code arc)
            cai = _generate_token("CAI")
            _store_token(cai, "CAI", task_id, project_id)
            # Store on task record
            _set_task_field(project_id, task_id, "commit_approval_id", cai, provider=provider)
            response_extras["commit_approval_id"] = cai
        # no_code: no CAI issued — closed is the only next gate

    elif target_status == "committed":
        # Unreachable for no_code (blocked by ALLOWED_TRANSITIONS_BY_TYPE above)
        commit_sha = (transition_evidence.get("commit_sha") or "").strip()
        if not commit_sha:
            return _validation_error(
                400,
                "transition_evidence.commit_sha is required for committed",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                required_fields=["transition_evidence.commit_sha"],
            )
        if not re.match(r'^[0-9a-f]{40}$', commit_sha.lower()):
            return _validation_error(
                400,
                f"Invalid commit_sha: expected 40-char hex. Got: '{commit_sha}'",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                required_fields=["transition_evidence.commit_sha"],
            )

        owner = transition_evidence.get("owner")
        repo = transition_evidence.get("repo")
        if not owner or not repo:
            resolved_owner, resolved_repo = _resolve_github_repo(project_id)
            owner = owner or resolved_owner
            repo = repo or resolved_repo
        if not owner or not repo:
            return _validation_error(
                400,
                (
                    f"Cannot resolve GitHub repo for project '{project_id}'. "
                    "Provide owner and repo in transition_evidence, or set the "
                    "project's repo field in the projects table."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                required_fields=["transition_evidence.owner", "transition_evidence.repo"],
            )
        valid, reason = _validate_commit(owner, repo, commit_sha)
        if not valid:
            return _validation_error(
                400,
                f"GitHub commit validation failed: {reason}",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={"github_owner": owner, "github_repo": repo},
            )

        # Retrieve the Commit Approval ID from the task record to verify coding-complete was reached
        cai_on_record = task.get("commit_approval_id", "")
        if not cai_on_record:
            return _validation_error(
                409,
                (
                    "commit_approval_id not found on task. "
                    "Advance to coding-complete first to receive a commit-approval-id."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={
                    "token_type": "CAI (Commit Approval ID)",
                    "token_purpose": "Proves coding-complete gate was reached. Generated automatically when advancing to coding-complete.",
                    "prerequisite_status": "coding-complete",
                    "prerequisite_call": {
                        "tool": "checkout.advance",
                        "arguments": {
                            "record_id": task_id,
                            "target_status": "coding-complete",
                            "provider": "<provider>",
                            "governance_hash": "<governance_hash>",
                        },
                    },
                },
            )

        # Generate + store Commit Complete ID
        cci = _generate_token("CCI")
        _store_token(cci, "CCI", task_id, project_id)
        # Store on task record
        _set_task_field(project_id, task_id, "commit_complete_id", cci, provider=provider)
        response_extras["commit_complete_id"] = cci
        response_extras["commit_approval_id_consumed"] = cai_on_record

    elif target_status == "pr":
        if not active_session:
            return _validation_error(
                409,
                "Task must be checked out to advance to pr.",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                example_fix=_example_checkout_fix(task_id),
            )
        # Verify CCI exists on the task (ensures committed was reached)
        cci_on_record = task.get("commit_complete_id", "")
        if not cci_on_record:
            return _validation_error(
                409,
                (
                    "commit_complete_id not found on task. "
                    "Advance to committed (with commit_sha) first to receive a commit-complete-id."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={
                    "token_type": "CCI (Commit Complete ID)",
                    "token_purpose": "Proves committed gate was reached with a valid commit SHA. Generated automatically when advancing to committed.",
                    "prerequisite_status": "committed",
                    "prerequisite_call": {
                        "tool": "checkout.advance",
                        "arguments": {
                            "record_id": task_id,
                            "target_status": "committed",
                            "provider": "<provider>",
                            "governance_hash": "<governance_hash>",
                            "transition_evidence": {"commit_sha": "<40-char-hex>"},
                        },
                    },
                },
            )

    elif target_status == "merged-main":
        pr_id = body.get("pr_id") or transition_evidence.get("pr_id")
        merged_at = body.get("merged_at") or transition_evidence.get("merged_at")
        if not pr_id or not merged_at:
            return _validation_error(
                400,
                "pr_id and merged_at are required for merged-main",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                required_fields=["pr_id", "merged_at"],
            )
        owner = transition_evidence.get("owner")
        repo = transition_evidence.get("repo")
        if not owner or not repo:
            resolved_owner, resolved_repo = _resolve_github_repo(project_id)
            owner = owner or resolved_owner
            repo = repo or resolved_repo
        if not owner or not repo:
            return _validation_error(
                400,
                (
                    f"Cannot resolve GitHub repo for project '{project_id}'. "
                    "Provide owner and repo in transition_evidence, or set the "
                    "project's repo field in the projects table."
                ),
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                required_fields=["transition_evidence.owner", "transition_evidence.repo"],
            )
        valid, reason = _validate_pr_merged(owner, repo, int(pr_id), str(merged_at))
        if not valid:
            return _validation_error(
                400,
                f"PR merge validation failed: {reason}",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                extra_details={"github_owner": owner, "github_repo": repo, "pr_id": pr_id},
            )
        transition_evidence["pr_id"] = pr_id
        transition_evidence["merged_at"] = merged_at

    elif target_status == "deploy-init":
        # Unreachable for code_only and no_code (blocked above)
        if not active_session:
            return _validation_error(
                409,
                "Task must be checked out to advance to deploy-init.",
                task_id=task_id,
                current_status=current_status,
                target_status=target_status,
                transition_type=transition_type,
                provider=provider or session_id,
                example_fix=_example_checkout_fix(task_id),
            )

    elif target_status == "deploy-success":
        # ENC-FTR-059: Matrix-driven deploy-success gate dispatch (v{MATRIX_VERSION})
        # Unreachable for code_only and no_code (blocked by ALLOWED_TRANSITIONS_BY_TYPE above)
        ds_gate = get_deploy_success_gate(transition_type)
        if not ds_gate:
            return _validation_error(
                400,
                f"deploy-success gate is not applicable for transition_type '{transition_type}'.",
                task_id=task_id, current_status=current_status, target_status=target_status,
                transition_type=transition_type, provider=provider or session_id,
            )
        ev_key = ds_gate["evidence_key"]
        ev_label = ds_gate["label"]
        evidence_obj = transition_evidence.get(ev_key) or body.get(ev_key)
        if not evidence_obj or not isinstance(evidence_obj, dict):
            failure_count = _increment_failure_count(
                project_id, task_id, task, "deploy-success", provider
            )
            if failure_count >= 3:
                _invoke_assistant(task_id, task, "deploy-success", transition_evidence)
            return _validation_error(
                400,
                f"{ev_label} is required for deploy-success on {transition_type} tasks.",
                task_id=task_id, current_status=current_status, target_status=target_status,
                transition_type=transition_type, provider=provider or session_id,
                required_fields=[ev_label],
            )
        validator_fn = _DEPLOY_SUCCESS_VALIDATORS.get(transition_type)
        if validator_fn:
            valid, reason = validator_fn(evidence_obj)
            if not valid:
                failure_count = _increment_failure_count(
                    project_id, task_id, task, "deploy-success", provider
                )
                if failure_count >= 3:
                    _invoke_assistant(task_id, task, "deploy-success", transition_evidence)
                return _validation_error(
                    400,
                    f"{ev_key} validation failed: {reason}",
                    task_id=task_id, current_status=current_status, target_status=target_status,
                    transition_type=transition_type, provider=provider or session_id,
                    required_fields=[ev_label],
                )
        transition_evidence[ev_key] = evidence_obj
        if components:
            try:
                component_required_policies = (
                    _get_component_required_transition_types(components)
                    or component_required_policies
                )
            except ComponentMisconfiguredError as exc:
                return _component_misconfigured_response(exc)
        if "external_deploy" in component_required_policies:
            external_evidence = (
                transition_evidence.get("external_deploy_evidence")
                or body.get("external_deploy_evidence")
            )
            valid, reason = _validate_external_deploy_evidence(external_evidence)
            if not valid:
                return _error(
                    422,
                    f"external_deploy_evidence validation failed: {reason}",
                    code="INVALID_INPUT",
                    retryable=False,
                    details={
                        "task_id": task_id,
                        "current_status": current_status,
                        "target_status": target_status,
                        "transition_type": transition_type,
                        "component_required_transition_types": sorted(component_required_policies),
                        "required_fields": [
                            "transition_evidence.external_deploy_evidence.comp_external_id",
                            "transition_evidence.external_deploy_evidence.retrieval_steps",
                        ],
                        "required_evidence_schema": _EXTERNAL_DEPLOY_EVIDENCE_SCHEMA,
                    },
                )
            transition_evidence["external_deploy_evidence"] = external_evidence
        logger.info(
            "deploy-success gate passed for %s (type=%s, matrix_version=%d)",
            task_id, transition_type, MATRIX_VERSION,
        )
        # Clear CAI and CCI tokens from task after successful deploy (all arc types)
        response_extras["tokens_cleared"] = True

    elif target_status == "closed":
        # ENC-FTR-059: Matrix-driven closed gate dispatch (v{MATRIX_VERSION})
        cl_gate = get_closed_gate(transition_type)
        if cl_gate:
            ev_key = cl_gate["evidence_key"]
            ev_type = cl_gate.get("evidence_type", "string")
            ev_label = cl_gate["label"]
            validator_id = cl_gate.get("validator_id")

            if ev_type == "object":
                # Object evidence (e.g. code_on_main_evidence)
                evidence_obj = transition_evidence.get(ev_key) or body.get(ev_key)
                if not evidence_obj or not isinstance(evidence_obj, dict):
                    return _validation_error(
                        400,
                        f"{ev_label} is required for closed on {transition_type} tasks.",
                        task_id=task_id, current_status=current_status, target_status=target_status,
                        transition_type=transition_type, provider=provider or session_id,
                        required_fields=[ev_label],
                    )
                if validator_id == "code_on_main":
                    # code_on_main requires GitHub compare API validation
                    owner = transition_evidence.get("owner")
                    repo = transition_evidence.get("repo")
                    if not owner or not repo:
                        resolved_owner, resolved_repo = _resolve_github_repo(project_id)
                        owner = owner or resolved_owner
                        repo = repo or resolved_repo
                    if not owner or not repo:
                        return _validation_error(
                            400,
                            (
                                f"Cannot resolve GitHub repo for project '{project_id}'. "
                                "Provide owner and repo in transition_evidence, or set the "
                                "project's repo field in the projects table."
                            ),
                            task_id=task_id, current_status=current_status,
                            target_status=target_status, transition_type=transition_type,
                            provider=provider or session_id,
                            required_fields=["transition_evidence.owner", "transition_evidence.repo"],
                        )
                    valid, reason = _validate_code_on_main_evidence(owner, repo, evidence_obj)
                    if not valid:
                        return _validation_error(
                            400, f"{ev_key} validation failed: {reason}",
                            task_id=task_id, current_status=current_status,
                            target_status=target_status, transition_type=transition_type,
                            provider=provider or session_id, required_fields=[ev_label],
                        )
                transition_evidence[ev_key] = evidence_obj
            else:
                # String evidence (live_validation_evidence, no_code_evidence)
                str_evidence = (
                    transition_evidence.get(ev_key) or body.get(ev_key) or ""
                ).strip()
                if not str_evidence:
                    return _validation_error(
                        400,
                        f"{ev_label} is required for closed on {transition_type} tasks.",
                        task_id=task_id, current_status=current_status, target_status=target_status,
                        transition_type=transition_type, provider=provider or session_id,
                        required_fields=[ev_label],
                    )
                transition_evidence[ev_key] = str_evidence
            logger.info(
                "closed gate passed for %s (type=%s, matrix_version=%d)",
                task_id, transition_type, MATRIX_VERSION,
            )

        if components:
            try:
                component_required_policies = (
                    _get_component_required_transition_types(components)
                    or component_required_policies
                )
            except ComponentMisconfiguredError as exc:
                return _component_misconfigured_response(exc)
        if "documentation" in component_required_policies:
            documentation_evidence = (
                transition_evidence.get("documentation_evidence")
                or body.get("documentation_evidence")
            )
            valid, reason, details, doc_ids = _validate_documentation_close_evidence(
                project_id=project_id,
                task_id=task_id,
                evidence=documentation_evidence,
            )
            if not valid:
                return _error(
                    422,
                    reason,
                    code="INVALID_INPUT",
                    retryable=False,
                    details={
                        "task_id": task_id,
                        "current_status": current_status,
                        "target_status": target_status,
                        "transition_type": transition_type,
                        "component_required_transition_types": sorted(component_required_policies),
                        "required_fields": ["transition_evidence.documentation_evidence"],
                        "required_evidence_schema": _DOCUMENTATION_EVIDENCE_SCHEMA,
                        **details,
                    },
                )
            transition_evidence["documentation_evidence"] = doc_ids

        # ENC-FTR-048: Gate task closure on structured acceptance criteria evidence.
        # Only applies when the task has structured AC (object form with evidence_acceptance).
        # Tasks with plain-string AC (legacy) are not gated — backward compatible.
        ac_list = task.get("acceptance_criteria", [])
        if ac_list:
            has_structured = any(isinstance(ac, dict) and "evidence_acceptance" in ac for ac in ac_list)
            if has_structured:
                unvalidated = []
                for i, ac in enumerate(ac_list):
                    if isinstance(ac, dict):
                        desc = ac.get("description", f"criterion[{i}]")
                        if not ac.get("evidence_acceptance", False):
                            unvalidated.append(f"[{i}] {desc}")
                    elif isinstance(ac, str):
                        # Plain string criteria in a mixed list are treated as unvalidated
                        unvalidated.append(f"[{i}] {ac}")
                if unvalidated:
                    return _validation_error(
                        400,
                        (
                            "Cannot close task: not all acceptance criteria have been validated. "
                            "Use tracker_set_acceptance_evidence to set evidence_acceptance=true "
                            "on each criterion before closing.\nUnvalidated:\n"
                            + "\n".join(unvalidated)
                        ),
                        task_id=task_id,
                        current_status=current_status,
                        target_status=target_status,
                        transition_type=transition_type,
                        provider=provider or session_id,
                    )

    else:
        # Generic advance — let tracker_mutation validate the transition
        pass

    # --- Perform status advance via tracker API ---
    advance_status, advance_result = _set_task_field(
        project_id, task_id, "status", target_status,
        provider=provider,
        transition_evidence=transition_evidence if transition_evidence else None,
        governance_hash=governance_hash,
    )
    if advance_status not in (200, 201):
        return _validation_error(
            advance_status,
            advance_result.get("error", f"Status advance failed (HTTP {advance_status})"),
            task_id=task_id,
            current_status=current_status,
            target_status=target_status,
            transition_type=transition_type,
            provider=provider or session_id,
            extra_details={"tracker_response": advance_result},
        )

    # --- Post-advance: clear tokens on deploy-success ---
    if target_status == "deploy-success":
        cai_on_record = task.get("commit_approval_id", "")
        cci_on_record = task.get("commit_complete_id", "")
        if cai_on_record:
            _delete_token(cai_on_record)
            _set_task_field(project_id, task_id, "commit_approval_id", "", provider=provider)
        if cci_on_record:
            _delete_token(cci_on_record)
            _set_task_field(project_id, task_id, "commit_complete_id", "", provider=provider)

    # --- Release checkout on close ---
    if target_status == "closed":
        _release_task(project_id, task_id)

    # --- Return updated task ---
    _, updated_task = _get_task(project_id, task_id)
    logger.info(
        "advance OK: %s %s->%s (type=%s, matrix_version=%d)",
        task_id, current_status, target_status, transition_type, MATRIX_VERSION,
    )
    advance_envelope = {
        "success": True,
        "task": updated_task,
        "previous_status": current_status,
        "new_status": target_status,
        "matrix_version": MATRIX_VERSION,
        **response_extras,
    }
    # ENC-ISS-441 / ENC-TSK-J96: task reached its final lifecycle state — nudge the
    # acting session toward retirement (additive-only envelope field).
    return _response(200, _with_retirement_prompt(advance_envelope, target_status))


def _handle_log(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../log — Append worklog (checkout required)."""
    description = (body.get("description") or "").strip()
    if not description:
        return _error(400, "description is required")
    provider = body.get("provider")
    governance_hash = body.get("governance_hash")

    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate — agent-origin worklog
    # appends (provider is a minted ENC-SES id) must present a valid Session
    # Claim ID before the append is forwarded to tracker_mutation.
    provider_id = str(provider or "").strip()
    if _AGENT_SESSION_ID_RE.match(provider_id):
        sci_err = _validate_sci_gate(provider_id, body.get("sci"))
        if sci_err:
            return sci_err

    # Validate checkout state
    status, task = _get_task(project_id, task_id)
    if status != 200:
        return _error(status, task.get("error", f"Task not found: {task_id}"))

    if not task.get("active_agent_session", False):
        return _error(409, (
            "Task must be checked out to append worklog. "
            "Call POST .../checkout first."
        ))

    log_status, log_result = _log_task(project_id, task_id, description, provider, governance_hash)
    if log_status not in (200, 201):
        return _error(log_status, log_result.get("error", f"Worklog append failed (HTTP {log_status})"))

    return _response(200, {"success": True, "task_id": task_id})


def _handle_status(project_id: str, task_id: str) -> dict:
    """GET .../status — Return checkout + task state."""
    status, task = _get_task(project_id, task_id)
    if status != 200:
        return _error(status, task.get("error", f"Task not found: {task_id}"))

    return _response(200, {
        "task_id": task_id,
        "project_id": project_id,
        "status": task.get("status"),
        "active_agent_session": task.get("active_agent_session", False),
        "active_agent_session_id": task.get("active_agent_session_id", ""),
        "commit_approval_id": task.get("commit_approval_id"),
        "commit_complete_id": task.get("commit_complete_id"),
        "task": task,
    })


def _handle_validate_cci(cci_id: str) -> dict:
    """GET /validate/commit-complete/{cci_id} — Validate a CCI token (GitHub Actions gate)."""
    if not re.match(r'^CCI-[0-9a-f]{32}$', cci_id):
        return _error(
            400,
            f"Invalid commit-complete-id format: {cci_id}",
            details={
                "expected_format": "CCI-{32 hex chars}",
                "pattern": "^CCI-[0-9a-f]{32}$",
                "provided_value": cci_id,
            },
        )

    token_record = _lookup_token(cci_id)
    if not token_record:
        return _response(404, {
            "valid": False,
            "token_id": cci_id,
            "reason": "commit-complete-id not recognized by checkout service",
        })

    return _response(200, {
        "valid": True,
        "token_id": cci_id,
        "token_type": token_record.get("token_type"),
        "task_id": token_record.get("task_id"),
        "project_id": token_record.get("project_id"),
        "created_at": token_record.get("created_at"),
    })


# ---------------------------------------------------------------------------
# ENC-FTR-058 Phase 2: Plan checkout handlers
# ---------------------------------------------------------------------------


def _example_plan_checkout_fix(plan_id: str) -> Dict[str, Any]:
    """Return an example MCP tool call for plan.checkout."""
    return {
        "tool": "plan.checkout",
        "arguments": {
            "record_id": plan_id,
            "active_agent_session_id": "<agent-session-id>",
        },
    }


def _example_plan_advance_fix(plan_id: str, target_status: str) -> Dict[str, Any]:
    """Return an example MCP tool call for plan.advance."""
    return {
        "tool": "plan.advance",
        "arguments": {
            "record_id": plan_id,
            "target_status": target_status,
            "provider": "<agent-session-id>",
            "governance_hash": "<governance_hash>",
        },
    }


def _example_plan_log_fix(plan_id: str) -> Dict[str, Any]:
    """Return an example MCP tool call for plan.log."""
    return {
        "tool": "plan.log",
        "arguments": {
            "record_id": plan_id,
            "description": "<worklog entry>",
            "provider": "<agent-session-id>",
            "governance_hash": "<governance_hash>",
        },
    }


def _plan_validation_error(
    status: int,
    message: str,
    *,
    plan_id: str = "",
    current_status: str = "",
    target_status: str = "",
    checkout_required: bool = False,
    required_fields: Optional[list] = None,
    example_fix: Optional[Any] = None,
) -> dict:
    """Return a plan-scoped error with self-correcting context."""
    details: Dict[str, Any] = {}
    if plan_id:
        details["plan_id"] = plan_id
    if current_status:
        details["current_status"] = current_status
    if target_status:
        details["target_status"] = target_status
    details["allowed_plan_transitions"] = dict(PLAN_ALLOWED_TRANSITIONS)
    details["plan_terminal_statuses"] = sorted(PLAN_TERMINAL_STATUSES)
    if checkout_required:
        details["checkout_required"] = True
    if required_fields:
        details["required_fields"] = required_fields
    if example_fix is not None:
        details["example_fix"] = example_fix
    # Filter empty values
    details = {k: v for k, v in details.items() if v not in (None, "", [], {})}
    return _error(status, message, details=details)


def _handle_plan_checkout(project_id: str, plan_id: str, body: dict) -> dict:
    """POST .../checkout — Check out a plan and advance drafted→started."""
    provider = (body.get("active_agent_session_id") or "").strip()
    if not provider:
        return _plan_validation_error(
            400,
            "active_agent_session_id is required in request body",
            plan_id=plan_id,
            required_fields=["active_agent_session_id"],
            example_fix=_example_plan_checkout_fix(plan_id),
        )

    # ENC-TSK-L35: plan checkout is session-requiring; bump the acting
    # session's own updated_at (best-effort, no enforcement change).
    _touch_if_agent_session(provider)

    status, result = _checkout_plan(project_id, plan_id, provider)
    if status not in (200, 201):
        return _error(
            status,
            result.get("error", f"Plan checkout failed (HTTP {status})"),
        )

    # If plan is in drafted status, advance to started
    _, plan = _get_plan(project_id, plan_id)
    current_status = (plan.get("status") or "").strip().lower()
    if current_status == "drafted":
        status2, result2 = _set_plan_field(
            project_id, plan_id, "status", "started",
            provider=provider,
            governance_hash=result.get("governance_hash"),
        )
        if status2 not in (200, 201):
            logger.warning(
                "Plan checkout OK for %s/%s but status advance to started failed: %s",
                project_id, plan_id, result2,
            )

    _, plan = _get_plan(project_id, plan_id)
    return _response(200, {
        "success": True,
        "plan": plan,
        "checked_out_by": provider,
        "checked_out_at": datetime.now(timezone.utc).isoformat(),
    })


def _handle_plan_release(project_id: str, plan_id: str, body: dict) -> dict:
    """DELETE .../checkout — Release plan checkout with mandatory check-in (ENC-TSK-A90)."""
    checkin_summary = (body.get("checkin_summary") or "").strip()
    if not checkin_summary:
        return _error(
            400,
            "checkin_summary is required when releasing a plan checkout. "
            "Provide a summary of progress made during this session.",
        )

    provider = (body.get("provider") or "").strip()
    governance_hash = body.get("governance_hash")

    log_status, log_result = _log_plan(
        project_id, plan_id,
        f"[CHECK-IN] {checkin_summary}",
        provider=provider,
        governance_hash=governance_hash,
    )
    if log_status not in (200, 201):
        logger.warning(
            "Plan check-in log failed for %s/%s: %s", project_id, plan_id, log_result,
        )

    status, result = _release_plan(project_id, plan_id)
    if status not in (200, 201):
        return _error(status, result.get("error", f"Plan release failed (HTTP {status})"))

    return _response(200, {"success": True, "plan_id": plan_id})


_PREFIX_MAP_CACHE: Optional[Dict[str, str]] = None
_PREFIX_MAP_CACHE_AT: float = 0.0


def _project_for_record_id(record_id: str, default_project: str) -> str:
    """ENC-ISS-417: resolve a record's owning project from its ID prefix.

    Objective IDs encode their project (e.g. ``INT-TSK-071`` -> ``intelligence``,
    ``ENC-TSK-A89`` -> ``enceladus``). The plan completion gate (ENC-TSK-A89) must
    resolve cross-project objective statuses in their OWN project partition, with
    parity to plan.objectives_status — otherwise a cross-project objective resolves
    as not_found in the plan's own partition and the plan can never complete.

    Mirrors tracker_mutation._get_prefix_map_cached (projects table scan, 300s cache).
    Falls back to ``default_project`` when the prefix is unmapped or the scan fails.
    """
    global _PREFIX_MAP_CACHE, _PREFIX_MAP_CACHE_AT
    prefix = str(record_id or "").split("-", 1)[0].strip().upper()
    if not prefix:
        return default_project
    now = time.time()
    if _PREFIX_MAP_CACHE is None or (now - _PREFIX_MAP_CACHE_AT) >= 300.0:
        try:
            resp = _ddb.scan(
                TableName=PROJECTS_TABLE,
                ProjectionExpression="project_id, prefix",
            )
            mapping: Dict[str, str] = {}
            for item in resp.get("Items", []):
                pid = item.get("project_id", {}).get("S", "")
                pfx = item.get("prefix", {}).get("S", "")
                if pid and pfx:
                    mapping[pfx.upper()] = pid
            _PREFIX_MAP_CACHE = mapping
            _PREFIX_MAP_CACHE_AT = now
        except Exception as exc:
            logger.warning("ENC-ISS-417: projects prefix-map scan failed: %s", exc)
            if _PREFIX_MAP_CACHE is None:
                return default_project
    return (_PREFIX_MAP_CACHE or {}).get(prefix, default_project)


def _validate_plan_objectives_complete(
    project_id: str,
    plan: dict,
) -> Optional[dict]:
    """Validate all objectives are in a terminal status (ENC-TSK-A89 completion gate)."""
    objectives = plan.get("objectives_set") or []
    if not objectives:
        return _error(
            400,
            "Cannot complete plan: objectives_set is empty. "
            "A plan must have at least one objective to complete.",
        )

    incomplete: list = []
    for obj_id in objectives:
        obj_id = str(obj_id).strip()
        if not obj_id:
            continue
        # ENC-ISS-417: resolve each objective in its OWN project partition (derived
        # from the ID prefix) so cross-project objectives are validated correctly
        # instead of resolving as not_found in the plan's own project.
        obj_project = _project_for_record_id(obj_id, project_id)
        obj_status_code, obj_record = _get_task(obj_project, obj_id)
        if obj_status_code != 200:
            for rtype in ("feature", "issue", "plan"):
                obj_status_code, obj_record = _tracker_request(
                    "GET", f"/{obj_project}/{rtype}/{obj_id}",
                )
                if obj_status_code == 200:
                    if isinstance(obj_record, dict) and isinstance(obj_record.get("record"), dict):
                        obj_record = obj_record["record"]
                    break
        if obj_status_code != 200:
            incomplete.append((obj_id, "not_found"))
            continue
        obj_status = (obj_record.get("status") or "unknown").strip().lower()
        if obj_status not in PLAN_TERMINAL_STATUSES:
            incomplete.append((obj_id, obj_status))

    if not incomplete:
        return None

    detail_lines = [f"  - {oid} ({ostatus})" for oid, ostatus in incomplete[:20]]
    if len(incomplete) > 20:
        detail_lines.append(f"  ... and {len(incomplete) - 20} more")
    return _error(
        400,
        (
            f"Cannot complete plan: {len(incomplete)} objective(s) are not in a terminal "
            f"status (ENC-TSK-A89 completion gate):\n"
            + "\n".join(detail_lines)
            + f"\nTerminal statuses: {sorted(PLAN_TERMINAL_STATUSES)}"
        ),
    )


def _handle_plan_advance(project_id: str, plan_id: str, body: dict) -> dict:
    """POST .../advance — Advance plan status through lifecycle."""
    target_status = (body.get("target_status") or "").strip().lower()
    provider = (body.get("provider") or "").strip()
    transition_evidence = body.get("transition_evidence") or {}
    governance_hash = body.get("governance_hash")

    if not target_status:
        return _plan_validation_error(
            400,
            "target_status is required",
            plan_id=plan_id,
            required_fields=["target_status"],
            example_fix=_example_plan_advance_fix(plan_id, "<target_status>"),
        )
    if not provider:
        return _plan_validation_error(
            400,
            "provider is required for plan advance requests",
            plan_id=plan_id,
            required_fields=["provider"],
            example_fix=_example_plan_advance_fix(plan_id, target_status),
        )

    # ENC-TSK-L35: plan advance is session-requiring; bump the acting
    # session's own updated_at (best-effort, no enforcement change).
    _touch_if_agent_session(provider)

    status, plan = _get_plan(project_id, plan_id)
    if status != 200:
        return _error(status, plan.get("error", f"Plan not found: {plan_id}"))

    current_status = (plan.get("status") or "").strip().lower()

    if not plan.get("active_agent_session", False):
        return _plan_validation_error(
            409,
            f"Plan {plan_id} must be checked out before advancing. "
            "Call POST .../checkout first.",
            plan_id=plan_id,
            current_status=current_status,
            target_status=target_status,
            checkout_required=True,
            example_fix=_example_plan_checkout_fix(plan_id),
        )

    allowed = PLAN_ALLOWED_TRANSITIONS.get(current_status, [])
    if target_status not in allowed:
        return _error(
            400,
            f"Cannot advance plan from '{current_status}' to '{target_status}'. "
            f"Allowed transitions: {allowed}",
        )

    if target_status == "complete":
        gate_error = _validate_plan_objectives_complete(project_id, plan)
        if gate_error is not None:
            return gate_error

    if target_status == "incomplete":
        incomplete_reason = (transition_evidence.get("incomplete_reason") or "").strip()
        if not incomplete_reason:
            return _error(
                400,
                "transition_evidence.incomplete_reason is required when marking a plan incomplete.",
            )
        _log_plan(
            project_id, plan_id,
            f"[INFO] Plan marked incomplete: {incomplete_reason}",
            provider=provider,
            governance_hash=governance_hash,
        )

    set_status, set_result = _set_plan_field(
        project_id, plan_id, "status", target_status,
        provider=provider,
        transition_evidence=transition_evidence if transition_evidence else None,
        governance_hash=governance_hash,
    )
    if set_status not in (200, 201):
        return _error(
            set_status,
            set_result.get("error", f"Plan advance failed (HTTP {set_status})"),
        )

    if target_status in ("complete", "incomplete"):
        _release_plan(project_id, plan_id)

    _, updated_plan = _get_plan(project_id, plan_id)
    plan_envelope = {
        "success": True,
        "plan": updated_plan,
        "previous_status": current_status,
        "new_status": target_status,
    }
    # ENC-ISS-441 / ENC-TSK-J96: plan reached its final lifecycle state — retirement nudge.
    return _response(
        200, _with_retirement_prompt(plan_envelope, target_status, terminal_statuses=("complete",))
    )


def _handle_plan_log(project_id: str, plan_id: str, body: dict) -> dict:
    """POST .../log — Append worklog to a checked-out plan."""
    description = (body.get("description") or "").strip()
    if not description:
        return _plan_validation_error(
            400,
            "description is required",
            plan_id=plan_id,
            required_fields=["description"],
            example_fix=_example_plan_log_fix(plan_id),
        )
    provider = body.get("provider")
    governance_hash = body.get("governance_hash")

    # ENC-TSK-L35: plan worklog append is session-requiring; bump the acting
    # session's own updated_at (best-effort, no enforcement change). Worklog
    # mirroring onto the session's own history happens centrally in
    # tracker_mutation._handle_log (the shared /log endpoint for every record
    # type), not here.
    _touch_if_agent_session(provider)

    status, plan = _get_plan(project_id, plan_id)
    if status != 200:
        return _error(status, plan.get("error", f"Plan not found: {plan_id}"))

    if not plan.get("active_agent_session", False):
        return _plan_validation_error(
            409,
            "Plan must be checked out to append worklog. "
            "Call POST .../checkout first.",
            plan_id=plan_id,
            current_status=plan.get("status", ""),
            checkout_required=True,
            example_fix=_example_plan_checkout_fix(plan_id),
        )

    log_status, log_result = _log_plan(project_id, plan_id, description, provider, governance_hash)
    if log_status not in (200, 201):
        return _error(log_status, log_result.get("error", f"Worklog append failed (HTTP {log_status})"))

    return _response(200, {"success": True, "plan_id": plan_id})


def _handle_plan_status(project_id: str, plan_id: str) -> dict:
    """GET .../status — Return plan checkout + state."""
    status, plan = _get_plan(project_id, plan_id)
    if status != 200:
        return _error(status, plan.get("error", f"Plan not found: {plan_id}"))

    return _response(200, {
        "plan_id": plan_id,
        "project_id": project_id,
        "status": plan.get("status"),
        "active_agent_session": plan.get("active_agent_session", False),
        "active_agent_session_id": plan.get("active_agent_session_id", ""),
        "objectives_set": plan.get("objectives_set", []),
        "plan": plan,
    })


# ---------------------------------------------------------------------------
# Route dispatcher
# ---------------------------------------------------------------------------

def _parse_path(raw_path: str) -> dict:
    """Parse route path into components."""
    path = unquote(raw_path).rstrip("/")
    # /api/v1/checkout/validate/commit-complete/{cci_id}
    m = re.match(r'^/api/v1/checkout/validate/commit-complete/([^/]+)$', path)
    if m:
        return {"route": "validate_cci", "cci_id": m.group(1)}

    # /api/v1/checkout/{project}/task/{task_id}/{action}
    m = re.match(r'^/api/v1/checkout/([^/]+)/task/([^/]+)/([^/]+)$', path)
    if m:
        return {
            "route": "task_action",
            "project_id": m.group(1),
            "task_id": m.group(2),
            "action": m.group(3),
        }

    # /api/v1/checkout/{project}/plan/{plan_id}/{action}  (ENC-FTR-058)
    m = re.match(r'^/api/v1/checkout/([^/]+)/plan/([^/]+)/([^/]+)$', path)
    if m:
        return {
            "route": "plan_action",
            "project_id": m.group(1),
            "plan_id": m.group(2),
            "action": m.group(3),
        }

    return {"route": "unknown"}


def lambda_handler(event: dict, context: Any) -> dict:
    """HTTP API Gateway entry point."""
    method = (event.get("requestContext", {}).get("http", {}).get("method") or
              event.get("httpMethod") or "GET").upper()
    raw_path = (event.get("requestContext", {}).get("http", {}).get("path") or
                event.get("path") or "/")

    # CORS preflight
    if method == "OPTIONS":
        return _response(200, "")

    # Auth check
    if not _is_authenticated(event):
        return _error(401, "Unauthorized: valid session or internal key required")

    # Parse body
    body: dict = {}
    raw_body = event.get("body") or ""
    if raw_body:
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            return _error(400, "Invalid JSON body")

    parsed = _parse_path(raw_path)
    route = parsed.get("route")

    if route == "validate_cci":
        return _handle_validate_cci(parsed["cci_id"])

    if route == "task_action":
        project_id = parsed["project_id"]
        task_id = parsed["task_id"]
        action = parsed["action"]

        if action == "checkout":
            if method == "POST":
                return _handle_checkout(project_id, task_id, body)
            elif method == "DELETE":
                return _handle_release(project_id, task_id, body)
            return _error(405, f"Method {method} not allowed for checkout")

        if action == "advance":
            if method == "POST":
                return _handle_advance(project_id, task_id, body)
            return _error(405, f"Method {method} not allowed for advance")

        if action == "log":
            if method == "POST":
                return _handle_log(project_id, task_id, body)
            return _error(405, f"Method {method} not allowed for log")

        if action == "status":
            if method == "GET":
                return _handle_status(project_id, task_id)
            return _error(405, f"Method {method} not allowed for status")

        return _error(404, f"Unknown action: {action}")

    if route == "plan_action":
        project_id = parsed["project_id"]
        plan_id = parsed["plan_id"]
        action = parsed["action"]

        if action == "checkout":
            if method == "POST":
                return _handle_plan_checkout(project_id, plan_id, body)
            elif method == "DELETE":
                return _handle_plan_release(project_id, plan_id, body)
            return _error(405, f"Method {method} not allowed for plan checkout")

        if action == "advance":
            if method == "POST":
                return _handle_plan_advance(project_id, plan_id, body)
            return _error(405, f"Method {method} not allowed for plan advance")

        if action == "log":
            if method == "POST":
                return _handle_plan_log(project_id, plan_id, body)
            return _error(405, f"Method {method} not allowed for plan log")

        if action == "status":
            if method == "GET":
                return _handle_plan_status(project_id, plan_id)
            return _error(405, f"Method {method} not allowed for plan status")

        return _error(404, f"Unknown plan action: {action}")

    return _error(404, f"Route not found: {raw_path}")


# ---------------------------------------------------------------------------
# Auto-checkout EventBridge handler
# ---------------------------------------------------------------------------

AUTO_CHECKOUT_WINDOW_MINUTES = 15
AUTO_CHECKOUT_PROVIDER = "coordination_dispatch"

def handler_auto_checkout(event: dict, context: Any) -> dict:
    """EventBridge entry point: auto-checkout tasks that have been waiting > 15 minutes.

    Scans for tasks where:
      - status = "open"
      - active_agent_session = False
      - updated_at older than AUTO_CHECKOUT_WINDOW_MINUTES

    This handles coordination-dispatched tasks that weren't checked out by the
    dispatched agent within the window. ENC-FTR-037.
    """
    logger.info("[START] Auto-checkout scan (window=%d min)", AUTO_CHECKOUT_WINDOW_MINUTES)

    # Query open tasks from each active project via tracker API
    # We rely on a list endpoint; fall back to a targeted project scan.
    checked_out = []
    errors = []

    # Fetch open tasks from enceladus project
    # Future: iterate over all active projects via project_service
    for project_id in ["enceladus", "devops", "harrisonfamily"]:
        status, result = _tracker_request("GET", f"/{project_id}?record_type=task&status=open")
        if status != 200:
            continue

        tasks = result.get("items") or result.get("records") or []
        cutoff = time.time() - AUTO_CHECKOUT_WINDOW_MINUTES * 60

        for task in tasks:
            if task.get("active_agent_session", False):
                continue  # Already checked out
            task_id = task.get("id") or task.get("record_id")
            if not task_id:
                continue

            # Parse updated_at
            updated_at_str = task.get("updated_at") or task.get("created_at") or ""
            try:
                updated_dt = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                updated_ts = updated_dt.timestamp()
            except (ValueError, AttributeError):
                continue

            if updated_ts > cutoff:
                continue  # Too recent

            # Auto-checkout
            co_status, co_result = _checkout_task(project_id, task_id, AUTO_CHECKOUT_PROVIDER)
            if co_status in (200, 201):
                _log_task(
                    project_id, task_id,
                    f"[INFO] Auto-checkout triggered after {AUTO_CHECKOUT_WINDOW_MINUTES}-minute "
                    f"window. Provider: {AUTO_CHECKOUT_PROVIDER}",
                    provider=AUTO_CHECKOUT_PROVIDER,
                )
                checked_out.append(f"{project_id}/{task_id}")
                logger.info("[SUCCESS] Auto-checked-out %s/%s", project_id, task_id)
            else:
                errors.append(f"{project_id}/{task_id}: {co_result.get('error', 'unknown')}")
                logger.warning("[WARN] Auto-checkout failed for %s/%s: %s", project_id, task_id, co_result)

    logger.info("[END] Auto-checkout: checked_out=%d, errors=%d", len(checked_out), len(errors))
    return {
        "checked_out": checked_out,
        "errors": errors,
        "checked_out_count": len(checked_out),
        "error_count": len(errors),
    }
