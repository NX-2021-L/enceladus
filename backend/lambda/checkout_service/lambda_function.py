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
    GITHUB_TOKEN                  GitHub PAT for commit/PR validation (optional — public repos only)
    CHECKOUT_TOKENS_TABLE         DynamoDB table for token storage (default: enceladus-checkout-tokens)
    CHECKOUT_TOKENS_REGION        AWS region for token table (default: us-west-2)
    COGNITO_USER_POOL_ID          us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID             6q607dk3liirhtecgps7hifmlk
    CORS_ORIGIN                   default: https://jreese.net
    TOKEN_TTL_DAYS                token expiry in days (default: 90)

Related: ENC-FTR-037
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
import urllib.request
import urllib.error
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    _JWT_AVAILABLE = True
except ImportError:
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
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
CHECKOUT_TOKENS_TABLE = os.environ.get("CHECKOUT_TOKENS_TABLE", "enceladus-checkout-tokens")
CHECKOUT_TOKENS_REGION = os.environ.get("CHECKOUT_TOKENS_REGION", "us-west-2")
TOKEN_TTL_DAYS = int(os.environ.get("TOKEN_TTL_DAYS", "90"))
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")

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


def _error(status: int, message: str) -> dict:
    return _response(status, {"error": message})


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
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_request(path: str) -> Tuple[int, dict]:
    url = f"{GITHUB_API_BASE}{path}"
    headers = {"User-Agent": "checkout-service/1.0", "Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
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


def _validate_commit(owner: str, repo: str, commit_sha: str) -> Tuple[bool, str]:
    """Verify commit SHA exists on GitHub. Returns (valid, reason)."""
    status, body = _github_request(f"/repos/{owner}/{repo}/commits/{commit_sha}")
    if status == 200:
        return True, ""
    if status == 404:
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
# Route handlers
# ---------------------------------------------------------------------------

def _handle_checkout(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../checkout — Atomic checkout + advance to in-progress."""
    provider = (body.get("active_agent_session_id") or "").strip()
    if not provider:
        return _error(400, "active_agent_session_id is required in request body")

    coordination_request_id = body.get("coordination_request_id", "")

    # Step 1: Check out the task (sets active_agent_session=True)
    status, result = _checkout_task(project_id, task_id, provider)
    if status not in (200, 201):
        return _error(status, result.get("error", f"Checkout failed (HTTP {status})"))

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
    return _response(200, {
        "success": True,
        "task": task,
        "checked_out_by": provider,
        "checked_out_at": datetime.now(timezone.utc).isoformat(),
        "coordination_request_id": coordination_request_id or None,
    })


def _handle_release(project_id: str, task_id: str, body: dict) -> dict:
    """DELETE .../checkout — Release checkout."""
    status, result = _release_task(project_id, task_id)
    if status not in (200, 201):
        return _error(status, result.get("error", f"Release failed (HTTP {status})"))
    return _response(200, {"success": True, "task_id": task_id})


def _handle_advance(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../advance — Advance status with gate validation + token issuance."""
    target_status = (body.get("target_status") or "").strip().lower()
    provider = (body.get("provider") or "").strip()
    transition_evidence = body.get("transition_evidence") or {}
    governance_hash = body.get("governance_hash")

    if not target_status:
        return _error(400, "target_status is required")

    # --- Fetch current task to validate checkout state ---
    status, task = _get_task(project_id, task_id)
    if status != 200:
        return _error(status, task.get("error", f"Task not found: {task_id}"))

    current_status = (task.get("status") or "").lower()
    active_session = task.get("active_agent_session", False)
    session_id = task.get("active_agent_session_id", "")

    # --- Per-status gate logic ---
    response_extras: dict = {}

    if target_status == "in-progress":
        # Delegate to checkout handler (checkout + advance)
        return _handle_checkout(project_id, task_id, body)

    elif target_status == "coding-complete":
        if not active_session:
            return _error(409, "Task must be checked out to advance to coding-complete. Use checkout endpoint first.")
        # Generate + store Commit Approval ID
        cai = _generate_token("CAI")
        _store_token(cai, "CAI", task_id, project_id)
        # Store on task record
        _set_task_field(project_id, task_id, "commit_approval_id", cai, provider=provider)
        response_extras["commit_approval_id"] = cai

    elif target_status == "committed":
        commit_sha = (transition_evidence.get("commit_sha") or "").strip()
        if not commit_sha:
            return _error(400, "transition_evidence.commit_sha is required for committed")
        if not re.match(r'^[0-9a-f]{40}$', commit_sha.lower()):
            return _error(400, f"Invalid commit_sha: expected 40-char hex. Got: '{commit_sha}'")

        owner = transition_evidence.get("owner", "NX-2021-L")
        repo = transition_evidence.get("repo", "enceladus")
        valid, reason = _validate_commit(owner, repo, commit_sha)
        if not valid:
            return _error(400, f"GitHub commit validation failed: {reason}")

        # Retrieve the Commit Approval ID from the task record to verify coding-complete was reached
        cai_on_record = task.get("commit_approval_id", "")
        if not cai_on_record:
            return _error(409, (
                "commit_approval_id not found on task. "
                "Advance to coding-complete first to receive a commit-approval-id."
            ))

        # Generate + store Commit Complete ID
        cci = _generate_token("CCI")
        _store_token(cci, "CCI", task_id, project_id)
        # Store on task record
        _set_task_field(project_id, task_id, "commit_complete_id", cci, provider=provider)
        response_extras["commit_complete_id"] = cci
        response_extras["commit_approval_id_consumed"] = cai_on_record

    elif target_status == "pr":
        if not active_session:
            return _error(409, "Task must be checked out to advance to pr.")
        # Verify CCI exists on the task (ensures committed was reached)
        cci_on_record = task.get("commit_complete_id", "")
        if not cci_on_record:
            return _error(409, (
                "commit_complete_id not found on task. "
                "Advance to committed (with commit_sha) first to receive a commit-complete-id."
            ))

    elif target_status == "merged-main":
        pr_id = body.get("pr_id") or transition_evidence.get("pr_id")
        merged_at = body.get("merged_at") or transition_evidence.get("merged_at")
        if not pr_id or not merged_at:
            return _error(400, "pr_id and merged_at are required for merged-main")
        owner = transition_evidence.get("owner", "NX-2021-L")
        repo = transition_evidence.get("repo", "enceladus")
        valid, reason = _validate_pr_merged(owner, repo, int(pr_id), str(merged_at))
        if not valid:
            return _error(400, f"PR merge validation failed: {reason}")
        transition_evidence["pr_id"] = pr_id
        transition_evidence["merged_at"] = merged_at

    elif target_status == "deploy-init":
        if not active_session:
            return _error(409, "Task must be checked out to advance to deploy-init.")

    elif target_status == "deploy-success":
        deploy_evidence = transition_evidence.get("deploy_evidence") or body.get("deploy_evidence")
        if not deploy_evidence or not isinstance(deploy_evidence, dict):
            return _error(400, "transition_evidence.deploy_evidence (GitHub Actions Jobs API object) is required for deploy-success")
        # Validate required deploy_evidence fields (ENC-TSK-726 rules)
        required_fields = ["id", "name", "run_id", "status", "conclusion", "started_at", "completed_at"]
        missing = [f for f in required_fields if not deploy_evidence.get(f)]
        if missing:
            return _error(400, f"deploy_evidence missing required fields: {missing}")
        if deploy_evidence.get("conclusion") != "success":
            return _error(400, f"deploy_evidence.conclusion must be 'success', got: {deploy_evidence.get('conclusion')}")
        transition_evidence["deploy_evidence"] = deploy_evidence
        # Clear CAI and CCI tokens from task after successful deploy
        response_extras["tokens_cleared"] = True

    elif target_status == "closed":
        live_validation_evidence = (
            transition_evidence.get("live_validation_evidence")
            or body.get("live_validation_evidence")
            or ""
        ).strip()
        if not live_validation_evidence:
            return _error(400, "transition_evidence.live_validation_evidence is required for closed")
        transition_evidence["live_validation_evidence"] = live_validation_evidence

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
        return _error(advance_status, advance_result.get("error", f"Status advance failed (HTTP {advance_status})"))

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
    return _response(200, {
        "success": True,
        "task": updated_task,
        "previous_status": current_status,
        "new_status": target_status,
        **response_extras,
    })


def _handle_log(project_id: str, task_id: str, body: dict) -> dict:
    """POST .../log — Append worklog (checkout required)."""
    description = (body.get("description") or "").strip()
    if not description:
        return _error(400, "description is required")
    provider = body.get("provider")
    governance_hash = body.get("governance_hash")

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
        return _error(400, f"Invalid commit-complete-id format: {cci_id}")

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
