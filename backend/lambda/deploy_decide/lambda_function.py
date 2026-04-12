"""
deploy_decide Lambda — Cognito-authenticated governance decisions for production deployments.

Handles approve/divert/revert actions on deployment_decision (ENC-DPL) records.
Part of the Generational Metabolism Framework (DOC-63420302EF65).

Routes:
  POST /api/v1/deploy/decide  — Execute a deployment decision (approve/divert/revert)

Auth: Cognito JWT only (human-operator actions). Internal API key is NOT accepted
for decide actions — this is a deliberate governance constraint ensuring only
io can authorize production deployments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import boto3
import jwt
from botocore.config import Config

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DEPLOY_REGION = os.environ.get("DEPLOY_REGION", "us-west-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")

# GitHub App config (for merge/retarget/close API calls)
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_INSTALLATION_ID = os.environ.get("GITHUB_INSTALLATION_ID", "")
GITHUB_PRIVATE_KEY_SECRET = os.environ.get(
    "GITHUB_PRIVATE_KEY_SECRET", "devops/github-app/private-key"
)
ALLOWED_REPOS = [
    r.strip()
    for r in os.environ.get("ALLOWED_REPOS", "NX-2021-L/enceladus").split(",")
    if r.strip()
]
GAMMA_INTEGRATION_BRANCH = os.environ.get("GAMMA_INTEGRATION_BRANCH", "v4/main")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------

_ddb_client = None
_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0
_github_private_key_cache: Optional[str] = None
_github_private_key_fetched_at: float = 0

JWKS_TTL = 3600  # 1 hour
GITHUB_KEY_TTL = 3600  # 1 hour

# ---------------------------------------------------------------------------
# CORS / Response helpers
# ---------------------------------------------------------------------------

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": CORS_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Cookie",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json",
}

_ERROR_CODE_MAP = {
    400: "INVALID_INPUT",
    401: "PERMISSION_DENIED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    409: "CONFLICT",
    429: "RATE_LIMITED",
}


def _ok(body: dict) -> dict:
    body["success"] = True
    return {"statusCode": 200, "headers": _CORS_HEADERS, "body": json.dumps(body)}


def _error(status_code: int, message: str, **extra) -> dict:
    code = _ERROR_CODE_MAP.get(status_code, "INTERNAL_ERROR")
    retryable = extra.pop("retryable", status_code >= 500)
    body = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": extra,
        },
    }
    body.update(extra)
    return {"statusCode": status_code, "headers": _CORS_HEADERS, "body": json.dumps(body)}


def _options() -> dict:
    return {"statusCode": 204, "headers": _CORS_HEADERS, "body": ""}


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client(
            "dynamodb",
            region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb_client


def _get_decision(project_id: str, record_id: str) -> Optional[Dict]:
    """Read a deployment_decision record from DynamoDB."""
    resp = _get_ddb().get_item(
        TableName=DEPLOY_TABLE,
        Key={
            "project_id": {"S": project_id},
            "record_id": {"S": record_id},
        },
    )
    item = resp.get("Item")
    if not item:
        return None
    return _unmarshal(item)


def _update_decision(
    project_id: str,
    record_id: str,
    status: str,
    final_target: str,
    decided_by: str,
    decision_reason: str = "",
) -> Dict:
    """Update a deployment_decision record with the decision."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expr_names = {
        "#s": "status",
        "#ft": "final_target",
        "#db": "decided_by",
        "#da": "decided_at",
        "#ua": "updated_at",
        "#ws": "write_source",
    }
    expr_values = {
        ":s": {"S": status},
        ":ft": {"S": final_target},
        ":db": {"S": decided_by},
        ":da": {"S": now},
        ":ua": {"S": now},
        ":ws": {"S": "mutation_api"},
    }
    update_expr = "SET #s = :s, #ft = :ft, #db = :db, #da = :da, #ua = :ua, #ws = :ws"

    if decision_reason:
        expr_names["#dr"] = "decision_reason"
        expr_values[":dr"] = {"S": decision_reason}
        update_expr += ", #dr = :dr"

    resp = _get_ddb().update_item(
        TableName=DEPLOY_TABLE,
        Key={
            "project_id": {"S": project_id},
            "record_id": {"S": record_id},
        },
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
        ConditionExpression="attribute_exists(project_id)",
        ReturnValues="ALL_NEW",
    )
    return _unmarshal(resp.get("Attributes", {}))


def _unmarshal(item: Dict) -> Dict:
    """Simple DynamoDB item unmarshaller."""
    result = {}
    for k, v in item.items():
        if "S" in v:
            result[k] = v["S"]
        elif "N" in v:
            result[k] = int(v["N"]) if "." not in v["N"] else float(v["N"])
        elif "BOOL" in v:
            result[k] = v["BOOL"]
        elif "NULL" in v:
            result[k] = None
        elif "SS" in v:
            result[k] = list(v["SS"])
        elif "L" in v:
            result[k] = [_unmarshal_value(i) for i in v["L"]]
        elif "M" in v:
            result[k] = _unmarshal(v["M"])
    return result


def _unmarshal_value(v: Dict) -> Any:
    if "S" in v:
        return v["S"]
    if "N" in v:
        return int(v["N"]) if "." not in v["N"] else float(v["N"])
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "M" in v:
        return _unmarshal(v["M"])
    if "L" in v:
        return [_unmarshal_value(i) for i in v["L"]]
    return str(v)


# ---------------------------------------------------------------------------
# Cognito JWT validation
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < JWKS_TTL:
        return _jwks_cache

    region = COGNITO_USER_POOL_ID.split("_")[0] if "_" in COGNITO_USER_POOL_ID else "us-east-1"
    url = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        _jwks_cache = json.loads(resp.read().decode())
    _jwks_fetched_at = now
    return _jwks_cache


def _validate_cognito_token(event: Dict) -> Optional[Dict]:
    """Validate Cognito JWT from cookie. Returns claims dict or None."""
    token = _extract_token(event)
    if not token:
        return None

    try:
        jwks = _get_jwks()
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        key_data = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key_data = k
                break
        if not key_data:
            logger.warning("No matching JWK kid found")
            return None

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            options={"verify_exp": True},
        )
        return claims
    except jwt.ExpiredSignatureError:
        logger.info("Cognito token expired")
        return None
    except Exception as e:
        logger.warning(f"Cognito token validation failed: {e}")
        return None


def _extract_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header."""
    cookies = event.get("cookies", [])
    if not cookies:
        cookie_header = ""
        headers = event.get("headers", {})
        for k, v in headers.items():
            if k.lower() == "cookie":
                cookie_header = v
                break
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(";")]

    for c in cookies:
        if c.startswith("enceladus_id_token="):
            return c.split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# GitHub App authentication
# ---------------------------------------------------------------------------


def _get_github_private_key() -> str:
    global _github_private_key_cache, _github_private_key_fetched_at
    now = time.time()
    if _github_private_key_cache and (now - _github_private_key_fetched_at) < GITHUB_KEY_TTL:
        return _github_private_key_cache

    sm = boto3.client("secretsmanager", region_name=DEPLOY_REGION)
    resp = sm.get_secret_value(SecretId=GITHUB_PRIVATE_KEY_SECRET)
    _github_private_key_cache = resp["SecretString"]
    _github_private_key_fetched_at = now
    return _github_private_key_cache


def _generate_app_jwt() -> str:
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (9 * 60),
        "iss": str(GITHUB_APP_ID),
    }
    private_key = _get_github_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256")


def _get_installation_token() -> str:
    app_jwt = _generate_app_jwt()
    url = f"https://api.github.com/app/installations/{GITHUB_INSTALLATION_ID}/access_tokens"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
    return data["token"]


def _github_api(
    method: str, path: str, body: Optional[Dict] = None
) -> Tuple[int, Dict]:
    """Call GitHub REST API with installation token auth."""
    token = _get_installation_token()
    url = f"https://api.github.com{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode()
            return e.code, json.loads(body_text)
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


# ---------------------------------------------------------------------------
# Decision handlers
# ---------------------------------------------------------------------------


def _handle_approve(decision: Dict, user_sub: str, reason: str) -> dict:
    """Approve a deployment — merge the PR via GitHub API."""
    pr_number = decision.get("github_pr_number")
    repo = decision.get("github_repo", "NX-2021-L/enceladus")
    owner, repo_name = repo.split("/", 1) if "/" in repo else ("NX-2021-L", repo)

    if f"{owner}/{repo_name}" not in ALLOWED_REPOS:
        return _error(403, f"Repository {owner}/{repo_name} not in allowed repos")

    # Merge the PR
    status, gh_resp = _github_api(
        "PUT",
        f"/repos/{owner}/{repo_name}/pulls/{pr_number}/merge",
        {"merge_method": "merge"},
    )

    if status not in (200, 201):
        msg = gh_resp.get("message", "Unknown GitHub error")
        logger.error(f"GitHub merge failed for PR #{pr_number}: {status} {msg}")
        return _error(
            502,
            f"GitHub merge failed: {msg}",
            github_status=status,
            github_response=gh_resp,
        )

    # Update DynamoDB record
    updated = _update_decision(
        project_id=decision["project_id"],
        record_id=decision["record_id"],
        status="approved",
        final_target="prod",
        decided_by=user_sub,
        decision_reason=reason,
    )

    logger.info(f"PR #{pr_number} approved and merged by {user_sub}")
    return _ok({
        "action": "approve",
        "pr_number": pr_number,
        "merged": True,
        "merge_sha": gh_resp.get("sha", ""),
        "decision": updated,
    })


def _handle_divert(decision: Dict, user_sub: str, reason: str) -> dict:
    """Divert a deployment — retarget PR base branch to gamma integration branch."""
    pr_number = decision.get("github_pr_number")
    repo = decision.get("github_repo", "NX-2021-L/enceladus")
    owner, repo_name = repo.split("/", 1) if "/" in repo else ("NX-2021-L", repo)

    if f"{owner}/{repo_name}" not in ALLOWED_REPOS:
        return _error(403, f"Repository {owner}/{repo_name} not in allowed repos")

    # Retarget PR base branch to gamma integration branch
    status, gh_resp = _github_api(
        "PATCH",
        f"/repos/{owner}/{repo_name}/pulls/{pr_number}",
        {"base": GAMMA_INTEGRATION_BRANCH},
    )

    if status not in (200, 201):
        msg = gh_resp.get("message", "Unknown GitHub error")
        logger.error(f"GitHub retarget failed for PR #{pr_number}: {status} {msg}")
        return _error(
            502,
            f"GitHub retarget failed: {msg}",
            github_status=status,
            github_response=gh_resp,
        )

    # Add comment explaining the diversion
    comment_body = (
        f"**Deployment diverted to gamma** by {user_sub} via Enceladus Deployment Manager.\n\n"
        f"This PR has been retargeted from `main` to `{GAMMA_INTEGRATION_BRANCH}`.\n"
    )
    if reason:
        comment_body += f"\n**Reason:** {reason}\n"

    _github_api(
        "POST",
        f"/repos/{owner}/{repo_name}/issues/{pr_number}/comments",
        {"body": comment_body},
    )

    # Update DynamoDB record
    updated = _update_decision(
        project_id=decision["project_id"],
        record_id=decision["record_id"],
        status="diverted",
        final_target="gamma",
        decided_by=user_sub,
        decision_reason=reason,
    )

    logger.info(f"PR #{pr_number} diverted to {GAMMA_INTEGRATION_BRANCH} by {user_sub}")
    return _ok({
        "action": "divert",
        "pr_number": pr_number,
        "new_base": GAMMA_INTEGRATION_BRANCH,
        "decision": updated,
    })


def _handle_revert(decision: Dict, user_sub: str, reason: str) -> dict:
    """Revert a deployment — close the PR without merging."""
    pr_number = decision.get("github_pr_number")
    repo = decision.get("github_repo", "NX-2021-L/enceladus")
    owner, repo_name = repo.split("/", 1) if "/" in repo else ("NX-2021-L", repo)

    if not reason:
        return _error(400, "Revert requires a reason (decision_reason field)")

    if f"{owner}/{repo_name}" not in ALLOWED_REPOS:
        return _error(403, f"Repository {owner}/{repo_name} not in allowed repos")

    # Add closing comment with reason
    comment_body = (
        f"**Deployment reverted** by {user_sub} via Enceladus Deployment Manager.\n\n"
        f"**Reason:** {reason}\n\n"
        f"The PR branch is preserved for future rework."
    )
    _github_api(
        "POST",
        f"/repos/{owner}/{repo_name}/issues/{pr_number}/comments",
        {"body": comment_body},
    )

    # Close the PR
    status, gh_resp = _github_api(
        "PATCH",
        f"/repos/{owner}/{repo_name}/pulls/{pr_number}",
        {"state": "closed"},
    )

    if status not in (200, 201):
        msg = gh_resp.get("message", "Unknown GitHub error")
        logger.error(f"GitHub close failed for PR #{pr_number}: {status} {msg}")
        return _error(
            502,
            f"GitHub close failed: {msg}",
            github_status=status,
            github_response=gh_resp,
        )

    # Update DynamoDB record
    updated = _update_decision(
        project_id=decision["project_id"],
        record_id=decision["record_id"],
        status="reverted",
        final_target="blocked",
        decided_by=user_sub,
        decision_reason=reason,
    )

    logger.info(f"PR #{pr_number} reverted (closed) by {user_sub}: {reason}")
    return _ok({
        "action": "revert",
        "pr_number": pr_number,
        "closed": True,
        "decision": updated,
    })


# ---------------------------------------------------------------------------
# Route patterns
# ---------------------------------------------------------------------------

_DECIDE_PATTERN = re.compile(r"^(?:/api/v1)?/deploy/decide$")
_OPTIONS_PATTERN = re.compile(r"^(?:/api/v1)?/deploy/")

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Main entry point for deploy_decide Lambda."""
    method = event.get("requestContext", {}).get("http", {}).get("method", "").upper()
    raw_path = event.get("rawPath", event.get("path", ""))

    # CORS preflight
    if method == "OPTIONS":
        return _options()

    # Only POST /deploy/decide is supported
    if not _DECIDE_PATTERN.search(raw_path):
        return _error(404, f"Route not found: {method} {raw_path}")

    if method != "POST":
        return _error(405, f"Method {method} not allowed. Use POST.")

    # -----------------------------------------------------------------------
    # Auth: Cognito ONLY — no internal API key path
    # -----------------------------------------------------------------------
    claims = _validate_cognito_token(event)
    if not claims:
        return _error(
            401,
            "Cognito authentication required. Deploy decisions are human-only actions.",
        )

    user_sub = claims.get("sub", "unknown")
    user_email = claims.get("email", user_sub)

    # -----------------------------------------------------------------------
    # Parse request body
    # -----------------------------------------------------------------------
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return _error(400, "Invalid JSON in request body")

    action = body.get("action", "").lower()
    if action not in ("approve", "divert", "revert"):
        return _error(
            400,
            f"Invalid action: '{action}'. Must be 'approve', 'divert', or 'revert'.",
            allowed_actions=["approve", "divert", "revert"],
        )

    pr_number = body.get("pr_number")
    if not pr_number:
        return _error(400, "pr_number is required")

    project_id = body.get("project_id", "enceladus")
    reason = body.get("decision_reason", "")

    # -----------------------------------------------------------------------
    # Look up the deployment_decision record
    # -----------------------------------------------------------------------
    record_id = f"decision#ENC-DPL-{pr_number}"
    decision = _get_decision(project_id, record_id)

    if not decision:
        return _error(
            404,
            f"No deployment decision found for PR #{pr_number}",
            pr_number=pr_number,
            record_id=record_id,
        )

    current_status = decision.get("status", "")
    if current_status != "pending_approval":
        return _error(
            409,
            f"Decision for PR #{pr_number} is in status '{current_status}', not 'pending_approval'",
            current_status=current_status,
            pr_number=pr_number,
        )

    # -----------------------------------------------------------------------
    # Execute the decision
    # -----------------------------------------------------------------------
    logger.info(
        f"Executing {action} on PR #{pr_number} by {user_email} (sub={user_sub})"
    )

    if action == "approve":
        return _handle_approve(decision, user_sub, reason)
    elif action == "divert":
        return _handle_divert(decision, user_sub, reason)
    elif action == "revert":
        return _handle_revert(decision, user_sub, reason)

    # Should never reach here
    return _error(500, "Unexpected action routing failure")
