"""github_integration/lambda_function.py — GitHub Integration API for Enceladus

Lambda API that proxies GitHub issue operations through a registered GitHub App.
Authenticates to GitHub using RS256 JWT → installation access token flow.

Routes (via API Gateway proxy):
    POST   /api/v1/github/issues        — create a GitHub issue
    POST   /api/v1/github/webhook       — receive GitHub webhook events
    GET    /api/v1/github/projects       — list org projects (Projects v2)
    POST   /api/v1/github/projects/sync  — sync issue to project board
    OPTIONS /api/v1/github/*             — CORS preflight

Auth:
    /issues: Cognito JWT cookie or X-Coordination-Internal-Key header.
    /webhook: GitHub HMAC-SHA256 signature (X-Hub-Signature-256).

Environment variables:
    COGNITO_USER_POOL_ID        us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID           6q607dk3liirhtecgps7hifmlk
    GITHUB_APP_ID               GitHub App numeric ID
    GITHUB_INSTALLATION_ID      Installation ID for NX-2021-L org
    GITHUB_PRIVATE_KEY_SECRET   Secrets Manager secret name (default: devops/github-app/private-key)
    GITHUB_WEBHOOK_SECRET       Secrets Manager secret name for webhook HMAC key
    TRACKER_API_BASE            Tracker mutation API base URL
    DYNAMODB_REGION             default: us-west-2
    COORDINATION_INTERNAL_API_KEY  (service auth key)

ENC-FTR-021 Phase 2 (ENC-TSK-575) + Phase 3 (ENC-TSK-569) + Phase 4 (ENC-TSK-570).
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
# Configuration
# ---------------------------------------------------------------------------

COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
COORDINATION_INTERNAL_API_KEY_PREVIOUS = os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
COORDINATION_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    COORDINATION_INTERNAL_API_KEY,
    COORDINATION_INTERNAL_API_KEY_PREVIOUS,
)
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

# Webhook configuration (Phase 3)
GITHUB_WEBHOOK_SECRET_NAME = os.environ.get(
    "GITHUB_WEBHOOK_SECRET", "devops/github-app/webhook-secret"
)
TRACKER_API_BASE = os.environ.get(
    "TRACKER_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker",
)

# Record ID parsing: prefix → project, type suffix → record type
_PREFIX_TO_PROJECT = {"ENC": "enceladus", "DVP": "devops"}
_TYPE_SUFFIX_TO_RECORD_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature"}

# Regex to extract Enceladus record ID from GitHub issue body footer.
# Handles both Lambda-created (**Enceladus Record**: `X`) and
# frontend-created (Enceladus Record: `X`) formats.
_RE_RECORD_ID = re.compile(
    r"(?:\*\*)?Enceladus Record(?:\*\*)?:\s*`([A-Z]+-(?:TSK|ISS|FTR)-\d{3,})`"
)

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
# Webhook secret cache
# ---------------------------------------------------------------------------

_webhook_secret_cache: Optional[str] = None
_webhook_secret_fetched_at: float = 0.0
_WEBHOOK_SECRET_TTL: float = 3600.0


def _get_webhook_secret() -> str:
    """Fetch GitHub webhook HMAC secret from Secrets Manager (cached)."""
    global _webhook_secret_cache, _webhook_secret_fetched_at
    now = time.time()
    if _webhook_secret_cache and (now - _webhook_secret_fetched_at) < _WEBHOOK_SECRET_TTL:
        return _webhook_secret_cache

    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=GITHUB_WEBHOOK_SECRET_NAME)
    _webhook_secret_cache = resp["SecretString"]
    _webhook_secret_fetched_at = now
    return _webhook_secret_cache


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
# GitHub GraphQL API (Phase 4 — Projects v2)
# ---------------------------------------------------------------------------

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


def _graphql_request(query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
    """Execute a GitHub GraphQL query/mutation using installation token."""
    token = _get_installation_token()
    payload: Dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables

    req = urllib.request.Request(
        GITHUB_GRAPHQL_URL,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        logger.error("GraphQL request failed: %s %s", exc.code, body_text)
        raise ValueError(f"GraphQL request failed ({exc.code}): {body_text}") from exc

    if data.get("errors"):
        err_msgs = "; ".join(e.get("message", "") for e in data["errors"])
        raise ValueError(f"GraphQL errors: {err_msgs}")
    return data.get("data", {})


# ---------------------------------------------------------------------------
# Project field cache (5-min TTL)
# ---------------------------------------------------------------------------

_project_fields_cache: Dict[str, Dict] = {}  # project_node_id -> field data
_project_fields_fetched_at: Dict[str, float] = {}
_PROJECT_FIELDS_TTL: float = 300.0  # 5 minutes

_GQL_PROJECT_FIELDS = """
query($projectId: ID!) {
  node(id: $projectId) {
    ... on ProjectV2 {
      fields(first: 30) {
        nodes {
          ... on ProjectV2SingleSelectField {
            id
            name
            options { id name }
          }
          ... on ProjectV2Field {
            id
            name
          }
        }
      }
    }
  }
}
"""


def _get_project_fields(project_node_id: str) -> Dict[str, Any]:
    """Get project field definitions (cached). Returns {field_name: {id, options}}."""
    now = time.time()
    cached_at = _project_fields_fetched_at.get(project_node_id, 0.0)
    if project_node_id in _project_fields_cache and (now - cached_at) < _PROJECT_FIELDS_TTL:
        return _project_fields_cache[project_node_id]

    data = _graphql_request(_GQL_PROJECT_FIELDS, {"projectId": project_node_id})
    node = data.get("node") or {}
    fields_nodes = (node.get("fields") or {}).get("nodes") or []

    result: Dict[str, Any] = {}
    for f in fields_nodes:
        name = f.get("name", "")
        if not name:
            continue
        entry: Dict[str, Any] = {"id": f["id"], "name": name}
        if "options" in f:
            entry["options"] = {
                opt["name"].lower(): opt["id"] for opt in f["options"]
            }
        result[name.lower()] = entry

    _project_fields_cache[project_node_id] = result
    _project_fields_fetched_at[project_node_id] = now
    return result


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
    if COORDINATION_INTERNAL_API_KEYS:
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key in COORDINATION_INTERNAL_API_KEYS:
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
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
# Webhook signature verification
# ---------------------------------------------------------------------------


def _verify_webhook_signature(event: Dict) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    headers = event.get("headers") or {}
    signature_header = (
        headers.get("x-hub-signature-256")
        or headers.get("X-Hub-Signature-256")
        or ""
    )
    if not signature_header.startswith("sha256="):
        return False

    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")

    secret = _get_webhook_secret()
    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    received = signature_header[len("sha256="):]
    return hmac.compare_digest(expected, received)


# ---------------------------------------------------------------------------
# Record ID parsing helpers
# ---------------------------------------------------------------------------


def _extract_record_id(issue_body: str) -> Optional[str]:
    """Extract Enceladus record ID from GitHub issue body footer."""
    if not issue_body:
        return None
    m = _RE_RECORD_ID.search(issue_body)
    return m.group(1) if m else None


def _parse_record_id(record_id: str) -> Optional[Dict[str, str]]:
    """Parse record ID into project_id, record_type, record_id.

    E.g. 'ENC-TSK-564' -> {project_id: 'enceladus', record_type: 'task', ...}
    """
    parts = record_id.split("-")
    if len(parts) != 3:
        return None
    prefix, type_suffix, _number = parts
    record_type = _TYPE_SUFFIX_TO_RECORD_TYPE.get(type_suffix)
    project_id = _PREFIX_TO_PROJECT.get(prefix)
    if not record_type or not project_id:
        return None
    return {
        "project_id": project_id,
        "record_type": record_type,
        "record_id": record_id,
    }


# ---------------------------------------------------------------------------
# Tracker API client (HTTPS with internal key auth)
# ---------------------------------------------------------------------------


def _tracker_api_call(
    method: str, path: str, body: Optional[Dict] = None
) -> Tuple[int, Dict]:
    """Call the tracker mutation API. Returns (status_code, response_dict)."""
    url = f"{TRACKER_API_BASE}/{path}"
    data = json.dumps(body).encode("utf-8") if body else None

    req = urllib.request.Request(
        url,
        method=method,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        resp_text = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(resp_text)
        except (json.JSONDecodeError, TypeError):
            return exc.code, {"error": resp_text}
    except Exception as exc:
        logger.error("Tracker API call failed: %s %s — %s", method, url, exc)
        return 0, {"error": str(exc)}


# ---------------------------------------------------------------------------
# POST /api/v1/github/webhook — GitHub webhook receiver
# ---------------------------------------------------------------------------


def _handle_webhook(event: Dict) -> Dict:
    """Process incoming GitHub webhook events.

    Uses HMAC signature verification — NOT Cognito/internal-key auth.
    """
    if not _verify_webhook_signature(event):
        logger.warning("Webhook signature verification failed")
        return _error(401, "Invalid webhook signature.")

    body = _parse_body(event)
    if not body:
        return _error(400, "Invalid JSON payload.")

    headers = event.get("headers") or {}
    gh_event = (
        headers.get("x-github-event")
        or headers.get("X-GitHub-Event")
        or ""
    )
    action = body.get("action", "")
    delivery_id = (
        headers.get("x-github-delivery")
        or headers.get("X-GitHub-Delivery")
        or "unknown"
    )

    logger.info(
        "Webhook received: event=%s action=%s delivery=%s",
        gh_event, action, delivery_id,
    )

    # Extract issue data and linked record
    issue = body.get("issue") or {}
    issue_body_text = issue.get("body") or ""
    issue_number = issue.get("number", 0)
    issue_url = issue.get("html_url", "")
    repo_full = body.get("repository", {}).get("full_name", "")

    record_id = _extract_record_id(issue_body_text)
    if not record_id:
        logger.info(
            "Webhook %s/%s on %s#%d: no linked Enceladus record",
            gh_event, action, repo_full, issue_number,
        )
        return _response(200, {
            "processed": False,
            "reason": "no_linked_record",
            "event": gh_event,
            "action": action,
        })

    parsed = _parse_record_id(record_id)
    if not parsed:
        logger.warning("Webhook: unparseable record_id '%s'", record_id)
        return _response(200, {
            "processed": False,
            "reason": "unparseable_record_id",
            "record_id": record_id,
        })

    project_id = parsed["project_id"]
    record_type = parsed["record_type"]

    # Dispatch by event type + action
    if gh_event == "issues" and action == "closed":
        return _webhook_issue_closed(
            project_id, record_type, record_id,
            issue_number, repo_full, body,
        )
    elif gh_event == "issues" and action == "reopened":
        return _webhook_issue_reopened(
            project_id, record_type, record_id,
            issue_number, repo_full,
        )
    elif gh_event == "issue_comment" and action == "created":
        return _webhook_comment_created(
            project_id, record_type, record_id,
            issue_number, repo_full, body,
        )
    else:
        logger.info(
            "Webhook %s/%s on %s#%d (record %s): ignored",
            gh_event, action, repo_full, issue_number, record_id,
        )
        return _response(200, {
            "processed": False,
            "reason": "action_not_handled",
            "event": gh_event,
            "action": action,
            "record_id": record_id,
        })


def _webhook_issue_closed(
    project_id: str, record_type: str, record_id: str,
    issue_number: int, repo_full: str, payload: Dict,
) -> Dict:
    """Handle issues.closed → close the linked Enceladus record."""
    closed_by = payload.get("sender", {}).get("login", "unknown")
    api_path = f"{project_id}/{record_type}/{record_id}"

    status, resp = _tracker_api_call("PATCH", api_path, {
        "action": "close",
        "note": f"Closed via GitHub ({repo_full}#{issue_number}) by @{closed_by}",
    })

    logger.info(
        "Webhook issues.closed: record=%s tracker_status=%d",
        record_id, status,
    )

    if status == 200:
        return _response(200, {
            "processed": True, "event": "issues.closed",
            "record_id": record_id, "tracker_status": status,
        })
    elif status == 404:
        return _response(200, {
            "processed": False, "reason": "record_not_found",
            "record_id": record_id,
        })
    elif 400 <= status < 500:
        return _response(200, {
            "processed": False, "reason": "tracker_rejected",
            "record_id": record_id, "tracker_status": status,
            "tracker_error": resp.get("error", ""),
        })
    else:
        return _error(502, f"Tracker API error (status {status})")


def _webhook_issue_reopened(
    project_id: str, record_type: str, record_id: str,
    issue_number: int, repo_full: str,
) -> Dict:
    """Handle issues.reopened → reopen the linked Enceladus record."""
    api_path = f"{project_id}/{record_type}/{record_id}"

    status, resp = _tracker_api_call("PATCH", api_path, {"action": "reopen"})

    logger.info(
        "Webhook issues.reopened: record=%s tracker_status=%d",
        record_id, status,
    )

    if status == 200:
        return _response(200, {
            "processed": True, "event": "issues.reopened",
            "record_id": record_id, "tracker_status": status,
        })
    elif status == 404:
        return _response(200, {
            "processed": False, "reason": "record_not_found",
            "record_id": record_id,
        })
    elif 400 <= status < 500:
        return _response(200, {
            "processed": False, "reason": "tracker_rejected",
            "record_id": record_id, "tracker_status": status,
            "tracker_error": resp.get("error", ""),
        })
    else:
        return _error(502, f"Tracker API error (status {status})")


def _webhook_comment_created(
    project_id: str, record_type: str, record_id: str,
    issue_number: int, repo_full: str, payload: Dict,
) -> Dict:
    """Handle issue_comment.created → append worklog to linked record."""
    comment = payload.get("comment", {})
    comment_author = comment.get("user", {}).get("login", "unknown")
    comment_body = comment.get("body", "").strip()
    comment_url = comment.get("html_url", "")

    # Skip comments from our own bot to prevent feedback loops
    comment_user = comment.get("user", {})
    if comment_user.get("type") == "Bot":
        via_app = comment.get("performed_via_github_app") or {}
        if str(via_app.get("id", "")) == GITHUB_APP_ID:
            return _response(200, {
                "processed": False, "reason": "self_bot_comment",
                "record_id": record_id,
            })

    if not comment_body:
        return _response(200, {
            "processed": False, "reason": "empty_comment",
            "record_id": record_id,
        })

    # Truncate long comments
    max_len = 1500
    if len(comment_body) > max_len:
        comment_body = comment_body[:max_len] + "... (truncated)"

    description = (
        f"[GitHub] @{comment_author} commented on "
        f"{repo_full}#{issue_number}:\n\n{comment_body}"
    )
    if comment_url:
        description += f"\n\n[View comment]({comment_url})"

    api_path = f"{project_id}/{record_type}/{record_id}/log"
    status, resp = _tracker_api_call("POST", api_path, {
        "description": description,
    })

    logger.info(
        "Webhook issue_comment.created: record=%s tracker_status=%d",
        record_id, status,
    )

    if status == 200:
        return _response(200, {
            "processed": True, "event": "issue_comment.created",
            "record_id": record_id, "tracker_status": status,
        })
    elif status == 404:
        return _response(200, {
            "processed": False, "reason": "record_not_found",
            "record_id": record_id,
        })
    elif 400 <= status < 500:
        return _response(200, {
            "processed": False, "reason": "tracker_rejected",
            "record_id": record_id, "tracker_status": status,
        })
    else:
        return _error(502, f"Tracker API error (status {status})")


# ---------------------------------------------------------------------------
# GET /api/v1/github/projects — List org projects (Phase 4)
# ---------------------------------------------------------------------------

_GQL_LIST_PROJECTS = """
query($org: String!, $first: Int!) {
  organization(login: $org) {
    projectsV2(first: $first) {
      nodes {
        id
        title
        shortDescription
        url
        closed
        fields(first: 30) {
          nodes {
            ... on ProjectV2SingleSelectField {
              id
              name
              options { id name }
            }
            ... on ProjectV2Field {
              id
              name
            }
          }
        }
      }
    }
  }
}
"""


def _handle_list_projects(event: Dict, claims: Dict) -> Dict:
    """List GitHub Projects v2 for an organization."""
    qs = event.get("queryStringParameters") or {}
    org = qs.get("org", "NX-2021-L")
    include_closed = qs.get("include_closed", "false").lower() == "true"

    try:
        data = _graphql_request(_GQL_LIST_PROJECTS, {"org": org, "first": 20})
    except ValueError as exc:
        return _error(502, f"GitHub GraphQL error: {exc}")

    org_data = data.get("organization") or {}
    projects_nodes = (org_data.get("projectsV2") or {}).get("nodes") or []

    projects = []
    for p in projects_nodes:
        if not include_closed and p.get("closed"):
            continue
        fields = []
        for f in (p.get("fields") or {}).get("nodes") or []:
            entry = {"id": f.get("id"), "name": f.get("name", "")}
            if "options" in f:
                entry["options"] = [
                    {"id": o["id"], "name": o["name"]} for o in f["options"]
                ]
            fields.append(entry)
        projects.append({
            "node_id": p["id"],
            "title": p.get("title", ""),
            "description": p.get("shortDescription", ""),
            "url": p.get("url", ""),
            "closed": p.get("closed", False),
            "fields": fields,
        })

    return _response(200, {"success": True, "projects": projects})


# ---------------------------------------------------------------------------
# POST /api/v1/github/projects/sync — Add issue to project board (Phase 4)
# ---------------------------------------------------------------------------

_GQL_GET_ISSUE_NODE_ID = """
query($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    issue(number: $number) {
      id
      title
      url
    }
  }
}
"""

_GQL_ADD_TO_PROJECT = """
mutation($projectId: ID!, $contentId: ID!) {
  addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) {
    item {
      id
    }
  }
}
"""

_GQL_UPDATE_FIELD = """
mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
  updateProjectV2ItemFieldValue(input: {
    projectId: $projectId,
    itemId: $itemId,
    fieldId: $fieldId,
    value: {singleSelectOptionId: $optionId}
  }) {
    projectV2Item { id }
  }
}
"""

# Enceladus status → GitHub Projects v2 option name (case-insensitive lookup)
_STATUS_MAP = {
    "open": ["todo", "backlog", "open"],
    "in_progress": ["in progress", "in-progress", "doing"],
    "in-progress": ["in progress", "in-progress", "doing"],
    "closed": ["done", "closed", "complete"],
}

# Priority: Enceladus P0/P1/P2 → possible option names
_PRIORITY_MAP = {
    "p0": ["p0", "urgent", "critical"],
    "p1": ["p1", "high"],
    "p2": ["p2", "medium"],
    "p3": ["p3", "low"],
}


def _find_option_id(
    field_entry: Dict, value: str, mapping: Dict[str, List[str]]
) -> Optional[str]:
    """Find a single-select option ID by mapping Enceladus value to GitHub option name."""
    options = field_entry.get("options", {})  # {lower_name: option_id}
    # Direct match first
    if value.lower() in options:
        return options[value.lower()]
    # Mapped aliases
    aliases = mapping.get(value.lower(), [])
    for alias in aliases:
        if alias.lower() in options:
            return options[alias.lower()]
    return None


def _handle_sync_to_project(event: Dict, claims: Dict) -> Dict:
    """Add an issue to a GitHub Projects v2 board and set field values."""
    body = _parse_body(event)
    if not body:
        return _error(400, "Invalid JSON body.")

    owner = str(body.get("owner", "")).strip()
    repo = str(body.get("repo", "")).strip()
    issue_number = body.get("issue_number")
    project_node_id = str(body.get("project_id", "")).strip()
    status_value = str(body.get("status", "")).strip()
    priority_value = str(body.get("priority", "")).strip()

    # Allow issue_url as alternative to owner/repo/number
    issue_url = str(body.get("issue_url", "")).strip()
    if issue_url and not (owner and repo and issue_number):
        m = re.match(
            r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", issue_url
        )
        if m:
            owner, repo, issue_number = m.group(1), m.group(2), int(m.group(3))

    if not owner or not repo or not issue_number:
        return _error(400, "Provide owner, repo, issue_number (or issue_url).")
    if not project_node_id:
        return _error(400, "Field 'project_id' (node ID) is required.")

    issue_number = int(issue_number)

    # Step 1: Get issue node ID
    try:
        issue_data = _graphql_request(
            _GQL_GET_ISSUE_NODE_ID,
            {"owner": owner, "repo": repo, "number": issue_number},
        )
    except ValueError as exc:
        return _error(502, f"Failed to get issue node ID: {exc}")

    issue_node = (issue_data.get("repository") or {}).get("issue")
    if not issue_node:
        return _error(404, f"Issue {owner}/{repo}#{issue_number} not found.")
    issue_node_id = issue_node["id"]

    # Step 2: Add issue to project
    try:
        add_data = _graphql_request(
            _GQL_ADD_TO_PROJECT,
            {"projectId": project_node_id, "contentId": issue_node_id},
        )
    except ValueError as exc:
        return _error(502, f"Failed to add issue to project: {exc}")

    item_id = (add_data.get("addProjectV2ItemById") or {}).get("item", {}).get("id")
    if not item_id:
        return _error(502, "Project item creation returned no item ID.")

    # Step 3: Set field values (Status, Priority)
    field_updates = []
    if status_value or priority_value:
        try:
            fields = _get_project_fields(project_node_id)
        except ValueError as exc:
            logger.warning("Failed to fetch project fields: %s", exc)
            fields = {}

        if status_value and "status" in fields:
            option_id = _find_option_id(fields["status"], status_value, _STATUS_MAP)
            if option_id:
                try:
                    _graphql_request(_GQL_UPDATE_FIELD, {
                        "projectId": project_node_id,
                        "itemId": item_id,
                        "fieldId": fields["status"]["id"],
                        "optionId": option_id,
                    })
                    field_updates.append({"field": "Status", "value": status_value})
                except ValueError as exc:
                    logger.warning("Failed to set Status field: %s", exc)

        if priority_value and "priority" in fields:
            option_id = _find_option_id(fields["priority"], priority_value, _PRIORITY_MAP)
            if option_id:
                try:
                    _graphql_request(_GQL_UPDATE_FIELD, {
                        "projectId": project_node_id,
                        "itemId": item_id,
                        "fieldId": fields["priority"]["id"],
                        "optionId": option_id,
                    })
                    field_updates.append({"field": "Priority", "value": priority_value})
                except ValueError as exc:
                    logger.warning("Failed to set Priority field: %s", exc)

    logger.info(
        "Synced issue %s/%s#%d to project, item_id=%s fields=%s user=%s",
        owner, repo, issue_number, item_id, field_updates,
        claims.get("email") or claims.get("sub", "unknown"),
    )

    return _response(200, {
        "success": True,
        "item_id": item_id,
        "issue_node_id": issue_node_id,
        "issue": f"{owner}/{repo}#{issue_number}",
        "field_updates": field_updates,
    })


# ---------------------------------------------------------------------------
# Commit validation (ENC-FTR-022)
# ---------------------------------------------------------------------------


def _handle_validate_commit(event: Dict, claims: Dict) -> Dict:
    """GET /api/v1/github/commits/validate?owner=X&repo=Y&sha=Z

    Validates a commit SHA exists in a GitHub repository.
    Used by tracker mutation Lambda to gate the task→pushed transition.
    """
    qs = event.get("queryStringParameters") or {}
    owner = (qs.get("owner") or "").strip()
    repo = (qs.get("repo") or "").strip()
    sha = (qs.get("sha") or "").strip()

    if not owner or not repo or not sha:
        return _error(400, "Required query params: owner, repo, sha")

    full_repo = f"{owner}/{repo}"
    if full_repo not in ALLOWED_REPOS:
        return _error(403, f"Repository not allowed: {full_repo}")

    token = _get_installation_token()
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{sha}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            commit = data.get("commit", {})
            author = commit.get("author", {})
            return _response(200, {
                "valid": True,
                "sha": data.get("sha", sha),
                "message": commit.get("message", "")[:200],
                "author": author.get("name", ""),
                "date": author.get("date", ""),
            })
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 422):
            return _response(200, {"valid": False, "sha": sha, "reason": "commit_not_found"})
        body = exc.read().decode("utf-8", errors="replace")[:500]
        logger.error("GitHub commit validation API error %s: %s", exc.code, body)
        return _error(502, f"GitHub API error ({exc.code})")


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict, context: Any) -> Dict:
    method, path = _path_method(event)

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # Webhook endpoint — uses HMAC signature, NOT Cognito/internal-key auth
    if method == "POST" and "/github/webhook" in path:
        return _handle_webhook(event)

    # Authenticate (all other routes)
    claims, auth_err = _authenticate(event)
    if auth_err:
        return auth_err

    # Route
    if method == "POST" and "/github/projects/sync" in path:
        return _handle_sync_to_project(event, claims)
    elif method == "GET" and "/github/projects" in path:
        return _handle_list_projects(event, claims)
    elif method == "GET" and "/github/commits/validate" in path:
        return _handle_validate_commit(event, claims)
    elif method == "POST" and "/github/issues" in path:
        return _handle_create_issue(event, claims)
    else:
        return _error(404, f"Route not found: {method} {path}")
