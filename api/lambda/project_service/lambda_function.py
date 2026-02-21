"""project_service/lambda_function.py

Lambda service for centralized project lifecycle management via the Enceladus API.
Handles creation, listing, and retrieval of projects from the `projects` DynamoDB
table.  All project initialization flows through this service — agents and users
cannot create projects by writing directly to DynamoDB.

Routes (via API Gateway proxy):
    POST   /api/v1/projects                        Create a new project
    GET    /api/v1/projects                        List all projects
    GET    /api/v1/projects/{projectName}           Get a single project
    OPTIONS /api/v1/projects[/{projectName}]        CORS preflight

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header.
    Validates the JWT using Cognito JWKS (RS256, cached module-level).

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    PROJECTS_TABLE         default: projects
    TRACKER_TABLE          default: devops-project-tracker
    DYNAMODB_REGION        default: us-west-2
    S3_BUCKET              default: jreese-net
    S3_REFERENCE_PREFIX    default: mobile/v1/reference
    TEMPLATE_URL           default: agentharmony GitHub raw URL
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
S3_BUCKET = os.environ.get("S3_BUCKET", "jreese-net")
S3_REFERENCE_PREFIX = os.environ.get("S3_REFERENCE_PREFIX", "mobile/v1/reference")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = "https://jreese.net"
PREFIX_GSI = "prefix-index"
TRACKER_GSI = "project-type-index"
TEMPLATE_URL = os.environ.get(
    "TEMPLATE_URL",
    "https://raw.githubusercontent.com/me-jreese/agentharmony/main/"
    "src/agent-reference-template/%24PROJECT-reference-template.md",
)

# Validation patterns
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,49}$")
_PREFIX_PATTERN = re.compile(r"^[A-Z]{3}$")
_REPO_URL_PATTERN = re.compile(r"^https?://[^\s]+$")
_VALID_CREATE_STATUSES = {"planning", "development", "active_production"}
_ALL_STATUSES = _VALID_CREATE_STATUSES | {"closed", "archived"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level caches (reused across warm Lambda invocations)
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

_deserializer = TypeDeserializer()

# ---------------------------------------------------------------------------
# JWT Auth (identical pattern to tracker_mutation)
# ---------------------------------------------------------------------------


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
    keys = _get_jwks()
    pub_key = keys.get(kid)
    if pub_key is None:
        raise ValueError("Token key ID not found in JWKS")
    try:
        claims = jwt.decode(
            token, pub_key, algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID, options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc
    return claims


def _extract_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header or API Gateway v2 cookies."""
    headers = event.get("headers") or {}
    cookie_parts: List[str] = []

    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if isinstance(part, str) and part.strip())
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if not part.startswith("enceladus_id_token="):
            continue
        return unquote(part[len("enceladus_id_token="):])
    return None


def _cookie_names(event: Dict[str, Any]) -> List[str]:
    """Collect cookie names only (never values) for auth diagnostics."""
    headers = event.get("headers") or {}
    names: List[str] = []

    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        for part in cookie_header.split(";"):
            token = part.strip()
            if "=" in token:
                names.append(token.split("=", 1)[0].strip())

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        for part in event_cookies:
            if isinstance(part, str) and "=" in part:
                names.append(part.split("=", 1)[0].strip())
    elif isinstance(event_cookies, str) and "=" in event_cookies:
        names.append(event_cookies.split("=", 1)[0].strip())

    return sorted(set(name for name in names if name))


def _event_path(event: Dict[str, Any]) -> str:
    return event.get("rawPath") or event.get("path", "")


def _event_method(event: Dict[str, Any]) -> str:
    return (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )


# ---------------------------------------------------------------------------
# AWS Clients (module-level for container reuse)
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", region_name=DYNAMODB_REGION)
    return _s3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_z() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deserialize_item(raw: Dict) -> Dict[str, Any]:
    return {k: _deserializer.deserialize(v) for k, v in raw.items()}


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str, **extra) -> Dict:
    body: Dict[str, Any] = {"success": False, "error": message}
    body.update(extra)
    return _response(status_code, body)


# ---------------------------------------------------------------------------
# days_since_active computation
# ---------------------------------------------------------------------------


def _compute_days_since_active(project_id: str) -> Optional[int]:
    """Query devops-project-tracker for the max updated_at across all records."""
    ddb = _get_ddb()
    try:
        resp = ddb.query(
            TableName=TRACKER_TABLE,
            IndexName=TRACKER_GSI,
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": project_id}},
            ProjectionExpression="updated_at",
            ScanIndexForward=False,
        )
    except (BotoCoreError, ClientError):
        return None

    max_ts: Optional[str] = None
    for item in resp.get("Items", []):
        ts = item.get("updated_at", {}).get("S")
        if ts and (max_ts is None or ts > max_ts):
            max_ts = ts
    # Handle pagination
    while resp.get("LastEvaluatedKey"):
        try:
            resp = ddb.query(
                TableName=TRACKER_TABLE,
                IndexName=TRACKER_GSI,
                KeyConditionExpression="project_id = :pid",
                ExpressionAttributeValues={":pid": {"S": project_id}},
                ProjectionExpression="updated_at",
                ScanIndexForward=False,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
        except (BotoCoreError, ClientError):
            break
        for item in resp.get("Items", []):
            ts = item.get("updated_at", {}).get("S")
            if ts and (max_ts is None or ts > max_ts):
                max_ts = ts

    if not max_ts:
        return None
    try:
        last_dt = _dt.datetime.fromisoformat(max_ts.replace("Z", "+00:00"))
        now_dt = _dt.datetime.now(_dt.timezone.utc)
        return (now_dt - last_dt).days
    except (ValueError, TypeError):
        return None


def _enrich_project(item: Dict[str, Any]) -> Dict[str, Any]:
    """Add days_since_active to a project dict."""
    pid = item.get("project_id", "")
    days = _compute_days_since_active(pid)
    item["days_since_active"] = days
    return item


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_create_input(body: Dict) -> Tuple[Optional[Dict], Optional[str]]:
    errors: List[str] = []
    name = (body.get("name") or "").strip()
    if not name or not _NAME_PATTERN.match(name):
        errors.append("name: required, 1-50 chars, must match ^[a-z][a-z0-9_-]*$")
    prefix = (body.get("prefix") or "").strip().upper()
    if not prefix or not _PREFIX_PATTERN.match(prefix):
        errors.append("prefix: required, exactly 3 uppercase letters")
    summary = (body.get("summary") or "").strip()
    if not summary or len(summary) > 500:
        errors.append("summary: required, 1-500 chars")
    status = (body.get("status") or "planning").strip()
    if status not in _VALID_CREATE_STATUSES:
        errors.append(f"status: must be one of {sorted(_VALID_CREATE_STATUSES)}")
    parent = body.get("parent")
    if parent is not None:
        parent = str(parent).strip()
        if not parent:
            parent = None
    repo = body.get("repo")
    if repo is not None:
        repo = str(repo).strip()
        if not repo:
            repo = None
        elif len(repo) > 2048 or not _REPO_URL_PATTERN.match(repo):
            errors.append("repo: when provided, must be a valid http(s) URL up to 2048 characters")
    if errors:
        return None, "; ".join(errors)
    return {
        "name": name, "prefix": prefix, "summary": summary,
        "status": status, "parent": parent, "repo": repo,
    }, None


# ---------------------------------------------------------------------------
# Reference doc template
# ---------------------------------------------------------------------------


def _fetch_reference_template(project_name: str) -> str:
    """Fetch the latest reference doc template from agentharmony GitHub and
    substitute $PROJECT placeholders."""
    try:
        with urllib.request.urlopen(TEMPLATE_URL, timeout=10) as resp:
            template = resp.read().decode("utf-8")
    except Exception as exc:
        logger.warning("Failed to fetch template from GitHub: %s — using minimal fallback", exc)
        template = (
            "# $PROJECT Reference Document\n\n"
            "## 1. Executive Summary\n\nTBD\n\n"
            "## 2. Project Overview\n\nTBD\n\n"
            "## 3. Technical Architecture\n\nTBD\n\n"
            "## 4. Document Update Log\n\n"
            f"| Date | Author | Summary |\n|------|--------|---------|\n"
            f"| {_now_z()} | project-service | Initial document created |\n"
        )
    return template.replace("$PROJECT", project_name)


# ---------------------------------------------------------------------------
# CREATE project (POST /api/v1/projects)
# ---------------------------------------------------------------------------


def _handle_create(body: Dict, claims: Dict) -> Dict:
    data, validation_error = _validate_create_input(body)
    if validation_error:
        return _error(400, validation_error)

    ddb = _get_ddb()
    name = data["name"]
    prefix = data["prefix"]
    summary = data["summary"]
    status = data["status"]
    parent = data["parent"]
    repo = data["repo"]
    now = _now_z()
    created_by = claims.get("sub", "unknown")

    # Step 2: Check name uniqueness
    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": name}},
            ProjectionExpression="project_id, prefix, #s",
            ExpressionAttributeNames={"#s": "status"},
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("name uniqueness check failed: %s", exc)
        return _error(500, "Database read failed.")
    if resp.get("Item"):
        existing = _deserialize_item(resp["Item"])
        return _error(409, f"Project '{name}' already exists", existing_project=existing)

    # Step 3: Check prefix uniqueness
    try:
        resp = ddb.query(
            TableName=PROJECTS_TABLE,
            IndexName=PREFIX_GSI,
            KeyConditionExpression="prefix = :p",
            ExpressionAttributeValues={":p": {"S": prefix}},
            ProjectionExpression="project_id, prefix",
            Limit=1,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("prefix uniqueness check failed: %s", exc)
        return _error(500, "Database read failed.")
    if resp.get("Items"):
        existing = _deserialize_item(resp["Items"][0])
        return _error(409, f"Prefix '{prefix}' is already assigned to project '{existing['project_id']}'")

    # Step 4: Verify parent exists (if provided)
    path = f"projects/{name}"
    if parent:
        try:
            resp = ddb.get_item(
                TableName=PROJECTS_TABLE,
                Key={"project_id": {"S": parent}},
                ProjectionExpression="project_id, #p",
                ExpressionAttributeNames={"#p": "path"},
            )
        except (BotoCoreError, ClientError) as exc:
            logger.error("parent check failed: %s", exc)
            return _error(500, "Database read failed.")
        if not resp.get("Item"):
            return _error(400, f"Parent project '{parent}' not found")
        parent_item = _deserialize_item(resp["Item"])
        parent_path = parent_item.get("path", f"projects/{parent}")
        path = f"{parent_path}/{name}"

    # Step 6: PutItem to projects table
    item: Dict[str, Dict[str, str]] = {
        "project_id": {"S": name},
        "prefix": {"S": prefix},
        # Path remains computed internally for hierarchy support and backward compatibility.
        "path": {"S": path},
        "summary": {"S": summary},
        "status": {"S": status},
        "created_at": {"S": now},
        "updated_at": {"S": now},
        "created_by": {"S": created_by},
    }
    if parent:
        item["parent"] = {"S": parent}
    if repo:
        item["repo"] = {"S": repo}

    try:
        ddb.put_item(
            TableName=PROJECTS_TABLE,
            Item=item,
            ConditionExpression="attribute_not_exists(project_id)",
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        return _error(409, f"Project '{name}' already exists (race condition)")
    except (BotoCoreError, ClientError) as exc:
        logger.error("projects table write failed: %s", exc)
        return _error(500, "Failed to create project entry.")

    init_status = {"projects_table": "created"}

    # Step 7: PutItem reference metadata row to tracker table
    ref_sk = f"reference#{name}"
    s3_key = f"{S3_REFERENCE_PREFIX}/{name}.md"
    try:
        ddb.put_item(
            TableName=TRACKER_TABLE,
            Item={
                "project_id": {"S": name},
                "record_id": {"S": ref_sk},
                "record_type": {"S": "reference"},
                "item_id": {"S": name},
                "title": {"S": f"{name} reference document"},
                "status": {"S": "active"},
                "s3_key": {"S": s3_key},
                "s3_bucket": {"S": S3_BUCKET},
                "sync_version": {"N": "1"},
                "created_at": {"S": now},
                "updated_at": {"S": now},
            },
            ConditionExpression="attribute_not_exists(project_id)",
        )
        init_status["tracker_reference_row"] = "created"
    except (BotoCoreError, ClientError) as exc:
        logger.error("tracker reference row failed: %s — rolling back projects entry", exc)
        _rollback_projects_entry(name)
        return _error(500, "Initialization failed at step 'tracker_reference_row'. Rolled back projects_table entry.",
                       failed_step="tracker_reference_row")

    # Step 8: Upload reference doc template to S3
    try:
        template_content = _fetch_reference_template(name)
        _get_s3().put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=template_content.encode("utf-8"),
            ContentType="text/markdown; charset=utf-8",
            CacheControl="max-age=0, s-maxage=300, must-revalidate",
        )
        init_status["s3_reference_doc"] = "created"
    except Exception as exc:
        logger.error("S3 reference doc failed: %s — rolling back both entries", exc)
        _rollback_tracker_reference(name, ref_sk)
        _rollback_projects_entry(name)
        return _error(500, "Initialization failed at step 's3_reference_doc'. Rolled back all entries.",
                       failed_step="s3_reference_doc")

    logger.info("project created: %s (prefix=%s, status=%s)", name, prefix, status)

    project_data = {
        "project_id": name,
        "prefix": prefix,
        # Deprecated client-facing field; retained to avoid breaking existing consumers.
        "path": path,
        "repo": repo,
        "summary": summary,
        "status": status,
        "parent": parent,
        "created_at": now,
        "updated_at": now,
        "created_by": created_by,
    }
    return _response(201, {
        "success": True,
        "project": project_data,
        "initialization": init_status,
    })


def _rollback_projects_entry(name: str) -> None:
    try:
        _get_ddb().delete_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": name}},
        )
        logger.info("rollback: deleted projects entry for %s", name)
    except Exception as exc:
        logger.error("rollback failed for projects entry %s: %s", name, exc)


def _rollback_tracker_reference(name: str, ref_sk: str) -> None:
    try:
        _get_ddb().delete_item(
            TableName=TRACKER_TABLE,
            Key={"project_id": {"S": name}, "record_id": {"S": ref_sk}},
        )
        logger.info("rollback: deleted tracker reference for %s", name)
    except Exception as exc:
        logger.error("rollback failed for tracker reference %s: %s", name, exc)


# ---------------------------------------------------------------------------
# LIST projects (GET /api/v1/projects)
# ---------------------------------------------------------------------------


def _handle_list(query_params: Dict) -> Dict:
    ddb = _get_ddb()

    try:
        resp = ddb.scan(TableName=PROJECTS_TABLE)
        items = resp.get("Items", [])
        while resp.get("LastEvaluatedKey"):
            resp = ddb.scan(
                TableName=PROJECTS_TABLE,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
    except (BotoCoreError, ClientError) as exc:
        logger.error("scan failed: %s", exc)
        return _error(500, "Database read failed.")

    projects = [_deserialize_item(raw) for raw in items]

    # Filter
    status_filter = query_params.get("status")
    active_filter = query_params.get("active")
    if status_filter:
        projects = [p for p in projects if p.get("status") == status_filter]
    elif active_filter and active_filter.lower() == "true":
        projects = [p for p in projects if p.get("status") not in ("closed", "archived")]

    # Enrich with days_since_active
    for p in projects:
        _enrich_project(p)

    projects.sort(key=lambda p: p.get("project_id", ""))

    return _response(200, {
        "success": True,
        "projects": projects,
        "count": len(projects),
    })


# ---------------------------------------------------------------------------
# GET single project (GET /api/v1/projects/{name})
# ---------------------------------------------------------------------------


def _handle_get(project_name: str) -> Dict:
    ddb = _get_ddb()

    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_name}},
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    raw_item = resp.get("Item")
    if not raw_item:
        return _error(404, f"Project '{project_name}' not found")

    project = _enrich_project(_deserialize_item(raw_item))
    return _response(200, {"success": True, "project": project})


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------

_PROJECTS_PATH = re.compile(
    r"^(?:/api/v1)?/projects(?:/(?P<projectName>[a-z0-9_-]+))?$"
)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict, context: Any) -> Dict:
    method = _event_method(event)
    path = _event_path(event)

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # Auth
    token = _extract_token(event)
    if not token:
        logger.warning(
            "auth failed: no enceladus_id_token found. method=%s path=%s cookie_names=%s has_event_cookies=%s",
            method,
            path,
            _cookie_names(event),
            bool(event.get("cookies")),
        )
        return _error(401, "Authentication required. Please sign in.")
    try:
        claims = _verify_token(token)
    except ValueError as exc:
        logger.warning(
            "auth failed: token validation failed. method=%s path=%s error=%s",
            method,
            path,
            str(exc),
        )
        return _error(401, str(exc))

    # Parse path
    path_params = event.get("pathParameters") or {}
    project_name = path_params.get("projectName")
    if project_name is None:
        m = _PROJECTS_PATH.match(path)
        if m:
            project_name = m.group("projectName")

    # Route
    if method == "POST" and project_name is None:
        try:
            body = json.loads(event.get("body") or "{}")
        except (ValueError, TypeError):
            return _error(400, "Invalid JSON body.")
        return _handle_create(body, claims)

    elif method == "GET" and project_name is None:
        qs = event.get("queryStringParameters") or {}
        return _handle_list(qs)

    elif method == "GET" and project_name:
        return _handle_get(project_name)

    else:
        return _error(405, "Method not allowed.")
