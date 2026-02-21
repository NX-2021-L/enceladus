"""tracker_mutation/lambda_function.py

Lambda mutation API for the Enceladus PWA project tracker.
Handles PATCH requests to close/complete records or submit free-text update notes.

Route (via API Gateway proxy):
    PATCH /{projectId}/{recordType}/{recordId}
    OPTIONS /{projectId}/{recordType}/{recordId}  (CORS preflight)

Request body (JSON):
    { "action": "close" | "note" | "reopen", "note": "optional text ≤ 2000 chars (for note action)" }

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header.
    Validates the JWT using Cognito JWKS (RS256, cached module-level).

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k (enceladus-status-users pool)
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk (enceladus-status-web app client)
    DYNAMODB_TABLE         default: devops-project-tracker
    DYNAMODB_REGION        default: us-west-2

CORS:
    Allows https://jreese.net only. Lambda returns CORS headers on every response.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple
import urllib.request
from urllib.parse import unquote

import boto3
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

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = "https://jreese.net"
MAX_NOTE_LENGTH = 2000

# Valid record types and their closed/default statuses
_RECORD_TYPES = {"task", "issue", "feature"}
_CLOSED_STATUS = {"task": "closed", "issue": "closed", "feature": "completed"}
_DEFAULT_STATUS = {"task": "open", "issue": "open", "feature": "planned"}

# EventBridge event config for reopen notifications
EVENT_BUS = os.environ.get("EVENT_BUS", "default")
EVENT_SOURCE = "enceladus.tracker"
EVENT_DETAIL_TYPE_REOPENED = "record.status.reopened"

# Type segment mapping for SK construction
_TYPE_SEG_TO_SK_PREFIX = {"task": "task", "issue": "issue", "feature": "feature"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# EventBridge client (lazy)
# ---------------------------------------------------------------------------

_events_client = None


def _get_events():
    global _events_client
    if _events_client is None:
        _events_client = boto3.client("events")
    return _events_client


# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}   # kid → public key object
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0  # refresh JWKS hourly

# Project validation cache — 5-min TTL, fail-open
_project_cache: Dict[str, bool] = {}  # project_id → exists
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0


def _get_jwks() -> Dict[str, Any]:
    """Fetch (or return cached) Cognito JWKS keyed by kid."""
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
    """Validate a Cognito JWT and return the decoded claims.

    Raises ValueError with a user-safe message on any failure.
    """
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
            token,
            pub_key,
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

    return claims


def _extract_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header or API Gateway v2 cookies."""
    headers = event.get("headers") or {}
    cookie_parts = []

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


# ---------------------------------------------------------------------------
# Project validation (fail-open)
# ---------------------------------------------------------------------------


def _validate_project_exists(project_id: str) -> Optional[str]:
    """Check if project_id exists in the projects table.

    Returns None if the project exists (or if the table is unreachable),
    or an error message string if the project is definitively not registered.
    Fail-open: any exception returns None (allow the mutation).
    """
    global _project_cache, _project_cache_at
    now = time.time()

    # Invalidate stale cache
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now

    if project_id in _project_cache:
        return None if _project_cache[project_id] else (
            f"Project '{project_id}' is not registered. "
            "Create it via POST /api/v1/projects first."
        )

    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="project_id",
        )
        exists = "Item" in resp
        _project_cache[project_id] = exists
        if not exists:
            return (
                f"Project '{project_id}' is not registered. "
                "Create it via POST /api/v1/projects first."
            )
        return None
    except Exception as exc:
        # Fail-open: if projects table is unreachable, allow the mutation
        logger.warning("project validation failed (fail-open): %s", exc)
        return None


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

_ddb = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _now_z() -> str:
    """UTC timestamp string."""
    import datetime as dt
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_key(project_id: str, record_type: str, record_id: str) -> Dict[str, Dict]:
    """Build the DynamoDB primary key for a record."""
    prefix = _TYPE_SEG_TO_SK_PREFIX[record_type]
    sk = f"{prefix}#{record_id.upper()}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": sk},
    }


def _get_record(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """GetItem with ConsistentRead. Returns deserialized item or None."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    try:
        resp = ddb.get_item(
            TableName=DYNAMODB_TABLE,
            Key=key,
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("get_item failed: %s", exc)
        raise
    item = resp.get("Item")
    if item is None:
        return None
    # Minimal deserialize for what we need
    return {
        "status": item.get("status", {}).get("S"),
        "sync_version": int(item.get("sync_version", {}).get("N", "0")),
        "record_type": item.get("record_type", {}).get("S"),
        "updated_at": item.get("updated_at", {}).get("S"),
    }


def _action_close(
    project_id: str,
    record_type: str,
    record_id: str,
    current_version: int,
) -> str:
    """UpdateItem to close/complete a record. Returns new updated_at."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    now = _now_z()
    closed_status = _CLOSED_STATUS[record_type]
    description = "Closed via Enceladus PWA"

    history_entry = {
        "M": {
            "timestamp": {"S": now},
            "status": {"S": "close_audit"},
            "description": {"S": description},
            "agent_details": {"S": "Enceladus PWA (human user)"},
            "closed_time": {"S": now},
        }
    }

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE,
            Key=key,
            UpdateExpression=(
                "SET #status = :status, updated_at = :ts, last_update_note = :note, "
                "sync_version = sync_version + :one, "
                "#history = list_append(#history, :entry)"
            ),
            ConditionExpression="sync_version = :expected",
            ExpressionAttributeNames={
                "#status": "status",
                "#history": "history",
            },
            ExpressionAttributeValues={
                ":status": {"S": closed_status},
                ":ts": {"S": now},
                ":note": {"S": description},
                ":one": {"N": "1"},
                ":entry": {"L": [history_entry]},
                ":expected": {"N": str(current_version)},
            },
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        raise ValueError("Record was modified concurrently. Please refresh and try again.")
    except (BotoCoreError, ClientError) as exc:
        logger.error("update_item (close) failed: %s", exc)
        raise

    return now


def _action_note(
    project_id: str,
    record_type: str,
    record_id: str,
    note_text: str,
    current_version: int,
) -> str:
    """UpdateItem to set the #update field on a record. Returns new updated_at."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    now = _now_z()

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE,
            Key=key,
            UpdateExpression=(
                "SET #update = :note, updated_at = :ts, "
                "sync_version = sync_version + :one"
            ),
            ConditionExpression="sync_version = :expected",
            ExpressionAttributeNames={
                "#update": "update",
            },
            ExpressionAttributeValues={
                ":note": {"S": note_text},
                ":ts": {"S": now},
                ":one": {"N": "1"},
                ":expected": {"N": str(current_version)},
            },
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        raise ValueError("Record was modified concurrently. Please refresh and try again.")
    except (BotoCoreError, ClientError) as exc:
        logger.error("update_item (note) failed: %s", exc)
        raise

    return now


def _emit_reopen_event(
    project_id: str,
    record_type: str,
    record_id: str,
    previous_status: str,
    new_status: str,
    reopened_at: str,
) -> None:
    """Emit EventBridge event when a record transitions out of final status."""
    detail = {
        "project_id": project_id,
        "record_type": record_type,
        "record_id": record_id,
        "previous_status": previous_status,
        "new_status": new_status,
        "reopened_at": reopened_at,
    }
    try:
        _get_events().put_events(
            Entries=[{
                "Source": EVENT_SOURCE,
                "DetailType": EVENT_DETAIL_TYPE_REOPENED,
                "Detail": json.dumps(detail),
                "EventBusName": EVENT_BUS,
            }]
        )
        logger.info(
            "emitted %s event for %s/%s/%s",
            EVENT_DETAIL_TYPE_REOPENED, project_id, record_type, record_id,
        )
    except Exception as exc:
        # Non-fatal: reopen succeeds even if event emission fails
        logger.error("EventBridge put_events failed: %s", exc)


def _action_reopen(
    project_id: str,
    record_type: str,
    record_id: str,
    current_version: int,
) -> str:
    """UpdateItem to reopen a closed/completed record. Returns new updated_at.

    Sets status back to the default open status for the record type.
    Appends a history entry with status='reopened'.
    Emits an EventBridge event for monitoring/coordination.
    """
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    now = _now_z()
    default_status = _DEFAULT_STATUS[record_type]
    closed_status = _CLOSED_STATUS[record_type]
    description = "Reopened via Enceladus PWA"

    history_entry = {
        "M": {
            "timestamp": {"S": now},
            "status": {"S": "reopened"},
            "description": {"S": description},
        }
    }

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE,
            Key=key,
            UpdateExpression=(
                "SET #status = :new_status, updated_at = :ts, "
                "last_update_note = :note, "
                "sync_version = sync_version + :one, "
                "#history = list_append(#history, :entry)"
            ),
            ConditionExpression=(
                "sync_version = :expected AND #status = :closed_val"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#history": "history",
            },
            ExpressionAttributeValues={
                ":new_status": {"S": default_status},
                ":ts": {"S": now},
                ":note": {"S": description},
                ":one": {"N": "1"},
                ":entry": {"L": [history_entry]},
                ":expected": {"N": str(current_version)},
                ":closed_val": {"S": closed_status},
            },
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        raise ValueError(
            "Record is not currently in a closed/completed status, "
            "or was modified concurrently. Please refresh and try again."
        )
    except (BotoCoreError, ClientError) as exc:
        logger.error("update_item (reopen) failed: %s", exc)
        raise

    _emit_reopen_event(project_id, record_type, record_id, closed_status, default_status, now)
    return now


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "PATCH, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str) -> Dict:
    return _response(status_code, {"success": False, "error": message})


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------

# Matches both the full CloudFront-forwarded path (/api/v1/tracker/...) and the
# short path (/.../...) that API Gateway may send when invoked directly.
_PATH_PATTERN = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<projectId>[a-z0-9_-]+)/(?P<recordType>task|issue|feature)/(?P<recordId>[A-Za-z0-9_-]+)$"
)


def _parse_path(event: Dict) -> Optional[Tuple[str, str, str]]:
    """Parse path params from event. Returns (projectId, recordType, recordId) or None."""
    # API Gateway HTTP API sends rawPath; REST API sends path + pathParameters
    path = event.get("rawPath") or event.get("path", "")

    # Also check pathParameters from API Gateway proxy
    path_params = event.get("pathParameters") or {}
    project_id = path_params.get("projectId")
    record_type = path_params.get("recordType")
    record_id = path_params.get("recordId")

    if project_id and record_type and record_id:
        if record_type not in _RECORD_TYPES:
            return None
        return project_id, record_type.lower(), record_id

    # Fallback: parse from raw path
    m = _PATH_PATTERN.match(path)
    if not m:
        return None
    return m.group("projectId"), m.group("recordType"), m.group("recordId")


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (event.get("requestContext") or {}).get("http", {}).get("method") or \
             event.get("httpMethod", "")

    # CORS preflight
    if method == "OPTIONS":
        return {
            "statusCode": 204,
            "headers": _cors_headers(),
            "body": "",
        }

    if method != "PATCH":
        return _error(405, "Method not allowed. Use PATCH.")

    # --- Parse path ---
    parsed = _parse_path(event)
    if parsed is None:
        return _error(400, "Invalid path. Expected /api/v1/tracker/{projectId}/{recordType}/{recordId}")
    project_id, record_type, record_id = parsed

    # --- Validate project is registered ---
    project_err = _validate_project_exists(project_id)
    if project_err:
        return _error(404, project_err)

    logger.info("mutation request project=%s type=%s id=%s", project_id, record_type, record_id)

    # --- Auth ---
    token = _extract_token(event)
    if not token:
        logger.warning("auth failed: no enceladus_id_token cookie in request")
        return _error(401, "Authentication required. Please sign in.")
    try:
        _claims = _verify_token(token)
    except ValueError as exc:
        logger.warning("auth failed: %s", exc)
        return _error(401, str(exc))

    # --- Parse body ---
    try:
        body_raw = event.get("body") or "{}"
        body = json.loads(body_raw)
    except (ValueError, TypeError):
        return _error(400, "Invalid JSON body.")

    action = body.get("action")
    if action not in ("close", "note", "reopen"):
        return _error(400, "Field 'action' must be 'close', 'note', or 'reopen'.")

    note_text = body.get("note", "")
    if action == "note":
        if not note_text or not str(note_text).strip():
            return _error(400, "Field 'note' is required and must not be empty.")
        note_text = str(note_text).strip()
        if len(note_text) > MAX_NOTE_LENGTH:
            return _error(400, f"Note exceeds maximum length of {MAX_NOTE_LENGTH} characters.")

    # --- Verify record exists ---
    try:
        existing = _get_record(project_id, record_type, record_id)
    except Exception:
        return _error(500, "Database read failed. Please try again.")

    if existing is None:
        return _error(404, f"Record not found: {record_id} (project={project_id} type={record_type})")

    current_version = existing["sync_version"]

    # --- Execute mutation ---
    try:
        if action == "close":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            if current_status == closed_status:
                logger.info(
                    "close no-op %s/%s/%s already status=%s",
                    project_id, record_type, record_id, closed_status,
                )
                return _response(200, {
                    "success": True,
                    "action": "close",
                    "record_id": record_id,
                    "updated_status": closed_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            updated_at = _action_close(project_id, record_type, record_id, current_version)
            logger.info("closed %s/%s/%s → status=%s", project_id, record_type, record_id, closed_status)
            return _response(200, {
                "success": True,
                "action": "close",
                "record_id": record_id,
                "updated_status": closed_status,
                "updated_at": updated_at,
            })

        elif action == "reopen":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            default_status = _DEFAULT_STATUS[record_type]
            if current_status == default_status:
                logger.info(
                    "reopen no-op %s/%s/%s already status=%s",
                    project_id, record_type, record_id, default_status,
                )
                return _response(200, {
                    "success": True,
                    "action": "reopen",
                    "record_id": record_id,
                    "updated_status": default_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            if current_status != closed_status:
                logger.info(
                    "reopen rejected %s/%s/%s status=%s expected=%s",
                    project_id, record_type, record_id, current_status, closed_status,
                )
                return _error(
                    400,
                    f"Cannot reopen: record status is '{current_status}', not '{closed_status}'."
                )
            updated_at = _action_reopen(project_id, record_type, record_id, current_version)
            logger.info(
                "reopened %s/%s/%s → status=%s",
                project_id, record_type, record_id, default_status,
            )
            return _response(200, {
                "success": True,
                "action": "reopen",
                "record_id": record_id,
                "updated_status": default_status,
                "updated_at": updated_at,
            })

        else:  # note
            updated_at = _action_note(project_id, record_type, record_id, note_text, current_version)
            logger.info("note saved for %s/%s/%s (%d chars)", project_id, record_type, record_id, len(note_text))
            return _response(200, {
                "success": True,
                "action": "note",
                "record_id": record_id,
                "updated_at": updated_at,
            })

    except ValueError as exc:
        return _error(409, str(exc))
    except Exception as exc:
        logger.error("mutation failed: %s", exc)
        return _error(500, "Database write failed. Please try again.")
