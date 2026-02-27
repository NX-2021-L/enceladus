"""tracker_mutation/lambda_function.py — Full Tracker CRUD API

Lambda API for the Enceladus project tracker. Serves both the PWA UI (Cognito JWT)
and the MCP server (X-Coordination-Internal-Key).

Routes (via API Gateway):
  GET    /api/v1/tracker/pending-updates                          — pending updates
  GET    /api/v1/tracker/{project}                                — list records
  GET    /api/v1/tracker/{project}/{type}/{id}                    — get record
  POST   /api/v1/tracker/{project}/{type}                         — create record
  PATCH  /api/v1/tracker/{project}/{type}/{id}                    — update field / PWA action
  POST   /api/v1/tracker/{project}/{type}/{id}/log                — append worklog
  POST   /api/v1/tracker/{project}/{type}/{id}/checkout           — session checkout
  DELETE /api/v1/tracker/{project}/{type}/{id}/checkout            — session release
  POST   /api/v1/tracker/{project}/{type}/{id}/acceptance-evidence — set evidence
  OPTIONS *                                                        — CORS preflight

Auth:
  1. X-Coordination-Internal-Key header (service-to-service, MCP server)
  2. enceladus_id_token cookie (Cognito JWT, PWA users)

Environment variables:
  DYNAMODB_TABLE          default: devops-project-tracker
  DYNAMODB_REGION         default: us-west-2
  PROJECTS_TABLE          default: projects
  COGNITO_USER_POOL_ID    us-east-1_b2D0V3E1k
  COGNITO_CLIENT_ID       6q607dk3liirhtecgps7hifmlk
  COORDINATION_INTERNAL_API_KEY  (service auth key)
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
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


def _first_nonempty_env(*names: str) -> str:
    for name in names:
        value = str(os.environ.get(name, "")).strip()
        if value:
            return value
    return ""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COORDINATION_INTERNAL_API_KEY = _first_nonempty_env(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
)
COORDINATION_INTERNAL_API_KEY_PREVIOUS = _first_nonempty_env(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY_PREVIOUS",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
)
COORDINATION_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS", ""),
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    COORDINATION_INTERNAL_API_KEY,
    COORDINATION_INTERNAL_API_KEY_PREVIOUS,
)
_INTERNAL_SCOPE_MAP_RAW = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY_SCOPES", "")
    or os.environ.get("ENCELADUS_INTERNAL_API_KEY_SCOPES", "")
).strip()
GITHUB_INTEGRATION_API_BASE = os.environ.get("GITHUB_INTEGRATION_API_BASE", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
MAX_NOTE_LENGTH = 2000

# Valid record types and their closed/default statuses
_RECORD_TYPES = {"task", "issue", "feature"}
_CLOSED_STATUS = {"task": "closed", "issue": "closed", "feature": "completed"}
_DEFAULT_STATUS = {"task": "open", "issue": "open", "feature": "planned"}
_TRACKER_TYPE_SUFFIX = {"task": "TSK", "issue": "ISS", "feature": "FTR"}
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature"}

# Category validation per record type
_VALID_CATEGORIES = {
    "feature": {"epic", "capability", "enhancement", "infrastructure"},
    "task": {"implementation", "investigation", "documentation", "maintenance", "validation"},
    "issue": {"bug", "debt", "risk", "security", "performance"},
}

# Status transition rules — strictly sequential, one step forward only (ENC-FTR-022)
_VALID_TRANSITIONS = {
    "feature": {
        "planned": {"in-progress"},
        "in-progress": {"completed"},
        "completed": {"production"},
        "production": {"deprecated"},
    },
    "task": {
        "open": {"in-progress"},
        "in-progress": {"coding-complete"},
        "coding-complete": {"committed"},
        "committed": {"pushed"},
        "pushed": {"merged-main"},
        "merged-main": {"deployed"},
        "deployed": {"closed"},
    },
    "issue": {
        "open": {"in-progress", "closed"},
        "in-progress": {"closed"},
    },
}

# Backward (revert) transitions — allowed only with transition_evidence.revert_reason
_REVERT_TRANSITIONS = {
    "feature": {
        "in-progress": {"planned"},
        "completed": {"in-progress"},
        "production": {"completed"},
        "deprecated": {"production"},
    },
    "task": {
        "in-progress": {"open"},
        "coding-complete": {"in-progress"},
        "committed": {"coding-complete"},
        "pushed": {"committed"},
        "merged-main": {"pushed"},
    },
    "issue": {
        "in-progress": {"open"},
    },
}

# EventBridge event config for reopen notifications
EVENT_BUS = os.environ.get("EVENT_BUS", "default")
EVENT_SOURCE = "enceladus.tracker"
EVENT_DETAIL_TYPE_REOPENED = "record.status.reopened"

# Type segment mapping for SK construction
_TYPE_SEG_TO_SK_PREFIX = {"task": "task", "issue": "issue", "feature": "feature"}

# Counter management
_TRACKER_COUNTER_PREFIX = "counter#"
_TRACKER_CREATE_MAX_ATTEMPTS = 32

# Relation fields
_RELATION_ID_FIELDS = {"related_task_ids", "related_issue_ids", "related_feature_ids"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS clients (lazy init)
# ---------------------------------------------------------------------------

_ddb = None
_events_client = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_events():
    global _events_client
    if _events_client is None:
        _events_client = boto3.client("events")
    return _events_client


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _now_z() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _ser_value(val: Any) -> Dict:
    """Serialize supported Python values to DynamoDB typed format."""
    if isinstance(val, dict):
        return {"M": {str(k): _ser_value(v) for k, v in val.items()}}
    if isinstance(val, list):
        return {"L": [_ser_value(v) for v in val]}
    if isinstance(val, bool):
        return {"BOOL": val}
    if isinstance(val, (int, float)):
        return {"N": str(val)}
    if val is None:
        return {"NULL": True}
    return _ser_s(str(val))


def _deser_val(v: Dict) -> Any:
    """Deserialize a single DynamoDB attribute value."""
    if "S" in v:
        return v["S"]
    if "N" in v:
        n = v["N"]
        return int(n) if "." not in n else float(n)
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "L" in v:
        return [_deser_val(i) for i in v["L"]]
    if "M" in v:
        return {k: _deser_val(val) for k, val in v["M"].items()}
    if "SS" in v:
        return list(v["SS"])
    if "NS" in v:
        return [int(n) if "." not in n else float(n) for n in v["NS"]]
    return str(v)


def _deser_item(item: Dict) -> Dict[str, Any]:
    """Deserialize a full DynamoDB item."""
    return {k: _deser_val(v) for k, v in item.items()}


def _normalize_write_source(body: dict, claims: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Normalize write_source payload from PWA and MCP clients.

    Supports both nested write_source maps and legacy top-level provider fields.
    When JWT claims are available, defaults provider to claims.sub for user-attributed writes.
    """
    if not isinstance(body, dict):
        return {
            "channel": "mutation_api",
            "provider": "",
            "dispatch_id": "",
            "coordination_request_id": "",
        }

    raw_ws = body.get("write_source")
    ws = raw_ws if isinstance(raw_ws, dict) else {}
    auth_mode = str(claims.get("auth_mode", "")) if isinstance(claims, dict) else ""

    channel = str(ws.get("channel") or "").strip()
    if not channel:
        channel = "mcp_server" if auth_mode == "internal-key" else "mutation_api"

    provider = str(ws.get("provider") or body.get("provider") or "").strip()
    if not provider and isinstance(claims, dict):
        provider = str(claims.get("sub") or "").strip()

    dispatch_id = str(ws.get("dispatch_id") or body.get("dispatch_id") or "").strip()
    coordination_request_id = str(
        ws.get("coordination_request_id") or body.get("coordination_request_id") or ""
    ).strip()

    normalized = {
        "channel": channel,
        "provider": provider,
        "dispatch_id": dispatch_id,
        "coordination_request_id": coordination_request_id,
    }
    body["write_source"] = normalized
    return normalized


def _build_write_source(body: dict) -> Dict[str, Any]:
    """Build a structured write_source map for DynamoDB attribution."""
    ws = _normalize_write_source(body)
    return {
        "M": {
            "channel": _ser_s(ws.get("channel", "mutation_api")),
            "provider": _ser_s(ws.get("provider", "")),
            "dispatch_id": _ser_s(ws.get("dispatch_id", "")),
            "coordination_request_id": _ser_s(ws.get("coordination_request_id", "")),
            "timestamp": _ser_s(_now_z()),
        }
    }


def _write_source_note_suffix(body: dict) -> str:
    """Build optional suffix for last_update_note with provider context."""
    ws = _normalize_write_source(body)
    provider = ws.get("provider", "")
    dispatch_id = ws.get("dispatch_id", "")
    parts = []
    if provider:
        parts.append(f"provider={provider}")
    if dispatch_id:
        parts.append(f"dispatch={dispatch_id}")
    return f" [{', '.join(parts)}]" if parts else ""


def _is_conditional_check_failed(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

# Project validation cache
_project_cache: Dict[str, bool] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0


def _parse_internal_scope_map(raw: str) -> Dict[str, set[str]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid COORDINATION_INTERNAL_API_KEY_SCOPES JSON; ignoring scoped auth map")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: Dict[str, set[str]] = {}
    for key, value in parsed.items():
        token = str(key or "").strip()
        if not token:
            continue
        scopes: set[str] = set()
        if isinstance(value, list):
            items = value
        else:
            items = str(value).split(",")
        for item in items:
            scope = str(item or "").strip().lower()
            if scope:
                scopes.add(scope)
        if scopes:
            out[token] = scopes
    return out


INTERNAL_API_KEY_SCOPES = _parse_internal_scope_map(_INTERNAL_SCOPE_MAP_RAW)


def _scope_match(granted: str, required: str) -> bool:
    if granted in {"*", "all"}:
        return True
    if granted == required:
        return True
    if granted.endswith("*"):
        return required.startswith(granted[:-1])
    return False


def _internal_key_has_scopes(internal_key: str, required_scopes: Optional[List[str]]) -> bool:
    if not required_scopes:
        return True
    if not INTERNAL_API_KEY_SCOPES:
        return True
    granted = INTERNAL_API_KEY_SCOPES.get(internal_key) or INTERNAL_API_KEY_SCOPES.get("*") or set()
    if not granted:
        return False
    for required in required_scopes:
        req = str(required or "").strip().lower()
        if req and not any(_scope_match(g, req) for g in granted):
            return False
    return True


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


def _authenticate(event: Dict, required_scopes: Optional[List[str]] = None) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Authenticate via internal API key or Cognito JWT.

    Returns (claims, None) on success or (None, error_response) on failure.
    """
    headers = event.get("headers") or {}

    # Try internal API key first
    internal_key = (
        headers.get("x-coordination-internal-key")
        or headers.get("X-Coordination-Internal-Key")
        or ""
    )
    if internal_key and COORDINATION_INTERNAL_API_KEYS and internal_key in COORDINATION_INTERNAL_API_KEYS:
        if not _internal_key_has_scopes(internal_key, required_scopes):
            return None, _error(403, "Forbidden: internal key scope is insufficient for this operation.")
        return {"auth_mode": "internal-key"}, None

    # Fall back to Cognito JWT
    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in or provide API key.")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Project validation (fail-open)
# ---------------------------------------------------------------------------

def _validate_project_exists(project_id: str) -> Optional[str]:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now
    if project_id in _project_cache:
        return None if _project_cache[project_id] else (
            f"Project '{project_id}' is not registered."
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
            return f"Project '{project_id}' is not registered."
        return None
    except Exception as exc:
        logger.warning("project validation failed (fail-open): %s", exc)
        return None


def _get_project_prefix(project_id: str) -> Optional[str]:
    """Get prefix for a project from the projects table."""
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="prefix",
        )
        item = resp.get("Item")
        if item:
            return item.get("prefix", {}).get("S")
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _build_key(project_id: str, record_type: str, record_id: str) -> Dict[str, Dict]:
    """Build the DynamoDB primary key for a record."""
    prefix = _TYPE_SEG_TO_SK_PREFIX[record_type]
    sk = f"{prefix}#{record_id.upper()}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": sk},
    }


def _get_record_full(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """GetItem with ConsistentRead. Returns full deserialized item or None."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    resp = ddb.get_item(TableName=DYNAMODB_TABLE, Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if item is None:
        return None
    return _deser_item(item)


def _get_record_raw(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """GetItem with ConsistentRead. Returns raw DynamoDB item or None."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    resp = ddb.get_item(TableName=DYNAMODB_TABLE, Key=key, ConsistentRead=True)
    return resp.get("Item")


def _classify_related_ids(related_ids: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rid in related_ids:
        rid_u = rid.strip().upper()
        parts = rid_u.split("-")
        if len(parts) < 2:
            continue
        type_seg = parts[1]
        rtype = {"TSK": "task", "ISS": "issue", "FTR": "feature"}.get(type_seg)
        if not rtype:
            continue
        field = f"related_{rtype}_ids"
        out.setdefault(field, []).append(rid_u)
    return out


# ---------------------------------------------------------------------------
# Counter management for record creation
# ---------------------------------------------------------------------------

def _max_existing_number(project_id: str, record_type: str) -> int:
    """Scan all records to find the highest numeric suffix (fallback for missing counter)."""
    ddb = _get_ddb()
    kwargs: Dict[str, Any] = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :rtype_prefix)",
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":rtype_prefix": _ser_s(f"{record_type}#"),
        },
        "ProjectionExpression": "record_id",
    }
    max_num = 0
    while True:
        query_resp = ddb.query(**kwargs)
        for item in query_resp.get("Items", []):
            sk = item.get("record_id", {}).get("S", "")
            human_id = sk.split("#", 1)[1] if "#" in sk else sk
            parts = human_id.split("-")
            if len(parts) >= 3:
                try:
                    max_num = max(max_num, int(parts[-1]))
                except ValueError:
                    pass
        last_key = query_resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return max_num


def _next_record_id(project_id: str, prefix: str, record_type: str) -> str:
    """Allocate the next sequential record ID using an atomic counter."""
    ddb = _get_ddb()
    type_suffix = _TRACKER_TYPE_SUFFIX.get(record_type, "TSK")
    counter_key = {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(f"{_TRACKER_COUNTER_PREFIX}{record_type}"),
    }

    counter_item = ddb.get_item(
        TableName=DYNAMODB_TABLE, Key=counter_key, ConsistentRead=True,
    ).get("Item")

    seed_num = 0
    if not counter_item:
        seed_num = _max_existing_number(project_id, record_type)

    now = _now_z()
    update_resp = ddb.update_item(
        TableName=DYNAMODB_TABLE,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :seed) + :one, "
            "updated_at = :now, "
            "created_at = if_not_exists(created_at, :now), "
            "record_type = if_not_exists(record_type, :counter_type), "
            "item_id = if_not_exists(item_id, :counter_item_id)"
        ),
        ExpressionAttributeValues={
            ":seed": {"N": str(seed_num)},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":counter_type": _ser_s("counter"),
            ":counter_item_id": _ser_s(f"COUNTER-{record_type.upper()}"),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    next_num = int(attrs.get("next_num", {"N": str(seed_num + 1)}).get("N", str(seed_num + 1)))
    return f"{prefix}-{type_suffix}-{next_num:03d}"


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str, **extra) -> Dict:
    body = {"success": False, "error": message}
    body.update(extra)
    return _response(status_code, body)


# ---------------------------------------------------------------------------
# EventBridge (reopen events)
# ---------------------------------------------------------------------------

def _emit_reopen_event(project_id, record_type, record_id, previous_status, new_status, reopened_at):
    detail = {
        "project_id": project_id, "record_type": record_type,
        "record_id": record_id, "previous_status": previous_status,
        "new_status": new_status, "reopened_at": reopened_at,
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": EVENT_DETAIL_TYPE_REOPENED,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:
        logger.error("EventBridge put_events failed: %s", exc)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_get_record(project_id: str, record_type: str, record_id: str) -> Dict:
    """GET /{project}/{type}/{id} — return full deserialized record."""
    try:
        item = _get_record_full(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if item is None:
        return _error(404, f"Record not found: {record_id}")

    return _response(200, {"success": True, "record": item})


def _handle_list_records(project_id: str, query_params: Dict) -> Dict:
    """GET /{project} — list records with optional type/status filters."""
    ddb = _get_ddb()
    record_type = query_params.get("type", "")
    status_filter = query_params.get("status", "")

    try:
        if record_type and record_type in _RECORD_TYPES:
            # Query using GSI
            kwargs: Dict[str, Any] = {
                "TableName": DYNAMODB_TABLE,
                "IndexName": "project-type-index",
                "KeyConditionExpression": "project_id = :pid AND record_type = :rtype",
                "ExpressionAttributeValues": {
                    ":pid": _ser_s(project_id),
                    ":rtype": _ser_s(record_type),
                },
            }
            if status_filter:
                kwargs["FilterExpression"] = "#st = :st"
                kwargs["ExpressionAttributeNames"] = {"#st": "status"}
                kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)

            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                last_key = resp.get("LastEvaluatedKey")
                if not last_key:
                    break
                kwargs["ExclusiveStartKey"] = last_key
        else:
            # Query all records for project
            kwargs = {
                "TableName": DYNAMODB_TABLE,
                "KeyConditionExpression": "project_id = :pid",
                "ExpressionAttributeValues": {":pid": _ser_s(project_id)},
            }
            filter_parts = []
            expr_names: Dict[str, str] = {}
            if status_filter:
                filter_parts.append("#st = :st")
                expr_names["#st"] = "status"
                kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)
            if record_type:
                filter_parts.append("record_type = :rtype")
                kwargs["ExpressionAttributeValues"][":rtype"] = _ser_s(record_type)
            if filter_parts:
                kwargs["FilterExpression"] = " AND ".join(filter_parts)
            if expr_names:
                kwargs["ExpressionAttributeNames"] = expr_names

            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                last_key = resp.get("LastEvaluatedKey")
                if not last_key:
                    break
                kwargs["ExclusiveStartKey"] = last_key

        # Deserialize and filter out counter records
        records = []
        for raw in items:
            item = _deser_item(raw)
            if item.get("record_type") == "counter":
                continue
            records.append(item)

        return _response(200, {"success": True, "records": records, "count": len(records)})

    except Exception as exc:
        logger.error("list failed: %s", exc)
        return _error(500, "Database query failed.")


def _handle_pending_updates(query_params: Dict) -> Dict:
    """GET /pending-updates — list records with non-empty update notes."""
    ddb = _get_ddb()
    project_id = query_params.get("project", "")
    scan_all = query_params.get("all", "").lower() in ("true", "1", "yes")

    try:
        if project_id and not scan_all:
            kwargs: Dict[str, Any] = {
                "TableName": DYNAMODB_TABLE,
                "KeyConditionExpression": "project_id = :pid",
                "FilterExpression": "attribute_exists(#upd) AND #upd <> :empty AND record_type <> :counter",
                "ExpressionAttributeNames": {"#upd": "update"},
                "ExpressionAttributeValues": {
                    ":pid": _ser_s(project_id),
                    ":empty": _ser_s(""),
                    ":counter": _ser_s("counter"),
                },
            }
            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                if not resp.get("LastEvaluatedKey"):
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        else:
            kwargs = {
                "TableName": DYNAMODB_TABLE,
                "FilterExpression": "attribute_exists(#upd) AND #upd <> :empty AND record_type <> :counter",
                "ExpressionAttributeNames": {"#upd": "update"},
                "ExpressionAttributeValues": {
                    ":empty": _ser_s(""),
                    ":counter": _ser_s("counter"),
                },
            }
            items = []
            while True:
                resp = ddb.scan(**kwargs)
                items.extend(resp.get("Items", []))
                if not resp.get("LastEvaluatedKey"):
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

        records = [_deser_item(raw) for raw in items]
        return _response(200, {"success": True, "records": records, "count": len(records)})

    except Exception as exc:
        logger.error("pending_updates failed: %s", exc)
        return _error(500, "Database query failed.")


def _handle_create_record(project_id: str, record_type: str, body: Dict) -> Dict:
    """POST /{project}/{type} — create a new tracker record."""
    title = body.get("title", "").strip()
    if not title:
        return _error(400, "Field 'title' is required.")

    priority = body.get("priority")
    description = str(body.get("description") or "")
    assigned_to = str(body.get("assigned_to") or "")
    status = str(body.get("status") or _DEFAULT_STATUS.get(record_type, "open"))
    severity = str(body.get("severity") or "")
    hypothesis = str(body.get("hypothesis") or "")
    success_metrics = body.get("success_metrics") or []
    related_str = body.get("related", "")
    user_story = str(body.get("user_story") or "").strip()
    category = str(body.get("category") or "").strip()
    intent = str(body.get("intent") or "").strip()
    evidence = body.get("evidence") or []
    primary_task = str(body.get("primary_task") or "").strip()
    coordination = body.get("coordination", False)
    coordination_request_id = str(body.get("coordination_request_id") or "").strip()
    dispatch_id = str(body.get("dispatch_id") or "").strip()

    if dispatch_id:
        coordination = True
    if coordination and not coordination_request_id:
        return _error(400, "coordination=true requires coordination_request_id.")

    # Acceptance criteria normalization
    raw_ac = body.get("acceptance_criteria")
    acceptance_criteria: List[str] = []
    if isinstance(raw_ac, str):
        stripped = raw_ac.strip()
        if stripped:
            acceptance_criteria = [stripped]
    elif isinstance(raw_ac, list):
        acceptance_criteria = [str(x).strip() for x in raw_ac if str(x).strip()]

    # Validation per record type
    if record_type == "task" and not acceptance_criteria:
        return _error(400, "Task creation requires acceptance_criteria (min 1).")

    if record_type == "feature":
        if not user_story:
            return _error(400, "Feature creation requires user_story.")
        if not acceptance_criteria:
            return _error(400, "Feature creation requires acceptance_criteria (min 1).")

    if record_type == "issue":
        if not isinstance(evidence, list) or len(evidence) == 0:
            return _error(400, "Issue creation requires evidence (min 1 entry with description + steps_to_duplicate).")
        for i, ev in enumerate(evidence):
            if not isinstance(ev, dict):
                return _error(400, f"evidence[{i}] must be an object.")
            if not ev.get("description", "").strip():
                return _error(400, f"evidence[{i}].description is required.")
            steps = ev.get("steps_to_duplicate")
            if not isinstance(steps, list) or len(steps) == 0:
                return _error(400, f"evidence[{i}].steps_to_duplicate requires at least one step.")

    if primary_task:
        if record_type not in ("feature", "issue"):
            return _error(400, f"primary_task is only valid on feature/issue records, not {record_type}.")
        if "-TSK-" not in primary_task:
            return _error(400, f"primary_task must reference a task ID (contains -TSK-). Got: '{primary_task}'.")

    # Category warning (soft)
    category_warning = ""
    if category and category not in _VALID_CATEGORIES.get(record_type, set()):
        valid = sorted(_VALID_CATEGORIES.get(record_type, set()))
        category_warning = f"category '{category}' not in valid set for {record_type}: {valid}"

    # Resolve project prefix
    prefix = _get_project_prefix(project_id)
    if not prefix:
        return _error(404, f"Project '{project_id}' not found or has no prefix.")

    ddb = _get_ddb()
    now = _now_z()
    note_suffix = _write_source_note_suffix(body)

    # Build the DynamoDB item
    item: Dict[str, Any] = {
        "project_id": _ser_s(project_id),
        "record_type": _ser_s(record_type),
        "title": _ser_s(title),
        "status": _ser_s(status),
        "sync_version": {"N": "1"},
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "coordination": {"BOOL": bool(coordination)},
        "write_source": _build_write_source(body),
        "history": {"L": [{"M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("created"),
            "description": _ser_s(f"Created via tracker API{note_suffix}: {title}"),
        }}]},
    }
    if coordination_request_id:
        item["coordination_request_id"] = _ser_s(coordination_request_id)
    if description:
        item["description"] = _ser_s(description)
    if priority:
        item["priority"] = _ser_s(priority)
    if assigned_to:
        item["assigned_to"] = _ser_s(assigned_to)
    if record_type == "issue":
        if severity:
            item["severity"] = _ser_s(severity)
        if hypothesis:
            item["hypothesis"] = _ser_s(hypothesis)
    if record_type == "feature" and isinstance(success_metrics, list) and success_metrics:
        item["success_metrics"] = {"L": [_ser_s(str(x)) for x in success_metrics if str(x).strip()]}

    # Acceptance criteria
    if acceptance_criteria:
        if record_type == "feature":
            ac_items = [{"M": {
                "description": _ser_s(ac), "evidence": _ser_s(""),
                "evidence_acceptance": {"BOOL": False},
            }} for ac in acceptance_criteria]
            item["acceptance_criteria"] = {"L": ac_items}
        else:
            item["acceptance_criteria"] = {"L": [_ser_s(x) for x in acceptance_criteria]}

    # Ontology fields
    if record_type == "feature" and user_story:
        item["user_story"] = _ser_s(user_story)
    if record_type == "issue" and evidence:
        ev_items = []
        for ev in evidence:
            ev_map: Dict[str, Any] = {
                "description": _ser_s(str(ev.get("description", ""))),
                "steps_to_duplicate": {"L": [_ser_s(str(s)) for s in ev.get("steps_to_duplicate", [])]},
            }
            if ev.get("observed_by"):
                ev_map["observed_by"] = _ser_s(str(ev["observed_by"]))
            if ev.get("timestamp"):
                ev_map["timestamp"] = _ser_s(str(ev["timestamp"]))
            ev_items.append({"M": ev_map})
        item["evidence"] = {"L": ev_items}
    if record_type == "task":
        item["active_agent_session"] = {"BOOL": False}
        item["active_agent_session_id"] = _ser_s("")
        item["active_agent_session_parent"] = {"BOOL": False}
    if category:
        item["category"] = _ser_s(category)
    if intent:
        item["intent"] = _ser_s(intent)
    if primary_task and record_type in ("feature", "issue"):
        item["primary_task"] = _ser_s(primary_task)
    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        for field_name, ids in _classify_related_ids(related_ids).items():
            if ids:
                item[field_name] = {"L": [_ser_s(i) for i in ids]}

    # Create with counter-based ID allocation
    try:
        for attempt in range(1, _TRACKER_CREATE_MAX_ATTEMPTS + 1):
            new_id = _next_record_id(project_id, prefix, record_type)
            sk = f"{record_type}#{new_id}"
            item["record_id"] = _ser_s(sk)
            item["item_id"] = _ser_s(new_id)
            try:
                ddb.put_item(
                    TableName=DYNAMODB_TABLE, Item=item,
                    ConditionExpression="attribute_not_exists(record_id)",
                )
                break
            except ClientError as exc:
                if _is_conditional_check_failed(exc) and attempt < _TRACKER_CREATE_MAX_ATTEMPTS:
                    continue
                raise
        else:
            return _error(500, f"Failed to allocate unique record ID after {_TRACKER_CREATE_MAX_ATTEMPTS} attempts.")
    except Exception as exc:
        logger.error("create failed: %s", exc)
        return _error(500, "Database write failed.")

    # Best-effort bidirectional relationships
    bidi_warnings = []
    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        inverse_field = f"related_{record_type}_ids"
        for target_id in related_ids:
            try:
                target_id_upper = target_id.upper()
                target_parts = target_id_upper.split("-")
                if len(target_parts) != 3:
                    continue
                target_type_seg = target_parts[1]
                target_type = _ID_SEGMENT_TO_TYPE.get(target_type_seg)
                if not target_type:
                    continue
                # We need target's project_id — try looking it up from the prefix
                target_prefix_map = _get_prefix_map_cached()
                target_project = target_prefix_map.get(target_parts[0])
                if not target_project:
                    continue
                target_key = _build_key(target_project, target_type, target_id_upper)
                ddb.update_item(
                    TableName=DYNAMODB_TABLE, Key=target_key,
                    UpdateExpression="SET #rel = list_append(if_not_exists(#rel, :empty), :new_id)",
                    ExpressionAttributeNames={"#rel": inverse_field},
                    ExpressionAttributeValues={
                        ":new_id": {"L": [_ser_s(new_id)]},
                        ":empty": {"L": []},
                    },
                    ConditionExpression="attribute_exists(record_id)",
                )
            except Exception as exc:
                bidi_warnings.append(f"Could not add inverse relationship on {target_id}: {exc}")

    result: Dict[str, Any] = {"success": True, "record_id": new_id, "created_at": now}
    if category_warning:
        result["warning"] = category_warning
    if bidi_warnings:
        result["bidi_warnings"] = bidi_warnings
    return _response(201, result)


# Prefix map cache for bidirectional relationships
_prefix_map_cache: Optional[Dict[str, str]] = None
_prefix_map_cache_at: float = 0.0


def _get_prefix_map_cached() -> Dict[str, str]:
    global _prefix_map_cache, _prefix_map_cache_at
    now = time.time()
    if _prefix_map_cache is not None and (now - _prefix_map_cache_at) < 300.0:
        return _prefix_map_cache
    try:
        ddb = _get_ddb()
        resp = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, prefix",
        )
        mapping = {}
        for item in resp.get("Items", []):
            pid = item.get("project_id", {}).get("S", "")
            pfx = item.get("prefix", {}).get("S", "")
            if pid and pfx:
                mapping[pfx] = pid
        _prefix_map_cache = mapping
        _prefix_map_cache_at = now
        return mapping
    except Exception:
        return _prefix_map_cache or {}


# ---------------------------------------------------------------------------
# Lifecycle governance helpers (ENC-FTR-022)
# ---------------------------------------------------------------------------


def _validate_commit_via_github(owner: str, repo: str, sha: str) -> Tuple[bool, str]:
    """Call github_integration Lambda's /commits/validate endpoint."""
    if not GITHUB_INTEGRATION_API_BASE:
        logger.warning("GITHUB_INTEGRATION_API_BASE not set; skipping commit validation")
        return True, "validation_skipped"
    url = (
        f"{GITHUB_INTEGRATION_API_BASE}/commits/validate"
        f"?owner={urllib.parse.quote(owner)}"
        f"&repo={urllib.parse.quote(repo)}"
        f"&sha={urllib.parse.quote(sha)}"
    )
    req = urllib.request.Request(url, method="GET", headers={
        "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("valid"):
                return True, data.get("message", "")
            return False, data.get("reason", "commit_not_found")
    except Exception as exc:
        logger.error("Commit validation call failed: %s", exc)
        return False, f"validation_service_error: {exc}"


def _query_all_project_tasks(project_id: str) -> List[Dict]:
    """Query all task records for a project. Returns deserialized items."""
    ddb = _get_ddb()
    items: List[Dict] = []
    kwargs = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":prefix": {"S": "task#"},
        },
        "ProjectionExpression": "record_id, item_id, #s, parent",
        "ExpressionAttributeNames": {"#s": "status"},
    }
    while True:
        resp = ddb.query(**kwargs)
        for raw in resp.get("Items", []):
            items.append(_deser_item(raw))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items


def _validate_feature_production_gate(project_id: str, feature_data: Dict) -> Optional[Dict]:
    """Enforce: feature -> production requires >=1 child task, all deployed/closed recursively."""
    primary = (feature_data.get("primary_task") or "").strip()
    related = feature_data.get("related_task_ids") or []
    root_ids: set = set()
    if primary:
        root_ids.add(primary)
    for r in related:
        rid = r.strip() if isinstance(r, str) else ""
        if rid:
            root_ids.add(rid)

    if not root_ids:
        return _error(400,
            "Cannot transition to 'production': feature has no child tasks. "
            "Set primary_task or related_task_ids first.")

    all_tasks = _query_all_project_tasks(project_id)
    task_map = {t.get("item_id", ""): t for t in all_tasks}

    # Build parent -> children graph
    parent_children: Dict[str, List[str]] = {}
    for t in all_tasks:
        p = (t.get("parent") or "").strip()
        if p:
            parent_children.setdefault(p, []).append(t.get("item_id", ""))

    # BFS: expand root_ids through parent->child relationships
    visited: set = set()
    queue = list(root_ids)
    while queue:
        tid = queue.pop(0)
        if tid in visited:
            continue
        visited.add(tid)
        for child_id in parent_children.get(tid, []):
            queue.append(child_id)

    # Check all visited tasks are deployed or closed
    not_ready = []
    for tid in sorted(visited):
        task = task_map.get(tid)
        if not task:
            not_ready.append(f"{tid} (not_found)")
            continue
        status = (task.get("status") or "unknown").strip().lower()
        if status not in ("deployed", "closed"):
            not_ready.append(f"{tid} ({status})")

    if not_ready:
        return _error(400,
            f"Cannot transition to 'production': "
            f"{len(not_ready)} task(s) not deployed/closed:\n"
            + "\n".join(not_ready[:20]))
    return None


def _normalize_feature_acceptance_criterion(entry: Any, index: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalize one feature acceptance criterion to governed map form."""
    if isinstance(entry, dict):
        description = str(entry.get("description") or "").strip()
        if not description:
            return None, (
                f"acceptance_criteria[{index}] requires a non-empty 'description' field."
            )
        evidence = str(entry.get("evidence") or "")
        evidence_acceptance = bool(entry.get("evidence_acceptance", False))
        return {
            "description": description,
            "evidence": evidence,
            "evidence_acceptance": evidence_acceptance,
        }, None

    description = str(entry).strip()
    if not description:
        return None, (
            f"acceptance_criteria[{index}] must be a non-empty string or object."
        )
    return {
        "description": description,
        "evidence": "",
        "evidence_acceptance": False,
    }, None


def _normalize_acceptance_criteria_value(record_type: str, raw_value: Any) -> Tuple[Optional[List[Any]], Optional[str]]:
    """Normalize PATCH acceptance_criteria payloads, including JSON-stringified arrays."""
    parsed_value = raw_value

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return None, "acceptance_criteria must not be empty."
        if stripped[0] in "[{":
            try:
                parsed_value = json.loads(stripped)
            except json.JSONDecodeError:
                parsed_value = stripped
        else:
            parsed_value = stripped

    if isinstance(parsed_value, dict):
        parsed_list: List[Any] = [parsed_value]
    elif isinstance(parsed_value, list):
        parsed_list = parsed_value
    else:
        parsed_list = [parsed_value]

    if record_type == "feature":
        normalized_feature_criteria: List[Dict[str, Any]] = []
        for idx, entry in enumerate(parsed_list):
            normalized, error = _normalize_feature_acceptance_criterion(entry, idx)
            if error:
                return None, error
            normalized_feature_criteria.append(normalized)
        if not normalized_feature_criteria:
            return None, "Feature acceptance_criteria requires at least one criterion."
        return normalized_feature_criteria, None

    normalized_list = [str(x).strip() for x in parsed_list if str(x).strip()]
    if not normalized_list:
        return None, "acceptance_criteria requires at least one non-empty criterion."
    return normalized_list, None


def _handle_update_field(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """PATCH /{project}/{type}/{id} — update a single field on a record.

    Body: {"field": "status", "value": "in-progress", "write_source": {...}}
    Also supports legacy PWA actions: {"action": "close|note|reopen", "note": "..."}
    """
    # Detect PWA action vs MCP field update
    action = body.get("action")
    if action:
        return _handle_pwa_action(project_id, record_type, record_id, body, action)

    _normalize_write_source(body)

    field = body.get("field", "").strip()
    value = body.get("value", "")
    if not field:
        return _error(400, "Field 'field' is required (or use 'action' for PWA mutations).")

    if field == "acceptance_criteria":
        normalized_criteria, normalize_error = _normalize_acceptance_criteria_value(record_type, value)
        if normalize_error:
            return _error(400, normalize_error)
        value = normalized_criteria

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Fetch existing record
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    item_data = _deser_item(raw_item)
    warnings: List[str] = []

    # --- Session ownership enforcement ---
    if field != "active_agent_session":
        ws = _normalize_write_source(body)
        current_session = item_data.get("active_agent_session", False)
        current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
        provider = str(ws.get("provider", "")).strip()
        if current_session and current_session_id:
            if not provider:
                return _error(
                    400,
                    f"Record is checked out by '{current_session_id}'. "
                    "write_source.provider is required for modifications.",
                )
            if current_session_id != provider:
                return _error(409, f"Record is checked out by '{current_session_id}'. Cannot modify.")

    # --- Validation for specific fields ---
    if field == "status":
        current_status = item_data.get("status", "").strip().lower()
        new_lower = value.strip().lower()
        closing = new_lower in ("closed", "completed", "complete")
        transition_evidence = body.get("transition_evidence", {})

        if record_type == "task" and current_status != new_lower:
            ws = _normalize_write_source(body)
            provider = str(ws.get("provider", "")).strip()
            current_session = bool(item_data.get("active_agent_session"))
            current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
            if not provider:
                return _error(
                    400,
                    "Task status transitions require write_source.provider "
                    "(agent identity).",
                )
            if not current_session or not current_session_id:
                return _error(
                    409,
                    "Task status transitions require an active checkout. "
                    "Check out the task before changing status.",
                )
            if provider != current_session_id:
                return _error(
                    409,
                    f"Task is checked out by '{current_session_id}'. "
                    f"Cannot transition status as '{provider}'.",
                )

        # Enforce valid transitions — forward + revert (ENC-FTR-022)
        if current_status != new_lower:
            type_transitions = _VALID_TRANSITIONS.get(record_type, {})
            valid_next = type_transitions.get(current_status, set())
            revert_targets = _REVERT_TRANSITIONS.get(record_type, {}).get(current_status, set())

            if new_lower in valid_next:
                pass  # valid forward transition
            elif new_lower in revert_targets:
                revert_reason = transition_evidence.get("revert_reason", "").strip()
                if not revert_reason:
                    return _error(400,
                        f"Reverting {record_type} from '{current_status}' to '{new_lower}' "
                        f"requires transition_evidence.revert_reason")
            elif valid_next or revert_targets:
                return _error(400,
                    f"Invalid status transition for {record_type}: "
                    f"'{current_status}' -> '{value}'. "
                    f"Valid forward: {sorted(valid_next)}. "
                    f"Valid revert (with revert_reason): {sorted(revert_targets)}")

        # --- Evidence-gated forward transitions (ENC-FTR-022) ---
        if record_type == "task" and new_lower == "pushed":
            commit_sha = transition_evidence.get("commit_sha", "").strip()
            if not commit_sha:
                return _error(400,
                    "Cannot transition to 'pushed': transition_evidence.commit_sha required")
            if not re.match(r'^[0-9a-f]{40}$', commit_sha.lower()):
                return _error(400,
                    f"Invalid commit_sha: expected 40-char hex. Got: '{commit_sha}'")
            owner = transition_evidence.get("owner", "NX-2021-L")
            repo = transition_evidence.get("repo", "enceladus")
            valid, reason = _validate_commit_via_github(owner, repo, commit_sha)
            if not valid:
                return _error(400,
                    f"GitHub commit validation failed for {commit_sha}: {reason}")

        if record_type == "task" and new_lower == "merged-main":
            merge_evidence = transition_evidence.get("merge_evidence", "").strip()
            if not merge_evidence:
                return _error(400,
                    "Cannot transition to 'merged-main': "
                    "transition_evidence.merge_evidence required")

        if record_type == "task" and new_lower == "deployed":
            deployment_ref = transition_evidence.get("deployment_ref", "").strip()
            if not deployment_ref:
                return _error(400,
                    "Cannot transition to 'deployed': "
                    "transition_evidence.deployment_ref required")

        if record_type == "feature" and new_lower == "production":
            prod_err = _validate_feature_production_gate(project_id, item_data)
            if prod_err:
                return prod_err

        # Hard enforcement of governed fields on close
        if record_type == "feature" and closing:
            if not item_data.get("user_story"):
                return _error(400, "Cannot complete feature: user_story is required.")
            ac_list = item_data.get("acceptance_criteria", [])
            if not ac_list:
                return _error(400, "Cannot complete feature: acceptance_criteria is required (min 1).")
            unvalidated = []
            for i, ac in enumerate(ac_list):
                if isinstance(ac, dict):
                    desc = ac.get("description", f"criterion[{i}]")
                    if not ac.get("evidence_acceptance", False):
                        unvalidated.append(f"[{i}] {desc}")
                elif isinstance(ac, str):
                    unvalidated.append(f"[{i}] {ac}")
            if unvalidated:
                return _error(400,
                    "Cannot complete feature: not all acceptance criteria validated. "
                    "Unvalidated:\n" + "\n".join(unvalidated))
        elif record_type == "feature" and not closing:
            if not item_data.get("user_story"):
                warnings.append("Feature missing governed field: user_story")
            if not item_data.get("acceptance_criteria"):
                warnings.append("Feature missing governed field: acceptance_criteria")

        if record_type == "issue" and closing:
            if not item_data.get("evidence"):
                return _error(400, "Cannot close issue: evidence is required (min 1).")

    if field == "parent" and value.strip():
        parent_type = None
        if "-TSK-" in value:
            parent_type = "task"
        elif "-ISS-" in value:
            parent_type = "issue"
        elif "-FTR-" in value:
            parent_type = "feature"
        if parent_type and parent_type != record_type:
            return _error(400,
                f"Parent must be the same record type. This is a {record_type} "
                f"but parent '{value}' is a {parent_type}.")

    if field == "primary_task":
        if record_type not in ("feature", "issue"):
            return _error(400, f"primary_task is only valid on feature/issue records.")
        if value.strip() and "-TSK-" not in value:
            return _error(400, f"primary_task must reference a task ID. Got: '{value}'.")

    now = _now_z()
    note_suffix = _write_source_note_suffix(body)

    # --- Session checkout/release ---
    if field == "active_agent_session":
        checking_out = value if isinstance(value, bool) else str(value).strip().lower() in ("true", "1", "yes")
        ws = _normalize_write_source(body)
        agent_id = str(ws.get("provider", "")).strip()

        if checking_out:
            if not agent_id:
                return _error(400, "Checkout requires write_source.provider as agent identity.")
            checkout_note = f"Agent session checkout by {agent_id}{note_suffix}"
            history_entry = {"M": {
                "timestamp": _ser_s(now), "status": _ser_s("worklog"),
                "description": _ser_s(checkout_note),
            }}
            try:
                ddb.update_item(
                    TableName=DYNAMODB_TABLE, Key=key,
                    UpdateExpression=(
                        "SET active_agent_session = :t, active_agent_session_id = :aid, "
                        "checkout_state = :checked_out, checked_out_by = :aid, checked_out_at = :now, "
                        "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                        "sync_version = if_not_exists(sync_version, :zero) + :one, "
                        "history = list_append(if_not_exists(history, :empty), :hentry)"
                    ),
                    ConditionExpression="active_agent_session <> :t OR attribute_not_exists(active_agent_session)",
                    ExpressionAttributeValues={
                        ":t": {"BOOL": True}, ":aid": _ser_s(agent_id),
                        ":checked_out": _ser_s("checked_out"),
                        ":now": _ser_s(now), ":note": _ser_s(checkout_note),
                        ":wsrc": _build_write_source(body),
                        ":zero": {"N": "0"}, ":one": {"N": "1"},
                        ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
                    },
                )
            except ClientError as exc:
                if _is_conditional_check_failed(exc):
                    current_agent = item_data.get("active_agent_session_id", "unknown")
                    return _error(409, f"Task already checked out by '{current_agent}'.")
                raise
            return _response(200, {
                "success": True, "record_id": record_id,
                "checkout": True, "checkout_state": "checked_out",
                "active_agent_session_id": agent_id, "updated_at": now,
            })
        else:
            release_note = f"Agent session released{note_suffix}"
            release_agent = str(ws.get("provider", "")).strip() or str(
                item_data.get("active_agent_session_id", "")
            ).strip()
            history_entry = {"M": {
                "timestamp": _ser_s(now), "status": _ser_s("worklog"),
                "description": _ser_s(release_note),
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET active_agent_session = :f, active_agent_session_id = :empty_s, "
                    "checkout_state = :checked_in, checked_in_by = :checkin_by, checked_in_at = :now, "
                    "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                    "sync_version = if_not_exists(sync_version, :zero) + :one, "
                    "history = list_append(if_not_exists(history, :empty_l), :hentry)"
                ),
                ExpressionAttributeValues={
                    ":f": {"BOOL": False}, ":empty_s": _ser_s(""),
                    ":checked_in": _ser_s("checked_in"), ":checkin_by": _ser_s(release_agent),
                    ":now": _ser_s(now), ":note": _ser_s(release_note),
                    ":wsrc": _build_write_source(body),
                    ":zero": {"N": "0"}, ":one": {"N": "1"},
                    ":hentry": {"L": [history_entry]}, ":empty_l": {"L": []},
                },
            )
            return _response(200, {
                "success": True, "record_id": record_id,
                "checkout": False, "checkout_state": "checked_in", "updated_at": now,
            })

    # --- Generic field update ---
    note_val = value if len(str(value)) <= 100 else str(value)[:100] + "..."
    note_text = f"Field '{field}' set to '{note_val}'{note_suffix}"

    # Enrich worklog with evidence details (ENC-FTR-022)
    transition_evidence = body.get("transition_evidence", {})
    if field == "status" and transition_evidence:
        evidence_parts = []
        if transition_evidence.get("commit_sha"):
            evidence_parts.append(f"commit: {transition_evidence['commit_sha'][:12]}")
        if transition_evidence.get("deployment_ref"):
            evidence_parts.append(f"deploy: {transition_evidence['deployment_ref']}")
        if transition_evidence.get("merge_evidence"):
            evidence_parts.append(f"merge: {transition_evidence['merge_evidence'][:80]}")
        if transition_evidence.get("revert_reason"):
            evidence_parts.append(f"revert: {transition_evidence['revert_reason'][:80]}")
        if evidence_parts:
            note_text += f" [evidence: {', '.join(evidence_parts)}]"

    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(note_text),
    }}

    # Build extra SET clauses for evidence fields (ENC-FTR-022)
    extra_sets = []
    extra_vals = {}
    if field == "status" and transition_evidence:
        if transition_evidence.get("commit_sha"):
            extra_sets.append("commit_sha = :commit_sha")
            extra_vals[":commit_sha"] = {"S": transition_evidence["commit_sha"].strip().lower()}
        if transition_evidence.get("deployment_ref"):
            extra_sets.append("deployment_ref = :deploy_ref")
            extra_vals[":deploy_ref"] = {"S": transition_evidence["deployment_ref"].strip()}
        if transition_evidence.get("merge_evidence"):
            extra_sets.append("merge_evidence = :merge_ev")
            extra_vals[":merge_ev"] = {"S": transition_evidence["merge_evidence"].strip()}

    update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
        "history = list_append(if_not_exists(history, :empty), :hentry)"
    )
    if extra_sets:
        update_expr += ", " + ", ".join(extra_sets)

    attr_values = {
        ":val": _ser_value(value), ":now": _ser_s(now),
        ":note": _ser_s(note_text), ":wsrc": _build_write_source(body),
        ":zero": {"N": "0"}, ":one": {"N": "1"},
        ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
    }
    attr_values.update(extra_vals)

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#fld": field},
            ExpressionAttributeValues=attr_values,
        )
    except Exception as exc:
        logger.error("update_item failed: %s", exc)
        return _error(500, "Database write failed.")

    result: Dict[str, Any] = {
        "success": True, "record_id": record_id,
        "field": field, "value": value, "updated_at": now,
    }
    if warnings:
        result["warnings"] = warnings
    return _response(200, result)


def _handle_pwa_action(project_id: str, record_type: str, record_id: str, body: Dict, action: str) -> Dict:
    """Handle legacy PWA mutations: close, note, reopen."""
    if action not in ("close", "note", "reopen"):
        return _error(400, "Field 'action' must be 'close', 'note', or 'reopen'.")

    note_text = body.get("note", "")
    if action == "note":
        if not note_text or not str(note_text).strip():
            return _error(400, "Field 'note' is required and must not be empty.")
        note_text = str(note_text).strip()
        if len(note_text) > MAX_NOTE_LENGTH:
            return _error(400, f"Note exceeds maximum length of {MAX_NOTE_LENGTH} characters.")

    try:
        existing = _get_record_full(project_id, record_type, record_id)
    except Exception:
        return _error(500, "Database read failed. Please try again.")

    if existing is None:
        return _error(404, f"Record not found: {record_id}")

    current_version = existing.get("sync_version", 0)
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    try:
        if action == "close":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            if current_status == closed_status:
                return _response(200, {
                    "success": True, "action": "close", "record_id": record_id,
                    "updated_status": closed_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            now = _now_z()
            description = "Closed via Enceladus PWA"
            history_entry = {"M": {
                "timestamp": {"S": now}, "status": {"S": "close_audit"},
                "description": {"S": description},
                "agent_details": {"S": "Enceladus PWA (human user)"},
                "closed_time": {"S": now},
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #status = :status, updated_at = :ts, last_update_note = :note, "
                    "sync_version = sync_version + :one, "
                    "#history = list_append(#history, :entry)"
                ),
                ConditionExpression="sync_version = :expected",
                ExpressionAttributeNames={"#status": "status", "#history": "history"},
                ExpressionAttributeValues={
                    ":status": {"S": closed_status}, ":ts": {"S": now},
                    ":note": {"S": description}, ":one": {"N": "1"},
                    ":entry": {"L": [history_entry]},
                    ":expected": {"N": str(current_version)},
                },
            )
            return _response(200, {
                "success": True, "action": "close", "record_id": record_id,
                "updated_status": closed_status, "updated_at": now,
            })

        elif action == "reopen":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            default_status = _DEFAULT_STATUS[record_type]
            if current_status == default_status:
                return _response(200, {
                    "success": True, "action": "reopen", "record_id": record_id,
                    "updated_status": default_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            if current_status != closed_status:
                return _error(400, f"Cannot reopen: record status is '{current_status}', not '{closed_status}'.")
            now = _now_z()
            description = "Reopened via Enceladus PWA"
            history_entry = {"M": {
                "timestamp": {"S": now}, "status": {"S": "reopened"},
                "description": {"S": description},
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #status = :new_status, updated_at = :ts, last_update_note = :note, "
                    "sync_version = sync_version + :one, "
                    "#history = list_append(#history, :entry)"
                ),
                ConditionExpression="sync_version = :expected AND #status = :closed_val",
                ExpressionAttributeNames={"#status": "status", "#history": "history"},
                ExpressionAttributeValues={
                    ":new_status": {"S": default_status}, ":ts": {"S": now},
                    ":note": {"S": description}, ":one": {"N": "1"},
                    ":entry": {"L": [history_entry]},
                    ":expected": {"N": str(current_version)},
                    ":closed_val": {"S": closed_status},
                },
            )
            _emit_reopen_event(project_id, record_type, record_id, closed_status, default_status, now)
            return _response(200, {
                "success": True, "action": "reopen", "record_id": record_id,
                "updated_status": default_status, "updated_at": now,
            })

        else:  # note
            now = _now_z()
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #update = :note, updated_at = :ts, "
                    "sync_version = sync_version + :one"
                ),
                ConditionExpression="sync_version = :expected",
                ExpressionAttributeNames={"#update": "update"},
                ExpressionAttributeValues={
                    ":note": {"S": note_text}, ":ts": {"S": now},
                    ":one": {"N": "1"}, ":expected": {"N": str(current_version)},
                },
            )
            return _response(200, {
                "success": True, "action": "note", "record_id": record_id,
                "updated_at": now,
            })

    except ValueError as exc:
        return _error(409, str(exc))
    except ClientError as exc:
        if _is_conditional_check_failed(exc):
            return _error(409, "Record was modified concurrently. Please refresh and try again.")
        logger.error("mutation failed: %s", exc)
        return _error(500, "Database write failed. Please try again.")
    except Exception as exc:
        logger.error("mutation failed: %s", exc)
        return _error(500, "Database write failed. Please try again.")


def _handle_log(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/log — append worklog entry to history."""
    description = body.get("description", "").strip()
    if not description:
        return _error(400, "Field 'description' is required.")
    _normalize_write_source(body)

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Verify record exists
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    # Session ownership enforcement
    item_data = _deser_item(raw_item)
    ws = _normalize_write_source(body)
    current_session = item_data.get("active_agent_session", False)
    current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
    provider = str(ws.get("provider", "")).strip()
    if current_session and current_session_id:
        if not provider:
            return _error(
                400,
                f"Record is checked out by '{current_session_id}'. "
                "write_source.provider is required for modifications.",
            )
        if current_session_id != provider:
            return _error(409, f"Record is checked out by '{current_session_id}'. Cannot modify.")

    now = _now_z()
    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(description),
    }}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                "SET updated_at = :now, last_update_note = :note, "
                "write_source = :wsrc, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ExpressionAttributeValues={
                ":now": _ser_s(now), ":note": _ser_s(description),
                ":wsrc": _build_write_source(body),
                ":zero": {"N": "0"}, ":one": {"N": "1"},
                ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
            },
        )
    except Exception as exc:
        logger.error("update_item (log) failed: %s", exc)
        return _error(500, "Database write failed.")

    return _response(200, {"success": True, "record_id": record_id, "updated_at": now})


def _handle_checkout(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/checkout — session checkout."""
    body["field"] = "active_agent_session"
    body["value"] = True
    return _handle_update_field(project_id, record_type, record_id, body)


def _handle_release(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """DELETE /{project}/{type}/{id}/checkout — session release."""
    body["field"] = "active_agent_session"
    body["value"] = False
    return _handle_update_field(project_id, record_type, record_id, body)


def _handle_acceptance_evidence(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/acceptance-evidence — set evidence on acceptance criterion."""
    criterion_index = body.get("criterion_index")
    evidence_text = body.get("evidence", "").strip()
    evidence_acceptance = body.get("evidence_acceptance", False)

    if criterion_index is None:
        return _error(400, "Field 'criterion_index' is required.")
    try:
        criterion_index = int(criterion_index)
    except (ValueError, TypeError):
        return _error(400, "Field 'criterion_index' must be an integer.")

    if evidence_acceptance and not evidence_text:
        return _error(400, "Cannot set evidence_acceptance=true without providing evidence text.")

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Fetch the record
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    item_data = _deser_item(raw_item)

    if item_data.get("record_type") != "feature":
        return _error(400, f"acceptance-evidence only applies to features. This is a {item_data.get('record_type')}.")

    ac_list = item_data.get("acceptance_criteria", [])
    if not ac_list:
        return _error(400, f"Feature '{record_id}' has no acceptance_criteria.")

    if criterion_index < 0 or criterion_index >= len(ac_list):
        return _error(400,
            f"criterion_index {criterion_index} out of range. "
            f"Feature has {len(ac_list)} criteria (indices 0-{len(ac_list) - 1}).")

    # Get description from existing criterion
    raw_ac = raw_item.get("acceptance_criteria", {}).get("L", [])
    ac_item = raw_ac[criterion_index]
    if "S" in ac_item:
        description = ac_item["S"]
    elif "M" in ac_item:
        description = ac_item["M"].get("description", {}).get("S", "")
    else:
        description = str(ac_list[criterion_index])

    now = _now_z()
    note_suffix = _write_source_note_suffix(body)
    ac_updated = {"M": {
        "description": _ser_s(description),
        "evidence": _ser_s(evidence_text),
        "evidence_acceptance": {"BOOL": evidence_acceptance},
    }}
    status_word = "accepted" if evidence_acceptance else "updated"
    note_text = (
        f"Acceptance criterion [{criterion_index}] evidence {status_word}"
        f"{note_suffix}: {description[:80]}"
    )
    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(note_text),
    }}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                f"SET acceptance_criteria[{criterion_index}] = :ac_item, "
                "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ExpressionAttributeValues={
                ":ac_item": ac_updated, ":now": _ser_s(now),
                ":note": _ser_s(note_text), ":wsrc": _build_write_source(body),
                ":zero": {"N": "0"}, ":one": {"N": "1"},
                ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
            },
        )
    except Exception as exc:
        logger.error("update_item (evidence) failed: %s", exc)
        return _error(500, "Database write failed.")

    # Build criteria summary
    criteria_summary = []
    for i, ac in enumerate(ac_list):
        if isinstance(ac, dict):
            desc = ac.get("description", str(ac))
            ev_acc = ac.get("evidence_acceptance", False)
        elif isinstance(ac, str):
            desc = ac
            ev_acc = False
        else:
            desc = str(ac)
            ev_acc = False
        if i == criterion_index:
            desc = description
            ev_acc = evidence_acceptance
        criteria_summary.append({"index": i, "description": desc[:100], "evidence_acceptance": ev_acc})

    all_accepted = all(c["evidence_acceptance"] for c in criteria_summary)

    return _response(200, {
        "success": True, "record_id": record_id,
        "criterion_index": criterion_index,
        "evidence_acceptance": evidence_acceptance,
        "updated_at": now, "criteria_summary": criteria_summary,
        "all_criteria_accepted": all_accepted, "completion_eligible": all_accepted,
    })


# ---------------------------------------------------------------------------
# Path parsing & routing
# ---------------------------------------------------------------------------

# Route patterns — order matters (most specific first)
_RE_PENDING_UPDATES = re.compile(r"^(?:/api/v1/tracker)?/pending-updates$")
_RE_RECORD_SUB = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature)/(?P<id>[A-Za-z0-9_-]+)/(?P<sub>log|checkout|acceptance-evidence)$"
)
_RE_RECORD = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature)/(?P<id>[A-Za-z0-9_-]+)$"
)
_RE_TYPE_COLLECTION = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature)$"
)
_RE_PROJECT = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)$"
)


def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )
    path = event.get("rawPath") or event.get("path", "")
    query_params = event.get("queryStringParameters") or {}

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # --- Route: GET /pending-updates ---
    if method == "GET" and _RE_PENDING_UPDATES.match(path):
        claims, auth_err = _authenticate(event, ["tracker:read"])
        if auth_err:
            return auth_err
        return _handle_pending_updates(query_params)

    # --- Route: sub-resource operations (log, checkout, acceptance-evidence) ---
    m_sub = _RE_RECORD_SUB.match(path)
    if m_sub:
        project_id = m_sub.group("project")
        record_type = m_sub.group("type")
        record_id = m_sub.group("id")
        sub = m_sub.group("sub")

        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        try:
            body = json.loads(event.get("body") or "{}")
        except (ValueError, TypeError):
            body = {}
        _normalize_write_source(body, claims)

        if sub == "log" and method == "POST":
            return _handle_log(project_id, record_type, record_id, body)
        elif sub == "checkout" and method == "POST":
            return _handle_checkout(project_id, record_type, record_id, body)
        elif sub == "checkout" and method == "DELETE":
            return _handle_release(project_id, record_type, record_id, body)
        elif sub == "acceptance-evidence" and method == "POST":
            return _handle_acceptance_evidence(project_id, record_type, record_id, body)
        else:
            return _error(405, f"Method {method} not allowed on /{sub}.")

    # --- Route: single record (GET, PATCH) ---
    m_record = _RE_RECORD.match(path)
    if m_record:
        project_id = m_record.group("project")
        record_type = m_record.group("type")
        record_id = m_record.group("id")

        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        if method == "GET":
            return _handle_get_record(project_id, record_type, record_id)
        elif method == "PATCH":
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_update_field(project_id, record_type, record_id, body)
        else:
            return _error(405, f"Method {method} not allowed. Use GET or PATCH.")

    # --- Route: type collection (POST = create) ---
    m_type = _RE_TYPE_COLLECTION.match(path)
    if m_type:
        project_id = m_type.group("project")
        record_type = m_type.group("type")

        claims, auth_err = _authenticate(event, ["tracker:write"])
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        if method == "POST":
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_create_record(project_id, record_type, body)
        else:
            return _error(405, f"Method {method} not allowed. Use POST to create.")

    # --- Route: project listing (GET) ---
    m_project = _RE_PROJECT.match(path)
    if m_project:
        project_id = m_project.group("project")

        # Don't require auth for listing? Actually yes, require it.
        claims, auth_err = _authenticate(event, ["tracker:read"])
        if auth_err:
            return auth_err

        if method == "GET":
            return _handle_list_records(project_id, query_params)
        else:
            return _error(405, f"Method {method} not allowed. Use GET to list.")

    return _error(404, f"No route matched: {method} {path}")
