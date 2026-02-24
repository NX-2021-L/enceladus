"""feed_query/lambda_function.py

Lambda API for Enceladus feed read and subscription lifecycle.

Routes (via API Gateway proxy):
    GET     /api/v1/feed
    POST    /api/v1/feed/subscriptions
    GET     /api/v1/feed/subscriptions/{subscriptionId}
    DELETE  /api/v1/feed/subscriptions/{subscriptionId}
    OPTIONS /api/v1/feed*

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header.
    Validates the JWT using Cognito JWKS (RS256, cached module-level).

Environment variables:
    COGNITO_USER_POOL_ID      default: ""
    COGNITO_CLIENT_ID         default: ""
    DYNAMODB_TABLE            default: devops-project-tracker
    SUBSCRIPTIONS_TABLE       default: feed-subscriptions
    COORDINATION_TABLE        default: coordination-requests
    DYNAMODB_REGION           default: us-west-2
    PROJECTS_TABLE            default: projects
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import urllib.request

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
SUBSCRIPTIONS_TABLE = os.environ.get("SUBSCRIPTIONS_TABLE", "feed-subscriptions")
COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
CORS_ORIGIN = "https://jreese.net"
FEED_CACHE_CONTROL = "max-age=0, s-maxage=300, must-revalidate"

CLOSED_ITEM_MAX_AGE_DAYS = 0
MAX_SCOPE_RECORD_IDS = 500
MAX_SCOPE_STATUSES = 20
MAX_DURATION_MINUTES = 10080
DEFAULT_DURATION_MINUTES = 60
VALID_RECORD_TYPES = {"task", "issue", "feature"}
VALID_DELIVERY_MODES = {"poll", "push"}

_CLOSED_STATUSES = {"closed", "complete", "completed"}

# Status normalisation mappings
_STATUS_TASK = {"open", "closed", "in_progress", "planned"}
_STATUS_ISSUE = {"open", "closed"}
_STATUS_FEATURE = {"planned", "in_progress", "completed", "closed"}
_VALID_PRIORITIES = {"P0", "P1", "P2", "P3"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

_project_cache: Optional[List[Dict[str, str]]] = None
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0

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


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_now() -> int:
    return int(time.time())


def _parse_iso8601(raw: str) -> Optional[dt.datetime]:
    if not raw:
        return None
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("body")
    if raw in (None, ""):
        return {}
    if not isinstance(raw, str):
        raise ValueError("JSON body must be a string")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JSON body must be an object")
    return parsed


# ---------------------------------------------------------------------------
# Auth (same Cognito pattern as existing Lambdas)
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
        return jwt.decode(
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


def _extract_token(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("enceladus_id_token="):
            return part[len("enceladus_id_token=") :]

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        for part in event_cookies:
            if isinstance(part, str) and part.startswith("enceladus_id_token="):
                return part[len("enceladus_id_token=") :]
    return None


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json", "Cache-Control": FEED_CACHE_CONTROL},
        "body": json.dumps(body),
    }


def _error(status_code: int, message: str, **extra: Any) -> Dict[str, Any]:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code == 409:
            code = "CONFLICT"
        elif status_code == 429:
            code = "RATE_LIMITED"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500 or code in {"SUBSCRIPTION_EXPIRED"}))
    details = dict(extra)
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    payload.update(details)
    return _response(status_code, payload)


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _ddb_str(item: Dict[str, Any], key: str, default: str = "") -> str:
    return item.get(key, {}).get("S", default)


def _ddb_int(item: Dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(item.get(key, {}).get("N", str(default)))
    except (ValueError, TypeError):
        return default


def _ddb_bool(item: Dict[str, Any], key: str, default: bool = False) -> bool:
    """Extract a boolean from a DynamoDB item, handling both BOOL and string types."""
    attr = item.get(key, {})
    if "BOOL" in attr:
        return bool(attr["BOOL"])
    if "S" in attr:
        return attr["S"].lower() in ("true", "1", "yes", "on")
    return default


def _ddb_str_set(item: Dict[str, Any], key: str) -> List[str]:
    attr = item.get(key, {})
    ss = attr.get("SS")
    if isinstance(ss, list):
        return sorted(str(v) for v in ss if str(v).strip())
    raw_list = attr.get("L")
    if isinstance(raw_list, list):
        values: List[str] = []
        for entry in raw_list:
            if isinstance(entry, dict) and "S" in entry:
                text = str(entry["S"]).strip()
                if text:
                    values.append(text)
        return values
    return []


# ---------------------------------------------------------------------------
# Project discovery
# ---------------------------------------------------------------------------


def _get_active_projects() -> List[Dict[str, str]]:
    """Fetch active projects from the projects table (cached 5 min)."""
    global _project_cache, _project_cache_at
    now = time.time()
    if _project_cache is not None and (now - _project_cache_at) < _PROJECT_CACHE_TTL:
        return _project_cache

    ddb = _get_ddb()
    try:
        resp = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id",
        )
        projects = [
            {"project_id": item["project_id"]["S"]}
            for item in resp.get("Items", [])
            if "project_id" in item
        ]
        _project_cache = projects
        _project_cache_at = now
        return projects
    except Exception as exc:
        logger.warning("Failed to scan projects table: %s", exc)
        return _project_cache or []


# ---------------------------------------------------------------------------
# Subscription helpers (DVP-TSK-254)
# ---------------------------------------------------------------------------


def _new_subscription_id() -> str:
    return f"SUB-{uuid.uuid4().hex[:12].upper()}"


def _collect_coordination_record_ids(coordination_request_id: str) -> List[str]:
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=COORDINATION_TABLE,
            Key={"request_id": {"S": coordination_request_id}},
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError):
        return []

    item = resp.get("Item") or {}
    if not item:
        return []

    out: List[str] = []
    feature_id = _ddb_str(item, "feature_id")
    if feature_id:
        out.append(feature_id)
    out.extend(_ddb_str_set(item, "task_ids"))
    out.extend(_ddb_str_set(item, "issue_ids"))

    seen = set()
    uniq: List[str] = []
    for rid in out:
        normalized = str(rid).strip().upper()
        if not normalized or normalized in seen:
            continue
        uniq.append(normalized)
        seen.add(normalized)
    return uniq


def _normalize_scope(scope: Any, coordination_request_id: Optional[str]) -> Dict[str, Any]:
    if scope in (None, {}):
        scope = {}
    if not isinstance(scope, dict):
        raise ValueError("'scope' must be an object")

    project_id = str(scope.get("project_id") or "").strip()

    raw_record_ids = scope.get("record_ids") or []
    if not isinstance(raw_record_ids, list):
        raise ValueError("'scope.record_ids' must be an array")

    record_ids: List[str] = []
    seen_ids = set()
    for rid in raw_record_ids[:MAX_SCOPE_RECORD_IDS]:
        normalized = str(rid).strip().upper()
        if not normalized or normalized in seen_ids:
            continue
        record_ids.append(normalized)
        seen_ids.add(normalized)

    if coordination_request_id:
        for rid in _collect_coordination_record_ids(coordination_request_id):
            if rid not in seen_ids:
                record_ids.append(rid)
                seen_ids.add(rid)

    raw_record_types = scope.get("record_types") or []
    if not isinstance(raw_record_types, list):
        raise ValueError("'scope.record_types' must be an array")

    record_types: List[str] = []
    for rtype in raw_record_types:
        normalized = str(rtype).strip().lower()
        if normalized in VALID_RECORD_TYPES and normalized not in record_types:
            record_types.append(normalized)

    filters = scope.get("filters") or {}
    if not isinstance(filters, dict):
        raise ValueError("'scope.filters' must be an object")

    raw_statuses = filters.get("status") or []
    if not isinstance(raw_statuses, list):
        raise ValueError("'scope.filters.status' must be an array")

    statuses: List[str] = []
    for status in raw_statuses[:MAX_SCOPE_STATUSES]:
        normalized = str(status).strip().replace("-", "_").lower()
        if normalized and normalized not in statuses:
            statuses.append(normalized)

    updated_since = str(filters.get("updated_since") or "").strip()
    if updated_since and _parse_iso8601(updated_since) is None:
        raise ValueError("'scope.filters.updated_since' must be ISO-8601 UTC")

    return {
        "project_id": project_id or None,
        "record_ids": record_ids,
        "record_types": record_types,
        "filters": {
            "status": statuses,
            "updated_since": updated_since or None,
        },
    }


def _deserialize_subscription(item: Dict[str, Any]) -> Dict[str, Any]:
    scope_raw = _ddb_str(item, "scope_json", "{}")
    push_raw = _ddb_str(item, "push_config_json", "{}")
    try:
        scope = json.loads(scope_raw) if scope_raw else {}
    except json.JSONDecodeError:
        scope = {}
    try:
        push_config = json.loads(push_raw) if push_raw else {}
    except json.JSONDecodeError:
        push_config = {}

    return {
        "subscription_id": _ddb_str(item, "subscription_id"),
        "state": _ddb_str(item, "state", "active"),
        "requestor_id": _ddb_str(item, "requestor_id"),
        "scope": scope,
        "duration_minutes": _ddb_int(item, "duration_minutes", DEFAULT_DURATION_MINUTES),
        "delivery_mode": _ddb_str(item, "delivery_mode", "poll"),
        "push_config": push_config,
        "coordination_request_id": _ddb_str(item, "coordination_request_id") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "activated_at": _ddb_str(item, "activated_at") or None,
        "updated_at": _ddb_str(item, "updated_at") or None,
        "expires_at": _ddb_str(item, "expires_at") or None,
        "expires_epoch": _ddb_int(item, "expires_epoch"),
        "cancelled_at": _ddb_str(item, "cancelled_at") or None,
        "created_by": _ddb_str(item, "created_by") or None,
    }


def _subscription_public(sub: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "subscription_id": sub.get("subscription_id"),
        "state": sub.get("state"),
        "scope": sub.get("scope") or {},
        "duration_minutes": sub.get("duration_minutes"),
        "delivery_mode": sub.get("delivery_mode"),
        "coordination_request_id": sub.get("coordination_request_id"),
        "created_at": sub.get("created_at"),
        "activated_at": sub.get("activated_at"),
        "updated_at": sub.get("updated_at"),
        "expires_at": sub.get("expires_at"),
        "cancelled_at": sub.get("cancelled_at"),
    }


def _expire_subscription_if_needed(sub: Dict[str, Any]) -> Dict[str, Any]:
    if sub.get("state") != "active":
        return sub

    expires_epoch = int(sub.get("expires_epoch") or 0)
    if expires_epoch <= _unix_now():
        ddb = _get_ddb()
        now = _now_z()
        try:
            ddb.update_item(
                TableName=SUBSCRIPTIONS_TABLE,
                Key={"subscription_id": {"S": sub["subscription_id"]}},
                UpdateExpression="SET #state = :expired, updated_at = :ts",
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":expired": {"S": "expired"},
                    ":ts": {"S": now},
                },
            )
        except Exception:
            pass
        sub = {**sub, "state": "expired", "updated_at": now}
    return sub


def _get_subscription(subscription_id: str) -> Optional[Dict[str, Any]]:
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=SUBSCRIPTIONS_TABLE,
            Key={"subscription_id": {"S": subscription_id}},
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed reading subscription: {exc}") from exc

    item = resp.get("Item")
    if not item:
        return None

    return _expire_subscription_if_needed(_deserialize_subscription(item))


def _create_subscription(body: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    requestor_id = str(body.get("requestor_id") or "").strip()
    if not requestor_id:
        requestor_id = str(claims.get("sub") or claims.get("email") or "").strip()
    if not requestor_id:
        raise ValueError("'requestor_id' is required")

    coordination_request_id = str(body.get("coordination_request_id") or "").strip() or None

    scope = _normalize_scope(body.get("scope"), coordination_request_id)

    duration_raw = body.get("duration_minutes", DEFAULT_DURATION_MINUTES)
    try:
        duration_minutes = int(duration_raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("'duration_minutes' must be an integer") from exc
    if duration_minutes < 1 or duration_minutes > MAX_DURATION_MINUTES:
        raise ValueError(f"'duration_minutes' must be in range 1..{MAX_DURATION_MINUTES}")

    delivery_mode = str(body.get("delivery_mode") or "poll").strip().lower()
    if delivery_mode not in VALID_DELIVERY_MODES:
        raise ValueError("'delivery_mode' must be 'poll' or 'push'")

    push_config = body.get("push_config") or {}
    if not isinstance(push_config, dict):
        raise ValueError("'push_config' must be an object")

    now_epoch = _unix_now()
    created_at = _now_z()
    expires_epoch = now_epoch + duration_minutes * 60
    expires_at = dt.datetime.fromtimestamp(expires_epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    subscription_id = _new_subscription_id()
    created_by = str(claims.get("email") or claims.get("sub") or "unknown")

    ddb_item: Dict[str, Any] = {
        "subscription_id": {"S": subscription_id},
        "state": {"S": "active"},
        "requestor_id": {"S": requestor_id},
        "scope_json": {"S": json.dumps(scope, separators=(",", ":"), sort_keys=True)},
        "duration_minutes": {"N": str(duration_minutes)},
        "delivery_mode": {"S": delivery_mode},
        "push_config_json": {"S": json.dumps(push_config, separators=(",", ":"), sort_keys=True)},
        "created_at": {"S": created_at},
        "activated_at": {"S": created_at},
        "updated_at": {"S": created_at},
        "expires_at": {"S": expires_at},
        "expires_epoch": {"N": str(expires_epoch)},
        "created_by": {"S": created_by},
    }
    if coordination_request_id:
        ddb_item["coordination_request_id"] = {"S": coordination_request_id}

    ddb = _get_ddb()
    try:
        ddb.put_item(
            TableName=SUBSCRIPTIONS_TABLE,
            Item=ddb_item,
            ConditionExpression="attribute_not_exists(subscription_id)",
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed creating subscription: {exc}") from exc

    return {
        "subscription_id": subscription_id,
        "state": "active",
        "requestor_id": requestor_id,
        "scope": scope,
        "duration_minutes": duration_minutes,
        "delivery_mode": delivery_mode,
        "push_config": push_config,
        "coordination_request_id": coordination_request_id,
        "created_at": created_at,
        "activated_at": created_at,
        "updated_at": created_at,
        "expires_at": expires_at,
        "expires_epoch": expires_epoch,
        "created_by": created_by,
    }


def _cancel_subscription(subscription_id: str) -> Optional[Dict[str, Any]]:
    ddb = _get_ddb()
    now = _now_z()
    try:
        ddb.update_item(
            TableName=SUBSCRIPTIONS_TABLE,
            Key={"subscription_id": {"S": subscription_id}},
            ConditionExpression="attribute_exists(subscription_id)",
            UpdateExpression="SET #state = :cancelled, cancelled_at = :ts, updated_at = :ts",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":cancelled": {"S": "cancelled"},
                ":ts": {"S": now},
            },
        )
    except ddb.exceptions.ConditionalCheckFailedException:
        return None
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed cancelling subscription: {exc}") from exc

    return _get_subscription(subscription_id)


def _apply_subscription_scope(
    tasks: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
    features: List[Dict[str, Any]],
    subscription: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], int]:
    scope = subscription.get("scope") or {}
    scope_project_id = str(scope.get("project_id") or "").strip()

    scope_record_ids = {
        str(r).strip().upper()
        for r in (scope.get("record_ids") or [])
        if str(r).strip()
    }

    raw_record_types = scope.get("record_types") or []
    scope_record_types = {
        str(r).strip().lower()
        for r in raw_record_types
        if str(r).strip().lower() in VALID_RECORD_TYPES
    }

    filters = scope.get("filters") or {}
    status_filters = {
        str(s).strip().replace("-", "_").lower()
        for s in (filters.get("status") or [])
        if str(s).strip()
    }
    updated_since = _parse_iso8601(str(filters.get("updated_since") or ""))

    def keep_item(item: Dict[str, Any], item_id_key: str, record_type: str) -> bool:
        if scope_record_types and record_type not in scope_record_types:
            return False

        if scope_project_id and item.get("project_id") != scope_project_id:
            return False

        item_id = str(item.get(item_id_key) or "").strip().upper()
        if scope_record_ids and item_id not in scope_record_ids:
            return False

        if status_filters:
            status = str(item.get("status") or "").strip().replace("-", "_").lower()
            if status not in status_filters:
                return False

        if updated_since is not None:
            updated_at = _parse_iso8601(str(item.get("updated_at") or ""))
            if updated_at is None or updated_at < updated_since:
                return False

        return True

    scoped_tasks = [t for t in tasks if keep_item(t, "task_id", "task")]
    scoped_issues = [i for i in issues if keep_item(i, "issue_id", "issue")]
    scoped_features = [f for f in features if keep_item(f, "feature_id", "feature")]

    matched = len(scoped_tasks) + len(scoped_issues) + len(scoped_features)
    return scoped_tasks, scoped_issues, scoped_features, matched


# ---------------------------------------------------------------------------
# Feed query + transform
# ---------------------------------------------------------------------------


def _normalize_status(raw: str, valid: set, default: str) -> str:
    """Normalise status values (e.g. 'in-progress' -> 'in_progress')."""
    s = raw.replace("-", "_").lower().strip()
    return s if s in valid else default


def _normalize_priority(raw: str) -> str:
    p = raw.upper().strip()
    return p if p in _VALID_PRIORITIES else "P3"


def _normalize_severity(raw: str) -> str:
    s = raw.lower().strip()
    return s if s in _VALID_SEVERITIES else "medium"


def _is_stale_closed(item: Dict[str, Any], cutoff: dt.datetime) -> bool:
    """Check if a DDB item is closed and older than the cutoff."""
    status = _ddb_str(item, "status").replace("-", "_").lower()
    if status not in _CLOSED_STATUSES:
        return False
    updated = _ddb_str(item, "updated_at")
    if not updated:
        return True
    parsed = _parse_iso8601(updated)
    if parsed is None:
        return True
    return parsed < cutoff


def _transform_task_from_ddb(item: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "task_id": _ddb_str(item, "item_id"),
        "project_id": project_id,
        "title": _ddb_str(item, "title"),
        "description": "",
        "status": _normalize_status(_ddb_str(item, "status"), _STATUS_TASK, "open"),
        "priority": _normalize_priority(_ddb_str(item, "priority", "P3")),
        "assigned_to": _ddb_str(item, "assigned_to") or None,
        "related_feature_ids": _ddb_str_set(item, "related_feature_ids"),
        "related_task_ids": _ddb_str_set(item, "related_task_ids"),
        "related_issue_ids": _ddb_str_set(item, "related_issue_ids"),
        "checklist_total": _ddb_int(item, "checklist_total"),
        "checklist_done": _ddb_int(item, "checklist_done"),
        "checklist": [],
        "history": [],
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "active_agent_session": _ddb_bool(item, "active_agent_session"),
        "active_agent_session_parent": _ddb_bool(item, "active_agent_session_parent"),
        "coordination": _ddb_bool(item, "coordination"),
    }
    session_id = _ddb_str(item, "active_agent_session_id")
    if session_id:
        result["active_agent_session_id"] = session_id
    return result


def _transform_issue_from_ddb(item: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    return {
        "issue_id": _ddb_str(item, "item_id"),
        "project_id": project_id,
        "title": _ddb_str(item, "title"),
        "description": "",
        "status": _normalize_status(_ddb_str(item, "status"), _STATUS_ISSUE, "open"),
        "priority": _normalize_priority(_ddb_str(item, "priority", "P3")),
        "severity": _normalize_severity(_ddb_str(item, "severity", "medium")),
        "hypothesis": None,
        "related_feature_ids": _ddb_str_set(item, "related_feature_ids"),
        "related_task_ids": _ddb_str_set(item, "related_task_ids"),
        "related_issue_ids": _ddb_str_set(item, "related_issue_ids"),
        "history": [],
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "coordination": _ddb_bool(item, "coordination"),
    }


def _transform_feature_from_ddb(item: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    return {
        "feature_id": _ddb_str(item, "item_id"),
        "project_id": project_id,
        "title": _ddb_str(item, "title"),
        "description": "",
        "status": _normalize_status(_ddb_str(item, "status"), _STATUS_FEATURE, "planned"),
        "owners": _ddb_str_set(item, "owners"),
        "success_metrics_count": _ddb_int(item, "success_metrics_count"),
        "success_metrics": [],
        "related_task_ids": _ddb_str_set(item, "related_task_ids"),
        "related_feature_ids": _ddb_str_set(item, "related_feature_ids"),
        "related_issue_ids": _ddb_str_set(item, "related_issue_ids"),
        "history": [],
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "coordination": _ddb_bool(item, "coordination"),
    }


_TRANSFORM = {
    "task": _transform_task_from_ddb,
    "issue": _transform_issue_from_ddb,
    "feature": _transform_feature_from_ddb,
}


def _query_all_records() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    ddb = _get_ddb()
    projects = _get_active_projects()
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)

    all_tasks: List[Dict[str, Any]] = []
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []

    for proj in projects:
        pid = proj["project_id"]
        paginator = ddb.get_paginator("query")
        try:
            for page in paginator.paginate(
                TableName=DYNAMODB_TABLE,
                IndexName="project-type-index",
                KeyConditionExpression="project_id = :pid",
                ExpressionAttributeValues={":pid": {"S": pid}},
            ):
                for raw_item in page.get("Items", []):
                    record_type = _ddb_str(raw_item, "record_type")
                    if record_type not in _TRANSFORM:
                        continue
                    if _is_stale_closed(raw_item, cutoff):
                        continue

                    transformed = _TRANSFORM[record_type](raw_item, pid)
                    if record_type == "task":
                        all_tasks.append(transformed)
                    elif record_type == "issue":
                        all_issues.append(transformed)
                    elif record_type == "feature":
                        all_features.append(transformed)
        except (BotoCoreError, ClientError) as exc:
            logger.error("DynamoDB query failed for project %s: %s", pid, exc)
            continue

    all_tasks.sort(key=lambda x: x.get("task_id", ""))
    all_issues.sort(key=lambda x: x.get("issue_id", ""))
    all_features.sort(key=lambda x: x.get("feature_id", ""))

    return all_tasks, all_issues, all_features


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    ).upper()
    path = event.get("rawPath") or event.get("path") or ""

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    token = _extract_token(event)
    if not token:
        return _error(401, "Authentication required. Please sign in.")

    try:
        claims = _verify_token(token)
    except ValueError as exc:
        return _error(401, str(exc))

    if method == "POST" and re.search(r"/api/v1/feed/subscriptions/?$", path):
        try:
            body = _json_body(event)
            subscription = _create_subscription(body, claims)
        except ValueError as exc:
            return _error(400, str(exc))
        except RuntimeError as exc:
            return _error(500, str(exc))

        return _response(
            201,
            {
                "success": True,
                "subscription": _subscription_public(subscription),
            },
        )

    match_sub = re.search(r"/api/v1/feed/subscriptions/([A-Za-z0-9_-]+)/?$", path)
    if method == "GET" and match_sub:
        subscription_id = match_sub.group(1)
        try:
            sub = _get_subscription(subscription_id)
        except RuntimeError as exc:
            return _error(500, str(exc))

        if not sub:
            return _error(404, f"Subscription '{subscription_id}' not found")

        return _response(200, {"success": True, "subscription": _subscription_public(sub)})

    if method == "DELETE" and match_sub:
        subscription_id = match_sub.group(1)
        try:
            sub = _cancel_subscription(subscription_id)
        except RuntimeError as exc:
            return _error(500, str(exc))

        if not sub:
            return _error(404, f"Subscription '{subscription_id}' not found")

        return _response(200, {"success": True, "subscription": _subscription_public(sub)})

    if method != "GET" or not re.search(r"/api/v1/feed/?$", path):
        return _error(404, f"Unsupported route: {method} {path}")

    try:
        tasks, issues, features = _query_all_records()
    except Exception as exc:
        logger.error("feed query failed: %s", exc)
        return _error(500, "Failed to query feed data. Please try again.")

    qs = event.get("queryStringParameters") or {}
    subscription_meta = {
        "subscription_id": None,
        "scope_applied": False,
        "items_matched": len(tasks) + len(issues) + len(features),
    }

    subscription_id = str(qs.get("subscription_id") or "").strip()
    if subscription_id:
        try:
            sub = _get_subscription(subscription_id)
        except RuntimeError as exc:
            return _error(500, str(exc))

        if not sub:
            return _error(404, f"Subscription '{subscription_id}' not found")

        state = str(sub.get("state") or "")
        if state == "expired":
            return _error(
                410,
                "Subscription has expired",
                code="SUBSCRIPTION_EXPIRED",
                retryable=False,
                subscription_id=subscription_id,
            )
        if state != "active":
            return _error(409, f"Subscription state '{state}' does not permit feed queries")

        tasks, issues, features, matched = _apply_subscription_scope(tasks, issues, features, sub)
        subscription_meta = {
            "subscription_id": subscription_id,
            "scope_applied": True,
            "items_matched": matched,
        }

    return _response(
        200,
        {
            "generated_at": _now_z(),
            "version": "1.0",
            "tasks": tasks,
            "issues": issues,
            "features": features,
            "subscription": subscription_meta,
        },
    )
