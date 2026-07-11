"""feed_query/lambda_function.py

Lambda API for Enceladus feed read and subscription lifecycle.

Routes (via API Gateway proxy):
    GET     /api/v1/feed
    GET     /api/v1/feed/corpus
    GET     /api/v1/feed/delta
    POST    /api/v1/feed/refresh
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
    DOCUMENTS_TABLE           default: documents
    GRAPH_QUERY_API_FUNCTION  default: "" (unset disables the OpenSearch tier,
                              ENC-TSK-M39 -- full refresh falls back to the DDB
                              fan-out unconditionally, e.g. on v3-prod where
                              graph_query_api has no OpenSearch/VPC access)
"""

from __future__ import annotations

import concurrent.futures
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

import corpus as feed_corpus
import delta as feed_delta

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
# Configuration
# ---------------------------------------------------------------------------

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
SUBSCRIPTIONS_TABLE = os.environ.get("SUBSCRIPTIONS_TABLE", "feed-subscriptions")
COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
FEED_PUBLISHER_FUNCTION = os.environ.get("FEED_PUBLISHER_FUNCTION", "devops-feed-publisher")
# ENC-TSK-M39: graph_query_api is already VPC-attached with OpenSearch access;
# feed_query invokes it as a selection-tier proxy instead of joining the VPC
# itself. Empty/unset means the OpenSearch tier is unavailable (e.g. v3-prod).
GRAPH_QUERY_API_FUNCTION = os.environ.get("GRAPH_QUERY_API_FUNCTION", "")
OPENSEARCH_TIER_INVOKE_TIMEOUT_S = 5
CORS_ORIGIN = "https://jreese.net"
FEED_CACHE_CONTROL = "max-age=0, s-maxage=300, must-revalidate"
INCREMENTAL_LOOKBACK_SECONDS = 10

CLOSED_ITEM_MAX_AGE_DAYS = 365
MAX_SCOPE_RECORD_IDS = 500
MAX_SCOPE_STATUSES = 20
MAX_DURATION_MINUTES = 10080
DEFAULT_DURATION_MINUTES = 60
VALID_RECORD_TYPES = {"task", "issue", "feature", "lesson", "plan"}
VALID_DELIVERY_MODES = {"poll", "push"}

_CLOSED_STATUSES = {"closed", "complete", "completed"}

# Status normalisation mappings
_STATUS_TASK = {
    "open", "closed", "in_progress", "planned",
    "coding_complete", "committed", "pushed", "pr",
    "merged_main", "deploy_init", "deploy_success",
    "coding_updates", "deployed",
}
_STATUS_ISSUE = {"open", "in_progress", "closed"}
_STATUS_FEATURE = {"planned", "in_progress", "completed", "closed", "production", "deprecated"}
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

_corpus_cache_entries: Optional[List[Dict[str, Any]]] = None
_corpus_cache_at: float = 0.0
_CORPUS_CACHE_TTL = 30.0

_ddb = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            # ENC-TSK-M36: botocore's default max_pool_connections is 10 --
            # with _fan_out_by_project running _MAX_PROJECT_FANOUT_WORKERS
            # (24) threads against this SAME shared client, anything beyond
            # 10 concurrent Query calls would silently queue for a free
            # pooled connection, capping real concurrency at 10 regardless of
            # thread count. Sized to stay >= the fan-out width.
            config=Config(
                retries={"max_attempts": 3, "mode": "standard"},
                max_pool_connections=32,
            ),
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


def _to_iso8601_z(ts: dt.datetime) -> str:
    """Format timestamp in canonical UTC Zulu form (second precision)."""
    return ts.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _ddb_attr(item: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Safely extract a DynamoDB attribute wrapper dict from ``item[key]``.

    DynamoDB attributes are normally stored as type-tagged dicts like
    ``{"S": "foo"}``. This helper handles three edge cases that broke
    feed_query on 2026-04-07 (ENC-TSK-C31):

    * the attribute is missing: returns ``{}``
    * the attribute is stored as Python ``None``: returns ``{}`` (prior code
      did ``item.get(key, {})`` which returns ``None`` when the key exists
      with value ``None``, then crashed on ``.get("S", ...)``)
    * the attribute is stored as something that is not a dict: returns ``{}``
    """
    attr = item.get(key)
    if isinstance(attr, dict):
        return attr
    return {}


def _ddb_str(item: Dict[str, Any], key: str, default: str = "") -> str:
    v = _ddb_attr(item, key).get("S", default)
    return v if isinstance(v, str) else default


def _ddb_int(item: Dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(_ddb_attr(item, key).get("N", str(default)))
    except (ValueError, TypeError):
        return default


def _ddb_float(item: Dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(_ddb_attr(item, key).get("N", str(default)))
    except (ValueError, TypeError):
        return default


def _ddb_bool(item: Dict[str, Any], key: str, default: bool = False) -> bool:
    """Extract a boolean from a DynamoDB item, handling both BOOL and string types."""
    attr = _ddb_attr(item, key)
    if "BOOL" in attr:
        return bool(attr["BOOL"])
    if "S" in attr:
        s = attr["S"]
        return isinstance(s, str) and s.lower() in ("true", "1", "yes", "on")
    return default


def _ddb_str_set(item: Dict[str, Any], key: str) -> List[str]:
    attr = _ddb_attr(item, key)
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


MAX_HISTORY_ENTRIES = 10

# Per-type caps on full-refresh response (ENC-TSK-C34). The full /api/v1/feed
# response is a single synchronous Lambda payload and must fit under the AWS
# Lambda 6 MB sync response limit. With history entries populated per-record
# (ENC-TSK-C01), the pre-cap response exceeded that limit and produced the
# opaque {"message":"Internal Server Error"} that broke PWA plan + lesson
# rendering. The rows this cap applies to are the minimal 5-field snapshot
# projection (_handle_snapshot._rows), not full record bodies, so headroom
# under the 6 MB limit is large.
#
# ENC-TSK-M36: these caps are applied PER ACTIVE PROJECT (see
# _query_all_records), not globally across every project sharing this table
# -- a global cap meant one recently-active project could crowd out another
# project's entire issue/feature/lesson/plan representation in the snapshot.
# Worst case with N active projects is now N x (100 + 10*4) rows; at ~150
# bytes/row that's comfortably inside the 6 MB limit even for a few dozen
# projects, and the frontend already caps the visible feed list at 50 items
# post-fetch (frontend/ui-v2/src/api/feeds.ts::fetchFeedSnapshot).
MAX_TASKS_FULL_REFRESH = 100
MAX_ISSUES_FULL_REFRESH = 10
MAX_FEATURES_FULL_REFRESH = 10
MAX_LESSONS_FULL_REFRESH = 10
MAX_PLANS_FULL_REFRESH = 10


def _cap_by_updated_at(records: List[Dict[str, Any]], cap: int) -> List[Dict[str, Any]]:
    """Return the ``cap`` most-recently-updated records.

    Sort key is the ``updated_at`` ISO-8601 string descending; records with a
    missing or empty ``updated_at`` sort last so they are the first to be
    dropped when the cap is exceeded. If ``records`` is already at or below
    ``cap`` it is returned unchanged.
    """
    if cap <= 0 or len(records) <= cap:
        return records
    # Pair records with a sort key that naturally places empties at the end.
    def _sort_key(r: Dict[str, Any]) -> str:
        v = r.get("updated_at")
        return v if isinstance(v, str) and v else ""
    # Sort descending; Python's sort is stable so ties preserve original order.
    ordered = sorted(records, key=_sort_key, reverse=True)
    return ordered[:cap]


def _ddb_history(item: Dict[str, Any], key: str = "history") -> List[Dict[str, str]]:
    """Extract history entries from a DynamoDB item, capped at MAX_HISTORY_ENTRIES.

    Returns a list of {timestamp, status, description} dicts matching the
    HistoryEntry TypeScript interface consumed by the PWA HistoryFeed component.
    Only the most recent entries are returned when the list exceeds the cap.

    Hardened against any unexpected input shape: attribute stored as None,
    malformed L list, non-dict or M=None entries, and nested values that are
    not the expected {'S': ...} wire format. Any single bad entry is skipped;
    any uncaught failure returns [] rather than crashing the caller.
    """
    try:
        # _ddb_attr coerces missing / None / non-dict attribute to {}.
        attr = _ddb_attr(item, key)
        raw_list = attr.get("L")
        if not isinstance(raw_list, list):
            return []
        entries: List[Dict[str, str]] = []
        for entry in raw_list:
            try:
                if not isinstance(entry, dict):
                    continue
                m = entry.get("M")
                if not isinstance(m, dict):
                    continue

                def _s(field: str) -> str:
                    node = m.get(field)
                    if not isinstance(node, dict):
                        return ""
                    v = node.get("S", "")
                    return v if isinstance(v, str) else ""

                entries.append({
                    "timestamp": _s("timestamp"),
                    "status": _s("status"),
                    "description": _s("description"),
                })
            except Exception as entry_exc:  # noqa: BLE001
                logger.warning(
                    "_ddb_history: skipping malformed entry in item_id=%s: %s",
                    _ddb_str(item, "item_id") or "?",
                    entry_exc,
                )
                continue
        if len(entries) > MAX_HISTORY_ENTRIES:
            entries = entries[-MAX_HISTORY_ENTRIES:]
        return entries
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "_ddb_history: unexpected failure for item_id=%s: %s",
            _ddb_str(item, "item_id") or "?",
            exc,
        )
        return []


def _ddb_list_of_maps(item: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    """Extract a list of maps from a DynamoDB item (L type containing M types).

    Handles nested S, N, BOOL, and L-of-S values within each map entry.
    Used for structured attributes like acceptance_criteria and evidence.
    """
    attr = _ddb_attr(item, key)
    raw_list = attr.get("L")
    if not isinstance(raw_list, list):
        return []
    result: List[Dict[str, Any]] = []
    for entry in raw_list:
        if not isinstance(entry, dict) or "M" not in entry:
            continue
        m = entry["M"]
        if not isinstance(m, dict):
            continue
        obj: Dict[str, Any] = {}
        for k, v in m.items():
            if "S" in v:
                obj[k] = v["S"]
            elif "N" in v:
                try:
                    obj[k] = int(v["N"])
                except (ValueError, TypeError):
                    obj[k] = v["N"]
            elif "BOOL" in v:
                obj[k] = bool(v["BOOL"])
            elif "L" in v:
                obj[k] = [
                    sub.get("S", "") for sub in v["L"]
                    if isinstance(sub, dict) and "S" in sub
                ]
        result.append(obj)
    return result


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
    lessons: List[Dict[str, Any]],
    plans: List[Dict[str, Any]],
    subscription: Dict[str, Any],
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    int,
]:
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
    scoped_lessons = [l for l in lessons if keep_item(l, "lesson_id", "lesson")]
    scoped_plans = [p for p in plans if keep_item(p, "plan_id", "plan")]

    matched = (
        len(scoped_tasks)
        + len(scoped_issues)
        + len(scoped_features)
        + len(scoped_lessons)
        + len(scoped_plans)
    )
    return (
        scoped_tasks,
        scoped_issues,
        scoped_features,
        scoped_lessons,
        scoped_plans,
        matched,
    )


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
        "history": _ddb_history(item),
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "active_agent_session": _ddb_bool(item, "active_agent_session"),
        "active_agent_session_parent": _ddb_bool(item, "active_agent_session_parent"),
        "checkout_state": _ddb_str(item, "checkout_state") or None,
        "checked_out_by": _ddb_str(item, "checked_out_by") or None,
        "checked_out_at": _ddb_str(item, "checked_out_at") or None,
        "checked_in_by": _ddb_str(item, "checked_in_by") or None,
        "checked_in_at": _ddb_str(item, "checked_in_at") or None,
        "coordination": _ddb_bool(item, "coordination"),
        # Philosophy fields (ENC-FTR-017 / ENC-TSK-606)
        "category": _ddb_str(item, "category") or None,
        "intent": _ddb_str(item, "intent") or None,
        "acceptance_criteria": _ddb_str_set(item, "acceptance_criteria"),
        # Plan tree fields (ENC-ISS-139 / ENC-TSK-A57)
        "subtask_ids": _ddb_str_set(item, "subtask_ids"),
        "transition_type": _ddb_str(item, "transition_type") or None,
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
        "history": _ddb_history(item),
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "coordination": _ddb_bool(item, "coordination"),
        # Philosophy fields (ENC-FTR-017 / ENC-TSK-606)
        "category": _ddb_str(item, "category") or None,
        "intent": _ddb_str(item, "intent") or None,
        "primary_task": _ddb_str(item, "primary_task") or None,
        "evidence": _ddb_list_of_maps(item, "evidence"),
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
        "history": _ddb_history(item),
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "parent": _ddb_str(item, "parent") or None,
        "coordination": _ddb_bool(item, "coordination"),
        # Philosophy fields (ENC-FTR-017 / ENC-TSK-606)
        "category": _ddb_str(item, "category") or None,
        "intent": _ddb_str(item, "intent") or None,
        "user_story": _ddb_str(item, "user_story") or None,
        "primary_task": _ddb_str(item, "primary_task") or None,
        "acceptance_criteria": _ddb_list_of_maps(item, "acceptance_criteria"),
    }


_STATUS_LESSON = {"draft", "active", "graduated", "deprecated"}

# ENC-FTR-058: Plan record type
_STATUS_PLAN = {"drafted", "started", "complete", "incomplete"}


def _transform_plan_from_ddb(item: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    return {
        "plan_id": _ddb_str(item, "item_id"),
        "project_id": project_id,
        "title": _ddb_str(item, "title"),
        "description": _ddb_str(item, "description") or "",
        "status": _normalize_status(_ddb_str(item, "status"), _STATUS_PLAN, "drafted"),
        "priority": _normalize_priority(_ddb_str(item, "priority", "P2")),
        "category": _ddb_str(item, "category") or None,
        "objectives_set": _ddb_str_set(item, "objectives_set"),
        "attached_documents": _ddb_str_set(item, "attached_documents"),
        "related_feature_id": _ddb_str(item, "related_feature_id") or None,
        "checkout_state": _ddb_str(item, "checkout_state") or None,
        "checked_out_by": _ddb_str(item, "checked_out_by") or None,
        "checked_out_at": _ddb_str(item, "checked_out_at") or None,
        "related_task_ids": _ddb_str_set(item, "related_task_ids"),
        "related_issue_ids": _ddb_str_set(item, "related_issue_ids"),
        "related_feature_ids": _ddb_str_set(item, "related_feature_ids"),
        "history": _ddb_history(item),
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
    }


def _ddb_map(item: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Extract a DynamoDB Map attribute as a plain dict with N values as floats."""
    attr = _ddb_attr(item, key)
    m = attr.get("M", {})
    if not isinstance(m, dict):
        return {}
    result = {}
    for k, v in m.items():
        if not isinstance(v, dict):
            continue
        if "N" in v:
            try:
                result[k] = float(v["N"])
            except (ValueError, TypeError):
                continue
        elif "S" in v:
            result[k] = v["S"]
        elif "BOOL" in v:
            result[k] = v["BOOL"]
    return result


def _transform_lesson_from_ddb(item: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    return {
        "lesson_id": _ddb_str(item, "item_id"),
        "project_id": project_id,
        "title": _ddb_str(item, "title"),
        "observation": _ddb_str(item, "observation"),
        "insight": _ddb_str(item, "insight"),
        "evidence_chain": _ddb_str_set(item, "evidence_chain"),
        "provenance": _ddb_str(item, "provenance"),
        "confidence": _ddb_float(item, "confidence"),
        "pillar_scores": _ddb_map(item, "pillar_scores"),
        "resonance_score": _ddb_float(item, "resonance_score"),
        "pillar_composite": _ddb_float(item, "pillar_composite"),
        "extensions": _ddb_list_of_maps(item, "extensions"),
        "category": _ddb_str(item, "category") or None,
        "status": _normalize_status(_ddb_str(item, "status"), _STATUS_LESSON, "active"),
        "lesson_version": _ddb_int(item, "lesson_version", 1),
        "analysis_reference": _ddb_str(item, "analysis_reference") or None,
        "governance_proposal": _ddb_str(item, "governance_proposal") or None,
        "related_task_ids": _ddb_str_set(item, "related_task_ids"),
        "related_issue_ids": _ddb_str_set(item, "related_issue_ids"),
        "related_feature_ids": _ddb_str_set(item, "related_feature_ids"),
        "history": _ddb_history(item),
        "updated_at": _ddb_str(item, "updated_at") or None,
        "last_update_note": _ddb_str(item, "last_update_note") or None,
        "created_at": _ddb_str(item, "created_at") or None,
    }


_TRANSFORM = {
    "task": _transform_task_from_ddb,
    "issue": _transform_issue_from_ddb,
    "feature": _transform_feature_from_ddb,
    "lesson": _transform_lesson_from_ddb,
    "plan": _transform_plan_from_ddb,
}


# ENC-TSK-M36: bound how many active projects are fanned out to concurrently.
# A plain constant rather than "len(projects)" unbounded, so an unexpectedly
# large projects table can't spawn hundreds of simultaneous DynamoDB queries
# from a single Lambda invocation.
#
# Verified live against gamma post-deploy: with max_workers=8 the measured
# /api/v1/feed/tasks.json Lambda execution `Duration` (CloudWatch REPORT
# lines, not network/API-Gateway overhead) stayed ~19-24s -- essentially
# unchanged from the pre-fix serial baseline. Each per-project Query is
# I/O-bound (network + DynamoDB service time, no CPU work), so raising the
# thread count costs nothing but connection-pool headroom; 8 was too narrow
# relative to the number of active projects sharing project-type-index for
# concurrency to move the wall-clock number. Raised to 24 -- still cheap for
# a 256 MB Lambda making read-only Query calls.
_MAX_PROJECT_FANOUT_WORKERS = 24


def _query_project_tracker_records(
    pid: str, cutoff: dt.datetime
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Query every tracker record for ONE project via project-type-index.

    Factored out of what were two near-identical copies of this loop
    (_query_all_records / _query_corpus_tracker_records, ENC-TSK-L23) so the
    per-project fetch happens in exactly one place. Called concurrently, one
    call per active project (ENC-TSK-M36) -- previously each caller ran this
    same paginated query SEQUENTIALLY across every active project, which is
    the confirmed root cause of the ~20s feed/tasks.json and feed/corpus
    cold-cache latency (ENC-TSK-M36): N projects x paginated GSI query, one
    at a time, no concurrency.
    """
    ddb = _get_ddb()
    tasks: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    features: List[Dict[str, Any]] = []
    lessons: List[Dict[str, Any]] = []
    plans: List[Dict[str, Any]] = []

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
                # Per-record isolation: a single malformed record must not
                # take down the entire feed response (ENC-TSK-C31).
                try:
                    if _is_stale_closed(raw_item, cutoff):
                        continue
                    transformed = _TRANSFORM[record_type](raw_item, pid)
                except Exception as rec_exc:  # noqa: BLE001
                    logger.error(
                        "feed_query: skipping record_type=%s item_id=%s project=%s: %s",
                        record_type,
                        _ddb_str(raw_item, "item_id") or "?",
                        pid,
                        rec_exc,
                    )
                    continue
                if record_type == "task":
                    tasks.append(transformed)
                elif record_type == "issue":
                    issues.append(transformed)
                elif record_type == "feature":
                    features.append(transformed)
                elif record_type == "lesson":
                    lessons.append(transformed)
                elif record_type == "plan":
                    plans.append(transformed)
    except (BotoCoreError, ClientError) as exc:
        logger.error("DynamoDB query failed for project %s: %s", pid, exc)

    return tasks, issues, features, lessons, plans


def _fan_out_by_project(
    projects: List[Dict[str, str]], cutoff: dt.datetime
) -> List[Tuple[str, Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]]]:
    """Run `_query_project_tracker_records` for every project concurrently.

    Returns `[(project_id, (tasks, issues, features, lessons, plans)), ...]`
    in the SAME project order as the input list (order is restored after the
    executor map so both callers stay deterministic) -- a raised per-project
    exception is already caught and logged inside `_query_project_tracker_records`
    itself, so this never needs to handle executor-side failures specially.
    """
    if not projects:
        return []
    max_workers = min(_MAX_PROJECT_FANOUT_WORKERS, len(projects))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(
            pool.map(lambda proj: _query_project_tracker_records(proj["project_id"], cutoff), projects)
        )
    return [(proj["project_id"], result) for proj, result in zip(projects, results)]


_FEED_RECORD_TYPE_CAPS = {
    "task": MAX_TASKS_FULL_REFRESH,
    "issue": MAX_ISSUES_FULL_REFRESH,
    "feature": MAX_FEATURES_FULL_REFRESH,
    "lesson": MAX_LESSONS_FULL_REFRESH,
    "plan": MAX_PLANS_FULL_REFRESH,
}

_graph_query_lambda_client = None

# Set right before _query_all_records() returns; read immediately afterward by
# the two callers (ENC-TSK-M39, live AC verification). Safe as module state --
# a single Lambda execution environment processes one invocation at a time.
_last_feed_query_source = "ddb_fanout"


def _get_graph_query_lambda_client():
    global _graph_query_lambda_client
    if _graph_query_lambda_client is None:
        _graph_query_lambda_client = boto3.client(
            "lambda",
            region_name=DYNAMODB_REGION,
            # ENC-TSK-M39: bound the circuit-breaker's worst case. Without an
            # explicit read_timeout this would inherit botocore's 60s default,
            # which would make an OpenSearch-tier hang far slower than just
            # falling straight back to the DDB fan-out this replaces.
            config=Config(connect_timeout=2, read_timeout=OPENSEARCH_TIER_INVOKE_TIMEOUT_S, retries={"max_attempts": 1}),
        )
    return _graph_query_lambda_client


def _query_all_records_via_opensearch(
    projects: List[Dict[str, str]], cutoff: dt.datetime
) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """OpenSearch-tier fast path for the full feed refresh (ENC-TSK-M39).

    feed_query is not VPC-attached and the OpenSearch domain is only reachable
    from inside the VPC graph_query_api already runs in -- rather than adding a
    new VPC attachment to this Lambda, this invokes graph_query_api (action=
    "feed_selection") as a selection-tier proxy: it asks the records_read
    OpenSearch alias (CDC-fresh, ENC-TSK-L41-L44) for the top-N most-recently-
    updated record keys per (project, record_type), then hydrates full record
    bodies with a bounded DynamoDB BatchGetItem via the same helper the
    incremental/delta path already uses -- replacing N sequential/concurrent
    paginated GSI Query calls (one per project, unbounded result size) with a
    single OpenSearch selection round-trip plus a handful of BatchGetItem
    calls bounded by the existing per-type caps.

    Returns None on ANY failure (invoke error, timeout, malformed response, or
    an explicit ok=False) so the caller falls back to the DDB fan-out -- this
    IS the circuit breaker; there is no retry or trip-state, matching the only
    other fallback pattern in this codebase (graph_query_api's OpenSearch ->
    Neo4j keyword-rank fallback).
    """
    if not GRAPH_QUERY_API_FUNCTION:
        return None

    project_ids = [p["project_id"] for p in projects if p.get("project_id")]
    if not project_ids:
        return [], [], [], [], []

    payload = {
        "action": "feed_selection",
        "project_ids": project_ids,
        "caps": _FEED_RECORD_TYPE_CAPS,
    }
    try:
        response = _get_graph_query_lambda_client().invoke(
            FunctionName=GRAPH_QUERY_API_FUNCTION,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        result = json.loads(response["Payload"].read())
    except (BotoCoreError, ClientError, ValueError, KeyError) as exc:
        logger.warning(
            "feed_query: OpenSearch-tier selection invoke failed, falling back to DDB fan-out: %s", exc
        )
        return None

    if response.get("FunctionError") or not isinstance(result, dict) or not result.get("ok"):
        logger.warning(
            "feed_query: OpenSearch-tier selection returned an error, falling back to DDB fan-out: %s", result
        )
        return None

    selection = result.get("selection") or {}
    changed_keys: List[Dict[str, Dict[str, str]]] = []
    for pid in project_ids:
        for rtype in _FEED_RECORD_TYPE_CAPS:
            for bare_id in selection.get(f"{pid}#{rtype}", []) or []:
                changed_keys.append({
                    "project_id": {"S": pid},
                    "record_id": {"S": f"{rtype}#{bare_id}"},
                })

    if not changed_keys:
        return [], [], [], [], []

    tasks, issues, features, lessons, plans, _closed_ids = _hydrate_records_via_batch_get(changed_keys, cutoff)
    return tasks, issues, features, lessons, plans


def _query_all_records() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    global _last_feed_query_source
    projects = _get_active_projects()
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)

    try:
        opensearch_result = _query_all_records_via_opensearch(projects, cutoff)
    except Exception as exc:  # noqa: BLE001 — never let the fast path take the feed down
        logger.warning("feed_query: OpenSearch-tier path raised unexpectedly, falling back to DDB fan-out: %s", exc)
        opensearch_result = None

    if opensearch_result is not None:
        _last_feed_query_source = "opensearch"
        return opensearch_result

    _last_feed_query_source = "ddb_fanout"
    return _query_all_records_via_ddb(projects, cutoff)


def _query_all_records_via_ddb(
    projects: List[Dict[str, str]], cutoff: dt.datetime
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    all_tasks: List[Dict[str, Any]] = []
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []
    all_lessons: List[Dict[str, Any]] = []
    all_plans: List[Dict[str, Any]] = []

    # ENC-TSK-M36 (feed data-truth): the per-type caps below used to apply
    # to the GLOBAL cross-project pool (all projects' lessons merged, THEN
    # capped to 10 total). tasks.json/project-type-index is shared by every
    # governed project in this table (enceladus, plus several others) -- a
    # global cap meant any project's issue/feature/lesson/plan representation
    # in the cold-start snapshot could be crowded out entirely by a more
    # recently active sibling project, even though that project's own data
    # was never actually missing from DynamoDB (confirmed via /feed/corpus,
    # which has no caps and returns the full per-project set). Capping PER
    # PROJECT before merging guarantees every active project keeps its own
    # fair slice of the snapshot regardless of what other tenants are doing.
    for _pid, (tasks, issues, features, lessons, plans) in _fan_out_by_project(projects, cutoff):
        all_tasks.extend(_cap_by_updated_at(tasks, MAX_TASKS_FULL_REFRESH))
        all_issues.extend(_cap_by_updated_at(issues, MAX_ISSUES_FULL_REFRESH))
        all_features.extend(_cap_by_updated_at(features, MAX_FEATURES_FULL_REFRESH))
        all_lessons.extend(_cap_by_updated_at(lessons, MAX_LESSONS_FULL_REFRESH))
        all_plans.extend(_cap_by_updated_at(plans, MAX_PLANS_FULL_REFRESH))

    all_tasks.sort(key=lambda x: x.get("task_id", ""))
    all_issues.sort(key=lambda x: x.get("issue_id", ""))
    all_features.sort(key=lambda x: x.get("feature_id", ""))
    all_lessons.sort(key=lambda x: x.get("lesson_id", ""))
    all_plans.sort(key=lambda x: x.get("plan_id", ""))

    return all_tasks, all_issues, all_features, all_lessons, all_plans


def _query_corpus_tracker_records() -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    """Load the full tracker corpus without per-type refresh caps (ENC-TSK-L23).

    ENC-TSK-M36: shares `_query_project_tracker_records` / `_fan_out_by_project`
    with `_query_all_records` -- this used to be its own near-identical copy of
    the per-project query loop, run sequentially. Same concurrency fix applies
    here since this is the function `seedCacheFromCorpus` (warm IndexedDB
    cache) and the Home dashboard's count tiles ultimately depend on.
    """
    projects = _get_active_projects()
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)

    all_tasks: List[Dict[str, Any]] = []
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []
    all_lessons: List[Dict[str, Any]] = []
    all_plans: List[Dict[str, Any]] = []

    for _pid, (tasks, issues, features, lessons, plans) in _fan_out_by_project(projects, cutoff):
        all_tasks.extend(tasks)
        all_issues.extend(issues)
        all_features.extend(features)
        all_lessons.extend(lessons)
        all_plans.extend(plans)

    return all_tasks, all_issues, all_features, all_lessons, all_plans


def _deserialize_document_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "document_id": _ddb_str(item, "document_id"),
        "project_id": _ddb_str(item, "project_id"),
        "title": _ddb_str(item, "title"),
        "status": _ddb_str(item, "status") or "active",
        "updated_at": _ddb_str(item, "updated_at") or None,
        "created_at": _ddb_str(item, "created_at") or None,
        "document_subtype": _ddb_str(item, "document_subtype") or "general",
        "subtypepattern": _ddb_str(item, "subtypepattern") or "",
        "keywords": _ddb_str_set(item, "keywords"),
    }


def _scan_documents_for_corpus() -> List[Dict[str, Any]]:
    ddb = _get_ddb()
    items: List[Dict[str, Any]] = []
    scan_params: Dict[str, Any] = {"TableName": DOCUMENTS_TABLE}
    try:
        while True:
            resp = ddb.scan(**scan_params)
            for raw_item in resp.get("Items", []):
                try:
                    items.append(_deserialize_document_item(raw_item))
                except Exception as exc:  # noqa: BLE001
                    logger.error("feed_query corpus: skipping document item: %s", exc)
            last_key = resp.get("LastEvaluatedKey")
            if not isinstance(last_key, dict) or not last_key:
                break
            scan_params["ExclusiveStartKey"] = last_key
    except (BotoCoreError, ClientError) as exc:
        logger.error("Corpus documents scan failed: %s", exc)
    return items


def _get_corpus_entries() -> List[Dict[str, Any]]:
    global _corpus_cache_entries, _corpus_cache_at
    now = time.time()
    if _corpus_cache_entries is not None and now - _corpus_cache_at < _CORPUS_CACHE_TTL:
        return _corpus_cache_entries

    tasks, issues, features, lessons, plans = _query_corpus_tracker_records()
    tracker_entries = feed_corpus.build_tracker_entries_from_records(
        tasks, issues, features, lessons, plans
    )
    document_entries = [
        entry
        for entry in (
            feed_corpus.build_document_entry(doc) for doc in _scan_documents_for_corpus()
        )
        if entry
    ]
    _corpus_cache_entries = tracker_entries + document_entries
    _corpus_cache_at = now
    return _corpus_cache_entries


# ---------------------------------------------------------------------------
# Typed relationship edges (ENC-ISS-137 / ENC-FTR-049 / ENC-TSK-A57)
# ---------------------------------------------------------------------------

def _query_typed_relationships(project_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Query typed relationship edges for given projects.

    Returns a dict mapping source_record_id -> list of edge dicts.
    Each edge: {relationship_type, target_id, weight, confidence, reason, created_at}
    """
    ddb = _get_ddb()
    edges_by_source: Dict[str, List[Dict[str, Any]]] = {}

    for pid in project_ids:
        try:
            paginator = ddb.get_paginator("query")
            for page in paginator.paginate(
                TableName=DYNAMODB_TABLE,
                KeyConditionExpression="project_id = :pid AND begins_with(SK, :rel_prefix)",
                ExpressionAttributeValues={
                    ":pid": {"S": pid},
                    ":rel_prefix": {"S": "rel#"},
                },
            ):
                for raw_item in page.get("Items", []):
                    sk = _ddb_str(raw_item, "SK")
                    if not sk or not sk.startswith("rel#"):
                        continue
                    # SK format: rel#{source_id}#{relationship_type}#{target_id}
                    parts = sk.split("#", 4)
                    if len(parts) < 4:
                        continue
                    _, source_id, rel_type, target_id = parts[0], parts[1], parts[2], parts[3]

                    status = _ddb_str(raw_item, "status")
                    if status == "archived":
                        continue

                    edge = {
                        "relationship_type": rel_type,
                        "target_id": target_id,
                        "weight": _ddb_float(raw_item, "weight"),
                        "confidence": _ddb_float(raw_item, "confidence"),
                        "reason": _ddb_str(raw_item, "reason") or None,
                        "created_at": _ddb_str(raw_item, "created_at") or None,
                    }
                    edges_by_source.setdefault(source_id, []).append(edge)
        except (BotoCoreError, ClientError) as exc:
            logger.error("Relationship query failed for project %s: %s", pid, exc)
            continue

    return edges_by_source


def _attach_typed_relationships(
    records: List[Dict[str, Any]],
    id_key: str,
    edges_by_source: Dict[str, List[Dict[str, Any]]],
) -> None:
    """Attach typed_relationships array to each record that has edges."""
    for record in records:
        record_id = record.get(id_key, "")
        edges = edges_by_source.get(record_id, [])
        if edges:
            record["typed_relationships"] = edges


# ENC-TSK-M48: batches fan out concurrently (see _hydrate_records_via_batch_get)
# with the same reasoning/sizing as _MAX_PROJECT_FANOUT_WORKERS (ENC-TSK-M36) --
# each BatchGetItem call is I/O-bound, and the shared DDB client's
# max_pool_connections=32 (also M36) already has headroom for this.
_MAX_BATCH_GET_WORKERS = 24


def _fetch_and_transform_batch(
    batch: List[Dict[str, Dict[str, str]]], cutoff: dt.datetime
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[str],
]:
    """BatchGetItem + ``_TRANSFORM`` for a single <=100-key chunk."""
    ddb = _get_ddb()
    tasks: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    features: List[Dict[str, Any]] = []
    lessons: List[Dict[str, Any]] = []
    plans: List[Dict[str, Any]] = []
    closed_ids: List[str] = []

    try:
        resp = ddb.batch_get_item(
            RequestItems={DYNAMODB_TABLE: {"Keys": batch, "ConsistentRead": False}}
        )
        items_to_process = resp.get("Responses", {}).get(DYNAMODB_TABLE, [])

        # One retry for unprocessed keys (DynamoDB throughput back-off).
        unprocessed = (
            resp.get("UnprocessedKeys", {}).get(DYNAMODB_TABLE, {}).get("Keys", [])
        )
        if unprocessed:
            resp2 = ddb.batch_get_item(
                RequestItems={DYNAMODB_TABLE: {"Keys": unprocessed, "ConsistentRead": False}}
            )
            items_to_process.extend(resp2.get("Responses", {}).get(DYNAMODB_TABLE, []))

        for raw_item in items_to_process:
            record_type = _ddb_str(raw_item, "record_type")
            pid = _ddb_str(raw_item, "project_id")
            if record_type not in _TRANSFORM:
                continue

            item_id = _ddb_str(raw_item, "item_id")
            # Per-record isolation: a single malformed record must not
            # take down the entire delta response (ENC-TSK-C31).
            try:
                if _is_stale_closed(raw_item, cutoff):
                    if item_id:
                        closed_ids.append(item_id)
                    continue
                transformed = _TRANSFORM[record_type](raw_item, pid)
            except Exception as rec_exc:  # noqa: BLE001
                logger.error(
                    "feed_query hydrate: skipping record_type=%s item_id=%s project=%s: %s",
                    record_type,
                    item_id or "?",
                    pid,
                    rec_exc,
                )
                continue
            if record_type == "task":
                tasks.append(transformed)
            elif record_type == "issue":
                issues.append(transformed)
            elif record_type == "feature":
                features.append(transformed)
            elif record_type == "lesson":
                lessons.append(transformed)
            elif record_type == "plan":
                plans.append(transformed)

    except (BotoCoreError, ClientError) as exc:
        logger.error("BatchGetItem failed: %s", exc)

    return tasks, issues, features, lessons, plans, closed_ids


def _hydrate_records_via_batch_get(
    changed_keys: List[Dict[str, Dict[str, str]]], cutoff: dt.datetime
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[str],
]:
    """BatchGetItem + ``_TRANSFORM`` hydration for a list of (project_id, record_id) keys.

    Factored out of ``_query_incremental`` (ENC-TSK-M39) so the OpenSearch-tier
    selection path can reuse the exact same bounded-fetch/transform/sort logic
    instead of re-deriving it -- the two callers differ only in how they arrive
    at ``changed_keys`` (a GSI query here, an OpenSearch msearch selection for
    the full-refresh path). Returns (tasks, issues, features, lessons, plans,
    closed_ids), sorted the same way both callers already expect.

    ENC-TSK-M48: chunks fan out concurrently instead of one BatchGetItem call
    at a time -- fine for the incremental path's small per-poll delta, but the
    OpenSearch-tier full-refresh path can hand this thousands of keys across
    20+ active projects, and sequential chunking was the actual live-latency
    bottleneck (graph_query_api's own selection round trip is already fast).
    """
    if not changed_keys:
        return [], [], [], [], [], []

    batches = [changed_keys[i : i + 100] for i in range(0, len(changed_keys), 100)]
    max_workers = min(_MAX_BATCH_GET_WORKERS, len(batches))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        batch_results = list(
            pool.map(lambda batch: _fetch_and_transform_batch(batch, cutoff), batches)
        )

    all_tasks: List[Dict[str, Any]] = []
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []
    all_lessons: List[Dict[str, Any]] = []
    all_plans: List[Dict[str, Any]] = []
    closed_ids: List[str] = []
    for tasks, issues, features, lessons, plans, batch_closed_ids in batch_results:
        all_tasks.extend(tasks)
        all_issues.extend(issues)
        all_features.extend(features)
        all_lessons.extend(lessons)
        all_plans.extend(plans)
        closed_ids.extend(batch_closed_ids)

    all_tasks.sort(key=lambda x: x.get("task_id", ""))
    all_issues.sort(key=lambda x: x.get("issue_id", ""))
    all_features.sort(key=lambda x: x.get("feature_id", ""))
    all_lessons.sort(key=lambda x: x.get("lesson_id", ""))
    all_plans.sort(key=lambda x: x.get("plan_id", ""))

    return all_tasks, all_issues, all_features, all_lessons, all_plans, closed_ids


def _query_incremental(
    since_iso: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Query records updated since *since_iso* using the type-updated-index GSI.

    Strategy (ENC-TSK-605):
      1. For each record_type (task, issue, feature), query the GSI with
         ``updated_at > :since`` to collect (project_id, record_id) keys.
      2. BatchGetItem on the main table for full attributes.
      3. Transform via ``_TRANSFORM`` — records filtered by ``_is_stale_closed``
         are captured in *closed_ids* so the client can evict them.

    Returns (tasks, issues, features, closed_ids).
    """
    ddb = _get_ddb()
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)

    # Step 1: Collect keys of recently changed records from the GSI.
    # Table keys (project_id, record_id) are always projected into any GSI.
    changed_keys: List[Dict[str, Dict[str, str]]] = []

    for rtype in ("task", "issue", "feature", "lesson", "plan"):
        try:
            paginator = ddb.get_paginator("query")
            for page in paginator.paginate(
                TableName=DYNAMODB_TABLE,
                IndexName="type-updated-index",
                KeyConditionExpression="record_type = :rt AND updated_at > :since",
                ExpressionAttributeValues={
                    ":rt": {"S": rtype},
                    ":since": {"S": since_iso},
                },
                ProjectionExpression="project_id, record_id, record_type",
            ):
                for item in page.get("Items", []):
                    pid = _ddb_str(item, "project_id")
                    rid = _ddb_str(item, "record_id")
                    if pid and rid:
                        changed_keys.append({
                            "project_id": {"S": pid},
                            "record_id": {"S": rid},
                        })
        except (BotoCoreError, ClientError) as exc:
            logger.error("Incremental GSI query failed for %s: %s", rtype, exc)

    if not changed_keys:
        return [], [], [], [], [], []

    # Step 2: BatchGetItem + transform (shared with the OpenSearch-tier path).
    return _hydrate_records_via_batch_get(changed_keys, cutoff)


# ---------------------------------------------------------------------------
# Feed refresh (ENC-TSK-797)
# ---------------------------------------------------------------------------

_lambda_client = None


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=DYNAMODB_REGION)
    return _lambda_client


def _handle_feed_refresh() -> Dict[str, Any]:
    """Invoke feed_publisher synchronously to regenerate all S3 feeds."""
    try:
        response = _get_lambda_client().invoke(
            FunctionName=FEED_PUBLISHER_FUNCTION,
            InvocationType="RequestResponse",
            Payload=json.dumps({"Records": [], "source": "pwa_refresh"}).encode("utf-8"),
        )
        status_code = response.get("StatusCode", 500)
        payload_raw = response["Payload"].read()
        try:
            payload = json.loads(payload_raw)
        except (json.JSONDecodeError, TypeError):
            payload = {"raw": payload_raw.decode("utf-8", errors="replace")}

        if status_code == 200 and not response.get("FunctionError"):
            return _response(200, {
                "success": True,
                "message": "Feed regeneration complete",
                "generated_at": payload.get("generated_at"),
            })
        else:
            logger.error("feed_publisher invoke error: status=%d payload=%s", status_code, payload)
            return _error(502, "Feed regeneration failed")
    except (BotoCoreError, ClientError) as exc:
        logger.error("feed_publisher invoke exception: %s", exc)
        return _error(502, f"Feed regeneration failed: {exc}")


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def _handle_snapshot() -> Dict[str, Any]:
    """
    ENC-TSK-K98 — authenticated cold-start snapshot (GET /api/v1/feed/tasks.json).

    Replaces the previously PUBLIC S3 object at /mobile/v1/tasks.json. The whole
    handler is JWT-gated (see lambda_handler: token is extracted + verified
    before any dispatch), so an unauthenticated request 401s here instead of
    reading a public file. Returns only the minimal fields the ui-v2 cockpit
    needs to seed its feed before the realtime WSS connects
    ({item_id, title, status, record_type, updated_at}) across all record types.
    The minimal projection also shrinks the payload from ~7.7MB of full records
    to a few KB and stops leaking descriptions / session / worklog data.
    """
    try:
        tasks, issues, features, lessons, plans = _query_all_records()
    except Exception as exc:  # noqa: BLE001 — surface a structured 500, not opaque
        logger.error("snapshot query failed: %s", exc)
        return _error(500, "Failed to query snapshot. Please try again.")

    def _rows(records: List[Dict[str, Any]], id_key: str, record_type: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in records:
            rid = r.get(id_key) or r.get("item_id")
            if not rid:
                continue
            out.append(
                {
                    "item_id": rid,
                    "title": r.get("title") or rid,
                    "status": r.get("status") or "open",
                    "record_type": record_type,
                    "updated_at": r.get("updated_at") or None,
                }
            )
        return out

    rows = (
        _rows(tasks, "task_id", "task")
        + _rows(issues, "issue_id", "issue")
        + _rows(features, "feature_id", "feature")
        + _rows(lessons, "lesson_id", "lesson")
        + _rows(plans, "plan_id", "plan")
    )

    body = {"generated_at": _now_z(), "tasks": rows, "feed_source": _last_feed_query_source}
    return {
        "statusCode": 200,
        "headers": {
            **_cors_headers(),
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
        "body": json.dumps(body),
    }


def _delta_corpus_entry(raw_item: Dict[str, Any], project_id: str) -> Optional[Dict[str, Any]]:
    record_type = _ddb_str(raw_item, "record_type")
    if record_type not in _TRANSFORM:
        return None
    transformed = _TRANSFORM[record_type](raw_item, project_id)
    item_id = _ddb_str(raw_item, "item_id") or transformed.get(f"{record_type}_id", "")
    attrs: Dict[str, Any] = {}
    for key in ("status", "priority", "category", "severity"):
        value = transformed.get(key)
        if value:
            attrs[key] = value
    return feed_corpus.build_tracker_entry(
        record_type,
        str(item_id),
        project_id,
        str(transformed.get("title") or item_id),
        transformed.get("updated_at"),
        attrs,
    )


def _handle_delta(qs: Dict[str, Any]) -> Dict[str, Any]:
    """GET /api/v1/feed/delta?since=<version_seq> — version-ordered incremental sync (ENC-TSK-L27)."""
    since = feed_delta.parse_since_version((qs or {}).get("since"))
    if since is None:
        return _error(400, "'since' must be a non-negative integer version_seq")

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)
    try:
        items, tombstones, latest = feed_delta.query_version_delta(
            _get_ddb(),
            DYNAMODB_TABLE,
            since,
            is_stale_closed=_is_stale_closed,
            transform_record=_delta_corpus_entry,
            cutoff=cutoff,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("feed delta query failed: %s", exc)
        return _error(500, "Failed to query feed delta. Please try again.")

    body = {
        "success": True,
        "generated_at": _now_z(),
        "since": since,
        "latest_version_seq": latest,
        "items": items,
        "tombstones": tombstones,
    }
    return {
        "statusCode": 200,
        "headers": {
            **_cors_headers(),
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
        "body": json.dumps(body),
    }


def _handle_corpus(qs: Dict[str, Any]) -> Dict[str, Any]:
    """GET /api/v1/feed/corpus — cursor-paginated multi-table feed corpus (ENC-TSK-L23)."""
    query = feed_corpus.parse_corpus_query(qs or {})
    if query["sort"] not in feed_corpus.VALID_SORTS:
        return _error(400, f"Invalid sort '{query['sort']}'")

    if query["cursor"] and feed_corpus.decode_cursor(query["cursor"]) is None:
        return _error(400, "Invalid cursor")

    try:
        entries = _get_corpus_entries()
        page = feed_corpus.paginate_corpus(entries, query)
    except Exception as exc:  # noqa: BLE001
        logger.error("feed corpus query failed: %s", exc)
        return _error(500, "Failed to query feed corpus. Please try again.")

    body = {
        "success": True,
        "generated_at": _now_z(),
        "version": "1.0",
        **page,
    }
    return {
        "statusCode": 200,
        "headers": {
            **_cors_headers(),
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
        "body": json.dumps(body),
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    ).upper()
    path = event.get("rawPath") or event.get("path") or ""

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    token = _extract_token(event)
    headers = event.get("headers") or {}
    internal_key = headers.get("x-coordination-internal-key") or headers.get("X-Coordination-Internal-Key")
    internal_ok = False
    if internal_key:
        expected = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
        previous = os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
        valid = {k for k in (expected, previous) if k}
        internal_ok = internal_key in valid

    if not token and not internal_ok:
        return _error(401, "Authentication required. Please sign in.")

    claims: Dict[str, Any] = {"internal_service": True} if internal_ok and not token else {}
    if token:
        try:
            claims = _verify_token(token)
        except ValueError as exc:
            return _error(401, str(exc))

    if method == "POST" and re.search(r"/api/v1/feed/refresh/?$", path):
        return _handle_feed_refresh()

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

    # ENC-TSK-K98 — authenticated cold-start snapshot; replaces the public
    # /mobile/v1/tasks.json S3 object. JWT already enforced above.
    if method == "GET" and re.search(r"/api/v1/feed/tasks\.json/?$", path):
        return _handle_snapshot()

    if method == "GET" and re.search(r"/api/v1/feed/corpus/?$", path):
        return _handle_corpus(event.get("queryStringParameters") or {})

    if method == "GET" and re.search(r"/api/v1/feed/delta/?$", path):
        return _handle_delta(event.get("queryStringParameters") or {})

    if method != "GET" or not re.search(r"/api/v1/feed/?$", path):
        return _error(404, f"Unsupported route: {method} {path}")

    qs = event.get("queryStringParameters") or {}

    # --- Incremental delta query (ENC-TSK-607) ---
    since_param = str(qs.get("since") or "").strip()
    if since_param:
        parsed_since = _parse_iso8601(since_param)
        if parsed_since is None:
            return _error(400, "'since' must be ISO-8601 UTC (e.g. 2026-02-25T12:00:00Z)")
        # Add a small overlap window to avoid permanently missing updates when
        # GSI propagation lags behind the client watermark by a few seconds.
        incremental_since = _to_iso8601_z(
            parsed_since - dt.timedelta(seconds=INCREMENTAL_LOOKBACK_SECONDS)
        )
        try:
            tasks, issues, features, lessons, plans, closed_ids = _query_incremental(incremental_since)
        except Exception as exc:
            logger.error("incremental feed query failed: %s", exc)
            return _error(500, "Failed to query feed delta. Please try again.")

        body = {
            "generated_at": _now_z(),
            "version": "1.0",
            "tasks": tasks,
            "issues": issues,
            "features": features,
            "lessons": lessons,
            "plans": plans,
            "closed_ids": closed_ids,
        }
        return {
            "statusCode": 200,
            "headers": {
                **_cors_headers(),
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate",
            },
            "body": json.dumps(body),
        }

    # --- Full query (existing behaviour, unchanged) ---
    # ENC-TSK-C32 follow-up: wrap the ENTIRE full-refresh tail in a broad
    # try/except so ANY unexpected exception (JSON serialization of Decimal,
    # datetime, or other non-serializable values; post-query attachment
    # crashes; anything else) returns a structured _error envelope with the
    # exception class + message instead of escaping the handler and letting
    # Lambda runtime return the opaque {"message":"Internal Server Error"}
    # that made the live 500 impossible to diagnose from the client side.
    try:
        try:
            tasks, issues, features, lessons, plans = _query_all_records()
        except Exception as exc:
            logger.error("feed query failed: %s", exc)
            return _error(500, "Failed to query feed data. Please try again.")

        # --- Attach typed relationship edges + context node scores (ENC-TSK-A57/K26) ---
        try:
            project_ids = list({r.get("project_id", "") for r in tasks + issues + features + lessons + plans if r.get("project_id")})
            if project_ids:
                from record_extensions import (
                    attach_record_extensions,
                    query_typed_relationships_for_projects,
                )

                edges_by_source = query_typed_relationships_for_projects(
                    _get_ddb(),
                    DYNAMODB_TABLE,
                    project_ids,
                    ddb_str=_ddb_str,
                    ddb_float=_ddb_float,
                )
                attach_record_extensions(tasks, "task_id", "task", edges_by_source)
                attach_record_extensions(issues, "issue_id", "issue", edges_by_source)
                attach_record_extensions(features, "feature_id", "feature", edges_by_source)
                attach_record_extensions(lessons, "lesson_id", "lesson", edges_by_source)
                attach_record_extensions(plans, "plan_id", "plan", edges_by_source)
        except Exception as exc:
            logger.warning("Failed to attach record extensions: %s", exc)

        subscription_meta = {
            "subscription_id": None,
            "scope_applied": False,
            "items_matched": len(tasks) + len(issues) + len(features) + len(lessons) + len(plans),
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

            (
                tasks,
                issues,
                features,
                lessons,
                plans,
                matched,
            ) = _apply_subscription_scope(tasks, issues, features, lessons, plans, sub)
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
                "lessons": lessons,
                "plans": plans,
                "subscription": subscription_meta,
                "feed_source": _last_feed_query_source,
            },
        )
    except Exception as outer_exc:  # noqa: BLE001
        # Final safety net for the full-refresh path (ENC-TSK-C32 follow-up).
        # Catches json.dumps serialization failures (e.g. boto3 Decimal,
        # datetime), post-query attachment errors, and anything else that
        # would otherwise escape the handler and surface as the opaque
        # {"message":"Internal Server Error"} from Lambda runtime. Returns a
        # structured _error envelope with the exception class and message so
        # the PWA (and any diagnosing curl) gets actionable information.
        logger.exception("feed full refresh failed in outer safety net")
        return _error(
            500,
            f"Full refresh failed: {type(outer_exc).__name__}: {outer_exc}",
        )
