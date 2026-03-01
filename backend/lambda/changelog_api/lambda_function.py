"""changelog_api/lambda_function.py

Lambda API handler for the Enceladus Changelog service.
Serves cross-project changelog history (deploy# audit records) and per-project
current version data from S3, supporting the ENC-FTR-033 changelog feature.

Routes (via API Gateway proxy):
    GET /api/v1/changelog/history/{projectId}  — Single-project changelog history
    GET /api/v1/changelog/history              — Multi-project changelog (projects= param)
    GET /api/v1/changelog/version/{projectId}  — Current version for a project
    GET /api/v1/changelog/versions             — Multi-project version summary (projects= param)
    OPTIONS /api/v1/changelog/*                — CORS preflight

Auth:
    Reads the `enceladus_id_token` cookie from the Cookie header (Cognito JWT).
    Optional service-to-service auth via X-Coordination-Internal-Key when
    COORDINATION_INTERNAL_API_KEY is set.

Environment variables:
    COGNITO_USER_POOL_ID   us-east-1_b2D0V3E1k
    COGNITO_CLIENT_ID      6q607dk3liirhtecgps7hifmlk
    DEPLOY_TABLE           default: devops-deployment-manager
    DEPLOY_REGION          default: us-west-2
    CONFIG_BUCKET          default: jreese-net
    CONFIG_PREFIX          default: deploy-config
    PROJECTS_TABLE         default: projects

Related: ENC-FTR-033
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
from urllib.parse import unquote


import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.types import TypeDeserializer

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

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")
DEPLOY_REGION = os.environ.get("DEPLOY_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk")
COORDINATION_INTERNAL_API_KEY = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    or os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEY", "")
    or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "")
)
COORDINATION_INTERNAL_API_KEY_PREVIOUS = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
    or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
)
COORDINATION_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS", ""),
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    COORDINATION_INTERNAL_API_KEY,
    COORDINATION_INTERNAL_API_KEY_PREVIOUS,
)
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "jreese-net")
CONFIG_PREFIX = os.environ.get("CONFIG_PREFIX", "deploy-config")
CORS_ORIGIN = "https://jreese.net"

MAX_HISTORY_LIMIT = 100
DEFAULT_HISTORY_LIMIT = 20
MAX_PROJECTS_PER_REQUEST = 20

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_deser = TypeDeserializer()

# ---------------------------------------------------------------------------
# Module-level client caches
# ---------------------------------------------------------------------------

_ddb = None
_s3 = None

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb", region_name=DEPLOY_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _get_s3():
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3", region_name=DEPLOY_REGION)
    return _s3


# ---------------------------------------------------------------------------
# CORS + Response helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=_json_default),
    }


def _ok(body: Any) -> Dict:
    if isinstance(body, dict) and "success" not in body:
        body["success"] = True
    return _response(200, body)


def _error(status_code: int, message: str, **extra: Any) -> Dict:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 403:
            code = "FORBIDDEN"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500))
    payload: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": dict(extra),
        },
    }
    return _response(status_code, payload)


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _ddb_deser(item: Dict) -> Dict:
    return {k: _deser.deserialize(v) for k, v in item.items()}


def _parse_limit(raw: Any, default: int, min_value: int = 1, max_value: int = 100) -> int:
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(max_value, val))


# ---------------------------------------------------------------------------
# Auth (Cognito JWT + internal key, same as deploy_intake)
# ---------------------------------------------------------------------------


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache

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
    header = jwt.get_unverified_header(token)
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
    cookie_parts = []
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(p.strip() for p in cookie_header.split(";") if p.strip())
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(p.strip() for p in event_cookies if isinstance(p, str) and p.strip())
    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict) -> Tuple[Optional[Dict[str, Any]], Optional[Dict]]:
    """Authenticate via internal key or Cognito cookie. Returns (claims, None) or (None, error)."""
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
        return None, _error(401, "Authentication required")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("Auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _query_project_history(project_id: str, limit: int, change_type_filter: Optional[str]) -> List[Dict]:
    """Query deploy# records for a single project from devops-deployment-manager."""
    ddb = _get_ddb()
    results = []
    kwargs: Dict[str, Any] = {
        "TableName": DEPLOY_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":prefix": {"S": "deploy#"},
        },
        "ScanIndexForward": False,
    }
    if change_type_filter:
        kwargs["FilterExpression"] = "change_type = :ct"
        kwargs["ExpressionAttributeValues"][":ct"] = {"S": change_type_filter}

    # Fetch up to 3x the limit to account for filter reduction, cap at reasonable page size
    fetch_target = min(limit * 3, 300)
    kwargs["Limit"] = fetch_target

    while True:
        resp = ddb.query(**kwargs)
        results.extend(_ddb_deser(item) for item in resp.get("Items", []))
        if len(results) >= limit or "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    results.sort(key=lambda r: r.get("deployed_at", ""), reverse=True)
    return results[:limit]


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------


def _read_current_version(project_id: str) -> Optional[Dict]:
    """Read deploy-config/{project_id}/current-version.json from S3."""
    s3 = _get_s3()
    key = f"{CONFIG_PREFIX}/{project_id}/current-version.json"
    try:
        resp = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)
        data = json.loads(resp["Body"].read())
        return {
            "project_id": project_id,
            "version": data.get("version", ""),
            "deployed_at": data.get("deployed_at", ""),
            "spec_id": data.get("spec_id", ""),
        }
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        logger.warning("S3 read failed for %s: %s", project_id, e)
        return None
    except Exception as e:
        logger.warning("Unexpected error reading version for %s: %s", project_id, e)
        return None


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _handle_history_single(project_id: str, qs: Dict) -> Dict:
    """GET /api/v1/changelog/history/{projectId}"""
    limit = _parse_limit(qs.get("limit"), default=DEFAULT_HISTORY_LIMIT, max_value=MAX_HISTORY_LIMIT)
    change_type = (qs.get("change_type") or "").strip().lower() or None
    if change_type and change_type not in {"major", "minor", "patch"}:
        return _error(400, f"Invalid change_type filter: {change_type!r}. Must be major, minor, or patch.")

    entries = _query_project_history(project_id, limit, change_type)
    return _ok({
        "project_id": project_id,
        "count": len(entries),
        "entries": entries,
    })


def _handle_history_multi(qs: Dict) -> Dict:
    """GET /api/v1/changelog/history?projects=a,b,c"""
    raw_projects = (qs.get("projects") or "").strip()
    if not raw_projects:
        return _error(400, "projects query parameter required for multi-project history. Provide a comma-separated list of project IDs.")

    project_ids = [p.strip() for p in raw_projects.split(",") if p.strip()]
    if len(project_ids) > MAX_PROJECTS_PER_REQUEST:
        return _error(400, f"Too many projects. Maximum {MAX_PROJECTS_PER_REQUEST} per request.")

    limit = _parse_limit(qs.get("limit"), default=DEFAULT_HISTORY_LIMIT, max_value=MAX_HISTORY_LIMIT)
    change_type = (qs.get("change_type") or "").strip().lower() or None
    if change_type and change_type not in {"major", "minor", "patch"}:
        return _error(400, f"Invalid change_type filter: {change_type!r}.")

    all_entries: List[Dict] = []
    with ThreadPoolExecutor(max_workers=min(len(project_ids), 5)) as pool:
        futures = {
            pool.submit(_query_project_history, pid, limit, change_type): pid
            for pid in project_ids
        }
        for future in as_completed(futures):
            try:
                all_entries.extend(future.result())
            except Exception as e:
                pid = futures[future]
                logger.warning("History query failed for project %s: %s", pid, e)

    all_entries.sort(key=lambda r: r.get("deployed_at", ""), reverse=True)
    return _ok({
        "projects": project_ids,
        "count": len(all_entries[:limit]),
        "entries": all_entries[:limit],
    })


def _handle_version_single(project_id: str) -> Dict:
    """GET /api/v1/changelog/version/{projectId}"""
    version_data = _read_current_version(project_id)
    if version_data is None:
        return _error(404, f"No version data found for project '{project_id}'. Has it been deployed?")
    return _ok(version_data)


def _handle_versions_multi(qs: Dict) -> Dict:
    """GET /api/v1/changelog/versions?projects=a,b,c"""
    raw_projects = (qs.get("projects") or "").strip()
    if not raw_projects:
        return _error(400, "projects query parameter required. Provide a comma-separated list of project IDs.")

    project_ids = [p.strip() for p in raw_projects.split(",") if p.strip()]
    if len(project_ids) > MAX_PROJECTS_PER_REQUEST:
        return _error(400, f"Too many projects. Maximum {MAX_PROJECTS_PER_REQUEST} per request.")

    versions: List[Dict] = []
    with ThreadPoolExecutor(max_workers=min(len(project_ids), 5)) as pool:
        futures = {pool.submit(_read_current_version, pid): pid for pid in project_ids}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                versions.append(result)

    versions.sort(key=lambda v: v.get("deployed_at", ""), reverse=True)
    return _ok({
        "projects": project_ids,
        "count": len(versions),
        "versions": versions,
    })


# ---------------------------------------------------------------------------
# Path routing
# ---------------------------------------------------------------------------

_HISTORY_SINGLE_PATTERN = re.compile(
    r"(?:/api/v1/changelog)?/history/(?P<projectId>[a-z0-9_-]+)$"
)
_HISTORY_MULTI_PATTERN = re.compile(
    r"(?:/api/v1/changelog)?/history$"
)
_VERSION_SINGLE_PATTERN = re.compile(
    r"(?:/api/v1/changelog)?/version/(?P<projectId>[a-z0-9_-]+)$"
)
_VERSIONS_MULTI_PATTERN = re.compile(
    r"(?:/api/v1/changelog)?/versions$"
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Main Lambda entry point."""
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    ).upper()
    path = event.get("rawPath") or event.get("path") or ""

    logger.info("changelog_api: %s %s", method, path)

    if method == "OPTIONS":
        return _response(204, "")

    if method != "GET":
        return _error(405, f"Method {method} not allowed. This API is read-only.")

    _claims, auth_error = _authenticate(event)
    if auth_error:
        return auth_error

    qs: Dict[str, str] = event.get("queryStringParameters") or {}

    try:
        # GET /history/{projectId}
        m = _HISTORY_SINGLE_PATTERN.search(path)
        if m:
            return _handle_history_single(m.group("projectId"), qs)

        # GET /history?projects=...
        if _HISTORY_MULTI_PATTERN.search(path):
            return _handle_history_multi(qs)

        # GET /version/{projectId}
        m = _VERSION_SINGLE_PATTERN.search(path)
        if m:
            return _handle_version_single(m.group("projectId"))

        # GET /versions?projects=...
        if _VERSIONS_MULTI_PATTERN.search(path):
            return _handle_versions_multi(qs)

        return _error(404, f"Route not found: {method} {path}")

    except (ClientError, BotoCoreError) as e:
        logger.error("AWS error: %s", e, exc_info=True)
        return _error(500, "Internal service error")
    except Exception as e:
        logger.error("Unexpected error: %s", e, exc_info=True)
        return _error(500, "Internal service error")
