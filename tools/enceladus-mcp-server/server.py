#!/usr/bin/env python3
"""Enceladus MCP Server — governed tool/resource endpoint for agent sessions.

Exposes allowlisted Enceladus system resources as MCP tools and resources
so provider sessions (Codex, Claude Agent SDK, AWS native) can read context
and write approved updates through one governed contract.

Architecture (from DVP-FTR-023 v0.3):
  Agent Session -> Enceladus MCP Client -> THIS SERVER -> Enceladus System Resources

System resources accessed:
  - DynamoDB: devops-project-tracker, projects, documents, coordination-requests
  - S3: reference docs, agent documents, deployment artifacts
  - HTTPS API: coordination API, deployment API (for orchestration-dependent ops)

Transport: stdio (for provider session integration via MCP profile)

Related: DVP-TSK-245, DVP-TSK-252, DVP-FTR-023, DVP-TSK-248
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
    Tool,
)

# ---------------------------------------------------------------------------
# Lazy boto3 import (provider sessions may need pip install)
# ---------------------------------------------------------------------------

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    _BOTO_AVAILABLE = True
except ImportError:
    _BOTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("ENCELADUS_TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("ENCELADUS_PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("ENCELADUS_DOCUMENTS_TABLE", "documents")
COORDINATION_TABLE = os.environ.get("ENCELADUS_COORDINATION_TABLE", "coordination-requests")
DEPLOY_TABLE = os.environ.get("ENCELADUS_DEPLOY_TABLE", "devops-deployment-manager")
AWS_REGION = os.environ.get("ENCELADUS_REGION", "us-west-2")
S3_BUCKET = os.environ.get("ENCELADUS_S3_BUCKET", "jreese-net")
S3_REFERENCE_PREFIX = os.environ.get("ENCELADUS_S3_REFERENCE_PREFIX", "mobile/v1/reference")
S3_DOCUMENTS_PREFIX = os.environ.get("ENCELADUS_S3_DOCUMENTS_PREFIX", "agent-documents")
GOVERNANCE_PROJECT_ID = os.environ.get("ENCELADUS_GOVERNANCE_PROJECT_ID", "devops")
GOVERNANCE_KEYWORD = os.environ.get("ENCELADUS_GOVERNANCE_KEYWORD", "governance-file")
GOVERNANCE_CATALOG_TTL_SECONDS = int(os.environ.get("ENCELADUS_GOVERNANCE_CATALOG_TTL_SECONDS", "300"))

COORDINATION_API_BASE = os.environ.get(
    "ENCELADUS_COORDINATION_API_BASE",
    "https://jreese.net/api/v1/coordination",
)
DOCUMENT_API_BASE = os.environ.get(
    "ENCELADUS_DOCUMENT_API_BASE",
    "https://jreese.net/api/v1/documents",
)
DOCUMENT_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", ""),
)
DEPLOY_API_BASE = os.environ.get(
    "ENCELADUS_DEPLOY_API_BASE",
    "https://jreese.net/api/v1/deploy",
)
DEPLOY_QUEUE_NAME = os.environ.get("ENCELADUS_DEPLOY_QUEUE", "devops-deploy-queue.fifo")
DEPLOY_CONFIG_BUCKET = os.environ.get("ENCELADUS_DEPLOY_CONFIG_BUCKET", "jreese-net")
DEPLOY_CONFIG_PREFIX = os.environ.get("ENCELADUS_DEPLOY_CONFIG_PREFIX", "deploy-config")
DEPLOY_CHANGE_TYPES = ("patch", "minor", "major")
DEPLOYMENT_TYPES = (
    "github_public_static",
    "github_private_sst",
    "github_public_workers",
    "github_private_workers",
    "lambda_update",
    "lambda_layer",
    "container_template",
    "glue_crawler_update",
    "glue_job_update",
    "eventbridge_rule",
    "s3_asset_sync",
    "cloudfront_config",
    "step_function_update",
)
GITHUB_DEPLOYMENT_TYPES = {
    "github_public_static",
    "github_private_sst",
    "github_public_workers",
    "github_private_workers",
}
NON_UI_SERVICE_GROUP_BY_TYPE = {
    "lambda_update": "lambda",
    "lambda_layer": "lambda",
    "container_template": "container",
    "glue_crawler_update": "glue",
    "glue_job_update": "glue",
    "eventbridge_rule": "eventbridge",
    "s3_asset_sync": "s3",
    "cloudfront_config": "cloudfront",
    "step_function_update": "step_function",
}
DEPLOY_API_COOKIE = os.environ.get("ENCELADUS_DEPLOY_COOKIE", "")

# GSI names
GSI_PROJECT_TYPE = "project-type-index"

SERVER_NAME = "enceladus"
SERVER_VERSION = "0.4.0"
HTTP_USER_AGENT = os.environ.get("ENCELADUS_HTTP_USER_AGENT", f"enceladus-mcp-server/{SERVER_VERSION}")

logger = logging.getLogger(SERVER_NAME)

# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

_ddb_client = None
_s3_client = None
_sqs_client = None
_deploy_queue_url: Optional[str] = None
_governance_catalog_cache: Dict[str, Dict[str, Any]] = {}
_governance_catalog_cached_at: float = 0.0


def _build_ssl_context() -> Optional[ssl.SSLContext]:
    """Build an SSL context with certifi fallback for reliable HTTPS calls."""
    cert_file = str(os.environ.get("SSL_CERT_FILE", "") or "").strip()
    if cert_file:
        try:
            return ssl.create_default_context(cafile=cert_file)
        except Exception as exc:
            logger.warning("SSL_CERT_FILE %r is not usable: %s", cert_file, exc)

    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            return ssl.create_default_context()
        except Exception:
            return None


_SSL_CTX = _build_ssl_context()


def _json_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if extra:
        headers.update(extra)
    return headers


def _urlopen(req: urllib.request.Request, timeout: int):
    if _SSL_CTX is not None:
        return urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX)
    return urllib.request.urlopen(req, timeout=timeout)


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        if not _BOTO_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Run: pip install boto3")
        _ddb_client = boto3.client(
            "dynamodb",
            region_name=AWS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )
    return _ddb_client


def _get_s3():
    global _s3_client
    if _s3_client is None:
        if not _BOTO_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Run: pip install boto3")
        _s3_client = boto3.client("s3", region_name=AWS_REGION)
    return _s3_client


def _get_sqs():
    global _sqs_client
    if _sqs_client is None:
        if not _BOTO_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Run: pip install boto3")
        _sqs_client = boto3.client("sqs", region_name=AWS_REGION)
    return _sqs_client


def _get_deploy_queue_url() -> str:
    """Resolve SQS FIFO queue URL from queue name (cached)."""
    global _deploy_queue_url
    if _deploy_queue_url is not None:
        return _deploy_queue_url
    sqs = _get_sqs()
    resp = sqs.get_queue_url(QueueName=DEPLOY_QUEUE_NAME)
    _deploy_queue_url = resp["QueueUrl"]
    return _deploy_queue_url


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_compact() -> str:
    """Compact UTC timestamp for ID generation (YYYYMMDDTHHmmss)."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


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


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


# Record-ID to DynamoDB key mapping (mirrors tracker.py item_key logic)
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature"}
_PREFIX_MAP_CACHE: Optional[Dict[str, str]] = None
_DEFAULT_STATUS_BY_TYPE = {"task": "open", "issue": "open", "feature": "planned"}
_TRACKER_TYPE_SUFFIX = {"task": "TSK", "issue": "ISS", "feature": "FTR"}
_TRACKER_COUNTER_PREFIX = "counter#"
_TRACKER_CREATE_MAX_ATTEMPTS = int(os.environ.get("ENCELADUS_TRACKER_CREATE_MAX_ATTEMPTS", "32"))


def _get_prefix_map() -> Dict[str, str]:
    """Build prefix -> project_name map from projects table."""
    global _PREFIX_MAP_CACHE
    if _PREFIX_MAP_CACHE is not None:
        return _PREFIX_MAP_CACHE
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
    _PREFIX_MAP_CACHE = mapping
    return mapping


def _tracker_key(record_id: str) -> Dict[str, Dict]:
    """Convert a record ID like 'DVP-TSK-245' into DynamoDB key dict."""
    record_id = record_id.strip().upper()
    parts = record_id.split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid record ID format: {record_id!r}. Expected PREFIX-TYPE-NNN")
    prefix, type_seg, _num = parts
    prefix_map = _get_prefix_map()
    if prefix not in prefix_map:
        raise ValueError(f"Unknown project prefix {prefix!r}. Known: {sorted(prefix_map)}")
    project_name = prefix_map[prefix]
    record_type = _ID_SEGMENT_TO_TYPE.get(type_seg)
    if not record_type:
        raise ValueError(f"Unknown type segment {type_seg!r} in {record_id!r}")
    sk = f"{record_type}#{record_id}"
    return {"project_id": _ser_s(project_name), "record_id": _ser_s(sk)}


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


def _tracker_counter_key(project_id: str, record_type: str) -> Dict[str, Dict[str, str]]:
    return {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(f"{_TRACKER_COUNTER_PREFIX}{record_type}"),
    }


def _record_numeric_suffix(record_id: str) -> Optional[int]:
    parts = str(record_id).strip().split("-")
    if len(parts) < 3:
        return None
    try:
        return int(parts[-1])
    except ValueError:
        return None


def _max_existing_tracker_number(ddb: Any, project_id: str, record_type: str) -> int:
    kwargs: Dict[str, Any] = {
        "TableName": TRACKER_TABLE,
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
            sk = _deser_val(item.get("record_id", {}))
            human_id = sk.split("#", 1)[1] if "#" in sk else sk
            parsed = _record_numeric_suffix(human_id)
            if parsed is not None:
                max_num = max(max_num, parsed)
        last_key = query_resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return max_num


def _next_tracker_record_id(ddb: Any, project_id: str, prefix: str, record_type: str) -> str:
    type_suffix = _TRACKER_TYPE_SUFFIX.get(record_type, "TSK")
    counter_key = _tracker_counter_key(project_id, record_type)
    counter_item = ddb.get_item(
        TableName=TRACKER_TABLE,
        Key=counter_key,
        ConsistentRead=True,
    ).get("Item")

    seed_num = 0
    if not counter_item:
        seed_num = _max_existing_tracker_number(ddb, project_id, record_type)

    now = _now_z()
    update_resp = ddb.update_item(
        TableName=TRACKER_TABLE,
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
    next_num_attr = attrs.get("next_num", {"N": str(seed_num + 1)})
    next_num = int(str(next_num_attr.get("N", str(seed_num + 1))))
    return f"{prefix}-{type_suffix}-{next_num:03d}"


def _is_conditional_check_failed(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    return str(exc.response.get("Error", {}).get("Code", "")) == "ConditionalCheckFailedException"


def _normalize_string_list(value: Any) -> Optional[List[str]]:
    """Normalize a string/list[str] into non-empty trimmed strings."""
    if value is None:
        return []
    if isinstance(value, str):
        source = [value]
    elif isinstance(value, list):
        source = value
    else:
        return None

    out: List[str] = []
    for entry in source:
        if not isinstance(entry, str):
            return None
        stripped = entry.strip()
        if stripped:
            out.append(stripped)
    return out


def _result_text(data: Any) -> list:
    """Format a result as TextContent for MCP tool response."""
    if isinstance(data, str):
        return [TextContent(type="text", text=data)]
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _error_payload(
    code: str,
    message: str,
    retryable: bool = False,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details or {},
        },
    }


def _error_result(msg: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"ERROR: {msg}")], isError=True)


def _tool_input_hash(arguments: Dict[str, Any]) -> str:
    payload = json.dumps(arguments or {}, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _tool_result_status(content: list[TextContent]) -> str:
    if not content:
        return "error"
    text = content[0].text if hasattr(content[0], "text") else ""
    if isinstance(text, str) and text.startswith("ERROR:"):
        return "error"
    try:
        parsed = json.loads(text) if isinstance(text, str) else {}
        if isinstance(parsed, dict) and parsed.get("error"):
            return "error"
    except Exception:
        pass
    return "success"


def _tool_error_code(content: list[TextContent]) -> str:
    if not content:
        return "tool_error"
    text = content[0].text if hasattr(content[0], "text") else ""
    raw = str(text or "")
    normalized = raw.lower()
    if "governance_stale" in normalized:
        return "governance_stale"
    if "missing governance_hash" in normalized:
        return "governance_hash_missing"
    if "not found" in normalized:
        return "record_not_found"
    if "unknown tool" in normalized:
        return "unknown_tool"
    return "tool_error"


def _audit_tool_invocation(
    name: str,
    arguments: Dict[str, Any],
    status: str,
    *,
    latency_ms: int = 0,
    error_code: str = "",
) -> None:
    request_id = str(arguments.get("coordination_request_id") or arguments.get("request_id") or "")
    invocation_id = str(arguments.get("invocation_id") or f"mcpi-{uuid.uuid4().hex[:20]}")
    caller_identity = str(arguments.get("caller_identity") or "unknown")
    payload = {
        "invocation_id": invocation_id,
        "caller_identity": caller_identity,
        "request_id": request_id,
        "dispatch_id": str(arguments.get("dispatch_id") or ""),
        "tool_name": name,
        "input_hash": _tool_input_hash(arguments),
        "result_status": status,
        "latency_ms": int(max(0, latency_ms)),
        "error_code": str(error_code or ""),
        "timestamp": _now_z(),
    }
    logger.info("[AUDIT] %s", json.dumps(payload, sort_keys=True))


def _require_governance_hash(args: dict) -> Optional[str]:
    provided = str(args.get("governance_hash") or "").strip()
    if not provided:
        return "Missing governance_hash for write-capable MCP tool call"
    current = _compute_governance_hash()
    if provided != current:
        return "GOVERNANCE_STALE: provided governance_hash does not match current governance bundle"
    return None


def _require_governance_hash_envelope(args: dict) -> Optional[Dict[str, Any]]:
    provided = str(args.get("governance_hash") or "").strip()
    if not provided:
        return _error_payload(
            "PERMISSION_DENIED",
            "Missing governance_hash for write-capable MCP tool call",
            retryable=False,
        )
    current = _compute_governance_hash()
    if provided != current:
        return _error_payload(
            "GOVERNANCE_STALE",
            "provided governance_hash does not match current governance bundle",
            retryable=True,
            details={"provided": provided, "current": current},
        )
    return None


def _error_code_from_http_status(status_code: int) -> str:
    if status_code == 404:
        return "NOT_FOUND"
    if status_code == 409:
        return "CONFLICT"
    if status_code == 429:
        return "RATE_LIMITED"
    if status_code == 408:
        return "TIMEOUT"
    if status_code in (401, 403):
        return "PERMISSION_DENIED"
    if 400 <= status_code < 500:
        return "INVALID_INPUT"
    if status_code >= 500:
        return "UPSTREAM_ERROR"
    return "UPSTREAM_ERROR"


def _normalize_legacy_error_payload(
    response_body: Any,
    status_code: int,
    default_code: Optional[str] = None,
) -> Dict[str, Any]:
    if isinstance(response_body, dict):
        existing = response_body.get("error")
        if isinstance(existing, dict) and {"code", "message", "retryable"}.issubset(existing.keys()):
            return response_body
        if isinstance(existing, str):
            code = default_code or _error_code_from_http_status(status_code)
            return _error_payload(code, existing, retryable=code in {"TIMEOUT", "UPSTREAM_ERROR", "RATE_LIMITED"})
    code = default_code or _error_code_from_http_status(status_code)
    message = (
        response_body if isinstance(response_body, str)
        else f"Request failed with status {status_code}"
    )
    return _error_payload(code, message, retryable=code in {"TIMEOUT", "UPSTREAM_ERROR", "RATE_LIMITED"})


def _deploy_api_request(
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base = DEPLOY_API_BASE.rstrip("/")
    route = path if path.startswith("/") else f"/{path}"
    url = f"{base}{route}"
    if query:
        encoded_qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        if encoded_qs:
            url = f"{url}?{encoded_qs}"
    headers = _json_headers()
    if DEPLOY_API_COOKIE:
        headers["Cookie"] = DEPLOY_API_COOKIE
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=body)
    try:
        with _urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8")
            return json.loads(text) if text else {"success": True}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw or str(exc)}
        return _normalize_legacy_error_payload(parsed, exc.code)
    except urllib.error.URLError as exc:
        return _error_payload("UPSTREAM_ERROR", f"Deployment API unreachable: {exc}", retryable=True)
    except Exception as exc:  # pragma: no cover - defensive fallback
        return _error_payload("INTERNAL_ERROR", f"Deployment API request failed: {exc}", retryable=False)


def _document_api_request(
    method: str,
    path: str = "",
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base = DOCUMENT_API_BASE.rstrip("/")
    route = path if path.startswith("/") else (f"/{path}" if path else "")
    url = f"{base}{route}"
    if query:
        encoded_qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
        if encoded_qs:
            url = f"{url}?{encoded_qs}"

    headers = _json_headers()
    if DOCUMENT_API_INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = DOCUMENT_API_INTERNAL_API_KEY
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None

    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=body)
    try:
        with _urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8")
            return json.loads(text) if text else {"success": True}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw or str(exc)}
        return _normalize_legacy_error_payload(parsed, exc.code)
    except urllib.error.URLError as exc:
        return _error_payload("UPSTREAM_ERROR", f"Document API unreachable: {exc}", retryable=True)
    except Exception as exc:  # pragma: no cover - defensive fallback
        return _error_payload("INTERNAL_ERROR", f"Document API request failed: {exc}", retryable=False)


# ---------------------------------------------------------------------------
# Governance hash computation
# ---------------------------------------------------------------------------


def _governance_uri_from_file_name(file_name: str) -> Optional[str]:
    name = str(file_name or "").strip()
    if not name:
        return None
    if name == "agents.md":
        return "governance://agents.md"
    if name.startswith("agents/"):
        return f"governance://{name}"
    return None


def _governance_catalog(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    global _governance_catalog_cache, _governance_catalog_cached_at

    now = time.time()
    if (
        not force_refresh
        and _governance_catalog_cache
        and (now - _governance_catalog_cached_at) < GOVERNANCE_CATALOG_TTL_SECONDS
    ):
        return _governance_catalog_cache

    try:
        ddb = _get_ddb()
        items: List[Dict[str, Any]] = []
        resp = ddb.query(
            TableName=DOCUMENTS_TABLE,
            IndexName="project-updated-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": _ser_s(GOVERNANCE_PROJECT_ID)},
            ScanIndexForward=False,
        )
        items.extend(resp.get("Items", []))
        while resp.get("LastEvaluatedKey"):
            resp = ddb.query(
                TableName=DOCUMENTS_TABLE,
                IndexName="project-updated-index",
                KeyConditionExpression="project_id = :pid",
                ExpressionAttributeValues={":pid": _ser_s(GOVERNANCE_PROJECT_ID)},
                ScanIndexForward=False,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))
    except Exception as exc:
        logger.warning("governance catalog query failed: %s", exc)
        _governance_catalog_cache = {}
        _governance_catalog_cached_at = now
        return _governance_catalog_cache

    catalog: Dict[str, Dict[str, Any]] = {}
    for raw in items:
        doc = _deser_item(raw)
        if str(doc.get("status") or "").lower() != "active":
            continue

        file_name = str(doc.get("file_name") or "").strip()
        uri = _governance_uri_from_file_name(file_name)
        if not uri:
            continue

        keywords = [str(k).strip().lower() for k in doc.get("keywords") or [] if str(k).strip()]
        if GOVERNANCE_KEYWORD and GOVERNANCE_KEYWORD.lower() not in keywords:
            continue

        existing = catalog.get(uri)
        if existing and str(existing.get("updated_at") or "") >= str(doc.get("updated_at") or ""):
            continue

        catalog[uri] = {
            "document_id": doc.get("document_id"),
            "project_id": doc.get("project_id"),
            "title": doc.get("title"),
            "file_name": file_name,
            "s3_bucket": doc.get("s3_bucket") or S3_BUCKET,
            "s3_key": doc.get("s3_key"),
            "content_hash": doc.get("content_hash"),
            "updated_at": doc.get("updated_at"),
        }

    _governance_catalog_cache = catalog
    _governance_catalog_cached_at = now
    return catalog


def _compute_governance_hash() -> str:
    """SHA-256 of governance resources resolved from docstore catalog."""
    catalog = _governance_catalog()
    h = hashlib.sha256()

    if not catalog:
        h.update(b"enceladus-governance-docstore-empty")
        return h.hexdigest()

    for uri in sorted(catalog.keys()):
        meta = catalog[uri]
        content_hash = str(meta.get("content_hash") or "").strip()
        if not content_hash:
            s3_key = str(meta.get("s3_key") or "").strip()
            if not s3_key:
                continue
            try:
                resp = _get_s3().get_object(
                    Bucket=str(meta.get("s3_bucket") or S3_BUCKET),
                    Key=s3_key,
                )
                content_hash = hashlib.sha256(resp["Body"].read()).hexdigest()
            except Exception:
                continue

        h.update(uri.encode("utf-8"))
        h.update(b"\n")
        h.update(content_hash.encode("utf-8"))
        h.update(b"\n")

    return h.hexdigest()


# ===================================================================
# MCP SERVER DEFINITION
# ===================================================================

app = Server(SERVER_NAME)


# -------------------------------------------------------------------
# RESOURCES — governance + project reference (read-only)
# -------------------------------------------------------------------


@app.list_resources()
async def list_resources() -> list[Resource]:
    resources = []

    # Governance files (authoritative source: docstore)
    for uri, meta in sorted(_governance_catalog().items()):
        file_name = str(meta.get("file_name") or "")
        mime_type = "application/json" if file_name.endswith(".json") else "text/markdown"
        label = "agents.md — Global governance directives" if uri == "governance://agents.md" else file_name
        resources.append(
            Resource(
                uri=uri,
                name=label,
                mimeType=mime_type,
            )
        )

    return resources


@app.list_resource_templates()
async def list_resource_templates() -> list[ResourceTemplate]:
    return [
        ResourceTemplate(
            uriTemplate="projects://reference/{project_id}",
            name="Project reference document",
            description="Fetch the latest project reference markdown from S3.",
            mimeType="text/markdown",
        ),
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    # governance://... from docstore
    if uri.startswith("governance://"):
        catalog = _governance_catalog()
        meta = catalog.get(uri)
        if not meta:
            return f"# Governance resource not found in docstore: {uri}"
        s3_key = str(meta.get("s3_key") or "").strip()
        if not s3_key:
            return f"# Governance resource missing s3_key: {uri}"
        try:
            resp = _get_s3().get_object(
                Bucket=str(meta.get("s3_bucket") or S3_BUCKET),
                Key=s3_key,
            )
            return resp["Body"].read().decode("utf-8")
        except Exception as exc:
            return f"# Failed to fetch governance resource {uri}: {exc}"

    # projects://reference/{project_id}
    if uri.startswith("projects://reference/"):
        project_id = uri.replace("projects://reference/", "")
        s3_key = f"{S3_REFERENCE_PREFIX}/{project_id}.md"
        try:
            resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
            return resp["Body"].read().decode("utf-8")
        except Exception as exc:
            return f"# Failed to fetch reference for {project_id}: {exc}"

    return f"# Unknown resource URI: {uri}"


# -------------------------------------------------------------------
# TOOLS — governed write/read operations
# -------------------------------------------------------------------


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # --- Project Lifecycle Management (6.4) ---
        Tool(
            name="projects_list",
            description="List all projects. Optionally filter by status or active flag.",
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["planning", "development", "active_production"],
                        "description": "Filter by project status.",
                    },
                    "active": {
                        "type": "boolean",
                        "description": "If true, return only active projects.",
                    },
                },
            },
        ),
        Tool(
            name="projects_get",
            description="Get details for a specific project by name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_name": {
                        "type": "string",
                        "description": "The project name to retrieve.",
                    }
                },
                "required": ["project_name"],
            },
        ),
        # --- Tracker CRUD (6.4.3) ---
        Tool(
            name="tracker_get",
            description="Get a single tracker record (task, issue, or feature) by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The record ID (e.g., DVP-TSK-074).",
                    }
                },
                "required": ["record_id"],
            },
        ),
        Tool(
            name="tracker_list",
            description="List tracker records for a project. Filter by type and/or status.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., devops).",
                    },
                    "record_type": {
                        "type": "string",
                        "enum": ["task", "issue", "feature"],
                        "description": "Filter by record type.",
                    },
                    "status": {
                        "type": "string",
                        "description": "Filter by status (e.g., open, in-progress, closed).",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="tracker_set",
            description="Set a field value on a tracker record.",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The record ID to update.",
                    },
                    "field": {
                        "type": "string",
                        "description": "The field to set (e.g., status, priority, assigned_to).",
                    },
                    "value": {
                        "type": "string",
                        "description": "The new value for the field.",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                    "coordination_request_id": {
                        "type": "string",
                        "description": "Coordination request ID for write audit traceability.",
                    },
                    "dispatch_id": {
                        "type": "string",
                        "description": "Dispatch identifier associated with this write.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider name associated with this write.",
                    },
                },
                "required": ["record_id", "field", "value", "governance_hash"],
            },
        ),
        Tool(
            name="tracker_log",
            description="Append a worklog entry to a tracker record's history.",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The record ID to log against.",
                    },
                    "description": {
                        "type": "string",
                        "description": "The worklog description text.",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                    "coordination_request_id": {
                        "type": "string",
                        "description": "Coordination request ID for write audit traceability.",
                    },
                    "dispatch_id": {
                        "type": "string",
                        "description": "Dispatch identifier associated with this write.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider name associated with this write.",
                    },
                },
                "required": ["record_id", "description", "governance_hash"],
            },
        ),
        Tool(
            name="tracker_create",
            description="Create a new tracker record (task, issue, or feature) in a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "record_type": {
                        "type": "string",
                        "enum": ["task", "issue", "feature"],
                        "description": "The type of record to create.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Title for the new record.",
                    },
                    "priority": {
                        "type": "string",
                        "description": "Priority (e.g., P0, P1, P2).",
                    },
                    "related": {
                        "type": "string",
                        "description": "Comma-separated related record IDs.",
                    },
                    "acceptance_criteria": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Acceptance criteria for task records. "
                            "Required when record_type is 'task'."
                        ),
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                    "coordination_request_id": {
                        "type": "string",
                        "description": "Coordination request ID for write audit traceability.",
                    },
                    "dispatch_id": {
                        "type": "string",
                        "description": "Dispatch identifier associated with this write.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider name associated with this write.",
                    },
                },
                "required": ["project_id", "record_type", "title", "governance_hash"],
            },
        ),
        # --- Documents (6.3) ---
        Tool(
            name="documents_search",
            description="Search for documents by project, keyword, related item, or title.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Filter by project.",
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search in document keywords.",
                    },
                    "related": {
                        "type": "string",
                        "description": "Related record ID to search for.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Title substring to search for.",
                    },
                },
            },
        ),
        Tool(
            name="documents_get",
            description="Get a document by its DOC-ID, including content from S3.",
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "The document ID (e.g., DOC-ABC123DEF456).",
                    },
                    "include_content": {
                        "type": "boolean",
                        "description": "Whether to include the document body. Default true.",
                        "default": True,
                    },
                },
                "required": ["document_id"],
            },
        ),
        Tool(
            name="documents_list",
            description="List all documents for a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    }
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="documents_put",
            description=(
                "Create a new document via Enceladus document API. "
                "Uses the same backend service as direct API writes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project ID for the new document.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Document title.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Document body content (markdown).",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional summary/description.",
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional keyword tags.",
                    },
                    "related_items": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional related tracker IDs.",
                    },
                    "file_name": {
                        "type": "string",
                        "description": "Optional output file name (.md/.markdown).",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["project_id", "title", "content", "governance_hash"],
            },
        ),
        Tool(
            name="documents_patch",
            description=(
                "Update an existing document via Enceladus document API. "
                "Uses the same backend service as direct API writes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "Document ID to update.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Optional updated title.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Optional updated markdown content.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional updated description.",
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional replacement keywords list.",
                    },
                    "related_items": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional replacement related_items list.",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["active", "archived"],
                        "description": "Optional status change.",
                    },
                    "file_name": {
                        "type": "string",
                        "description": "Optional updated file name (.md/.markdown).",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["document_id", "governance_hash"],
            },
        ),
        # --- Reference Search (DVP-TSK-293) ---
        Tool(
            name="reference_search",
            description=(
                "Search a project reference document and return matched snippets "
                "with line numbers, section context, and surrounding lines. "
                "Avoids downloading the full reference document."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., devops).",
                    },
                    "query": {
                        "type": "string",
                        "description": "Search text or regex pattern.",
                    },
                    "regex": {
                        "type": "boolean",
                        "description": "If true, treat query as a regex pattern. Default false.",
                        "default": False,
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "description": "If true, search is case-sensitive. Default false.",
                        "default": False,
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Lines of context before/after each match. Default 2, max 10.",
                        "default": 2,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of snippets to return. Default 20, max 100.",
                        "default": 20,
                    },
                    "section": {
                        "type": "string",
                        "description": "Only return matches within sections whose heading matches this pattern.",
                    },
                },
                "required": ["project_id", "query"],
            },
        ),
        # --- Deployment (6.2) ---
        Tool(
            name="deploy_state_get",
            description="Get the current deployment state (ACTIVE/PAUSED) for a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    }
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="deploy_history",
            description="List recent deployments for a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="deploy_history_list",
            description="List recent deployments for a project. Preferred v0.3 capability name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="deploy_submit",
            description="Submit a deployment request through the deployment intake API.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., devops).",
                    },
                    "change_type": {
                        "type": "string",
                        "enum": ["patch", "minor", "major"],
                        "description": "Semantic version bump type.",
                    },
                    "deployment_type": {
                        "type": "string",
                        "enum": list(DEPLOYMENT_TYPES),
                        "description": "Deployment type key from the v0.3 registry.",
                    },
                    "summary": {
                        "type": "string",
                        "description": "Human-readable summary of the deployment.",
                    },
                    "changes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of change descriptions.",
                    },
                    "related_record_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tracker record IDs related to this deploy (e.g., DVP-TSK-249).",
                    },
                    "files_changed": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of changed file paths.",
                    },
                    "auto_trigger": {
                        "type": "boolean",
                        "description": "If true (default), send SQS trigger when state is ACTIVE.",
                        "default": True,
                    },
                    "submitted_by": {
                        "type": "string",
                        "description": "Optional submitter identity for audit.",
                    },
                    "github_config": {
                        "type": "object",
                        "description": "GitHub deployment config for github_* deployment types.",
                    },
                    "non_ui_config": {
                        "type": "object",
                        "description": "Non-UI deployment config for infrastructure deployment types.",
                    },
                },
                "required": ["project_id", "change_type", "deployment_type", "summary", "changes"],
            },
        ),
        Tool(
            name="deploy_state_set",
            description="Set the deployment state (ACTIVE or PAUSED) for a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "state": {
                        "type": "string",
                        "enum": ["ACTIVE", "PAUSED"],
                        "description": "The desired deployment state.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for the state change.",
                    },
                },
                "required": ["project_id", "state"],
            },
        ),
        Tool(
            name="deploy_status",
            description="Get the status of a specific deployment spec by its SPEC-ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "spec_id": {
                        "type": "string",
                        "description": "The deployment spec ID (e.g., SPEC-20260219T143000).",
                    },
                },
                "required": ["project_id", "spec_id"],
            },
        ),
        Tool(
            name="deploy_status_get",
            description="Get the status of a specific deployment spec by its SPEC-ID. Preferred v0.3 capability name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "spec_id": {
                        "type": "string",
                        "description": "The deployment spec ID (e.g., SPEC-20260219T143000).",
                    },
                },
                "required": ["project_id", "spec_id"],
            },
        ),
        Tool(
            name="deploy_trigger",
            description="Manually trigger the deploy orchestration pipeline by sending a message to the SQS FIFO queue. Use when requests are pending but the pipeline wasn't triggered automatically.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="deploy_pending_requests",
            description="List all pending (not yet included in a spec) deployment requests for a project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                },
                "required": ["project_id"],
            },
        ),
        # --- Coordination (6.1) ---
        Tool(
            name="coordination_capabilities",
            description="Get current coordination service capabilities, provider status, and execution modes.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="coordination_request_get",
            description="Get the current state of a coordination request by ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The coordination request ID.",
                    }
                },
                "required": ["request_id"],
            },
        ),
        # --- Governance (8) ---
        Tool(
            name="governance_hash",
            description="Compute and return the SHA-256 governance hash of loaded governance files.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # --- System ---
        Tool(
            name="connection_health",
            description="Test connectivity to DynamoDB, S3, and compute governance hash. Use at session start.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # --- Dispatch Plan Generation (6.1.2) ---
        Tool(
            name="dispatch_plan_generate",
            description=(
                "Generate a dispatch-plan for a coordination request. "
                "Follows governance-first init sequence: loads governance, tests connections, "
                "reads coordination request, applies heuristics, and produces a validated plan. "
                "Optionally accepts a dispatch_plan_override to bypass auto-generation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The coordination request ID to generate a dispatch-plan for.",
                    },
                    "dispatch_plan_override": {
                        "type": "object",
                        "description": "Optional pre-built dispatch-plan JSON that bypasses auto-generation.",
                    },
                },
                "required": ["request_id"],
            },
        ),
        Tool(
            name="dispatch_plan_dry_run",
            description=(
                "Generate a dispatch-plan without a real coordination request. "
                "Useful for previewing what the heuristics would produce for a given set of outcomes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "outcomes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of outcome strings to plan for.",
                    },
                    "preferred_provider": {
                        "type": "string",
                        "enum": ["openai_codex", "claude_agent_sdk", "aws_native", "aws_bedrock_agent"],
                        "description": "Optional preferred provider override.",
                    },
                },
                "required": ["project_id", "outcomes"],
            },
        ),
    ]


# -------------------------------------------------------------------
# TOOL HANDLERS
# -------------------------------------------------------------------


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    args = arguments or {}
    started = time.perf_counter()
    try:
        handler = _TOOL_HANDLERS.get(name)
        if handler is None:
            result = _error_result(f"Unknown tool: {name}").content
            _audit_tool_invocation(
                name,
                args,
                "error",
                latency_ms=int((time.perf_counter() - started) * 1000),
                error_code="unknown_tool",
            )
            return result
        result = await handler(args)
        status = _tool_result_status(result)
        _audit_tool_invocation(
            name,
            args,
            status,
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code="" if status == "success" else _tool_error_code(result),
        )
        return result
    except Exception as exc:
        logger.exception("tool call failed: %s", name)
        _audit_tool_invocation(
            name,
            args,
            "error",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code="tool_exception",
        )
        return _error_result(f"Tool '{name}' failed: {exc}").content


# --- Projects ---


async def _projects_list(args: dict) -> list[TextContent]:
    ddb = _get_ddb()
    scan_kwargs: Dict[str, Any] = {"TableName": PROJECTS_TABLE}

    filter_parts: List[str] = []
    expr_vals: Dict[str, Any] = {}

    status = args.get("status")
    active = args.get("active")

    if status:
        filter_parts.append("#st = :status")
        expr_vals[":status"] = _ser_s(status)
    elif active:
        filter_parts.append("#st = :active_prod")
        expr_vals[":active_prod"] = _ser_s("active_production")

    if filter_parts:
        scan_kwargs["FilterExpression"] = " AND ".join(filter_parts)
        scan_kwargs["ExpressionAttributeValues"] = expr_vals
        scan_kwargs["ExpressionAttributeNames"] = {"#st": "status"}

    resp = ddb.scan(**scan_kwargs)
    items = [_deser_item(i) for i in resp.get("Items", [])]
    # Normalize: projects table uses 'project_id' as PK, surface as 'name' for consistency
    for item in items:
        if "project_id" in item and "name" not in item:
            item["name"] = item["project_id"]
    return _result_text({"projects": items, "count": len(items)})


async def _projects_get(args: dict) -> list[TextContent]:
    name = args["project_name"]
    ddb = _get_ddb()
    # Projects table uses 'project_id' as the partition key
    resp = ddb.get_item(TableName=PROJECTS_TABLE, Key={"project_id": _ser_s(name)})
    item = resp.get("Item")
    if not item:
        return _result_text({"error": f"Project '{name}' not found"})
    project = _deser_item(item)
    if "project_id" in project and "name" not in project:
        project["name"] = project["project_id"]
    return _result_text({"project": project})


# --- Tracker ---


async def _tracker_get(args: dict) -> list[TextContent]:
    record_id = args["record_id"]
    ddb = _get_ddb()
    try:
        key = _tracker_key(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})
    resp = ddb.get_item(TableName=TRACKER_TABLE, Key=key)
    item = resp.get("Item")
    if not item:
        return _result_text({"error": f"Record '{record_id}' not found"})
    result = _deser_item(item)
    # Surface record_id as 'id' for consistency with tracker.py output
    if "record_id" in result and "id" not in result:
        # Extract the human-readable ID from "task#DVP-TSK-245"
        sk = result["record_id"]
        result["id"] = sk.split("#", 1)[1] if "#" in sk else sk
    return _result_text(result)


async def _tracker_list(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    record_type = args.get("record_type")
    status_filter = args.get("status")
    ddb = _get_ddb()

    if record_type:
        # Use GSI project-type-index
        key_expr = "project_id = :pid AND record_type = :rtype"
        expr_vals = {":pid": _ser_s(project_id), ":rtype": _ser_s(record_type)}
        query_kwargs: Dict[str, Any] = {
            "TableName": TRACKER_TABLE,
            "IndexName": GSI_PROJECT_TYPE,
            "KeyConditionExpression": key_expr,
            "ExpressionAttributeValues": expr_vals,
        }
        if status_filter:
            query_kwargs["FilterExpression"] = "#st = :st"
            query_kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)
            query_kwargs["ExpressionAttributeNames"] = {"#st": "status"}
        resp = ddb.query(**query_kwargs)
    else:
        # Scan with project filter
        filter_expr = "project_id = :pid"
        expr_vals = {":pid": _ser_s(project_id)}
        scan_kwargs: Dict[str, Any] = {
            "TableName": TRACKER_TABLE,
            "FilterExpression": filter_expr,
            "ExpressionAttributeValues": expr_vals,
        }
        if status_filter:
            scan_kwargs["FilterExpression"] += " AND #st = :st"
            scan_kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)
            scan_kwargs["ExpressionAttributeNames"] = {"#st": "status"}
        resp = ddb.scan(**scan_kwargs)

    items = [_deser_item(i) for i in resp.get("Items", [])]
    # Extract human-readable ID from record_id sort key
    for item in items:
        sk = item.get("record_id", "")
        item["id"] = sk.split("#", 1)[1] if "#" in sk else sk
    items.sort(key=lambda x: x.get("id", ""))
    summary = [
        {"id": r.get("id"), "type": r.get("record_type"), "status": r.get("status"),
         "priority": r.get("priority"), "title": (r.get("title", "")[:80])}
        for r in items
    ]
    return _result_text({"records": summary, "count": len(items)})


async def _tracker_set(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    field = args["field"]
    value = args["value"]
    ddb = _get_ddb()

    try:
        key = _tracker_key(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    # Validate record exists
    existing = ddb.get_item(TableName=TRACKER_TABLE, Key=key)
    if not existing.get("Item"):
        return _result_text({"error": f"Record '{record_id}' not found"})

    now = _now_z()
    update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "sync_version = if_not_exists(sync_version, :zero) + :one"
    )
    expr_vals = {
        ":val": _ser_s(value),
        ":now": _ser_s(now),
        ":note": _ser_s(f"Field '{field}' set to '{value}' via MCP server"),
        ":zero": {"N": "0"},
        ":one": {"N": "1"},
    }
    expr_names = {"#fld": field}

    # Append to history
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(f"Field '{field}' set to '{value}' via MCP server"),
        }
    }
    update_expr += ", history = list_append(if_not_exists(history, :empty), :hentry)"
    expr_vals[":hentry"] = {"L": [history_entry]}
    expr_vals[":empty"] = {"L": []}

    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key=key,
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )
    return _result_text({"success": True, "record_id": record_id, "field": field, "value": value, "updated_at": now})


async def _tracker_log(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    description = args["description"]
    ddb = _get_ddb()

    try:
        key = _tracker_key(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    existing = ddb.get_item(TableName=TRACKER_TABLE, Key=key)
    if not existing.get("Item"):
        return _result_text({"error": f"Record '{record_id}' not found"})

    now = _now_z()
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(description),
        }
    }
    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key=key,
        UpdateExpression=(
            "SET updated_at = :now, "
            "last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "history = list_append(if_not_exists(history, :empty), :hentry)"
        ),
        ExpressionAttributeValues={
            ":now": _ser_s(now),
            ":note": _ser_s(description),
            ":zero": {"N": "0"},
            ":one": {"N": "1"},
            ":hentry": {"L": [history_entry]},
            ":empty": {"L": []},
        },
    )
    return _result_text({"success": True, "record_id": record_id, "updated_at": now})


async def _tracker_create(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    project_id = args["project_id"]
    record_type = args["record_type"]
    title = args["title"]
    priority = args.get("priority")
    description = str(args.get("description") or "")
    assigned_to = str(args.get("assigned_to") or "")
    status = str(args.get("status") or _DEFAULT_STATUS_BY_TYPE.get(record_type, "open"))
    severity = str(args.get("severity") or "")
    hypothesis = str(args.get("hypothesis") or "")
    success_metrics = args.get("success_metrics") or []
    related_str = args.get("related", "")
    acceptance_criteria = _normalize_string_list(args.get("acceptance_criteria"))
    if acceptance_criteria is None:
        return _result_text(
            {
                "error": (
                    "Invalid acceptance_criteria: expected a string or list of strings."
                )
            }
        )
    if record_type == "task" and not acceptance_criteria:
        return _result_text(
            {
                "error": (
                    "Task creation requires acceptance_criteria with at least one "
                    "non-empty criterion."
                )
            }
        )
    ddb = _get_ddb()

    # Resolve prefix from projects table
    proj_resp = ddb.get_item(TableName=PROJECTS_TABLE, Key={"project_id": _ser_s(project_id)})
    proj = proj_resp.get("Item")
    if not proj:
        return _result_text({"error": f"Project '{project_id}' not found in projects table"})
    prefix = _deser_val(proj.get("prefix", {"S": "UNK"}))

    now = _now_z()
    item: Dict[str, Any] = {
        "project_id": _ser_s(project_id),
        "record_type": _ser_s(record_type),
        "title": _ser_s(title),
        "status": _ser_s(status),
        "sync_version": {"N": "1"},
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": _ser_s(now),
                        "status": _ser_s("created"),
                        "description": _ser_s(f"Created via MCP server: {title}"),
                    }
                }
            ]
        },
    }

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
    if record_type == "task" and acceptance_criteria:
        item["acceptance_criteria"] = {"L": [_ser_s(x) for x in acceptance_criteria]}

    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        for field, ids in _classify_related_ids(related_ids).items():
            if ids:
                item[field] = {"L": [_ser_s(i) for i in ids]}

    max_attempts = max(1, _TRACKER_CREATE_MAX_ATTEMPTS)
    for attempt in range(1, max_attempts + 1):
        new_id = _next_tracker_record_id(ddb, project_id, prefix, record_type)
        sk = f"{record_type}#{new_id}"
        item["record_id"] = _ser_s(sk)
        item["item_id"] = _ser_s(new_id)
        try:
            ddb.put_item(
                TableName=TRACKER_TABLE,
                Item=item,
                ConditionExpression="attribute_not_exists(record_id)",
            )
            return _result_text({"success": True, "record_id": new_id, "created_at": now})
        except ClientError as exc:
            if _is_conditional_check_failed(exc) and attempt < max_attempts:
                continue
            raise

    return _result_text(
        {
            "error": (
                f"Failed to allocate a unique record ID for {record_type} in project "
                f"'{project_id}' after {max_attempts} attempts."
            )
        }
    )


# --- Documents ---


async def _documents_search(args: dict) -> list[TextContent]:
    ddb = _get_ddb()
    project_id = args.get("project_id")
    keyword = args.get("keyword")
    related = args.get("related")
    title_q = args.get("title")

    # Scan with filters (documents table has no GSI for these queries)
    filter_parts: List[str] = []
    expr_vals: Dict[str, Any] = {}
    expr_names: Dict[str, str] = {}

    if project_id:
        filter_parts.append("project_id = :pid")
        expr_vals[":pid"] = _ser_s(project_id)
    if keyword:
        filter_parts.append("contains(keywords, :kw)")
        expr_vals[":kw"] = _ser_s(keyword)
    if related:
        filter_parts.append("contains(related_items, :rel)")
        expr_vals[":rel"] = _ser_s(related)
    if title_q:
        filter_parts.append("contains(#ttl, :ttl)")
        expr_vals[":ttl"] = _ser_s(title_q)
        expr_names["#ttl"] = "title"

    scan_kwargs: Dict[str, Any] = {"TableName": DOCUMENTS_TABLE}
    if filter_parts:
        scan_kwargs["FilterExpression"] = " AND ".join(filter_parts)
        scan_kwargs["ExpressionAttributeValues"] = expr_vals
        if expr_names:
            scan_kwargs["ExpressionAttributeNames"] = expr_names

    resp = ddb.scan(**scan_kwargs)
    items = [_deser_item(i) for i in resp.get("Items", [])]
    # Return metadata only, not content
    summary = [
        {
            "document_id": d.get("id") or d.get("document_id"),
            "title": d.get("title"),
            "project_id": d.get("project_id"),
            "keywords": d.get("keywords"),
            "created_at": d.get("created_at"),
        }
        for d in items
    ]
    return _result_text({"documents": summary, "count": len(summary)})


async def _documents_get(args: dict) -> list[TextContent]:
    doc_id = args["document_id"]
    include_content = args.get("include_content", True)
    ddb = _get_ddb()

    resp = ddb.get_item(TableName=DOCUMENTS_TABLE, Key={"document_id": _ser_s(doc_id)})
    item = resp.get("Item")
    if not item:
        return _result_text({"error": f"Document '{doc_id}' not found"})

    doc = _deser_item(item)

    if include_content:
        # Fetch content from S3
        s3_key = doc.get("s3_key")
        if s3_key:
            try:
                s3_resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
                doc["content"] = s3_resp["Body"].read().decode("utf-8")
            except Exception as exc:
                doc["content_error"] = str(exc)

    return _result_text(doc)


async def _documents_list(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    ddb = _get_ddb()

    resp = ddb.scan(
        TableName=DOCUMENTS_TABLE,
        FilterExpression="project_id = :pid",
        ExpressionAttributeValues={":pid": _ser_s(project_id)},
    )
    items = [_deser_item(i) for i in resp.get("Items", [])]
    summary = [
        {
            "document_id": d.get("id") or d.get("document_id"),
            "title": d.get("title"),
            "status": d.get("status"),
            "keywords": d.get("keywords"),
            "created_at": d.get("created_at"),
            "size_bytes": d.get("size_bytes"),
        }
        for d in items
    ]
    summary.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return _result_text({"documents": summary, "count": len(summary)})


async def _documents_put(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash_envelope(args)
    if governance_error:
        return _result_text(governance_error)

    body: Dict[str, Any] = {
        "project_id": args["project_id"],
        "title": args["title"],
        "content": args["content"],
    }
    for key in ("description", "keywords", "related_items", "file_name"):
        if key in args and args.get(key) is not None:
            body[key] = args.get(key)

    result = _document_api_request("PUT", payload=body)
    return _result_text(result)


async def _documents_patch(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash_envelope(args)
    if governance_error:
        return _result_text(governance_error)

    document_id = str(args["document_id"]).strip()
    if not document_id:
        return _result_text(
            _error_payload("INVALID_INPUT", "document_id is required")
        )

    body: Dict[str, Any] = {}
    for key in ("title", "content", "description", "keywords", "related_items", "status", "file_name"):
        if key in args and args.get(key) is not None:
            body[key] = args.get(key)
    if not body:
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                "At least one updatable field is required for documents_patch",
            )
        )

    encoded_id = urllib.parse.quote(document_id, safe="")
    result = _document_api_request("PATCH", path=f"/{encoded_id}", payload=body)
    return _result_text(result)


# --- Reference Search (DVP-TSK-293) ---


async def _reference_search(args: dict) -> list[TextContent]:
    """Search a project reference document for matching text/regex snippets."""
    import re as _re

    project_id = args.get("project_id", "").strip()
    query = args.get("query", "").strip()

    if not project_id:
        return _result_text({"error": "project_id is required"})
    if not query:
        return _result_text({"error": "query is required"})
    if len(query) > 500:
        return _result_text({"error": "query exceeds maximum length of 500 characters"})

    is_regex = bool(args.get("regex", False))
    case_sensitive = bool(args.get("case_sensitive", False))
    context_lines = max(0, min(int(args.get("context_lines", 2)), 10))
    max_results = max(1, min(int(args.get("max_results", 20)), 100))
    section_filter = args.get("section")

    # Fetch reference document from S3
    s3_key = f"{S3_REFERENCE_PREFIX}/{project_id}.md"
    try:
        resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
        content = resp["Body"].read().decode("utf-8")
        last_modified = resp.get("LastModified")
        last_modified_str = (
            last_modified.strftime("%Y-%m-%dT%H:%M:%SZ") if last_modified else None
        )
    except Exception as exc:
        error_msg = str(exc)
        if "NoSuchKey" in error_msg or "404" in error_msg:
            return _result_text(
                _error_payload(
                    "NOT_FOUND",
                    f"Reference document not found for project: {project_id}",
                    details={"s3_key": s3_key},
                )
            )
        return _result_text(
            _error_payload("UPSTREAM_ERROR", f"S3 read failed: {exc}", retryable=True)
        )

    lines = content.splitlines()
    total_lines = len(lines)

    # Compile search pattern
    flags = 0 if case_sensitive else _re.IGNORECASE
    try:
        if is_regex:
            pattern = _re.compile(query, flags)
        else:
            pattern = _re.compile(_re.escape(query), flags)
    except _re.error as exc:
        return _result_text(
            _error_payload("INVALID_INPUT", f"Invalid regex pattern: {exc}")
        )

    # Compile optional section filter
    section_pat = None
    if section_filter:
        try:
            section_pat = _re.compile(section_filter, _re.IGNORECASE)
        except _re.error as exc:
            return _result_text(
                _error_payload("INVALID_INPUT", f"Invalid section filter pattern: {exc}")
            )

    # Build section index: list of (line_number, heading_text)
    section_index = []
    for idx, line in enumerate(lines, start=1):
        if _re.match(r"^#{1,6}\s+", line):
            section_index.append((idx, line.rstrip()))

    def _find_section(line_num: int):
        sec_line, sec_heading = 0, ""
        for sl, sh in section_index:
            if sl <= line_num:
                sec_line, sec_heading = sl, sh
            else:
                break
        return sec_line, sec_heading

    # Search
    snippets = []
    for idx, line in enumerate(lines):
        line_num = idx + 1
        matches = list(pattern.finditer(line))
        if not matches:
            continue

        sec_line, sec_heading = _find_section(line_num)
        if section_pat and not section_pat.search(sec_heading):
            continue

        ctx_start = max(0, idx - context_lines)
        ctx_end = min(total_lines, idx + context_lines + 1)

        snippets.append({
            "line_number": line_num,
            "section": sec_heading,
            "section_line": sec_line,
            "context_before": lines[ctx_start:idx],
            "matched_line": line,
            "context_after": lines[idx + 1 : ctx_end],
            "match_positions": [[m.start(), m.end()] for m in matches],
        })

        if len(snippets) >= max_results:
            break

    return _result_text({
        "success": True,
        "project_id": project_id,
        "query": query,
        "search_mode": "regex" if is_regex else "text",
        "match_count": len(snippets),
        "snippets": snippets,
        "document_info": {
            "total_lines": total_lines,
            "last_modified": last_modified_str,
            "s3_key": s3_key,
        },
    })


# --- Deployment ---


async def _deploy_state_get(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    result = _deploy_api_request("GET", f"/state/{project_id}")
    return _result_text(result)


async def _deploy_history(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    limit = args.get("limit", 10)
    result = _deploy_api_request("GET", f"/history/{project_id}", query={"limit": limit})
    return _result_text(result)


async def _deploy_submit(args: dict) -> list[TextContent]:
    """Submit a deployment request via deploy_intake API."""
    project_id = args["project_id"]
    change_type = args["change_type"]
    deployment_type = args["deployment_type"]
    summary = args["summary"]
    changes = args.get("changes", [])
    related_ids = args.get("related_record_ids") or []
    files_changed = args.get("files_changed") or []
    auto_trigger = bool(args.get("auto_trigger", True))
    submitted_by = str(args.get("submitted_by") or "mcp-server")
    github_config = args.get("github_config")
    non_ui_config = args.get("non_ui_config")

    # Validate change_type
    if change_type not in DEPLOY_CHANGE_TYPES:
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                f"Invalid change_type: {change_type!r}. Must be one of {DEPLOY_CHANGE_TYPES}",
                details={"field": "change_type"},
            )
        )
    if deployment_type not in DEPLOYMENT_TYPES:
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                f"Invalid deployment_type: {deployment_type!r}. Must be one of {DEPLOYMENT_TYPES}",
                details={"field": "deployment_type"},
            )
        )
    if not isinstance(changes, list) or not all(isinstance(c, str) for c in changes):
        return _result_text(_error_payload("INVALID_INPUT", "changes must be an array of strings"))
    if not isinstance(related_ids, list) or not all(isinstance(r, str) for r in related_ids):
        return _result_text(_error_payload("INVALID_INPUT", "related_record_ids must be an array of strings"))
    if not isinstance(files_changed, list) or not all(isinstance(f, str) for f in files_changed):
        return _result_text(_error_payload("INVALID_INPUT", "files_changed must be an array of strings"))

    is_non_ui = deployment_type not in GITHUB_DEPLOYMENT_TYPES
    if is_non_ui:
        if not isinstance(non_ui_config, dict):
            return _result_text(
                _error_payload(
                    "INVALID_INPUT",
                    "non_ui_config is required for non-UI deployment types",
                    details={"field": "non_ui_config"},
                )
            )
        expected_group = NON_UI_SERVICE_GROUP_BY_TYPE.get(deployment_type, "")
        service_group = str(non_ui_config.get("service_group") or "")
        target_arn = str(non_ui_config.get("target_arn") or "")
        if expected_group and service_group != expected_group:
            return _result_text(
                _error_payload(
                    "INVALID_INPUT",
                    f"non_ui_config.service_group must be '{expected_group}' for deployment_type '{deployment_type}'",
                    details={"field": "non_ui_config.service_group"},
                )
            )
        if not target_arn:
            return _result_text(
                _error_payload(
                    "INVALID_INPUT",
                    "non_ui_config.target_arn is required for non-UI deployment types",
                    details={"field": "non_ui_config.target_arn"},
                )
            )

    body: Dict[str, Any] = {
        "project_id": project_id,
        "change_type": change_type,
        "deployment_type": deployment_type,
        "summary": summary,
        "changes": changes,
        "related_record_ids": related_ids,
        "files_changed": files_changed,
        "auto_trigger": auto_trigger,
        "submitted_by": submitted_by,
    }
    if isinstance(github_config, dict):
        body["github_config"] = github_config
    if isinstance(non_ui_config, dict):
        body["non_ui_config"] = non_ui_config

    result = _deploy_api_request("POST", "/submit", payload=body)
    return _result_text(result)


async def _deploy_state_set(args: dict) -> list[TextContent]:
    """Set deployment state via deploy_intake API, governance-gated."""
    governance_error = _require_governance_hash_envelope(args)
    if governance_error:
        return _result_text(governance_error)

    project_id = args["project_id"]
    state = args["state"].upper()
    reason = args.get("reason")

    if state not in ("ACTIVE", "PAUSED"):
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                f"Invalid state: {state!r}. Must be ACTIVE or PAUSED.",
                details={"field": "state"},
            )
        )
    result = _deploy_api_request("PATCH", f"/state/{project_id}", payload={"state": state, "reason": reason})
    return _result_text(result)


async def _deploy_status(args: dict) -> list[TextContent]:
    """Get a specific deployment spec by its SPEC-ID."""
    project_id = args["project_id"]
    spec_id = args["spec_id"]
    result = _deploy_api_request("GET", f"/status/{spec_id}", query={"project": project_id})
    return _result_text(result)


async def _deploy_trigger(args: dict) -> list[TextContent]:
    """Manually trigger the deploy orchestration pipeline via SQS."""
    project_id = args["project_id"]

    try:
        queue_url = _get_deploy_queue_url()
        sqs = _get_sqs()
        body = json.dumps({
            "project_id": project_id,
            "trigger": "manual_mcp",
            "ts": _now_compact(),
        })
        resp = sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=body,
            MessageGroupId=project_id,
        )
        return _result_text({
            "success": True,
            "project_id": project_id,
            "sqs_message_id": resp.get("MessageId", ""),
            "triggered_at": _now_z(),
        })
    except Exception as exc:
        return _result_text(_error_payload("UPSTREAM_ERROR", f"Failed to send SQS trigger: {exc}", retryable=True))


async def _deploy_pending_requests(args: dict) -> list[TextContent]:
    """List all pending deployment requests for a project."""
    project_id = args["project_id"]
    ddb = _get_ddb()

    results = []
    kwargs: Dict[str, Any] = {
        "TableName": DEPLOY_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "FilterExpression": "#st = :pending",
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":prefix": _ser_s("request#"),
            ":pending": _ser_s("pending"),
        },
    }
    while True:
        resp = ddb.query(**kwargs)
        results.extend([_deser_item(i) for i in resp.get("Items", [])])
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    # Sort by submitted_at
    results.sort(key=lambda r: r.get("submitted_at", ""))
    summary = [
        {
            "request_id": r.get("request_id"),
            "change_type": r.get("change_type"),
            "summary": r.get("summary"),
            "submitted_at": r.get("submitted_at"),
            "submitted_by": r.get("submitted_by"),
        }
        for r in results
    ]
    return _result_text({"requests": summary, "count": len(summary), "project_id": project_id})


async def _deploy_status_get(args: dict) -> list[TextContent]:
    return await _deploy_status(args)


async def _deploy_history_list(args: dict) -> list[TextContent]:
    return await _deploy_history(args)


# --- Coordination ---


async def _coordination_capabilities(args: dict) -> list[TextContent]:
    """Fetch capabilities from the coordination API (public endpoint)."""
    try:
        url = f"{COORDINATION_API_BASE}/capabilities"
        req = urllib.request.Request(
            url=url,
            method="GET",
            headers=_json_headers(),
        )
        with _urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return _result_text(body)
    except Exception as exc:
        return _result_text({"error": f"Failed to fetch coordination capabilities: {exc}"})


async def _coordination_request_get(args: dict) -> list[TextContent]:
    """Get coordination request by ID from DynamoDB (direct read)."""
    request_id = args["request_id"]
    ddb = _get_ddb()

    resp = ddb.get_item(
        TableName=COORDINATION_TABLE,
        Key={"request_id": _ser_s(request_id)},
    )
    item = resp.get("Item")
    if not item:
        return _result_text({"error": f"Coordination request '{request_id}' not found"})
    return _result_text(_deser_item(item))


# --- Governance ---


async def _governance_hash(args: dict) -> list[TextContent]:
    h = _compute_governance_hash()
    return _result_text({"governance_hash": h, "computed_at": _now_z()})


# --- System ---


async def _connection_health(args: dict) -> list[TextContent]:
    health: Dict[str, str] = {}

    # DynamoDB
    try:
        ddb = _get_ddb()
        ddb.describe_table(TableName=TRACKER_TABLE)
        health["dynamodb"] = "ok"
    except Exception as exc:
        health["dynamodb"] = f"unreachable: {exc}"

    # S3
    try:
        s3 = _get_s3()
        s3.head_bucket(Bucket=S3_BUCKET)
        health["s3"] = "ok"
    except Exception as exc:
        health["s3"] = f"unreachable: {exc}"

    # Governance hash
    try:
        gov_hash = _compute_governance_hash()
        health["governance_hash"] = gov_hash
    except Exception as exc:
        health["governance_hash"] = f"error: {exc}"

    health["checked_at"] = _now_z()
    health["server_version"] = SERVER_VERSION
    return _result_text(health)


# --- Dispatch Plan Generation ---


async def _dispatch_plan_generate(args: dict) -> list[TextContent]:
    """Generate a dispatch-plan for a coordination request."""
    from dispatch_plan_generator import (
        QualityGateError,
        generate_dispatch_plan,
    )

    request_id = args["request_id"]
    override_plan = args.get("dispatch_plan_override")

    try:
        plan = generate_dispatch_plan(
            request_id=request_id,
            override_plan=override_plan,
        )
        return _result_text(plan)
    except QualityGateError as exc:
        return _result_text({
            "error": f"Quality gate failure: {exc}",
            "gate": exc.gate,
            "request_id": request_id,
        })
    except ValueError as exc:
        return _result_text({"error": str(exc), "request_id": request_id})


async def _dispatch_plan_dry_run(args: dict) -> list[TextContent]:
    """Generate a dispatch-plan preview without a real coordination request."""
    from dispatch_plan_generator import (
        PROVIDER_EXECUTION_MODES,
        build_dispatch_plan,
        compute_governance_hash,
        decompose_outcomes,
        estimate_duration,
        select_provider,
        should_decompose,
        test_connection_health,
        validate_dispatch_plan,
    )

    project_id = args["project_id"]
    outcomes = args["outcomes"]
    preferred_provider = args.get("preferred_provider")

    if not outcomes:
        return _result_text({"error": "No outcomes provided"})

    gov_hash = compute_governance_hash()
    conn_health = test_connection_health()

    provider, rationale = select_provider(
        outcomes, project_id,
        preferred_provider=preferred_provider,
        connection_health=conn_health,
    )
    needs_decomp, decomposition = should_decompose(outcomes, provider)

    if needs_decomp:
        groups = decompose_outcomes(outcomes, project_id, preferred_provider, conn_health)
        if len(groups) > 1:
            decomposition = "parallel"
    else:
        groups = [{
            "provider": provider,
            "execution_mode": PROVIDER_EXECUTION_MODES.get(provider, "preflight"),
            "outcomes": outcomes,
            "sequence_order": 0,
        }]

    estimated = estimate_duration(groups)

    import uuid
    plan = build_dispatch_plan(
        request_id="dry-run-" + str(uuid.uuid4())[:8],
        project_id=project_id,
        outcomes=outcomes,
        governance_hash=gov_hash,
        connection_health=conn_health,
        dispatch_groups=groups,
        rationale=rationale + " [DRY RUN — no coordination request loaded]",
        decomposition=decomposition,
        estimated_duration_minutes=estimated,
        related_record_ids=[],
        requestor_session_id=None,
    )

    try:
        warnings = validate_dispatch_plan(plan, outcomes)
        if warnings:
            plan["_validation_warnings"] = warnings
    except Exception as exc:
        plan["_validation_error"] = str(exc)

    plan["_dry_run"] = True
    return _result_text(plan)


# -------------------------------------------------------------------
# Handler dispatch map
# -------------------------------------------------------------------

_TOOL_HANDLERS = {
    "projects_list": _projects_list,
    "projects_get": _projects_get,
    "tracker_get": _tracker_get,
    "tracker_list": _tracker_list,
    "tracker_set": _tracker_set,
    "tracker_log": _tracker_log,
    "tracker_create": _tracker_create,
    "documents_search": _documents_search,
    "documents_get": _documents_get,
    "documents_list": _documents_list,
    "documents_put": _documents_put,
    "documents_patch": _documents_patch,
    "reference_search": _reference_search,
    "deploy_state_get": _deploy_state_get,
    "deploy_history": _deploy_history,
    "deploy_history_list": _deploy_history_list,
    "deploy_submit": _deploy_submit,
    "deploy_state_set": _deploy_state_set,
    "deploy_status": _deploy_status,
    "deploy_status_get": _deploy_status_get,
    "deploy_trigger": _deploy_trigger,
    "deploy_pending_requests": _deploy_pending_requests,
    "coordination_capabilities": _coordination_capabilities,
    "coordination_request_get": _coordination_request_get,
    "governance_hash": _governance_hash,
    "connection_health": _connection_health,
    "dispatch_plan_generate": _dispatch_plan_generate,
    "dispatch_plan_dry_run": _dispatch_plan_dry_run,
}


# ===================================================================
# ENTRY POINT
# ===================================================================


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    logger.info("[START] Enceladus MCP Server v%s", SERVER_VERSION)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
