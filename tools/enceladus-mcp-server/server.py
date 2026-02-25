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
import re
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
# SSL context for HTTPS requests (macOS Python may lack default CA bundle)
# ---------------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext:
    """Build an SSL context with proper CA certificates.

    Python framework installs on macOS often lack the default CA bundle at
    /Library/Frameworks/Python.framework/.../cert.pem. If SSL_CERT_FILE env
    var is not set, fall back to certifi's CA bundle if available.
    """
    # If SSL_CERT_FILE is explicitly set, default context will use it
    if os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context()

    # Check if default OpenSSL CA paths exist
    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return ssl.create_default_context()

    # Default CA bundle missing — try certifi
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        # Last resort: return default context (may fail on verify)
        return ssl.create_default_context()


_SSL_CTX = _build_ssl_context()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("ENCELADUS_TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("ENCELADUS_PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("ENCELADUS_DOCUMENTS_TABLE", "documents")
COORDINATION_TABLE = os.environ.get("ENCELADUS_COORDINATION_TABLE", "coordination-requests")
DEPLOY_TABLE = os.environ.get("ENCELADUS_DEPLOY_TABLE", "devops-deployment-manager")
GOVERNANCE_POLICIES_TABLE = os.environ.get(
    "ENCELADUS_GOVERNANCE_POLICIES_TABLE",
    "governance-policies",
)
AGENT_COMPLIANCE_TABLE = os.environ.get(
    "ENCELADUS_AGENT_COMPLIANCE_TABLE",
    "agent-compliance-violations",
)
DOCUMENT_STORAGE_POLICY_ID = os.environ.get(
    "ENCELADUS_DOCUMENT_STORAGE_POLICY_ID",
    "document_storage_cloud_only",
)
COMPLIANCE_ENFORCEMENT_DEFAULT = os.environ.get(
    "ENCELADUS_COMPLIANCE_ENFORCEMENT_DEFAULT",
    "enforce",
).strip().lower()
AWS_REGION = os.environ.get("ENCELADUS_REGION", "us-west-2")
S3_BUCKET = os.environ.get("ENCELADUS_S3_BUCKET", "jreese-net")
S3_REFERENCE_PREFIX = os.environ.get("ENCELADUS_S3_REFERENCE_PREFIX", "mobile/v1/reference")
S3_DOCUMENTS_PREFIX = os.environ.get("ENCELADUS_S3_DOCUMENTS_PREFIX", "agent-documents")
GOVERNANCE_PROJECT_ID = os.environ.get("ENCELADUS_GOVERNANCE_PROJECT_ID", "devops")
GOVERNANCE_KEYWORD = os.environ.get("ENCELADUS_GOVERNANCE_KEYWORD", "governance-file")
GOVERNANCE_CATALOG_TTL_SECONDS = int(os.environ.get("ENCELADUS_GOVERNANCE_CATALOG_TTL_SECONDS", "300"))
S3_GOVERNANCE_PREFIX = os.environ.get("ENCELADUS_S3_GOVERNANCE_PREFIX", "governance/live")
S3_GOVERNANCE_HISTORY_PREFIX = os.environ.get("ENCELADUS_S3_GOVERNANCE_HISTORY_PREFIX", "governance/history")

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
DEPLOY_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", ""),
)
DEPLOY_QUEUE_NAME = os.environ.get("ENCELADUS_DEPLOY_QUEUE", "devops-deploy-queue.fifo")
DEPLOY_CONFIG_BUCKET = os.environ.get("ENCELADUS_DEPLOY_CONFIG_BUCKET", "jreese-net")
DEPLOY_CONFIG_PREFIX = os.environ.get("ENCELADUS_DEPLOY_CONFIG_PREFIX", "deploy-config")
DEPLOY_CHANGE_TYPES = ("patch", "minor", "major")
DOCUMENT_ALLOWED_FILE_EXTENSIONS = (".md", ".markdown")
DOCUMENT_MAX_TITLE_LENGTH = int(os.environ.get("ENCELADUS_DOCUMENT_MAX_TITLE_LENGTH", "500"))
DOCUMENT_MAX_DESCRIPTION_LENGTH = int(
    os.environ.get("ENCELADUS_DOCUMENT_MAX_DESCRIPTION_LENGTH", "5000")
)
DOCUMENT_MAX_CONTENT_SIZE_BYTES = int(
    os.environ.get("ENCELADUS_DOCUMENT_MAX_CONTENT_BYTES", "1048576")
)
DOCUMENT_MAX_KEYWORDS = int(os.environ.get("ENCELADUS_DOCUMENT_MAX_KEYWORDS", "50"))
DOCUMENT_MAX_RELATED_ITEMS = int(
    os.environ.get("ENCELADUS_DOCUMENT_MAX_RELATED_ITEMS", "100")
)
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
SERVER_VERSION = "0.4.1"
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


# Record-ID to DynamoDB key mapping (mirrors tracker.py item_key logic)
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature"}
_PREFIX_MAP_CACHE: Optional[Dict[str, str]] = None
_DEFAULT_STATUS_BY_TYPE = {"task": "open", "issue": "open", "feature": "planned"}
_RELATION_ID_FIELDS = {
    "related_task_ids",
    "related_issue_ids",
    "related_feature_ids",
}
_RELATION_FIELDS = set(_RELATION_ID_FIELDS) | {"depends_on"}
_DEPENDENCY_TYPES = ("task", "issue", "feature")
_SINGLE_CHAR_TOKEN_RE = re.compile(r"^[A-Za-z0-9,\-\s]$")
_COORDINATION_REQUEST_ID_RE = re.compile(r"^(CRQ|DSP)-[A-Z0-9-]{3,64}$", re.IGNORECASE)
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


def _is_s3_not_found_error(exc: Exception) -> bool:
    """Return True when an S3 exception represents a missing object."""
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", "")).strip()
        if code in {"NoSuchKey", "NotFound", "404"}:
            return True
        status = str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "")).strip()
        if status == "404":
            return True

    msg = str(exc)
    return (
        "NoSuchKey" in msg
        or "NotFound" in msg
        or "404" in msg
    )


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _looks_char_split(value: Any) -> bool:
    if not isinstance(value, list) or len(value) < 6:
        return False
    return all(
        isinstance(part, str)
        and len(part) == 1
        and bool(_SINGLE_CHAR_TOKEN_RE.match(part))
        for part in value
    )


def _try_parse_json_container(raw: str) -> Optional[Any]:
    text = raw.strip()
    if len(text) < 2:
        return None
    if not ((text[0] == "[" and text[-1] == "]") or (text[0] == "{" and text[-1] == "}")):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _coerce_relation_id_list(value: Any, field_name: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        parsed = _try_parse_json_container(text)
        if parsed is not None:
            return _coerce_relation_id_list(parsed, field_name)
        return _dedupe_preserve_order(
            [token.strip().upper() for token in text.split(",") if token.strip()]
        )
    if isinstance(value, (tuple, set)):
        value = list(value)
    if isinstance(value, list):
        if _looks_char_split(value):
            return _coerce_relation_id_list("".join(value), field_name)
        out: List[str] = []
        for entry in value:
            if entry is None:
                continue
            if not isinstance(entry, str):
                raise ValueError(
                    f"{field_name} expects relation IDs as strings; got {type(entry).__name__}"
                )
            text = entry.strip()
            if not text:
                continue
            parsed = _try_parse_json_container(text)
            if parsed is not None:
                out.extend(_coerce_relation_id_list(parsed, field_name))
                continue
            out.extend(token.strip().upper() for token in text.split(",") if token.strip())
        return _dedupe_preserve_order(out)
    raise ValueError(f"{field_name} must be a string or list of strings")


def _normalize_depends_on(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        parsed = _try_parse_json_container(text)
        if parsed is not None:
            return _normalize_depends_on(parsed)
        value = _coerce_relation_id_list(text, "depends_on")

    if isinstance(value, (tuple, set)):
        value = list(value)

    if isinstance(value, list):
        if _looks_char_split(value):
            return _normalize_depends_on("".join(value))

        grouped: Dict[str, List[str]] = {rtype: [] for rtype in _DEPENDENCY_TYPES}
        unknown: List[str] = []

        for entry in value:
            if entry is None:
                continue
            if isinstance(entry, dict):
                dep_type = str(entry.get("type", "")).strip().lower()
                if dep_type not in _DEPENDENCY_TYPES:
                    raise ValueError(
                        "depends_on object entries must include type in {task, issue, feature}"
                    )
                dep_ids = _coerce_relation_id_list(entry.get("ids"), "depends_on")
                if dep_ids:
                    grouped[dep_type].extend(dep_ids)
                continue
            if isinstance(entry, (str, list, tuple, set)):
                dep_ids = _coerce_relation_id_list(entry, "depends_on")
                for rid in dep_ids:
                    parts = rid.split("-")
                    rtype = _ID_SEGMENT_TO_TYPE.get(parts[1]) if len(parts) >= 3 else None
                    if rtype:
                        grouped[rtype].append(rid)
                    else:
                        unknown.append(rid)
                continue
            raise ValueError(
                f"depends_on entries must be strings or {{type, ids}} objects; got {type(entry).__name__}"
            )

        out: List[Any] = []
        for dep_type in _DEPENDENCY_TYPES:
            dep_ids = _dedupe_preserve_order(grouped[dep_type])
            if dep_ids:
                out.append({"type": dep_type, "ids": dep_ids})
        out.extend(_dedupe_preserve_order(unknown))
        return out

    raise ValueError("depends_on must be a string, list, or object list")


def _normalize_relation_field(field: str, value: Any) -> Any:
    if field in _RELATION_ID_FIELDS:
        return _coerce_relation_id_list(value, field)
    if field == "depends_on":
        return _normalize_depends_on(value)
    return value


def _field_value_for_note(value: Any, max_len: int = 220) -> str:
    if isinstance(value, (list, dict)):
        rendered = json.dumps(value, separators=(", ", ": "))
    else:
        rendered = str(value)
    if len(rendered) <= max_len:
        return rendered
    return rendered[: max_len - 3] + "..."


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


def _normalize_optional_bool(value: Any, field_name: str) -> Optional[bool]:
    """Normalize optional bool-like values."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "t", "1", "yes", "y", "on"}:
            return True
        if text in {"false", "f", "0", "no", "n", "off"}:
            return False
    raise ValueError(f"{field_name} must be a boolean.")


def _normalize_coordination_request_id(value: Any) -> str:
    """Normalize coordination or dispatch request identifiers."""
    if value is None:
        return ""
    text = str(value).strip().upper()
    if not text:
        return ""
    if not _COORDINATION_REQUEST_ID_RE.fullmatch(text):
        raise ValueError(
            "coordination_request_id must match CRQ-* or DSP-* "
            "with only uppercase letters, numbers, or hyphens."
        )
    return text


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


def _build_write_source(args: dict) -> Dict[str, Any]:
    """Build a structured write_source map for DynamoDB attribution.

    Stamps every MCP server write with channel + optional provider context,
    enabling downstream anomaly detection (ENC-ISS-009 Phase 0B).
    """
    return {
        "M": {
            "channel": _ser_s("mcp_server"),
            "provider": _ser_s(str(args.get("provider") or "")),
            "dispatch_id": _ser_s(str(args.get("dispatch_id") or "")),
            "coordination_request_id": _ser_s(
                str(args.get("coordination_request_id") or "")
            ),
            "timestamp": _ser_s(_now_z()),
        }
    }


def _write_source_note_suffix(args: dict) -> str:
    """Build an optional suffix for last_update_note with provider context."""
    provider = str(args.get("provider") or "")
    dispatch_id = str(args.get("dispatch_id") or "")
    parts = []
    if provider:
        parts.append(f"provider={provider}")
    if dispatch_id:
        parts.append(f"dispatch={dispatch_id}")
    return f" [{', '.join(parts)}]" if parts else ""


def _validate_session_ownership(
    existing_item: Dict[str, Any],
    args: dict,
    record_id: str,
) -> Optional[Dict[str, Any]]:
    """Validate caller has session ownership for writes to checked-out records.

    ENC-ISS-009 Phase 3A: When a task has active_agent_session=true, only the
    agent identified by active_agent_session_id may write to it. The caller
    identity is matched against both ``provider`` and ``dispatch_id`` args —
    dispatched sessions check out via dispatch_id, so either field matching
    the owning agent is sufficient.

    Returns an error payload if validation fails, None if the write is allowed.
    """
    item_data = _deser_item(existing_item)
    if not item_data.get("active_agent_session"):
        return None  # Not checked out — any caller can write

    owning_agent = str(item_data.get("active_agent_session_id") or "").strip()
    caller_provider = str(args.get("provider") or "").strip()
    caller_dispatch = str(args.get("dispatch_id") or "").strip()

    if not caller_provider and not caller_dispatch:
        return _error_payload(
            "SESSION_WRITE_REJECTED",
            f"Record '{record_id}' is checked out by agent '{owning_agent}'. "
            "You must provide your agent identity via the 'provider' or "
            "'dispatch_id' parameter to write to a checked-out record.",
        )

    # Match on either provider or dispatch_id
    if caller_provider == owning_agent or caller_dispatch == owning_agent:
        return None  # Caller matches session owner — write allowed

    caller_label = caller_provider or caller_dispatch
    return _error_payload(
        "SESSION_WRITE_REJECTED",
        f"Record '{record_id}' is checked out by agent '{owning_agent}', "
        f"but caller identifies as '{caller_label}'. Only the owning agent "
        "may write to a checked-out record.",
        retryable=True,
    )


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
    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if DEPLOY_API_INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = DEPLOY_API_INTERNAL_API_KEY
    if DEPLOY_API_COOKIE:
        headers["Cookie"] = DEPLOY_API_COOKIE
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=20, context=_SSL_CTX) as resp:
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


def _is_authentication_required_error(payload: Dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False

    code = ""
    message = ""
    error_obj = payload.get("error")
    if isinstance(error_obj, dict):
        code = str(error_obj.get("code") or "").strip().upper()
        message = str(error_obj.get("message") or "")
    elif isinstance(error_obj, str):
        message = error_obj

    envelope = payload.get("error_envelope")
    if isinstance(envelope, dict):
        if not code:
            code = str(envelope.get("code") or "").strip().upper()
        if not message:
            message = str(envelope.get("message") or "")

    return code == "PERMISSION_DENIED" and "authentication required" in message.lower()


def _deploy_state_get_direct(project_id: str) -> Dict[str, Any]:
    key = f"{DEPLOY_CONFIG_PREFIX}/{project_id}/state.json"
    try:
        s3 = _get_s3()
        resp = s3.get_object(Bucket=DEPLOY_CONFIG_BUCKET, Key=key)
        payload = json.loads(resp["Body"].read().decode("utf-8"))
        if not isinstance(payload, dict):
            payload = {}
        return {"success": True, "project_id": project_id, **payload}
    except ClientError as exc:
        code = (exc.response or {}).get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "404", "NotFound"}:
            return {
                "success": True,
                "project_id": project_id,
                "state": "ACTIVE",
                "updated_at": None,
                "updated_by": "default",
                "reason": None,
            }
        return _error_payload(
            "UPSTREAM_ERROR",
            f"Failed to read deployment state directly: {exc}",
            retryable=True,
        )
    except Exception as exc:
        return _error_payload(
            "INTERNAL_ERROR",
            f"Failed to read deployment state directly: {exc}",
            retryable=False,
        )


def _deploy_history_direct(project_id: str, limit: int = 10) -> Dict[str, Any]:
    ddb = _get_ddb()
    results: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "TableName": DEPLOY_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":prefix": _ser_s("deploy#"),
        },
        "ScanIndexForward": False,
    }
    try:
        while True:
            resp = ddb.query(**kwargs)
            results.extend([_deser_item(item) for item in resp.get("Items", [])])
            if len(results) >= limit or "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    except Exception as exc:
        return _error_payload(
            "UPSTREAM_ERROR",
            f"Failed to read deployment history directly: {exc}",
            retryable=True,
        )
    results.sort(key=lambda r: r.get("deployed_at", ""), reverse=True)
    return {"success": True, "project_id": project_id, "deployments": results[:limit]}


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

    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if DOCUMENT_API_INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = DOCUMENT_API_INTERNAL_API_KEY
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None

    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=20, context=_SSL_CTX) as resp:
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


def _is_allowed_document_file_name(file_name: str) -> bool:
    name = str(file_name or "").strip()
    if not name:
        return False
    if "/" in name or "\\" in name:
        return False
    lowered = name.lower()
    return any(lowered.endswith(ext) for ext in DOCUMENT_ALLOWED_FILE_EXTENSIONS)


def _normalize_document_string_list(
    value: Any,
    *,
    field_name: str,
    max_items: int,
    lower: bool = False,
) -> tuple[Optional[List[str]], Optional[Dict[str, Any]]]:
    if value is None:
        return [], None
    if not isinstance(value, list):
        return None, _error_payload(
            "INVALID_INPUT",
            f"Field '{field_name}' must be an array of strings.",
            retryable=False,
        )
    normalized: List[str] = []
    for raw in value[:max_items]:
        token = str(raw).strip()
        if not token:
            continue
        normalized.append(token.lower() if lower else token)
    return normalized, None


def _project_exists(project_id: str) -> tuple[bool, Optional[Dict[str, Any]]]:
    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": _ser_s(project_id)},
            ProjectionExpression="project_id",
        )
    except Exception as exc:
        return False, _error_payload(
            "UPSTREAM_ERROR",
            f"Project lookup failed: {exc}",
            retryable=True,
        )
    return bool(resp.get("Item")), None


def _document_put_direct(payload: Dict[str, Any]) -> Dict[str, Any]:
    project_id = str(payload.get("project_id") or "").strip()
    title = str(payload.get("title") or "").strip()
    content = payload.get("content")

    if not project_id:
        return _error_payload("INVALID_INPUT", "Field 'project_id' is required.", retryable=False)
    if not title:
        return _error_payload("INVALID_INPUT", "Field 'title' is required.", retryable=False)
    if len(title) > DOCUMENT_MAX_TITLE_LENGTH:
        return _error_payload(
            "INVALID_INPUT",
            f"Title exceeds {DOCUMENT_MAX_TITLE_LENGTH} characters.",
            retryable=False,
        )
    if content is None or not isinstance(content, str) or not content:
        return _error_payload(
            "INVALID_INPUT",
            "Field 'content' is required (document body).",
            retryable=False,
        )
    content_bytes = content.encode("utf-8")
    if len(content_bytes) > DOCUMENT_MAX_CONTENT_SIZE_BYTES:
        return _error_payload(
            "INVALID_INPUT",
            f"Content exceeds {DOCUMENT_MAX_CONTENT_SIZE_BYTES} bytes.",
            retryable=False,
        )

    project_ok, project_error = _project_exists(project_id)
    if project_error:
        return project_error
    if not project_ok:
        return _error_payload(
            "NOT_FOUND",
            f"Project '{project_id}' is not registered.",
            retryable=False,
        )

    description = str(payload.get("description") or "").strip()[:DOCUMENT_MAX_DESCRIPTION_LENGTH]
    file_name = str(payload.get("file_name") or "").strip()
    if file_name and not _is_allowed_document_file_name(file_name):
        return _error_payload(
            "INVALID_INPUT",
            "file_name must end with .md or .markdown and include no path separators.",
            retryable=False,
        )

    related_items, rel_error = _normalize_document_string_list(
        payload.get("related_items"),
        field_name="related_items",
        max_items=DOCUMENT_MAX_RELATED_ITEMS,
        lower=False,
    )
    if rel_error:
        return rel_error
    keywords, kw_error = _normalize_document_string_list(
        payload.get("keywords"),
        field_name="keywords",
        max_items=DOCUMENT_MAX_KEYWORDS,
        lower=True,
    )
    if kw_error:
        return kw_error

    document_id = f"DOC-{uuid.uuid4().hex[:12].upper()}"
    now = _now_z()
    s3_key = f"{S3_DOCUMENTS_PREFIX}/{project_id}/{document_id}.md"
    content_hash = hashlib.sha256(content_bytes).hexdigest()

    s3 = _get_s3()
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=content_bytes,
            ContentType="text/markdown; charset=utf-8",
        )
    except Exception as exc:
        return _error_payload(
            "UPSTREAM_ERROR",
            f"Failed to store document content: {exc}",
            retryable=True,
        )

    item = {
        "document_id": _ser_s(document_id),
        "project_id": _ser_s(project_id),
        "title": _ser_s(title),
        "description": _ser_s(description),
        "file_name": _ser_s(file_name or f"{document_id}.md"),
        "s3_bucket": _ser_s(S3_BUCKET),
        "s3_key": _ser_s(s3_key),
        "content_type": _ser_s("text/markdown"),
        "content_hash": _ser_s(content_hash),
        "size_bytes": {"N": str(len(content_bytes))},
        "related_items": _ser_value(related_items or []),
        "keywords": _ser_value(keywords or []),
        "created_by": _ser_s("mcp-server-direct-fallback"),
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "status": _ser_s("active"),
        "version": {"N": "1"},
    }

    ddb = _get_ddb()
    try:
        ddb.put_item(
            TableName=DOCUMENTS_TABLE,
            Item=item,
            ConditionExpression="attribute_not_exists(document_id)",
        )
    except Exception as exc:
        try:
            s3.delete_object(Bucket=S3_BUCKET, Key=s3_key)
        except Exception:
            pass
        return _error_payload(
            "UPSTREAM_ERROR",
            f"Failed to save document metadata: {exc}",
            retryable=True,
        )

    return {
        "success": True,
        "document_id": document_id,
        "s3_location": f"s3://{S3_BUCKET}/{s3_key}",
        "content_hash": content_hash,
        "size_bytes": len(content_bytes),
        "created_at": now,
        "write_mode": "direct_fallback",
    }


def _document_patch_direct(document_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    doc_id = str(document_id or "").strip()
    if not doc_id:
        return _error_payload("INVALID_INPUT", "document_id is required", retryable=False)

    ddb = _get_ddb()
    try:
        existing_resp = ddb.get_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": _ser_s(doc_id)},
            ConsistentRead=True,
        )
    except Exception as exc:
        return _error_payload("UPSTREAM_ERROR", f"Database read failed: {exc}", retryable=True)
    existing_item = existing_resp.get("Item")
    if not existing_item:
        return _error_payload("NOT_FOUND", f"Document not found: {doc_id}", retryable=False)

    existing = _deser_item(existing_item)
    project_id = str(existing.get("project_id") or "").strip()
    if not project_id:
        return _error_payload(
            "UPSTREAM_ERROR",
            f"Document '{doc_id}' has no project_id metadata.",
            retryable=False,
        )

    now = _now_z()
    current_version = int(existing.get("version") or 0)
    expr_parts = ["updated_at = :ts", "#ver = if_not_exists(#ver, :zero) + :one"]
    attr_names: Dict[str, str] = {"#ver": "version"}
    attr_values: Dict[str, Any] = {
        ":ts": _ser_s(now),
        ":one": {"N": "1"},
        ":zero": {"N": "0"},
    }

    if "title" in payload:
        title = str(payload.get("title") or "").strip()
        if not title:
            return _error_payload(
                "INVALID_INPUT",
                f"Title must be 1-{DOCUMENT_MAX_TITLE_LENGTH} characters.",
                retryable=False,
            )
        if len(title) > DOCUMENT_MAX_TITLE_LENGTH:
            return _error_payload(
                "INVALID_INPUT",
                f"Title must be 1-{DOCUMENT_MAX_TITLE_LENGTH} characters.",
                retryable=False,
            )
        expr_parts.append("title = :title")
        attr_values[":title"] = _ser_s(title)

    if "description" in payload:
        expr_parts.append("description = :desc")
        attr_values[":desc"] = _ser_s(
            str(payload.get("description") or "").strip()[:DOCUMENT_MAX_DESCRIPTION_LENGTH]
        )

    if "related_items" in payload:
        related_items, rel_error = _normalize_document_string_list(
            payload.get("related_items"),
            field_name="related_items",
            max_items=DOCUMENT_MAX_RELATED_ITEMS,
            lower=False,
        )
        if rel_error:
            return rel_error
        expr_parts.append("related_items = :ri")
        attr_values[":ri"] = _ser_value(related_items or [])

    if "keywords" in payload:
        keywords, kw_error = _normalize_document_string_list(
            payload.get("keywords"),
            field_name="keywords",
            max_items=DOCUMENT_MAX_KEYWORDS,
            lower=True,
        )
        if kw_error:
            return kw_error
        expr_parts.append("keywords = :kw")
        attr_values[":kw"] = _ser_value(keywords or [])

    if "status" in payload:
        status = str(payload.get("status") or "").strip().lower()
        if status not in {"active", "archived"}:
            return _error_payload(
                "INVALID_INPUT",
                "Status must be 'active' or 'archived'.",
                retryable=False,
            )
        expr_parts.append("#status = :status")
        attr_names["#status"] = "status"
        attr_values[":status"] = _ser_s(status)

    if "file_name" in payload:
        file_name = str(payload.get("file_name") or "").strip()
        if not _is_allowed_document_file_name(file_name):
            return _error_payload(
                "INVALID_INPUT",
                "file_name must end with .md or .markdown and include no path separators.",
                retryable=False,
            )
        expr_parts.append("file_name = :file_name")
        attr_values[":file_name"] = _ser_s(file_name)

    if "content" in payload:
        content = payload.get("content")
        if content is None or not isinstance(content, str) or not content:
            return _error_payload(
                "INVALID_INPUT",
                "Field 'content' must be a non-empty string.",
                retryable=False,
            )
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > DOCUMENT_MAX_CONTENT_SIZE_BYTES:
            return _error_payload(
                "INVALID_INPUT",
                f"Content must be 1-{DOCUMENT_MAX_CONTENT_SIZE_BYTES} bytes.",
                retryable=False,
            )
        s3_key = str(existing.get("s3_key") or f"{S3_DOCUMENTS_PREFIX}/{project_id}/{doc_id}.md")
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        try:
            _get_s3().put_object(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Body=content_bytes,
                ContentType="text/markdown; charset=utf-8",
            )
        except Exception as exc:
            return _error_payload(
                "UPSTREAM_ERROR",
                f"Failed to update document content: {exc}",
                retryable=True,
            )
        expr_parts.extend(["content_hash = :hash", "size_bytes = :size", "s3_key = :s3k"])
        attr_values[":hash"] = _ser_s(content_hash)
        attr_values[":size"] = {"N": str(len(content_bytes))}
        attr_values[":s3k"] = _ser_s(s3_key)

    update_expr = "SET " + ", ".join(expr_parts)
    try:
        ddb.update_item(
            TableName=DOCUMENTS_TABLE,
            Key={"document_id": _ser_s(doc_id)},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
        )
    except Exception as exc:
        return _error_payload("UPSTREAM_ERROR", f"Database write failed: {exc}", retryable=True)

    return {
        "success": True,
        "document_id": doc_id,
        "updated_at": now,
        "version": current_version + 1,
        "write_mode": "direct_fallback",
    }


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


def _governance_catalog_from_s3() -> Dict[str, Dict[str, Any]]:
    """Build governance catalog from deterministic S3 prefix (ENC-TSK-474).

    Lists objects under ``S3_GOVERNANCE_PREFIX`` and derives governance URIs
    from S3 key structure.  Content hash is SHA-256 of raw file content,
    matching the hash algorithm used by docstore uploads.
    """
    try:
        s3 = _get_s3()
        prefix = S3_GOVERNANCE_PREFIX.rstrip("/") + "/"
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
        objects = list(resp.get("Contents", []))
        while resp.get("IsTruncated"):
            resp = s3.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=prefix,
                ContinuationToken=resp["NextContinuationToken"],
            )
            objects.extend(resp.get("Contents", []))
    except Exception as exc:
        logger.warning("S3 governance listing failed: %s", exc)
        return {}

    catalog: Dict[str, Dict[str, Any]] = {}
    for obj in objects:
        s3_key = obj["Key"]
        rel_path = s3_key[len(prefix):]
        if not rel_path or rel_path.endswith("/"):
            continue

        uri = _governance_uri_from_file_name(rel_path)
        if not uri:
            continue

        try:
            content_resp = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
            content = content_resp["Body"].read()
            content_hash = hashlib.sha256(content).hexdigest()
        except Exception as exc:
            logger.warning("Failed to read governance file s3://%s/%s: %s", S3_BUCKET, s3_key, exc)
            continue

        last_modified = obj.get("LastModified")
        updated_at = last_modified.isoformat() if hasattr(last_modified, "isoformat") else str(last_modified or "")

        catalog[uri] = {
            "file_name": rel_path,
            "s3_bucket": S3_BUCKET,
            "s3_key": s3_key,
            "content_hash": content_hash,
            "updated_at": updated_at,
        }

    return catalog


def _governance_catalog_from_docstore() -> Dict[str, Dict[str, Any]]:
    """Legacy: build governance catalog from docstore DynamoDB scan.

    Falls back to querying all documents in ``GOVERNANCE_PROJECT_ID`` and
    filtering by ``GOVERNANCE_KEYWORD``.  Retained for backwards compatibility
    before governance files are migrated to the deterministic S3 prefix.
    """
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
        logger.warning("governance catalog docstore query failed: %s", exc)
        return {}

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

    return catalog


def _governance_catalog(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """Build governance catalog with two-tier resolution (ENC-TSK-474).

    Primary: deterministic S3 prefix (``governance/live/``).
    Fallback: legacy docstore DynamoDB scan (``GOVERNANCE_PROJECT_ID``).
    """
    global _governance_catalog_cache, _governance_catalog_cached_at

    now = time.time()
    if (
        not force_refresh
        and _governance_catalog_cache
        and (now - _governance_catalog_cached_at) < GOVERNANCE_CATALOG_TTL_SECONDS
    ):
        return _governance_catalog_cache

    catalog = _governance_catalog_from_s3()

    if not catalog:
        logger.warning(
            "No governance files at s3://%s/%s/ — falling back to docstore scan. "
            "Migrate governance files to the deterministic S3 path.",
            S3_BUCKET,
            S3_GOVERNANCE_PREFIX,
        )
        catalog = _governance_catalog_from_docstore()

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


def _default_document_storage_policy() -> Dict[str, Any]:
    """Fallback policy when governance-policies table is unavailable."""
    return {
        "policy_id": DOCUMENT_STORAGE_POLICY_ID,
        "status": "active",
        "enforcement_mode": COMPLIANCE_ENFORCEMENT_DEFAULT or "enforce",
        "allowed_targets": ["docstore_api", "governance_s3", "mcp_validator", "bedrock_action"],
        "forbidden_path_prefixes": ["/", "~/", "../", "./", "\\\\", "C:\\"],
    }


def _load_document_storage_policy(policy_id: str = DOCUMENT_STORAGE_POLICY_ID) -> Dict[str, Any]:
    fallback = _default_document_storage_policy()
    fallback["policy_source"] = "default"
    fallback["policy_id"] = policy_id or DOCUMENT_STORAGE_POLICY_ID
    try:
        resp = _get_ddb().get_item(
            TableName=GOVERNANCE_POLICIES_TABLE,
            Key={"policy_id": _ser_s(fallback["policy_id"])},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return fallback
        loaded = _deser_item(item)
        if not isinstance(loaded, dict):
            return fallback
        loaded.setdefault("policy_id", fallback["policy_id"])
        loaded.setdefault("status", "active")
        loaded.setdefault("enforcement_mode", COMPLIANCE_ENFORCEMENT_DEFAULT or "enforce")
        loaded.setdefault("allowed_targets", fallback["allowed_targets"])
        loaded["policy_source"] = "dynamodb"
        return loaded
    except Exception as exc:
        logger.warning(
            "[POLICY] Failed to load policy '%s' from %s: %s",
            fallback["policy_id"],
            GOVERNANCE_POLICIES_TABLE,
            exc,
        )
        return fallback


def _looks_like_local_path(path_value: str) -> bool:
    text = str(path_value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if lowered.startswith(("/", "~/", "../", "./", "\\\\")):
        return True
    return bool(re.match(r"^[a-z]:[\\/]", lowered))


def _evaluate_document_policy(
    *,
    operation: str,
    storage_target: str,
    args: Dict[str, Any],
    policy_id: str = DOCUMENT_STORAGE_POLICY_ID,
) -> Dict[str, Any]:
    policy = _load_document_storage_policy(policy_id)
    allowed_targets_raw = policy.get("allowed_targets")
    if isinstance(allowed_targets_raw, list):
        allowed_targets = {
            str(entry).strip().lower()
            for entry in allowed_targets_raw
            if str(entry).strip()
        }
    else:
        allowed_targets = set()
    if not allowed_targets:
        allowed_targets = {"docstore_api", "governance_s3", "mcp_validator", "bedrock_action"}

    operation_name = str(operation or "").strip().lower() or "unknown_operation"
    target_name = str(storage_target or "").strip().lower() or "unknown_target"
    policy_status = str(policy.get("status") or "active").strip().lower()
    enforcement_mode = str(policy.get("enforcement_mode") or COMPLIANCE_ENFORCEMENT_DEFAULT or "enforce").strip().lower()

    reasons: List[str] = []

    if policy_status != "active":
        reasons.append(f"policy status={policy_status} (enforcement skipped)")
    if target_name not in allowed_targets:
        reasons.append(f"storage_target '{target_name}' is not allowlisted")

    suspicious_fields: Dict[str, str] = {}
    for field in ("file_name", "path", "output_path", "local_path", "target_path", "destination"):
        if field not in args:
            continue
        raw = str(args.get(field) or "").strip()
        if not raw:
            continue
        if _looks_like_local_path(raw):
            suspicious_fields[field] = raw

    if suspicious_fields:
        fields = ", ".join(f"{key}={value}" for key, value in suspicious_fields.items())
        reasons.append(f"local filesystem path detected ({fields})")

    if operation_name.startswith("documents_"):
        file_name = str(args.get("file_name") or "").strip()
        if file_name and ("/" in file_name or "\\" in file_name):
            reasons.append("documents_* file_name must be basename only (no path segments)")

    should_enforce = policy_status == "active" and enforcement_mode == "enforce"
    denied = should_enforce and bool(reasons)
    decision = "denied" if denied else "allowed"

    return {
        "success": True,
        "policy_id": str(policy.get("policy_id") or policy_id or DOCUMENT_STORAGE_POLICY_ID),
        "policy_source": str(policy.get("policy_source") or "unknown"),
        "policy_status": policy_status,
        "enforcement_mode": enforcement_mode,
        "operation": operation_name,
        "storage_target": target_name,
        "allowed_targets": sorted(allowed_targets),
        "decision": decision,
        "allowed": not denied,
        "reasons": reasons,
        "checked_at": _now_z(),
    }


def _record_compliance_event(
    *,
    evaluation: Dict[str, Any],
    args: Dict[str, Any],
) -> None:
    event_id = f"CMP-{uuid.uuid4().hex[:20].upper()}"
    now = _now_z()
    epoch = int(time.time())
    details = {
        "operation": evaluation.get("operation"),
        "storage_target": evaluation.get("storage_target"),
        "decision": evaluation.get("decision"),
        "reasons": evaluation.get("reasons"),
        "policy_source": evaluation.get("policy_source"),
        "policy_status": evaluation.get("policy_status"),
        "enforcement_mode": evaluation.get("enforcement_mode"),
    }

    item = {
        "violation_id": _ser_s(event_id),
        "policy_id": _ser_s(str(evaluation.get("policy_id") or DOCUMENT_STORAGE_POLICY_ID)),
        "event_epoch": {"N": str(epoch)},
        "event_time": _ser_s(now),
        "result": _ser_s(str(evaluation.get("decision") or "unknown")),
        "provider": _ser_s(str(args.get("provider") or "unknown")),
        "project_id": _ser_s(str(args.get("project_id") or GOVERNANCE_PROJECT_ID or "")),
        "coordination_request_id": _ser_s(str(args.get("coordination_request_id") or args.get("request_id") or "")),
        "dispatch_id": _ser_s(str(args.get("dispatch_id") or "")),
        "details": _ser_value(details),
        "created_at": _ser_s(now),
    }
    try:
        _get_ddb().put_item(TableName=AGENT_COMPLIANCE_TABLE, Item=item)
    except Exception as exc:
        logger.warning("[POLICY] Failed to persist compliance event %s: %s", event_id, exc)


def _enforce_document_storage_policy(
    *,
    operation: str,
    storage_target: str,
    args: Dict[str, Any],
    policy_id: str = DOCUMENT_STORAGE_POLICY_ID,
) -> Optional[Dict[str, Any]]:
    evaluation = _evaluate_document_policy(
        operation=operation,
        storage_target=storage_target,
        args=args,
        policy_id=policy_id,
    )
    _record_compliance_event(evaluation=evaluation, args=args)
    if evaluation.get("allowed") is True:
        return None
    return _error_payload(
        "POLICY_DENIED",
        "; ".join(str(reason) for reason in evaluation.get("reasons") or []) or "document policy denied",
        retryable=False,
        details=evaluation,
    )


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

    # Governance files (authoritative source: S3 governance/live/, fallback: docstore)
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
    uri_text = str(uri or "").strip()

    # governance://... from deterministic S3 path (fallback: docstore)
    if uri_text.startswith("governance://"):
        catalog = _governance_catalog()
        meta = catalog.get(uri_text)
        if not meta:
            return f"# Governance resource not found: {uri_text}"
        s3_key = str(meta.get("s3_key") or "").strip()
        if not s3_key:
            return f"# Governance resource missing s3_key: {uri_text}"
        try:
            resp = _get_s3().get_object(
                Bucket=str(meta.get("s3_bucket") or S3_BUCKET),
                Key=s3_key,
            )
            return resp["Body"].read().decode("utf-8")
        except Exception as exc:
            return f"# Failed to fetch governance resource {uri_text}: {exc}"

    # projects://reference/{project_id}
    if uri_text.startswith("projects://reference/"):
        project_id = uri_text.replace("projects://reference/", "")
        s3_key = f"{S3_REFERENCE_PREFIX}/{project_id}.md"
        try:
            resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
            return resp["Body"].read().decode("utf-8")
        except Exception as exc:
            return f"# Failed to fetch reference for {project_id}: {exc}"

    return f"# Unknown resource URI: {uri_text}"


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
            name="tracker_pending_updates",
            description="List tracker records with pending update notes. Supports single project or all projects.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., devops). Omit if all=true.",
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Scan all projects for pending updates. If true, project_id is ignored.",
                    },
                },
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
                    "coordination": {
                        "type": "boolean",
                        "description": (
                            "Whether this record is coordination-scoped. "
                            "If true, coordination_request_id is required."
                        ),
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
                            "Acceptance criteria. Required for tasks (min 1). "
                            "Also accepted for features (governed field, min 1)."
                        ),
                    },
                    "user_story": {
                        "type": "string",
                        "description": (
                            "User story for feature records (governed field). "
                            "Format: 'As a [USER/SYSTEM] I need/want to be able to [X] so that [Y]'. "
                            "Required when record_type is 'feature'."
                        ),
                    },
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "steps_to_duplicate": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "observed_by": {"type": "string"},
                                "timestamp": {"type": "string"},
                            },
                            "required": ["description", "steps_to_duplicate"],
                        },
                        "description": (
                            "Structured evidence for issue records (governed field, min 1). "
                            "Each entry must include description and steps_to_duplicate."
                        ),
                    },
                    "category": {
                        "type": "string",
                        "description": (
                            "Classification category. "
                            "Features: epic|capability|enhancement|infrastructure. "
                            "Tasks: implementation|investigation|documentation|maintenance|validation. "
                            "Issues: bug|debt|risk|security|performance."
                        ),
                    },
                    "intent": {
                        "type": "string",
                        "description": "Free-text WHY this record exists.",
                    },
                    "primary_task": {
                        "type": "string",
                        "description": (
                            "Task ID of the execution entry-point task for features/issues (§5.5). "
                            "Must reference a valid task ID (contains -TSK- segment). "
                            "Only valid for feature and issue record types."
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
        # --- Acceptance Criteria Evidence Handshake (§7.1.1) ---
        Tool(
            name="tracker_set_acceptance_evidence",
            description=(
                "Set evidence on a specific acceptance criterion of a feature record. "
                "Part of the governed evidence handshake: features cannot be completed "
                "until ALL acceptance criteria have evidence and evidence_acceptance=true."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The feature record ID (must be a feature).",
                    },
                    "criterion_index": {
                        "type": "integer",
                        "description": "Zero-based index of the acceptance criterion to update.",
                    },
                    "evidence": {
                        "type": "string",
                        "description": (
                            "Evidence that the criterion was met in production. "
                            "Should reference deployment IDs, test results, monitoring data, etc."
                        ),
                    },
                    "evidence_acceptance": {
                        "type": "boolean",
                        "description": "Whether the criterion has been validated and accepted.",
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
                "required": [
                    "record_id", "criterion_index", "evidence",
                    "evidence_acceptance", "governance_hash",
                ],
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
        Tool(
            name="check_document_policy",
            description=(
                "Evaluate document-storage governance policy for a proposed write. "
                "Returns allow/deny with reasons and writes an audit event."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "description": "Operation name (e.g., documents_put, documents_patch).",
                    },
                    "storage_target": {
                        "type": "string",
                        "description": "Logical storage target (e.g., docstore_api, governance_s3).",
                    },
                    "file_name": {
                        "type": "string",
                        "description": "Optional proposed file name/path to validate.",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Optional project ID for audit context.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Optional provider identity for audit context.",
                    },
                    "coordination_request_id": {
                        "type": "string",
                        "description": "Optional coordination request ID for audit context.",
                    },
                    "dispatch_id": {
                        "type": "string",
                        "description": "Optional dispatch ID for audit context.",
                    },
                },
                "required": ["operation", "storage_target"],
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
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["project_id", "change_type", "deployment_type", "summary", "changes", "governance_hash"],
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
            name="governance_update",
            description=(
                "Update a governance resource with automatic version archival. "
                "Archives the current version to governance/history/ before writing "
                "the new content to governance/live/. Returns the new governance hash."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_name": {
                        "type": "string",
                        "description": (
                            "Governance file name (e.g., 'agents.md' or 'agents/foo.md'). "
                            "Must map to a valid governance:// URI."
                        ),
                    },
                    "content": {
                        "type": "string",
                        "description": "New markdown content for the governance file.",
                    },
                    "change_summary": {
                        "type": "string",
                        "description": "Brief description of what changed in this update.",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["file_name", "content", "change_summary", "governance_hash"],
            },
        ),
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


def _compute_completeness_score(item_data: Dict[str, Any]) -> Dict[str, Any]:
    """Compute ontology completeness score (0-100) for a tracker record.

    Returns dict with score, max_points, earned_points, and missing_fields.
    Scoring criteria per record type based on ENC-FTR-011 product ontology.
    """
    record_type = item_data.get("record_type", "")
    earned = 0
    total = 0
    missing: List[str] = []

    # Common fields (all types): title, description, priority, category, intent
    common_checks = [
        ("title", 10),
        ("description", 5),
        ("priority", 5),
        ("category", 10),
        ("intent", 5),
    ]
    for field_name, points in common_checks:
        total += points
        val = item_data.get(field_name)
        if val and str(val).strip():
            earned += points
        else:
            missing.append(field_name)

    if record_type == "feature":
        # Governed: user_story (15), acceptance_criteria (15), evidence_validated (15)
        # Optional: owners (5), success_metrics (5), parent (5)
        feature_checks = [
            ("user_story", 15, True),
            ("acceptance_criteria", 15, True),
            ("owners", 5, False),
            ("success_metrics", 5, False),
            ("parent", 5, False),
        ]
        for field_name, points, governed in feature_checks:
            total += points
            val = item_data.get(field_name)
            has_val = bool(val and (isinstance(val, list) and len(val) > 0 or isinstance(val, str) and val.strip()))
            if has_val:
                earned += points
            elif governed:
                missing.append(f"{field_name} (governed)")
            else:
                missing.append(field_name)
        # Evidence validation score (governed, 15 points)
        total += 15
        ac_list = item_data.get("acceptance_criteria", [])
        if ac_list:
            validated_count = 0
            for ac in ac_list:
                if isinstance(ac, dict) and ac.get("evidence_acceptance", False):
                    validated_count += 1
            if validated_count == len(ac_list):
                earned += 15
            elif validated_count > 0:
                earned += round(15 * validated_count / len(ac_list))
                missing.append(f"evidence_validated ({validated_count}/{len(ac_list)} criteria)")
            else:
                missing.append("evidence_validated (0 criteria accepted — use tracker_set_acceptance_evidence)")
        else:
            missing.append("evidence_validated (no acceptance_criteria)")

    elif record_type == "task":
        # Governed: acceptance_criteria (15), active_agent_session fields (5 for presence)
        # Optional: assigned_to (5), parent (10), checklist (5)
        task_checks = [
            ("acceptance_criteria", 15, True),
            ("assigned_to", 5, False),
            ("parent", 10, False),
            ("checklist", 5, False),
        ]
        for field_name, points, governed in task_checks:
            total += points
            val = item_data.get(field_name)
            has_val = bool(val and (isinstance(val, list) and len(val) > 0 or isinstance(val, str) and val.strip()))
            if has_val:
                earned += points
            elif governed:
                missing.append(f"{field_name} (governed)")
            else:
                missing.append(field_name)

    elif record_type == "issue":
        # Governed: evidence (25)
        # Optional: severity (5), hypothesis (10), technical_notes (5)
        issue_checks = [
            ("evidence", 25, True),
            ("severity", 5, False),
            ("hypothesis", 10, False),
            ("technical_notes", 5, False),
        ]
        for field_name, points, governed in issue_checks:
            total += points
            val = item_data.get(field_name)
            has_val = bool(val and (isinstance(val, list) and len(val) > 0 or isinstance(val, str) and val.strip()))
            if has_val:
                earned += points
            elif governed:
                missing.append(f"{field_name} (governed)")
            else:
                missing.append(field_name)

    score = round((earned / total) * 100) if total > 0 else 0
    return {
        "completeness_score": score,
        "earned_points": earned,
        "max_points": total,
        "missing_fields": missing,
    }


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
        sk = result["record_id"]
        result["id"] = sk.split("#", 1)[1] if "#" in sk else sk
    # Add completeness score (ENC-FTR-013 ontology)
    result["ontology"] = _compute_completeness_score(result)
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
    # Orphan detection (ENC-FTR-013): flag tasks without Feature lineage
    orphan_count = 0
    summary = []
    for r in items:
        entry: Dict[str, Any] = {
            "id": r.get("id"),
            "type": r.get("record_type"),
            "status": r.get("status"),
            "priority": r.get("priority"),
            "title": (r.get("title", "")[:80]),
        }
        if r.get("record_type") == "task":
            has_parent = bool(r.get("parent"))
            has_feature_link = bool(r.get("related_feature_ids"))
            if not has_parent and not has_feature_link:
                entry["orphan"] = True
                orphan_count += 1
        summary.append(entry)
    result: Dict[str, Any] = {"records": summary, "count": len(items)}
    if orphan_count > 0:
        result["orphan_tasks"] = orphan_count
        result["orphan_warning"] = (
            f"{orphan_count} task(s) have no parent or feature lineage. "
            "Consider linking them to a feature for traceability."
        )
    return _result_text(result)


async def _tracker_pending_updates(args: dict) -> list[TextContent]:
    """List tracker records with non-empty pending update notes.

    Supports scanning a single project or all projects.
    Used by MCP-only session initialization to check for pending PWA updates
    without requiring tracker.py fallback.
    """
    project_id = args.get("project_id")
    scan_all = args.get("all", False)

    if not project_id and not scan_all:
        return _result_text({"error": "Provide project_id or all=true"})

    ddb = _get_ddb()

    # Build filter expression for records with non-empty 'update' field
    filter_expr = "attribute_exists(#upd)"
    expr_names = {"#upd": "update"}
    expr_vals = {}

    if scan_all:
        # Scan entire table for pending updates
        scan_kwargs: Dict[str, Any] = {
            "TableName": TRACKER_TABLE,
            "FilterExpression": filter_expr,
            "ExpressionAttributeNames": expr_names,
        }
    else:
        # Scan with project filter
        filter_expr += " AND project_id = :pid"
        expr_vals[":pid"] = _ser_s(project_id)
        scan_kwargs: Dict[str, Any] = {
            "TableName": TRACKER_TABLE,
            "FilterExpression": filter_expr,
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_vals,
        }

    try:
        items = []
        # Support pagination for large result sets
        last_evaluated_key = None
        while True:
            if last_evaluated_key:
                scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

            resp = ddb.scan(**scan_kwargs)
            items.extend([_deser_item(i) for i in resp.get("Items", [])])

            last_evaluated_key = resp.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break
    except (BotoCoreError, ClientError) as exc:
        return _result_text({"error": f"DynamoDB scan failed: {exc}"})

    # Format results
    summary = []
    for r in items:
        sk = r.get("record_id", "")
        entry = {
            "id": sk.split("#", 1)[1] if "#" in sk else sk,
            "type": r.get("record_type"),
            "update": r.get("update", ""),
        }
        summary.append(entry)

    # Sort by ID for consistency
    summary.sort(key=lambda x: x.get("id", ""))

    result: Dict[str, Any] = {"records": summary, "count": len(summary)}
    if not summary:
        result["message"] = "No pending updates found"
    return _result_text(result)


async def _tracker_set(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    field = args["field"]
    value = args["value"]
    ddb = _get_ddb()

    if field in _RELATION_FIELDS:
        try:
            value = _normalize_relation_field(field, value)
        except ValueError as exc:
            return _result_text(
                _error_payload(
                    "INVALID_RELATION_VALUE",
                    f"Invalid value for {field}: {exc}",
                )
            )

    try:
        key = _tracker_key(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    # Validate record exists and fetch for soft validation
    existing = ddb.get_item(TableName=TRACKER_TABLE, Key=key)
    if not existing.get("Item"):
        return _result_text({"error": f"Record '{record_id}' not found"})

    # --- Session ownership enforcement (ENC-ISS-009 Phase 3A) ---
    # Checkout/release operations handle their own validation; skip for those.
    if field != "active_agent_session":
        ownership_error = _validate_session_ownership(existing["Item"], args, record_id)
        if ownership_error:
            return _result_text(ownership_error)

    # --- Parent same-kind constraint (ENC-TSK-460 §5.1) ---
    if field == "parent" and value.strip():
        item_data_for_parent = _deser_item(existing["Item"])
        record_type_for_parent = item_data_for_parent.get("record_type", "")
        # Determine parent record type from ID segment
        parent_type = None
        if "-TSK-" in value:
            parent_type = "task"
        elif "-ISS-" in value:
            parent_type = "issue"
        elif "-FTR-" in value:
            parent_type = "feature"
        if parent_type and parent_type != record_type_for_parent:
            return _result_text(
                _error_payload(
                    "PARENT_KIND_MISMATCH",
                    f"Cannot set parent: parent must be the same record type. "
                    f"This record is a {record_type_for_parent} but parent '{value}' is a {parent_type}. "
                    f"Use related_*_ids for cross-type references or primary_task for "
                    f"feature/issue → task execution links (§5.5).",
                )
            )

    # --- primary_task validation (ENC-TSK-460 §5.5) ---
    if field == "primary_task":
        item_data_for_pt = _deser_item(existing["Item"])
        record_type_for_pt = item_data_for_pt.get("record_type", "")
        if record_type_for_pt not in ("feature", "issue"):
            return _result_text(
                _error_payload(
                    "INVALID_FIELD",
                    f"primary_task is only valid on feature and issue records, "
                    f"not {record_type_for_pt}.",
                )
            )
        if value.strip() and "-TSK-" not in value:
            return _result_text(
                _error_payload(
                    "INVALID_PRIMARY_TASK",
                    f"primary_task must reference a task ID (contains -TSK- segment). "
                    f"Got: '{value}'.",
                )
            )

    # --- State machine enforcement + soft validation (ENC-FTR-013 ontology) ---
    _VALID_TRANSITIONS = {
        "feature": {
            "planned": {"in-progress", "completed"},
            "in-progress": {"completed"},
        },
        "task": {
            "open": {"in-progress", "closed"},
            "in-progress": {"closed"},
        },
        "issue": {
            "open": {"in-progress", "closed"},
            "in-progress": {"closed"},
        },
    }
    warnings: List[str] = []
    if field == "status":
        item_data = _deser_item(existing["Item"])
        record_type = item_data.get("record_type", "")
        current_status = item_data.get("status", "").strip().lower()
        new_lower = value.strip().lower()
        closing = new_lower in ("closed", "completed", "complete")

        # Enforce valid transitions (reject invalid ones)
        if current_status != new_lower:
            type_transitions = _VALID_TRANSITIONS.get(record_type, {})
            valid_next = type_transitions.get(current_status)
            if valid_next is not None and new_lower not in valid_next:
                return _result_text(
                    _error_payload(
                        "INVALID_TRANSITION",
                        f"Invalid status transition for {record_type}: "
                        f"'{current_status}' -> '{value}'. "
                        f"Valid next statuses: {sorted(valid_next)}",
                    )
                )

        # --- Hard enforcement of governed fields on close (ENC-FTR-013 + ENC-ISS-018) ---
        if record_type == "feature":
            if closing:
                if not item_data.get("user_story"):
                    return _result_text(
                        _error_payload(
                            "GOVERNED_FIELD_MISSING",
                            "Cannot complete feature: user_story is required. "
                            "Set user_story before completing this feature.",
                        )
                    )
                ac_list = item_data.get("acceptance_criteria", [])
                if not ac_list:
                    return _result_text(
                        _error_payload(
                            "GOVERNED_FIELD_MISSING",
                            "Cannot complete feature: acceptance_criteria is required (min 1). "
                            "Set acceptance_criteria before completing this feature.",
                        )
                    )
                # Evidence handshake gate (§7.1.1): ALL criteria must have
                # evidence + evidence_acceptance=true before completion
                unvalidated = []
                for i, ac in enumerate(ac_list):
                    if isinstance(ac, dict):
                        desc = ac.get("description", f"criterion[{i}]")
                        if not ac.get("evidence_acceptance", False):
                            unvalidated.append(f"[{i}] {desc}")
                    elif isinstance(ac, str):
                        # Legacy string format — not yet upgraded to structured
                        unvalidated.append(f"[{i}] {ac}")
                if unvalidated:
                    return _result_text(
                        _error_payload(
                            "ACCEPTANCE_CRITERIA_NOT_VALIDATED",
                            "Cannot complete feature: not all acceptance criteria have been "
                            "validated in production. Use tracker_set_acceptance_evidence to "
                            "provide evidence for each criterion. Unvalidated criteria:\n"
                            + "\n".join(unvalidated),
                        )
                    )
            else:
                if not item_data.get("user_story"):
                    warnings.append("Feature missing governed field: user_story")
                if not item_data.get("acceptance_criteria"):
                    warnings.append("Feature missing governed field: acceptance_criteria")
            if closing and not item_data.get("category"):
                warnings.append("Feature missing classification: category")
        elif record_type == "task":
            if not item_data.get("acceptance_criteria"):
                warnings.append("Task missing governed field: acceptance_criteria")
            if new_lower == "in-progress" and not item_data.get("active_agent_session"):
                warnings.append(
                    "Task moving to in-progress without active_agent_session=true. "
                    "Consider checking out the task first."
                )
        elif record_type == "issue":
            if closing and not item_data.get("evidence"):
                return _result_text(
                    _error_payload(
                        "GOVERNED_FIELD_MISSING",
                        "Cannot close issue: evidence is required (min 1). "
                        "Add evidence before closing this issue.",
                    )
                )
            elif not item_data.get("evidence"):
                warnings.append("Issue missing governed field: evidence")
            if new_lower == "in-progress" and not item_data.get("hypothesis"):
                warnings.append(
                    "Issue moving to in-progress without hypothesis populated."
                )

    now = _now_z()
    note_suffix = _write_source_note_suffix(args)

    # --- Agent session checkout/release protocol (ENC-FTR-013 ontology) ---
    if field == "active_agent_session":
        checking_out = value.strip().lower() in ("true", "1", "yes")
        agent_id = str(args.get("provider") or "").strip()

        if checking_out:
            # CHECKOUT: require agent identity
            if not agent_id:
                return _result_text(
                    _error_payload(
                        "AGENT_ID_REQUIRED",
                        "Cannot check out task: 'provider' field is required as agent identity "
                        "(active_agent_session_id). Provide your agent identity via the 'provider' parameter.",
                    )
                )
            # Pessimistic lock: only succeed if not already checked out
            checkout_note = f"Agent session checkout by {agent_id} via MCP server{note_suffix}"
            history_entry = {
                "M": {
                    "timestamp": _ser_s(now),
                    "status": _ser_s("worklog"),
                    "description": _ser_s(checkout_note),
                }
            }
            try:
                ddb.update_item(
                    TableName=TRACKER_TABLE,
                    Key=key,
                    UpdateExpression=(
                        "SET active_agent_session = :t, "
                        "active_agent_session_id = :aid, "
                        "updated_at = :now, last_update_note = :note, "
                        "write_source = :wsrc, "
                        "sync_version = if_not_exists(sync_version, :zero) + :one, "
                        "history = list_append(if_not_exists(history, :empty), :hentry)"
                    ),
                    ConditionExpression=(
                        "active_agent_session <> :t OR attribute_not_exists(active_agent_session)"
                    ),
                    ExpressionAttributeValues={
                        ":t": {"BOOL": True},
                        ":aid": _ser_s(agent_id),
                        ":now": _ser_s(now),
                        ":note": _ser_s(checkout_note),
                        ":wsrc": _build_write_source(args),
                        ":zero": {"N": "0"},
                        ":one": {"N": "1"},
                        ":hentry": {"L": [history_entry]},
                        ":empty": {"L": []},
                    },
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    # Another agent already holds the session
                    item_data = _deser_item(existing["Item"])
                    current_agent = item_data.get("active_agent_session_id", "unknown")
                    return _result_text(
                        _error_payload(
                            "SESSION_LOCKED",
                            f"Task is already checked out by agent '{current_agent}'. "
                            f"Wait for release or contact the owning agent.",
                            retryable=True,
                        )
                    )
                raise
            return _result_text({
                "success": True,
                "record_id": record_id,
                "checkout": True,
                "active_agent_session_id": agent_id,
                "updated_at": now,
            })
        else:
            # RELEASE: clear session
            release_note = f"Agent session released via MCP server{note_suffix}"
            history_entry = {
                "M": {
                    "timestamp": _ser_s(now),
                    "status": _ser_s("worklog"),
                    "description": _ser_s(release_note),
                }
            }
            ddb.update_item(
                TableName=TRACKER_TABLE,
                Key=key,
                UpdateExpression=(
                    "SET active_agent_session = :f, "
                    "active_agent_session_id = :empty_s, "
                    "updated_at = :now, last_update_note = :note, "
                    "write_source = :wsrc, "
                    "sync_version = if_not_exists(sync_version, :zero) + :one, "
                    "history = list_append(if_not_exists(history, :empty_l), :hentry)"
                ),
                ExpressionAttributeValues={
                    ":f": {"BOOL": False},
                    ":empty_s": _ser_s(""),
                    ":now": _ser_s(now),
                    ":note": _ser_s(release_note),
                    ":wsrc": _build_write_source(args),
                    ":zero": {"N": "0"},
                    ":one": {"N": "1"},
                    ":hentry": {"L": [history_entry]},
                    ":empty_l": {"L": []},
                },
            )
            return _result_text({
                "success": True,
                "record_id": record_id,
                "checkout": False,
                "updated_at": now,
            })

    note_text = f"Field '{field}' set to '{_field_value_for_note(value)}' via MCP server{note_suffix}"
    update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one"
    )
    expr_vals = {
        ":val": _ser_value(value),
        ":now": _ser_s(now),
        ":note": _ser_s(note_text),
        ":wsrc": _build_write_source(args),
        ":zero": {"N": "0"},
        ":one": {"N": "1"},
    }
    expr_names = {"#fld": field}

    # Append to history
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(note_text),
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
    result = {"success": True, "record_id": record_id, "field": field, "value": value, "updated_at": now}
    if warnings:
        result["warnings"] = warnings
    return _result_text(result)


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

    # --- Session ownership enforcement (ENC-ISS-009 Phase 3A) ---
    ownership_error = _validate_session_ownership(existing["Item"], args, record_id)
    if ownership_error:
        return _result_text(ownership_error)

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
            "write_source = :wsrc, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "history = list_append(if_not_exists(history, :empty), :hentry)"
        ),
        ExpressionAttributeValues={
            ":now": _ser_s(now),
            ":note": _ser_s(description),
            ":wsrc": _build_write_source(args),
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
    dispatch_id = str(args.get("dispatch_id") or "").strip()
    try:
        coordination = _normalize_optional_bool(args.get("coordination"), "coordination")
        coordination_request_id = _normalize_coordination_request_id(
            args.get("coordination_request_id")
        )
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if dispatch_id:
        coordination = True
    coordination_flag = bool(coordination) if coordination is not None else False
    if coordination_flag and not coordination_request_id:
        if dispatch_id and _COORDINATION_REQUEST_ID_RE.fullmatch(dispatch_id):
            coordination_request_id = dispatch_id.upper()
        else:
            return _result_text(
                {
                    "error": (
                        "coordination=true requires coordination_request_id "
                        "matching CRQ-* or DSP-*."
                    )
                }
            )

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

    # --- Ontology governed field validation (ENC-FTR-012) ---
    user_story = str(args.get("user_story") or "").strip()
    category = str(args.get("category") or "").strip()
    intent = str(args.get("intent") or "").strip()
    evidence = args.get("evidence") or []

    # Feature: user_story required, acceptance_criteria required (min 1)
    if record_type == "feature":
        if not user_story:
            return _result_text(
                {
                    "error": (
                        "Feature creation requires user_story. "
                        "Format: 'As a [USER/SYSTEM] I need/want to be able to [X] so that [Y]'."
                    )
                }
            )
        if not acceptance_criteria:
            return _result_text(
                {
                    "error": (
                        "Feature creation requires acceptance_criteria with at least one "
                        "non-empty criterion."
                    )
                }
            )

    # Issue: evidence required (min 1, each with steps_to_duplicate)
    if record_type == "issue":
        if not isinstance(evidence, list) or len(evidence) == 0:
            return _result_text(
                {
                    "error": (
                        "Issue creation requires evidence with at least one entry. "
                        "Each entry must include 'description' and 'steps_to_duplicate'."
                    )
                }
            )
        for i, ev in enumerate(evidence):
            if not isinstance(ev, dict):
                return _result_text({"error": f"evidence[{i}] must be an object."})
            if not ev.get("description", "").strip():
                return _result_text({"error": f"evidence[{i}].description is required."})
            steps = ev.get("steps_to_duplicate")
            if not isinstance(steps, list) or len(steps) == 0:
                return _result_text(
                    {"error": f"evidence[{i}].steps_to_duplicate requires at least one step."}
                )

    # primary_task validation (ENC-TSK-460 §5.5) — only features/issues
    primary_task = str(args.get("primary_task") or "").strip()
    if primary_task:
        if record_type not in ("feature", "issue"):
            return _result_text(
                {
                    "error": (
                        f"primary_task is only valid on feature and issue records, "
                        f"not {record_type}."
                    )
                }
            )
        if "-TSK-" not in primary_task:
            return _result_text(
                {
                    "error": (
                        f"primary_task must reference a task ID (contains -TSK- segment). "
                        f"Got: '{primary_task}'."
                    )
                }
            )

    # Category validation (soft — warn in response but allow creation)
    _VALID_CATEGORIES = {
        "feature": {"epic", "capability", "enhancement", "infrastructure"},
        "task": {"implementation", "investigation", "documentation", "maintenance", "validation"},
        "issue": {"bug", "debt", "risk", "security", "performance"},
    }
    category_warning = ""
    if category and category not in _VALID_CATEGORIES.get(record_type, set()):
        valid = sorted(_VALID_CATEGORIES.get(record_type, set()))
        category_warning = f"Warning: category '{category}' not in valid set for {record_type}: {valid}"

    ddb = _get_ddb()

    # Resolve prefix from projects table
    proj_resp = ddb.get_item(TableName=PROJECTS_TABLE, Key={"project_id": _ser_s(project_id)})
    proj = proj_resp.get("Item")
    if not proj:
        return _result_text({"error": f"Project '{project_id}' not found in projects table"})
    prefix = _deser_val(proj.get("prefix", {"S": "UNK"}))

    now = _now_z()
    note_suffix = _write_source_note_suffix(args)
    item: Dict[str, Any] = {
        "project_id": _ser_s(project_id),
        "record_type": _ser_s(record_type),
        "title": _ser_s(title),
        "status": _ser_s(status),
        "sync_version": {"N": "1"},
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "coordination": {"BOOL": coordination_flag},
        "write_source": _build_write_source(args),
        "history": {
            "L": [
                {
                    "M": {
                        "timestamp": _ser_s(now),
                        "status": _ser_s("created"),
                        "description": _ser_s(
                            f"Created via MCP server{note_suffix}: {title}"
                        ),
                    }
                }
            ]
        },
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
    if acceptance_criteria:
        if record_type == "feature":
            # Features use structured acceptance criteria with evidence tracking
            ac_items = []
            for ac_text in acceptance_criteria:
                ac_items.append({
                    "M": {
                        "description": _ser_s(ac_text),
                        "evidence": _ser_s(""),
                        "evidence_acceptance": {"BOOL": False},
                    }
                })
            item["acceptance_criteria"] = {"L": ac_items}
        else:
            # Tasks use plain string acceptance criteria
            item["acceptance_criteria"] = {"L": [_ser_s(x) for x in acceptance_criteria]}

    # --- Ontology fields (ENC-FTR-012) ---

    # Feature: user_story (governed, required — validated above)
    if record_type == "feature" and user_story:
        item["user_story"] = _ser_s(user_story)

    # Issue: evidence (governed, required — validated above)
    if record_type == "issue" and evidence:
        ev_items = []
        for ev in evidence:
            ev_map: Dict[str, Any] = {
                "description": _ser_s(str(ev.get("description", ""))),
                "steps_to_duplicate": {
                    "L": [_ser_s(str(s)) for s in ev.get("steps_to_duplicate", [])]
                },
            }
            if ev.get("observed_by"):
                ev_map["observed_by"] = _ser_s(str(ev["observed_by"]))
            if ev.get("timestamp"):
                ev_map["timestamp"] = _ser_s(str(ev["timestamp"]))
            ev_items.append({"M": ev_map})
        item["evidence"] = {"L": ev_items}

    # Task: agent session defaults (governed, required on create)
    if record_type == "task":
        item["active_agent_session"] = {"BOOL": False}
        item["active_agent_session_id"] = _ser_s("")
        item["active_agent_session_parent"] = {"BOOL": False}

    # Common optional ontology fields
    if category:
        item["category"] = _ser_s(category)
    if intent:
        item["intent"] = _ser_s(intent)

    # primary_task (ENC-TSK-460 §5.5) — features/issues only, validated above
    if primary_task and record_type in ("feature", "issue"):
        item["primary_task"] = _ser_s(primary_task)

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
            break
        except ClientError as exc:
            if _is_conditional_check_failed(exc) and attempt < max_attempts:
                continue
            raise
    else:
        return _result_text(
            {
                "error": (
                    f"Failed to allocate a unique record ID for {record_type} in project "
                    f"'{project_id}' after {max_attempts} attempts."
                )
            }
        )

    # --- Bidirectional relationship enforcement (ENC-FTR-013 ontology) ---
    # Best-effort: add inverse relationship on target records
    bidi_warnings: List[str] = []
    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        # Determine the relationship field name for the new record's type
        inverse_field = f"related_{record_type}_ids"
        for target_id in related_ids:
            try:
                target_key = _tracker_key(target_id)
                # Append new_id to the target's inverse relationship list
                ddb.update_item(
                    TableName=TRACKER_TABLE,
                    Key=target_key,
                    UpdateExpression=(
                        "SET #rel = list_append(if_not_exists(#rel, :empty), :new_id)"
                    ),
                    ExpressionAttributeNames={"#rel": inverse_field},
                    ExpressionAttributeValues={
                        ":new_id": {"L": [_ser_s(new_id)]},
                        ":empty": {"L": []},
                    },
                    ConditionExpression="attribute_exists(record_id)",
                )
            except (ClientError, ValueError) as exc:
                bidi_warnings.append(
                    f"Could not add inverse relationship on {target_id}: {exc}"
                )

    result = {"success": True, "record_id": new_id, "created_at": now}
    if category_warning:
        result["warning"] = category_warning
    if bidi_warnings:
        result["bidi_warnings"] = bidi_warnings
    return _result_text(result)


# --- Acceptance Criteria Evidence Handshake (§7.1.1) ---


async def _tracker_set_acceptance_evidence(args: dict) -> list[TextContent]:
    """Set evidence on a specific acceptance criterion of a feature record."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    criterion_index = args["criterion_index"]
    evidence = args["evidence"]
    evidence_acceptance = args["evidence_acceptance"]
    ddb = _get_ddb()

    try:
        key = _tracker_key(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    # Fetch the record
    existing = ddb.get_item(TableName=TRACKER_TABLE, Key=key)
    if not existing.get("Item"):
        return _result_text({"error": f"Record '{record_id}' not found"})

    item_data = _deser_item(existing["Item"])

    # Must be a feature
    if item_data.get("record_type") != "feature":
        return _result_text(
            _error_payload(
                "WRONG_RECORD_TYPE",
                f"tracker_set_acceptance_evidence only applies to features. "
                f"Record '{record_id}' is a {item_data.get('record_type', 'unknown')}.",
            )
        )

    # Validate acceptance_criteria exists and has the index
    ac_list = item_data.get("acceptance_criteria", [])
    if not ac_list:
        return _result_text(
            _error_payload(
                "NO_ACCEPTANCE_CRITERIA",
                f"Feature '{record_id}' has no acceptance_criteria.",
            )
        )
    if criterion_index < 0 or criterion_index >= len(ac_list):
        return _result_text(
            _error_payload(
                "INDEX_OUT_OF_RANGE",
                f"criterion_index {criterion_index} is out of range. "
                f"Feature has {len(ac_list)} criteria (indices 0-{len(ac_list) - 1}).",
            )
        )

    # Validate evidence is non-empty when accepting
    if evidence_acceptance and not evidence.strip():
        return _result_text(
            _error_payload(
                "EVIDENCE_REQUIRED",
                "Cannot set evidence_acceptance=true without providing evidence text. "
                "Describe how this criterion was validated in production.",
            )
        )

    # Build the DynamoDB update for the specific criterion item.
    # acceptance_criteria is stored as L[M{description, evidence, evidence_acceptance}]
    # We need to handle both legacy (plain strings) and structured formats.
    raw_ac = existing["Item"].get("acceptance_criteria", {}).get("L", [])
    ac_item = raw_ac[criterion_index]

    # Determine if this is a legacy string or structured map
    if "S" in ac_item:
        # Legacy string format — we need to upgrade it to structured
        description = ac_item["S"]
    elif "M" in ac_item:
        description = ac_item["M"].get("description", {}).get("S", "")
    else:
        description = str(ac_list[criterion_index])

    now = _now_z()
    note_suffix = _write_source_note_suffix(args)

    # Update the specific index in the acceptance_criteria list
    update_expr = (
        f"SET acceptance_criteria[{criterion_index}] = :ac_item, "
        "updated_at = :now, last_update_note = :note, "
        "write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
        "history = list_append(if_not_exists(history, :empty), :hentry)"
    )
    ac_updated = {
        "M": {
            "description": _ser_s(description),
            "evidence": _ser_s(evidence),
            "evidence_acceptance": {"BOOL": evidence_acceptance},
        }
    }
    status_word = "accepted" if evidence_acceptance else "updated"
    note_text = (
        f"Acceptance criterion [{criterion_index}] evidence {status_word} "
        f"via MCP server{note_suffix}: {description[:80]}"
    )
    history_entry = {
        "M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(note_text),
        }
    }
    expr_vals = {
        ":ac_item": ac_updated,
        ":now": _ser_s(now),
        ":note": _ser_s(note_text),
        ":wsrc": _build_write_source(args),
        ":zero": {"N": "0"},
        ":one": {"N": "1"},
        ":hentry": {"L": [history_entry]},
        ":empty": {"L": []},
    }

    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key=key,
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_vals,
    )

    # Build summary of all criteria status
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
        # Override the one we just updated
        if i == criterion_index:
            desc = description
            ev_acc = evidence_acceptance
        criteria_summary.append({
            "index": i,
            "description": desc[:100],
            "evidence_acceptance": ev_acc,
        })

    all_accepted = all(c["evidence_acceptance"] for c in criteria_summary)

    return _result_text({
        "success": True,
        "record_id": record_id,
        "criterion_index": criterion_index,
        "evidence_acceptance": evidence_acceptance,
        "updated_at": now,
        "criteria_summary": criteria_summary,
        "all_criteria_accepted": all_accepted,
        "completion_eligible": all_accepted,
    })


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
    policy_error = _enforce_document_storage_policy(
        operation="documents_put",
        storage_target="docstore_api",
        args=args,
    )
    if policy_error:
        return _result_text(policy_error)

    body: Dict[str, Any] = {
        "project_id": args["project_id"],
        "title": args["title"],
        "content": args["content"],
    }
    for key in ("description", "keywords", "related_items", "file_name"):
        if key in args and args.get(key) is not None:
            body[key] = args.get(key)

    result = _document_api_request("PUT", payload=body)
    if _is_authentication_required_error(result):
        logger.info(
            "[INFO] documents_put received auth-required response from document API; using direct fallback for project %s",
            body.get("project_id"),
        )
        result = _document_put_direct(body)
    return _result_text(result)


async def _documents_patch(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash_envelope(args)
    if governance_error:
        return _result_text(governance_error)
    policy_error = _enforce_document_storage_policy(
        operation="documents_patch",
        storage_target="docstore_api",
        args=args,
    )
    if policy_error:
        return _result_text(policy_error)

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
    if _is_authentication_required_error(result):
        logger.info(
            "[INFO] documents_patch received auth-required response from document API; using direct fallback for document %s",
            document_id,
        )
        result = _document_patch_direct(document_id, body)
    return _result_text(result)


async def _check_document_policy(args: dict) -> list[TextContent]:
    operation = str(args.get("operation") or "").strip()
    storage_target = str(args.get("storage_target") or "").strip()
    if not operation:
        return _result_text(_error_payload("INVALID_INPUT", "operation is required"))
    if not storage_target:
        return _result_text(_error_payload("INVALID_INPUT", "storage_target is required"))

    evaluation = _evaluate_document_policy(
        operation=operation,
        storage_target=storage_target,
        args=args,
    )
    _record_compliance_event(evaluation=evaluation, args=args)
    return _result_text(evaluation)


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
    if _is_authentication_required_error(result):
        logger.info(
            "[INFO] deploy_state_get received PERMISSION_DENIED from deploy API; using direct fallback for project %s",
            project_id,
        )
        result = _deploy_state_get_direct(project_id)
    return _result_text(result)


async def _deploy_history(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    try:
        limit = int(args.get("limit", 10))
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 50))
    result = _deploy_api_request("GET", f"/history/{project_id}", query={"limit": limit})
    if _is_authentication_required_error(result):
        logger.info(
            "[INFO] deploy_history received PERMISSION_DENIED from deploy API; using direct fallback for project %s",
            project_id,
        )
        result = _deploy_history_direct(project_id, limit)
    return _result_text(result)


async def _deploy_submit(args: dict) -> list[TextContent]:
    """Submit a deployment request via deploy_intake API, governance-gated."""
    governance_error = _require_governance_hash_envelope(args)
    if governance_error:
        return _result_text(governance_error)

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
        import urllib.request

        url = f"{COORDINATION_API_BASE}/capabilities"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", HTTP_USER_AGENT)
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
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


async def _governance_update(args: dict) -> list[TextContent]:
    """Update a governance resource with automatic version archival (ENC-TSK-474)."""
    err = _require_governance_hash_envelope(args)
    if err:
        return _result_text(err)
    policy_error = _enforce_document_storage_policy(
        operation="governance_update",
        storage_target="governance_s3",
        args=args,
    )
    if policy_error:
        return _result_text(policy_error)

    file_name = str(args.get("file_name") or "").strip()
    content = str(args.get("content") or "")
    change_summary = str(args.get("change_summary") or "").strip()

    if not file_name:
        return _result_text(_error_payload("INVALID_INPUT", "file_name is required", retryable=False))
    if not content:
        return _result_text(_error_payload("INVALID_INPUT", "content is required", retryable=False))
    if not change_summary:
        return _result_text(_error_payload("INVALID_INPUT", "change_summary is required", retryable=False))

    uri = _governance_uri_from_file_name(file_name)
    if not uri:
        return _result_text(_error_payload(
            "INVALID_INPUT",
            f"file_name '{file_name}' does not map to a valid governance:// URI. "
            "Must be 'agents.md' or start with 'agents/'.",
            retryable=False,
        ))

    live_key = f"{S3_GOVERNANCE_PREFIX.rstrip('/')}/{file_name}"
    s3 = _get_s3()

    # Archive current version if present. Fail closed on archive errors so
    # version-history guarantees are preserved.
    archive_key = None
    existing_content: Optional[bytes] = None
    try:
        existing = s3.get_object(Bucket=S3_BUCKET, Key=live_key)
        existing_content = existing["Body"].read()
    except Exception as exc:
        if _is_s3_not_found_error(exc):
            logger.info("[GOVERNANCE] No existing version to archive for %s", uri)
        else:
            return _result_text(_error_payload(
                "UPSTREAM_ERROR",
                f"Failed to read existing governance file for archival safety: {exc}",
                retryable=True,
            ))

    if existing_content is not None:
        timestamp = _now_z().replace(":", "-")
        archive_key = f"{S3_GOVERNANCE_HISTORY_PREFIX.rstrip('/')}/{file_name}/{timestamp}.md"
        try:
            s3.put_object(
                Bucket=S3_BUCKET,
                Key=archive_key,
                Body=existing_content,
                ContentType="text/markdown; charset=utf-8",
                Metadata={
                    "change_summary": change_summary[:256],
                    "archived_at": _now_z(),
                    "previous_hash": hashlib.sha256(existing_content).hexdigest(),
                },
            )
            logger.info("[GOVERNANCE] Archived %s → s3://%s/%s", uri, S3_BUCKET, archive_key)
        except Exception as exc:
            return _result_text(_error_payload(
                "UPSTREAM_ERROR",
                f"Failed to archive existing governance file; update aborted: {exc}",
                retryable=True,
            ))

    # Write new content to live path
    content_bytes = content.encode("utf-8")
    new_hash = hashlib.sha256(content_bytes).hexdigest()
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=live_key,
            Body=content_bytes,
            ContentType="text/markdown; charset=utf-8",
            Metadata={
                "change_summary": change_summary[:256],
                "updated_at": _now_z(),
                "content_sha256": new_hash,
            },
        )
    except Exception as exc:
        return _result_text(_error_payload(
            "UPSTREAM_ERROR",
            f"Failed to write governance file to S3: {exc}",
            retryable=True,
        ))

    # Invalidate catalog cache so next governance_hash reflects the update
    global _governance_catalog_cache, _governance_catalog_cached_at
    _governance_catalog_cache = {}
    _governance_catalog_cached_at = 0

    new_governance_hash = _compute_governance_hash()
    logger.info("[GOVERNANCE] Updated %s — new governance_hash: %s", uri, new_governance_hash)

    result = {
        "status": "updated",
        "uri": uri,
        "s3_key": live_key,
        "content_hash": new_hash,
        "content_size_bytes": len(content_bytes),
        "governance_hash": new_governance_hash,
        "updated_at": _now_z(),
    }
    if archive_key:
        result["archived_to"] = f"s3://{S3_BUCKET}/{archive_key}"

    return _result_text(result)


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
    "tracker_pending_updates": _tracker_pending_updates,
    "tracker_set": _tracker_set,
    "tracker_log": _tracker_log,
    "tracker_create": _tracker_create,
    "tracker_set_acceptance_evidence": _tracker_set_acceptance_evidence,
    "documents_search": _documents_search,
    "documents_get": _documents_get,
    "documents_list": _documents_list,
    "documents_put": _documents_put,
    "documents_patch": _documents_patch,
    "check_document_policy": _check_document_policy,
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
    "governance_update": _governance_update,
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
