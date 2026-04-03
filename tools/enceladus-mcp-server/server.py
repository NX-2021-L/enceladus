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
import base64
import hashlib
import hmac
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


def _first_nonempty_env(*names: str) -> str:
    for name in names:
        value = str(os.environ.get(name, "")).strip()
        if value:
            return value
    return ""


def _collect_nonempty_env_keys(*names: str) -> tuple[str, ...]:
    seen: set[str] = set()
    keys: List[str] = []
    for name in names:
        raw = str(os.environ.get(name, "")).strip()
        if not raw:
            continue
        for part in raw.split(","):
            key = part.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return tuple(keys)

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
GOVERNANCE_RESOURCE_BODY_TTL_SECONDS = float(
    os.environ.get("ENCELADUS_GOVERNANCE_RESOURCE_BODY_TTL_SECONDS", "30")
)
S3_GOVERNANCE_PREFIX = os.environ.get("ENCELADUS_S3_GOVERNANCE_PREFIX", "governance/live")
S3_GOVERNANCE_HISTORY_PREFIX = os.environ.get("ENCELADUS_S3_GOVERNANCE_HISTORY_PREFIX", "governance/history")

COORDINATION_API_BASE = os.environ.get(
    "ENCELADUS_COORDINATION_API_BASE",
    "https://jreese.net/api/v1/coordination",
)
COMMON_INTERNAL_API_KEY = _first_nonempty_env(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
)
COMMON_INTERNAL_API_KEYS = _collect_nonempty_env_keys(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEYS",
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEYS",
)
COORDINATION_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
COORDINATION_API_INTERNAL_API_KEYS = _collect_nonempty_env_keys(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS",
)
DOCUMENT_API_BASE = os.environ.get(
    "ENCELADUS_DOCUMENT_API_BASE",
    "https://jreese.net/api/v1/documents",
)
DOCUMENT_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
DEPLOY_API_BASE = os.environ.get(
    "ENCELADUS_DEPLOY_API_BASE",
    "https://jreese.net/api/v1/deploy",
)
DEPLOY_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
DEPLOY_API_INTERNAL_API_KEYS = _collect_nonempty_env_keys(
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEY",
    "ENCELADUS_DEPLOY_API_INTERNAL_API_KEYS",
)
CHANGELOG_API_BASE = os.environ.get(
    "ENCELADUS_CHANGELOG_API_BASE",
    "https://jreese.net/api/v1/changelog",
)
TRACKER_API_BASE = os.environ.get(
    "ENCELADUS_TRACKER_API_BASE",
    "https://jreese.net/api/v1/tracker",
)
# ENC-FTR-037: Checkout service base URL
CHECKOUT_SERVICE_API_BASE = os.environ.get(
    "CHECKOUT_SERVICE_API_BASE",
    "https://jreese.net/api/v1/checkout",
)
# ENC-FTR-049: Typed relationship edge feature flag
ENABLE_TYPED_RELATIONSHIPS = os.environ.get(
    "ENABLE_TYPED_RELATIONSHIPS", "false"
).lower() == "true"
# ENC-FTR-050: Context Node feature flag (default off — all new code paths gated)
ENABLE_CONTEXT_NODES = os.environ.get(
    "ENABLE_CONTEXT_NODES", "false"
).lower() == "true"
# ENC-FTR-052: Governed Lesson Primitive feature flag
ENABLE_LESSON_PRIMITIVE = os.environ.get(
    "ENABLE_LESSON_PRIMITIVE", "false"
).lower() == "true"

TRACKER_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
TRACKER_API_INTERNAL_API_KEYS = _collect_nonempty_env_keys(
    "ENCELADUS_TRACKER_API_INTERNAL_API_KEY",
    "ENCELADUS_TRACKER_API_INTERNAL_API_KEYS",
)
GOVERNANCE_API_BASE = os.environ.get(
    "ENCELADUS_GOVERNANCE_API_BASE",
    "https://jreese.net/api/v1/governance",
)
GOVERNANCE_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_GOVERNANCE_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
PROJECTS_API_BASE = os.environ.get(
    "ENCELADUS_PROJECTS_API_BASE",
    "https://jreese.net/api/v1/coordination/projects",
)
PROJECTS_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)
PROJECTS_API_INTERNAL_API_KEYS = _collect_nonempty_env_keys(
    "ENCELADUS_PROJECTS_API_INTERNAL_API_KEY",
    "ENCELADUS_PROJECTS_API_INTERNAL_API_KEYS",
)
GRAPH_QUERY_API_BASE = os.environ.get(
    "ENCELADUS_GRAPH_QUERY_API_BASE",
    "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker/graphsearch",
)
HEALTH_API_URL = os.environ.get(
    "ENCELADUS_HEALTH_API_URL",
    "https://jreese.net/api/v1/health",
)
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
GITHUB_API_BASE = os.environ.get(
    "ENCELADUS_GITHUB_API_BASE",
    "https://jreese.net/api/v1/github",
)
GITHUB_API_INTERNAL_API_KEY = os.environ.get(
    "ENCELADUS_GITHUB_API_INTERNAL_API_KEY",
    COMMON_INTERNAL_API_KEY,
)

# Tracker governance constants mirrored from tracker_mutation Lambda so MCP clients
# can preflight status transitions and reduce avoidable rejected writes.
TRACKER_VALID_CATEGORIES = {
    "feature": {"epic", "capability", "enhancement", "infrastructure"},
    "task": {"implementation", "investigation", "documentation", "maintenance", "validation"},
    "issue": {"bug", "debt", "risk", "security", "performance"},
}
TRACKER_VALID_TRANSITIONS = {
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
TRACKER_REVERT_TRANSITIONS = {
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
TRACKER_STATUS_EVIDENCE_REQUIREMENTS = {
    "task": {
        "pushed": {
            "required": ["transition_evidence.commit_sha"],
            "notes": "commit_sha must be a 40-char lowercase/uppercase hex SHA.",
        },
        "merged-main": {
            "required": ["transition_evidence.merge_evidence"],
            "notes": "merge_evidence should describe merge confirmation.",
        },
        "deployed": {
            "required": ["transition_evidence.deployment_ref"],
            "notes": "deployment_ref should point to deployment proof/spec/run.",
        },
    }
}
TRACKER_PRIORITY_ENUM = ("P0", "P1", "P2", "P3")

# GSI names
GSI_PROJECT_TYPE = "project-type-index"

SERVER_NAME = "enceladus"
SERVER_VERSION = "1.0.0"
HTTP_USER_AGENT = os.environ.get("ENCELADUS_HTTP_USER_AGENT", f"enceladus-mcp-server/{SERVER_VERSION}")

MCP_TRANSPORT = os.environ.get("ENCELADUS_MCP_TRANSPORT", "stdio")
MCP_API_KEY = os.environ.get("ENCELADUS_MCP_API_KEY", "")
# Access token lifetime in seconds. Default 8 hours — long enough to cover a full
# work session without forcing re-auth, short enough to bound token exposure.
MCP_TOKEN_TTL = int(os.environ.get("ENCELADUS_MCP_TOKEN_TTL", "28800"))
# Refresh token lifetime — 30 days. Stateless HMAC-signed; no server storage needed.
_REFRESH_TOKEN_TTL = 30 * 24 * 3600
OAUTH_CLIENT_ID = os.environ.get("ENCELADUS_OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("ENCELADUS_OAUTH_CLIENT_SECRET", "")

# Cognito-direct OAuth (ENC-FTR-045): when set, OAuth metadata points directly
# to Cognito Hosted UI and bearer tokens are validated as Cognito JWTs.
COGNITO_USER_POOL_ID = os.environ.get("ENCELADUS_COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID_CODE = os.environ.get("ENCELADUS_COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET_CODE = os.environ.get("ENCELADUS_COGNITO_CLIENT_SECRET", "")
COGNITO_DOMAIN = os.environ.get("ENCELADUS_COGNITO_DOMAIN", "")
COGNITO_REGION = os.environ.get("ENCELADUS_COGNITO_REGION", "")


def _cognito_mode_active() -> bool:
    """Return True when Cognito-direct OAuth is configured (ENC-FTR-045)."""
    return bool(COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID_CODE and COGNITO_DOMAIN)


INTERFACE_MODE_RAW = "raw"
INTERFACE_MODE_CODE = "code"
CODE_MODE_TOOL_NAMES = ("search", "coordination", "get_compact_context", "execute")
_CODE_MODE_TOOL_SET = set(CODE_MODE_TOOL_NAMES)


def _normalize_interface_mode(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {INTERFACE_MODE_RAW, INTERFACE_MODE_CODE}:
        return normalized
    return INTERFACE_MODE_RAW


INTERFACE_MODE = _normalize_interface_mode(
    os.environ.get("ENCELADUS_MCP_INTERFACE_MODE")
    or os.environ.get("COORDINATION_INTERFACE_MODE")
    or INTERFACE_MODE_RAW
)

logger = logging.getLogger(SERVER_NAME)

# ---------------------------------------------------------------------------
# Dynamic MCP toolset context (ENC-TSK-826)
# ---------------------------------------------------------------------------

DYNAMIC_TOOLSETS_ENABLED = (
    os.environ.get("ENCELADUS_DYNAMIC_TOOLSETS_ENABLED", "true").strip().lower()
    not in {"0", "false", "no", "off"}
)
_SESSION_TOOLSET_CONTEXTS: Dict[str, Dict[str, Any]] = {}
_TOOLSET_BASE_NAMESPACES = {"projects", "tracker", "checkout", "documents", "reference", "coordination", "governance"}
_TOOLSET_CATEGORY_NAMESPACES = {
    "implementation": _TOOLSET_BASE_NAMESPACES | {"deploy", "changelog", "github"},
    "maintenance": _TOOLSET_BASE_NAMESPACES | {"deploy", "changelog", "github"},
    "validation": _TOOLSET_BASE_NAMESPACES | {"deploy", "changelog"},
    "investigation": _TOOLSET_BASE_NAMESPACES,
    "documentation": _TOOLSET_BASE_NAMESPACES,
}


def _tool_namespace(tool_name: str) -> str:
    name = str(tool_name or "").strip()
    if name.startswith("projects_"):
        return "projects"
    if name.startswith("tracker_"):
        return "tracker"
    if name in {"checkout_task", "release_task", "advance_task_status", "append_worklog", "validate_commit_complete"}:
        return "checkout"
    if name.startswith("documents_") or name == "check_document_policy":
        return "documents"
    if name in {"reference_search", "get_code_map", "get_issue_context", "get_architecture_excerpts"}:
        return "reference"
    if name.startswith("deploy_"):
        return "deploy"
    if name.startswith("changelog_"):
        return "changelog"
    if name.startswith("coordination_") or name.startswith("dispatch_plan_"):
        return "coordination"
    if name.startswith("governance_") or name == "connection_health":
        return "governance"
    if name.startswith("github_"):
        return "github"
    return "misc"


def _toolset_namespaces_for_category(category: str) -> set[str]:
    normalized = str(category or "").strip().lower()
    if normalized in _TOOLSET_CATEGORY_NAMESPACES:
        return set(_TOOLSET_CATEGORY_NAMESPACES[normalized])
    # Unknown categories default to full visibility to avoid accidental lockout.
    return {
        "projects",
        "tracker",
        "checkout",
        "documents",
        "reference",
        "deploy",
        "changelog",
        "coordination",
        "governance",
        "github",
        "misc",
    }


def _current_request_session() -> Any:
    try:
        return app.request_context.session
    except LookupError:
        return None


def _current_session_toolset_context(*, create: bool = False) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    session = _current_request_session()
    if session is None:
        return None, None
    key = str(id(session))
    if create:
        return key, _SESSION_TOOLSET_CONTEXTS.setdefault(key, {})
    return key, _SESSION_TOOLSET_CONTEXTS.get(key)


async def _notify_tools_list_changed_if_supported() -> bool:
    # Lambda Function URL transport is stateless today, so contextful toolset
    # notifications cannot be relied on across requests.
    if MCP_TRANSPORT == "streamable_http":
        return False

    session = _current_request_session()
    if session is None or not hasattr(session, "send_tool_list_changed"):
        return False
    try:
        await session.send_tool_list_changed()
        return True
    except Exception as exc:
        logger.info("Dynamic toolset fallback to full tool list (no tools/list_changed support): %s", exc)
        return False


def _filter_tool_list_for_session_context(tools: List[Tool]) -> List[Tool]:
    if not DYNAMIC_TOOLSETS_ENABLED:
        return tools
    _session_key, ctx = _current_session_toolset_context(create=False)
    if not ctx or not ctx.get("tool_filter_active"):
        return tools

    allowed_namespaces = set(ctx.get("allowed_namespaces") or [])
    if not allowed_namespaces:
        return tools

    filtered = [tool for tool in tools if _tool_namespace(tool.name) in allowed_namespaces]
    # Safety valve: never return an empty list due to a context mismatch.
    return filtered or tools


async def _sync_dynamic_toolset_on_checkout(record_id: str, checkout_response: Dict[str, Any]) -> None:
    if not DYNAMIC_TOOLSETS_ENABLED:
        return
    _session_key, ctx = _current_session_toolset_context(create=True)
    if ctx is None:
        return

    task_payload = checkout_response.get("task") if isinstance(checkout_response, dict) else {}
    if not isinstance(task_payload, dict):
        task_payload = {}
    category = str(task_payload.get("category") or "").strip().lower()
    project_id = str(task_payload.get("project_id") or "").strip()
    allowed_namespaces = sorted(_toolset_namespaces_for_category(category))

    changed = (
        str(ctx.get("active_task_id") or "") != str(record_id or "")
        or str(ctx.get("active_project_id") or "") != project_id
        or str(ctx.get("active_category") or "") != category
        or list(ctx.get("allowed_namespaces") or []) != allowed_namespaces
    )

    ctx.update(
        {
            "active_task_id": str(record_id or ""),
            "active_project_id": project_id,
            "active_category": category,
            "allowed_namespaces": allowed_namespaces,
        }
    )

    if not changed and ctx.get("tool_filter_active"):
        return

    notified = await _notify_tools_list_changed_if_supported()
    if notified:
        ctx["supports_list_changed"] = True
        ctx["tool_filter_active"] = True
    else:
        # Fallback mode for clients that do not support notifications.
        ctx["supports_list_changed"] = False
        ctx["tool_filter_active"] = False


async def _sync_dynamic_toolset_on_task_release(record_id: str) -> None:
    if not DYNAMIC_TOOLSETS_ENABLED:
        return
    _session_key, ctx = _current_session_toolset_context(create=False)
    if not ctx:
        return
    active_task_id = str(ctx.get("active_task_id") or "")
    if active_task_id and active_task_id != str(record_id or ""):
        return

    had_filter = bool(ctx.get("tool_filter_active"))
    ctx.clear()
    if had_filter:
        await _notify_tools_list_changed_if_supported()

# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

_ddb_client = None
_s3_client = None
_governance_catalog_cache: Dict[str, Dict[str, Any]] = {}
_governance_catalog_cached_at: float = 0.0
_governance_resource_body_cache: Dict[str, Dict[str, Any]] = {}


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
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan"}
_PREFIX_MAP_CACHE: Optional[Dict[str, str]] = None
_DEFAULT_STATUS_BY_TYPE = {"task": "open", "issue": "open", "feature": "planned", "lesson": "draft", "plan": "drafted"}
_RELATION_ID_FIELDS = {
    "related_task_ids",
    "related_issue_ids",
    "related_feature_ids",
}
_RELATION_FIELDS = set(_RELATION_ID_FIELDS) | {"depends_on"}
_DEPENDENCY_TYPES = ("task", "issue", "feature")
_SINGLE_CHAR_TOKEN_RE = re.compile(r"^[A-Za-z0-9,\-\s]$")
_COORDINATION_REQUEST_ID_RE = re.compile(r"^(CRQ|DSP)-[A-Z0-9-]{3,64}$", re.IGNORECASE)
_TRACKER_TYPE_SUFFIX = {"task": "TSK", "issue": "ISS", "feature": "FTR", "lesson": "LSN", "plan": "PLN"}
_TRACKER_COUNTER_PREFIX = "counter#"
_TRACKER_CREATE_MAX_ATTEMPTS = int(os.environ.get("ENCELADUS_TRACKER_CREATE_MAX_ATTEMPTS", "32"))


def _get_prefix_map(*, _refresh: bool = False) -> Dict[str, str]:
    """Build prefix -> project_name map via projects HTTP API.

    On cache miss for a specific prefix, callers should retry with
    _refresh=True to pick up newly created projects (ENC-ISS-123).
    """
    global _PREFIX_MAP_CACHE
    if _PREFIX_MAP_CACHE is not None and not _refresh:
        return _PREFIX_MAP_CACHE
    resp = _projects_api_request("GET")
    projects = resp.get("projects", [])
    mapping = {}
    for proj in projects:
        pid = str(proj.get("project_id") or proj.get("name") or "").strip()
        pfx = str(proj.get("prefix") or "").strip().upper()
        if pid and pfx:
            mapping[pfx] = pid
    _PREFIX_MAP_CACHE = mapping
    return mapping


def _resolve_prefix(prefix: str) -> str:
    """Resolve a project prefix to project_id, retrying on cache miss."""
    prefix_map = _get_prefix_map()
    if prefix in prefix_map:
        return prefix_map[prefix]
    # Cache miss — re-fetch in case a new project was created (ENC-ISS-123)
    prefix_map = _get_prefix_map(_refresh=True)
    if prefix in prefix_map:
        return prefix_map[prefix]
    raise ValueError(f"Unknown project prefix {prefix!r}. Known: {sorted(prefix_map)}")


def _parse_record_id(record_id: str) -> Tuple[str, str, str]:
    """Parse 'ENC-TSK-564' or 'ENC-TSK-564-0A' into (project_id, record_type, record_id).

    Returns (project_id, record_type, normalized_record_id).
    Accepts 3-segment (base) and 4-segment (sub-task) IDs (ENC-FTR-056).
    Raises ValueError if format is invalid or prefix unknown.
    """
    record_id = record_id.strip().upper()
    parts = record_id.split("-")
    if len(parts) < 3 or len(parts) > 4:
        raise ValueError(f"Invalid record ID format: {record_id!r}. Expected PREFIX-TYPE-NNN or PREFIX-TYPE-NNN-SS")
    prefix = parts[0]
    type_seg = parts[1]
    project_id = _resolve_prefix(prefix)
    record_type = _ID_SEGMENT_TO_TYPE.get(type_seg)
    if not record_type:
        raise ValueError(f"Unknown type segment {type_seg!r} in {record_id!r}")
    return project_id, record_type, record_id


def _tracker_key(record_id: str) -> Dict[str, Dict]:
    """Convert a record ID like 'DVP-TSK-245' or 'DVP-TSK-245-0A' into DynamoDB key dict."""
    record_id = record_id.strip().upper()
    parts = record_id.split("-")
    if len(parts) < 3 or len(parts) > 4:
        raise ValueError(f"Invalid record ID format: {record_id!r}. Expected PREFIX-TYPE-NNN or PREFIX-TYPE-NNN-SS")
    prefix = parts[0]
    type_seg = parts[1]
    project_name = _resolve_prefix(prefix)
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


_BASE36_CHARS_MCP = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _b36_to_str_mcp(v: int) -> str:
    r = []
    for _ in range(3):
        r.append(_BASE36_CHARS_MCP[v % 36])
        v //= 36
    return "".join(reversed(r))

def _str_to_b36_mcp(s: str) -> int:
    result = 0
    for ch in s:
        idx = _BASE36_CHARS_MCP.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid base-36 character {ch!r}")
        result = result * 36 + idx
    return result

def _is_legacy_pattern_mcp(s: str) -> bool:
    if s.isdigit():
        return True
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        num = int(s[1:])
        if 1 <= num <= 99:
            return True
    return False

_EXT_B36_TO_COUNTER_MCP: dict = {}
_EXT_COUNTER_TO_B36_MCP: list = []

def _init_ext_tables_mcp():
    idx = 0
    for v in range(46656):
        s = _b36_to_str_mcp(v)
        if not _is_legacy_pattern_mcp(s):
            _EXT_COUNTER_TO_B36_MCP.append(v)
            _EXT_B36_TO_COUNTER_MCP[v] = 3574 + idx
            idx += 1

_init_ext_tables_mcp()


def _encode_base36(n: int) -> str:
    """Encode a non-negative integer into a 3-char sequence (ENC-FTR-056)."""
    if n < 0:
        raise ValueError(f"Counter must be >= 0, got {n}")
    if n > 46655:
        raise ValueError(f"Base-36 capacity exhausted at counter {n}.")
    if n <= 999:
        return str(n).zfill(3)
    offset = n - 1000
    letter_index = offset // 99
    number = (offset % 99) + 1
    if letter_index <= 25:
        return chr(65 + letter_index) + str(number).zfill(2)
    ext_idx = n - 3574
    return _b36_to_str_mcp(_EXT_COUNTER_TO_B36_MCP[ext_idx])


def _decode_base36(s: str) -> int:
    """Decode a sequence string back into an integer (ENC-FTR-056)."""
    if not s:
        raise ValueError("Empty sequence")
    s = s.upper()
    if s.isdigit():
        return int(s)
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        letter_index = ord(s[0]) - 65
        number = int(s[1:])
        if 0 <= letter_index <= 25 and 1 <= number <= 99:
            return 1000 + (letter_index * 99) + (number - 1)
    try:
        b36_val = _str_to_b36_mcp(s)
    except ValueError:
        raise ValueError(f"Invalid sequence: {s!r}")
    counter = _EXT_B36_TO_COUNTER_MCP.get(b36_val)
    if counter is not None:
        return counter
    raise ValueError(f"Invalid sequence: {s!r}")


def _record_numeric_suffix(record_id: str) -> Optional[int]:
    parts = str(record_id).strip().split("-")
    if len(parts) < 3:
        return None
    try:
        return _decode_base36(parts[2])
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
    return f"{prefix}-{type_suffix}-{_encode_base36(next_num)}"


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


def _normalize_env_string_list(raw: Any) -> List[str]:
    if raw in (None, "", []):
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        parsed: Any = None
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
        if isinstance(parsed, list):
            source = parsed
        else:
            source = text.split(",")
    elif isinstance(raw, list):
        source = raw
    else:
        return []

    out: List[str] = []
    for entry in source:
        if entry is None:
            continue
        value = str(entry).strip()
        if value and value not in out:
            out.append(value)
    return out


def _configured_raw_tool_allowlist() -> Optional[set[str]]:
    raw_tools = _normalize_env_string_list(
        os.environ.get("COORDINATION_ALLOWED_RAW_TOOLS_JSON")
        or os.environ.get("COORDINATION_ALLOWED_RAW_TOOLS")
    )
    if raw_tools:
        return set(raw_tools)

    legacy_tools = [
        tool
        for tool in _normalize_env_string_list(
            os.environ.get("COORDINATION_ALLOWED_TOOLS_JSON")
            or os.environ.get("COORDINATION_ALLOWED_TOOLS")
        )
        if tool not in _CODE_MODE_TOOL_SET
    ]
    if legacy_tools:
        return set(legacy_tools)
    return None


def _raw_tool_allowed(tool_name: str) -> bool:
    allowlist = _configured_raw_tool_allowlist()
    if allowlist is None:
        return True
    return str(tool_name or "").strip() in allowlist


def _tool_content_to_plain(content: list[TextContent]) -> Any:
    texts = [item.text for item in content if hasattr(item, "text")]
    if not texts:
        return None
    if len(texts) == 1:
        text = texts[0]
        if isinstance(text, str):
            stripped = text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    return json.loads(stripped)
                except json.JSONDecodeError:
                    pass
        return text

    parsed_items: List[Any] = []
    for text in texts:
        if isinstance(text, str):
            stripped = text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    parsed_items.append(json.loads(stripped))
                    continue
                except json.JSONDecodeError:
                    pass
        parsed_items.append(text)
    return parsed_items


async def _invoke_raw_tool(
    name: str,
    arguments: Dict[str, Any],
    *,
    require_allowlist: bool = True,
) -> Dict[str, Any]:
    tool_name = str(name or "").strip()
    if not tool_name:
        raise ValueError("tool name is required")
    if tool_name in _CODE_MODE_TOOL_SET:
        raise ValueError(f"Meta tool '{tool_name}' cannot be invoked as a raw tool")
    if require_allowlist and not _raw_tool_allowed(tool_name):
        raise PermissionError(f"Raw tool '{tool_name}' is outside the current session boundary")

    handler = _TOOL_HANDLERS.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown raw tool '{tool_name}'")

    content = await handler(arguments or {})
    status = _tool_result_status(content)
    return {
        "tool": tool_name,
        "arguments": arguments or {},
        "content": content,
        "payload": _tool_content_to_plain(content),
        "status": status,
        "error_code": "" if status == "success" else _tool_error_code(content),
    }


def _meta_tool_success(
    tool_name: str,
    *,
    action: str = "",
    result: Any = None,
    mode: str = "",
    steps: Optional[List[Dict[str, Any]]] = None,
    underlying_calls: Optional[List[Dict[str, Any]]] = None,
    warnings: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
    partial: bool = False,
) -> list[TextContent]:
    payload: Dict[str, Any] = {
        "success": True,
        "interface_mode": INTERFACE_MODE,
        "tool": tool_name,
    }
    if action:
        payload["action"] = action
    if mode:
        payload["mode"] = mode
    if result is not None:
        payload["result"] = result
    if steps is not None:
        payload["step_results"] = steps
    payload["dry_run"] = bool(dry_run)
    payload["partial"] = bool(partial)
    payload["underlying_calls"] = underlying_calls or []
    if metadata:
        payload["metadata"] = metadata
    if warnings:
        payload["warnings"] = warnings
    return _result_text(payload)


def _meta_tool_error(
    tool_name: str,
    *,
    code: str,
    message: str,
    action: str = "",
    mode: str = "",
    underlying_calls: Optional[List[Dict[str, Any]]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> list[TextContent]:
    payload = _error_payload(code=code, message=message, details=details)
    payload["interface_mode"] = INTERFACE_MODE
    payload["tool"] = tool_name
    if action:
        payload["action"] = action
    if mode:
        payload["mode"] = mode
    payload["underlying_calls"] = underlying_calls or []
    return _result_text(payload)


def _result_text(data: Any) -> list:
    """Format a result as TextContent for MCP tool response."""
    if isinstance(data, str):
        return [TextContent(type="text", text=data)]
    return [TextContent(type="text", text=json.dumps(data, default=str))]


def _paginate(items: list, page_size: int, cursor: str | None, key_fn) -> tuple:
    """Client-side cursor pagination helper (ENC-TSK-820).

    Returns (page_items, next_cursor_or_None, total_count).
    key_fn(item) -> str  must produce a unique, deterministic sort key per item.
    cursor is a base64-encoded key value; items with key <= cursor are skipped.
    """
    total = len(items)
    page_size = max(1, min(page_size, 100))

    if cursor:
        try:
            decoded = base64.urlsafe_b64decode(cursor.encode()).decode()
        except Exception:
            decoded = ""
        # Skip past the cursor position
        start_idx = 0
        for i, item in enumerate(items):
            if key_fn(item) == decoded:
                start_idx = i + 1
                break
        items = items[start_idx:]

    page = items[:page_size]
    next_cursor = None
    if len(items) > page_size:
        last_key = key_fn(page[-1])
        next_cursor = base64.urlsafe_b64encode(last_key.encode()).decode()

    return page, next_cursor, total


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


_governance_hash_api_cache: Optional[str] = None
_governance_hash_api_cache_at: float = 0.0
_GOVERNANCE_HASH_API_TTL = 60.0  # seconds


def _get_governance_hash_via_api() -> str:
    """Fetch governance hash from HTTP API with short TTL cache.

    Resolution order:
      1) governance API /hash (authoritative)
      2) health API governance_hash (auth-safe fallback)
      3) local computation from governance resources
    """
    global _governance_hash_api_cache, _governance_hash_api_cache_at
    now = time.time()
    if _governance_hash_api_cache and (now - _governance_hash_api_cache_at) < _GOVERNANCE_HASH_API_TTL:
        return _governance_hash_api_cache

    def _cache_and_return(value: str) -> str:
        nonlocal now
        global _governance_hash_api_cache, _governance_hash_api_cache_at
        _governance_hash_api_cache = value
        _governance_hash_api_cache_at = now
        return value

    try:
        resp = _governance_api_request("GET", "/hash")
        h = str(resp.get("governance_hash") or "").strip()
        if h:
            return _cache_and_return(h)
    except Exception:
        pass

    # Fallback for auth-gated environments where /hash cannot be called directly.
    try:
        health = _health_api_request()
        h = str(health.get("governance_hash") or "").strip()
        if h:
            return _cache_and_return(h)
    except Exception:
        pass

    # Final fallback to local computation.
    return _compute_governance_hash()


def _cache_governance_hash(value: str) -> None:
    global _governance_hash_api_cache, _governance_hash_api_cache_at
    _governance_hash_api_cache = value
    _governance_hash_api_cache_at = time.time()


def _current_governance_hash_for_validation(provided: str) -> str:
    """Resolve current governance hash with stale-cache self-healing.

    Primary compare uses API/health hash. If it mismatches the provided hash,
    perform one forced local recomputation from governance resources.
    """
    current = _get_governance_hash_via_api()
    if provided == current:
        return current

    fresh_local = _compute_governance_hash(force_refresh=True)
    if provided == fresh_local:
        _cache_governance_hash(fresh_local)
        return fresh_local
    return current


def _require_governance_hash(args: dict) -> Optional[str]:
    provided = str(args.get("governance_hash") or "").strip()
    if not provided:
        return "Missing governance_hash for write-capable MCP tool call"
    current = _current_governance_hash_for_validation(provided)
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
    current = _current_governance_hash_for_validation(provided)
    if provided != current:
        fresh_local = _compute_governance_hash(force_refresh=True)
        return _error_payload(
            "GOVERNANCE_STALE",
            "provided governance_hash does not match current governance bundle",
            retryable=True,
            details={
                "provided": provided,
                "current": current,
                "fresh_local": fresh_local,
            },
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
        envelope = response_body.get("error_envelope")
        if isinstance(envelope, dict):
            code = str(envelope.get("code") or default_code or _error_code_from_http_status(status_code)).strip().upper()
            message = str(
                envelope.get("message")
                or response_body.get("error")
                or f"Request failed with status {status_code}"
            )
            retryable = bool(
                envelope.get(
                    "retryable",
                    code in {"TIMEOUT", "UPSTREAM_ERROR", "RATE_LIMITED"},
                )
            )
            details = envelope.get("details")
            if not isinstance(details, dict):
                details = {}
            merged_details = dict(details)
            for key, value in response_body.items():
                if key in {"success", "error", "error_envelope"}:
                    continue
                merged_details.setdefault(key, value)
            return {
                "success": False,
                "error": message,
                "error_envelope": {
                    "code": code,
                    "message": message,
                    "retryable": retryable,
                    "details": merged_details,
                },
                **merged_details,
            }
        existing = response_body.get("error")
        if isinstance(existing, dict) and {"code", "message", "retryable"}.issubset(existing.keys()):
            return response_body
        if isinstance(existing, str):
            code = default_code or _error_code_from_http_status(status_code)
            return {
                "success": False,
                "error": existing,
                "error_envelope": {
                    "code": code,
                    "message": existing,
                    "retryable": code in {"TIMEOUT", "UPSTREAM_ERROR", "RATE_LIMITED"},
                    "details": {},
                },
            }
    code = default_code or _error_code_from_http_status(status_code)
    message = (
        response_body if isinstance(response_body, str)
        else f"Request failed with status {status_code}"
    )
    return {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": code in {"TIMEOUT", "UPSTREAM_ERROR", "RATE_LIMITED"},
            "details": {},
        },
    }


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
    if DEPLOY_API_COOKIE:
        headers["Cookie"] = DEPLOY_API_COOKIE
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None

    # Try configured deploy key first, then fallback candidates to survive auth-key drift/rotation.
    key_candidates: List[str] = []
    for candidate in (
        DEPLOY_API_INTERNAL_API_KEY,
        *DEPLOY_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers, data=body)
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
            if exc.code in (401, 403) and idx < len(key_candidates) - 1:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Deployment API unreachable: {exc}", retryable=True)
        except Exception as exc:  # pragma: no cover - defensive fallback
            return _error_payload("INTERNAL_ERROR", f"Deployment API request failed: {exc}", retryable=False)

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _changelog_api_request(
    method: str,
    path: str,
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP client for the changelog API — mirrors _deploy_api_request."""
    base = CHANGELOG_API_BASE.rstrip("/")
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
    if DEPLOY_API_COOKIE:
        headers["Cookie"] = DEPLOY_API_COOKIE

    key_candidates: List[str] = []
    for candidate in (
        DEPLOY_API_INTERNAL_API_KEY,
        *DEPLOY_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers, data=None)
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
            if exc.code in (401, 403) and idx < len(key_candidates) - 1:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Changelog API unreachable: {exc}", retryable=True)
        except Exception as exc:  # pragma: no cover - defensive fallback
            return _error_payload("INTERNAL_ERROR", f"Changelog API request failed: {exc}", retryable=False)

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _github_api_request(
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the GitHub integration API."""
    base = GITHUB_API_BASE.rstrip("/")
    route = path if path.startswith("/") else f"/{path}"
    url = f"{base}{route}"
    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if GITHUB_API_INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = GITHUB_API_INTERNAL_API_KEY
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
        return _error_payload("UPSTREAM_ERROR", f"GitHub API unreachable: {exc}", retryable=True)
    except Exception as exc:
        return _error_payload("INTERNAL_ERROR", f"GitHub API request failed: {exc}", retryable=False)


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


def _tracker_api_request(
    method: str,
    path: str = "",
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the tracker CRUD API (Phase 2a)."""
    base = TRACKER_API_BASE.rstrip("/")
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
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None

    key_candidates: List[str] = []
    for candidate in (
        TRACKER_API_INTERNAL_API_KEY,
        *TRACKER_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers, data=body)
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
            if exc.code in (401, 403) and idx < len(key_candidates) - 1:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Tracker API unreachable: {exc}", retryable=True)
        except Exception as exc:
            return _error_payload("INTERNAL_ERROR", f"Tracker API request failed: {exc}", retryable=False)

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _checkout_api_request(
    method: str,
    path: str = "",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the checkout service API (ENC-FTR-037)."""
    base = CHECKOUT_SERVICE_API_BASE.rstrip("/")
    route = path if path.startswith("/") else (f"/{path}" if path else "")
    url = f"{base}{route}"
    headers: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body: Optional[bytes] = json.dumps(payload).encode("utf-8")
    else:
        body = None

    for candidate in (
        TRACKER_API_INTERNAL_API_KEY,
        *TRACKER_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
        "",
    ):
        key = str(candidate or "").strip()
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers, data=body)
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
            if exc.code in (401, 403) and key:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Checkout service unreachable: {exc}", retryable=True)
        except Exception as exc:
            return _error_payload("INTERNAL_ERROR", f"Checkout API request failed: {exc}", retryable=False)
        break

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _governance_api_request(
    method: str,
    path: str = "",
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the governance API (Phase 2b)."""
    base = GOVERNANCE_API_BASE.rstrip("/")
    route = path if path.startswith("/") else (f"/{path}" if path else "")
    url = f"{base}{route}"
    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }
    if GOVERNANCE_API_INTERNAL_API_KEY:
        headers["X-Coordination-Internal-Key"] = GOVERNANCE_API_INTERNAL_API_KEY
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    req = urllib.request.Request(url=url, method=method.upper(), headers=headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
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
        return _error_payload("UPSTREAM_ERROR", f"Governance API unreachable: {exc}", retryable=True)
    except Exception as exc:
        return _error_payload("INTERNAL_ERROR", f"Governance API request failed: {exc}", retryable=False)


def _projects_api_request(
    method: str,
    path: str = "",
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the projects API (Phase 2b, read-only)."""
    base = PROJECTS_API_BASE.rstrip("/")
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
    key_candidates: List[str] = []
    for candidate in (
        PROJECTS_API_INTERNAL_API_KEY,
        *PROJECTS_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers)
        try:
            with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
                text = resp.read().decode("utf-8")
                return json.loads(text) if text else {"success": True}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"error": raw or str(exc)}
            if exc.code in (401, 403) and idx < len(key_candidates) - 1:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Projects API unreachable: {exc}", retryable=True)
        except Exception as exc:
            return _error_payload("INTERNAL_ERROR", f"Projects API request failed: {exc}", retryable=False)

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _coordination_api_request(
    method: str,
    path: str = "",
    payload: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP request to the coordination API."""
    base = COORDINATION_API_BASE.rstrip("/")
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
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None

    key_candidates: List[str] = []
    for candidate in (
        COORDINATION_API_INTERNAL_API_KEY,
        *COORDINATION_API_INTERNAL_API_KEYS,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method=method.upper(), headers=attempt_headers, data=body)
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
            if exc.code in (401, 403) and idx < len(key_candidates) - 1:
                continue
            return _normalize_legacy_error_payload(parsed, exc.code)
        except urllib.error.URLError as exc:
            return _error_payload("UPSTREAM_ERROR", f"Coordination API unreachable: {exc}", retryable=True)
        except Exception as exc:
            return _error_payload("INTERNAL_ERROR", f"Coordination API request failed: {exc}", retryable=False)

    return _error_payload("PERMISSION_DENIED", "Authentication required", retryable=False)


def _health_api_request() -> Dict[str, Any]:
    """HTTP request to the health API (Phase 2b)."""
    headers = {"Accept": "application/json", "User-Agent": HTTP_USER_AGENT}
    req = urllib.request.Request(url=HEALTH_API_URL, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
            text = resp.read().decode("utf-8")
            return json.loads(text) if text else {}
    except Exception as exc:
        return {"error": str(exc), "dynamodb": "unknown", "s3": "unknown"}


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
    if name == "governance_data_dictionary.json":
        return "governance://governance_data_dictionary.json"
    return None


def _governance_catalog_from_s3() -> Dict[str, Dict[str, Any]]:
    """Build governance catalog from deterministic S3 prefix (ENC-TSK-474).

    Lists objects under ``S3_GOVERNANCE_PREFIX`` and derives governance URIs
    from S3 key structure.

    Important: this catalog path avoids fetching object bodies to keep
    resources/list and resources/read bootstrap latency low. Content hashes are
    computed lazily in ``_compute_governance_hash`` when needed.
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

        last_modified = obj.get("LastModified")
        updated_at = last_modified.isoformat() if hasattr(last_modified, "isoformat") else str(last_modified or "")

        catalog[uri] = {
            "file_name": rel_path,
            "s3_bucket": S3_BUCKET,
            "s3_key": s3_key,
            "content_hash": "",
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


def _governance_s3_keys_from_uri(uri_text: str) -> List[str]:
    uri = str(uri_text or "").strip()
    if uri == "governance://agents.md":
        prefix = S3_GOVERNANCE_PREFIX.rstrip("/")
        return [
            f"{prefix}/agents.md",
            f"{prefix}/agents/agents.md",
        ]
    if uri.startswith("governance://agents/"):
        rel = uri.replace("governance://", "", 1)
        return [f"{S3_GOVERNANCE_PREFIX.rstrip('/')}/{rel}"]
    return []


def _read_governance_text_cached(
    *,
    uri: str,
    bucket: str,
    key: str,
    force_refresh: bool = False,
) -> str:
    now = time.time()
    if not force_refresh:
        cached = _governance_resource_body_cache.get(uri)
        if cached and (now - float(cached.get("cached_at") or 0.0)) < GOVERNANCE_RESOURCE_BODY_TTL_SECONDS:
            return str(cached.get("text") or "")

    resp = _get_s3().get_object(Bucket=bucket, Key=key)
    text = resp["Body"].read().decode("utf-8")
    _governance_resource_body_cache[uri] = {
        "cached_at": now,
        "bucket": bucket,
        "key": key,
        "text": text,
    }
    return text


def _compute_governance_hash(force_refresh: bool = False) -> str:
    """SHA-256 of governance resources resolved from docstore catalog."""
    catalog = _governance_catalog(force_refresh=force_refresh)
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
                text = _read_governance_text_cached(
                    uri=uri,
                    bucket=str(meta.get("s3_bucket") or S3_BUCKET),
                    key=s3_key,
                    force_refresh=force_refresh,
                )
                content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
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
    seen_uris: set[str] = set()

    # Governance files (authoritative source: S3 governance/live/, fallback: docstore)
    for uri, meta in sorted(_governance_catalog().items()):
        seen_uris.add(uri)
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

    # Ensure agents.md is always discoverable, even when catalog resolution is empty.
    if "governance://agents.md" not in seen_uris:
        resources.insert(
            0,
            Resource(
                uri="governance://agents.md",
                name="agents.md — Global governance directives",
                mimeType="text/markdown",
            ),
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
        direct_err = ""
        for direct_key in _governance_s3_keys_from_uri(uri_text):
            try:
                return _read_governance_text_cached(
                    uri=uri_text,
                    bucket=S3_BUCKET,
                    key=direct_key,
                )
            except Exception as exc:
                direct_err = str(exc)

        catalog = _governance_catalog()
        meta = catalog.get(uri_text)
        if not meta:
            if direct_err:
                return f"# Failed to fetch governance resource {uri_text} from deterministic S3 path: {direct_err}"
            return f"# Governance resource not found: {uri_text}"
        s3_key = str(meta.get("s3_key") or "").strip()
        if not s3_key:
            return f"# Governance resource missing s3_key: {uri_text}"
        try:
            return _read_governance_text_cached(
                uri=uri_text,
                bucket=str(meta.get("s3_bucket") or S3_BUCKET),
                key=s3_key,
            )
        except Exception as exc:
            return f"# Failed to fetch governance resource {uri_text}: {exc}"

    # projects://reference/{project_id} (ENC-ISS-108: reads from document store)
    if uri_text.startswith("projects://reference/"):
        project_id = uri_text.replace("projects://reference/", "")
        content, _source_info, error = _fetch_reference_content(project_id)
        if content:
            return content
        error_msg = error.get("message", "not found") if error else "not found"
        return f"# Failed to fetch reference for {project_id}: {error_msg}"

    return f"# Unknown resource URI: {uri_text}"


# -------------------------------------------------------------------
# TOOLS — governed write/read operations
# -------------------------------------------------------------------


def _code_mode_tool_catalog() -> list[Tool]:
    return [
        Tool(
            name="search",
            description=(
                "Compact read-only discovery surface over governed Enceladus resources. "
                "Use action + arguments to access project, tracker, document, deploy, changelog, "
                "governance, reference, and health lookups."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": (
                            "Read action identifier such as projects.list, tracker.get, "
                            "tracker.graphsearch, documents.search, deploy.history, "
                            "changelog.version, governance.dictionary, reference.search, "
                            "or system.connection_health."
                        ),
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Arguments forwarded to the governed underlying read tool.",
                    },
                },
                "required": ["action"],
            },
        ),
        Tool(
            name="coordination",
            description=(
                "Compact coordination/orchestration surface for capabilities, request inspection, "
                "dispatch-plan generation, and managed-session auth helpers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": (
                            "Coordination action identifier such as capabilities.get, request.get, "
                            "dispatch_plan.generate, dispatch_plan.dry_run, or auth.cognito_session."
                        ),
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Arguments forwarded to the governed coordination helper.",
                    },
                },
                "required": ["action"],
            },
        ),
        Tool(
            name="get_compact_context",
            description=(
                "Budgeted composite context assembly that reuses existing issue-context, codemap, "
                "architecture, document, governance, and project helpers while preserving raw codemap payloads."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "description": "Context mode: record, issue, task, feature, project, document, or topic.",
                    },
                    "record_id": {
                        "type": "string",
                        "description": "Tracker record ID for record-oriented modes.",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Project ID for project/topic modes and codemap lookups.",
                    },
                    "document_id": {
                        "type": "string",
                        "description": "Document ID for document mode.",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Optional codemap domain filter using the existing get_code_map payload semantics.",
                    },
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional architecture or topic domains.",
                    },
                    "max_tokens": {
                        "type": "integer",
                        "description": "Token budget forwarded to existing composite helpers where supported.",
                    },
                    "history_limit": {
                        "type": "integer",
                        "description": "History limit forwarded to record context helpers.",
                    },
                    "query": {
                        "type": "string",
                        "description": "Topic or reference search query.",
                    },
                    "include_code_map": {
                        "type": "boolean",
                        "description": "If true (default), include the existing get_code_map payload under code_map.",
                    },
                    "include_governance": {
                        "type": "boolean",
                        "description": "If true, include governance dictionary slices when available.",
                    },
                    "include_related_documents": {
                        "type": "boolean",
                        "description": "If true, include related document summaries when available.",
                    },
                },
            },
        ),
        Tool(
            name="execute",
            description=(
                "Governed workflow runner for ordered mutation or lifecycle steps. "
                "Each step resolves through existing MCP/HTTP handlers, supports dry_run, "
                "and returns per-step status with resolved underlying calls."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, resolve and validate steps without executing them.",
                    },
                    "steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "description": (
                                        "Action identifier such as tracker.create, documents.patch, "
                                        "deploy.submit, checkout.advance, or github.create_issue."
                                    ),
                                },
                                "arguments": {
                                    "type": "object",
                                    "description": "Arguments forwarded to the governed underlying tool.",
                                },
                                "on_error": {
                                    "type": "string",
                                    "description": "abort (default) or continue.",
                                },
                                "dry_run": {
                                    "type": "boolean",
                                    "description": "Optional step-level dry-run override.",
                                },
                            },
                            "required": ["action"],
                        },
                        "description": "Ordered governed execution steps.",
                    },
                },
                "required": ["steps"],
            },
        ),
    ]


@app.list_tools()
async def list_tools() -> list[Tool]:
    if INTERFACE_MODE == INTERFACE_MODE_CODE:
        return _code_mode_tool_catalog()
    tools = [
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
                    },
                    "include_history": {
                        "type": "boolean",
                        "description": "If true, include full history[] and write_source fields. Default false (summary only).",
                    },
                },
                "required": ["record_id"],
            },
        ),
        Tool(
            name="tracker_validation_rules",
            description=(
                "Preflight tracker edit rules for a record before calling tracker_set. "
                "Returns allowed status transitions, required transition_evidence fields, "
                "checkout/provider requirements, and dictionary-backed field guidance."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The record ID to preflight (e.g., ENC-TSK-628).",
                    },
                    "target_status": {
                        "type": "string",
                        "description": "Optional status to preflight against current record state.",
                    },
                    "provider": {
                        "type": "string",
                        "description": (
                            "Optional provider identity to evaluate task checkout ownership "
                            "requirements for status transitions."
                        ),
                    },
                    "include_dictionary": {
                        "type": "boolean",
                        "description": (
                            "If true (default), include governance dictionary lookup for "
                            "this record type."
                        ),
                    },
                },
                "required": ["record_id"],
            },
        ),
        Tool(
            name="tracker_list",
            description="List tracker records for a project. Filter by type and/or status. Paginated (default 25).",
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
                    "page_size": {
                        "type": "integer",
                        "description": "Max records per page (default 25, max 100).",
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Pagination cursor from previous response's next_cursor.",
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
            description="Set a field on a tracker record. Task status→use advance_task_status. Task worklogs→use append_worklog.",
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
                        "type": ["string", "number", "boolean", "object", "array", "null"],
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
                    "transition_evidence": {
                        "type": "object",
                        "description": (
                            "Evidence for gated status transitions (ENC-FTR-022). "
                            "NOTE: Task status transitions must use advance_task_status tool. "
                            "Any revert: {revert_reason}."
                        ),
                    },
                },
                "required": ["record_id", "field", "value", "governance_hash"],
            },
        ),
        Tool(
            name="tracker_log",
            description="Append worklog to an issue or feature. For tasks, use append_worklog (checkout required).",
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
                    "hypothesis": {
                        "type": "string",
                        "description": "Root cause hypothesis (issues). Required if technical_notes not provided.",
                    },
                    "technical_notes": {
                        "type": "string",
                        "description": "Technical investigation context (issues). Required if hypothesis not provided.",
                    },
                    "location_hint": {
                        "type": "string",
                        "description": "Suspected code paths for investigation (issues). Required at issue creation.",
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
                "Set evidence on a specific acceptance criterion of a feature or task record. "
                "Part of the governed evidence handshake: features cannot be completed and "
                "tasks cannot be closed until ALL structured acceptance criteria have "
                "evidence and evidence_acceptance=true (ENC-FTR-048)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The feature or task record ID.",
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
            description="List documents for a project. Paginated (default 25).",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name.",
                    },
                    "page_size": {
                        "type": "integer",
                        "description": "Max documents per page (default 25, max 100).",
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Pagination cursor from previous response's next_cursor.",
                    },
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
        # --- Code Navigation (ENC-TSK-805) ---
        Tool(
            name="get_code_map",
            description=(
                "Get a code navigation map for a project by querying the component registry. "
                "Returns component source_paths and domain-to-file mappings. "
                "Use domain param to filter to a specific domain (e.g., 'auth', 'routing')."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., enceladus).",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Optional domain filter (e.g., 'auth', 'tracker', 'feeds'). Returns only files for that domain.",
                    },
                },
                "required": ["project_id"],
            },
        ),
        # --- Context Assembly (ENC-TSK-829/830) ---
        Tool(
            name="get_issue_context",
            description=(
                "Composite context retrieval for a tracker record. Bundles record core fields, "
                "relationship graph, component source paths, domain architecture excerpts, and "
                "recent history into a single response. Replaces 4-5 sequential tool calls. "
                "For issues with a location_hint, auto-resolves to matching components via fuzzy matching. "
                "Use include_* flags to control which sections are returned."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "Tracker record ID (e.g., ENC-ISS-105, ENC-TSK-829).",
                    },
                    "include_components": {
                        "type": "boolean",
                        "description": "Include component source paths from component registry. Default true.",
                        "default": True,
                    },
                    "include_architecture": {
                        "type": "boolean",
                        "description": "Include domain architecture excerpts for matched components. Default true.",
                        "default": True,
                    },
                    "include_recent_history": {
                        "type": "boolean",
                        "description": "Include recent worklog/history entries. Default true.",
                        "default": True,
                    },
                    "history_limit": {
                        "type": "integer",
                        "description": "Max history entries to return. Default 10.",
                        "default": 10,
                    },
                    "max_tokens": {
                        "type": "integer",
                        "description": "Approximate output budget in tokens. Sections are truncated in priority order when exceeded. Default 2500.",
                        "default": 2500,
                    },
                },
                "required": ["record_id"],
            },
        ),
        Tool(
            name="get_architecture_excerpts",
            description=(
                "Return architecture documentation excerpts for specific domains. "
                "Maps component registry domains to architecture source files and returns "
                "only matched sections with heading metadata. Use this instead of loading "
                "full architecture docs when only one or two domains are relevant. "
                "Supports 30+ domain aliases: compute, data, dynamodb, lambda, api, governance, "
                "security, auth, cognito, frontend, pwa, cloudfront, deploy, monitoring, mcp, "
                "coordination, infrastructure, cloudformation, and more."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., enceladus).",
                    },
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Domain names to retrieve excerpts for (e.g., ['compute', 'auth', 'deploy']).",
                    },
                    "max_excerpt_tokens": {
                        "type": "integer",
                        "description": "Max approximate tokens for all excerpts combined. Default 1200.",
                        "default": 1200,
                    },
                },
                "required": ["project_id", "domains"],
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
            description=(
                "Submit a deployment request. Returns request_id and projected_next_version. "
                "Major/minor deploys require release notes via documents_put (guidance returned in response). "
                "Patch deploys have no release notes requirement."
            ),
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
                    "pr_id": {
                        "type": "integer",
                        "description": "GitHub PR number that was merged for this deployment (required by deploy_intake). E.g. 75.",
                    },
                    "merged_at": {
                        "type": "string",
                        "description": "ISO 8601 timestamp when the PR was merged (e.g. '2026-03-02T04:35:24Z'). Must match GitHub API value.",
                    },
                    "pr_owner": {
                        "type": "string",
                        "description": "GitHub repo owner for PR merge validation. Defaults to 'NX-2021-L' if omitted.",
                    },
                    "pr_repo": {
                        "type": "string",
                        "description": "GitHub repo name for PR merge validation. Defaults to 'enceladus' if omitted.",
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
                "required": ["project_id", "change_type", "deployment_type", "summary", "changes", "pr_id", "merged_at", "governance_hash"],
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
            description="Manually trigger the deploy orchestration pipeline through the deploy intake API. Use when requests are pending but the pipeline wasn't triggered automatically.",
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
                    "limit": {
                        "type": "integer",
                        "description": "Maximum pending requests to return (default 50, max 200).",
                    },
                },
                "required": ["project_id"],
            },
        ),
        # --- Changelog (ENC-FTR-033) ---
        Tool(
            name="changelog_history",
            description="Fetch deployment history for a project. Returns version, change_type, changes[], deployed_at. Filterable by change_type.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., 'enceladus', 'devops').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max entries to return (default 20, max 100).",
                        "default": 20,
                    },
                    "change_type": {
                        "type": "string",
                        "description": "Filter by change type: 'major', 'minor', or 'patch'.",
                        "enum": ["major", "minor", "patch"],
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="changelog_history_all",
            description="Fetch deployment history across multiple projects. Returns merged time-sorted deploy records.",
            inputSchema={
                "type": "object",
                "properties": {
                    "projects": {
                        "type": "string",
                        "description": "Comma-separated project names (e.g., 'enceladus,devops,harrisonfamily').",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max entries per project to return (default 20, max 100).",
                        "default": 20,
                    },
                    "change_type": {
                        "type": "string",
                        "description": "Filter by change type: 'major', 'minor', or 'patch'.",
                        "enum": ["major", "minor", "patch"],
                    },
                },
                "required": ["projects"],
            },
        ),
        Tool(
            name="changelog_version",
            description=(
                "Fetch the current deployed version for a project. "
                "Reads S3 deploy-config/{project_id}/current-version.json and returns "
                "{project_id, version, deployed_at, spec_id}. "
                "Use this to display the active version of any Enceladus project."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "The project name (e.g., 'enceladus', 'devops').",
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
        Tool(
            name="coordination_cognito_session",
            description=(
                "Create a Cognito-authenticated cookie bundle for terminal diagnostics "
                "against protected Enceladus PWA routes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_origin": {
                        "type": "string",
                        "description": "Optional https origin for browser cookie scoping (default: https://jreese.net).",
                    },
                    "include_set_cookie_headers": {
                        "type": "boolean",
                        "description": "Include serialized Set-Cookie header strings in the response. Default true.",
                        "default": True,
                    },
                    "include_tokens": {
                        "type": "boolean",
                        "description": "Include raw Cognito tokens in response for advanced debugging. Default false.",
                        "default": False,
                    },
                },
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
        Tool(
            name="governance_get",
            description=(
                "Read a governance file by name and return its content. "
                "Use to load governance://agents.md and other governance resources "
                "during session bootstrap without requiring direct S3 access."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_name": {
                        "type": "string",
                        "description": (
                            "Governance file name (e.g., 'agents.md' or "
                            "'agents/dispatch-heuristics.md'). "
                            "Defaults to 'agents.md' if not specified."
                        ),
                    },
                },
                "required": ["file_name"],
            },
        ),
        Tool(
            name="governance_dictionary",
            description="Query governance data dictionary. No args=compact index; entity=full schema; entity+field=definition; entity+field+value=enum validation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity": {
                        "type": "string",
                        "description": (
                            "Entity to look up (e.g., 'tracker.task', "
                            "'deploy.request', 'document.create'). "
                            "Omit for compact index of all entities."
                        ),
                    },
                    "field": {
                        "type": "string",
                        "description": (
                            "Field within the entity to look up "
                            "(e.g., 'status', 'priority'). "
                            "Requires entity."
                        ),
                    },
                    "value": {
                        "type": "string",
                        "description": (
                            "Value to validate against the field's enum. "
                            "Requires entity and field."
                        ),
                    },
                },
            },
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
            description="Generate a dispatch-plan for a coordination request. Accepts optional dispatch_plan_override to bypass auto-generation.",
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
        # ---------------------------------------------------------------
        # GitHub Integration (ENC-FTR-021 Phase 2)
        # ---------------------------------------------------------------
        Tool(
            name="github_create_issue",
            description=(
                "Create a GitHub issue in a repository via the Enceladus GitHub integration. "
                "The issue is created through the registered GitHub App. Optionally links the "
                "issue back to an Enceladus tracker record."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "GitHub repository owner (organization or user).",
                    },
                    "repo": {
                        "type": "string",
                        "description": "GitHub repository name.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Issue title.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Issue body/description (markdown).",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional labels to assign to the issue.",
                    },
                    "record_id": {
                        "type": "string",
                        "description": "Optional Enceladus tracker record ID to link (e.g., ENC-TSK-575).",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "Optional Enceladus project ID for traceability.",
                    },
                },
                "required": ["owner", "repo", "title"],
            },
        ),
        # ---------------------------------------------------------------
        # GitHub Projects v2 (ENC-FTR-021 Phase 4)
        # ---------------------------------------------------------------
        Tool(
            name="github_projects_sync",
            description=(
                "Add a GitHub issue to a GitHub Projects v2 board and optionally set "
                "Status and Priority fields. Requires the issue to already exist. "
                "Use github_create_issue first if needed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "GitHub repository owner (organization or user).",
                    },
                    "repo": {
                        "type": "string",
                        "description": "GitHub repository name.",
                    },
                    "issue_number": {
                        "type": "integer",
                        "description": "GitHub issue number.",
                    },
                    "issue_url": {
                        "type": "string",
                        "description": "GitHub issue URL (alternative to owner/repo/issue_number).",
                    },
                    "project_id": {
                        "type": "string",
                        "description": "GitHub Projects v2 node ID (starts with PVT_). Get from github_projects_list.",
                    },
                    "status": {
                        "type": "string",
                        "description": "Optional status to set (e.g., open, in_progress, closed).",
                    },
                    "priority": {
                        "type": "string",
                        "description": "Optional priority to set (e.g., P0, P1, P2).",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="github_projects_list",
            description=(
                "List GitHub Projects v2 boards for an organization, including field "
                "definitions and option IDs. Use to discover project_id (node ID) for "
                "github_projects_sync."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "org": {
                        "type": "string",
                        "description": "GitHub organization login. Default: NX-2021-L.",
                    },
                    "include_closed": {
                        "type": "boolean",
                        "description": "Include closed projects. Default: false.",
                    },
                },
            },
        ),
        # --- Checkout Service Tools (ENC-FTR-037) ---
        Tool(
            name="checkout_task",
            description=(
                "Check out a task and advance to in-progress. REQUIRED before coding. "
                "Set task.components via tracker_set before checkout (required for agent advances)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The task record ID (e.g., ENC-TSK-730).",
                    },
                    "active_agent_session_id": {
                        "type": "string",
                        "description": "Agent identity checking out the task (e.g., 'claude_agent_sdk').",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                    "coordination_request_id": {
                        "type": "string",
                        "description": "Optional coordination request ID for audit traceability.",
                    },
                },
                "required": ["record_id", "active_agent_session_id", "governance_hash"],
            },
        ),
        Tool(
            name="release_task",
            description=(
                "Release the checkout on a tracker task. "
                "Call when the session is ending or work is complete. "
                "For completed work, prefer advance_task_status to closed instead."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The task record ID to release.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider releasing the task.",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["record_id", "governance_hash"],
            },
        ),
        Tool(
            name="advance_task_status",
            description=(
                "Advance a task's status through the lifecycle arc (the ONLY way to change task status). "
                "Lifecycle: open→in-progress→coding-complete→committed→pr→merged-main→deploy-init→deploy-success→closed. "
                "Each transition may require transition_evidence. Use tracker_validation_rules to preflight. "
                "Requires task checkout and task.components set via tracker_set. "
                "ENC-ISS-106: Parent tasks (those with non-empty subtask_ids) cannot advance from "
                "coding-complete onward unless all direct children have reached at least the target status. "
                "Children at 'closed' satisfy any stage. Advance children before the parent. "
                "Query governance_dictionary(entity='checkout_service') for full gate specs per transition_type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The task record ID to advance.",
                    },
                    "target_status": {
                        "type": "string",
                        "description": (
                            "Target status. Lifecycle: open→in-progress→coding-complete→"
                            "committed→pr→merged-main→deploy-init→deploy-success→closed."
                        ),
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider advancing the task (must match checkout owner).",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                    "transition_evidence": {
                        "type": "object",
                        "description": "Evidence for gated transitions. Use tracker_validation_rules to see required fields for each status.",
                    },
                    "pr_id": {
                        "type": "integer",
                        "description": "GitHub PR number (shortcut for merged-main, same as transition_evidence.pr_id).",
                    },
                    "merged_at": {
                        "type": "string",
                        "description": "PR merged_at timestamp (shortcut for merged-main).",
                    },
                },
                "required": ["record_id", "target_status", "provider", "governance_hash"],
            },
        ),
        Tool(
            name="append_worklog",
            description="Append worklog to a checked-out task. For issues/features use tracker_log.",
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "string",
                        "description": "The task record ID to log against.",
                    },
                    "description": {
                        "type": "string",
                        "description": "Worklog text. Use [START], [INFO], [SUCCESS], [ERROR], [END] tags.",
                    },
                    "provider": {
                        "type": "string",
                        "description": "Provider appending the worklog (must match checkout owner).",
                    },
                    "governance_hash": {
                        "type": "string",
                        "description": "Current governance hash for write authorization.",
                    },
                },
                "required": ["record_id", "description", "provider", "governance_hash"],
            },
        ),
        Tool(
            name="validate_commit_complete",
            description=(
                "Validate a commit-complete-id (CCI-xxx) token issued by the checkout service. "
                "Returns validity + associated task_id. "
                "Used by GitHub Actions pr-commit-gate to verify PRs contain a valid CCI."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "cci_id": {
                        "type": "string",
                        "description": "The commit-complete-id token to validate (format: CCI-{32hex}).",
                    },
                },
                "required": ["cci_id"],
            },
        ),
    ]
    # Expose code-mode meta-tools in raw mode so remote raw-mode clients
    # can discover them via tools/list (ENC-ISS-112).  Handlers already
    # exist in _TOOL_HANDLERS; this just makes them visible.
    tools.extend(_code_mode_tool_catalog())
    return _filter_tool_list_for_session_context(tools)


# -------------------------------------------------------------------
# TOOL HANDLERS
# -------------------------------------------------------------------


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    args = arguments or {}
    started = time.perf_counter()
    try:
        if INTERFACE_MODE == INTERFACE_MODE_CODE and name not in _CODE_MODE_TOOL_SET:
            result = _error_result(
                f"Tool '{name}' is not exposed in code mode. Use one of: {', '.join(CODE_MODE_TOOL_NAMES)}"
            ).content
            _audit_tool_invocation(
                name,
                args,
                "error",
                latency_ms=int((time.perf_counter() - started) * 1000),
                error_code="tool_not_exposed",
            )
            return result
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
    query_params: Dict[str, Any] = {}
    status = args.get("status")
    active = args.get("active")
    if status:
        query_params["status"] = status
    elif active:
        query_params["active"] = "true"
    resp = _projects_api_request("GET", query=query_params or None)
    return _result_text(resp)


async def _projects_get(args: dict) -> list[TextContent]:
    name = args["project_name"]
    resp = _projects_api_request("GET", f"/{name}")
    return _result_text(resp)


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
    include_history = args.get("include_history", False)
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})
    resp = _tracker_api_request("GET", f"/{project_id}/{record_type}/{rid}")
    if resp.get("error"):
        return _result_text(resp)
    record = resp.get("record", resp)
    # Add completeness score (ENC-FTR-013 ontology)
    record["ontology"] = _compute_completeness_score(record)
    # Summary mode: strip verbose fields unless include_history=true
    if not include_history:
        for key in ("history", "write_source", "sync_version", "last_updated_by",
                     "ttl", "gsi1pk", "gsi1sk", "gsi2pk", "gsi2sk"):
            record.pop(key, None)
    return _result_text(record)


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _build_forward_path(record_type: str, current_status: str, terminal_status: str) -> List[str]:
    transitions = TRACKER_VALID_TRANSITIONS.get(record_type, {})
    path: List[str] = []
    seen = {current_status}
    cursor = current_status
    while cursor != terminal_status:
        next_options = sorted(transitions.get(cursor, set()))
        if not next_options:
            break
        nxt = next_options[0]
        path.append(nxt)
        if nxt in seen:
            break
        seen.add(nxt)
        cursor = nxt
    if path and path[-1] == terminal_status:
        return path
    if current_status == terminal_status:
        return []
    return []


async def _tracker_validation_rules(args: dict) -> list[TextContent]:
    record_id = args["record_id"]
    target_status = _normalized_status(args.get("target_status"))
    provider = str(args.get("provider") or "").strip()
    include_dictionary = args.get("include_dictionary", True)

    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    resp = _tracker_api_request("GET", f"/{project_id}/{record_type}/{rid}")
    if resp.get("error"):
        return _result_text(resp)
    record = resp.get("record", resp)

    current_status = _normalized_status(record.get("status"))
    valid_forward = sorted(TRACKER_VALID_TRANSITIONS.get(record_type, {}).get(current_status, set()))
    valid_revert = sorted(TRACKER_REVERT_TRANSITIONS.get(record_type, {}).get(current_status, set()))
    terminal_status = "completed" if record_type == "feature" else "closed"
    close_path = _build_forward_path(record_type, current_status, terminal_status)

    checkout_state = {
        "active_agent_session": bool(record.get("active_agent_session")),
        "active_agent_session_id": str(record.get("active_agent_session_id") or "").strip(),
        "checkout_state": str(record.get("checkout_state") or "").strip(),
        "checked_out_by": str(record.get("checked_out_by") or "").strip(),
    }

    status_requirements = {
        "provider_required_for_task_status_change": (record_type == "task"),
        "active_checkout_required_for_task_status_change": (record_type == "task"),
        "owner_match_required_for_task_status_change": (record_type == "task"),
        "transition_evidence_requirements": TRACKER_STATUS_EVIDENCE_REQUIREMENTS.get(record_type, {}),
    }

    preflight: Dict[str, Any] = {
        "target_status": target_status or None,
        "allowed": None,
        "reasons": [],
    }
    if target_status:
        if target_status == current_status:
            preflight["allowed"] = True
            preflight["reasons"].append("No status change required.")
        elif target_status in valid_forward:
            preflight["allowed"] = True
            if target_status in TRACKER_STATUS_EVIDENCE_REQUIREMENTS.get(record_type, {}):
                req = TRACKER_STATUS_EVIDENCE_REQUIREMENTS[record_type][target_status]
                preflight["reasons"].append(
                    f"Transition requires evidence fields: {', '.join(req['required'])}."
                )
        elif target_status in valid_revert:
            preflight["allowed"] = True
            preflight["reasons"].append(
                "Revert transition requires transition_evidence.revert_reason."
            )
        else:
            preflight["allowed"] = False
            preflight["reasons"].append(
                f"Invalid transition from '{current_status}' to '{target_status}'."
            )

        if record_type == "task" and target_status != current_status:
            if not provider:
                preflight["allowed"] = False
                preflight["reasons"].append(
                    "Task status transitions require provider identity."
                )
            owner = checkout_state["active_agent_session_id"]
            if not checkout_state["active_agent_session"] or not owner:
                preflight["allowed"] = False
                preflight["reasons"].append(
                    "Task status transitions require an active checkout."
                )
            elif provider and provider != owner:
                preflight["allowed"] = False
                preflight["reasons"].append(
                    f"Task is checked out by '{owner}', not '{provider}'."
                )

    result: Dict[str, Any] = {
        "record_id": record_id,
        "record_type": record_type,
        "current_status": current_status,
        "allowed_categories": sorted(TRACKER_VALID_CATEGORIES.get(record_type, set())),
        "allowed_priorities": list(TRACKER_PRIORITY_ENUM),
        "status_rules": {
            "valid_forward": valid_forward,
            "valid_revert": valid_revert,
            "terminal_status": terminal_status,
            "path_to_terminal": close_path,
            "requirements": status_requirements,
        },
        "checkout_state": checkout_state,
        "preflight": preflight,
        "tips": [
            "Call this tool before tracker_set status updates to avoid avoidable 400/409 rejections.",
            "For task status changes, include provider and satisfy checkout ownership first.",
        ],
    }

    if include_dictionary:
        dict_query = f"/dictionary?entity={urllib.parse.quote(f'tracker.{record_type}', safe='')}"
        dict_resp = _governance_api_request("GET", dict_query)
        if dict_resp.get("error"):
            result["dictionary_lookup_error"] = dict_resp["error"]
        else:
            result["dictionary"] = dict_resp

    return _result_text(result)


async def _tracker_list(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    record_type = args.get("record_type")
    status_filter = args.get("status")
    page_size = int(args.get("page_size", 25))
    cursor = args.get("cursor")
    query_params: Dict[str, Any] = {}
    if record_type:
        query_params["type"] = record_type
    if status_filter:
        query_params["status"] = status_filter
    resp = _tracker_api_request("GET", f"/{project_id}", query=query_params or None)
    if resp.get("error"):
        return _result_text(resp)
    items = resp.get("records", [])
    # Orphan detection (ENC-FTR-013): flag tasks without Feature lineage
    orphan_count = 0
    summary = []
    for r in items:
        entry: Dict[str, Any] = {
            "id": r.get("id") or r.get("item_id", ""),
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
    # Cursor pagination (ENC-TSK-820)
    page, next_cursor, total = _paginate(
        summary, page_size, cursor,
        key_fn=lambda e: e.get("id", ""),
    )
    result: Dict[str, Any] = {"records": page, "count": len(page), "total": total}
    if next_cursor:
        result["next_cursor"] = next_cursor
    if orphan_count > 0:
        result["orphan_tasks"] = orphan_count
        result["orphan_warning"] = (
            f"{orphan_count} task(s) have no parent or feature lineage. "
            "Consider linking them to a feature for traceability."
        )
    return _result_text(result)


async def _tracker_pending_updates(args: dict) -> list[TextContent]:
    """List tracker records with non-empty pending update notes."""
    project_id = args.get("project_id")
    scan_all = args.get("all", False)

    if not project_id and not scan_all:
        return _result_text({"error": "Provide project_id or all=true"})

    query_params: Dict[str, Any] = {}
    if project_id:
        query_params["project"] = project_id
    if scan_all:
        query_params["all"] = "true"
    resp = _tracker_api_request("GET", "/pending-updates", query=query_params)
    return _result_text(resp)


async def _tracker_set(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    field = args["field"]
    value = args["value"]

    # ENC-FTR-037: Task status transitions must go through checkout service.
    try:
        _, record_type, _ = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type == "task" and str(field).lower() == "status":
        return _result_text({
            "error": (
                "Task status must be changed via advance_task_status (checkout service). "
                "Use the advance_task_status tool with target_status and your provider identity. "
                "This ensures the checkout gate, token issuance, and GitHub API validation are enforced."
            )
        })

    # --- Phase 2d: HTTP API migration ---
    # All business logic (field validation, session ownership,
    # write source tracking, history append) is handled by the tracker Lambda.
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    payload: Dict[str, Any] = {
        "field": field,
        "value": value,
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]
    if args.get("dispatch_id"):
        payload["dispatch_id"] = args["dispatch_id"]
    if args.get("provider"):
        payload["provider"] = args["provider"]
    if args.get("coordination") is not None:
        payload["coordination"] = args["coordination"]
    if args.get("transition_evidence"):
        payload["transition_evidence"] = args["transition_evidence"]

    resp = _tracker_api_request("PATCH", f"/{project_id}/{record_type}/{rid}", payload=payload)
    return _result_text(resp)


async def _tracker_log(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    description = args["description"]

    # ENC-FTR-037: Task worklogs must go through checkout service.
    try:
        _, record_type, _ = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type == "task":
        return _result_text({
            "error": (
                "Task worklogs must be appended via append_worklog (checkout service). "
                "Use the append_worklog tool. The task must be checked out first via checkout_task."
            )
        })

    # --- Phase 2d: HTTP API migration ---
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    payload: Dict[str, Any] = {
        "description": description,
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]
    if args.get("dispatch_id"):
        payload["dispatch_id"] = args["dispatch_id"]
    if args.get("provider"):
        payload["provider"] = args["provider"]

    resp = _tracker_api_request("POST", f"/{project_id}/{record_type}/{rid}/log", payload=payload)
    return _result_text(resp)


async def _tracker_create(args: dict) -> list[TextContent]:
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    project_id = args["project_id"]
    record_type = args["record_type"]

    # --- Phase 2d: HTTP API migration ---
    # All validation (ontology, governed fields, ID generation, bidirectional relations)
    # is handled by the tracker Lambda.
    payload: Dict[str, Any] = {
        "title": args["title"],
        "governance_hash": args.get("governance_hash", ""),
    }
    for key in ("priority", "description", "assigned_to", "status", "severity",
                "hypothesis", "technical_notes", "location_hint",
                "success_metrics", "related", "dispatch_id",
                "coordination", "coordination_request_id", "acceptance_criteria",
                "user_story", "category", "intent", "evidence", "primary_task",
                "provider", "is_child", "parent_task_id",
                # ENC-TSK-A97: Plan-specific fields
                "objectives_set", "attached_documents", "related_feature_id"):
        if args.get(key) is not None:
            payload[key] = args[key]

    resp = _tracker_api_request("POST", f"/{project_id}/{record_type}", payload=payload)
    return _result_text(resp)

# --- Acceptance Criteria Evidence Handshake (§7.1.1) ---


async def _tracker_set_acceptance_evidence(args: dict) -> list[TextContent]:
    """Set evidence on a specific acceptance criterion of a feature record."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]

    # --- Phase 2d: HTTP API migration ---
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    payload: Dict[str, Any] = {
        "criterion_index": args["criterion_index"],
        "evidence": args["evidence"],
        "evidence_acceptance": args["evidence_acceptance"],
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]
    if args.get("dispatch_id"):
        payload["dispatch_id"] = args["dispatch_id"]
    if args.get("provider"):
        payload["provider"] = args["provider"]

    resp = _tracker_api_request("POST", f"/{project_id}/{record_type}/{rid}/acceptance-evidence", payload=payload)
    return _result_text(resp)

# --- Documents ---


async def _documents_search(args: dict) -> list[TextContent]:
    query: Dict[str, Any] = {}
    if args.get("project_id"):
        query["project"] = args["project_id"]
    if args.get("keyword"):
        query["keyword"] = args["keyword"]
    if args.get("related"):
        query["related"] = args["related"]
    if args.get("title"):
        query["title"] = args["title"]

    resp = _document_api_request("GET", "/search", query=query or None)
    return _result_text(resp)


async def _documents_get(args: dict) -> list[TextContent]:
    doc_id = args["document_id"]
    include_content = args.get("include_content", True)
    query = {"include_content": "true" if include_content else "false"}
    resp = _document_api_request("GET", f"/{urllib.parse.quote(str(doc_id), safe='')}", query=query)
    return _result_text(resp)


async def _documents_list(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    page_size = int(args.get("page_size", 25))
    cursor = args.get("cursor")
    resp = _document_api_request("GET", query={"project": project_id})
    if isinstance(resp, dict) and resp.get("error"):
        return _result_text(resp)
    # Response is typically {"documents": [...]} or a list
    docs = resp.get("documents", []) if isinstance(resp, dict) else resp if isinstance(resp, list) else []
    # Cursor pagination (ENC-TSK-820)
    page, next_cursor, total = _paginate(
        docs, page_size, cursor,
        key_fn=lambda d: d.get("document_id", d.get("id", "")),
    )
    result: Dict[str, Any] = {"documents": page, "count": len(page), "total": total}
    if next_cursor:
        result["next_cursor"] = next_cursor
    return _result_text(result)


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
        logger.error(
            "[ERROR] documents_put: document API auth failed for project %s — "
            "check ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY config. "
            "Direct datastore fallback is disabled (agent IAM denies all DynamoDB/S3 writes).",
            body.get("project_id"),
        )
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
        logger.error(
            "[ERROR] documents_patch: document API auth failed for document %s — "
            "check ENCELADUS_DOCUMENT_API_INTERNAL_API_KEY config. "
            "Direct datastore fallback is disabled (agent IAM denies all DynamoDB/S3 writes).",
            document_id,
        )
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


# --- Reference Search (DVP-TSK-293, ENC-ISS-108) ---


def _fetch_reference_content(project_id: str) -> tuple:
    """Fetch reference document content from the document store API.

    Returns (content, source_info, error_payload) where:
    - On success: (str, dict, None)
    - On failure: (None, None, dict)

    ENC-ISS-108: All reference documents live in the document store (keyword
    'reference'). The legacy S3 path (mobile/v1/reference/) is retired.
    """
    try:
        search_resp = _document_api_request(
            "GET", "/search",
            query={"project": project_id, "keyword": "reference"},
        )
        docs = []
        if isinstance(search_resp, dict):
            if search_resp.get("documents"):
                docs = search_resp["documents"]
            elif search_resp.get("results"):
                docs = search_resp["results"]
            elif isinstance(search_resp.get("data"), list):
                docs = search_resp["data"]
        elif isinstance(search_resp, list):
            docs = search_resp

        if not docs:
            return (None, None, _error_payload(
                "NOT_FOUND",
                f"Reference document not found for project: {project_id}. "
                f"Create one via documents_put with keyword 'reference'.",
                details={"project_id": project_id},
            ))

        doc = docs[0]
        doc_id = doc.get("document_id") or doc.get("id", "")
        if not doc_id:
            return (None, None, _error_payload(
                "INTERNAL_ERROR",
                f"Document search returned result without document_id for {project_id}.",
            ))

        get_resp = _document_api_request(
            "GET",
            f"/{urllib.parse.quote(str(doc_id), safe='')}",
            query={"include_content": "true"},
        )
        doc_content = get_resp.get("content", "") if isinstance(get_resp, dict) else ""
        if not doc_content:
            return (None, None, _error_payload(
                "NOT_FOUND",
                f"Reference document {doc_id} for {project_id} has no content.",
                details={"document_id": doc_id, "project_id": project_id},
            ))

        source_info = {
            "source": "document_store",
            "document_id": doc_id,
            "last_modified": get_resp.get("updated_at") or get_resp.get("created_at"),
        }
        return (doc_content, source_info, None)

    except Exception as exc:
        return (None, None, _error_payload(
            "UPSTREAM_ERROR",
            f"Document store API failed for {project_id}: {exc}",
            retryable=True,
        ))


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

    # Fetch reference document (ENC-ISS-108: document store first, S3 fallback)
    content, source_info, error = _fetch_reference_content(project_id)
    if error:
        return _result_text(error)

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
            **source_info,
        },
    })


# --- Code Navigation (ENC-TSK-805) ---


async def _get_code_map(args: dict) -> list[TextContent]:
    """Return a code navigation map for a project from the component registry."""
    project_id = args["project_id"]
    domain = args.get("domain")

    # Query components for this project
    resp = _coordination_api_request(
        "GET", "/components", query={"project_id": project_id, "status": "active"}
    )
    components = resp.get("components", [])
    if not components and resp.get("error"):
        return _result_text(resp)

    result: Dict[str, Any] = {"project_id": project_id, "components": []}

    for comp in components:
        source_paths = comp.get("source_paths", {})
        if not source_paths:
            # Include component even without source_paths (basic info)
            result["components"].append({
                "component_id": comp.get("component_id"),
                "category": comp.get("category"),
                "transition_type": comp.get("transition_type"),
            })
            continue

        # If domain filter is specified, only include components that have that domain
        if domain:
            domains = source_paths.get("domains", {})
            if domain in domains:
                result["components"].append({
                    "component_id": comp.get("component_id"),
                    "category": comp.get("category"),
                    "domain": domain,
                    "files": domains[domain],
                    "primary": source_paths.get("primary"),
                    "architecture_sections": source_paths.get("architecture_sections", []),
                })
            # Skip components without the requested domain
            continue

        # No domain filter — return full source_paths
        entry: Dict[str, Any] = {
            "component_id": comp.get("component_id"),
            "category": comp.get("category"),
            "transition_type": comp.get("transition_type"),
            "primary": source_paths.get("primary"),
            "directory": source_paths.get("directory"),
        }
        if source_paths.get("workflow"):
            entry["workflow"] = source_paths["workflow"]
        if source_paths.get("domains"):
            entry["domains"] = list(source_paths["domains"].keys())
        if source_paths.get("architecture_sections"):
            entry["architecture_sections"] = source_paths["architecture_sections"]
        result["components"].append(entry)

    return _result_text(result)


# --- Context Assembly (ENC-TSK-829 / ENC-TSK-830 / ENC-TSK-825) ---

# Domain-to-architecture-file mapping (ENC-TSK-830, expanded ENC-TSK-825)
# Per design doc DOC-CA6AFFD18E98 §2.2
_DATA_COMPUTE = {
    "file": "docs/architecture/data-compute.md",
    "s3_key": "agent-documents/enceladus/architecture/data-compute.md",
}
_SECURITY_FRONTEND = {
    "file": "docs/architecture/security-frontend.md",
    "s3_key": "agent-documents/enceladus/architecture/security-frontend.md",
}
_OPERATIONS = {
    "file": "docs/architecture/operations.md",
    "s3_key": "agent-documents/enceladus/architecture/operations.md",
}

_DOMAIN_ARCHITECTURE_MAP: Dict[str, Dict[str, Any]] = {
    # Primary domains
    "compute": {**_DATA_COMPUTE, "description": "Data layer, Lambda functions, DynamoDB, S3, compute infrastructure"},
    "operations": {**_OPERATIONS, "description": "Deployment, CI/CD, monitoring, orchestration"},
    "security_frontend": {**_SECURITY_FRONTEND, "description": "Authentication, authorization, PWA frontend, Cloudflare, API Gateway"},
    # Data / compute aliases
    "data": {**_DATA_COMPUTE, "alias_of": "compute"},
    "dynamodb": {**_DATA_COMPUTE, "alias_of": "compute"},
    "tracker": {**_DATA_COMPUTE, "alias_of": "compute"},
    "lambda": {**_DATA_COMPUTE, "alias_of": "compute"},
    "api": {**_DATA_COMPUTE, "alias_of": "compute"},
    "api-gateway": {**_DATA_COMPUTE, "alias_of": "compute"},
    "governance": {**_DATA_COMPUTE, "alias_of": "compute"},
    # Security / frontend aliases
    "security": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "iam": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "cognito": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "auth": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "authentication": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "edge": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "frontend": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "pwa": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "ui": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "cloudfront": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    "cdn": {**_SECURITY_FRONTEND, "alias_of": "security_frontend"},
    # Operations aliases
    "deploy": {**_OPERATIONS, "alias_of": "operations"},
    "ci-cd": {**_OPERATIONS, "alias_of": "operations"},
    "github-actions": {**_OPERATIONS, "alias_of": "operations"},
    "monitoring": {**_OPERATIONS, "alias_of": "operations"},
    "cloudwatch": {**_OPERATIONS, "alias_of": "operations"},
    "mcp": {**_OPERATIONS, "alias_of": "operations"},
    "mcp-server": {**_OPERATIONS, "alias_of": "operations"},
    "coordination": {**_OPERATIONS, "alias_of": "operations"},
    "bedrock": {**_OPERATIONS, "alias_of": "operations"},
    "infrastructure": {**_OPERATIONS, "alias_of": "operations"},
    "cloudformation": {**_OPERATIONS, "alias_of": "operations"},
}

# Canonical (non-alias) domain names for display
_CANONICAL_DOMAINS = sorted(
    d for d, m in _DOMAIN_ARCHITECTURE_MAP.items() if "alias_of" not in m
)

# Project-specific architecture doc availability
_PROJECT_ARCHITECTURE_SUPPORT: Dict[str, bool] = {
    "enceladus": True,
    # Projects without architecture docs return helpful fallback
}


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token for English text."""
    return max(1, len(text) // 4)


def _resolve_location_hint_to_components(
    location_hint: str, all_components: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Resolve a location_hint string to matching components via fuzzy matching.

    Per design doc DOC-4C6035E777C0 §2-3:
    1. Exact domain match (weight 3)
    2. Keyword match against component names/categories/domains (weight 2-3)
    3. Path match if hint contains file path indicators (weight 1)
    4. Fallback: all components with match_confidence="none"
    """
    import re as _re

    if not location_hint or not all_components:
        return []

    hint_lower = location_hint.lower().strip()
    # Tokenize: split on whitespace and punctuation, keep meaningful tokens
    hint_tokens = set(_re.findall(r"[a-z0-9_]+", hint_lower))
    # Detect file path in hint
    is_path_hint = "/" in hint_lower or _re.search(r"\.\w{2,4}$", hint_lower)

    scored: List[tuple] = []  # (score, component, confidence)

    for comp in all_components:
        score = 0
        sp = comp.get("source_paths") or {}
        domains = sp.get("domains") or {}

        # 1. Exact domain name match (weight 3 per hit)
        for domain_name in domains:
            if domain_name.lower() in hint_tokens:
                score += 3

        # 2. Component name / category keyword match (weight 2)
        comp_name = comp.get("component_name", "").lower()
        comp_category = comp.get("category", "").lower()
        comp_desc = comp.get("description", "").lower()
        name_tokens = set(_re.findall(r"[a-z0-9_]+", comp_name))
        for ht in hint_tokens:
            if ht in name_tokens:
                score += 2
            if ht == comp_category:
                score += 2
            # Partial match in description (weight 1)
            if ht in comp_desc and len(ht) > 2:
                score += 1

        # 3. Path-based matching (weight 1 per segment hit)
        if is_path_hint:
            primary = sp.get("primary", "")
            directory = sp.get("directory", "")
            for path in [primary, directory]:
                path_segments = set(_re.findall(r"[a-z0-9_]+", path.lower()))
                for ht in hint_tokens:
                    if ht in path_segments:
                        score += 1
        else:
            # Even without path hint, check directory segments (weight 1)
            directory = sp.get("directory", "")
            dir_segments = set(_re.findall(r"[a-z0-9_]+", directory.lower()))
            for ht in hint_tokens:
                if ht in dir_segments:
                    score += 1

        if score > 0:
            confidence = "exact" if score >= 6 else "fuzzy"
            scored.append((score, comp, confidence))

    # Sort by score descending, take top 3
    scored.sort(key=lambda x: x[0], reverse=True)

    # Minimum threshold: score >= 2
    results = []
    for score, comp, confidence in scored[:3]:
        if score < 2:
            break
        sp = comp.get("source_paths") or {}
        entry: Dict[str, Any] = {
            "component_id": comp.get("component_id", ""),
            "match_confidence": confidence,
            "match_score": score,
            "category": comp.get("category"),
        }
        if sp.get("primary"):
            entry["primary"] = sp["primary"]
        if sp.get("directory"):
            entry["directory"] = sp["directory"]
        if sp.get("domains"):
            entry["domains"] = list(sp["domains"].keys())
        if sp.get("architecture_sections"):
            entry["architecture_sections"] = sp["architecture_sections"]
        results.append(entry)

    return results


def _read_architecture_file(domain: str) -> Optional[str]:
    """Read an architecture doc from local filesystem or S3 fallback."""
    mapping = _DOMAIN_ARCHITECTURE_MAP.get(domain)
    if not mapping:
        return None

    import pathlib as _pathlib
    server_dir = _pathlib.Path(__file__).resolve().parent

    # Try repo-relative path (local dev: server.py is at tools/enceladus-mcp-server/)
    repo_root = server_dir.parent.parent
    local_path = repo_root / mapping["file"]
    if local_path.is_file():
        try:
            return local_path.read_text(encoding="utf-8")
        except Exception:
            pass

    # Try package-relative path (Lambda: architecture docs bundled alongside server.py) (ENC-ISS-111)
    package_path = server_dir / mapping["file"]
    if package_path.is_file():
        try:
            return package_path.read_text(encoding="utf-8")
        except Exception:
            pass

    # S3 fallback for Lambda/remote transports
    try:
        resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=mapping["s3_key"])
        return resp["Body"].read().decode("utf-8")
    except Exception:
        return None


def _extract_sections_for_domain(content: str, max_tokens: int) -> List[Dict[str, Any]]:
    """Extract top-level sections from a markdown document, respecting token budget."""
    import re as _re
    sections: List[Dict[str, Any]] = []
    current_heading = ""
    current_lines: List[str] = []
    line_start = 1
    total_tokens = 0

    lines = content.split("\n")
    for i, line in enumerate(lines):
        heading_match = _re.match(r"^(#{1,3})\s+(.+)", line)
        if heading_match:
            # Flush previous section
            if current_heading and current_lines:
                section_text = "\n".join(current_lines).strip()
                section_tokens = _estimate_tokens(section_text)
                if total_tokens + section_tokens <= max_tokens:
                    sections.append({
                        "heading": current_heading,
                        "line_start": line_start,
                        "excerpt": section_text,
                        "tokens": section_tokens,
                    })
                    total_tokens += section_tokens
                else:
                    # Budget exceeded — truncate and stop
                    remaining = max_tokens - total_tokens
                    if remaining > 50:
                        truncated = section_text[: remaining * 4]
                        sections.append({
                            "heading": current_heading,
                            "line_start": line_start,
                            "excerpt": truncated + "\n... [truncated]",
                            "tokens": remaining,
                            "truncated": True,
                        })
                    break

            current_heading = heading_match.group(2).strip()
            current_lines = []
            line_start = i + 1
        else:
            current_lines.append(line)

    # Flush last section
    if current_heading and current_lines and total_tokens < max_tokens:
        section_text = "\n".join(current_lines).strip()
        section_tokens = _estimate_tokens(section_text)
        remaining = max_tokens - total_tokens
        if section_tokens <= remaining:
            sections.append({
                "heading": current_heading,
                "line_start": line_start,
                "excerpt": section_text,
                "tokens": section_tokens,
            })
        elif remaining > 50:
            truncated = section_text[: remaining * 4]
            sections.append({
                "heading": current_heading,
                "line_start": line_start,
                "excerpt": truncated + "\n... [truncated]",
                "tokens": remaining,
                "truncated": True,
            })

    return sections


async def _get_architecture_excerpts(args: dict) -> list[TextContent]:
    """Return architecture excerpts for specific domains (ENC-TSK-830, enhanced ENC-TSK-825).

    Enhancements over v1: expanded domain aliases (13+ per design doc DOC-CA6AFFD18E98),
    freshness metadata, project-aware error handling for cross-project support.
    """
    project_id = args.get("project_id", "").strip()
    domains = args.get("domains") or []
    max_excerpt_tokens = int(args.get("max_excerpt_tokens", 1200))

    if not project_id:
        return _result_text({"error": "project_id is required"})
    if not domains:
        return _result_text({"error": "domains is required (list of domain names)"})

    # Project-aware architecture support (DOC-CA6AFFD18E98 §6)
    if not _PROJECT_ARCHITECTURE_SUPPORT.get(project_id):
        return _result_text({
            "error": "no_architecture",
            "project_id": project_id,
            "suggestion": "Use reference_search or get_code_map for project docs. "
                          "Architecture excerpts require docs/architecture/ files with [SECTION] markers.",
        })

    if not isinstance(domains, list):
        domains = [str(domains)]

    result_excerpts: List[Dict[str, Any]] = []
    warnings: List[str] = []
    tokens_used = 0
    seen_files: set[str] = set()

    for domain in domains:
        domain_lower = str(domain).strip().lower()
        mapping = _DOMAIN_ARCHITECTURE_MAP.get(domain_lower)
        if not mapping:
            warnings.append(
                f"Unknown domain '{domain}'. Valid domains: {_CANONICAL_DOMAINS}"
            )
            continue

        # Deduplicate aliases pointing to same file
        file_key = mapping["file"]
        if file_key in seen_files:
            continue
        seen_files.add(file_key)

        remaining_budget = max_excerpt_tokens - tokens_used
        if remaining_budget <= 50:
            warnings.append(f"Token budget exhausted; skipped domain '{domain}'")
            break

        content = _read_architecture_file(domain_lower)
        source_type = "live"  # direct file read = always fresh
        if content is None:
            warnings.append(f"Architecture file not found for domain '{domain}'")
            continue

        sections = _extract_sections_for_domain(content, remaining_budget)
        domain_tokens = sum(s.get("tokens", 0) for s in sections)
        tokens_used += domain_tokens

        # Resolve canonical domain name for aliases
        canonical = mapping.get("alias_of", domain_lower)

        result_excerpts.append({
            "domain": canonical,
            "source": mapping["file"],
            "section_count": len(sections),
            "sections": sections,
            "tokens": domain_tokens,
            "freshness": source_type,
        })

    return _result_text({
        "success": True,
        "project_id": project_id,
        "excerpts": result_excerpts,
        "budget": {
            "requested_max_tokens": max_excerpt_tokens,
            "tokens_used": tokens_used,
            "domains_requested": len(domains),
            "domains_returned": len(result_excerpts),
        },
        "warnings": warnings if warnings else None,
    })


async def _get_issue_context(args: dict) -> list[TextContent]:
    """Composite context retrieval for a tracker record (ENC-TSK-829, enhanced ENC-TSK-825).

    Bundles: record core fields, relationships, component source paths,
    domain architecture excerpts, and recent history in one call.

    ENC-TSK-825 enhancements:
    - location_hint fuzzy matching for issues (per DOC-4C6035E777C0)
    - match_confidence on component entries
    - Sparse registry fallback with actionable suggestions
    """
    record_id = args.get("record_id", "").strip()
    if not record_id:
        return _result_text({"error": "record_id is required"})

    include_components = args.get("include_components", True)
    include_architecture = args.get("include_architecture", True)
    include_recent_history = args.get("include_recent_history", True)
    history_limit = int(args.get("history_limit", 10))
    max_tokens = int(args.get("max_tokens", 2500))

    # Parse record ID to get project/type
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    # 1. Fetch the record
    record_resp = _tracker_api_request("GET", f"/{project_id}/{record_type}/{rid}")
    if not isinstance(record_resp, dict) or record_resp.get("error"):
        return _result_text(record_resp or {"error": "Failed to fetch record"})
    # Unwrap record envelope — API returns {"record": {...}} (ENC-ISS-110)
    record_resp = record_resp.get("record", record_resp)

    # Build compact record core
    budget_used = 0
    record_core = {
        "id": record_id.upper(),
        "type": record_type,
        "title": record_resp.get("title", ""),
        "status": record_resp.get("status", ""),
        "priority": record_resp.get("priority", ""),
        "category": record_resp.get("category", ""),
        "intent": record_resp.get("intent", ""),
    }
    # Add type-specific fields
    if record_type == "issue":
        for f in ("hypothesis", "technical_notes", "location_hint", "severity"):
            val = record_resp.get(f)
            if val:
                record_core[f] = val
    if record_type == "task":
        for f in ("transition_type", "checkout_state", "components"):
            val = record_resp.get(f)
            if val:
                record_core[f] = val
        ac = record_resp.get("acceptance_criteria")
        if ac:
            record_core["acceptance_criteria"] = ac

    budget_used += _estimate_tokens(json.dumps(record_core))

    # 2. Relationships
    relationships: Dict[str, Any] = {}
    for rel_field in ("related_task_ids", "related_issue_ids", "related_feature_ids", "parent"):
        val = record_resp.get(rel_field)
        if val:
            relationships[rel_field] = val
    if relationships:
        budget_used += _estimate_tokens(json.dumps(relationships))

    # 3. Components (optional) — with location_hint fuzzy matching (ENC-TSK-825)
    components_data: List[Dict[str, Any]] = []
    component_domains: set[str] = set()
    truncated_sections: List[str] = []
    component_resolution_method = None  # "explicit", "location_hint", or "sparse_fallback"

    if include_components and budget_used < max_tokens:
        comp_ids = record_resp.get("components") or []

        # Query component registry for this project
        comp_resp = _coordination_api_request(
            "GET", "/components",
            query={"project_id": project_id, "status": "active"},
        )
        all_components = comp_resp.get("components", [])

        if comp_ids:
            # Explicit component match (tasks have components field)
            component_resolution_method = "explicit"
            for comp in all_components:
                cid = comp.get("component_id", "")
                if cid in comp_ids:
                    entry: Dict[str, Any] = {
                        "component_id": cid,
                        "match_confidence": "explicit",
                        "category": comp.get("category"),
                    }
                    sp = comp.get("source_paths") or {}
                    if sp.get("primary"):
                        entry["primary"] = sp["primary"]
                    if sp.get("directory"):
                        entry["directory"] = sp["directory"]
                    if sp.get("domains"):
                        entry["domains"] = list(sp["domains"].keys())
                        component_domains.update(sp["domains"].keys())
                    if sp.get("architecture_sections"):
                        entry["architecture_sections"] = sp["architecture_sections"]
                    components_data.append(entry)

        elif all_components:
            # No explicit components — try location_hint fuzzy matching (DOC-4C6035E777C0 §2-3)
            location_hint = record_resp.get("location_hint", "")
            if location_hint:
                component_resolution_method = "location_hint"
                matched = _resolve_location_hint_to_components(location_hint, all_components)
                if matched:
                    components_data = matched
                    # Extract domains from matched components for architecture lookup
                    for entry in components_data:
                        for d in entry.get("domains", []):
                            component_domains.add(d)
                else:
                    # location_hint provided but no matches above threshold
                    component_resolution_method = "sparse_fallback"
            else:
                component_resolution_method = "sparse_fallback"

        if not components_data and all_components:
            # Sparse registry fallback (DOC-4C6035E777C0 §4.2, §6)
            component_resolution_method = "sparse_fallback"

        if components_data:
            budget_used += _estimate_tokens(json.dumps(components_data))
    elif include_components:
        truncated_sections.append("components")

    # 4. Architecture excerpts (optional)
    arch_excerpts: List[Dict[str, Any]] = []
    if include_architecture and component_domains and budget_used < max_tokens:
        arch_budget = min(max_tokens - budget_used, 1200)
        if arch_budget > 100:
            arch_result = await _get_architecture_excerpts({
                "project_id": project_id,
                "domains": sorted(component_domains),
                "max_excerpt_tokens": arch_budget,
            })
            # Parse the result
            try:
                arch_text = arch_result[0].text if arch_result else "{}"
                arch_parsed = json.loads(arch_text)
                arch_excerpts = arch_parsed.get("excerpts", [])
                budget_used += sum(e.get("tokens", 0) for e in arch_excerpts)
            except (json.JSONDecodeError, IndexError, AttributeError):
                truncated_sections.append("architecture_excerpts")
        else:
            truncated_sections.append("architecture_excerpts")
    elif include_architecture and not component_domains:
        pass  # No domains to query
    elif include_architecture:
        truncated_sections.append("architecture_excerpts")

    # 5. Recent history (optional)
    recent_history: List[Dict[str, Any]] = []
    if include_recent_history and budget_used < max_tokens:
        full_history = record_resp.get("history") or []
        for entry in reversed(full_history):
            if len(recent_history) >= history_limit:
                break
            h_entry = {
                "timestamp": entry.get("timestamp", ""),
                "status": entry.get("status", ""),
                "description": entry.get("description", ""),
            }
            entry_tokens = _estimate_tokens(json.dumps(h_entry))
            if budget_used + entry_tokens > max_tokens:
                truncated_sections.append("recent_history")
                break
            recent_history.append(h_entry)
            budget_used += entry_tokens
        recent_history.reverse()
    elif include_recent_history:
        truncated_sections.append("recent_history")

    # Build final response
    response: Dict[str, Any] = {
        "success": True,
        "record": record_core,
    }
    if relationships:
        response["relationships"] = relationships
    if components_data:
        response["components"] = components_data
    elif component_resolution_method == "sparse_fallback":
        # Sparse fallback: actionable suggestion instead of empty list (DOC-4C6035E777C0 §6)
        response["components"] = []
        response["component_resolution"] = {
            "method": "sparse_fallback",
            "suggestion": "No component match found. Use reference_search or get_code_map "
                          "to locate relevant code. Add a location_hint to the issue for "
                          "better component resolution.",
        }
    if component_resolution_method and component_resolution_method != "sparse_fallback":
        response["component_resolution"] = {"method": component_resolution_method}
    if arch_excerpts:
        response["architecture_excerpts"] = arch_excerpts
    if recent_history:
        response["recent_history"] = recent_history
    response["budget"] = {
        "requested_max_tokens": max_tokens,
        "estimated_output_tokens": budget_used,
        "truncated_sections": truncated_sections if truncated_sections else [],
    }

    return _result_text(response)


# --- Code Mode Meta-Tools (ENC-FTR-044) ---

_SEARCH_ACTIONS: Dict[str, Dict[str, Any]] = {
    "projects.list": {"tool": "projects_list"},
    "projects.get": {"tool": "projects_get"},
    "tracker.get": {"tool": "tracker_get"},
    "tracker.list": {"tool": "tracker_list"},
    "tracker.pending_updates": {"tool": "tracker_pending_updates"},
    "tracker.validation_rules": {"tool": "tracker_validation_rules"},
    "documents.search": {"tool": "documents_search"},
    "documents.get": {"tool": "documents_get"},
    "documents.list": {"tool": "documents_list"},
    "reference.search": {"tool": "reference_search"},
    "deploy.state_get": {"tool": "deploy_state_get"},
    "deploy.history": {"tool": "deploy_history"},
    "deploy.history_list": {"tool": "deploy_history_list"},
    "deploy.status": {"tool": "deploy_status"},
    "deploy.status_get": {"tool": "deploy_status_get"},
    "deploy.pending_requests": {"tool": "deploy_pending_requests"},
    "changelog.history": {"tool": "changelog_history"},
    "changelog.history_all": {"tool": "changelog_history_all"},
    "changelog.version": {"tool": "changelog_version"},
    "governance.hash": {"tool": "governance_hash"},
    "governance.get": {"tool": "governance_get"},
    "governance.dictionary": {"tool": "governance_dictionary"},
    "system.connection_health": {"tool": "connection_health"},
    "github.projects_list": {"tool": "github_projects_list"},
    "tracker.graphsearch": {"tool": "tracker_graphsearch"},
}

_COORDINATION_ACTIONS: Dict[str, Dict[str, Any]] = {
    "capabilities.get": {"tool": "coordination_capabilities"},
    "request.get": {"tool": "coordination_request_get"},
    "auth.cognito_session": {"tool": "coordination_cognito_session"},
    "dispatch_plan.generate": {"tool": "dispatch_plan_generate"},
    "dispatch_plan.dry_run": {"tool": "dispatch_plan_dry_run"},
}

_EXECUTE_ACTIONS: Dict[str, Dict[str, Any]] = {
    "tracker.create": {"tool": "tracker_create", "requires_governance_hash": True},
    "tracker.set": {"tool": "tracker_set", "requires_governance_hash": True},
    "tracker.log": {"tool": "tracker_log", "requires_governance_hash": True},
    "tracker.set_acceptance_evidence": {
        "tool": "tracker_set_acceptance_evidence",
        "requires_governance_hash": True,
    },
    "documents.check_policy": {"tool": "check_document_policy"},
    "documents.put": {"tool": "documents_put", "requires_governance_hash": True},
    "documents.patch": {"tool": "documents_patch", "requires_governance_hash": True},
    "deploy.submit": {"tool": "deploy_submit", "requires_governance_hash": True},
    "deploy.state_set": {"tool": "deploy_state_set", "requires_governance_hash": True},
    "deploy.trigger": {"tool": "deploy_trigger"},
    "checkout.task": {"tool": "checkout_task", "requires_governance_hash": True},
    "checkout.release": {"tool": "release_task", "requires_governance_hash": True},
    "checkout.advance": {"tool": "advance_task_status", "requires_governance_hash": True},
    "checkout.append_worklog": {"tool": "append_worklog", "requires_governance_hash": True},
    "github.create_issue": {"tool": "github_create_issue"},
    "github.projects_sync": {"tool": "github_projects_sync"},
}

# ENC-FTR-049: Conditionally register typed relationship actions behind feature flag
if ENABLE_TYPED_RELATIONSHIPS:
    _EXECUTE_ACTIONS["tracker.create_relationship"] = {
        "tool": "tracker_create_relationship", "requires_governance_hash": True,
    }
    _EXECUTE_ACTIONS["tracker.archive_relationship"] = {
        "tool": "tracker_archive_relationship", "requires_governance_hash": True,
    }
    _SEARCH_ACTIONS["tracker.list_relationships"] = {
        "tool": "tracker_list_relationships",
    }

# ENC-FTR-052: Conditionally register lesson actions behind feature flag
if ENABLE_LESSON_PRIMITIVE:
    _EXECUTE_ACTIONS["tracker.create_lesson"] = {
        "tool": "tracker_create_lesson", "requires_governance_hash": True,
    }
    _EXECUTE_ACTIONS["tracker.extend_lesson"] = {
        "tool": "tracker_extend_lesson", "requires_governance_hash": True,
    }
    _SEARCH_ACTIONS["tracker.list_lessons"] = {
        "tool": "tracker_list_lessons",
    }

# ENC-FTR-058 / ENC-TSK-A97: Plan action aliases in code-mode surface
_SEARCH_ACTIONS["plan.objectives_status"] = {"tool": "plan_objectives_status"}
_EXECUTE_ACTIONS["plan.create"] = {"tool": "tracker_create", "requires_governance_hash": True}
_EXECUTE_ACTIONS["plan.checkout"] = {"tool": "checkout_task", "requires_governance_hash": True}
_EXECUTE_ACTIONS["plan.advance"] = {"tool": "advance_task_status", "requires_governance_hash": True}

_RECORD_CONTEXT_MODES = {"record", "issue", "task", "feature", "lesson"}


def _merge_meta_tool_arguments(args: Dict[str, Any], reserved: set[str]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    raw_args = args.get("arguments")
    if isinstance(raw_args, dict):
        merged.update(raw_args)
    for key, value in args.items():
        if key in reserved or key in merged:
            continue
        merged[key] = value
    return merged


def _raw_call_summary(raw_call: Dict[str, Any], *, status_override: str = "") -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "tool": raw_call.get("tool"),
        "status": status_override or raw_call.get("status") or "unknown",
    }
    arguments = raw_call.get("arguments")
    if isinstance(arguments, dict) and arguments:
        summary["arguments"] = arguments
    error_code = str(raw_call.get("error_code") or "").strip()
    if error_code:
        summary["error_code"] = error_code
    return summary


def _result_metadata(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    metadata: Dict[str, Any] = {}
    if payload.get("next_cursor") is not None:
        metadata["next_cursor"] = payload.get("next_cursor")
    pagination = payload.get("pagination")
    if metadata.get("next_cursor") is None and isinstance(pagination, dict):
        if pagination.get("next_cursor") is not None:
            metadata["next_cursor"] = pagination.get("next_cursor")
    for key in ("count", "match_count", "total_count"):
        if payload.get(key) is not None:
            metadata[key] = payload.get(key)
    if isinstance(payload.get("budget"), dict):
        metadata["budget"] = payload.get("budget")
    if isinstance(payload.get("warnings"), list) and payload.get("warnings"):
        metadata["warnings"] = payload.get("warnings")
    return metadata


async def _best_effort_raw_tool(
    tool_name: str,
    tool_args: Dict[str, Any],
    *,
    underlying_calls: List[Dict[str, Any]],
    warnings: List[str],
    warning_label: str,
) -> Any:
    try:
        raw_call = await _invoke_raw_tool(tool_name, tool_args)
    except PermissionError as exc:
        warnings.append(str(exc))
        return None
    except Exception as exc:
        warnings.append(f"{warning_label}: {exc}")
        return None

    underlying_calls.append(_raw_call_summary(raw_call))
    if raw_call["status"] != "success":
        warnings.append(
            f"{warning_label}: {raw_call.get('error_code') or 'tool_error'}"
        )
        return None
    return raw_call["payload"]


async def _search(args: dict) -> list[TextContent]:
    action = str(args.get("action") or "").strip()
    if not action:
        return _meta_tool_error(
            "search",
            code="invalid_input",
            message="action is required",
        )

    entry = _SEARCH_ACTIONS.get(action)
    if not entry:
        return _meta_tool_error(
            "search",
            code="unknown_action",
            message=f"Unknown search action '{action}'",
            action=action,
        )

    raw_args = _merge_meta_tool_arguments(args, {"action", "arguments"})
    try:
        raw_call = await _invoke_raw_tool(entry["tool"], raw_args)
    except PermissionError as exc:
        return _meta_tool_error(
            "search",
            code="boundary_denied",
            message=str(exc),
            action=action,
        )
    except Exception as exc:
        return _meta_tool_error(
            "search",
            code="tool_resolution_failed",
            message=str(exc),
            action=action,
        )

    if raw_call["status"] != "success":
        return _meta_tool_error(
            "search",
            code=raw_call.get("error_code") or "tool_error",
            message=f"Underlying tool '{entry['tool']}' returned an error",
            action=action,
            underlying_calls=[_raw_call_summary(raw_call)],
            details={"result": raw_call["payload"]},
        )

    return _meta_tool_success(
        "search",
        action=action,
        result=raw_call["payload"],
        metadata=_result_metadata(raw_call["payload"]),
        underlying_calls=[_raw_call_summary(raw_call)],
    )


async def _coordination_meta(args: dict) -> list[TextContent]:
    action = str(args.get("action") or "").strip()
    if not action:
        return _meta_tool_error(
            "coordination",
            code="invalid_input",
            message="action is required",
        )

    entry = _COORDINATION_ACTIONS.get(action)
    if not entry:
        return _meta_tool_error(
            "coordination",
            code="unknown_action",
            message=f"Unknown coordination action '{action}'",
            action=action,
        )

    raw_args = _merge_meta_tool_arguments(args, {"action", "arguments"})
    try:
        raw_call = await _invoke_raw_tool(entry["tool"], raw_args)
    except PermissionError as exc:
        return _meta_tool_error(
            "coordination",
            code="boundary_denied",
            message=str(exc),
            action=action,
        )
    except Exception as exc:
        return _meta_tool_error(
            "coordination",
            code="tool_resolution_failed",
            message=str(exc),
            action=action,
        )

    if raw_call["status"] != "success":
        return _meta_tool_error(
            "coordination",
            code=raw_call.get("error_code") or "tool_error",
            message=f"Underlying tool '{entry['tool']}' returned an error",
            action=action,
            underlying_calls=[_raw_call_summary(raw_call)],
            details={"result": raw_call["payload"]},
        )

    return _meta_tool_success(
        "coordination",
        action=action,
        result=raw_call["payload"],
        metadata=_result_metadata(raw_call["payload"]),
        underlying_calls=[_raw_call_summary(raw_call)],
    )


async def _get_compact_context_meta(args: dict) -> list[TextContent]:
    mode = str(args.get("mode") or "").strip().lower()
    if not mode:
        if args.get("record_id"):
            mode = "record"
        elif args.get("document_id"):
            mode = "document"
        elif args.get("query"):
            mode = "topic"
        elif args.get("project_id"):
            mode = "project"
    if not mode:
        return _meta_tool_error(
            "get_compact_context",
            code="invalid_input",
            message="mode is required (or provide record_id, document_id, query, or project_id)",
        )

    warnings: List[str] = []
    underlying_calls: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}
    include_code_map = args.get("include_code_map", True) is not False
    include_related_documents = args.get("include_related_documents", True) is not False
    include_governance = args.get("include_governance", True) is not False

    if mode in _RECORD_CONTEXT_MODES:
        record_id = str(args.get("record_id") or "").strip()
        if not record_id:
            return _meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="record_id is required for record-oriented context modes",
                mode=mode,
            )

        raw_args = {
            "record_id": record_id,
            "include_components": args.get("include_components", True),
            "include_architecture": args.get("include_architecture", True),
            "include_recent_history": args.get("include_recent_history", True),
            "history_limit": args.get("history_limit", 10),
            "max_tokens": args.get("max_tokens", 2500),
        }
        try:
            record_call = await _invoke_raw_tool("get_issue_context", raw_args)
        except PermissionError as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )

        underlying_calls.append(_raw_call_summary(record_call))
        if record_call["status"] != "success":
            return _meta_tool_error(
                "get_compact_context",
                code=record_call.get("error_code") or "tool_error",
                message="Underlying issue-context assembly failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": record_call["payload"]},
            )

        context["record_context"] = record_call["payload"]
        project_id = str(
            args.get("project_id")
            or ((record_call["payload"] or {}).get("project_id") if isinstance(record_call["payload"], dict) else "")
        ).strip()
        if not project_id:
            try:
                project_id, _record_type, _rid = _parse_record_id(record_id)
            except ValueError:
                project_id = ""

        if project_id:
            project_payload = await _best_effort_raw_tool(
                "projects_get",
                {"project_name": project_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project lookup failed",
            )
            if project_payload is not None:
                context["project"] = project_payload

        if include_code_map and project_id:
            code_map_payload = await _best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if include_related_documents:
            related_docs = await _best_effort_raw_tool(
                "documents_search",
                {"project_id": project_id, "related": record_id} if project_id else {"related": record_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="related document lookup failed",
            )
            if related_docs is not None:
                context["related_documents"] = related_docs

        if include_governance:
            governance_entity = str(args.get("governance_entity") or "").strip()
            if not governance_entity:
                try:
                    _project_id, record_type, _rid = _parse_record_id(record_id)
                    governance_entity = f"tracker.{record_type}"
                except ValueError:
                    governance_entity = ""
            if governance_entity:
                governance_payload = await _best_effort_raw_tool(
                    "governance_dictionary",
                    {"entity": governance_entity},
                    underlying_calls=underlying_calls,
                    warnings=warnings,
                    warning_label="governance lookup failed",
                )
                if governance_payload is not None:
                    context["governance"] = governance_payload

    elif mode == "project":
        project_id = str(args.get("project_id") or "").strip()
        if not project_id:
            return _meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="project_id is required for project mode",
                mode=mode,
            )
        try:
            project_call = await _invoke_raw_tool("projects_get", {"project_name": project_id})
        except PermissionError as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )
        underlying_calls.append(_raw_call_summary(project_call))
        if project_call["status"] != "success":
            return _meta_tool_error(
                "get_compact_context",
                code=project_call.get("error_code") or "tool_error",
                message="Project lookup failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": project_call["payload"]},
            )
        context["project"] = project_call["payload"]

        if include_code_map:
            code_map_payload = await _best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if include_related_documents:
            docs_payload = await _best_effort_raw_tool(
                "documents_list",
                {"project_id": project_id, "page_size": args.get("page_size", 10)},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project document lookup failed",
            )
            if docs_payload is not None:
                context["documents"] = docs_payload

        if args.get("domains"):
            arch_payload = await _best_effort_raw_tool(
                "get_architecture_excerpts",
                {
                    "project_id": project_id,
                    "domains": args.get("domains"),
                    "max_excerpt_tokens": args.get("max_excerpt_tokens", 1200),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="architecture excerpts unavailable",
            )
            if arch_payload is not None:
                context["architecture"] = arch_payload

        governance_entity = str(args.get("governance_entity") or "").strip()
        if include_governance and governance_entity:
            governance_payload = await _best_effort_raw_tool(
                "governance_dictionary",
                {"entity": governance_entity},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="governance lookup failed",
            )
            if governance_payload is not None:
                context["governance"] = governance_payload

    elif mode == "document":
        document_id = str(args.get("document_id") or "").strip()
        if not document_id:
            return _meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="document_id is required for document mode",
                mode=mode,
            )
        try:
            document_call = await _invoke_raw_tool("documents_get", {"document_id": document_id, "include_content": True})
        except PermissionError as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return _meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )
        underlying_calls.append(_raw_call_summary(document_call))
        if document_call["status"] != "success":
            return _meta_tool_error(
                "get_compact_context",
                code=document_call.get("error_code") or "tool_error",
                message="Document lookup failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": document_call["payload"]},
            )
        context["document"] = document_call["payload"]

        document_payload = document_call["payload"] if isinstance(document_call["payload"], dict) else {}
        document_record = document_payload.get("document") if isinstance(document_payload.get("document"), dict) else {}
        project_id = str(args.get("project_id") or document_record.get("project_id") or "").strip()
        if include_code_map and project_id:
            code_map_payload = await _best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        related_items = document_record.get("related_items") if isinstance(document_record, dict) else None
        if include_related_documents and related_items:
            context["related_items"] = related_items

    elif mode == "topic":
        query = str(args.get("query") or "").strip()
        project_id = str(args.get("project_id") or "").strip()
        if not query and not project_id:
            return _meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="topic mode requires query or project_id",
                mode=mode,
            )

        if project_id:
            project_payload = await _best_effort_raw_tool(
                "projects_get",
                {"project_name": project_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project lookup failed",
            )
            if project_payload is not None:
                context["project"] = project_payload

        document_search_args: Dict[str, Any] = {}
        if project_id:
            document_search_args["project_id"] = project_id
        if args.get("keyword"):
            document_search_args["keyword"] = args.get("keyword")
        if args.get("title"):
            document_search_args["title"] = args.get("title")
        elif query:
            document_search_args["title"] = query
        if args.get("related"):
            document_search_args["related"] = args.get("related")
        docs_payload = await _best_effort_raw_tool(
            "documents_search",
            document_search_args,
            underlying_calls=underlying_calls,
            warnings=warnings,
            warning_label="document topic search failed",
        )
        if docs_payload is not None:
            context["documents"] = docs_payload

        if project_id and query:
            reference_payload = await _best_effort_raw_tool(
                "reference_search",
                {
                    "project_id": project_id,
                    "query": query,
                    "context_lines": args.get("context_lines", 2),
                    "max_results": args.get("max_results", 10),
                    **({"section": args.get("section")} if args.get("section") else {}),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="reference search failed",
            )
            if reference_payload is not None:
                context["reference"] = reference_payload

        if include_code_map and project_id:
            code_map_payload = await _best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if project_id and args.get("domains"):
            arch_payload = await _best_effort_raw_tool(
                "get_architecture_excerpts",
                {
                    "project_id": project_id,
                    "domains": args.get("domains"),
                    "max_excerpt_tokens": args.get("max_excerpt_tokens", 1200),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="architecture excerpts unavailable",
            )
            if arch_payload is not None:
                context["architecture"] = arch_payload

        governance_entity = str(args.get("governance_entity") or "").strip()
        if include_governance and governance_entity:
            governance_payload = await _best_effort_raw_tool(
                "governance_dictionary",
                {"entity": governance_entity},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="governance lookup failed",
            )
            if governance_payload is not None:
                context["governance"] = governance_payload
    else:
        return _meta_tool_error(
            "get_compact_context",
            code="unknown_mode",
            message=f"Unknown context mode '{mode}'",
            mode=mode,
        )

    # ENC-FTR-050: Context Node assembly manifest (flagged off by default)
    if ENABLE_CONTEXT_NODES and args.get("max_tokens"):
        try:
            import importlib
            _scoring = importlib.import_module("context_node_scoring")
            token_budget = int(args.get("max_tokens", 2500))
            record_id = str(args.get("record_id") or args.get("query") or "")
            # Build candidate list from context sections
            _candidates = []
            for section_key, section_val in context.items():
                if isinstance(section_val, dict):
                    _est_tokens = len(json.dumps(section_val, default=str)) // 4
                    _candidates.append({
                        "record_id": section_key,
                        "title": section_key,
                        "token_cost": _est_tokens,
                        "record_type": "task",
                        "updated_at": section_val.get("updated_at", "2026-01-01T00:00:00Z"),
                    })
            if _candidates:
                _inc, _exc, _manifest = _scoring.score_candidates(
                    _candidates, query=record_id, seed_record_id=record_id,
                    budget=token_budget, graph_healthy=False,
                )
                context["context_assembly_manifest"] = {
                    "enabled": True,
                    "token_budget": token_budget,
                    **_manifest,
                    "included_sections": [i.get("record_id", "") for i in _inc],
                    "excluded_sections": [e.get("record_id", "") for e in _exc],
                }
                # AC9: Telemetry logging
                logger.info(
                    "[CONTEXT_NODE_TELEMETRY] mode=%s budget=%d used=%d efficiency=%.4f "
                    "included=%d excluded=%d",
                    mode, token_budget, _manifest.get("tokens_used", 0),
                    _manifest.get("packing_efficiency", 0),
                    _manifest.get("items_included", 0),
                    _manifest.get("items_excluded", 0),
                )
        except Exception as _cn_err:
            warnings.append(f"context_node_scoring unavailable: {_cn_err}")

    return _meta_tool_success(
        "get_compact_context",
        mode=mode,
        result=context,
        underlying_calls=underlying_calls,
        warnings=warnings,
        metadata={"section_count": len(context)},
        partial=bool(warnings),
    )


async def _execute(args: dict) -> list[TextContent]:
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return _meta_tool_error(
            "execute",
            code="invalid_input",
            message="steps must be a non-empty array",
        )

    overall_dry_run = bool(args.get("dry_run", False))
    step_results: List[Dict[str, Any]] = []
    underlying_calls: List[Dict[str, Any]] = []
    failed_steps: List[Dict[str, Any]] = []

    for index, raw_step in enumerate(steps, start=1):
        if not isinstance(raw_step, dict):
            failed_steps.append({"step": index, "error": "step must be an object"})
            step_results.append({"step": index, "status": "invalid", "error": "step must be an object"})
            break

        action = str(raw_step.get("action") or "").strip()
        on_error = str(raw_step.get("on_error") or "abort").strip().lower()
        entry = _EXECUTE_ACTIONS.get(action)
        if not action or entry is None:
            error_message = f"Unknown execute action '{action}'" if action else "step action is required"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            step_results.append({"step": index, "action": action, "status": "invalid", "error": error_message})
            if on_error != "continue":
                break
            continue

        step_args = {}
        if isinstance(raw_step.get("arguments"), dict):
            step_args.update(raw_step["arguments"])
        step_dry_run = overall_dry_run or bool(raw_step.get("dry_run", False))
        summary = {
            "tool": entry["tool"],
            "arguments": step_args,
            "status": "dry_run" if step_dry_run else "pending",
        }

        if entry.get("requires_governance_hash") and not step_args.get("governance_hash"):
            error_message = f"Action '{action}' requires governance_hash"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "blocked"
            summary["error_code"] = "governance_hash_missing"
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "blocked",
                "error": error_message,
                "resolved_calls": [summary],
            })
            if on_error != "continue":
                break
            continue

        if not _raw_tool_allowed(entry["tool"]):
            error_message = f"Raw tool '{entry['tool']}' is outside the current session boundary"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "blocked"
            summary["error_code"] = "boundary_denied"
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "blocked",
                "error": error_message,
                "resolved_calls": [summary],
            })
            if on_error != "continue":
                break
            continue

        if step_dry_run:
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "dry_run",
                "resolved_calls": [summary],
            })
            continue

        try:
            raw_call = await _invoke_raw_tool(entry["tool"], step_args)
        except Exception as exc:
            error_message = str(exc)
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "error"
            summary["error_code"] = "tool_resolution_failed"
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "error",
                "error": error_message,
                "resolved_calls": [summary],
            })
            if on_error != "continue":
                break
            continue

        call_summary = _raw_call_summary(raw_call)
        underlying_calls.append(call_summary)
        if raw_call["status"] != "success":
            error_message = f"Underlying tool '{entry['tool']}' returned an error"
            failed_steps.append({
                "step": index,
                "action": action,
                "error": error_message,
                "error_code": raw_call.get("error_code") or "tool_error",
            })
            step_results.append({
                "step": index,
                "action": action,
                "status": "error",
                "error": error_message,
                "result": raw_call["payload"],
                "resolved_calls": [call_summary],
            })
            if on_error != "continue":
                break
            continue

        step_results.append({
            "step": index,
            "action": action,
            "status": "success",
            "result": raw_call["payload"],
            "resolved_calls": [call_summary],
        })

    if failed_steps:
        return _result_text({
            "success": False,
            "interface_mode": INTERFACE_MODE,
            "tool": "execute",
            "dry_run": overall_dry_run,
            "partial": any(step.get("status") == "success" for step in step_results),
            "step_results": step_results,
            "underlying_calls": underlying_calls,
            "error": {
                "code": "step_failed",
                "message": "One or more execute steps failed",
                "details": {"failed_steps": failed_steps},
            },
        })

    return _meta_tool_success(
        "execute",
        steps=step_results,
        underlying_calls=underlying_calls,
        dry_run=overall_dry_run,
        metadata={"step_count": len(step_results)},
    )


# --- Deployment ---


async def _deploy_state_get(args: dict) -> list[TextContent]:
    project_id = args["project_id"]
    result = _deploy_api_request("GET", f"/state/{project_id}")
    if _is_authentication_required_error(result):
        logger.error(
            "[ERROR] deploy_state_get: deploy API auth failed for project %s — "
            "check ENCELADUS_DEPLOY_API_INTERNAL_API_KEY config. "
            "Direct datastore fallback is disabled (MCP API boundary policy).",
            project_id,
        )
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
        logger.error(
            "[ERROR] deploy_history: deploy API auth failed for project %s — "
            "check ENCELADUS_DEPLOY_API_INTERNAL_API_KEY config. "
            "Direct datastore fallback is disabled (MCP API boundary policy).",
            project_id,
        )
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
    pr_id = args.get("pr_id")
    merged_at = str(args.get("merged_at") or "")
    pr_owner = str(args.get("pr_owner") or "NX-2021-L")
    pr_repo = str(args.get("pr_repo") or "enceladus")

    # Validate pr_id and merged_at
    if pr_id is None or not merged_at:
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                "pr_id (integer) and merged_at (ISO 8601 string) are required for deploy_submit. "
                "Advance the task to 'merged-main' first to obtain these values.",
                details={"fields": ["pr_id", "merged_at"]},
            )
        )
    try:
        pr_id = int(pr_id)
    except (TypeError, ValueError):
        return _result_text(
            _error_payload(
                "INVALID_INPUT",
                f"pr_id must be an integer, got {pr_id!r}",
                details={"field": "pr_id"},
            )
        )

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
        "pr_id": pr_id,
        "merged_at": merged_at,
        "pr_owner": pr_owner,
        "pr_repo": pr_repo,
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
    """Manually trigger the deploy orchestration pipeline via deploy_intake API."""
    project_id = args["project_id"]
    result = _deploy_api_request("POST", f"/trigger/{project_id}")
    return _result_text(result)


async def _deploy_pending_requests(args: dict) -> list[TextContent]:
    """List all pending deployment requests for a project."""
    project_id = args["project_id"]
    try:
        limit = int(args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 200))
    result = _deploy_api_request("GET", f"/pending/{project_id}", query={"limit": limit})
    return _result_text(result)


async def _deploy_status_get(args: dict) -> list[TextContent]:
    return await _deploy_status(args)


async def _deploy_history_list(args: dict) -> list[TextContent]:
    return await _deploy_history(args)


# --- Changelog (ENC-FTR-033) ---


async def _changelog_history(args: dict) -> list[TextContent]:
    """Fetch deployment history for a single project from the changelog API."""
    project_id = args["project_id"]
    try:
        limit = int(args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 100))
    query: Dict[str, Any] = {"limit": limit}
    if args.get("change_type"):
        query["change_type"] = str(args["change_type"])
    result = _changelog_api_request("GET", f"/history/{project_id}", query=query)
    return _result_text(result)


async def _changelog_history_all(args: dict) -> list[TextContent]:
    """Fetch deployment history across multiple projects from the changelog API."""
    projects_raw = args.get("projects", "")
    if isinstance(projects_raw, list):
        projects = ",".join(str(p).strip() for p in projects_raw if str(p).strip())
    else:
        projects = str(projects_raw or "").strip()
    try:
        limit = int(args.get("limit", 20))
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 100))
    query: Dict[str, Any] = {"projects": projects, "limit": limit}
    if args.get("change_type"):
        query["change_type"] = str(args["change_type"])
    result = _changelog_api_request("GET", "/history", query=query)
    return _result_text(result)


async def _changelog_version(args: dict) -> list[TextContent]:
    """Fetch the current deployed version for a project from the changelog API."""
    project_id = args["project_id"]
    result = _changelog_api_request("GET", f"/version/{project_id}")
    return _result_text(result)


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
    """Get coordination request by ID via coordination API."""
    request_id = args["request_id"]
    result = _coordination_api_request("GET", f"/requests/{urllib.parse.quote(request_id, safe='')}")
    return _result_text(result)


async def _coordination_cognito_session(args: dict) -> list[TextContent]:
    """Create Cognito cookie/session payload for terminal PWA diagnostics."""
    payload: Dict[str, Any] = {}
    if args.get("target_origin"):
        payload["target_origin"] = str(args.get("target_origin") or "").strip()
    if "include_set_cookie_headers" in args:
        payload["include_set_cookie_headers"] = bool(args.get("include_set_cookie_headers"))
    if "include_tokens" in args:
        payload["include_tokens"] = bool(args.get("include_tokens"))

    result = _coordination_api_request("POST", "/auth/cognito/session", payload=payload)
    return _result_text(result)


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
    content_text = str(args.get("content") or "")
    change_summary = str(args.get("change_summary") or "").strip()

    if not file_name:
        return _result_text(_error_payload("INVALID_INPUT", "file_name is required", retryable=False))
    if not content_text:
        return _result_text(_error_payload("INVALID_INPUT", "content is required", retryable=False))
    if not change_summary:
        return _result_text(_error_payload("INVALID_INPUT", "change_summary is required", retryable=False))

    # --- Phase 2d: HTTP API migration ---
    # Archival, hash computation, and S3 writes are handled by the coordination Lambda.
    # file_name is included in both URL path and body — Lambda reads from body.
    payload: Dict[str, Any] = {
        "file_name": file_name,
        "content": content_text,
        "change_summary": change_summary,
        "governance_hash": args.get("governance_hash", ""),
    }
    encoded_name = urllib.parse.quote(file_name, safe="")  # encode slashes → %2F so API Gateway routes correctly
    resp = _governance_api_request("PUT", f"/{encoded_name}", payload=payload)
    # Invalidate local resource/hash caches after successful governance write.
    global _governance_catalog_cache, _governance_catalog_cached_at
    _governance_catalog_cache = {}
    _governance_catalog_cached_at = 0.0
    _governance_resource_body_cache.clear()
    new_hash = str(resp.get("governance_hash") or "").strip()
    if new_hash:
        _cache_governance_hash(new_hash)
    return _result_text(resp)

async def _governance_hash(args: dict) -> list[TextContent]:
    governance_hash = _get_governance_hash_via_api()
    return _result_text({"success": True, "governance_hash": governance_hash})


async def _governance_get(args: dict) -> list[TextContent]:
    """Read a governance file by file_name via HTTP API (ENC-FTR-040).

    Migrated from direct S3 boto3 access to HTTP API so that:
    1. MCP sessions without S3 IAM permissions (e.g. enceladus-agent-cli) can read
       governance files — the Lambda has the necessary S3 role.
    2. agents/ sub-path files (e.g. agents/plan-capture.md) are accessible even
       though the MCP server's S3 catalog may not enumerate them.
    """
    file_name = str(args.get("file_name") or "agents.md").strip()
    uri = _governance_uri_from_file_name(file_name)
    if not uri:
        return _result_text(
            _error_payload(
                "NOT_FOUND",
                f"Cannot resolve governance URI for file_name: {file_name!r}. "
                "Accepted values: 'agents.md', 'governance_data_dictionary.json', "
                "or any path starting with 'agents/'.",
                retryable=False,
            )
        )
    encoded_name = urllib.parse.quote(file_name, safe="")  # encode slashes → %2F
    resp = _governance_api_request("GET", f"/{encoded_name}")
    return _result_text(resp)


async def _governance_dictionary(args: dict) -> list[TextContent]:
    """Query governance data dictionary with optional entity/field/value filtering."""
    entity = (args.get("entity") or "").strip()
    field = (args.get("field") or "").strip()
    value = (args.get("value") or "").strip()

    query_parts: list[str] = []
    if entity:
        query_parts.append(f"entity={urllib.parse.quote(entity, safe='')}")
    if field:
        query_parts.append(f"field={urllib.parse.quote(field, safe='')}")
    if value:
        query_parts.append(f"value={urllib.parse.quote(value, safe='')}")

    query_string = f"?{'&'.join(query_parts)}" if query_parts else ""
    resp = _governance_api_request("GET", f"/dictionary{query_string}")

    if resp.get("error"):
        return _result_text(resp)
    return _result_text(resp)


# --- Graph Search ---


def _graph_query_api_request(
    query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """HTTP GET to the graph query API (direct API Gateway, not CloudFront)."""
    base = GRAPH_QUERY_API_BASE.rstrip("/")
    url = base
    if query:
        encoded_qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None}, doseq=True)
        if encoded_qs:
            url = f"{url}?{encoded_qs}"
    headers = {
        "Accept": "application/json",
        "User-Agent": HTTP_USER_AGENT,
    }

    key_candidates: List[str] = []
    for candidate in (
        COMMON_INTERNAL_API_KEY,
        *COMMON_INTERNAL_API_KEYS,
    ):
        key = str(candidate or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
    if not key_candidates:
        key_candidates.append("")

    for idx, key in enumerate(key_candidates):
        attempt_headers = dict(headers)
        if key:
            attempt_headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method="GET", headers=attempt_headers)
        try:
            with urllib.request.urlopen(req, timeout=20, context=_SSL_CTX) as resp:
                text = resp.read().decode("utf-8")
                return json.loads(text) if text else {"success": True}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw_body": raw}
            if exc.code == 401 and idx < len(key_candidates) - 1:
                continue
            parsed.setdefault("error", f"Graph query API returned {exc.code}")
            parsed["http_status"] = exc.code
            return parsed
        except urllib.error.URLError as exc:
            return {"error": f"Graph query API unreachable: {exc.reason}"}
    return {"error": "Graph query API request failed — no valid API key"}


async def _tracker_graphsearch(args: dict) -> list[TextContent]:
    """Execute a graph search query against the Neo4j graph index."""
    search_type = args.get("search_type")
    project_id = args.get("project_id")
    if not search_type:
        return _result_text({"error": "search_type is required"})
    if not project_id:
        return _result_text({"error": "project_id is required"})

    query_params: Dict[str, Any] = {
        "search_type": search_type,
        "project_id": project_id,
    }
    if args.get("record_id"):
        query_params["record_id"] = args["record_id"]
    if args.get("depth") is not None:
        query_params["depth"] = args["depth"]
    if args.get("direction"):
        query_params["direction"] = args["direction"]
    if args.get("record_type"):
        query_params["record_type"] = args["record_type"]
    # keyword search
    if args.get("keyword"):
        query_params["query"] = args["keyword"]
    if args.get("query"):
        query_params["query"] = args["query"]
    # path search
    if args.get("from_record_id"):
        query_params["from_record_id"] = args["from_record_id"]
    if args.get("to_record_id"):
        query_params["to_record_id"] = args["to_record_id"]
    # ENC-FTR-049: edge-type filtering and weight thresholds
    for key in ("edge_types", "edge_type", "min_weight"):
        if args.get(key) is not None:
            query_params[key] = args[key]

    resp = _graph_query_api_request(query=query_params)
    if resp.get("error"):
        return _result_text(resp)
    return _result_text(resp)


# --- ENC-FTR-049: Typed Relationship Edge Tools ---


async def _tracker_create_relationship(args: dict) -> list:
    """Create a typed relationship edge between two tracker records."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    project_id = args.get("project_id", "")
    if not project_id:
        return _result_text({"error": "project_id is required"})

    payload = {
        "source_id": args.get("source_id", ""),
        "target_id": args.get("target_id", ""),
        "relationship_type": args.get("relationship_type", ""),
        "reason": args.get("reason", ""),
        "governance_hash": args.get("governance_hash", ""),
    }
    for key in ("weight", "confidence", "provenance"):
        if args.get(key) is not None:
            payload[key] = args[key]

    resp = _tracker_api_request("POST", f"/{project_id}/relationship", payload=payload)
    return _result_text(resp)


async def _tracker_archive_relationship(args: dict) -> list:
    """Archive (soft-delete) a typed relationship edge. Data preserved in DynamoDB."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    project_id = args.get("project_id", "")
    if not project_id:
        return _result_text({"error": "project_id is required"})

    # Send as query params — APIGW HTTP API does not forward body for DELETE
    query_params = {
        "source_id": args.get("source_id", ""),
        "target_id": args.get("target_id", ""),
        "relationship_type": args.get("relationship_type", ""),
    }

    resp = _tracker_api_request("DELETE", f"/{project_id}/relationship", query=query_params)
    return _result_text(resp)


async def _tracker_list_relationships(args: dict) -> list:
    """List typed relationship edges with optional filters."""
    project_id = args.get("project_id", "")
    if not project_id:
        return _result_text({"error": "project_id is required"})

    query_params: Dict[str, Any] = {}
    for key in ("source_id", "target_id", "relationship_type", "min_weight", "provenance", "page_size", "cursor"):
        if args.get(key) is not None:
            query_params[key] = args[key]

    resp = _tracker_api_request("GET", f"/{project_id}/relationship", query=query_params)
    return _result_text(resp)


# --- System ---


def _graph_health_check() -> Dict[str, Any]:
    """Check Neo4j graph index health via graph_query_api /health endpoint."""
    base = GRAPH_QUERY_API_BASE.rstrip("/")
    url = f"{base}/health"
    headers = {"Accept": "application/json", "User-Agent": HTTP_USER_AGENT}
    for key in (COMMON_INTERNAL_API_KEY, *COMMON_INTERNAL_API_KEYS):
        key = str(key or "").strip()
        if not key:
            continue
        headers["X-Coordination-Internal-Key"] = key
        req = urllib.request.Request(url=url, method="GET", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass
    return {"status": "unreachable"}


async def _connection_health(args: dict) -> list[TextContent]:
    # --- Phase 2d: HTTP API migration ---
    resp = _health_api_request()
    resp["server_version"] = SERVER_VERSION
    resp["auth_config"] = {
        "common_internal_api_key_configured": bool(COMMON_INTERNAL_API_KEY),
        "coordination_api_internal_api_key_configured": bool(COORDINATION_API_INTERNAL_API_KEY),
        "deploy_api_internal_api_key_configured": bool(DEPLOY_API_INTERNAL_API_KEY),
        "document_api_internal_api_key_configured": bool(DOCUMENT_API_INTERNAL_API_KEY),
        "tracker_api_internal_api_key_configured": bool(TRACKER_API_INTERNAL_API_KEY),
    }
    resp["graph_index"] = _graph_health_check()
    return _result_text(resp)


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
# GitHub integration (ENC-FTR-021 Phase 2)
# -------------------------------------------------------------------


async def _github_create_issue(args: dict) -> list[TextContent]:
    """Create a GitHub issue via the GitHub integration Lambda."""
    owner = str(args.get("owner", "")).strip()
    repo = str(args.get("repo", "")).strip()
    title = str(args.get("title", "")).strip()

    if not owner or not repo or not title:
        return _result_text(_error_payload(
            "INVALID_INPUT",
            "Fields 'owner', 'repo', and 'title' are required.",
        ))

    payload: Dict[str, Any] = {
        "owner": owner,
        "repo": repo,
        "title": title,
    }
    body = str(args.get("body", "")).strip()
    if body:
        payload["body"] = body
    labels = args.get("labels")
    if labels and isinstance(labels, list):
        payload["labels"] = [str(l).strip() for l in labels if str(l).strip()]
    record_id = str(args.get("record_id", "")).strip()
    if record_id:
        payload["record_id"] = record_id
    project_id = str(args.get("project_id", "")).strip()
    if project_id:
        payload["project_id"] = project_id

    resp = _github_api_request("POST", "/issues", payload=payload)
    return _result_text(resp)


async def _github_projects_sync(args: dict) -> list[TextContent]:
    """Sync a GitHub issue to a Projects v2 board."""
    project_id = str(args.get("project_id", "")).strip()
    if not project_id:
        return _result_text(_error_payload(
            "INVALID_INPUT", "Field 'project_id' (Projects v2 node ID) is required.",
        ))

    payload: Dict[str, Any] = {"project_id": project_id}

    owner = str(args.get("owner", "")).strip()
    if owner:
        payload["owner"] = owner
    repo = str(args.get("repo", "")).strip()
    if repo:
        payload["repo"] = repo
    issue_number = args.get("issue_number")
    if issue_number is not None:
        payload["issue_number"] = int(issue_number)
    issue_url = str(args.get("issue_url", "")).strip()
    if issue_url:
        payload["issue_url"] = issue_url
    status = str(args.get("status", "")).strip()
    if status:
        payload["status"] = status
    priority = str(args.get("priority", "")).strip()
    if priority:
        payload["priority"] = priority

    resp = _github_api_request("POST", "/projects/sync", payload=payload)
    return _result_text(resp)


async def _github_projects_list(args: dict) -> list[TextContent]:
    """List GitHub Projects v2 for an organization."""
    params = []
    org = str(args.get("org", "")).strip()
    if org:
        params.append(f"org={org}")
    if args.get("include_closed"):
        params.append("include_closed=true")

    path = "/projects"
    if params:
        path += "?" + "&".join(params)

    resp = _github_api_request("GET", path)
    return _result_text(resp)


# -------------------------------------------------------------------
# Checkout Service Handlers (ENC-FTR-037)
# -------------------------------------------------------------------


async def _checkout_task(args: dict) -> list[TextContent]:
    """checkout_task — Check out a task and advance to in-progress."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    active_agent_session_id = (args.get("active_agent_session_id") or "").strip()
    if not active_agent_session_id:
        return _result_text({"error": "active_agent_session_id is required"})

    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type not in ("task", "plan"):
        return _result_text({"error": f"checkout only applies to tasks and plans, not {record_type}"})

    payload: Dict[str, Any] = {
        "active_agent_session_id": active_agent_session_id,
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]

    resp = _checkout_api_request("POST", f"/{project_id}/{record_type}/{rid}/checkout", payload=payload)
    if isinstance(resp, dict) and resp.get("success"):
        await _sync_dynamic_toolset_on_checkout(record_id, resp)
    return _result_text(resp)


async def _release_task(args: dict) -> list[TextContent]:
    """release_task — Release the checkout on a task."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    payload: Dict[str, Any] = {"governance_hash": args.get("governance_hash", "")}
    if args.get("provider"):
        payload["provider"] = args["provider"]
    if args.get("checkin_summary"):
        payload["checkin_summary"] = args["checkin_summary"]

    resp = _checkout_api_request("DELETE", f"/{project_id}/{record_type}/{rid}/checkout", payload=payload)
    if isinstance(resp, dict) and resp.get("success"):
        await _sync_dynamic_toolset_on_task_release(record_id)
    return _result_text(resp)


async def _advance_task_status(args: dict) -> list[TextContent]:
    """advance_task_status — Advance a task's lifecycle status via the checkout service."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type not in ("task", "plan"):
        return _result_text({"error": f"advance_task_status only applies to tasks and plans, not {record_type}"})

    payload: Dict[str, Any] = {
        "target_status": args["target_status"],
        "provider": args.get("provider", ""),
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("transition_evidence"):
        payload["transition_evidence"] = args["transition_evidence"]
    if args.get("pr_id") is not None:
        payload["pr_id"] = args["pr_id"]
    if args.get("merged_at"):
        payload["merged_at"] = args["merged_at"]
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]
    if args.get("live_validation_evidence"):
        payload["live_validation_evidence"] = args["live_validation_evidence"]

    resp = _checkout_api_request("POST", f"/{project_id}/{record_type}/{rid}/advance", payload=payload)
    if (
        isinstance(resp, dict)
        and resp.get("success")
        and str(args.get("target_status") or "").strip().lower() == "closed"
    ):
        await _sync_dynamic_toolset_on_task_release(record_id)
    return _result_text(resp)


async def _append_worklog(args: dict) -> list[TextContent]:
    """append_worklog — Append a worklog to a checked-out task via checkout service."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args["record_id"]
    description = (args.get("description") or "").strip()
    if not description:
        return _result_text({"error": "description is required"})

    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type != "task":
        return _result_text({
            "error": (
                f"append_worklog is for tasks only. For {record_type} records, use tracker_log directly."
            )
        })

    payload: Dict[str, Any] = {
        "description": description,
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("provider"):
        payload["provider"] = args["provider"]
    if args.get("coordination_request_id"):
        payload["coordination_request_id"] = args["coordination_request_id"]

    resp = _checkout_api_request("POST", f"/{project_id}/{record_type}/{rid}/log", payload=payload)
    return _result_text(resp)


async def _validate_commit_complete(args: dict) -> list[TextContent]:
    """validate_commit_complete — Validate a CCI token issued by the checkout service."""
    cci_id = (args.get("cci_id") or "").strip()
    if not cci_id:
        return _result_text({"error": "cci_id is required"})

    resp = _checkout_api_request("GET", f"/validate/commit-complete/{cci_id}")
    return _result_text(resp)


# -------------------------------------------------------------------
# ENC-FTR-058 / ENC-TSK-A97: Plan objectives status handler
# -------------------------------------------------------------------


async def _plan_objectives_status(args: dict) -> list[TextContent]:
    """Return the completion status of all objectives in a plan's objectives_set."""
    record_id = args.get("record_id", "")
    if not record_id:
        return _result_text({"error": "record_id is required (plan ID)"})

    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    if record_type != "plan":
        return _result_text({"error": f"record_id must be a plan, got {record_type}"})

    # Fetch the plan record
    plan_resp = _tracker_api_request("GET", f"/{project_id}/plan/{rid}")
    if isinstance(plan_resp, dict) and plan_resp.get("error"):
        return _result_text(plan_resp)
    plan = plan_resp.get("record", plan_resp) if isinstance(plan_resp, dict) else plan_resp

    objectives_set = plan.get("objectives_set", []) or []
    if not objectives_set:
        return _result_text({
            "plan_id": record_id,
            "status": plan.get("status", ""),
            "objectives": [],
            "summary": {"total": 0, "closed": 0, "open": 0, "progress_pct": 0},
        })

    # Resolve each objective's current status
    terminal_statuses = {"closed", "completed", "complete", "archived", "deprecated", "production"}
    objectives = []
    for obj_id in objectives_set:
        try:
            obj_proj, obj_type, obj_rid = _parse_record_id(obj_id)
            obj_resp = _tracker_api_request("GET", f"/{obj_proj}/{obj_type}/{obj_rid}")
            obj_record = obj_resp.get("record", obj_resp) if isinstance(obj_resp, dict) else obj_resp
            obj_status = obj_record.get("status", "unknown") if isinstance(obj_record, dict) else "unknown"
            obj_title = obj_record.get("title", obj_id) if isinstance(obj_record, dict) else obj_id
        except (ValueError, Exception):
            obj_status = "unknown"
            obj_title = obj_id
        objectives.append({"id": obj_id, "title": obj_title, "status": obj_status})

    closed_count = sum(1 for o in objectives if o["status"] in terminal_statuses)
    total = len(objectives)

    return _result_text({
        "plan_id": record_id,
        "status": plan.get("status", ""),
        "objectives": objectives,
        "summary": {
            "total": total,
            "closed": closed_count,
            "open": total - closed_count,
            "progress_pct": round((closed_count / total) * 100) if total > 0 else 0,
        },
    })


# -------------------------------------------------------------------
# ENC-FTR-052: Governed Lesson Primitive handlers
# -------------------------------------------------------------------


async def _tracker_create_lesson(args: dict) -> list[TextContent]:
    """Create a new lesson record with evidence chain validation."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    project_id = args.get("project_id", "")
    if not project_id:
        return _result_text({"error": "project_id is required"})

    payload: Dict[str, Any] = {
        "title": args.get("title", ""),
        "observation": args.get("observation", ""),
        "insight": args.get("insight", ""),
        "evidence_chain": args.get("evidence_chain", []),
        "governance_hash": args.get("governance_hash", ""),
    }
    for key in ("category", "provenance", "confidence", "analysis_reference",
                "pillar_scores", "priority", "description", "related"):
        if args.get(key) is not None:
            payload[key] = args[key]

    resp = _tracker_api_request("POST", f"/{project_id}/lesson", payload=payload)
    return _result_text(resp)


async def _tracker_extend_lesson(args: dict) -> list[TextContent]:
    """Append an extension to a lesson (append-only contextualization)."""
    governance_error = _require_governance_hash(args)
    if governance_error:
        return _result_text({"error": governance_error})

    record_id = args.get("record_id", "")
    if not record_id:
        return _result_text({"error": "record_id is required"})

    try:
        project_id, record_type, rid = _parse_record_id(record_id)
    except ValueError as exc:
        return _result_text({"error": str(exc)})

    payload: Dict[str, Any] = {
        "content": args.get("content", ""),
        "author": args.get("author", ""),
        "governance_hash": args.get("governance_hash", ""),
    }
    if args.get("evidence_ids"):
        payload["evidence_ids"] = args["evidence_ids"]
    if args.get("pillar_scores"):
        payload["pillar_scores"] = args["pillar_scores"]

    resp = _tracker_api_request("POST", f"/{project_id}/lesson/{rid}/extend", payload=payload)
    return _result_text(resp)


async def _tracker_list_lessons(args: dict) -> list[TextContent]:
    """List lesson records for a project with optional filters."""
    project_id = args.get("project_id", "")
    if not project_id:
        return _result_text({"error": "project_id is required"})

    query_params: Dict[str, str] = {"type": "lesson"}
    for key in ("status", "category", "page_size", "cursor"):
        if args.get(key):
            query_params[key] = str(args[key])

    resp = _tracker_api_request("GET", f"/{project_id}", query=query_params)
    return _result_text(resp)


# -------------------------------------------------------------------
# Handler dispatch map
# -------------------------------------------------------------------

_TOOL_HANDLERS = {
    "search": _search,
    "coordination": _coordination_meta,
    "get_compact_context": _get_compact_context_meta,
    "execute": _execute,
    "projects_list": _projects_list,
    "projects_get": _projects_get,
    "tracker_get": _tracker_get,
    "tracker_validation_rules": _tracker_validation_rules,
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
    "get_code_map": _get_code_map,
    "get_issue_context": _get_issue_context,
    "get_architecture_excerpts": _get_architecture_excerpts,
    "deploy_state_get": _deploy_state_get,
    "deploy_history": _deploy_history,
    "deploy_history_list": _deploy_history_list,
    "deploy_submit": _deploy_submit,
    "deploy_state_set": _deploy_state_set,
    "deploy_status": _deploy_status,
    "deploy_status_get": _deploy_status_get,
    "deploy_trigger": _deploy_trigger,
    "deploy_pending_requests": _deploy_pending_requests,
    "changelog_history": _changelog_history,
    "changelog_history_all": _changelog_history_all,
    "changelog_version": _changelog_version,
    "coordination_capabilities": _coordination_capabilities,
    "coordination_request_get": _coordination_request_get,
    "coordination_cognito_session": _coordination_cognito_session,
    "governance_update": _governance_update,
    "governance_hash": _governance_hash,
    "governance_get": _governance_get,
    "governance_dictionary": _governance_dictionary,
    "connection_health": _connection_health,
    "dispatch_plan_generate": _dispatch_plan_generate,
    "dispatch_plan_dry_run": _dispatch_plan_dry_run,
    "github_create_issue": _github_create_issue,
    "github_projects_sync": _github_projects_sync,
    "github_projects_list": _github_projects_list,
    # ENC-FTR-047: Graph search
    "tracker_graphsearch": _tracker_graphsearch,
    # ENC-FTR-049: Typed relationship edges
    "tracker_create_relationship": _tracker_create_relationship,
    "tracker_archive_relationship": _tracker_archive_relationship,
    "tracker_list_relationships": _tracker_list_relationships,
    # ENC-FTR-037: Checkout service tools
    "checkout_task": _checkout_task,
    "release_task": _release_task,
    "advance_task_status": _advance_task_status,
    "append_worklog": _append_worklog,
    "validate_commit_complete": _validate_commit_complete,
    # ENC-FTR-052: Governed Lesson Primitive
    "tracker_create_lesson": _tracker_create_lesson,
    "tracker_extend_lesson": _tracker_extend_lesson,
    "tracker_list_lessons": _tracker_list_lessons,
    # ENC-FTR-058 / ENC-TSK-A97: Plan tools
    "plan_objectives_status": _plan_objectives_status,
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


# ---------------------------------------------------------------------------
# HTTP / Lambda transport (ENCELADUS_MCP_TRANSPORT=streamable_http)
# ---------------------------------------------------------------------------

_http_session_manager: Any = None


def _get_http_session_manager() -> Any:
    global _http_session_manager
    if _http_session_manager is None:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        _http_session_manager = StreamableHTTPSessionManager(
            app=app, json_response=True, stateless=True,
        )
    return _http_session_manager


def _get_server_base_url(event: Dict[str, Any]) -> str:
    """Derive the public base URL, preferring CUSTOM_DOMAIN when set (ENC-TSK-873).

    When behind CloudFront, the Host header is replaced with the origin domain.
    CUSTOM_DOMAIN env var lets the Lambda return the vanity URL in OAuth metadata.
    """
    custom = os.environ.get("CUSTOM_DOMAIN", "").strip().rstrip("/")
    if custom:
        # Ensure scheme prefix
        if not custom.startswith("https://"):
            custom = f"https://{custom}"
        return custom
    headers = event.get("headers") or {}
    host = headers.get("host", headers.get("x-forwarded-host", ""))
    scheme = headers.get("x-forwarded-proto", "https")
    return f"{scheme}://{host}" if host else ""


# ---------------------------------------------------------------------------
# Cognito JWKS + JWT validation (ENC-FTR-045)
# ---------------------------------------------------------------------------

_cognito_jwks_cache: Dict[str, Any] = {}
_cognito_jwks_fetched_at: float = 0.0
_COGNITO_JWKS_TTL: float = 3600.0


def _get_cognito_jwks() -> Dict[str, Any]:
    """Fetch and cache Cognito JWKS keys. Requires PyJWT[crypto]."""
    global _cognito_jwks_cache, _cognito_jwks_fetched_at
    now = time.time()
    if _cognito_jwks_cache and (now - _cognito_jwks_fetched_at) < _COGNITO_JWKS_TTL:
        return _cognito_jwks_cache

    if not COGNITO_USER_POOL_ID:
        raise ValueError("COGNITO_USER_POOL_ID not set")

    region = COGNITO_REGION or COGNITO_USER_POOL_ID.split("_")[0]
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )

    try:
        import jwt as _jwt_mod
        from jwt.algorithms import RSAAlgorithm as _RSA
    except ImportError:
        raise ValueError("PyJWT[crypto] is required for Cognito JWT validation")

    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    with urllib.request.urlopen(url, timeout=5, context=ctx) as resp:
        data = json.loads(resp.read())

    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data.get("kid")
        if kid:
            new_cache[kid] = _RSA.from_jwk(json.dumps(key_data))

    _cognito_jwks_cache = new_cache
    _cognito_jwks_fetched_at = now
    return _cognito_jwks_cache


def _verify_cognito_jwt(token: str) -> Dict[str, Any]:
    """Validate a Cognito-issued JWT (access or id token). Returns claims dict."""
    try:
        import jwt as _jwt_mod
    except ImportError:
        raise ValueError("PyJWT[crypto] is required for Cognito JWT validation")

    try:
        header = _jwt_mod.get_unverified_header(token)
    except Exception as exc:
        raise ValueError(f"Invalid token header: {exc}") from exc

    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg != "RS256":
        raise ValueError(f"Unexpected token algorithm: {alg}")

    key = _get_cognito_jwks().get(kid)
    if key is None:
        raise ValueError("Token key ID not found in JWKS")

    region = COGNITO_REGION or COGNITO_USER_POOL_ID.split("_", 1)[0]
    expected_issuer = f"https://cognito-idp.{region}.amazonaws.com/{COGNITO_USER_POOL_ID}"

    try:
        claims = _jwt_mod.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=expected_issuer,
            options={"verify_exp": True, "verify_aud": False},
        )
    except _jwt_mod.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except _jwt_mod.InvalidIssuerError:
        raise ValueError("Token issuer mismatch")
    except _jwt_mod.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc

    # Validate client_id for access tokens or aud for id tokens
    if COGNITO_CLIENT_ID_CODE:
        token_use = str(claims.get("token_use") or "").strip().lower()
        if token_use == "access":
            cid = str(claims.get("client_id") or "")
            if not hmac.compare_digest(cid, COGNITO_CLIENT_ID_CODE):
                raise ValueError("Token client_id mismatch")
        elif token_use == "id":
            aud = str(claims.get("aud") or "")
            if not hmac.compare_digest(aud, COGNITO_CLIENT_ID_CODE):
                raise ValueError("Token audience mismatch")

    return claims


# ---------------------------------------------------------------------------
# Cognito-direct OAuth endpoints (ENC-FTR-045)
# ---------------------------------------------------------------------------


def _handle_cognito_oauth_server_metadata(event: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 8414: Authorization Server Metadata pointing directly to Cognito Hosted UI."""
    base = _get_server_base_url(event)
    cognito_domain = COGNITO_DOMAIN.rstrip("/")
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "public, max-age=3600"},
        "body": json.dumps({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_types_supported": ["code"],
            "scopes_supported": ["openid", "email", "profile"],
            "code_challenge_methods_supported": ["S256"],
            "service_documentation": f"{base}/.well-known/oauth-protected-resource",
        }),
        "isBase64Encoded": False,
    }


def _get_client_ip(event: Dict[str, Any]) -> str:
    """Extract client IP from Lambda event for observability logging."""
    rc = (event.get("requestContext") or {}).get("http") or {}
    return (
        rc.get("sourceIp")
        or (event.get("headers") or {}).get("x-forwarded-for", "").split(",")[0].strip()
        or "unknown"
    )


def _log_auth_failure(endpoint: str, error_type: str, event: Dict[str, Any], **extra: Any) -> None:
    """Emit structured auth failure log without leaking tokens or secrets."""
    payload: Dict[str, Any] = {
        "event": "auth_failure",
        "endpoint": endpoint,
        "error_type": error_type,
        "client_ip": _get_client_ip(event),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload.update(extra)
    logger.warning("[AUTH_FAILURE] %s", json.dumps(payload, sort_keys=True))


def _handle_cognito_authorize(event: Dict[str, Any]) -> Dict[str, Any]:
    """Proxy /authorize — redirect to Cognito Hosted UI, using a fixed server-side
    callback URL so that dynamic localhost ports from CLI clients don't need to be
    registered in Cognito's CallbackURLs.  The client's original redirect_uri and
    state are encoded into the Cognito state parameter and recovered in /callback.
    Unsupported params like ``resource`` (RFC 8707) are stripped (ENC-ISS-124)."""
    import base64 as b64

    qs = event.get("queryStringParameters") or {}
    base = _get_server_base_url(event)
    cognito_domain = COGNITO_DOMAIN.rstrip("/")

    # Validate required OAuth params (ENC-TSK-930 AC3)
    missing = [p for p in ("response_type", "client_id") if not qs.get(p)]
    if missing:
        _log_auth_failure("/authorize", "missing_params", event, missing_params=missing)
        return {
            "statusCode": 400,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({
                "error": "invalid_request",
                "error_description": f"Missing required parameter(s): {', '.join(missing)}",
            }),
            "isBase64Encoded": False,
        }

    client_redirect_uri = qs.get("redirect_uri", "")
    client_state = qs.get("state", "")

    # Encode client redirect_uri + state into an opaque Cognito state blob
    relay = json.dumps({"ru": client_redirect_uri, "st": client_state}, separators=(",", ":"))
    cognito_state = b64.urlsafe_b64encode(relay.encode()).decode().rstrip("=")

    # Build Cognito authorize URL with server-side callback
    params = {}
    for key in ("response_type", "client_id",
                "code_challenge", "code_challenge_method", "scope"):
        val = qs.get(key, "")
        if val:
            params[key] = val
    params["redirect_uri"] = f"{base}/callback"
    params["state"] = cognito_state

    if "scope" not in params:
        params["scope"] = "openid email profile"

    location = f"{cognito_domain}/oauth2/authorize?{urllib.parse.urlencode(params)}"
    return {
        "statusCode": 302,
        "headers": {"location": location, "cache-control": "no-store"},
        "body": "",
        "isBase64Encoded": False,
    }


def _callback_error_html(title: str, detail: str) -> Dict[str, Any]:
    """Return a user-facing HTML error page for /callback failures (ENC-TSK-930 AC3)."""
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Authentication Error</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:60px auto;"
        "text-align:center;color:#333}h1{font-size:1.4em;color:#c00}"
        "p{margin:1em 0;line-height:1.5}</style></head><body>"
        f"<h1>{title}</h1><p>{detail}</p>"
        "<p>Please close this window and try again.</p>"
        "</body></html>"
    )
    return {
        "statusCode": 400,
        "headers": {"content-type": "text/html; charset=utf-8", "cache-control": "no-store"},
        "body": html,
        "isBase64Encoded": False,
    }


def _handle_cognito_callback(event: Dict[str, Any]) -> Dict[str, Any]:
    """Server-side OAuth callback — receives the auth code from Cognito and relays
    it to the client's original redirect_uri (typically http://localhost:{port}/callback)."""
    import base64 as b64

    qs = event.get("queryStringParameters") or {}
    code = qs.get("code", "")
    cognito_state = qs.get("state", "")
    error = qs.get("error", "")
    error_description = qs.get("error_description", "")

    # Decode the original client redirect_uri and state
    client_redirect_uri = ""
    client_state = ""
    if cognito_state:
        try:
            padded = cognito_state + "=" * (-len(cognito_state) % 4)
            relay = json.loads(b64.urlsafe_b64decode(padded).decode())
            client_redirect_uri = relay.get("ru", "")
            client_state = relay.get("st", "")
        except Exception:
            _log_auth_failure("/callback", "invalid_state", event)

    if error:
        _log_auth_failure("/callback", "cognito_error", event,
                          cognito_error_code=error,
                          has_redirect=bool(client_redirect_uri))
        if client_redirect_uri:
            sep = "&" if "?" in client_redirect_uri else "?"
            location = f"{client_redirect_uri}{sep}error={urllib.parse.quote(error, safe='')}"
            if client_state:
                location += f"&state={urllib.parse.quote(client_state, safe='')}"
            return {"statusCode": 302, "headers": {"location": location, "cache-control": "no-store"},
                    "body": "", "isBase64Encoded": False}
        detail = error_description or error
        return _callback_error_html("Authentication Failed", detail)

    if not client_redirect_uri:
        _log_auth_failure("/callback", "missing_redirect_uri", event)
        return _callback_error_html(
            "Invalid Request",
            "Could not determine where to send you back. The relay state was missing or corrupted.",
        )

    if not code:
        _log_auth_failure("/callback", "missing_code", event)
        return _callback_error_html(
            "Authorization Failed",
            "No authorization code was received from the identity provider.",
        )

    # Relay auth code to client's original redirect_uri
    sep = "&" if "?" in client_redirect_uri else "?"
    location = f"{client_redirect_uri}{sep}code={urllib.parse.quote(code, safe='')}"
    if client_state:
        location += f"&state={urllib.parse.quote(client_state, safe='')}"

    return {
        "statusCode": 302,
        "headers": {"location": location, "cache-control": "no-store"},
        "body": "",
        "isBase64Encoded": False,
    }


def _handle_cognito_token(event: Dict[str, Any]) -> Dict[str, Any]:
    """Proxy /oauth/token — forward to Cognito, replacing the client's redirect_uri
    with the server-side callback URL that was actually used with Cognito."""
    cognito_domain = COGNITO_DOMAIN.rstrip("/")
    token_url = f"{cognito_domain}/oauth2/token"
    base = _get_server_base_url(event)

    body_raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64 as b64
        body_raw = b64.b64decode(body_raw).decode()

    # Validate grant_type is present (ENC-TSK-930 AC3)
    params = urllib.parse.parse_qs(body_raw, keep_blank_values=True)
    grant_type = (params.get("grant_type") or [""])[0]
    if not grant_type:
        _log_auth_failure("/oauth/token", "missing_grant_type", event)
        return {
            "statusCode": 400,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({
                "error": "invalid_request",
                "error_description": "Missing required parameter: grant_type",
            }),
            "isBase64Encoded": False,
        }

    # Replace client's redirect_uri with the server-side callback used in /authorize
    if "redirect_uri" in params:
        params["redirect_uri"] = [f"{base}/callback"]
        body_raw = urllib.parse.urlencode({k: v[0] for k, v in params.items()})

    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass

    req = urllib.request.Request(
        token_url,
        data=body_raw.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            resp_body = resp.read().decode("utf-8")
            return {
                "statusCode": resp.status,
                "headers": {"content-type": "application/json", "cache-control": "no-store"},
                "body": resp_body,
                "isBase64Encoded": False,
            }
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace") if exc.fp else "{}"
        _log_auth_failure("/oauth/token", "cognito_rejected", event,
                          cognito_error_code=exc.code,
                          grant_type=grant_type)
        # Return Cognito's error as-is (RFC 6749 format)
        return {
            "statusCode": exc.code,
            "headers": {"content-type": "application/json"},
            "body": err_body,
            "isBase64Encoded": False,
        }
    except Exception as exc:
        _log_auth_failure("/oauth/token", "proxy_error", event,
                          error_class=type(exc).__name__)
        return {
            "statusCode": 502,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "server_error", "error_description": str(exc)}),
            "isBase64Encoded": False,
        }


def _handle_cognito_register(event: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 7591: Dynamic Client Registration — returns pre-configured Cognito app client."""
    body_raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64 as b64
        body_raw = b64.b64decode(body_raw).decode()
    try:
        reg = json.loads(body_raw) if body_raw else {}
    except Exception:
        reg = {}
    redirect_uris = reg.get("redirect_uris", [])
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps({
            "client_id": COGNITO_CLIENT_ID_CODE,
            "client_secret": COGNITO_CLIENT_SECRET_CODE,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid email profile",
            "token_endpoint_auth_method": "client_secret_post",
        }),
        "isBase64Encoded": False,
    }


def _handle_oauth_protected_resource(event: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 9728: OAuth 2.0 Protected Resource Metadata."""
    base = _get_server_base_url(event)
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "public, max-age=3600"},
        "body": json.dumps({
            "resource": base,
            "authorization_servers": [base],
            "scopes_supported": ["openid", "email", "profile"],
            "bearer_methods_supported": ["header"],
        }),
        "isBase64Encoded": False,
    }


def _handle_oauth_server_metadata(event: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 8414: OAuth 2.0 Authorization Server Metadata."""
    base = _get_server_base_url(event)
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "public, max-age=3600"},
        "body": json.dumps({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "service_documentation": f"{base}/.well-known/oauth-protected-resource",
        }),
        "isBase64Encoded": False,
    }


def _mint_auth_code(payload: dict) -> str:
    """Create a self-contained, HMAC-signed authorization code (no server state needed)."""
    import base64 as b64
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(OAUTH_CLIENT_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return b64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + sig


def _verify_auth_code(code: str) -> Optional[dict]:
    """Verify and decode a self-contained authorization code. Returns None if invalid."""
    import base64 as b64
    parts = code.rsplit(".", 1)
    if len(parts) != 2:
        return None
    encoded, sig = parts
    # Restore base64 padding
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = b64.urlsafe_b64decode(padded)
    except Exception:
        return None
    expected_sig = hmac.new(OAUTH_CLIENT_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def _mint_refresh_token() -> str:
    """Create a self-contained, HMAC-signed refresh token (stateless — no server storage needed).

    The token payload is: {"typ": "rt", "iat": <unix>, "exp": <unix+30d>}
    Signed with OAUTH_CLIENT_SECRET so it survives Lambda cold starts and can be
    validated on any invocation without shared state.
    """
    import base64 as b64
    now = int(time.time())
    payload = {"typ": "rt", "iat": now, "exp": now + _REFRESH_TOKEN_TTL}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(OAUTH_CLIENT_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return b64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + sig


def _verify_refresh_token(token: str) -> Optional[dict]:
    """Verify and decode a refresh token. Returns None if signature is invalid or token is expired."""
    import base64 as b64
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return None
    encoded, sig = parts
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = b64.urlsafe_b64decode(padded)
    except Exception:
        return None
    expected_sig = hmac.new(OAUTH_CLIENT_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if payload.get("typ") != "rt":
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def _handle_oauth_authorize(event: Dict[str, Any]) -> Dict[str, Any]:
    """OAuth 2.0 Authorization endpoint — Authorization Code flow with PKCE."""
    qs = event.get("queryStringParameters") or {}
    response_type = qs.get("response_type", "")
    client_id = qs.get("client_id", "")
    redirect_uri = qs.get("redirect_uri", "")
    state = qs.get("state", "")
    code_challenge = qs.get("code_challenge", "")
    code_challenge_method = qs.get("code_challenge_method", "")

    if not OAUTH_CLIENT_ID or not OAUTH_CLIENT_SECRET:
        return {
            "statusCode": 500,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "server_error", "error_description": "OAuth not configured"}),
            "isBase64Encoded": False,
        }

    if response_type != "code":
        return _oauth_error_redirect(redirect_uri, state, "unsupported_response_type")

    if not hmac.compare_digest(client_id, OAUTH_CLIENT_ID):
        return _oauth_error_redirect(redirect_uri, state, "invalid_client")

    if code_challenge_method and code_challenge_method != "S256":
        return _oauth_error_redirect(redirect_uri, state, "invalid_request",
                                     "Only S256 code_challenge_method is supported")

    # Mint a self-contained authorization code (60s TTL)
    code = _mint_auth_code({
        "cc": code_challenge,
        "ccm": code_challenge_method or "S256",
        "ru": redirect_uri,
        "cid": client_id,
        "exp": int(time.time()) + 60,
    })

    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}code={urllib.parse.quote(code, safe='')}"
    if state:
        location += f"&state={urllib.parse.quote(state, safe='')}"
    return {
        "statusCode": 302,
        "headers": {"location": location, "cache-control": "no-store"},
        "body": "",
        "isBase64Encoded": False,
    }


def _oauth_error_redirect(redirect_uri: str, state: str, error: str,
                           description: str = "") -> Dict[str, Any]:
    """Build an OAuth error redirect or JSON response if no redirect_uri."""
    if not redirect_uri:
        body: dict = {"error": error}
        if description:
            body["error_description"] = description
        return {
            "statusCode": 400,
            "headers": {"content-type": "application/json"},
            "body": json.dumps(body),
            "isBase64Encoded": False,
        }
    sep = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{sep}error={urllib.parse.quote(error, safe='')}"
    if description:
        location += f"&error_description={urllib.parse.quote(description, safe='')}"
    if state:
        location += f"&state={urllib.parse.quote(state, safe='')}"
    return {
        "statusCode": 302,
        "headers": {"location": location, "cache-control": "no-store"},
        "body": "",
        "isBase64Encoded": False,
    }


def _handle_oauth_register(event: Dict[str, Any]) -> Dict[str, Any]:
    """OAuth 2.0 Dynamic Client Registration (RFC 7591) — returns static client metadata."""
    base = _get_server_base_url(event)
    body_raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64 as b64
        body_raw = b64.b64decode(body_raw).decode()
    try:
        reg = json.loads(body_raw) if body_raw else {}
    except Exception:
        reg = {}
    redirect_uris = reg.get("redirect_uris", [])
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": json.dumps({
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }),
        "isBase64Encoded": False,
    }


def _touch_oauth_client_usage() -> None:
    """Fire-and-forget call to update last_used_at for this OAuth client on the coordination API."""
    if not OAUTH_CLIENT_ID or not COORDINATION_API_BASE or not COORDINATION_API_INTERNAL_API_KEY:
        return
    try:
        base = COORDINATION_API_BASE.rstrip("/")
        url = f"{base}/auth/oauth-clients/{urllib.parse.quote(OAUTH_CLIENT_ID, safe='')}/usage"
        req = urllib.request.Request(url, method="PATCH", data=b"{}")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Coordination-Internal-Key", COORDINATION_API_INTERNAL_API_KEY)
        ctx = ssl.create_default_context()
        urllib.request.urlopen(req, timeout=5, context=ctx)
    except Exception:
        logger.debug("Failed to update OAuth client usage (non-critical)", exc_info=True)


def _handle_oauth_token(event: Dict[str, Any]) -> Dict[str, Any]:
    """OAuth 2.0 token endpoint — authorization_code with PKCE."""
    if not OAUTH_CLIENT_ID or not OAUTH_CLIENT_SECRET:
        return {
            "statusCode": 500,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "server_error", "error_description": "OAuth not configured"}),
            "isBase64Encoded": False,
        }

    body_raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        import base64 as b64
        body_raw = b64.b64decode(body_raw).decode()
    params = urllib.parse.parse_qs(body_raw)

    grant_type = (params.get("grant_type") or [""])[0]
    client_id = (params.get("client_id") or [""])[0]
    client_secret = (params.get("client_secret") or [""])[0]

    # Validate client credentials if provided
    if client_id and not hmac.compare_digest(client_id, OAUTH_CLIENT_ID):
        return {
            "statusCode": 401,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "invalid_client"}),
            "isBase64Encoded": False,
        }
    if client_secret and not hmac.compare_digest(client_secret, OAUTH_CLIENT_SECRET):
        return {
            "statusCode": 401,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "invalid_client"}),
            "isBase64Encoded": False,
        }

    if grant_type == "authorization_code":
        code = (params.get("code") or [""])[0]
        code_verifier = (params.get("code_verifier") or [""])[0]

        payload = _verify_auth_code(code)
        if payload is None:
            return {
                "statusCode": 400,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}),
                "isBase64Encoded": False,
            }

        # Verify PKCE: S256 = BASE64URL(SHA256(code_verifier)) must match code_challenge
        stored_challenge = payload.get("cc", "")
        if stored_challenge and code_verifier:
            import base64 as b64
            computed = b64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
            if not hmac.compare_digest(computed, stored_challenge):
                return {
                    "statusCode": 400,
                    "headers": {"content-type": "application/json"},
                    "body": json.dumps({"error": "invalid_grant", "error_description": "PKCE verification failed"}),
                    "isBase64Encoded": False,
                }

        _touch_oauth_client_usage()
        return {
            "statusCode": 200,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({
                "access_token": MCP_API_KEY,
                "token_type": "bearer",
                "expires_in": MCP_TOKEN_TTL,
                # Refresh token lets Claude.ai silently renew without prompting
                # the user to reconnect. Stateless HMAC-signed, 30-day TTL.
                "refresh_token": _mint_refresh_token(),
            }),
            "isBase64Encoded": False,
        }

    elif grant_type == "client_credentials":
        if not client_id or not client_secret:
            return {
                "statusCode": 401,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": "invalid_client"}),
                "isBase64Encoded": False,
            }
        _touch_oauth_client_usage()
        # RFC 6749 §4.4.3: refresh tokens SHOULD NOT be issued for client_credentials.
        return {
            "statusCode": 200,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({
                "access_token": MCP_API_KEY,
                "token_type": "bearer",
                "expires_in": MCP_TOKEN_TTL,
            }),
            "isBase64Encoded": False,
        }

    elif grant_type == "refresh_token":
        refresh_token = (params.get("refresh_token") or [""])[0]
        if not refresh_token:
            return {
                "statusCode": 400,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": "invalid_request", "error_description": "refresh_token is required"}),
                "isBase64Encoded": False,
            }
        payload = _verify_refresh_token(refresh_token)
        if payload is None:
            return {
                "statusCode": 400,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}),
                "isBase64Encoded": False,
            }
        _touch_oauth_client_usage()
        return {
            "statusCode": 200,
            "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps({
                "access_token": MCP_API_KEY,
                "token_type": "bearer",
                "expires_in": MCP_TOKEN_TTL,
                # Rotate the refresh token on every use (RFC 6749 §10.4 best practice)
                "refresh_token": _mint_refresh_token(),
            }),
            "isBase64Encoded": False,
        }

    return {
        "statusCode": 400,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"error": "unsupported_grant_type"}),
        "isBase64Encoded": False,
    }


def _handle_oauth_route(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Route OAuth / well-known requests. Returns None if path is not an OAuth route.

    When Cognito mode is active (ENC-FTR-045), dispatches to Cognito-direct
    handlers; otherwise uses the self-contained HMAC-based flow.
    """
    req_ctx = (event.get("requestContext") or {}).get("http", {})
    path = req_ctx.get("path", "")
    method = req_ctx.get("method", "GET").upper()

    if path == "/.well-known/oauth-protected-resource" and method == "GET":
        return _handle_oauth_protected_resource(event)

    cognito = _cognito_mode_active()

    if path == "/.well-known/oauth-authorization-server" and method == "GET":
        return _handle_cognito_oauth_server_metadata(event) if cognito else _handle_oauth_server_metadata(event)
    if path == "/authorize" and method == "GET":
        return _handle_cognito_authorize(event) if cognito else _handle_oauth_authorize(event)
    if path == "/callback" and method == "GET" and cognito:
        return _handle_cognito_callback(event)
    if path == "/oauth/token" and method == "POST":
        return _handle_cognito_token(event) if cognito else _handle_oauth_token(event)
    if path == "/oauth/register" and method == "POST":
        return _handle_cognito_register(event) if cognito else _handle_oauth_register(event)
    return None


async def _handle_lambda_event(event: Dict[str, Any]) -> Dict[str, Any]:
    import base64
    import anyio

    # 0. Handle OAuth routes (unauthenticated — they ARE the auth endpoints)
    oauth_response = _handle_oauth_route(event)
    if oauth_response is not None:
        return oauth_response

    # 1. Bearer auth check
    base = _get_server_base_url(event)
    auth_header = (event.get("headers") or {}).get("authorization", "")

    if _cognito_mode_active():
        # Cognito JWT validation (ENC-FTR-045)
        token = ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
        if not token:
            return {
                "statusCode": 401,
                "headers": {
                    "content-type": "application/json",
                    "www-authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"',
                },
                "body": json.dumps({"error": "Unauthorized", "error_description": "Bearer token required"}),
                "isBase64Encoded": False,
            }
        try:
            _verify_cognito_jwt(token)
        except ValueError as exc:
            _log_auth_failure("/mcp", "jwt_validation_failed", event,
                              error_detail=str(exc))
            return {
                "statusCode": 401,
                "headers": {
                    "content-type": "application/json",
                    "www-authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"',
                },
                "body": json.dumps({"error": "invalid_token", "error_description": str(exc)}),
                "isBase64Encoded": False,
            }
    elif MCP_API_KEY:
        # Self-contained static key validation (original flow)
        if auth_header != f"Bearer {MCP_API_KEY}":
            return {
                "statusCode": 401,
                "headers": {
                    "content-type": "application/json",
                    "www-authenticate": f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"',
                },
                "body": json.dumps({"error": "Unauthorized"}),
                "isBase64Encoded": False,
            }

    # 2. Decode body
    body_raw = event.get("body") or ""
    body_bytes = (
        base64.b64decode(body_raw) if event.get("isBase64Encoded") else body_raw.encode()
    )

    # 3. Build ASGI scope from Lambda Function URL event
    headers_raw = event.get("headers", {}) or {}
    asgi_headers = [(k.encode(), v.encode()) for k, v in headers_raw.items()]
    req_ctx = (event.get("requestContext") or {}).get("http", {})
    path = req_ctx.get("path", "/mcp")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": req_ctx.get("method", "POST").upper(),
        "path": path,
        "raw_path": event.get("rawPath", path).encode(),
        "query_string": event.get("rawQueryString", "").encode(),
        "root_path": "",
        "scheme": "https",
        "server": ("lambda", 443),
        "headers": asgi_headers,
    }

    # 4. ASGI receive/send callables
    body_consumed = False

    async def receive():
        nonlocal body_consumed
        if not body_consumed:
            body_consumed = True
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        await anyio.sleep_forever()

    resp_status = 200
    resp_headers: Dict[str, str] = {}
    resp_body = b""

    async def send(message):
        nonlocal resp_status, resp_headers, resp_body
        if message["type"] == "http.response.start":
            resp_status = int(message["status"])  # coerce HTTPStatus enum → int
            for k, v in message.get("headers", []):
                resp_headers[k.decode()] = v.decode()
        elif message["type"] == "http.response.body":
            resp_body += message.get("body", b"")

    # 5. Run per-invocation task group (stateless)
    manager = _get_http_session_manager()
    async with anyio.create_task_group() as tg:
        manager._task_group = tg
        manager._has_started = True
        await manager.handle_request(scope, receive, send)
        tg.cancel_scope.cancel()

    return {
        "statusCode": resp_status,
        "headers": resp_headers,
        "body": resp_body.decode("utf-8", errors="replace"),
        "isBase64Encoded": False,
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    if MCP_TRANSPORT != "streamable_http":
        return {
            "statusCode": 400,
            "headers": {"content-type": "application/json"},
            "body": json.dumps(
                {"error": "lambda_handler requires ENCELADUS_MCP_TRANSPORT=streamable_http"}
            ),
            "isBase64Encoded": False,
        }
    return asyncio.run(_handle_lambda_event(event))
