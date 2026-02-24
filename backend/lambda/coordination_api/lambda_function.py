"""coordination_api/lambda_function.py

Coordination-mode API for DVP-FTR-023.

Routes (API Gateway HTTP API):
    POST    /api/v1/coordination/requests
    GET     /api/v1/coordination/requests/{requestId}
    POST    /api/v1/coordination/requests/{requestId}/dispatch
    POST    /api/v1/coordination/requests/{requestId}/callback
    GET     /api/v1/coordination/capabilities
    OPTIONS /api/v1/coordination/*

Primary responsibilities:
- Persist request state machine with deterministic transitions.
- Decompose outcomes into tracker artifacts before dispatch.
- Dispatch execution (host-v2 via SSM for host-backed modes, direct API for managed-session modes).
- Provide deterministic completion read path (poll request status).
- Support optional callback updates with per-request callback token.
"""

from __future__ import annotations

import datetime as dt
import asyncio
import dataclasses
import hashlib
import importlib.util
import json
import logging
import os
import pathlib
import re
import shlex
import ssl
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

try:
    from mcp_client import CoordinationMcpClient
except ModuleNotFoundError:
    _MCP_MODULE_PATH = pathlib.Path(__file__).with_name("mcp_client.py")
    _MCP_SPEC = importlib.util.spec_from_file_location("coordination_mcp_client", _MCP_MODULE_PATH)
    if _MCP_SPEC is None or _MCP_SPEC.loader is None:
        raise
    _MCP_MODULE = importlib.util.module_from_spec(_MCP_SPEC)
    _MCP_SPEC.loader.exec_module(_MCP_MODULE)
    CoordinationMcpClient = _MCP_MODULE.CoordinationMcpClient

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:
    _JWT_AVAILABLE = False

try:
    import certifi

    _CERT_BUNDLE = certifi.where()
except Exception:
    _CERT_BUNDLE = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")
TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
SSM_REGION = os.environ.get("SSM_REGION", "us-west-2")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
GOVERNANCE_PROJECT_ID = os.environ.get("GOVERNANCE_PROJECT_ID", "devops")
GOVERNANCE_KEYWORD = os.environ.get("GOVERNANCE_KEYWORD", "governance-file")

COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")

HOST_V2_INSTANCE_ID = os.environ.get("HOST_V2_INSTANCE_ID", "i-0523f94e99ec15a1e")
HOST_V2_WORK_ROOT = os.environ.get("HOST_V2_WORK_ROOT", "/home/ec2-user/claude-code-dev")
HOST_V2_PROJECT = os.environ.get("HOST_V2_PROJECT", "devops")
HOST_V2_AWS_PROFILE = os.environ.get("HOST_V2_AWS_PROFILE", "ec2-role")
HOST_V2_TIMEOUT_SECONDS = int(
    os.environ.get("HOST_V2_TIMEOUT_SECONDS", os.environ.get("DISPATCH_TIMEOUT_SECONDS", "1800"))
)
DISPATCH_TIMEOUT_CEILING_SECONDS = int(os.environ.get("DISPATCH_TIMEOUT_CEILING_SECONDS", "1800"))
SSM_DOCUMENT_NAME = os.environ.get("SSM_DOCUMENT_NAME", "AWS-RunShellScript")
HOST_V2_ENCELADUS_MCP_INSTALLER = os.environ.get(
    "HOST_V2_ENCELADUS_MCP_INSTALLER",
    "tools/enceladus-mcp-server/install_profile.sh",
)
HOST_V2_PROVIDER_CHECK_SCRIPT = os.environ.get(
    "HOST_V2_PROVIDER_CHECK_SCRIPT",
    "projects/devops/tools/agentcli-host-v2/provider_rotation_check.py",
)
HOST_V2_MCP_PROFILE_PATH = os.environ.get("HOST_V2_MCP_PROFILE_PATH", ".claude/mcp.json")
HOST_V2_MCP_MARKER_PATH = os.environ.get(
    "HOST_V2_MCP_MARKER_PATH",
    ".cache/enceladus/mcp-profile-installed-v1.json",
)
HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS = tuple(
    int(part.strip())
    for part in os.environ.get("HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS", "2,5,10").split(",")
    if part.strip()
)
if not HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS:
    HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS = (2, 5, 10)
HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS = int(
    os.environ.get(
        "HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS",
        str(len(HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS) + 1),
    )
)
HOST_V2_MCP_BOOTSTRAP_SCRIPT = os.environ.get(
    "HOST_V2_MCP_BOOTSTRAP_SCRIPT",
    "tools/enceladus-mcp-server/host_v2_first_bootstrap.sh",
)
HOST_V2_FLEET_LAUNCH_TEMPLATE_ID = os.environ.get("HOST_V2_FLEET_LAUNCH_TEMPLATE_ID", "")
HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION = os.environ.get("HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION", "$Default")
HOST_V2_FLEET_USER_DATA_TEMPLATE = os.environ.get(
    "HOST_V2_FLEET_USER_DATA_TEMPLATE",
    "tools/enceladus-mcp-server/host_v2_user_data_template.sh",
)
HOST_V2_FLEET_ENABLED = os.environ.get("HOST_V2_FLEET_ENABLED", "true").lower() == "true"
HOST_V2_FLEET_FALLBACK_TO_STATIC = os.environ.get("HOST_V2_FLEET_FALLBACK_TO_STATIC", "true").lower() == "true"
HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES = int(os.environ.get("HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES", "3"))
HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS = int(os.environ.get("HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS", "420"))
HOST_V2_FLEET_READINESS_POLL_SECONDS = int(os.environ.get("HOST_V2_FLEET_READINESS_POLL_SECONDS", "15"))
HOST_V2_FLEET_INSTANCE_TTL_SECONDS = int(os.environ.get("HOST_V2_FLEET_INSTANCE_TTL_SECONDS", "3600"))
HOST_V2_FLEET_SWEEP_ON_DISPATCH = os.environ.get("HOST_V2_FLEET_SWEEP_ON_DISPATCH", "true").lower() == "true"
HOST_V2_FLEET_SWEEP_GRACE_SECONDS = int(os.environ.get("HOST_V2_FLEET_SWEEP_GRACE_SECONDS", "300"))
HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL = (
    os.environ.get("HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL", "true").lower() == "true"
)
HOST_V2_FLEET_TAG_MANAGED_BY_VALUE = os.environ.get(
    "HOST_V2_FLEET_TAG_MANAGED_BY_VALUE",
    "enceladus-coordination",
)
HOST_V2_FLEET_NAME_PREFIX = os.environ.get("HOST_V2_FLEET_NAME_PREFIX", "enceladus-host-v2-fleet")
DEFAULT_OPENAI_CODEX_MODEL = os.environ.get("DEFAULT_OPENAI_CODEX_MODEL", "gpt-5.1-codex-max")
OPENAI_API_BASE_URL = os.environ.get("OPENAI_API_BASE_URL", "https://api.openai.com")
OPENAI_API_TIMEOUT_SECONDS = float(os.environ.get("OPENAI_API_TIMEOUT_SECONDS", "45"))
OPENAI_API_ORGANIZATION = os.environ.get("OPENAI_API_ORGANIZATION", "")
OPENAI_API_PROJECT = os.environ.get("OPENAI_API_PROJECT", "")
OPENAI_MAX_OUTPUT_TOKENS_MIN = int(os.environ.get("OPENAI_MAX_OUTPUT_TOKENS_MIN", "64"))
OPENAI_MAX_OUTPUT_TOKENS_MAX = int(os.environ.get("OPENAI_MAX_OUTPUT_TOKENS_MAX", "16384"))
DEFAULT_CLAUDE_AGENT_MODEL = os.environ.get("DEFAULT_CLAUDE_AGENT_MODEL", "claude-sonnet-4-6")
ANTHROPIC_API_BASE_URL = os.environ.get("ANTHROPIC_API_BASE_URL", "https://api.anthropic.com")
ANTHROPIC_API_VERSION = os.environ.get("ANTHROPIC_API_VERSION", "2023-06-01")
ANTHROPIC_API_TIMEOUT_SECONDS = float(os.environ.get("ANTHROPIC_API_TIMEOUT_SECONDS", "120"))
ANTHROPIC_API_STREAM_TIMEOUT_SECONDS = float(os.environ.get("ANTHROPIC_API_STREAM_TIMEOUT_SECONDS", "300"))
CLAUDE_API_MAX_TOKENS_DEFAULT = int(os.environ.get("CLAUDE_API_MAX_TOKENS_DEFAULT", "4096"))
CLAUDE_API_MAX_TOKENS_MIN = int(os.environ.get("CLAUDE_API_MAX_TOKENS_MIN", "64"))
CLAUDE_API_MAX_TOKENS_MAX = int(os.environ.get("CLAUDE_API_MAX_TOKENS_MAX", "128000"))
CLAUDE_THINKING_BUDGET_DEFAULT = int(os.environ.get("CLAUDE_THINKING_BUDGET_DEFAULT", "8192"))
CLAUDE_THINKING_BUDGET_MIN = int(os.environ.get("CLAUDE_THINKING_BUDGET_MIN", "1024"))
CLAUDE_THINKING_BUDGET_MAX = int(os.environ.get("CLAUDE_THINKING_BUDGET_MAX", "65536"))
CLAUDE_PROMPT_CACHE_TTL = os.environ.get("CLAUDE_PROMPT_CACHE_TTL", "1h")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
OPENAI_API_KEY_SECRET_ID = os.environ.get(
    "OPENAI_API_KEY_SECRET_ID",
    "devops/coordination/openai/api-key",
)
ANTHROPIC_API_KEY_SECRET_ID = os.environ.get(
    "ANTHROPIC_API_KEY_SECRET_ID",
    "devops/coordination/anthropic/api-key",
)
ROTATION_WARNING_DAYS = int(os.environ.get("ROTATION_WARNING_DAYS", "14"))

MAX_OUTCOMES = int(os.environ.get("MAX_OUTCOMES", "25"))
MAX_OUTCOME_LENGTH = int(os.environ.get("MAX_OUTCOME_LENGTH", "500"))
MAX_TITLE_LENGTH = int(os.environ.get("MAX_TITLE_LENGTH", "240"))
MAX_CONSTRAINT_SIZE = int(os.environ.get("MAX_CONSTRAINT_SIZE", "5000"))
IDEMPOTENCY_WINDOW_SECONDS = int(os.environ.get("IDEMPOTENCY_WINDOW_SECONDS", "86400"))
CALLBACK_TOKEN_TTL_SECONDS = int(os.environ.get("CALLBACK_TOKEN_TTL_SECONDS", "7200"))
MAX_DISPATCH_ATTEMPTS = int(os.environ.get("MAX_DISPATCH_ATTEMPTS", "3"))
DEBOUNCE_WINDOW_SECONDS = int(os.environ.get("DEBOUNCE_WINDOW_SECONDS", "180"))  # 3 min per v0.3 contract §6.1.1
DISPATCH_LOCK_BUFFER_SECONDS = int(os.environ.get("DISPATCH_LOCK_BUFFER_SECONDS", "60"))
DEAD_LETTER_TIMEOUT_MULTIPLIER = int(os.environ.get("DEAD_LETTER_TIMEOUT_MULTIPLIER", "2"))
DEAD_LETTER_SNS_TOPIC_ARN = os.environ.get("DEAD_LETTER_SNS_TOPIC_ARN", "")

COORDINATION_GSI_PROJECT = os.environ.get("COORDINATION_GSI_PROJECT", "project-updated-index")
COORDINATION_GSI_IDEMPOTENCY = os.environ.get("COORDINATION_GSI_IDEMPOTENCY", "idempotency-key-index")
TRACKER_GSI_PROJECT_TYPE = os.environ.get("TRACKER_GSI_PROJECT_TYPE", "project-type-index")
ENCELADUS_MCP_SERVER_PATH = os.environ.get(
    "ENCELADUS_MCP_SERVER_PATH",
    "tools/enceladus-mcp-server/server.py",
)

ENABLE_CLAUDE_HEADLESS = os.environ.get("ENABLE_CLAUDE_HEADLESS", "false").lower() == "true"

# v0.3 callback infrastructure
CALLBACK_EVENTBRIDGE_BUS = os.environ.get("CALLBACK_EVENTBRIDGE_BUS", "default")
CALLBACK_SQS_QUEUE_URL = os.environ.get("CALLBACK_SQS_QUEUE_URL", "")
CALLBACK_EVENT_SOURCE = os.environ.get("CALLBACK_EVENT_SOURCE", "enceladus.coordination")
CALLBACK_EVENT_DETAIL_TYPE = os.environ.get("CALLBACK_EVENT_DETAIL_TYPE", "coordination.callback")
FEED_SUBSCRIPTIONS_TABLE = os.environ.get("FEED_SUBSCRIPTIONS_TABLE", "feed-subscriptions")
FEED_PUSH_DEFAULT_EVENT_BUS = os.environ.get("FEED_PUSH_DEFAULT_EVENT_BUS", "default")
FEED_PUSH_HTTP_TIMEOUT_SECONDS = float(os.environ.get("FEED_PUSH_HTTP_TIMEOUT_SECONDS", "5"))
MCP_CONNECTIVITY_BACKOFF_SECONDS = (10, 30, 60)
DISPATCH_WORKLOG_MAX_ENTRIES = int(os.environ.get("DISPATCH_WORKLOG_MAX_ENTRIES", "100"))
WORKER_RUNTIME_LOG_GROUP = os.environ.get("WORKER_RUNTIME_LOG_GROUP", "/enceladus/coordination/worker-runtime")
MCP_SERVER_LOG_GROUP = os.environ.get("MCP_SERVER_LOG_GROUP", "/enceladus/mcp/server")
MCP_AUDIT_CALLER_IDENTITY = os.environ.get("MCP_AUDIT_CALLER_IDENTITY", "devops-coordination-api")
COORDINATION_PUBLIC_BASE_URL = os.environ.get("COORDINATION_PUBLIC_BASE_URL", "https://jreese.net")
COORDINATION_MCP_HTTP_PATH = os.environ.get("COORDINATION_MCP_HTTP_PATH", "/api/v1/coordination/mcp")
ENABLE_MCP_GOVERNANCE_PROMPT = os.environ.get("ENABLE_MCP_GOVERNANCE_PROMPT", "true").lower() == "true"
GOVERNANCE_PROMPT_MAX_CHARS = int(os.environ.get("GOVERNANCE_PROMPT_MAX_CHARS", "120000"))
GOVERNANCE_PROMPT_RESOURCE_URIS_FALLBACK = (
    "governance://agents.md",
    "governance://agents/agents-reference-project-tracking.md",
    "governance://agents/agents-reference-guide-numbering.md",
    "governance://agents/agents-reference-markdown.md",
    "governance://agents/agent-manifest.json",
    "governance://agents/agent-schema.json",
)

_VALID_EXECUTION_MODES = {
    "preflight",
    "codex_full_auto",
    "codex_app_server",
    "claude_headless",
    "claude_agent_sdk",
    "aws_step_function",
    "bedrock_agent",
}

# ---------------------------------------------------------------------------
# Anthropic model routing — maps task_complexity to optimal model
# ---------------------------------------------------------------------------
_CLAUDE_MODEL_ROUTING = {
    "simple": "claude-haiku-4-5-20251001",
    "standard": "claude-sonnet-4-6",
    "complex": "claude-opus-4-6",
    "critical": "claude-opus-4-6",
}
_CLAUDE_VALID_TASK_COMPLEXITIES = {"simple", "standard", "complex", "critical"}

# Pricing per million tokens (USD) for cost attribution
_CLAUDE_PRICING = {
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00, "cache_write_5m": 1.25, "cache_write_1h": 2.00, "cache_read": 0.10},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30},
    "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30},
    "claude-opus-4-6": {"input": 5.00, "output": 25.00, "cache_write_5m": 6.25, "cache_write_1h": 10.00, "cache_read": 0.50},
}
_CLAUDE_DEFAULT_PRICING = {"input": 3.00, "output": 15.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30}

# Models that support adaptive thinking (no manual budget_tokens)
_CLAUDE_ADAPTIVE_THINKING_MODELS = {"claude-opus-4-6"}

# Context window limits per model
_CLAUDE_CONTEXT_LIMITS = {
    "claude-haiku-4-5-20251001": 200_000,
    "claude-sonnet-4-6": 200_000,
    "claude-sonnet-4-5-20250929": 200_000,
    "claude-opus-4-6": 200_000,
}
_CLAUDE_DEFAULT_CONTEXT_LIMIT = 200_000
_VALID_TERMINAL_STATES = {"succeeded", "failed", "cancelled", "dead_letter"}
_VALID_PROVIDERS = {"claude_agent_sdk", "openai_codex", "aws_native", "aws_bedrock_agent"}
_CLAUDE_PERMISSION_MODES = {"plan", "acceptEdits", "default"}
_ENCELADUS_ALLOWED_TOOLS = {
    "projects_list",
    "projects_get",
    "tracker_get",
    "tracker_list",
    "tracker_set",
    "tracker_log",
    "tracker_create",
    "documents_search",
    "documents_get",
    "documents_list",
    "check_document_policy",
    "documents_put",
    "documents_patch",
    "deploy_state_get",
    "deploy_history",
    "deploy_submit",
    "deploy_state_set",
    "deploy_status",
    "deploy_trigger",
    "deploy_pending_requests",
    "coordination_capabilities",
    "coordination_request_get",
    "governance_hash",
    "connection_health",
    "dispatch_plan_generate",
    "dispatch_plan_dry_run",
}
_RETRY_BACKOFF_SECONDS = (10, 60, 300)
_RETRIABLE_FAILURE_CLASSES = {"network_timeout", "provider_transient", "host_unavailable"}
_NON_RETRIABLE_FAILURE_CLASSES = {"auth_invalid", "governance_stale", "input_validation"}

_STATE_INTAKE_RECEIVED = "intake_received"
_STATE_QUEUED = "queued"
_STATE_DISPATCHING = "dispatching"
_STATE_RUNNING = "running"
_STATE_DEAD_LETTER = "dead_letter"

_TRANSITIONS = {
    "intake_received": {"queued", "cancelled"},
    "queued": {"dispatching", "failed", "cancelled"},
    "dispatching": {"running", "queued", "failed", "cancelled", "dead_letter"},
    "running": {"succeeded", "failed", "cancelled", "dead_letter"},
    "succeeded": set(),
    "failed": {"dispatching", "cancelled", "dead_letter"},
    "cancelled": set(),
    "dead_letter": set(),
}

_TYPE_TO_SEGMENT = {
    "task": "TSK",
    "issue": "ISS",
    "feature": "FTR",
}

_SEGMENT_TO_TYPE = {v: k for k, v in _TYPE_TO_SEGMENT.items()}

_DEFAULT_STATUS = {
    "task": "open",
    "issue": "open",
    "feature": "planned",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

_deserializer = TypeDeserializer()
_serializer = TypeSerializer()


def _serialize(value: Any) -> Dict[str, Any]:
    return _serializer.serialize(value)


def _deserialize(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _deserializer.deserialize(v) for k, v in raw.items()}


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_now() -> int:
    return int(time.time())


def _fetch_log_stream_token(log_group: str, stream_name: str) -> Optional[str]:
    try:
        resp = _get_logs().describe_log_streams(
            logGroupName=log_group,
            logStreamNamePrefix=stream_name,
            limit=1,
        )
    except Exception:
        return None
    streams = resp.get("logStreams") or []
    if not streams:
        return None
    return streams[0].get("uploadSequenceToken")


def _emit_cloudwatch_json(log_group: str, payload: Dict[str, Any], stream_name: str = "coordination-audit") -> None:
    if not log_group:
        return
    logs = _get_logs()
    key = (log_group, stream_name)

    try:
        logs.create_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            return
    except Exception:
        return

    try:
        logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            return
    except Exception:
        return

    event = {
        "timestamp": int(time.time() * 1000),
        "message": json.dumps(payload, sort_keys=True, default=str),
    }
    kwargs: Dict[str, Any] = {
        "logGroupName": log_group,
        "logStreamName": stream_name,
        "logEvents": [event],
    }
    token = _cloudwatch_sequence_tokens.get(key)
    if token:
        kwargs["sequenceToken"] = token

    try:
        resp = logs.put_log_events(**kwargs)
        _cloudwatch_sequence_tokens[key] = resp.get("nextSequenceToken", "")
        return
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"InvalidSequenceTokenException", "DataAlreadyAcceptedException"}:
            return
    except Exception:
        return

    retry_token = _fetch_log_stream_token(log_group, stream_name)
    retry_kwargs: Dict[str, Any] = {
        "logGroupName": log_group,
        "logStreamName": stream_name,
        "logEvents": [event],
    }
    if retry_token:
        retry_kwargs["sequenceToken"] = retry_token
    try:
        resp = logs.put_log_events(**retry_kwargs)
        _cloudwatch_sequence_tokens[key] = resp.get("nextSequenceToken", "")
    except Exception:
        return


def _emit_structured_observability(
    *,
    component: str,
    event: str,
    request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    latency_ms: Optional[int] = None,
    error_code: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    mirror_log_group: Optional[str] = None,
) -> None:
    payload: Dict[str, Any] = {
        "timestamp": _now_z(),
        "component": component,
        "event": event,
        "request_id": str(request_id or ""),
        "dispatch_id": str(dispatch_id or ""),
        "tool_name": str(tool_name or ""),
        "latency_ms": int(max(0, latency_ms or 0)),
        "error_code": str(error_code or ""),
    }
    if extra:
        payload.update(extra)
    logger.info("[OBSERVABILITY] %s", json.dumps(payload, sort_keys=True, default=str))
    if mirror_log_group:
        _emit_cloudwatch_json(mirror_log_group, payload, stream_name="structured-observability")


def _classify_mcp_error(exc: Exception) -> str:
    msg = str(exc).lower()
    if "governance_stale" in msg or "stale" in msg:
        return "governance_stale"
    if "missing governance_hash" in msg:
        return "governance_hash_missing"
    if "not found" in msg:
        return "record_not_found"
    if "timeout" in msg:
        return "mcp_timeout"
    return "mcp_tool_error"


# ---------------------------------------------------------------------------
# AWS client singletons
# ---------------------------------------------------------------------------

_ddb = None
_ssm = None
_ec2 = None
_eb = None
_sqs = None
_sns = None
_logs = None
_mcp = CoordinationMcpClient()
_secretsmanager = None
_cloudwatch_sequence_tokens: Dict[Tuple[str, str], str] = {}
_feed_subscriptions_table_available: Optional[bool] = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ddb


def _get_ssm():
    global _ssm
    if _ssm is None:
        _ssm = boto3.client(
            "ssm",
            region_name=SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ssm


def _get_ec2():
    global _ec2
    if _ec2 is None:
        _ec2 = boto3.client(
            "ec2",
            region_name=SSM_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ec2


def _get_eb():
    global _eb
    if _eb is None:
        _eb = boto3.client(
            "events",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _eb


def _get_sqs():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client(
            "sqs",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sqs


def _get_sns():
    global _sns
    if _sns is None:
        _sns = boto3.client(
            "sns",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _sns


def _get_logs():
    global _logs
    if _logs is None:
        _logs = boto3.client(
            "logs",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _logs


def _feed_subscriptions_enabled() -> bool:
    global _feed_subscriptions_table_available
    if _feed_subscriptions_table_available is not None:
        return _feed_subscriptions_table_available

    if not FEED_SUBSCRIPTIONS_TABLE:
        _feed_subscriptions_table_available = False
        logger.info("[INFO] Feed subscription operations disabled: FEED_SUBSCRIPTIONS_TABLE unset.")
        return False

    try:
        _get_ddb().describe_table(TableName=FEED_SUBSCRIPTIONS_TABLE)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code == "ResourceNotFoundException":
            _feed_subscriptions_table_available = False
            logger.info(
                "[INFO] Feed subscription operations disabled: table '%s' not found.",
                FEED_SUBSCRIPTIONS_TABLE,
            )
            return False
        if code in {"AccessDeniedException", "UnauthorizedOperation"}:
            _feed_subscriptions_table_available = False
            logger.warning(
                "Feed subscription operations disabled: missing DescribeTable access for '%s'.",
                FEED_SUBSCRIPTIONS_TABLE,
            )
            return False
        raise

    _feed_subscriptions_table_available = True
    return True


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


# ---------------------------------------------------------------------------
# Auth (same Cognito cookie validation pattern as existing Enceladus Lambdas)
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0


def _extract_token(event: Dict[str, Any]) -> Optional[str]:
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    cookie_parts: List[str] = []
    if cookie_header:
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())

    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if isinstance(part, str) and part.strip())
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())

    for part in cookie_parts:
        if part.startswith("enceladus_id_token="):
            return part[len("enceladus_id_token=") :]
    return None


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

    key = _get_jwks().get(kid)
    if key is None:
        raise ValueError("Token key ID not found in JWKS")

    try:
        return jwt.decode(
            token,
            key,
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


def _authenticate(event: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    # Optional internal auth path for trusted orchestrators / smoke tests.
    if COORDINATION_INTERNAL_API_KEY:
        headers = event.get("headers") or {}
        internal_key = (
            headers.get("x-coordination-internal-key")
            or headers.get("X-Coordination-Internal-Key")
            or ""
        )
        if internal_key and internal_key == COORDINATION_INTERNAL_API_KEY:
            return {"auth_mode": "internal-key"}, None

    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in.")

    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": (
            "Accept, Authorization, Content-Type, Cookie, X-Coordination-Callback-Token, "
            "X-Coordination-Internal-Key"
        ),
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, payload: Any) -> Dict[str, Any]:
    def _json_default(obj: Any) -> Any:
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(payload, default=_json_default),
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
    retryable = bool(extra.pop("retryable", status_code >= 500 or code in {"TIMEOUT", "UPSTREAM_ERROR", "DEBOUNCE_ACTIVE"}))
    details = dict(extra)
    body: Dict[str, Any] = {
        "success": False,
        # legacy field retained for backwards compatibility
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    body.update(details)
    return _response(status_code, body)


def _json_body(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("body")
    if raw in (None, ""):
        return {}

    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode("utf-8")

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON body: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValueError("JSON body must be an object")
    return parsed


def _path_method(event: Dict[str, Any]) -> Tuple[str, str]:
    method = (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod") or "").upper()
    path = event.get("rawPath") or event.get("path") or "/"
    return method, path


# ---------------------------------------------------------------------------
# Project metadata cache / ID helpers
# ---------------------------------------------------------------------------

_project_cache: Dict[str, Dict[str, Any]] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0
_ENCELADUS_MCP_SERVER_MODULE = None
_DISPATCH_PLAN_GENERATOR_MODULE = None
_MCP_RESOURCE_CACHE: Dict[str, str] = {}


@dataclass
class ProjectMeta:
    project_id: str
    prefix: str


def _load_project_meta(project_id: str) -> ProjectMeta:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now

    if project_id in _project_cache:
        cached = _project_cache[project_id]
        return ProjectMeta(project_id=project_id, prefix=cached["prefix"])

    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": _serialize(project_id)},
            ConsistentRead=True,
            ProjectionExpression="project_id, #pfx",
            ExpressionAttributeNames={"#pfx": "prefix"},
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed reading projects table: {exc}") from exc

    item = resp.get("Item")
    if not item:
        raise ValueError(f"Project '{project_id}' is not registered")

    plain = _deserialize(item)
    prefix = str(plain.get("prefix") or "").upper()
    if not re.fullmatch(r"[A-Z]{3}", prefix):
        raise ValueError(f"Project '{project_id}' has invalid prefix '{prefix}'")

    _project_cache[project_id] = {"prefix": prefix}
    return ProjectMeta(project_id=project_id, prefix=prefix)


def _next_tracker_sequence(project_id: str, record_type: str) -> int:
    ddb = _get_ddb()
    max_num = 0

    paginator = ddb.get_paginator("query")
    try:
        pages = paginator.paginate(
            TableName=TRACKER_TABLE,
            IndexName=TRACKER_GSI_PROJECT_TYPE,
            KeyConditionExpression="project_id = :pid AND record_type = :rt",
            ExpressionAttributeValues={
                ":pid": _serialize(project_id),
                ":rt": _serialize(record_type),
            },
            ProjectionExpression="item_id",
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Failed querying tracker for next ID: {exc}") from exc

    for page in pages:
        for raw in page.get("Items", []):
            iid = _deserialize(raw).get("item_id", "")
            parts = iid.split("-")
            if len(parts) < 3:
                continue
            try:
                n = int(parts[-1])
            except ValueError:
                continue
            if n > max_num:
                max_num = n

    return max_num + 1


def _build_record_id(prefix: str, record_type: str, seq: int) -> str:
    return f"{prefix}-{_TYPE_TO_SEGMENT[record_type]}-{seq:03d}"


def _key_for_record_id(record_id: str) -> Tuple[str, str, str]:
    parts = record_id.upper().split("-")
    if len(parts) != 3:
        raise ValueError(f"Invalid record ID: {record_id}")

    prefix, segment, _ = parts
    record_type = _SEGMENT_TO_TYPE.get(segment)
    if not record_type:
        raise ValueError(f"Unsupported record ID segment '{segment}'")

    # Resolve project by prefix from cache (or table scan fallback).
    for project_id, data in _project_cache.items():
        if data.get("prefix") == prefix:
            return project_id, record_type, f"{record_type}#{record_id.upper()}"

    # Slow fallback if prefix cache does not include this project yet.
    ddb = _get_ddb()
    scan = ddb.scan(TableName=PROJECTS_TABLE, ProjectionExpression="project_id, #pfx", ExpressionAttributeNames={"#pfx": "prefix"})
    items = scan.get("Items", [])
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, #pfx",
            ExpressionAttributeNames={"#pfx": "prefix"},
            ExclusiveStartKey=scan["LastEvaluatedKey"],
        )
        items.extend(scan.get("Items", []))

    for raw in items:
        row = _deserialize(raw)
        pid = row.get("project_id")
        pfx = str(row.get("prefix") or "").upper()
        if pid and pfx:
            _project_cache[pid] = {"prefix": pfx}
        if pfx == prefix:
            return pid, record_type, f"{record_type}#{record_id.upper()}"

    raise ValueError(f"Unknown project prefix in record ID '{record_id}'")


# ---------------------------------------------------------------------------
# Tracker record helpers
# ---------------------------------------------------------------------------


def _resolve_mcp_server_path() -> str:
    candidates = [ENCELADUS_MCP_SERVER_PATH]
    cwd = pathlib.Path.cwd()
    candidates.extend(
        [
            str(cwd / "tools/enceladus-mcp-server/server.py"),
            str(cwd / "projects/enceladus/tools/enceladus-mcp-server/server.py"),
            str(cwd / "projects/devops/tools/enceladus-mcp-server/server.py"),
            str(pathlib.Path(__file__).resolve().parents[3] / "enceladus-mcp-server/server.py"),
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError(
        "Enceladus MCP server module not found; set ENCELADUS_MCP_SERVER_PATH to server.py"
    )


def _load_mcp_server_module():
    global _ENCELADUS_MCP_SERVER_MODULE
    if _ENCELADUS_MCP_SERVER_MODULE is not None:
        return _ENCELADUS_MCP_SERVER_MODULE

    module_path = _resolve_mcp_server_path()
    spec = importlib.util.spec_from_file_location("enceladus_mcp_server_runtime", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load MCP server module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _ENCELADUS_MCP_SERVER_MODULE = module
    return _ENCELADUS_MCP_SERVER_MODULE


def _resolve_dispatch_plan_generator_path() -> str:
    candidates = [
        "dispatch_plan_generator.py",
        str(pathlib.Path(__file__).with_name("dispatch_plan_generator.py")),
        str(pathlib.Path(__file__).resolve().parents[3] / "tools/enceladus-mcp-server/dispatch_plan_generator.py"),
        str(pathlib.Path.cwd() / "tools/enceladus-mcp-server/dispatch_plan_generator.py"),
        str(pathlib.Path.cwd() / "projects/enceladus/repo/tools/enceladus-mcp-server/dispatch_plan_generator.py"),
        str(pathlib.Path.cwd() / "projects/enceladus/tools/enceladus-mcp-server/dispatch_plan_generator.py"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError(
        "Dispatch plan generator module not found; ensure dispatch_plan_generator.py is packaged with coordination_api"
    )


def _load_dispatch_plan_generator_module():
    global _DISPATCH_PLAN_GENERATOR_MODULE
    if _DISPATCH_PLAN_GENERATOR_MODULE is not None:
        return _DISPATCH_PLAN_GENERATOR_MODULE

    try:
        import dispatch_plan_generator as dispatch_plan_module  # type: ignore

        _DISPATCH_PLAN_GENERATOR_MODULE = dispatch_plan_module
        return _DISPATCH_PLAN_GENERATOR_MODULE
    except ModuleNotFoundError:
        pass

    module_path = _resolve_dispatch_plan_generator_path()
    spec = importlib.util.spec_from_file_location(
        "coordination_dispatch_plan_generator_runtime",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load dispatch plan generator module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _DISPATCH_PLAN_GENERATOR_MODULE = module
    return _DISPATCH_PLAN_GENERATOR_MODULE


def _generate_dispatch_plan_for_request(request_id: str) -> Dict[str, Any]:
    module = _load_dispatch_plan_generator_module()
    generate_fn = getattr(module, "generate_dispatch_plan", None)
    if not callable(generate_fn):
        raise RuntimeError("dispatch_plan_generator module missing generate_dispatch_plan")
    plan = generate_fn(request_id)
    if not isinstance(plan, dict):
        raise RuntimeError("dispatch_plan_generator returned non-object plan")
    return plan


def _ensure_request_dispatch_plan(request: Dict[str, Any], *, persist: bool = False) -> Dict[str, Any]:
    dispatch_plan = request.get("dispatch_plan") or {}
    dispatches = dispatch_plan.get("dispatches") if isinstance(dispatch_plan, dict) else None
    if isinstance(dispatches, list) and dispatches:
        return request

    request_id = str(request.get("request_id") or "").strip()
    if not request_id:
        raise RuntimeError("Cannot generate dispatch_plan without request_id")

    request["dispatch_plan"] = _generate_dispatch_plan_for_request(request_id)
    request.setdefault("dispatch_outcomes", {})
    request["updated_at"] = _now_z()
    request["updated_epoch"] = _unix_now()
    if persist:
        _update_request(request)
    return request


def _resolve_dispatch_entry_from_plan(request: Dict[str, Any], requested_dispatch_id: str) -> Optional[Dict[str, Any]]:
    dispatch_plan = request.get("dispatch_plan") or {}
    dispatches = dispatch_plan.get("dispatches") if isinstance(dispatch_plan, dict) else None
    if not isinstance(dispatches, list) or not dispatches:
        return None

    dispatch_outcomes = request.get("dispatch_outcomes") or {}

    def _outcome_state(dispatch_id: str) -> str:
        outcome = dispatch_outcomes.get(dispatch_id) or {}
        return str(outcome.get("state") or "").strip().lower()

    requested = str(requested_dispatch_id or "").strip()
    if requested:
        for dispatch in dispatches:
            dispatch_id = str(dispatch.get("dispatch_id") or "").strip()
            if dispatch_id != requested:
                continue
            state = _outcome_state(dispatch_id)
            if state in _VALID_TERMINAL_STATES:
                raise ValueError(f"Dispatch '{dispatch_id}' already completed with state '{state}'")
            return dispatch
        raise ValueError(f"Dispatch '{requested}' is not present in request dispatch_plan")

    def _sort_key(entry: Dict[str, Any]) -> Tuple[int, str]:
        try:
            sequence_order = int(entry.get("sequence_order") or 0)
        except (TypeError, ValueError):
            sequence_order = 0
        return sequence_order, str(entry.get("dispatch_id") or "")

    for dispatch in sorted(dispatches, key=_sort_key):
        dispatch_id = str(dispatch.get("dispatch_id") or "").strip()
        if not dispatch_id:
            continue
        if _outcome_state(dispatch_id) in _VALID_TERMINAL_STATES:
            continue
        return dispatch

    raise RuntimeError("All dispatches in dispatch_plan already reached terminal states")


def _parse_mcp_result(result: Any) -> Dict[str, Any]:
    if not isinstance(result, list) or not result:
        raise RuntimeError("MCP tool returned no content")
    payload = result[0]
    text = getattr(payload, "text", None)
    if text is None and isinstance(payload, dict):
        text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("MCP tool returned empty text payload")
    if text.startswith("ERROR:"):
        raise RuntimeError(text.replace("ERROR:", "", 1).strip())
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"MCP tool returned non-JSON payload: {text[:200]}") from exc
    if isinstance(data, dict):
        if data.get("error"):
            raise RuntimeError(str(data.get("error")))
        return data
    return {"result": data}


def _call_mcp_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    module = _load_mcp_server_module()
    invocation_id = f"mcpi-{uuid.uuid4().hex[:20]}"
    sanitized_args = {k: v for k, v in arguments.items() if v is not None}
    sanitized_args.setdefault("invocation_id", invocation_id)
    sanitized_args.setdefault("caller_identity", MCP_AUDIT_CALLER_IDENTITY)
    input_hash = hashlib.sha256(
        json.dumps(sanitized_args, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    started = time.perf_counter()
    status = "error"
    error_code = ""

    try:
        result = asyncio.run(module.call_tool(name, sanitized_args))
        parsed = _parse_mcp_result(result)
        status = "success"
    except Exception as exc:
        error_code = _classify_mcp_error(exc)
        raise
    finally:
        latency_ms = int((time.perf_counter() - started) * 1000)
        request_id = str(
            sanitized_args.get("coordination_request_id")
            or sanitized_args.get("request_id")
            or ""
        )
        dispatch_id = str(sanitized_args.get("dispatch_id") or "")
        caller_identity = str(sanitized_args.get("caller_identity") or MCP_AUDIT_CALLER_IDENTITY)
        audit_payload = {
            "invocation_id": invocation_id,
            "caller_identity": caller_identity,
            "request_id": request_id,
            "dispatch_id": dispatch_id,
            "tool_name": name,
            "input_hash": input_hash,
            "result_status": status,
            "latency_ms": latency_ms,
            "error_code": error_code,
            "timestamp": _now_z(),
        }
        logger.info("[AUDIT] %s", json.dumps(audit_payload, sort_keys=True))
        _emit_cloudwatch_json(MCP_SERVER_LOG_GROUP, audit_payload, stream_name="mcp-tool-audit")
        _emit_structured_observability(
            component="mcp_server",
            event="tool_invocation",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name=name,
            latency_ms=latency_ms,
            error_code=error_code,
            extra={
                "invocation_id": invocation_id,
                "caller_identity": caller_identity,
                "input_hash": input_hash,
                "result_status": status,
            },
            mirror_log_group=MCP_SERVER_LOG_GROUP,
        )

    return parsed


def _compute_governance_hash_local() -> str:
    ddb = _get_ddb()
    resp = ddb.query(
        TableName=DOCUMENTS_TABLE,
        IndexName="project-updated-index",
        KeyConditionExpression="project_id = :pid",
        ExpressionAttributeValues={":pid": {"S": str(GOVERNANCE_PROJECT_ID)}},
        ScanIndexForward=False,
    )
    items = list(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = ddb.query(
            TableName=DOCUMENTS_TABLE,
            IndexName="project-updated-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": str(GOVERNANCE_PROJECT_ID)}},
            ScanIndexForward=False,
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))

    def _uri_from_file_name(name: str) -> Optional[str]:
        fn = str(name or "").strip()
        if fn == "agents.md":
            return "governance://agents.md"
        if fn.startswith("agents/"):
            return f"governance://{fn}"
        return None

    selected: Dict[str, Dict[str, Any]] = {}
    for raw in items:
        doc = _deserialize(raw)
        if str(doc.get("status") or "").lower() != "active":
            continue
        keywords = [str(k).strip().lower() for k in doc.get("keywords") or [] if str(k).strip()]
        if GOVERNANCE_KEYWORD and GOVERNANCE_KEYWORD.lower() not in keywords:
            continue
        uri = _uri_from_file_name(str(doc.get("file_name") or ""))
        if not uri:
            continue
        existing = selected.get(uri)
        if existing and str(existing.get("updated_at") or "") >= str(doc.get("updated_at") or ""):
            continue
        selected[uri] = doc

    h = hashlib.sha256()
    if not selected:
        h.update(b"enceladus-governance-docstore-empty")
        return h.hexdigest()

    for uri in sorted(selected.keys()):
        doc = selected[uri]
        content_hash = str(doc.get("content_hash") or "").strip()
        if not content_hash:
            content_hash = hashlib.sha256(
                str(doc.get("document_id") or "").encode("utf-8")
            ).hexdigest()
        h.update(uri.encode("utf-8"))
        h.update(b"\n")
        h.update(content_hash.encode("utf-8"))
        h.update(b"\n")

    return h.hexdigest()


def _classify_related(related_ids: Sequence[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rid in related_ids:
        ridu = str(rid).strip().upper()
        parts = ridu.split("-")
        if len(parts) < 3:
            continue
        segment = parts[1]
        rtype = _SEGMENT_TO_TYPE.get(segment)
        if not rtype:
            continue
        field = f"related_{rtype}_ids"
        out.setdefault(field, []).append(ridu)
    return out


def _normalize_string_list(value: Any, field_name: str) -> List[str]:
    """Normalize a string/list[str] into non-empty trimmed strings."""
    if value is None:
        return []
    if isinstance(value, str):
        source = [value]
    elif isinstance(value, list):
        source = value
    else:
        raise ValueError(f"{field_name} must be a string or list of strings")

    out: List[str] = []
    for entry in source:
        if not isinstance(entry, str):
            raise ValueError(f"{field_name} must contain only strings")
        stripped = entry.strip()
        if stripped:
            out.append(stripped)
    return out


def _create_tracker_record_auto(
    project_id: str,
    prefix: str,
    record_type: str,
    title: str,
    description: str,
    priority: str,
    assigned_to: str,
    related_ids: Optional[List[str]] = None,
    status: Optional[str] = None,
    success_metrics: Optional[List[str]] = None,
    acceptance_criteria: Optional[List[str]] = None,
    severity: Optional[str] = None,
    hypothesis: Optional[str] = None,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> str:
    normalized_acceptance_criteria = _normalize_string_list(
        acceptance_criteria,
        "acceptance_criteria",
    )
    if record_type == "task" and not normalized_acceptance_criteria:
        raise ValueError(
            "Task creation requires acceptance_criteria with at least one non-empty criterion"
        )

    ddb = _get_ddb()
    now = _now_z()
    for _ in range(5):
        seq = _next_tracker_sequence(project_id, record_type)
        record_id = _build_record_id(prefix, record_type, seq)
        item: Dict[str, Any] = {
            "project_id": project_id,
            "record_id": f"{record_type}#{record_id}",
            "record_type": record_type,
            "item_id": record_id,
            "title": title,
            "description": description,
            "priority": priority,
            "assigned_to": assigned_to,
            "status": status or _DEFAULT_STATUS[record_type],
            "created_at": now,
            "updated_at": now,
            "sync_version": 1,
            "last_update_note": "Created via coordination API",
            "history": [
                {
                    "timestamp": now,
                    "status": "created",
                    "description": f"Created via coordination API: {title}",
                }
            ],
        }
        if related_ids:
            item.update(_classify_related(related_ids))
        if record_type == "feature":
            item["owners"] = [assigned_to]
            if success_metrics:
                item["success_metrics"] = success_metrics
        if record_type == "task":
            item["acceptance_criteria"] = normalized_acceptance_criteria
        if record_type == "issue":
            if severity:
                item["severity"] = severity
            if hypothesis:
                item["hypothesis"] = hypothesis

        try:
            ddb.put_item(
                TableName=TRACKER_TABLE,
                Item={k: _serialize(v) for k, v in item.items()},
                ConditionExpression="attribute_not_exists(record_id)",
            )
            return record_id
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            raise

    raise RuntimeError("Failed allocating tracker record id after retries")


def _append_tracker_history(
    record_id: str,
    status: str,
    note: str,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> None:
    _ = governance_hash, coordination_request_id, dispatch_id, provider
    project_id, _record_type, sk = _key_for_record_id(record_id)
    ddb = _get_ddb()
    now = _now_z()
    entry = [{"timestamp": now, "status": status, "description": note[:1000]}]
    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
        UpdateExpression=(
            "SET updated_at = :ts, last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "#history = list_append(if_not_exists(#history, :empty), :entry)"
        ),
        ExpressionAttributeNames={"#history": "history"},
        ExpressionAttributeValues={
            ":ts": _serialize(now),
            ":note": _serialize(note[:1000]),
            ":zero": _serialize(0),
            ":one": _serialize(1),
            ":empty": _serialize([]),
            ":entry": _serialize(entry),
        },
    )


def _set_tracker_status(
    record_id: str,
    new_status: str,
    note: str,
    *,
    governance_hash: Optional[str] = None,
    coordination_request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> None:
    _ = governance_hash, coordination_request_id, dispatch_id, provider
    project_id, _record_type, sk = _key_for_record_id(record_id)
    ddb = _get_ddb()
    now = _now_z()
    ddb.update_item(
        TableName=TRACKER_TABLE,
        Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
        UpdateExpression=(
            "SET #status = :new_status, updated_at = :ts, last_update_note = :note, "
            "sync_version = if_not_exists(sync_version, :zero) + :one"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":new_status": _serialize(new_status),
            ":ts": _serialize(now),
            ":note": _serialize(note[:1000]),
            ":zero": _serialize(0),
            ":one": _serialize(1),
        },
    )
    _append_tracker_history(
        record_id,
        "worklog",
        note,
        governance_hash=governance_hash,
        coordination_request_id=coordination_request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )


def _resolve_project_id_for_prefix(prefix: str) -> Optional[str]:
    normalized_prefix = str(prefix or "").strip().upper()
    if not normalized_prefix:
        return None

    for project_id, data in _project_cache.items():
        if str(data.get("prefix") or "").upper() == normalized_prefix:
            return str(project_id)

    ddb = _get_ddb()
    scan = ddb.scan(
        TableName=PROJECTS_TABLE,
        ProjectionExpression="project_id, #pfx",
        ExpressionAttributeNames={"#pfx": "prefix"},
    )
    items = scan.get("Items", [])
    while scan.get("LastEvaluatedKey"):
        scan = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, #pfx",
            ExpressionAttributeNames={"#pfx": "prefix"},
            ExclusiveStartKey=scan["LastEvaluatedKey"],
        )
        items.extend(scan.get("Items", []))

    for raw in items:
        row = _deserialize(raw)
        project_id = str(row.get("project_id") or "").strip()
        project_prefix = str(row.get("prefix") or "").strip().upper()
        if project_id and project_prefix:
            _project_cache[project_id] = {"prefix": project_prefix}
        if project_prefix == normalized_prefix:
            return project_id or None

    return None


def _tracker_record_snapshot(record_id: str) -> Optional[Dict[str, Any]]:
    normalized_id = str(record_id or "").strip().upper()
    parts = normalized_id.split("-")
    if len(parts) != 3:
        return None

    prefix, segment, _num = parts
    segment_alias = "TSK" if segment == "TASK" else segment
    record_type = _SEGMENT_TO_TYPE.get(segment_alias)
    if not record_type:
        return None

    project_id = _resolve_project_id_for_prefix(prefix)
    if not project_id:
        return None

    sk = f"{record_type}#{normalized_id}"

    ddb = _get_ddb()
    try:
        resp = ddb.get_item(
            TableName=TRACKER_TABLE,
            Key={"project_id": _serialize(project_id), "record_id": _serialize(sk)},
            ConsistentRead=True,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.warning("Failed reading tracker snapshot for %s: %s", record_id, exc)
        return None

    item = resp.get("Item")
    if not item:
        return None

    plain = _deserialize(item)
    history = plain.get("history")
    sync_version_raw = plain.get("sync_version")
    try:
        sync_version = int(sync_version_raw)
    except (TypeError, ValueError):
        sync_version = 0

    return {
        "status": str(plain.get("status") or ""),
        "updated_at": str(plain.get("updated_at") or ""),
        "sync_version": sync_version,
        "history_len": len(history) if isinstance(history, list) else 0,
    }


def _collect_tracker_snapshots(record_ids: Sequence[str]) -> Dict[str, Optional[Dict[str, Any]]]:
    snapshots: Dict[str, Optional[Dict[str, Any]]] = {}
    seen: set[str] = set()
    for raw_id in record_ids:
        record_id = str(raw_id or "").strip().upper()
        if not record_id or record_id in seen:
            continue
        seen.add(record_id)
        snapshots[record_id] = _tracker_record_snapshot(record_id)
    return snapshots


def _related_records_mutated(
    before: Dict[str, Optional[Dict[str, Any]]],
    after: Dict[str, Optional[Dict[str, Any]]],
) -> Tuple[bool, List[str]]:
    changed_ids: List[str] = []
    for record_id in sorted(set(before.keys()) | set(after.keys())):
        if before.get(record_id) != after.get(record_id):
            changed_ids.append(record_id)
    return bool(changed_ids), changed_ids


def _requires_related_record_mutation_guard(request: Dict[str, Any], execution_mode: str) -> bool:
    if execution_mode not in {"codex_app_server", "codex_full_auto"}:
        return False

    related = [str(item).strip() for item in (request.get("related_record_ids") or []) if str(item).strip()]
    if not related:
        return False

    constraints = request.get("constraints")
    if not isinstance(constraints, dict):
        constraints = {}

    require_guard = constraints.get("require_related_record_mutation")
    if isinstance(require_guard, bool):
        return require_guard

    allow_noop_success = constraints.get("allow_noop_success")
    if isinstance(allow_noop_success, bool) and allow_noop_success:
        return False

    return True


# ---------------------------------------------------------------------------
# Decomposition + request model helpers
# ---------------------------------------------------------------------------


def _normalize_outcomes(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        raise ValueError("'outcomes' must be a list of strings")
    if not raw:
        raise ValueError("'outcomes' cannot be empty")
    if len(raw) > MAX_OUTCOMES:
        raise ValueError(f"'outcomes' exceeds max count ({MAX_OUTCOMES})")

    normalized: List[str] = []
    for idx, val in enumerate(raw, start=1):
        if not isinstance(val, str):
            raise ValueError(f"Outcome {idx} must be a string")
        text = val.strip()
        if not text:
            raise ValueError(f"Outcome {idx} is empty")
        if len(text) > MAX_OUTCOME_LENGTH:
            raise ValueError(
                f"Outcome {idx} exceeds max length ({MAX_OUTCOME_LENGTH})"
            )
        normalized.append(text)
    return normalized


def _validate_constraints(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("'constraints' must be an object")
    encoded = json.dumps(raw)
    if len(encoded) > MAX_CONSTRAINT_SIZE:
        raise ValueError("'constraints' payload too large")
    return raw


def _validate_provider_session(raw: Any) -> Dict[str, Any]:
    """Validate provider_session (v0.2) or provider_preferences (v0.3).

    v0.3 adds 'preferred_provider' field. Both field names accepted for
    backward compatibility per contract versioning policy.
    """
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise ValueError("'provider_session'/'provider_preferences' must be an object")

    allowed = {
        "thread_id",
        "fork_from_thread_id",
        "session_id",
        "fork_from_session_id",
        "provider_session_id",
        "model",
        "preferred_provider",
        "permission_mode",
        "allowed_tools",
        "system_prompt",
        "task_complexity",
        "thinking",
        "stream",
    }
    unknown = sorted(k for k in raw.keys() if k not in allowed)
    if unknown:
        raise ValueError(
            f"'provider_preferences' contains unsupported fields: {', '.join(unknown)}"
        )

    out: Dict[str, Any] = {}

    preferred = raw.get("preferred_provider")
    if preferred not in (None, ""):
        if not isinstance(preferred, str):
            raise ValueError("'provider_preferences.preferred_provider' must be a string")
        preferred = preferred.strip().lower()
        if preferred and preferred not in _VALID_PROVIDERS:
            raise ValueError(
                f"Unsupported preferred_provider '{preferred}'. "
                f"Allowed: {sorted(_VALID_PROVIDERS)}"
            )
        if preferred:
            out["preferred_provider"] = preferred

    for field in (
        "thread_id",
        "fork_from_thread_id",
        "session_id",
        "fork_from_session_id",
        "provider_session_id",
        "model",
    ):
        value = raw.get(field)
        if value in (None, ""):
            continue
        if not isinstance(value, str):
            raise ValueError(f"'provider_preferences.{field}' must be a string")
        text = value.strip()
        if not text:
            continue
        if len(text) > 240:
            raise ValueError(f"'provider_preferences.{field}' exceeds max length (240)")
        out[field] = text

    if "thread_id" in out and "session_id" in out and out["thread_id"] != out["session_id"]:
        raise ValueError("Specify either 'thread_id' or 'session_id', not conflicting values")
    if (
        "fork_from_thread_id" in out
        and "fork_from_session_id" in out
        and out["fork_from_thread_id"] != out["fork_from_session_id"]
    ):
        raise ValueError(
            "Specify either 'fork_from_thread_id' or 'fork_from_session_id', not conflicting values"
        )
    if "thread_id" in out and "fork_from_thread_id" in out:
        raise ValueError("Specify either 'thread_id' or 'fork_from_thread_id', not both")
    if "session_id" in out and "fork_from_session_id" in out:
        raise ValueError("Specify either 'session_id' or 'fork_from_session_id', not both")

    permission_mode = raw.get("permission_mode")
    if permission_mode not in (None, ""):
        if not isinstance(permission_mode, str):
            raise ValueError("'provider_preferences.permission_mode' must be a string")
        normalized_mode = permission_mode.strip()
        if normalized_mode not in _CLAUDE_PERMISSION_MODES:
            raise ValueError(
                f"Unsupported permission_mode '{normalized_mode}'. "
                f"Allowed: {sorted(_CLAUDE_PERMISSION_MODES)}"
            )
        out["permission_mode"] = normalized_mode

    allowed_tools = raw.get("allowed_tools")
    if allowed_tools not in (None, ""):
        if not isinstance(allowed_tools, list):
            raise ValueError("'provider_preferences.allowed_tools' must be a list of strings")
        normalized_tools: List[str] = []
        for idx, tool_name in enumerate(allowed_tools, start=1):
            if not isinstance(tool_name, str):
                raise ValueError(f"'provider_preferences.allowed_tools[{idx}]' must be a string")
            tool = tool_name.strip()
            if not tool:
                continue
            if len(tool) > 128:
                raise ValueError(f"'provider_preferences.allowed_tools[{idx}]' exceeds max length (128)")
            if tool not in _ENCELADUS_ALLOWED_TOOLS:
                raise ValueError(
                    f"'provider_preferences.allowed_tools[{idx}]' is not an allowlisted Enceladus MCP tool: {tool}"
                )
            if tool not in normalized_tools:
                normalized_tools.append(tool)
        if normalized_tools:
            out["allowed_tools"] = normalized_tools

    # system_prompt — optional string for Claude system message
    system_prompt = raw.get("system_prompt")
    if system_prompt not in (None, ""):
        if not isinstance(system_prompt, str):
            raise ValueError("'provider_preferences.system_prompt' must be a string")
        if len(system_prompt) > 100_000:
            raise ValueError("'provider_preferences.system_prompt' exceeds max length (100000)")
        out["system_prompt"] = system_prompt

    # task_complexity — drives model routing (simple/standard/complex/critical)
    task_complexity = raw.get("task_complexity")
    if task_complexity not in (None, ""):
        if not isinstance(task_complexity, str):
            raise ValueError("'provider_preferences.task_complexity' must be a string")
        tc = task_complexity.strip().lower()
        if tc not in _CLAUDE_VALID_TASK_COMPLEXITIES:
            raise ValueError(
                f"Unsupported task_complexity '{tc}'. "
                f"Allowed: {sorted(_CLAUDE_VALID_TASK_COMPLEXITIES)}"
            )
        out["task_complexity"] = tc

    # thinking — enable extended thinking (bool or dict with budget_tokens)
    thinking = raw.get("thinking")
    if thinking is not None:
        if isinstance(thinking, bool):
            out["thinking"] = thinking
        elif isinstance(thinking, dict):
            budget = thinking.get("budget_tokens")
            if budget is not None:
                try:
                    budget = int(budget)
                except (TypeError, ValueError):
                    raise ValueError("'provider_preferences.thinking.budget_tokens' must be an integer")
                if budget < CLAUDE_THINKING_BUDGET_MIN or budget > CLAUDE_THINKING_BUDGET_MAX:
                    raise ValueError(
                        f"'provider_preferences.thinking.budget_tokens' must be between "
                        f"{CLAUDE_THINKING_BUDGET_MIN} and {CLAUDE_THINKING_BUDGET_MAX}"
                    )
            out["thinking"] = thinking
        else:
            raise ValueError("'provider_preferences.thinking' must be a boolean or object with budget_tokens")

    # stream — enable streaming response
    stream = raw.get("stream")
    if stream is not None:
        if not isinstance(stream, bool):
            raise ValueError("'provider_preferences.stream' must be a boolean")
        out["stream"] = stream

    return out


def _coerce_execution_mode(value: Optional[str]) -> str:
    if not value:
        return "preflight"
    mode = value.strip().lower()
    if mode not in _VALID_EXECUTION_MODES:
        raise ValueError(
            f"Unsupported execution_mode '{value}'. "
            f"Allowed: {sorted(_VALID_EXECUTION_MODES)}"
        )
    if mode == "claude_headless" and not ENABLE_CLAUDE_HEADLESS:
        raise ValueError("claude_headless mode is disabled by environment policy")
    return mode


def _derive_idempotency_key(
    project_id: str,
    initiative_title: str,
    outcomes: Sequence[str],
    requestor_session_id: str,
    explicit: Optional[str] = None,
) -> str:
    if explicit:
        key = explicit.strip()
        if not key:
            raise ValueError("'idempotency_key' cannot be blank when provided")
        if len(key) > 128:
            raise ValueError("'idempotency_key' exceeds max length (128)")
        return key

    digest = hashlib.sha256(
        json.dumps(
            {
                "project_id": project_id,
                "initiative_title": initiative_title,
                "outcomes": list(outcomes),
                "requestor_session_id": requestor_session_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return f"coord-{digest[:32]}"


def _new_request_id() -> str:
    return f"CRQ-{uuid.uuid4().hex[:12].upper()}"


def _new_dispatch_id() -> str:
    return f"DSP-{uuid.uuid4().hex[:12].upper()}"


def _new_callback_token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def _find_recent_by_idempotency(project_id: str, key: str) -> Optional[Dict[str, Any]]:
    ddb = _get_ddb()
    lower_bound = (_unix_now() - IDEMPOTENCY_WINDOW_SECONDS)
    now_epoch = _unix_now()

    index_candidates = [COORDINATION_GSI_IDEMPOTENCY, "idempotency-index"]
    resp = None
    for index_name in index_candidates:
        try:
            resp = ddb.query(
                TableName=COORDINATION_TABLE,
                IndexName=index_name,
                KeyConditionExpression="idempotency_key = :k AND created_epoch >= :min_epoch",
                FilterExpression="project_id = :pid",
                ExpressionAttributeValues={
                    ":k": _serialize(key),
                    ":pid": _serialize(project_id),
                    ":min_epoch": _serialize(lower_bound),
                },
                ScanIndexForward=False,
                Limit=1,
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ValidationException" and index_name != index_candidates[-1]:
                continue
            logger.warning("idempotency lookup skipped due to query error: %s", exc)
            return None
        except BotoCoreError as exc:
            logger.warning("idempotency lookup skipped due to query error: %s", exc)
            return None

    if not resp:
        return None

    items = resp.get("Items") or []
    if not items:
        return None
    candidate = _deserialize(items[0])
    expires = int(candidate.get("idempotency_expires_epoch") or 0)
    if expires and expires < now_epoch:
        return None
    return candidate


def _classify_dispatch_failure(exc: Exception) -> Tuple[str, bool]:
    msg = str(exc).lower()
    if any(token in msg for token in ("timeout", "timed out", "socket", "connection reset")):
        return "network_timeout", True
    if any(token in msg for token in ("unreachable", "host", "invocationdoesnotexist", "no such instance")):
        return "host_unavailable", True
    if any(token in msg for token in ("unauthorized", "forbidden", "access denied", "expiredtoken", "invalid api key")):
        return "auth_invalid", False
    if any(token in msg for token in ("schema", "validation", "missing required", "unsupported")):
        return "input_validation", False
    if any(token in msg for token in ("governance", "stale hash", "policy denied")):
        return "governance_stale", False
    return "provider_transient", True


def _retry_backoff_seconds(attempt_number: int) -> int:
    idx = max(0, min(attempt_number - 1, len(_RETRY_BACKOFF_SECONDS) - 1))
    return _RETRY_BACKOFF_SECONDS[idx]


def _release_dispatch_lock(request: Dict[str, Any], reason: str) -> None:
    request["lock_expires_epoch"] = 0
    request["lock_released_at"] = _now_z()
    request["lock_release_reason"] = reason


def _acquire_dispatch_lock(request_id: str, lock_expires_epoch: int) -> bool:
    ddb = _get_ddb()
    now_epoch = _unix_now()
    try:
        ddb.update_item(
            TableName=COORDINATION_TABLE,
            Key=_request_key(request_id),
            UpdateExpression="SET lock_expires_epoch = :lock, updated_epoch = :ts",
            ConditionExpression="attribute_not_exists(lock_expires_epoch) OR lock_expires_epoch <= :now",
            ExpressionAttributeValues={
                ":lock": _serialize(lock_expires_epoch),
                ":ts": _serialize(now_epoch),
                ":now": _serialize(now_epoch),
            },
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _publish_dead_letter_alert(request: Dict[str, Any], reason: str) -> None:
    if not DEAD_LETTER_SNS_TOPIC_ARN:
        return
    try:
        _get_sns().publish(
            TopicArn=DEAD_LETTER_SNS_TOPIC_ARN,
            Subject=f"[coordination] dead-letter {request.get('request_id')}",
            Message=json.dumps(
                {
                    "request_id": request.get("request_id"),
                    "project_id": request.get("project_id"),
                    "reason": reason,
                    "dispatch_attempts": request.get("dispatch_attempts"),
                    "state": request.get("state"),
                    "timestamp": _now_z(),
                }
            ),
        )
    except Exception as exc:
        logger.warning("dead-letter SNS publish failed: %s", exc)


def _move_to_dead_letter(request: Dict[str, Any], reason: str, failure_class: Optional[str] = None) -> None:
    if request.get("state") != _STATE_DEAD_LETTER:
        _append_state_transition(
            request,
            _STATE_DEAD_LETTER,
            reason,
            extra={"failure_class": failure_class} if failure_class else None,
        )
    _release_dispatch_lock(request, "dead_letter")
    _cleanup_dispatch_host(request, "dead_letter")
    request["result"] = {
        **(request.get("result") or {}),
        "summary": (request.get("result") or {}).get("summary") or reason,
        "dead_letter_reason": reason,
        "failure_class": failure_class,
    }
    _publish_dead_letter_alert(request, reason)



# ---------------------------------------------------------------------------
# Intake debounce queue — record-ID dedup + merge (v0.3 contract §6.1.1)
# ---------------------------------------------------------------------------


def _extract_record_ids_from_body(request_body: Dict[str, Any]) -> set:
    """Extract all tracker record IDs referenced anywhere in an incoming request body."""
    ids: set = set()
    _ID_PATTERN = re.compile(r"\b[A-Z]{3}-(?:TSK|ISS|FTR)-\d{3}(?:-[0-9][A-Z])?\b")

    for rid in request_body.get("related_record_ids") or []:
        if isinstance(rid, str) and rid.strip():
            ids.add(rid.strip().upper())

    for outcome in request_body.get("outcomes") or []:
        if isinstance(outcome, str):
            ids.update(_ID_PATTERN.findall(outcome.upper()))

    constraints = request_body.get("constraints")
    if constraints:
        ids.update(_ID_PATTERN.findall(json.dumps(constraints).upper()))

    return ids


def _extract_record_ids_from_request(request: Dict[str, Any]) -> set:
    """Extract record IDs from a persisted coordination request item."""
    ids: set = set()
    _ID_PATTERN = re.compile(r"\b[A-Z]{3}-(?:TSK|ISS|FTR)-\d{3}(?:-[0-9][A-Z])?\b")

    for rid in request.get("related_record_ids") or []:
        if isinstance(rid, str) and rid.strip():
            ids.add(rid.strip().upper())

    for outcome in request.get("outcomes") or []:
        if isinstance(outcome, str):
            ids.update(_ID_PATTERN.findall(outcome.upper()))

    constraints = request.get("constraints")
    if constraints:
        ids.update(_ID_PATTERN.findall(json.dumps(constraints).upper()))

    fid = request.get("feature_id")
    if fid:
        ids.add(fid.upper())
    for tid in request.get("task_ids") or []:
        ids.add(tid.upper())
    for iid in request.get("issue_ids") or []:
        ids.add(iid.upper())

    return ids


def _find_intake_candidates(project_id: str, now_epoch: int) -> List[Dict[str, Any]]:
    """Find all coordination requests in intake_received state within debounce window."""
    ddb = _get_ddb()
    candidates: List[Dict[str, Any]] = []

    try:
        resp = ddb.query(
            TableName=COORDINATION_TABLE,
            IndexName=COORDINATION_GSI_PROJECT,
            KeyConditionExpression="project_id = :pid AND updated_epoch >= :min_epoch",
            FilterExpression="#s = :intake_state",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":pid": _serialize(project_id),
                ":min_epoch": _serialize(now_epoch - DEBOUNCE_WINDOW_SECONDS - 60),
                ":intake_state": _serialize(_STATE_INTAKE_RECEIVED),
            },
            ScanIndexForward=False,
        )
        for raw in resp.get("Items", []):
            item = _deserialize(raw)
            expires = int(item.get("debounce_window_expires_epoch") or 0)
            if expires > now_epoch:
                candidates.append(item)
    except (BotoCoreError, ClientError) as exc:
        logger.warning("intake candidate lookup skipped: %s", exc)

    return candidates


def _dispatch_uses_host_runtime(execution_mode: str) -> bool:
    mode = str(execution_mode or "").strip().lower()
    return mode not in {"claude_agent_sdk", "codex_app_server", "codex_full_auto"}


def _fleet_launch_ready() -> bool:
    return bool(HOST_V2_FLEET_ENABLED and HOST_V2_FLEET_LAUNCH_TEMPLATE_ID)


def _active_host_dispatches(
    project_id: str,
    *,
    current_request_id: str = "",
    instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ddb = _get_ddb()
    now_epoch = _unix_now()
    cutoff = now_epoch - max(HOST_V2_TIMEOUT_SECONDS, 600) - 600
    active: List[Dict[str, Any]] = []
    last_evaluated_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "TableName": COORDINATION_TABLE,
            "IndexName": COORDINATION_GSI_PROJECT,
            "KeyConditionExpression": "project_id = :pid AND updated_epoch >= :cutoff",
            "ExpressionAttributeValues": {
                ":pid": _serialize(project_id),
                ":cutoff": _serialize(cutoff),
            },
            "ScanIndexForward": False,
            "Limit": 50,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key
        resp = ddb.query(**kwargs)
        for raw in resp.get("Items", []):
            item = _deserialize(raw)
            rid = str(item.get("request_id") or "")
            if not rid or rid == current_request_id:
                continue
            state = str(item.get("state") or "")
            if state not in {"dispatching", "running"}:
                continue
            execution_mode = str(item.get("execution_mode") or "")
            if not _dispatch_uses_host_runtime(execution_mode):
                continue
            lock_expires_epoch = int(item.get("lock_expires_epoch") or 0)
            if lock_expires_epoch and lock_expires_epoch < now_epoch:
                continue
            dispatch = item.get("dispatch") or {}
            candidate_instance_id = str(dispatch.get("instance_id") or HOST_V2_INSTANCE_ID)
            if instance_id and candidate_instance_id != instance_id:
                continue
            active.append(
                {
                    "request_id": rid,
                    "state": state,
                    "dispatch_id": str(dispatch.get("dispatch_id") or ""),
                    "command_id": str(dispatch.get("command_id") or ""),
                    "instance_id": candidate_instance_id,
                    "lock_expires_epoch": lock_expires_epoch,
                    "execution_mode": execution_mode,
                    "host_kind": str(dispatch.get("host_kind") or "static"),
                }
            )
        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    return active


def _count_active_host_dispatches(project_id: str, *, current_request_id: str = "") -> int:
    return len(_active_host_dispatches(project_id, current_request_id=current_request_id))


def _find_active_host_dispatch(
    project_id: str,
    current_request_id: str,
    *,
    instance_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    active = _active_host_dispatches(
        project_id,
        current_request_id=current_request_id,
        instance_id=instance_id or HOST_V2_INSTANCE_ID,
    )
    return active[0] if active else None


def _launch_fleet_instance(project_id: str, request_id: str, dispatch_id: str) -> Dict[str, Any]:
    ec2 = _get_ec2()
    name_suffix = dispatch_id.lower().replace("dsp-", "")[:12]
    instance_name = f"{HOST_V2_FLEET_NAME_PREFIX}-{name_suffix}"
    tags = [
        {"Key": "Name", "Value": instance_name},
        {"Key": "enceladus:managed-by", "Value": HOST_V2_FLEET_TAG_MANAGED_BY_VALUE},
        {"Key": "enceladus:project", "Value": str(project_id)},
        {"Key": "enceladus:coordination-request-id", "Value": str(request_id)},
        {"Key": "enceladus:dispatch-id", "Value": str(dispatch_id)},
        {"Key": "enceladus:fleet-node", "Value": "true"},
    ]
    response = ec2.run_instances(
        MinCount=1,
        MaxCount=1,
        LaunchTemplate={
            "LaunchTemplateId": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
            "Version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
        },
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
        InstanceInitiatedShutdownBehavior="terminate",
    )
    instances = response.get("Instances") or []
    if not instances:
        raise RuntimeError("Fleet launch failed: run_instances returned no instances")
    instance = instances[0]
    instance_id = str(instance.get("InstanceId") or "")
    if not instance_id:
        raise RuntimeError("Fleet launch failed: missing InstanceId")
    return {
        "instance_id": instance_id,
        "launch_template_id": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
        "launch_template_version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
        "launched_at": _now_z(),
        "dispatch_id": dispatch_id,
        "project_id": project_id,
    }


def _wait_for_fleet_instance_readiness(instance_id: str) -> Dict[str, Any]:
    deadline = time.time() + max(30, HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS)
    poll_seconds = max(3, HOST_V2_FLEET_READINESS_POLL_SECONDS)
    ec2 = _get_ec2()
    ssm = _get_ssm()
    last_state = "unknown"

    while time.time() < deadline:
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            if code == "InvalidInstanceID.NotFound":
                time.sleep(poll_seconds)
                continue
            raise

        reservations = response.get("Reservations") or []
        if not reservations or not (reservations[0].get("Instances") or []):
            time.sleep(poll_seconds)
            continue
        instance = (reservations[0].get("Instances") or [])[0]
        last_state = str(((instance.get("State") or {}).get("Name") or "unknown")).lower()
        if last_state in {"terminated", "shutting-down", "stopping", "stopped"}:
            raise RuntimeError(f"Fleet instance {instance_id} entered terminal state '{last_state}' before readiness")
        if last_state != "running":
            time.sleep(poll_seconds)
            continue

        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}],
            MaxResults=1,
        )
        details = info.get("InstanceInformationList") or []
        if details and str(details[0].get("PingStatus") or "").lower() == "online":
            return {
                "instance_id": instance_id,
                "state": last_state,
                "ssm_ping_status": "Online",
                "ready_at": _now_z(),
            }
        time.sleep(poll_seconds)

    raise RuntimeError(
        f"Fleet instance {instance_id} readiness timeout after {HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS}s "
        f"(last_state={last_state})"
    )


def _cleanup_dispatch_host(request: Dict[str, Any], reason: str) -> Dict[str, Any]:
    dispatch = dict(request.get("dispatch") or {})
    if str(dispatch.get("host_kind") or "").lower() != "fleet":
        return request
    if not HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL:
        dispatch["host_cleanup_state"] = "skipped_by_config"
        dispatch["host_cleanup_reason"] = reason
        dispatch["host_cleanup_at"] = _now_z()
        request["dispatch"] = dispatch
        return request

    cleanup_state = str(dispatch.get("host_cleanup_state") or "")
    if cleanup_state in {"terminated", "already_terminated"}:
        return request

    instance_id = str(dispatch.get("instance_id") or "")
    if not instance_id:
        return request

    try:
        _get_ec2().terminate_instances(InstanceIds=[instance_id])
        dispatch["host_cleanup_state"] = "terminated"
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        if code == "InvalidInstanceID.NotFound":
            dispatch["host_cleanup_state"] = "already_terminated"
        else:
            dispatch["host_cleanup_state"] = "termination_failed"
            dispatch["host_cleanup_error"] = str(exc)
    dispatch["host_cleanup_reason"] = reason
    dispatch["host_cleanup_at"] = _now_z()
    request["dispatch"] = dispatch
    return request


def _sweep_orphan_fleet_hosts(project_id: str) -> Dict[str, Any]:
    if not _fleet_launch_ready():
        return {"enabled": False, "scanned": 0, "terminated": 0, "kept": 0}

    try:
        active_dispatches = _active_host_dispatches(project_id)
    except Exception as exc:
        logger.warning("fleet sweep skipped: unable to read active dispatches (%s)", exc)
        return {"enabled": True, "error": str(exc), "scanned": 0, "terminated": 0, "kept": 0}

    active_instance_ids = {str(item.get("instance_id") or "") for item in active_dispatches if item.get("instance_id")}
    max_age = max(300, HOST_V2_FLEET_INSTANCE_TTL_SECONDS + HOST_V2_FLEET_SWEEP_GRACE_SECONDS)
    now_epoch = _unix_now()
    filters = [
        {"Name": "tag:enceladus:managed-by", "Values": [HOST_V2_FLEET_TAG_MANAGED_BY_VALUE]},
        {"Name": "tag:enceladus:project", "Values": [project_id]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ]

    scanned = 0
    kept = 0
    terminate_ids: List[str] = []
    try:
        paginator = _get_ec2().get_paginator("describe_instances")
        for page in paginator.paginate(Filters=filters):
            for reservation in page.get("Reservations") or []:
                for instance in reservation.get("Instances") or []:
                    scanned += 1
                    iid = str(instance.get("InstanceId") or "")
                    if not iid:
                        continue
                    if iid in active_instance_ids:
                        kept += 1
                        continue
                    launched_at = instance.get("LaunchTime")
                    launched_epoch = int(launched_at.timestamp()) if hasattr(launched_at, "timestamp") else now_epoch
                    age_seconds = max(0, now_epoch - launched_epoch)
                    if age_seconds >= max_age:
                        terminate_ids.append(iid)
                    else:
                        kept += 1
    except Exception as exc:
        logger.warning("fleet sweep describe_instances failed: %s", exc)
        return {
            "enabled": True,
            "error": str(exc),
            "scanned": scanned,
            "terminated": 0,
            "kept": kept,
            "active_dispatches": len(active_dispatches),
        }

    terminated = 0
    if terminate_ids:
        try:
            for i in range(0, len(terminate_ids), 50):
                batch = terminate_ids[i : i + 50]
                _get_ec2().terminate_instances(InstanceIds=batch)
                terminated += len(batch)
        except Exception as exc:
            logger.warning("fleet sweep terminate failed: %s", exc)
            return {
                "enabled": True,
                "error": str(exc),
                "scanned": scanned,
                "terminated": terminated,
                "kept": kept,
                "active_dispatches": len(active_dispatches),
            }

    return {
        "enabled": True,
        "scanned": scanned,
        "terminated": terminated,
        "kept": kept,
        "active_dispatches": len(active_dispatches),
    }


def _resolve_host_dispatch_target(
    request: Dict[str, Any],
    execution_mode: str,
    dispatch_id: str,
    *,
    host_allocation: str = "auto",
) -> Dict[str, Any]:
    if not _dispatch_uses_host_runtime(execution_mode):
        return {
            "instance_id": HOST_V2_INSTANCE_ID,
            "host_kind": "managed_session",
            "host_allocation": "managed",
            "host_source": "provider_api",
        }

    allocation = str(host_allocation or "auto").strip().lower()
    if allocation not in {"auto", "static", "fleet"}:
        raise ValueError(f"Unsupported host_allocation '{host_allocation}'")

    if allocation == "static":
        return {
            "instance_id": HOST_V2_INSTANCE_ID,
            "host_kind": "static",
            "host_allocation": "static",
            "host_source": "host_v2",
        }

    fleet_available = _fleet_launch_ready()
    if (allocation == "fleet" or (allocation == "auto" and fleet_available)) and fleet_available:
        project_id = str(request.get("project_id") or "")
        request_id = str(request.get("request_id") or "")
        if HOST_V2_FLEET_SWEEP_ON_DISPATCH:
            sweep_result = _sweep_orphan_fleet_hosts(project_id)
            logger.info("[INFO] fleet orphan sweep result: %s", json.dumps(sweep_result, sort_keys=True))
        active_dispatches = _count_active_host_dispatches(project_id, current_request_id=request_id)
        if HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES > 0 and active_dispatches >= HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES:
            raise RuntimeError(
                "host_fleet_capacity_exceeded:"
                f" active={active_dispatches} max={HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES}"
            )

        launch = _launch_fleet_instance(project_id, request_id, dispatch_id)
        instance_id = launch["instance_id"]
        try:
            readiness = _wait_for_fleet_instance_readiness(instance_id)
        except Exception:
            try:
                _get_ec2().terminate_instances(InstanceIds=[instance_id])
            except Exception:
                logger.warning("failed terminating fleet instance after readiness error: %s", instance_id)
            raise

        return {
            "instance_id": instance_id,
            "host_kind": "fleet",
            "host_allocation": "fleet",
            "host_source": "launch_template",
            "launch_template_id": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
            "launch_template_version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
            "launched_at": launch.get("launched_at"),
            "ready_at": readiness.get("ready_at"),
            "instance_ttl_seconds": HOST_V2_FLEET_INSTANCE_TTL_SECONDS,
        }

    if allocation == "fleet":
        if HOST_V2_FLEET_FALLBACK_TO_STATIC:
            return {
                "instance_id": HOST_V2_INSTANCE_ID,
                "host_kind": "static",
                "host_allocation": "fleet-fallback-static",
                "host_source": "host_v2",
            }
        raise RuntimeError("host_fleet_unavailable: launch template not configured")

    return {
        "instance_id": HOST_V2_INSTANCE_ID,
        "host_kind": "static",
        "host_allocation": "auto-static",
        "host_source": "host_v2",
    }


def _find_dedup_match(
    project_id: str,
    incoming_record_ids: set,
    now_epoch: int,
) -> Optional[Dict[str, Any]]:
    """Find an existing intake_received request whose record IDs overlap with incoming."""
    if not incoming_record_ids:
        return None

    candidates = _find_intake_candidates(project_id, now_epoch)
    for candidate in candidates:
        existing_ids = _extract_record_ids_from_request(candidate)
        if incoming_record_ids & existing_ids:
            return candidate

    return None


def _merge_requests(
    existing: Dict[str, Any],
    new_body: Dict[str, Any],
    new_requestor_session_id: str,
) -> Dict[str, Any]:
    """Merge a new request body into an existing intake_received request.

    v0.3 contract section 6.1.1 merge rules:
    - initiative_title: concatenated with ' + ' or kept if identical
    - outcomes: union deduplicated by exact string match
    - constraints: deep-merged, later overrides
    - related_record_ids: union set
    - source_sessions: array of all contributing session IDs
    - source_requests: array of original request IDs that were merged
    """
    now = _now_z()
    now_epoch = _unix_now()

    existing_title = existing.get("initiative_title", "")
    new_title = str(new_body.get("initiative_title") or "").strip()
    if new_title and new_title != existing_title:
        merged_title = f"{existing_title} + {new_title}"
        if len(merged_title) > MAX_TITLE_LENGTH * 2:
            merged_title = merged_title[: MAX_TITLE_LENGTH * 2]
    else:
        merged_title = existing_title
    existing["initiative_title"] = merged_title

    existing_outcomes = list(existing.get("outcomes") or [])
    new_outcomes = list(new_body.get("outcomes") or [])
    seen = set(existing_outcomes)
    for outcome in new_outcomes:
        if outcome not in seen:
            existing_outcomes.append(outcome)
            seen.add(outcome)
    existing["outcomes"] = existing_outcomes

    existing_constraints = dict(existing.get("constraints") or {})
    new_constraints = dict(new_body.get("constraints") or {})
    existing_constraints.update(new_constraints)
    existing["constraints"] = existing_constraints

    existing_related = set(existing.get("related_record_ids") or [])
    new_related = set(new_body.get("related_record_ids") or [])
    existing["related_record_ids"] = sorted(existing_related | new_related)

    sessions = list(existing.get("source_sessions") or [])
    original_session = existing.get("requestor_session_id")
    if original_session and original_session not in sessions:
        sessions.append(original_session)
    if new_requestor_session_id and new_requestor_session_id not in sessions:
        sessions.append(new_requestor_session_id)
    existing["source_sessions"] = sessions

    source_requests = list(existing.get("source_requests") or [])
    own_id = existing.get("request_id")
    if own_id and own_id not in source_requests:
        source_requests.append(own_id)
    existing["source_requests"] = source_requests

    existing["debounce_window_expires_epoch"] = now_epoch + DEBOUNCE_WINDOW_SECONDS
    existing["debounce_window_expires"] = (
        dt.datetime.fromtimestamp(
            now_epoch + DEBOUNCE_WINDOW_SECONDS, tz=dt.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    history = list(existing.get("state_history") or [])
    history.append({
        "timestamp": now,
        "from": _STATE_INTAKE_RECEIVED,
        "to": _STATE_INTAKE_RECEIVED,
        "reason": f"Merged with incoming request (session={new_requestor_session_id})",
        "meta": {
            "merged_title": new_title,
            "merged_outcomes_count": len(new_outcomes),
            "merged_related_count": len(new_related),
        },
    })
    existing["state_history"] = history

    existing["updated_at"] = now
    existing["updated_epoch"] = now_epoch
    existing["sync_version"] = int(existing.get("sync_version", 0)) + 1
    existing["last_merge_at"] = now

    return existing


def _promote_expired_intake_requests(project_id: str) -> List[str]:
    """Promote intake_received requests whose debounce window has expired to queued.

    On-read promotion pattern: called during create/get to avoid separate scheduler.
    """
    now_epoch = _unix_now()
    promoted: List[str] = []

    try:
        ddb = _get_ddb()
        resp = ddb.query(
            TableName=COORDINATION_TABLE,
            IndexName=COORDINATION_GSI_PROJECT,
            KeyConditionExpression="project_id = :pid AND updated_epoch >= :min_epoch",
            FilterExpression="#s = :intake_state",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":pid": _serialize(project_id),
                ":min_epoch": _serialize(now_epoch - DEBOUNCE_WINDOW_SECONDS - 300),
                ":intake_state": _serialize(_STATE_INTAKE_RECEIVED),
            },
            ScanIndexForward=False,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.warning("intake promotion scan skipped: %s", exc)
        return promoted

    for raw in resp.get("Items", []):
        item = _deserialize(raw)
        expires = int(item.get("debounce_window_expires_epoch") or 0)
        if expires > 0 and expires <= now_epoch:
            try:
                _append_state_transition(
                    item,
                    _STATE_QUEUED,
                    "Debounce window expired — promoted to queued",
                    extra={"debounce_expires_epoch": expires, "promoted_at_epoch": now_epoch},
                )
                dispatch_plan_ready = False
                try:
                    item = _ensure_request_dispatch_plan(item, persist=False)
                    dispatches = ((item.get("dispatch_plan") or {}).get("dispatches") or [])
                    dispatch_plan_ready = bool(dispatches)
                except Exception as plan_exc:
                    logger.warning(
                        "dispatch_plan generation failed for promoted request %s: %s",
                        item.get("request_id"),
                        plan_exc,
                    )
                _update_request(item)
                promoted.append(item["request_id"])
                logger.info(
                    "[INFO] promoted intake_received -> queued: %s (dispatch_plan=%s)",
                    item["request_id"],
                    "ready" if dispatch_plan_ready else "missing",
                )
            except Exception as exc:
                logger.warning("failed to promote request %s: %s", item.get("request_id"), exc)

    return promoted


def _decompose_and_create_tracker_artifacts(
    project_id: str,
    initiative_title: str,
    outcomes: Sequence[str],
    request_id: str,
    assigned_to: str,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    meta = _load_project_meta(project_id)
    governance_hash = _compute_governance_hash_local()
    if not governance_hash:
        raise RuntimeError("Missing governance hash")

    acceptance_criteria = [
        f"Outcome {idx}: {outcome}" for idx, outcome in enumerate(outcomes, start=1)
    ]
    invocation_meta = {
        "governance_hash": governance_hash,
        "coordination_request_id": request_id,
        "dispatch_id": dispatch_id or "",
        "provider": provider or "",
        "timestamp": _now_z(),
    }
    meta_json = json.dumps(invocation_meta, sort_keys=True)

    feature_description = (
        f"Coordination decomposition for request {request_id}. "
        f"Initiative: {initiative_title}. "
        f"Invocation metadata: {meta_json}"
    )

    feature_id = _create_tracker_record_auto(
        project_id=project_id,
        prefix=meta.prefix,
        record_type="feature",
        title=f"{initiative_title[:120]} (coordination request)",
        description=feature_description,
        priority="P1",
        assigned_to=assigned_to,
        success_metrics=acceptance_criteria,
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )
    _append_tracker_history(
        feature_id,
        "worklog",
        f"MCP_INVOCATION: {meta_json}",
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )

    task_ids: List[str] = []
    issue_ids: List[str] = []

    for idx, outcome in enumerate(outcomes, start=1):
        task_id = _create_tracker_record_auto(
            project_id=project_id,
            prefix=meta.prefix,
            record_type="task",
            title=f"Execute outcome {idx}: {outcome[:90]}",
            description=(
                f"Generated by coordination request {request_id}. "
                f"Outcome: {outcome}. Invocation metadata: {meta_json}"
            ),
            priority="P1",
            assigned_to=assigned_to,
            related_ids=[feature_id],
            acceptance_criteria=[f"Outcome {idx}: {outcome}"],
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )
        task_ids.append(task_id)
        _append_tracker_history(
            task_id,
            "worklog",
            f"MCP_INVOCATION: {meta_json}",
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )

    issue_ids.append(
        _create_tracker_record_auto(
            project_id=project_id,
            prefix=meta.prefix,
            record_type="issue",
            title=f"Coordination risk tracking for {initiative_title[:80]}",
            description=(
                f"Generated for request {request_id} to track dispatch/callback "
                f"orchestration failures. Invocation metadata: {meta_json}"
            ),
            priority="P1",
            assigned_to=assigned_to,
            severity="high",
            hypothesis=(
                "Asynchronous worker execution may fail or return non-deterministic "
                "completion signals without explicit request-state transitions."
            ),
            related_ids=[feature_id, *task_ids],
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )
    )
    _append_tracker_history(
        issue_ids[0],
        "worklog",
        f"MCP_INVOCATION: {meta_json}",
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )

    _append_tracker_history(
        feature_id,
        "worklog",
        (
            f"Coordination request {request_id} decomposed into {len(task_ids)} tasks "
            f"and {len(issue_ids)} issue(s)."
        ),
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )
    for criterion in acceptance_criteria:
        _append_tracker_history(
            feature_id,
            "worklog",
            f"ACCEPTANCE CRITERIA: {criterion} | metadata={meta_json}",
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )

    return {
        "feature_id": feature_id,
        "task_ids": task_ids,
        "issue_ids": issue_ids,
        "acceptance_criteria": acceptance_criteria,
        "governance_hash": governance_hash,
    }


# ---------------------------------------------------------------------------
# Coordination request persistence helpers
# ---------------------------------------------------------------------------


def _request_key(request_id: str) -> Dict[str, Any]:
    return {"request_id": _serialize(request_id)}


def _append_state_transition(
    request: Dict[str, Any],
    next_state: str,
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    prev = request.get("state")
    if prev not in _TRANSITIONS:
        raise ValueError(f"Unknown current state '{prev}'")
    if next_state not in _TRANSITIONS[prev]:
        raise ValueError(f"Invalid state transition {prev} -> {next_state}")

    now = _now_z()
    transition = {
        "timestamp": now,
        "from": prev,
        "to": next_state,
        "reason": reason,
    }
    if extra:
        transition["meta"] = extra

    history = list(request.get("state_history") or [])
    history.append(transition)

    request["state"] = next_state
    request["state_history"] = history
    request["updated_at"] = now
    request["updated_epoch"] = _unix_now()
    request["sync_version"] = int(request.get("sync_version", 0)) + 1
    transition_meta = extra or {}
    _emit_structured_observability(
        component="coordination_api",
        event="state_transition",
        request_id=str(request.get("request_id") or ""),
        dispatch_id=str(transition_meta.get("dispatch_id") or ""),
        tool_name="state.transition",
        latency_ms=0,
        error_code=str(transition_meta.get("error_code") or transition_meta.get("failure_class") or ""),
        extra={
            "from_state": prev,
            "to_state": next_state,
            "reason": reason,
        },
    )
    return request


def _get_request(request_id: str) -> Optional[Dict[str, Any]]:
    ddb = _get_ddb()
    resp = ddb.get_item(TableName=COORDINATION_TABLE, Key=_request_key(request_id), ConsistentRead=True)
    raw = resp.get("Item")
    if not raw:
        return None
    return _deserialize(raw)


def _put_request(item: Dict[str, Any]) -> None:
    ddb = _get_ddb()
    ddb.put_item(
        TableName=COORDINATION_TABLE,
        Item={k: _serialize(v) for k, v in item.items()},
        ConditionExpression="attribute_not_exists(request_id)",
    )


def _update_request(item: Dict[str, Any]) -> None:
    ddb = _get_ddb()
    ddb.put_item(TableName=COORDINATION_TABLE, Item={k: _serialize(v) for k, v in item.items()})


def _redact_request(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    out.pop("callback_token", None)
    return out


# ---------------------------------------------------------------------------
# SSM dispatch / execution state refresh
# ---------------------------------------------------------------------------


def _build_secret_fetch_commands(
    *,
    provider_label: str,
    secret_id: str,
    exported_var: str,
    exit_code: int,
) -> List[str]:
    escaped_secret_id = json.dumps(secret_id)
    escaped_region = json.dumps(SECRETS_REGION)
    err_file = f"/tmp/coord_secret_err_{provider_label.lower()}.log"
    safe_label = provider_label.upper()

    return [
        "COORD_PREFLIGHT_TS=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"",
        (
            "if ! command -v aws >/dev/null 2>&1; then "
            f"echo '[ERROR] aws cli not found on host-v2 (required for {safe_label} key load)'; "
            f"echo \"COORDINATION_PREFLIGHT_ERROR={{\\\"stage\\\":\\\"provider_secret\\\",\\\"provider\\\":\\\"{provider_label}\\\",\\\"code\\\":\\\"aws_cli_missing\\\",\\\"secret_ref\\\":\\\"{secret_id}\\\",\\\"secret_arn\\\":\\\"{secret_id}\\\",\\\"failure_reason\\\":\\\"aws_cli_missing\\\",\\\"timestamp\\\":\\\"$COORD_PREFLIGHT_TS\\\"}}\"; "
            f"exit {exit_code}; "
            "fi"
        ),
        f"COORD_SECRET_ID={escaped_secret_id}",
        f"COORD_SECRET_REGION={escaped_region}",
        (
            "COORD_SECRET_ARN=\"$(aws --region \"$COORD_SECRET_REGION\" "
            "secretsmanager describe-secret "
            "--secret-id \"$COORD_SECRET_ID\" "
            f"--query ARN --output text 2>{err_file} || true)\""
        ),
        "if [ -z \"$COORD_SECRET_ARN\" ] || [ \"$COORD_SECRET_ARN\" = \"None\" ]; then COORD_SECRET_ARN=\"$COORD_SECRET_ID\"; fi",
        (
            f"COORD_SECRET_VALUE=\"$(aws --region \"$COORD_SECRET_REGION\" "
            "secretsmanager get-secret-value "
            "--secret-id \"$COORD_SECRET_ID\" "
            "--query SecretString --output text "
            f"2>{err_file} || true)\""
        ),
        (
            "if [ -z \"$COORD_SECRET_VALUE\" ] || [ \"$COORD_SECRET_VALUE\" = \"None\" ]; then "
            f"echo '[ERROR] failed to load {safe_label} key from Secrets Manager'; "
            f"if [ -s {err_file} ]; then tail -n 5 {err_file}; fi; "
            f"echo \"COORDINATION_PREFLIGHT_ERROR={{\\\"stage\\\":\\\"provider_secret\\\",\\\"provider\\\":\\\"{provider_label}\\\",\\\"code\\\":\\\"secret_fetch_failed\\\",\\\"secret_ref\\\":\\\"{secret_id}\\\",\\\"secret_arn\\\":\\\"$COORD_SECRET_ARN\\\",\\\"failure_reason\\\":\\\"secret_fetch_failed\\\",\\\"timestamp\\\":\\\"$COORD_PREFLIGHT_TS\\\"}}\"; "
            f"exit {exit_code}; "
            "fi"
        ),
        f"export {exported_var}=\"$COORD_SECRET_VALUE\"",
        "unset COORD_SECRET_VALUE",
        "unset COORD_SECRET_ARN",
        "unset COORD_SECRET_ID",
        "unset COORD_SECRET_REGION",
        "unset COORD_PREFLIGHT_TS",
        f"rm -f {err_file}",
        "echo 'COORDINATION_PREFLIGHT_PROVIDER_SECRET=pass'",
    ]


def _providers_for_execution_mode(execution_mode: str) -> List[str]:
    if execution_mode in {"codex_full_auto", "codex_app_server"}:
        return ["openai"]
    if execution_mode in {"claude_headless", "claude_agent_sdk"}:
        return ["anthropic"]
    if execution_mode == "bedrock_agent":
        return []  # Bedrock uses IAM role, no API key secrets needed
    return ["openai", "anthropic"]


def _build_dispatch_payload_commands(request: Dict[str, Any], execution_mode: str, dispatch_id: str) -> List[str]:
    provider_refs: List[str] = []
    providers = _providers_for_execution_mode(execution_mode)
    if "openai" in providers and OPENAI_API_KEY_SECRET_ID:
        provider_refs.append(OPENAI_API_KEY_SECRET_ID)
    if "anthropic" in providers and ANTHROPIC_API_KEY_SECRET_ID:
        provider_refs.append(ANTHROPIC_API_KEY_SECRET_ID)

    payload = {
        "coordination_request_id": request["request_id"],
        "dispatch_id": dispatch_id,
        "project_id": request["project_id"],
        "execution_mode": execution_mode,
        "provider_secret_refs": provider_refs,
        "enceladus_mcp_profile_installer": HOST_V2_ENCELADUS_MCP_INSTALLER,
        "enceladus_mcp_bootstrap_mode": "setup_if_missing_once",
        "enceladus_mcp_profile_path": HOST_V2_MCP_PROFILE_PATH,
        "enceladus_mcp_marker_path": HOST_V2_MCP_MARKER_PATH,
        "enceladus_mcp_bootstrap_max_attempts": HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return [
        f"export COORDINATION_REQUEST_ID={json.dumps(request['request_id'])}",
        f"export COORDINATION_DISPATCH_ID={json.dumps(dispatch_id)}",
        f"export COORDINATION_EXECUTION_MODE={json.dumps(execution_mode)}",
        "export COORDINATION_DISPATCH_PAYLOAD_PATH=/tmp/coordination_dispatch_payload.json",
        f"printf %s {shlex.quote(payload_json)} > \"$COORDINATION_DISPATCH_PAYLOAD_PATH\"",
        "echo COORDINATION_DISPATCH_PAYLOAD=$(cat \"$COORDINATION_DISPATCH_PAYLOAD_PATH\")",
        (
            "echo \"{\\\"timestamp\\\":\\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\","
            "\\\"component\\\":\\\"worker_runtime\\\",\\\"event\\\":\\\"dispatch_start\\\","
            "\\\"request_id\\\":\\\"$COORDINATION_REQUEST_ID\\\",\\\"dispatch_id\\\":\\\"$COORDINATION_DISPATCH_ID\\\","
            "\\\"tool_name\\\":\\\"worker_runtime\\\",\\\"latency_ms\\\":0,\\\"error_code\\\":\\\"\\\"}\""
        ),
    ]


def _build_mcp_profile_bootstrap_commands() -> List[str]:
    installer_candidates: List[str] = []
    for candidate in (
        HOST_V2_ENCELADUS_MCP_INSTALLER,
        "tools/enceladus-mcp-server/install_profile.sh",
        "projects/enceladus/repo/tools/enceladus-mcp-server/install_profile.sh",
        "projects/enceladus/tools/enceladus-mcp-server/install_profile.sh",
        "projects/devops/tools/enceladus-mcp-server/install_profile.sh",
    ):
        normalized = str(candidate or "").strip()
        if normalized and normalized not in installer_candidates:
            installer_candidates.append(normalized)

    retry_backoffs = [int(v) for v in HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS if int(v) >= 0]
    if not retry_backoffs:
        retry_backoffs = [2, 5, 10]
    max_attempts = max(1, HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS)
    log_path = "/tmp/coordination-mcp-profile.log"

    return [
        f"COORD_MCP_INSTALLER_CANDIDATES_JSON={shlex.quote(json.dumps(installer_candidates, separators=(',', ':')))}",
        f"COORD_MCP_PROFILE_PATH_RAW={json.dumps(HOST_V2_MCP_PROFILE_PATH)}",
        f"COORD_MCP_MARKER_PATH_RAW={json.dumps(HOST_V2_MCP_MARKER_PATH)}",
        (
            "case \"$COORD_MCP_PROFILE_PATH_RAW\" in "
            "/*) COORD_MCP_PROFILE_PATH=\"$COORD_MCP_PROFILE_PATH_RAW\" ;; "
            "*) COORD_MCP_PROFILE_PATH=\"$HOME/$COORD_MCP_PROFILE_PATH_RAW\" ;; "
            "esac"
        ),
        (
            "case \"$COORD_MCP_MARKER_PATH_RAW\" in "
            "/*) COORD_MCP_MARKER_PATH=\"$COORD_MCP_MARKER_PATH_RAW\" ;; "
            "*) COORD_MCP_MARKER_PATH=\"$HOME/$COORD_MCP_MARKER_PATH_RAW\" ;; "
            "esac"
        ),
        "COORD_MCP_SKIP_INSTALL=0",
        (
            "if [ -f \"$COORD_MCP_PROFILE_PATH\" ] "
            "&& grep -q '\"enceladus\"' \"$COORD_MCP_PROFILE_PATH\" 2>/dev/null "
            "&& [ -f \"$COORD_MCP_MARKER_PATH\" ]; then "
            "COORD_MCP_SKIP_INSTALL=1; "
            "echo 'COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=warm_skip'; "
            "fi"
        ),
        "COORD_MCP_INSTALLER=''",
        (
            "if [ \"$COORD_MCP_SKIP_INSTALL\" -eq 0 ]; then "
            "COORD_MCP_INSTALLER=$(python3 -c "
            "'import json,os,sys; "
            "c=json.loads(sys.argv[1]); "
            "print(next((x for x in c if os.path.isfile(x) and os.access(x, os.X_OK)), \"\"))' "
            "\"$COORD_MCP_INSTALLER_CANDIDATES_JSON\"); "
            "fi"
        ),
        (
            "if [ \"$COORD_MCP_SKIP_INSTALL\" -eq 0 ] && [ -z \"$COORD_MCP_INSTALLER\" ]; then "
            "echo '[ERROR] Enceladus MCP installer not found or not executable'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'mcp', 'code': 'installer_missing'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 23; "
            "fi"
        ),
        f"COORD_MCP_BOOTSTRAP_MAX_ATTEMPTS={max_attempts}",
        (
            f"COORD_MCP_BOOTSTRAP_BACKOFFS={json.dumps(' '.join(str(v) for v in retry_backoffs))}"
        ),
        f"COORD_MCP_PROFILE_LOG={log_path}",
        "COORD_MCP_BOOTSTRAP_DONE=0",
        "COORD_MCP_ATTEMPT=1",
        (
            "if [ \"$COORD_MCP_SKIP_INSTALL\" -eq 0 ]; then "
            "while [ \"$COORD_MCP_ATTEMPT\" -le \"$COORD_MCP_BOOTSTRAP_MAX_ATTEMPTS\" ]; do "
            "if \"$COORD_MCP_INSTALLER\" >\"$COORD_MCP_PROFILE_LOG\" 2>&1; then "
            "COORD_MCP_BOOTSTRAP_DONE=1; break; "
            "fi; "
            "tail -n 40 \"$COORD_MCP_PROFILE_LOG\" || true; "
            "if [ \"$COORD_MCP_ATTEMPT\" -lt \"$COORD_MCP_BOOTSTRAP_MAX_ATTEMPTS\" ]; then "
            "COORD_MCP_BACKOFF=$(python3 -c "
            "'import sys; vals=[int(v) for v in (sys.argv[1] or \"\").split() if v.strip()]; "
            "idx=max(0,min(int(sys.argv[2])-1,len(vals)-1)); "
            "print(vals[idx] if vals else 2)' "
            "\"$COORD_MCP_BOOTSTRAP_BACKOFFS\" \"$COORD_MCP_ATTEMPT\"); "
            "echo \"[WARNING] Enceladus MCP profile bootstrap failed (attempt $COORD_MCP_ATTEMPT); retrying in $COORD_MCP_BACKOFF s\"; "
            "sleep \"$COORD_MCP_BACKOFF\"; "
            "fi; "
            "COORD_MCP_ATTEMPT=$((COORD_MCP_ATTEMPT + 1)); "
            "done; "
            "fi"
        ),
        (
            "if [ \"$COORD_MCP_SKIP_INSTALL\" -eq 0 ] && [ \"$COORD_MCP_BOOTSTRAP_DONE\" -ne 1 ]; then "
            "echo '[ERROR] Enceladus MCP profile bootstrap failed'; "
            "tail -n 40 \"$COORD_MCP_PROFILE_LOG\" || true; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'mcp', 'code': 'bootstrap_failed'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 24; "
            "fi"
        ),
        (
            "if [ ! -f \"$COORD_MCP_PROFILE_PATH\" ] || ! grep -q '\"enceladus\"' \"$COORD_MCP_PROFILE_PATH\"; then "
            "echo '[ERROR] Enceladus MCP profile validation failed'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'mcp', 'code': 'profile_missing'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 25; "
            "fi"
        ),
        (
            "if [ \"$COORD_MCP_SKIP_INSTALL\" -eq 0 ]; then "
            "mkdir -p \"$(dirname \"$COORD_MCP_MARKER_PATH\")\"; "
            "printf '{\"installed_at\":\"%s\",\"installer\":\"%s\",\"profile\":\"%s\"}\\n' "
            "\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$COORD_MCP_INSTALLER\" \"$COORD_MCP_PROFILE_PATH\" "
            "> \"$COORD_MCP_MARKER_PATH\"; "
            "echo 'COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=cold_install'; "
            "else "
            "echo 'COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=warm_skip'; "
            "fi"
        ),
        f"echo {shlex.quote('COORDINATION_PREFLIGHT_OK=' + json.dumps({'stage': 'mcp', 'status': 'ok'}, sort_keys=True, separators=(',', ':')))}",
    ]


def _build_provider_rotation_check_commands(execution_mode: str) -> List[str]:
    providers = ",".join(_providers_for_execution_mode(execution_mode))
    script = HOST_V2_PROVIDER_CHECK_SCRIPT
    fallback = "tools/agentcli-host-v2/provider_rotation_check.py"
    return [
        f"COORD_PROVIDER_CHECK_SCRIPT={json.dumps(script)}",
        f"COORD_PROVIDER_CHECK_PROVIDERS={json.dumps(providers)}",
        (
            "if [ -f \"$COORD_PROVIDER_CHECK_SCRIPT\" ]; then "
            "COORD_PROVIDER_CHECK_OUTPUT=\"$(python3 \"$COORD_PROVIDER_CHECK_SCRIPT\" --format json --providers "
            "\"$COORD_PROVIDER_CHECK_PROVIDERS\" --region "
            f"{SECRETS_REGION} 2>/tmp/coord_provider_check.err || true)\"; "
            f"elif [ -f {json.dumps(fallback)} ]; then "
            "COORD_PROVIDER_CHECK_OUTPUT=\"$("
            f"python3 {json.dumps(fallback)} --format json --providers \"$COORD_PROVIDER_CHECK_PROVIDERS\" "
            f"--region {SECRETS_REGION} 2>/tmp/coord_provider_check.err || true)\"; "
            "else "
            "echo '[ERROR] provider rotation check script not found on host-v2'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'provider_preflight', 'code': 'script_missing'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 21; "
            "fi"
        ),
        (
            "if [ -z \"$COORD_PROVIDER_CHECK_OUTPUT\" ]; then "
            "echo '[ERROR] provider preflight returned empty output'; "
            "if [ -s /tmp/coord_provider_check.err ]; then tail -n 20 /tmp/coord_provider_check.err; fi; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'provider_preflight', 'code': 'empty_output'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 22; "
            "fi"
        ),
        "echo COORDINATION_PROVIDER_PREFLIGHT=$COORD_PROVIDER_CHECK_OUTPUT",
        (
            "python3 -c \"import json,sys; data=json.loads(sys.argv[1]); "
            "sys.exit(0 if data.get('passed') else 1)\" \"$COORD_PROVIDER_CHECK_OUTPUT\" "
            "|| (echo '[ERROR] provider preflight failed'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'provider_preflight', 'code': 'providers_failed'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 22)"
        ),
        f"echo {shlex.quote('COORDINATION_PREFLIGHT_OK=' + json.dumps({'stage': 'provider_preflight', 'status': 'ok'}, sort_keys=True, separators=(',', ':')))}",
    ]


def _normalize_rotation_tags(raw_tags: Any) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    if not isinstance(raw_tags, list):
        return tags
    for entry in raw_tags:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("Key") or "").strip()
        value = str(entry.get("Value") or "").strip()
        if key:
            tags[key] = value
    return tags


def _iso_days_until(timestamp: str) -> Optional[int]:
    if not timestamp:
        return None
    try:
        due = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    return int((due - now).total_seconds() // 86_400)


def _provider_secret_status(provider: str, secret_id: str) -> Dict[str, Any]:
    status = {
        "provider": provider,
        "secret_ref": secret_id,
        "secret_ref_configured": bool(secret_id),
        "secret_status": "missing",
        "secret_arn": None,
        "rotation_policy": None,
        "last_rotated": None,
        "next_rotation_due": None,
        "days_until_rotation_due": None,
        "rotation_warning": None,
    }
    if not secret_id:
        return status
    try:
        resp = _get_secretsmanager().describe_secret(SecretId=secret_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code == "ResourceNotFoundException":
            status["secret_status"] = "missing"
        else:
            status["secret_status"] = "error"
        status["error"] = code
        return status
    except BotoCoreError:
        status["secret_status"] = "error"
        status["error"] = "BotoCoreError"
        return status

    tags = _normalize_rotation_tags(resp.get("Tags"))
    status["secret_arn"] = resp.get("ARN")
    status["secret_status"] = "active"
    status["rotation_policy"] = tags.get("rotation_policy")
    status["last_rotated"] = tags.get("last_rotated")
    status["next_rotation_due"] = tags.get("next_rotation_due")
    days = _iso_days_until(tags.get("next_rotation_due", ""))
    status["days_until_rotation_due"] = days
    if days is not None:
        if days < 0:
            status["secret_status"] = "expired"
        status["rotation_warning"] = days <= ROTATION_WARNING_DAYS
    return status


def _provider_secret_readiness() -> Dict[str, Dict[str, Any]]:
    return {
        "openai_codex": _provider_secret_status("openai_codex", OPENAI_API_KEY_SECRET_ID),
        "claude_agent_sdk": _provider_secret_status("claude_agent_sdk", ANTHROPIC_API_KEY_SECRET_ID),
    }


def _extract_provider_api_key(provider: str, secret_string: str) -> Optional[str]:
    raw = str(secret_string or "").strip()
    if not raw:
        return None
    if raw.startswith("{") and raw.endswith("}"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        candidates = (
            ("api_key", "key", "token", "openai_api_key")
            if provider == "openai"
            else ("api_key", "anthropic_api_key", "key", "token")
        )
        for field in candidates:
            value = payload.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None
    return raw


def _provider_health_probe(provider: str, api_key: str, timeout_seconds: int) -> Tuple[bool, str]:
    if provider == "openai":
        url = "https://api.openai.com/v1/models"
        headers = {"Authorization": f"Bearer {api_key}"}
    elif provider == "anthropic":
        url = "https://api.anthropic.com/v1/models"
        headers = {"x-api-key": api_key, "anthropic-version": ANTHROPIC_API_VERSION}
    else:
        return False, "unsupported_provider"

    req = urllib.request.Request(url=url, method="GET", headers=headers)
    context = ssl.create_default_context(cafile=_CERT_BUNDLE) if _CERT_BUNDLE else None
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds, context=context) as resp:
            code = int(getattr(resp, "status", 0) or 0)
        if 200 <= code < 300:
            return True, f"http_{code}"
        return False, f"http_{code}"
    except urllib.error.HTTPError as exc:
        return False, f"http_{exc.code}"
    except urllib.error.URLError as exc:
        return False, f"url_error:{exc.reason}"
    except Exception as exc:  # pragma: no cover
        return False, f"unexpected:{exc.__class__.__name__}"


def _provider_preflight_fetch_and_probe(
    provider: str,
    secret_id: str,
    timeout_seconds: int = 5,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "provider": provider,
        "secret_ref": secret_id,
        "secret_arn": secret_id,
        "checked_at": _now_z(),
        "timeout_seconds": timeout_seconds,
        "ok": False,
        "failure_reason": None,
        "health_check": None,
    }
    try:
        meta = _get_secretsmanager().describe_secret(SecretId=secret_id)
        result["secret_arn"] = str(meta.get("ARN") or secret_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        result["failure_reason"] = f"describe_secret_failed:{code}"
        return result
    except BotoCoreError:
        result["failure_reason"] = "describe_secret_failed:BotoCoreError"
        return result

    try:
        secret_string = (
            _get_secretsmanager().get_secret_value(SecretId=secret_id).get("SecretString") or ""
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        result["failure_reason"] = f"secret_fetch_failed:{code}"
        return result
    except BotoCoreError:
        result["failure_reason"] = "secret_fetch_failed:BotoCoreError"
        return result

    api_key = _extract_provider_api_key(provider, str(secret_string))
    if not api_key:
        result["failure_reason"] = "secret_value_missing_api_key"
        return result

    ok, health = _provider_health_probe(provider, api_key, timeout_seconds)
    result["ok"] = ok
    result["health_check"] = health
    if not ok:
        result["failure_reason"] = f"provider_health_failed:{health}"
    return result


def _lambda_provider_preflight(execution_mode: str, timeout_seconds: int = 5) -> Dict[str, Any]:
    providers = _providers_for_execution_mode(execution_mode)
    secret_by_provider = {
        "openai": OPENAI_API_KEY_SECRET_ID,
        "anthropic": ANTHROPIC_API_KEY_SECRET_ID,
    }
    results = [
        _provider_preflight_fetch_and_probe(provider, secret_by_provider[provider], timeout_seconds)
        for provider in providers
    ]
    return {
        "checked_at": _now_z(),
        "timeout_seconds": timeout_seconds,
        "passed": all(item.get("ok") for item in results),
        "results": results,
    }


def _fetch_provider_api_key(provider: str, secret_id: str) -> str:
    if not secret_id:
        raise RuntimeError(f"Missing secret reference for provider '{provider}'")
    try:
        secret_string = (
            _get_secretsmanager().get_secret_value(SecretId=secret_id).get("SecretString") or ""
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        raise RuntimeError(f"Provider secret fetch failed ({provider}): {code}") from exc
    except BotoCoreError as exc:
        raise RuntimeError(f"Provider secret fetch failed ({provider}): {exc.__class__.__name__}") from exc

    api_key = _extract_provider_api_key(provider, str(secret_string))
    if not api_key:
        raise RuntimeError(f"Provider secret missing API key value ({provider})")
    return api_key


def _coerce_openai_max_output_tokens(raw: Any) -> Optional[int]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return min(max(value, OPENAI_MAX_OUTPUT_TOKENS_MIN), OPENAI_MAX_OUTPUT_TOKENS_MAX)


def _prepend_managed_session_bootstrap(prompt: str, project_id: str) -> str:
    project = str(project_id or "").strip()
    base_prompt = str(prompt or "").strip()
    if not project:
        return base_prompt
    bootstrap = f"agents.md project={project}"
    if base_prompt.startswith(bootstrap):
        return base_prompt
    if not base_prompt:
        return bootstrap
    return f"{bootstrap}\n\n{base_prompt}"


def _read_mcp_resource_text(uri: str) -> str:
    uri = str(uri or "").strip()
    if not uri:
        return ""

    cached = _MCP_RESOURCE_CACHE.get(uri)
    if cached is not None:
        return cached

    text = ""
    try:
        module = _load_mcp_server_module()
        read_resource = getattr(module, "read_resource", None)
        if callable(read_resource):
            value = asyncio.run(read_resource(uri))
            if isinstance(value, str):
                text = value
    except Exception as exc:
        logger.warning("[WARNING] unable to read MCP resource %s: %s", uri, exc)

    text = str(text or "")
    _MCP_RESOURCE_CACHE[uri] = text
    return text


def _list_mcp_governance_resource_uris() -> List[str]:
    try:
        module = _load_mcp_server_module()
        list_resources = getattr(module, "list_resources", None)
        if not callable(list_resources):
            raise RuntimeError("list_resources is unavailable")
        payload = asyncio.run(list_resources())
    except Exception as exc:
        logger.warning("[WARNING] unable to list MCP governance resources dynamically: %s", exc)
        return list(GOVERNANCE_PROMPT_RESOURCE_URIS_FALLBACK)

    uris: List[str] = []
    for item in payload or []:
        uri = getattr(item, "uri", None)
        if uri is None and isinstance(item, dict):
            uri = item.get("uri")
        uri = str(uri or "").strip()
        if uri.startswith("governance://"):
            uris.append(uri)

    if not uris:
        return list(GOVERNANCE_PROMPT_RESOURCE_URIS_FALLBACK)

    # Keep bootstrap anchor first, then deterministic sort for all remaining URIs.
    ordered = sorted(set(uris))
    if "governance://agents.md" in ordered:
        ordered.remove("governance://agents.md")
        ordered.insert(0, "governance://agents.md")
    return ordered


def _build_mcp_governance_context(project_id: str) -> Dict[str, Any]:
    project = str(project_id or "").strip()
    if not ENABLE_MCP_GOVERNANCE_PROMPT:
        return {
            "loaded": False,
            "source": "disabled",
            "included_uris": [],
            "truncated": False,
            "text": "",
        }
    if not project:
        return {
            "loaded": False,
            "source": "project_missing",
            "included_uris": [],
            "truncated": False,
            "text": "",
        }

    max_chars = max(5000, GOVERNANCE_PROMPT_MAX_CHARS)
    chunks: List[str] = []
    included_uris: List[str] = []
    total_chars = 0
    truncated = False

    for uri in _list_mcp_governance_resource_uris():
        body = _read_mcp_resource_text(uri).strip()
        if not body:
            continue
        chunk = f"### {uri}\n{body}"
        projected = total_chars + len(chunk) + 2
        if projected > max_chars:
            remaining = max_chars - total_chars
            if remaining > 500:
                body_budget = max(0, remaining - len(uri) - 30)
                chunk = f"### {uri}\n{body[:body_budget]}\n[TRUNCATED]"
                chunks.append(chunk)
                included_uris.append(uri)
            truncated = True
            break
        chunks.append(chunk)
        included_uris.append(uri)
        total_chars += len(chunk) + 2

    if not chunks:
        return {
            "loaded": False,
            "source": "mcp_resources",
            "included_uris": [],
            "truncated": False,
            "text": "",
        }

    bundle = (
        "Authoritative governance context loaded via Enceladus MCP resources.\n"
        "Follow this bundle as policy for this managed dispatch.\n\n"
        + "\n\n".join(chunks)
    )
    return {
        "loaded": True,
        "source": "mcp_resources",
        "included_uris": included_uris,
        "truncated": truncated,
        "text": bundle,
    }


def _build_managed_session_prompt(prompt: str, project_id: str) -> Tuple[str, Dict[str, Any]]:
    project = str(project_id or "").strip()
    task_prompt = str(prompt or "").strip()
    fallback_prompt = _prepend_managed_session_bootstrap(task_prompt, project)

    governance = _build_mcp_governance_context(project)
    if not governance.get("loaded"):
        return fallback_prompt, governance

    bootstrap = f"agents.md project={project}" if project else ""
    parts: List[str] = []
    if bootstrap:
        parts.append(bootstrap)
    parts.append(governance.get("text", ""))
    if task_prompt:
        parts.append(f"Dispatch task:\n{task_prompt}")

    return "\n\n".join(part for part in parts if part), governance


def _normalize_openai_schema(schema: Any) -> Any:
    if isinstance(schema, dict):
        normalized: Dict[str, Any] = {}
        for key, value in schema.items():
            if key == "properties" and isinstance(value, dict):
                normalized[key] = {str(prop): _normalize_openai_schema(prop_schema) for prop, prop_schema in value.items()}
                continue
            if key in {"allOf", "anyOf", "oneOf", "prefixItems"} and isinstance(value, list):
                normalized[key] = [_normalize_openai_schema(item) for item in value]
                continue
            if isinstance(value, (dict, list)):
                normalized[key] = _normalize_openai_schema(value)
                continue
            normalized[key] = value

        schema_type = normalized.get("type")
        has_properties = isinstance(normalized.get("properties"), dict)
        is_object_type = schema_type == "object" or (
            isinstance(schema_type, list) and "object" in {str(item) for item in schema_type}
        )
        if (has_properties or is_object_type) and "additionalProperties" not in normalized:
            normalized["additionalProperties"] = False
        return normalized
    if isinstance(schema, list):
        return [_normalize_openai_schema(item) for item in schema]
    return schema


def _coerce_openai_json_schema_format(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    schema = raw.get("schema")
    if not isinstance(schema, dict):
        return None
    normalized_schema = _normalize_openai_schema(schema)
    name = str(raw.get("name") or "coordination_response").strip() or "coordination_response"
    formatted: Dict[str, Any] = {
        "type": "json_schema",
        "name": name[:120],
        "schema": normalized_schema,
    }
    strict = raw.get("strict")
    if isinstance(strict, bool):
        formatted["strict"] = strict
    return formatted


def _coerce_openai_text_format(constraints: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    json_schema = constraints.get("json_schema")
    if isinstance(json_schema, dict):
        formatted = _coerce_openai_json_schema_format(json_schema)
        if formatted:
            return formatted

    response_format = constraints.get("response_format")
    if not isinstance(response_format, dict):
        return None

    if response_format.get("type") == "json_schema":
        nested = response_format.get("json_schema")
        candidate = nested if isinstance(nested, dict) else response_format
        return _coerce_openai_json_schema_format(candidate)

    nested_schema = response_format.get("json_schema")
    if isinstance(nested_schema, dict):
        return _coerce_openai_json_schema_format(nested_schema)
    return None


def _coerce_openai_tools(constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []

    raw_tools = constraints.get("tools")
    if isinstance(raw_tools, list):
        for item in raw_tools:
            if isinstance(item, dict) and isinstance(item.get("type"), str):
                tools.append(dict(item))

    raw_functions = constraints.get("functions")
    if isinstance(raw_functions, list):
        for item in raw_functions:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            parameters = item.get("parameters")
            if not isinstance(parameters, dict):
                parameters = {"type": "object", "properties": {}, "additionalProperties": False}
            else:
                parameters = _normalize_openai_schema(parameters)
            function_tool: Dict[str, Any] = {
                "type": "function",
                "name": name[:120],
                "parameters": parameters,
            }
            description = item.get("description")
            if isinstance(description, str) and description.strip():
                function_tool["description"] = description.strip()[:500]
            strict = item.get("strict")
            if isinstance(strict, bool):
                function_tool["strict"] = strict
            tools.append(function_tool)

    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for tool in tools:
        try:
            key = json.dumps(tool, sort_keys=True, default=str)
        except Exception:
            key = str(tool)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(tool)
    return deduped


def _extract_openai_text_response(response_payload: Dict[str, Any]) -> str:
    top_level_text = response_payload.get("output_text")
    if isinstance(top_level_text, str) and top_level_text.strip():
        return top_level_text.strip()[:2000]

    chunks: List[str] = []
    output = response_payload.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                block_type = str(block.get("type") or "").strip().lower()
                if block_type not in {"output_text", "text"}:
                    continue
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    chunks.append(text.strip())
    if chunks:
        return "\n".join(chunks)[:2000]

    fallback = str(response_payload.get("summary") or response_payload.get("status") or "").strip()
    return fallback[:2000]


def _dispatch_openai_codex_api(
    request: Dict[str, Any],
    prompt: Optional[str],
    dispatch_id: str,
    execution_mode: str = "codex_app_server",
) -> Dict[str, Any]:
    provider_session = request.get("provider_session") or {}
    model = str(provider_session.get("model") or DEFAULT_OPENAI_CODEX_MODEL).strip() or DEFAULT_OPENAI_CODEX_MODEL

    resolved_prompt = str(prompt or "").strip()
    if not resolved_prompt:
        initiative = str(request.get("initiative_title") or "").strip()
        outcomes = [str(item).strip() for item in (request.get("outcomes") or []) if str(item).strip()]
        lines = []
        if initiative:
            lines.append(f"Initiative: {initiative}")
        if outcomes:
            lines.append("Outcomes:")
            lines.extend(f"- {item}" for item in outcomes)
        resolved_prompt = "\n".join(lines).strip()
    if not resolved_prompt:
        raise RuntimeError(f"Missing prompt for {execution_mode} dispatch")
    resolved_prompt, governance_context = _build_managed_session_prompt(
        resolved_prompt,
        str(request.get("project_id") or ""),
    )

    constraints = request.get("constraints")
    if not isinstance(constraints, dict):
        constraints = {}

    request_body: Dict[str, Any] = {
        "model": model,
        "input": resolved_prompt,
    }

    max_output_tokens = _coerce_openai_max_output_tokens(
        constraints.get("max_output_tokens", constraints.get("max_tokens"))
    )
    if max_output_tokens is not None:
        request_body["max_output_tokens"] = max_output_tokens

    text_format = _coerce_openai_text_format(constraints)
    if text_format:
        request_body["text"] = {"format": text_format}

    tools = _coerce_openai_tools(constraints)
    if tools:
        request_body["tools"] = tools

    tool_choice = constraints.get("tool_choice")
    if isinstance(tool_choice, (str, dict)):
        request_body["tool_choice"] = tool_choice

    parallel_tool_calls = constraints.get("parallel_tool_calls")
    if isinstance(parallel_tool_calls, bool):
        request_body["parallel_tool_calls"] = parallel_tool_calls

    conversation = (
        provider_session.get("conversation_id")
        or provider_session.get("thread_id")
        or provider_session.get("session_id")
    )
    if isinstance(conversation, str) and conversation.strip():
        request_body["conversation"] = conversation.strip()

    previous_response_id = (
        provider_session.get("provider_session_id")
        or provider_session.get("previous_response_id")
        or provider_session.get("fork_from_session_id")
        or provider_session.get("fork_from_thread_id")
    )
    if isinstance(previous_response_id, str) and previous_response_id.strip():
        request_body["previous_response_id"] = previous_response_id.strip()

    metadata: Dict[str, str] = {}
    for key, value in (
        ("coordination_request_id", request.get("request_id")),
        ("dispatch_id", dispatch_id),
        ("project_id", request.get("project_id")),
    ):
        if value not in (None, ""):
            metadata[key] = str(value)[:240]
    if governance_context.get("loaded"):
        metadata["governance_source"] = str(governance_context.get("source") or "mcp_resources")[:64]
        metadata["governance_resources"] = str(len(governance_context.get("included_uris") or []))
        metadata["governance_truncated"] = "true" if governance_context.get("truncated") else "false"
    if metadata:
        request_body["metadata"] = metadata

    api_key = _fetch_provider_api_key("openai", OPENAI_API_KEY_SECRET_ID)
    endpoint = f"{OPENAI_API_BASE_URL.rstrip('/')}/v1/responses"
    request_json = json.dumps(request_body).encode("utf-8")
    started_at = _now_z()
    started = time.perf_counter()
    headers = {
        "Authorization": f"Bearer {api_key}",
        "content-type": "application/json",
    }
    if OPENAI_API_ORGANIZATION:
        headers["OpenAI-Organization"] = OPENAI_API_ORGANIZATION
    if OPENAI_API_PROJECT:
        headers["OpenAI-Project"] = OPENAI_API_PROJECT

    req = urllib.request.Request(
        url=endpoint,
        method="POST",
        data=request_json,
        headers=headers,
    )
    context = ssl.create_default_context(cafile=_CERT_BUNDLE) if _CERT_BUNDLE else None
    try:
        with urllib.request.urlopen(req, timeout=OPENAI_API_TIMEOUT_SECONDS, context=context) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            raw_body = resp.read().decode("utf-8", errors="replace")
            response_headers = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body[:400] if body else str(exc)
        _emit_structured_observability(
            component="coordination_api",
            event="dispatch_openai_codex_api",
            request_id=str(request.get("request_id") or ""),
            dispatch_id=dispatch_id,
            tool_name="openai.responses.create",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=f"http_{exc.code}",
            extra={"execution_mode": execution_mode},
        )
        raise RuntimeError(f"OpenAI Responses request failed (http_{exc.code}): {message}") from exc
    except urllib.error.URLError as exc:
        _emit_structured_observability(
            component="coordination_api",
            event="dispatch_openai_codex_api",
            request_id=str(request.get("request_id") or ""),
            dispatch_id=dispatch_id,
            tool_name="openai.responses.create",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code="url_error",
            extra={"execution_mode": execution_mode, "reason": str(exc.reason)},
        )
        raise RuntimeError(f"OpenAI Responses request failed: {exc.reason}") from exc

    if status < 200 or status >= 300:
        raise RuntimeError(f"OpenAI Responses request returned http_{status}")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenAI Responses payload was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("OpenAI Responses payload is not an object")
    if isinstance(payload.get("error"), dict):
        error_type = str(payload["error"].get("type") or "unknown")
        error_message = str(payload["error"].get("message") or "Unknown OpenAI error")
        raise RuntimeError(f"OpenAI Responses API error ({error_type}): {error_message}")

    response_status = str(payload.get("status") or "completed").strip().lower()
    terminal_state = "succeeded"
    if response_status in {"cancelled", "canceled"}:
        terminal_state = "cancelled"
    elif response_status not in {"completed", "succeeded"}:
        terminal_state = "failed"

    summary = _extract_openai_text_response(payload)
    if not summary:
        summary = (
            "OpenAI Responses request completed"
            if terminal_state == "succeeded"
            else f"OpenAI Responses request {response_status or 'failed'}"
        )

    completed_at = _now_z()
    execution_id = str(payload.get("id") or f"resp-{uuid.uuid4().hex[:16]}")
    conversation_id = str(payload.get("conversation") or request_body.get("conversation") or "")
    request_id_header = str(
        response_headers.get("x-request-id")
        or response_headers.get("request-id")
        or response_headers.get("openai-request-id")
        or ""
    )
    provider_result: Dict[str, Any] = {
        "provider": "openai_codex",
        "session_id": conversation_id or execution_id,
        "thread_id": conversation_id or execution_id,
        "provider_session_id": execution_id,
        "previous_response_id": request_body.get("previous_response_id"),
        "fork_from_session_id": provider_session.get("fork_from_session_id")
        or provider_session.get("fork_from_thread_id"),
        "model": str(payload.get("model") or model),
        "response_status": response_status,
        "usage": payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
        "summary": summary[:2000],
        "request_id": request_id_header,
        "completed_at": completed_at,
    }
    if isinstance(payload.get("incomplete_details"), dict):
        provider_result["incomplete_details"] = payload.get("incomplete_details")
    if text_format:
        provider_result["requested_text_format"] = text_format
    if tools:
        provider_result["requested_tools"] = [tool.get("name") or tool.get("type") for tool in tools]
    provider_result["governance_context"] = {
        "loaded": bool(governance_context.get("loaded")),
        "source": str(governance_context.get("source") or "prompt_bootstrap_only"),
        "resource_count": len(governance_context.get("included_uris") or []),
        "truncated": bool(governance_context.get("truncated")),
        "resources": list(governance_context.get("included_uris") or []),
    }

    _emit_structured_observability(
        component="coordination_api",
        event="dispatch_openai_codex_api",
        request_id=str(request.get("request_id") or ""),
        dispatch_id=dispatch_id,
            tool_name="openai.responses.create",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code="",
        extra={
            "execution_mode": execution_mode,
            "model": provider_result["model"],
            "response_status": response_status,
            "request_id_header": request_id_header,
            "response_id": execution_id,
            "governance_loaded": bool(governance_context.get("loaded")),
            "governance_resource_count": len(governance_context.get("included_uris") or []),
        },
    )
    return {
        "dispatch_id": dispatch_id,
        "execution_id": execution_id,
        "execution_mode": execution_mode,
        "provider": "openai_codex",
        "transport": "openai_responses_api",
        "api_endpoint": endpoint,
        "project_id": request.get("project_id"),
        "coordination_request_id": request.get("request_id"),
        "provider_secret_refs": [OPENAI_API_KEY_SECRET_ID] if OPENAI_API_KEY_SECRET_ID else [],
        "sent_at": started_at,
        "completed_at": completed_at,
        "status": terminal_state,
        "provider_result": provider_result,
    }


def _extract_claude_text_response(message_payload: Dict[str, Any]) -> str:
    content = message_payload.get("content")
    chunks: List[str] = []
    thinking_chunks: List[str] = []
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "thinking":
                thinking = item.get("thinking")
                if isinstance(thinking, str) and thinking.strip():
                    thinking_chunks.append(thinking.strip())
            elif item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    chunks.append(text.strip())
    if chunks:
        return "\n".join(chunks)[:2000]
    fallback = str(message_payload.get("output_text") or message_payload.get("summary") or "").strip()
    return fallback[:2000]


def _extract_claude_thinking_response(message_payload: Dict[str, Any]) -> str:
    """Extract thinking content blocks from Claude response."""
    content = message_payload.get("content")
    thinking_chunks: List[str] = []
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "thinking":
                thinking = item.get("thinking")
                if isinstance(thinking, str) and thinking.strip():
                    thinking_chunks.append(thinking.strip())
    return "\n".join(thinking_chunks)[:5000] if thinking_chunks else ""


def _coerce_claude_max_tokens(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return CLAUDE_API_MAX_TOKENS_DEFAULT
    return min(max(value, CLAUDE_API_MAX_TOKENS_MIN), CLAUDE_API_MAX_TOKENS_MAX)


def _resolve_claude_model(provider_session: Dict[str, Any]) -> str:
    """Resolve Claude model using task_complexity routing or explicit model override."""
    explicit_model = str(provider_session.get("model") or "").strip()
    if explicit_model:
        return explicit_model
    task_complexity = str(provider_session.get("task_complexity") or "standard").strip().lower()
    return _CLAUDE_MODEL_ROUTING.get(task_complexity, DEFAULT_CLAUDE_AGENT_MODEL)


def _build_claude_thinking_param(provider_session: Dict[str, Any], model: str) -> Optional[Dict[str, Any]]:
    """Build the thinking parameter based on provider_session and model capabilities."""
    thinking_config = provider_session.get("thinking")
    if thinking_config is None or thinking_config is False:
        return None
    if model in _CLAUDE_ADAPTIVE_THINKING_MODELS:
        return {"type": "adaptive"}
    if isinstance(thinking_config, dict):
        budget = int(thinking_config.get("budget_tokens", CLAUDE_THINKING_BUDGET_DEFAULT))
        budget = min(max(budget, CLAUDE_THINKING_BUDGET_MIN), CLAUDE_THINKING_BUDGET_MAX)
        return {"type": "enabled", "budget_tokens": budget}
    return {"type": "enabled", "budget_tokens": CLAUDE_THINKING_BUDGET_DEFAULT}


def _calculate_claude_cost(usage: Dict[str, Any], model: str) -> Dict[str, Any]:
    """Calculate estimated cost from usage breakdown and model pricing."""
    pricing = _CLAUDE_PRICING.get(model, _CLAUDE_DEFAULT_PRICING)
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    cache_creation = int(usage.get("cache_creation_input_tokens") or 0)
    cache_read = int(usage.get("cache_read_input_tokens") or 0)
    cache_ttl = CLAUDE_PROMPT_CACHE_TTL
    cache_write_key = "cache_write_1h" if cache_ttl == "1h" else "cache_write_5m"

    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    cache_write_cost = (cache_creation / 1_000_000) * pricing[cache_write_key]
    cache_read_cost = (cache_read / 1_000_000) * pricing["cache_read"]
    total = input_cost + output_cost + cache_write_cost + cache_read_cost

    return {
        "model": model,
        "input_cost_usd": round(input_cost, 6),
        "output_cost_usd": round(output_cost, 6),
        "cache_write_cost_usd": round(cache_write_cost, 6),
        "cache_read_cost_usd": round(cache_read_cost, 6),
        "total_cost_usd": round(total, 6),
        "cache_hit_ratio": round(cache_read / max(cache_read + input_tokens + cache_creation, 1), 4),
    }


def _count_claude_tokens(
    api_key: str,
    model: str,
    messages: list,
    system: Optional[list] = None,
) -> Optional[int]:
    """Pre-flight token count using Anthropic's free /v1/messages/count_tokens endpoint."""
    endpoint = f"{ANTHROPIC_API_BASE_URL.rstrip('/')}/v1/messages/count_tokens"
    body: Dict[str, Any] = {"model": model, "messages": messages}
    if system:
        body["system"] = system
    req_data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url=endpoint,
        method="POST",
        data=req_data,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "content-type": "application/json",
        },
    )
    ctx = ssl.create_default_context(cafile=_CERT_BUNDLE) if _CERT_BUNDLE else None
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            return int(payload.get("input_tokens") or 0)
    except Exception as exc:
        logger.warning("[WARNING] Token counting failed (non-blocking): %s", exc)
        return None


def _parse_sse_stream(resp) -> Dict[str, Any]:
    """Parse Anthropic SSE stream into a complete message payload."""
    message: Dict[str, Any] = {}
    content_blocks: List[Dict[str, Any]] = []
    current_block: Optional[Dict[str, Any]] = None
    current_text = ""
    current_thinking = ""
    current_signature = ""

    for raw_line in resp:
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line or line.startswith(":"):
            continue
        if line.startswith("event: "):
            event_type = line[7:].strip()
            continue
        if line.startswith("data: "):
            data_str = line[6:]
            try:
                data = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            evt = data.get("type", event_type if "event_type" in dir() else "")
            if evt == "message_start":
                message = data.get("message", {})
                content_blocks = []
            elif evt == "content_block_start":
                block = data.get("content_block", {})
                current_block = block
                current_text = ""
                current_thinking = ""
                current_signature = ""
            elif evt == "content_block_delta":
                delta = data.get("delta", {})
                delta_type = delta.get("type", "")
                if delta_type == "text_delta":
                    current_text += delta.get("text", "")
                elif delta_type == "thinking_delta":
                    current_thinking += delta.get("thinking", "")
                elif delta_type == "signature_delta":
                    current_signature += delta.get("signature", "")
            elif evt == "content_block_stop":
                if current_block:
                    block_type = current_block.get("type", "text")
                    if block_type == "text":
                        content_blocks.append({"type": "text", "text": current_text})
                    elif block_type == "thinking":
                        entry: Dict[str, Any] = {"type": "thinking", "thinking": current_thinking}
                        if current_signature:
                            entry["signature"] = current_signature
                        content_blocks.append(entry)
                    else:
                        content_blocks.append({**current_block, "text": current_text})
                current_block = None
            elif evt == "message_delta":
                delta = data.get("delta", {})
                if "stop_reason" in delta:
                    message["stop_reason"] = delta["stop_reason"]
                usage_delta = data.get("usage", {})
                if usage_delta:
                    existing = message.get("usage", {})
                    existing.update(usage_delta)
                    message["usage"] = existing
            elif evt == "message_stop":
                break

    message["content"] = content_blocks
    return message


def _dispatch_claude_api(request: Dict[str, Any], prompt: Optional[str], dispatch_id: str) -> Dict[str, Any]:
    """Dispatch a request to the Anthropic Messages API with full feature support.

    Features (DVP-TSK-357/358/359/360/361/362/363):
    - System prompt with prompt caching (1h TTL)
    - Intelligent model routing by task_complexity
    - Extended thinking (adaptive for Opus 4.6, manual budget for others)
    - Streaming SSE support
    - Pre-flight token counting
    - Enhanced observability with token breakdown and cost attribution
    """
    provider_session = request.get("provider_session") or {}

    # --- Model routing (DVP-TSK-358) ---
    model = _resolve_claude_model(provider_session)
    task_complexity = str(provider_session.get("task_complexity") or "standard").strip().lower()
    model_routing_reason = (
        f"explicit_override" if provider_session.get("model")
        else f"task_complexity={task_complexity}"
    )

    permission_mode = str(provider_session.get("permission_mode") or "acceptEdits").strip() or "acceptEdits"
    allowed_tools = provider_session.get("allowed_tools")
    if not isinstance(allowed_tools, list) or not allowed_tools:
        allowed_tools = sorted(_ENCELADUS_ALLOWED_TOOLS)
    normalized_allowed_tools = [str(tool).strip() for tool in allowed_tools if str(tool).strip()]

    resolved_prompt = str(prompt or "").strip()
    if not resolved_prompt:
        initiative = str(request.get("initiative_title") or "").strip()
        outcomes = [str(item).strip() for item in (request.get("outcomes") or []) if str(item).strip()]
        lines = []
        if initiative:
            lines.append(f"Initiative: {initiative}")
        if outcomes:
            lines.append("Outcomes:")
            lines.extend(f"- {item}" for item in outcomes)
        resolved_prompt = "\n".join(lines).strip()
    if not resolved_prompt:
        raise RuntimeError("Missing prompt for claude_agent_sdk dispatch")
    resolved_prompt, governance_context = _build_managed_session_prompt(
        resolved_prompt,
        str(request.get("project_id") or ""),
    )

    max_tokens = _coerce_claude_max_tokens((request.get("constraints") or {}).get("max_tokens"))
    api_key = _fetch_provider_api_key("anthropic", ANTHROPIC_API_KEY_SECRET_ID)
    endpoint = f"{ANTHROPIC_API_BASE_URL.rstrip('/')}/v1/messages"

    # --- System prompt with prompt caching (DVP-TSK-357) ---
    system_prompt = provider_session.get("system_prompt")
    system_blocks = None
    if system_prompt:
        system_blocks = [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral", "ttl": CLAUDE_PROMPT_CACHE_TTL},
            }
        ]

    # --- Build request body ---
    request_body: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": resolved_prompt}],
    }
    if system_blocks:
        request_body["system"] = system_blocks

    # --- Extended thinking (DVP-TSK-359) ---
    thinking_param = _build_claude_thinking_param(provider_session, model)
    if thinking_param:
        request_body["thinking"] = thinking_param
        # API requires max_tokens > budget_tokens when using manual thinking
        budget = thinking_param.get("budget_tokens")
        if budget is not None and max_tokens <= budget:
            max_tokens = budget + max(budget, CLAUDE_API_MAX_TOKENS_DEFAULT)
            request_body["max_tokens"] = max_tokens

    # --- Streaming (DVP-TSK-360) ---
    use_streaming = bool(provider_session.get("stream"))
    if thinking_param and max_tokens > 21333:
        use_streaming = True
    if use_streaming:
        request_body["stream"] = True

    # --- Pre-flight token counting (DVP-TSK-361) ---
    preflight_token_count = _count_claude_tokens(
        api_key=api_key,
        model=model,
        messages=request_body["messages"],
        system=system_blocks,
    )
    context_limit = _CLAUDE_CONTEXT_LIMITS.get(model, _CLAUDE_DEFAULT_CONTEXT_LIMIT)
    if preflight_token_count is not None and preflight_token_count > context_limit:
        raise RuntimeError(
            f"Estimated input tokens ({preflight_token_count}) exceed model context "
            f"window ({context_limit}) for {model}"
        )

    request_json = json.dumps(request_body).encode("utf-8")
    started_at = _now_z()
    started = time.perf_counter()
    timeout = ANTHROPIC_API_STREAM_TIMEOUT_SECONDS if use_streaming else ANTHROPIC_API_TIMEOUT_SECONDS
    req = urllib.request.Request(
        url=endpoint,
        method="POST",
        data=request_json,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "content-type": "application/json",
        },
    )
    context = ssl.create_default_context(cafile=_CERT_BUNDLE) if _CERT_BUNDLE else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            response_headers = dict(resp.headers.items())
            if use_streaming:
                payload = _parse_sse_stream(resp)
            else:
                raw_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body[:400] if body else str(exc)
        _emit_structured_observability(
            component="coordination_api",
            event="dispatch_claude_api",
            request_id=str(request.get("request_id") or ""),
            dispatch_id=dispatch_id,
            tool_name="anthropic.messages.create",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=f"http_{exc.code}",
            extra={"execution_mode": "claude_agent_sdk", "model": model},
        )
        raise RuntimeError(f"Claude API request failed (http_{exc.code}): {message}") from exc
    except urllib.error.URLError as exc:
        _emit_structured_observability(
            component="coordination_api",
            event="dispatch_claude_api",
            request_id=str(request.get("request_id") or ""),
            dispatch_id=dispatch_id,
            tool_name="anthropic.messages.create",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code="url_error",
            extra={"execution_mode": "claude_agent_sdk", "model": model, "reason": str(exc.reason)},
        )
        raise RuntimeError(f"Claude API request failed: {exc.reason}") from exc

    if not use_streaming:
        if status < 200 or status >= 300:
            raise RuntimeError(f"Claude API request returned http_{status}")
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Claude API response was not valid JSON") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("Claude API response payload is not an object")
    if isinstance(payload.get("error"), dict):
        error_type = str(payload["error"].get("type") or "unknown")
        error_message = str(payload["error"].get("message") or "Unknown Claude API error")
        raise RuntimeError(f"Claude API error ({error_type}): {error_message}")

    summary = _extract_claude_text_response(payload)
    thinking_summary = _extract_claude_thinking_response(payload)
    completed_at = _now_z()
    execution_id = str(payload.get("id") or f"claude-msg-{uuid.uuid4().hex[:16]}")
    request_id_header = str(response_headers.get("request-id") or "")

    # --- Enhanced usage + cost attribution (DVP-TSK-363) ---
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    cost_attribution = _calculate_claude_cost(usage, model)

    # --- Parse rate limit headers for capacity monitoring ---
    rate_limits = {}
    for header_key in ("anthropic-ratelimit-requests-remaining",
                       "anthropic-ratelimit-input-tokens-remaining",
                       "anthropic-ratelimit-output-tokens-remaining"):
        val = response_headers.get(header_key)
        if val is not None:
            try:
                rate_limits[header_key.replace("anthropic-ratelimit-", "")] = int(val)
            except (TypeError, ValueError):
                pass

    provider_result = {
        "provider": "claude_agent_sdk",
        "session_id": execution_id,
        "fork_from_session_id": provider_session.get("fork_from_session_id"),
        "model": str(payload.get("model") or model),
        "permission_mode": permission_mode,
        "allowed_tools": normalized_allowed_tools,
        "usage": usage,
        "cost_attribution": cost_attribution,
        "stop_reason": str(payload.get("stop_reason") or ""),
        "summary": summary,
        "thinking_summary": thinking_summary if thinking_summary else None,
        "request_id": request_id_header,
        "completed_at": completed_at,
        "model_routing": {
            "task_complexity": task_complexity,
            "resolved_model": model,
            "reason": model_routing_reason,
        },
        "features_used": {
            "system_prompt": bool(system_blocks),
            "prompt_caching": bool(system_blocks),
            "cache_ttl": CLAUDE_PROMPT_CACHE_TTL if system_blocks else None,
            "extended_thinking": bool(thinking_param),
            "streaming": use_streaming,
            "preflight_token_count": preflight_token_count,
        },
        "governance_context": {
            "loaded": bool(governance_context.get("loaded")),
            "source": str(governance_context.get("source") or "prompt_bootstrap_only"),
            "resource_count": len(governance_context.get("included_uris") or []),
            "truncated": bool(governance_context.get("truncated")),
            "resources": list(governance_context.get("included_uris") or []),
        },
    }
    if rate_limits:
        provider_result["rate_limits"] = rate_limits

    _emit_structured_observability(
        component="coordination_api",
        event="dispatch_claude_api",
        request_id=str(request.get("request_id") or ""),
        dispatch_id=dispatch_id,
        tool_name="anthropic.messages.create",
        latency_ms=int((time.perf_counter() - started) * 1000),
        error_code="",
        extra={
            "execution_mode": "claude_agent_sdk",
            "model": provider_result["model"],
            "stop_reason": provider_result["stop_reason"],
            "request_id_header": request_id_header,
            "task_complexity": task_complexity,
            "model_routing_reason": model_routing_reason,
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "cache_creation_input_tokens": usage.get("cache_creation_input_tokens"),
            "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
            "total_cost_usd": cost_attribution.get("total_cost_usd"),
            "cache_hit_ratio": cost_attribution.get("cache_hit_ratio"),
            "streaming": use_streaming,
            "thinking_enabled": bool(thinking_param),
            "preflight_token_count": preflight_token_count,
            "governance_loaded": bool(governance_context.get("loaded")),
            "governance_resource_count": len(governance_context.get("included_uris") or []),
        },
    )
    return {
        "dispatch_id": dispatch_id,
        "execution_id": execution_id,
        "execution_mode": "claude_agent_sdk",
        "provider": "claude_agent_sdk",
        "transport": "anthropic_messages_api",
        "api_endpoint": endpoint,
        "project_id": request.get("project_id"),
        "coordination_request_id": request.get("request_id"),
        "provider_secret_refs": [ANTHROPIC_API_KEY_SECRET_ID] if ANTHROPIC_API_KEY_SECRET_ID else [],
        "sent_at": started_at,
        "completed_at": completed_at,
        "status": "succeeded",
        "provider_result": provider_result,
    }


def _build_mcp_connectivity_check_commands() -> List[str]:
    check_py = """
import json
import sys
import urllib.request

for candidate in (
    "projects/enceladus/tools/enceladus-mcp-server",
    "projects/devops/tools/enceladus-mcp-server",
    "tools/enceladus-mcp-server",
    "/home/ec2-user/claude-code-dev/projects/devops/tools/enceladus-mcp-server",
    "/home/ec2-user/claude-code-dev/projects/enceladus/tools/enceladus-mcp-server",
):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

health = None
fallback_reason = None
capabilities_status = "unreachable"
governance_hash = ""
coordination_api_base = "https://jreese.net/api/v1/coordination"
try:
    import dispatch_plan_generator as dpg
    health = dpg.test_connection_health()
    try:
        governance_hash = str(dpg.compute_governance_hash() or "")
    except Exception as gov_exc:
        fallback_reason = f"governance_hash:{gov_exc}"
    coordination_api_base = str(getattr(dpg, "COORDINATION_API_BASE", coordination_api_base) or coordination_api_base)
except Exception as exc:  # pragma: no cover - host runtime fallback
    fallback_reason = str(exc)

if health is None:
    import boto3
    health = {}
    try:
        boto3.client("dynamodb", region_name="us-west-2").describe_table(TableName="devops-project-tracker")
        health["dynamodb"] = "ok"
    except Exception:
        health["dynamodb"] = "unreachable"
    try:
        boto3.client("s3", region_name="us-west-2").list_objects_v2(Bucket="jreese-net", Prefix="mobile/v1/", MaxKeys=1)
        health["s3"] = "ok"
    except Exception:
        health["s3"] = "unreachable"
    try:
        req = urllib.request.Request(
            f"{coordination_api_base.rstrip('/')}/capabilities",
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            capabilities_status = "ok" if getattr(resp, "status", 500) == 200 else "degraded"
    except Exception:
        capabilities_status = "unreachable"
    health["api_gateway"] = capabilities_status
    health["fallback"] = (
        "ok"
        if health["dynamodb"] == "ok" and health["s3"] == "ok" and health["api_gateway"] == "ok"
        else "degraded"
    )
    if fallback_reason:
        health["fallback_reason"] = fallback_reason[:300]

if capabilities_status != "ok":
    try:
        req = urllib.request.Request(
            f"{coordination_api_base.rstrip('/')}/capabilities",
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            capabilities_status = "ok" if getattr(resp, "status", 500) == 200 else "degraded"
    except Exception:
        capabilities_status = "unreachable"

health["coordination_capabilities"] = capabilities_status
health["governance_hash"] = "ok" if len(governance_hash) >= 32 else "unreachable"

print("[INFO] Enceladus MCP connection health " + json.dumps(health, sort_keys=True))
if governance_hash:
    print("[INFO] Enceladus governance hash " + governance_hash)
required = {
    "dynamodb": health.get("dynamodb", "unreachable"),
    "s3": health.get("s3", "unreachable"),
    "api_gateway": health.get("api_gateway", "unreachable"),
    "coordination_capabilities": health.get("coordination_capabilities", "unreachable"),
    "governance_hash": health.get("governance_hash", "unreachable"),
}
sys.exit(0 if all(str(v).lower() == "ok" for v in required.values()) else 1)
""".strip()
    backoffs = " ".join(str(v) for v in MCP_CONNECTIVITY_BACKOFF_SECONDS)
    check_py_json = json.dumps(check_py)
    return [
        "MCP_CONN_OK=0",
        f"MCP_CHECK_SCRIPT_JSON={shlex.quote(check_py_json)}",
        (
            f"for MCP_BACKOFF in {backoffs}; do "
            "if python3 -c 'import json,sys; exec(json.loads(sys.argv[1]))' \"$MCP_CHECK_SCRIPT_JSON\" "
            ">/tmp/coordination_mcp_health.log 2>&1; then "
            "cat /tmp/coordination_mcp_health.log; MCP_CONN_OK=1; break; "
            "fi; "
            "cat /tmp/coordination_mcp_health.log || true; "
            "echo \"[WARNING] Enceladus MCP connectivity check failed; retrying in ${MCP_BACKOFF}s\"; "
            "sleep \"$MCP_BACKOFF\"; "
            "done"
        ),
        (
            "if [ \"$MCP_CONN_OK\" -ne 1 ]; then "
            "echo '[ERROR] Enceladus MCP connectivity validation failed after retries'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'mcp_connectivity', 'code': 'connectivity_failed'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 22; "
            "fi"
        ),
        f"echo {shlex.quote('COORDINATION_PREFLIGHT_OK=' + json.dumps({'stage': 'mcp_connectivity', 'status': 'ok'}, sort_keys=True, separators=(',', ':')))}",
        "echo 'COORDINATION_PREFLIGHT_MCP=pass'",
    ]


def _lookup_dispatch_execution_mode(request: Dict[str, Any], dispatch_id: str) -> str:
    if not dispatch_id:
        return str(request.get("execution_mode") or "unknown")
    dispatch_plan = request.get("dispatch_plan") or {}
    for dispatch in dispatch_plan.get("dispatches") or []:
        if str(dispatch.get("dispatch_id") or "") == dispatch_id:
            return str(dispatch.get("execution_mode") or request.get("execution_mode") or "unknown")
    outcome = (request.get("dispatch_outcomes") or {}).get(dispatch_id) or {}
    return str(outcome.get("execution_mode") or request.get("execution_mode") or "unknown")


def _callback_provider_for_execution_mode(execution_mode: str) -> str:
    mode = str(execution_mode or "").strip().lower()
    if mode.startswith("codex"):
        return "openai_codex"
    if mode.startswith("claude"):
        return "claude_agent_sdk"
    if mode.startswith("bedrock"):
        return "aws_bedrock_agent"
    return "aws_native"


def _append_dispatch_worklog(
    request: Dict[str, Any],
    *,
    dispatch_id: str,
    provider: str,
    execution_mode: str,
    outcome_state: str,
    summary: str,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
) -> Dict[str, Any]:
    logs = list(request.get("dispatch_worklogs") or [])
    log_entry = {
        "dispatch_id": dispatch_id or "primary",
        "provider": provider or "unknown",
        "execution_mode": execution_mode or "unknown",
        "start_ts": start_ts or _now_z(),
        "end_ts": end_ts or _now_z(),
        "outcome_state": outcome_state,
        "summary": (summary or "")[:1000],
    }
    logs.append(log_entry)
    if len(logs) > DISPATCH_WORKLOG_MAX_ENTRIES:
        logs = logs[-DISPATCH_WORKLOG_MAX_ENTRIES:]
    request["dispatch_worklogs"] = logs
    return request


def _recent_dispatch_worklogs(request: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    logs = list(request.get("dispatch_worklogs") or [])
    return logs[-limit:]


def _build_result_payload(
    request: Dict[str, Any],
    *,
    state: str,
    summary: str,
    execution_id: Optional[str],
    provider: str,
    details: Optional[Dict[str, Any]] = None,
    feed_updates: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_feed_updates = dict(feed_updates or {})
    items_modified = list(normalized_feed_updates.get("items_modified") or [])
    if not items_modified:
        items_modified = list(
            dict.fromkeys(
                ([request.get("feature_id")] if request.get("feature_id") else [])
                + list(request.get("task_ids") or [])
                + list(request.get("issue_ids") or [])
            )
        )
    normalized_feed_updates["items_modified"] = items_modified

    payload: Dict[str, Any] = {
        "state": state,
        "summary": (summary or "")[:2000],
        "execution_id": execution_id or None,
        "provider": provider,
        "details": details or {},
        "feed_updates": normalized_feed_updates,
    }
    if reason:
        payload["reason"] = reason
    if state == "failed":
        payload["last_worklogs"] = _recent_dispatch_worklogs(request, limit=5)
    return payload


def _is_timeout_failure(status: str, status_details: str, summary: str) -> bool:
    s = str(status or "").lower()
    d = str(status_details or "").lower()
    m = str(summary or "").lower()
    return "timeout" in s or "timedout" in s or "timeout" in d or "timed out" in d or "timeout" in m


def _extract_json_marker(blob: str, marker: str) -> Optional[Dict[str, Any]]:
    if not blob:
        return None
    for line in reversed(blob.splitlines()):
        if not line.startswith(marker):
            continue
        raw = line[len(marker) :].strip()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if isinstance(parsed, dict):
            return parsed
        return None
    return None


def _build_ssm_commands(
    request: Dict[str, Any],
    execution_mode: str,
    prompt: Optional[str],
    dispatch_id: str = "primary",
) -> List[str]:
    project = request["project_id"]
    feature_id = request.get("feature_id")
    request_id = request["request_id"]
    provider_session = request.get("provider_session") or {}

    managed_prompt = _prepend_managed_session_bootstrap(str(prompt or ""), project)
    escaped_prompt = json.dumps(managed_prompt)
    escaped_thread_id = json.dumps(str(provider_session.get("thread_id") or provider_session.get("session_id") or ""))
    escaped_fork_thread_id = json.dumps(
        str(provider_session.get("fork_from_thread_id") or provider_session.get("fork_from_session_id") or "")
    )
    provider_model = str(provider_session.get("model") or "")
    if execution_mode == "claude_agent_sdk" and not provider_model:
        provider_model = DEFAULT_CLAUDE_AGENT_MODEL
    escaped_model = json.dumps(provider_model)
    escaped_provider_session_id = json.dumps(
        str(provider_session.get("provider_session_id") or provider_session.get("session_id") or "")
    )
    escaped_session_id = json.dumps(str(provider_session.get("session_id") or provider_session.get("thread_id") or ""))
    escaped_fork_session_id = json.dumps(
        str(provider_session.get("fork_from_session_id") or provider_session.get("fork_from_thread_id") or "")
    )
    permission_mode = str(provider_session.get("permission_mode") or "")
    if execution_mode == "claude_agent_sdk" and not permission_mode:
        permission_mode = "acceptEdits"
    escaped_permission_mode = json.dumps(permission_mode)
    allowed_tools = provider_session.get("allowed_tools")
    if not isinstance(allowed_tools, list) or not allowed_tools:
        allowed_tools = sorted(_ENCELADUS_ALLOWED_TOOLS)
    normalized_allowed_tools = [str(tool).strip() for tool in allowed_tools if str(tool).strip()]
    escaped_allowed_tools_csv = json.dumps(",".join(normalized_allowed_tools))
    escaped_allowed_tools_json = json.dumps(json.dumps(normalized_allowed_tools))

    # Derive HOME from HOST_V2_WORK_ROOT (e.g. /home/ec2-user/claude-code-dev -> /home/ec2-user)
    host_v2_home = "/".join(HOST_V2_WORK_ROOT.rstrip("/").split("/")[:4]) or "/home/ec2-user"

    callback_url = f"{COORDINATION_PUBLIC_BASE_URL.rstrip('/')}/api/v1/coordination/requests/{request_id}/callback"
    callback_token = str(request.get("callback_token") or "")
    callback_provider = _callback_provider_for_execution_mode(execution_mode)
    callback_payload_script = (
        "import json, os, sys;"
        "rc=int(sys.argv[1]);"
        "state='succeeded' if rc==0 else 'failed';"
        "summary='worker runtime completed' if rc==0 else f'worker runtime failed (exit={rc})';"
        "dispatch_id=os.environ.get('COORDINATION_DISPATCH_ID','');"
        "provider=os.environ.get('COORDINATION_CALLBACK_PROVIDER','aws_native');"
        "exec_mode=os.environ.get('COORDINATION_EXECUTION_MODE','unknown');"
        "payload={"
        "'provider':provider,"
        "'state':state,"
        "'dispatch_id':dispatch_id,"
        "'execution_id':dispatch_id,"
        "'summary':summary,"
        "'details':{"
        "'execution_mode':exec_mode,"
        "'exit_code':rc,"
        "'request_id':os.environ.get('COORDINATION_REQUEST_ID','')"
        "}"
        "};"
        "print(json.dumps(payload, separators=(',',':')))"
    )

    commands: List[str] = [
        "set -euo pipefail",
        # SSM RunCommand env preamble — SSM sessions run as root with empty HOME
        # and minimal PATH. Set env vars to match interactive ec2-user session.
        f"export HOME={host_v2_home}",
        f"export PATH={host_v2_home}/.local/bin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:$PATH",
        f"cd {HOST_V2_WORK_ROOT}",
        f"export PROJECT={project}",
        f"export AWS_REGION={DYNAMODB_REGION}",
        f"export AWS_DEFAULT_REGION={DYNAMODB_REGION}",
        f"export COORDINATION_CALLBACK_URL={json.dumps(callback_url)}",
        f"export COORDINATION_CALLBACK_TOKEN={json.dumps(callback_token)}",
        f"export COORDINATION_CALLBACK_PROVIDER={json.dumps(callback_provider)}",
        f"export COORDINATION_EXECUTION_MODE={json.dumps(execution_mode)}",
        (
            "if aws configure list-profiles 2>/dev/null | grep -qx "
            f"'{HOST_V2_AWS_PROFILE}'; then export AWS_PROFILE={HOST_V2_AWS_PROFILE}; "
            "else unset AWS_PROFILE; fi"
        ),
        (
            "__coordination_callback_on_exit() { "
            "COORD_RC=$?; "
            "if [ -z \"${COORDINATION_CALLBACK_URL:-}\" ] || [ -z \"${COORDINATION_CALLBACK_TOKEN:-}\" ]; then "
            "  return 0; "
            "fi; "
            f"COORDINATION_CALLBACK_PAYLOAD=$(python3 -c {shlex.quote(callback_payload_script)} \"$COORD_RC\" 2>/dev/null || "
            "echo '{\"provider\":\"aws_native\",\"state\":\"failed\",\"summary\":\"callback payload generation failed\"}'); "
            "curl -sS --max-time 10 "
            "-H 'Content-Type: application/json' "
            "-H \"X-Coordination-Callback-Token: ${COORDINATION_CALLBACK_TOKEN}\" "
            "-X POST \"${COORDINATION_CALLBACK_URL}\" "
            "-d \"${COORDINATION_CALLBACK_PAYLOAD}\" >/tmp/coordination_callback_response.log 2>&1 || true; "
            "}; "
            "trap '__coordination_callback_on_exit' EXIT"
        ),
        "if ! command -v python3 >/dev/null 2>&1; then "
        "echo '[ERROR] python3 not found on host-v2'; "
        f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'runtime', 'code': 'python_missing'}, sort_keys=True, separators=(',', ':')))}; "
        "exit 30; fi",
        "echo 'COORDINATION_PREFLIGHT_PYTHON=pass'",
        (
            "if ! python3 -c \"import boto3, yaml\" >/dev/null 2>&1; then "
            "python3 -m ensurepip --upgrade >/dev/null 2>&1 || true; "
            "python3 -m pip install --user --break-system-packages --quiet boto3 PyYAML >/dev/null 2>&1 || true; "
            "fi"
        ),
        (
            "if ! python3 -c \"import boto3, yaml\" >/dev/null 2>&1; then "
            "echo '[ERROR] boto3/PyYAML unavailable after bootstrap'; "
            f"echo {shlex.quote('COORDINATION_PREFLIGHT_ERROR=' + json.dumps({'stage': 'runtime', 'code': 'boto3_unavailable'}, sort_keys=True, separators=(',', ':')))}; "
            "exit 31; "
            "fi"
        ),
        "echo 'COORDINATION_PREFLIGHT_BOTO3=pass'",
        "aws sts get-caller-identity",
        (
            f"python3 tools/context_sync.py --project {project} --skip-records; "
            f"python3 tools/tracker.py pending-updates --project {project} || true; "
        ),
    ]
    commands.extend(_build_dispatch_payload_commands(request, execution_mode, dispatch_id))
    commands.extend(_build_mcp_connectivity_check_commands())
    commands.extend(_build_provider_rotation_check_commands(execution_mode))
    commands.append(
        f"echo {shlex.quote('COORDINATION_PREFLIGHT_OK=' + json.dumps({'stage': 'runtime', 'status': 'ok'}, sort_keys=True, separators=(',', ':')))}"
    )

    if feature_id:
        commands.append(
            (
                "python3 tools/tracker.py log "
                f"{feature_id} worklog "
                f"\"Coordination request {request_id} started on host-v2 via SSM.\""
            )
        )

    if execution_mode == "preflight":
        commands.append("echo '[INFO] preflight mode complete - provider checks passed'")
    elif execution_mode == "codex_full_auto":
        commands.extend(_build_mcp_profile_bootstrap_commands())
        commands.extend(
            _build_secret_fetch_commands(
                provider_label="openai",
                secret_id=OPENAI_API_KEY_SECRET_ID,
                exported_var="CODEX_API_KEY",
                exit_code=18,
            )
        )
        commands.extend(
            [
                f"COORDINATION_PROMPT={escaped_prompt}",
                "if command -v codex >/dev/null 2>&1; then",
                (
                    "  timeout "
                    f"{HOST_V2_TIMEOUT_SECONDS} "
                    "./launch_devops_codex.sh \"$COORDINATION_PROMPT\""
                ),
                "else",
                "  echo '[ERROR] codex binary not found on host-v2'",
                "  exit 16",
                "fi",
            ]
        )
    elif execution_mode == "codex_app_server":
        commands.extend(_build_mcp_profile_bootstrap_commands())
        commands.extend(
            _build_secret_fetch_commands(
                provider_label="openai",
                secret_id=OPENAI_API_KEY_SECRET_ID,
                exported_var="CODEX_API_KEY",
                exit_code=18,
            )
        )
        commands.extend(
            [
                f"COORDINATION_PROMPT={escaped_prompt}",
                f"COORDINATION_PROVIDER_THREAD_ID={escaped_thread_id}",
                f"COORDINATION_PROVIDER_FORK_THREAD_ID={escaped_fork_thread_id}",
                f"COORDINATION_PROVIDER_MODEL={escaped_model}",
                f"COORDINATION_PROVIDER_SESSION_ID={escaped_provider_session_id}",
                "if [ -x ./launch_devops_codex_app_server.sh ]; then",
                (
                    "  timeout "
                    f"{HOST_V2_TIMEOUT_SECONDS} "
                    "./launch_devops_codex_app_server.sh \"$COORDINATION_PROMPT\""
                ),
                "elif [ -x ./projects/devops/tools/agentcli-host-v2/launch_devops_codex_app_server.sh ]; then",
                (
                    "  timeout "
                    f"{HOST_V2_TIMEOUT_SECONDS} "
                    "./projects/devops/tools/agentcli-host-v2/launch_devops_codex_app_server.sh \"$COORDINATION_PROMPT\""
                ),
                "else",
                "  echo '[ERROR] codex app-server launcher not found on host-v2'",
                "  exit 20",
                "fi",
            ]
        )
    elif execution_mode == "claude_headless":
        commands.extend(_build_mcp_profile_bootstrap_commands())
        commands.extend(
            _build_secret_fetch_commands(
                provider_label="anthropic",
                secret_id=ANTHROPIC_API_KEY_SECRET_ID,
                exported_var="ANTHROPIC_API_KEY",
                exit_code=19,
            )
        )
        commands.extend(
            [
                f"COORDINATION_PROMPT={escaped_prompt}",
                "if command -v claude >/dev/null 2>&1; then",
                f"  timeout {HOST_V2_TIMEOUT_SECONDS} claude \"$COORDINATION_PROMPT\"",
                "else",
                "  echo '[ERROR] claude binary not found on host-v2'",
                "  exit 17",
                "fi",
            ]
        )
    elif execution_mode == "claude_agent_sdk":
        commands.extend(_build_mcp_profile_bootstrap_commands())
        commands.extend(
            _build_secret_fetch_commands(
                provider_label="anthropic",
                secret_id=ANTHROPIC_API_KEY_SECRET_ID,
                exported_var="ANTHROPIC_API_KEY",
                exit_code=19,
            )
        )
        commands.extend(
            [
                f"COORDINATION_PROMPT={escaped_prompt}",
                f"COORDINATION_PROVIDER_SESSION_ID={escaped_session_id}",
                f"COORDINATION_PROVIDER_FORK_FROM_SESSION_ID={escaped_fork_session_id}",
                f"COORDINATION_PROVIDER_MODEL={escaped_model}",
                f"COORDINATION_PERMISSION_MODE={escaped_permission_mode}",
                f"COORDINATION_ALLOWED_TOOLS={escaped_allowed_tools_csv}",
                f"COORDINATION_ALLOWED_TOOLS_JSON={escaped_allowed_tools_json}",
                "if [ -x ./projects/devops/tools/agentcli-host-v2/launch_devops_claude_agent_sdk.sh ]; then",
                (
                    "  timeout "
                    f"{HOST_V2_TIMEOUT_SECONDS} "
                    "./projects/devops/tools/agentcli-host-v2/launch_devops_claude_agent_sdk.sh \"$COORDINATION_PROMPT\""
                ),
                "elif command -v claude >/dev/null 2>&1; then",
                f"  timeout {HOST_V2_TIMEOUT_SECONDS} claude \"$COORDINATION_PROMPT\"",
                (
                    "  python3 -c 'import json,os,time; "
                    "sid=os.getenv(\"COORDINATION_PROVIDER_SESSION_ID\") or f\"claude-sdk-{int(time.time())}\"; "
                    "payload={"
                    "\"session_id\":sid,"
                    "\"fork_from_session_id\":os.getenv(\"COORDINATION_PROVIDER_FORK_FROM_SESSION_ID\") or None,"
                    "\"model\":os.getenv(\"COORDINATION_PROVIDER_MODEL\") or None,"
                    "\"permission_mode\":os.getenv(\"COORDINATION_PERMISSION_MODE\") or None,"
                    "\"allowed_tools\":(os.getenv(\"COORDINATION_ALLOWED_TOOLS\") or \"\").split(\",\") if os.getenv(\"COORDINATION_ALLOWED_TOOLS\") else [],"
                    "\"completed_at\":time.strftime(\"%Y-%m-%dT%H:%M:%SZ\", time.gmtime())"
                    "}; "
                    "print(\"COORDINATION_CLAUDE_SDK_RESULT=\"+json.dumps(payload, separators=(\",\",\":\")))'"
                ),
                "else",
                "  echo '[ERROR] claude sdk launcher and claude binary not found on host-v2'",
                "  exit 23",
                "fi",
            ]
        )

    return commands


def _send_dispatch(
    request: Dict[str, Any],
    execution_mode: str,
    prompt: Optional[str],
    dispatch_id: str,
    host_allocation: str = "auto",
) -> Dict[str, Any]:
    ssm = _get_ssm()
    dispatch_target = _resolve_host_dispatch_target(
        request,
        execution_mode,
        dispatch_id,
        host_allocation=host_allocation,
    )
    target_instance_id = str(dispatch_target.get("instance_id") or HOST_V2_INSTANCE_ID)
    commands = _build_ssm_commands(request, execution_mode, prompt, dispatch_id)
    timeout_ceiling = max(60, DISPATCH_TIMEOUT_CEILING_SECONDS)
    timeout_seconds = min(max(HOST_V2_TIMEOUT_SECONDS, 60), timeout_ceiling)
    started = time.perf_counter()

    try:
        resp = ssm.send_command(
            DocumentName=SSM_DOCUMENT_NAME,
            InstanceIds=[target_instance_id],
            Parameters={
                "commands": commands,
                "executionTimeout": [str(timeout_seconds)],
            },
            CloudWatchOutputConfig={
                "CloudWatchOutputEnabled": True,
                "CloudWatchLogGroupName": WORKER_RUNTIME_LOG_GROUP,
            },
            TimeoutSeconds=timeout_seconds,
            Comment=f"Coordination request {request['request_id']} ({execution_mode})",
        )
    except (BotoCoreError, ClientError) as exc:
        error_code = "ssm_send_command_failed"
        if isinstance(exc, ClientError):
            error_code = str(exc.response.get("Error", {}).get("Code") or error_code)
        _emit_structured_observability(
            component="coordination_api",
            event="dispatch_send_command",
            request_id=str(request.get("request_id") or ""),
            dispatch_id=dispatch_id,
            tool_name="ssm.send_command",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=error_code,
            extra={
                "execution_mode": execution_mode,
                "instance_id": target_instance_id,
                "host_kind": dispatch_target.get("host_kind"),
                "worker_log_group": WORKER_RUNTIME_LOG_GROUP,
            },
        )
        if str(dispatch_target.get("host_kind") or "") == "fleet":
            try:
                _get_ec2().terminate_instances(InstanceIds=[target_instance_id])
            except Exception:
                logger.warning(
                    "failed terminating fleet instance after send_command failure: %s",
                    target_instance_id,
                )
        raise RuntimeError(f"SSM dispatch failed: {exc}") from exc

    command = resp.get("Command") or {}
    _emit_structured_observability(
        component="coordination_api",
        event="dispatch_send_command",
        request_id=str(request.get("request_id") or ""),
        dispatch_id=dispatch_id,
        tool_name="ssm.send_command",
        latency_ms=int((time.perf_counter() - started) * 1000),
        error_code="",
        extra={
            "execution_mode": execution_mode,
            "instance_id": target_instance_id,
            "command_id": command.get("CommandId"),
            "host_kind": dispatch_target.get("host_kind"),
            "worker_log_group": WORKER_RUNTIME_LOG_GROUP,
        },
    )
    return {
        "dispatch_id": dispatch_id,
        "command_id": command.get("CommandId"),
        "document_name": SSM_DOCUMENT_NAME,
        "instance_id": target_instance_id,
        "region": SSM_REGION,
        "sent_at": _now_z(),
        "execution_mode": execution_mode,
        "host_kind": dispatch_target.get("host_kind"),
        "host_allocation": dispatch_target.get("host_allocation"),
        "host_source": dispatch_target.get("host_source"),
        "host_launch_template_id": dispatch_target.get("launch_template_id"),
        "host_launch_template_version": dispatch_target.get("launch_template_version"),
        "host_launched_at": dispatch_target.get("launched_at"),
        "host_ready_at": dispatch_target.get("ready_at"),
        "host_instance_ttl_seconds": dispatch_target.get("instance_ttl_seconds"),
        "coordination_request_id": request.get("request_id"),
        "project_id": request.get("project_id"),
        "timeout_seconds": timeout_seconds,
        "provider_secret_refs": [
            ref
            for ref in (
                OPENAI_API_KEY_SECRET_ID if "openai" in _providers_for_execution_mode(execution_mode) else None,
                ANTHROPIC_API_KEY_SECRET_ID if "anthropic" in _providers_for_execution_mode(execution_mode) else None,
            )
            if ref
        ],
        "enceladus_mcp_profile_installer": HOST_V2_ENCELADUS_MCP_INSTALLER,
    }


def _refresh_request_from_ssm(request: Dict[str, Any]) -> Dict[str, Any]:
    if request.get("state") != _STATE_RUNNING:
        return request

    dispatch = request.get("dispatch") or {}
    command_id = dispatch.get("command_id")
    if not command_id:
        return request
    instance_id = str(dispatch.get("instance_id") or HOST_V2_INSTANCE_ID)

    ssm = _get_ssm()

    try:
        inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"InvocationDoesNotExist", "InvalidCommandId"}:
            return request
        raise

    status = (inv.get("Status") or "").lower()
    status_details = inv.get("StatusDetails") or ""
    stdout = (inv.get("StandardOutputContent") or "")[:4000]
    stderr = (inv.get("StandardErrorContent") or "")[:4000]
    preflight_error = (
        _extract_json_marker(stdout, "COORDINATION_PREFLIGHT_ERROR=")
        or _extract_json_marker(stderr, "COORDINATION_PREFLIGHT_ERROR=")
    )
    preflight_ok = (
        _extract_json_marker(stdout, "COORDINATION_PREFLIGHT_OK=")
        or _extract_json_marker(stderr, "COORDINATION_PREFLIGHT_OK=")
    )
    provider_preflight = (
        _extract_json_marker(stdout, "COORDINATION_PROVIDER_PREFLIGHT=")
        or _extract_json_marker(stderr, "COORDINATION_PROVIDER_PREFLIGHT=")
    )
    provider_result: Optional[Dict[str, Any]] = None
    dispatch_started_epoch = int(request.get("dispatch_started_epoch") or 0)
    if (
        dispatch_started_epoch > 0
        and _unix_now() > dispatch_started_epoch + (HOST_V2_TIMEOUT_SECONDS * DEAD_LETTER_TIMEOUT_MULTIPLIER)
    ):
        _move_to_dead_letter(
            request,
            "Request exceeded running timeout window (2x dispatch timeout)",
            failure_class="network_timeout",
        )
        _update_request(request)
        _finalize_tracker_from_request(request)
        return request

    status_compact = status.replace(" ", "").replace("_", "")
    if status in {"pending", "delayed"} or status_compact == "inprogress":
        request["dispatch"] = {
            **dispatch,
            "last_ssm_status": status,
            "last_ssm_status_details": status_details,
            "last_polled_at": _now_z(),
        }
        _update_request(request)
        return request

    terminal_state = "succeeded" if status == "success" else "failed"
    reason = f"SSM command reached terminal status {status} ({status_details})"
    if terminal_state == "failed" and preflight_error:
        error_code = str(preflight_error.get("code") or "preflight_failed")
        reason = f"Host preflight failed ({error_code})"

    _append_state_transition(
        request,
        terminal_state,
        reason,
        extra={"ssm_status": status, "ssm_status_details": status_details},
    )
    if (dispatch.get("execution_mode") or "") == "codex_app_server":
        provider_result = _extract_json_marker(stdout, "COORDINATION_APP_SERVER_RESULT=")
        if provider_result is None:
            provider_result = _extract_json_marker(stderr, "COORDINATION_APP_SERVER_RESULT=")
        if provider_result:
            codex_session = _mcp.codex_turn_complete(
                request_id=request.get("request_id", ""),
                command_id=str(command_id or ""),
                provider_result=provider_result,
                existing_provider_session=request.get("provider_session") or {},
            )
            request["provider_session"] = {
                **(request.get("provider_session") or {}),
                **codex_session,
            }
    elif (dispatch.get("execution_mode") or "") == "claude_agent_sdk":
        provider_result = _extract_json_marker(stdout, "COORDINATION_CLAUDE_SDK_RESULT=")
        if provider_result is None:
            provider_result = _extract_json_marker(stderr, "COORDINATION_CLAUDE_SDK_RESULT=")
        if provider_result:
            request["provider_session"] = {
                **(request.get("provider_session") or {}),
                "provider": "claude_agent_sdk",
                "session_id": provider_result.get("session_id"),
                "fork_from_session_id": provider_result.get("fork_from_session_id"),
                "model": provider_result.get("model"),
                "permission_mode": provider_result.get("permission_mode"),
                "allowed_tools": provider_result.get("allowed_tools"),
                "completed_at": provider_result.get("completed_at"),
            }

    request["dispatch"] = {
        **dispatch,
        "last_ssm_status": status,
        "last_ssm_status_details": status_details,
        "last_polled_at": _now_z(),
        "completed_at": _now_z(),
    }
    summary = reason
    if provider_result and provider_result.get("thread_id"):
        summary = (
            f"{reason}; thread={provider_result.get('thread_id')} "
            f"turn={provider_result.get('turn_id')}"
        )
    if provider_result and provider_result.get("session_id"):
        summary = f"{reason}; session={provider_result.get('session_id')}"
    timeout_failure = terminal_state == "failed" and _is_timeout_failure(status, status_details, summary)
    request = _append_dispatch_worklog(
        request,
        dispatch_id=str(dispatch.get("dispatch_id") or "primary"),
        provider=str(dispatch.get("provider") or "host_v2"),
        execution_mode=str(dispatch.get("execution_mode") or request.get("execution_mode") or "unknown"),
        outcome_state=terminal_state,
        summary=summary,
        start_ts=str(dispatch.get("sent_at") or ""),
        end_ts=_now_z(),
    )
    request["result"] = _build_result_payload(
        request,
        state=terminal_state,
        summary=summary,
        execution_id=str(command_id or ""),
        provider=str(dispatch.get("provider") or "host_v2"),
        details={
            "stdout_tail": stdout,
            "stderr_tail": stderr,
            "provider_result": provider_result,
            "ssm_status": status,
            "ssm_status_details": status_details,
            "instance_id": instance_id,
            "preflight_error": preflight_error,
            "preflight_ok": preflight_ok,
            "provider_preflight": provider_preflight,
        },
        reason="timeout" if timeout_failure else None,
    )
    _release_dispatch_lock(request, "ssm_terminal")
    request = _cleanup_dispatch_host(request, "ssm_terminal")

    _update_request(request)
    _finalize_tracker_from_request(request)
    return request


# ---------------------------------------------------------------------------
# Tracker lifecycle updates tied to coordination request state
# ---------------------------------------------------------------------------


def _finalize_tracker_from_request(request: Dict[str, Any]) -> None:
    state = request.get("state")
    rid = request["request_id"]
    task_ids = list(request.get("task_ids") or [])
    issue_ids = list(request.get("issue_ids") or [])
    feature_id = request.get("feature_id")
    provider = (
        str((request.get("provider_session") or {}).get("provider") or "")
        or str(request.get("execution_provider") or "")
    )
    dispatch_id = str((request.get("dispatch") or {}).get("dispatch_id") or "")
    governance_hash = str(request.get("governance_hash") or "")

    if state in {"succeeded", "failed", "cancelled", "dead_letter"}:
        try:
            _cancel_coordination_linked_subscriptions(rid, terminal_state=state)
        except Exception as exc:
            logger.warning("Failed cancelling coordination-linked subscriptions for %s: %s", rid, exc)

    if state == "succeeded":
        for tid in task_ids:
            _set_tracker_status(
                tid,
                "closed",
                f"Coordination request {rid} completed successfully.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        if feature_id:
            _set_tracker_status(
                feature_id,
                "completed",
                f"Coordination request {rid} completed successfully.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for iid in issue_ids:
            _append_tracker_history(
                iid,
                "worklog",
                f"Coordination request {rid} succeeded; issue retained for audit trail.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        return

    if state in {"failed", "cancelled", "dead_letter"}:
        detail = request.get("result", {}).get("summary") or f"Request ended in state {state}."
        if feature_id:
            _append_tracker_history(
                feature_id,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for tid in task_ids:
            _append_tracker_history(
                tid,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for iid in issue_ids:
            _append_tracker_history(
                iid,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )


def _safe_json_dict(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _subscription_scope_matches(
    subscription: Dict[str, Any],
    *,
    project_id: str,
    item_ids: Sequence[str],
    coordination_request_id: str,
) -> bool:
    if str(subscription.get("state") or "").lower() != "active":
        return False
    if str(subscription.get("delivery_mode") or "").lower() != "push":
        return False

    sub_coord = str(subscription.get("coordination_request_id") or "")
    if sub_coord and sub_coord != coordination_request_id:
        return False

    scope = _safe_json_dict(subscription.get("scope_json"))
    scope_project = str(scope.get("project_id") or "").strip()
    if scope_project and scope_project != project_id:
        return False

    scope_record_ids = {
        str(record_id).strip()
        for record_id in (scope.get("record_ids") or [])
        if str(record_id).strip()
    }
    if scope_record_ids:
        return bool(scope_record_ids & set(item_ids))

    return True


def _deliver_feed_push_event(
    *,
    subscription_id: str,
    push_config: Dict[str, Any],
    payload: Dict[str, Any],
) -> None:
    detail_type = str(push_config.get("detail_type") or "feed.update")
    endpoint = str(push_config.get("endpoint") or "").strip()
    event_bus = str(push_config.get("event_bus") or "").strip()

    if endpoint.startswith("arn:aws:events:"):
        event_bus = endpoint.split(":event-bus/")[-1] if ":event-bus/" in endpoint else endpoint

    if event_bus or endpoint.startswith("arn:aws:events:"):
        _get_eb().put_events(
            Entries=[
                {
                    "Source": "enceladus.feed",
                    "DetailType": detail_type,
                    "Detail": json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    "EventBusName": event_bus or FEED_PUSH_DEFAULT_EVENT_BUS,
                }
            ]
        )
        return

    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        req_headers = {"Content-Type": "application/json"}
        token = str(push_config.get("token") or "").strip()
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        user_headers = push_config.get("headers") or {}
        if isinstance(user_headers, dict):
            req_headers.update({str(k): str(v) for k, v in user_headers.items() if str(k).strip()})
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=req_headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=FEED_PUSH_HTTP_TIMEOUT_SECONDS) as resp:
            _ = resp.read()
        return

    logger.warning("Push subscription %s has unsupported endpoint/event_bus config", subscription_id)


def _publish_feed_push_updates(
    *,
    project_id: str,
    coordination_request_id: str,
    state: str,
    summary: str,
    item_ids: Sequence[str],
) -> None:
    if not item_ids:
        return
    if not _feed_subscriptions_enabled():
        return

    try:
        now = _now_z()
        ddb = _get_ddb()
        expr_names = {"#state": "state"}
        expr_values = {
            ":active": _serialize("active"),
            ":push": _serialize("push"),
        }
        filter_expr = "#state = :active AND delivery_mode = :push"
        last_key = None
        delivered = 0

        while True:
            kwargs: Dict[str, Any] = {
                "TableName": FEED_SUBSCRIPTIONS_TABLE,
                "FilterExpression": filter_expr,
                "ExpressionAttributeNames": expr_names,
                "ExpressionAttributeValues": expr_values,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            page = ddb.scan(**kwargs)
            for raw_item in page.get("Items", []):
                sub = _deserialize(raw_item)
                if not _subscription_scope_matches(
                    sub,
                    project_id=project_id,
                    item_ids=item_ids,
                    coordination_request_id=coordination_request_id,
                ):
                    continue

                push_config = _safe_json_dict(sub.get("push_config_json"))
                payload = {
                    "subscription_id": sub.get("subscription_id"),
                    "project_id": project_id,
                    "coordination_request_id": coordination_request_id,
                    "state": state,
                    "summary": summary,
                    "items_modified": list(item_ids),
                    "delivered_at": now,
                }
                try:
                    _deliver_feed_push_event(
                        subscription_id=str(sub.get("subscription_id") or ""),
                        push_config=push_config,
                        payload=payload,
                    )
                    delivered += 1
                except Exception as exc:
                    logger.warning(
                        "Failed delivering push update for subscription=%s: %s",
                        sub.get("subscription_id"),
                        exc,
                    )
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break

        if delivered:
            logger.info(
                "[INFO] Delivered feed push updates for coordination=%s subscriptions=%d items=%d",
                coordination_request_id,
                delivered,
                len(item_ids),
            )
    except Exception as exc:
        logger.warning("Skipping feed push publish due to subscription lookup error: %s", exc)


def _cancel_coordination_linked_subscriptions(
    coordination_request_id: str,
    *,
    terminal_state: str,
) -> int:
    if not coordination_request_id:
        return 0
    if not _feed_subscriptions_enabled():
        return 0

    ddb = _get_ddb()
    now = _now_z()
    cancelled = 0
    expr_names = {"#state": "state"}
    expr_values = {
        ":rid": _serialize(coordination_request_id),
        ":active": _serialize("active"),
    }
    filter_expr = "coordination_request_id = :rid AND #state = :active"
    last_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "TableName": FEED_SUBSCRIPTIONS_TABLE,
            "FilterExpression": filter_expr,
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_values,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        page = ddb.scan(**kwargs)
        for raw_item in page.get("Items", []):
            sub = _deserialize(raw_item)
            sub_id = str(sub.get("subscription_id") or "")
            if not sub_id:
                continue
            try:
                ddb.update_item(
                    TableName=FEED_SUBSCRIPTIONS_TABLE,
                    Key={"subscription_id": _serialize(sub_id)},
                    ConditionExpression="attribute_exists(subscription_id) AND #state = :active",
                    UpdateExpression=(
                        "SET #state = :cancelled, cancelled_at = :ts, updated_at = :ts, "
                        "cancelled_reason = :reason"
                    ),
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={
                        ":active": _serialize("active"),
                        ":cancelled": _serialize("cancelled"),
                        ":ts": _serialize(now),
                        ":reason": _serialize(
                            f"coordination_terminal:{terminal_state}:{coordination_request_id}"
                        ),
                    },
                )
                cancelled += 1
            except ddb.exceptions.ConditionalCheckFailedException:
                continue
            except Exception as exc:
                logger.warning("Failed cancelling subscription %s: %s", sub_id, exc)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            break

    if cancelled:
        logger.info(
            "[INFO] Auto-cancelled %d feed subscriptions for coordination=%s state=%s",
            cancelled,
            coordination_request_id,
            terminal_state,
        )
    return cancelled


# ---------------------------------------------------------------------------
# v0.3 Multi-provider callback adapters
# ---------------------------------------------------------------------------


def _normalize_callback_body(body: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Normalize provider-specific callback payload into canonical v0.3 schema.

    Each provider may send completion events in different formats. This
    adapter normalizes them into the standard callback contract:
        {state, dispatch_id, summary, execution_id, provider, details, feed_updates}
    """
    if provider == "claude_agent_sdk":
        return _normalize_claude_sdk_callback(body)
    elif provider == "openai_codex":
        return _normalize_codex_callback(body)
    elif provider == "aws_native":
        return _normalize_aws_native_callback(body)
    # Fallback: treat as already-normalized generic callback
    return body


def _normalize_claude_sdk_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Claude Agent SDK completion event.

    Claude Agent SDK callbacks may arrive as structured completion events
    with fields: result, session_id, model, usage, stop_reason, output.
    """
    normalized: Dict[str, Any] = {
        "provider": "claude_agent_sdk",
    }

    # Map SDK completion status to coordination state
    stop_reason = str(body.get("stop_reason") or body.get("status") or "").lower()
    if stop_reason in ("end_turn", "tool_use", "completed", "succeeded"):
        normalized["state"] = "succeeded"
    elif stop_reason in ("max_tokens", "timeout", "error", "failed"):
        normalized["state"] = "failed"
    elif stop_reason in ("cancelled", "canceled"):
        normalized["state"] = "cancelled"
    else:
        # If 'state' is passed directly (generic callback), use it
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(body.get("dispatch_id") or "")
    normalized["execution_id"] = str(
        body.get("execution_id") or body.get("session_id") or ""
    )

    # Build summary from SDK output
    sdk_output = body.get("output") or body.get("result")
    if isinstance(sdk_output, str):
        normalized["summary"] = sdk_output[:2000]
    elif isinstance(sdk_output, dict):
        normalized["summary"] = str(sdk_output.get("summary") or sdk_output.get("text") or "")[:2000]
    else:
        normalized["summary"] = str(body.get("summary") or "")[:2000]

    # Preserve SDK-specific details
    details: Dict[str, Any] = {}
    for sdk_field in (
        "model",
        "usage",
        "stop_reason",
        "session_id",
        "fork_from_session_id",
        "permission_mode",
        "allowed_tools",
    ):
        if body.get(sdk_field) is not None:
            details[sdk_field] = body[sdk_field]
    if body.get("details") and isinstance(body["details"], dict):
        details.update(body["details"])
    normalized["details"] = details

    normalized["feed_updates"] = body.get("feed_updates") or {}

    return normalized


def _normalize_codex_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize OpenAI Codex completion event.

    Codex callbacks may arrive from SSM command output or from Codex App
    Server JSON-RPC responses with fields: thread_id, turn_id, turn_status,
    completed_at, output.
    """
    normalized: Dict[str, Any] = {
        "provider": "openai_codex",
    }

    # Map Codex turn status to coordination state
    turn_status = str(body.get("turn_status") or body.get("status") or "").lower()
    if turn_status in ("completed", "succeeded", "success"):
        normalized["state"] = "succeeded"
    elif turn_status in ("failed", "error", "errored"):
        normalized["state"] = "failed"
    elif turn_status in ("cancelled", "canceled", "stopped"):
        normalized["state"] = "cancelled"
    else:
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(body.get("dispatch_id") or "")
    normalized["execution_id"] = str(
        body.get("execution_id") or body.get("thread_id") or ""
    )
    normalized["summary"] = str(body.get("summary") or body.get("output") or "")[:2000]

    details: Dict[str, Any] = {}
    for codex_field in (
        "provider_session_id",
        "thread_id",
        "turn_id",
        "turn_status",
        "completed_at",
        "model",
    ):
        if body.get(codex_field) is not None:
            details[codex_field] = body[codex_field]
    if body.get("details") and isinstance(body["details"], dict):
        details.update(body["details"])
    normalized["details"] = details

    normalized["feed_updates"] = body.get("feed_updates") or {}

    return normalized


def _update_provider_session_from_callback(
    request: Dict[str, Any],
    *,
    provider: str,
    execution_id: str,
    details: Dict[str, Any],
) -> None:
    existing = dict(request.get("provider_session") or {})
    merged = dict(existing)
    merged["provider"] = provider

    if execution_id:
        merged["execution_id"] = execution_id

    if provider == "openai_codex":
        for field in (
            "provider_session_id",
            "thread_id",
            "turn_id",
            "turn_status",
            "completed_at",
            "model",
        ):
            value = details.get(field)
            if value is not None and value != "":
                merged[field] = value
    elif provider == "claude_agent_sdk":
        for field in (
            "session_id",
            "fork_from_session_id",
            "permission_mode",
            "allowed_tools",
            "completed_at",
            "model",
        ):
            value = details.get(field)
            if value is not None and value != "":
                merged[field] = value

    request["provider_session"] = merged


def _normalize_aws_native_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize AWS-native callback (EventBridge event or SQS message).

    AWS-native callbacks come from Step Functions, Lambda, or CodeBuild
    completion events. The detail payload may include status, output,
    execution_arn, and state_machine fields.
    """
    normalized: Dict[str, Any] = {
        "provider": "aws_native",
    }

    # EventBridge detail may nest the actual payload
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else body

    status = str(detail.get("status") or detail.get("state") or "").lower()
    if status in ("succeeded", "completed", "success"):
        normalized["state"] = "succeeded"
    elif status in ("failed", "aborted", "timed_out", "timeout"):
        normalized["state"] = "failed"
    elif status in ("cancelled", "canceled"):
        normalized["state"] = "cancelled"
    else:
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(
        detail.get("dispatch_id") or body.get("dispatch_id") or ""
    )
    normalized["execution_id"] = str(
        detail.get("execution_id")
        or detail.get("executionArn")
        or detail.get("command_id")
        or ""
    )
    normalized["summary"] = str(
        detail.get("summary") or detail.get("output") or detail.get("cause") or ""
    )[:2000]

    details: Dict[str, Any] = {}
    for aws_field in ("executionArn", "stateMachineArn", "command_id", "build_id",
                       "build_status", "source", "detail-type"):
        val = body.get(aws_field) or detail.get(aws_field)
        if val is not None:
            details[aws_field] = val
    if detail.get("details") and isinstance(detail["details"], dict):
        details.update(detail["details"])
    normalized["details"] = details

    normalized["feed_updates"] = detail.get("feed_updates") or body.get("feed_updates") or {}

    return normalized


# ---------------------------------------------------------------------------
# v0.3 Dispatch-level plan status tracking
# ---------------------------------------------------------------------------


def _compute_plan_status(request: Dict[str, Any]) -> Dict[str, Any]:
    """Compute plan-level status from individual dispatch outcomes.

    For requests with a dispatch_plan, each dispatch can independently reach
    a terminal state. This returns a summary of completion progress.
    """
    dispatch_plan = request.get("dispatch_plan") or {}
    dispatches = dispatch_plan.get("dispatches") or []

    if not dispatches:
        # Legacy single-dispatch request — derive from request state
        state = request.get("state", "")
        if state in _VALID_TERMINAL_STATES:
            return {"completed": 1, "pending": 0, "failed": 1 if state == "failed" else 0, "total": 1}
        return {"completed": 0, "pending": 1, "failed": 0, "total": 1}

    dispatch_outcomes = request.get("dispatch_outcomes") or {}
    completed = 0
    failed = 0
    pending = 0

    for d in dispatches:
        did = d.get("dispatch_id", "")
        outcome = dispatch_outcomes.get(did, {})
        d_state = outcome.get("state", "pending")
        if d_state == "succeeded":
            completed += 1
        elif d_state == "failed":
            failed += 1
            completed += 1  # failed is terminal, counts as "done"
        elif d_state == "cancelled":
            completed += 1
        else:
            pending += 1

    return {
        "completed": completed,
        "pending": pending,
        "failed": failed,
        "total": len(dispatches),
    }


def _update_dispatch_outcome(
    request: Dict[str, Any],
    dispatch_id: str,
    state: str,
    summary: str,
    execution_id: str,
    provider: str,
    details: Dict[str, Any],
) -> Dict[str, Any]:
    """Record a dispatch-level outcome within the request.

    For multi-dispatch plans, each dispatch reports independently.
    Returns the updated request.
    """
    outcomes = dict(request.get("dispatch_outcomes") or {})
    outcomes[dispatch_id] = {
        "state": state,
        "summary": summary[:2000],
        "execution_id": execution_id,
        "provider": provider,
        "details": details,
        "completed_at": _now_z(),
    }
    request["dispatch_outcomes"] = outcomes
    return request


def _evaluate_plan_terminal_state(request: Dict[str, Any]) -> Optional[str]:
    """Determine if all dispatches have completed and what the overall state should be.

    Returns the terminal state string if the plan is complete, or None if
    dispatches are still pending.
    """
    plan_status = _compute_plan_status(request)
    if plan_status["pending"] > 0:
        return None

    if plan_status["failed"] == 0:
        return "succeeded"

    rollback_policy = (request.get("dispatch_plan") or {}).get("rollback_policy") or {}
    on_partial = rollback_policy.get("on_partial_failure", "continue")

    if plan_status["failed"] == plan_status["total"]:
        return "failed"

    # Partial failure — depends on policy
    if on_partial == "halt_remaining":
        return "failed"
    elif on_partial == "rollback_completed":
        return "failed"
    else:
        # "continue" — if any succeeded, the plan succeeded with partial failures
        return "succeeded" if (plan_status["completed"] - plan_status["failed"]) > 0 else "failed"


# ---------------------------------------------------------------------------
# v0.3 EventBridge / SQS callback emit helpers
# ---------------------------------------------------------------------------


def _emit_callback_event(request: Dict[str, Any], callback_body: Dict[str, Any]) -> None:
    """Emit an EventBridge event for callback observability.

    Published on every callback receipt so downstream systems can react
    to coordination completion events.
    """
    try:
        eb = _get_eb()
        eb.put_events(
            Entries=[
                {
                    "Source": CALLBACK_EVENT_SOURCE,
                    "DetailType": CALLBACK_EVENT_DETAIL_TYPE,
                    "EventBusName": CALLBACK_EVENTBRIDGE_BUS,
                    "Detail": json.dumps({
                        "request_id": request["request_id"],
                        "project_id": request.get("project_id"),
                        "state": callback_body.get("state"),
                        "dispatch_id": callback_body.get("dispatch_id"),
                        "provider": callback_body.get("provider"),
                        "execution_id": callback_body.get("execution_id"),
                        "summary": (callback_body.get("summary") or "")[:500],
                        "plan_status": _compute_plan_status(request),
                        "timestamp": _now_z(),
                    }),
                }
            ]
        )
    except Exception as exc:
        logger.warning("Failed emitting callback EventBridge event: %s", exc)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _mcp_jsonrpc_response(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return _response(
        200,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        },
    )


def _mcp_jsonrpc_error(
    request_id: Any,
    *,
    code: int,
    message: str,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if data:
        body["error"]["data"] = data
    return _response(200, body)


def _mcp_to_plain(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_mcp_to_plain(item) for item in value]
    if isinstance(value, tuple):
        return [_mcp_to_plain(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _mcp_to_plain(v) for k, v in value.items()}
    if dataclasses.is_dataclass(value):
        return {str(k): _mcp_to_plain(v) for k, v in dataclasses.asdict(value).items()}
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _mcp_to_plain(model_dump(exclude_none=True))
    to_dict = getattr(value, "dict", None)
    if callable(to_dict):
        return _mcp_to_plain(to_dict())
    return str(value)


def _mcp_mime_type_for_uri(uri: str) -> str:
    uri_text = str(uri or "").strip()
    if uri_text.endswith(".json"):
        return "application/json"
    if uri_text.startswith("governance://") or uri_text.startswith("projects://reference/"):
        return "text/markdown"
    return "text/plain"


def _run_async(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Defensive fallback for runtimes that already have an active loop.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _dispatch_mcp_jsonrpc_method(method: str, params: Dict[str, Any]) -> Dict[str, Any]:
    method_name = str(method or "").strip()
    params = params if isinstance(params, dict) else {}
    module = _load_mcp_server_module()

    if method_name == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "enceladus",
                "version": "0.4.1",
            },
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
            },
        }

    if method_name in {"initialized", "notifications/initialized", "ping"}:
        return {}

    if method_name in {"tools/list", "list_tools"}:
        payload = _run_async(module.list_tools())
        return {"tools": _mcp_to_plain(payload or [])}

    if method_name in {"tools/call", "call_tool"}:
        tool_name = str(params.get("name") or "").strip()
        if not tool_name:
            raise ValueError("tools/call requires params.name")

        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ValueError("tools/call requires params.arguments to be an object")

        call_args = dict(args)
        call_args.setdefault("caller_identity", MCP_AUDIT_CALLER_IDENTITY)
        result = _run_async(module.call_tool(tool_name, call_args))
        content = _mcp_to_plain(result or [])
        is_error = any(
            isinstance(item, dict) and str(item.get("text") or "").startswith("ERROR:")
            for item in (content if isinstance(content, list) else [])
        )
        return {
            "content": content if isinstance(content, list) else [content],
            "isError": is_error,
        }

    if method_name in {"resources/list", "list_resources"}:
        payload = _run_async(module.list_resources())
        return {"resources": _mcp_to_plain(payload or [])}

    if method_name in {"resources/templates/list", "list_resource_templates"}:
        payload = _run_async(module.list_resource_templates())
        return {"resourceTemplates": _mcp_to_plain(payload or [])}

    if method_name in {"resources/read", "read_resource"}:
        uri = str(params.get("uri") or "").strip()
        if not uri:
            raise ValueError("resources/read requires params.uri")
        text = _run_async(module.read_resource(uri))
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": _mcp_mime_type_for_uri(uri),
                    "text": str(text or ""),
                }
            ]
        }

    raise KeyError(method_name)


def _handle_mcp_http(event: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    method, _ = _path_method(event)
    if method == "GET":
        return _response(
            200,
            {
                "success": True,
                "transport": "streamable_http",
                "protocol": "jsonrpc-2.0",
                "mcp_path": COORDINATION_MCP_HTTP_PATH,
                "authenticated": bool(claims),
                "methods_supported": [
                    "initialize",
                    "ping",
                    "tools/list",
                    "tools/call",
                    "resources/list",
                    "resources/templates/list",
                    "resources/read",
                ],
            },
        )

    try:
        request = _json_body(event)
    except ValueError as exc:
        return _mcp_jsonrpc_error(
            None,
            code=-32700,
            message=f"Parse error: {exc}",
        )

    request_id = request.get("id")
    method_name = request.get("method")
    params = request.get("params", {})
    jsonrpc = request.get("jsonrpc")

    if jsonrpc != "2.0" or not isinstance(method_name, str):
        return _mcp_jsonrpc_error(
            request_id,
            code=-32600,
            message="Invalid Request",
            data={"hint": "Expected JSON-RPC 2.0 object with string method"},
        )

    try:
        result = _dispatch_mcp_jsonrpc_method(method_name, params if isinstance(params, dict) else {})
        return _mcp_jsonrpc_response(request_id, result)
    except KeyError:
        return _mcp_jsonrpc_error(
            request_id,
            code=-32601,
            message=f"Method not found: {method_name}",
        )
    except ValueError as exc:
        return _mcp_jsonrpc_error(
            request_id,
            code=-32602,
            message=f"Invalid params: {exc}",
        )
    except Exception as exc:
        logger.exception("mcp http method failed: %s", method_name)
        return _mcp_jsonrpc_error(
            request_id,
            code=-32603,
            message=f"Internal error: {exc}",
        )


def _handle_capabilities() -> Dict[str, Any]:
    provider_secrets = _provider_secret_readiness()
    return _response(
        200,
        {
            "success": True,
            "capabilities": {
                "contract_version": "0.3.0",
                "execution_modes": [
                    {
                        "mode": "preflight",
                        "supported": True,
                        "description": "Host-v2 connectivity + Enceladus context checks only.",
                    },
                    {
                        "mode": "codex_full_auto",
                        "supported": True,
                        "description": (
                            "Runs OpenAI Codex managed sessions through the Responses API "
                            "with governance context preloaded via Enceladus MCP resources."
                        ),
                    },
                    {
                        "mode": "codex_app_server",
                        "supported": True,
                        "description": (
                            "Runs OpenAI Codex managed sessions through the Responses API "
                            "with session resume/fork support and MCP governance preloading."
                        ),
                    },
                    {
                        "mode": "claude_headless",
                        "supported": ENABLE_CLAUDE_HEADLESS,
                        "description": "Runs Claude CLI headless on host-v2 (gated by env).",
                    },
                    {
                        "mode": "claude_agent_sdk",
                        "supported": True,
                        "description": "Claude Agent SDK managed session with structured completion events.",
                    },
                    {
                        "mode": "aws_step_function",
                        "supported": True,
                        "description": "AWS Step Functions / Lambda / CodeBuild native execution.",
                    },
                ],
                "providers": {
                    "openai_codex": {
                        "status": provider_secrets["openai_codex"].get("secret_status"),
                        "managed_sessions": True,
                        "execution_modes": ["codex_full_auto", "codex_app_server"],
                        "default_model": DEFAULT_OPENAI_CODEX_MODEL,
                        "key_env_var": "CODEX_API_KEY",
                        "api_endpoint": f"{OPENAI_API_BASE_URL.rstrip('/')}/v1/responses",
                        "transport_by_mode": {
                            "codex_app_server": "openai_responses_api",
                            "codex_full_auto": "openai_responses_api",
                        },
                        "secret_ref_configured": provider_secrets["openai_codex"].get("secret_ref_configured"),
                        "secret_ref": provider_secrets["openai_codex"].get("secret_ref"),
                        "secret_arn": provider_secrets["openai_codex"].get("secret_arn"),
                        "rotation_policy": provider_secrets["openai_codex"].get("rotation_policy"),
                        "last_rotated": provider_secrets["openai_codex"].get("last_rotated"),
                        "next_rotation_due": provider_secrets["openai_codex"].get("next_rotation_due"),
                        "days_until_rotation_due": provider_secrets["openai_codex"].get("days_until_rotation_due"),
                        "rotation_warning": provider_secrets["openai_codex"].get("rotation_warning"),
                        "callback_mechanism": "Direct OpenAI Responses API response (synchronous)",
                        "governance_context_source": "enceladus_mcp_resources",
                        "mcp_server_configuration": {
                            "url": f"{COORDINATION_PUBLIC_BASE_URL.rstrip('/')}{COORDINATION_MCP_HTTP_PATH}",
                            "label": "Enceladus MCP Remote Gateway",
                            "transport": "streamable_http",
                            "auth_mode": "cognito_or_internal_key",
                            "auth_header": "X-Coordination-Internal-Key",
                            "access_token_secret_ref": provider_secrets["openai_codex"].get("secret_ref"),
                            "compatibility": {
                                "chatgpt_custom_gpt": True,
                                "managed_codex_sessions": True,
                            },
                        },
                    },
                    "claude_agent_sdk": {
                        "status": provider_secrets["claude_agent_sdk"].get("secret_status"),
                        "managed_sessions": True,
                        "execution_modes": ["claude_headless", "claude_agent_sdk"],
                        "key_env_var": "ANTHROPIC_API_KEY",
                        "default_model": DEFAULT_CLAUDE_AGENT_MODEL,
                        "api_version": ANTHROPIC_API_VERSION,
                        "governance_context_source": "enceladus_mcp_resources",
                        "default_permission_mode": "acceptEdits",
                        "permission_modes": sorted(_CLAUDE_PERMISSION_MODES),
                        "allowed_tools": sorted(_ENCELADUS_ALLOWED_TOOLS),
                        "model_routing": {
                            "task_complexities": sorted(_CLAUDE_VALID_TASK_COMPLEXITIES),
                            "routing_table": _CLAUDE_MODEL_ROUTING,
                            "description": "Set task_complexity in provider_preferences to auto-select model",
                        },
                        "features": {
                            "system_prompt": True,
                            "prompt_caching": {
                                "supported": True,
                                "default_ttl": CLAUDE_PROMPT_CACHE_TTL,
                                "description": "System prompts cached with ephemeral TTL",
                            },
                            "extended_thinking": {
                                "supported": True,
                                "adaptive_models": sorted(_CLAUDE_ADAPTIVE_THINKING_MODELS),
                                "budget_range": [CLAUDE_THINKING_BUDGET_MIN, CLAUDE_THINKING_BUDGET_MAX],
                                "default_budget": CLAUDE_THINKING_BUDGET_DEFAULT,
                            },
                            "streaming": True,
                            "token_counting": True,
                            "cost_attribution": True,
                        },
                        "secret_ref_configured": provider_secrets["claude_agent_sdk"].get("secret_ref_configured"),
                        "secret_ref": provider_secrets["claude_agent_sdk"].get("secret_ref"),
                        "secret_arn": provider_secrets["claude_agent_sdk"].get("secret_arn"),
                        "rotation_policy": provider_secrets["claude_agent_sdk"].get("rotation_policy"),
                        "last_rotated": provider_secrets["claude_agent_sdk"].get("last_rotated"),
                        "next_rotation_due": provider_secrets["claude_agent_sdk"].get("next_rotation_due"),
                        "days_until_rotation_due": provider_secrets["claude_agent_sdk"].get("days_until_rotation_due"),
                        "rotation_warning": provider_secrets["claude_agent_sdk"].get("rotation_warning"),
                        "callback_mechanism": "Direct Anthropic Messages API response (synchronous or streaming SSE)",
                    },
                    "aws_native": {
                        "status": "active",
                        "managed_sessions": False,
                        "execution_modes": ["aws_step_function"],
                        "callback_mechanism": "EventBridge event or SQS message",
                        "eventbridge_bus": CALLBACK_EVENTBRIDGE_BUS,
                        "detail_type": CALLBACK_EVENT_DETAIL_TYPE,
                    },
                },
                "host_v2": {
                    "instance_id": HOST_V2_INSTANCE_ID,
                    "project": HOST_V2_PROJECT,
                    "work_root": HOST_V2_WORK_ROOT,
                    "mcp_bootstrap": {
                        "mode": "setup_if_missing_once",
                        "profile_path": HOST_V2_MCP_PROFILE_PATH,
                        "marker_path": HOST_V2_MCP_MARKER_PATH,
                        "max_attempts": HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS,
                        "retry_backoff_seconds": list(HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS),
                        "bootstrap_script": HOST_V2_MCP_BOOTSTRAP_SCRIPT,
                    },
                    "fleet_template": {
                        "enabled": HOST_V2_FLEET_ENABLED,
                        "ready": bool(HOST_V2_FLEET_LAUNCH_TEMPLATE_ID),
                        "launch_template_id": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
                        "launch_template_version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
                        "user_data_template": HOST_V2_FLEET_USER_DATA_TEMPLATE,
                        "fallback_to_static": HOST_V2_FLEET_FALLBACK_TO_STATIC,
                        "max_active_dispatches": HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES,
                        "readiness_timeout_seconds": HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS,
                        "readiness_poll_seconds": HOST_V2_FLEET_READINESS_POLL_SECONDS,
                        "instance_ttl_seconds": HOST_V2_FLEET_INSTANCE_TTL_SECONDS,
                        "sweep_on_dispatch": HOST_V2_FLEET_SWEEP_ON_DISPATCH,
                        "sweep_grace_seconds": HOST_V2_FLEET_SWEEP_GRACE_SECONDS,
                        "auto_terminate_on_terminal": HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL,
                    },
                },
                "enceladus_mcp_profile": {
                    "installer": HOST_V2_ENCELADUS_MCP_INSTALLER,
                    "server_name": "enceladus",
                    "profile_path": HOST_V2_MCP_PROFILE_PATH,
                    "marker_path": HOST_V2_MCP_MARKER_PATH,
                    "mcp_server_configuration": {
                        "server_name": "enceladus",
                        "server_label": "Enceladus Governance & System Resource API",
                        "auth_mode": "profile_entry",
                        "description": "Stdio-based MCP server for agent sessions. Installed via .claude/mcp.json profile. Provides access to DynamoDB tracker (tasks/issues/features), projects, documents, governance resources, and deployment APIs.",
                        "transport": "stdio",
                        "tools_provided": 27,
                        "resources_provided": 3,
                        "remote_gateway": {
                            "url": f"{COORDINATION_PUBLIC_BASE_URL.rstrip('/')}{COORDINATION_MCP_HTTP_PATH}",
                            "transport": "streamable_http",
                            "auth_mode": "cognito_or_internal_key",
                            "auth_header": "X-Coordination-Internal-Key",
                            "methods_supported": [
                                "initialize",
                                "ping",
                                "tools/list",
                                "tools/call",
                                "resources/list",
                                "resources/templates/list",
                                "resources/read",
                            ],
                            "compatibility": {
                                "chatgpt_custom_gpt": True,
                                "managed_codex_sessions": True,
                            },
                        },
                    },
                },
                "callback": {
                    "endpoint": "POST /api/v1/coordination/requests/{requestId}/callback",
                    "auth": "X-Coordination-Callback-Token header",
                    "supported_providers": sorted(_VALID_PROVIDERS),
                    "eventbridge_ingestion": {
                        "bus": CALLBACK_EVENTBRIDGE_BUS,
                        "source": CALLBACK_EVENT_SOURCE,
                        "detail_type": CALLBACK_EVENT_DETAIL_TYPE,
                    },
                    "sqs_ingestion": {
                        "configured": bool(CALLBACK_SQS_QUEUE_URL),
                    },
                    "multi_dispatch_support": True,
                },
                "reliability_controls": {
                    "idempotency_window_seconds": IDEMPOTENCY_WINDOW_SECONDS,
                    "idempotency_index": COORDINATION_GSI_IDEMPOTENCY,
                    "max_dispatch_attempts": MAX_DISPATCH_ATTEMPTS,
                    "retry_backoff_seconds": list(_RETRY_BACKOFF_SECONDS),
                    "retriable_failure_classes": sorted(_RETRIABLE_FAILURE_CLASSES),
                    "non_retriable_failure_classes": sorted(_NON_RETRIABLE_FAILURE_CLASSES),
                    "lock_ttl_buffer_seconds": DISPATCH_LOCK_BUFFER_SECONDS,
                    "dead_letter_timeout_multiplier": DEAD_LETTER_TIMEOUT_MULTIPLIER,
                },
                "intake": {
                    "debounce_window_seconds": DEBOUNCE_WINDOW_SECONDS,
                    "dedup_by": "record_id_overlap",
                    "merge_behavior": {
                        "initiative_title": "concatenate_with_plus",
                        "outcomes": "union_dedup",
                        "constraints": "deep_merge_latest_wins",
                        "related_record_ids": "union_set",
                    },
                    "promotion": "on_read",
                },
                "mcp_remote_gateway": {
                    "url": f"{COORDINATION_PUBLIC_BASE_URL.rstrip('/')}{COORDINATION_MCP_HTTP_PATH}",
                    "transport": "streamable_http",
                    "auth_mode": "cognito_or_internal_key",
                    "auth_header": "X-Coordination-Internal-Key",
                    "compatibility": {
                        "chatgpt_custom_gpt": True,
                        "managed_codex_sessions": True,
                    },
                },
                "deterministic_completion_path": "GET /api/v1/coordination/requests/{requestId}",
            },
        },
    )


def _handle_create_request(event: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    try:
        body = _json_body(event)
    except ValueError as exc:
        return _error(400, str(exc))

    project_id = str(body.get("project_id") or "").strip()
    initiative_title = str(body.get("initiative_title") or "").strip()
    requestor_session_id = str(body.get("requestor_session_id") or "").strip()

    if not project_id:
        return _error(400, "Missing required field 'project_id'")
    if not initiative_title:
        return _error(400, "Missing required field 'initiative_title'")
    if len(initiative_title) > MAX_TITLE_LENGTH:
        return _error(400, f"'initiative_title' exceeds max length ({MAX_TITLE_LENGTH})")
    if not requestor_session_id:
        return _error(400, "Missing required field 'requestor_session_id'")

    try:
        outcomes = _normalize_outcomes(body.get("outcomes"))
        constraints = _validate_constraints(body.get("constraints"))
        # v0.3: accept both 'provider_preferences' and legacy 'provider_session'
        provider_prefs_raw = body.get("provider_preferences") or body.get("provider_session")
        provider_session = _validate_provider_session(provider_prefs_raw)
        execution_mode = _coerce_execution_mode(body.get("execution_mode"))
        _load_project_meta(project_id)
    except (ValueError, RuntimeError) as exc:
        return _error(400, str(exc))

    # v0.3: optional callback_config from requestor
    callback_config = body.get("callback_config")
    if callback_config is not None:
        if not isinstance(callback_config, dict):
            return _error(400, "'callback_config' must be an object")

    explicit_idempotency = body.get("idempotency_key")
    if explicit_idempotency is not None and not isinstance(explicit_idempotency, str):
        return _error(400, "'idempotency_key' must be a string when provided")

    try:
        idempotency_key = _derive_idempotency_key(
            project_id=project_id,
            initiative_title=initiative_title,
            outcomes=outcomes,
            requestor_session_id=requestor_session_id,
            explicit=explicit_idempotency,
        )
    except ValueError as exc:
        return _error(400, str(exc))

    existing = _find_recent_by_idempotency(project_id, idempotency_key)
    if existing and existing.get("state") in {"intake_received", "queued", "dispatching", "running", "succeeded"}:
        return _response(
            200,
            {
                "success": True,
                "reused": True,
                "request": _redact_request(existing),
            },
        )

    # --- Intake debounce: on-read promotion of expired intake_received requests ---
    try:
        promoted = _promote_expired_intake_requests(project_id)
        if promoted:
            logger.info("[INFO] promoted %d expired intake request(s): %s", len(promoted), promoted)
    except Exception as exc:
        logger.warning("intake promotion during create failed (non-fatal): %s", exc)

    # --- Intake debounce: record-ID dedup check ---
    now_epoch = _unix_now()
    incoming_record_ids = _extract_record_ids_from_body(body)

    if incoming_record_ids:
        dedup_match = _find_dedup_match(project_id, incoming_record_ids, now_epoch)
        if dedup_match:
            try:
                merged = _merge_requests(dedup_match, body, requestor_session_id)
                _update_request(merged)
                logger.info(
                    "[INFO] merged incoming request into %s (overlapping IDs: %s)",
                    merged["request_id"],
                    incoming_record_ids & _extract_record_ids_from_request(dedup_match),
                )
                return _response(
                    200,
                    {
                        "success": True,
                        "request": _redact_request(merged),
                        "merged_with": merged["request_id"],
                    },
                )
            except Exception as exc:
                logger.warning("dedup merge failed (proceeding with new request): %s", exc)

    # --- Create new coordination request in intake_received state ---
    request_id = _new_request_id()
    now = _now_z()
    now_epoch = _unix_now()
    callback_token = _new_callback_token()
    callback_expiry_epoch = now_epoch + CALLBACK_TOKEN_TTL_SECONDS
    debounce_expires_epoch = now_epoch + DEBOUNCE_WINDOW_SECONDS
    idempotency_expires_epoch = now_epoch + IDEMPOTENCY_WINDOW_SECONDS
    debounce_expires_iso = (
        dt.datetime.fromtimestamp(debounce_expires_epoch, tz=dt.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    assigned_to = str(body.get("assigned_to") or "AGENT-003")

    try:
        decomposition = _decompose_and_create_tracker_artifacts(
            project_id=project_id,
            initiative_title=initiative_title,
            outcomes=outcomes,
            request_id=request_id,
            assigned_to=assigned_to,
        )
    except Exception as exc:
        logger.exception("decomposition failed")
        return _error(500, f"Failed creating tracker decomposition artifacts: {exc}")

    item = {
        "request_id": request_id,
        "project_id": project_id,
        "initiative_title": initiative_title,
        "outcomes": outcomes,
        "constraints": constraints,
        "requestor_session_id": requestor_session_id,
        "related_record_ids": sorted(incoming_record_ids) if incoming_record_ids else [],
        "request_timestamp": now,
        "created_at": now,
        "updated_at": now,
        "created_epoch": now_epoch,
        "updated_epoch": now_epoch,
        "state": _STATE_INTAKE_RECEIVED,
        "state_history": [
            {
                "timestamp": now,
                "from": None,
                "to": _STATE_INTAKE_RECEIVED,
                "reason": "Request created — entering debounce window",
            }
        ],
        "debounce_window_expires_epoch": debounce_expires_epoch,
        "debounce_window_expires": debounce_expires_iso,
        "source_sessions": [requestor_session_id],
        "source_requests": [],
        "execution_mode": execution_mode,
        "execution_provider": "host_v2",
        "idempotency_key": idempotency_key,
        "idempotency_expires_epoch": idempotency_expires_epoch,
        "ttl_epoch": idempotency_expires_epoch,
        "sync_version": 1,
        "dispatch_attempts": 0,
        "lock_expires_epoch": 0,
        "provider_session": provider_session,
        "callback_token": callback_token,
        "callback_token_expires_epoch": callback_expiry_epoch,
        "created_by": claims.get("email") or claims.get("cognito:username") or "unknown",
        "feature_id": decomposition["feature_id"],
        "task_ids": decomposition["task_ids"],
        "issue_ids": decomposition["issue_ids"],
        "acceptance_criteria": decomposition["acceptance_criteria"],
        "governance_hash": decomposition.get("governance_hash"),
        "result": None,
        "dispatch_outcomes": {},
        "callback_config": callback_config or {},
        "mcp": {
            "last_create": _mcp.coordination_request_create(
                request_id=request_id,
                project_id=project_id,
                state=_STATE_INTAKE_RECEIVED,
                requestor_session_id=requestor_session_id,
            )
        },
    }

    try:
        _put_request(item)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return _error(409, "Coordination request ID collision; retry")
        logger.exception("put request failed")
        return _error(500, f"Failed persisting coordination request: {exc}")

    _append_tracker_history(
        decomposition["feature_id"],
        "worklog",
        f"Coordination request {request_id} intake_received (debounce expires {debounce_expires_iso})",
        governance_hash=decomposition.get("governance_hash"),
        coordination_request_id=request_id,
    )

    return _response(
        201,
        {
            "success": True,
            "request": {
                **_redact_request(item),
                "debounce_window_expires": debounce_expires_iso,
                "merged_with": None,
            },
        },
    )


def _handle_get_request(request_id: str) -> Dict[str, Any]:
    try:
        request = _get_request(request_id)
    except Exception as exc:
        return _error(500, f"Failed reading request: {exc}")

    if not request:
        return _error(404, f"Request '{request_id}' not found")

    # --- Intake debounce: on-read promotion of expired intake_received requests ---
    project_id = request.get("project_id")
    if project_id:
        try:
            promoted = _promote_expired_intake_requests(project_id)
            if promoted:
                logger.info("[INFO] on-read promoted %d intake request(s): %s", len(promoted), promoted)
                # Re-read the request if it was among those promoted
                if request_id in promoted:
                    request = _get_request(request_id) or request
        except Exception as exc:
            logger.warning("intake promotion during get failed (non-fatal): %s", exc)

    try:
        request = _refresh_request_from_ssm(request)
    except Exception as exc:
        logger.exception("ssm refresh failed")
        return _error(500, f"Failed refreshing request status: {exc}")

    request.setdefault("mcp", {})
    request["mcp"]["last_get"] = _mcp.coordination_request_get(request_id=request_id)
    return _response(200, {"success": True, "request": _redact_request(request)})


def _handle_dispatch_request(event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    request = _get_request(request_id)
    if not request:
        return _error(404, f"Request '{request_id}' not found")

    if request.get("state") == _STATE_INTAKE_RECEIVED:
        debounce_expires_epoch = int(request.get("debounce_window_expires_epoch") or 0)
        retry_in = max(0, debounce_expires_epoch - _unix_now()) if debounce_expires_epoch else 0
        return _error(
            409,
            "Request is still in debounce window",
            code="DEBOUNCE_ACTIVE",
            retryable=True,
            request=_redact_request(request),
            debounce_expires_epoch=debounce_expires_epoch or None,
            retry_in_seconds=retry_in,
        )

    if request.get("state") not in {"queued", "failed"}:
        return _error(
            409,
            f"Request state '{request.get('state')}' is not dispatchable",
            request=_redact_request(request),
        )

    dispatch_attempts = int(request.get("dispatch_attempts") or 0)
    if dispatch_attempts >= MAX_DISPATCH_ATTEMPTS:
        if request.get("state") == _STATE_QUEUED:
            _append_state_transition(
                request,
                "failed",
                "Dispatch cap reached",
                extra={"reason": "max_attempts_exceeded", "max_attempts": MAX_DISPATCH_ATTEMPTS},
            )
        request["result"] = {
            "summary": "Dispatch attempts exceeded max threshold",
            "failure_class": "max_attempts_exceeded",
        }
        _move_to_dead_letter(request, "Retries exhausted (max_attempts_exceeded)", failure_class="max_attempts_exceeded")
        _update_request(request)
        _finalize_tracker_from_request(request)
        return _error(
            409,
            "Dispatch attempts exceeded max threshold",
            max_attempts=MAX_DISPATCH_ATTEMPTS,
            request=_redact_request(request),
        )

    try:
        body = _json_body(event)
    except ValueError as exc:
        return _error(400, str(exc))

    try:
        provider_prefs_raw = body.get("provider_preferences") or body.get("provider_session")
        provider_session = _validate_provider_session(provider_prefs_raw)
    except ValueError as exc:
        return _error(400, str(exc))

    if request.get("state") == _STATE_QUEUED:
        try:
            request = _ensure_request_dispatch_plan(request, persist=True)
        except Exception as exc:
            logger.warning(
                "dispatch_plan generation before dispatch failed for %s (falling back to legacy routing): %s",
                request_id,
                exc,
            )

    requested_dispatch_id = str(body.get("dispatch_id") or "").strip()
    if requested_dispatch_id and not re.fullmatch(r"[A-Za-z0-9-]{6,64}", requested_dispatch_id):
        return _error(400, "'dispatch_id' must match [A-Za-z0-9-]{6,64}")

    plan_entry = None
    try:
        plan_entry = _resolve_dispatch_entry_from_plan(request, requested_dispatch_id)
    except ValueError as exc:
        return _error(400, str(exc))
    except RuntimeError as exc:
        return _error(409, str(exc), request=_redact_request(request))

    planned_provider = ""
    if plan_entry:
        dispatch_id = str(plan_entry.get("dispatch_id") or "").strip()
        if not dispatch_id:
            return _error(500, "Dispatch plan entry is missing dispatch_id")
        if not re.fullmatch(r"[A-Za-z0-9-]{6,64}", dispatch_id):
            return _error(500, f"Dispatch plan entry has invalid dispatch_id '{dispatch_id}'")

        planned_provider = str(plan_entry.get("provider") or "").strip().lower()
        try:
            execution_mode = _coerce_execution_mode(
                plan_entry.get("execution_mode") or body.get("execution_mode") or request.get("execution_mode")
            )
        except ValueError as exc:
            return _error(400, str(exc))

        requested_mode_raw = str(body.get("execution_mode") or "").strip()
        if requested_mode_raw:
            try:
                requested_mode = _coerce_execution_mode(requested_mode_raw)
            except ValueError as exc:
                return _error(400, str(exc))
            if requested_mode != execution_mode:
                return _error(
                    409,
                    f"Dispatch '{dispatch_id}' is pinned to execution_mode '{execution_mode}' by dispatch_plan",
                    requested_execution_mode=requested_mode,
                    plan_execution_mode=execution_mode,
                )

        provider_config = plan_entry.get("provider_config") or {}
        if isinstance(provider_config, dict):
            merged_provider_session = {
                **(request.get("provider_session") or {}),
                **provider_session,
            }
            for key in ("model", "thread_id", "fork_from_thread_id", "max_turns"):
                value = provider_config.get(key)
                if value not in (None, ""):
                    merged_provider_session[key] = value
            provider_session = merged_provider_session
    else:
        try:
            execution_mode = _coerce_execution_mode(body.get("execution_mode") or request.get("execution_mode"))
        except ValueError as exc:
            return _error(400, str(exc))
        dispatch_id = requested_dispatch_id or _new_dispatch_id()

    preflight = _lambda_provider_preflight(execution_mode, timeout_seconds=5)
    if not preflight.get("passed"):
        failed = next((item for item in preflight.get("results", []) if not item.get("ok")), {})
        error_payload = {
            "stage": "provider_preflight",
            "provider": failed.get("provider"),
            "secret_ref": failed.get("secret_ref"),
            "secret_arn": failed.get("secret_arn") or failed.get("secret_ref"),
            "failure_reason": failed.get("failure_reason"),
            "timestamp": failed.get("checked_at") or _now_z(),
        }
        logger.error("[ERROR] %s", json.dumps(error_payload, sort_keys=True))
        return _error(
            409,
            "Provider preflight failed",
            preflight=preflight,
            provider=error_payload["provider"],
            secret_arn=error_payload["secret_arn"],
            failure_reason=error_payload["failure_reason"],
            timestamp=error_payload["timestamp"],
        )

    prompt = body.get("prompt")
    if prompt is not None and not isinstance(prompt, str):
        return _error(400, "'prompt' must be a string when provided")
    allow_host_concurrency_override = bool(body.get("allow_host_concurrency_override"))
    host_allocation = str(body.get("host_allocation") or "auto").strip().lower()
    if host_allocation not in {"auto", "static", "fleet"}:
        return _error(400, "'host_allocation' must be one of ['auto', 'static', 'fleet']")
    if not re.fullmatch(r"[A-Za-z0-9-]{6,64}", dispatch_id):
        return _error(400, "'dispatch_id' must match [A-Za-z0-9-]{6,64}")

    now = _now_z()
    now_epoch = _unix_now()
    lock_expires_epoch = now_epoch + HOST_V2_TIMEOUT_SECONDS + DISPATCH_LOCK_BUFFER_SECONDS
    current_attempt = dispatch_attempts + 1

    try:
        direct_dispatch_mode = execution_mode in {"claude_agent_sdk", "codex_app_server", "codex_full_auto"}
        uses_host_dispatch = not direct_dispatch_mode
        uses_fleet_dispatch = uses_host_dispatch and host_allocation in {"auto", "fleet"} and _fleet_launch_ready()
        if uses_host_dispatch and not allow_host_concurrency_override:
            project_id = str(request.get("project_id") or "")
            if uses_fleet_dispatch:
                active_host_dispatches = _count_active_host_dispatches(
                    project_id,
                    current_request_id=request_id,
                )
                if (
                    HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES > 0
                    and active_host_dispatches >= HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES
                ):
                    return _error(
                        409,
                        "Fleet capacity limit reached for host-backed dispatches",
                        active_host_dispatches=active_host_dispatches,
                        max_active_host_dispatches=HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES,
                    )
            else:
                active_host_dispatch = _find_active_host_dispatch(
                    project_id,
                    request_id,
                    instance_id=HOST_V2_INSTANCE_ID,
                )
                if active_host_dispatch:
                    return _error(
                        409,
                        "Active host dispatch exists for this project",
                        active_dispatch=active_host_dispatch,
                    )

        if not _acquire_dispatch_lock(request_id, lock_expires_epoch):
            return _error(409, "Request is already locked for dispatch", lock_expires_epoch=request.get("lock_expires_epoch"))

        _append_state_transition(
            request,
            _STATE_DISPATCHING,
            "Dispatch requested",
            extra={"execution_mode": execution_mode},
        )

        if provider_session:
            request["provider_session"] = {
                **(request.get("provider_session") or {}),
                **provider_session,
            }

        require_related_mutation_guard = _requires_related_record_mutation_guard(
            request,
            execution_mode,
        )
        related_snapshots_before: Dict[str, Optional[Dict[str, Any]]] = {}
        if require_related_mutation_guard:
            related_snapshots_before = _collect_tracker_snapshots(
                request.get("related_record_ids") or []
            )

        if execution_mode == "claude_agent_sdk":
            dispatch_meta = _dispatch_claude_api(
                request=request,
                prompt=prompt,
                dispatch_id=dispatch_id,
            )
        elif execution_mode in {"codex_app_server", "codex_full_auto"}:
            dispatch_meta = _dispatch_openai_codex_api(
                request=request,
                prompt=prompt,
                dispatch_id=dispatch_id,
                execution_mode=execution_mode,
            )
        else:
            dispatch_meta = _send_dispatch(
                request,
                execution_mode=execution_mode,
                prompt=prompt,
                dispatch_id=dispatch_id,
                host_allocation=host_allocation,
            )

        request.setdefault("mcp", {})
        request["mcp"]["last_dispatch"] = _mcp.coordination_request_dispatch(
            request_id=request_id,
            execution_mode=execution_mode,
            provider_session=request.get("provider_session") or {},
        )

        running_reason = "SSM dispatch accepted"
        running_extra: Dict[str, Any] = {"command_id": dispatch_meta.get("command_id")}
        running_provider = planned_provider or "host_v2"
        running_summary = f"Dispatch started (command_id={dispatch_meta.get('command_id')})"
        if execution_mode == "claude_agent_sdk":
            running_reason = "Claude API dispatch accepted"
            running_extra = {"execution_id": dispatch_meta.get("execution_id")}
            running_provider = planned_provider or "claude_agent_sdk"
            running_summary = f"Dispatch started (execution_id={dispatch_meta.get('execution_id')})"
        elif execution_mode in {"codex_app_server", "codex_full_auto"}:
            running_reason = "OpenAI Responses API dispatch accepted"
            running_extra = {"execution_id": dispatch_meta.get("execution_id")}
            running_provider = planned_provider or "openai_codex"
            running_summary = f"Dispatch started (execution_id={dispatch_meta.get('execution_id')})"
        else:
            running_extra.update(
                {
                    "instance_id": dispatch_meta.get("instance_id"),
                    "host_kind": dispatch_meta.get("host_kind"),
                }
            )
            running_summary = (
                f"Dispatch started (command_id={dispatch_meta.get('command_id')}, "
                f"instance_id={dispatch_meta.get('instance_id')}, host_kind={dispatch_meta.get('host_kind')})"
            )

        _append_state_transition(
            request,
            _STATE_RUNNING,
            running_reason,
            extra=running_extra,
        )

        request["dispatch"] = dispatch_meta
        request["execution_mode"] = execution_mode
        request["execution_provider"] = running_provider
        request["dispatch_attempts"] = current_attempt
        request["lock_expires_epoch"] = lock_expires_epoch
        request["dispatch_started_epoch"] = now_epoch
        request["lambda_provider_preflight"] = preflight
        request["updated_at"] = now
        request["updated_epoch"] = now_epoch
        request.pop("next_retry_epoch", None)
        request.pop("retry_plan", None)
        request = _append_dispatch_worklog(
            request,
            dispatch_id=dispatch_id,
            provider=running_provider,
            execution_mode=execution_mode,
            outcome_state="running",
            summary=running_summary,
            start_ts=str(dispatch_meta.get("sent_at") or now),
            end_ts=str(dispatch_meta.get("sent_at") or now),
        )

        if execution_mode in {"claude_agent_sdk", "codex_app_server", "codex_full_auto"}:
            provider_result = dispatch_meta.get("provider_result") or {}
            terminal_state = str(dispatch_meta.get("status") or "succeeded").strip().lower()
            if terminal_state not in _VALID_TERMINAL_STATES:
                terminal_state = "succeeded"

            if (
                terminal_state == "succeeded"
                and require_related_mutation_guard
            ):
                related_snapshots_after = _collect_tracker_snapshots(
                    request.get("related_record_ids") or []
                )
                records_mutated, changed_record_ids = _related_records_mutated(
                    related_snapshots_before,
                    related_snapshots_after,
                )
                provider_result["related_record_mutation_guard"] = {
                    "required": True,
                    "mutated": records_mutated,
                    "changed_record_ids": changed_record_ids,
                    "monitored_record_ids": sorted(related_snapshots_after.keys()),
                }
                if not records_mutated:
                    logger.warning(
                        "Direct provider dispatch produced no related tracker mutations request_id=%s dispatch_id=%s mode=%s",
                        request_id,
                        dispatch_id,
                        execution_mode,
                    )
                    terminal_state = "failed"
                    provider_result["failure_class"] = "no_effect"
                    provider_result["response_status"] = "no_effect"
                    provider_result["summary"] = (
                        "Direct provider dispatch returned completion but made no updates to related tracker records. "
                        "Marked failed to prevent false-success completion."
                    )[:2000]

            dispatch_meta["status"] = terminal_state
            dispatch_meta["provider_result"] = provider_result

            provider_label = "Claude API request" if execution_mode == "claude_agent_sdk" else "OpenAI Responses request"
            terminal_summary = str(
                provider_result.get("summary")
                or (
                    f"{provider_label} completed"
                    if terminal_state == "succeeded"
                    else f"{provider_label} failed"
                )
            )[:2000]
            _append_state_transition(
                request,
                terminal_state,
                f"{provider_label} {terminal_state}",
                extra={
                    "execution_id": dispatch_meta.get("execution_id"),
                    "request_id": provider_result.get("request_id"),
                    "status": provider_result.get("response_status") or provider_result.get("stop_reason"),
                },
            )
            if execution_mode == "claude_agent_sdk":
                request["provider_session"] = {
                    **(request.get("provider_session") or {}),
                    "provider": "claude_agent_sdk",
                    "session_id": provider_result.get("session_id"),
                    "fork_from_session_id": provider_result.get("fork_from_session_id"),
                    "model": provider_result.get("model"),
                    "permission_mode": provider_result.get("permission_mode"),
                    "allowed_tools": provider_result.get("allowed_tools"),
                    "completed_at": provider_result.get("completed_at"),
                    "execution_id": dispatch_meta.get("execution_id"),
                }
                result_provider = "claude_agent_sdk"
                result_details = {
                    "provider_result": provider_result,
                    "transport": dispatch_meta.get("transport"),
                    "api_endpoint": dispatch_meta.get("api_endpoint"),
                    "request_id": provider_result.get("request_id"),
                    "usage": provider_result.get("usage"),
                    "stop_reason": provider_result.get("stop_reason"),
                }
                release_reason = "claude_api_terminal"
            else:
                request["provider_session"] = {
                    **(request.get("provider_session") or {}),
                    "provider": "openai_codex",
                    "session_id": provider_result.get("session_id")
                    or provider_result.get("thread_id")
                    or provider_result.get("provider_session_id"),
                    "thread_id": provider_result.get("thread_id") or provider_result.get("session_id"),
                    "fork_from_thread_id": provider_result.get("fork_from_session_id"),
                    "provider_session_id": provider_result.get("provider_session_id"),
                    "model": provider_result.get("model"),
                    "completed_at": provider_result.get("completed_at"),
                    "execution_id": dispatch_meta.get("execution_id"),
                }
                result_provider = "openai_codex"
                result_details = {
                    "provider_result": provider_result,
                    "transport": dispatch_meta.get("transport"),
                    "api_endpoint": dispatch_meta.get("api_endpoint"),
                    "request_id": provider_result.get("request_id"),
                    "usage": provider_result.get("usage"),
                    "response_status": provider_result.get("response_status"),
                }
                release_reason = "openai_api_terminal"
            request = _append_dispatch_worklog(
                request,
                dispatch_id=dispatch_id,
                provider=result_provider,
                execution_mode=execution_mode,
                outcome_state=terminal_state,
                summary=terminal_summary,
                start_ts=str(dispatch_meta.get("sent_at") or now),
                end_ts=str(dispatch_meta.get("completed_at") or _now_z()),
            )
            request["result"] = _build_result_payload(
                request,
                state=terminal_state,
                summary=terminal_summary,
                execution_id=str(dispatch_meta.get("execution_id") or ""),
                provider=result_provider,
                details=result_details,
            )
            _release_dispatch_lock(request, release_reason)
            request = _cleanup_dispatch_host(request, release_reason)
            _update_request(request)
            _finalize_tracker_from_request(request)
            return _response(
                200,
                {
                    "success": terminal_state == "succeeded",
                    "request": _redact_request(request),
                },
            )

        _update_request(request)

        feature_id = request.get("feature_id")
        if feature_id:
            _append_tracker_history(
                feature_id,
                "worklog",
                (
                    f"Coordination request {request_id} dispatched: "
                    f"command_id={dispatch_meta.get('command_id')} mode={execution_mode}"
                ),
                governance_hash=request.get("governance_hash"),
                coordination_request_id=request_id,
                dispatch_id=str(dispatch_meta.get("dispatch_id") or ""),
                provider=str((request.get("provider_session") or {}).get("provider") or request.get("execution_provider") or ""),
            )

        for tid in request.get("task_ids") or []:
            _set_tracker_status(
                tid,
                "in-progress",
                f"Coordination request {request_id} running via SSM",
                governance_hash=request.get("governance_hash"),
                coordination_request_id=request_id,
                dispatch_id=str(dispatch_meta.get("dispatch_id") or ""),
                provider=str((request.get("provider_session") or {}).get("provider") or request.get("execution_provider") or ""),
            )

    except Exception as exc:
        logger.exception("dispatch failed")
        failure_class, retryable = _classify_dispatch_failure(exc)
        retryable = retryable and failure_class in _RETRIABLE_FAILURE_CLASSES
        request["dispatch_attempts"] = current_attempt
        request["result"] = {
            "summary": f"Dispatch failed: {exc}",
            "failure_class": failure_class,
            "retryable": retryable,
        }
        request = _append_dispatch_worklog(
            request,
            dispatch_id=dispatch_id,
            provider=(
                planned_provider
                or (
                    "claude_agent_sdk"
                    if execution_mode == "claude_agent_sdk"
                    else ("openai_codex" if execution_mode in {"codex_app_server", "codex_full_auto"} else "host_v2")
                )
            ),
            execution_mode=execution_mode,
            outcome_state="failed",
            summary=f"Dispatch failed before remote execution: {exc}",
            start_ts=now,
            end_ts=_now_z(),
        )

        if request.get("state") == _STATE_DISPATCHING:
            if retryable and current_attempt < MAX_DISPATCH_ATTEMPTS:
                retry_in = _retry_backoff_seconds(current_attempt)
                _append_state_transition(
                    request,
                    _STATE_QUEUED,
                    f"Retriable dispatch failure ({failure_class}); retry scheduled",
                    extra={"retry_in_seconds": retry_in, "attempt": current_attempt, "max_attempts": MAX_DISPATCH_ATTEMPTS},
                )
                request["next_retry_epoch"] = now_epoch + retry_in
                request["retry_plan"] = {
                    "failure_class": failure_class,
                    "retry_in_seconds": retry_in,
                    "retriable_classes": sorted(_RETRIABLE_FAILURE_CLASSES),
                    "non_retriable_classes": sorted(_NON_RETRIABLE_FAILURE_CLASSES),
                }
                _release_dispatch_lock(request, "retry_scheduled")
                request = _cleanup_dispatch_host(request, "retry_scheduled")
                _update_request(request)
                return _response(
                    202,
                    {
                        "success": False,
                        "retry_scheduled": True,
                        "failure_class": failure_class,
                        "retry_in_seconds": retry_in,
                        "request": _redact_request(request),
                    },
                )

            _append_state_transition(
                request,
                "failed",
                "Dispatch failed",
                extra={"error": str(exc)[:1000], "failure_class": failure_class},
            )

        _release_dispatch_lock(request, "dispatch_failed")
        request = _cleanup_dispatch_host(request, "dispatch_failed")
        if retryable and current_attempt >= MAX_DISPATCH_ATTEMPTS:
            _move_to_dead_letter(request, "Retries exhausted after dispatch failures", failure_class=failure_class)
        _update_request(request)
        _finalize_tracker_from_request(request)
        if retryable and current_attempt >= MAX_DISPATCH_ATTEMPTS:
            return _error(409, "Dispatch retries exhausted", failure_class=failure_class, request=_redact_request(request))
        return _error(500, f"Dispatch failed: {exc}", failure_class=failure_class)

    return _response(
        202,
        {
            "success": True,
            "request": _redact_request(request),
        },
    )


def _handle_callback(event: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    """v0.3 multi-provider callback handler.

    Accepts callbacks from Claude Agent SDK, OpenAI Codex, and AWS-native
    providers. Each provider's payload is normalized to the canonical schema
    before processing. Supports dispatch-level tracking for multi-dispatch plans.

    v0.3 additions:
    - 'dispatch_id' field identifies which dispatch within a plan is reporting
    - 'provider' field identifies the callback source for adapter selection
    - 'feed_updates' field carries items_modified for feed subscription delivery
    - Response includes 'plan_status' with completed/pending/failed counts
    """
    request = _get_request(request_id)
    if not request:
        return _error(404, f"Request '{request_id}' not found")

    # --- Auth: validate callback token ---
    headers = event.get("headers") or {}
    token = (
        headers.get("x-coordination-callback-token")
        or headers.get("X-Coordination-Callback-Token")
        or ""
    )

    expected = str(request.get("callback_token") or "")
    if not expected or token != expected:
        return _error(401, "Invalid callback token")

    if _unix_now() > int(request.get("callback_token_expires_epoch") or 0):
        return _error(401, "Callback token expired")

    # --- Parse body ---
    try:
        body = _json_body(event)
    except ValueError as exc:
        return _error(400, str(exc))

    # --- State guard ---
    if request.get("state") not in {"dispatching", "running"}:
        return _error(409, f"Cannot callback request in state '{request.get('state')}'")

    # --- Provider-specific normalization ---
    provider = str(body.get("provider") or "").strip().lower()
    if provider and provider not in _VALID_PROVIDERS:
        return _error(400, f"Unsupported provider '{provider}'. Allowed: {sorted(_VALID_PROVIDERS)}")

    if provider:
        normalized = _normalize_callback_body(body, provider)
    else:
        # Legacy v0.2 callback — no provider normalization
        normalized = body

    next_state = str(normalized.get("state") or "").strip().lower()
    if next_state not in _VALID_TERMINAL_STATES:
        return _error(400, f"'state' must be one of {sorted(_VALID_TERMINAL_STATES)}")

    dispatch_id = str(normalized.get("dispatch_id") or "").strip()
    summary = str(normalized.get("summary") or "")[:2000]
    execution_id = str(normalized.get("execution_id") or "")
    details = normalized.get("details") or {}
    feed_updates = normalized.get("feed_updates") or {}
    feed_updates = normalized.get("feed_updates") or {}
    effective_provider = str(normalized.get("provider") or provider or "unknown")
    if effective_provider in {"openai_codex", "claude_agent_sdk"} and isinstance(details, dict):
        _update_provider_session_from_callback(
            request,
            provider=effective_provider,
            execution_id=execution_id,
            details=details,
        )

    try:
        # --- Dispatch-level outcome tracking (v0.3) ---
        if dispatch_id:
            _update_dispatch_outcome(
                request=request,
                dispatch_id=dispatch_id,
                state=next_state,
                summary=summary,
                execution_id=execution_id,
                provider=effective_provider,
                details=details,
            )

            # Evaluate if all dispatches are complete
            plan_terminal = _evaluate_plan_terminal_state(request)
            if plan_terminal:
                # All dispatches done — transition the request to terminal state
                _append_state_transition(
                    request,
                    plan_terminal,
                    f"All dispatches completed (plan terminal: {plan_terminal})",
                    extra={
                        "dispatch_id": dispatch_id,
                        "execution_id": execution_id,
                        "provider": effective_provider,
                        "plan_status": _compute_plan_status(request),
                    },
                )
                timeout_failure = plan_terminal == "failed" and _is_timeout_failure("", "", summary)
                request = _append_dispatch_worklog(
                    request,
                    dispatch_id=dispatch_id,
                    provider=effective_provider,
                    execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                    outcome_state=next_state,
                    summary=summary or f"Dispatch callback: {next_state}",
                )
                request["result"] = _build_result_payload(
                    request,
                    state=plan_terminal,
                    summary=summary or f"Plan completed: {plan_terminal}",
                    execution_id=execution_id or None,
                    provider=effective_provider,
                    details=details,
                    feed_updates=feed_updates,
                    reason="timeout" if timeout_failure else None,
                )
                _release_dispatch_lock(request, "callback_terminal")
                request = _cleanup_dispatch_host(request, "callback_terminal")
                _update_request(request)
                _finalize_tracker_from_request(request)
            else:
                # More dispatches pending — stay in 'running', persist outcome
                request["updated_at"] = _now_z()
                request["updated_epoch"] = _unix_now()
                request = _append_dispatch_worklog(
                    request,
                    dispatch_id=dispatch_id,
                    provider=effective_provider,
                    execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                    outcome_state=next_state,
                    summary=summary or f"Dispatch callback: {next_state}",
                )
                _update_request(request)

                # Log dispatch-level completion to tracker
                feature_id = request.get("feature_id")
                if feature_id:
                    _append_tracker_history(
                        feature_id,
                        "worklog",
                        (
                            f"Dispatch {dispatch_id} ({effective_provider}) "
                            f"completed with state={next_state}. "
                            f"Plan progress: {_compute_plan_status(request)}"
                        ),
                        governance_hash=request.get("governance_hash"),
                        coordination_request_id=request_id,
                        dispatch_id=dispatch_id,
                        provider=effective_provider,
                    )
        else:
            # --- Legacy single-dispatch callback (v0.2 compat) ---
            _append_state_transition(
                request,
                next_state,
                "Callback update received",
                extra={
                    "execution_id": execution_id,
                    "provider": effective_provider,
                } if (execution_id or effective_provider != "unknown") else None,
            )
            timeout_failure = next_state == "failed" and _is_timeout_failure("", "", summary)
            request = _append_dispatch_worklog(
                request,
                dispatch_id=dispatch_id or "primary",
                provider=effective_provider,
                execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                outcome_state=next_state,
                summary=summary or f"Terminal callback received: {next_state}",
            )
            request["result"] = _build_result_payload(
                request,
                state=next_state,
                summary=summary or f"Terminal callback received: {next_state}",
                execution_id=execution_id or None,
                provider=effective_provider,
                details=details,
                feed_updates=feed_updates,
                reason="timeout" if timeout_failure else None,
            )
            _release_dispatch_lock(request, "callback_terminal")
            request = _cleanup_dispatch_host(request, "callback_terminal")
            _update_request(request)
            _finalize_tracker_from_request(request)

        feed_item_ids = [
            str(item_id).strip()
            for item_id in ((feed_updates or {}).get("items_modified") or [])
            if str(item_id).strip()
        ]
        if not feed_item_ids:
            feed_item_ids = [str(item_id).strip() for item_id in (request.get("related_record_ids") or []) if str(item_id).strip()]
        if feed_item_ids:
            _publish_feed_push_updates(
                project_id=str(request.get("project_id") or ""),
                coordination_request_id=request_id,
                state=next_state,
                summary=summary or f"Dispatch callback: {next_state}",
                item_ids=feed_item_ids,
            )

        request.setdefault("mcp", {})
        request["mcp"]["last_callback"] = _mcp.coordination_request_callback(
            request_id=request_id,
            state=next_state,
            provider=effective_provider,
            execution_id=execution_id,
            details=details if isinstance(details, dict) else {},
        )
        _update_request(request)

        # --- Emit EventBridge observability event ---
        _emit_callback_event(request, normalized)

    except Exception as exc:
        logger.exception("callback update failed")
        return _error(500, f"Failed processing callback: {exc}")

    return _response(
        200,
        {
            "success": True,
            "request": _redact_request(request),
            "plan_status": _compute_plan_status(request),
        },
    )


def _handle_eventbridge_callback(event: Dict[str, Any]) -> Dict[str, Any]:
    """Process an EventBridge-delivered callback event.

    AWS-native providers (Step Functions, Lambda, CodeBuild) can deliver
    completion events via EventBridge with detail-type 'coordination.callback'.
    This handler extracts the request_id from the event detail and processes
    it through the standard callback pipeline.
    """
    detail = event.get("detail") or {}
    request_id = str(detail.get("request_id") or "").strip()
    if not request_id:
        logger.warning("EventBridge callback missing request_id in detail")
        return _error(400, "EventBridge callback missing 'request_id' in detail")

    request = _get_request(request_id)
    if not request:
        logger.warning("EventBridge callback for unknown request: %s", request_id)
        return _error(404, f"Request '{request_id}' not found")

    # Validate callback token from detail payload
    token = str(detail.get("callback_token") or "")
    expected = str(request.get("callback_token") or "")
    if not expected or token != expected:
        return _error(401, "Invalid callback token in EventBridge event")

    if _unix_now() > int(request.get("callback_token_expires_epoch") or 0):
        return _error(401, "Callback token expired")

    if request.get("state") not in {"dispatching", "running"}:
        return _error(409, f"Cannot callback request in state '{request.get('state')}'")

    # Normalize as aws_native provider
    normalized = _normalize_aws_native_callback(detail)

    next_state = str(normalized.get("state") or "").strip().lower()
    if next_state not in _VALID_TERMINAL_STATES:
        return _error(400, f"Invalid terminal state from EventBridge event: {next_state}")

    dispatch_id = str(normalized.get("dispatch_id") or "").strip()
    summary = str(normalized.get("summary") or "")[:2000]
    execution_id = str(normalized.get("execution_id") or "")
    details = normalized.get("details") or {}

    try:
        if dispatch_id:
            _update_dispatch_outcome(
                request=request,
                dispatch_id=dispatch_id,
                state=next_state,
                summary=summary,
                execution_id=execution_id,
                provider="aws_native",
                details=details,
            )
            plan_terminal = _evaluate_plan_terminal_state(request)
            if plan_terminal:
                _append_state_transition(request, plan_terminal, f"EventBridge plan terminal: {plan_terminal}")
                timeout_failure = plan_terminal == "failed" and _is_timeout_failure("", "", summary)
                request = _append_dispatch_worklog(
                    request,
                    dispatch_id=dispatch_id,
                    provider="aws_native",
                    execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                    outcome_state=next_state,
                    summary=summary or f"EventBridge callback: {next_state}",
                )
                request["result"] = _build_result_payload(
                    request,
                    state=plan_terminal,
                    summary=summary,
                    execution_id=execution_id or None,
                    provider="aws_native",
                    details=details,
                    reason="timeout" if timeout_failure else None,
                )
                _release_dispatch_lock(request, "eventbridge_terminal")
                request = _cleanup_dispatch_host(request, "eventbridge_terminal")
                _update_request(request)
                _finalize_tracker_from_request(request)
            else:
                request["updated_at"] = _now_z()
                request["updated_epoch"] = _unix_now()
                request = _append_dispatch_worklog(
                    request,
                    dispatch_id=dispatch_id,
                    provider="aws_native",
                    execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                    outcome_state=next_state,
                    summary=summary or f"EventBridge callback: {next_state}",
                )
                _update_request(request)
        else:
            _append_state_transition(request, next_state, "EventBridge callback received")
            timeout_failure = next_state == "failed" and _is_timeout_failure("", "", summary)
            request = _append_dispatch_worklog(
                request,
                dispatch_id=dispatch_id or "primary",
                provider="aws_native",
                execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                outcome_state=next_state,
                summary=summary or f"EventBridge callback: {next_state}",
            )
            request["result"] = _build_result_payload(
                request,
                state=next_state,
                summary=summary or f"EventBridge callback: {next_state}",
                execution_id=execution_id or None,
                provider="aws_native",
                details=details,
                reason="timeout" if timeout_failure else None,
            )
            _release_dispatch_lock(request, "eventbridge_terminal")
            request = _cleanup_dispatch_host(request, "eventbridge_terminal")
            _update_request(request)
            _finalize_tracker_from_request(request)

        feed_item_ids = [
            str(item_id).strip()
            for item_id in ((feed_updates or {}).get("items_modified") or [])
            if str(item_id).strip()
        ]
        if not feed_item_ids:
            feed_item_ids = [str(item_id).strip() for item_id in (request.get("related_record_ids") or []) if str(item_id).strip()]
        if feed_item_ids:
            _publish_feed_push_updates(
                project_id=str(request.get("project_id") or ""),
                coordination_request_id=request_id,
                state=next_state,
                summary=summary or f"EventBridge callback: {next_state}",
                item_ids=feed_item_ids,
            )

        _emit_callback_event(request, normalized)
    except Exception as exc:
        logger.exception("EventBridge callback processing failed")
        return _error(500, f"Failed processing EventBridge callback: {exc}")

    return _response(200, {"success": True, "request": _redact_request(request), "plan_status": _compute_plan_status(request)})


def _handle_sqs_callback(event: Dict[str, Any]) -> Dict[str, Any]:
    """Process SQS-delivered callback messages.

    For async processing where webhook is not suitable. Each SQS record
    contains a JSON body with the standard callback payload plus request_id
    and callback_token.
    """
    records = event.get("Records") or []
    results: List[Dict[str, Any]] = []
    failures: List[str] = []

    for record in records:
        message_id = record.get("messageId", "unknown")
        try:
            body_raw = record.get("body") or "{}"
            body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw

            request_id = str(body.get("request_id") or "").strip()
            if not request_id:
                failures.append(f"{message_id}: missing request_id")
                continue

            request = _get_request(request_id)
            if not request:
                failures.append(f"{message_id}: request {request_id} not found")
                continue

            token = str(body.get("callback_token") or "")
            expected = str(request.get("callback_token") or "")
            if not expected or token != expected:
                failures.append(f"{message_id}: invalid callback token")
                continue

            if _unix_now() > int(request.get("callback_token_expires_epoch") or 0):
                failures.append(f"{message_id}: callback token expired")
                continue

            if request.get("state") not in {"dispatching", "running"}:
                failures.append(f"{message_id}: invalid state {request.get('state')}")
                continue

            provider = str(body.get("provider") or "aws_native").strip().lower()
            normalized = _normalize_callback_body(body, provider)

            next_state = str(normalized.get("state") or "").strip().lower()
            if next_state not in _VALID_TERMINAL_STATES:
                failures.append(f"{message_id}: invalid terminal state {next_state}")
                continue

            dispatch_id = str(normalized.get("dispatch_id") or "").strip()
            summary = str(normalized.get("summary") or "")[:2000]
            execution_id = str(normalized.get("execution_id") or "")
            details = normalized.get("details") or {}
            feed_updates = normalized.get("feed_updates") or {}

            if dispatch_id:
                _update_dispatch_outcome(
                    request=request,
                    dispatch_id=dispatch_id,
                    state=next_state,
                    summary=summary,
                    execution_id=execution_id,
                    provider=provider,
                    details=details,
                )
                plan_terminal = _evaluate_plan_terminal_state(request)
                if plan_terminal:
                    _append_state_transition(request, plan_terminal, f"SQS plan terminal: {plan_terminal}")
                    timeout_failure = plan_terminal == "failed" and _is_timeout_failure("", "", summary)
                    request = _append_dispatch_worklog(
                        request,
                        dispatch_id=dispatch_id,
                        provider=provider,
                        execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                        outcome_state=next_state,
                        summary=summary or f"SQS callback: {next_state}",
                    )
                    request["result"] = _build_result_payload(
                        request,
                        state=plan_terminal,
                        summary=summary,
                        execution_id=execution_id or None,
                        provider=provider,
                        details=details,
                        reason="timeout" if timeout_failure else None,
                    )
                    _release_dispatch_lock(request, "sqs_terminal")
                    request = _cleanup_dispatch_host(request, "sqs_terminal")
                    _update_request(request)
                    _finalize_tracker_from_request(request)
                else:
                    request["updated_at"] = _now_z()
                    request["updated_epoch"] = _unix_now()
                    request = _append_dispatch_worklog(
                        request,
                        dispatch_id=dispatch_id,
                        provider=provider,
                        execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                        outcome_state=next_state,
                        summary=summary or f"SQS callback: {next_state}",
                    )
                    _update_request(request)
            else:
                _append_state_transition(request, next_state, "SQS callback received")
                timeout_failure = next_state == "failed" and _is_timeout_failure("", "", summary)
                request = _append_dispatch_worklog(
                    request,
                    dispatch_id=dispatch_id or "primary",
                    provider=provider,
                    execution_mode=_lookup_dispatch_execution_mode(request, dispatch_id),
                    outcome_state=next_state,
                    summary=summary or f"SQS callback: {next_state}",
                )
                request["result"] = _build_result_payload(
                    request,
                    state=next_state,
                    summary=summary or f"SQS callback: {next_state}",
                    execution_id=execution_id or None,
                    provider=provider,
                    details=details,
                    reason="timeout" if timeout_failure else None,
                )
                _release_dispatch_lock(request, "sqs_terminal")
                request = _cleanup_dispatch_host(request, "sqs_terminal")
                _update_request(request)
                _finalize_tracker_from_request(request)

            feed_item_ids = [
                str(item_id).strip()
                for item_id in ((feed_updates or {}).get("items_modified") or [])
                if str(item_id).strip()
            ]
            if not feed_item_ids:
                feed_item_ids = [
                    str(item_id).strip()
                    for item_id in (request.get("related_record_ids") or [])
                    if str(item_id).strip()
                ]
            if feed_item_ids:
                _publish_feed_push_updates(
                    project_id=str(request.get("project_id") or ""),
                    coordination_request_id=request_id,
                    state=next_state,
                    summary=summary or f"SQS callback: {next_state}",
                    item_ids=feed_item_ids,
                )

            _emit_callback_event(request, normalized)
            results.append({"message_id": message_id, "request_id": request_id, "state": next_state})

        except Exception as exc:
            logger.exception("SQS callback failed for message %s", message_id)
            failures.append(f"{message_id}: {exc}")

    return _response(
        200,
        {
            "success": len(failures) == 0,
            "processed": len(results),
            "results": results,
            "failures": failures,
        },
    )


# ---------------------------------------------------------------------------
# Main Lambda handler
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    # --- v0.3: EventBridge callback ingestion ---
    # EventBridge events have 'source' and 'detail-type' at top level.
    event_source = event.get("source") or ""
    detail_type = event.get("detail-type") or ""
    if (
        event_source == CALLBACK_EVENT_SOURCE
        and detail_type == CALLBACK_EVENT_DETAIL_TYPE
    ):
        logger.info("[INFO] EventBridge callback event received")
        return _handle_eventbridge_callback(event)

    # --- v0.3: SQS callback ingestion ---
    # SQS events have 'Records' with 'eventSource' = 'aws:sqs'.
    records = event.get("Records")
    if isinstance(records, list) and records:
        first_source = (records[0].get("eventSource") or "")
        if first_source == "aws:sqs":
            logger.info("[INFO] SQS callback batch received (%d records)", len(records))
            return _handle_sqs_callback(event)

    # --- Standard API Gateway HTTP routing ---
    method, path = _path_method(event)

    if method == "OPTIONS":
        return _response(200, {"success": True})

    logger.info("[INFO] route method=%s path=%s", method, path)

    # GET /api/v1/coordination/capabilities is intentionally public.
    if method == "GET" and path == "/api/v1/coordination/capabilities":
        return _handle_capabilities()

    # POST /api/v1/coordination/requests/{requestId}/callback
    # Callback auth is enforced via per-request callback token.
    match_callback = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)/callback", path)
    if method == "POST" and match_callback:
        request_id = match_callback.group(1)
        return _handle_callback(event, request_id)

    # Auth all other routes.
    claims, auth_err = _authenticate(event)
    if auth_err:
        return auth_err

    # GET/POST /api/v1/coordination/mcp
    # Auth required (Cognito cookie or X-Coordination-Internal-Key).
    if method in {"GET", "POST"} and path == COORDINATION_MCP_HTTP_PATH:
        return _handle_mcp_http(event, claims or {})

    # POST /api/v1/coordination/requests
    if method == "POST" and path == "/api/v1/coordination/requests":
        return _handle_create_request(event, claims or {})

    # GET /api/v1/coordination/requests/{requestId}
    match_get = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)", path)
    if method == "GET" and match_get:
        request_id = match_get.group(1)
        return _handle_get_request(request_id)

    # POST /api/v1/coordination/requests/{requestId}/dispatch
    match_dispatch = re.fullmatch(r"/api/v1/coordination/requests/([A-Za-z0-9\-]+)/dispatch", path)
    if method == "POST" and match_dispatch:
        request_id = match_dispatch.group(1)
        return _handle_dispatch_request(event, request_id)

    return _error(404, f"Unsupported route: {method} {path}")
