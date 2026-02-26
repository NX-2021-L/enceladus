"""config.py — Central configuration — environment variables, constants, routing tables, logging.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import logging
import os
import re


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

__all__ = [
    "ANTHROPIC_API_BASE_URL",
    "ANTHROPIC_API_KEY_SECRET_ID",
    "ANTHROPIC_API_STREAM_TIMEOUT_SECONDS",
    "ANTHROPIC_API_TIMEOUT_SECONDS",
    "ANTHROPIC_API_VERSION",
    "CALLBACK_EVENTBRIDGE_BUS",
    "CALLBACK_EVENT_DETAIL_TYPE",
    "CALLBACK_EVENT_SOURCE",
    "CALLBACK_SQS_QUEUE_URL",
    "CALLBACK_TOKEN_TTL_SECONDS",
    "CLAUDE_API_MAX_TOKENS_DEFAULT",
    "CLAUDE_API_MAX_TOKENS_MAX",
    "CLAUDE_API_MAX_TOKENS_MIN",
    "CLAUDE_PROMPT_CACHE_TTL",
    "CLAUDE_THINKING_BUDGET_DEFAULT",
    "CLAUDE_THINKING_BUDGET_MAX",
    "CLAUDE_THINKING_BUDGET_MIN",
    "COGNITO_CLIENT_ID",
    "COGNITO_USER_POOL_ID",
    "COORDINATION_GSI_IDEMPOTENCY",
    "COORDINATION_GSI_PROJECT",
    "COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEYS",
    "COORDINATION_MCP_HTTP_PATH",
    "COORDINATION_PUBLIC_BASE_URL",
    "COORDINATION_TABLE",
    "CORS_ORIGIN",
    "DEAD_LETTER_SNS_TOPIC_ARN",
    "DEAD_LETTER_TIMEOUT_MULTIPLIER",
    "DEBOUNCE_WINDOW_SECONDS",
    "DEFAULT_CLAUDE_AGENT_MODEL",
    "DEFAULT_OPENAI_CODEX_MODEL",
    "DISPATCH_LOCK_BUFFER_SECONDS",
    "DISPATCH_TIMEOUT_CEILING_SECONDS",
    "DISPATCH_WORKLOG_MAX_ENTRIES",
    "DOCUMENTS_TABLE",
    "DYNAMODB_REGION",
    "ENABLE_CLAUDE_HEADLESS",
    "ENABLE_MCP_GOVERNANCE_PROMPT",
    "ENCELADUS_MCP_SERVER_PATH",
    "FEED_PUSH_DEFAULT_EVENT_BUS",
    "FEED_PUSH_HTTP_TIMEOUT_SECONDS",
    "FEED_SUBSCRIPTIONS_TABLE",
    "GOVERNANCE_KEYWORD",
    "GOVERNANCE_PROJECT_ID",
    "GOVERNANCE_PROMPT_MAX_CHARS",
    "GOVERNANCE_PROMPT_RESOURCE_URIS_FALLBACK",
    "HOST_V2_AWS_PROFILE",
    "HOST_V2_ENCELADUS_MCP_INSTALLER",
    "HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL",
    "HOST_V2_FLEET_ENABLED",
    "HOST_V2_FLEET_FALLBACK_TO_STATIC",
    "HOST_V2_FLEET_INSTANCE_TTL_SECONDS",
    "HOST_V2_FLEET_LAUNCH_TEMPLATE_ID",
    "HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION",
    "HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES",
    "HOST_V2_FLEET_NAME_PREFIX",
    "HOST_V2_FLEET_READINESS_POLL_SECONDS",
    "HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS",
    "HOST_V2_FLEET_SWEEP_GRACE_SECONDS",
    "HOST_V2_FLEET_SWEEP_ON_DISPATCH",
    "HOST_V2_FLEET_TAG_MANAGED_BY_VALUE",
    "HOST_V2_FLEET_USER_DATA_TEMPLATE",
    "HOST_V2_INSTANCE_ID",
    "HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS",
    "HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS",
    "HOST_V2_MCP_BOOTSTRAP_SCRIPT",
    "HOST_V2_MCP_MARKER_PATH",
    "HOST_V2_MCP_PROFILE_PATH",
    "HOST_V2_PROJECT",
    "HOST_V2_PROVIDER_CHECK_SCRIPT",
    "HOST_V2_TIMEOUT_SECONDS",
    "HOST_V2_WORK_ROOT",
    "IDEMPOTENCY_WINDOW_SECONDS",
    "MAX_CONSTRAINT_SIZE",
    "MAX_DISPATCH_ATTEMPTS",
    "MAX_OUTCOMES",
    "MAX_OUTCOME_LENGTH",
    "MAX_TITLE_LENGTH",
    "MCP_AUDIT_CALLER_IDENTITY",
    "MCP_CONNECTIVITY_BACKOFF_SECONDS",
    "MCP_SERVER_LOG_GROUP",
    "OPENAI_API_BASE_URL",
    "OPENAI_API_KEY_SECRET_ID",
    "OPENAI_API_ORGANIZATION",
    "OPENAI_API_PROJECT",
    "OPENAI_API_TIMEOUT_SECONDS",
    "OPENAI_MAX_OUTPUT_TOKENS_MAX",
    "OPENAI_MAX_OUTPUT_TOKENS_MIN",
    "PROJECTS_TABLE",
    "ROTATION_WARNING_DAYS",
    "SECRETS_REGION",
    "SSM_DOCUMENT_NAME",
    "SSM_REGION",
    "TRACKER_GSI_PROJECT_TYPE",
    "TRACKER_TABLE",
    "WORKER_RUNTIME_LOG_GROUP",
    "_CLAUDE_ADAPTIVE_THINKING_MODELS",
    "_CLAUDE_CONTEXT_LIMITS",
    "_CLAUDE_DEFAULT_CONTEXT_LIMIT",
    "_CLAUDE_DEFAULT_PRICING",
    "_CLAUDE_MODEL_ROUTING",
    "_CLAUDE_PERMISSION_MODES",
    "_CLAUDE_PRICING",
    "_CLAUDE_VALID_TASK_COMPLEXITIES",
    "_DEFAULT_STATUS",
    "_ENCELADUS_ALLOWED_TOOLS",
    "_NON_RETRIABLE_FAILURE_CLASSES",
    "_RETRIABLE_FAILURE_CLASSES",
    "_RETRY_BACKOFF_SECONDS",
    "_SEGMENT_TO_TYPE",
    "_STATE_DEAD_LETTER",
    "_STATE_DISPATCHING",
    "_STATE_INTAKE_RECEIVED",
    "_STATE_QUEUED",
    "_STATE_RUNNING",
    "_TRANSITIONS",
    "_TYPE_TO_SEGMENT",
    "_VALID_EXECUTION_MODES",
    "_VALID_PROVIDERS",
    "_VALID_TERMINAL_STATES",
    "logger",
]

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
COORDINATION_INTERNAL_API_KEY_PREVIOUS = os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
COORDINATION_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    COORDINATION_INTERNAL_API_KEY,
    COORDINATION_INTERNAL_API_KEY_PREVIOUS,
)

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

