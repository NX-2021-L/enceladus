"""Dispatch Orchestrator Lambda — EventBridge-triggered dispatch-plan execution.

Receives events when coordination requests transition to 'queued' state,
generates dispatch plans using the governance-first initialization pattern,
and executes dispatches according to the plan.

Architecture (from DVP-FTR-023 v0.3 §6.1.2):
  EventBridge event (coordination.request.queued)
    -> THIS LAMBDA
    -> Generate dispatch-plan (via dispatch_plan_generator or init agent session)
    -> Store plan in coordination-requests record
    -> Execute dispatches (SSM, Claude Agent SDK, Step Function)
    -> Track per-dispatch status via callbacks

EventBridge event structure:
  {
    "source": "enceladus.coordination",
    "detail-type": "coordination.request.queued",
    "detail": {
      "request_id": "string",
      "project_id": "string",
      "execution_mode": "optional override",
      "dispatch_plan_override": "optional pre-built plan JSON"
    }
  }

Related: DVP-TSK-252, DVP-FTR-023
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger("dispatch_orchestrator")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COORDINATION_TABLE = os.environ.get("COORDINATION_TABLE", "coordination-requests")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")

# SSM dispatch config (for openai_codex and claude_headless modes)
SSM_REGION = os.environ.get("SSM_REGION", "us-east-2")
SSM_DOCUMENT_NAME = os.environ.get("SSM_DOCUMENT_NAME", "AWS-RunShellScript")
HOST_V2_INSTANCE_ID = os.environ.get("HOST_V2_INSTANCE_ID", "")
HOST_V2_WORK_ROOT = os.environ.get("HOST_V2_WORK_ROOT", "/home/ssm-user/claude-code-dev")
HOST_V2_TIMEOUT_SECONDS = int(os.environ.get("HOST_V2_TIMEOUT_SECONDS", "3600"))
WORKER_RUNTIME_LOG_GROUP = os.environ.get("WORKER_RUNTIME_LOG_GROUP", "/enceladus/coordination/worker-runtime")

# EventBridge for completion events
EVENTBRIDGE_BUS = os.environ.get("EVENTBRIDGE_BUS", "default")

# Callback token generation
CALLBACK_TOKEN_SECRET = os.environ.get("CALLBACK_TOKEN_SECRET", "dispatch-orchestrator-default")

# Secrets Manager references for provider API keys
OPENAI_API_KEY_SECRET_ID = os.environ.get("OPENAI_API_KEY_SECRET_ID", "")
ANTHROPIC_API_KEY_SECRET_ID = os.environ.get("ANTHROPIC_API_KEY_SECRET_ID", "")

# MCP profile installer path on host-v2
HOST_V2_ENCELADUS_MCP_INSTALLER = os.environ.get(
    "HOST_V2_ENCELADUS_MCP_INSTALLER",
    f"{HOST_V2_WORK_ROOT}/projects/devops/tools/enceladus-mcp-server/install_profile.sh",
)

# AWS profile on host-v2
HOST_V2_AWS_PROFILE = os.environ.get("HOST_V2_AWS_PROFILE", "reese")

# Bedrock Agent dispatch config (DVP-TSK-339 through DVP-TSK-344)
BEDROCK_AGENT_ROLE_ARN = os.environ.get("BEDROCK_AGENT_ROLE_ARN", "")
BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN = os.environ.get("BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN", "")
BEDROCK_AGENT_DEFAULT_MODEL = os.environ.get(
    "BEDROCK_AGENT_DEFAULT_MODEL", "anthropic.claude-3-5-sonnet-20241022-v2:0"
)
BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS = int(
    os.environ.get("BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS", "120")
)
BEDROCK_AGENT_CLEANUP = os.environ.get("BEDROCK_AGENT_CLEANUP", "true").lower() == "true"
BEDROCK_AGENT_REGION = os.environ.get("BEDROCK_AGENT_REGION", DYNAMODB_REGION)

# State constants
_STATE_QUEUED = "queued"
_STATE_DISPATCHING = "dispatching"
_STATE_RUNNING = "running"
_STATE_FAILED = "failed"

# ---------------------------------------------------------------------------
# AWS Clients
# ---------------------------------------------------------------------------

_ddb_client = None
_ssm_client = None
_events_client = None
_secrets_client = None


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client(
            "dynamodb", region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )
    return _ddb_client


def _get_ssm():
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = boto3.client("ssm", region_name=SSM_REGION)
    return _ssm_client


def _get_events():
    global _events_client
    if _events_client is None:
        _events_client = boto3.client("events", region_name=DYNAMODB_REGION)
    return _events_client


def _get_secrets():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager", region_name=DYNAMODB_REGION)
    return _secrets_client


_bedrock_agent_client = None
_bedrock_agent_runtime_client = None


def _get_bedrock_agent():
    global _bedrock_agent_client
    if _bedrock_agent_client is None:
        _bedrock_agent_client = boto3.client("bedrock-agent", region_name=BEDROCK_AGENT_REGION)
    return _bedrock_agent_client


def _get_bedrock_agent_runtime():
    global _bedrock_agent_runtime_client
    if _bedrock_agent_runtime_client is None:
        _bedrock_agent_runtime_client = boto3.client(
            "bedrock-agent-runtime", region_name=BEDROCK_AGENT_REGION
        )
    return _bedrock_agent_runtime_client


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit_structured_observability(
    *,
    event: str,
    request_id: Optional[str] = None,
    dispatch_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    latency_ms: int = 0,
    error_code: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload: Dict[str, Any] = {
        "timestamp": _now_z(),
        "component": "dispatch_orchestrator",
        "event": event,
        "request_id": str(request_id or ""),
        "dispatch_id": str(dispatch_id or ""),
        "tool_name": str(tool_name or ""),
        "latency_ms": int(max(0, latency_ms)),
        "error_code": str(error_code or ""),
    }
    if extra:
        payload.update(extra)
    logger.info("[OBSERVABILITY] %s", json.dumps(payload, sort_keys=True, default=str))


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _deser_val(v: Dict) -> Any:
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
    return str(v)


def _deser_item(item: Dict) -> Dict[str, Any]:
    return {k: _deser_val(v) for k, v in item.items()}


# ---------------------------------------------------------------------------
# Dispatch-Plan Generation
# ---------------------------------------------------------------------------


def _generate_dispatch_plan_direct(request_id: str, override_plan: Optional[Dict] = None) -> Dict[str, Any]:
    """Generate dispatch-plan by importing the generator directly.

    This is the fast path when the generator is bundled with this Lambda.
    For the full governance-first init agent session pattern, use
    _generate_dispatch_plan_via_agent() instead.
    """
    # Add the generator to path
    generator_dir = os.path.join(
        os.environ.get("ENCELADUS_WORKSPACE_ROOT", HOST_V2_WORK_ROOT),
        "projects/devops/tools/enceladus-mcp-server",
    )
    if generator_dir not in sys.path:
        sys.path.insert(0, generator_dir)

    from dispatch_plan_generator import generate_dispatch_plan, QualityGateError

    return generate_dispatch_plan(
        request_id=request_id,
        override_plan=override_plan,
    )


def _generate_dispatch_plan_via_agent(request_id: str) -> Dict[str, Any]:
    """Generate dispatch-plan via a full init agent session.

    This is the canonical path per v0.3 contract §6.1.2.
    The init agent session:
      1. Loads governance
      2. Tests connections
      3. Reads coordination request
      4. Applies heuristics
      5. Returns dispatch-plan

    For now, this delegates to the direct generator. In production,
    this would invoke a Claude Agent SDK session with the Enceladus
    MCP profile and have it call the dispatch_plan_generate MCP tool.
    """
    # TODO: DVP-TSK-253 — Implement full Claude Agent SDK init session
    # For now, use direct generation
    logger.info("[INFO] Using direct dispatch-plan generation (agent session not yet implemented)")
    return _generate_dispatch_plan_direct(request_id)


# ---------------------------------------------------------------------------
# State Transitions
# ---------------------------------------------------------------------------


def _transition_state(request_id: str, new_state: str, dispatch_plan: Optional[Dict] = None) -> None:
    """Update coordination request state in DynamoDB."""
    ddb = _get_ddb()
    now = _now_z()

    update_expr = "SET #st = :state, updated_at = :now"
    expr_vals: Dict[str, Any] = {
        ":state": _ser_s(new_state),
        ":now": _ser_s(now),
    }
    expr_names = {"#st": "state"}

    if dispatch_plan:
        update_expr += ", dispatch_plan = :plan"
        expr_vals[":plan"] = _ser_s(json.dumps(dispatch_plan, default=str))

    # Append to state_history
    history_entry = {
        "M": {
            "state": _ser_s(new_state),
            "timestamp": _ser_s(now),
            "actor": _ser_s("dispatch_orchestrator"),
        }
    }
    update_expr += ", state_history = list_append(if_not_exists(state_history, :empty), :hentry)"
    expr_vals[":hentry"] = {"L": [history_entry]}
    expr_vals[":empty"] = {"L": []}

    ddb.update_item(
        TableName=COORDINATION_TABLE,
        Key={"request_id": _ser_s(request_id)},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )
    logger.info("[INFO] Request %s transitioned to '%s'", request_id, new_state)


# ---------------------------------------------------------------------------
# Dispatch Execution
# ---------------------------------------------------------------------------


def _generate_callback_token(request_id: str, dispatch_id: str) -> str:
    """Generate a callback token for a dispatch.

    In production, this would use HMAC or JWT with a shared secret.
    For now, use a UUID-based token stored alongside the dispatch record.
    """
    import hashlib
    token_input = f"{CALLBACK_TOKEN_SECRET}:{request_id}:{dispatch_id}:{_now_z()}"
    return hashlib.sha256(token_input.encode()).hexdigest()[:48]


def _build_ssm_commands_for_dispatch(
    dispatch: Dict[str, Any],
    request: Dict[str, Any],
    callback_token: str,
) -> List[str]:
    """Build SSM commands for a single dispatch within a plan."""
    project_id = request.get("project_id", "")
    request_id = request.get("request_id", "")
    dispatch_id = dispatch.get("dispatch_id", "")
    provider = dispatch.get("provider", "")
    execution_mode = dispatch.get("execution_mode", "preflight")
    outcomes = dispatch.get("outcomes", [])
    provider_config = dispatch.get("provider_config", {})

    # Build prompt from outcomes
    prompt = (
        f"Coordination request {request_id}, dispatch {dispatch_id}.\n"
        f"Project: {project_id}\n"
        f"Outcomes to deliver:\n"
    )
    for i, outcome in enumerate(outcomes, 1):
        prompt += f"  {i}. {outcome}\n"
    prompt += (
        f"\nWhen complete, call back to: {dispatch.get('callback_config', {}).get('endpoint', '')}\n"
        f"with X-Coordination-Callback-Token: {callback_token}\n"
        f"and dispatch_id: {dispatch_id}"
    )

    escaped_prompt = json.dumps(prompt)
    escaped_thread_id = json.dumps(str(provider_config.get("thread_id") or ""))
    escaped_model = json.dumps(str(provider_config.get("model") or ""))

    commands: List[str] = [
        "set -euo pipefail",
        f"cd {HOST_V2_WORK_ROOT}",
        f"export PROJECT={project_id}",
        f"export AWS_REGION={DYNAMODB_REGION}",
        f"export AWS_DEFAULT_REGION={DYNAMODB_REGION}",
        f"export COORDINATION_REQUEST_ID={json.dumps(request_id)}",
        f"export COORDINATION_DISPATCH_ID={json.dumps(dispatch_id)}",
        (
            "echo \"{\\\"timestamp\\\":\\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\","
            "\\\"component\\\":\\\"worker_runtime\\\",\\\"event\\\":\\\"dispatch_start\\\","
            "\\\"request_id\\\":\\\"$COORDINATION_REQUEST_ID\\\",\\\"dispatch_id\\\":\\\"$COORDINATION_DISPATCH_ID\\\","
            "\\\"tool_name\\\":\\\"worker_runtime\\\",\\\"latency_ms\\\":0,\\\"error_code\\\":\\\"\\\"}\""
        ),
        (
            "if aws configure list-profiles 2>/dev/null | grep -qx "
            f"'{HOST_V2_AWS_PROFILE}'; then export AWS_PROFILE={HOST_V2_AWS_PROFILE}; "
            "else unset AWS_PROFILE; fi"
        ),
        (
            "if ! python3 -c \"import boto3, yaml\" >/dev/null 2>&1; then "
            "python3 -m pip install --user --break-system-packages --quiet boto3 PyYAML >/dev/null 2>&1 || true; "
            "fi"
        ),
        # Install Enceladus MCP profile
        f"if [ -x '{HOST_V2_ENCELADUS_MCP_INSTALLER}' ]; then bash '{HOST_V2_ENCELADUS_MCP_INSTALLER}'; fi",
        # Context sync
        (
            "if python3 -c \"import boto3, yaml\" >/dev/null 2>&1; then "
            f"python3 tools/context_sync.py --project {project_id} --skip-records || true; "
            "fi"
        ),
    ]

    if execution_mode == "preflight":
        commands.append("echo '[INFO] preflight mode complete'")
    elif execution_mode in ("codex_full_auto", "codex_app_server"):
        # Fetch OpenAI API key
        if OPENAI_API_KEY_SECRET_ID:
            commands.extend([
                (
                    f"export CODEX_API_KEY=$(aws secretsmanager get-secret-value "
                    f"--secret-id '{OPENAI_API_KEY_SECRET_ID}' --query SecretString --output text)"
                ),
            ])
        commands.extend([
            f"COORDINATION_PROMPT={escaped_prompt}",
            "if command -v codex >/dev/null 2>&1; then",
            f"  timeout {HOST_V2_TIMEOUT_SECONDS} codex \"$COORDINATION_PROMPT\"",
            "else",
            "  echo '[ERROR] codex binary not found'",
            "  exit 16",
            "fi",
        ])
    elif execution_mode in ("claude_headless", "claude_agent_sdk"):
        # Fetch Anthropic API key
        if ANTHROPIC_API_KEY_SECRET_ID:
            commands.extend([
                (
                    f"export ANTHROPIC_API_KEY=$(aws secretsmanager get-secret-value "
                    f"--secret-id '{ANTHROPIC_API_KEY_SECRET_ID}' --query SecretString --output text)"
                ),
            ])
        commands.extend([
            f"COORDINATION_PROMPT={escaped_prompt}",
            "if command -v claude >/dev/null 2>&1; then",
            f"  timeout {HOST_V2_TIMEOUT_SECONDS} claude \"$COORDINATION_PROMPT\"",
            "else",
            "  echo '[ERROR] claude binary not found'",
            "  exit 17",
            "fi",
        ])

    return commands


def _execute_ssm_dispatch(
    dispatch: Dict[str, Any],
    request: Dict[str, Any],
    callback_token: str,
) -> Dict[str, Any]:
    """Execute a dispatch via SSM send_command."""
    ssm = _get_ssm()
    commands = _build_ssm_commands_for_dispatch(dispatch, request, callback_token)
    request_id = str(request.get("request_id") or "")
    dispatch_id = str(dispatch.get("dispatch_id") or "")
    timeout_seconds = min(
        max(HOST_V2_TIMEOUT_SECONDS, 60),
        28_800,
    )
    started = time.perf_counter()

    try:
        resp = ssm.send_command(
            DocumentName=SSM_DOCUMENT_NAME,
            InstanceIds=[HOST_V2_INSTANCE_ID],
            Parameters={
                "commands": commands,
                "executionTimeout": [str(timeout_seconds)],
            },
            CloudWatchOutputConfig={
                "CloudWatchOutputEnabled": True,
                "CloudWatchLogGroupName": WORKER_RUNTIME_LOG_GROUP,
            },
            TimeoutSeconds=timeout_seconds,
            Comment=(
                f"Dispatch {dispatch.get('dispatch_id', 'unknown')} "
                f"for request {request.get('request_id', 'unknown')} "
                f"({dispatch.get('execution_mode', 'unknown')})"
            ),
        )
    except (BotoCoreError, ClientError) as exc:
        error_code = "ssm_send_command_failed"
        if isinstance(exc, ClientError):
            error_code = str(exc.response.get("Error", {}).get("Code") or error_code)
        _emit_structured_observability(
            event="dispatch_send_command",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name="ssm.send_command",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=error_code,
            extra={
                "instance_id": HOST_V2_INSTANCE_ID,
                "worker_log_group": WORKER_RUNTIME_LOG_GROUP,
                "execution_mode": str(dispatch.get("execution_mode") or ""),
            },
        )
        raise RuntimeError(f"SSM dispatch failed: {exc}") from exc

    command = resp.get("Command") or {}
    _emit_structured_observability(
        event="dispatch_send_command",
        request_id=request_id,
        dispatch_id=dispatch_id,
        tool_name="ssm.send_command",
        latency_ms=int((time.perf_counter() - started) * 1000),
        error_code="",
        extra={
            "instance_id": HOST_V2_INSTANCE_ID,
            "worker_log_group": WORKER_RUNTIME_LOG_GROUP,
            "execution_mode": str(dispatch.get("execution_mode") or ""),
            "command_id": command.get("CommandId"),
        },
    )
    return {
        "command_id": command.get("CommandId"),
        "dispatch_id": dispatch_id,
        "provider": dispatch.get("provider"),
        "execution_mode": dispatch.get("execution_mode"),
        "sent_at": _now_z(),
    }


def _execute_eventbridge_dispatch(
    dispatch: Dict[str, Any],
    request: Dict[str, Any],
    callback_token: str,
) -> Dict[str, Any]:
    """Execute a dispatch via EventBridge (for aws_native provider)."""
    events = _get_events()

    detail = {
        "dispatch_id": dispatch.get("dispatch_id"),
        "request_id": request.get("request_id"),
        "project_id": request.get("project_id"),
        "outcomes": dispatch.get("outcomes", []),
        "constraints": dispatch.get("constraints", {}),
        "callback_config": dispatch.get("callback_config", {}),
        "callback_token": callback_token,
    }

    try:
        events.put_events(
            Entries=[{
                "Source": "enceladus.coordination",
                "DetailType": "coordination.dispatch.execute",
                "Detail": json.dumps(detail, default=str),
                "EventBusName": EVENTBRIDGE_BUS,
            }]
        )
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"EventBridge dispatch failed: {exc}") from exc

    return {
        "dispatch_id": dispatch.get("dispatch_id"),
        "provider": "aws_native",
        "execution_mode": "aws_step_function",
        "sent_at": _now_z(),
        "delivery_method": "eventbridge",
    }


# ---------------------------------------------------------------------------
# Bedrock Agent Dispatch (DVP-TSK-339 through DVP-TSK-344)
# ---------------------------------------------------------------------------


_COMPLEXITY_KEYWORDS = {"architecture", "design", "analyze", "complex", "multi-step", "reasoning"}


def _select_bedrock_foundation_model(
    outcomes: List[str],
    provider_config: Dict[str, Any],
) -> str:
    """Select foundation model based on task complexity for cost efficiency.

    DVP-TSK-339: Cost optimization heuristic.
    - Simple (1 outcome, <200 chars, no complexity keywords): Haiku
    - Otherwise: Sonnet
    - Explicit foundation_model_id in bedrock_config overrides heuristic.
    """
    bedrock_config = provider_config.get("bedrock_config") or {}
    explicit = bedrock_config.get("foundation_model_id")
    if explicit:
        return explicit

    total_chars = sum(len(o) for o in outcomes)
    combined = " ".join(outcomes).lower()
    has_complex = any(kw in combined for kw in _COMPLEXITY_KEYWORDS)

    if len(outcomes) <= 1 and total_chars < 200 and not has_complex:
        return "anthropic.claude-3-5-sonnet-20241022-v2:0"
    return "anthropic.claude-3-5-sonnet-20241022-v2:0"


def _build_bedrock_action_group_function_schema() -> Dict[str, Any]:
    """Return function-details schema for the Enceladus Bedrock action group Lambda."""
    return {
        "functions": [
            {
                "name": "tracker_get",
                "description": "Fetch a tracker record by ID.",
                "parameters": {
                    "recordId": {"type": "string", "required": True, "description": "Tracker item ID (for example DVP-TSK-367)."}
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "tracker_list",
                "description": "List tracker records for a project.",
                "parameters": {
                    "projectId": {"type": "string", "required": True, "description": "Project ID (for example devops)."},
                    "recordType": {"type": "string", "required": False, "description": "Record type: task, issue, or feature."},
                    "limit": {"type": "integer", "required": False, "description": "Max records to return (1-50)."},
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "tracker_log",
                "description": "Append worklog entry to a tracker record.",
                "parameters": {
                    "recordId": {"type": "string", "required": True, "description": "Tracker item ID."},
                    "description": {"type": "string", "required": True, "description": "Worklog message."},
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "tracker_status",
                "description": "Set status for a tracker record.",
                "parameters": {
                    "recordId": {"type": "string", "required": True, "description": "Tracker item ID."},
                    "status": {"type": "string", "required": True, "description": "Target status value."},
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "tracker_create",
                "description": "Create a new tracker record.",
                "parameters": {
                    "project_id": {"type": "string", "required": True, "description": "Project ID."},
                    "record_type": {"type": "string", "required": True, "description": "Record type: task, issue, or feature."},
                    "title": {"type": "string", "required": True, "description": "Record title."},
                    "description": {"type": "string", "required": False, "description": "Record description."},
                    "priority": {"type": "string", "required": False, "description": "Priority value (P0-P3)."},
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "project_get",
                "description": "Fetch project metadata by project ID.",
                "parameters": {
                    "projectId": {"type": "string", "required": True, "description": "Project ID."}
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "projects_list",
                "description": "List all projects.",
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "documents_search",
                "description": "Search documents by keyword.",
                "parameters": {
                    "keyword": {"type": "string", "required": True, "description": "Search keyword."},
                    "project": {"type": "string", "required": False, "description": "Optional project filter."},
                    "limit": {"type": "integer", "required": False, "description": "Max records to return (1-25)."},
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "document_get",
                "description": "Fetch document content by document ID.",
                "parameters": {
                    "documentId": {"type": "string", "required": True, "description": "Document ID."}
                },
                "requireConfirmation": "DISABLED",
            },
            {
                "name": "deployment_state_get",
                "description": "Get deployment state for a project.",
                "parameters": {
                    "projectId": {"type": "string", "required": True, "description": "Project ID."}
                },
                "requireConfirmation": "DISABLED",
            },
        ]
    }


def _create_bedrock_agent(
    dispatch_id: str,
    request_id: str,
    outcomes: List[str],
    provider_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Create an ephemeral Bedrock Agent for a dispatch.

    DVP-TSK-340: Full lifecycle — create agent, action group, KB, prepare, alias.
    Returns dict with agent_id, agent_alias_id, foundation_model, agent_name.
    """
    client = _get_bedrock_agent()
    bedrock_config = provider_config.get("bedrock_config") or {}
    if not BEDROCK_AGENT_ROLE_ARN:
        raise RuntimeError("BEDROCK_AGENT_ROLE_ARN is required for Bedrock dispatch.")

    model_id = _select_bedrock_foundation_model(outcomes, provider_config)

    # Build instruction from outcomes
    instruction = (
        f"You are an Enceladus coordination agent executing dispatch {dispatch_id} "
        f"for request {request_id}. Your task outcomes are:\n"
    )
    for i, outcome in enumerate(outcomes, 1):
        instruction += f"{i}. {outcome}\n"
    instruction += "\nExecute each outcome using your available tools. Report results clearly."

    # Override instruction if explicitly provided
    if bedrock_config.get("agent_instruction"):
        instruction = bedrock_config["agent_instruction"]

    agent_name = f"enceladus-dispatch-{dispatch_id[:8]}"

    # Step 1: Create agent
    create_resp = client.create_agent(
        agentName=agent_name,
        agentResourceRoleArn=BEDROCK_AGENT_ROLE_ARN,
        foundationModel=model_id,
        instruction=instruction,
        idleSessionTTLInSeconds=bedrock_config.get("idle_session_ttl_seconds", 300),
        description=f"Ephemeral agent for dispatch {dispatch_id}",
    )
    agent_id = create_resp["agent"]["agentId"]
    logger.info("[INFO] Bedrock agent created: %s (model=%s)", agent_id, model_id)

    # Bedrock rejects action-group mutations while the agent is still creating.
    # Wait until the initial create has settled into a mutable draft state.
    create_deadline = time.time() + BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS
    while time.time() < create_deadline:
        status_resp = client.get_agent(agentId=agent_id)
        status = status_resp["agent"]["agentStatus"]
        if status in {"FAILED", "DELETING"}:
            raise RuntimeError(f"Bedrock agent {agent_id} reached terminal status '{status}' during create")
        if status not in {"CREATING"}:
            break
        time.sleep(3)
    else:
        raise RuntimeError(
            f"Bedrock agent {agent_id} stayed in CREATING for more than "
            f"{BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS}s"
        )

    # Step 2: Create action group (if Lambda ARN configured)
    action_group_lambda = (
        bedrock_config.get("action_group_lambda_arn") or BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN
    )
    if action_group_lambda:
        function_schema = _build_bedrock_action_group_function_schema()
        client.create_agent_action_group(
            agentId=agent_id,
            agentVersion="DRAFT",
            actionGroupName="enceladus-tools",
            actionGroupExecutor={"lambda": action_group_lambda},
            functionSchema=function_schema,
            description="Enceladus system tool actions for tracker, documents, projects, and deployment",
        )
        logger.info("[INFO] Action group created for agent %s", agent_id)

    # Step 3: Associate knowledge base (if configured)
    kb_id = bedrock_config.get("knowledge_base_id")
    if kb_id:
        client.associate_agent_knowledge_base(
            agentId=agent_id,
            agentVersion="DRAFT",
            knowledgeBaseId=kb_id,
            description="Project knowledge base",
        )
        logger.info("[INFO] Knowledge base %s associated with agent %s", kb_id, agent_id)

    # Step 4: Prepare agent
    client.prepare_agent(agentId=agent_id)

    # Step 5: Poll until PREPARED
    deadline = time.time() + BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS
    while time.time() < deadline:
        status_resp = client.get_agent(agentId=agent_id)
        status = status_resp["agent"]["agentStatus"]
        if status == "PREPARED":
            break
        elif status in ("FAILED", "DELETING"):
            raise RuntimeError(f"Bedrock agent {agent_id} reached terminal status '{status}'")
        time.sleep(5)
    else:
        raise RuntimeError(
            f"Bedrock agent {agent_id} preparation timed out after "
            f"{BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS}s"
        )
    logger.info("[INFO] Bedrock agent %s prepared", agent_id)

    # Step 6: Create alias
    alias_resp = client.create_agent_alias(
        agentId=agent_id,
        agentAliasName=f"dispatch-{dispatch_id[:8]}",
    )
    agent_alias_id = alias_resp["agentAlias"]["agentAliasId"]

    # Poll alias until PREPARED
    alias_deadline = time.time() + 60
    while time.time() < alias_deadline:
        alias_status = client.get_agent_alias(
            agentId=agent_id, agentAliasId=agent_alias_id
        )
        if alias_status["agentAlias"]["agentAliasStatus"] == "PREPARED":
            break
        time.sleep(3)
    logger.info("[INFO] Bedrock agent alias %s prepared", agent_alias_id)

    return {
        "agent_id": agent_id,
        "agent_alias_id": agent_alias_id,
        "foundation_model": model_id,
        "agent_name": agent_name,
    }


def _invoke_bedrock_agent(
    agent_id: str,
    agent_alias_id: str,
    prompt: str,
    session_id: str,
) -> str:
    """Invoke a Bedrock Agent and collect the full streaming response.

    DVP-TSK-341: Streaming response collector.
    """
    client = _get_bedrock_agent_runtime()

    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=agent_alias_id,
        sessionId=session_id,
        inputText=prompt,
    )

    full_response = ""
    for event in response.get("completion", []):
        if "chunk" in event:
            full_response += event["chunk"]["bytes"].decode("utf-8")

    return full_response


def _cleanup_bedrock_agent(agent_id: str) -> None:
    """Delete an ephemeral Bedrock Agent after dispatch completion.

    DVP-TSK-342: Teardown with skip-in-use-check for reliable cleanup.
    """
    client = _get_bedrock_agent()
    try:
        client.delete_agent(agentId=agent_id, skipResourceInUseCheck=True)
        logger.info("[INFO] Bedrock agent %s deleted", agent_id)
    except Exception as exc:
        logger.warning("[WARNING] Failed to delete Bedrock agent %s: %s", agent_id, exc)


def _execute_bedrock_dispatch(
    dispatch: Dict[str, Any],
    request: Dict[str, Any],
    callback_token: str,
) -> Dict[str, Any]:
    """Execute a dispatch via ephemeral Bedrock Agent.

    DVP-TSK-343: Main entry point for Bedrock Agent dispatch execution.
    Creates agent, invokes with outcomes prompt, collects response, cleans up.
    """
    dispatch_id = str(dispatch.get("dispatch_id") or "")
    request_id = str(request.get("request_id") or "")
    outcomes = dispatch.get("outcomes", [])
    provider_config = dispatch.get("provider_config", {})

    started = time.perf_counter()
    agent_info: Optional[Dict[str, Any]] = None

    try:
        # Create ephemeral agent
        agent_info = _create_bedrock_agent(dispatch_id, request_id, outcomes, provider_config)

        _emit_structured_observability(
            event="bedrock_agent_created",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name="bedrock-agent.create_agent",
            latency_ms=int((time.perf_counter() - started) * 1000),
            extra={
                "agent_id": agent_info["agent_id"],
                "model": agent_info["foundation_model"],
            },
        )

        # Build prompt from outcomes
        prompt = (
            f"Execute the following coordination outcomes for request {request_id}:\n"
        )
        for i, outcome in enumerate(outcomes, 1):
            prompt += f"{i}. {outcome}\n"
        prompt += (
            f"\nCallback token: {callback_token}\n"
            f"Dispatch ID: {dispatch_id}\n"
            f"Report results for each outcome clearly."
        )

        # Invoke agent
        session_id = f"dispatch-{dispatch_id[:32]}"
        invoke_start = time.perf_counter()
        response_text = _invoke_bedrock_agent(
            agent_info["agent_id"],
            agent_info["agent_alias_id"],
            prompt,
            session_id,
        )

        _emit_structured_observability(
            event="bedrock_agent_invoked",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name="bedrock-agent-runtime.invoke_agent",
            latency_ms=int((time.perf_counter() - invoke_start) * 1000),
            extra={"response_length": len(response_text)},
        )

        return {
            "dispatch_id": dispatch_id,
            "provider": "aws_bedrock_agent",
            "execution_mode": "bedrock_agent",
            "sent_at": _now_z(),
            "delivery_method": "bedrock_agent",
            "agent_id": agent_info["agent_id"],
            "foundation_model": agent_info["foundation_model"],
            "response_preview": response_text[:500],
        }

    except Exception as exc:
        _emit_structured_observability(
            event="bedrock_agent_error",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name="bedrock-agent",
            latency_ms=int((time.perf_counter() - started) * 1000),
            error_code=str(type(exc).__name__),
        )
        raise

    finally:
        # Cleanup: delete agent if configured and agent was created
        bedrock_config = provider_config.get("bedrock_config") or {}
        retain = bedrock_config.get("retain_agent", False)
        if agent_info and not retain and BEDROCK_AGENT_CLEANUP:
            _cleanup_bedrock_agent(agent_info["agent_id"])


def _execute_dispatch(
    dispatch: Dict[str, Any],
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """Execute a single dispatch from the plan."""
    dispatch_id = dispatch.get("dispatch_id", str(uuid.uuid4()))
    provider = dispatch.get("provider", "")
    callback_token = _generate_callback_token(request.get("request_id", ""), dispatch_id)

    logger.info(
        "[INFO] Executing dispatch %s: provider=%s, mode=%s, outcomes=%d",
        dispatch_id, provider, dispatch.get("execution_mode"), len(dispatch.get("outcomes", [])),
    )

    # Store callback token for later validation
    _store_dispatch_token(request.get("request_id", ""), dispatch_id, callback_token)

    if provider == "aws_native":
        return _execute_eventbridge_dispatch(dispatch, request, callback_token)
    elif provider == "aws_bedrock_agent":
        return _execute_bedrock_dispatch(dispatch, request, callback_token)
    else:
        # openai_codex, claude_agent_sdk — both dispatch via SSM to host-v2
        return _execute_ssm_dispatch(dispatch, request, callback_token)


def _store_dispatch_token(request_id: str, dispatch_id: str, token: str) -> None:
    """Store a callback token for dispatch validation.

    Appends to the dispatch_tokens map on the coordination-requests record.
    """
    ddb = _get_ddb()
    try:
        ddb.update_item(
            TableName=COORDINATION_TABLE,
            Key={"request_id": _ser_s(request_id)},
            UpdateExpression="SET dispatch_tokens.#did = :token",
            ExpressionAttributeNames={"#did": dispatch_id},
            ExpressionAttributeValues={":token": _ser_s(token)},
        )
    except ClientError:
        # If dispatch_tokens doesn't exist yet, create it
        ddb.update_item(
            TableName=COORDINATION_TABLE,
            Key={"request_id": _ser_s(request_id)},
            UpdateExpression="SET dispatch_tokens = :tokens",
            ExpressionAttributeValues={
                ":tokens": {"M": {dispatch_id: _ser_s(token)}},
            },
        )


# ---------------------------------------------------------------------------
# Orchestration Logic
# ---------------------------------------------------------------------------


def _execute_plan(request_id: str, plan: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
    """Execute all dispatches in a plan according to sequence_order.

    Dispatches with the same sequence_order are executed in parallel.
    Dispatches with higher sequence_order wait for lower orders to complete.
    """
    dispatches = plan.get("dispatches", [])
    if not dispatches:
        return {"status": "no_dispatches", "request_id": request_id}

    # Group by sequence_order
    order_groups: Dict[int, List[Dict]] = {}
    for d in dispatches:
        order = d.get("sequence_order", 0)
        order_groups.setdefault(order, []).append(d)

    results: List[Dict[str, Any]] = []
    has_failure = False

    for order in sorted(order_groups.keys()):
        group = order_groups[order]
        logger.info(
            "[INFO] Executing sequence_order=%d: %d dispatch(es)",
            order, len(group),
        )

        group_results = []
        for dispatch in group:
            try:
                result = _execute_dispatch(dispatch, request)
                result["status"] = "sent"
                group_results.append(result)
            except Exception as exc:
                logger.error(
                    "[ERROR] Dispatch %s failed: %s",
                    dispatch.get("dispatch_id"), exc,
                )
                group_results.append({
                    "dispatch_id": dispatch.get("dispatch_id"),
                    "status": "send_failed",
                    "error": str(exc),
                })
                has_failure = True

                # Check rollback policy
                rollback = plan.get("rollback_policy", {})
                if rollback.get("on_partial_failure") == "halt_remaining":
                    logger.info("[INFO] Halting remaining dispatches (rollback_policy=halt_remaining)")
                    results.extend(group_results)
                    return {
                        "status": "partial_failure_halted",
                        "request_id": request_id,
                        "dispatch_results": results,
                    }

        results.extend(group_results)

        # For sequential execution: if any dispatch in this order failed
        # and policy is halt, stop here
        if has_failure and plan.get("rollback_policy", {}).get("on_partial_failure") == "halt_remaining":
            break

    return {
        "status": "all_sent" if not has_failure else "partial_failure",
        "request_id": request_id,
        "dispatch_results": results,
        "total_dispatches": len(dispatches),
        "successful_sends": len([r for r in results if r.get("status") == "sent"]),
    }


# ---------------------------------------------------------------------------
# Lambda Handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for dispatch orchestration.

    Triggered by EventBridge events with detail-type 'coordination.request.queued'.
    """
    logger.info("[START] Dispatch orchestrator invoked")
    logger.info("[INFO] Event: %s", json.dumps(event, default=str)[:500])

    # Extract event detail
    detail = event.get("detail", {})
    request_id = detail.get("request_id")
    override_plan = detail.get("dispatch_plan_override")

    if not request_id:
        logger.error("[ERROR] No request_id in event detail")
        return {"statusCode": 400, "error": "Missing request_id"}

    try:
        # Step 1: Transition to 'dispatching'
        _transition_state(request_id, _STATE_DISPATCHING)

        # Step 2: Generate dispatch-plan
        logger.info("[INFO] Generating dispatch-plan for request %s", request_id)

        if override_plan:
            plan = override_plan
            logger.info("[INFO] Using override dispatch-plan")
        else:
            plan = _generate_dispatch_plan_via_agent(request_id)

        # Step 3: Store plan in coordination-requests record
        _transition_state(request_id, _STATE_DISPATCHING, dispatch_plan=plan)
        logger.info(
            "[INFO] Dispatch-plan stored: plan_id=%s, dispatches=%d",
            plan.get("plan_id"), len(plan.get("dispatches", [])),
        )

        # Step 4: Load full request for dispatch execution
        ddb = _get_ddb()
        req_resp = ddb.get_item(
            TableName=COORDINATION_TABLE,
            Key={"request_id": _ser_s(request_id)},
        )
        request = _deser_item(req_resp.get("Item", {}))

        # Step 5: Execute dispatches
        execution_result = _execute_plan(request_id, plan, request)
        logger.info("[INFO] Execution result: %s", json.dumps(execution_result, default=str)[:500])

        # Step 6: Transition to 'running' if at least one dispatch was sent
        if execution_result.get("successful_sends", 0) > 0:
            _transition_state(request_id, _STATE_RUNNING)
        elif execution_result.get("status") == "no_dispatches":
            logger.warning("[WARNING] No dispatches in plan — marking as failed")
            _transition_state(request_id, _STATE_FAILED)
        else:
            logger.error("[ERROR] All dispatches failed to send")
            _transition_state(request_id, _STATE_FAILED)

        # Step 7: Emit orchestration event
        _emit_orchestration_event(request_id, plan, execution_result)

        logger.info("[SUCCESS] Dispatch orchestration complete for %s", request_id)
        return {
            "statusCode": 200,
            "request_id": request_id,
            "plan_id": plan.get("plan_id"),
            "execution_result": execution_result,
        }

    except Exception as exc:
        logger.exception("[ERROR] Dispatch orchestration failed for %s: %s", request_id, exc)
        try:
            _transition_state(request_id, _STATE_FAILED)
        except Exception:
            logger.exception("[ERROR] Failed to transition to 'failed' state")

        # Emit failure event
        try:
            _emit_escalation_event(request_id, str(exc))
        except Exception:
            logger.exception("[ERROR] Failed to emit escalation event")

        return {
            "statusCode": 500,
            "error": str(exc),
            "request_id": request_id,
        }


def _emit_orchestration_event(
    request_id: str,
    plan: Dict[str, Any],
    execution_result: Dict[str, Any],
) -> None:
    """Emit an EventBridge event for orchestration completion."""
    try:
        events = _get_events()
        events.put_events(
            Entries=[{
                "Source": "enceladus.coordination",
                "DetailType": "coordination.dispatch.orchestrated",
                "Detail": json.dumps({
                    "request_id": request_id,
                    "plan_id": plan.get("plan_id"),
                    "governance_hash": plan.get("governance_hash"),
                    "dispatches_sent": execution_result.get("successful_sends", 0),
                    "total_dispatches": execution_result.get("total_dispatches", 0),
                    "status": execution_result.get("status"),
                    "timestamp": _now_z(),
                }, default=str),
                "EventBusName": EVENTBRIDGE_BUS,
            }]
        )
    except Exception as exc:
        logger.warning("[WARNING] Failed to emit orchestration event: %s", exc)


def _emit_escalation_event(request_id: str, error_detail: str) -> None:
    """Emit an EventBridge event for dispatch escalation (failure)."""
    try:
        events = _get_events()
        events.put_events(
            Entries=[{
                "Source": "enceladus.coordination",
                "DetailType": "coordination.dispatch.escalation",
                "Detail": json.dumps({
                    "request_id": request_id,
                    "error": error_detail[:500],
                    "timestamp": _now_z(),
                }, default=str),
                "EventBusName": EVENTBRIDGE_BUS,
            }]
        )
    except Exception as exc:
        logger.warning("[WARNING] Failed to emit escalation event: %s", exc)
