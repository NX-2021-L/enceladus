"""handlers.py — HTTP route handlers, MCP HTTP bridge, capabilities endpoint.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from config import (
    ANTHROPIC_API_VERSION,
    CALLBACK_EVENTBRIDGE_BUS,
    CALLBACK_EVENT_DETAIL_TYPE,
    CALLBACK_EVENT_SOURCE,
    CALLBACK_SQS_QUEUE_URL,
    CALLBACK_TOKEN_TTL_SECONDS,
    CLAUDE_PROMPT_CACHE_TTL,
    CLAUDE_THINKING_BUDGET_DEFAULT,
    CLAUDE_THINKING_BUDGET_MAX,
    CLAUDE_THINKING_BUDGET_MIN,
    COORDINATION_GSI_IDEMPOTENCY,
    COORDINATION_MCP_HTTP_PATH,
    COORDINATION_PUBLIC_BASE_URL,
    DEAD_LETTER_TIMEOUT_MULTIPLIER,
    DEBOUNCE_WINDOW_SECONDS,
    DEFAULT_CLAUDE_AGENT_MODEL,
    DEFAULT_OPENAI_CODEX_MODEL,
    DISPATCH_LOCK_BUFFER_SECONDS,
    ENABLE_CLAUDE_HEADLESS,
    HOST_V2_ENCELADUS_MCP_INSTALLER,
    HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL,
    HOST_V2_FLEET_ENABLED,
    HOST_V2_FLEET_FALLBACK_TO_STATIC,
    HOST_V2_FLEET_INSTANCE_TTL_SECONDS,
    HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
    HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
    HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES,
    HOST_V2_FLEET_READINESS_POLL_SECONDS,
    HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS,
    HOST_V2_FLEET_SWEEP_GRACE_SECONDS,
    HOST_V2_FLEET_SWEEP_ON_DISPATCH,
    HOST_V2_FLEET_USER_DATA_TEMPLATE,
    HOST_V2_INSTANCE_ID,
    HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS,
    HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS,
    HOST_V2_MCP_BOOTSTRAP_SCRIPT,
    HOST_V2_MCP_MARKER_PATH,
    HOST_V2_MCP_PROFILE_PATH,
    HOST_V2_PROJECT,
    HOST_V2_TIMEOUT_SECONDS,
    HOST_V2_WORK_ROOT,
    IDEMPOTENCY_WINDOW_SECONDS,
    MAX_DISPATCH_ATTEMPTS,
    MAX_TITLE_LENGTH,
    MCP_AUDIT_CALLER_IDENTITY,
    OPENAI_API_BASE_URL,
    _CLAUDE_ADAPTIVE_THINKING_MODELS,
    _CLAUDE_MODEL_ROUTING,
    _CLAUDE_PERMISSION_MODES,
    _CLAUDE_VALID_TASK_COMPLEXITIES,
    _ENCELADUS_ALLOWED_TOOLS,
    _NON_RETRIABLE_FAILURE_CLASSES,
    _RETRIABLE_FAILURE_CLASSES,
    _RETRY_BACKOFF_SECONDS,
    _STATE_DISPATCHING,
    _STATE_INTAKE_RECEIVED,
    _STATE_QUEUED,
    _STATE_RUNNING,
    _VALID_PROVIDERS,
    _VALID_TERMINAL_STATES,
    logger,
)
from serialization import _now_z, _unix_now
from aws_clients import _mcp
from http_utils import _error, _json_body, _path_method, _response
from project_utils import _load_project_meta
from mcp_integration import _load_mcp_server_module
from tracker_ops import _append_tracker_history, _collect_tracker_snapshots, _related_records_mutated, _requires_related_record_mutation_guard, _set_tracker_status
from decomposition import (
    _acquire_dispatch_lock,
    _classify_dispatch_failure,
    _coerce_execution_mode,
    _derive_idempotency_key,
    _find_recent_by_idempotency,
    _move_to_dead_letter,
    _new_callback_token,
    _new_dispatch_id,
    _new_request_id,
    _normalize_outcomes,
    _release_dispatch_lock,
    _retry_backoff_seconds,
    _validate_constraints,
    _validate_provider_session,
)
from intake_dedup import (
    _cleanup_dispatch_host,
    _count_active_host_dispatches,
    _decompose_and_create_tracker_artifacts,
    _extract_record_ids_from_body,
    _extract_record_ids_from_request,
    _find_active_host_dispatch,
    _find_dedup_match,
    _fleet_launch_ready,
    _merge_requests,
    _promote_expired_intake_requests,
)
from persistence import _append_state_transition, _get_request, _put_request, _redact_request, _update_request
from dispatch_ssm import (
    _append_dispatch_worklog,
    _build_result_payload,
    _dispatch_claude_api,
    _dispatch_openai_codex_api,
    _is_timeout_failure,
    _lambda_provider_preflight,
    _lookup_dispatch_execution_mode,
    _provider_secret_readiness,
    _refresh_request_from_ssm,
    _send_dispatch,
)
from lifecycle import (
    _compute_plan_status,
    _emit_callback_event,
    _evaluate_plan_terminal_state,
    _finalize_tracker_from_request,
    _normalize_aws_native_callback,
    _normalize_callback_body,
    _publish_feed_push_updates,
    _update_dispatch_outcome,
    _update_provider_session_from_callback,
)

__all__ = [
    "_dispatch_mcp_jsonrpc_method",
    "_handle_callback",
    "_handle_capabilities",
    "_handle_create_request",
    "_handle_dispatch_request",
    "_handle_eventbridge_callback",
    "_handle_get_request",
    "_handle_mcp_http",
    "_handle_sqs_callback",
    "_mcp_jsonrpc_error",
    "_mcp_jsonrpc_response",
    "_mcp_mime_type_for_uri",
    "_mcp_to_plain",
    "_run_async",
]

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
        execution_mode = _coerce_execution_mode(body.get("execution_mode") or request.get("execution_mode"))
    except ValueError as exc:
        return _error(400, str(exc))

    try:
        provider_prefs_raw = body.get("provider_preferences") or body.get("provider_session")
        provider_session = _validate_provider_session(provider_prefs_raw)
    except ValueError as exc:
        return _error(400, str(exc))

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
    dispatch_id = str(body.get("dispatch_id") or _new_dispatch_id()).strip().upper()
    if not re.fullmatch(r"[A-Z0-9-]{6,64}", dispatch_id):
        return _error(400, "'dispatch_id' must match [A-Z0-9-]{6,64}")

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
        running_provider = "host_v2"
        running_summary = f"Dispatch started (command_id={dispatch_meta.get('command_id')})"
        if execution_mode == "claude_agent_sdk":
            running_reason = "Claude API dispatch accepted"
            running_extra = {"execution_id": dispatch_meta.get("execution_id")}
            running_provider = "claude_agent_sdk"
            running_summary = f"Dispatch started (execution_id={dispatch_meta.get('execution_id')})"
        elif execution_mode in {"codex_app_server", "codex_full_auto"}:
            running_reason = "OpenAI Responses API dispatch accepted"
            running_extra = {"execution_id": dispatch_meta.get("execution_id")}
            running_provider = "openai_codex"
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
                "claude_agent_sdk"
                if execution_mode == "claude_agent_sdk"
                else ("openai_codex" if execution_mode in {"codex_app_server", "codex_full_auto"} else "host_v2")
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


