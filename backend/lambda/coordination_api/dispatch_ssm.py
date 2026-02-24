"""dispatch_ssm.py — SSM dispatch, provider APIs (OpenAI/Claude), execution state refresh.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import pathlib
import re
import shlex
import ssl
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from config import (
    ANTHROPIC_API_BASE_URL,
    ANTHROPIC_API_KEY_SECRET_ID,
    ANTHROPIC_API_STREAM_TIMEOUT_SECONDS,
    ANTHROPIC_API_TIMEOUT_SECONDS,
    ANTHROPIC_API_VERSION,
    CLAUDE_API_MAX_TOKENS_DEFAULT,
    CLAUDE_API_MAX_TOKENS_MAX,
    CLAUDE_API_MAX_TOKENS_MIN,
    CLAUDE_PROMPT_CACHE_TTL,
    CLAUDE_THINKING_BUDGET_DEFAULT,
    CLAUDE_THINKING_BUDGET_MAX,
    CLAUDE_THINKING_BUDGET_MIN,
    COORDINATION_PUBLIC_BASE_URL,
    DEAD_LETTER_TIMEOUT_MULTIPLIER,
    DEFAULT_CLAUDE_AGENT_MODEL,
    DEFAULT_OPENAI_CODEX_MODEL,
    DISPATCH_TIMEOUT_CEILING_SECONDS,
    DISPATCH_WORKLOG_MAX_ENTRIES,
    DYNAMODB_REGION,
    ENABLE_MCP_GOVERNANCE_PROMPT,
    GOVERNANCE_PROMPT_MAX_CHARS,
    GOVERNANCE_PROMPT_RESOURCE_URIS_FALLBACK,
    HOST_V2_AWS_PROFILE,
    HOST_V2_ENCELADUS_MCP_INSTALLER,
    HOST_V2_INSTANCE_ID,
    HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS,
    HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS,
    HOST_V2_MCP_MARKER_PATH,
    HOST_V2_MCP_PROFILE_PATH,
    HOST_V2_PROVIDER_CHECK_SCRIPT,
    HOST_V2_TIMEOUT_SECONDS,
    HOST_V2_WORK_ROOT,
    MCP_CONNECTIVITY_BACKOFF_SECONDS,
    OPENAI_API_BASE_URL,
    OPENAI_API_KEY_SECRET_ID,
    OPENAI_API_ORGANIZATION,
    OPENAI_API_PROJECT,
    OPENAI_API_TIMEOUT_SECONDS,
    OPENAI_MAX_OUTPUT_TOKENS_MAX,
    OPENAI_MAX_OUTPUT_TOKENS_MIN,
    ROTATION_WARNING_DAYS,
    SECRETS_REGION,
    SSM_DOCUMENT_NAME,
    SSM_REGION,
    WORKER_RUNTIME_LOG_GROUP,
    _CLAUDE_ADAPTIVE_THINKING_MODELS,
    _CLAUDE_CONTEXT_LIMITS,
    _CLAUDE_DEFAULT_CONTEXT_LIMIT,
    _CLAUDE_DEFAULT_PRICING,
    _CLAUDE_MODEL_ROUTING,
    _CLAUDE_PRICING,
    _ENCELADUS_ALLOWED_TOOLS,
    _STATE_RUNNING,
    logger,
)
from serialization import _emit_structured_observability, _now_z, _unix_now
from aws_clients import _get_ec2, _get_secretsmanager, _get_ssm, _mcp
from auth import _CERT_BUNDLE
from project_utils import _MCP_RESOURCE_CACHE
from mcp_integration import _load_mcp_server_module
from decomposition import _move_to_dead_letter, _release_dispatch_lock
from intake_dedup import _cleanup_dispatch_host, _resolve_host_dispatch_target
from persistence import _append_state_transition, _update_request
from lifecycle import _finalize_tracker_from_request

__all__ = [
    "_append_dispatch_worklog",
    "_build_claude_thinking_param",
    "_build_dispatch_payload_commands",
    "_build_managed_session_prompt",
    "_build_mcp_connectivity_check_commands",
    "_build_mcp_governance_context",
    "_build_mcp_profile_bootstrap_commands",
    "_build_provider_rotation_check_commands",
    "_build_result_payload",
    "_build_secret_fetch_commands",
    "_build_ssm_commands",
    "_calculate_claude_cost",
    "_callback_provider_for_execution_mode",
    "_coerce_claude_max_tokens",
    "_coerce_openai_json_schema_format",
    "_coerce_openai_max_output_tokens",
    "_coerce_openai_text_format",
    "_coerce_openai_tools",
    "_count_claude_tokens",
    "_dispatch_claude_api",
    "_dispatch_openai_codex_api",
    "_extract_claude_text_response",
    "_extract_claude_thinking_response",
    "_extract_json_marker",
    "_extract_openai_text_response",
    "_extract_provider_api_key",
    "_fetch_provider_api_key",
    "_is_timeout_failure",
    "_iso_days_until",
    "_lambda_provider_preflight",
    "_list_mcp_governance_resource_uris",
    "_lookup_dispatch_execution_mode",
    "_normalize_openai_schema",
    "_normalize_rotation_tags",
    "_parse_sse_stream",
    "_prepend_managed_session_bootstrap",
    "_provider_health_probe",
    "_provider_preflight_fetch_and_probe",
    "_provider_secret_readiness",
    "_provider_secret_status",
    "_providers_for_execution_mode",
    "_read_mcp_resource_text",
    "_recent_dispatch_worklogs",
    "_refresh_request_from_ssm",
    "_resolve_claude_model",
    "_send_dispatch",
]

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


