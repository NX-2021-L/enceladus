"""decomposition.py — Request decomposition into tracker artifacts, model helpers, idempotency.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from config import (
    CLAUDE_THINKING_BUDGET_MAX,
    CLAUDE_THINKING_BUDGET_MIN,
    COORDINATION_GSI_IDEMPOTENCY,
    COORDINATION_TABLE,
    DEAD_LETTER_SNS_TOPIC_ARN,
    ENABLE_CLAUDE_HEADLESS,
    IDEMPOTENCY_WINDOW_SECONDS,
    MAX_CONSTRAINT_SIZE,
    MAX_OUTCOMES,
    MAX_OUTCOME_LENGTH,
    _CLAUDE_PERMISSION_MODES,
    _CLAUDE_VALID_TASK_COMPLEXITIES,
    _ENCELADUS_ALLOWED_TOOLS,
    _RETRY_BACKOFF_SECONDS,
    _STATE_DEAD_LETTER,
    _VALID_EXECUTION_MODES,
    _VALID_PROVIDERS,
    logger,
)
from serialization import _deserialize, _now_z, _serialize, _unix_now
from aws_clients import _get_ddb, _get_sns
from intake_dedup import _cleanup_dispatch_host
from persistence import _append_state_transition, _request_key

__all__ = [
    "_acquire_dispatch_lock",
    "_classify_dispatch_failure",
    "_coerce_execution_mode",
    "_derive_idempotency_key",
    "_find_recent_by_idempotency",
    "_move_to_dead_letter",
    "_new_callback_token",
    "_new_dispatch_id",
    "_new_request_id",
    "_normalize_outcomes",
    "_publish_dead_letter_alert",
    "_release_dispatch_lock",
    "_retry_backoff_seconds",
    "_validate_constraints",
    "_validate_provider_session",
]

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
        "batch_eligible",
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

    # batch_eligible — signals dispatch can be deferred to batch API for cost savings
    batch_eligible = raw.get("batch_eligible")
    if batch_eligible is not None:
        if not isinstance(batch_eligible, bool):
            raise ValueError("'provider_preferences.batch_eligible' must be a boolean")
        out["batch_eligible"] = batch_eligible

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



