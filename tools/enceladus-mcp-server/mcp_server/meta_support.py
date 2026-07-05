"""Shared helpers for code-mode meta-tools (search/coordination/context/execute)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from mcp.types import TextContent

from mcp_server.runtime import RUNTIME

logger = logging.getLogger(__name__)

RECORD_CONTEXT_MODES = {"record", "issue", "task", "feature", "lesson"}


def _error_payload(
    code: str,
    message: str,
    retryable: bool = False,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if RUNTIME.error_payload is not None:
        return RUNTIME.error_payload(code=code, message=message, retryable=retryable, details=details)
    return {
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details or {},
        },
    }


def meta_tool_success(
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
        "interface_mode": RUNTIME.interface_mode,
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
    return RUNTIME.result_text(payload)


def meta_tool_error(
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
    payload["interface_mode"] = RUNTIME.interface_mode
    payload["tool"] = tool_name
    if action:
        payload["action"] = action
    if mode:
        payload["mode"] = mode
    payload["underlying_calls"] = underlying_calls or []
    return RUNTIME.result_text(payload)

def merge_meta_tool_arguments(args: Dict[str, Any], reserved: set[str]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    raw_args = args.get("arguments")
    if isinstance(raw_args, dict):
        merged.update(raw_args)
    for key, value in args.items():
        if key in reserved or key in merged:
            continue
        merged[key] = value
    return merged


def raw_call_summary(raw_call: Dict[str, Any], *, status_override: str = "") -> Dict[str, Any]:
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


def result_metadata(payload: Any) -> Dict[str, Any]:
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


async def best_effort_raw_tool(
    tool_name: str,
    tool_args: Dict[str, Any],
    *,
    underlying_calls: List[Dict[str, Any]],
    warnings: List[str],
    warning_label: str,
) -> Any:
    try:
        raw_call = await RUNTIME.invoke_raw_tool(tool_name, tool_args)
    except PermissionError as exc:
        warnings.append(str(exc))
        return None
    except Exception as exc:
        warnings.append(f"{warning_label}: {exc}")
        return None

    underlying_calls.append(raw_call_summary(raw_call))
    if raw_call["status"] != "success":
        warnings.append(
            f"{warning_label}: {raw_call.get('error_code') or 'tool_error'}"
        )
        return None
    return raw_call["payload"]
