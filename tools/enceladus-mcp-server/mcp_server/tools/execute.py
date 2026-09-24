"""Code-mode `execute` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from mcp.types import TextContent

from mcp_server.meta_support import (
    meta_tool_error,
    meta_tool_success,
    raw_call_summary,
)
from mcp_server.runtime import RUNTIME

logger = logging.getLogger(__name__)

EXECUTE_ACTIONS: Dict[str, Dict[str, Any]] | None = None


def register_actions(actions: Dict[str, Dict[str, Any]]) -> None:
    global EXECUTE_ACTIONS
    EXECUTE_ACTIONS = actions


async def execute(args: dict) -> list[TextContent]:
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return meta_tool_error(
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
        entry = (EXECUTE_ACTIONS or {}).get(action)
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

        allowed = RUNTIME.raw_tool_allowed
        if allowed is None or not allowed(entry["tool"]):
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
            raw_call = await RUNTIME.invoke_raw_tool(entry["tool"], step_args)
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

        call_summary = raw_call_summary(raw_call)
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
        return RUNTIME.result_text({
            "success": False,
            "interface_mode": RUNTIME.interface_mode,
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

    return meta_tool_success(
        "execute",
        steps=step_results,
        underlying_calls=underlying_calls,
        dry_run=overall_dry_run,
        metadata={"step_count": len(step_results)},
    )
