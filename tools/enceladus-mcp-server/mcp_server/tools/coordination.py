"""Code-mode `coordination` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from mcp.types import TextContent

from mcp_server.meta_support import (
    merge_meta_tool_arguments,
    meta_tool_error,
    meta_tool_success,
    raw_call_summary,
    result_metadata,
)
from mcp_server.runtime import RUNTIME
from mcp_server.tools.execute import (
    IDEMPOTENCY_KEY_ARGS,
    SCHEMA_HASH_ARGS,
    _action_contract,
    _first_arg,
    _sha256,
    _with_problem,
    problem_details,
    resolve_call,
    schema_hash_for,
    validate_step_arguments,
)

logger = logging.getLogger(__name__)

COORDINATION_ACTIONS: Dict[str, Dict[str, Any]] | None = None


def register_actions(actions: Dict[str, Dict[str, Any]]) -> None:
    global COORDINATION_ACTIONS
    COORDINATION_ACTIONS = actions


async def coordination_meta(args: dict) -> list[TextContent]:
    action = str(args.get("action") or "").strip()
    if not action:
        return meta_tool_error(
            "coordination",
            code="invalid_input",
            message="action is required",
        )

    entry = (COORDINATION_ACTIONS or {}).get(action)
    if not entry:
        return meta_tool_error(
            "coordination",
            code="unknown_action",
            message=f"Unknown coordination action '{action}'",
            action=action,
        )

    raw_args = merge_meta_tool_arguments(args, {"action", "arguments"})

    # DVP-TSK-892 follow-up (ruling E2-R16): dry_run:true on a WRITE action returns a
    # ResolvedCall v1 and dispatches nothing.  A dry_run nested inside `arguments` is the
    # underlying tool's own native option (e.g. agent.checkout_release_backfill) and still
    # passes through untouched, as does dry_run on read-only actions.
    nested = args.get("arguments") if isinstance(args.get("arguments"), dict) else {}
    if (
        args.get("dry_run") is True
        and "dry_run" not in nested
        and not (entry.get("annotations") or {}).get("readOnlyHint")
    ):
        return _coordination_dry_run(args, action, entry, raw_args)

    try:
        raw_call = await RUNTIME.invoke_raw_tool(entry["tool"], raw_args)
    except PermissionError as exc:
        return meta_tool_error(
            "coordination",
            code="boundary_denied",
            message=str(exc),
            action=action,
        )
    except Exception as exc:
        return meta_tool_error(
            "coordination",
            code="tool_resolution_failed",
            message=str(exc),
            action=action,
        )

    if raw_call["status"] != "success":
        return meta_tool_error(
            "coordination",
            code=raw_call.get("error_code") or "tool_error",
            message=f"Underlying tool '{entry['tool']}' returned an error",
            action=action,
            underlying_calls=[raw_call_summary(raw_call)],
            details={"result": raw_call["payload"]},
        )

    return meta_tool_success(
        "coordination",
        action=action,
        result=raw_call["payload"],
        metadata=result_metadata(raw_call["payload"]),
        underlying_calls=[raw_call_summary(raw_call)],
    )


def _coordination_dry_run(args: dict, action: str, entry: Dict[str, Any], raw_args: Dict[str, Any]) -> list[TextContent]:
    """ResolvedCall v1 preview of one coordination write action. Zero writes, no dispatch."""
    step_args = {k: v for k, v in raw_args.items() if k not in ("dry_run", *IDEMPOTENCY_KEY_ARGS, *SCHEMA_HASH_ARGS)}
    allowed = RUNTIME.raw_tool_allowed
    if allowed is None or not allowed(entry["tool"]):
        return meta_tool_error(
            "coordination",
            code="boundary_denied",
            message=f"Raw tool '{entry['tool']}' is outside the current session boundary",
            action=action,
        )
    contract = _action_contract(action, "coordination")
    live_hash = schema_hash_for(contract, entry)
    sent_hash = _first_arg(args, SCHEMA_HASH_ARGS)
    if sent_hash and sent_hash != live_hash:
        message = f"schemaHash for action '{action}' does not match the live registry"
        return _with_problem(
            meta_tool_error("coordination", code="schema_hash_mismatch", message=message, action=action),
            problem_details(409, "Schema hash mismatch", message, slug="schema-hash-mismatch",
                            errors=[{"pointer": "/schemaHash", "detail": message, "code": "schema_hash_mismatch"}]),
        )
    field_errors = validate_step_arguments(contract, step_args)
    if field_errors:
        message = f"Arguments for action '{action}' failed validation"
        return _with_problem(
            meta_tool_error("coordination", code="validation_failed", message=message, action=action),
            problem_details(422, "Validation failed", message, errors=field_errors),
        )
    key = _first_arg(args, IDEMPOTENCY_KEY_ARGS)
    warnings: List[str] = []
    if not key:
        warnings.append("no Idempotency-Key supplied; idempotencyKey is derived from the request and is not a replay guard")
    resolved = resolve_call(
        action,
        entry,
        step_args,
        idempotency_key=key or f"dry-{_sha256({'action': action, 'arguments': step_args})[:32]}",
        schema_hash=live_hash,
        contract=contract,
        warnings=warnings,
    )
    summary = {"tool": entry["tool"], "arguments": step_args, "status": "dry_run"}
    return RUNTIME.result_text({
        "success": True,
        "interface_mode": RUNTIME.interface_mode,
        "tool": "coordination",
        "action": action,
        "dry_run": True,
        "partial": False,
        "resolved_call": resolved,
        "underlying_calls": [summary],
    })
