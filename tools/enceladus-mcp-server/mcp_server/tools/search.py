"""Code-mode `search` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from mcp.types import TextContent

from mcp_server.catalog import CATALOG_SCHEMA_VERSION, VIA_ORDER, filter_catalog
from mcp_server.meta_support import (
    merge_meta_tool_arguments,
    meta_tool_error,
    meta_tool_success,
    raw_call_summary,
    result_metadata,
)
from mcp_server.runtime import RUNTIME

logger = logging.getLogger(__name__)

SEARCH_ACTIONS: Dict[str, Dict[str, Any]] | None = None


def register_actions(actions: Dict[str, Dict[str, Any]]) -> None:
    global SEARCH_ACTIONS
    SEARCH_ACTIONS = actions


def _builtin_action(action: str, raw_args: Dict[str, Any]) -> list[TextContent]:
    """Actions answered by the dispatcher itself (no underlying raw tool)."""
    if action != "actions.schemas":
        return meta_tool_error(
            "search",
            code="unknown_action",
            message=f"Unknown search action '{action}'",
            action=action,
        )
    provider = RUNTIME.action_catalog
    if provider is None:
        return meta_tool_error(
            "search",
            code="tool_resolution_failed",
            message="action catalog is not bound",
            action=action,
        )
    via = str(raw_args.get("via") or "").strip()
    if via and via not in VIA_ORDER:
        return meta_tool_error(
            "search",
            code="invalid_input",
            message=f"via must be one of: {', '.join(VIA_ORDER)}",
            action=action,
        )
    names = raw_args.get("names")
    if names is not None and not isinstance(names, list):
        return meta_tool_error(
            "search",
            code="invalid_input",
            message="names must be an array of action names",
            action=action,
        )
    catalog = provider()
    actions = filter_catalog(catalog, via=via or None, names=names)
    return meta_tool_success(
        "search",
        action=action,
        result={
            "schemaVersion": CATALOG_SCHEMA_VERSION,
            "count": len(actions),
            "registry_size": len(catalog),
            "actions": actions,
        },
        metadata={"action_count": len(actions)},
    )


async def search(args: dict) -> list[TextContent]:
    action = str(args.get("action") or "").strip()
    if not action:
        return meta_tool_error(
            "search",
            code="invalid_input",
            message="action is required",
        )

    entry = (SEARCH_ACTIONS or {}).get(action)
    if not entry:
        return meta_tool_error(
            "search",
            code="unknown_action",
            message=f"Unknown search action '{action}'",
            action=action,
        )

    raw_args = merge_meta_tool_arguments(args, {"action", "arguments"})
    if entry.get("builtin"):
        return _builtin_action(action, raw_args)

    try:
        raw_call = await RUNTIME.invoke_raw_tool(entry["tool"], raw_args)
    except PermissionError as exc:
        return meta_tool_error(
            "search",
            code="boundary_denied",
            message=str(exc),
            action=action,
        )
    except Exception as exc:
        return meta_tool_error(
            "search",
            code="tool_resolution_failed",
            message=str(exc),
            action=action,
        )

    if raw_call["status"] != "success":
        return meta_tool_error(
            "search",
            code=raw_call.get("error_code") or "tool_error",
            message=f"Underlying tool '{entry['tool']}' returned an error",
            action=action,
            underlying_calls=[raw_call_summary(raw_call)],
            details={"result": raw_call["payload"]},
        )

    return meta_tool_success(
        "search",
        action=action,
        result=raw_call["payload"],
        metadata=result_metadata(raw_call["payload"]),
        underlying_calls=[raw_call_summary(raw_call)],
    )
