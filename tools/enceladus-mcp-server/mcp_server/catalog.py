"""Unwrapped action catalog (DVP-TSK-843).

Builds the per-action contract ``{name, title, inputSchema, outputSchema,
annotations, requiresGovernanceHash, via, flag?}`` for every action reachable via
the code-mode ``search`` / ``execute`` / ``coordination`` wrappers plus the
first-party top-level tools.  The catalog is derived, never hand-listed:

  * names, titles, annotations, flags, governance requirement and output schemas
    come from the registry entries built by ``mcp_server.actions``;
  * ``inputSchema`` comes from the raw ``Tool(...)`` definition server.py already
    publishes for the underlying tool, or -- for the 55 actions that have none --
    from ``mcp_server.action_schemas`` (see that module for how it is kept honest).

This module has no dependency on server.py: server.py passes the raw tool schemas
in, which keeps it importable from the parity tooling and the unit tests.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Mapping, Optional

from mcp_server.action_schemas import ACTION_INPUT_SCHEMAS

CATALOG_SCHEMA_VERSION = "1.0.0"

_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}

# First-party tools that are reachable at the top level rather than through a
# wrapper.  In code mode that is get_compact_context; the other three code-mode
# tools (search, coordination, execute) are the wrappers themselves.
TOP_LEVEL_ACTIONS: Dict[str, Dict[str, Any]] = {
    "get_compact_context": {
        "tool": "get_compact_context",
        "title": "Get compact context",
        "annotations": dict(_READ_ONLY),
    },
}

# Raw / meta tools that are not an action behind any wrapper.  They still carry
# annotations so that 100% of first-party tools are annotated.
UNWRAPPED_TOOL_ANNOTATIONS: Dict[str, Dict[str, bool]] = {
    "get_architecture_excerpts": dict(_READ_ONLY),
    "get_code_map": dict(_READ_ONLY),
    "get_issue_context": dict(_READ_ONLY),
    "validate_commit_complete": dict(_READ_ONLY),
    # Writes a governance file to the bundle: overwrites the stored object.
    "governance_update": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    # The wrappers.  search is read-only by construction; coordination and execute
    # dispatch to actions that mutate, so they are neither read-only nor idempotent.
    "search": dict(_READ_ONLY),
    "coordination": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    "execute": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
}

VIA_ORDER = ("top-level", "search", "coordination", "execute")


def _registry_items(
    search_actions: Mapping[str, Mapping[str, Any]],
    coordination_actions: Mapping[str, Mapping[str, Any]],
    execute_actions: Mapping[str, Mapping[str, Any]],
) -> Iterable[tuple]:
    for name, entry in TOP_LEVEL_ACTIONS.items():
        yield "top-level", name, entry
    for via, registry in (
        ("search", search_actions),
        ("coordination", coordination_actions),
        ("execute", execute_actions),
    ):
        for name, entry in registry.items():
            yield via, name, entry


def resolve_input_schema(
    tool: str,
    raw_input_schemas: Mapping[str, Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Raw ``Tool`` definition first; otherwise the single declaration in action_schemas."""
    if tool in raw_input_schemas:
        return copy.deepcopy(dict(raw_input_schemas[tool]))
    if tool in ACTION_INPUT_SCHEMAS:
        return copy.deepcopy(ACTION_INPUT_SCHEMAS[tool])
    return None


def _ensure_governance_hash(schema: Dict[str, Any]) -> Dict[str, Any]:
    """execute() rejects a step without governance_hash before the handler runs, so the
    contract of every requires_governance_hash action must list it as required even
    when the raw Tool definition forgot to (deploy_state_set did)."""
    props = schema.setdefault("properties", {})
    props.setdefault(
        "governance_hash",
        {"type": "string", "description": "Current governance hash; obtain from governance.hash (search)."},
    )
    required = schema.setdefault("required", [])
    if "governance_hash" not in required:
        required.append("governance_hash")
    return schema


def _builtin_input_schema(name: str) -> Dict[str, Any]:
    if name == "actions.schemas":
        return {
            "type": "object",
            "properties": {
                "via": {
                    "type": "string",
                    "enum": list(VIA_ORDER),
                    "description": "Restrict the listing to one surface.",
                },
                "names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Restrict the listing to these action names.",
                },
            },
        }
    raise KeyError(name)


def build_action_catalog(
    search_actions: Mapping[str, Mapping[str, Any]],
    coordination_actions: Mapping[str, Mapping[str, Any]],
    execute_actions: Mapping[str, Mapping[str, Any]],
    raw_input_schemas: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Return one contract dict per registered action (top-level tools included)."""
    catalog: List[Dict[str, Any]] = []
    for via, name, entry in _registry_items(search_actions, coordination_actions, execute_actions):
        if entry.get("builtin"):
            input_schema: Optional[Dict[str, Any]] = _builtin_input_schema(name)
        else:
            input_schema = resolve_input_schema(entry["tool"], raw_input_schemas)
        if input_schema is not None and entry.get("requires_governance_hash"):
            input_schema = _ensure_governance_hash(input_schema)
        item: Dict[str, Any] = {
            "name": name,
            "title": entry["title"],
            "inputSchema": input_schema,
            "outputSchema": copy.deepcopy(entry.get("output")),
            "annotations": dict(entry["annotations"]),
            "requiresGovernanceHash": bool(entry.get("requires_governance_hash", False)),
            "via": via,
        }
        if entry.get("flag"):
            item["flag"] = entry["flag"]
        if via == "execute" or (via == "coordination" and not entry["annotations"].get("readOnlyHint")):
            # DVP-TSK-892 / caps schema 1.1.0 (ruling E2-R16): execute(dry_run=true) and the
            # coordination wrapper's dry_run:true resolve every WRITE action server-side with
            # zero writes (ResolvedCall v1).  Reads are never degraded and carry no dryRun.
            item["dryRun"] = True
        catalog.append(item)
    return catalog


def filter_catalog(
    catalog: List[Dict[str, Any]],
    *,
    via: Optional[str] = None,
    names: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    wanted = {str(n).strip() for n in names} if names else None
    return [
        item
        for item in catalog
        if (not via or item["via"] == via) and (wanted is None or item["name"] in wanted)
    ]


def tool_annotations(
    tool_name: str,
    search_actions: Mapping[str, Mapping[str, Any]],
    coordination_actions: Mapping[str, Mapping[str, Any]],
    execute_actions: Mapping[str, Mapping[str, Any]],
) -> Optional[Dict[str, bool]]:
    """Annotations for a raw tool name, or None when the tool is unknown.

    A tool reachable under several actions (tracker_create backs tracker.create and
    plan.create) must carry one set of annotations; the registry tests enforce that.
    """
    if tool_name in UNWRAPPED_TOOL_ANNOTATIONS:
        return dict(UNWRAPPED_TOOL_ANNOTATIONS[tool_name])
    for _via, _name, entry in _registry_items(search_actions, coordination_actions, execute_actions):
        if entry.get("tool") == tool_name and not entry.get("builtin"):
            return dict(entry["annotations"])
    return None
