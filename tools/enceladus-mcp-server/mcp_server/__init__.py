"""Decomposed MCP server package (ENC-TSK-L09 / B64 Ph3)."""
from mcp_server.actions import ActionFeatureFlags, build_action_registries
from mcp_server.runtime import RUNTIME, bind_runtime
from mcp_server.tools.context import get_compact_context_meta
from mcp_server.tools.coordination import coordination_meta, register_actions as register_coordination_actions
from mcp_server.tools.execute import execute, register_actions as register_execute_actions
from mcp_server.tools.search import register_actions as register_search_actions, search

__all__ = [
    "ActionFeatureFlags",
    "RUNTIME",
    "bind_runtime",
    "build_action_registries",
    "execute",
    "get_compact_context_meta",
    "coordination_meta",
    "register_coordination_actions",
    "register_execute_actions",
    "register_search_actions",
    "search",
]
