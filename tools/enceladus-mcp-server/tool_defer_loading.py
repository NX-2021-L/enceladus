"""Anthropic deferred tool-loading policy for Enceladus MCP (ENC-TSK-G15 / FTR-099 A3.2).

Single source of truth for:
- eager-load (non-deferred) code-mode tools
- BM25 tool search registration
- mcp_toolset default_config / per-tool configs
- keyword-rich server instructions for BM25 discovery
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Beta headers required when using tool search + defer_loading with MCP connector.
ANTHROPIC_ADVANCED_TOOL_USE_BETA = "advanced-tool-use-2025-11-20"
ANTHROPIC_MCP_CLIENT_BETA = "mcp-client-2025-11-20"

BM25_TOOL_SEARCH_TYPE = "tool_search_tool_bm25_20251119"
BM25_TOOL_SEARCH_NAME = "tool_search_tool_bm25"

DEFAULT_MCP_SERVER_NAME = "enceladus"

# Telemetry-informed eager-load set (G49): highest-frequency governed session tools.
EAGER_LOAD_TOOLS: Tuple[str, ...] = (
    "search",
    "get_compact_context",
    "execute",
    "coordination",
)

# Representative natural-language queries BM25 should route correctly (AC-3).
BM25_REPRESENTATIVE_QUERIES: Tuple[str, ...] = (
    "get tracker task record by id",
    "search documents in docstore",
    "advance checkout task lifecycle status",
    "list open tasks for project",
    "deploy lambda to gamma environment",
)

ENCELADUS_MCP_SERVER_INSTRUCTIONS = """
Enceladus governed MCP server for multi-agent software delivery.

Use search for read-only discovery: tracker.get, tracker.list, tracker.graphsearch,
documents.search, documents.get, deploy.history, governance.dictionary,
reference.search, system.connection_health, projects.list.

Use get_compact_context for budgeted composite context: record, issue, task, feature,
project, document, topic modes; hybrid retrieval with vector graph keyword RRF.

Use execute for governed mutations and lifecycle: tracker.set, tracker.set_acceptance_evidence,
checkout.task, checkout.advance, checkout.release, documents.put, documents.patch,
deploy.submit, github.create_issue, plan operations.

Use coordination for dispatch plans, capabilities, request inspection, cognito session.

Deferred raw tools include tracker CRUD, docstore read/write, deploy triggers,
changelog, governance hash, dispatch_plan_generate, github projects, code map,
architecture excerpts, issue context, component registry, and handoff helpers.
Search by tool name, record type (task issue feature plan lesson), lifecycle,
docstore, deploy gamma, governance hash, checkout, tracker mutation.
""".strip()


def normalize_eager_tools(tools: Optional[Iterable[str]] = None) -> Tuple[str, ...]:
    source = tools if tools is not None else EAGER_LOAD_TOOLS
    normalized: List[str] = []
    for item in source:
        name = str(item or "").strip()
        if name and name not in normalized:
            normalized.append(name)
    return tuple(normalized)


def build_mcp_toolset(
    *,
    mcp_server_name: str = DEFAULT_MCP_SERVER_NAME,
    eager_tools: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Anthropic mcp_toolset block: defer all tools except eager-load overrides."""
    eager = normalize_eager_tools(eager_tools)
    configs = {tool: {"defer_loading": False} for tool in eager}
    return {
        "type": "mcp_toolset",
        "mcp_server_name": mcp_server_name,
        "default_config": {"defer_loading": True},
        "configs": configs,
    }


def build_bm25_tool_search_tool() -> Dict[str, str]:
    return {
        "type": BM25_TOOL_SEARCH_TYPE,
        "name": BM25_TOOL_SEARCH_NAME,
    }


def build_anthropic_deferred_tools_array(
    *,
    mcp_server_name: str = DEFAULT_MCP_SERVER_NAME,
    eager_tools: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Tools array for Anthropic Messages API: BM25 search + deferred MCP toolset."""
    return [
        build_bm25_tool_search_tool(),
        build_mcp_toolset(mcp_server_name=mcp_server_name, eager_tools=eager_tools),
    ]


def anthropic_beta_headers() -> str:
    return f"{ANTHROPIC_ADVANCED_TOOL_USE_BETA},{ANTHROPIC_MCP_CLIENT_BETA}"


def estimate_tool_definition_token_footprint(
    *,
    eager_tool_count: int,
    deferred_tool_count: int,
    tokens_per_tool: int = 800,
) -> Dict[str, int]:
    """Rough before/after footprint for AC-4 measurement (/context style)."""
    before = (eager_tool_count + deferred_tool_count) * tokens_per_tool
    # Loaded up front: BM25 search tool (~200) + eager tools only.
    after = 200 + (eager_tool_count * tokens_per_tool)
    reduction_pct = 0.0
    if before > 0:
        reduction_pct = round((1.0 - (after / before)) * 100.0, 1)
    return {
        "before_tokens_est": before,
        "after_tokens_est": after,
        "reduction_percent_est": reduction_pct,
    }


def defer_loading_policy_summary(
    *,
    eager_tools: Optional[Iterable[str]] = None,
    deferred_tool_count: int = 0,
) -> Dict[str, Any]:
    eager = normalize_eager_tools(eager_tools)
    footprint = estimate_tool_definition_token_footprint(
        eager_tool_count=len(eager),
        deferred_tool_count=deferred_tool_count,
    )
    return {
        "eager_load_tools": list(eager),
        "bm25_tool_search": build_bm25_tool_search_tool(),
        "mcp_toolset": build_mcp_toolset(eager_tools=eager),
        "server_instructions": ENCELADUS_MCP_SERVER_INSTRUCTIONS,
        "anthropic_beta": anthropic_beta_headers(),
        "bm25_representative_queries": list(BM25_REPRESENTATIVE_QUERIES),
        "token_footprint_estimate": footprint,
    }
