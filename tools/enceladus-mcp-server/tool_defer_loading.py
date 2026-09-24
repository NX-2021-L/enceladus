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

TOOLSET_CACHE_TTL = "1h"
SONNET_TOOLSET_CACHE_MIN_TOKENS = 2048
OPUS_TOOLSET_CACHE_MIN_TOKENS = 4096
TOKENS_PER_DEFERRED_TOOL_EST = 800
BM25_TOOL_SEARCH_TOKEN_EST = 200

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
    apply_cache_control: bool = True,
) -> List[Dict[str, Any]]:
    """Tools array for Anthropic Messages API: BM25 search + deferred MCP toolset."""
    tools: List[Dict[str, Any]] = [
        build_bm25_tool_search_tool(),
        build_mcp_toolset(mcp_server_name=mcp_server_name, eager_tools=eager_tools),
    ]
    if apply_cache_control:
        tools = apply_toolset_cache_control(tools)
    return tools


def apply_toolset_cache_control(
    tools: Sequence[Dict[str, Any]],
    *,
    ttl: str = TOOLSET_CACHE_TTL,
) -> List[Dict[str, Any]]:
    """Attach ephemeral cache_control to the last tool block (Anthropic tools-array caching)."""
    if not tools:
        return []
    copied = [dict(item) for item in tools]
    last = dict(copied[-1])
    last["cache_control"] = {"type": "ephemeral", "ttl": ttl}
    copied[-1] = last
    return copied


def expected_toolset_cache_hit_rate(*, total_turns: int = 10) -> Dict[str, Any]:
    """Analytical cache-hit expectation for multi-turn sessions: turn 1 writes, rest read."""
    if total_turns < 1:
        return {"hit_rate": 0.0, "meets_sixty_percent_ac": False, "total_turns": 0}
    read_turns = max(total_turns - 1, 0)
    hit_rate = read_turns / total_turns
    return {
        "hit_rate": round(hit_rate, 4),
        "meets_sixty_percent_ac": hit_rate >= 0.6,
        "total_turns": total_turns,
        "cache_read_turns": read_turns,
    }


def estimate_mcp_toolset_cache_eligible_tokens(
    *,
    eager_tool_count: Optional[int] = None,
    deferred_tool_count: int = 0,
    tokens_per_tool: int = TOKENS_PER_DEFERRED_TOOL_EST,
) -> Dict[str, Any]:
    """Estimate full MCP catalog tokens eligible for toolset caching (post-defer_loading)."""
    eager_count = eager_tool_count if eager_tool_count is not None else len(EAGER_LOAD_TOOLS)
    instruction_tokens = max(len(ENCELADUS_MCP_SERVER_INSTRUCTIONS) // 4, 1)
    catalog_tokens = (
        BM25_TOOL_SEARCH_TOKEN_EST
        + instruction_tokens
        + (eager_count + deferred_tool_count) * tokens_per_tool
    )
    return {
        "catalog_tokens_est": catalog_tokens,
        "meets_sonnet_minimum": catalog_tokens >= SONNET_TOOLSET_CACHE_MIN_TOKENS,
        "meets_opus_minimum": catalog_tokens >= OPUS_TOOLSET_CACHE_MIN_TOKENS,
        "sonnet_minimum": SONNET_TOOLSET_CACHE_MIN_TOKENS,
        "opus_minimum": OPUS_TOOLSET_CACHE_MIN_TOKENS,
    }


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
    cache_eligibility = estimate_mcp_toolset_cache_eligible_tokens(
        eager_tool_count=len(eager),
        deferred_tool_count=deferred_tool_count,
    )
    tools_array = build_anthropic_deferred_tools_array(eager_tools=eager)
    return {
        "supported": True,
        "eager_load_tools": list(eager),
        "bm25_tool_search": build_bm25_tool_search_tool(),
        "mcp_toolset": build_mcp_toolset(eager_tools=eager),
        "tools_array": tools_array,
        "toolset_cache_control": tools_array[-1].get("cache_control") if tools_array else None,
        "server_instructions": ENCELADUS_MCP_SERVER_INSTRUCTIONS,
        "anthropic_beta": anthropic_beta_headers(),
        "bm25_representative_queries": list(BM25_REPRESENTATIVE_QUERIES),
        "token_footprint_estimate": footprint,
        "toolset_cache_eligibility": cache_eligibility,
        "toolset_cache_hit_rate_model": expected_toolset_cache_hit_rate(total_turns=10),
    }
