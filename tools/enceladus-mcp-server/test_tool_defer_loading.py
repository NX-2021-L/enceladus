"""Tests for ENC-TSK-G15 deferred tool-loading policy."""

from __future__ import annotations

import unittest

from tool_defer_loading import (
    BM25_REPRESENTATIVE_QUERIES,
    EAGER_LOAD_TOOLS,
    ENCELADUS_MCP_SERVER_INSTRUCTIONS,
    OPUS_TOOLSET_CACHE_MIN_TOKENS,
    SONNET_TOOLSET_CACHE_MIN_TOKENS,
    TOOLSET_CACHE_TTL,
    anthropic_beta_headers,
    apply_toolset_cache_control,
    build_anthropic_deferred_tools_array,
    build_mcp_toolset,
    defer_loading_policy_summary,
    estimate_mcp_toolset_cache_eligible_tokens,
    estimate_tool_definition_token_footprint,
    expected_toolset_cache_hit_rate,
)


class ToolDeferLoadingPolicyTests(unittest.TestCase):
    def test_eager_load_tools_are_four_code_mode_meta_tools(self):
        self.assertEqual(
            set(EAGER_LOAD_TOOLS),
            {"search", "get_compact_context", "execute", "coordination"},
        )

    def test_build_mcp_toolset_defers_by_default(self):
        toolset = build_mcp_toolset()
        self.assertEqual(toolset["type"], "mcp_toolset")
        self.assertTrue(toolset["default_config"]["defer_loading"])
        for tool in EAGER_LOAD_TOOLS:
            self.assertFalse(toolset["configs"][tool]["defer_loading"])

    def test_build_anthropic_deferred_tools_array_registers_bm25(self):
        tools = build_anthropic_deferred_tools_array()
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["type"], "tool_search_tool_bm25_20251119")
        self.assertEqual(tools[1]["type"], "mcp_toolset")
        self.assertEqual(
            tools[-1]["cache_control"],
            {"type": "ephemeral", "ttl": TOOLSET_CACHE_TTL},
        )

    def test_apply_toolset_cache_control_targets_last_tool(self):
        tools = apply_toolset_cache_control(
            [{"type": "tool_search_tool_bm25_20251119"}, {"type": "mcp_toolset"}]
        )
        self.assertNotIn("cache_control", tools[0])
        self.assertEqual(tools[1]["cache_control"]["ttl"], TOOLSET_CACHE_TTL)

    def test_mcp_toolset_exceeds_cache_minimums(self):
        eligibility = estimate_mcp_toolset_cache_eligible_tokens(deferred_tool_count=36)
        self.assertGreaterEqual(
            eligibility["catalog_tokens_est"], SONNET_TOOLSET_CACHE_MIN_TOKENS
        )
        self.assertGreaterEqual(
            eligibility["catalog_tokens_est"], OPUS_TOOLSET_CACHE_MIN_TOKENS
        )
        self.assertTrue(eligibility["meets_sonnet_minimum"])
        self.assertTrue(eligibility["meets_opus_minimum"])

    def test_server_instructions_are_keyword_rich(self):
        text = ENCELADUS_MCP_SERVER_INSTRUCTIONS.lower()
        for keyword in (
            "tracker",
            "docstore",
            "checkout",
            "deploy",
            "governance",
            "dispatch",
        ):
            self.assertIn(keyword, text)

    def test_token_footprint_reduction_exceeds_seventy_percent(self):
        footprint = estimate_tool_definition_token_footprint(
            eager_tool_count=len(EAGER_LOAD_TOOLS),
            deferred_tool_count=36,
        )
        self.assertGreaterEqual(footprint["reduction_percent_est"], 70.0)

    def test_policy_summary_includes_representative_queries(self):
        summary = defer_loading_policy_summary(deferred_tool_count=36)
        self.assertEqual(summary["bm25_representative_queries"], list(BM25_REPRESENTATIVE_QUERIES))
        self.assertIn("advanced-tool-use", summary["anthropic_beta"])
        self.assertIn("mcp-client", summary["anthropic_beta"])
        self.assertTrue(summary["toolset_cache_eligibility"]["meets_opus_minimum"])
        self.assertEqual(
            summary["toolset_cache_control"],
            {"type": "ephemeral", "ttl": TOOLSET_CACHE_TTL},
        )

    def test_expected_toolset_cache_hit_rate_exceeds_sixty_percent(self):
        model = expected_toolset_cache_hit_rate(total_turns=10)
        self.assertGreaterEqual(model["hit_rate"], 0.6)
        self.assertTrue(model["meets_sixty_percent_ac"])


if __name__ == "__main__":
    unittest.main()
