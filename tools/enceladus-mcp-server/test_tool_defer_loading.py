"""Tests for ENC-TSK-G15 deferred tool-loading policy."""

from __future__ import annotations

import unittest

from tool_defer_loading import (
    BM25_REPRESENTATIVE_QUERIES,
    EAGER_LOAD_TOOLS,
    ENCELADUS_MCP_SERVER_INSTRUCTIONS,
    anthropic_beta_headers,
    build_anthropic_deferred_tools_array,
    build_mcp_toolset,
    defer_loading_policy_summary,
    estimate_tool_definition_token_footprint,
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


if __name__ == "__main__":
    unittest.main()
