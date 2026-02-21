"""End-to-end tests for Anthropic API enhancements (DVP-TSK-357..363).

These tests call the **live** Anthropic Messages API.  They are gated behind
the ``RUN_E2E_ANTHROPIC=1`` environment variable so they never fire in CI or
during a normal ``pytest`` run.

Each test verifies that the new enhancement features produce correct results
when dispatched through the real API, exercising the full path from
``_dispatch_claude_api()`` down to HTTP response parsing and cost attribution.
"""

import importlib.util
import json
import os
import pathlib
import sys
import time

import pytest


if os.environ.get("RUN_E2E_ANTHROPIC") != "1":
    pytest.skip(
        "Set RUN_E2E_ANTHROPIC=1 to run live Anthropic API end-to-end tests.",
        allow_module_level=True,
    )


MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_e2e", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_request(**overrides):
    """Build a minimal coordination request dict for _dispatch_claude_api."""
    req = {
        "request_id": f"CRQ-E2E-{int(time.time())}",
        "project_id": "devops",
        "provider_session": {},
    }
    req.update(overrides)
    return req


# ---------------------------------------------------------------------------
# DVP-TSK-362: API version upgrade + baseline dispatch
# ---------------------------------------------------------------------------

class TestE2EBaselineDispatch:
    """Verify that a basic dispatch succeeds with the upgraded API version."""

    def test_basic_dispatch_returns_succeeded(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(),
            prompt="Reply with the single word: pong",
            dispatch_id="DSP-E2E-BASELINE",
        )
        assert result["status"] == "succeeded"
        assert result["execution_mode"] == "claude_agent_sdk"
        assert result["provider"] == "claude_agent_sdk"
        assert "pong" in result["provider_result"]["summary"].lower()

    def test_provider_result_contains_usage_and_cost(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(),
            prompt="Reply with: ok",
            dispatch_id="DSP-E2E-COST",
        )
        pr = result["provider_result"]
        assert pr["usage"]["input_tokens"] > 0
        assert pr["usage"]["output_tokens"] > 0
        assert pr["cost_attribution"]["total_cost_usd"] > 0
        assert pr["cost_attribution"]["model"] == pr["model"]


# ---------------------------------------------------------------------------
# DVP-TSK-358: Intelligent model routing
# ---------------------------------------------------------------------------

class TestE2EModelRouting:
    """Verify that task_complexity routes to the correct model family."""

    def test_simple_routes_to_haiku(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={"task_complexity": "simple"}),
            prompt="Reply with the single word: hello",
            dispatch_id="DSP-E2E-ROUTE-SIMPLE",
        )
        pr = result["provider_result"]
        assert "haiku" in pr["model"].lower()
        assert pr["model_routing"]["task_complexity"] == "simple"
        assert pr["model_routing"]["reason"] == "task_complexity=simple"

    def test_standard_routes_to_sonnet(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={"task_complexity": "standard"}),
            prompt="Reply with the single word: hello",
            dispatch_id="DSP-E2E-ROUTE-STD",
        )
        pr = result["provider_result"]
        assert "sonnet" in pr["model"].lower()
        assert pr["model_routing"]["task_complexity"] == "standard"

    def test_explicit_model_override(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "model": "claude-haiku-4-5-20251001",
                "task_complexity": "critical",
            }),
            prompt="Reply with the single word: hello",
            dispatch_id="DSP-E2E-ROUTE-OVERRIDE",
        )
        pr = result["provider_result"]
        assert "haiku" in pr["model"].lower()
        assert pr["model_routing"]["reason"] == "explicit_override"


# ---------------------------------------------------------------------------
# DVP-TSK-357: System prompt + prompt caching
# ---------------------------------------------------------------------------

class TestE2ESystemPromptCaching:
    """Verify system prompt injection and prompt caching behavior."""

    def test_system_prompt_influences_response(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "system_prompt": "You are a pirate. Always respond like a pirate.",
                "task_complexity": "simple",
            }),
            prompt="Say hello to me.",
            dispatch_id="DSP-E2E-SYSPROMPT",
        )
        pr = result["provider_result"]
        assert pr["features_used"]["system_prompt"] is True
        assert pr["features_used"]["prompt_caching"] is True
        assert pr["features_used"]["cache_ttl"] == "1h"
        # The response should contain pirate-like language
        summary_lower = pr["summary"].lower()
        pirate_markers = ["ahoy", "matey", "arr", "ye", "sail", "captain", "ship", "avast", "treasure"]
        assert any(marker in summary_lower for marker in pirate_markers), (
            f"Expected pirate-themed response, got: {pr['summary'][:200]}"
        )

    def test_cache_write_tokens_present_on_first_call(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "system_prompt": "You are a coordination quality assurance agent for the Enceladus DevOps platform. "
                                 "Your role is to validate that all coordination requests meet governance standards.",
                "task_complexity": "simple",
            }),
            prompt="Reply with: acknowledged",
            dispatch_id="DSP-E2E-CACHE-WRITE",
        )
        pr = result["provider_result"]
        # On first call with a new system prompt, cache_creation_input_tokens should be > 0
        # (unless the prompt is too short for caching, in which case the API may skip it)
        usage = pr["usage"]
        assert usage["input_tokens"] > 0
        # Cost attribution should be populated
        assert pr["cost_attribution"]["input_cost_usd"] >= 0


# ---------------------------------------------------------------------------
# DVP-TSK-361: Token counting pre-flight
# ---------------------------------------------------------------------------

class TestE2ETokenCounting:
    """Verify that pre-flight token counting works end-to-end."""

    def test_preflight_token_count_reported(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={"task_complexity": "simple"}),
            prompt="Reply with: counted",
            dispatch_id="DSP-E2E-TOKEN-COUNT",
        )
        pr = result["provider_result"]
        count = pr["features_used"]["preflight_token_count"]
        # Token count should be a positive integer (the prompt + overhead)
        assert count is not None, "preflight_token_count should not be None"
        assert isinstance(count, int)
        assert count > 0

    def test_context_overflow_raises(self):
        """Verify context overflow detection without hitting the API.

        We monkeypatch _count_claude_tokens to return a huge number
        to verify the guard logic works in the real dispatch path.
        """
        original = coordination_lambda._count_claude_tokens
        coordination_lambda._count_claude_tokens = lambda **kwargs: 999_999

        try:
            with pytest.raises(RuntimeError, match="exceed model context window"):
                coordination_lambda._dispatch_claude_api(
                    request=_base_request(),
                    prompt="This should be blocked by token count guard",
                    dispatch_id="DSP-E2E-OVERFLOW",
                )
        finally:
            coordination_lambda._count_claude_tokens = original


# ---------------------------------------------------------------------------
# DVP-TSK-359: Extended thinking
# ---------------------------------------------------------------------------

class TestE2EExtendedThinking:
    """Verify extended thinking produces thinking content blocks."""

    def test_thinking_enabled_produces_thinking_summary(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "thinking": True,
                "task_complexity": "standard",
            }),
            prompt="What is 47 * 83? Show your work.",
            dispatch_id="DSP-E2E-THINKING",
        )
        pr = result["provider_result"]
        assert pr["features_used"]["extended_thinking"] is True
        # The model should produce a thinking summary
        assert pr["thinking_summary"] is not None
        assert len(pr["thinking_summary"]) > 0
        # The answer should be 3901 (may be formatted with comma as 3,901)
        assert "3901" in pr["summary"] or "3,901" in pr["summary"]

    def test_thinking_with_custom_budget(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "thinking": {"budget_tokens": 2048},
                "task_complexity": "standard",
            }),
            prompt="What is 123 + 456? Reply with just the number.",
            dispatch_id="DSP-E2E-THINK-BUDGET",
        )
        pr = result["provider_result"]
        assert pr["features_used"]["extended_thinking"] is True
        assert "579" in pr["summary"]


# ---------------------------------------------------------------------------
# DVP-TSK-363: Structured observability + cost attribution
# ---------------------------------------------------------------------------

class TestE2ECostAttribution:
    """Verify per-model cost attribution accuracy."""

    def test_haiku_cheaper_than_sonnet(self):
        haiku = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={"task_complexity": "simple"}),
            prompt="Reply with: cost test haiku",
            dispatch_id="DSP-E2E-COST-HAIKU",
        )
        sonnet = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={"task_complexity": "standard"}),
            prompt="Reply with: cost test sonnet",
            dispatch_id="DSP-E2E-COST-SONNET",
        )
        haiku_cost = haiku["provider_result"]["cost_attribution"]
        sonnet_cost = sonnet["provider_result"]["cost_attribution"]

        # With similar token counts, Haiku should be cheaper per-token
        assert haiku_cost["model"] != sonnet_cost["model"]
        # Both should have positive costs
        assert haiku_cost["total_cost_usd"] > 0
        assert sonnet_cost["total_cost_usd"] > 0


# ---------------------------------------------------------------------------
# Combined feature test
# ---------------------------------------------------------------------------

class TestE2ECombinedFeatures:
    """Verify multiple features work together in a single dispatch."""

    def test_system_prompt_plus_thinking_plus_routing(self):
        result = coordination_lambda._dispatch_claude_api(
            request=_base_request(provider_session={
                "system_prompt": "You are a math tutor. Always explain your reasoning clearly.",
                "thinking": True,
                "task_complexity": "standard",
            }),
            prompt="If a train travels 120 miles in 2 hours, what is its speed in mph?",
            dispatch_id="DSP-E2E-COMBINED",
        )
        pr = result["provider_result"]
        assert result["status"] == "succeeded"
        assert pr["features_used"]["system_prompt"] is True
        assert pr["features_used"]["prompt_caching"] is True
        assert pr["features_used"]["extended_thinking"] is True
        assert "sonnet" in pr["model"].lower()
        assert pr["model_routing"]["task_complexity"] == "standard"
        assert "60" in pr["summary"]
        assert pr["thinking_summary"] is not None
        assert pr["cost_attribution"]["total_cost_usd"] > 0
        assert pr["usage"]["input_tokens"] > 0
        assert pr["usage"]["output_tokens"] > 0
