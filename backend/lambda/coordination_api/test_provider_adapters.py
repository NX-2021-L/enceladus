"""Unit tests for provider adapter registry (ENC-TSK-L11)."""

from __future__ import annotations

import unittest

from provider_adapters import (
    A2AProviderAdapter,
    get_adapter_for_execution_mode,
    get_provider_adapter,
    list_registered_provider_ids,
    reset_provider_adapters_for_tests,
    wire_default_provider_adapters,
)


class ProviderAdapterRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_provider_adapters_for_tests()

    def tearDown(self) -> None:
        reset_provider_adapters_for_tests()

    def test_wire_registers_claude_codex_bedrock_and_a2a(self) -> None:
        wire_default_provider_adapters(
            claude_dispatch=lambda *_a, **_k: {"provider": "claude_agent_sdk"},
            codex_dispatch=lambda *_a, **_k: {"provider": "openai_codex"},
            bedrock_dispatch=lambda *_a, **_k: {"provider": "aws_bedrock_agent"},
        )
        self.assertEqual(
            sorted(list_registered_provider_ids()),
            ["a2a", "aws_bedrock_agent", "claude_agent_sdk", "openai_codex"],
        )

    def test_execution_mode_aliases_resolve(self) -> None:
        wire_default_provider_adapters(
            claude_dispatch=lambda *_a, **_k: {},
            codex_dispatch=lambda *_a, **_k: {},
            bedrock_dispatch=lambda *_a, **_k: {},
        )
        self.assertEqual(
            get_adapter_for_execution_mode("codex_full_auto").provider_id,
            "openai_codex",
        )
        self.assertEqual(
            get_adapter_for_execution_mode("bedrock_agent").provider_id,
            "aws_bedrock_agent",
        )

    def test_claude_adapter_delegates(self) -> None:
        seen = {}

        def _dispatch(request, prompt, dispatch_id):
            seen.update(
                {
                    "request": request,
                    "prompt": prompt,
                    "dispatch_id": dispatch_id,
                }
            )
            return {"provider": "claude_agent_sdk", "dispatch_id": dispatch_id}

        wire_default_provider_adapters(
            claude_dispatch=_dispatch,
            codex_dispatch=lambda *_a, **_k: {},
            bedrock_dispatch=lambda *_a, **_k: {},
        )
        adapter = get_provider_adapter("claude_agent_sdk")
        result = adapter.dispatch({"request_id": "req-1"}, "hello", "disp-1")
        self.assertEqual(result["provider"], "claude_agent_sdk")
        self.assertEqual(seen["prompt"], "hello")

    def test_codex_adapter_passes_execution_mode(self) -> None:
        seen = {}

        def _dispatch(request, prompt, dispatch_id, execution_mode=None):
            seen["execution_mode"] = execution_mode
            return {"provider": "openai_codex"}

        wire_default_provider_adapters(
            claude_dispatch=lambda *_a, **_k: {},
            codex_dispatch=_dispatch,
            bedrock_dispatch=lambda *_a, **_k: {},
        )
        adapter = get_adapter_for_execution_mode("codex_full_auto")
        adapter.dispatch({}, None, "disp-2", execution_mode="codex_full_auto")
        self.assertEqual(seen["execution_mode"], "codex_full_auto")

    def test_a2a_adapter_is_empty_implementation(self) -> None:
        adapter = A2AProviderAdapter()
        with self.assertRaises(NotImplementedError):
            adapter.dispatch({}, None, "disp-a2a")


if __name__ == "__main__":
    unittest.main()
