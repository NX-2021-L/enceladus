"""Claude Agent SDK provider adapter (delegates to coordination dispatch)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import CallableProviderAdapter, DispatchFn


class ClaudeProviderAdapter(CallableProviderAdapter):
    provider_id = "claude_agent_sdk"

    def __init__(self, dispatch_fn: DispatchFn) -> None:
        super().__init__("claude_agent_sdk", dispatch_fn)


def build_claude_adapter(dispatch_fn: DispatchFn) -> ClaudeProviderAdapter:
    return ClaudeProviderAdapter(dispatch_fn)
