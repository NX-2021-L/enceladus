"""OpenAI Codex provider adapter (delegates to coordination dispatch)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import DispatchFn, ProviderAdapter


class CodexProviderAdapter:
    provider_id = "openai_codex"

    def __init__(self, dispatch_fn: DispatchFn) -> None:
        self._dispatch_fn = dispatch_fn

    def dispatch(
        self,
        request: Dict[str, Any],
        prompt: Optional[str],
        dispatch_id: str,
        *,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        mode = execution_mode or "codex_app_server"
        return self._dispatch_fn(
            request,
            prompt,
            dispatch_id,
            execution_mode=mode,
        )


def build_codex_adapter(dispatch_fn: DispatchFn) -> CodexProviderAdapter:
    return CodexProviderAdapter(dispatch_fn)
