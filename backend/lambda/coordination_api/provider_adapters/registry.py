"""Registry and routing for coordination API provider adapters (ENC-TSK-L11)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .a2a import A2AProviderAdapter
from .base import CallableProviderAdapter, DispatchFn, ProviderAdapter
from .bedrock import build_bedrock_adapter
from .claude import build_claude_adapter
from .codex import build_codex_adapter

_EXECUTION_MODE_ALIASES: Dict[str, str] = {
    "claude_agent_sdk": "claude_agent_sdk",
    "codex_app_server": "openai_codex",
    "codex_full_auto": "openai_codex",
    "bedrock_agent": "aws_bedrock_agent",
    "a2a": "a2a",
}

_ADAPTERS: Dict[str, ProviderAdapter] = {}
_A2A_ADAPTER = A2AProviderAdapter()
_WIRED = False


def register_provider_adapter(provider_id: str, adapter: ProviderAdapter) -> None:
    _ADAPTERS[str(provider_id).strip()] = adapter


def register_callable_adapter(provider_id: str, dispatch_fn: DispatchFn) -> None:
    register_provider_adapter(provider_id, CallableProviderAdapter(provider_id, dispatch_fn))


def get_provider_adapter(provider_id: str) -> Optional[ProviderAdapter]:
    return _ADAPTERS.get(str(provider_id or "").strip())


def get_adapter_for_execution_mode(execution_mode: str) -> Optional[ProviderAdapter]:
    provider_id = _EXECUTION_MODE_ALIASES.get(str(execution_mode or "").strip())
    if not provider_id:
        return None
    return get_provider_adapter(provider_id)


def list_registered_provider_ids() -> List[str]:
    return sorted(_ADAPTERS.keys())


def dispatch_via_provider_adapter(
    execution_mode: str,
    request: Dict[str, Any],
    prompt: Optional[str],
    dispatch_id: str,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    adapter = get_adapter_for_execution_mode(execution_mode)
    if adapter is None:
        return None
    return adapter.dispatch(
        request,
        prompt,
        dispatch_id,
        execution_mode=execution_mode,
        **kwargs,
    )


def wire_default_provider_adapters(
    *,
    claude_dispatch: DispatchFn,
    codex_dispatch: DispatchFn,
    bedrock_dispatch: DispatchFn,
) -> None:
    """Bind live dispatch callables once lambda_function defines them."""
    global _WIRED
    if _WIRED:
        return
    register_provider_adapter("claude_agent_sdk", build_claude_adapter(claude_dispatch))
    register_provider_adapter("openai_codex", build_codex_adapter(codex_dispatch))
    register_provider_adapter("aws_bedrock_agent", build_bedrock_adapter(bedrock_dispatch))
    register_provider_adapter("a2a", _A2A_ADAPTER)
    _WIRED = True


def reset_provider_adapters_for_tests() -> None:
    global _WIRED
    _ADAPTERS.clear()
    _WIRED = False
