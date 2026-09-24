"""Provider adapter package for coordination API outbound dispatch."""

from .base import CallableProviderAdapter, ProviderAdapter, UnimplementedProviderAdapter
from .a2a import A2AProviderAdapter
from .registry import (
    dispatch_via_provider_adapter,
    get_adapter_for_execution_mode,
    get_provider_adapter,
    list_registered_provider_ids,
    register_callable_adapter,
    register_provider_adapter,
    reset_provider_adapters_for_tests,
    wire_default_provider_adapters,
)

__all__ = [
    "A2AProviderAdapter",
    "CallableProviderAdapter",
    "ProviderAdapter",
    "UnimplementedProviderAdapter",
    "dispatch_via_provider_adapter",
    "get_adapter_for_execution_mode",
    "get_provider_adapter",
    "list_registered_provider_ids",
    "register_callable_adapter",
    "register_provider_adapter",
    "reset_provider_adapters_for_tests",
    "wire_default_provider_adapters",
]
