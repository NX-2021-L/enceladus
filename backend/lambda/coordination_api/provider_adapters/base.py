"""Provider adapter interface for coordination API dispatch (ENC-TSK-L11 / B64 Ph3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Protocol, runtime_checkable


DispatchFn = Callable[..., Dict[str, Any]]


@runtime_checkable
class ProviderAdapter(Protocol):
    """Outbound dispatch contract for a managed agent provider surface."""

    provider_id: str

    def dispatch(
        self,
        request: Dict[str, Any],
        prompt: Optional[str],
        dispatch_id: str,
        *,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute provider-specific dispatch and return dispatch metadata."""


class CallableProviderAdapter:
    """Thin adapter wrapper around an existing dispatch callable."""

    __slots__ = ("provider_id", "_dispatch_fn")

    def __init__(self, provider_id: str, dispatch_fn: DispatchFn) -> None:
        self.provider_id = provider_id
        self._dispatch_fn = dispatch_fn

    def dispatch(
        self,
        request: Dict[str, Any],
        prompt: Optional[str],
        dispatch_id: str,
        *,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._dispatch_fn(request, prompt, dispatch_id)


class UnimplementedProviderAdapter(ABC):
    """Seam for future providers; committed empty implementation for A2A."""

    provider_id: str

    @abstractmethod
    def dispatch(
        self,
        request: Dict[str, Any],
        prompt: Optional[str],
        dispatch_id: str,
        *,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError
