"""A2A provider adapter seam (empty implementation, ENC-TSK-L11 AC-3)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import UnimplementedProviderAdapter


class A2AProviderAdapter(UnimplementedProviderAdapter):
    """Placeholder for Agent-to-Agent transport; intentionally unimplemented."""

    provider_id = "a2a"

    def dispatch(
        self,
        request: Dict[str, Any],
        prompt: Optional[str],
        dispatch_id: str,
        *,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        raise NotImplementedError(
            "A2A provider adapter seam is committed but not yet implemented"
        )
