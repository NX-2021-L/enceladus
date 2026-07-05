"""AWS Bedrock Agent provider adapter (delegates to coordination dispatch)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import CallableProviderAdapter, DispatchFn


class BedrockProviderAdapter(CallableProviderAdapter):
    provider_id = "aws_bedrock_agent"

    def __init__(self, dispatch_fn: DispatchFn) -> None:
        super().__init__("aws_bedrock_agent", dispatch_fn)


def build_bedrock_adapter(dispatch_fn: DispatchFn) -> BedrockProviderAdapter:
    return BedrockProviderAdapter(dispatch_fn)
