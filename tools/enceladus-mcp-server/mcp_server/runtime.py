"""Runtime bindings for decomposed code-mode meta-tool handlers."""
from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Dict, List, Optional

InvokeRawTool = Callable[..., Awaitable[Dict[str, Any]]]
RawToolAllowed = Callable[[str], bool]
ResultText = Callable[[Any], list]
ParseRecordId = Callable[[str], tuple]
InvokeHybridRetrieval = Callable[..., Dict[str, Any]]
ErrorPayload = Callable[..., Dict[str, Any]]
ActionCatalog = Callable[[], List[Dict[str, Any]]]


class McpRuntime:
    interface_mode: str = "raw"
    invoke_raw_tool: Optional[InvokeRawTool] = None
    raw_tool_allowed: Optional[RawToolAllowed] = None
    result_text: Optional[ResultText] = None
    parse_record_id: Optional[ParseRecordId] = None
    invoke_hybrid_retrieval: Optional[InvokeHybridRetrieval] = None
    error_payload: Optional[ErrorPayload] = None
    enable_context_nodes: bool = False
    # DVP-TSK-843: returns the unwrapped per-action contracts for search(actions.schemas).
    action_catalog: Optional[ActionCatalog] = None


# ENC-TSK-S26-0A: 1-based execute step index for the step currently invoking a raw tool
# (None outside execute). Read by server._invoke_raw_tool for the [WRITE-AUDIT] line.
EXECUTE_STEP_INDEX: ContextVar[Optional[int]] = ContextVar("enc_execute_step_index", default=None)

RUNTIME = McpRuntime()


def bind_runtime(**kwargs: Any) -> None:
    for key, value in kwargs.items():
        setattr(RUNTIME, key, value)
