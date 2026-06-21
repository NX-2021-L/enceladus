"""ENC-TSK-G12 — canonical Enceladus handoff mandate payload schema (API layer).

Source of truth: DOC-B8641F56EED3 Section VIII ("structured handoffs of goal,
constraints, prior findings, tools allowed, output schema, and budget_tokens under
2-3k tokens are the right shape") and Section IX (structured outputs: output_config
+ strict:true compile a JSON Schema into a grammar for constrained decoding, which
eliminates the JSON parse-and-retry cycles that burn 10-30% of output tokens).

This module defines ONE canonical schema and the total (lossless) projections onto
both handoff surfaces:

  * F2 — the governed docstore *handoff document* (document_subtype=handoff), whose
    required envelope fields are source_record_id, handoff_status, action_checklist,
    verification_criteria, with the mandate body carried inline.
  * F3 — the *dispatch prompt block* the orchestrator emits to a subagent.

Stdlib only (the coordination_api Lambda runtime has no pydantic): a dataclass plus a
hand-authored strict JSON Schema. The schema is wired onto the dispatch-generator tool
definition via mandate_tool_definition(strict=True) / mandate_output_format(strict=True).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

# The six canonical mandate fields (DOC-B8641F56EED3 Section VIII). Order is stable.
MANDATE_FIELDS: List[str] = [
    "goal",
    "constraints",
    "prior_findings",
    "tools_allowed",
    "output_schema",
    "budget_tokens",
]

# Default name used for both the strict function tool and the output_config format.
MANDATE_TOOL_NAME = "enceladus_handoff_mandate"

# Soft ceiling per DOC-B8641F56EED3 Section VIII ("under 2-3k tokens").
MANDATE_TOKEN_CEILING = 3000


@dataclass
class HandoffMandate:
    """Canonical typed mandate an orchestrator emits to a subagent.

    Fields mirror DOC-B8641F56EED3 Section VIII exactly. `output_schema` is the JSON
    Schema the *subagent* must conform to (opaque payload, not constrained here).
    """

    goal: str
    constraints: List[str] = field(default_factory=list)
    prior_findings: List[str] = field(default_factory=list)
    tools_allowed: List[str] = field(default_factory=list)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    budget_tokens: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "constraints": list(self.constraints),
            "prior_findings": list(self.prior_findings),
            "tools_allowed": list(self.tools_allowed),
            "output_schema": dict(self.output_schema),
            "budget_tokens": int(self.budget_tokens),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HandoffMandate":
        missing = [f for f in MANDATE_FIELDS if f not in data]
        if missing:
            raise ValueError(f"HandoffMandate missing required fields: {missing}")
        return cls(
            goal=str(data["goal"]),
            constraints=list(data.get("constraints") or []),
            prior_findings=list(data.get("prior_findings") or []),
            tools_allowed=list(data.get("tools_allowed") or []),
            output_schema=dict(data.get("output_schema") or {}),
            budget_tokens=int(data.get("budget_tokens") or 0),
        )

    # -- size guard (AC-3: serializes under 2-3k tokens) ------------------------
    def serialized_bytes(self) -> int:
        return len(json.dumps(self.to_dict(), separators=(",", ":")))

    def estimated_tokens(self) -> int:
        # ~4 chars/token is the standard rough estimate for English+JSON.
        return (self.serialized_bytes() + 3) // 4

    # -- F3: dispatch prompt block (total, lossless over the 6 mandate fields) --
    def to_dispatch_prompt_block(self) -> Dict[str, Any]:
        """Project the mandate onto the dispatch prompt block structure (F3).

        Every mandate field maps to exactly one prompt-block field; no field is
        dropped (asserted by test_handoff_mandate.test_f3_coverage_lossless).
        """
        return {
            "objective": self.goal,
            "constraints": list(self.constraints),
            "prior_findings": list(self.prior_findings),
            "tools_allowed": list(self.tools_allowed),
            "output_schema": dict(self.output_schema),
            "budget_tokens": int(self.budget_tokens),
        }

    # -- F2: docstore handoff document fields ----------------------------------
    def to_handoff_document_fields(
        self,
        source_record_id: str,
        handoff_status: str = "pending",
        action_checklist: List[str] | None = None,
        verification_criteria: str | None = None,
    ) -> Dict[str, Any]:
        """Project the mandate onto docstore handoff-document fields (F2).

        Envelope fields (source_record_id, handoff_status) are supplied at mint time.
        When not supplied explicitly, action_checklist is derived from goal+constraints
        and verification_criteria from output_schema, so the mandate alone fully
        determines the handoff body (no lossy mapping of the canonical schema).
        """
        derived_checklist = action_checklist
        if derived_checklist is None:
            derived_checklist = [self.goal] + [f"Honor constraint: {c}" for c in self.constraints]
        derived_verification = verification_criteria
        if derived_verification is None:
            derived_verification = (
                "Subagent output conforms to output_schema: "
                + json.dumps(self.output_schema, separators=(",", ":"))
            )
        return {
            "source_record_id": source_record_id,
            "handoff_status": handoff_status,
            "action_checklist": list(derived_checklist),
            "verification_criteria": derived_verification,
            # mandate body carried inline so no canonical field is lost
            "mandate": self.to_dict(),
        }


# Field names of each projected surface (used by coverage tests).
F3_PROMPT_BLOCK_FIELDS: List[str] = [
    "objective", "constraints", "prior_findings", "tools_allowed", "output_schema", "budget_tokens",
]
F2_HANDOFF_ENVELOPE_FIELDS: List[str] = [
    "source_record_id", "handoff_status", "action_checklist", "verification_criteria",
]


# --- Strict JSON Schema (constrained-decoding grammar source) ------------------
def mandate_json_schema(strict: bool = True) -> Dict[str, Any]:
    """The canonical mandate JSON Schema.

    Under strict mode every property is required and additionalProperties is false,
    which is what Anthropic/OpenAI structured outputs compile into a decode-time
    grammar (DOC-B8641F56EED3 Section IX).
    """
    schema: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": "The single objective the subagent must accomplish.",
            },
            "constraints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Task boundaries and rules the subagent must respect.",
            },
            "prior_findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Context already established that the subagent should not rediscover.",
            },
            "tools_allowed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Allowlisted tool identifiers the subagent may call.",
            },
            "output_schema": {
                "type": "object",
                "description": "JSON Schema the subagent's final result must conform to.",
            },
            "budget_tokens": {
                "type": "integer",
                "minimum": 1,
                "description": "Output token budget for the subagent loop.",
            },
        },
        "required": list(MANDATE_FIELDS),
    }
    if strict:
        schema["additionalProperties"] = False
    return schema


def mandate_tool_definition(strict: bool = True, name: str = MANDATE_TOOL_NAME) -> Dict[str, Any]:
    """Dispatch-generator subagent-invocation tool definition (Responses-API shape).

    Matches the function-tool shape consumed by coordination_api `_coerce_openai_tools`
    ({type, name, parameters, strict}). strict=True enforces the canonical schema via
    constrained decoding, eliminating JSON parse-and-retry cycles (G12 AC-4).
    """
    return {
        "type": "function",
        "name": name,
        "description": "Emit the typed handoff mandate for one subagent dispatch.",
        "parameters": mandate_json_schema(strict=strict),
        "strict": bool(strict),
    }


def mandate_output_format(strict: bool = True, name: str = MANDATE_TOOL_NAME) -> Dict[str, Any]:
    """output_config.format / text.format json_schema block for the mandate (G12 AC-4)."""
    return {
        "type": "json_schema",
        "name": name,
        "schema": mandate_json_schema(strict=strict),
        "strict": bool(strict),
    }
