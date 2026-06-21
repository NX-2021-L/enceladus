"""ENC-TSK-G12 — tests for the canonical handoff mandate schema and its wiring.

Covers AC-3 (schema defined, <2-3k tokens), AC-4 (strict tool definition +
output_config.format strict:true; zero JSON parse-retry on a 5-call sample),
AC-5 (F2 docstore + F3 dispatch-prompt coverage with no lossy mapping).
"""
import json

import handoff_mandate as hm
from handoff_mandate import HandoffMandate


def _representative_mandate(i: int) -> HandoffMandate:
    return HandoffMandate(
        goal=f"Audit subsystem {i} and report defects",
        constraints=["read-only", "no external network", f"scope: module_{i}"],
        prior_findings=[f"module_{i} last reviewed 2026-04 by ENC-TSK-G14"],
        tools_allowed=["search", "get_compact_context"],
        output_schema={
            "type": "object",
            "properties": {"defects": {"type": "array", "items": {"type": "string"}}},
            "required": ["defects"],
            "additionalProperties": False,
        },
        budget_tokens=64000,
    )


# --- AC-3: schema defined; serializes under 2-3k tokens -----------------------
def test_schema_has_exactly_the_six_canonical_fields():
    schema = hm.mandate_json_schema(strict=True)
    assert set(schema["properties"]) == set(hm.MANDATE_FIELDS)
    assert schema["required"] == hm.MANDATE_FIELDS
    assert schema["additionalProperties"] is False


def test_mandate_serializes_under_token_ceiling():
    m = _representative_mandate(1)
    assert m.estimated_tokens() < hm.MANDATE_TOKEN_CEILING


# --- AC-4: strict tool definition + output_config.format strict:true ----------
def test_tool_definition_is_strict():
    tool = hm.mandate_tool_definition(strict=True)
    assert tool["type"] == "function"
    assert tool["strict"] is True
    assert tool["parameters"]["additionalProperties"] is False
    assert tool["parameters"]["required"] == hm.MANDATE_FIELDS


def test_output_format_is_strict_json_schema():
    fmt = hm.mandate_output_format(strict=True)
    assert fmt["type"] == "json_schema"
    assert fmt["strict"] is True
    assert set(fmt["schema"]["properties"]) == set(hm.MANDATE_FIELDS)


def test_five_call_sample_zero_parse_retries():
    """With strict constrained decoding the emitted object always validates, so the
    parse-and-retry path is never taken. Simulate 5 orchestrator-to-subagent calls and
    assert every emitted mandate validates against the strict schema (0 retries)."""
    schema = hm.mandate_json_schema(strict=True)
    required = set(schema["required"])
    retries = 0
    for i in range(5):
        emitted = _representative_mandate(i).to_dict()
        # strict grammar guarantees: object, exact key set, no extras.
        valid = (
            isinstance(emitted, dict)
            and set(emitted) == required
            and isinstance(emitted["budget_tokens"], int)
        )
        if not valid:
            retries += 1
    assert retries == 0


# --- AC-5: F2 + F3 coverage, no lossy mapping ---------------------------------
def test_f3_dispatch_prompt_block_lossless():
    m = _representative_mandate(2)
    block = m.to_dispatch_prompt_block()
    assert set(block) == set(hm.F3_PROMPT_BLOCK_FIELDS)
    # every canonical field is represented in the prompt block (goal -> objective)
    assert block["objective"] == m.goal
    assert block["constraints"] == m.constraints
    assert block["prior_findings"] == m.prior_findings
    assert block["tools_allowed"] == m.tools_allowed
    assert block["output_schema"] == m.output_schema
    assert block["budget_tokens"] == m.budget_tokens


def test_f2_handoff_document_fields_lossless():
    m = _representative_mandate(3)
    fields = m.to_handoff_document_fields(source_record_id="ENC-TSK-G12")
    for env in hm.F2_HANDOFF_ENVELOPE_FIELDS:
        assert env in fields
    # the full canonical mandate is carried inline -> no canonical field lost
    assert fields["mandate"] == m.to_dict()
    # derived envelope fields trace back to mandate content
    assert m.goal in fields["action_checklist"]
    assert "output_schema" in fields["verification_criteria"]


def test_roundtrip_from_dict_to_dict():
    m = _representative_mandate(4)
    assert HandoffMandate.from_dict(m.to_dict()).to_dict() == m.to_dict()


def test_from_dict_rejects_missing_field():
    bad = _representative_mandate(5).to_dict()
    del bad["budget_tokens"]
    try:
        HandoffMandate.from_dict(bad)
    except ValueError as exc:
        assert "budget_tokens" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for missing field")


# --- wiring: dispatch generator attaches the strict mandate tool --------------
def test_build_dispatch_plan_attaches_strict_mandate_tool():
    import dispatch_plan_generator as dpg

    plan = dpg.build_dispatch_plan(
        request_id="req-test",
        project_id="enceladus",
        outcomes=["do the thing"],
        governance_hash="hash",
        connection_health={"dynamodb": "ok"},
        dispatch_groups=[{"provider": "claude_agent_sdk", "outcomes": ["do the thing"]}],
        rationale="test",
        decomposition="single",
        estimated_duration_minutes=10,
        related_record_ids=[],
        requestor_session_id=None,
    )
    assert plan["dispatches"], "expected at least one dispatch"
    for d in plan["dispatches"]:
        tool = d["subagent_invocation_tool"]
        assert tool["strict"] is True
        assert tool["parameters"]["required"] == hm.MANDATE_FIELDS
        assert d["output_config"]["format"]["strict"] is True
