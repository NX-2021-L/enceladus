"""DVP-TSK-892 (DVP-PLN-010 E2-W1.7, C-5): execute adopts ResolvedCall v1, RFC 9457
problem details with errors[].pointer, and Idempotency-Key replay.

The ResolvedCall v1 JSON Schema below is transcribed from DOC-3724FD572867 s1.3
(Contract B).  The kit-published schema (DVP-TSK-891 / E2-W1.2) was not available when
this was written; AC1 requires re-pointing ``RESOLVED_CALL_V1_SCHEMA`` at the kit schema
once that task merges (additionalProperties is false so drift in either direction fails).
"""
import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

import jsonschema

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")

_ANNOTATIONS = {
    "type": "object",
    "required": ["readOnlyHint", "destructiveHint", "idempotentHint"],
    "properties": {k: {"type": "boolean"} for k in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")},
}
RESOLVED_CALL_V1_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["v", "surface", "action", "arguments", "schemaHash", "underlying", "sideEffects",
                 "placeholders", "annotations", "idempotencyKey", "source"],
    "properties": {
        "v": {"const": 1},
        "surface": {"type": "string", "minLength": 1},
        "action": {"type": "string", "minLength": 1},
        "arguments": {},
        "schemaHash": {"type": "string", "minLength": 1},
        "governanceHash": {"type": "string"},
        "principal": {"type": "string"},
        "underlying": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["handler", "method", "path"],
                "additionalProperties": False,
                "properties": {"handler": {"type": "string"}, "method": {"type": "string"},
                               "path": {"type": "string"}, "body": {}},
            },
        },
        "sideEffects": {
            "type": "object",
            "required": ["writeCount", "kinds"],
            "additionalProperties": False,
            "properties": {"writeCount": {"type": "integer", "minimum": 0},
                           "kinds": {"type": "array", "items": {"type": "string"}}},
        },
        "sentence": {"type": "string"},
        "diff": {"type": "array", "items": {"type": "object", "required": ["pointer", "before", "after"]}},
        "placeholders": {
            "type": "array",
            "items": {"type": "object", "required": ["pointer", "label"], "additionalProperties": False,
                      "properties": {"pointer": {"type": "string"}, "label": {"type": "string"}}},
        },
        "annotations": _ANNOTATIONS,
        "idempotencyKey": {"type": "string", "minLength": 1},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "source": {"enum": ["server-dry-run", "client-preview"]},
    },
}
PROBLEM_SCHEMA = {
    "type": "object",
    "required": ["type", "title", "status"],
    "properties": {
        "type": {"type": "string"}, "title": {"type": "string"}, "status": {"type": "integer"},
        "detail": {"type": "string"},
        "errors": {"type": "array", "items": {"type": "object", "required": ["pointer", "detail"],
                                              "properties": {"pointer": {"type": "string"}, "detail": {"type": "string"},
                                                             "code": {"type": "string"}}}},
    },
}
GOV = "a" * 64


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server():
    name = f"enceladus_server_execute_rc_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "ENCELADUS_MCP_INTERFACE_MODE": "code"}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _call(server, arguments):
    allowed = "tracker_create,tracker_set,documents_patch,tracker_log"
    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": allowed}, clear=False):
        return json.loads(_run(server.call_tool("execute", arguments))[0].text)


def _sample_steps():
    return [
        {"action": "tracker.create", "arguments": {
            "project_id": "devops", "record_type": "task", "title": "sample", "governance_hash": GOV}},
        {"action": "tracker.set", "arguments": {
            "record_id": "DVP-TSK-1", "field": "priority", "value": "P1", "governance_hash": GOV}},
        {"action": "tracker.log", "arguments": {
            "record_id": "DVP-TSK-1", "description": "note", "governance_hash": GOV}},
    ]


def test_dry_run_returns_resolved_call_v1_per_step_for_governed_multistep_sample():
    server = _load_server()
    payload = _call(server, {"dry_run": True, "steps": _sample_steps(), "idempotency_key": "k-1"})
    assert payload["success"] is True and payload["dry_run"] is True
    validator = jsonschema.Draft202012Validator(RESOLVED_CALL_V1_SCHEMA)
    calls = []
    for step in payload["step_results"]:
        assert step["status"] == "dry_run"
        rc = step["resolved_call"]
        validator.validate(rc)
        calls.append(rc)
        assert rc["source"] == "server-dry-run" and rc["surface"] == "enceladus"
        assert rc["governanceHash"] == GOV
        assert rc["idempotencyKey"] == "k-1"
        # additive: the legacy summary is unchanged
        assert step["resolved_calls"][0]["tool"] == rc["underlying"][0]["handler"]
    create, set_, log = calls
    assert create["placeholders"] == [{"pointer": "/record_id", "label": "<new record_id>"}]
    assert set_["placeholders"] == [] and log["placeholders"] == []
    assert create["sideEffects"]["writeCount"] == 1
    assert set_["annotations"]["destructiveHint"] is True
    assert len({create["schemaHash"], set_["schemaHash"]}) == 2


def test_read_only_action_has_zero_write_count_and_derived_key_warns():
    server = _load_server()
    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "check_document_policy", "ENCELADUS_MCP_PRINCIPAL": "agent-x"}):
        payload = json.loads(_run(server.call_tool(
            "execute", {"dry_run": True, "steps": [{"action": "documents.check_policy", "arguments": {"operation": "put", "storage_target": "docstore"}}]},
        ))[0].text)
    rc = payload["step_results"][0]["resolved_call"]
    jsonschema.Draft202012Validator(RESOLVED_CALL_V1_SCHEMA).validate(rc)
    assert rc["sideEffects"] == {"writeCount": 0, "kinds": []}
    assert rc["principal"] == "agent-x"
    assert rc["idempotencyKey"].startswith("dry-") and rc["warnings"]
    assert "governanceHash" not in rc


def test_dry_run_performs_zero_writes():
    server = _load_server()
    calls = {"n": 0}

    async def _handler(_args):
        calls["n"] += 1
        return server._result_text({"success": True})

    for tool in ("tracker_create", "tracker_set", "tracker_log"):
        server._TOOL_HANDLERS[tool] = _handler
    _call(server, {"dry_run": True, "steps": _sample_steps()})
    assert calls["n"] == 0


def test_validation_failure_is_rfc9457_with_pointer_per_offending_field():
    server = _load_server()
    steps = [{"action": "tracker.create", "arguments": {"project_id": 7, "governance_hash": GOV}}]
    payload = _call(server, {"dry_run": True, "steps": steps})
    assert payload["success"] is False
    problem = payload["problem"]
    jsonschema.Draft202012Validator(PROBLEM_SCHEMA).validate(problem)
    assert problem["status"] == 422
    pointers = {e["pointer"] for e in problem["errors"]}
    assert {"/project_id", "/record_type", "/title"} <= pointers
    assert all(e["step"] == 1 for e in problem["errors"])
    step_problem = payload["step_results"][0]["problem"]
    assert {e["pointer"] for e in step_problem["errors"]} == pointers
    assert payload["step_results"][0]["status"] == "invalid"


def test_missing_governance_hash_and_unknown_action_carry_problem_pointers():
    server = _load_server()
    payload = _call(server, {"steps": [
        {"action": "tracker.set", "arguments": {"record_id": "X", "field": "f", "value": "v"}, "on_error": "continue"},
        {"action": "nope.nothing"},
    ]})
    assert payload["success"] is False
    pointers = {(e["step"], e["pointer"]) for e in payload["problem"]["errors"]}
    assert pointers == {(1, "/governance_hash"), (2, "/action")}
    # legacy fields intact
    assert payload["error"]["code"] == "step_failed"
    assert payload["step_results"][0]["status"] == "blocked"


def test_empty_steps_returns_problem_pointing_at_steps():
    server = _load_server()
    payload = _call(server, {"steps": []})
    assert payload["success"] is False and payload["error"]["code"] == "invalid_input"
    assert payload["problem"]["errors"][0]["pointer"] == "/steps"


def test_schema_hash_echo_matches_and_mismatch_is_409():
    server = _load_server()
    steps = _sample_steps()[1:2]
    ok = _call(server, {"dry_run": True, "steps": steps})
    live = ok["step_results"][0]["resolved_call"]["schemaHash"]
    echoed = _call(server, {"dry_run": True, "steps": steps, "schema_hash": live})
    assert echoed["success"] is True
    bad = _call(server, {"dry_run": True, "steps": steps, "schema_hash": "0" * 64})
    assert bad["success"] is False and bad["problem"]["status"] == 409


def test_idempotency_key_replay_returns_stored_receipt_without_double_apply():
    server = _load_server()
    calls = {"n": 0}

    async def _tracker_set(_args):
        calls["n"] += 1
        return server._result_text({"success": True, "n": calls["n"]})

    server._TOOL_HANDLERS["tracker_set"] = _tracker_set
    request = {"steps": _sample_steps()[1:2], "idempotency_key": "idem-1"}
    first = _call(server, request)
    second = _call(server, request)
    assert first["success"] is True and calls["n"] == 1
    assert second["idempotent_replay"] is True
    assert second["step_results"] == first["step_results"]
    assert second["idempotency_key"] == "idem-1"
    # no key -> always executes
    _call(server, {"steps": request["steps"]})
    assert calls["n"] == 2


def test_idempotency_key_reuse_with_different_request_is_rejected():
    server = _load_server()

    async def _tracker_set(_args):
        return server._result_text({"success": True})

    server._TOOL_HANDLERS["tracker_set"] = _tracker_set
    steps = _sample_steps()[1:2]
    _call(server, {"steps": steps, "idempotency_key": "idem-2"})
    other = [{"action": "tracker.set", "arguments": {**steps[0]["arguments"], "value": "P2"}}]
    reused = _call(server, {"steps": other, "idempotency_key": "idem-2"})
    assert reused["success"] is False
    assert reused["problem"]["status"] == 422
    assert reused["problem"]["errors"][0]["pointer"] == "/idempotency_key"


def test_failed_execution_is_not_stored_and_stays_retryable():
    server = _load_server()
    calls = {"n": 0}

    async def _tracker_set(_args):
        calls["n"] += 1
        return server._result_text({"success": False, "error": {"code": "boom", "message": "boom"}})

    server._TOOL_HANDLERS["tracker_set"] = _tracker_set
    request = {"steps": _sample_steps()[1:2], "idempotency_key": "idem-3"}
    _call(server, request)
    _call(server, request)
    assert calls["n"] == 2
