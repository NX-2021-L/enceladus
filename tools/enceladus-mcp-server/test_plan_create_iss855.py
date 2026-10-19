"""ENC-ISS-855 / ENC-TSK-R44: code-mode plan.create creates plans.

plan.create was a bare alias of tracker.create (record_type enum task|issue|feature), so
execute rejected record_type=plan with a 422 and record_type=task silently created a task.
It now carries its own plan contract and execute injects record_type=plan on every path.
Secondary: tracker.create rejects 'parent' instead of dropping it (the API reads
is_child + parent_task_id).
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
GOV = "a" * 64


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server():
    name = f"enceladus_server_iss855_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "ENCELADUS_MCP_INTERFACE_MODE": "code"}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _call(server, tool, arguments):
    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_create"}, clear=False):
        return json.loads(_run(server.call_tool(tool, arguments))[0].text)


def _schemas(server, *names):
    payload = _call(server, "search", {"action": "actions.schemas", "arguments": {"names": list(names)}})
    return {a["name"]: a for a in payload["result"]["actions"]}


def _capture_tracker_api(server):
    captured = []

    def _fake(method, path="", payload=None, query=None):
        captured.append({"method": method, "path": path, "payload": payload})
        return {"success": True, "record_id": "ENC-PLN-999"}

    return captured, _fake


# --- AC1: plan.create has its own plan contract ------------------------------------------

def test_plan_create_schema_is_plan_specific_and_distinct_from_tracker_create():
    server = _load_server()
    actions = _schemas(server, "plan.create", "tracker.create")
    plan, create = actions["plan.create"]["inputSchema"], actions["tracker.create"]["inputSchema"]

    assert set(plan["required"]) == {"governance_hash", "project_id", "title"}
    assert plan["properties"]["record_type"]["const"] == "plan"
    for field in ("priority", "description", "intent", "category", "objectives_set",
                  "related_feature_id", "attached_documents", "related",
                  "coordination_request_id", "dispatch_id", "provider"):
        assert field in plan["properties"], field
    for field in ("acceptance_criteria", "transition_type", "user_story", "evidence",
                  "hypothesis", "location_hint", "primary_task", "parent"):
        assert field not in plan["properties"], field
    assert plan["properties"]["objectives_set"]["items"] == {"type": "string", "minLength": 1}
    assert plan != create
    jsonschema.Draft202012Validator.check_schema(plan)


def test_plan_create_schema_hash_differs_from_tracker_create():
    server = _load_server()
    payload = _call(server, "execute", {"dry_run": True, "steps": [
        {"action": "plan.create", "arguments": {"project_id": "enceladus", "title": "p", "governance_hash": GOV}},
        {"action": "tracker.create", "arguments": {
            "project_id": "enceladus", "record_type": "plan", "title": "p", "governance_hash": GOV}},
    ]})
    hashes = [s["resolved_call"]["schemaHash"] for s in payload["step_results"]]
    assert hashes[0] != hashes[1]


# --- AC2: record_type=plan is injected server-side ---------------------------------------

def test_plan_create_dry_run_injects_record_type_plan():
    server = _load_server()
    payload = _call(server, "execute", {"dry_run": True, "steps": [
        {"action": "plan.create", "arguments": {"project_id": "enceladus", "title": "p", "governance_hash": GOV}},
    ]})
    assert payload["success"] is True, payload
    step = payload["step_results"][0]
    assert step["status"] == "dry_run"
    assert step["resolved_call"]["underlying"][0]["handler"] == "tracker_create"
    assert step["resolved_call"]["arguments"]["record_type"] == "plan"


def test_plan_create_accepts_explicit_record_type_plan():
    server = _load_server()
    payload = _call(server, "execute", {"dry_run": True, "steps": [
        {"action": "plan.create", "arguments": {
            "project_id": "enceladus", "record_type": "plan", "title": "p", "governance_hash": GOV}},
    ]})
    assert payload["success"] is True, payload


def test_plan_create_rejects_non_plan_record_type_on_dry_run_and_real_path():
    server = _load_server()
    calls = []

    async def _tracker_create(args):
        calls.append(args)
        return server._result_text({"success": True, "record_id": "ENC-TSK-999"})

    server._TOOL_HANDLERS["tracker_create"] = _tracker_create
    for dry_run in (True, False):
        for wrong in ("task", "issue", "feature"):
            payload = _call(server, "execute", {"dry_run": dry_run, "steps": [
                {"action": "plan.create", "arguments": {
                    "project_id": "enceladus", "record_type": wrong, "title": "p", "governance_hash": GOV}},
            ]})
            assert payload["success"] is False
            assert payload["problem"]["status"] == 422
            assert [e["pointer"] for e in payload["problem"]["errors"]] == ["/record_type"]
    assert calls == [], "plan.create must never reach tracker_create with a non-plan type"


def test_plan_create_real_call_posts_plan_payload_to_plan_route():
    server = _load_server()
    captured, fake = _capture_tracker_api(server)
    with patch.object(server, "_require_governance_hash", return_value=None), \
         patch.object(server, "_tracker_api_request", side_effect=fake):
        payload = _call(server, "execute", {"steps": [
            {"action": "plan.create", "arguments": {
                "project_id": "enceladus", "title": "p", "governance_hash": GOV,
                "objectives_set": ["ENC-TSK-001", "ENC-TSK-002"], "related_feature_id": "ENC-FTR-058"}},
        ]})
    assert payload["success"] is True, payload
    assert len(captured) == 1
    assert captured[0]["method"] == "POST"
    assert captured[0]["path"] == "/enceladus/plan"
    body = captured[0]["payload"]
    assert body["objectives_set"] == ["ENC-TSK-001", "ENC-TSK-002"]
    assert body["related_feature_id"] == "ENC-FTR-058"
    assert "record_type" not in body and "project_id" not in body


# --- AC3: raw parity ----------------------------------------------------------------------

def test_tracker_create_and_list_record_type_enums_include_plan():
    server = _load_server()
    actions = _schemas(server, "tracker.create", "tracker.list")
    assert "plan" in actions["tracker.create"]["inputSchema"]["properties"]["record_type"]["enum"]
    assert "plan" in actions["tracker.list"]["inputSchema"]["properties"]["record_type"]["enum"]
    payload = _call(server, "execute", {"dry_run": True, "steps": [
        {"action": "tracker.create", "arguments": {
            "project_id": "enceladus", "record_type": "plan", "title": "p", "governance_hash": GOV}},
    ]})
    assert payload["success"] is True, payload


# --- AC4: 'parent' is rejected, never silently dropped ------------------------------------

def test_tracker_create_handler_rejects_parent_without_calling_the_api():
    server = _load_server()
    captured, fake = _capture_tracker_api(server)
    with patch.object(server, "_require_governance_hash", return_value=None), \
         patch.object(server, "_tracker_api_request", side_effect=fake):
        result = json.loads(_run(server._tracker_create({
            "project_id": "enceladus", "record_type": "task", "title": "t", "governance_hash": GOV,
            "acceptance_criteria": ["x"], "parent": "ENC-TSK-R03",
        }))[0].text)
    assert captured == []
    assert result["success"] is False
    problem = result["error"]["details"]["problem"]
    assert problem["status"] == 422
    assert problem["errors"][0]["pointer"] == "/parent"
    assert "parent_task_id" in problem["detail"] and "is_child" in problem["detail"]


def test_tracker_create_dry_run_rejects_parent_with_pointer():
    server = _load_server()
    payload = _call(server, "execute", {"dry_run": True, "steps": [
        {"action": "tracker.create", "arguments": {
            "project_id": "enceladus", "record_type": "task", "title": "t", "governance_hash": GOV,
            "acceptance_criteria": ["x"], "parent": "ENC-TSK-R03"}},
    ]})
    assert payload["success"] is False
    errors = payload["problem"]["errors"]
    assert [e["pointer"] for e in errors] == ["/parent"]
    assert "parent_task_id" in errors[0]["detail"]


def test_tracker_create_still_forwards_is_child_and_parent_task_id():
    server = _load_server()
    captured, fake = _capture_tracker_api(server)
    with patch.object(server, "_require_governance_hash", return_value=None), \
         patch.object(server, "_tracker_api_request", side_effect=fake):
        _run(server._tracker_create({
            "project_id": "enceladus", "record_type": "task", "title": "t", "governance_hash": GOV,
            "acceptance_criteria": ["x"], "is_child": True, "parent_task_id": "ENC-TSK-R03",
        }))
    assert captured[0]["payload"]["is_child"] is True
    assert captured[0]["payload"]["parent_task_id"] == "ENC-TSK-R03"
