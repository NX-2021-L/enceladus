"""ENC-TSK-967 (DVP-PLN-013 E4-W1.2, phase 2b): MCP escalation.list / escalation.request wrappers.

Argument passthrough for the producer API and the list filters, caps.json
registration with annotations, and the FTR-121 invariant that no decide action
exists on the MCP surface.
"""
import asyncio
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("enceladus_server_escalation_producer_e4", HERE / "server.py")
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake(method, path, query=None, payload=None, **kw):
        seen.append({"method": method, "path": path, "query": query, "payload": payload})
        return {"success": True}

    monkeypatch.setattr(server, "_tracker_api_request", fake)
    monkeypatch.setattr(server, "_require_governance_hash", lambda args: None)
    return seen


def _run(coro):
    # new_event_loop, not asyncio.run: run() unsets the current loop and breaks sibling tests.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_request_passes_producer_fields_through(calls):
    call = {"capability": "tracker.set", "callHash": "a" * 64}
    _run(server._escalation_request({
        "project_id": "devops", "kind": "tool_call", "source_principal": "think-prod",
        "source": "think", "proposedCalls": [call], "candidates": None, "title": "t"}))
    payload = calls[0]["payload"]
    assert (calls[0]["method"], calls[0]["path"]) == ("POST", "/devops/escalation")
    assert payload["kind"] == "tool_call" and payload["source_principal"] == "think-prod"
    assert payload["proposedCalls"] == [call] and payload["source"] == "think"
    assert "candidates" not in payload  # unset args are never invented


def test_request_legacy_payload_shape_is_unchanged(calls):
    _run(server._escalation_request({
        "project_id": "enceladus", "target_record_id": "ENC-TSK-1", "mutation_type": "deploy_arc_change",
        "payload": {"a": 1}, "justification": "why"}))
    payload = calls[0]["payload"]
    assert payload["mutation_type"] == "deploy_arc_change" and payload["target_record_id"] == "ENC-TSK-1"
    assert not {"kind", "proposedCalls", "candidates", "source_principal"} & set(payload)


def test_list_passes_kind_state_and_all_projects(calls):
    _run(server._escalation_list({"project_id": "enceladus", "kind": "tool_call,stale_lock",
                                  "state": "pending", "all_projects": True}))
    assert calls[0]["path"] == "/enceladus/escalation/list"
    assert calls[0]["query"]["kind"] == "tool_call,stale_lock"
    assert calls[0]["query"]["state"] == "pending"
    assert calls[0]["query"]["all_projects"] == "true"


def test_list_default_query_adds_no_filters(calls):
    _run(server._escalation_list({"project_id": "enceladus"}))
    query = calls[0]["query"]
    assert query["kind"] is None and query["state"] is None and query["all_projects"] is None


def _caps_actions():
    found = {}

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("name"), str) and "annotations" in node:
                found[node["name"]] = node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(json.loads((HERE / "parity" / "caps.json").read_text()))
    return found


def test_caps_register_list_and_request_with_annotations():
    caps = _caps_actions()
    assert caps["escalation.list"]["annotations"]["readOnlyHint"] is True
    assert caps["escalation.request"]["annotations"]["destructiveHint"] is False
    list_props = caps["escalation.list"]["inputSchema"]["properties"]
    assert {"kind", "state", "all_projects"} <= set(list_props)
    request_props = caps["escalation.request"]["inputSchema"]["properties"]
    assert {"kind", "candidates", "proposedCalls", "source_principal"} <= set(request_props)


def test_no_decide_action_exists_on_the_mcp_surface():
    assert not [name for name in _caps_actions() if "decide" in name.lower()]
    assert not [name for name in vars(server) if name.startswith("_escalation") and "decide" in name]
