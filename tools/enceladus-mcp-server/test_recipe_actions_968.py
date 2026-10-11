"""DVP-TSK-968 part A: recipe MCP actions (registry, x-io-minted outputs, caps.json, argument passthrough)."""
import asyncio
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent.parent / "backend" / "lambda" / "shared_layer" / "python"))
SPEC = importlib.util.spec_from_file_location("enceladus_server_recipe_968", HERE / "server.py")
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)

MUTATING = ["recipe.create", "recipe.validate", "recipe.publish_request", "recipe.deprecate"]
READS = ["recipe.get", "recipe.list"]


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
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_registry_has_recipe_actions_with_governance_and_no_approve_action():
    execute, search = server._EXECUTE_ACTIONS, server._SEARCH_ACTIONS
    for name in MUTATING:
        assert execute[name]["requires_governance_hash"] is True, name
    for name in READS:
        assert name in search and not search[name].get("requires_governance_hash")
    everything = set(execute) | set(search) | set(server._COORDINATION_ACTIONS)
    assert not [n for n in everything if n.startswith("recipe") and any(w in n for w in ("approve", "decide", "publish."))]
    assert "recipe.publish" not in everything


def test_minted_ids_carry_x_io_minted():
    execute = server._EXECUTE_ACTIONS
    props = execute["recipe.create"]["output"]["properties"]
    assert props["recipe_id"]["x-io-minted"] is True
    assert execute["recipe.publish_request"]["output"]["properties"]["escalation_id"]["x-io-minted"] is True
    assert execute["recipe.deprecate"]["output"]["properties"]["escalation_id"]["x-io-minted"] is True


def test_caps_snapshot_lists_the_actions_with_dry_run_and_outputs():
    caps = json.loads((HERE / "parity" / "caps.json").read_text())
    by_name = {a["name"]: a for a in caps["actions"]}
    for name in MUTATING + READS:
        assert name in by_name, name
    for name in MUTATING:
        assert "dry_run" in by_name[name]["inputSchema"]["properties"], name
        assert "governance_hash" in by_name[name]["inputSchema"]["required"], name
    assert by_name["recipe.create"]["outputSchema"]["properties"]["recipe_id"]["x-io-minted"] is True
    assert by_name["recipe.publish_request"]["outputSchema"]["properties"]["escalation_id"]["x-io-minted"] is True
    for surface in ("io-finance", "io-travel"):
        snap = json.loads((HERE / "parity" / "surfaces" / f"{surface}.caps.json").read_text())
        assert snap["surface"] == surface and snap["actions"]


def test_create_passes_dry_run_and_never_sends_a_recipe_id_unless_given(calls):
    _run(server._recipe_create({"project_id": "devops", "name": "daily-close", "project_ids": ["devops"],
                                "definition": {"steps": []}, "dry_run": True, "governance_hash": "g"}))
    assert calls[0]["method"] == "POST" and calls[0]["path"] == "/devops/recipe"
    assert calls[0]["payload"]["dry_run"] is True and "recipe_id" not in calls[0]["payload"]
    _run(server._recipe_create({"project_id": "devops", "recipe_id": "DVP-REC-001", "name": "daily-close",
                                "project_ids": ["devops"], "definition": {}}))
    assert calls[1]["payload"]["recipe_id"] == "DVP-REC-001" and "dry_run" not in calls[1]["payload"]


def test_routes_for_validate_publish_deprecate_get_list(calls):
    base = {"project_id": "devops", "recipe_id": "DVP-REC-001", "version": "1.0.0"}
    _run(server._recipe_validate(dict(base)))
    _run(server._recipe_publish_request(dict(base, rationale="ship", dry_run=False)))
    _run(server._recipe_deprecate(dict(base, reason="old", target="retired")))
    _run(server._recipe_get(dict(base)))
    _run(server._recipe_list({"project_id": "devops", "status": "published", "limit": 5}))
    assert [(c["method"], c["path"]) for c in calls] == [
        ("POST", "/devops/recipe/DVP-REC-001/validate"), ("POST", "/devops/recipe/DVP-REC-001/publish-request"),
        ("POST", "/devops/recipe/DVP-REC-001/deprecate"), ("GET", "/devops/recipe/DVP-REC-001"),
        ("GET", "/devops/recipe/list")]
    assert calls[1]["payload"]["rationale"] == "ship" and calls[1]["payload"]["dry_run"] is False
    assert calls[2]["payload"]["target"] == "retired"
    assert calls[3]["query"] == {"version": "1.0.0"} and calls[4]["query"]["status"] == "published"


def test_malformed_ids_and_missing_governance_make_no_call(calls, monkeypatch):
    _run(server._recipe_get({"project_id": "devops", "recipe_id": "../x"}))
    _run(server._recipe_validate({"project_id": "devops", "recipe_id": ""}))
    monkeypatch.setattr(server, "_require_governance_hash", lambda args: "governance_hash required")
    _run(server._recipe_create({"project_id": "devops", "name": "daily-close"}))
    assert calls == []
