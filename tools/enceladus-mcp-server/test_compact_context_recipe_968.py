"""DVP-TSK-968: get_compact_context routes REC-/RUN- ids to the recipe / recipe_run get handlers."""
import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
ALLOWED = {"COORDINATION_ALLOWED_RAW_TOOLS": "recipe_get,recipe_run_get,get_issue_context,projects_get"}


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server(**env):
    name = f"enceladus_server_968_{uuid.uuid4().hex}"
    env = {"ENCELADUS_MCP_INTERFACE_MODE": "code", **env}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def test_recipe_record_kind():
    from mcp_server.tools.context import recipe_record_kind
    assert recipe_record_kind("DVP-REC-001") == ("recipe_get", "recipe_id")
    assert recipe_record_kind("dvp-run-012") == ("recipe_run_get", "run_id")
    assert recipe_record_kind("ENC-TSK-Q33") is None
    assert recipe_record_kind("") is None and recipe_record_kind(None) is None


def test_recipe_and_run_ids_route_to_get_handlers_and_skip_the_compact_route():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    seen = []

    async def _recipe(a):
        seen.append(("recipe_get", dict(a)))
        return server._result_text({"success": True, "recipe": {"recipe_id": a["recipe_id"]}})

    async def _run_get(a):
        seen.append(("recipe_run_get", dict(a)))
        return server._result_text({"success": True, "run": {"run_id": a["run_id"], "status": "awaiting_gate"}})

    server._TOOL_HANDLERS["recipe_get"] = _recipe
    server._TOOL_HANDLERS["recipe_run_get"] = _run_get
    assert server._compact_context_route_query({"mode": "task", "record_id": "DVP-REC-001"}) is None
    with patch.object(server, "_health_api_request", return_value={"tracker_capabilities": {"compact_context": True}}), \
         patch.object(server, "_coordination_api_request") as route, \
         patch.dict(os.environ, ALLOWED, clear=False):
        rec = json.loads(_run(server._get_compact_context_meta(
            {"mode": "task", "record_id": "DVP-REC-001", "project_id": "devops"}))[0].text)
        run = json.loads(_run(server._get_compact_context_meta(
            {"mode": "task", "record_id": "DVP-RUN-001", "project_id": "devops"}))[0].text)
    route.assert_not_called()
    assert rec["success"] is True and rec["result"]["record_context"]["recipe"]["recipe_id"] == "DVP-REC-001"
    assert run["success"] is True and run["result"]["record_context"]["run"]["status"] == "awaiting_gate"
    assert seen == [("recipe_get", {"project_id": "devops", "recipe_id": "DVP-REC-001"}),
                    ("recipe_run_get", {"project_id": "devops", "run_id": "DVP-RUN-001"})]
