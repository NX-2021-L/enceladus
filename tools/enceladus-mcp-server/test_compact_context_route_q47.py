"""ENC-TSK-Q47: get_compact_context re-point at the context.compact route with local fallback."""
import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server(**env):
    name = f"enceladus_server_q47_{uuid.uuid4().hex}"
    env = {"ENCELADUS_MCP_INTERFACE_MODE": "code", **env}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _stub_raw_tools(server):
    async def _issue(_a):
        return server._result_text({"success": True, "project_id": "enceladus",
                                    "record": {"id": "ENC-TSK-Q33", "title": "T", "intent": "I"}})

    async def _proj(_a):
        return server._result_text({"project": {"project_id": "enceladus"}})

    server._TOOL_HANDLERS["get_issue_context"] = _issue
    server._TOOL_HANDLERS["projects_get"] = _proj


ARGS = {"mode": "task", "record_id": "ENC-TSK-Q33", "project_id": "enceladus",
        "include_code_map": False, "include_related_documents": False,
        "include_governance": False, "include_hybrid_retrieval": False}
ALLOWED = {"COORDINATION_ALLOWED_RAW_TOOLS": "get_issue_context,projects_get"}


def _compose_local(server):
    with patch.dict(os.environ, ALLOWED, clear=False):
        return _run(server._get_compact_context_local(dict(ARGS)))[0].text


def _route_response_from_local(local_text):
    p = json.loads(local_text)
    return {"success": True, "header": {"mode": p["mode"], "partial": p["partial"]},
            "sections": p["result"], "underlying_calls": p["underlying_calls"],
            "warnings": p.get("warnings") or [], "metadata": p.get("metadata") or {}}


def test_route_off_composes_locally_without_probing():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="off")
    _stub_raw_tools(server)
    with patch.object(server, "_health_api_request") as health, \
         patch.object(server, "_coordination_api_request") as route, \
         patch.dict(os.environ, ALLOWED, clear=False):
        out = _run(server._get_compact_context_meta(dict(ARGS)))[0].text
    health.assert_not_called()
    route.assert_not_called()
    assert json.loads(out)["success"] is True


def test_capability_false_composes_locally():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    _stub_raw_tools(server)
    local = _compose_local(server)
    with patch.object(server, "_health_api_request", return_value={"tracker_capabilities": {"census": True}}), \
         patch.object(server, "_coordination_api_request") as route, \
         patch.dict(os.environ, ALLOWED, clear=False):
        out = _run(server._get_compact_context_meta(dict(ARGS)))[0].text
    route.assert_not_called()
    assert out == local


def test_capability_true_calls_route_and_preserves_legacy_shape():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    _stub_raw_tools(server)
    local = _compose_local(server)
    routed = _route_response_from_local(local)
    with patch.object(server, "_health_api_request", return_value={"tracker_capabilities": {"compact_context": True}}) as health, \
         patch.object(server, "_coordination_api_request", return_value=routed) as route:
        first = _run(server._get_compact_context_meta(dict(ARGS)))[0].text
        second = _run(server._get_compact_context_meta(dict(ARGS)))[0].text
    assert first == local  # byte-identical legacy response
    assert second == local
    assert health.call_count == 1  # probe cached per process
    args, kwargs = route.call_args
    assert args[:2] == ("GET", "/context/compact")
    q = kwargs["query"]
    assert q["fields"] == "full" and q["mode"] == "task" and q["record_id"] == "ENC-TSK-Q33"
    assert q["include_code_map"] == "false"


def test_route_error_falls_back_to_local():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    _stub_raw_tools(server)
    local = _compose_local(server)
    with patch.object(server, "_health_api_request", return_value={"tracker_capabilities": {"compact_context": True}}), \
         patch.object(server, "_coordination_api_request", return_value={"success": False, "error": {"code": "UPSTREAM_ERROR"}}), \
         patch.dict(os.environ, ALLOWED, clear=False):
        out = _run(server._get_compact_context_meta(dict(ARGS)))[0].text
    assert out == local


def test_unknown_args_and_disabled_flag_compose_locally():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    assert server._compact_context_route_query({**ARGS, "mystery": 1}) is None
    server.COMPACT_CONTEXT_ROUTE_DISABLED = True  # set by coordination_api on its hosted module
    with patch.object(server, "_health_api_request") as health:
        assert server._compact_context_route_available() is False
    health.assert_not_called()


def test_failed_probe_is_not_cached_forever():
    server = _load_server(ENCELADUS_COMPACT_CONTEXT_ROUTE="auto")
    with patch.object(server, "_health_api_request", return_value={"error": "down"}):
        assert server._compact_context_route_available() is False
    server._COMPACT_CONTEXT_PROBE["at"] -= 61
    with patch.object(server, "_health_api_request", return_value={"tracker_capabilities": {"compact_context": True}}):
        assert server._compact_context_route_available() is True
