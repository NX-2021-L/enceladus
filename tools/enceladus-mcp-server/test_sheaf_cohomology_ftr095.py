"""Tests for ENC-FTR-095 / ENC-TSK-I90: tracker.sheaf_cohomology MCP action.

Verifies the search action is registered in code mode and forwards to the
graph_query_api sheaf_cohomology search_type, returning h1_dim,
inconsistency_nodes[], and computation_ms.
"""

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
    module_name = f"enceladus_server_sheaf_{uuid.uuid4().hex}"
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


def test_sheaf_cohomology_action_registered():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    assert "tracker.sheaf_cohomology" in server._SEARCH_ACTIONS
    assert server._SEARCH_ACTIONS["tracker.sheaf_cohomology"]["tool"] == "tracker_sheaf_cohomology"
    assert "tracker_sheaf_cohomology" in server._TOOL_HANDLERS


def test_sheaf_cohomology_forwards_to_graph_query_api():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    captured = {}

    def _fake_graph_query_api_request(query=None):
        captured["query"] = query
        return {
            "success": True,
            "h1_dim": 1,
            "h1_structural": 1,
            "inconsistency_nodes": ["ENC-TSK-100", "ENC-TSK-101"],
            "inconsistency_edges": [
                {"start": "ENC-TSK-100", "end": "ENC-TSK-101", "type": "RELATED_TO"}
            ],
            "computation_ms": 0.42,
            "node_count": 2,
            "edge_count": 1,
        }

    server._graph_query_api_request = _fake_graph_query_api_request

    with patch.dict(
        os.environ,
        {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_sheaf_cohomology"},
        clear=False,
    ):
        payload = json.loads(
            _run(
                server.call_tool(
                    "search",
                    {
                        "action": "tracker.sheaf_cohomology",
                        "arguments": {
                            "project_id": "enceladus",
                            "vertex_set_query": "ENC-TSK-100",
                        },
                    },
                )
            )[0].text
        )

    assert payload["success"] is True
    assert payload["underlying_calls"][0]["tool"] == "tracker_sheaf_cohomology"
    assert payload["result"]["h1_dim"] == 1
    assert payload["result"]["inconsistency_nodes"] == ["ENC-TSK-100", "ENC-TSK-101"]
    assert "computation_ms" in payload["result"]
    # vertex_set_query and search_type forwarded to the graph query API.
    assert captured["query"]["search_type"] == "sheaf_cohomology"
    assert captured["query"]["project_id"] == "enceladus"
    assert captured["query"]["vertex_set_query"] == "ENC-TSK-100"


def test_sheaf_cohomology_requires_project_id():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    with patch.dict(
        os.environ,
        {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_sheaf_cohomology"},
        clear=False,
    ):
        payload = json.loads(
            _run(
                server.call_tool(
                    "search",
                    {"action": "tracker.sheaf_cohomology", "arguments": {}},
                )
            )[0].text
        )

    # The handler returns an error envelope when project_id is missing.
    blob = json.dumps(payload)
    assert "project_id is required" in blob


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
