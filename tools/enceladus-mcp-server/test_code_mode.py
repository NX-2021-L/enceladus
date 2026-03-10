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
    module_name = f"enceladus_server_code_mode_{uuid.uuid4().hex}"
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


def _tool_dump(tool):
    model_dump = getattr(tool, "model_dump", None)
    if callable(model_dump):
        return model_dump(exclude_none=True)
    to_dict = getattr(tool, "dict", None)
    if callable(to_dict):
        return to_dict()
    return {
        "name": getattr(tool, "name", ""),
        "description": getattr(tool, "description", ""),
        "inputSchema": getattr(tool, "inputSchema", {}),
    }


def test_code_mode_list_tools_exposes_only_four_tools_and_reduces_payload_size():
    raw_server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="raw")
    code_server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    raw_tools = _run(raw_server.list_tools())
    code_tools = _run(code_server.list_tools())

    assert [tool.name for tool in code_tools] == [
        "search",
        "coordination",
        "get_compact_context",
        "execute",
    ]

    raw_blob = json.dumps([_tool_dump(tool) for tool in raw_tools], sort_keys=True)
    code_blob = json.dumps([_tool_dump(tool) for tool in code_tools], sort_keys=True)
    assert len(code_blob) < len(raw_blob) * 0.3


def test_code_mode_rejects_external_raw_tool_calls():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    result = _run(server.call_tool("tracker_get", {"record_id": "ENC-TSK-852"}))

    assert "not exposed in code mode" in result[0].text


def test_search_uses_boundary_scoped_raw_tools():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    async def _tracker_list(args):
        assert args["project_id"] == "enceladus"
        return server._result_text(
            {
                "count": 1,
                "records": [{"id": "ENC-TSK-852", "type": "task"}],
                "next_cursor": None,
            }
        )

    server._TOOL_HANDLERS["tracker_list"] = _tracker_list

    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_list"}, clear=False):
        ok = json.loads(
            _run(
                server.call_tool(
                    "search",
                    {"action": "tracker.list", "arguments": {"project_id": "enceladus"}},
                )
            )[0].text
        )
        blocked = json.loads(
            _run(
                server.call_tool(
                    "search",
                    {"action": "tracker.get", "arguments": {"record_id": "ENC-TSK-852"}},
                )
            )[0].text
        )

    assert ok["success"] is True
    assert ok["result"]["records"][0]["id"] == "ENC-TSK-852"
    assert ok["underlying_calls"][0]["tool"] == "tracker_list"
    assert blocked["success"] is False
    assert blocked["error"]["code"] == "boundary_denied"


def test_get_compact_context_preserves_existing_codemap_payload():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    record_context = {
        "success": True,
        "record": {"id": "ENC-TSK-852", "type": "task", "title": "Implement code mode"},
        "budget": {"requested_max_tokens": 2500, "estimated_output_tokens": 300},
    }
    code_map = {
        "project_id": "enceladus",
        "components": [{"component_id": "comp-enceladus-mcp-server", "primary": "tools/enceladus-mcp-server/server.py"}],
    }

    async def _get_issue_context(_args):
        return server._result_text(record_context)

    async def _get_code_map(_args):
        return server._result_text(code_map)

    async def _documents_search(_args):
        return server._result_text({"documents": [{"document_id": "DOC-B49A1CF616B2"}]})

    async def _governance_dictionary(_args):
        return server._result_text({"entity": "tracker.task", "fields": {"status": {"type": "enum"}}})

    async def _projects_get(_args):
        return server._result_text({"project": {"project_id": "enceladus", "prefix": "ENC"}})

    server._TOOL_HANDLERS["get_issue_context"] = _get_issue_context
    server._TOOL_HANDLERS["get_code_map"] = _get_code_map
    server._TOOL_HANDLERS["documents_search"] = _documents_search
    server._TOOL_HANDLERS["governance_dictionary"] = _governance_dictionary
    server._TOOL_HANDLERS["projects_get"] = _projects_get

    with patch.dict(
        os.environ,
        {
            "COORDINATION_ALLOWED_RAW_TOOLS": (
                "get_issue_context,get_code_map,documents_search,governance_dictionary,projects_get"
            )
        },
        clear=False,
    ):
        payload = json.loads(
            _run(
                server.call_tool(
                    "get_compact_context",
                    {
                        "mode": "task",
                        "record_id": "ENC-TSK-852",
                        "project_id": "enceladus",
                    },
                )
            )[0].text
        )

    assert payload["success"] is True
    assert payload["result"]["record_context"] == record_context
    assert payload["result"]["code_map"] == code_map
    assert payload["result"]["related_documents"]["documents"][0]["document_id"] == "DOC-B49A1CF616B2"


def test_execute_dry_run_resolves_without_calling_mutation_handler():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    calls = {"tracker_set": 0}

    async def _tracker_set(_args):
        calls["tracker_set"] += 1
        return server._result_text({"success": True})

    server._TOOL_HANDLERS["tracker_set"] = _tracker_set

    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_set"}, clear=False):
        payload = json.loads(
            _run(
                server.call_tool(
                    "execute",
                    {
                        "dry_run": True,
                        "steps": [
                            {
                                "action": "tracker.set",
                                "arguments": {
                                    "record_id": "ENC-TSK-852",
                                    "field": "priority",
                                    "value": "P1",
                                    "governance_hash": "abc123",
                                },
                            }
                        ],
                    },
                )
            )[0].text
        )

    assert payload["success"] is True
    assert payload["dry_run"] is True
    assert payload["step_results"][0]["status"] == "dry_run"
    assert payload["underlying_calls"][0]["tool"] == "tracker_set"
    assert calls["tracker_set"] == 0
