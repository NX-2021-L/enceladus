import asyncio
import importlib.util
import pathlib
import sys
from unittest.mock import patch

from mcp.types import Tool


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_dynamic_toolsets", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _tools():
    return [
        Tool(name="projects_get", description="", inputSchema={"type": "object"}),
        Tool(name="tracker_get", description="", inputSchema={"type": "object"}),
        Tool(name="deploy_submit", description="", inputSchema={"type": "object"}),
        Tool(name="github_create_issue", description="", inputSchema={"type": "object"}),
    ]


def test_filter_tool_list_for_session_context_limits_by_namespace():
    context = {
        "tool_filter_active": True,
        "allowed_namespaces": ["projects", "tracker"],
    }
    with patch.object(server, "_current_session_toolset_context", return_value=("sess-1", context)):
        filtered = server._filter_tool_list_for_session_context(_tools())
    assert [tool.name for tool in filtered] == ["projects_get", "tracker_get"]


def test_filter_tool_list_for_session_context_falls_back_when_inactive():
    context = {
        "tool_filter_active": False,
        "allowed_namespaces": ["projects"],
    }
    with patch.object(server, "_current_session_toolset_context", return_value=("sess-1", context)):
        filtered = server._filter_tool_list_for_session_context(_tools())
    assert [tool.name for tool in filtered] == [tool.name for tool in _tools()]


def test_sync_dynamic_toolset_on_checkout_enables_filter_when_notification_supported():
    context = {}
    response = {
        "success": True,
        "task": {
            "project_id": "enceladus",
            "category": "implementation",
        },
    }
    with patch.object(server, "_current_session_toolset_context", return_value=("sess-1", context)), patch.object(
        server,
        "_notify_tools_list_changed_if_supported",
        return_value=True,
    ):
        _run(server._sync_dynamic_toolset_on_checkout("ENC-TSK-826", response))

    assert context["active_task_id"] == "ENC-TSK-826"
    assert context["active_project_id"] == "enceladus"
    assert context["active_category"] == "implementation"
    assert context["tool_filter_active"] is True
    assert "deploy" in context["allowed_namespaces"]


def test_sync_dynamic_toolset_on_checkout_uses_fallback_when_notification_unsupported():
    context = {}
    response = {
        "success": True,
        "task": {
            "project_id": "enceladus",
            "category": "investigation",
        },
    }
    with patch.object(server, "_current_session_toolset_context", return_value=("sess-1", context)), patch.object(
        server,
        "_notify_tools_list_changed_if_supported",
        return_value=False,
    ):
        _run(server._sync_dynamic_toolset_on_checkout("ENC-TSK-828", response))

    assert context["active_task_id"] == "ENC-TSK-828"
    assert context["tool_filter_active"] is False
    assert "deploy" not in context["allowed_namespaces"]


def test_sync_dynamic_toolset_on_task_release_clears_matching_context():
    context = {
        "active_task_id": "ENC-TSK-826",
        "tool_filter_active": True,
        "allowed_namespaces": ["projects"],
    }
    with patch.object(server, "_current_session_toolset_context", return_value=("sess-1", context)), patch.object(
        server,
        "_notify_tools_list_changed_if_supported",
        return_value=True,
    ):
        _run(server._sync_dynamic_toolset_on_task_release("ENC-TSK-826"))

    assert context == {}
