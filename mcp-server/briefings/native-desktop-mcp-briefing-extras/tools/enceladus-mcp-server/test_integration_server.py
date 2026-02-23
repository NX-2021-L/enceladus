import asyncio
import importlib.util
import json
import os
import pathlib
import sys

import pytest


if os.environ.get("RUN_AWS_INTEGRATION") != "1":
    pytest.skip("Set RUN_AWS_INTEGRATION=1 to run live AWS integration tests.", allow_module_level=True)


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_integration", MODULE_PATH)
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


def _call_tool(name: str, args: dict) -> dict:
    content = _run(server._TOOL_HANDLERS[name](args))
    assert content, f"{name} returned empty content"
    return json.loads(content[0].text)


def test_tracker_handlers_against_live_dynamodb():
    tracker_get = _call_tool("tracker_get", {"record_id": "DVP-TSK-280"})
    assert tracker_get["id"] == "DVP-TSK-280"
    assert tracker_get["project_id"] == "devops"

    tracker_list = _call_tool(
        "tracker_list",
        {"project_id": "devops", "record_type": "task", "status": "open"},
    )
    assert tracker_list["count"] >= 1
    assert all(record["type"] == "task" for record in tracker_list["records"])


def test_projects_and_connection_health_handlers():
    project = _call_tool("projects_get", {"project_name": "devops"})
    assert project["project"]["project_id"] == "devops"
    assert project["project"]["prefix"] == "DVP"

    health = _call_tool("connection_health", {})
    assert health["dynamodb"] == "ok"
    assert "governance_hash" in health


def test_dispatch_plan_dry_run_handler():
    dry_run = _call_tool(
        "dispatch_plan_dry_run",
        {
            "project_id": "devops",
            "outcomes": [
                "Validate MCP dry-run integration path",
                "Generate test coverage evidence for DVP-TSK-280",
            ],
        },
    )

    assert dry_run["_dry_run"] is True
    assert dry_run["plan_version"] == "0.3.0"
    assert dry_run["dispatches"], "Expected one or more dispatches in dry-run plan"
