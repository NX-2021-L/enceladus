import asyncio
import importlib.util
import json
import pathlib
import sys


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_mcp_server_bedrock_integration", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def test_dispatch_plan_dry_run_selects_bedrock_provider():
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(
            server._TOOL_HANDLERS["dispatch_plan_dry_run"](
                {
                    "project_id": "devops",
                    "preferred_provider": "aws_bedrock_agent",
                    "outcomes": [
                        "Use bedrock agent to summarize open devops tasks from tracker",
                        "Call documents search to retrieve latest coordination runbook notes",
                    ],
                }
            )
        )
    finally:
        loop.close()

    assert result and getattr(result[0], "text", "")
    plan = json.loads(result[0].text)
    assert plan.get("_dry_run") is True
    assert plan.get("dispatches"), "Expected at least one dispatch in dry-run plan"

    dispatch = plan["dispatches"][0]
    assert dispatch["provider"] == "aws_bedrock_agent"
    assert dispatch["execution_mode"] == "bedrock_agent"
    assert "bedrock_config" in dispatch["provider_config"]
