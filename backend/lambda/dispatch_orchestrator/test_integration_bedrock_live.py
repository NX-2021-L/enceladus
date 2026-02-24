import importlib.util
import os
import pathlib
import random
import string
import sys
import time

import boto3
import pytest
from botocore.exceptions import ClientError


if os.environ.get("RUN_AWS_BEDROCK_INTEGRATION") != "1":
    pytest.skip("Set RUN_AWS_BEDROCK_INTEGRATION=1 to run live Bedrock integration tests.", allow_module_level=True)


MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("dispatch_orchestrator_bedrock_integration", MODULE_PATH)
dispatch_orchestrator = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = dispatch_orchestrator
SPEC.loader.exec_module(dispatch_orchestrator)


REGION = os.environ.get("AWS_REGION", "us-west-2")
ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "356364570033")
BEDROCK_ROLE_ARN = os.environ.get(
    "BEDROCK_AGENT_ROLE_ARN",
    f"arn:aws:iam::{ACCOUNT_ID}:role/enceladus-bedrock-agent-execution-role",
)
ACTION_GROUP_LAMBDA_ARN = os.environ.get(
    "BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN",
    f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:enceladus-bedrock-agent-actions",
)


def _token(prefix: str) -> str:
    suffix = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    return f"{prefix}-{suffix}"


def _wait_for_agent_delete(agent_id: str, timeout_seconds: int = 120) -> None:
    client = boto3.client("bedrock-agent", region_name=REGION)
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            client.get_agent(agentId=agent_id)
            time.sleep(5)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ResourceNotFoundException", "ValidationException"}:
                return
            raise
    raise AssertionError(f"Agent {agent_id} was not deleted within {timeout_seconds}s")


def _set_bedrock_runtime_config() -> None:
    dispatch_orchestrator.BEDROCK_AGENT_ROLE_ARN = BEDROCK_ROLE_ARN
    dispatch_orchestrator.BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN = ACTION_GROUP_LAMBDA_ARN
    dispatch_orchestrator.BEDROCK_AGENT_REGION = REGION
    dispatch_orchestrator.BEDROCK_AGENT_CLEANUP = True
    dispatch_orchestrator.BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS = 180


def test_live_bedrock_agent_create_invoke_delete_with_action_group():
    _set_bedrock_runtime_config()

    dispatch_id = _token("DSP")
    request_id = _token("CRQ")
    provider_config = {
        "bedrock_config": {
            "action_group_lambda_arn": ACTION_GROUP_LAMBDA_ARN,
            "retain_agent": False,
            "idle_session_ttl_seconds": 300,
        }
    }

    agent_id = ""
    try:
        agent = dispatch_orchestrator._create_bedrock_agent(
            dispatch_id=dispatch_id,
            request_id=request_id,
            outcomes=["List all available projects and summarize them."],
            provider_config=provider_config,
        )
        agent_id = agent["agent_id"]
        assert agent_id
        assert agent["agent_alias_id"]

        bedrock_client = boto3.client("bedrock-agent", region_name=REGION)
        action_groups = bedrock_client.list_agent_action_groups(
            agentId=agent_id,
            agentVersion="DRAFT",
            maxResults=50,
        ).get("actionGroupSummaries", [])
        assert any(g.get("actionGroupName") == "enceladus-tools" for g in action_groups)

        response_text = dispatch_orchestrator._invoke_bedrock_agent(
            agent_id=agent["agent_id"],
            agent_alias_id=agent["agent_alias_id"],
            session_id=f"integration-{dispatch_id.lower()}",
            prompt=(
                "Use your tools to list active projects and return a short summary with project IDs."
            ),
        )
        assert isinstance(response_text, str)
        assert response_text.strip(), "Expected non-empty Bedrock response text"
    finally:
        if agent_id:
            dispatch_orchestrator._cleanup_bedrock_agent(agent_id)
            _wait_for_agent_delete(agent_id)


def test_live_execute_bedrock_dispatch_pipeline():
    _set_bedrock_runtime_config()

    dispatch_id = _token("DSP")
    request_id = _token("CRQ")
    dispatch = {
        "dispatch_id": dispatch_id,
        "provider": "aws_bedrock_agent",
        "execution_mode": "bedrock_agent",
        "outcomes": ["Respond with a brief staging validation confirmation for this dispatch."],
        "provider_config": {
            "bedrock_config": {
                "action_group_lambda_arn": ACTION_GROUP_LAMBDA_ARN,
                "foundation_model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                "retain_agent": False,
                "idle_session_ttl_seconds": 300,
            }
        },
    }
    request = {
        "request_id": request_id,
        "project_id": "devops",
    }
    callback_token = _token("CB")

    result = dispatch_orchestrator._execute_bedrock_dispatch(
        dispatch=dispatch,
        request=request,
        callback_token=callback_token,
    )

    assert result["provider"] == "aws_bedrock_agent"
    assert result["execution_mode"] == "bedrock_agent"
    assert result["delivery_method"] == "bedrock_agent"
    assert result.get("response_preview", "").strip(), "Expected non-empty dispatch response preview"

    agent_id = result.get("agent_id")
    assert agent_id
    _wait_for_agent_delete(agent_id)
