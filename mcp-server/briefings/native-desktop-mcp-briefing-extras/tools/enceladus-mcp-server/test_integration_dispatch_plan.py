import importlib.util
import os
import pathlib
import sys
import time
import uuid

import pytest
from boto3.dynamodb.types import TypeSerializer


if os.environ.get("RUN_AWS_INTEGRATION") != "1":
    pytest.skip("Set RUN_AWS_INTEGRATION=1 to run live AWS integration tests.", allow_module_level=True)


MODULE_PATH = pathlib.Path(__file__).with_name("dispatch_plan_generator.py")
SPEC = importlib.util.spec_from_file_location("dispatch_plan_generator_integration", MODULE_PATH)
dpg = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = dpg
SPEC.loader.exec_module(dpg)


_SERIALIZER = TypeSerializer()


def _serialize_item(item: dict) -> dict:
    return {key: _SERIALIZER.serialize(value) for key, value in item.items()}


@pytest.fixture
def cleanup_request_ids():
    request_ids = []
    yield request_ids
    ddb = dpg._get_ddb()
    for request_id in request_ids:
        ddb.delete_item(
            TableName=dpg.COORDINATION_TABLE,
            Key={"request_id": {"S": request_id}},
        )


def test_live_connection_health():
    health = dpg.test_connection_health()
    assert health["dynamodb"] == "ok"
    assert "s3" in health
    assert "api_gateway" in health


def test_live_governance_hash_is_stable():
    hash_a = dpg.compute_governance_hash()
    hash_b = dpg.compute_governance_hash()
    assert len(hash_a) == 64
    assert hash_a == hash_b


def test_generate_dispatch_plan_from_live_request(cleanup_request_ids):
    request_id = f"CRQ-ITG-{uuid.uuid4().hex[:12].upper()}"
    now_epoch = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

    request_item = {
        "request_id": request_id,
        "project_id": "devops",
        "initiative_title": "Integration dispatch plan generation",
        "outcomes": [
            "Validate live dispatch-plan generation against coordination table",
            "Generate integration test evidence for DVP-TSK-280",
        ],
        "constraints": {},
        "related_record_ids": ["DVP-TSK-280"],
        "requestor_session_id": f"integration-session-{uuid.uuid4().hex[:8]}",
        "source_requests": [request_id],
        "provider_session": {"preferred_provider": "claude_agent_sdk"},
        "state": "queued",
        "created_at": now_iso,
        "updated_at": now_iso,
        "created_epoch": now_epoch,
        "updated_epoch": now_epoch,
    }

    ddb = dpg._get_ddb()
    ddb.put_item(
        TableName=dpg.COORDINATION_TABLE,
        Item=_serialize_item(request_item),
    )
    cleanup_request_ids.append(request_id)

    plan = dpg.generate_dispatch_plan(request_id)

    assert plan["plan_version"] == "0.3.0"
    assert request_id in plan["source_request_ids"]
    assert plan["project_id"] == "devops"
    assert len(plan["governance_hash"]) == 64
    assert plan["connection_health"]["dynamodb"] == "ok"
    assert plan["dispatches"], "Expected at least one dispatch in generated plan"
