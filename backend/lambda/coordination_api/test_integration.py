import importlib.util
import json
import os
import pathlib
import sys
import time
import uuid

import pytest


if os.environ.get("RUN_AWS_INTEGRATION") != "1":
    pytest.skip("Set RUN_AWS_INTEGRATION=1 to run live AWS integration tests.", allow_module_level=True)


MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_integration", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)


def _response_body(response: dict) -> dict:
    return json.loads(response["body"])


def _create_event(payload: dict) -> dict:
    return {"body": json.dumps(payload)}


def _stub_decomposition() -> dict:
    return {
        "feature_id": "DVP-FTR-023",
        "task_ids": ["DVP-TSK-248"],
        "issue_ids": [],
        "acceptance_criteria": ["integration test acceptance"],
        "governance_hash": "a" * 64,
    }


@pytest.fixture
def cleanup_request_ids():
    request_ids = []
    yield request_ids
    ddb = coordination_lambda._get_ddb()
    for request_id in request_ids:
        ddb.delete_item(
            TableName=coordination_lambda.COORDINATION_TABLE,
            Key=coordination_lambda._request_key(request_id),
        )


def test_create_get_round_trip_and_idempotency(monkeypatch, cleanup_request_ids):
    monkeypatch.setattr(coordination_lambda, "_append_tracker_history", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        coordination_lambda,
        "_decompose_and_create_tracker_artifacts",
        lambda **kwargs: _stub_decomposition(),
    )

    payload = {
        "project_id": "devops",
        "initiative_title": f"Integration round trip {uuid.uuid4().hex[:8]}",
        "outcomes": ["Verify DynamoDB round trip for coordination request"],
        "requestor_session_id": f"integration-session-{uuid.uuid4().hex[:8]}",
    }

    create_response = coordination_lambda._handle_create_request(
        _create_event(payload),
        {"email": "integration@test.local"},
    )
    assert create_response["statusCode"] == 201

    created = _response_body(create_response)["request"]
    request_id = created["request_id"]
    cleanup_request_ids.append(request_id)

    assert created["state"] == "intake_received"
    assert coordination_lambda._get_request(request_id) is not None

    get_response = coordination_lambda._handle_get_request(request_id)
    assert get_response["statusCode"] == 200
    fetched = _response_body(get_response)["request"]
    assert fetched["request_id"] == request_id
    assert fetched["project_id"] == "devops"

    reused_response = coordination_lambda._handle_create_request(
        _create_event(payload),
        {"email": "integration@test.local"},
    )
    assert reused_response["statusCode"] == 200
    reused_body = _response_body(reused_response)
    assert reused_body["reused"] is True
    assert reused_body["request"]["request_id"] == request_id


def test_debounce_promotes_intake_received_to_queued(monkeypatch, cleanup_request_ids):
    monkeypatch.setattr(coordination_lambda, "DEBOUNCE_WINDOW_SECONDS", 1)
    monkeypatch.setattr(coordination_lambda, "_append_tracker_history", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        coordination_lambda,
        "_decompose_and_create_tracker_artifacts",
        lambda **kwargs: _stub_decomposition(),
    )

    payload = {
        "project_id": "devops",
        "initiative_title": f"Integration debounce {uuid.uuid4().hex[:8]}",
        "outcomes": ["Validate intake debounce promotion behavior"],
        "requestor_session_id": f"integration-session-{uuid.uuid4().hex[:8]}",
        "related_record_ids": [f"DVP-TSK-{900 + int(time.time()) % 50:03d}"],
    }

    create_response = coordination_lambda._handle_create_request(
        _create_event(payload),
        {"email": "integration@test.local"},
    )
    assert create_response["statusCode"] == 201

    request_id = _response_body(create_response)["request"]["request_id"]
    cleanup_request_ids.append(request_id)

    time.sleep(2)

    get_response = coordination_lambda._handle_get_request(request_id)
    assert get_response["statusCode"] == 200
    request = _response_body(get_response)["request"]
    assert request["state"] == "queued"
    assert any(step.get("to") == "queued" for step in request.get("state_history", []))


def test_state_machine_reaches_terminal_state_via_callback(monkeypatch, cleanup_request_ids):
    monkeypatch.setattr(coordination_lambda, "_append_tracker_history", lambda *args, **kwargs: None)
    monkeypatch.setattr(coordination_lambda, "_set_tracker_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        coordination_lambda,
        "_decompose_and_create_tracker_artifacts",
        lambda **kwargs: _stub_decomposition(),
    )

    payload = {
        "project_id": "devops",
        "initiative_title": f"Integration callback {uuid.uuid4().hex[:8]}",
        "outcomes": ["Validate callback state transition to succeeded"],
        "requestor_session_id": f"integration-session-{uuid.uuid4().hex[:8]}",
    }

    create_response = coordination_lambda._handle_create_request(
        _create_event(payload),
        {"email": "integration@test.local"},
    )
    assert create_response["statusCode"] == 201
    request_id = _response_body(create_response)["request"]["request_id"]
    cleanup_request_ids.append(request_id)

    request = coordination_lambda._get_request(request_id)
    assert request is not None

    coordination_lambda._append_state_transition(request, "queued", "integration test queue promotion")
    coordination_lambda._append_state_transition(request, "dispatching", "integration test dispatch start")
    coordination_lambda._append_state_transition(request, "running", "integration test running")
    coordination_lambda._update_request(request)

    callback_event = {
        "headers": {
            "x-coordination-callback-token": request["callback_token"],
        },
        "body": json.dumps(
            {
                "provider": "openai_codex",
                "state": "succeeded",
                "execution_id": f"exec-{uuid.uuid4().hex[:10]}",
                "summary": "integration callback completed",
            }
        ),
    }

    callback_response = coordination_lambda._handle_callback(callback_event, request_id)
    assert callback_response["statusCode"] == 200
    callback_body = _response_body(callback_response)
    assert callback_body["request"]["state"] == "succeeded"

    refreshed = coordination_lambda._get_request(request_id)
    assert refreshed is not None
    assert refreshed["state"] == "succeeded"
    assert any(step.get("to") == "succeeded" for step in refreshed.get("state_history", []))
