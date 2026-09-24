import importlib.util
import pathlib
import sys


MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_error_passthrough", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def test_normalize_legacy_error_payload_preserves_error_envelope_details():
    payload = {
        "success": False,
        "error": "Invalid transition_type 'manual'.",
        "error_envelope": {
            "code": "INVALID_INPUT",
            "message": "Invalid transition_type 'manual'.",
            "retryable": False,
            "details": {
                "field": "transition_type",
                "allowed_values": ["github_pr_deploy", "lambda_deploy"],
            },
        },
        "field": "transition_type",
    }

    normalized = server._normalize_legacy_error_payload(payload, 400)

    assert normalized["error"] == "Invalid transition_type 'manual'."
    assert normalized["error_envelope"]["code"] == "INVALID_INPUT"
    assert normalized["error_envelope"]["details"]["field"] == "transition_type"
    assert normalized["error_envelope"]["details"]["allowed_values"] == [
        "github_pr_deploy",
        "lambda_deploy",
    ]


def test_normalize_legacy_error_payload_preserves_escalation_fields():
    """ENC-TSK-H50 (ENC-ISS-142 gate #2): the checkout-service escalation fields
    failure_classification + recommended_next_actions (ENC-TSK-H49) must survive the
    MCP boundary, not be flattened away when the error envelope is normalized."""
    payload = {
        "success": False,
        "error": "Task status transitions require an active checkout.",
        "error_envelope": {
            "code": "CONFLICT",
            "message": "Task status transitions require an active checkout.",
            "retryable": False,
            "details": {"task_id": "ENC-TSK-999", "target_status": "coding-complete"},
            "failure_classification": "deterministic-governance",
            "recommended_next_actions": [
                {
                    "action": "checkout_task",
                    "description": "Check out the task before advancing its status.",
                },
                {
                    "action": "escalate",
                    "description": "If you do not own the checkout, escalate per the agents.md Escalation Protocol instead of forcing the gate.",
                },
            ],
        },
    }

    normalized = server._normalize_legacy_error_payload(payload, 409)

    env = normalized["error_envelope"]
    # canonical fields still normalized
    assert env["code"] == "CONFLICT"
    assert env["retryable"] is False
    assert env["details"]["task_id"] == "ENC-TSK-999"
    # escalation fields preserved end-to-end (the H50 fix)
    assert env["failure_classification"] == "deterministic-governance"
    assert [a["action"] for a in env["recommended_next_actions"]] == [
        "checkout_task",
        "escalate",
    ]


def test_normalize_legacy_error_payload_unknown_envelope_keys_survive():
    """The fix is generic: any additional structured envelope key (not just the two
    H49 fields) survives, so future checkout-service signals are not silently dropped."""
    payload = {
        "success": False,
        "error_envelope": {
            "code": "RATE_LIMITED",
            "message": "slow down",
            "some_future_signal": {"k": "v"},
        },
    }

    normalized = server._normalize_legacy_error_payload(payload, 429)

    assert normalized["error_envelope"]["some_future_signal"] == {"k": "v"}
    # canonical normalization still applied (retryable inferred for RATE_LIMITED)
    assert normalized["error_envelope"]["retryable"] is True
