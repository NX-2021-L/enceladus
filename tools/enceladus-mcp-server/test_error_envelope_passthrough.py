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
