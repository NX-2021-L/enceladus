"""deploy_intake auth/route regression tests (ENC-ISS-039).

Validates that deploy routes accept internal key auth and preserve
cookie-based behavior for browser sessions.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from decimal import Decimal
from botocore.exceptions import ClientError
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "deploy_intake",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
deploy_intake = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(deploy_intake)


def _event(
    *,
    method: str = "GET",
    path: str = "/api/v1/deploy/state/enceladus",
    headers: dict | None = None,
    body: dict | None = None,
    query: dict | None = None,
) -> dict:
    return {
        "requestContext": {"http": {"method": method}},
        "rawPath": path,
        "path": path,
        "headers": headers or {},
        "queryStringParameters": query or {},
        "body": json.dumps(body) if body is not None else None,
    }


class DeployIntakeAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_internal_key = deploy_intake.COORDINATION_INTERNAL_API_KEY
        self._original_internal_key_previous = deploy_intake.COORDINATION_INTERNAL_API_KEY_PREVIOUS
        self._original_internal_keys = deploy_intake.COORDINATION_INTERNAL_API_KEYS
        self._original_sqs_queue_url = deploy_intake.SQS_QUEUE_URL

    def tearDown(self) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = self._original_internal_key
        deploy_intake.COORDINATION_INTERNAL_API_KEY_PREVIOUS = self._original_internal_key_previous
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = self._original_internal_keys
        deploy_intake.SQS_QUEUE_URL = self._original_sqs_queue_url

    def test_cors_allows_internal_key_header(self) -> None:
        headers = deploy_intake._cors_headers()
        self.assertIn("X-Coordination-Internal-Key", headers["Access-Control-Allow-Headers"])

    @patch.object(deploy_intake, "_handle_get_state")
    def test_internal_key_allows_state_route(self, mock_get_state) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_get_state.return_value = deploy_intake._ok({"project_id": "enceladus", "state": "ACTIVE"})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/state/enceladus",
                headers={"X-Coordination-Internal-Key": "test-internal-key"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_state.assert_called_once_with("enceladus")

    @patch.object(deploy_intake, "_handle_get_history")
    def test_internal_key_allows_history_route(self, mock_get_history) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_get_history.return_value = deploy_intake._ok({"project_id": "enceladus", "deployments": []})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/history/enceladus",
                headers={"x-coordination-internal-key": "test-internal-key"},
                query={"limit": "5"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_history.assert_called_once_with("enceladus", 5)

    @patch.object(deploy_intake, "_handle_get_pending")
    def test_internal_key_allows_pending_route(self, mock_get_pending) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_get_pending.return_value = deploy_intake._ok({"project_id": "enceladus", "requests": []})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/pending/enceladus",
                headers={"X-Coordination-Internal-Key": "test-internal-key"},
                query={"limit": "3"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_pending.assert_called_once_with("enceladus", 3)

    @patch.object(deploy_intake, "_handle_trigger")
    def test_internal_key_allows_trigger_route(self, mock_handle_trigger) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_handle_trigger.return_value = deploy_intake._ok({"project_id": "enceladus", "triggered": True})

        resp = deploy_intake.lambda_handler(
            _event(
                method="POST",
                path="/api/v1/deploy/trigger/enceladus",
                headers={"X-Coordination-Internal-Key": "test-internal-key"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_handle_trigger.assert_called_once_with("enceladus")

    @patch.object(deploy_intake, "_handle_get_history")
    def test_history_invalid_limit_defaults(self, mock_get_history) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_get_history.return_value = deploy_intake._ok({"project_id": "enceladus", "deployments": []})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/history/enceladus",
                headers={"X-Coordination-Internal-Key": "test-internal-key"},
                query={"limit": "not-a-number"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_history.assert_called_once_with("enceladus", 10)

    def test_invalid_internal_key_returns_401(self) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "expected-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("expected-key",)
        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/state/enceladus",
                headers={"X-Coordination-Internal-Key": "wrong-key"},
            ),
            None,
        )
        self.assertEqual(resp["statusCode"], 401)
        body = json.loads(resp["body"])
        self.assertIn("Authentication required", body["error"])

    @patch.object(deploy_intake, "_verify_token", return_value={"sub": "user-1"})
    @patch.object(deploy_intake, "_handle_get_state")
    def test_cookie_auth_still_supported(self, mock_get_state, _mock_verify) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "expected-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("expected-key",)
        mock_get_state.return_value = deploy_intake._ok({"project_id": "enceladus", "state": "ACTIVE"})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/state/enceladus",
                headers={"cookie": "enceladus_id_token=test-cookie-token"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_state.assert_called_once_with("enceladus")

    @patch.object(deploy_intake, "_get_s3")
    def test_state_get_404_defaults_to_active(self, mock_get_s3) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("test-internal-key",)
        mock_get_s3.return_value.get_object.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}},
            "GetObject",
        )

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/state/enceladus",
                headers={"X-Coordination-Internal-Key": "test-internal-key"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("state"), "ACTIVE")

    @patch.object(deploy_intake, "_handle_get_state")
    def test_previous_internal_key_allows_state_route(self, mock_get_state) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "active-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEY_PREVIOUS = "previous-key"
        deploy_intake.COORDINATION_INTERNAL_API_KEYS = ("active-key", "previous-key")
        mock_get_state.return_value = deploy_intake._ok({"project_id": "enceladus", "state": "ACTIVE"})

        resp = deploy_intake.lambda_handler(
            _event(
                method="GET",
                path="/api/v1/deploy/state/enceladus",
                headers={"X-Coordination-Internal-Key": "previous-key"},
            ),
            None,
        )

        self.assertEqual(resp["statusCode"], 200)
        mock_get_state.assert_called_once_with("enceladus")

    @patch.object(deploy_intake, "_resolve_deploy_state", return_value=("PAUSED", None))
    @patch.object(deploy_intake, "_get_sqs")
    def test_trigger_paused_does_not_send_sqs(self, mock_get_sqs, _mock_state) -> None:
        deploy_intake.SQS_QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/123/test.fifo"
        resp = deploy_intake._handle_trigger("enceladus")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("project_state"), "PAUSED")
        self.assertFalse(body.get("triggered"))
        mock_get_sqs.assert_not_called()

    @patch.object(deploy_intake, "_resolve_deploy_state", return_value=("ACTIVE", None))
    @patch.object(deploy_intake, "_get_sqs")
    def test_trigger_active_sends_sqs_message(self, mock_get_sqs, _mock_state) -> None:
        deploy_intake.SQS_QUEUE_URL = "https://sqs.us-west-2.amazonaws.com/123/test.fifo"
        mock_get_sqs.return_value.send_message.return_value = {"MessageId": "msg-123"}

        resp = deploy_intake._handle_trigger("enceladus")

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("triggered"))
        self.assertEqual(body.get("message_id"), "msg-123")
        mock_get_sqs.return_value.send_message.assert_called_once()

    def test_response_serializes_decimal_values(self) -> None:
        resp = deploy_intake._response(
            200,
            {"count": Decimal("4"), "ratio": Decimal("1.25")},
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["count"], 4)
        self.assertEqual(body["ratio"], 1.25)


if __name__ == "__main__":
    unittest.main()
