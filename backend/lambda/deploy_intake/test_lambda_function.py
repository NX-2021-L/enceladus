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

    def tearDown(self) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = self._original_internal_key

    def test_cors_allows_internal_key_header(self) -> None:
        headers = deploy_intake._cors_headers()
        self.assertIn("X-Coordination-Internal-Key", headers["Access-Control-Allow-Headers"])

    @patch.object(deploy_intake, "_handle_get_state")
    def test_internal_key_allows_state_route(self, mock_get_state) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "test-internal-key"
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

    def test_invalid_internal_key_returns_401(self) -> None:
        deploy_intake.COORDINATION_INTERNAL_API_KEY = "expected-key"
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


if __name__ == "__main__":
    unittest.main()
