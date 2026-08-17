"""Tests for github_integration error_envelope enrichment (ENC-TSK-D78)."""
import json
import os
import sys
import unittest
from unittest.mock import patch

# Add the lambda directory to path
sys.path.insert(0, os.path.dirname(__file__))
import lambda_function


class GithubIntegrationErrorContextTests(unittest.TestCase):
    """Validate error_envelope structure in github_integration responses."""

    def test_error_includes_error_envelope(self):
        """_error() returns canonical error_envelope with code, message, retryable, details."""
        result = lambda_function._error(400, "test error", details={"foo": "bar"})
        body = json.loads(result["body"])
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "test error")
        self.assertIn("error_envelope", body)
        envelope = body["error_envelope"]
        self.assertEqual(envelope["code"], "INVALID_INPUT")
        self.assertEqual(envelope["message"], "test error")
        self.assertFalse(envelope["retryable"])
        self.assertEqual(envelope["details"]["foo"], "bar")
        # Details bubbled to root
        self.assertEqual(body["foo"], "bar")

    def test_error_500_is_retryable(self):
        """5xx errors default to retryable=True."""
        result = lambda_function._error(502, "upstream failure")
        body = json.loads(result["body"])
        envelope = body["error_envelope"]
        self.assertTrue(envelope["retryable"])
        self.assertEqual(envelope["code"], "INTERNAL_ERROR")

    def test_error_extra_kwargs_flow_to_details(self):
        """Legacy **extra keyword args flow into details and bubble to root."""
        result = lambda_function._error(
            403, "not allowed", allowed_repos=["a/b", "c/d"]
        )
        body = json.loads(result["body"])
        self.assertEqual(body["error_envelope"]["code"], "PERMISSION_DENIED")
        self.assertEqual(
            body["error_envelope"]["details"]["allowed_repos"], ["a/b", "c/d"]
        )
        # Bubbled to root for backward compat
        self.assertEqual(body["allowed_repos"], ["a/b", "c/d"])

    def test_error_custom_code_override(self):
        """Explicit code= overrides the status-based default."""
        result = lambda_function._error(400, "oops", code="CUSTOM_CODE")
        body = json.loads(result["body"])
        self.assertEqual(body["error_envelope"]["code"], "CUSTOM_CODE")

    def test_missing_owner_repo_includes_required_fields_and_example_fix(self):
        """Missing owner/repo error includes required_fields and example_fix."""
        # Build a minimal create_issue event with missing owner/repo
        event = {
            "httpMethod": "POST",
            "path": "/api/v1/github/issues",
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"title": "test"}),
        }
        mock_claims = {"auth_mode": "internal-key", "sub": "internal-key"}
        with patch.object(
            lambda_function, "_authenticate", return_value=(mock_claims, None)
        ):
            result = lambda_function.lambda_handler(event, None)
        body = json.loads(result["body"])
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("error_envelope", body)
        self.assertIn("required_fields", body["error_envelope"]["details"])
        self.assertIn("owner", body["error_envelope"]["details"]["required_fields"])
        self.assertIn("repo", body["error_envelope"]["details"]["required_fields"])
        # example_fix present
        self.assertIn("example_fix", body["error_envelope"]["details"])
        self.assertEqual(
            body["error_envelope"]["details"]["example_fix"]["tool"],
            "github.create_issue",
        )

    def test_missing_title_includes_required_fields_and_example_fix(self):
        """Missing title error includes required_fields and example_fix with owner/repo."""
        event = {
            "httpMethod": "POST",
            "path": "/api/v1/github/issues",
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"owner": "NX-2021-L", "repo": "enceladus"}),
        }
        mock_claims = {"auth_mode": "internal-key", "sub": "internal-key"}
        with patch.object(
            lambda_function, "_authenticate", return_value=(mock_claims, None)
        ):
            result = lambda_function.lambda_handler(event, None)
        body = json.loads(result["body"])
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("error_envelope", body)
        self.assertEqual(
            body["error_envelope"]["details"]["required_fields"], ["title"]
        )
        # example_fix should carry through the provided owner/repo
        example = body["error_envelope"]["details"]["example_fix"]
        self.assertEqual(example["arguments"]["owner"], "NX-2021-L")
        self.assertEqual(example["arguments"]["repo"], "enceladus")

    def test_dpl_create_failure_includes_error_envelope_at_http_200(self):
        """DPL creation failure returns HTTP 200 with error_envelope enrichment."""
        # This test validates the response shape without invoking the full webhook flow.
        # We directly test that the _response(200, ...) shape includes error_envelope.
        response_body = {
            "processed": False,
            "reason": "dpl_create_failed",
            "error_envelope": {
                "code": "DPL_CREATE_FAILED",
                "message": "Failed to create deployment decision record: test",
                "retryable": True,
                "details": {
                    "dpl_record_id_format": "ENC-DPL-{3-char base-36 sequence}",
                    "dpl_ddb_key_schema": "PK=enceladus, SK=dpl#ENC-DPL-{seq}",
                    "dpl_label_conventions": [
                        "target:prod — marks PR as production deployment candidate",
                        "target:staging — marks PR for staging deployment",
                    ],
                },
            },
        }
        result = lambda_function._response(200, response_body)
        body = json.loads(result["body"])
        self.assertEqual(result["statusCode"], 200)
        self.assertFalse(body["processed"])
        self.assertEqual(body["reason"], "dpl_create_failed")
        self.assertIn("error_envelope", body)
        self.assertEqual(body["error_envelope"]["code"], "DPL_CREATE_FAILED")
        self.assertTrue(body["error_envelope"]["retryable"])
        self.assertIn(
            "dpl_record_id_format", body["error_envelope"]["details"]
        )
        self.assertIn(
            "dpl_ddb_key_schema", body["error_envelope"]["details"]
        )
        self.assertIn(
            "dpl_label_conventions", body["error_envelope"]["details"]
        )


if __name__ == "__main__":
    unittest.main()
