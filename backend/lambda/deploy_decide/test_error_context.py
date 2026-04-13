"""Tests for deploy_decide error_envelope enrichment (ENC-TSK-D79)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import lambda_function


class DeployDecideErrorContextTests(unittest.TestCase):
    def test_missing_pr_number_includes_envelope_details(self):
        """Missing pr_number returns error_envelope with required_fields and example_fix."""
        result = lambda_function._error(
            400, "pr_number is required",
            required_fields=["pr_number", "action"],
            allowed_actions=["approve", "divert", "revert"],
            example_fix={"tool": "deploy.decide", "arguments": {"pr_number": "123", "action": "approve"}},
        )
        body = json.loads(result["body"])
        self.assertIn("error_envelope", body)
        details = body["error_envelope"]["details"]
        self.assertIn("required_fields", details)
        self.assertIn("example_fix", details)
        self.assertIn("allowed_actions", details)

    def test_invalid_action_includes_allowed_actions(self):
        """Error includes allowed_actions list for invalid action."""
        result = lambda_function._error(
            400, "Invalid action",
            allowed_actions=["approve", "divert", "revert"],
        )
        body = json.loads(result["body"])
        details = body["error_envelope"]["details"]
        self.assertEqual(details["allowed_actions"], ["approve", "divert", "revert"])
