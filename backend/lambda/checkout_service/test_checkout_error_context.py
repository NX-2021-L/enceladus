import importlib.util
import json
import os
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "checkout_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(checkout_service)


class CheckoutServiceErrorContextTests(unittest.TestCase):
    def test_checkout_missing_session_id_includes_self_correcting_context(self):
        response = checkout_service._handle_checkout("enceladus", "ENC-TSK-840", {})
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "active_agent_session_id is required in request body")
        details = body["error_envelope"]["details"]
        self.assertEqual(details["required_fields"], ["active_agent_session_id"])
        self.assertIn("github_pr_deploy", details["allowed_transition_types"])
        rank_table = {entry["transition_type"]: entry["rank"] for entry in details["strictness_rank"]}
        self.assertEqual(rank_table["github_pr_deploy"], 0)
        self.assertEqual(details["example_fix"][0]["tool"], "tracker_set")
        self.assertEqual(details["example_fix"][-1]["tool"], "checkout_task")

    @patch.object(checkout_service, "_get_required_transition_type", return_value="github_pr_deploy")
    @patch.object(checkout_service, "_get_task")
    def test_advance_missing_deploy_evidence_includes_full_schema(self, mock_get_task, _mock_required_type):
        mock_get_task.return_value = (
            200,
            {
                "status": "deploy-init",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "codex-agent",
                "components": ["comp-checkout-service"],
            },
        )

        response = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-840",
            {
                "target_status": "deploy-success",
                "provider": "codex-agent",
                "governance_hash": "hash",
            },
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["current_status"], "deploy-init")
        self.assertEqual(details["target_status"], "deploy-success")
        self.assertEqual(
            details["valid_next_statuses"],
            checkout_service.ALLOWED_TRANSITIONS_BY_TYPE["github_pr_deploy"],
        )
        schema = details["required_evidence_schema"]
        self.assertIn("name", schema["required_fields"])
        self.assertIn("head_sha", schema["required_fields"])
        self.assertEqual(
            schema["required_fields"]["status"]["allowed_values"],
            ["completed"],
        )


if __name__ == "__main__":
    unittest.main()
