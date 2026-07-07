"""ENC-TSK-L77 — v3 component policy evidence gates."""

from __future__ import annotations

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


def _deploy_evidence() -> dict:
    return {
        "id": 123,
        "name": "Deploy Lambda Artifacts (Gen2)",
        "run_id": 456,
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-07-07T04:00:00Z",
        "completed_at": "2026-07-07T04:01:00Z",
    }


class ExternalDeployEvidenceGateTests(unittest.TestCase):
    @patch.object(checkout_service, "_get_components_lifecycle", return_value={"comp-external": {"lifecycle_status": "active"}})
    @patch.object(checkout_service, "_get_component_required_transition_types", return_value={"external_deploy"})
    @patch.object(checkout_service, "_get_required_transition_type", return_value="external_deploy")
    @patch.object(checkout_service, "_get_task")
    def test_deploy_success_requires_external_deploy_evidence(self, mock_get_task, _required, _policies, _lifecycle):
        mock_get_task.return_value = (
            200,
            {
                "status": "deploy-init",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "test-session",
                "components": ["comp-external"],
            },
        )

        resp = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-EXT",
            {
                "target_status": "deploy-success",
                "provider": "test-session",
                "transition_evidence": {"deploy_evidence": _deploy_evidence()},
            },
        )

        self.assertEqual(resp["statusCode"], 422)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertIn("external_deploy_evidence", envelope["message"])
        self.assertIn("comp_external_id", envelope["details"]["required_fields"][0])

    @patch.object(checkout_service, "_get_components_lifecycle", return_value={"comp-external": {"lifecycle_status": "active"}})
    @patch.object(checkout_service, "_get_component_required_transition_types", return_value={"external_deploy"})
    @patch.object(checkout_service, "_get_required_transition_type", return_value="external_deploy")
    @patch.object(checkout_service, "_get_task")
    def test_deploy_success_rejects_short_retrieval_steps(self, mock_get_task, _required, _policies, _lifecycle):
        mock_get_task.return_value = (
            200,
            {
                "status": "deploy-init",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "test-session",
                "components": ["comp-external"],
            },
        )

        resp = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-EXT",
            {
                "target_status": "deploy-success",
                "provider": "test-session",
                "transition_evidence": {
                    "deploy_evidence": _deploy_evidence(),
                    "external_deploy_evidence": {
                        "comp_external_id": "cf-resource-1",
                        "retrieval_steps": "too short",
                    },
                },
            },
        )

        self.assertEqual(resp["statusCode"], 422)
        self.assertIn("at least 20", json.loads(resp["body"])["error_envelope"]["message"])


class DocumentationEvidenceGateTests(unittest.TestCase):
    def _task_sequence(self):
        initial = {
            "status": "coding-complete",
            "transition_type": "no_code",
            "active_agent_session": True,
            "active_agent_session_id": "test-session",
            "components": ["comp-docs"],
        }
        updated = {**initial, "status": "closed"}
        return [(200, initial), (200, updated)]

    @patch.object(checkout_service, "_get_components_lifecycle", return_value={"comp-docs": {"lifecycle_status": "active"}})
    @patch.object(checkout_service, "_get_component_required_transition_types", return_value={"documentation"})
    @patch.object(checkout_service, "_get_required_transition_type", return_value="documentation")
    @patch.object(checkout_service, "_closed_documentation_evidence_doc_ids", return_value={"DOC-ABC123"})
    @patch.object(checkout_service, "_get_document_metadata", return_value=(200, {"updated_at": "2026-07-07T03:00:00Z"}))
    @patch.object(checkout_service, "_get_task")
    def test_closed_rejects_stale_reused_doc_id(
        self, mock_get_task, _doc, _used, _required, _policies, _lifecycle
    ):
        mock_get_task.return_value = self._task_sequence()[0]

        resp = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-DOC",
            {
                "target_status": "closed",
                "provider": "test-session",
                "transition_evidence": {
                    "no_code_evidence": "Verified the docstore update path.",
                    "documentation_evidence": ["DOC-ABC123"],
                },
            },
        )

        self.assertEqual(resp["statusCode"], 422)
        details = json.loads(resp["body"])["error_envelope"]["details"]
        self.assertEqual(details["non_qualifying_doc_ids"], ["DOC-ABC123"])

    @patch.object(checkout_service, "_get_components_lifecycle", return_value={"comp-docs": {"lifecycle_status": "active"}})
    @patch.object(checkout_service, "_release_task")
    @patch.object(checkout_service, "_set_task_field", return_value=(200, {"success": True}))
    @patch.object(checkout_service, "_get_component_required_transition_types", return_value={"documentation"})
    @patch.object(checkout_service, "_get_required_transition_type", return_value="documentation")
    @patch.object(checkout_service, "_closed_documentation_evidence_doc_ids", return_value=set())
    @patch.object(checkout_service, "_get_document_metadata", return_value=(200, {"updated_at": "2026-07-07T03:00:00Z"}))
    @patch.object(checkout_service, "_get_task")
    def test_closed_accepts_novel_doc_id(
        self, mock_get_task, _doc, _used, _required, _policies, mock_set, mock_release, _lifecycle
    ):
        mock_get_task.side_effect = self._task_sequence()

        resp = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-DOC",
            {
                "target_status": "closed",
                "provider": "test-session",
                "transition_evidence": {
                    "no_code_evidence": "Verified the docstore update path.",
                    "documentation_evidence": ["DOC-DEF123"],
                },
            },
        )

        self.assertEqual(resp["statusCode"], 200)
        transition_evidence = mock_set.call_args.kwargs["transition_evidence"]
        self.assertEqual(transition_evidence["documentation_evidence"], ["DOC-DEF123"])
        mock_release.assert_called_once()


if __name__ == "__main__":
    unittest.main()
