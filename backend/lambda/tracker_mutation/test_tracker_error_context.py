import importlib.util
import json
import os
import unittest
from unittest.mock import MagicMock, patch


_SPEC = importlib.util.spec_from_file_location(
    "tracker_mutation",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(tracker_mutation)


def _mock_ddb_item(status="open", record_type="task", item_id="ENC-TSK-001", extra=None):
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"{record_type}#{item_id}"},
        "item_id": {"S": item_id},
        "status": {"S": status},
        "record_type": {"S": record_type},
        "sync_version": {"N": "1"},
        "history": {"L": []},
    }
    if extra:
        item.update(extra)
    return item


class TrackerMutationErrorContextTests(unittest.TestCase):
    def test_create_task_missing_acceptance_criteria_includes_governed_context(self):
        response = tracker_mutation._handle_create_record(
            "enceladus",
            "task",
            {"title": "Task without criteria"},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["missing_required_fields"], ["acceptance_criteria"])
        self.assertEqual(details["record_type"], "task")
        self.assertEqual(details["allowed_values"]["priority"], ["P0", "P1", "P2", "P3"])
        self.assertIn("implementation", details["allowed_values"]["category"])
        self.assertIn("acceptance_criteria", details["governed_rules"][0])

    @patch.object(tracker_mutation, "_get_record_raw")
    @patch.object(tracker_mutation, "_get_ddb")
    def test_tracker_set_invalid_transition_type_includes_strictness_rank(
        self,
        mock_get_ddb,
        mock_get_record_raw,
    ):
        mock_get_ddb.return_value = MagicMock()
        mock_get_record_raw.return_value = _mock_ddb_item()

        response = tracker_mutation._handle_update_field(
            "enceladus",
            "task",
            "ENC-TSK-001",
            {"field": "transition_type", "value": "manual"},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["field"], "transition_type")
        self.assertIn("github_pr_deploy", details["allowed_values"])
        rank_table = {entry["transition_type"]: entry["rank"] for entry in details["strictness_rank"]}
        self.assertEqual(rank_table["github_pr_deploy"], 0)
        self.assertEqual(rank_table["no_code"], 3)


    @patch.object(tracker_mutation, "ENABLE_LESSON_PRIMITIVE", True)
    def test_lesson_creation_missing_evidence_chain_includes_gate_thresholds(self):
        """Lesson creation error includes gate thresholds when evidence_chain is missing."""
        response = tracker_mutation._handle_create_record(
            "enceladus",
            "lesson",
            {
                "title": "Test lesson",
                "observation": "Observed pattern X",
                "insight": "Pattern X implies Y",
                "pillar_scores": {
                    "efficiency": 0.5,
                    "human_protection": 0.6,
                    "intention": 0.4,
                    "alignment": 0.5,
                },
                # evidence_chain intentionally omitted
            },
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["missing_required_fields"], ["evidence_chain"])
        self.assertEqual(details["record_type"], "lesson")
        # Verify gate thresholds are present in governed_rules
        rules_text = " ".join(details["governed_rules"])
        self.assertIn("min_evidence_chain", rules_text)
        self.assertIn("proposed", rules_text)
        self.assertIn("Gate thresholds by target status", details["governed_rules"][1])

    @patch.object(tracker_mutation, "ENABLE_LESSON_PRIMITIVE", True)
    @patch.object(tracker_mutation, "_get_record_raw")
    @patch.object(tracker_mutation, "_get_ddb")
    def test_lesson_status_transition_includes_gate_requirements(
        self,
        mock_get_ddb,
        mock_get_record_raw,
    ):
        """Lesson status transition error includes gate requirements for the target status."""
        mock_get_ddb.return_value = MagicMock()
        mock_get_record_raw.return_value = _mock_ddb_item(
            status="draft",
            record_type="lesson",
            item_id="ENC-LSN-001",
        )

        # Attempt an invalid transition: draft -> active (must go draft -> proposed first)
        response = tracker_mutation._handle_update_field(
            "enceladus",
            "lesson",
            "ENC-LSN-001",
            {"field": "status", "value": "active"},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["field"], "status")
        self.assertEqual(details["record_type"], "lesson")
        # The target "active" has gate requirements — verify they appear
        rules_text = " ".join(details["governed_rules"])
        self.assertIn("Gate requirements for 'active'", rules_text)
        self.assertIn("min_pillar_composite", rules_text)
        self.assertIn("min_resonance", rules_text)
        self.assertIn("min_confidence", rules_text)


if __name__ == "__main__":
    unittest.main()
