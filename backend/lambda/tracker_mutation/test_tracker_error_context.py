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


if __name__ == "__main__":
    unittest.main()
