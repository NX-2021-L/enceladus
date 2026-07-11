"""ENC-TSK-M66: contract tests for tracker.creation_rules (_handle_tracker_creation_rules).

Verifies the dictionary-derived creation_rules response for plan/feature/task
matches the actual required-field / initial-status behavior enforced by
backend/lambda/tracker_mutation/lambda_function.py's _handle_create_record and
_DEFAULT_STATUS (task: title + acceptance_criteria, status 'open'; feature:
title + user_story + acceptance_criteria, status 'planned'; plan: title only,
status 'drafted'), and that the M65 entity.composition sections drive the
attachment_contract for parent_type lookups.
"""
import importlib.util
import json
import pathlib
import sys
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_lambda_creation_rules", MODULE_PATH)
coordination_lambda = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = coordination_lambda
SPEC.loader.exec_module(coordination_lambda)


def _call(record_type, parent_type=None):
    qs = {"record_type": record_type}
    if parent_type:
        qs["parent_type"] = parent_type
    event = {"queryStringParameters": qs}
    resp = coordination_lambda._handle_tracker_creation_rules(event)
    body = json.loads(resp["body"])
    return resp["statusCode"], body


class TrackerCreationRulesContractTests(unittest.TestCase):
    def test_task_matches_actual_create_validation(self):
        status, body = _call("task")
        self.assertEqual(status, 200)
        self.assertEqual(body["valid_initial_status"], "open")
        self.assertIn("title", body["required_fields"])
        self.assertIn("acceptance_criteria", body["required_fields"])
        self.assertNotIn("user_story", body["required_fields"])

    def test_feature_matches_actual_create_validation(self):
        status, body = _call("feature")
        self.assertEqual(status, 200)
        self.assertEqual(body["valid_initial_status"], "planned")
        for field in ("title", "user_story", "acceptance_criteria"):
            self.assertIn(field, body["required_fields"])

    def test_plan_matches_actual_create_validation(self):
        status, body = _call("plan")
        self.assertEqual(status, 200)
        self.assertEqual(body["valid_initial_status"], "drafted")
        self.assertEqual(body["required_fields"], ["title"])

    def test_no_record_id_required(self):
        # AC-1: creation_rules never requires a record_id argument.
        status, body = _call("task")
        self.assertEqual(status, 200)
        self.assertNotIn("record_id", body)

    def test_response_is_dictionary_derived_not_hardcoded(self):
        # AC-2: mutating the bundled dictionary's constraints changes the
        # response, proving derivation rather than a hardcoded table.
        dict_path = pathlib.Path(__file__).with_name("governance_data_dictionary.json")
        original = dict_path.read_text(encoding="utf-8")
        try:
            data = json.loads(original)
            data["entities"]["tracker.plan"]["fields"]["category"] = {
                "type": "string",
                "constraints": {"min_length": 1},
            }
            dict_path.write_text(json.dumps(data), encoding="utf-8")
            status, body = _call("plan")
            self.assertEqual(status, 200)
            self.assertIn("category", body["required_fields"])
        finally:
            dict_path.write_text(original, encoding="utf-8")

    def test_attachment_contract_uses_m65_composition_sections(self):
        status, body = _call("task", parent_type="plan")
        self.assertEqual(status, 200)
        as_child = body["attachment_contract"]["as_child_of"]
        self.assertTrue(as_child["valid"])
        self.assertIn("task", as_child["allowed_child_record_types"])
        self.assertIn("objectives_set", as_child["attachment_mechanism"]["definition"])

    def test_attachment_contract_rejects_invalid_parent(self):
        status, body = _call("plan", parent_type="task")
        self.assertEqual(status, 200)
        as_child = body["attachment_contract"]["as_child_of"]
        self.assertFalse(as_child["valid"])

    def test_unknown_record_type_404(self):
        status, body = _call("not_a_type")
        self.assertEqual(status, 404)
        self.assertIn("plan", body.get("valid_record_types", []))

    def test_missing_record_type_400(self):
        resp = coordination_lambda._handle_tracker_creation_rules({"queryStringParameters": {}})
        self.assertEqual(resp["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
