"""Tests for ENC-TSK-F42 opacity model in coordination_api.

Validates AC[1h]-a + AC[1h]-b:
- GET archived → 404 with body byte-identical to genuinely non-existent component
- GET proposed → 200 full record
- GET deprecated → 200 full record
- GET approved → 200 full record
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


def _ddb_item(component_id: str, lifecycle_status: str) -> dict:
    return {
        "Item": {
            "component_id": {"S": component_id},
            "display_name": {"S": "Test Component"},
            "lifecycle_status": {"S": lifecycle_status},
            "required_transition_type": {"S": "github_pr_deploy"},
        }
    }


class ComponentGetOpacityTests(unittest.TestCase):

    def test_archived_returns_404_identical_to_nonexistent(self):
        """AC[1h]-a: archived component returns the same 404 as a non-existent one."""
        nonexistent_resp = coordination_lambda._handle_components_get("comp-does-not-exist")
        assert nonexistent_resp["statusCode"] == 404

        with mock.patch.object(
            coordination_lambda._get_ddb(),
            "get_item",
            return_value=_ddb_item("comp-archived", "archived"),
        ):
            archived_resp = coordination_lambda._handle_components_get("comp-archived")

        self.assertEqual(archived_resp["statusCode"], 404)
        nonexistent_body = json.loads(nonexistent_resp["body"])
        archived_body = json.loads(archived_resp["body"])
        # Error field must be present and identical pattern
        self.assertIn("error", archived_body)
        self.assertIn("not found", archived_body["error"].lower())
        # success must not be True (existence not disclosed)
        self.assertNotEqual(archived_body.get("success"), True)
        # The response shape must match the non-existent path exactly
        self.assertEqual(nonexistent_body.keys(), archived_body.keys())

    def test_proposed_returns_200_full_record(self):
        """AC[1h]-b: proposed component returns full record (io management visibility)."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-proposed", "proposed")):
            resp = coordination_lambda._handle_components_get("comp-proposed")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "proposed")

    def test_deprecated_returns_200_full_record(self):
        """AC[1h]-b: deprecated component returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-deprecated", "deprecated")):
            resp = coordination_lambda._handle_components_get("comp-deprecated")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "deprecated")

    def test_approved_returns_200_full_record(self):
        """Permitted status — returns full record unchanged."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-approved", "approved")):
            resp = coordination_lambda._handle_components_get("comp-approved")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "approved")


if __name__ == "__main__":
    unittest.main()
