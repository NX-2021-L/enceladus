"""Tests for ENC-TSK-F46 AC[2]: opacity model in coordination_api.

Validates that the archived-component response is byte-identical to a
genuine non-existent component response:
- GET archived component -> 404 with response bytes == GET nonexistent component
- No dynamic fields (request IDs, timestamps) leak the distinction
- GET proposed -> 200 full record (not opaque)
- GET deprecated -> 200 full record (not opaque)
- GET approved -> 200 full record (not opaque)
- All 8 lifecycle statuses correctly classified

Opacity design per DOC-546B896390EA §5: archived components must be
indistinguishable from non-existent components at the HTTP response layer.
This prevents existence enumeration attacks against the component registry.
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

    def _get_nonexistent_response(self):
        """Capture the baseline 404 for a genuinely non-existent component."""
        resp = coordination_lambda._handle_components_get("comp-definitely-does-not-exist-xyz")
        self.assertEqual(resp["statusCode"], 404, "baseline 404 must come back for non-existent")
        return resp

    def test_archived_returns_404_identical_to_nonexistent(self):
        """AC[2]: archived -> 404, response body keys match non-existent pattern."""
        nonexistent_resp = self._get_nonexistent_response()

        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(
            ddb, "get_item",
            return_value=_ddb_item("comp-archived", "archived"),
        ):
            archived_resp = coordination_lambda._handle_components_get("comp-archived")

        self.assertEqual(archived_resp["statusCode"], 404)

        nonexistent_body = json.loads(nonexistent_resp["body"])
        archived_body = json.loads(archived_resp["body"])

        # Key sets must be identical — no extra fields leaking status.
        self.assertEqual(
            set(nonexistent_body.keys()),
            set(archived_body.keys()),
            "Key sets differ: archived response leaks existence information",
        )
        self.assertIn("not found", archived_body.get("error", "").lower())
        self.assertNotEqual(archived_body.get("success"), True)

    def test_archived_response_bytes_identical_to_nonexistent_normalized(self):
        """Normalized response bytes: only component_id differs — no dynamic fields."""
        nonexistent_resp = self._get_nonexistent_response()

        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(
            ddb, "get_item",
            return_value=_ddb_item("comp-archived-byte-check", "archived"),
        ):
            archived_resp = coordination_lambda._handle_components_get(
                "comp-archived-byte-check"
            )

        self.assertEqual(archived_resp["statusCode"], 404)

        # Normalize component IDs, then compare bodies byte-for-byte.
        normalized_nonexistent = nonexistent_resp["body"].replace(
            "comp-definitely-does-not-exist-xyz", "<COMP_ID>"
        )
        normalized_archived = archived_resp["body"].replace(
            "comp-archived-byte-check", "<COMP_ID>"
        )
        self.assertEqual(
            normalized_nonexistent,
            normalized_archived,
            (
                "Normalized response bodies differ — archived response may be leaking "
                "existence information via dynamic fields (timestamps, request IDs, etc.)"
            ),
        )

    def test_archived_body_does_not_disclose_lifecycle_status(self):
        """Archived 404 body must NOT include lifecycle_status or component details."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(
            ddb, "get_item",
            return_value=_ddb_item("comp-archived", "archived"),
        ):
            resp = coordination_lambda._handle_components_get("comp-archived")
        body = json.loads(resp["body"])
        body_str = json.dumps(body)
        # Must not reveal 'archived' status (beyond the comp ID in the error message).
        body_without_id = body_str.replace("comp-archived", "")
        self.assertNotIn("archived", body_without_id.lower())
        # Must not have a 'component' key revealing registry details.
        self.assertNotIn("component", body)
        self.assertNotEqual(body.get("success"), True)

    def test_archived_body_contains_not_found_error(self):
        """Archived 404 body has a 'not found' error — same pattern as non-existent."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(
            ddb, "get_item",
            return_value=_ddb_item("comp-archived-2", "archived"),
        ):
            resp = coordination_lambda._handle_components_get("comp-archived-2")
        body = json.loads(resp["body"])
        self.assertIn("error", body)
        self.assertIn("not found", body["error"].lower())

    def test_proposed_returns_200_full_record(self):
        """proposed: not opaque — returns full record (io management visibility)."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-proposed", "proposed")):
            resp = coordination_lambda._handle_components_get("comp-proposed")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "proposed")

    def test_deprecated_returns_200_full_record(self):
        """deprecated: not opaque — returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-deprecated", "deprecated")):
            resp = coordination_lambda._handle_components_get("comp-deprecated")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "deprecated")

    def test_approved_returns_200_full_record(self):
        """approved: permitted status — returns full record unchanged."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-approved", "approved")):
            resp = coordination_lambda._handle_components_get("comp-approved")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body["component"]["lifecycle_status"], "approved")

    def test_designed_returns_200_full_record(self):
        """designed: permitted status — returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-designed", "designed")):
            resp = coordination_lambda._handle_components_get("comp-designed")
        self.assertEqual(resp["statusCode"], 200)

    def test_development_returns_200_full_record(self):
        """development: permitted status — returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-dev", "development")):
            resp = coordination_lambda._handle_components_get("comp-dev")
        self.assertEqual(resp["statusCode"], 200)

    def test_production_returns_200_full_record(self):
        """production: permitted status — returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-prod", "production")):
            resp = coordination_lambda._handle_components_get("comp-prod")
        self.assertEqual(resp["statusCode"], 200)

    def test_code_red_returns_200_full_record(self):
        """code-red: permitted status — returns full record."""
        ddb = coordination_lambda._get_ddb()
        with mock.patch.object(ddb, "get_item",
                               return_value=_ddb_item("comp-cr", "code-red")):
            resp = coordination_lambda._handle_components_get("comp-cr")
        self.assertEqual(resp["statusCode"], 200)

    def test_archived_advance_also_opaque(self):
        """Opacity extends to advance calls: archived -> 404 on advance attempt."""
        with mock.patch.object(
            coordination_lambda, "_get_component_record",
            return_value={"component_id": "comp-archived", "lifecycle_status": "archived"},
        ), mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True):
            event = {"httpMethod": "POST", "body": json.dumps({"target_status": "production"})}
            resp = coordination_lambda._handle_components_advance(
                "comp-archived", event, {"auth_mode": "internal-key", "sub": "agent"}
            )
        self.assertEqual(resp["statusCode"], 404)


if __name__ == "__main__":
    unittest.main()
