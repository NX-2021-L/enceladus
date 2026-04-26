"""Tests for ENC-TSK-F42 opacity model gate in checkout_service._handle_checkout.

Validates AC[2]-a, AC[2]-b, AC[2]-c:
- checkout.task archived component → 404 (identical to non-existent)
- checkout.task proposed component → 400 with descriptive message containing component_id
- checkout.task deprecated component → 400 with descriptive message
- checkout.task approved / development / production → proceeds normally (permitted)
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)


def _make_task(components, transition_type="github_pr_deploy"):
    return {
        "task_id": "ENC-TSK-TEST",
        "status": "open",
        "transition_type": transition_type,
        "components": components,
    }


def _ddb_lifecycle_side_effect(component_lifecycle_map):
    """Return a ddb.get_item side_effect that answers with lifecycle data."""
    def _side(TableName, Key):
        cid = Key["component_id"]["S"]
        ls = component_lifecycle_map.get(cid)
        if ls is None:
            return {}
        return {
            "Item": {
                "component_id": {"S": cid},
                "lifecycle_status": {"S": ls},
                "required_transition_type": {"S": "github_pr_deploy"},
            }
        }
    return _side


class CheckoutOpacityGateTests(unittest.TestCase):

    def _call_checkout(self, components, lifecycle_map):
        body = {"active_agent_session_id": "test-agent-session"}
        task = _make_task(components)
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect(lifecycle_map)):
            return checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)

    def test_archived_component_returns_404(self):
        """AC[2]-a: checkout against archived component returns 404."""
        resp = self._call_checkout(
            ["comp-archived"],
            {"comp-archived": "archived"},
        )
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertNotEqual(body.get("success"), True)

    def test_archived_404_body_matches_nonexistent_pattern(self):
        """AC[2]-a: archived 404 body says 'not found', identical shape to non-existent."""
        resp = self._call_checkout(
            ["comp-archived"],
            {"comp-archived": "archived"},
        )
        body = json.loads(resp["body"])
        self.assertIn("not found", body.get("error", "").lower())

    def test_proposed_component_returns_400_with_component_id(self):
        """AC[2]-b: proposed component returns 400 with component_id in message."""
        resp = self._call_checkout(
            ["comp-proposed"],
            {"comp-proposed": "proposed"},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("comp-proposed", json.dumps(body))

    def test_deprecated_component_returns_400_with_component_id(self):
        """AC[2]-b: deprecated component returns 400 with component_id in message."""
        resp = self._call_checkout(
            ["comp-deprecated"],
            {"comp-deprecated": "deprecated"},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("comp-deprecated", json.dumps(body))

    def test_approved_component_passes_gate(self):
        """AC[2]-c: approved (permitted) component passes the opacity gate."""
        with mock.patch.object(checkout_lambda, "_get_task",
                               return_value=(200, _make_task(["comp-approved"]))), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect(
                                   {"comp-approved": "approved"})), \
             mock.patch.object(checkout_lambda, "_checkout_task",
                               return_value=(200, {"governance_hash": "gh"})), \
             mock.patch.object(checkout_lambda, "_set_task_field",
                               return_value=(200, {})), \
             mock.patch.object(checkout_lambda, "_get_task",
                               return_value=(200, _make_task(["comp-approved"]))):
            body = {"active_agent_session_id": "test-agent-session"}
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        # Must not be blocked by the opacity gate (200 or pass-through)
        self.assertNotEqual(resp["statusCode"], 404)
        self.assertNotEqual(resp["statusCode"], 400)

    def test_development_and_production_pass_gate(self):
        """AC[2]-c: development and production statuses proceed normally."""
        for ls in ("development", "production"):
            with self.subTest(lifecycle_status=ls):
                with mock.patch.object(checkout_lambda, "_get_task",
                                       return_value=(200, _make_task([f"comp-{ls}"]))), \
                     mock.patch.object(checkout_lambda._ddb, "get_item",
                                       side_effect=_ddb_lifecycle_side_effect(
                                           {f"comp-{ls}": ls})), \
                     mock.patch.object(checkout_lambda, "_checkout_task",
                                       return_value=(200, {"governance_hash": "gh"})), \
                     mock.patch.object(checkout_lambda, "_set_task_field",
                                       return_value=(200, {})), \
                     mock.patch.object(checkout_lambda, "_get_task",
                                       return_value=(200, _make_task([f"comp-{ls}"]))):
                    body = {"active_agent_session_id": "test-agent-session"}
                    resp = checkout_lambda._handle_checkout(
                        "enceladus", "ENC-TSK-TEST", body
                    )
                self.assertNotIn(resp["statusCode"], (404, 400))


if __name__ == "__main__":
    unittest.main()
