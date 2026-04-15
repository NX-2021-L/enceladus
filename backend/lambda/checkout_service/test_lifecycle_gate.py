"""Tests for ENC-TSK-E10 component lifecycle_status gate in checkout_service.

Validates AC3-1 through AC3-5: _get_components_lifecycle helper + the gate
inside _handle_advance() that blocks on lifecycle_status='proposed' or
'rejected', preserves the active happy path, and demotes 'approved' to
active with a warning.
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


def _ddb_resp(items_by_cid):
    """Build a side_effect callable for ddb.get_item that returns lifecycle_status."""
    def _side(TableName, Key):
        cid = Key["component_id"]["S"]
        meta = items_by_cid.get(cid)
        if meta is None:
            return {}
        item = {"component_id": {"S": cid},
                "transition_type": {"S": meta.get("transition_type", "github_pr_deploy")}}
        if "lifecycle_status" in meta:
            item["lifecycle_status"] = {"S": meta["lifecycle_status"]}
        if "rejection_reason" in meta:
            item["rejection_reason"] = {"S": meta["rejection_reason"]}
        return {"Item": item}
    return _side


class GetComponentsLifecycleTests(unittest.TestCase):

    def test_empty_returns_empty(self):
        self.assertEqual(checkout_lambda._get_components_lifecycle([]), {})

    def test_pre_e08_record_no_lifecycle_defaults_active(self):
        with mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_resp({"comp-x": {}})):
            out = checkout_lambda._get_components_lifecycle(["comp-x"])
        self.assertEqual(out["comp-x"]["lifecycle_status"], "active")

    def test_proposed_returned(self):
        with mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_resp({"comp-x": {"lifecycle_status": "proposed"}})):
            out = checkout_lambda._get_components_lifecycle(["comp-x"])
        self.assertEqual(out["comp-x"]["lifecycle_status"], "proposed")

    def test_rejected_includes_reason(self):
        with mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_resp({"comp-x": {"lifecycle_status": "rejected",
                                                                  "rejection_reason": "scope creep"}})):
            out = checkout_lambda._get_components_lifecycle(["comp-x"])
        self.assertEqual(out["comp-x"]["lifecycle_status"], "rejected")
        self.assertEqual(out["comp-x"]["rejection_reason"], "scope creep")

    def test_missing_component_omitted(self):
        with mock.patch.object(checkout_lambda._ddb, "get_item", return_value={}):
            out = checkout_lambda._get_components_lifecycle(["comp-missing"])
        self.assertEqual(out, {})


class HandleAdvanceLifecycleGateTests(unittest.TestCase):
    """Higher-level tests exercising the lifecycle gate inside _handle_advance."""

    def _patch_task(self, components, transition_type="github_pr_deploy",
                    status="in-progress", checked_out=True):
        task = {
            "record_id": "ENC-TSK-FAKE",
            "components": components,
            "transition_type": transition_type,
            "status": status,
            "active_agent_session": checked_out,
            "active_agent_session_id": "sess-abc" if checked_out else "",
        }
        return mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task))

    def _advance_body(self, target="coding-complete"):
        return {
            "target_status": target,
            "provider": "test-agent",
            "transition_evidence": {},
            "governance_hash": "h",
        }

    def test_proposed_blocks_with_named_component(self):
        with self._patch_task(components=["comp-foo"]):
            with mock.patch.object(checkout_lambda._ddb, "get_item",
                                   side_effect=_ddb_resp({"comp-foo": {"lifecycle_status": "proposed"}})):
                resp = checkout_lambda._handle_advance("enceladus", "ENC-TSK-FAKE", self._advance_body())
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        body_str = json.dumps(body)
        self.assertIn("comp-foo", body_str)
        self.assertIn("component_not_approved", body_str)

    def test_mixed_active_and_proposed_blocks_citing_proposed(self):
        with self._patch_task(components=["comp-active", "comp-pending"]):
            with mock.patch.object(checkout_lambda._ddb, "get_item",
                                   side_effect=_ddb_resp({
                                       "comp-active": {"lifecycle_status": "active"},
                                       "comp-pending": {"lifecycle_status": "proposed"},
                                   })):
                resp = checkout_lambda._handle_advance("enceladus", "ENC-TSK-FAKE", self._advance_body())
        self.assertEqual(resp["statusCode"], 400)
        body_str = json.dumps(json.loads(resp["body"]))
        self.assertIn("comp-pending", body_str)
        self.assertNotIn('"comp-active"', body_str.replace("comp-active-x", ""))

    def test_rejected_blocks_with_reason_echoed(self):
        with self._patch_task(components=["comp-bad"]):
            with mock.patch.object(checkout_lambda._ddb, "get_item",
                                   side_effect=_ddb_resp({"comp-bad": {
                                       "lifecycle_status": "rejected",
                                       "rejection_reason": "duplicate of comp-foo",
                                   }})):
                resp = checkout_lambda._handle_advance("enceladus", "ENC-TSK-FAKE", self._advance_body())
        self.assertEqual(resp["statusCode"], 400)
        body_str = json.dumps(json.loads(resp["body"]))
        self.assertIn("component_rejected", body_str)
        self.assertIn("duplicate of comp-foo", body_str)

    def test_only_active_proceeds_past_lifecycle_gate(self):
        # Only-active should NOT trip the lifecycle gate. It may still trip
        # other downstream gates (subtask, evidence shape) — we only assert
        # the lifecycle gate did not produce the named-error structure.
        with self._patch_task(components=["comp-active"]):
            with mock.patch.object(checkout_lambda._ddb, "get_item",
                                   side_effect=_ddb_resp({"comp-active": {"lifecycle_status": "active"}})):
                resp = checkout_lambda._handle_advance("enceladus", "ENC-TSK-FAKE", self._advance_body())
        body_str = json.dumps(json.loads(resp["body"]))
        self.assertNotIn("component_not_approved", body_str)
        self.assertNotIn("component_rejected", body_str)

    def test_user_initiated_bypasses_proposed_block(self):
        body = self._advance_body()
        body["user_initiated"] = True
        with self._patch_task(components=["comp-pending"]):
            with mock.patch.object(checkout_lambda._ddb, "get_item",
                                   side_effect=_ddb_resp({"comp-pending": {"lifecycle_status": "proposed"}})):
                resp = checkout_lambda._handle_advance("enceladus", "ENC-TSK-FAKE", body)
        body_str = json.dumps(json.loads(resp["body"]))
        self.assertNotIn("component_not_approved", body_str)


if __name__ == "__main__":
    unittest.main()
