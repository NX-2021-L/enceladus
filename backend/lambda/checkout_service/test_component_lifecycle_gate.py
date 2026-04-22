"""Tests for ENC-TSK-F46 AC[4]: checkout response for each of 8 lifecycle statuses.

Covers the FTR-076 v2 / ENC-ISS-172 component lifecycle gate in checkout_service:

The 8 lifecycle statuses and their expected checkout responses:
  OPAQUE statuses (checkout -> 404):
    - archived

  BLOCKED statuses (checkout -> 400):
    - proposed
    - deprecated

  PERMITTED statuses (checkout -> proceeds normally):
    - approved
    - designed
    - development
    - production
    - code-red

Per DOC-546B896390EA §6 / ENC-ISS-172: the checkout_service validates
task.transition_type against the component registry BEFORE writing any
checkout lock, status mutation, or CAI token. If a component is in an
OPAQUE or BLOCKED lifecycle status, checkout fails fast.

Related: ENC-ISS-172, ENC-TSK-C15, ENC-FTR-076 v2
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
    """Return a ddb.get_item side_effect answering with lifecycle + required_transition_type."""
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


class CheckoutLifecycleGateAllStatusesTests(unittest.TestCase):
    """Checkout response for each of the 8 lifecycle statuses (ENC-TSK-F46 AC[4])."""

    def _call_checkout(self, lifecycle_status):
        cid = f"comp-{lifecycle_status.replace('-', '_')}"
        task = _make_task([cid])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect({cid: lifecycle_status})):
            return checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)

    # ---- OPAQUE status: archived -> 404 ----

    def test_archived_component_returns_404(self):
        """archived: checkout returns 404 (opaque — indistinguishable from non-existent)."""
        resp = self._call_checkout("archived")
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertNotEqual(body.get("success"), True)
        self.assertIn("not found", body.get("error", "").lower())

    def test_archived_checkout_body_says_not_found(self):
        """archived 404 body contains 'not found' error — identical pattern to non-existent."""
        resp = self._call_checkout("archived")
        body = json.loads(resp["body"])
        self.assertIn("not found", body.get("error", "").lower())

    # ---- BLOCKED statuses: proposed, deprecated -> 400 ----

    def test_proposed_component_returns_400(self):
        """proposed: checkout returns 400 (blocked — component not yet approved)."""
        resp = self._call_checkout("proposed")
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertNotEqual(body.get("success"), True)

    def test_proposed_checkout_body_contains_component_id(self):
        """proposed 400 body must contain the component_id for operator diagnosis."""
        cid = "comp-proposed"
        task = _make_task([cid])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect({cid: "proposed"})):
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn(cid, json.dumps(json.loads(resp["body"])))

    def test_deprecated_component_returns_400(self):
        """deprecated: checkout returns 400 (blocked — end-of-life component)."""
        resp = self._call_checkout("deprecated")
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertNotEqual(body.get("success"), True)

    def test_deprecated_checkout_body_contains_component_id(self):
        """deprecated 400 body must contain the component_id for operator diagnosis."""
        cid = "comp-deprecated"
        task = _make_task([cid])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect({cid: "deprecated"})):
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        self.assertEqual(resp["statusCode"], 400)
        self.assertIn(cid, json.dumps(json.loads(resp["body"])))

    # ---- PERMITTED statuses: approved, designed, development, production, code-red -> not blocked ----

    def _assert_permitted_status_not_blocked(self, lifecycle_status):
        """Helper: permitted status must not return 400 or 404 from the lifecycle gate."""
        resp = self._call_checkout(lifecycle_status)
        body = json.loads(resp["body"])
        body_str = json.dumps(body)
        # Must not be blocked by the opacity or lifecycle gate.
        self.assertNotEqual(
            resp["statusCode"], 404,
            f"lifecycle_status={lifecycle_status!r} returned 404 — must not be OPAQUE",
        )
        # Must not be blocked by the lifecycle gate (may still fail for other
        # downstream reasons, e.g. transition_type mismatch — that is acceptable).
        self.assertNotIn(
            "component_lifecycle_blocked", body_str,
            f"lifecycle_status={lifecycle_status!r} was blocked by lifecycle gate",
        )

    def test_approved_component_is_permitted(self):
        """approved: PERMITTED — checkout is not blocked by the lifecycle gate."""
        self._assert_permitted_status_not_blocked("approved")

    def test_designed_component_is_permitted(self):
        """designed: PERMITTED — checkout is not blocked by the lifecycle gate."""
        self._assert_permitted_status_not_blocked("designed")

    def test_development_component_is_permitted(self):
        """development: PERMITTED — checkout is not blocked by the lifecycle gate."""
        self._assert_permitted_status_not_blocked("development")

    def test_production_component_is_permitted(self):
        """production: PERMITTED — checkout is not blocked by the lifecycle gate."""
        self._assert_permitted_status_not_blocked("production")

    def test_code_red_component_is_permitted(self):
        """code-red: PERMITTED — checkout is not blocked by the lifecycle gate."""
        self._assert_permitted_status_not_blocked("code-red")

    # ---- All 8 statuses covered in a parametric sweep ----

    def test_all_8_statuses_are_classified(self):
        """Verify all 8 lifecycle statuses are classified as OPAQUE, BLOCKED, or PERMITTED."""
        opaque = frozenset({"archived"})
        blocked = frozenset({"proposed", "deprecated"})
        permitted = frozenset({"approved", "designed", "development", "production", "code-red"})
        all_statuses = opaque | blocked | permitted

        # All 8 statuses are present.
        self.assertEqual(len(all_statuses), 8)

        # Verify the gate constants on the module under test.
        self.assertEqual(checkout_lambda._OPAQUE_LIFECYCLE_STATUSES, opaque)
        self.assertEqual(checkout_lambda._BLOCKED_LIFECYCLE_STATUSES, blocked)

    # ---- Opacity: archived 404 body matches non-existent shape ----

    def test_archived_404_body_key_set_matches_not_found_pattern(self):
        """Archived 404 body keys must not differ from a genuine missing-component pattern."""
        archived_resp = self._call_checkout("archived")
        self.assertEqual(archived_resp["statusCode"], 404)
        archived_body = json.loads(archived_resp["body"])

        # Must have 'error' key.
        self.assertIn("error", archived_body)
        # Must NOT have 'success': True.
        self.assertNotEqual(archived_body.get("success"), True)
        # Must NOT have a 'lifecycle_status' key revealing the actual status.
        self.assertNotIn("lifecycle_status", archived_body)
        # Must NOT have a 'component' key revealing registry details.
        self.assertNotIn("component", archived_body)

    # ---- Mixed components: one blocked, one permitted -> blocked wins ----

    def test_mixed_proposed_and_approved_blocks(self):
        """If any component is proposed (BLOCKED), checkout is blocked even if others are permitted."""
        task = _make_task(["comp-approved", "comp-proposed"])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect({
                                   "comp-approved": "approved",
                                   "comp-proposed": "proposed",
                               })):
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        self.assertEqual(resp["statusCode"], 400)

    def test_mixed_archived_and_approved_returns_404(self):
        """If any component is archived (OPAQUE), checkout returns 404."""
        task = _make_task(["comp-approved", "comp-archived"])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)), \
             mock.patch.object(checkout_lambda._ddb, "get_item",
                               side_effect=_ddb_lifecycle_side_effect({
                                   "comp-approved": "approved",
                                   "comp-archived": "archived",
                               })):
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        self.assertEqual(resp["statusCode"], 404)

    def test_task_without_components_not_blocked(self):
        """Task with no components in the registry is not blocked by the lifecycle gate."""
        task = _make_task([])
        body = {"active_agent_session_id": "test-agent-session"}
        with mock.patch.object(checkout_lambda, "_get_task", return_value=(200, task)):
            resp = checkout_lambda._handle_checkout("enceladus", "ENC-TSK-TEST", body)
        # Should not be blocked by the lifecycle gate (may fail for other reasons).
        body_str = json.dumps(json.loads(resp["body"]))
        self.assertNotIn("component_lifecycle_blocked", body_str)


if __name__ == "__main__":
    unittest.main()
