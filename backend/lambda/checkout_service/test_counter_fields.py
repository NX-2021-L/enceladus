"""test_counter_fields.py — checkout_service observability of the FTR-076 v2
checkout_count field incremented by tracker_mutation during a successful
checkout.task call (ENC-TSK-F41 / DOC-546B896390EA §5).

The atomic ADD checkout_count :one is issued by tracker_mutation as part of
the same UpdateExpression that sets active_agent_session=True (see
tracker_mutation._handle_update_field). checkout_service._handle_checkout
invokes that write via HTTP and reads back the task record to surface the
incremented counter on its response and in logs. These tests validate:

  1. A successful checkout.task round-trip returns checkout_count from the
     tracker.get response verbatim on the checkout_service response body.
  2. A non-integer or missing counter is coerced to 0 without raising.
  3. The docstring on _handle_checkout references the F41 contract so future
     readers see the invariant directly.
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


def _task_payload(checkout_count=1, **extras):
    """Build a task body the tracker_mutation GET endpoint would return."""
    payload = {
        "record_id": "task#ENC-TSK-901",
        "item_id": "ENC-TSK-901",
        "record_type": "task",
        "status": "in-progress",
        "active_agent_session": True,
        "active_agent_session_id": "claude-code-f41-test",
        "transition_type": "github_pr_deploy",
        "components": [],
        "checkout_count": checkout_count,
        "closed_count": 0,
    }
    payload.update(extras)
    return payload


class CheckoutSurfacesCheckoutCountTests(unittest.TestCase):
    """checkout_service._handle_checkout must expose the incremented counter
    on its response body so callers can verify the FTR-076 v2 transition."""

    def _invoke_checkout(self, checkout_count_value):
        # The pre-checkout _get_task probe (components gate), the actual checkout
        # POST, the status PATCH to in-progress, the post-checkout _get_task read,
        # and the checkout_transition_type PATCH all route through _tracker_request.
        # Provide a side_effect list mirroring the real call sequence.
        task_body = _task_payload(checkout_count=checkout_count_value)
        wrapped_get = {"success": True, "record": task_body}

        def fake_tracker_request(method, path, body=None):
            if method == "GET":
                return 200, wrapped_get
            if method == "POST" and "/checkout" in path:
                return 200, {"success": True, "governance_hash": "h"}
            # PATCH for status advance or checkout_transition_type stamp
            return 200, {"success": True}

        with mock.patch.object(checkout_lambda, "_tracker_request",
                               side_effect=fake_tracker_request):
            resp = checkout_lambda._handle_checkout(
                "enceladus", "ENC-TSK-901",
                {"active_agent_session_id": "claude-code-f41-test"},
            )
        return resp

    def test_response_exposes_checkout_count_from_task_record(self):
        resp = self._invoke_checkout(checkout_count_value=1)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("checkout_count"), 1)

    def test_response_surfaces_incremented_checkout_count_on_second_invocation(self):
        resp = self._invoke_checkout(checkout_count_value=2)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("checkout_count"), 2)

    def test_missing_checkout_count_coerces_to_zero(self):
        """Pre-FTR-076 v2 task records without checkout_count must not crash the
        response assembly — absent attributes are treated as 0 per dict contract."""
        def fake_tracker_request(method, path, body=None):
            if method == "GET":
                # Return a task payload WITHOUT checkout_count to simulate a
                # pre-FTR-076-v2 record that predates the migration.
                task_body = {
                    "record_id": "task#ENC-TSK-902",
                    "item_id": "ENC-TSK-902",
                    "record_type": "task",
                    "status": "in-progress",
                    "active_agent_session": True,
                    "active_agent_session_id": "legacy-agent",
                    "transition_type": "github_pr_deploy",
                    "components": [],
                }
                return 200, {"success": True, "record": task_body}
            if method == "POST" and "/checkout" in path:
                return 200, {"success": True, "governance_hash": "h"}
            return 200, {"success": True}

        with mock.patch.object(checkout_lambda, "_tracker_request",
                               side_effect=fake_tracker_request):
            resp = checkout_lambda._handle_checkout(
                "enceladus", "ENC-TSK-902",
                {"active_agent_session_id": "legacy-agent"},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("checkout_count"), 0)

    def test_non_integer_checkout_count_coerces_to_zero(self):
        """If tracker returns garbage (e.g. string instead of int), coerce to 0
        defensively rather than raising."""
        def fake_tracker_request(method, path, body=None):
            if method == "GET":
                task_body = _task_payload(checkout_count="not-a-number")
                return 200, {"success": True, "record": task_body}
            if method == "POST" and "/checkout" in path:
                return 200, {"success": True, "governance_hash": "h"}
            return 200, {"success": True}

        with mock.patch.object(checkout_lambda, "_tracker_request",
                               side_effect=fake_tracker_request):
            resp = checkout_lambda._handle_checkout(
                "enceladus", "ENC-TSK-903",
                {"active_agent_session_id": "agent"},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("checkout_count"), 0)


class HandleCheckoutDocstringReferencesF41Tests(unittest.TestCase):
    """The F41 contract must be documented on the checkout_service handler so
    engineers reading checkout_service first can trace the atomic-increment
    invariant without needing to jump to tracker_mutation."""

    def test_handle_checkout_docstring_cites_f41(self):
        doc = checkout_lambda._handle_checkout.__doc__ or ""
        self.assertIn("ENC-TSK-F41", doc)
        self.assertIn("checkout_count", doc)
        self.assertIn("DOC-546B896390EA", doc)


if __name__ == "__main__":
    unittest.main()
