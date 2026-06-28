"""test_agent_session_id.py — ENC-TSK-I40 checkout value-swap.

Validates _resolve_agent_session_id() (the stamping integration point) and its
integration with _handle_checkout / _handle_plan_checkout.

AC-1: active_agent_session_id written at checkout is a server-minted ENC-SES-NNN;
      improvised strings are rejected with 400.
AC-2: the integration point is isolated in _resolve_agent_session_id so v4 can
      re-bind it without reshaping callers.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_i40",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)


class ResolveAgentSessionIdUnitTests(unittest.TestCase):
    """Direct unit tests for _resolve_agent_session_id (isolation point)."""

    def _resolve(self, raw):
        return checkout_lambda._resolve_agent_session_id(raw)

    # --- happy path ---

    def test_valid_ses_three_digit(self):
        ses_id, err = self._resolve("ENC-SES-001")
        self.assertIsNone(err)
        self.assertEqual(ses_id, "ENC-SES-001")

    def test_valid_ses_alphanum(self):
        ses_id, err = self._resolve("ENC-SES-00A")
        self.assertIsNone(err)
        self.assertEqual(ses_id, "ENC-SES-00A")

    def test_valid_ses_longer(self):
        ses_id, err = self._resolve("ENC-SES-0ZZZ")
        self.assertIsNone(err)
        self.assertEqual(ses_id, "ENC-SES-0ZZZ")

    def test_strips_whitespace(self):
        ses_id, err = self._resolve("  ENC-SES-001  ")
        self.assertIsNone(err)
        self.assertEqual(ses_id, "ENC-SES-001")

    # --- rejected: missing / empty ---

    def test_none_input(self):
        ses_id, err = self._resolve(None)
        self.assertIsNone(ses_id)
        self.assertIn("required", err)

    def test_empty_string(self):
        ses_id, err = self._resolve("")
        self.assertIsNone(ses_id)
        self.assertIn("required", err)

    def test_whitespace_only(self):
        ses_id, err = self._resolve("   ")
        self.assertIsNone(ses_id)
        self.assertIn("required", err)

    # --- AC-1: improvised strings are rejected ---

    def test_rejects_improvised_desktop_style(self):
        ses_id, err = self._resolve("cc-desktop-sonnet46-enc-tsk-i40")
        self.assertIsNone(ses_id)
        self.assertIn("ENC-SES-NNN", err)
        self.assertIn("agent.register", err)

    def test_rejects_coord_lead_style(self):
        ses_id, err = self._resolve("coord-lead-claudeai-opus-20260627")
        self.assertIsNone(ses_id)
        self.assertIn("ENC-SES-NNN", err)

    def test_rejects_lowercase_enc_ses(self):
        # IDs are uppercase per encode_seq; lowercase variant must not pass.
        ses_id, err = self._resolve("enc-ses-001")
        self.assertIsNone(ses_id)
        self.assertIn("ENC-SES-NNN", err)

    def test_rejects_arbitrary_string(self):
        ses_id, err = self._resolve("my-session")
        self.assertIsNone(ses_id)
        self.assertIn("ENC-SES-NNN", err)

    # --- AC-2: integration point is named and isolated ---

    def test_function_exists_and_is_isolated(self):
        """_resolve_agent_session_id must exist as a standalone callable."""
        fn = getattr(checkout_lambda, "_resolve_agent_session_id", None)
        self.assertIsNotNone(fn, "_resolve_agent_session_id not found in checkout_lambda")
        self.assertTrue(callable(fn))

    def test_ses_id_regex_exposed(self):
        """_SES_ID_RE must be a module-level constant (v4 rebind anchor)."""
        regex = getattr(checkout_lambda, "_SES_ID_RE", None)
        self.assertIsNotNone(regex, "_SES_ID_RE constant not found")


class HandleCheckoutSessionIdIntegrationTests(unittest.TestCase):
    """_handle_checkout rejects improvised session IDs; accepts ENC-SES-NNN."""

    def _make_pre_task(self, **overrides):
        base = {
            "status": "open",
            "transition_type": "github_pr_deploy",
            "components": [],
            "subtask_ids": [],
            "active_agent_session": False,
            "active_agent_session_id": "",
        }
        base.update(overrides)
        return base

    def _make_post_task(self, ses_id, **overrides):
        base = {
            "status": "in-progress",
            "transition_type": "github_pr_deploy",
            "components": [],
            "subtask_ids": [],
            "checkout_count": 1,
            "active_agent_session": True,
            "active_agent_session_id": ses_id,
        }
        base.update(overrides)
        return base

    def _run_checkout(self, ses_id):
        pre_task = self._make_pre_task()
        post_task = self._make_post_task(ses_id)

        def fake_tracker(method, path, payload=None):
            if method == "GET":
                return 200, pre_task
            if method == "POST" and "/checkout" in path:
                return 200, {"success": True, "governance_hash": "gh-test"}
            if method == "PATCH":
                return 200, {"success": True}
            return 200, {}

        with mock.patch.object(checkout_lambda, "_tracker_request", side_effect=fake_tracker):
            with mock.patch.object(checkout_lambda, "_get_task",
                                   side_effect=[(200, pre_task), (200, post_task)]):
                resp = checkout_lambda._handle_checkout(
                    "enceladus", "ENC-TSK-I40",
                    {"active_agent_session_id": ses_id},
                )
        return resp

    def test_valid_ses_id_accepted(self):
        resp = self._run_checkout("ENC-SES-001")
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"), body)
        self.assertEqual(resp["statusCode"], 200)

    def test_improvised_id_rejected_400(self):
        resp = checkout_lambda._handle_checkout(
            "enceladus", "ENC-TSK-I40",
            {"active_agent_session_id": "cc-desktop-sonnet46-enc-tsk-i40"},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body.get("success"))
        self.assertIn("ENC-SES-NNN", body.get("error", ""))

    def test_missing_id_rejected_400(self):
        resp = checkout_lambda._handle_checkout(
            "enceladus", "ENC-TSK-I40",
            {},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body.get("success"))

    def test_coord_lead_style_rejected(self):
        resp = checkout_lambda._handle_checkout(
            "enceladus", "ENC-TSK-I40",
            {"active_agent_session_id": "coord-lead-claudeai-opus-20260627"},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("ENC-SES-NNN", body.get("error", ""))


class HandlePlanCheckoutSessionIdTests(unittest.TestCase):
    """_handle_plan_checkout uses the same _resolve_agent_session_id integration point."""

    def test_improvised_id_rejected_400(self):
        resp = checkout_lambda._handle_plan_checkout(
            "enceladus", "ENC-PLN-058",
            {"active_agent_session_id": "coord-lead-claudeai-opus-20260627"},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body.get("success"))
        self.assertIn("ENC-SES-NNN", body.get("error", ""))

    def test_missing_id_rejected_400(self):
        resp = checkout_lambda._handle_plan_checkout(
            "enceladus", "ENC-PLN-058",
            {},
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertFalse(body.get("success"))


if __name__ == "__main__":
    unittest.main()
