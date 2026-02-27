"""test_lambda_function.py — Mock-based integration tests for tracker_mutation.

Tests the PATCH flow for close/note/reopen actions, auth validation,
project validation, and DynamoDB interactions. All locally runnable
without AWS credentials.

Part of ENC-TSK-531: Backend Lambda integration tests.

Run: python3 -m pytest test_lambda_function.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

# Ensure the Lambda directory is importable.
sys.path.insert(0, os.path.dirname(__file__))

# Load the module via importlib to avoid import conflicts.
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tracker_mutation)


def _make_event(
    project_id="devops",
    record_type="task",
    record_id="TSK-001",
    action="close",
    note="",
    cookie="enceladus_id_token=valid-jwt",
    method="PATCH",
    path_style="v1",
):
    """Build a mock API Gateway v2 event."""
    if path_style == "v1":
        path = f"/api/v1/tracker/{project_id}/{record_type}/{record_id}"
    else:
        path = f"/{project_id}/{record_type}/{record_id}"

    body = {"action": action}
    if note:
        body["note"] = note

    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": {"cookie": cookie} if cookie else {"host": "example.com"},
        "body": json.dumps(body),
        "rawPath": path,
    }


def _make_subresource_event(
    project_id="devops",
    record_type="task",
    record_id="TSK-001",
    subresource="checkout",
    method="POST",
    body=None,
    internal_key="valid-key",
):
    """Build a mock API Gateway v2 event for sub-resource routes."""
    path = f"/api/v1/tracker/{project_id}/{record_type}/{record_id}/{subresource}"
    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": {"x-coordination-internal-key": internal_key, "host": "example.com"},
        "body": json.dumps(body or {}),
        "rawPath": path,
    }


class OptionsTests(unittest.TestCase):
    """CORS preflight returns 204 with no body."""

    def test_options_returns_204(self):
        event = _make_event(method="OPTIONS")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 204)
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])


class MethodValidationTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    def test_get_rejected(self, _mock_verify, _mock_proj):
        event = _make_event(method="PUT")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 405)


class PathParsingTests(unittest.TestCase):
    def test_invalid_path(self):
        event = _make_event()
        event["requestContext"]["http"]["path"] = "/invalid/path/too/many"
        event["rawPath"] = "/invalid/path/too/many"
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertIn("No route matched", body["error"])


class AuthTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    def test_missing_cookie_returns_401(self, _mock_proj):
        event = _make_event(cookie="")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)
        body = json.loads(resp["body"])
        self.assertIn("Authentication required", body["error"])

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", side_effect=ValueError("Token expired"))
    def test_invalid_token_returns_401(self, _mock_verify, _mock_proj):
        event = _make_event()
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 401)
        body = json.loads(resp["body"])
        self.assertIn("Token expired", body["error"])


class InternalKeyScopeTests(unittest.TestCase):
    def setUp(self):
        self._orig_key = tracker_mutation.COORDINATION_INTERNAL_API_KEY
        self._orig_keys = tracker_mutation.COORDINATION_INTERNAL_API_KEYS
        self._orig_scopes = tracker_mutation.INTERNAL_API_KEY_SCOPES

    def tearDown(self):
        tracker_mutation.COORDINATION_INTERNAL_API_KEY = self._orig_key
        tracker_mutation.COORDINATION_INTERNAL_API_KEYS = self._orig_keys
        tracker_mutation.INTERNAL_API_KEY_SCOPES = self._orig_scopes

    def test_internal_key_scope_denied_for_write(self):
        tracker_mutation.COORDINATION_INTERNAL_API_KEY = "scope-key"
        tracker_mutation.COORDINATION_INTERNAL_API_KEYS = ("scope-key",)
        tracker_mutation.INTERNAL_API_KEY_SCOPES = {"scope-key": {"tracker:read"}}

        claims, auth_err = tracker_mutation._authenticate(
            {"headers": {"x-coordination-internal-key": "scope-key"}},
            required_scopes=["tracker:write"],
        )
        self.assertIsNone(claims)
        self.assertIsNotNone(auth_err)
        self.assertEqual(auth_err["statusCode"], 403)

    def test_internal_key_scope_allows_write(self):
        tracker_mutation.COORDINATION_INTERNAL_API_KEY = "scope-key"
        tracker_mutation.COORDINATION_INTERNAL_API_KEYS = ("scope-key",)
        tracker_mutation.INTERNAL_API_KEY_SCOPES = {"scope-key": {"tracker:*"}}

        claims, auth_err = tracker_mutation._authenticate(
            {"headers": {"x-coordination-internal-key": "scope-key"}},
            required_scopes=["tracker:write"],
        )
        self.assertEqual(claims, {"auth_mode": "internal-key"})
        self.assertIsNone(auth_err)


class ProjectValidationTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists",
                  return_value="Project 'bogus' is not registered.")
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    def test_unregistered_project_returns_404(self, _mock_verify, _mock_proj):
        event = _make_event(project_id="bogus")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 404)

    @patch.object(tracker_mutation, "_get_ddb")
    def test_project_cache_fail_open(self, mock_ddb):
        """If projects table lookup fails, mutation is still allowed (fail-open)."""
        tracker_mutation._project_cache = {}
        tracker_mutation._project_cache_at = 0.0
        mock_ddb.return_value.get_item.side_effect = Exception("DDB down")
        result = tracker_mutation._validate_project_exists("devops")
        self.assertIsNone(result)  # Fail-open: None means "allow"


class ActionValidationTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    def test_invalid_action_rejected(self, _mock_verify, _mock_proj):
        event = _make_event(action="delete")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("action", body["error"])

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    def test_note_action_requires_text(self, _mock_verify, _mock_proj):
        event = _make_event(action="note", note="")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("note", body["error"].lower())


class CloseActionTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_get_events", return_value=MagicMock())
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    @patch.object(tracker_mutation, "_get_ddb")
    def test_close_task_success(self, mock_ddb, _mock_verify, _mock_proj, _mock_events):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb

        # get_record returns existing open task
        fake_ddb.get_item.return_value = {
            "Item": {
                "status": {"S": "open"},
                "sync_version": {"N": "1"},
                "record_type": {"S": "task"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
            }
        }
        # update_item succeeds
        fake_ddb.update_item.return_value = {}

        event = _make_event(action="close")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    @patch.object(tracker_mutation, "_get_ddb")
    def test_close_nonexistent_record_returns_404(self, mock_ddb, _mock_verify, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {}  # No Item
        event = _make_event(action="close")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 404)


class NoteActionTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    @patch.object(tracker_mutation, "_get_ddb")
    def test_note_action_success(self, mock_ddb, _mock_verify, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb

        fake_ddb.get_item.return_value = {
            "Item": {
                "status": {"S": "open"},
                "sync_version": {"N": "1"},
                "record_type": {"S": "task"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
            }
        }
        fake_ddb.update_item.return_value = {}

        event = _make_event(action="note", note="Progress update")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    def test_note_too_long_rejected(self, _mock_verify, _mock_proj):
        event = _make_event(action="note", note="x" * 2001)
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("maximum length", body["error"])


class TokenExtractionTests(unittest.TestCase):
    def test_extract_from_cookie_header(self):
        event = {"headers": {"cookie": "enceladus_id_token=abc123; other=val"}}
        self.assertEqual(tracker_mutation._extract_token(event), "abc123")

    def test_extract_from_cookies_array(self):
        event = {"headers": {}, "cookies": ["enceladus_id_token=xyz789"]}
        self.assertEqual(tracker_mutation._extract_token(event), "xyz789")

    def test_missing_token_returns_none(self):
        event = {"headers": {"cookie": "other=val"}}
        self.assertIsNone(tracker_mutation._extract_token(event))

    def test_case_insensitive_cookie_header(self):
        event = {"headers": {"Cookie": "enceladus_id_token=abc123"}}
        self.assertEqual(tracker_mutation._extract_token(event), "abc123")


class DynamoDBKeyTests(unittest.TestCase):
    def test_build_key_task(self):
        key = tracker_mutation._build_key("devops", "task", "TSK-001")
        self.assertEqual(key["project_id"]["S"], "devops")
        self.assertEqual(key["record_id"]["S"], "task#TSK-001")

    def test_build_key_issue(self):
        key = tracker_mutation._build_key("devops", "issue", "ISS-002")
        self.assertEqual(key["record_id"]["S"], "issue#ISS-002")

    def test_build_key_feature(self):
        key = tracker_mutation._build_key("devops", "feature", "FTR-003")
        self.assertEqual(key["record_id"]["S"], "feature#FTR-003")


class LegacyPathTests(unittest.TestCase):
    """Test both legacy /{project}/{type}/{id} and v1 /api/v1/tracker/... paths."""

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_verify_token", return_value={"sub": "user1"})
    @patch.object(tracker_mutation, "_get_ddb")
    def test_legacy_path_works(self, mock_ddb, _mock_verify, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "status": {"S": "open"},
                "sync_version": {"N": "1"},
                "record_type": {"S": "task"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
            }
        }
        fake_ddb.update_item.return_value = {}

        event = _make_event(action="close", path_style="legacy")
        resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)


class CheckoutRouteTests(unittest.TestCase):
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_get_ddb")
    def test_checkout_uses_top_level_provider_identity(self, mock_ddb, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "status": {"S": "open"},
                "sync_version": {"N": "1"},
                "record_type": {"S": "task"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
                "active_agent_session": {"BOOL": False},
                "active_agent_session_id": {"S": ""},
            }
        }
        fake_ddb.update_item.return_value = {}

        event = _make_subresource_event(
            body={"provider": "codex-helper"},
            subresource="checkout",
            method="POST",
        )
        with patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), patch.object(
            tracker_mutation,
            "COORDINATION_INTERNAL_API_KEYS",
            ("valid-key",),
        ):
            resp = tracker_mutation.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)
        parsed = json.loads(resp["body"])
        self.assertTrue(parsed.get("checkout"))
        self.assertEqual(parsed.get("active_agent_session_id"), "codex-helper")

    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_get_ddb")
    def test_checkout_accepts_previous_internal_key(self, mock_ddb, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "status": {"S": "open"},
                "sync_version": {"N": "1"},
                "record_type": {"S": "task"},
                "updated_at": {"S": "2026-01-01T00:00:00Z"},
                "active_agent_session": {"BOOL": False},
                "active_agent_session_id": {"S": ""},
            }
        }
        fake_ddb.update_item.return_value = {}

        event = _make_subresource_event(
            body={"provider": "codex-helper"},
            subresource="checkout",
            method="POST",
            internal_key="legacy-key",
        )
        with patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "active-key"), patch.object(
            tracker_mutation,
            "COORDINATION_INTERNAL_API_KEYS",
            ("active-key", "legacy-key"),
        ):
            resp = tracker_mutation.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)
        parsed = json.loads(resp["body"])
        self.assertTrue(parsed.get("checkout"))


if __name__ == "__main__":
    unittest.main()
