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


class PlanRouteTests(unittest.TestCase):
    """ENC-TSK-B10: Verify plan record type routes match correctly."""

    def _plan_event(self, method, path, body=None, internal_key="valid-key"):
        return {
            "requestContext": {"http": {"method": method, "path": path}},
            "headers": {"x-coordination-internal-key": internal_key, "host": "example.com"},
            "body": json.dumps(body or {}),
            "rawPath": path,
        }

    # AC1: POST /api/v1/tracker/{project}/plan creates a plan record
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_get_project_prefix", return_value="ENC")
    @patch.object(tracker_mutation, "_get_ddb")
    def test_post_plan_creates_record(self, mock_get_ddb, _mock_prefix, _mock_proj):
        fake_ddb = MagicMock()
        mock_get_ddb.return_value = fake_ddb
        # Counter query returns empty (first plan)
        fake_ddb.query.return_value = {"Items": [], "Count": 0}
        fake_ddb.put_item.return_value = {}

        with patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            event = self._plan_event(
                "POST", "/api/v1/tracker/enceladus/plan",
                body={"title": "Test Plan", "category": "tactical"},
            )
            resp = tracker_mutation.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 201)
        parsed = json.loads(resp["body"])
        self.assertTrue(parsed["success"])
        self.assertIn("ENC-PLN-", parsed["record_id"])

    # AC2: PATCH /api/v1/tracker/{project}/plan/{id} routes correctly
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_get_ddb")
    def test_patch_plan_routes(self, mock_get_ddb, _mock_proj):
        fake_ddb = MagicMock()
        mock_get_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "project_id": {"S": "enceladus"},
                "record_id": {"S": "plan#ENC-PLN-001"},
                "record_type": {"S": "plan"},
                "item_id": {"S": "ENC-PLN-001"},
                "title": {"S": "Test Plan"},
                "status": {"S": "drafted"},
                "sync_version": {"N": "1"},
                "created_at": {"S": "2026-04-03T00:00:00Z"},
                "updated_at": {"S": "2026-04-03T00:00:00Z"},
                "history": {"L": []},
                "objectives_set": {"L": []},
                "coordination": {"BOOL": False},
            }
        }
        fake_ddb.update_item.return_value = {}

        with patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            event = self._plan_event(
                "PATCH", "/api/v1/tracker/enceladus/plan/ENC-PLN-001",
                body={"field": "title", "value": "Updated Plan"},
            )
            resp = tracker_mutation.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)

    # AC3: GET /api/v1/tracker/{project}/plan/{id} returns plan record
    @patch.object(tracker_mutation, "_validate_project_exists", return_value=None)
    @patch.object(tracker_mutation, "_get_ddb")
    def test_get_plan_routes(self, mock_get_ddb, _mock_proj):
        fake_ddb = MagicMock()
        mock_get_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": {
                "project_id": {"S": "enceladus"},
                "record_id": {"S": "plan#ENC-PLN-001"},
                "record_type": {"S": "plan"},
                "item_id": {"S": "ENC-PLN-001"},
                "title": {"S": "Test Plan"},
                "status": {"S": "drafted"},
                "sync_version": {"N": "1"},
                "created_at": {"S": "2026-04-03T00:00:00Z"},
                "updated_at": {"S": "2026-04-03T00:00:00Z"},
                "history": {"L": []},
                "objectives_set": {"L": []},
                "coordination": {"BOOL": False},
            }
        }

        with patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            event = self._plan_event(
                "GET", "/api/v1/tracker/enceladus/plan/ENC-PLN-001",
            )
            resp = tracker_mutation.lambda_handler(event, None)

        self.assertEqual(resp["statusCode"], 200)
        parsed = json.loads(resp["body"])
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["record"]["item_id"], "ENC-PLN-001")

    def test_plan_regex_matches_type_collection(self):
        """Route regex for POST /plan matches."""
        m = tracker_mutation._RE_TYPE_COLLECTION.match("/api/v1/tracker/enceladus/plan")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("type"), "plan")

    def test_plan_regex_matches_record(self):
        """Route regex for GET/PATCH /plan/{id} matches."""
        m = tracker_mutation._RE_RECORD.match("/api/v1/tracker/enceladus/plan/ENC-PLN-001")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("type"), "plan")
        self.assertEqual(m.group("id"), "ENC-PLN-001")

    def test_plan_regex_matches_subresource(self):
        """Route regex for POST /plan/{id}/log matches."""
        m = tracker_mutation._RE_RECORD_SUB.match("/api/v1/tracker/enceladus/plan/ENC-PLN-001/log")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("type"), "plan")

    def test_plan_type_seg_to_sk_prefix(self):
        """Plan SK prefix is registered."""
        self.assertEqual(tracker_mutation._TYPE_SEG_TO_SK_PREFIX["plan"], "plan")

    def test_classify_related_ids_includes_plan(self):
        """_classify_related_ids recognizes PLN segment."""
        result = tracker_mutation._classify_related_ids(["ENC-PLN-001"])
        self.assertIn("related_plan_ids", result)
        self.assertEqual(result["related_plan_ids"], ["ENC-PLN-001"])


class TaskCreateTransitionTypeTests(unittest.TestCase):
    """ENC-TSK-C26 / ENC-ISS-175: tracker.create must honor transition_type.

    Prior to the fix the Lambda's _handle_create_record never read
    transition_type from the POST body, so the persisted DynamoDB item had no
    transition_type field and the checkout service stamped the default
    github_pr_deploy. Combined with ENC-FTR-060 sealing this stranded any
    no_code/code_only intent permanently. These tests pin both the persistence
    contract and the validation contract for unknown values.
    """

    def _create_task_event(self, body, internal_key="valid-key"):
        path = "/api/v1/tracker/enceladus/task"
        return {
            "requestContext": {"http": {"method": "POST", "path": path}},
            "headers": {"x-coordination-internal-key": internal_key, "host": "example.com"},
            "body": json.dumps(body),
            "rawPath": path,
        }

    def _run(self, body):
        with patch.object(tracker_mutation, "_validate_project_exists", return_value=None), \
             patch.object(tracker_mutation, "_get_project_prefix", return_value="ENC"), \
             patch.object(tracker_mutation, "_get_ddb") as mock_get_ddb, \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            fake_ddb = MagicMock()
            mock_get_ddb.return_value = fake_ddb
            fake_ddb.query.return_value = {"Items": [], "Count": 0}
            fake_ddb.put_item.return_value = {}
            event = self._create_task_event(body)
            resp = tracker_mutation.lambda_handler(event, None)
            return resp, fake_ddb

    def test_create_task_persists_no_code_transition_type(self):
        resp, fake_ddb = self._run({
            "title": "C26 repro: no_code task",
            "category": "documentation",
            "acceptance_criteria": ["verify no_code persists"],
            "transition_type": "no_code",
        })
        self.assertEqual(resp["statusCode"], 201, resp.get("body"))
        parsed = json.loads(resp["body"])
        self.assertTrue(parsed.get("success"))
        # Capture the put_item call and confirm the transition_type field made
        # it onto the DynamoDB item.
        self.assertTrue(fake_ddb.put_item.called)
        item = fake_ddb.put_item.call_args.kwargs["Item"]
        self.assertIn("transition_type", item)
        self.assertEqual(item["transition_type"], {"S": "no_code"})

    def test_create_task_persists_code_only_transition_type(self):
        resp, fake_ddb = self._run({
            "title": "C26 repro: code_only task",
            "category": "implementation",
            "acceptance_criteria": ["verify code_only persists"],
            "transition_type": "code_only",
        })
        self.assertEqual(resp["statusCode"], 201)
        item = fake_ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["transition_type"], {"S": "code_only"})

    def test_create_task_normalizes_transition_type_case(self):
        """Mixed-case input must be normalized to lowercase before persistence."""
        resp, fake_ddb = self._run({
            "title": "C26 case-norm task",
            "category": "implementation",
            "acceptance_criteria": ["verify normalization"],
            "transition_type": "  No_Code  ",
        })
        self.assertEqual(resp["statusCode"], 201)
        item = fake_ddb.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["transition_type"], {"S": "no_code"})

    def test_create_task_omits_transition_type_when_not_provided(self):
        """Omitting transition_type must NOT add the field to the item.

        This preserves the read-side default behavior in the checkout service
        and graph projection — they fall back to github_pr_deploy when the
        field is absent.
        """
        resp, fake_ddb = self._run({
            "title": "C26 default-arc task",
            "category": "implementation",
            "acceptance_criteria": ["verify omission"],
        })
        self.assertEqual(resp["statusCode"], 201)
        item = fake_ddb.put_item.call_args.kwargs["Item"]
        self.assertNotIn("transition_type", item)

    def test_create_task_rejects_invalid_transition_type(self):
        with patch.object(tracker_mutation, "_validate_project_exists", return_value=None), \
             patch.object(tracker_mutation, "_get_project_prefix", return_value="ENC"), \
             patch.object(tracker_mutation, "_get_ddb") as mock_get_ddb, \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            fake_ddb = MagicMock()
            mock_get_ddb.return_value = fake_ddb
            event = self._create_task_event({
                "title": "C26 invalid arc",
                "category": "implementation",
                "acceptance_criteria": ["verify rejection"],
                "transition_type": "bogus_arc",
            })
            resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("transition_type", body.get("error", "") or body.get("message", ""))
        # Server must NOT have written anything for the rejected request.
        fake_ddb.put_item.assert_not_called()

    def test_create_non_task_rejects_transition_type(self):
        """transition_type is meaningless on non-task records and must be rejected."""
        with patch.object(tracker_mutation, "_validate_project_exists", return_value=None), \
             patch.object(tracker_mutation, "_get_project_prefix", return_value="ENC"), \
             patch.object(tracker_mutation, "_get_ddb") as mock_get_ddb, \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEY", "valid-key"), \
             patch.object(tracker_mutation, "COORDINATION_INTERNAL_API_KEYS", ("valid-key",)):
            fake_ddb = MagicMock()
            mock_get_ddb.return_value = fake_ddb
            path = "/api/v1/tracker/enceladus/feature"
            event = {
                "requestContext": {"http": {"method": "POST", "path": path}},
                "headers": {"x-coordination-internal-key": "valid-key", "host": "example.com"},
                "body": json.dumps({
                    "title": "C26 feature with bogus transition_type",
                    "category": "capability",
                    "user_story": "As a tester I want to verify rejection so that the contract holds",
                    "acceptance_criteria": ["verify rejection"],
                    "transition_type": "no_code",
                }),
                "rawPath": path,
            }
            resp = tracker_mutation.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 400)
        fake_ddb.put_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()
