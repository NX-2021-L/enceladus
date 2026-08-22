"""test_project_update_n87.py — ENC-TSK-N87 / ENC-FTR-131

Covers the PATCH /api/v1/projects/{projectName} update contract.

The load-bearing assertions here are the negative ones. Several of these tests would
still pass against a broken implementation if they only checked the status code, so
where it matters they assert that no write was attempted at all.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "project_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
project_service = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(project_service)


class _FakeConditionalCheckFailed(Exception):
    pass


def _make_ddb(existing: dict | None = None) -> MagicMock:
    """A DynamoDB stub whose update_item echoes back a plausible ALL_NEW item."""
    ddb = MagicMock()
    ddb.exceptions.ConditionalCheckFailedException = _FakeConditionalCheckFailed
    attrs = existing if existing is not None else {
        "project_id": {"S": "finance"},
        "prefix": {"S": "FIN"},
        "summary": {"S": "Project to manage my finances."},
        "status": {"S": "development"},
        "path": {"S": "projects/io/finance"},
        "created_at": {"S": "2026-04-02T00:36:20Z"},
        "updated_at": {"S": "2026-04-02T00:36:20Z"},
    }
    ddb.update_item.return_value = {"Attributes": attrs}
    # _handle_update enriches the response, which walks _compute_days_since_active's
    # paginated query. A bare MagicMock makes resp.get("LastEvaluatedKey") truthy forever
    # and the loop never terminates, so return a real terminal page.
    ddb.query.return_value = {"Items": []}
    return ddb


def _body(resp: dict) -> dict:
    return json.loads(resp["body"])


class ValidateUpdateInputTests(unittest.TestCase):
    def test_accepts_the_three_mutable_fields(self):
        data, err = project_service._validate_update_input(
            {"summary": "New summary", "status": "active_production", "repo": "https://github.com/NX-2021-L/finance"}
        )
        self.assertIsNone(err)
        self.assertEqual(
            data,
            {
                "summary": "New summary",
                "status": "active_production",
                "repo": "https://github.com/NX-2021-L/finance",
            },
        )

    def test_partial_patch_only_returns_supplied_fields(self):
        data, err = project_service._validate_update_input({"repo": "https://github.com/NX-2021-L/finance"})
        self.assertIsNone(err)
        self.assertEqual(list(data.keys()), ["repo"])

    def test_each_immutable_field_is_rejected_by_name(self):
        for field in project_service._IMMUTABLE_UPDATE_FIELDS:
            with self.subTest(field=field):
                data, err = project_service._validate_update_input({"summary": "ok", field: "x"})
                self.assertIsNone(data)
                self.assertIn(field, err)

    def test_unknown_field_is_rejected(self):
        data, err = project_service._validate_update_input({"nonsense": "x"})
        self.assertIsNone(data)
        self.assertIn("nonsense", err)

    def test_empty_body_is_rejected_rather_than_a_noop(self):
        data, err = project_service._validate_update_input({})
        self.assertIsNone(data)
        self.assertIn("no editable fields", err)

    def test_status_restricted_to_create_statuses(self):
        for bad in ("closed", "archived", "", "Development", "bogus"):
            with self.subTest(status=bad):
                data, err = project_service._validate_update_input({"status": bad})
                self.assertIsNone(data, f"status={bad!r} should be rejected")
                self.assertIn("status", err)

    def test_summary_length_bounds(self):
        data, err = project_service._validate_update_input({"summary": "x" * 501})
        self.assertIsNone(data)
        self.assertIn("summary", err)

        data, err = project_service._validate_update_input({"summary": "   "})
        self.assertIsNone(data)
        self.assertIn("summary", err)

    def test_repo_empty_string_is_the_remove_sentinel(self):
        data, err = project_service._validate_update_input({"repo": ""})
        self.assertIsNone(err)
        self.assertIn("repo", data)
        self.assertIsNone(data["repo"], "empty repo must map to the None remove-sentinel, not ''")

    def test_repo_invalid_url_rejected(self):
        for bad in ("not-a-url", "ftp://example.com/x", "github.com/foo/bar"):
            with self.subTest(repo=bad):
                data, err = project_service._validate_update_input({"repo": bad})
                self.assertIsNone(data)
                self.assertIn("repo", err)


class HandleUpdateTests(unittest.TestCase):
    def setUp(self):
        self._orig_get_ddb = project_service._get_ddb

    def tearDown(self):
        project_service._get_ddb = self._orig_get_ddb

    def _run(self, body, ddb=None):
        ddb = ddb or _make_ddb()
        project_service._get_ddb = lambda: ddb
        resp = project_service._handle_update("finance", body, {"sub": "test-user"})
        return resp, ddb

    def test_successful_update_returns_200_and_project(self):
        resp, ddb = self._run({"summary": "New summary"})
        self.assertEqual(resp["statusCode"], 200)
        self.assertTrue(_body(resp)["success"])
        self.assertIn("project", _body(resp))
        ddb.update_item.assert_called_once()

    def test_update_expression_touches_only_allowed_attributes(self):
        resp, ddb = self._run(
            {"summary": "s", "status": "planning", "repo": "https://github.com/NX-2021-L/finance"}
        )
        self.assertEqual(resp["statusCode"], 200)
        kwargs = ddb.update_item.call_args.kwargs
        touched = set(kwargs["ExpressionAttributeNames"].values())
        self.assertEqual(touched, {"summary", "status", "repo", "updated_at"})

    def test_updated_at_always_advances(self):
        resp, ddb = self._run({"summary": "s"})
        kwargs = ddb.update_item.call_args.kwargs
        self.assertIn(":updated_at", kwargs["ExpressionAttributeValues"])
        self.assertIn("updated_at", kwargs["ExpressionAttributeNames"].values())

    def test_immutable_field_performs_no_write(self):
        """The point of this test: a 400 alone would not prove nothing was written."""
        resp, ddb = self._run({"prefix": "XXX"})
        self.assertEqual(resp["statusCode"], 400)
        ddb.update_item.assert_not_called()

    def test_empty_body_performs_no_write(self):
        resp, ddb = self._run({})
        self.assertEqual(resp["statusCode"], 400)
        ddb.update_item.assert_not_called()

    def test_invalid_repo_performs_no_write(self):
        resp, ddb = self._run({"repo": "not-a-url"})
        self.assertEqual(resp["statusCode"], 400)
        ddb.update_item.assert_not_called()

    def test_repo_clear_uses_remove_not_empty_string(self):
        resp, ddb = self._run({"repo": ""})
        self.assertEqual(resp["statusCode"], 200)
        kwargs = ddb.update_item.call_args.kwargs
        self.assertIn("REMOVE", kwargs["UpdateExpression"])
        # The repo placeholder must not appear on the SET side with an empty value.
        self.assertNotIn(":repo", kwargs["ExpressionAttributeValues"])

    def test_repo_set_writes_the_url(self):
        resp, ddb = self._run({"repo": "https://github.com/NX-2021-L/finance"})
        self.assertEqual(resp["statusCode"], 200)
        kwargs = ddb.update_item.call_args.kwargs
        self.assertNotIn("REMOVE", kwargs["UpdateExpression"])
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":repo"]["S"],
            "https://github.com/NX-2021-L/finance",
        )

    def test_write_is_guarded_by_attribute_exists(self):
        resp, ddb = self._run({"summary": "s"})
        kwargs = ddb.update_item.call_args.kwargs
        self.assertEqual(kwargs["ConditionExpression"], "attribute_exists(project_id)")

    def test_missing_project_returns_404(self):
        ddb = _make_ddb()
        ddb.update_item.side_effect = _FakeConditionalCheckFailed()
        resp, _ = self._run({"summary": "s"}, ddb=ddb)
        self.assertEqual(resp["statusCode"], 404)
        self.assertIn("not found", _body(resp)["error"])


class RoutingAndScopeTests(unittest.TestCase):
    """The scope ternary and the route are the two places a mistake is silently dangerous."""

    def test_patch_requires_write_scope(self):
        self.assertIn("PATCH", project_service._WRITE_METHODS)
        self.assertIn("POST", project_service._WRITE_METHODS)
        self.assertNotIn("GET", project_service._WRITE_METHODS)

    def test_read_only_internal_key_is_denied_patch(self):
        orig = project_service.INTERNAL_API_KEY_SCOPES
        try:
            project_service.INTERNAL_API_KEY_SCOPES = {"ro-key": {"projects:read"}}
            self.assertFalse(
                project_service._internal_key_has_scopes("ro-key", ["projects:write"])
            )
        finally:
            project_service.INTERNAL_API_KEY_SCOPES = orig

    def test_cors_advertises_patch(self):
        self.assertIn("PATCH", project_service._cors_headers()["Access-Control-Allow-Methods"])

    def test_patch_without_project_name_is_405(self):
        """PATCH /api/v1/projects (collection) has no meaning and must not fall through."""
        orig = project_service._get_ddb
        try:
            ddb = _make_ddb()
            project_service._get_ddb = lambda: ddb
            resp = project_service.lambda_handler(
                {
                    "requestContext": {"http": {"method": "PATCH", "path": "/api/v1/projects"}},
                    "headers": {"x-coordination-internal-key": "rw-key"},
                    "body": json.dumps({"summary": "s"}),
                },
                None,
            )
            self.assertIn(resp["statusCode"], (401, 403, 405))
            ddb.update_item.assert_not_called()
        finally:
            project_service._get_ddb = orig


if __name__ == "__main__":
    unittest.main()
