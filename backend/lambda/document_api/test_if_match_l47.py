"""test_if_match_l47.py — Tests for ENC-TSK-L47 If-Match / HTTP 409 revision contract.

Covers the three ACs defined on ENC-TSK-L47:
  AC-1: version is echoed on read/write (write case asserted here — read echo
        already covered by the existing _get_single / _deserialize_item path).
  AC-2: If-Match header, when present, is compared against the current
        server-side version. Mismatch -> HTTP 409 with current server-side
        field values in the body. Match -> the write proceeds and version
        increments.
  AC-3: concurrent-write simulation — a stale If-Match produces 409, a fresh
        If-Match produces a successful write with an incremented revision.

Absence of the If-Match header must leave today's unconditional-PATCH
behavior fully intact.

Run: python3 -m pytest test_if_match_l47.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api_if_match",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}


def _doc_item(version=3):
    return {
        "document_id": {"S": "DOC-L47TEST0001"},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "doc"},
        "title": {"S": "Original title"},
        "version": {"N": str(version)},
    }


def _event(body, if_match=None):
    evt = {"body": json.dumps(body)}
    if if_match is not None:
        evt["headers"] = {"If-Match": if_match}
    return evt


class TestNoIfMatchHeaderUnchanged(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_write_succeeds_without_condition_on_expected(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}), CLAIMS, "DOC-L47TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        kwargs = fake_ddb.update_item.call_args.kwargs
        # Existing behavior preserved: ConditionExpression still guards against
        # same-request races, keyed off the freshly-read version (unconditional
        # from the caller's perspective since no If-Match was supplied).
        self.assertEqual(kwargs["ExpressionAttributeValues"][":expected"], {"N": "3"})
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("version"), 4)


class TestIfMatchFreshRevisionSucceeds(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_matching_if_match_writes(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="3"), CLAIMS, "DOC-L47TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("version"), 4)

    @patch.object(document_api, "_get_ddb")
    def test_quoted_etag_style_if_match_is_accepted(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match='"3"'), CLAIMS, "DOC-L47TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)


class TestIfMatchStaleRevisionConflicts(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_stale_if_match_returns_409_with_current_document(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="2"), CLAIMS, "DOC-L47TEST0001",
        )
        self.assertEqual(resp["statusCode"], 409)
        fake_ddb.update_item.assert_not_called()
        body = json.loads(resp["body"])
        self.assertFalse(body.get("success"))
        envelope = body.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "REVISION_CONFLICT")
        details = envelope.get("details", {})
        self.assertEqual(details.get("expected_revision"), "2")
        self.assertEqual(details.get("current_revision"), 3)
        self.assertEqual(details.get("current", {}).get("title"), "Original title")

    @patch.object(document_api, "_get_ddb")
    def test_race_between_precheck_and_commit_also_conflicts(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.side_effect = [
            {"Item": _doc_item(version=3)},   # initial read (pre-check passes)
            {"Item": _doc_item(version=4)},   # refetch after conflict
        ]

        class _FakeConditionalCheckFailedException(Exception):
            pass

        fake_ddb.exceptions.ConditionalCheckFailedException = _FakeConditionalCheckFailedException
        fake_ddb.update_item.side_effect = _FakeConditionalCheckFailedException()

        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="3"), CLAIMS, "DOC-L47TEST0001",
        )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        envelope = body.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "REVISION_CONFLICT")
        self.assertEqual(envelope.get("details", {}).get("current_revision"), 4)


if __name__ == "__main__":
    unittest.main()
