"""test_if_match_l47.py — Tests for ENC-TSK-L47 If-Match / HTTP 409 revision contract.

Covers the three ACs defined on ENC-TSK-L47:
  AC-1: sync_version is echoed on read (already covered by test_counter_fields.py /
        existing _deser_item behavior) and on write (this file: response body).
  AC-2: If-Match header, when present, is compared against the current server-side
        sync_version. Mismatch -> HTTP 409 with current server-side field values in
        the body. Match -> the write proceeds and sync_version increments.
  AC-3: concurrent-write simulation — a stale If-Match produces 409, a fresh
        If-Match produces a successful write with an incremented revision.

Absence of the If-Match header must leave today's unconditional-write behavior
fully intact (backward compatibility for every existing agent/PWA caller that
does not send the header).

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
    "tracker_mutation",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tracker_mutation)


def _mock_task_item(sync_version=3, **extra):
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": "task#ENC-TSK-L47T"},
        "item_id": {"S": "ENC-TSK-L47T"},
        "status": {"S": "in-progress"},
        "record_type": {"S": "task"},
        "sync_version": {"N": str(sync_version)},
        "history": {"L": []},
        "checkout_count": {"N": "0"},
        "closed_count": {"N": "0"},
        "title": {"S": "Original title"},
    }
    item.update(extra)
    return item


def _event_with_if_match(value):
    return {"headers": {"If-Match": value}}


def _call(body, event=None):
    return tracker_mutation._handle_update_field(
        "enceladus", "task", "ENC-TSK-L47T", body, event=event,
    )


class TestNoIfMatchHeaderUnchanged(unittest.TestCase):
    """Absent header: unconditional write, matching pre-L47 behavior exactly."""

    def test_write_succeeds_without_condition_expression(self):
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_task_item(sync_version=3)}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call({"field": "title", "value": "New title", "provider": "codex"})
        self.assertEqual(result.get("statusCode"), 200)
        kwargs = mock_ddb.update_item.call_args.kwargs
        self.assertNotIn("ConditionExpression", kwargs)
        body = json.loads(result["body"])
        self.assertTrue(body.get("success"))
        # AC-1: revision is echoed on write too.
        self.assertEqual(body.get("sync_version"), 4)


class TestIfMatchFreshRevisionSucceeds(unittest.TestCase):
    """AC-2 / AC-3: a fresh If-Match proceeds and increments the revision."""

    def test_matching_if_match_writes_and_guards_commit(self):
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_task_item(sync_version=3)}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call(
                {"field": "title", "value": "New title", "provider": "codex"},
                event=_event_with_if_match("3"),
            )
        self.assertEqual(result.get("statusCode"), 200)
        kwargs = mock_ddb.update_item.call_args.kwargs
        self.assertEqual(kwargs.get("ConditionExpression"), "sync_version = :if_match_expected")
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":if_match_expected"], {"N": "3"},
        )
        body = json.loads(result["body"])
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("sync_version"), 4)

    def test_quoted_etag_style_if_match_is_accepted(self):
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_task_item(sync_version=3)}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call(
                {"field": "title", "value": "New title", "provider": "codex"},
                event=_event_with_if_match('"3"'),
            )
        self.assertEqual(result.get("statusCode"), 200)


class TestIfMatchStaleRevisionConflicts(unittest.TestCase):
    """AC-2 / AC-3: a stale If-Match is rejected with 409 + current field values."""

    def test_stale_if_match_returns_409_with_current_record(self):
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_task_item(sync_version=3)}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call(
                {"field": "title", "value": "New title", "provider": "codex"},
                event=_event_with_if_match("2"),
            )
        self.assertEqual(result.get("statusCode"), 409)
        mock_ddb.update_item.assert_not_called()
        body = json.loads(result["body"])
        self.assertFalse(body.get("success"))
        envelope = body.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "REVISION_CONFLICT")
        details = envelope.get("details", {})
        self.assertEqual(details.get("expected_revision"), "2")
        self.assertEqual(details.get("current_revision"), 3)
        self.assertEqual(details.get("current", {}).get("title"), "Original title")

    def test_race_between_precheck_and_commit_also_conflicts(self):
        """Simulates a write landing between the pre-check and the commit: the
        ConditionExpression must catch it even though the early check passed."""
        from botocore.exceptions import ClientError

        mock_ddb = MagicMock()
        mock_ddb.get_item.side_effect = [
            {"Item": _mock_task_item(sync_version=3)},   # initial read (pre-check passes)
            {"Item": _mock_task_item(sync_version=4)},    # refetch after conflict
        ]
        conflict = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
            "UpdateItem",
        )
        mock_ddb.update_item.side_effect = conflict
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call(
                {"field": "title", "value": "New title", "provider": "codex"},
                event=_event_with_if_match("3"),
            )
        self.assertEqual(result.get("statusCode"), 409)
        body = json.loads(result["body"])
        envelope = body.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "REVISION_CONFLICT")
        self.assertEqual(envelope.get("details", {}).get("current_revision"), 4)


if __name__ == "__main__":
    unittest.main()
