"""Tests for document_api lesson-candidate curation-state support (ENC-TSK-J46 / ENC-FTR-096 Ph2).

Validates:
- _list_by_project honors the handoff_status filter (also usable for candidate
  curation-state) and the created_at sort used by candidate queues.
- PATCH handoff_status on a lesson-candidate document requires Cognito auth for
  the gated transitions (pending -> approved / stale); an internal-key (agent)
  session gets 403.
- Valid pending -> approved / pending -> stale transitions succeed for a Cognito
  session; invalid values / transitions are rejected.
- handoff_status remains blocked on non-handoff, non-lesson-candidate subtypes.
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
    "document_api_lesson_candidate",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


COGNITO_CLAIMS = {"auth_mode": "cognito", "sub": "user-sub", "email": "lead@example.com"}
INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}


def _event(body):
    return {"body": json.dumps(body)}


def _candidate_item(handoff_status="pending"):
    return {
        "document_id": {"S": "DOC-CANDIDATE01"},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "lesson-candidate"},
        "handoff_status": {"S": handoff_status},
        "version": {"N": "1"},
    }


class ListByProjectFilterTests(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_handoff_status_filter(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.scan.return_value = {
            "Items": [
                _candidate_item("pending"),
                dict(_candidate_item("approved"), document_id={"S": "DOC-CANDIDATE02"}),
            ]
        }
        resp = document_api._list_by_project(
            {"project": "enceladus", "handoff_status": "pending"}
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["documents"][0]["document_id"], "DOC-CANDIDATE01")

    @patch.object(document_api, "_get_ddb")
    def test_created_at_sort(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        older = dict(_candidate_item(), document_id={"S": "DOC-OLD"}, created_at={"S": "2026-01-01T00:00:00Z"})
        newer = dict(_candidate_item(), document_id={"S": "DOC-NEW"}, created_at={"S": "2026-06-01T00:00:00Z"})
        fake_ddb.scan.return_value = {"Items": [newer, older]}
        resp = document_api._list_by_project(
            {"project": "enceladus", "document_subtype": "lesson-candidate", "sort": "created_at"}
        )
        body = json.loads(resp["body"])
        self.assertEqual([d["document_id"] for d in body["documents"]], ["DOC-OLD", "DOC-NEW"])


class LessonCandidatePatchGateTests(unittest.TestCase):
    @patch.object(document_api, "_authenticate", return_value=(INTERNAL_CLAIMS, None))
    @patch.object(document_api, "_get_ddb")
    def test_internal_key_cannot_approve(self, mock_ddb, _auth):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _candidate_item("pending")}
        resp = document_api._handle_patch(
            _event({"handoff_status": "approved"}), INTERNAL_CLAIMS, "DOC-CANDIDATE01"
        )
        self.assertEqual(resp["statusCode"], 403)

    @patch.object(document_api, "_get_ddb")
    def test_cognito_can_reject_to_stale(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _candidate_item("pending")}

        with patch.object(document_api, "_get_content", return_value="body"), \
             patch.object(document_api, "_upload_content", return_value=("s3key", "hash", 4)):
            resp = document_api._handle_patch(
                _event({"handoff_status": "stale", "append_content": "Rejected: not useful."}),
                COGNITO_CLAIMS,
                "DOC-CANDIDATE01",
            )
        self.assertEqual(resp["statusCode"], 200)

    @patch.object(document_api, "_get_ddb")
    def test_invalid_status_value_rejected(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _candidate_item("pending")}
        resp = document_api._handle_patch(
            _event({"handoff_status": "bogus"}), COGNITO_CLAIMS, "DOC-CANDIDATE01"
        )
        self.assertEqual(resp["statusCode"], 400)

    @patch.object(document_api, "_get_ddb")
    def test_terminal_state_cannot_be_re_decided(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _candidate_item("approved")}
        resp = document_api._handle_patch(
            _event({"handoff_status": "stale"}), COGNITO_CLAIMS, "DOC-CANDIDATE01"
        )
        self.assertEqual(resp["statusCode"], 400)

    @patch.object(document_api, "_get_ddb")
    def test_handoff_status_blocked_on_other_subtypes(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        other = dict(_candidate_item("pending"), document_subtype={"S": "doc"})
        fake_ddb.get_item.return_value = {"Item": other}
        resp = document_api._handle_patch(
            _event({"handoff_status": "approved"}), COGNITO_CLAIMS, "DOC-CANDIDATE01"
        )
        self.assertEqual(resp["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
