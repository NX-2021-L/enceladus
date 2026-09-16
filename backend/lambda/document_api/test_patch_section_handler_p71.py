"""test_patch_section_handler_p71.py — Handler-level tests for
POST /documents/{document_id}/sections (ENC-TSK-P71, FR-B1-13..25).

Mirrors the MagicMock-based mocking style of test_hash_precondition_p70.py
(no moto; _get_ddb / _get_s3 / _get_content are patched directly on the
document_api module object).

Covers:
  AC-1: request-shape validation (op enum, anchor presence, OP_BODY_*,
        governance_hash presence).
  AC-6: if_match required (428) / hash-only (400 malformed) / mismatch (412);
        atomic staged write + single conditional UpdateItem; idempotency
        replay (200 IDEMPOTENT_REPLAY, no re-apply).
  AC-7: BODY_TOO_LARGE (413), DOCUMENT_TOO_LARGE (413), dry_run (no write).
  AC-8: success response field shape.

Run: python3 -m pytest test_patch_section_handler_p71.py -v
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "document_api_patch_section",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}
DOC_ID = "DOC-P71TEST0001"
CONTENT_A = "# Title\n\n## Alpha\n\nOriginal alpha body.\n\n## Beta\n\nBeta body.\n"
HASH_A = hashlib.sha256(CONTENT_A.encode("utf-8")).hexdigest()


class _CCFE(Exception):
    pass


def _doc_item(version=3, content_hash=HASH_A, section_idempotency=None):
    item = {
        "document_id": {"S": DOC_ID},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "doc"},
        "title": {"S": "Test doc"},
        "version": {"N": str(version)},
        "content_hash": {"S": content_hash},
        "s3_key": {"S": "agent-documents/enceladus/DOC-P71TEST0001.md"},
        "updated_at": {"S": "2026-09-15T00:00:00Z"},
    }
    if section_idempotency is not None:
        item["section_idempotency"] = {"M": section_idempotency}
    return item


def _req(payload, if_match=None):
    body = dict(payload)
    if if_match is not None:
        body["if_match"] = if_match
    return {"body": json.dumps(body)}


def _base_payload(**overrides):
    payload = {
        "anchor": {"heading_path": ["Alpha"]},
        "op": "replace",
        "body": "New alpha body.",
        "governance_hash": "abc123",
    }
    payload.update(overrides)
    return payload


class TestRequestShapeValidation(unittest.TestCase):
    def test_invalid_op_400(self):
        resp = document_api._handle_patch_section(
            _req(_base_payload(op="frobnicate"), if_match=HASH_A), CLAIMS, DOC_ID,
        )
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "INVALID_INPUT")

    def test_missing_anchor_400(self):
        payload = _base_payload()
        del payload["anchor"]
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "ANCHOR_INVALID")

    def test_delete_with_body_400_op_body_forbidden(self):
        payload = _base_payload(op="delete", body="not allowed")
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "OP_BODY_FORBIDDEN")

    def test_replace_without_body_400_op_body_required(self):
        payload = _base_payload(op="replace")
        del payload["body"]
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "OP_BODY_REQUIRED")

    def test_body_too_large_413(self):
        payload = _base_payload(body="x" * (262_144 + 1))
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 413)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertEqual(envelope["code"], "BODY_TOO_LARGE")
        self.assertEqual(envelope["details"]["limit_bytes"], 262_144)

    def test_governance_hash_missing_400(self):
        payload = _base_payload()
        del payload["governance_hash"]
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 400)

    def test_if_match_missing_428(self):
        resp = document_api._handle_patch_section(_req(_base_payload()), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 428)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "PRECONDITION_REQUIRED")

    def test_if_match_version_form_rejected_400(self):
        # patch_section is hash-only; the L47 version-counter form is malformed here.
        resp = document_api._handle_patch_section(_req(_base_payload(), if_match="3"), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "PRECONDITION_MALFORMED")


class TestDocumentAndAnchorLookup(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_document_not_found_404(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {}
        resp = document_api._handle_patch_section(_req(_base_payload(), if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 404)

    @patch.object(document_api, "_get_ddb")
    def test_content_hash_mismatch_412(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(content_hash="1" * 64)}
        resp = document_api._handle_patch_section(_req(_base_payload(), if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 412)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "CONTENT_HASH_MISMATCH")

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_ddb")
    def test_anchor_not_found_404_includes_outline(self, mock_ddb, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item()}
        mock_content.return_value = CONTENT_A
        payload = _base_payload(anchor={"heading_path": ["Nonexistent"]})
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "ANCHOR_NOT_FOUND")
        self.assertIn("outline", body["error_envelope"]["details"])
        outline_entries = body["error_envelope"]["details"]["outline"]
        self.assertGreater(len(outline_entries), 0)
        # ENC-TSK-P71-internal span fields must not leak into the response.
        for entry in outline_entries:
            self.assertNotIn("header_start_ln", entry)
            self.assertNotIn("header_end_ln", entry)


class TestSuccessfulWrite(unittest.TestCase):
    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_replace_happy_path_response_shape_and_calls(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        mock_content.return_value = CONTENT_A

        resp = document_api._handle_patch_section(
            _req(_base_payload(caused_by="ENC-TSK-P71-test"), if_match=HASH_A), CLAIMS, DOC_ID,
        )
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertTrue(payload["success"])
        self.assertEqual(payload["document_id"], DOC_ID)
        self.assertEqual(payload["version"], 4)
        self.assertEqual(len(payload["content_hash"]), 64)
        self.assertIn("size_bytes", payload)
        self.assertEqual(len(payload["event_id"]), 26)  # ULID
        self.assertEqual(payload["anchor_resolved"]["heading_path"], ["Alpha"])
        self.assertIn("bytes_changed", payload)
        self.assertIsInstance(payload["outline"], list)

        # Staged write then promote, never a direct canonical put.
        fake_s3.put_object.assert_called_once()
        put_kwargs = fake_s3.put_object.call_args.kwargs
        self.assertIn("versions/DOC-P71TEST0001/4.md", put_kwargs["Key"])
        fake_s3.copy_object.assert_called_once()
        copy_kwargs = fake_s3.copy_object.call_args.kwargs
        self.assertEqual(copy_kwargs["Key"], "agent-documents/enceladus/DOC-P71TEST0001.md")

        # Single conditional UpdateItem, content_hash = :expected_hash.
        fake_ddb.update_item.assert_called_once()
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "content_hash = :expected_hash")
        self.assertEqual(update_kwargs["ExpressionAttributeValues"][":expected_hash"], {"S": HASH_A})
        self.assertIn("list_append", update_kwargs["UpdateExpression"])
        self.assertIn("#ver = #ver + :one", update_kwargs["UpdateExpression"])

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_conditional_failure_deletes_staged_object_412(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.side_effect = [
            {"Item": _doc_item(version=3, content_hash=HASH_A)},
            {"Item": _doc_item(version=4, content_hash="2" * 64)},
        ]
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_ddb.update_item.side_effect = _CCFE("conditional check failed")
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        mock_content.return_value = CONTENT_A

        resp = document_api._handle_patch_section(_req(_base_payload(), if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 412)
        self.assertEqual(json.loads(resp["body"])["error_envelope"]["code"], "CONTENT_HASH_MISMATCH")
        fake_s3.delete_object.assert_called_once()
        fake_s3.copy_object.assert_not_called()

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_dry_run_does_not_write(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3
        mock_content.return_value = CONTENT_A

        resp = document_api._handle_patch_section(
            _req(_base_payload(dry_run=True), if_match=HASH_A), CLAIMS, DOC_ID,
        )
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertTrue(payload["dry_run"])
        self.assertIn("content_hash", payload)
        self.assertIn("bytes_changed", payload)
        self.assertIn("diff", payload)
        fake_ddb.update_item.assert_not_called()
        fake_s3.put_object.assert_not_called()

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_document_too_large_413(self, mock_ddb, mock_s3, mock_content):
        big_content = "# Title\n\n## Alpha\n\n" + ("y" * 900_000) + "\n\n## Beta\n\nBeta body.\n"
        big_hash = hashlib.sha256(big_content.encode("utf-8")).hexdigest()
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=big_hash)}
        mock_s3.return_value = MagicMock()
        mock_content.return_value = big_content

        payload = _base_payload(
            op="append", body="z" * 200_000, anchor={"heading_path": ["Beta"]},
        )
        resp = document_api._handle_patch_section(_req(payload, if_match=big_hash), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 413)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertEqual(envelope["code"], "DOCUMENT_TOO_LARGE")
        self.assertIn("limit_bytes", envelope["details"])
        self.assertIn("would_be_bytes", envelope["details"])
        fake_ddb.update_item.assert_not_called()


class TestIdempotency(unittest.TestCase):
    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_ddb")
    def test_replay_returns_200_without_reapplying(self, mock_ddb, mock_content):
        stored_response = {
            "success": True, "document_id": DOC_ID, "version": 4,
            "content_hash": "3" * 64, "size_bytes": 123, "event_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "anchor_resolved": {"heading_path": ["Alpha"], "level": 2, "ordinal": 1, "block_id": None},
            "bytes_changed": 5, "outline": [],
        }
        idem_map = {
            "idem-key-1": {
                "M": {
                    "if_match": {"S": HASH_A},
                    "response_json": {"S": json.dumps(stored_response)},
                    "expires_at": {"N": str(int(__import__("time").time()) + 3600)},
                }
            }
        }
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {
            "Item": _doc_item(version=4, content_hash="3" * 64, section_idempotency=idem_map),
        }
        mock_content.return_value = CONTENT_A  # should never be consulted

        payload = _base_payload(idempotency_key="idem-key-1")
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["replayed"])
        self.assertEqual(body["code"], "IDEMPOTENT_REPLAY")
        self.assertEqual(body["content_hash"], "3" * 64)
        fake_ddb.update_item.assert_not_called()

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_idempotency_key_persisted_on_write(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        mock_s3.return_value = MagicMock()
        mock_content.return_value = CONTENT_A

        payload = _base_payload(idempotency_key="idem-key-2")
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertIn("section_idempotency = :idem_map", update_kwargs["UpdateExpression"])
        idem_map = update_kwargs["ExpressionAttributeValues"][":idem_map"]["M"]
        self.assertIn("idem-key-2", idem_map)
        self.assertEqual(idem_map["idem-key-2"]["M"]["if_match"], {"S": HASH_A})


if __name__ == "__main__":
    unittest.main()
