"""test_hash_precondition_p70.py — Tests for ENC-TSK-P70 content-hash If-Match
precondition on put/patch/append (FR-B1-9..12).

Covers:
  AC-1: If-Match header or body field `if_match`; 64-hex -> content_hash form,
        digits -> ENC-TSK-L47 version form, anything else -> 400
        PRECONDITION_MALFORMED.
  AC-2: hash mismatch -> 412 CONTENT_HASH_MISMATCH with expected/current details;
        version mismatch still 409 REVISION_CONFLICT (see test_if_match_l47.py,
        unchanged and still green).
  AC-3: single conditional UpdateItem (content_hash = :expected_hash for the hash
        form); losing racer's staged S3 object is deleted best-effort on
        ConditionalCheckFailedException.
  AC-4: absent precondition -> precondition_absent:true in the response + a
        fire-and-forget LegacyWriteUnguarded CloudWatch metric.

Mirrors the MagicMock-based mocking style of test_if_match_l47.py / test_digest_manifest_p69.py
(no moto; _get_ddb / _get_s3 / _get_cloudwatch are patched directly).

Run: python3 -m pytest test_hash_precondition_p70.py -v
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
    "document_api_hash_precondition",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}
CONTENT_A = "# Hello\n\nOriginal body."
HASH_A = hashlib.sha256(CONTENT_A.encode("utf-8")).hexdigest()


def _doc_item(version=3, content_hash=HASH_A):
    return {
        "document_id": {"S": "DOC-P70TEST0001"},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "doc"},
        "title": {"S": "Original title"},
        "version": {"N": str(version)},
        "content_hash": {"S": content_hash},
        "updated_at": {"S": "2026-09-15T00:00:00Z"},
    }


def _event(body, if_match=None, if_match_header=None):
    payload = dict(body)
    if if_match is not None:
        payload["if_match"] = if_match
    evt = {"body": json.dumps(payload)}
    if if_match_header is not None:
        evt["headers"] = {"If-Match": if_match_header}
    return evt


class TestPreconditionMalformed(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_garbage_header_rejected_400(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item()}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match_header="not-a-valid-token"),
            CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"]).get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "PRECONDITION_MALFORMED")

    @patch.object(document_api, "_get_ddb")
    def test_body_field_garbage_rejected_400(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item()}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="zz-not-hex-or-digits"),
            CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"]).get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "PRECONDITION_MALFORMED")
        fake_ddb.update_item.assert_not_called()


class TestBodyFieldIfMatchAccepted(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_body_if_match_version_form_matches(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="3"), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertNotIn("precondition_absent", body)

    @patch.object(document_api, "_get_ddb")
    def test_header_takes_precedence_over_body(self, mock_ddb):
        # Header says the correct version (3); body says a wrong one (99). AC-1 says
        # header wins, so this should succeed rather than 409.
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="99", if_match_header="3"),
            CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)


class TestContentHashMismatch(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_stale_hash_returns_412_content_hash_mismatch(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(content_hash=HASH_A)}
        stale_hash = "0" * 64
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match=stale_hash), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 412)
        body = json.loads(resp["body"])
        envelope = body.get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "CONTENT_HASH_MISMATCH")
        details = envelope.get("details", {})
        self.assertEqual(details.get("expected_hash"), stale_hash)
        self.assertEqual(details.get("current_hash"), HASH_A)
        self.assertEqual(details.get("current_version"), 3)
        self.assertIn("updated_at", details)
        self.assertIn(
            "re-read digest via documents.manifest and retry",
            details.get("recommended_next_actions", []),
        )
        fake_ddb.update_item.assert_not_called()

    @patch.object(document_api, "_get_ddb")
    def test_matching_hash_succeeds_and_omits_precondition_absent(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(content_hash=HASH_A)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match=HASH_A), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertNotIn("precondition_absent", body)


class TestVersionMismatchStillRevisionConflict(unittest.TestCase):
    """AC-2: version mismatch must continue to return 409 REVISION_CONFLICT
    unchanged (the pre-existing L47 envelope) — see also test_if_match_l47.py."""

    @patch.object(document_api, "_get_ddb")
    def test_stale_version_still_409(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="2"), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 409)
        envelope = json.loads(resp["body"]).get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "REVISION_CONFLICT")


class TestGuardedContentWriteStagingAndConditionExpression(unittest.TestCase):
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_hash_guarded_content_write_stages_then_promotes(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3

        new_content = "# Hello\n\nUpdated body."
        resp = document_api._handle_patch(
            _event({"content": new_content}, if_match=HASH_A), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)

        # AC-3: S3 body written (to the staging key) before the conditional DDB
        # update, and only promoted (copied to canonical) after it succeeds.
        put_call = fake_s3.put_object.call_args
        self.assertIn("versions/DOC-P70TEST0001/4.md", put_call.kwargs["Key"])
        fake_s3.copy_object.assert_called_once()
        copy_kwargs = fake_s3.copy_object.call_args.kwargs
        self.assertEqual(copy_kwargs["Key"], "agent-documents/enceladus/DOC-P70TEST0001.md")
        fake_s3.delete_object.assert_not_called()

        # AC-3: ConditionExpression is content_hash = :expected_hash for the hash form.
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "content_hash = :expected_hash")
        self.assertEqual(update_kwargs["ExpressionAttributeValues"][":expected_hash"], {"S": HASH_A})

    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_conditional_failure_deletes_orphaned_staging_object(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.side_effect = [
            {"Item": _doc_item(version=3, content_hash=HASH_A)},  # initial read
            {"Item": _doc_item(version=4, content_hash="1" * 64)},  # post-conflict refresh
        ]

        class _CCFE(Exception):
            pass

        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_ddb.update_item.side_effect = _CCFE("conditional check failed")
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3

        resp = document_api._handle_patch(
            _event({"content": "# Hello\n\nRace loser."}, if_match=HASH_A),
            CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 412)
        envelope = json.loads(resp["body"]).get("error_envelope", {})
        self.assertEqual(envelope.get("code"), "CONTENT_HASH_MISMATCH")

        # AC-3: the loser's staged object must be cleaned up best-effort, never
        # promoted to the canonical key.
        fake_s3.delete_object.assert_called_once()
        del_kwargs = fake_s3.delete_object.call_args.kwargs
        self.assertIn("versions/DOC-P70TEST0001/4.md", del_kwargs["Key"])
        fake_s3.copy_object.assert_not_called()

    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_staging_delete_failure_logged_not_raised(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.side_effect = [
            {"Item": _doc_item(version=3, content_hash=HASH_A)},
            {"Item": _doc_item(version=4, content_hash="1" * 64)},
        ]

        class _CCFE(Exception):
            pass

        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_ddb.update_item.side_effect = _CCFE("conditional check failed")
        fake_s3 = MagicMock()
        fake_s3.delete_object.side_effect = RuntimeError("s3 unavailable")
        mock_s3.return_value = fake_s3

        resp = document_api._handle_patch(
            _event({"content": "# Hello\n\nRace loser."}, if_match=HASH_A),
            CLAIMS, "DOC-P70TEST0001",
        )
        # The 412 must still surface even though best-effort cleanup itself failed.
        self.assertEqual(resp["statusCode"], 412)


class TestAppendContentGuardedStaging(unittest.TestCase):
    @patch.object(document_api, "_get_content", return_value=CONTENT_A)
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_append_content_hash_guard_stages_then_promotes(self, mock_ddb, mock_s3, _mock_get_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_s3 = MagicMock()
        mock_s3.return_value = fake_s3

        resp = document_api._handle_patch(
            _event(
                {"append_content": "---\ntype: note\n---\nMore text."},
                if_match=HASH_A,
            ),
            CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        fake_s3.copy_object.assert_called_once()
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "content_hash = :expected_hash")


class TestAbsentPreconditionMetricAndFlag(unittest.TestCase):
    @patch.object(document_api, "_emit_legacy_write_unguarded_metric")
    @patch.object(document_api, "_get_ddb")
    def test_absent_precondition_flags_response_and_emits_metric(self, mock_ddb, mock_metric):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body.get("precondition_absent"))
        mock_metric.assert_called_once()
        call_args = mock_metric.call_args.args
        self.assertEqual(call_args[0], "enceladus")  # project_id
        self.assertEqual(call_args[1], "unknown")  # internal-key, no mcp UA -> unknown

    @patch.object(document_api, "_get_ddb")
    def test_metric_emission_never_raises_even_if_cloudwatch_client_fails(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3)}
        with patch.object(document_api, "_get_cloudwatch", side_effect=RuntimeError("no creds")):
            resp = document_api._handle_patch(
                _event({"title": "New title"}), CLAIMS, "DOC-P70TEST0001",
            )
        self.assertEqual(resp["statusCode"], 200)


class TestDeriveWriteSurface(unittest.TestCase):
    def test_internal_key_with_mcp_user_agent(self):
        event = {"headers": {"User-Agent": "enceladus-mcp-server/2.0"}}
        claims = {"auth_mode": "internal-key"}
        self.assertEqual(document_api._derive_write_surface(event, claims), "mcp")

    def test_internal_key_without_mcp_hint_is_unknown(self):
        event = {"headers": {}}
        claims = {"auth_mode": "internal-key"}
        self.assertEqual(document_api._derive_write_surface(event, claims), "unknown")

    def test_managed_token_is_lambda(self):
        claims = {"auth_mode": "managed-token"}
        self.assertEqual(document_api._derive_write_surface({}, claims), "lambda")

    def test_cognito_session_is_pwa(self):
        claims = {"sub": "user-123", "email": "someone@example.com"}
        self.assertEqual(document_api._derive_write_surface({}, claims), "pwa")


class TestClassifyPrecondition(unittest.TestCase):
    def test_hash_form(self):
        self.assertEqual(document_api._classify_precondition("a" * 64), "hash")

    def test_version_form(self):
        self.assertEqual(document_api._classify_precondition("42"), "version")

    def test_malformed(self):
        self.assertIsNone(document_api._classify_precondition("not-valid"))
        self.assertIsNone(document_api._classify_precondition("a" * 63))  # 63 hex chars
        self.assertIsNone(document_api._classify_precondition(""))


if __name__ == "__main__":
    unittest.main()


class TestIss763ExpressionAttributeValuesMatchConditionExpression(unittest.TestCase):
    """ENC-ISS-763 (P0, filed from a gamma 500 on every CORRECT hash-form
    guarded write): DynamoDB's UpdateItem rejects any ExpressionAttributeValues
    placeholder that neither UpdateExpression nor ConditionExpression actually
    reference ("ValidationException: ... unused in expressions"). attr_values
    must carry :expected_hash ONLY when the hash-form ConditionExpression
    ("content_hash = :expected_hash") is used, and :expected ONLY when the
    version-form ConditionExpression ("#ver = :expected") is used — never
    both, regardless of which precondition form the caller supplied."""

    @patch.object(document_api, "_get_ddb")
    def test_hash_form_carries_only_expected_hash(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match=HASH_A), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "content_hash = :expected_hash")
        values = update_kwargs["ExpressionAttributeValues"]
        self.assertIn(":expected_hash", values)
        self.assertNotIn(":expected", values)

    @patch.object(document_api, "_get_ddb")
    def test_version_form_carries_only_expected(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        resp = document_api._handle_patch(
            _event({"title": "New title"}, if_match="3"), CLAIMS, "DOC-P70TEST0001",
        )
        self.assertEqual(resp["statusCode"], 200)
        update_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "#ver = :expected")
        values = update_kwargs["ExpressionAttributeValues"]
        self.assertIn(":expected", values)
        self.assertNotIn(":expected_hash", values)
