"""test_oplog_history_p72.py — Tests for ENC-TSK-P72 operation log,
rejected-event recording, history sidecar, S3 body versioning,
documents.history / documents.diff, and at_version/at_event reads
(FR-B2-1..10).

Mirrors the MagicMock-based mocking style of test_hash_precondition_p70.py /
test_patch_section_handler_p71.py (no moto; _get_ddb / _get_s3 /
_get_cloudwatch are patched directly on the document_api module object).

Covers:
  AC-1: each write path (put, patch, append_content, patch_section,
        metadata-only patch) appends exactly one history_event in the SAME
        UpdateItem/put_item as the body/metadata write.
  AC-2: a rejected mutation (412/409/404) appends a `<op>-rejected` event via
        a separate unconditional UpdateItem, never advancing version, and
        never breaks the caller-visible error response if that bookkeeping
        write itself fails.
  AC-3: inline history rollover at the 200-event ceiling (sidecar NDJSON
        flush of the oldest 100 + history_overflow_count + history_sidecar_key).
  AC-4: version snapshot objects are written immutably (IfNoneMatch='*',
        HeadObject fallback, never silently overwritten).
  AC-5: documents.history pagination / filters / sidecar+inline merge /
        legacy placeholder for pre-existing documents.
  AC-6: documents.get?at_version=/at_event= reconstruction + hash
        verification (INTEGRITY_VIOLATION on mismatch).
  AC-7: version_seq/feed_scope are stamped via the dedicated DOCUMENTS_TABLE
        counter (enceladus_shared.version_seq's shape doesn't fit this
        table's document_id-only key schema — see _allocate_document_version_seq).

Run: python3 -m pytest test_oplog_history_p72.py -v
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
    "document_api_oplog_history",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)


CLAIMS = {"auth_mode": "internal-key", "sub": "internal-key"}
DOC_ID = "DOC-P72TEST0001"
CONTENT_A = "# Title\n\n## Alpha\n\nOriginal alpha body.\n\n## Beta\n\nBeta body.\n"
HASH_A = hashlib.sha256(CONTENT_A.encode("utf-8")).hexdigest()


class _CCFE(Exception):
    pass


def _no_such_key_exc():
    return type("NoSuchKey", (Exception,), {})


def _fake_counter_response(n=1):
    return {"Attributes": {"next_num": {"N": str(n)}}}


def _doc_item(version=3, content_hash=HASH_A, size_bytes=100, history=None):
    item = {
        "document_id": {"S": DOC_ID},
        "project_id": {"S": "enceladus"},
        "document_subtype": {"S": "doc"},
        "title": {"S": "Test doc"},
        "version": {"N": str(version)},
        "content_hash": {"S": content_hash},
        "size_bytes": {"N": str(size_bytes)},
        "s3_key": {"S": f"agent-documents/enceladus/{DOC_ID}.md"},
        "created_at": {"S": "2026-09-01T00:00:00Z"},
        "created_by": {"S": "creator@example.com"},
        "updated_at": {"S": "2026-09-15T00:00:00Z"},
    }
    if history is not None:
        item["history"] = {"L": history}
    return item


def _req(payload, if_match=None):
    body = dict(payload)
    if if_match is not None:
        body["if_match"] = if_match
    return {"body": json.dumps(body)}


def _mk_event(**overrides):
    kwargs = dict(
        event_id="EVT0000", ts="2026-09-15T00:00:00Z", actor="a", surface="mcp",
        op="patch", anchor=None, before_hash="h0", after_hash="h1",
        before_version=0, after_version=1, patch_bytes=None, document_bytes=1,
        caused_by=None, idempotency_key=None,
    )
    kwargs.update(overrides)
    return document_api._section_history_event(**kwargs)


class TestAC1EventPerWritePath(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_metadata_only_patch_appends_one_event_same_update_item(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.update_item.return_value = _fake_counter_response()

        resp = document_api._handle_patch(_req({"title": "New title"}), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)

        self.assertEqual(fake_ddb.update_item.call_count, 2)  # counter, then the record write
        main_call = fake_ddb.update_item.call_args_list[-1].kwargs
        self.assertIn("history = list_append", main_call["UpdateExpression"])
        self.assertIn("title = :", main_call["UpdateExpression"])
        self.assertIn("version_seq = :p72_vseq", main_call["UpdateExpression"])
        self.assertIn("feed_scope = :p72_fscope", main_call["UpdateExpression"])
        event = main_call["ExpressionAttributeValues"][":p72_new_event"]["L"][0]["M"]
        self.assertEqual(event["op"]["S"], "metadata")
        self.assertEqual(event["fields_changed"]["L"][0]["S"], "title")
        self.assertEqual(event["patch_bytes"], {"NULL": True})

    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_content_patch_appends_one_event_op_patch(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.update_item.return_value = _fake_counter_response()
        mock_s3.return_value = MagicMock()

        resp = document_api._handle_patch(_req({"content": "# New content body."}), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        main_call = fake_ddb.update_item.call_args_list[-1].kwargs
        event = main_call["ExpressionAttributeValues"][":p72_new_event"]["L"][0]["M"]
        self.assertEqual(event["op"]["S"], "patch")
        # dictionary contract: patch_bytes is null for whole-document put/patch (not a delta).
        self.assertEqual(event["patch_bytes"], {"NULL": True})

    @patch.object(document_api, "_get_content", return_value=CONTENT_A)
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_append_content_appends_one_event_with_patch_bytes(self, mock_ddb, mock_s3, _mc):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.update_item.return_value = _fake_counter_response()
        mock_s3.return_value = MagicMock()

        resp = document_api._handle_patch(_req({"append_content": "More."}), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        main_call = fake_ddb.update_item.call_args_list[-1].kwargs
        event = main_call["ExpressionAttributeValues"][":p72_new_event"]["L"][0]["M"]
        self.assertEqual(event["op"]["S"], "append_content")
        self.assertEqual(event["patch_bytes"], {"N": str(len("More.".encode("utf-8")))})

    @patch.object(document_api, "_get_content")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_patch_section_appends_one_event_op_replace(self, mock_ddb, mock_s3, mock_content):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.exceptions.ConditionalCheckFailedException = _CCFE
        fake_ddb.update_item.return_value = _fake_counter_response()
        mock_s3.return_value = MagicMock()
        mock_content.return_value = CONTENT_A

        payload = {
            "anchor": {"heading_path": ["Alpha"]}, "op": "replace",
            "body": "New alpha body.", "governance_hash": "abc123",
        }
        resp = document_api._handle_patch_section(_req(payload, if_match=HASH_A), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 200)
        main_call = fake_ddb.update_item.call_args_list[-1].kwargs
        self.assertIn("version_seq = :p72_vseq", main_call["UpdateExpression"])
        self.assertIn("feed_scope = :p72_fscope", main_call["UpdateExpression"])

    @patch.object(document_api, "_validate_project_exists", return_value=None)
    @patch.object(document_api, "_upload_content",
                  return_value=("agent-documents/enceladus/DOC-NEW.md", "abc123hash", 42))
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_put_create_appends_initial_event_op_put(self, mock_ddb, mock_s3, _mock_upload, _mock_proj):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.put_item.return_value = {}
        fake_ddb.update_item.return_value = _fake_counter_response()
        mock_s3.return_value = MagicMock()

        resp = document_api._handle_put({"body": json.dumps({
            "project_id": "enceladus", "title": "New Doc", "content": "# Hello\n\nBody.",
            "keywords": [], "document_subtype": "doc",
        })}, CLAIMS)
        self.assertEqual(resp["statusCode"], 201)
        fake_ddb.put_item.assert_called_once()
        item = fake_ddb.put_item.call_args.kwargs["Item"]
        self.assertIn("history", item)
        events = item["history"]["L"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["M"]["op"]["S"], "put")
        self.assertEqual(events[0]["M"]["before_hash"], {"NULL": True})
        self.assertEqual(events[0]["M"]["before_version"], {"N": "0"})
        self.assertEqual(events[0]["M"]["after_version"], {"N": "1"})
        self.assertIn("version_seq", item)
        self.assertIn("feed_scope", item)


class TestAC2RejectedEvents(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_content_hash_mismatch_appends_rejected_event_no_version_advance(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.update_item.return_value = _fake_counter_response()

        resp = document_api._handle_patch(_req({"title": "x"}, if_match="0" * 64), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 412)

        self.assertEqual(fake_ddb.update_item.call_count, 2)  # counter + rejected-event bookkeeping
        bookkeeping_call = fake_ddb.update_item.call_args_list[-1].kwargs
        self.assertNotIn("ConditionExpression", bookkeeping_call)
        event = bookkeeping_call["ExpressionAttributeValues"][":p72_new_event"]["L"][0]["M"]
        self.assertEqual(event["op"]["S"], "metadata-rejected")
        self.assertEqual(event["rejection_code"]["S"], "CONTENT_HASH_MISMATCH")
        self.assertEqual(event["before_version"], event["after_version"])

    @patch.object(document_api, "_get_ddb")
    def test_rejected_event_bookkeeping_failure_does_not_break_response(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, content_hash=HASH_A)}
        fake_ddb.update_item.side_effect = RuntimeError("ddb unavailable")

        resp = document_api._handle_patch(_req({"title": "x"}, if_match="0" * 64), CLAIMS, DOC_ID)
        self.assertEqual(resp["statusCode"], 412)  # best-effort: bookkeeping failure is swallowed


class TestAC3SidecarRollover(unittest.TestCase):
    @patch.object(document_api, "_get_s3")
    def test_rollover_at_200_flushes_oldest_100_to_sidecar(self, mock_s3):
        fake_s3 = MagicMock()
        fake_s3.exceptions.NoSuchKey = _no_such_key_exc()
        fake_s3.get_object.side_effect = fake_s3.exceptions.NoSuchKey()
        mock_s3.return_value = fake_s3

        existing = [
            document_api._ddb_value_from_python(_mk_event(
                event_id=f"EVT{i:04d}", ts=f"2026-01-01T00:{i:02d}:00Z",
                before_version=i, after_version=i + 1,
            ))
            for i in range(200)
        ]
        new_event = _mk_event(event_id="EVT0200", ts="2026-01-01T03:20:00Z", before_version=200, after_version=201)

        set_clauses, values = document_api._history_append_parts(existing, new_event, "enceladus", DOC_ID)

        fake_s3.put_object.assert_called_once()
        put_kwargs = fake_s3.put_object.call_args.kwargs
        self.assertIn(f"{DOC_ID}.history.jsonl", put_kwargs["Key"])
        lines = put_kwargs["Body"].decode("utf-8").strip().splitlines()
        self.assertEqual(len(lines), 100)
        self.assertEqual(json.loads(lines[0])["event_id"], "EVT0000")
        self.assertEqual(json.loads(lines[-1])["event_id"], "EVT0099")

        self.assertIn("history = :p72_new_history", set_clauses)
        self.assertIn(
            "history_overflow_count = if_not_exists(history_overflow_count, :p72_hoc_zero) + :p72_hoc_inc",
            set_clauses,
        )
        self.assertIn("history_sidecar_key = :p72_hsk", set_clauses)
        new_history = values[":p72_new_history"]["L"]
        self.assertEqual(len(new_history), 101)  # 100 remainder + 1 new
        self.assertEqual(new_history[0]["M"]["event_id"]["S"], "EVT0100")
        self.assertEqual(new_history[-1]["M"]["event_id"]["S"], "EVT0200")
        self.assertEqual(values[":p72_hoc_inc"], {"N": "100"})

    @patch.object(document_api, "_get_s3")
    def test_no_rollover_under_cap(self, mock_s3):
        set_clauses, values = document_api._history_append_parts([], _mk_event(), "enceladus", DOC_ID)
        mock_s3.assert_not_called()
        self.assertEqual(
            set_clauses,
            ["history = list_append(if_not_exists(history, :p72_empty_history), :p72_new_event)"],
        )
        self.assertEqual(values[":p72_empty_history"], {"L": []})


class TestAC4VersionImmutability(unittest.TestCase):
    def test_if_none_match_supported_used_directly(self):
        fake_s3 = MagicMock()
        document_api._put_version_object_immutable(fake_s3, "agent-documents/enceladus/versions/D/1.md", b"content")
        fake_s3.put_object.assert_called_once()
        self.assertEqual(fake_s3.put_object.call_args.kwargs.get("IfNoneMatch"), "*")

    def test_if_none_match_unsupported_falls_back_to_head_then_put(self):
        fake_s3 = MagicMock()
        fake_s3.put_object.side_effect = [TypeError("unexpected kwarg 'IfNoneMatch'"), None]
        from botocore.exceptions import ClientError
        fake_s3.head_object.side_effect = ClientError({"Error": {"Code": "404"}}, "HeadObject")
        document_api._put_version_object_immutable(fake_s3, "k", b"content")
        self.assertEqual(fake_s3.put_object.call_count, 2)
        fake_s3.head_object.assert_called_once()

    def test_existing_version_object_never_overwritten(self):
        fake_s3 = MagicMock()
        fake_s3.put_object.side_effect = TypeError("unexpected kwarg")
        fake_s3.head_object.return_value = {}  # exists -> no fallback put
        document_api._put_version_object_immutable(fake_s3, "k", b"content")
        self.assertEqual(fake_s3.put_object.call_count, 1)


class TestAC5DocumentsHistory(unittest.TestCase):
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_pagination_filters_and_merge(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        inline_events = [
            document_api._ddb_value_from_python(_mk_event(
                event_id=f"IN{i}", ts=f"2026-09-15T00:0{i}:00Z", actor="alice",
                before_version=i, after_version=i + 1,
            ))
            for i in range(3)
        ]
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=3, history=inline_events)}

        fake_s3 = MagicMock()
        fake_s3.exceptions.NoSuchKey = _no_such_key_exc()
        fake_s3.get_object.side_effect = fake_s3.exceptions.NoSuchKey()
        fake_s3.head_object.side_effect = fake_s3.exceptions.NoSuchKey()
        mock_s3.return_value = fake_s3

        resp = document_api._handle_document_history(DOC_ID, {"page_size": "2"})
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(len(body["events"]), 2)
        self.assertEqual(body["events"][0]["event_id"], "IN0")
        self.assertIsNotNone(body["next_cursor"])
        self.assertFalse(body["events"][0]["diff_available"])

        resp2 = document_api._handle_document_history(DOC_ID, {"page_size": "2", "cursor": body["next_cursor"]})
        body2 = json.loads(resp2["body"])
        self.assertEqual(len(body2["events"]), 1)
        self.assertEqual(body2["events"][0]["event_id"], "IN2")
        self.assertIsNone(body2["next_cursor"])

        resp3 = document_api._handle_document_history(DOC_ID, {"actor": "alice", "op": "patch"})
        self.assertEqual(len(json.loads(resp3["body"])["events"]), 3)
        resp4 = document_api._handle_document_history(DOC_ID, {"actor": "bob"})
        self.assertEqual(len(json.loads(resp4["body"])["events"]), 0)

    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_document_with_no_history_gets_legacy_placeholder(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=1, history=None)}
        fake_s3 = MagicMock()
        fake_s3.exceptions.NoSuchKey = _no_such_key_exc()
        fake_s3.get_object.side_effect = fake_s3.exceptions.NoSuchKey()
        mock_s3.return_value = fake_s3

        resp = document_api._handle_document_history(DOC_ID, {})
        body = json.loads(resp["body"])
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["op"], "legacy")
        self.assertIsNone(body["events"][0]["before_hash"])


class TestAC6AtVersionAtEvent(unittest.TestCase):
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_at_version_hash_match_reconstructed(self, mock_ddb, mock_s3):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        version_content = "# Old body\n"
        version_hash = hashlib.sha256(version_content.encode("utf-8")).hexdigest()
        history = [document_api._ddb_value_from_python(_mk_event(
            event_id="EVT1", after_hash=version_hash, before_version=1, after_version=2,
            document_bytes=len(version_content),
        ))]
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=2, history=history)}

        fake_s3 = MagicMock()
        fake_s3.exceptions.NoSuchKey = _no_such_key_exc()
        fake_s3.get_object.side_effect = [
            fake_s3.exceptions.NoSuchKey(),  # sidecar read (none)
            {"Body": MagicMock(read=lambda: version_content.encode("utf-8"))},  # version object
        ]
        mock_s3.return_value = fake_s3

        resp = document_api._get_single(DOC_ID, {"at_version": "2"})
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["reconstructed"])
        self.assertEqual(body["content"], version_content)
        self.assertEqual(body["content_hash"], version_hash)

    @patch.object(document_api, "_get_cloudwatch")
    @patch.object(document_api, "_get_s3")
    @patch.object(document_api, "_get_ddb")
    def test_at_version_hash_mismatch_500_integrity_violation(self, mock_ddb, mock_s3, mock_cw):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        history = [document_api._ddb_value_from_python(_mk_event(
            event_id="EVT1", after_hash="expectedhash", before_version=1, after_version=2,
        ))]
        fake_ddb.get_item.return_value = {"Item": _doc_item(version=2, history=history)}

        fake_s3 = MagicMock()
        fake_s3.exceptions.NoSuchKey = _no_such_key_exc()
        fake_s3.get_object.side_effect = [
            fake_s3.exceptions.NoSuchKey(),
            {"Body": MagicMock(read=lambda: b"corrupted content")},
        ]
        mock_s3.return_value = fake_s3
        mock_cw.return_value = MagicMock()

        resp = document_api._get_single(DOC_ID, {"at_version": "2"})
        self.assertEqual(resp["statusCode"], 500)
        envelope = json.loads(resp["body"])["error_envelope"]
        self.assertEqual(envelope["code"], "INTEGRITY_VIOLATION")
        mock_cw.return_value.put_metric_data.assert_called_once()


class TestAC7VersionSeqStamping(unittest.TestCase):
    @patch.object(document_api, "_get_ddb")
    def test_allocate_document_version_seq_uses_counter_sentinel_key(self, mock_ddb):
        fake_ddb = MagicMock()
        mock_ddb.return_value = fake_ddb
        fake_ddb.update_item.return_value = _fake_counter_response(42)
        seq = document_api._allocate_document_version_seq()
        self.assertEqual(seq, 42)
        call_kwargs = fake_ddb.update_item.call_args.kwargs
        self.assertEqual(call_kwargs["Key"], {"document_id": {"S": "__COUNTER__VERSION_SEQ__"}})
        self.assertNotIn("ConditionExpression", call_kwargs)


if __name__ == "__main__":
    unittest.main()
