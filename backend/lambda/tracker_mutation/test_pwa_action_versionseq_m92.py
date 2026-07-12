"""test_pwa_action_versionseq_m92.py — _handle_pwa_action() version_seq/feed_scope stamping (ENC-TSK-M92).

ROOT CAUSE this guards (P0): the PWA close/note/reopen/worklog button routes
through `_handle_pwa_action()`, NOT through `_handle_log()` (the MCP/checkout
path M79 patched). Prior to this fix none of `_handle_pwa_action`'s four
mutating branches stamped version_seq/feed_scope, so a gamma-native human UI
write LANDED (record updated, history appended) but never re-surfaced in the
feed-delta projection (version-seq-index GSI). Live symptom: io's worklog note
on ENC-TSK-L83 (2026-07-12T05:29:31Z, the `[USER] `-prefixed worklog branch)
landed but /api/v1/feed/delta latest_version_seq stayed pinned at 622.

The danger this class carries (per M92 AC-4): the socket connects and the UI
renders, so the system LOOKS healthy while carrying zero realtime traffic — a
silent non-publish. These tests fail if any PWA mutation stops advancing
version_seq, so the class cannot recur undetected.

Covers all four branches (worklog / note / close / reopen):
  * Persisted record carries version_seq (N) and feed_scope (S, "global").
  * The allocator (allocate_version_seq) is invoked exactly once per call.
  * Both attrs land in the UpdateExpression/values passed to ddb.update_item
    (worklog branch — the load-bearing path).
  * version_seq advances monotonically across successive PWA writes.
  * close still increments closed_count atomically (ADD clause preserved
    alongside the spliced SET vseq clause).

Run: python3 -m pytest test_pwa_action_versionseq_m92.py -q
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_pwa_versionseq",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)


class PwaActionVersionSeqBase(unittest.TestCase):
    """moto-backed tracker table (mirrors test_worklog_versionseq_m79.py fixtures)."""

    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        self.ddb.create_table(
            TableName=tm.DYNAMODB_TABLE,
            AttributeDefinitions=[
                {"AttributeName": "project_id", "AttributeType": "S"},
                {"AttributeName": "record_id", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "project_id", "KeyType": "HASH"},
                {"AttributeName": "record_id", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        for table, key in (
            (tm.CHECKOUT_TOKENS_TABLE, "pk"),
            (tm.AGENT_SESSIONS_TABLE, "session_id"),
            (tm.PROJECTS_TABLE, "project_id"),
        ):
            self.ddb.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        patcher = mock.patch.object(tm, "_ddb", self.ddb)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put_task(self, item_id="ENC-TSK-901", status="in-progress"):
        self.ddb.put_item(
            TableName=tm.DYNAMODB_TABLE,
            Item={
                "project_id": {"S": "enceladus"},
                "record_id": {"S": f"task#{item_id}"},
                "item_id": {"S": item_id},
                "record_type": {"S": "task"},
                "status": {"S": status},
                "title": {"S": "M92 pwa version_seq test task"},
                "sync_version": {"N": "0"},
                "history": {"L": []},
            },
        )

    def get_task(self, item_id="ENC-TSK-901"):
        resp = self.ddb.get_item(
            TableName=tm.DYNAMODB_TABLE,
            Key={"project_id": {"S": "enceladus"}, "record_id": {"S": f"task#{item_id}"}},
        )
        return resp.get("Item") or {}


class WorklogBranchTests(PwaActionVersionSeqBase):
    def test_worklog_stamps_version_seq_and_feed_scope_on_record(self):
        # The load-bearing path: io's L83 note traversed this branch.
        self.put_task()
        resp = tm._handle_pwa_action(
            "enceladus", "task", "ENC-TSK-901",
            {"note": "human worklog note that must publish to the feed"},
            "worklog",
        )
        self.assertEqual(resp["statusCode"], 200)
        item = self.get_task()
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertEqual(item["feed_scope"]["S"], "global")
        # The [USER] prefix that identified this branch in the live evidence.
        self.assertEqual(
            item["history"]["L"][-1]["M"]["description"]["S"],
            "[USER] human worklog note that must publish to the feed",
        )

    def test_allocator_invoked_exactly_once_per_call(self):
        self.put_task()
        with mock.patch.object(
            tm, "allocate_version_seq", wraps=tm.allocate_version_seq
        ) as spy:
            resp = tm._handle_pwa_action(
                "enceladus", "task", "ENC-TSK-901",
                {"note": "single-allocation check"}, "worklog",
            )
        self.assertEqual(resp["statusCode"], 200)
        spy.assert_called_once()

    def test_update_expression_carries_both_version_seq_and_feed_scope(self):
        self.put_task()
        real_ddb = self.ddb
        captured = {}

        class _SpyDdb:
            def update_item(self, **kwargs):
                if kwargs.get("Key", {}).get("record_id", {}).get("S") == "task#ENC-TSK-901":
                    captured["UpdateExpression"] = kwargs["UpdateExpression"]
                    captured["ExpressionAttributeValues"] = kwargs["ExpressionAttributeValues"]
                return real_ddb.update_item(**kwargs)

            def __getattr__(self, name):
                return getattr(real_ddb, name)

        with mock.patch.object(tm, "_ddb", _SpyDdb()):
            resp = tm._handle_pwa_action(
                "enceladus", "task", "ENC-TSK-901",
                {"note": "expression shape check"}, "worklog",
            )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("version_seq = :vseq", captured["UpdateExpression"])
        self.assertIn("feed_scope = :fscope", captured["UpdateExpression"])
        self.assertEqual(captured["ExpressionAttributeValues"][":fscope"], {"S": "global"})

    def test_sequential_worklogs_advance_version_seq_monotonically(self):
        self.put_task()
        tm._handle_pwa_action("enceladus", "task", "ENC-TSK-901", {"note": "first"}, "worklog")
        tm._handle_pwa_action("enceladus", "task", "ENC-TSK-901", {"note": "second"}, "worklog")
        item = self.get_task()
        self.assertEqual(item["version_seq"]["N"], "2")


class NoteBranchTests(PwaActionVersionSeqBase):
    def test_note_stamps_version_seq_and_feed_scope(self):
        self.put_task()
        resp = tm._handle_pwa_action(
            "enceladus", "task", "ENC-TSK-901",
            {"note": "a pending-update note"}, "note",
        )
        self.assertEqual(resp["statusCode"], 200)
        item = self.get_task()
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertEqual(item["feed_scope"]["S"], "global")


class CloseBranchTests(PwaActionVersionSeqBase):
    def test_close_stamps_version_seq_and_preserves_closed_count_add(self):
        # Regression: the spliced SET vseq clause must not break the ` ADD
        # closed_count :one` clause (SET ... , version_seq=:vseq ADD ...).
        self.put_task(status="in-progress")
        resp = tm._handle_pwa_action(
            "enceladus", "task", "ENC-TSK-901", {}, "close",
        )
        self.assertEqual(resp["statusCode"], 200)
        item = self.get_task()
        self.assertEqual(item["status"]["S"], "closed")
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertEqual(item["feed_scope"]["S"], "global")
        self.assertEqual(item["closed_count"]["N"], "1")


class ReopenBranchTests(PwaActionVersionSeqBase):
    def test_reopen_stamps_version_seq_and_feed_scope(self):
        self.put_task(status="closed")
        resp = tm._handle_pwa_action(
            "enceladus", "task", "ENC-TSK-901", {}, "reopen",
        )
        self.assertEqual(resp["statusCode"], 200)
        item = self.get_task()
        self.assertEqual(item["status"]["S"], "open")
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertEqual(item["feed_scope"]["S"], "global")


if __name__ == "__main__":
    unittest.main()
