"""test_worklog_versionseq_m79.py — _handle_log() version_seq/feed_scope stamping (ENC-TSK-M79).

Prior to this fix, `_handle_log()` (POST /{project}/{type}/{id}/log — the shared
worklog-append handler used by append_worklog/checkout-service) never stamped
version_seq/feed_scope on the updated record, so a pure worklog append never
re-surfaced the record in the feed delta projection (version-seq-index GSI).
This mirrors the generic single-field PATCH path's existing idiom: splice
`_version_seq_update_parts()` into the UpdateExpression/ExpressionAttributeValues.

Covers:
  * The allocator (`allocate_version_seq`) is invoked exactly once per
    `_handle_log()` call.
  * Both `version_seq` and `feed_scope` land in the UpdateExpression/values
    passed to `ddb.update_item`.
  * The persisted record actually carries `version_seq` (N) and
    `feed_scope` (S, "global") after the call, identically to what the
    generic PATCH path stamps on create/update.

Run: python3 -m pytest test_worklog_versionseq_m79.py -q
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
    "tracker_mutation_worklog_versionseq",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

PROVIDER = "github"


def _body(provider=PROVIDER, **extra):
    body = {"write_source": {"provider": provider, "channel": "mcp_server"}}
    body.update(extra)
    return body


class VersionSeqStampingBase(unittest.TestCase):
    """moto-backed tracker table (mirrors test_worklog_mirror_l35.py fixtures)."""

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

    def put_plan(self, item_id="ENC-PLN-901"):
        self.ddb.put_item(
            TableName=tm.DYNAMODB_TABLE,
            Item={
                "project_id": {"S": "enceladus"},
                "record_id": {"S": f"plan#{item_id}"},
                "item_id": {"S": item_id},
                "record_type": {"S": "plan"},
                "status": {"S": "drafted"},
                "title": {"S": "M79 version_seq worklog test plan"},
                "history": {"L": []},
            },
        )

    def get_plan_item(self, item_id="ENC-PLN-901"):
        resp = self.ddb.get_item(
            TableName=tm.DYNAMODB_TABLE,
            Key={"project_id": {"S": "enceladus"}, "record_id": {"S": f"plan#{item_id}"}},
        )
        return resp.get("Item") or {}


class HandleLogVersionSeqTests(VersionSeqStampingBase):
    def test_worklog_append_stamps_version_seq_and_feed_scope_on_record(self):
        # Persisted-state assertion: after a plain worklog append, the record
        # itself carries version_seq/feed_scope — the actual feed-visibility
        # fix, not just an UpdateExpression string check.
        self.put_plan()
        resp = tm._handle_log(
            "enceladus", "plan", "ENC-PLN-901",
            _body(description="worklog entry that must re-surface in the feed"),
        )
        self.assertEqual(resp["statusCode"], 200)

        item = self.get_plan_item()
        self.assertIn("version_seq", item)
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertIn("feed_scope", item)
        self.assertEqual(item["feed_scope"]["S"], "global")

    def test_allocator_invoked_exactly_once_per_log_call(self):
        self.put_plan()
        with mock.patch.object(
            tm, "allocate_version_seq", wraps=tm.allocate_version_seq
        ) as spy:
            resp = tm._handle_log(
                "enceladus", "plan", "ENC-PLN-901",
                _body(description="single-allocation check"),
            )
        self.assertEqual(resp["statusCode"], 200)
        spy.assert_called_once()

    def test_update_expression_carries_both_version_seq_and_feed_scope_attrs(self):
        # Assert the UpdateExpression/ExpressionAttributeValues actually
        # passed to ddb.update_item include both attrs — mirrors the generic
        # PATCH path's `_version_seq_update_parts()` splice idiom exactly.
        self.put_plan()
        real_ddb = self.ddb
        captured = {}

        class _SpyDdb:
            """Pass-through proxy: forwards every call to the real (moto) client,
            capturing only the update_item call that targets our test record so
            the allocator's own counter-row update_item calls aren't confused
            with the record's own write."""

            def update_item(self, **kwargs):
                if kwargs.get("Key", {}).get("record_id", {}).get("S") == "plan#ENC-PLN-901":
                    captured["UpdateExpression"] = kwargs["UpdateExpression"]
                    captured["ExpressionAttributeValues"] = kwargs["ExpressionAttributeValues"]
                return real_ddb.update_item(**kwargs)

            def __getattr__(self, name):
                return getattr(real_ddb, name)

        with mock.patch.object(tm, "_ddb", _SpyDdb()):
            resp = tm._handle_log(
                "enceladus", "plan", "ENC-PLN-901",
                _body(description="expression shape check"),
            )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("version_seq = :vseq", captured["UpdateExpression"])
        self.assertIn("feed_scope = :fscope", captured["UpdateExpression"])
        self.assertIn(":vseq", captured["ExpressionAttributeValues"])
        self.assertIn(":fscope", captured["ExpressionAttributeValues"])
        self.assertEqual(captured["ExpressionAttributeValues"][":fscope"], {"S": "global"})

    def test_sequential_worklog_appends_allocate_monotonically_increasing_seq(self):
        self.put_plan()
        tm._handle_log("enceladus", "plan", "ENC-PLN-901", _body(description="first"))
        tm._handle_log("enceladus", "plan", "ENC-PLN-901", _body(description="second"))
        item = self.get_plan_item()
        self.assertEqual(item["version_seq"]["N"], "2")


if __name__ == "__main__":
    unittest.main()
