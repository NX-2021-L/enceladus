"""test_update_field_close_versionseq_p49.py — _handle_update_field() close-path
UpdateExpression ordering (ENC-TSK-P49).

ROOT CAUSE this guards (P0, found live 2026-08-26 during the ENC-PLN-082
close-out): the generic single-field PATCH path appended " ADD closed_count
:one" to the UpdateExpression BEFORE splicing the ENC-TSK-M92 version_seq /
feed_scope SET clause, assembling

    SET ... ADD closed_count :one, version_seq = :vseq, feed_scope = :fscope

— a DynamoDB ValidationException ("Syntax error; token: '=', near:
'version_seq = :vseq'"). Every governed task close (checkout.advance →
status=closed) returned "Database write failed." Non-close field updates carry
no ADD clause, so the defect was invisible until the first post-cutover close.
The PWA close branch (test_pwa_action_versionseq_m92.CloseBranchTests) already
splices vseq before ADD; this file gives the PATCH path the same guard.

Run: python3 -m pytest test_update_field_close_versionseq_p49.py -q
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
    "tracker_mutation_close_versionseq_p49",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)


class UpdateFieldCloseVersionSeqTests(unittest.TestCase):
    """moto-backed tracker table (mirrors test_pwa_action_versionseq_m92 fixtures)."""

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

    def put_task(self, item_id="ENC-TSK-949", status="coding-complete"):
        self.ddb.put_item(
            TableName=tm.DYNAMODB_TABLE,
            Item={
                "project_id": {"S": "enceladus"},
                "record_id": {"S": f"task#{item_id}"},
                "item_id": {"S": item_id},
                "record_type": {"S": "task"},
                "status": {"S": status},
                "transition_type": {"S": "no_code"},
                "title": {"S": "P49 close-path version_seq test task"},
                "sync_version": {"N": "0"},
                "closed_count": {"N": "0"},
                "history": {"L": []},
                # Active checkout by the test provider — the FSM requires an
                # active checkout for task status transitions.
                "checkout_state": {"S": "checked_out"},
                "checked_out_by": {"S": "p49-test-suite"},
                "active_agent_session": {"BOOL": True},
                "active_agent_session_id": {"S": "p49-test-suite"},
                "checkout_transition_type": {"S": "no_code"},
            },
        )

    def get_task(self, item_id="ENC-TSK-949"):
        resp = self.ddb.get_item(
            TableName=tm.DYNAMODB_TABLE,
            Key={"project_id": {"S": "enceladus"}, "record_id": {"S": f"task#{item_id}"}},
        )
        return resp.get("Item") or {}

    def _close_body(self):
        # Non-ENC-SES provider keeps the SCI gate out of scope; the ordering
        # under test is downstream of every auth/validation branch.
        return {
            "field": "status",
            "value": "closed",
            "transition_evidence": {"no_code_evidence": "P49 regression close"},
            "write_source": {"provider": "p49-test-suite", "channel": "test"},
        }

    def test_close_update_expression_keeps_set_section_contiguous(self):
        """The vseq SET clause must precede the ADD clause — never follow it."""
        self.put_task()
        real_ddb = self.ddb
        captured = {}

        class _SpyDdb:
            def update_item(self, **kwargs):
                if kwargs.get("Key", {}).get("record_id", {}).get("S") == "task#ENC-TSK-949":
                    expr = kwargs.get("UpdateExpression", "")
                    if "closed_count" in expr:
                        captured["UpdateExpression"] = expr
                return real_ddb.update_item(**kwargs)

            def __getattr__(self, name):
                return getattr(real_ddb, name)

        with mock.patch.object(tm, "_ddb", _SpyDdb()):
            resp = tm._handle_update_field(
                "enceladus", "task", "ENC-TSK-949", self._close_body()
            )
        self.assertEqual(resp["statusCode"], 200, msg=str(resp))
        expr = captured.get("UpdateExpression", "")
        self.assertIn("version_seq = :vseq", expr)
        self.assertIn(" ADD closed_count :one", expr)
        # The load-bearing ordering assertion: every SET assignment (including
        # the spliced vseq/fscope pair) sits BEFORE the ADD keyword.
        add_pos = expr.index(" ADD ")
        self.assertLess(expr.index("version_seq = :vseq"), add_pos)
        self.assertLess(expr.index("feed_scope = :fscope"), add_pos)

    def test_close_lands_with_counter_and_version_seq(self):
        """End-to-end through moto: the close commits, counter and vseq stamp."""
        self.put_task()
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-949", self._close_body()
        )
        self.assertEqual(resp["statusCode"], 200, msg=str(resp))
        item = self.get_task()
        self.assertEqual(item["status"]["S"], "closed")
        self.assertEqual(item["closed_count"]["N"], "1")
        self.assertEqual(item["version_seq"]["N"], "1")
        self.assertEqual(item["feed_scope"]["S"], "global")


if __name__ == "__main__":
    unittest.main()
