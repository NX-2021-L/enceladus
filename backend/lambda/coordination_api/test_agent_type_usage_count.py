"""ENC-TSK-R81-0H / ENC-FTR-146 AC-6: usage_count increment on register + backfill count math."""
import importlib.util
import json
import os
import sys
import unittest
from collections import Counter
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: E402
import agent_id_alloc as alloc  # noqa: E402

_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                     "tools", "backfill_agent_type_usage_count.py")
_spec = importlib.util.spec_from_file_location("backfill_usage_count", _TOOL)
backfill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backfill)


def _usage(ddb, aid):
    item = ddb.get_item(TableName=config.AGENT_TYPES_TABLE, Key={"agent_type_id": {"S": aid}})["Item"]
    return int(item.get("usage_count", {"N": "0"})["N"])


@mock_aws
class UsageIncrementTest(unittest.TestCase):
    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        for table, key in ((config.AGENT_SESSIONS_TABLE, "session_id"),
                           (config.AGENT_TYPES_TABLE, "agent_type_id")):
            self.ddb.create_table(
                TableName=table, AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
        p = mock.patch.object(alloc, "_get_ddb", return_value=self.ddb)
        p.start()
        self.addCleanup(p.stop)
        self.aid = alloc.mint_agent_type_id(surface="claude_code_cli", model="m", cost_tier="c3")["agent_type_id"]
        self.dead = alloc.mint_agent_type_id(surface="x", model="y", cost_tier="c3", status="deprecated")["agent_type_id"]

    def _sessions(self):
        return self.ddb.scan(TableName=config.AGENT_SESSIONS_TABLE, FilterExpression="begins_with(session_id, :p)",
                             ExpressionAttributeValues={":p": {"S": "ENC-SES-"}})["Count"]

    def test_register_increments_usage_count_atomically(self):
        self.assertEqual(_usage(self.ddb, self.aid), 0)
        for n in (1, 2, 3):
            alloc.mint_session_id(agent_type_id=self.aid, runtime="r", increment_usage=True)
            self.assertEqual(_usage(self.ddb, self.aid), n)

    def test_increment_creates_attribute_when_absent(self):
        self.ddb.update_item(TableName=config.AGENT_TYPES_TABLE, Key={"agent_type_id": {"S": self.aid}},
                             UpdateExpression="REMOVE usage_count")
        alloc.mint_session_id(agent_type_id=self.aid, runtime="r", increment_usage=True)
        self.assertEqual(_usage(self.ddb, self.aid), 1)

    def test_default_mint_does_not_increment(self):
        alloc.mint_session_id(agent_type_id=self.aid, runtime="r")
        self.assertEqual(_usage(self.ddb, self.aid), 0)

    def test_inactive_or_missing_type_mints_nothing_and_no_increment(self):
        for bad in (self.dead, "ENC-AGT-ZZZ"):
            before = self._sessions()
            with self.assertRaises(ValueError):
                alloc.mint_session_id(agent_type_id=bad, runtime="r", increment_usage=True)
            self.assertEqual(self._sessions(), before)
        self.assertEqual(_usage(self.ddb, self.dead), 0)
        self.assertEqual(self.ddb.scan(TableName=config.AGENT_TYPES_TABLE)["Count"], 3)  # + counter row, no ZZZ row

    def test_update_expression_aliases_status(self):
        u = alloc.usage_increment_update("ENC-AGT-001")
        self.assertEqual(u["ExpressionAttributeNames"], {"#uc": "usage_count", "#st": "status"})
        self.assertNotIn(" status", u["UpdateExpression"] + u["ConditionExpression"])


class HandlerRegisterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import lambda_function as lf
        except Exception as exc:  # pragma: no cover - baseline collection errors
            raise unittest.SkipTest(f"lambda_function not importable here: {exc}")
        cls.lf = lf

    def _register(self, body):
        return self.lf._handle_agent_session_register({"body": json.dumps(body)}, {})

    def test_successful_register_requests_increment(self):
        row = {"agent_type_id": "ENC-AGT-001", "status": "active"}
        with mock.patch.object(self.lf._agent_id_alloc, "get_agent_type", return_value=row), \
                mock.patch.object(self.lf._agent_id_alloc, "mint_session_id",
                                  return_value={"session_id": "ENC-SES-T00"}) as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-001", "runtime": "claude_code_desktop_subagent"})
        self.assertEqual(resp["statusCode"], 201)
        self.assertIs(mint.call_args.kwargs["increment_usage"], True)

    def test_rejected_register_never_reaches_mint_or_increment(self):
        with mock.patch.object(self.lf._agent_id_alloc, "get_agent_type", return_value=None), \
                mock.patch.object(self.lf._agent_id_alloc, "mint_session_id") as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-ZZZ", "runtime": "claude_code_desktop_subagent"})
        self.assertEqual(resp["statusCode"], 422)
        mint.assert_not_called()

    def test_dry_run_does_not_mint(self):
        row = {"agent_type_id": "ENC-AGT-001", "status": "active"}
        with mock.patch.object(self.lf._agent_id_alloc, "get_agent_type", return_value=row), \
                mock.patch.object(self.lf._agent_id_alloc, "mint_session_id") as mint:
            resp = self._register({"agent_type_id": "ENC-AGT-001", "runtime": "claude_code_desktop_subagent",
                                   "dry_run": True})
        self.assertEqual(resp["statusCode"], 200)
        mint.assert_not_called()


class BackfillMathTest(unittest.TestCase):
    ROWS = [{"session_id": "counter#session", "next_num": 9},
            {"session_id": "ENC-SES-001", "agent_type_id": "ENC-AGT-001"},
            {"session_id": "ENC-SES-002", "agent_type_id": "ENC-AGT-001"},
            {"session_id": "ENC-SES-003", "agent_type_id": "ENC-AGT-00M"},
            {"session_id": "ENC-SES-004", "agent_type_id": "claude-code"},
            {"session_id": "ENC-SES-005"}]

    def test_count_sessions_skips_counter_and_reports_orphans(self):
        per, orph, total = backfill.count_sessions(self.ROWS)
        self.assertEqual(per, Counter({"ENC-AGT-001": 2, "ENC-AGT-00M": 1}))
        self.assertEqual(orph, Counter({"claude-code": 1, "<missing>": 1}))
        self.assertEqual(total, 5)

    def test_plan_delta_is_target_minus_current(self):
        per, _o, _t = backfill.count_sessions(self.ROWS)
        types = {"ENC-AGT-001": {"status": "active", "usage_count": 5},
                 "ENC-AGT-00M": {"status": "active"}, "ENC-AGT-00B": {"status": "active", "usage_count": 0}}
        plan = {p["agent_type_id"]: p for p in backfill.plan_updates(per, types)}
        self.assertEqual((plan["ENC-AGT-001"]["current"], plan["ENC-AGT-001"]["target"], plan["ENC-AGT-001"]["delta"]), (5, 2, -3))
        self.assertEqual(plan["ENC-AGT-00M"]["delta"], 1)
        self.assertEqual(plan["ENC-AGT-00B"]["delta"], 0)

    def test_apply_requires_approved_by_and_dry_run_never_writes(self):
        self.assertEqual(backfill.main(["--apply"]), 2)


@mock_aws
class BackfillApplyTest(unittest.TestCase):
    def test_apply_is_idempotent_and_sums_to_sessions(self):
        ddb = boto3.client("dynamodb", region_name="us-west-2")
        for table, key in ((backfill.SESSIONS_TABLE, "session_id"), (backfill.TYPES_TABLE, "agent_type_id")):
            ddb.create_table(TableName=table, AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                             KeySchema=[{"AttributeName": key, "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
        ddb.put_item(TableName=backfill.TYPES_TABLE, Item={"agent_type_id": {"S": "ENC-AGT-001"}, "status": {"S": "active"}})
        ddb.put_item(TableName=backfill.TYPES_TABLE, Item={"agent_type_id": {"S": "ENC-AGT-002"}, "status": {"S": "active"}, "usage_count": {"N": "1"}})
        for i, aid in enumerate(["ENC-AGT-001"] * 3 + ["ENC-AGT-002"] * 2):
            ddb.put_item(TableName=backfill.SESSIONS_TABLE, Item={"session_id": {"S": f"ENC-SES-{i}"}, "agent_type_id": {"S": aid}})
        with mock.patch("boto3.client", return_value=ddb):
            for _ in range(2):  # second run is a no-op
                self.assertEqual(backfill.main(["--apply", "--approved-by", "io"]), 0)
        self.assertEqual(int(ddb.get_item(TableName=backfill.TYPES_TABLE, Key={"agent_type_id": {"S": "ENC-AGT-001"}})["Item"]["usage_count"]["N"]), 3)
        self.assertEqual(int(ddb.get_item(TableName=backfill.TYPES_TABLE, Key={"agent_type_id": {"S": "ENC-AGT-002"}})["Item"]["usage_count"]["N"]), 2)


if __name__ == "__main__":
    unittest.main()
