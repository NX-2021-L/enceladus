"""Tests for agent_id_alloc.py — server-side ENC-SES / ENC-AGT minting (ENC-TSK-I37).

Verifies the four task acceptance criteria server-side against real DynamoDB semantics
(moto): the two stores + monotonic counter (AC#1), server-only / monotonic / format-
enforced minting with no caller-supplied ids (AC#2), and the persisted property sets being
value-identical to the intended v4 node schemas (AC#3, the binding release gate).
"""
import os
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import config  # noqa: E402
import agent_id_alloc as alloc  # noqa: E402


class EncodeSeqTest(unittest.TestCase):
    def test_encoding_is_min_width_3_and_unbounded(self):
        self.assertEqual(alloc.encode_seq(1), "001")
        self.assertEqual(alloc.encode_seq(2), "002")
        self.assertEqual(alloc.encode_seq(35), "00Z")
        self.assertEqual(alloc.encode_seq(36), "010")
        self.assertEqual(alloc.encode_seq(46655), "ZZZ")   # ZZZ = 36**3 - 1
        self.assertEqual(alloc.encode_seq(46656), "1000")  # grows past 3 chars cleanly

    def test_encoding_is_a_strictly_increasing_bijection(self):
        seen = set()
        prev = ""
        for n in range(1, 2000):
            s = alloc.encode_seq(n)
            self.assertNotIn(s, seen)
            seen.add(s)
            # zero-padded fixed-width-per-magnitude strings sort with the counter
            if len(s) == len(prev):
                self.assertGreater(s, prev)
            prev = s

    def test_rejects_non_positive_and_bool(self):
        for bad in (0, -1, True, False, 1.0, "1"):
            with self.assertRaises(ValueError):
                alloc.encode_seq(bad)  # type: ignore[arg-type]


@mock_aws
class MintingTest(unittest.TestCase):
    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        for table, key in (
            (config.AGENT_SESSIONS_TABLE, "session_id"),
            (config.AGENT_TYPES_TABLE, "agent_type_id"),
        ):
            self.ddb.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        patcher = mock.patch.object(alloc, "_get_ddb", return_value=self.ddb)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- AC#1 / AC#2: monotonic single-assignment ----------------------------
    def test_session_ids_are_monotonic_and_formatted(self):
        ids = [
            alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="cc-desktop")["session_id"]
            for _ in range(3)
        ]
        self.assertEqual(ids, ["ENC-SES-001", "ENC-SES-002", "ENC-SES-003"])
        self.assertEqual(len(set(ids)), 3)

    def test_agent_type_ids_are_monotonic_and_formatted(self):
        ids = [
            alloc.mint_agent_type_id(surface="Claude Desktop", model="Opus 4.8", cost_tier="premium")["agent_type_id"]
            for _ in range(3)
        ]
        self.assertEqual(ids, ["ENC-AGT-001", "ENC-AGT-002", "ENC-AGT-003"])

    def test_no_id_is_ever_reissued(self):
        minted = {
            alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r")["session_id"]
            for _ in range(50)
        }
        self.assertEqual(len(minted), 50)  # monotonic single-assignment — no reuse

    def test_session_and_agent_counters_are_independent(self):
        s = alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r")["session_id"]
        a = alloc.mint_agent_type_id(surface="Codex", model="o-x", cost_tier="standard")["agent_type_id"]
        self.assertEqual(s, "ENC-SES-001")
        self.assertEqual(a, "ENC-AGT-001")  # each id-space has its own counter

    # -- AC#2: callers can never supply an id --------------------------------
    def test_caller_supplied_session_id_rejected(self):
        with self.assertRaises(alloc.CallerSuppliedIdError):
            alloc.mint_session_id(
                agent_type_id="ENC-AGT-001", runtime="r",
                caller_payload={"session_id": "ENC-SES-999"},
            )

    def test_caller_supplied_agent_type_id_rejected(self):
        with self.assertRaises(alloc.CallerSuppliedIdError):
            alloc.mint_agent_type_id(
                surface="s", model="m", cost_tier="c",
                caller_payload={"agent_type_id": "ENC-AGT-999"},
            )

    # -- AC#3 (binding gate): item shape value-identical to v4 node schema ----
    def test_session_item_matches_v4_node_property_set(self):
        item = alloc.mint_session_id(
            agent_type_id="ENC-AGT-007", runtime="cc-desktop", parent_session_id="ENC-SES-001",
        )
        expected_keys = {"session_id", *alloc.SESSION_NODE_PROPERTIES}
        self.assertEqual(set(item.keys()), expected_keys)
        self.assertEqual(item["agent_type_id"], "ENC-AGT-007")
        self.assertEqual(item["parent_session_id"], "ENC-SES-001")
        self.assertEqual(item["status"], "allocated")  # dispatched default
        self.assertEqual(item["claimed_at"], "")        # not claimed yet
        self.assertTrue(item["created_at"])

    def test_agent_type_item_matches_v4_node_property_set(self):
        item = alloc.mint_agent_type_id(
            surface="Claude Desktop", model="Opus 4.8", cost_tier="premium", usage_count=0,
        )
        expected_keys = {"agent_type_id", *alloc.AGENT_TYPE_NODE_PROPERTIES}
        self.assertEqual(set(item.keys()), expected_keys)
        self.assertEqual(item["surface"], "Claude Desktop")
        self.assertEqual(item["model"], "Opus 4.8")
        self.assertEqual(item["cost_tier"], "premium")
        self.assertEqual(item["status"], "active")
        self.assertEqual(item["usage_count"], 0)

    def test_self_allocated_session_is_claimed_with_timestamp(self):
        item = alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r", status="claimed")
        self.assertEqual(item["status"], "claimed")
        self.assertEqual(item["claimed_at"], item["created_at"])

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r", status="bogus")
        with self.assertRaises(ValueError):
            alloc.mint_agent_type_id(surface="s", model="m", cost_tier="c", status="bogus")

    # -- AC#1: counter row coexists but is not a node ------------------------
    def test_counter_row_is_isolated_from_nodes(self):
        alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r")
        alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r")
        scan = self.ddb.scan(TableName=config.AGENT_SESSIONS_TABLE)["Items"]
        keys = [row["session_id"]["S"] for row in scan]
        self.assertIn("counter#ENC-SES", keys)               # counter persisted in-table
        nodes = [k for k in keys if not k.startswith("counter#")]
        self.assertEqual(sorted(nodes), ["ENC-SES-001", "ENC-SES-002"])
        counter_row = next(r for r in scan if r["session_id"]["S"] == "counter#ENC-SES")
        self.assertEqual(counter_row["record_kind"]["S"], "counter")
        self.assertEqual(counter_row["next_num"]["N"], "2")

    # -- read helpers (server-side verification) -----------------------------
    def test_get_round_trips_minted_records(self):
        sid = alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="r")["session_id"]
        aid = alloc.mint_agent_type_id(surface="s", model="m", cost_tier="c")["agent_type_id"]
        self.assertEqual(alloc.get_session(sid)["session_id"], sid)
        self.assertEqual(alloc.get_agent_type(aid)["agent_type_id"], aid)
        self.assertIsNone(alloc.get_session("ENC-SES-404"))


if __name__ == "__main__":
    unittest.main()
