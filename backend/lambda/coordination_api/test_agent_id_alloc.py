"""Tests for agent_id_alloc.py — server-side ENC-SES / ENC-AGT minting (ENC-TSK-I37).

Verifies the four task acceptance criteria server-side against real DynamoDB semantics
(moto): the two stores + monotonic counter (AC#1), server-only / monotonic / format-
enforced minting with no caller-supplied ids (AC#2), and the persisted property sets being
value-identical to the intended v4 node schemas (AC#3, the binding release gate).
"""
import datetime as dt
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


@mock_aws
class AgentMutationTest(unittest.TestCase):
    """ENC-TSK-I38: tests for claim_session, retire_session, list_*, find_agent_type."""

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

    def _mint_session(self, **kw):
        return alloc.mint_session_id(
            agent_type_id=kw.get("agent_type_id", "ENC-AGT-001"),
            runtime=kw.get("runtime", "cc-desktop"),
            status=kw.get("status", "allocated"),
        )

    def _mint_type(self, **kw):
        return alloc.mint_agent_type_id(
            surface=kw.get("surface", "Claude Desktop"),
            model=kw.get("model", "claude-sonnet-4-6"),
            cost_tier=kw.get("cost_tier", "standard"),
        )

    # -- claim_session ---------------------------------------------------

    def test_claim_allocated_session(self):
        sid = self._mint_session()["session_id"]
        item = alloc.claim_session(sid)
        self.assertEqual(item["status"], "claimed")
        self.assertTrue(item["claimed_at"])
        persisted = alloc.get_session(sid)
        self.assertEqual(persisted["status"], "claimed")

    def test_claim_with_matching_lineage(self):
        sid = self._mint_session(agent_type_id="ENC-AGT-007")["session_id"]
        item = alloc.claim_session(sid, expected_agent_type_id="ENC-AGT-007")
        self.assertEqual(item["status"], "claimed")

    def test_claim_rejects_lineage_mismatch(self):
        sid = self._mint_session(agent_type_id="ENC-AGT-001")["session_id"]
        with self.assertRaises(ValueError):
            alloc.claim_session(sid, expected_agent_type_id="ENC-AGT-999")

    def test_claim_already_claimed_raises(self):
        sid = self._mint_session(status="claimed")["session_id"]
        with self.assertRaises(ValueError):
            alloc.claim_session(sid)

    def test_claim_missing_session_raises(self):
        with self.assertRaises(ValueError):
            alloc.claim_session("ENC-SES-404")

    def test_claim_empty_session_id_raises(self):
        with self.assertRaises(ValueError):
            alloc.claim_session("")

    # -- retire_session --------------------------------------------------

    def test_retire_from_allocated(self):
        sid = self._mint_session(status="allocated")["session_id"]
        item = alloc.retire_session(sid)
        self.assertEqual(item["status"], "retired")

    def test_retire_from_claimed(self):
        sid = self._mint_session(status="claimed")["session_id"]
        item = alloc.retire_session(sid)
        self.assertEqual(item["status"], "retired")

    def test_retire_already_retired_raises(self):
        sid = self._mint_session(status="allocated")["session_id"]
        alloc.retire_session(sid)
        with self.assertRaises(ValueError):
            alloc.retire_session(sid)

    def test_retire_missing_session_raises(self):
        with self.assertRaises(ValueError):
            alloc.retire_session("ENC-SES-404")

    def test_retire_empty_session_id_raises(self):
        with self.assertRaises(ValueError):
            alloc.retire_session("")

    # -- list_sessions ---------------------------------------------------

    def test_list_sessions_excludes_counter_rows(self):
        self._mint_session()
        self._mint_session()
        sessions = alloc.list_sessions()
        ids = [s["session_id"] for s in sessions]
        self.assertNotIn("counter#ENC-SES", ids)
        self.assertIn("ENC-SES-001", ids)
        self.assertIn("ENC-SES-002", ids)
        self.assertEqual(len(sessions), 2)

    def test_list_sessions_filter_by_status(self):
        self._mint_session(status="allocated")
        self._mint_session(status="claimed")
        allocated = alloc.list_sessions(status="allocated")
        self.assertEqual(len(allocated), 1)
        self.assertEqual(allocated[0]["status"], "allocated")
        claimed = alloc.list_sessions(status="claimed")
        self.assertEqual(len(claimed), 1)

    def test_list_sessions_filter_by_agent_type_id(self):
        self._mint_session(agent_type_id="ENC-AGT-001")
        self._mint_session(agent_type_id="ENC-AGT-002")
        results = alloc.list_sessions(agent_type_id="ENC-AGT-001")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["agent_type_id"], "ENC-AGT-001")

    def test_list_sessions_empty_table(self):
        self.assertEqual(alloc.list_sessions(), [])

    # -- list_agent_types ------------------------------------------------

    def test_list_agent_types_excludes_counter_rows(self):
        self._mint_type()
        self._mint_type(model="claude-opus-4-8")
        types = alloc.list_agent_types()
        ids = [t["agent_type_id"] for t in types]
        self.assertNotIn("counter#ENC-AGT", ids)
        self.assertEqual(len(types), 2)

    def test_list_agent_types_filter_by_status(self):
        self._mint_type()
        # Can't create deprecated via mint directly, so update manually
        self.ddb.update_item(
            TableName=config.AGENT_TYPES_TABLE,
            Key={"agent_type_id": {"S": "ENC-AGT-001"}},
            UpdateExpression="SET #st = :dep",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":dep": {"S": "deprecated"}},
        )
        self._mint_type(model="claude-opus-4-8")
        deprecated = alloc.list_agent_types(status="deprecated")
        self.assertEqual(len(deprecated), 1)
        active = alloc.list_agent_types(status="active")
        self.assertEqual(len(active), 1)

    def test_list_agent_types_empty_table(self):
        self.assertEqual(alloc.list_agent_types(), [])

    # -- find_agent_type (idempotent type.register) ----------------------

    def test_find_agent_type_returns_existing(self):
        self._mint_type(surface="Claude Desktop", model="claude-sonnet-4-6")
        found = alloc.find_agent_type(surface="Claude Desktop", model="claude-sonnet-4-6")
        self.assertIsNotNone(found)
        self.assertEqual(found["model"], "claude-sonnet-4-6")

    def test_find_agent_type_returns_none_for_missing(self):
        result = alloc.find_agent_type(surface="Claude Desktop", model="nonexistent-model")
        self.assertIsNone(result)

    def test_find_agent_type_prefers_active_over_deprecated(self):
        # Mint two entries for same surface+model (simulating a stale + fresh pair)
        self._mint_type(surface="s", model="m")
        self._mint_type(surface="s", model="m")
        # Deprecate first
        self.ddb.update_item(
            TableName=config.AGENT_TYPES_TABLE,
            Key={"agent_type_id": {"S": "ENC-AGT-001"}},
            UpdateExpression="SET #st = :dep",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":dep": {"S": "deprecated"}},
        )
        found = alloc.find_agent_type(surface="s", model="m")
        self.assertIsNotNone(found)
        self.assertEqual(found["status"], "active")


@mock_aws
class IdleSweepTest(unittest.TestCase):
    """ENC-TSK-I71: scheduled idle-sweep backstop (ENC-FTR-117 AC#8).

    The append-only flip path (allocated/claimed -> retired) and idempotency are exercised
    against real DynamoDB semantics via moto. Idleness is controlled deterministically by
    injecting ``now`` rather than sleeping.
    """

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
        # An instant well after every session is minted, so freshly-minted sessions read as
        # idle against a positive threshold.
        self._future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)

    def _mint(self, **kw):
        return alloc.mint_session_id(
            agent_type_id=kw.get("agent_type_id", "ENC-AGT-001"),
            runtime=kw.get("runtime", "cc-desktop"),
            status=kw.get("status", "allocated"),
        )

    # -- AC#1: allocated/claimed idle sessions are reaped to retired ---------

    def test_sweep_retires_idle_allocated_session(self):
        sid = self._mint(status="allocated")["session_id"]
        summary = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        self.assertEqual(summary["retired_count"], 1)
        self.assertIn(sid, summary["retired"])
        self.assertEqual(alloc.get_session(sid)["status"], "retired")

    def test_sweep_retires_idle_claimed_session(self):
        sid = self._mint(status="claimed")["session_id"]
        summary = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        self.assertEqual(summary["retired_count"], 1)
        self.assertIn(sid, summary["retired"])
        self.assertEqual(alloc.get_session(sid)["status"], "retired")

    # -- AC#1: fresh sessions within the threshold are left alone ------------

    def test_sweep_leaves_fresh_sessions_untouched(self):
        sid = self._mint(status="claimed")["session_id"]
        # now() ~ mint time; a 24h threshold means the session is not yet idle.
        summary = alloc.sweep_idle_sessions(idle_threshold_seconds=86400)
        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(summary["retired_count"], 0)
        self.assertEqual(alloc.get_session(sid)["status"], "claimed")

    def test_sweep_keys_off_claimed_at_not_created_at(self):
        # Idleness is measured from the LAST lifecycle transition (claimed_at), not from
        # creation. A long-existing session that was only just (re)claimed must NOT be
        # reaped — this guards against a regression that keys off created_at alone.
        sid = self._mint(status="claimed")["session_id"]
        fresh = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.ddb.update_item(
            TableName=config.AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": sid}},
            UpdateExpression="SET created_at = :old, claimed_at = :fresh",
            ExpressionAttributeValues={
                ":old": {"S": "2000-01-01T00:00:00Z"},  # ancient creation
                ":fresh": {"S": fresh},                  # but claimed just now
            },
        )
        now_soon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
        summary = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=now_soon)
        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(alloc.get_session(sid)["status"], "claimed")

    # -- AC#2: idempotent — already-retired sessions are skipped -------------

    def test_sweep_is_idempotent_and_skips_already_retired(self):
        sid = self._mint(status="allocated")["session_id"]
        first = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        self.assertEqual(first["retired_count"], 1)
        # Second run: the now-retired session is excluded from the live-status scan, so it
        # is neither re-scanned nor re-retired — no duplicate state change.
        second = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        self.assertEqual(second["scanned_live"], 0)
        self.assertEqual(second["candidate_count"], 0)
        self.assertEqual(second["retired_count"], 0)
        self.assertEqual(alloc.get_session(sid)["status"], "retired")

    # -- AC#2: nothing is deleted (append-only) -----------------------------

    def test_sweep_never_deletes_rows(self):
        self._mint(status="allocated")
        self._mint(status="claimed")
        alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        rows = self.ddb.scan(TableName=config.AGENT_SESSIONS_TABLE)["Items"]
        ids = sorted(r["session_id"]["S"] for r in rows)
        # Both node rows AND the counter sentinel survive — only the status flipped.
        self.assertEqual(ids, ["ENC-SES-001", "ENC-SES-002", "counter#ENC-SES"])
        nodes = [r for r in rows if not r["session_id"]["S"].startswith("counter#")]
        self.assertTrue(all(r["status"]["S"] == "retired" for r in nodes))

    # -- AC#2: the idle threshold is configurable ---------------------------

    def test_sweep_threshold_is_configurable(self):
        sid = self._mint(status="claimed")["session_id"]
        now_1h = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1, minutes=1)
        # A 2-hour threshold: the ~1h-old session is NOT yet idle.
        wide = alloc.sweep_idle_sessions(idle_threshold_seconds=7200, now=now_1h)
        self.assertEqual(wide["retired_count"], 0)
        self.assertEqual(alloc.get_session(sid)["status"], "claimed")
        # A 30-minute threshold: the same session IS idle and gets reaped.
        tight = alloc.sweep_idle_sessions(idle_threshold_seconds=1800, now=now_1h)
        self.assertEqual(tight["retired_count"], 1)
        self.assertEqual(alloc.get_session(sid)["status"], "retired")

    # -- dry_run reports candidates without mutating ------------------------

    def test_sweep_dry_run_reports_without_mutating(self):
        sid = self._mint(status="allocated")["session_id"]
        summary = alloc.sweep_idle_sessions(
            idle_threshold_seconds=3600, now=self._future, dry_run=True
        )
        self.assertTrue(summary["dry_run"])
        self.assertEqual(summary["candidate_count"], 1)
        self.assertIn(sid, summary["candidate_ids"])
        self.assertEqual(summary["retired_count"], 0)
        # Untouched on disk.
        self.assertEqual(alloc.get_session(sid)["status"], "allocated")

    # -- the counter sentinel row is never a candidate ----------------------

    def test_sweep_ignores_counter_row(self):
        self._mint(status="allocated")  # also creates counter#ENC-SES
        summary = alloc.sweep_idle_sessions(idle_threshold_seconds=3600, now=self._future)
        self.assertNotIn("counter#ENC-SES", summary["candidate_ids"])
        self.assertNotIn("counter#ENC-SES", summary["retired"])
        counter = self.ddb.get_item(
            TableName=config.AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": "counter#ENC-SES"}},
        ).get("Item")
        self.assertIsNotNone(counter)

    # -- input validation ---------------------------------------------------

    def test_sweep_rejects_invalid_threshold(self):
        for bad in (-1, True, "3600", 3.5):
            with self.assertRaises(ValueError):
                alloc.sweep_idle_sessions(idle_threshold_seconds=bad, now=self._future)


@mock_aws
class SciTokenTest(unittest.TestCase):
    """ENC-ISS-441 / ENC-TSK-J92: Session Claim ID mint-on-claim + revoke-on-retire."""

    def setUp(self):
        self.ddb = boto3.client("dynamodb", region_name="us-west-2")
        for table, key in (
            (config.AGENT_SESSIONS_TABLE, "session_id"),
            (config.AGENT_TYPES_TABLE, "agent_type_id"),
            (config.CHECKOUT_TOKENS_TABLE, "pk"),
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

    def _claimed_session(self):
        minted = alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="test")
        return alloc.claim_session(minted["session_id"])

    def _token_count(self):
        return self.ddb.scan(TableName=config.CHECKOUT_TOKENS_TABLE)["Count"]

    def _get_token(self, token_id):
        resp = self.ddb.get_item(
            TableName=config.CHECKOUT_TOKENS_TABLE, Key={"pk": {"S": token_id}}
        )
        return resp.get("Item")

    # -- mint-on-claim --------------------------------------------------------
    def test_mint_sci_shape_and_binding(self):
        import time as _time

        session = self._claimed_session()
        sci = alloc.mint_sci(session)
        self.assertRegex(sci["token_id"], r"^SCI-[0-9a-f]{32}$")
        self.assertEqual(sci["token_type"], "SCI")
        self.assertEqual(sci["session_id"], session["session_id"])
        self.assertEqual(sci["agent_type_id"], "ENC-AGT-001")
        self.assertFalse(sci["revoked"])
        self.assertAlmostEqual(
            sci["ttl"], int(_time.time()) + alloc.SCI_TTL_SECONDS, delta=60
        )
        item = self._get_token(sci["token_id"])
        self.assertIsNotNone(item)
        self.assertEqual(item["token_type"]["S"], "SCI")
        self.assertEqual(item["session_id"]["S"], session["session_id"])
        self.assertFalse(item["revoked"]["BOOL"])
        # session stamped with the token id (post-mint attribute, mint shape untouched)
        stamped = alloc.get_session(session["session_id"])
        self.assertEqual(stamped["sci_token_id"], sci["token_id"])

    def test_mint_sci_requires_session_id(self):
        with self.assertRaises(ValueError):
            alloc.mint_sci({})

    def test_mint_sci_rejects_unclaimed_session(self):
        from botocore.exceptions import ClientError as _CE

        minted = alloc.mint_session_id(agent_type_id="ENC-AGT-001", runtime="test")
        with self.assertRaises(_CE):
            alloc.mint_sci(minted)  # session-stamp condition requires status=claimed

    def test_failed_claim_mints_nothing(self):
        session = self._claimed_session()
        with self.assertRaises(ValueError):
            alloc.claim_session(session["session_id"])  # double-claim rejected
        self.assertEqual(self._token_count(), 0)  # no orphan tokens

    # -- revoke-on-retire ------------------------------------------------------
    def test_revoke_sci_for_session(self):
        session = self._claimed_session()
        sci = alloc.mint_sci(session)
        revoked = alloc.revoke_sci_for_session(
            session["session_id"], reason="explicit_retire"
        )
        self.assertTrue(revoked["revoked"])
        self.assertEqual(revoked["revocation_reason"], "explicit_retire")
        self.assertTrue(revoked["revoked_at"])
        item = self._get_token(sci["token_id"])
        self.assertTrue(item["revoked"]["BOOL"])

    def test_revoke_is_idempotent_and_preserves_first_reason(self):
        session = self._claimed_session()
        alloc.mint_sci(session)
        alloc.revoke_sci_for_session(session["session_id"], reason="explicit_retire")
        second = alloc.revoke_sci_for_session(
            session["session_id"], reason="idle_ttl_exceeded"
        )
        self.assertTrue(second["revoked"])
        self.assertTrue(second.get("already_revoked"))
        stamped = alloc.get_session(session["session_id"])
        item = self._get_token(stamped["sci_token_id"])
        self.assertEqual(item["revocation_reason"]["S"], "explicit_retire")

    def test_revoke_without_token_returns_none(self):
        session = self._claimed_session()
        self.assertIsNone(alloc.revoke_sci_for_session(session["session_id"]))

    def test_revoke_missing_session_raises(self):
        with self.assertRaises(ValueError):
            alloc.revoke_sci_for_session("ENC-SES-404")


if __name__ == "__main__":
    unittest.main()
