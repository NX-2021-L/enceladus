"""test_noop_suppression_r28.py -- no-op write suppression (ENC-TSK-R28, ENC-PLN-100 C2.3).

Cardinal rule under test: a suppressed write must NEVER cause a valid governance
gate to fail. Identical single-field sets short-circuit with {"no_op": true} and no
DynamoDB write ONLY when TRACKER_NOOP_SUPPRESSION=true and no carve-out applies
(worklog/history, evidence, touch, freshness-gate fields, status, live task state).

Run: python3 -m pytest test_noop_suppression_r28.py -q
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
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
    "tracker_mutation_noop_suppression_r28",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tm = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

PROJECT = "enceladus"
WS = {"provider": "r28-test-suite", "channel": "test"}  # non-ENC-SES: SCI gate out of scope


class _CountingDdb:
    """Delegating wrapper that records every mutating call against the tracker table."""

    def __init__(self, real):
        self._real = real
        self.writes = []

    def update_item(self, **kw):
        self.writes.append(("update_item", kw))
        return self._real.update_item(**kw)

    def put_item(self, **kw):
        self.writes.append(("put_item", kw))
        return self._real.put_item(**kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


class NoOpSuppressionTests(unittest.TestCase):
    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        real = boto3.client("dynamodb", region_name="us-west-2")
        real.create_table(
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
            real.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        self.real = real
        self.ddb = _CountingDdb(real)
        p = mock.patch.object(tm, "_ddb", self.ddb)
        p.start()
        self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {"TRACKER_NOOP_SUPPRESSION": "true"})
        env.start()
        self.addCleanup(env.stop)

    # -- fixtures -----------------------------------------------------------
    def put_issue(self, item_id="ENC-ISS-9001", **extra):
        item = {
            "project_id": {"S": PROJECT},
            "record_id": {"S": f"issue#{item_id}"},
            "item_id": {"S": item_id},
            "record_type": {"S": "issue"},
            "status": {"S": "open"},
            "title": {"S": "same title"},
            "documentation_evidence": {"S": '["DOC-AAAA11112222"]'},
            "evidence": {"L": [{"M": {"description": {"S": "d"}, "steps_to_duplicate": {"L": [{"S": "s"}]}}}]},
            "auto_walk_opt_out": {"BOOL": False},
            "sync_version": {"N": "3"},
            "updated_at": {"S": "2026-01-01T00:00:00Z"},
            "history": {"L": []},
        }
        item.update(extra)
        self.real.put_item(TableName=tm.DYNAMODB_TABLE, Item=item)
        return item_id

    def put_task(self, item_id="ENC-TSK-9001", status="coding-complete", checked_out=False):
        item = {
            "project_id": {"S": PROJECT},
            "record_id": {"S": f"task#{item_id}"},
            "item_id": {"S": item_id},
            "record_type": {"S": "task"},
            "status": {"S": status},
            "title": {"S": "same title"},
            "sync_version": {"N": "1"},
            "updated_at": {"S": "2026-01-01T00:00:00Z"},
            "history": {"L": []},
        }
        if checked_out:
            item.update({
                "active_agent_session": {"BOOL": True},
                "active_agent_session_id": {"S": WS["provider"]},
                "checkout_state": {"S": "checked_out"},
            })
        self.real.put_item(TableName=tm.DYNAMODB_TABLE, Item=item)
        return item_id

    def stored(self, rtype, item_id):
        return self.real.get_item(
            TableName=tm.DYNAMODB_TABLE,
            Key={"project_id": {"S": PROJECT}, "record_id": {"S": f"{rtype}#{item_id}"}},
        ).get("Item", {})

    def patch(self, rtype, item_id, field, value, **extra):
        body = {"field": field, "value": value, "write_source": dict(WS)}
        body.update(extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            resp = tm._handle_update_field(PROJECT, rtype, item_id, body)
        return resp, json.loads(resp["body"]), buf.getvalue()

    def tracker_writes(self):
        """EVERY mutating call on the tracker table (record writes + counter allocations)."""
        return [w for w in self.ddb.writes if w[1].get("TableName") == tm.DYNAMODB_TABLE]

    def record_writes(self):
        """Only the UpdateItem/PutItem against the patched record itself."""
        return [
            w for w in self.tracker_writes()
            if str((w[1].get("Key") or {}).get("record_id", {}).get("S", "")).split("#")[0] in ("issue", "task")
        ]

    # -- AC1: identical set -> no_op, zero writes ----------------------------
    def test_identical_set_returns_no_op_and_performs_no_write(self):
        iid = self.put_issue()
        before = self.stored("issue", iid)
        with mock.patch.object(tm, "_version_seq_update_parts") as vseq:
            resp, body, _ = self.patch("issue", iid, "title", "same title")
        self.assertEqual(resp["statusCode"], 200, msg=str(resp))
        self.assertTrue(body["success"])
        self.assertIs(body["no_op"], True)
        self.assertEqual(body["sync_version"], 3)
        self.assertEqual(self.tracker_writes(), [])
        vseq.assert_not_called()  # the version_seq counter write is saved too
        self.assertEqual(self.stored("issue", iid), before)

    def test_different_value_still_writes(self):
        iid = self.put_issue()
        resp, body, out = self.patch("issue", iid, "title", "new title")
        self.assertEqual(resp["statusCode"], 200, msg=str(resp))
        self.assertNotIn("no_op", body)
        self.assertEqual(len(self.record_writes()), 1)
        self.assertEqual(self.stored("issue", iid)["title"]["S"], "new title")
        self.assertEqual(self.stored("issue", iid)["sync_version"]["N"], "4")
        self.assertNotIn("TrackerNoOpSuppressed", out)

    def test_type_difference_is_not_a_noop(self):
        iid = self.put_issue(effort={"S": "1"})
        resp, body, _ = self.patch("issue", iid, "effort", 1)  # N "1" != S "1"
        self.assertNotIn("no_op", body)
        self.assertEqual(len(self.record_writes()), 1)

    def test_absent_attribute_is_not_a_noop(self):
        iid = self.put_issue()
        resp, body, _ = self.patch("issue", iid, "owner_note", "")
        self.assertNotIn("no_op", body)
        self.assertEqual(len(self.record_writes()), 1)

    # -- AC3: metric ----------------------------------------------------------
    def test_suppressed_write_emits_emf_metric(self):
        iid = self.put_issue()
        _, body, out = self.patch("issue", iid, "title", "same title")
        self.assertIs(body["no_op"], True)
        emf = json.loads(out.strip().splitlines()[-1])
        directive = emf["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual(directive["Metrics"][0]["Name"], "TrackerNoOpSuppressed")
        self.assertEqual(directive["Namespace"], "Enceladus/Tracker")
        self.assertEqual(emf["TrackerNoOpSuppressed"], 1)
        self.assertEqual(emf["RecordType"], "issue")
        self.assertEqual(emf["Field"], "title")

    def test_metric_failure_never_breaks_the_response(self):
        iid = self.put_issue()
        with mock.patch("builtins.print", side_effect=OSError("stdout closed")):
            resp = tm._handle_update_field(
                PROJECT, "issue", iid,
                {"field": "title", "value": "same title", "write_source": dict(WS)},
            )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIs(json.loads(resp["body"])["no_op"], True)

    # -- AC4: flag ------------------------------------------------------------
    def test_flag_off_and_unset_behave_exactly_as_before(self):
        iid = self.put_issue()
        for env in ({"TRACKER_NOOP_SUPPRESSION": "false"}, {"TRACKER_NOOP_SUPPRESSION": ""}):
            self.ddb.writes.clear()
            with mock.patch.dict(os.environ, env):
                resp, body, out = self.patch("issue", iid, "title", "same title")
            self.assertEqual(resp["statusCode"], 200, msg=str(resp))
            self.assertNotIn("no_op", body)
            self.assertEqual(len(self.record_writes()), 1)
            self.assertNotIn("TrackerNoOpSuppressed", out)
        with mock.patch.dict(os.environ):
            os.environ.pop("TRACKER_NOOP_SUPPRESSION", None)
            self.ddb.writes.clear()
            _, body, _ = self.patch("issue", iid, "title", "same title")
            self.assertNotIn("no_op", body)
            self.assertEqual(len(self.record_writes()), 1)

    # -- AC2: never-suppress carve-outs --------------------------------------
    def assert_writes(self, rtype, iid, field, value, **extra):
        self.ddb.writes.clear()
        resp, body, out = self.patch(rtype, iid, field, value, **extra)
        self.assertNotEqual(body.get("no_op"), True, msg=f"{field} was suppressed")
        self.assertNotIn("TrackerNoOpSuppressed", out)
        self.assertGreaterEqual(len(self.record_writes()), 1, msg=f"{field}: expected a real write ({resp})")

    def test_documentation_evidence_is_never_suppressed(self):
        # read by the checkout_service P7 novelty-or-freshness close gate (ruling A10)
        iid = self.put_issue()
        self.assert_writes("issue", iid, "documentation_evidence", '["DOC-AAAA11112222"]')

    def test_evidence_fields_are_never_suppressed(self):
        iid = self.put_issue()
        same = self.stored("issue", iid)["evidence"]
        self.assert_writes("issue", iid, "evidence", tm._deser_val(same))
        self.assert_writes("issue", iid, "deploy_evidence", "x")
        self.assert_writes("issue", iid, "live_validation_evidence", "x")
        self.assert_writes("issue", iid, "acceptance_criteria", [{"description": "a"}])

    def test_touch_and_freshness_fields_are_never_suppressed(self):
        iid = self.put_issue()
        self.assert_writes("issue", iid, "updated_at", "2026-01-01T00:00:00Z")
        self.assert_writes("issue", iid, "sync_version", 3)
        self.assert_writes("issue", iid, "touch", "x")
        self.assert_writes("issue", iid, "last_update_note", "x")
        self.assert_writes("issue", iid, "title", "same title", touch=True)
        self.assert_writes("issue", iid, "title", "same title", force=True)

    def test_worklog_history_and_status_are_never_suppressed(self):
        iid = self.put_issue()
        self.assert_writes("issue", iid, "history", [])
        self.assert_writes("issue", iid, "worklog", "x")
        self.assert_writes("issue", iid, "status", "open")  # closed_count / lifecycle semantics
        self.assert_writes("issue", iid, "auto_walk_opt_out", False)  # explicit set records a marker

    def test_transition_evidence_in_body_is_never_suppressed(self):
        iid = self.put_issue()
        self.assert_writes("issue", iid, "title", "same title", transition_evidence={"documentation_evidence": ["DOC-A"]})

    def test_if_match_request_is_never_suppressed(self):
        iid = self.put_issue()
        self.ddb.writes.clear()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), mock.patch.object(tm, "_extract_if_match", return_value="3"):
            resp = tm._handle_update_field(
                PROJECT, "issue", iid, {"field": "title", "value": "same title", "write_source": dict(WS)}
            )
        self.assertEqual(resp["statusCode"], 200, msg=str(resp))
        self.assertNotIn("no_op", json.loads(resp["body"]))
        self.assertEqual(len(self.record_writes()), 1)
        self.assertEqual(self.stored("issue", iid)["sync_version"]["N"], "4")

    def test_live_task_liveness_is_never_suppressed(self):
        # updated_at is the liveness signal for stale_checkout_monitor / auto-checkout
        tid = self.put_task(status="coding-complete", checked_out=True)
        self.assert_writes("task", tid, "title", "same title")
        tid2 = self.put_task("ENC-TSK-9002", status="in-progress")
        self.assert_writes("task", tid2, "title", "same title")
        tid3 = self.put_task("ENC-TSK-9003", status="open")
        self.assert_writes("task", tid3, "title", "same title")

    def test_idle_post_coding_task_noop_is_suppressed(self):
        tid = self.put_task("ENC-TSK-9004", status="merged-main")
        _, body, _ = self.patch("task", tid, "title", "same title")
        self.assertIs(body["no_op"], True)
        self.assertEqual(self.tracker_writes(), [])

    def test_validation_errors_are_not_masked_by_suppression(self):
        # priority carries a validator; an invalid value must still 4xx even if it
        # somehow equalled the stored value.
        iid = self.put_issue(priority={"S": "P-bogus"})
        resp, body, _ = self.patch("issue", iid, "priority", "P-bogus")
        self.assertEqual(resp["statusCode"], 400, msg=str(resp))
        self.assertNotIn("no_op", body)

    # -- pure decision function ----------------------------------------------
    def test_decision_function_table(self):
        raw = {"title": {"S": "t"}, "documentation_evidence": {"S": "x"}}
        ok = dict(field="title", value="t", raw_item=raw, item_data={}, record_type="issue", body={})
        self.assertTrue(tm._is_suppressible_noop(**ok))
        for override in (
            dict(field="documentation_evidence", value="x"),
            dict(field="title", value="u"),
            dict(field="title", body={"touch": True}),
            dict(field="title", if_match="1"),
            dict(field="related_task_ids", value=[]),
        ):
            self.assertFalse(tm._is_suppressible_noop(**{**ok, **override}), msg=str(override))


if __name__ == "__main__":
    unittest.main()
