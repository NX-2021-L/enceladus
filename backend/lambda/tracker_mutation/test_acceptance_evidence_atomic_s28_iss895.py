"""test_acceptance_evidence_atomic_iss895.py -- ENC-ISS-895 / ENC-TSK-S52.

tracker.set_acceptance_evidence is a first-class governed write: one TransactWriteItems carries the record
update (criterion rewrite + history + stamps), the audit item and, when keyed, the idempotency marker.
Runs against moto's DynamoDB so TransactionCanceledException rollback semantics are real.
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
    "tracker_mutation_ace_audit_iss895", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

PROJECT = "enceladus"
TASK = "ENC-TSK-9"
WS = {"provider": "iss895-test-suite", "channel": "test"}
PATH = f"/api/v1/tracker/{PROJECT}/task/{TASK}/acceptance-evidence"
RESPONSE_KEYS = {"success", "record_id", "criterion_index", "evidence_acceptance", "updated_at",
                 "criteria_summary", "all_criteria_accepted", "completion_eligible"}


class _Ctx:
    aws_request_id = "req-iss895"
    memory_limit_in_mb = 512
    function_version = "$LATEST"


class _TxnSpy:
    def __init__(self, real):
        self._real = real
        self.txns = []

    def transact_write_items(self, **kw):
        self.txns.append(kw["TransactItems"])
        return self._real.transact_write_items(**kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


class AcceptanceEvidenceAtomicTests(unittest.TestCase):
    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        env = mock.patch.dict(os.environ, {"WRITE_FAULT_INJECT": ""})
        env.start()
        self.addCleanup(env.stop)
        tm._WA.clear()
        self.addCleanup(tm._WA.clear)
        real = boto3.client("dynamodb", region_name="us-west-2")
        real.create_table(
            TableName=tm.DYNAMODB_TABLE,
            AttributeDefinitions=[{"AttributeName": "project_id", "AttributeType": "S"},
                                  {"AttributeName": "record_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "project_id", "KeyType": "HASH"},
                       {"AttributeName": "record_id", "KeyType": "RANGE"}],
            BillingMode="PAY_PER_REQUEST",
        )
        self.real = real
        self.spy = _TxnSpy(real)
        tm._wa_ddb_attach(real)
        p = mock.patch.object(tm, "_ddb", self.spy)
        p.start()
        self.addCleanup(p.stop)
        real.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            "project_id": {"S": PROJECT}, "record_id": {"S": f"task#{TASK}"}, "item_id": {"S": TASK},
            "record_type": {"S": "task"}, "status": {"S": "open"}, "title": {"S": "t"},
            "sync_version": {"N": "1"}, "updated_at": {"S": "2026-01-01T00:00:00Z"}, "history": {"L": []},
            "acceptance_criteria": {"L": [
                {"M": {"description": {"S": "first"}, "evidence": {"S": ""}, "evidence_acceptance": {"BOOL": False}}},
                {"M": {"description": {"S": "second"}, "evidence": {"S": ""}, "evidence_acceptance": {"BOOL": False}}},
            ]}})

    # -- helpers ----------------------------------------------------------
    def scan(self, prefix=""):
        items = self.real.scan(TableName=tm.DYNAMODB_TABLE)["Items"]
        return [i for i in items if i["project_id"]["S"].startswith(prefix)]

    def stored(self):
        return self.real.get_item(TableName=tm.DYNAMODB_TABLE, Key={
            "project_id": {"S": PROJECT}, "record_id": {"S": f"task#{TASK}"}})["Item"]

    @staticmethod
    def kinds(ops):
        out = []
        for op in ops:
            kind = next(iter(op))
            out.append(kind + ":" + (op[kind].get("Item", {}).get("project_id") or
                                     op[kind].get("Key", {}).get("project_id"))["S"].split("#")[0])
        return out

    def call(self, headers=None, **extra):
        """Full lambda_handler path (wrapper seeds _WA, injects the ack, emits [WRITE-AUDIT])."""
        body = {"criterion_index": 0, "evidence": "proof", "evidence_acceptance": True, "write_source": dict(WS)}
        body.update(extra)
        ev = {"httpMethod": "POST", "rawPath": PATH, "headers": headers or {}, "body": json.dumps(body)}
        buf = io.StringIO()

        def inner(e, c):
            return tm._handle_acceptance_evidence(PROJECT, "task", TASK, json.loads(e["body"]))

        with mock.patch.object(tm, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
            resp = tm.lambda_handler(ev, _Ctx())
        lines = [json.loads(ln.split("[WRITE-AUDIT] ", 1)[1]) for ln in buf.getvalue().splitlines()
                 if ln.startswith("[WRITE-AUDIT] ")]
        return resp, lines

    # -- tests ------------------------------------------------------------
    def test_one_transaction_record_plus_audit_with_stamps(self):
        resp, (line,) = self.call(headers={"X-Correlation-Id": "corr-ace-1"})
        self.assertEqual(resp["statusCode"], 200, msg=resp["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:audit"])
        it = self.stored()
        ac0 = it["acceptance_criteria"]["L"][0]["M"]
        self.assertEqual((ac0["evidence"]["S"], ac0["evidence_acceptance"]["BOOL"], ac0["description"]["S"]),
                         ("proof", True, "first"))
        self.assertFalse(it["acceptance_criteria"]["L"][1]["M"]["evidence_acceptance"]["BOOL"])
        self.assertEqual(it["sync_version"]["N"], "2")
        self.assertEqual(it["correlation_id"]["S"], "corr-ace-1")
        self.assertEqual(it["write_tool"]["S"], "tracker.set_acceptance_evidence")
        self.assertEqual(it["projection_status"]["S"], "pending")
        self.assertIn("t_ack", it)
        self.assertIn("version_seq", it)
        # history worklog entry preserved
        (h,) = it["history"]["L"]
        self.assertTrue(h["M"]["description"]["S"].startswith("Acceptance criterion [0] evidence accepted"))
        self.assertEqual(h["M"]["status"]["S"], "worklog")
        (a,) = self.scan("audit#")
        self.assertEqual(a["project_id"]["S"], f"audit#{TASK}")
        self.assertEqual(a["write_tool"]["S"], "tracker.set_acceptance_evidence")
        self.assertEqual(a["correlation_id"]["S"], "corr-ace-1")
        self.assertEqual(a["receipt_hash"]["S"], tm._s28_receipt_hash(
            json.dumps({k: v for k, v in json.loads(resp["body"]).items()
                        if k in RESPONSE_KEYS}, default=str)))
        self.assertEqual(self.scan("idem#"), [])
        # [WRITE-AUDIT] line joins the audit item
        self.assertEqual(line["tool"], "tracker.set_acceptance_evidence")
        self.assertEqual(line["correlation_id"], "corr-ace-1")
        self.assertIs(line["atomic_commit"], True)
        self.assertEqual(line["txn_items"], 2)
        self.assertEqual(line["attempt_outcome"], "success")
        self.assertEqual(line["record_id"], TASK)
        self.assertEqual(line["t_ack"], int(it["t_ack"]["N"]))

    def test_response_shape_unchanged(self):
        resp, _ = self.call()
        body = json.loads(resp["body"])
        self.assertEqual(set(body), RESPONSE_KEYS | {"t_ack", "server_total_ms", "version_seq"})
        self.assertEqual(body["criterion_index"], 0)
        self.assertIs(body["evidence_acceptance"], True)
        self.assertIs(body["all_criteria_accepted"], False)
        self.assertIs(body["completion_eligible"], False)
        self.assertEqual(body["criteria_summary"], [
            {"index": 0, "description": "first", "evidence_acceptance": True},
            {"index": 1, "description": "second", "evidence_acceptance": False}])
        resp2, _ = self.call(criterion_index=1)
        self.assertIs(json.loads(resp2["body"])["completion_eligible"], True)

    def test_keyed_write_adds_marker_and_replays_byte_identical(self):
        first, _ = self.call(idempotency_key="ace-k1")
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:audit", "Put:idem"])
        again, (line,) = self.call(idempotency_key="ace-k1")
        self.assertEqual(len(self.spy.txns), 1)  # replay writes nothing
        self.assertEqual(json.loads(again["body"])["criteria_summary"], json.loads(first["body"])["criteria_summary"])
        self.assertEqual(self.stored()["sync_version"]["N"], "2")
        self.assertEqual(len(self.scan("audit#")), 1)
        self.assertIs(line.get("idempotent_replay"), True)

    def test_server_generated_correlation_id_when_caller_sends_none(self):
        resp, (line,) = self.call()
        self.assertEqual(resp["statusCode"], 200)
        cid = line["correlation_id"]
        self.assertTrue(cid and cid.startswith("srv-"))
        self.assertIs(line["correlation_id_generated"], True)
        (a,) = self.scan("audit#")
        self.assertEqual(a["correlation_id"]["S"], cid)
        self.assertEqual(self.stored()["correlation_id"]["S"], cid)

    def test_body_correlation_id_is_honoured_and_not_generated(self):
        resp, (line,) = self.call(correlation_id="corr-body")
        self.assertEqual(line["correlation_id"], "corr-body")
        self.assertNotIn("correlation_id_generated", line)
        (a,) = self.scan("audit#")
        self.assertEqual(a["correlation_id"]["S"], "corr-body")

    def test_failing_audit_put_rolls_back_record(self):
        before = self.stored()
        real_audit = tm._s28_audit_put

        def bad_audit(*a, **k):  # an audit Put whose condition can never hold -> whole transaction cancels
            op = real_audit(*a, **k)
            op["Put"]["ConditionExpression"] = "attribute_exists(project_id)"
            return op

        with mock.patch.object(tm, "_s28_audit_put", bad_audit):
            resp, (line,) = self.call(idempotency_key="ace-fail")
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(self.stored(), before)  # record unchanged: criteria, history, sync_version, stamps
        self.assertEqual((self.scan("audit#"), self.scan("idem#")), ([], []))
        self.assertEqual(line["attempt_outcome"], "error")

    def test_fault_injection_leaves_record_untouched(self):
        before = self.stored()
        for mode in ("before_commit", "cancel_commit"):
            with mock.patch.dict(os.environ, {"WRITE_FAULT_INJECT": mode}):
                resp, _ = self.call(idempotency_key="ace-f")
            self.assertEqual(resp["statusCode"], 500, msg=mode)
            self.assertEqual(self.stored(), before)
            self.assertEqual((self.scan("audit#"), self.scan("idem#")), ([], []))

    def test_validation_rejections_write_nothing(self):
        for extra in ({"criterion_index": 7}, {"evidence": "", "evidence_acceptance": True}):
            resp, _ = self.call(**extra)
            self.assertEqual(resp["statusCode"], 400)
        self.assertEqual(self.spy.txns, [])
        self.assertEqual(self.scan("audit#"), [])


if __name__ == "__main__":
    unittest.main()
