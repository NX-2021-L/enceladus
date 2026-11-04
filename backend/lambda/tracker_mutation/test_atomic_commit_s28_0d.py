"""test_atomic_commit_s28_0d.py -- ENC-TSK-S28-0D atomic governed commit (tracker_mutation).

One TransactWriteItems carries record + audit item (+ ID counter on create) (+ idempotency
marker when keyed). Runs against moto's DynamoDB so TransactionCanceledException semantics
are real. Run: python3 -m pytest test_atomic_commit_s28_0d.py -q
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import time
import unittest
from unittest import mock

import boto3
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_atomic_commit_s28_0d", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

PROJECT = "enceladus"
WS = {"provider": "s28-test-suite", "channel": "test"}  # non-ENC-SES provider: SCI gate out of scope


class _Ctx:
    aws_request_id = "req-s28"
    memory_limit_in_mb = 512
    function_version = "$LATEST"


class _TxnSpy:
    """Delegating client that records transact_write_items calls and can race the first one."""

    def __init__(self, real):
        self._real = real
        self.txns = []
        self.before_first = None

    def transact_write_items(self, **kw):
        self.txns.append(kw["TransactItems"])
        if self.before_first and len(self.txns) == 1:
            self.before_first()
        return self._real.transact_write_items(**kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


class AtomicCommitTests(unittest.TestCase):
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
        for p in (
            mock.patch.object(tm, "_ddb", self.spy),
            mock.patch.object(tm, "_get_project_prefix", return_value="ENC"),
            mock.patch.object(tm, "_get_prefix_map_cached", return_value={"ENC": PROJECT}),
            mock.patch.object(tm, "_id_service_enabled", return_value=False),
        ):
            p.start()
            self.addCleanup(p.stop)
        # counter at 1 so the next task is ENC-TSK-002 (base36)
        real.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            "project_id": {"S": PROJECT}, "record_id": {"S": "counter#task"}, "next_num": {"N": "1"}})

    # -- helpers ------------------------------------------------------------
    def create(self, key="", **extra):
        body = {"title": "atomic", "category": "implementation", "write_source": dict(WS),
                "acceptance_criteria": ["one"]}
        if key:
            body["idempotency_key"] = key
        body.update(extra)
        if not tm._WA:  # direct handler call; under lambda_handler the wrapper already seeded _WA
            tm._WA.update({"t": {}, "extra": {}, "correlation_id": "corr-s28", "write_tool": "tracker.create",
                           "request_id": "req-s28", "idempotency_key": key, "ddb_ops": 0, "ddb_ms": 0.0,
                           "ddb_retries": 0})
        return tm._handle_create_record(PROJECT, "task", body)

    def scan(self, prefix=""):
        items = self.real.scan(TableName=tm.DYNAMODB_TABLE)["Items"]
        return [i for i in items if i["project_id"]["S"].startswith(prefix)]

    def counter(self):
        return int(self.real.get_item(TableName=tm.DYNAMODB_TABLE, Key={
            "project_id": {"S": PROJECT}, "record_id": {"S": "counter#task"}})["Item"]["next_num"]["N"])

    def records(self):
        return [i for i in self.scan(PROJECT) if i["record_id"]["S"].startswith("task#")]

    @staticmethod
    def kinds(ops):
        out = []
        for op in ops:
            kind = next(iter(op))
            out.append(kind + ":" + (op[kind].get("Item", {}).get("project_id") or
                                     op[kind].get("Key", {}).get("project_id"))["S"].split("#")[0])
        return out

    # -- create --------------------------------------------------------------
    def test_create_is_one_transaction_with_counter_record_and_audit(self):
        resp = self.create()
        self.assertEqual(resp["statusCode"], 201, msg=resp["body"])
        body = json.loads(resp["body"])
        self.assertEqual(body["record_id"], "ENC-TSK-002")
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:enceladus", "Put:audit"])
        self.assertEqual(self.counter(), 2)
        self.assertEqual([r["item_id"]["S"] for r in self.records()], ["ENC-TSK-002"])
        audit = self.scan("audit#")
        self.assertEqual(len(audit), 1)
        a = audit[0]
        self.assertEqual(a["project_id"]["S"], "audit#ENC-TSK-002")
        self.assertRegex(a["record_id"]["S"], r"^\d{4}-\d\d-\d\dT[\d:.]+Z#corr-s28$")
        self.assertEqual(a["correlation_id"]["S"], "corr-s28")
        self.assertEqual(a["write_tool"]["S"], "tracker.create")
        self.assertEqual(a["provider"]["S"], "s28-test-suite")
        self.assertEqual(a["request_id"]["S"], "req-s28")
        self.assertEqual(a["attempt_outcome"]["S"], "success")
        self.assertEqual(a["receipt_hash"]["S"], tm._s28_receipt_hash(resp["body"]))
        self.assertIn("version_seq", a)
        self.assertEqual(self.scan("idem#"), [])  # no key, no marker
        for it in self.scan("audit#"):  # audit/marker rows stay out of every GSI and feed projection
            self.assertNotIn("record_type", it)
            self.assertNotIn("updated_at", it)

    def test_keyed_create_adds_marker_with_exact_receipt_and_24h_ttl(self):
        t0 = int(time.time())
        resp = self.create(key="k-1")
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:enceladus", "Put:audit", "Put:idem"])
        (marker,) = self.scan("idem#")
        self.assertEqual(marker["project_id"]["S"], "idem#enceladus#k-1")
        self.assertEqual(marker["receipt"]["S"], resp["body"])
        self.assertEqual(marker["receipt_hash"]["S"], tm._s28_receipt_hash(resp["body"]))
        ttl = int(marker["ttl"]["N"])
        self.assertTrue(t0 + 86400 <= ttl <= int(time.time()) + 86400)
        self.assertIn("expires_at", marker)

    def test_counter_race_retries_then_succeeds(self):
        def race():  # another writer takes ENC-TSK-002 between our observe and our commit
            self.real.update_item(TableName=tm.DYNAMODB_TABLE, Key={
                "project_id": {"S": PROJECT}, "record_id": {"S": "counter#task"}},
                UpdateExpression="SET next_num = :n", ExpressionAttributeValues={":n": {"N": "2"}})
        self.spy.before_first = race
        resp = self.create()
        self.assertEqual(resp["statusCode"], 201, msg=resp["body"])
        self.assertEqual(json.loads(resp["body"])["record_id"], "ENC-TSK-003")
        self.assertEqual(len(self.spy.txns), 2)  # first cancelled on the counter, second committed
        self.assertEqual(self.counter(), 3)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(len(self.scan("audit#")), 1)

    def test_counter_race_gives_up_after_three_retries(self):
        real_txn = self.spy.transact_write_items

        def always_lose(**kw):
            self.real.update_item(TableName=tm.DYNAMODB_TABLE, Key={
                "project_id": {"S": PROJECT}, "record_id": {"S": "counter#task"}},
                UpdateExpression="ADD next_num :one", ExpressionAttributeValues={":one": {"N": "1"}})
            return real_txn(**kw)
        with mock.patch.object(self.spy, "transact_write_items", side_effect=always_lose) as m:
            resp = self.create()
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(m.call_count, 4)  # 1 attempt + 3 retries
        self.assertEqual(self.records(), [])
        self.assertEqual(self.scan("audit#"), [])

    def test_replay_with_same_key_is_byte_identical_and_writes_nothing(self):
        first = self.create(key="k-replay")
        second = self.create(key="k-replay")
        self.assertEqual(second["statusCode"], 200)
        self.assertEqual(second["headers"].get("idempotent_replay"), "true")
        self.assertEqual(second["body"], first["body"])
        self.assertEqual(len(self.spy.txns), 1)  # no second transaction
        self.assertEqual(self.counter(), 2)
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(len(self.scan("audit#")), 1)

    def test_replay_after_ttl_expiry_is_a_fresh_write(self):
        self.create(key="k-exp")
        marker = self.scan("idem#")[0]
        self.real.update_item(TableName=tm.DYNAMODB_TABLE,
                              Key={"project_id": marker["project_id"], "record_id": marker["record_id"]},
                              UpdateExpression="SET #t = :past", ExpressionAttributeNames={"#t": "ttl"},
                              ExpressionAttributeValues={":past": {"N": str(int(time.time()) - 5)}})
        resp = self.create(key="k-exp")
        self.assertEqual(resp["statusCode"], 201)
        self.assertEqual(len(self.records()), 2)

    def test_concurrent_same_key_loses_marker_race_and_replays(self):
        first = self.create(key="k-race")

        # pre-check misses (as in a race); the transaction's marker condition catches it
        with mock.patch.object(tm, "_s28_idem_lookup", side_effect=[None, first["body"]]):
            resp = self.create(key="k-race")
        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(resp["body"], first["body"])
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.counter(), 2)  # the losing transaction rolled its counter back

    def test_id_service_path_commits_record_audit_without_counter(self):
        verdict = {"allow": True, "record_id": "ENC-TSK-ZZ", "item_id_provenance": "sig"}
        with mock.patch.object(tm, "_id_service_enabled", return_value=True), \
                mock.patch.object(tm, "_invoke_id_service", return_value=verdict):
            resp = self.create(key="k-id")
        self.assertEqual(resp["statusCode"], 201, msg=resp["body"])
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Put:enceladus", "Put:audit", "Put:idem"])
        self.assertEqual(self.counter(), 1)

    # -- fault injection ------------------------------------------------------
    def _faulted_create(self, mode):
        buf = io.StringIO()

        def inner(event, context):
            return self.create(key="k-fault")
        ev = {"httpMethod": "POST", "rawPath": f"/api/v1/tracker/{PROJECT}/task",
              "headers": {"x-correlation-id": "corr-s28"}, "body": "{}"}
        with mock.patch.dict(os.environ, {"WRITE_FAULT_INJECT": mode}), \
                mock.patch.object(tm, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
            # lambda_handler wipes _WA in _wa_begin, so re-seed inside inner via create()
            resp = tm.lambda_handler(ev, _Ctx())
        lines = [json.loads(ln.split("[WRITE-AUDIT] ", 1)[1]) for ln in buf.getvalue().splitlines()
                 if ln.startswith("[WRITE-AUDIT] ")]
        return resp, lines

    def test_before_commit_fault_leaves_nothing_and_logs_error(self):
        resp, lines = self._faulted_create("before_commit")
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(self.spy.txns, [])
        self.assertEqual((self.records(), self.scan("audit#"), self.scan("idem#")), ([], [], []))
        self.assertEqual(self.counter(), 1)
        (line,) = lines
        self.assertEqual(line["attempt_outcome"], "error")
        self.assertEqual(line["fault_inject"], "before_commit")

    def test_cancel_commit_fault_cancels_whole_transaction(self):
        resp, lines = self._faulted_create("cancel_commit")
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(len(self.spy.txns), 1)
        self.assertIn("ConditionCheck", self.spy.txns[0][-1])
        self.assertEqual((self.records(), self.scan("audit#"), self.scan("idem#")), ([], [], []))
        self.assertEqual(self.counter(), 1)  # counter increment rolled back with the rest
        (line,) = lines
        self.assertEqual(line["attempt_outcome"], "error")
        self.assertEqual(line["fault_inject"], "cancel_commit")
        self.assertEqual(line["ddb_txn_ops"], 1)

    def test_unset_fault_hook_is_inert(self):
        self.assertEqual(self.create()["statusCode"], 201)

    # -- update --------------------------------------------------------------
    def _seed_task(self):
        self.real.put_item(TableName=tm.DYNAMODB_TABLE, Item={
            "project_id": {"S": PROJECT}, "record_id": {"S": "task#ENC-TSK-9"}, "item_id": {"S": "ENC-TSK-9"},
            "record_type": {"S": "task"}, "status": {"S": "open"}, "title": {"S": "old"},
            "sync_version": {"N": "1"}, "updated_at": {"S": "2026-01-01T00:00:00Z"}, "history": {"L": []}})

    def update(self, key="", **extra):
        body = {"field": "title", "value": "new", "write_source": dict(WS)}
        if key:
            body["idempotency_key"] = key
        body.update(extra)
        if not tm._WA:
            tm._WA.update({"t": {}, "extra": {}, "correlation_id": "corr-u", "write_tool": "tracker.set",
                           "request_id": "req-u", "idempotency_key": key, "ddb_ops": 0, "ddb_ms": 0.0,
                           "ddb_retries": 0})
        return tm._handle_update_field(PROJECT, "task", "ENC-TSK-9", body)

    def stored_task(self):
        return self.real.get_item(TableName=tm.DYNAMODB_TABLE, Key={
            "project_id": {"S": PROJECT}, "record_id": {"S": "task#ENC-TSK-9"}})["Item"]

    def test_update_is_one_transaction_record_plus_audit_with_history_append(self):
        self._seed_task()
        resp = self.update()
        self.assertEqual(resp["statusCode"], 200, msg=resp["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:audit"])
        it = self.stored_task()
        self.assertEqual(it["title"]["S"], "new")
        self.assertEqual(it["sync_version"]["N"], "2")
        self.assertEqual(len(it["history"]["L"]), 1)  # list_append semantics preserved inside the Update
        (a,) = self.scan("audit#")
        self.assertEqual(a["project_id"]["S"], "audit#ENC-TSK-9")
        self.assertEqual(a["receipt_hash"]["S"], tm._s28_receipt_hash(resp["body"]))
        self.assertEqual(a["write_tool"]["S"], "tracker.set")

    def test_keyed_update_stores_marker_and_replays(self):
        self._seed_task()
        first = self.update(key="u-1")
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:enceladus", "Put:audit", "Put:idem"])
        again = self.update(key="u-1")
        self.assertEqual(again["body"], first["body"])
        self.assertEqual(again["statusCode"], 200)
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.stored_task()["sync_version"]["N"], "2")

    def test_update_faults_leave_record_and_audit_untouched(self):
        self._seed_task()
        for mode in ("before_commit", "cancel_commit"):
            with mock.patch.dict(os.environ, {"WRITE_FAULT_INJECT": mode}):
                resp = self.update(key="u-f")
            self.assertEqual(resp["statusCode"], 500, msg=mode)
            self.assertEqual(self.stored_task()["title"]["S"], "old")
            self.assertEqual(self.stored_task()["sync_version"]["N"], "1")
            self.assertEqual((self.scan("audit#"), self.scan("idem#")), ([], []))

    def test_write_audit_line_counts_transaction_as_one_ddb_op(self):
        self._seed_task()
        buf = io.StringIO()
        ev = {"httpMethod": "PATCH", "rawPath": f"/api/v1/tracker/{PROJECT}/task/ENC-TSK-9",
              "headers": {}, "body": "{}"}
        client = self.spy._real
        tm._wa_ddb_attach(client)  # the real hooks, as in production
        with mock.patch.object(tm, "_lambda_handler_inner", lambda e, c: self.update()), \
                contextlib.redirect_stdout(buf):
            tm.lambda_handler(ev, _Ctx())
        (line,) = [json.loads(ln.split("[WRITE-AUDIT] ", 1)[1]) for ln in buf.getvalue().splitlines()
                   if ln.startswith("[WRITE-AUDIT] ")]
        self.assertEqual(line["attempt_outcome"], "success")
        self.assertIs(line["atomic_commit"], True)
        self.assertEqual(line["txn_items"], 2)
        self.assertIn("t_commit_ms", line)
        self.assertIn("t_ddb_ms", line)


if __name__ == "__main__":
    unittest.main()
