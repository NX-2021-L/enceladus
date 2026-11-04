"""test_atomic_commit_s28_0d.py -- ENC-TSK-S28-0D atomic governed commit (document_api).

documents item + audit item (+ idempotency marker) in ONE TransactWriteItems; S3 body first,
deleted again when the transaction fails. Runs against moto's DynamoDB.
Run: python3 -m pytest test_atomic_commit_s28_0d.py -q
"""

from __future__ import annotations

import contextlib
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

import lambda_function as da  # noqa: E402


class _Ctx:
    aws_request_id = "req-d-s28"
    memory_limit_in_mb = 256
    function_version = "$LATEST"


class _TxnSpy:
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


class DocumentAtomicCommitTests(unittest.TestCase):
    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        self.addCleanup(self._moto.stop)
        da._WA.clear()
        self.addCleanup(da._WA.clear)
        env = mock.patch.dict(os.environ, {"WRITE_FAULT_INJECT": ""})
        env.start()
        self.addCleanup(env.stop)
        real = boto3.client("dynamodb", region_name="us-west-2")
        real.create_table(
            TableName=da.DOCUMENTS_TABLE,
            AttributeDefinitions=[{"AttributeName": "document_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "document_id", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        self.real = real
        self.spy = _TxnSpy(real)
        self.store = mock.MagicMock()
        for p in (
            mock.patch.object(da, "_ddb", self.spy),
            mock.patch.object(da, "_authenticate", return_value=({"sub": "u1", "email": "u1@example.com"}, None)),
            mock.patch.object(da, "_validate_project_exists", return_value=None),
            mock.patch.object(da, "_upload_content", return_value=("agent-documents/devops/DOC-X.md", "h" * 64, 12)),
            mock.patch.object(da, "_content_store", return_value=self.store),
            mock.patch.object(da, "_allocate_document_version_seq", return_value=7),
        ):
            p.start()
            self.addCleanup(p.stop)

    # -- helpers ------------------------------------------------------------
    def event(self, method, body, path="/api/v1/documents", key="", cid="corr-d"):
        body = dict(body)
        if key:
            body["idempotency_key"] = key
        return {"requestContext": {"http": {"method": method, "path": path}}, "rawPath": path,
                "headers": {"cookie": "enceladus_id_token=jwt", "x-correlation-id": cid},
                "queryStringParameters": {}, "body": json.dumps(body)}

    def put(self, key="", **env):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
            resp = da.lambda_handler(self.event("PUT", {
                "project_id": "devops", "title": "T", "content": "# Hello\n\nbody", "document_subtype": "doc",
            }, key=key), _Ctx())
        lines = [json.loads(ln.split("[WRITE-AUDIT] ", 1)[1]) for ln in buf.getvalue().splitlines()
                 if ln.startswith("[WRITE-AUDIT] ")]
        return resp, lines

    def scan(self, prefix=""):
        return [i for i in self.real.scan(TableName=da.DOCUMENTS_TABLE)["Items"]
                if i["document_id"]["S"].startswith(prefix)]

    def docs(self):
        return [i for i in self.scan() if i["document_id"]["S"].startswith("DOC-")]

    @staticmethod
    def kinds(ops):
        return [next(iter(op)) + ":" + (op[next(iter(op))].get("Item") or op[next(iter(op))]["Key"])["document_id"]["S"].split("#")[0].split("-")[0]
                for op in ops]

    # -- put -------------------------------------------------------------------
    def test_put_is_one_transaction_document_plus_audit(self):
        resp, _ = self.put()
        self.assertEqual(resp["statusCode"], 201, msg=resp["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Put:DOC", "Put:audit"])
        (doc,) = self.docs()
        doc_id = json.loads(resp["body"])["document_id"]
        self.assertEqual(doc["document_id"]["S"], doc_id)
        (audit,) = self.scan("audit#")
        self.assertTrue(audit["document_id"]["S"].startswith(f"audit#{doc_id}#"))
        self.assertTrue(audit["document_id"]["S"].endswith("#corr-d"))
        self.assertEqual(audit["target_record_id"]["S"], doc_id)
        self.assertEqual(audit["receipt_hash"]["S"], da._s28_receipt_hash(resp["body"]))
        self.assertEqual(audit["write_tool"]["S"], "documents.put")
        self.assertEqual(audit["correlation_id"]["S"], "corr-d")
        self.assertEqual(audit["attempt_outcome"]["S"], "success")

    def test_keyed_put_adds_marker_and_replays_byte_identical(self):
        t0 = int(time.time())
        first, _ = self.put(key="dk-1")
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Put:DOC", "Put:audit", "Put:idem"])
        (marker,) = self.scan("idem#")
        self.assertEqual(marker["document_id"]["S"], "idem#devops#dk-1#marker")
        self.assertEqual(marker["receipt"]["S"], first["body"])
        self.assertTrue(t0 + 86400 <= int(marker["ttl"]["N"]) <= int(time.time()) + 86400)
        again, _ = self.put(key="dk-1")
        self.assertEqual(again["statusCode"], 200)
        self.assertEqual(again["headers"].get("idempotent_replay"), "true")
        self.assertEqual(again["body"], first["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(len(self.docs()), 1)
        self.assertEqual(len(self.scan("audit#")), 1)

    def test_before_commit_fault_deletes_s3_and_writes_nothing(self):
        resp, lines = self.put(key="dk-f", WRITE_FAULT_INJECT="before_commit")
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(self.spy.txns, [])
        self.store.delete_object.assert_called_once_with("agent-documents/devops/DOC-X.md")
        self.assertEqual((self.docs(), self.scan("audit#"), self.scan("idem#")), ([], [], []))
        self.assertEqual((lines[0]["attempt_outcome"], lines[0]["fault_inject"]), ("error", "before_commit"))

    def test_cancel_commit_fault_cancels_transaction_and_deletes_s3(self):
        resp, lines = self.put(key="dk-c", WRITE_FAULT_INJECT="cancel_commit")
        self.assertEqual(resp["statusCode"], 500)
        self.assertEqual(len(self.spy.txns), 1)
        self.assertIn("ConditionCheck", self.spy.txns[0][-1])
        self.store.delete_object.assert_called_once_with("agent-documents/devops/DOC-X.md")
        self.assertEqual((self.docs(), self.scan("audit#"), self.scan("idem#")), ([], [], []))
        self.assertEqual((lines[0]["attempt_outcome"], lines[0]["fault_inject"]), ("error", "cancel_commit"))

    # -- patch -------------------------------------------------------------------
    def _seed(self):
        self.real.put_item(TableName=da.DOCUMENTS_TABLE, Item={
            "document_id": {"S": "DOC-AAAA11112222"}, "project_id": {"S": "devops"}, "title": {"S": "old"},
            "version": {"N": "1"}, "status": {"S": "active"}, "document_subtype": {"S": "doc"},
            "content_hash": {"S": "x"}, "size_bytes": {"N": "3"}, "history": {"L": []},
            "updated_at": {"S": "2026-01-01T00:00:00Z"}})

    def patch(self, key="", **env):
        buf = io.StringIO()
        path = "/api/v1/documents/DOC-AAAA11112222"
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(buf):
            resp = da.lambda_handler(self.event("PATCH", {"title": "new"}, path=path, key=key), _Ctx())
        return resp

    def test_patch_is_one_transaction_update_plus_audit(self):
        self._seed()
        resp = self.patch(key="pk-1")
        self.assertEqual(resp["statusCode"], 200, msg=resp["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual(self.kinds(self.spy.txns[0]), ["Update:DOC", "Put:audit", "Put:idem"])
        item = self.real.get_item(TableName=da.DOCUMENTS_TABLE, Key={"document_id": {"S": "DOC-AAAA11112222"}})["Item"]
        self.assertEqual((item["title"]["S"], item["version"]["N"]), ("new", "2"))
        (audit,) = self.scan("audit#")
        self.assertEqual(audit["receipt_hash"]["S"], da._s28_receipt_hash(resp["body"]))
        again = self.patch(key="pk-1")
        self.assertEqual(again["body"], resp["body"])
        self.assertEqual(len(self.spy.txns), 1)

    def test_patch_cancel_commit_leaves_document_and_audit_untouched(self):
        self._seed()
        resp = self.patch(WRITE_FAULT_INJECT="cancel_commit")
        self.assertEqual(resp["statusCode"], 500)
        item = self.real.get_item(TableName=da.DOCUMENTS_TABLE, Key={"document_id": {"S": "DOC-AAAA11112222"}})["Item"]
        self.assertEqual((item["title"]["S"], item["version"]["N"]), ("old", "1"))
        self.assertEqual(self.scan("audit#"), [])

    def test_patch_stale_version_still_409_through_transaction(self):
        self._seed()
        body = {"title": "new", "if_match": "0"}
        resp = da.lambda_handler(self.event("PATCH", body, path="/api/v1/documents/DOC-AAAA11112222"), _Ctx())
        self.assertEqual(resp["statusCode"], 409, msg=resp["body"])
        self.assertEqual(self.spy.txns, [])  # rejected by the pre-check; transaction never opened

    def test_patch_lost_race_inside_transaction_maps_to_409_and_writes_no_audit(self):
        self._seed()

        def race():  # another writer bumps the version between our read and our commit
            self.real.update_item(TableName=da.DOCUMENTS_TABLE, Key={"document_id": {"S": "DOC-AAAA11112222"}},
                                  UpdateExpression="SET #v = :two", ExpressionAttributeNames={"#v": "version"},
                                  ExpressionAttributeValues={":two": {"N": "2"}})
        self.spy.before_first = race
        resp = da.lambda_handler(
            self.event("PATCH", {"title": "new", "if_match": "1"}, path="/api/v1/documents/DOC-AAAA11112222",
                       key="pk-race"), _Ctx())
        self.assertEqual(resp["statusCode"], 409, msg=resp["body"])
        self.assertEqual(len(self.spy.txns), 1)
        self.assertEqual((self.scan("audit#"), self.scan("idem#")), ([], []))


if __name__ == "__main__":
    unittest.main()
