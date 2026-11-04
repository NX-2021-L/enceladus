"""ENC-TSK-S26-0A: tracker_mutation [WRITE-AUDIT] line + correlation_id stamping.

Run: python3 -m pytest test_write_audit_s26_0a.py -q
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

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_write_audit_s26_0a", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

REQUIRED = {
    "correlation_id", "request_id", "tool", "project_id", "record_id", "idempotency_key", "surface",
    "attempt_outcome", "success", "server_total_ms", "cold_start", "init_ms", "t_auth_ms", "t_validate_ms",
    "t_counter_ms", "t_ddb_ms", "ddb_ops", "ddb_retries", "memory_mb", "runtime", "arch",
    "function_version", "hops", "version_seq", "t_ack",
}


class _Ctx:
    aws_request_id = "req-1"
    memory_limit_in_mb = 512
    function_version = "$LATEST"


def _invoke(event, inner):
    buf = io.StringIO()
    with mock.patch.object(tm, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
        resp = tm.lambda_handler(event, _Ctx())
    lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
             if l.startswith("[WRITE-AUDIT] ")]
    return resp, lines


class WriteAuditTests(unittest.TestCase):
    def test_header_correlation_id_and_required_keys(self):
        def inner(event, context):
            tm._WA["version_seq"] = 42
            return {"statusCode": 201, "body": json.dumps({"record_id": "ENC-TSK-9"})}
        ev = {"httpMethod": "POST", "rawPath": "/api/v1/tracker/enceladus/task",
              "headers": {"x-correlation-id": "corr-h"}, "body": "{}"}
        _, lines = _invoke(ev, inner)
        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertTrue(REQUIRED <= set(line), REQUIRED - set(line))
        self.assertEqual((line["correlation_id"], line["tool"], line["project_id"], line["record_id"]),
                         ("corr-h", "tracker.create", "enceladus", "ENC-TSK-9"))
        self.assertEqual((line["surface"], line["version_seq"], line["attempt_outcome"], line["success"]),
                         ("tracker_mutation", 42, "success", True))

    def test_body_correlation_id_accepted_and_stripped(self):
        seen = {}

        def inner(event, context):
            seen["body"] = json.loads(event["body"])
            return {"statusCode": 400, "body": "{}"}
        ev = {"httpMethod": "PATCH", "rawPath": "/api/v1/tracker/enceladus/task/ENC-TSK-1",
              "headers": {}, "body": json.dumps({"field": "title", "value": "x", "correlation_id": "corr-b"})}
        _, lines = _invoke(ev, inner)
        self.assertNotIn("correlation_id", seen["body"])
        self.assertEqual(seen["body"]["field"], "title")
        self.assertEqual((lines[0]["correlation_id"], lines[0]["tool"], lines[0]["record_id"]),
                         ("corr-b", "tracker.set", "ENC-TSK-1"))
        self.assertEqual((lines[0]["attempt_outcome"], lines[0]["success"]), ("rejected", False))

    def test_reads_are_not_audited(self):
        _, lines = _invoke({"httpMethod": "GET", "rawPath": "/x"}, lambda e, c: {"statusCode": 200, "body": "{}"})
        self.assertEqual(lines, [])

    def test_correlation_id_stamped_on_create_item_and_update_expression(self):
        with mock.patch.object(tm, "_VERSION_SEQ_AVAILABLE", True), \
                mock.patch.object(tm, "allocate_version_seq", return_value=7), \
                mock.patch.object(tm, "_get_ddb", return_value=object()):
            tm._WA.clear()
            tm._WA["correlation_id"] = "corr-x"
            tm._WA["write_tool"] = "tracker.set"
            item = {}
            tm._stamp_version_seq_on_create_item(item)
            self.assertEqual(item["correlation_id"], {"S": "corr-x"})
            self.assertEqual(item["write_tool"], {"S": "tracker.set"})
            expr, vals = tm._version_seq_update_parts()
            self.assertIn("correlation_id = :wa_cid", expr)
            self.assertEqual(vals[":wa_cid"], {"S": "corr-x"})
            self.assertIn("write_tool = :wa_tool", expr)
            self.assertEqual(vals[":wa_tool"], {"S": "tracker.set"})
            self.assertEqual(tm._WA["version_seq"], 7)
            tm._WA.clear()
            expr2, vals2 = tm._version_seq_update_parts()
            self.assertNotIn("correlation_id", expr2)
            self.assertNotIn("write_tool", expr2)


if __name__ == "__main__":
    unittest.main()
