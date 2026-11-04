"""ENC-TSK-S28-0E: t_ack/version_seq/server_total_ms in write responses and item stamps.

Run: python3 -m pytest test_ack_s28_0e.py -q
"""
from __future__ import annotations

import importlib.util
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
    "ack_s28_0e_mod", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)


class _Ctx:
    aws_request_id = "req-1"
    memory_limit_in_mb = 512
    function_version = "$LATEST"


class AckTests(unittest.TestCase):
    def test_response_carries_ack_fields(self):
        def inner(event, context):
            m._wa_ack_now()
            m._WA["version_seq"] = 42
            return {"statusCode": 201, "body": json.dumps({"record_id": "X-1"})}
        ev = {"httpMethod": "POST", "rawPath": "/api/v1/tracker/enceladus/task", "headers": {}, "body": "{}"}
        with mock.patch.object(m, "_lambda_handler_inner", inner):
            resp = m.lambda_handler(ev, _Ctx())
        body = json.loads(resp["body"])
        self.assertEqual(body["version_seq"], 42)
        self.assertEqual(body["record_id"], "X-1")
        self.assertIsInstance(body["t_ack"], int)
        self.assertIsInstance(body["server_total_ms"], int)

    def test_error_response_untouched(self):
        def inner(event, context):
            return {"statusCode": 409, "body": json.dumps({"error": "x"})}
        ev = {"httpMethod": "POST", "rawPath": "/api/v1/tracker/enceladus/task", "headers": {}, "body": "{}"}
        with mock.patch.object(m, "_lambda_handler_inner", inner):
            resp = m.lambda_handler(ev, _Ctx())
        self.assertEqual(json.loads(resp["body"]), {"error": "x"})

    def test_item_stamp_t_ack_and_pending(self):
        m._WA.clear(); m._WA.update({"t0": 0.0})
        with mock.patch.object(m, "_VERSION_SEQ_AVAILABLE", False):
            item = {}
            m._stamp_version_seq_on_create_item(item)
        self.assertEqual(item["projection_status"], {"S": "pending"})
        self.assertIn("N", item["t_ack"])


if __name__ == "__main__":
    unittest.main()
