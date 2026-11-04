"""ENC-TSK-S26-0A: checkout_service [WRITE-AUDIT] line + X-Correlation-Id forwarding.

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

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda_write_audit_s26_0a", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
co = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = co
_SPEC.loader.exec_module(co)

REQUIRED = {
    "correlation_id", "request_id", "tool", "project_id", "record_id", "surface", "attempt_outcome",
    "success", "server_total_ms", "cold_start", "init_ms", "t_invoke_ms", "t_ddb_ms", "ddb_ops",
    "memory_mb", "runtime", "arch", "function_version", "hops", "t_ack",
}


class _Ctx:
    aws_request_id = "req-c1"
    memory_limit_in_mb = 256
    function_version = "$LATEST"


class _Resp:
    status = 200

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class CheckoutWriteAuditTests(unittest.TestCase):
    def test_line_and_forwarded_header(self):
        sent = {}

        def inner(event, context):
            req_headers = {}
            with mock.patch.object(co.urllib.request, "urlopen", lambda req, timeout=0: (
                    req_headers.update({k.lower(): v for k, v in req.header_items()}),
                    sent.update(body=json.loads(req.data.decode())), _Resp())[-1]):
                co._tracker_request("PATCH", "/enceladus/task/ENC-TSK-1", {"field": "status"})
            sent["headers"] = req_headers
            return {"statusCode": 200, "body": "{}"}
        ev = {"requestContext": {"http": {"method": "POST", "path": "/api/v1/checkout/enceladus/task/ENC-TSK-1/advance"}},
              "headers": {"X-Correlation-Id": "corr-c"}, "body": json.dumps({"correlation_id": "corr-c2"})}
        buf = io.StringIO()
        with mock.patch.object(co, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
            co.lambda_handler(ev, _Ctx())
        self.assertEqual(sent["headers"]["x-correlation-id"], "corr-c")  # header wins over body
        self.assertEqual(sent["body"]["correlation_id"], "corr-c")
        line = json.loads(buf.getvalue().split("[WRITE-AUDIT] ", 1)[1])
        self.assertTrue(REQUIRED <= set(line), REQUIRED - set(line))
        self.assertEqual((line["tool"], line["project_id"], line["record_id"], line["surface"]),
                         ("checkout.advance", "enceladus", "ENC-TSK-1", "checkout_service"))
        self.assertGreaterEqual(line["t_invoke_ms"], 0)

    def test_no_correlation_id_leaves_tracker_payload_untouched(self):
        co._WA.clear()
        captured = {}
        with mock.patch.object(co.urllib.request, "urlopen",
                               lambda req, timeout=0: (captured.update(d=req.data), _Resp())[-1]):
            co._tracker_request("PATCH", "/p/task/T", {"field": "x"})
        self.assertEqual(json.loads(captured["d"]), {"field": "x"})


if __name__ == "__main__":
    unittest.main()
