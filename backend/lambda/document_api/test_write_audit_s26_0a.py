"""ENC-TSK-S26-0A / ENC-TSK-E73: document_api [WRITE-AUDIT] line + correlation_id stamping.

Run: python3 -m pytest test_write_audit_s26_0a.py -q
"""
from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

import lambda_function as da

REQUIRED = {
    "correlation_id", "request_id", "tool", "project_id", "record_id", "idempotency_key", "surface",
    "attempt_outcome", "success", "server_total_ms", "cold_start", "init_ms", "t_auth_ms", "t_ddb_ms",
    "ddb_ops", "ddb_retries", "memory_mb", "runtime", "arch", "function_version", "hops", "version_seq",
    "t_ack", "content_hash", "document_subtype", "caller_environment",
}


class _Ctx:
    aws_request_id = "req-d1"
    memory_limit_in_mb = 256
    function_version = "$LATEST"


def _invoke(event, inner):
    buf = io.StringIO()
    with mock.patch.object(da, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
        resp = da.lambda_handler(event, _Ctx())
    lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
             if l.startswith("[WRITE-AUDIT] ")]
    return resp, lines


class DocumentWriteAuditTests(unittest.TestCase):
    def test_put_line_has_e73_fields_and_body_correlation_id(self):
        seen = {}

        def inner(event, context):
            seen["body"] = json.loads(event["body"])
            da._WA["project_id"] = "enceladus"
            da._WA["version_seq"] = 9
            da._WA["extra"]["document_subtype"] = "doc"
            return {"statusCode": 201, "body": json.dumps({"document_id": "DOC-ABC", "content_hash": "h1"})}
        ev = {"httpMethod": "PUT", "rawPath": "/api/v1/documents", "headers": {},
              "body": json.dumps({"title": "t", "correlation_id": "corr-d"})}
        _, lines = _invoke(ev, inner)
        self.assertNotIn("correlation_id", seen["body"])
        line = lines[0]
        self.assertTrue(REQUIRED <= set(line), REQUIRED - set(line))
        self.assertEqual((line["correlation_id"], line["tool"], line["record_id"], line["surface"]),
                         ("corr-d", "documents.put", "DOC-ABC", "document_api"))
        self.assertEqual((line["content_hash"], line["document_subtype"], line["attempt_outcome"]),
                         ("h1", "doc", "success"))
        self.assertIn(line["caller_environment"], ("prod", "gamma"))

    def test_rejected_put_and_header_correlation_id(self):
        ev = {"httpMethod": "PUT", "rawPath": "/api/v1/documents",
              "headers": {"X-Correlation-Id": "corr-h"}, "body": "{}"}
        _, lines = _invoke(ev, lambda e, c: {"statusCode": 400, "body": "{}"})
        self.assertEqual((lines[0]["correlation_id"], lines[0]["attempt_outcome"], lines[0]["success"]),
                         ("corr-h", "rejected", False))

    def test_patch_update_parts_carry_correlation_id(self):
        with mock.patch.object(da, "_allocate_document_version_seq", return_value=5):
            da._WA.clear()
            da._WA["correlation_id"] = "corr-p"
            clauses, vals = da._document_version_seq_update_parts()
            self.assertIn("correlation_id = :wa_cid", clauses)
            self.assertEqual(vals[":wa_cid"], {"S": "corr-p"})
            self.assertEqual(da._WA["version_seq"], 5)
            da._WA.clear()


if __name__ == "__main__":
    unittest.main()
