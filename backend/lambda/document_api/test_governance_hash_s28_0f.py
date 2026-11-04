"""ENC-TSK-S28-0F: document_api tool-side governance_hash verification (direct invoke is never pre-validated).

Run: python3 -m pytest test_governance_hash_s28_0f.py -q
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from unittest import mock

import lambda_function as da

CUR = "c" * 64
OLD = "0" * 64


class _Ctx:
    aws_request_id = "req-dg1"
    memory_limit_in_mb = 256
    function_version = "3"


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def read(self):
        return json.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _event(gov=None, method="PUT", path="/api/v1/documents"):
    body = {"title": "t"}
    if gov is not None:
        body["governance_hash"] = gov
    return {"requestContext": {"http": {"method": method}}, "rawPath": path, "headers": {}, "body": json.dumps(body)}


def _run(event, inner):
    buf = io.StringIO()
    with mock.patch.object(da, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
        resp = da.lambda_handler(event, _Ctx())
    lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
             if l.startswith("[WRITE-AUDIT] ")]
    return resp, lines


class DocumentGovernanceHashTests(unittest.TestCase):
    def setUp(self):
        da._GOV_HASH_CACHE.update({"value": "", "at": 0.0, "fail_at": 0.0})

    def test_mismatch_is_409_envelope_and_audit_line_false(self):
        inner = mock.Mock(return_value={"statusCode": 201, "body": "{}"})
        with mock.patch.object(da, "_current_governance_hash", return_value=CUR):
            resp, lines = _run(_event(OLD), inner)
        inner.assert_not_called()
        self.assertEqual(resp["statusCode"], 409)
        env = json.loads(resp["body"])["error_envelope"]
        self.assertEqual(env["code"], "GOVERNANCE_STALE")
        self.assertEqual((env["details"]["provided"], env["details"]["current"]), (OLD, CUR))
        self.assertEqual(len(lines), 1)
        self.assertIs(lines[0]["governance_hash_verified"], False)
        self.assertEqual(lines[0]["http_status"], 409)

    def test_match_proceeds_verified_true(self):
        inner = mock.Mock(return_value={"statusCode": 201, "body": "{}"})
        with mock.patch.object(da, "_current_governance_hash", return_value=CUR):
            resp, lines = _run(_event(CUR), inner)
        inner.assert_called_once()
        self.assertIs(lines[0]["governance_hash_verified"], True)

    def test_missing_hash_unchanged_and_flagged_false(self):
        inner = mock.Mock(return_value={"statusCode": 201, "body": "{}"})
        with mock.patch.object(da, "_current_governance_hash", side_effect=AssertionError("no fetch")):
            resp, lines = _run(_event(None), inner)
        inner.assert_called_once()
        self.assertIs(lines[0]["governance_hash_verified"], False)

    def test_cache_ttl_and_gamma_url(self):
        calls = []

        def fake_urlopen(req, timeout=0):
            calls.append(req.full_url)
            return _Resp({"governance_hash": CUR})

        with mock.patch.object(da.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.dict(os.environ, {"ENVIRONMENT_SUFFIX": "", "AWS_LAMBDA_FUNCTION_NAME": "devops-document-api-gamma"}):
            self.assertEqual(da._current_governance_hash(), CUR)
            self.assertEqual(da._current_governance_hash(), CUR)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], "https://enceladus-gamma.jreese.net/api/v1/governance/hash")


if __name__ == "__main__":
    unittest.main()
