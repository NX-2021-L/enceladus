"""ENC-TSK-S28-0F: tool-side governance_hash verification (a direct invoke is never pre-validated).

Run: python3 -m pytest test_governance_hash_s28_0f.py -q
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
    "tracker_mutation_governance_hash_s28_0f", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
tm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tm
_spec.loader.exec_module(tm)

CUR = "c" * 64
OLD = "0" * 64


class _Ctx:
    aws_request_id = "req-g1"
    memory_limit_in_mb = 512
    function_version = "7"


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def read(self):
        return json.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _event(gov=None, method="POST"):
    body = {"field": "title", "value": "x"}
    if gov is not None:
        body["governance_hash"] = gov
    return {"requestContext": {"http": {"method": method}}, "rawPath": "/api/v1/tracker/enceladus/task/ENC-TSK-1",
            "headers": {}, "body": json.dumps(body)}


def _run(event, inner):
    buf = io.StringIO()
    with mock.patch.object(tm, "_lambda_handler_inner", inner), contextlib.redirect_stdout(buf):
        resp = tm.lambda_handler(event, _Ctx())
    lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
             if l.startswith("[WRITE-AUDIT] ")]
    return resp, lines


class TrackerGovernanceHashTests(unittest.TestCase):
    def setUp(self):
        tm._GOV_HASH_CACHE.update({"value": "", "at": 0.0, "fail_at": 0.0})

    def test_mismatch_is_409_and_inner_handler_not_called(self):
        inner = mock.Mock(return_value={"statusCode": 200, "body": "{}"})
        with mock.patch.object(tm, "_current_governance_hash", return_value=CUR):
            resp, lines = _run(_event(OLD), inner)
        inner.assert_not_called()
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        env = body["error_envelope"]
        self.assertEqual(env["code"], "GOVERNANCE_STALE")
        self.assertTrue(env["retryable"])
        self.assertEqual((env["details"]["provided"], env["details"]["current"]), (OLD, CUR))
        self.assertIn("self_correct", env["details"])
        self.assertEqual(len(lines), 1)
        self.assertIs(lines[0]["governance_hash_verified"], False)
        self.assertEqual((lines[0]["http_status"], lines[0]["attempt_outcome"]), (409, "rejected"))

    def test_match_proceeds_and_is_verified(self):
        inner = mock.Mock(return_value={"statusCode": 200, "body": "{}"})
        with mock.patch.object(tm, "_current_governance_hash", return_value=CUR):
            resp, lines = _run(_event(CUR), inner)
        inner.assert_called_once()
        self.assertEqual(resp["statusCode"], 200)
        self.assertIs(lines[0]["governance_hash_verified"], True)

    def test_missing_hash_keeps_todays_behaviour_and_flags_false(self):
        inner = mock.Mock(return_value={"statusCode": 200, "body": "{}"})
        with mock.patch.object(tm, "_current_governance_hash", side_effect=AssertionError("no fetch")):
            resp, lines = _run(_event(None), inner)
        inner.assert_called_once()
        self.assertIs(lines[0]["governance_hash_verified"], False)

    def test_unreachable_governance_api_fails_open_but_flagged(self):
        inner = mock.Mock(return_value={"statusCode": 200, "body": "{}"})
        with mock.patch.object(tm, "_current_governance_hash", return_value=""):
            resp, lines = _run(_event(OLD), inner)
        inner.assert_called_once()
        self.assertIs(lines[0]["governance_hash_verified"], False)
        self.assertEqual(lines[0]["governance_hash_check"], "unavailable")

    def test_cache_is_60s_and_mismatch_forces_one_refresh(self):
        calls = []

        def fake_urlopen(req, timeout=0):
            calls.append(req.full_url)
            return _Resp({"governance_hash": CUR})

        with mock.patch.object(tm.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.dict(os.environ, {"ENVIRONMENT_SUFFIX": "-gamma", "COORDINATION_INTERNAL_API_KEY": "k"}):
            self.assertEqual(tm._current_governance_hash(), CUR)
            self.assertEqual(tm._current_governance_hash(), CUR)
            self.assertEqual(len(calls), 1)  # second read served from the module cache
            self.assertTrue(calls[0].startswith("https://enceladus-gamma.jreese.net/api/v1/governance/hash"))
            # stale cache: governance moved on, the entry is 30 s old -> a mismatch re-fetches exactly once
            tm._GOV_HASH_CACHE.update({"value": OLD, "at": tm.time.time() - 30})
            self.assertIsNone(tm._verify_governance_hash(CUR))
            self.assertEqual(len(calls), 2)

    def test_unreachable_api_backs_off_instead_of_stalling_every_write(self):
        calls = []

        def boom(req, timeout=0):
            calls.append(1)
            raise OSError("unreachable")

        with mock.patch.object(tm.urllib.request, "urlopen", boom):
            self.assertEqual(tm._current_governance_hash(), "")
            self.assertEqual(tm._current_governance_hash(), "")
        self.assertEqual(len(calls), len(tm._gov_hash_keys() or [""]))  # second call skipped during backoff

    def test_read_requests_are_not_gated(self):
        inner = mock.Mock(return_value={"statusCode": 200, "body": "{}"})
        with mock.patch.object(tm, "_current_governance_hash", side_effect=AssertionError("no fetch")), \
                contextlib.redirect_stdout(io.StringIO()), mock.patch.object(tm, "_lambda_handler_inner", inner):
            tm.lambda_handler(_event(OLD, method="GET"), _Ctx())
        inner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
