"""DVP-TSK-B51 (isolation W4l): deploy_intake deploy-config/ access goes through content_store (no AWS).

Env under test: CONTENT_STORE_MODE=dual with CONTENT_STORE_READ=legacy (the shipped writer-first phase), then with
CONTENT_STORE_READ unset (auto) to prove the later read flip is an env change only. Gamma-shaped: legacy keys carry
gamma/, content keys do not.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("deploy_intake_b51", os.path.join(HERE, "lambda_function.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

LEGACY = "jreese-net"
CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
PREFIX = "gamma/deploy-config"
CPREFIX = "deploy-config"


class _NoSuchKey(ClientError):
    """Like boto3's modeled s3.exceptions.NoSuchKey: a ClientError subclass named NoSuchKey, code NoSuchKey."""

    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")


_NoSuchKey.__name__ = "NoSuchKey"


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _Paginator:
    def __init__(self, s3):
        self._s3 = s3

    def paginate(self, Bucket, Prefix):
        self._s3.calls.append(("list", Bucket, Prefix, {}))
        keys = sorted(k for (b, k) in self._s3.objects if b == Bucket and k.startswith(Prefix))
        yield {"Contents": [{"Key": k} for k in keys]}


class FakeS3:
    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = Body
        return {"Bucket": Bucket}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _Paginator(self)

    def touched(self, op):
        return [(c[1], c[2]) for c in self.calls if c[0] == op]


class _Base(unittest.TestCase):
    read = "legacy"

    def setUp(self):
        env = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": "gamma/"}
        if self.read is not None:
            env["CONTENT_STORE_READ"] = self.read
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        if self.read is None:
            os.environ.pop("CONTENT_STORE_READ", None)
        self.s3 = FakeS3()
        for attr, value in (("CONFIG_BUCKET", LEGACY), ("CONFIG_PREFIX", PREFIX), ("_CONTENT_STORE", None)):
            p = mock.patch.object(mod, attr, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(mod, "_get_s3", lambda: self.s3)
        p.start()
        self.addCleanup(p.stop)

    def legacy(self, name):
        return (LEGACY, f"{PREFIX}/enceladus/{name}")

    def content(self, name):
        return (CONTENT, f"{CPREFIX}/enceladus/{name}")


class IntakeWritesAndLegacyReads(_Base):
    def test_set_state_lands_in_both_buckets_with_content_type(self):
        mod._handle_set_state("enceladus", {"state": "PAUSED", "reason": "freeze"})
        self.assertEqual(self.s3.touched("put"), [self.content("state.json"), self.legacy("state.json")])
        self.assertTrue(all(c[3] == {"ContentType": "application/json"} for c in self.s3.calls))
        written = {json.loads(self.s3.objects[k])["state"] for k in self.s3.objects}
        self.assertEqual(written, {"PAUSED"})

    def test_state_reads_hit_legacy_only(self):
        self.s3.objects[self.legacy("state.json")] = json.dumps({"state": "PAUSED"}).encode()
        self.s3.objects[self.content("state.json")] = json.dumps({"state": "ACTIVE"}).encode()
        state, err = mod._resolve_deploy_state("enceladus")
        self.assertEqual((state, err), ("PAUSED", None))
        resp = mod._handle_get_state("enceladus")
        self.assertEqual(json.loads(resp["body"])["state"], "PAUSED")
        self.assertEqual(self.s3.touched("get"), [self.legacy("state.json")] * 2)

    def test_missing_state_still_defaults_to_active(self):
        self.assertEqual(mod._resolve_deploy_state("enceladus"), ("ACTIVE", None))
        resp = mod._handle_get_state("enceladus")
        self.assertEqual(json.loads(resp["body"])["state"], "ACTIVE")


class IntakeAutoReadIsContentFirst(_Base):
    read = None

    def test_content_hit_never_touches_legacy(self):
        self.s3.objects[self.content("state.json")] = json.dumps({"state": "PAUSED"}).encode()
        self.assertEqual(mod._resolve_deploy_state("enceladus"), ("PAUSED", None))
        self.assertEqual(self.s3.touched("get"), [self.content("state.json")])

    def test_content_miss_falls_back_to_legacy_then_defaults(self):
        self.s3.objects[self.legacy("state.json")] = json.dumps({"state": "PAUSED"}).encode()
        self.assertEqual(mod._resolve_deploy_state("enceladus"), ("PAUSED", None))
        self.assertEqual(self.s3.touched("get"), [self.content("state.json"), self.legacy("state.json")])
        self.s3.objects.clear()
        self.assertEqual(mod._resolve_deploy_state("enceladus"), ("ACTIVE", None))


if __name__ == "__main__":
    unittest.main()
