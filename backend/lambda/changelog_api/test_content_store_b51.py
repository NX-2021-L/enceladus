"""DVP-TSK-B51 (isolation W4l): changelog_api reads current-version.json through content_store (no AWS).

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

_spec = importlib.util.spec_from_file_location("changelog_api_b51", os.path.join(HERE, "lambda_function.py"))
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


class ChangelogReads(_Base):
    def test_reads_hit_legacy_only(self):
        self.s3.objects[self.legacy("current-version.json")] = json.dumps({"version": "1.2.3", "deployed_at": "t", "spec_id": "S"}).encode()
        self.s3.objects[self.content("current-version.json")] = json.dumps({"version": "9.9.9"}).encode()
        out = mod._read_current_version("enceladus")
        self.assertEqual(out["version"], "1.2.3")
        self.assertEqual(self.s3.touched("get"), [self.legacy("current-version.json")])
        self.assertEqual(self.s3.touched("put"), [])

    def test_missing_version_is_none(self):
        self.assertIsNone(mod._read_current_version("enceladus"))


class ChangelogAutoReadIsContentFirst(_Base):
    read = None

    def test_content_first_then_legacy(self):
        self.s3.objects[self.legacy("current-version.json")] = json.dumps({"version": "1.2.3"}).encode()
        self.assertEqual(mod._read_current_version("enceladus")["version"], "1.2.3")
        self.assertEqual(self.s3.touched("get"), [self.content("current-version.json"), self.legacy("current-version.json")])
        self.s3.objects[self.content("current-version.json")] = json.dumps({"version": "2.0.0"}).encode()
        self.assertEqual(mod._read_current_version("enceladus")["version"], "2.0.0")


if __name__ == "__main__":
    unittest.main()
