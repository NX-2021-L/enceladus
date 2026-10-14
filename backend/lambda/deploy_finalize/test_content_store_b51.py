"""DVP-TSK-B51 (isolation W4l): deploy_finalize current-version.json write goes through content_store (no AWS).

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

_spec = importlib.util.spec_from_file_location("deploy_finalize_b51", os.path.join(HERE, "lambda_function.py"))
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


def _ddb():
    ddb = mock.MagicMock()
    ddb.get_item.return_value = {"Item": {
        "project_id": {"S": "enceladus"}, "record_id": {"S": "spec#SPEC-1"},
        "previous_version": {"S": "1.0.0"}, "new_version": {"S": "1.0.1"}, "change_type": {"S": "patch"},
    }}
    return ddb


class FinalizeWritesBoth(_Base):
    def _run(self):
        with mock.patch.object(mod, "_get_ddb", return_value=_ddb()):
            mod._handle_success("enceladus", "SPEC-1", "build-1", 12)

    def test_current_version_lands_in_both_buckets(self):
        self._run()
        self.assertEqual(self.s3.touched("put"), [self.content("current-version.json"), self.legacy("current-version.json")])
        self.assertTrue(all(c[3] == {"ContentType": "application/json"} for c in self.s3.calls))
        for key in (self.content("current-version.json"), self.legacy("current-version.json")):
            self.assertEqual(json.loads(self.s3.objects[key])["spec_id"], "SPEC-1")

    def test_finalize_never_reads(self):
        self._run()
        self.assertEqual(self.s3.touched("get"), [])

    def test_write_failure_is_still_logged_critical_not_raised(self):
        self.s3.put_object = mock.Mock(side_effect=ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, "PutObject"))
        with self.assertLogs(level="CRITICAL") as logs:
            self._run()
        self.assertIn("current-version.json S3 write FAILED", logs.output[0])


class FinalizeReadModeDoesNotMatterForWrites(_Base):
    read = None

    def test_auto_read_mode_writes_both_too(self):
        with mock.patch.object(mod, "_get_ddb", return_value=_ddb()):
            mod._handle_success("enceladus", "SPEC-1", "build-1", 12)
        self.assertEqual(self.s3.touched("put"), [self.content("current-version.json"), self.legacy("current-version.json")])


if __name__ == "__main__":
    unittest.main()
