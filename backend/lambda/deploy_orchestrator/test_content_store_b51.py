"""DVP-TSK-B51 (isolation W4l): deploy_orchestrator deploy-config/ and deploy-sources/ access goes through content_store (no AWS).

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

_spec = importlib.util.spec_from_file_location("deploy_orchestrator_b51", os.path.join(HERE, "lambda_function.py"))
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

SRC = "deploy-sources/enceladus"


def _zip(files):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, b in files.items():
            zf.writestr(n, b)
    return buf.getvalue()


class OrchestratorWritesAndLegacyReads(_Base):
    def test_deploy_config_miss_persists_to_both_buckets(self):
        with mock.patch.object(mod, "_read_project_deploy_config", return_value=None):
            cfg = mod._read_deploy_config("enceladus")
        self.assertEqual(self.s3.touched("get"), [self.legacy("deploy.json")])
        self.assertEqual(self.s3.touched("put"), [self.content("deploy.json"), self.legacy("deploy.json")])
        self.assertTrue(all(c[3] == {"ContentType": "application/json"} for c in self.s3.calls if c[0] == "put"))
        self.assertEqual(json.loads(self.s3.objects[self.legacy("deploy.json")]), cfg)

    def test_deploy_config_and_state_reads_hit_legacy_only(self):
        self.s3.objects[self.legacy("deploy.json")] = json.dumps({"build": {"version_file": "v"}}).encode()
        self.s3.objects[self.content("deploy.json")] = json.dumps({"build": {"version_file": "WRONG"}}).encode()
        self.assertEqual(mod._read_deploy_config("enceladus")["build"]["version_file"], "v")
        self.s3.objects[self.legacy("state.json")] = json.dumps({"state": "PAUSED"}).encode()
        self.assertEqual(mod._check_deploy_state("enceladus"), "PAUSED")
        self.assertEqual(self.s3.touched("get"), [self.legacy("deploy.json"), self.legacy("state.json")])
        self.assertEqual(self.s3.touched("put"), [])

    def test_record_only_current_version_lands_in_both_buckets(self):
        with mock.patch.object(mod, "_get_ddb", return_value=mock.MagicMock()):
            mod._finalize_record_only("enceladus", "SPEC-1", "1.0.0", "1.0.1", "patch", [], "sum", [], [])
        self.assertEqual(self.s3.touched("put"), [self.content("current-version.json"), self.legacy("current-version.json")])
        self.assertEqual(json.loads(self.s3.objects[self.content("current-version.json")])["version"], "1.0.1")

    def test_current_version_read_is_legacy_and_keeps_the_miss_fallback(self):
        self.s3.objects[self.legacy("current-version.json")] = json.dumps({"version": "1.2.3"}).encode()
        self.s3.objects[self.content("current-version.json")] = json.dumps({"version": "9.9.9"}).encode()
        self.assertEqual(mod._get_current_version("enceladus", {}), "1.2.3")
        self.assertEqual(self.s3.touched("get"), [self.legacy("current-version.json")])
        self.s3.objects.clear()
        self.assertEqual(mod._get_current_version("enceladus", {}), "0.0.0")

    def test_source_list_and_get_are_legacy_only(self):
        self.s3.objects[(LEGACY, f"{SRC}/20260301.zip")] = b"legacy"
        self.s3.objects[(LEGACY, f"{SRC}/20260302.zip")] = b"legacy2"
        self.s3.objects[(LEGACY, f"{SRC}/notes.txt")] = b"x"
        self.s3.objects[(CONTENT, f"{SRC}/99999999.zip")] = b"content"
        self.assertEqual(mod._list_source_archive_keys(LEGACY, SRC), [f"{SRC}/20260302.zip", f"{SRC}/20260301.zip"])
        self.assertEqual(self.s3.touched("list"), [(LEGACY, f"{SRC}/")])
        self.assertEqual(mod._get_source_object(self.s3, LEGACY, f"{SRC}/20260301.zip")["Body"].read(), b"legacy")
        self.assertEqual(self.s3.touched("get"), [(LEGACY, f"{SRC}/20260301.zip")])

    def test_build_lambda_zip_reads_the_source_archive_via_the_store(self):
        self.s3.objects[(LEGACY, f"{SRC}/20260301.zip")] = _zip({"backend/lambda/feed_publisher/lambda_function.py": "x"})
        with mock.patch.object(mod, "_read_project_deploy_config", return_value={"source": {"source_s3_bucket": LEGACY}}):
            pkg = mod._build_lambda_zip_from_source(
                "enceladus", {"target_arn": "arn:aws:lambda:us-west-2:1:function:devops-feed-publisher"})
        self.assertTrue(pkg)
        self.assertEqual(self.s3.touched("get"), [(LEGACY, f"{SRC}/20260301.zip")])

    def test_other_bucket_and_other_prefix_stay_raw(self):
        self.s3.objects[("custom-bucket", f"{SRC}/a.zip")] = b"a"
        self.s3.objects[(LEGACY, "custom-prefix/b.zip")] = b"b"
        self.s3.list_objects_v2 = mock.Mock(return_value={"Contents": [{"Key": "custom-prefix/b.zip"}]})
        self.assertEqual(mod._get_source_object(self.s3, "custom-bucket", f"{SRC}/a.zip")["Body"].read(), b"a")
        self.assertEqual(mod._get_source_object(self.s3, LEGACY, "custom-prefix/b.zip")["Body"].read(), b"b")
        self.assertEqual(mod._list_source_archive_keys(LEGACY, "custom-prefix"), ["custom-prefix/b.zip"])
        self.s3.list_objects_v2.assert_called_once()
        self.assertEqual(self.s3.touched("list"), [])
        self.assertEqual(self.s3.touched("get"), [("custom-bucket", f"{SRC}/a.zip"), (LEGACY, "custom-prefix/b.zip")])


class OrchestratorAutoReadIsContentFirst(_Base):
    read = None

    def test_config_reads_try_content_then_legacy(self):
        self.s3.objects[self.legacy("state.json")] = json.dumps({"state": "PAUSED"}).encode()
        self.assertEqual(mod._check_deploy_state("enceladus"), "PAUSED")
        self.assertEqual(self.s3.touched("get"), [self.content("state.json"), self.legacy("state.json")])

    def test_source_list_merges_both_and_get_is_content_first(self):
        self.s3.objects[(LEGACY, f"{SRC}/20260301.zip")] = b"legacy"
        self.s3.objects[(CONTENT, f"{SRC}/20260302.zip")] = b"content"
        # Gamma quirk for the later flip: deploy-sources/ keys are unprefixed in the legacy bucket, but the store re-adds
        # S3_ENV_PREFIX (gamma/) to every key it lists from the content bucket, so content-only archives list as
        # gamma/deploy-sources/... . The get strips it again, so both forms resolve; prod (empty prefix) is unaffected.
        keys = mod._list_source_archive_keys(LEGACY, SRC)
        self.assertEqual(keys, [f"gamma/{SRC}/20260302.zip", f"{SRC}/20260301.zip"])
        self.assertEqual(self.s3.touched("list"), [(CONTENT, f"{SRC}/"), (LEGACY, f"{SRC}/")])
        self.assertEqual(mod._get_source_object(self.s3, LEGACY, keys[0])["Body"].read(), b"content")
        self.assertEqual(mod._get_source_object(self.s3, LEGACY, keys[1])["Body"].read(), b"legacy")
        self.assertEqual(self.s3.touched("get"), [
            (CONTENT, f"{SRC}/20260302.zip"), (CONTENT, f"{SRC}/20260301.zip"), (LEGACY, f"{SRC}/20260301.zip")])


if __name__ == "__main__":
    unittest.main()
