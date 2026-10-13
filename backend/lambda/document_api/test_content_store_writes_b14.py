"""DVP-TSK-B14 (isolation W4d): document_api agent-documents/ writers go through content_store (no AWS).

Env under test: CONTENT_STORE_MODE=dual, CONTENT_STORE_READ=legacy. governance/ and mobile/v1/reference stay raw.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("document_api_b14", os.path.join(HERE, "lambda_function.py"))
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)

LEGACY = document_api.S3_BUCKET
CONTENT = "enceladus-content-356364570033-us-west-2"
ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": ""}


class _NoSuchKey(Exception):
    pass


def _err(code, op):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class FakeS3:
    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        if kw.get("IfNoneMatch") == "*" and (Bucket, Key) in self.objects:
            raise _err("PreconditionFailed", "PutObject")
        self.objects[(Bucket, Key)] = Body
        return {"Bucket": Bucket}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)])}

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise _err("404", "HeadObject")
        return {}

    def copy_object(self, Bucket, Key, CopySource, **kw):
        self.calls.append(("copy", Bucket, Key, dict(kw, CopySource=CopySource)))
        src = (CopySource["Bucket"], CopySource["Key"])
        if src not in self.objects:
            raise _err("NoSuchKey", "CopyObject")
        self.objects[(Bucket, Key)] = self.objects[src]
        return {"Bucket": Bucket}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Bucket, Key, {}))
        self.objects.pop((Bucket, Key), None)

    def buckets_touched(self, op):
        return [c[1] for c in self.calls if c[0] == op]


class _Base(unittest.TestCase):
    prefix = "agent-documents"
    env_prefix = ""

    def setUp(self):
        self.s3 = FakeS3()
        env = dict(ENV, S3_ENV_PREFIX=self.env_prefix)
        for p in (mock.patch.dict(os.environ, env), mock.patch.object(document_api, "_get_s3", return_value=self.s3),
                  mock.patch.object(document_api, "S3_PREFIX", self.prefix)):
            p.start()
            self.addCleanup(p.stop)
        document_api._CONTENT_STORE = None
        self.addCleanup(setattr, document_api, "_CONTENT_STORE", None)


class TestDualWriters(_Base):
    def test_upload_writes_both_buckets_content_first(self):
        key, _h, _n = document_api._upload_content("enceladus", "DOC-1", "hello")
        self.assertEqual(key, "agent-documents/enceladus/DOC-1.md")
        self.assertEqual(self.s3.objects[(CONTENT, key)], b"hello")
        self.assertEqual(self.s3.objects[(LEGACY, key)], b"hello")
        self.assertEqual(self.s3.buckets_touched("put"), [CONTENT, LEGACY])

    def test_immutable_version_put_is_legacy_first(self):
        vkey = "agent-documents/enceladus/versions/DOC-1/2.md"
        document_api._put_version_object_immutable(self.s3, vkey, b"v2")
        self.assertEqual(self.s3.buckets_touched("put"), [LEGACY, CONTENT])
        self.assertTrue(all(c[3].get("IfNoneMatch") == "*" for c in self.s3.calls))
        self.assertIn((CONTENT, vkey), self.s3.objects)

    def test_legacy_existing_version_key_never_writes_content(self):
        vkey = "agent-documents/enceladus/versions/DOC-1/2.md"
        self.s3.objects[(LEGACY, vkey)] = b"original"
        document_api._put_version_object_immutable(self.s3, vkey, b"other")  # PreconditionFailed is swallowed
        self.assertEqual(self.s3.buckets_touched("put"), [LEGACY])
        self.assertNotIn((CONTENT, vkey), self.s3.objects)
        self.assertEqual(self.s3.objects[(LEGACY, vkey)], b"original")

    def test_version_put_head_fallback_reads_legacy_then_writes_both(self):
        vkey = "agent-documents/enceladus/versions/DOC-1/3.md"
        real = self.s3.put_object
        state = {"n": 0}

        def put(Bucket, Key, Body, **kw):
            state["n"] += 1
            if "IfNoneMatch" in kw:
                raise TypeError("unexpected keyword IfNoneMatch")
            return real(Bucket=Bucket, Key=Key, Body=Body, **kw)
        self.s3.put_object = put
        document_api._put_version_object_immutable(self.s3, vkey, b"v3")
        self.assertEqual(self.s3.buckets_touched("head"), [LEGACY])
        self.assertEqual(self.s3.buckets_touched("put"), [CONTENT, LEGACY])

    def test_promote_copies_in_both_buckets(self):
        staging = "agent-documents/enceladus/versions/DOC-1/2.md"
        self.s3.objects[(CONTENT, staging)] = b"v2"
        self.s3.objects[(LEGACY, staging)] = b"v2"
        canonical = document_api._promote_staged_content(staging, "enceladus", "DOC-1")
        self.assertEqual(canonical, "agent-documents/enceladus/DOC-1.md")
        copies = [c for c in self.s3.calls if c[0] == "copy"]
        self.assertEqual([c[1] for c in copies], [CONTENT, LEGACY])
        self.assertEqual([c[3]["CopySource"]["Bucket"] for c in copies], [CONTENT, LEGACY])
        self.assertTrue(all(c[3]["MetadataDirective"] == "REPLACE" for c in copies))
        self.assertIn((CONTENT, canonical), self.s3.objects)
        self.assertIn((LEGACY, canonical), self.s3.objects)

    def test_promote_of_a_post_snapshot_staging_object_falls_back_to_the_legacy_source(self):
        staging = "agent-documents/enceladus/versions/DOC-1/9.md"
        self.s3.objects[(LEGACY, staging)] = b"v9"  # created after the W3 snapshot and the content put lost the race
        canonical = document_api._promote_staged_content(staging, "enceladus", "DOC-1")
        self.assertEqual(self.s3.objects[(CONTENT, canonical)], b"v9")
        self.assertEqual(self.s3.objects[(LEGACY, canonical)], b"v9")

    def test_delete_best_effort_removes_both(self):
        key = "agent-documents/enceladus/versions/DOC-1/2.md"
        self.s3.objects[(CONTENT, key)] = b"x"
        self.s3.objects[(LEGACY, key)] = b"x"
        document_api._delete_s3_object_best_effort(key)
        self.assertEqual(self.s3.objects, {})
        self.assertEqual(self.s3.buckets_touched("delete"), [CONTENT, LEGACY])

    def test_get_content_reads_legacy_only(self):
        key = "agent-documents/enceladus/DOC-1.md"
        self.s3.objects[(LEGACY, key)] = b"legacy-body"
        self.s3.objects[(CONTENT, key)] = b"stale-snapshot"
        self.assertEqual(document_api._get_content("enceladus", "DOC-1"), "legacy-body")
        self.assertEqual(self.s3.buckets_touched("get"), [LEGACY])

    def test_get_content_stored_bucket_fallback_stays_raw_and_self_heals_both(self):
        self.s3.objects[("other-bucket", "old/path.md")] = b"from-record"
        body = document_api._get_content("enceladus", "DOC-1", stored_s3_key="old/path.md", stored_s3_bucket="other-bucket")
        self.assertEqual(body, "from-record")
        self.assertEqual(self.s3.buckets_touched("get"), [LEGACY, "other-bucket"])  # computed miss (legacy), then the record's bucket
        key = "agent-documents/enceladus/DOC-1.md"
        self.assertEqual(self.s3.objects[(CONTENT, key)], b"from-record")
        self.assertEqual(self.s3.objects[(LEGACY, key)], b"from-record")

    def test_sidecar_reads_legacy_and_writes_both(self):
        key = "agent-documents/enceladus/DOC-1.history.jsonl"
        self.s3.objects[(LEGACY, key)] = b'{"n": 1}\n'
        self.s3.objects[(CONTENT, key)] = b"stale"
        document_api._append_history_sidecar("enceladus", "DOC-1", [{"n": 2}])
        self.assertEqual(self.s3.buckets_touched("get"), [LEGACY])
        self.assertEqual(self.s3.objects[(LEGACY, key)], b'{"n": 1}\n{"n": 2}\n')
        self.assertEqual(self.s3.objects[(CONTENT, key)], b'{"n": 1}\n{"n": 2}\n')

    def test_sidecar_without_history_starts_fresh(self):
        document_api._append_history_sidecar("enceladus", "DOC-2", [{"n": 1}])
        self.assertEqual(self.s3.objects[(LEGACY, "agent-documents/enceladus/DOC-2.history.jsonl")], b'{"n": 1}\n')

    def test_legacy_mode_is_a_plain_legacy_write(self):
        with mock.patch.dict(os.environ, {"CONTENT_STORE_MODE": "legacy", "CONTENT_BUCKET": ""}):
            document_api._CONTENT_STORE = None
            document_api._upload_content("enceladus", "DOC-1", "hello")
        self.assertEqual(self.s3.buckets_touched("put"), [LEGACY])


class TestGammaKeys(_Base):
    prefix = "gamma/agent-documents"
    env_prefix = "gamma/"

    def test_legacy_key_carries_gamma_and_content_key_does_not(self):
        key, _h, _n = document_api._upload_content("enceladus", "DOC-1", "hi", version=1)
        self.assertEqual(key, "gamma/agent-documents/enceladus/DOC-1.md")
        self.assertIn((LEGACY, "gamma/agent-documents/enceladus/DOC-1.md"), self.s3.objects)
        self.assertIn((CONTENT, "agent-documents/enceladus/DOC-1.md"), self.s3.objects)
        self.assertIn((LEGACY, "gamma/agent-documents/enceladus/versions/DOC-1/1.md"), self.s3.objects)
        self.assertIn((CONTENT, "agent-documents/enceladus/versions/DOC-1/1.md"), self.s3.objects)
        self.assertFalse([k for b, k in self.s3.objects if b == CONTENT and k.startswith("gamma/")])

    def test_promote_and_sidecar_in_gamma(self):
        staging = "gamma/agent-documents/enceladus/versions/DOC-1/2.md"
        self.s3.objects[(CONTENT, "agent-documents/enceladus/versions/DOC-1/2.md")] = b"v2"
        self.s3.objects[(LEGACY, staging)] = b"v2"
        document_api._promote_staged_content(staging, "enceladus", "DOC-1")
        self.assertIn((CONTENT, "agent-documents/enceladus/DOC-1.md"), self.s3.objects)
        self.assertIn((LEGACY, "gamma/agent-documents/enceladus/DOC-1.md"), self.s3.objects)
        document_api._append_history_sidecar("enceladus", "DOC-1", [{"n": 1}])
        self.assertIn((CONTENT, "agent-documents/enceladus/DOC-1.history.jsonl"), self.s3.objects)
        self.assertIn((LEGACY, "gamma/agent-documents/enceladus/DOC-1.history.jsonl"), self.s3.objects)


if __name__ == "__main__":
    unittest.main()
