"""DVP-TSK-B53 (isolation W4n): memory_consolidation's record-addressed body reads go through content_store (no AWS)."""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("memory_consolidation_b53", os.path.join(HERE, "lambda_function.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

LEGACY = mod.S3_BUCKET
CONTENT = "enceladus-content-356364570033-us-west-2"
KEY = "agent-documents/devops/DOC-000000000001.md"
ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": ""}


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.gets = []

    def get_object(self, Bucket, Key, **kw):
        self.gets.append((Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}


class TestBodyReads(unittest.TestCase):
    def _read(self, env, objects, bucket=None):
        s3 = FakeS3(objects)
        mod._s3_client, mod._CONTENT_STORE = s3, None
        doc = {"document_id": "DOC-000000000001", "s3_key": KEY}
        if bucket:
            doc["s3_bucket"] = bucket
        with mock.patch.dict(os.environ, env, clear=False):
            body = mod._read_document_body(doc)
        mod._CONTENT_STORE = None
        return body, s3.gets

    def test_content_first_reads_the_content_bucket_only(self):
        body, gets = self._read(dict(ENV), {(CONTENT, KEY): b"content", (LEGACY, KEY): b"legacy"})
        self.assertEqual(body, "content")
        self.assertEqual(gets, [(CONTENT, KEY)])

    def test_content_miss_falls_back_to_legacy(self):
        body, gets = self._read(dict(ENV), {(LEGACY, KEY): b"legacy"})
        self.assertEqual(body, "legacy")
        self.assertEqual(gets, [(CONTENT, KEY), (LEGACY, KEY)])

    def test_pinned_legacy_read_is_unchanged(self):
        body, gets = self._read(dict(ENV, CONTENT_STORE_READ="legacy"), {(LEGACY, KEY): b"legacy"})
        self.assertEqual(body, "legacy")
        self.assertEqual(gets, [(LEGACY, KEY)])

    def test_record_in_another_bucket_is_read_raw(self):
        body, gets = self._read(dict(ENV), {("other-bucket", KEY): b"other"}, bucket="other-bucket")
        self.assertEqual(body, "other")
        self.assertEqual(gets, [("other-bucket", KEY)])

    def test_missing_everywhere_returns_empty(self):
        body, gets = self._read(dict(ENV), {})
        self.assertEqual(body, "")


if __name__ == "__main__":
    unittest.main()
