"""DVP-TSK-B53 (isolation W4n): reference-doc reads for legacy-bucket rows go through content_store (no AWS)."""

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

import feed_utils as fu  # noqa: E402

CONTENT = "enceladus-content-356364570033-us-west-2"
KEY = "mobile/v1/reference/devops.md"
ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": "", "FEED_BUCKET": "jreese-net"}


class FakeS3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.gets = []

    def get_object(self, Bucket, Key, **kw):
        self.gets.append((Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}


class FakeDDB:
    def __init__(self, bucket):
        self.bucket = bucket

    def get_item(self, TableName, Key, ConsistentRead=False):
        return {"Item": {"project_id": {"S": "devops"}, "record_id": {"S": "reference#devops"},
                         "s3_key": {"S": KEY}, "s3_bucket": {"S": self.bucket}}}


class TestReferenceReads(unittest.TestCase):
    def _run(self, env, objects, row_bucket="jreese-net"):
        s3 = FakeS3(objects)
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, env, clear=False):
            out = fu.generate_reference_docs_from_s3(
                [fu.FeedProjectEntry(name="devops", prefix="DVP", path=Path(d), status="active", metadata={})], Path(d), FakeDDB(row_bucket), s3_client=s3)
            body = out["devops"].read_bytes() if "devops" in out else None
        return body, s3.gets

    def test_content_first_reads_the_content_bucket_only(self):
        body, gets = self._run(dict(ENV), {(CONTENT, KEY): b"# content", ("jreese-net", KEY): b"# legacy"})
        self.assertEqual(body, b"# content")
        self.assertEqual(gets, [(CONTENT, KEY)])

    def test_content_miss_falls_back_to_legacy(self):
        body, gets = self._run(dict(ENV), {("jreese-net", KEY): b"# legacy"})
        self.assertEqual(body, b"# legacy")
        self.assertEqual(gets, [(CONTENT, KEY), ("jreese-net", KEY)])

    def test_pinned_legacy_read_is_unchanged(self):
        body, gets = self._run(dict(ENV, CONTENT_STORE_READ="legacy"), {("jreese-net", KEY): b"# legacy"})
        self.assertEqual(body, b"# legacy")
        self.assertEqual(gets, [("jreese-net", KEY)])

    def test_row_in_another_bucket_is_read_raw(self):
        body, gets = self._run(dict(ENV), {("other-bucket", KEY): b"# other"}, row_bucket="other-bucket")
        self.assertEqual(body, b"# other")
        self.assertEqual(gets, [("other-bucket", KEY)])

    def test_legacy_mode_reads_legacy(self):
        body, gets = self._run({"CONTENT_STORE_MODE": "legacy", "FEED_BUCKET": "jreese-net"}, {("jreese-net", KEY): b"# legacy"})
        self.assertEqual(body, b"# legacy")
        self.assertEqual(gets, [("jreese-net", KEY)])


if __name__ == "__main__":
    unittest.main()
