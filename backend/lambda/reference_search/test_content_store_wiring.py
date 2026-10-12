"""DVP-TSK-B05 (isolation W4): reference_search reads via content_store (no AWS)."""

import datetime as dt
import io
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

from botocore.exceptions import ClientError  # noqa: E402

import lambda_function as lf  # noqa: E402

LEGACY, CONTENT = "jreese-net", "enceladus-content-gamma-1-us-west-2"


def _missing(op):
    return ClientError({"Error": {"Code": "NoSuchKey", "Message": "x"}}, op)


class FakeS3:
    def __init__(self, objects):
        self.objects = objects
        self.reads = []

    def get_object(self, Bucket, Key):
        self.reads.append((Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise _missing("GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)].encode()), "LastModified": dt.datetime(2026, 10, 12)}


ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": CONTENT, "S3_BUCKET": LEGACY, "S3_ENV_PREFIX": "gamma/"}


class TestReferenceSearchContentStore(unittest.TestCase):
    def _fetch(self, objects, project="devops", prefix="gamma/mobile/v1/reference"):
        s3 = FakeS3(objects)
        with mock.patch.dict(os.environ, ENV), mock.patch.object(lf, "_get_s3", return_value=s3), \
             mock.patch.object(lf, "_content_store", None), mock.patch.object(lf, "S3_REFERENCE_PREFIX", prefix):
            content, meta = lf._fetch_reference_doc(project)
        return content, meta, s3.reads

    def test_dual_reads_the_content_bucket_first(self):
        content, meta, reads = self._fetch({(CONTENT, "mobile/v1/reference/devops.md"): "# new\nline"})
        self.assertEqual(content, "# new\nline")
        self.assertEqual(meta["total_lines"], 2)
        self.assertEqual(reads, [(CONTENT, "mobile/v1/reference/devops.md")])

    def test_dual_falls_back_to_legacy_on_a_miss(self):
        content, _, reads = self._fetch({(LEGACY, "gamma/mobile/v1/reference/devops.md"): "# old"})
        self.assertEqual(content, "# old")
        self.assertEqual(reads, [(CONTENT, "mobile/v1/reference/devops.md"), (LEGACY, "gamma/mobile/v1/reference/devops.md")])

    def test_missing_in_both_is_still_not_found(self):
        content, meta, _ = self._fetch({})
        self.assertIsNone(content)
        self.assertIn("not found", meta["error"])
        self.assertEqual(meta["s3_key"], "gamma/mobile/v1/reference/devops.md")

    def test_legacy_mode_is_unchanged(self):
        s3 = FakeS3({(LEGACY, "mobile/v1/reference/devops.md"): "# legacy"})
        with mock.patch.dict(os.environ, {"CONTENT_STORE_MODE": "legacy", "S3_BUCKET": LEGACY}, clear=False), \
             mock.patch.object(lf, "_get_s3", return_value=s3), mock.patch.object(lf, "_content_store", None), \
             mock.patch.object(lf, "S3_REFERENCE_PREFIX", "mobile/v1/reference"):
            content, _ = lf._fetch_reference_doc("devops")
        self.assertEqual(content, "# legacy")
        self.assertEqual(s3.reads, [(LEGACY, "mobile/v1/reference/devops.md")])


if __name__ == "__main__":
    unittest.main()
