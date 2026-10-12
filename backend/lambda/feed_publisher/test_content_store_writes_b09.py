"""DVP-TSK-B09 (isolation W4c): mobile feed uploads go through content_store (no AWS)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

import feed_utils as fu  # noqa: E402

CONTENT = "enceladus-content-356364570033-us-west-2"


class FakeS3:
    def __init__(self):
        self.uploads = []

    def upload_file(self, path, Bucket, Key, ExtraArgs=None):
        self.uploads.append((Bucket, Key, dict(ExtraArgs or {})))


class TestFeedUploads(unittest.TestCase):
    def _publish(self, env):
        s3 = FakeS3()
        with tempfile.TemporaryDirectory() as d:
            feed = Path(d)
            (feed / "reference").mkdir()
            (feed / "tasks.json").write_text("{}")
            (feed / "reference" / "devops.md").write_text("# ref")
            (feed / "notes.txt").write_text("skip")
            with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(fu.boto3, "client", return_value=s3):
                keys = fu.publish_mobile_feeds_to_s3(feed, bucket="jreese-net", s3_prefix="mobile/v1")
        return keys, s3.uploads

    def test_legacy_mode_is_unchanged(self):
        keys, ups = self._publish({"CONTENT_STORE_MODE": "legacy"})
        self.assertEqual(sorted(keys), ["mobile/v1/reference/devops.md", "mobile/v1/tasks.json"])
        self.assertEqual(sorted((b, k) for b, k, _ in ups),
                         [("jreese-net", "mobile/v1/reference/devops.md"), ("jreese-net", "mobile/v1/tasks.json")])

    def test_dual_writes_both_buckets_with_the_same_headers(self):
        keys, ups = self._publish({"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "CONTENT_BUCKET": CONTENT,
                                   "S3_ENV_PREFIX": ""})
        self.assertEqual(len(keys), 2)
        self.assertEqual(sorted((b, k) for b, k, _ in ups), [
            (CONTENT, "mobile/v1/reference/devops.md"), (CONTENT, "mobile/v1/tasks.json"),
            ("jreese-net", "mobile/v1/reference/devops.md"), ("jreese-net", "mobile/v1/tasks.json")])
        for b, k, args in ups:
            self.assertEqual(args["CacheControl"], fu._MOBILE_FEED_CACHE_CONTROL)
            self.assertIn(args["ContentType"], ("application/json", "text/markdown; charset=utf-8"))

    def test_dual_without_content_bucket_fails_loudly(self):
        with self.assertRaises(Exception):
            self._publish({"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": ""})


if __name__ == "__main__":
    unittest.main()
