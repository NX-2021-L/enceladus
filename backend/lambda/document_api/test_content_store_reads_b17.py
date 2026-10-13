"""DVP-TSK-B17 (isolation W4e): document_api agent-documents/ reads go content-first (no AWS).

Env under test: CONTENT_STORE_MODE=dual with NO CONTENT_STORE_READ, so reads try the content bucket and fall back to
the legacy bucket only on a miss. Writes stay dual (see test_content_store_writes_b14.py).
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("document_api_b17", os.path.join(HERE, "lambda_function.py"))
document_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(document_api)

LEGACY = document_api.S3_BUCKET
CONTENT = "enceladus-content-356364570033-us-west-2"
ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": ""}


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

    def buckets_touched(self, op):
        return [c[1] for c in self.calls if c[0] == op]


class _Base(unittest.TestCase):
    prefix = "agent-documents"
    env_prefix = ""

    def setUp(self):
        self.s3 = FakeS3()
        env = dict(ENV, S3_ENV_PREFIX=self.env_prefix)
        patches = [
            mock.patch.dict(os.environ, env),
            mock.patch.object(document_api, "_get_s3", return_value=self.s3),
            mock.patch.object(document_api, "S3_PREFIX", self.prefix),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("CONTENT_STORE_READ", None)  # the B14 pin is gone: reads follow the mode
        document_api._CONTENT_STORE = None
        self.addCleanup(setattr, document_api, "_CONTENT_STORE", None)


class TestContentFirstReads(_Base):
    def test_get_content_reads_the_content_bucket_first(self):
        key = "agent-documents/enceladus/DOC-1.md"
        self.s3.objects[(CONTENT, key)] = b"content-body"
        self.s3.objects[(LEGACY, key)] = b"legacy-body"
        self.assertEqual(document_api._get_content("enceladus", "DOC-1"), "content-body")
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT])

    def test_get_content_content_miss_falls_back_to_legacy(self):
        key = "agent-documents/enceladus/DOC-1.md"
        self.s3.objects[(LEGACY, key)] = b"legacy-body"
        self.assertEqual(document_api._get_content("enceladus", "DOC-1"), "legacy-body")
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT, LEGACY])

    def test_get_content_missing_in_both_is_none(self):
        self.assertIsNone(document_api._get_content("enceladus", "DOC-9"))
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT, LEGACY])

    def test_sidecar_read_is_content_first_and_the_append_writes_both(self):
        key = "agent-documents/enceladus/DOC-1.history.jsonl"
        self.s3.objects[(CONTENT, key)] = b'{"n": 1}\n'
        self.s3.objects[(LEGACY, key)] = b"stale"
        document_api._append_history_sidecar("enceladus", "DOC-1", [{"n": 2}])
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT])
        self.assertEqual(self.s3.objects[(CONTENT, key)], b'{"n": 1}\n{"n": 2}\n')
        self.assertEqual(self.s3.objects[(LEGACY, key)], b'{"n": 1}\n{"n": 2}\n')

    def test_sidecar_content_miss_falls_back_to_legacy(self):
        key = "agent-documents/enceladus/DOC-1.history.jsonl"
        self.s3.objects[(LEGACY, key)] = b'{"n": 1}\n'
        document_api._append_history_sidecar("enceladus", "DOC-1", [{"n": 2}])
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT, LEGACY])
        self.assertEqual(self.s3.objects[(CONTENT, key)], b'{"n": 1}\n{"n": 2}\n')

    def test_history_events_load_reads_the_sidecar_content_first(self):
        key = "agent-documents/enceladus/DOC-1.history.jsonl"
        self.s3.objects[(CONTENT, key)] = b'{"n": 1}\n'
        events = document_api._load_document_history_events("DOC-1", "enceladus", [{"n": 2}])
        self.assertIn({"n": 1}, events)
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT])

    def test_the_cloudformation_pin_is_gone_for_document_api_only(self):
        yaml_path = os.path.abspath(os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml"))
        with open(yaml_path, encoding="utf-8") as fh:
            text = fh.read()

        def block(name):
            m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
            self.assertIsNotNone(m, name)
            return m.group(1)

        doc = block("DocumentApiFunction")
        self.assertIn("CONTENT_STORE_MODE: dual", doc)
        self.assertNotIn("CONTENT_STORE_READ: ", doc)
        self.assertIn("CONTENT_STORE_READ: legacy", block("MemoryConsolidationFunction"))  # its only store call is a write


class TestGammaReads(_Base):
    prefix = "gamma/agent-documents"
    env_prefix = "gamma/"

    def test_gamma_reads_the_unprefixed_content_key_then_the_prefixed_legacy_key(self):
        self.s3.objects[(LEGACY, "gamma/agent-documents/enceladus/DOC-1.md")] = b"legacy-body"
        self.assertEqual(document_api._get_content("enceladus", "DOC-1"), "legacy-body")
        gets = [(c[1], c[2]) for c in self.s3.calls if c[0] == "get"]
        self.assertEqual(gets, [(CONTENT, "agent-documents/enceladus/DOC-1.md"),
                                (LEGACY, "gamma/agent-documents/enceladus/DOC-1.md")])

    def test_gamma_content_hit_never_touches_legacy(self):
        self.s3.objects[(CONTENT, "agent-documents/enceladus/DOC-1.md")] = b"content-body"
        self.assertEqual(document_api._get_content("enceladus", "DOC-1"), "content-body")
        self.assertEqual(self.s3.buckets_touched("get"), [CONTENT])


if __name__ == "__main__":
    unittest.main()
