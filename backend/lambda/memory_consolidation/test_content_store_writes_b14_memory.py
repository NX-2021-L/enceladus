"""DVP-TSK-B14 (isolation W4d): memory_consolidation's draft-body put goes through content_store (no AWS)."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "shared_layer", "python")))

_spec = importlib.util.spec_from_file_location("memory_consolidation_b14", os.path.join(HERE, "lambda_function.py"))
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

LEGACY = mod.S3_BUCKET
CONTENT = "enceladus-content-356364570033-us-west-2"
ENV = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "CONTENT_BUCKET": CONTENT, "S3_ENV_PREFIX": ""}


class _Exc:
    class ConditionalCheckFailedException(Exception):
        pass


class FakeDDB:
    exceptions = _Exc

    def __init__(self):
        self.items = {}

    def get_item(self, TableName, Key, ConsistentRead=False):
        item = self.items.get(Key["document_id"]["S"])
        return {"Item": item} if item else {}

    def put_item(self, TableName, Item, ConditionExpression=None):
        self.items[Item["document_id"]["S"]] = Item


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = Body
        return {"Bucket": Bucket}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        raise KeyError(Key)


class TestDraftBodyWrite(unittest.TestCase):
    def setUp(self):
        self.s3, self.ddb = FakeS3(), FakeDDB()
        mod._s3_client, mod._ddb_client, mod._CONTENT_STORE = self.s3, self.ddb, None
        self.addCleanup(lambda: (setattr(mod, "_s3_client", None), setattr(mod, "_ddb_client", None),
                                 setattr(mod, "_CONTENT_STORE", None)))
        self._payload = mod.draft_candidate_payload("enceladus", {
            "member_ids": ["ENC-TSK-1", "ENC-TSK-2"],
            "source_handoff_ids": ["DOC-000000000001", "DOC-000000000002"],
            "frequency_count": 2,
        })

    def test_dual_writes_the_draft_body_to_both_buckets_and_records_the_legacy_bucket(self):
        with mock.patch.dict(os.environ, ENV):
            self.assertEqual(mod._put_lesson_candidate(self._payload), "created")
        key = mod._s3_key("enceladus", self._payload["document_id"])
        self.assertEqual([c[1] for c in self.s3.calls if c[0] == "put"], [CONTENT, LEGACY])
        self.assertEqual(self.s3.objects[(CONTENT, key)], self.s3.objects[(LEGACY, key)])
        item = self.ddb.items[self._payload["document_id"]]
        self.assertEqual(item["s3_bucket"]["S"], LEGACY)  # the record keeps naming the legacy bucket until a "content" wave
        self.assertEqual(item["s3_key"]["S"], key)

    def test_gamma_legacy_key_carries_the_prefix_and_content_key_does_not(self):
        with mock.patch.dict(os.environ, dict(ENV, S3_ENV_PREFIX="gamma/")), \
                mock.patch.object(mod, "S3_PREFIX", "gamma/agent-documents"):
            mod._put_lesson_candidate(self._payload)
        did = self._payload["document_id"]
        self.assertIn((LEGACY, f"gamma/agent-documents/enceladus/{did}.md"), self.s3.objects)
        self.assertIn((CONTENT, f"agent-documents/enceladus/{did}.md"), self.s3.objects)

    def test_legacy_mode_is_unchanged(self):
        with mock.patch.dict(os.environ, {"CONTENT_STORE_MODE": "legacy", "CONTENT_BUCKET": ""}):
            mod._put_lesson_candidate(self._payload)
        self.assertEqual([c[1] for c in self.s3.calls if c[0] == "put"], [LEGACY])

    def test_record_body_read_stays_raw(self):
        doc = {"document_id": "DOC-1", "s3_bucket": "record-bucket", "s3_key": "recorded/key.md"}
        with mock.patch.dict(os.environ, ENV):
            self.assertEqual(mod._read_document_body(doc), "")  # FakeS3.get raises -> swallowed
        self.assertEqual([(c[1], c[2]) for c in self.s3.calls], [("record-bucket", "recorded/key.md")])


if __name__ == "__main__":
    unittest.main()
