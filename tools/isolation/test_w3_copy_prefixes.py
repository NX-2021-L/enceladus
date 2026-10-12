"""DVP-TSK-B02: W3 copy planning and the parity check (no AWS)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import w3_copy_prefixes as w  # noqa: E402

OBJECTS = {
    "agent-documents/": [("agent-documents/a.md", 10), ("agent-documents/b.md", 20)],
    "gamma/agent-documents/": [("gamma/agent-documents/g.md", 5)],
    "governance/": [("governance/live/x.json", 7)],
}


class _Pager:
    def paginate(self, Bucket, Prefix):
        assert Bucket == w.SOURCE_BUCKET
        yield {"Contents": [{"Key": k, "Size": s} for k, s in OBJECTS.get(Prefix, [])]}


class _S3:
    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _Pager()


class TestPlan(unittest.TestCase):
    def test_production_and_gamma_mapping(self):
        pairs = w.plan_pairs(_S3(), "123")
        prod = "enceladus-content-123-us-west-2"
        gamma = "enceladus-content-gamma-123-us-west-2"
        self.assertIn(("agent-documents/a.md", prod, "agent-documents/a.md", 10), pairs)
        self.assertIn(("gamma/agent-documents/g.md", gamma, "agent-documents/g.md", 5), pairs)
        self.assertIn(("governance/live/x.json", prod, "governance/live/x.json", 7), pairs)
        self.assertEqual(len(pairs), 4)

    def test_only_listed_prefixes_and_never_lambda_artifacts(self):
        self.assertNotIn("lambda-artifacts/", w.PREFIXES)
        for p in w.PREFIXES:
            self.assertTrue(p.endswith("/"))

    def test_copy_keeps_metadata_and_requests_sha256(self):
        calls = []

        class _Dst:
            def copy_object(self, **kw):
                calls.append(kw)
        w.copy_one(_Dst(), "agent-documents/a.md", "b", "agent-documents/a.md")
        (kw,) = calls
        self.assertEqual(kw["MetadataDirective"], "COPY")
        self.assertEqual(kw["TaggingDirective"], "COPY")
        self.assertEqual(kw["ChecksumAlgorithm"], "SHA256")
        self.assertEqual(kw["CopySource"], {"Bucket": "jreese-net", "Key": "agent-documents/a.md"})
        self.assertNotIn("ServerSideEncryption", kw)  # the destination default (content key) encrypts


if __name__ == "__main__":
    unittest.main()
