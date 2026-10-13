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


import datetime as _dt

LM = _dt.datetime(2026, 10, 12, 23, 51, tzinfo=_dt.timezone.utc)


class _Pager:
    def paginate(self, Bucket, Prefix):
        assert Bucket == w.SOURCE_BUCKET
        yield {"Contents": [{"Key": k, "Size": s, "LastModified": LM} for k, s in OBJECTS.get(Prefix, [])]}


class _S3:
    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _Pager()


class TestPlan(unittest.TestCase):
    def test_production_and_gamma_mapping(self):
        pairs = w.plan_pairs(_S3(), "123")
        prod = "enceladus-content-123-us-west-2"
        gamma = "enceladus-content-gamma-123-us-west-2"
        self.assertIn(("agent-documents/a.md", prod, "agent-documents/a.md", 10, LM), pairs)
        self.assertIn(("gamma/agent-documents/g.md", gamma, "agent-documents/g.md", 5, LM), pairs)
        self.assertIn(("governance/live/x.json", prod, "governance/live/x.json", 7, LM), pairs)
        self.assertEqual(len(pairs), 4)

    def test_only_listed_prefixes_and_never_lambda_artifacts(self):
        self.assertNotIn("lambda-artifacts/", w.PREFIXES)
        for p in w.PREFIXES:
            self.assertTrue(p.endswith("/"))

    def test_w4_writer_first_prefixes_are_planned(self):
        # DVP-TSK-B39: the B32 prefixes and rhythm-cycle/ need the delta and parity before their reads flip.
        for p in ("intent-training/", "unlearning-tombstones/", "unlearning-state/", "gdmp-remediation-state/",
                  "rhythm-cycle/"):
            self.assertIn(p, w.PREFIXES)

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


class TestNeedsCopy(unittest.TestCase):
    """DVP-TSK-B12: a same-size rewrite of the source is recopied."""

    def test_missing_or_unchecksummed_or_resized_destinations_are_copied(self):
        self.assertTrue(w.needs_copy(None, 10, LM))
        self.assertTrue(w.needs_copy({"size": 10, "sha256": None, "last_modified": LM}, 10, LM))
        self.assertTrue(w.needs_copy({"size": 9, "sha256": "x", "last_modified": LM}, 10, LM))

    def test_same_size_source_rewritten_after_the_copy_is_recopied(self):
        copied = LM - _dt.timedelta(hours=1)
        self.assertTrue(w.needs_copy({"size": 10, "sha256": "x", "last_modified": copied}, 10, LM))

    def test_unchanged_source_is_skipped(self):
        copied = LM + _dt.timedelta(minutes=5)
        self.assertFalse(w.needs_copy({"size": 10, "sha256": "x", "last_modified": copied}, 10, LM))


class TestCompare(unittest.TestCase):
    """DVP-TSK-B12: objects written by a dual-mode Lambda carry CRC32, not SHA-256, so verify hashes the copy itself."""

    def _clients(self, src_body, dst_body, dst_sha=None):
        import io as _io

        class Src:
            def get_object(self, Bucket, Key):
                return {"Body": _io.BytesIO(src_body)}

        class Dst:
            def get_object_attributes(self, Bucket, Key, ObjectAttributes):
                return {"ObjectSize": len(dst_body), "Checksum": ({"ChecksumSHA256": dst_sha} if dst_sha else {"ChecksumCRC32": "x"}),
                        "LastModified": LM}

            def get_object(self, Bucket, Key):
                return {"Body": _io.BytesIO(dst_body)}
        return Src(), Dst()

    def test_crc_only_copy_is_hashed_and_matches(self):
        s, d = self._clients(b"feed", b"feed")
        self.assertEqual(w.compare(s, d, "mobile/v1/a.json", "b", "mobile/v1/a.json", 4)["status"], "ok")

    def test_crc_only_copy_with_different_bytes_is_a_mismatch(self):
        s, d = self._clients(b"feed", b"FEED")
        self.assertEqual(w.compare(s, d, "mobile/v1/a.json", "b", "mobile/v1/a.json", 4)["status"], "sha256_mismatch")


if __name__ == "__main__":
    unittest.main()
