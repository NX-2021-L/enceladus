"""Offline tests for elr_lib.digest -- stable digest schema."""

import unittest

from elr_lib import digest as elr_digest


class BuildDigestTests(unittest.TestCase):
    def test_stable_keys_always_present(self):
        d = elr_digest.build_digest("op.test", True, 200)
        for key in elr_digest.stable_keys():
            self.assertIn(key, d)
        self.assertEqual(d["operation"], "op.test")
        self.assertEqual(d["ok"], True)
        self.assertEqual(d["status"], 200)
        self.assertEqual(d["identity_posture"], "unknown")
        self.assertEqual(d["anomalies"], [])

    def test_optional_fields_omitted_when_not_supplied(self):
        d = elr_digest.build_digest("op.test", True, 200)
        for key in elr_digest.optional_fields():
            self.assertNotIn(key, d)

    def test_optional_fields_omitted_when_none(self):
        d = elr_digest.build_digest("op.test", True, 200, counts=None, record_ids=None)
        self.assertNotIn("counts", d)
        self.assertNotIn("record_ids", d)

    def test_optional_fields_included_when_supplied(self):
        d = elr_digest.build_digest(
            "op.test",
            True,
            200,
            content_hash="sha256:deadbeef",
            size_bytes=1234,
            counts={"records": 5},
            record_ids=["ENC-TSK-1", "ENC-TSK-2"],
            local_path="/tmp/out.json",
            compliance_score=0.97,
        )
        self.assertEqual(d["content_hash"], "sha256:deadbeef")
        self.assertEqual(d["size_bytes"], 1234)
        self.assertEqual(d["counts"], {"records": 5})
        self.assertEqual(d["record_ids"], ["ENC-TSK-1", "ENC-TSK-2"])
        self.assertEqual(d["local_path"], "/tmp/out.json")
        self.assertEqual(d["compliance_score"], 0.97)

    def test_rows_field_included_when_supplied(self):
        """rows was added for ENC-TSK-O52 / elr_batch_get.py -- per-item
        compact summaries for a batch operation.
        """
        rows = [{"id": "ENC-TSK-1", "kind": "tracker", "ok": True, "status_or_version": "open", "title": "A"}]
        d = elr_digest.build_digest("op.test", True, 200, rows=rows)
        self.assertEqual(d["rows"], rows)

    def test_rows_field_omitted_when_not_supplied(self):
        d = elr_digest.build_digest("op.test", True, 200)
        self.assertNotIn("rows", d)

    def test_valid_identity_postures_accepted(self):
        for posture in elr_digest.VALID_IDENTITY_POSTURES:
            d = elr_digest.build_digest("op.test", True, 200, identity_posture=posture)
            self.assertEqual(d["identity_posture"], posture)

    def test_invalid_identity_posture_raises(self):
        with self.assertRaises(ValueError):
            elr_digest.build_digest("op.test", True, 200, identity_posture="root-god-mode")

    def test_anomalies_normalized_to_string_list(self):
        d = elr_digest.build_digest("op.test", False, 500, anomalies=["boom", 42])
        self.assertEqual(d["anomalies"], ["boom", "42"])

    def test_unsupported_field_raises_digest_first_contract(self):
        with self.assertRaises(ValueError):
            elr_digest.build_digest("op.test", True, 200, full_body={"huge": "payload"})

    def test_unsupported_field_message_mentions_digest_first(self):
        with self.assertRaises(ValueError) as ctx:
            elr_digest.build_digest("op.test", True, 200, raw_response="everything")
        self.assertIn("digest-first", str(ctx.exception))

    def test_schema_is_stable_across_calls(self):
        d1 = elr_digest.build_digest("op.a", True, 200, identity_posture="internal-key")
        d2 = elr_digest.build_digest("op.b", False, 503, identity_posture="unknown", anomalies=["x"])
        self.assertEqual(set(d1.keys()), {"operation", "ok", "status", "identity_posture", "anomalies"})
        self.assertEqual(set(d2.keys()), {"operation", "ok", "status", "identity_posture", "anomalies"})


class CensusFieldsTests(unittest.TestCase):
    """ENC-TSK-Q16-0B: the six elr_list.py --census digest fields."""

    def test_census_fields_included_when_supplied(self):
        pages = [{"cursor": None, "first": {"id": "ENC-TSK-1"}, "last": {"id": "ENC-TSK-50"}, "n": 50}]
        as_of = {"kind": "wall_clock+max_updated_at", "started_at": "2026-09-24T05:00:00Z", "max_updated_at": None}
        by_type = {"task": 50, "issue": 0, "feature": 0, "plan": 0, "lesson": 0, "escalation": 0}
        d = elr_digest.build_digest(
            "elr_list.census",
            True,
            200,
            count=50,
            exhausted=True,
            count_truncated=False,
            pages=pages,
            as_of=as_of,
            by_type=by_type,
        )
        self.assertEqual(d["count"], 50)
        self.assertEqual(d["exhausted"], True)
        self.assertEqual(d["count_truncated"], False)
        self.assertEqual(d["pages"], pages)
        self.assertEqual(d["as_of"], as_of)
        self.assertEqual(d["by_type"], by_type)

    def test_census_fields_omitted_when_not_supplied(self):
        d = elr_digest.build_digest("elr_list.census", False, 500)
        for key in ("count", "exhausted", "count_truncated", "pages", "as_of", "by_type"):
            self.assertNotIn(key, d)

    def test_false_booleans_are_not_treated_as_absent(self):
        # exhausted/count_truncated are real booleans from the server --
        # False is a meaningful value and must still be reported, only a
        # literal None is ever omitted (matches every other optional field).
        d = elr_digest.build_digest("elr_list.census", True, 200, exhausted=False, count_truncated=False)
        self.assertIn("exhausted", d)
        self.assertFalse(d["exhausted"])
        self.assertIn("count_truncated", d)
        self.assertFalse(d["count_truncated"])


class ContentDigestTests(unittest.TestCase):
    def test_content_digest_shape_and_matches_hashlib(self):
        import hashlib

        data = b"hello world"
        result = elr_digest.content_digest(data)
        self.assertTrue(result["content_hash"].startswith("sha256:"))
        self.assertEqual(result["size_bytes"], len(data))
        self.assertEqual(result["content_hash"], f"sha256:{hashlib.sha256(data).hexdigest()}")

    def test_content_digest_deterministic(self):
        data = b"same-bytes"
        r1 = elr_digest.content_digest(data)
        r2 = elr_digest.content_digest(data)
        self.assertEqual(r1, r2)

    def test_content_digest_differs_for_different_bytes(self):
        r1 = elr_digest.content_digest(b"a")
        r2 = elr_digest.content_digest(b"b")
        self.assertNotEqual(r1["content_hash"], r2["content_hash"])


if __name__ == "__main__":
    unittest.main()
