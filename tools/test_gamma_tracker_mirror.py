#!/usr/bin/env python3
"""ENC-TSK-M98 unit tests: diff computation, direction-lock refusal, counter reset.

Self-running (python3 tools/test_gamma_tracker_mirror.py), stdlib-only — the
tool defers its boto3 import so no AWS SDK is needed here (ci.yml convention).
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "gamma_tracker_mirror", Path(__file__).parent / "gamma-tracker-mirror.py"
)
gtm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gtm)


def item(pid, rid, title="t", extra=None):
    it = {
        "project_id": {"S": pid},
        "record_id": {"S": rid},
        "item_id": {"S": rid.split("#")[-1]},
        "title": {"S": title},
    }
    if extra:
        it.update(extra)
    return it


class TestDirectionLock(unittest.TestCase):
    def test_happy_path(self):
        gtm.assert_direction_lock(
            "devops-project-tracker",
            "devops-project-tracker-gamma",
            ["enceladus-id-counters-gamma", "enceladus-id-idempotency-gamma"],
        )

    def test_refuses_non_gamma_dest(self):
        with self.assertRaises(gtm.DirectionLockError):
            gtm.assert_direction_lock(
                "devops-project-tracker", "devops-project-tracker", []
            )

    def test_refuses_tampered_source(self):
        with self.assertRaises(gtm.DirectionLockError):
            gtm.assert_direction_lock(
                "devops-project-tracker-gamma", "devops-project-tracker-gamma", []
            )

    def test_refuses_non_gamma_aux_table(self):
        with self.assertRaises(gtm.DirectionLockError):
            gtm.assert_direction_lock(
                "devops-project-tracker",
                "devops-project-tracker-gamma",
                ["enceladus-id-counters"],  # canonical counters must never be wiped
            )

    def test_wipe_table_refuses_non_gamma(self):
        with self.assertRaises(gtm.DirectionLockError):
            gtm.wipe_table(None, "devops-project-tracker")

    def test_main_exits_2_when_dest_wiring_tampered(self):
        # the runtime-detectable tamper: a write target losing its -gamma suffix
        original = gtm.GAMMA_TABLE
        gtm.GAMMA_TABLE = "devops-project-tracker"
        try:
            self.assertEqual(gtm.main([]), 2)
        finally:
            gtm.GAMMA_TABLE = original


class TestComputeDiff(unittest.TestCase):
    def test_classification(self):
        canonical = {
            ("enceladus", "task#ENC-TSK-M96"): item("enceladus", "task#ENC-TSK-M96", "real"),
            ("enceladus", "task#ENC-TSK-A01"): item("enceladus", "task#ENC-TSK-A01", "same"),
            ("enceladus", "issue#ENC-ISS-390"): item("enceladus", "issue#ENC-ISS-390", "governance_hash does not rotate"),
        }
        gamma = {
            ("enceladus", "task#ENC-TSK-A01"): item("enceladus", "task#ENC-TSK-A01", "same"),
            ("enceladus", "issue#ENC-ISS-390"): item("enceladus", "issue#ENC-ISS-390", "Gamma oracle fixture A"),
            ("enceladus", "task#ENC-TSK-L85"): item("enceladus", "task#ENC-TSK-L85", "M92 throwaway carrier"),
        }
        diff = gtm.compute_diff(canonical, gamma)
        self.assertEqual(diff["adds"], [("enceladus", "task#ENC-TSK-M96")])
        self.assertEqual(diff["changed"], [("enceladus", "issue#ENC-ISS-390")])
        self.assertEqual(diff["unchanged"], [("enceladus", "task#ENC-TSK-A01")])
        self.assertEqual(diff["deletes"], [("enceladus", "task#ENC-TSK-L85")])

    def test_manifest_flags_gamma_native_deletes(self):
        canonical = {}
        gamma = {
            ("enceladus", "task#ENC-TSK-L85"): item("enceladus", "task#ENC-TSK-L85", "M92 throwaway carrier"),
            ("enceladus", "counter#task"): {  # legacy counter row: no item_id → not a record
                "project_id": {"S": "enceladus"},
                "record_id": {"S": "counter#task"},
                "next_num": {"N": "2173"},
            },
        }
        diff = gtm.compute_diff(canonical, gamma)
        manifest = gtm.build_manifest(diff, canonical, gamma, "dry-run")
        self.assertEqual(manifest["counts"]["deletes"], 2)
        self.assertEqual(manifest["counts"]["gamma_native_deletes"], 1)
        flagged = {d["record_id"]: d["gamma_native_record"] for d in manifest["deletes"]}
        self.assertTrue(flagged["task#ENC-TSK-L85"])
        self.assertFalse(flagged["counter#task"])
        self.assertEqual(manifest["mode"], "dry-run")
        self.assertEqual(manifest["source_table"], "devops-project-tracker")


class FakeDdb:
    """Minimal DynamoDB client fake: paginated scan + capture of batch deletes."""

    def __init__(self, table_name, key_attrs, pages):
        self.table_name = table_name
        self.key_attrs = key_attrs
        self.pages = pages  # list of item-lists; each scan call pops one
        self.scan_calls = 0
        self.deleted_keys = []

    def describe_table(self, TableName):
        assert TableName == self.table_name
        return {"Table": {"KeySchema": [{"AttributeName": a, "KeyType": "HASH"} for a in self.key_attrs]}}

    def scan(self, **kwargs):
        page = self.pages[self.scan_calls]
        self.scan_calls += 1
        resp = {"Items": page, "Count": len(page)}
        if self.scan_calls < len(self.pages):
            resp["LastEvaluatedKey"] = {"marker": {"S": str(self.scan_calls)}}
        return resp

    def batch_write_item(self, RequestItems):
        for table, reqs in RequestItems.items():
            assert table == self.table_name
            assert len(reqs) <= 25
            for r in reqs:
                self.deleted_keys.append(r["DeleteRequest"]["Key"])
        return {"UnprocessedItems": {}}


class TestCounterReset(unittest.TestCase):
    def test_wipe_table_deletes_every_row_across_pages(self):
        rows_p1 = [{"counter_key": {"S": f"enceladus#{t}"}} for t in ("task", "issue", "lesson")]
        rows_p2 = [{"counter_key": {"S": "mod#plan"}}]
        fake = FakeDdb("enceladus-id-counters-gamma", ["counter_key"], [rows_p1, rows_p2])
        n = gtm.wipe_table(fake, "enceladus-id-counters-gamma")
        self.assertEqual(n, 4)
        self.assertEqual(
            sorted(k["counter_key"]["S"] for k in fake.deleted_keys),
            ["enceladus#issue", "enceladus#lesson", "enceladus#task", "mod#plan"],
        )

    def test_wipe_table_empty_table_is_noop(self):
        fake = FakeDdb("enceladus-id-idempotency-gamma", ["idempotency_key"], [[]])
        self.assertEqual(gtm.wipe_table(fake, "enceladus-id-idempotency-gamma"), 0)
        self.assertEqual(fake.deleted_keys, [])

    def test_batch_chunking_over_25(self):
        rows = [{"counter_key": {"S": f"p#{i}"}} for i in range(60)]
        fake = FakeDdb("x-gamma", ["counter_key"], [rows])
        self.assertEqual(gtm.wipe_table(fake, "x-gamma"), 60)
        self.assertEqual(len(fake.deleted_keys), 60)


if __name__ == "__main__":
    result = unittest.main(exit=False).result
    print(f"[{'SUCCESS' if result.wasSuccessful() else 'ERROR'}] gamma-tracker-mirror tests: "
          f"{result.testsRun} run, {len(result.failures)} failures, {len(result.errors)} errors")
    sys.exit(0 if result.wasSuccessful() else 1)
