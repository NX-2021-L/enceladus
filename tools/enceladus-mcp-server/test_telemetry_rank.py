"""Unit + E2E tests for telemetry_rank helpers (ENC-FTR-086, ENC-TSK-I83).

Covers the Convergence Surface read-path projection: canonicalization (D2),
the D3 rich-signal row shape (AC-2), the compute-on-read ranking, pagination,
eligibility, degradation, and the AC-5 E2E scenario.

Run with:
    cd tools/enceladus-mcp-server && python3 -m pytest test_telemetry_rank.py -v
or, without pytest:
    python3 -m unittest test_telemetry_rank
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import telemetry_rank as tr  # noqa: E402


def _task(item_id: str, category: str, created_at: str, updated_at: str, created_by: str):
    return {
        "item_id": item_id,
        "record_type": "task",
        "category": category,
        "created_at": created_at,
        "updated_at": updated_at,
        "created_by": created_by,
    }


class CanonicalizeTests(unittest.TestCase):
    def test_d2_policy(self):
        # NFC + lowercase + ws/underscore->hyphen + strip edge non-alnum.
        self.assertEqual(tr.canonicalize("Deploy_Gate"), "deploy-gate")
        self.assertEqual(tr.canonicalize("  deploy gate  "), "deploy-gate")
        self.assertEqual(tr.canonicalize("DeployGate"), "deploygate")
        self.assertEqual(tr.canonicalize("--implementation--"), "implementation")
        self.assertEqual(tr.canonicalize("a   b___c"), "a-b-c")

    def test_collapses_near_synonyms(self):
        # The canonicalization function collapses the classic D2 noise triple.
        forms = {tr.canonicalize(v) for v in ("deploy_gate", "deploy-gate", "Deploy Gate")}
        self.assertEqual(forms, {"deploy-gate"})

    def test_empty_and_none(self):
        self.assertEqual(tr.canonicalize(None), "")
        self.assertEqual(tr.canonicalize(""), "")
        self.assertEqual(tr.canonicalize("___"), "")


class EligibilityTests(unittest.TestCase):
    def test_known_eligible(self):
        self.assertTrue(tr.is_eligible("category"))
        self.assertTrue(tr.is_eligible("components"))
        self.assertFalse(tr.is_eligible("description"))

    def test_resolve_record_type(self):
        self.assertEqual(tr.resolve_record_type("category"), "task")
        self.assertEqual(tr.resolve_record_type("subtypepattern"), "document")
        self.assertEqual(tr.resolve_record_type("category", "issue"), "issue")


class RankRecordsTests(unittest.TestCase):
    def test_ac1_row_shape(self):
        records = [
            _task("ENC-TSK-001", "implementation", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "agent-a"),
            _task("ENC-TSK-002", "investigation", "2026-01-02T00:00:00Z", "2026-02-02T00:00:00Z", "agent-b"),
        ]
        out = tr.rank_records(records, "category", limit=10)
        self.assertIn("rows", out)
        for row in out["rows"]:
            self.assertIn("canonical_value", row)
            self.assertIn("count", row)
            self.assertIn("rank", row)
        self.assertEqual(out["schema_version"], tr.SCHEMA_VERSION)
        self.assertEqual(out["canonicalization_version"], tr.CANONICALIZATION_VERSION)

    def test_ac2_rich_signal(self):
        records = [
            _task("ENC-TSK-001", "Implementation", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", "agent-a"),
            _task("ENC-TSK-002", "implementation", "2026-01-02T00:00:00Z", "2026-04-01T00:00:00Z", "agent-b"),
        ]
        out = tr.rank_records(records, "category", limit=10)
        row = out["rows"][0]
        self.assertEqual(row["canonical_value"], "implementation")
        # raw_value_samples up to 3, distinct raw forms preserved
        self.assertLessEqual(len(row["raw_value_samples"]), tr.RAW_VALUE_SAMPLE_CAP)
        self.assertIn("Implementation", row["raw_value_samples"])
        # last_seen is the max updated_at across the bucket
        self.assertEqual(row["last_seen"], "2026-04-01T00:00:00Z")
        self.assertEqual(row["first_seen"], "2026-01-01T00:00:00Z")
        self.assertEqual(row["distinct_author_count"], 2)

    def test_ranking_order_and_rank(self):
        records = (
            [_task(f"ENC-TSK-1{i}", "implementation", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", f"a{i}") for i in range(3)]
            + [_task(f"ENC-TSK-2{i}", "validation", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", f"b{i}") for i in range(2)]
        )
        out = tr.rank_records(records, "category", limit=10)
        self.assertEqual(out["rows"][0]["canonical_value"], "implementation")
        self.assertEqual(out["rows"][0]["rank"], 1)
        self.assertEqual(out["rows"][0]["count"], 3)
        self.assertEqual(out["rows"][1]["canonical_value"], "validation")
        self.assertEqual(out["rows"][1]["rank"], 2)

    def test_list_valued_components(self):
        records = [
            {"item_id": "T1", "components": ["comp-a", "comp-b"], "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "created_by": "x"},
            {"item_id": "T2", "components": ["comp-a"], "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "created_by": "y"},
        ]
        out = tr.rank_records(records, "components", limit=10)
        top = out["rows"][0]
        self.assertEqual(top["canonical_value"], "comp-a")
        self.assertEqual(top["count"], 2)

    def test_pagination(self):
        records = [
            _task(f"ENC-TSK-{i}", f"cat{i}", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", f"a{i}")
            for i in range(5)
        ]
        page1 = tr.rank_records(records, "category", limit=2)
        self.assertEqual(len(page1["rows"]), 2)
        self.assertIsNotNone(page1["next_cursor"])
        page2 = tr.rank_records(records, "category", limit=2, cursor=page1["next_cursor"])
        self.assertEqual(len(page2["rows"]), 2)
        # Pages are disjoint and continue the rank sequence.
        self.assertEqual(page2["rows"][0]["rank"], 3)

    def test_malformed_records_skipped(self):
        records = [None, 42, {"item_id": "T1", "category": "implementation"}]
        out = tr.rank_records(records, "category", limit=10)  # type: ignore[arg-type]
        self.assertEqual(out["rows"][0]["canonical_value"], "implementation")

    def test_ac5_e2e_five_implementation_tasks(self):
        """AC-5: 5 tasks with category=implementation -> rank returns implementation count>=5."""
        records = [
            _task(f"ENC-TSK-E{i}", "implementation", "2026-01-01T00:00:00Z", f"2026-0{i+1}-01T00:00:00Z", f"author-{i}")
            for i in range(5)
        ]
        # Add noise of other categories to prove ranking selects implementation.
        records.append(_task("ENC-TSK-V1", "validation", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "v"))
        out = tr.rank_records(records, "category", limit=10)
        top = out["rows"][0]
        self.assertEqual(top["canonical_value"], "implementation")
        self.assertGreaterEqual(top["count"], 5)
        self.assertEqual(top["rank"], 1)


class CounterItemTests(unittest.TestCase):
    def test_rank_counter_items_shape(self):
        items = [
            {"canonical_value": "implementation", "count": 9, "raw_value_samples": ["implementation"], "last_seen": "2026-04-01T00:00:00Z", "distinct_author_count": 4},
            {"canonical_value": "validation", "count": 3},
        ]
        out = tr.rank_counter_items(items, limit=10)
        self.assertEqual(out["rows"][0]["canonical_value"], "implementation")
        self.assertEqual(out["rows"][0]["rank"], 1)
        self.assertEqual(out["rows"][1]["rank"], 2)
        self.assertEqual(out["schema_version"], tr.SCHEMA_VERSION)


class DegradeTests(unittest.TestCase):
    def test_degraded_payload(self):
        out = tr.degraded_payload("tracker_read_failed")
        self.assertEqual(out["rows"], [])
        self.assertTrue(out["degraded"])
        self.assertEqual(out["degraded_reason"], "tracker_read_failed")


if __name__ == "__main__":
    unittest.main()
