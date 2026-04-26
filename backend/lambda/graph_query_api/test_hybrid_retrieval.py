"""Unit tests for ENC-TSK-B92 Phase 1 hybrid retrieval helpers.

Exercises:
  - RRF fusion math (k=60 per-signal reciprocal-rank contribution)
  - RRF handling of missing-signal records (no contribution)
  - FSRS-6 T3 Lesson post-filter suppression + include_below_threshold
  - Backward-compat: when embeddings are absent the vector signal is empty
    and the pipeline degrades to graph + keyword only

These tests do not require Neo4j or Bedrock — they exercise the pure-Python
ranking and filtering logic.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Ensure the Lambda module directory is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class TestRRFFusion(unittest.TestCase):
    def test_single_signal_rrf(self):
        signals = {
            "vector": [
                {"record_id": "ENC-TSK-001", "score": 0.95, "rank": 1},
                {"record_id": "ENC-TSK-002", "score": 0.80, "rank": 2},
            ],
        }
        fused = lf._rrf_fuse(signals)
        self.assertEqual(len(fused), 2)
        self.assertEqual(fused[0]["record_id"], "ENC-TSK-001")
        # 1 / (60 + 1) for rank 1
        self.assertAlmostEqual(fused[0]["fused_score"], 1.0 / 61.0, places=8)
        self.assertAlmostEqual(fused[1]["fused_score"], 1.0 / 62.0, places=8)
        self.assertEqual(fused[0]["fused_rank"], 1)

    def test_multi_signal_agreement(self):
        """Record that appears in all three signals at rank 1 should win."""
        signals = {
            "vector": [{"record_id": "R1", "score": 0.99, "rank": 1}],
            "graph": [{"record_id": "R1", "score": 10.0, "rank": 1}],
            "keyword": [{"record_id": "R1", "score": 5.0, "rank": 1}],
        }
        fused = lf._rrf_fuse(signals)
        self.assertEqual(fused[0]["record_id"], "R1")
        # 3 * 1/(60+1)
        self.assertAlmostEqual(fused[0]["fused_score"], 3.0 / 61.0, places=8)

    def test_missing_signal_no_contribution(self):
        """Record missing from a signal contributes 0 from that signal."""
        signals = {
            "vector": [
                {"record_id": "A", "score": 0.9, "rank": 1},
                {"record_id": "B", "score": 0.8, "rank": 2},
            ],
            "graph": [
                {"record_id": "B", "score": 5.0, "rank": 1},
                {"record_id": "C", "score": 4.0, "rank": 2},
            ],
            "keyword": [],
        }
        fused = lf._rrf_fuse(signals)
        fused_by_rid = {item["record_id"]: item for item in fused}

        # A: vector only at rank 1
        self.assertAlmostEqual(fused_by_rid["A"]["fused_score"], 1.0 / 61.0, places=8)
        # B: vector rank 2 + graph rank 1
        self.assertAlmostEqual(
            fused_by_rid["B"]["fused_score"],
            1.0 / 62.0 + 1.0 / 61.0,
            places=8,
        )
        # C: graph only at rank 2
        self.assertAlmostEqual(fused_by_rid["C"]["fused_score"], 1.0 / 62.0, places=8)
        # B wins because it's in two signals.
        self.assertEqual(fused[0]["record_id"], "B")

    def test_empty_signals_returns_empty(self):
        fused = lf._rrf_fuse({})
        self.assertEqual(fused, [])

    def test_backward_compat_no_embeddings(self):
        """When vector is empty, fusion degrades to graph + keyword only."""
        signals = {
            "vector": [],
            "graph": [
                {"record_id": "ENC-TSK-100", "score": 9.0, "rank": 1},
            ],
            "keyword": [
                {"record_id": "ENC-TSK-100", "score": 3.0, "rank": 2},
                {"record_id": "ENC-TSK-200", "score": 2.0, "rank": 3},
            ],
        }
        fused = lf._rrf_fuse(signals)
        # No crash, ENC-TSK-100 ranked first from two signals, ENC-TSK-200 present.
        self.assertEqual(len(fused), 2)
        self.assertEqual(fused[0]["record_id"], "ENC-TSK-100")


class TestFSRSFilter(unittest.TestCase):
    def _lesson(self, rid: str, stability=None, resonance=None):
        node = {
            "record_id": rid,
            "_labels": ["Lesson"],
        }
        if stability is not None:
            node["stability"] = stability
        if resonance is not None:
            node["resonance_score"] = resonance
        return node

    def test_suppresses_below_threshold_lessons(self):
        nodes = [
            self._lesson("ENC-LSN-001", stability=0.9),
            self._lesson("ENC-LSN-002", stability=0.4),  # below T3=0.7
            {"record_id": "ENC-TSK-100", "_labels": ["Task"]},
        ]
        filtered = lf._apply_fsrs_t3_filter(nodes, include_below_threshold=False)
        rids = {n["record_id"] for n in filtered}
        self.assertIn("ENC-LSN-001", rids)
        self.assertIn("ENC-TSK-100", rids)
        self.assertNotIn("ENC-LSN-002", rids)

    def test_include_below_threshold_keeps_all(self):
        nodes = [
            self._lesson("ENC-LSN-001", stability=0.9),
            self._lesson("ENC-LSN-002", stability=0.4),
        ]
        filtered = lf._apply_fsrs_t3_filter(nodes, include_below_threshold=True)
        rids = [n["record_id"] for n in filtered]
        self.assertEqual(set(rids), {"ENC-LSN-001", "ENC-LSN-002"})
        # Both tagged, second marked below_t3
        by_rid = {n["record_id"]: n for n in filtered}
        self.assertFalse(by_rid["ENC-LSN-001"]["_below_t3"])
        self.assertTrue(by_rid["ENC-LSN-002"]["_below_t3"])

    def test_resonance_fallback_when_stability_missing(self):
        """Pre-FSRS-6 Lessons use resonance_score as stability proxy."""
        nodes = [
            self._lesson("ENC-LSN-029", resonance=0.6438),  # below 0.7
            self._lesson("ENC-LSN-100", resonance=0.85),    # above 0.7
        ]
        filtered = lf._apply_fsrs_t3_filter(nodes, include_below_threshold=False)
        rids = {n["record_id"] for n in filtered}
        self.assertNotIn("ENC-LSN-029", rids)
        self.assertIn("ENC-LSN-100", rids)

    def test_non_lessons_unaffected(self):
        """Non-Lesson labels are never filtered by T3."""
        nodes = [
            {"record_id": "ENC-TSK-A", "_labels": ["Task"]},
            {"record_id": "ENC-FTR-B", "_labels": ["Feature"]},
        ]
        filtered = lf._apply_fsrs_t3_filter(nodes, include_below_threshold=False)
        self.assertEqual(len(filtered), 2)

    def test_malformed_stability_tolerated(self):
        """Non-numeric stability is treated as missing (does not suppress)."""
        nodes = [
            self._lesson("ENC-LSN-X", stability="not-a-number"),
        ]
        filtered = lf._apply_fsrs_t3_filter(nodes, include_below_threshold=False)
        # Parse fails -> s_val None -> not suppressed.
        self.assertEqual(len(filtered), 1)


class TestEdgeWeights(unittest.TestCase):
    def test_ppr_edge_weight_ordering_matches_lsn029(self):
        """Per-rel-type weights must preserve LSN-029 ordering."""
        ordered = (
            "IMPLEMENTS",
            "ADDRESSES",
            "RELATED_TO",
            "LEARNED_FROM",
            "CHILD_OF",
            "PLAN_CONTAINS",
            "BELONGS_TO",
        )
        weights = [lf.GRAPH_EDGE_WEIGHTS[t] for t in ordered]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_label_vector_index_names(self):
        """B90 migration 001 created these exact index names."""
        self.assertEqual(
            set(lf.LABEL_VECTOR_INDEXES.values()),
            {
                "governed_task_embedding",
                "governed_issue_embedding",
                "governed_feature_embedding",
                "governed_plan_embedding",
                "governed_lesson_embedding",
                "governed_document_embedding",
            },
        )


class TestConstants(unittest.TestCase):
    def test_rrf_k_is_60(self):
        self.assertEqual(lf.RRF_K, 60)

    def test_t3_threshold_is_0_7(self):
        self.assertEqual(lf.FSRS_T3_THRESHOLD, 0.7)

    def test_ppr_damping_0_85(self):
        self.assertEqual(lf.PPR_DAMPING_FACTOR, 0.85)

    def test_valid_search_types_includes_hybrid(self):
        self.assertIn("hybrid", lf.VALID_SEARCH_TYPES)


if __name__ == "__main__":
    unittest.main()
