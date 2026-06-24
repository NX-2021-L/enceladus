#!/usr/bin/env python3
"""Unit tests for ENC-TSK-H91 correlation analysis (tools/correlation_analysis_h91.py).

stdlib unittest (NOT pytest). Synthetic in-memory data only — no network, no S3,
no live corpus. Exercises cosine correctness, threshold filtering, the pair-set
+ stats shape, and the pure-Python compute path explicitly (so the suite passes
where numpy is unavailable).
"""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import correlation_analysis_h91 as ca  # noqa: E402


def _node(rid, vec, rtype="task"):
    return {"record_id": rid, "record_type": rtype, ca.EMBEDDING_PROPERTY: list(vec)}


class CosineCorrectnessTest(unittest.TestCase):
    """Hand-built vectors: identical -> 1.0, orthogonal -> 0.0, known angle."""

    def test_identical_vectors_cosine_one(self):
        nodes = [_node("A", [1.0, 2.0, 3.0]), _node("B", [1.0, 2.0, 3.0])]
        pairs, stats = ca.cosine_pairs(nodes, threshold=0.5)
        self.assertEqual(stats["num_pairs"], 1)
        self.assertAlmostEqual(pairs[0]["cosine"], 1.0, places=9)

    def test_orthogonal_vectors_cosine_zero(self):
        # Orthogonal vectors -> cosine 0.0, below any positive threshold.
        nodes = [_node("A", [1.0, 0.0]), _node("B", [0.0, 1.0])]
        pairs, stats = ca.cosine_pairs(nodes, threshold=0.0001)
        self.assertEqual(stats["num_pairs"], 0)
        # Confirm the raw cosine via the pure-Python helper (always available).
        py_pairs = ca._cosine_pairs_python(nodes, [[1.0, 0.0], [0.0, 1.0]], threshold=-1.0)
        self.assertEqual(len(py_pairs), 1)
        self.assertAlmostEqual(py_pairs[0]["cosine"], 0.0, places=9)

    def test_known_angle_45_degrees(self):
        # [1,0] vs [1,1] -> cos(45deg) = 1/sqrt(2) ~= 0.7071.
        vecs = [[1.0, 0.0], [1.0, 1.0]]
        nodes = [_node("A", vecs[0]), _node("B", vecs[1])]
        py_pairs = ca._cosine_pairs_python(nodes, vecs, threshold=-1.0)
        self.assertAlmostEqual(py_pairs[0]["cosine"], 1.0 / math.sqrt(2.0), places=9)

    def test_negative_cosine_not_flagged_at_positive_threshold(self):
        # Anti-parallel vectors -> cosine -1.0, never flagged for threshold>=0.
        vecs = [[1.0, 0.0], [-1.0, 0.0]]
        nodes = [_node("A", vecs[0]), _node("B", vecs[1])]
        _, stats = ca.cosine_pairs(nodes, threshold=0.95)
        self.assertEqual(stats["num_pairs"], 0)
        py_pairs = ca._cosine_pairs_python(nodes, vecs, threshold=-2.0)
        self.assertAlmostEqual(py_pairs[0]["cosine"], -1.0, places=9)


class ThresholdFilteringTest(unittest.TestCase):
    """A corpus where exactly one pair exceeds 0.95 and the others don't."""

    def _corpus(self):
        # A and B are near-identical (cosine ~1.0 > 0.95). C is orthogonal-ish to
        # both, so neither (A,C) nor (B,C) crosses 0.95.
        return [
            _node("ENC-TSK-A", [1.0, 0.0, 0.0], "task"),
            _node("ENC-TSK-B", [1.0, 0.001, 0.0], "task"),
            _node("ENC-ISS-C", [0.0, 1.0, 0.0], "issue"),
        ]

    def test_exactly_one_pair_over_threshold(self):
        pairs, stats = ca.cosine_pairs(self._corpus(), threshold=0.95)
        self.assertEqual(stats["num_pairs"], 1)
        self.assertEqual(len(pairs), 1)
        flagged = {pairs[0]["a"], pairs[0]["b"]}
        self.assertEqual(flagged, {"ENC-TSK-A", "ENC-TSK-B"})
        self.assertGreater(pairs[0]["cosine"], 0.95)
        self.assertEqual(stats["num_nodes_involved"], 2)

    def test_pure_python_matches_default_path(self):
        corpus = self._corpus()
        _, vectors = ca._valid_vectors(corpus)
        py_pairs = ca._cosine_pairs_python(corpus, vectors, threshold=0.95)
        self.assertEqual(len(py_pairs), 1)
        self.assertEqual({py_pairs[0]["a"], py_pairs[0]["b"]}, {"ENC-TSK-A", "ENC-TSK-B"})


class PairAndStatsShapeTest(unittest.TestCase):
    def test_pair_record_keys(self):
        nodes = [_node("A", [1.0, 1.0], "feature"), _node("B", [1.0, 1.0], "plan")]
        pairs, _ = ca.cosine_pairs(nodes, threshold=0.5)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(set(pairs[0].keys()), {"a", "b", "a_type", "b_type", "cosine"})
        self.assertEqual(pairs[0]["a_type"], "feature")
        self.assertEqual(pairs[0]["b_type"], "plan")
        self.assertIsInstance(pairs[0]["cosine"], float)

    def test_stats_keys_present(self):
        nodes = [_node("A", [1.0, 0.0]), _node("B", [1.0, 0.0]), _node("C", [0.0, 1.0])]
        _, stats = ca.cosine_pairs(nodes, threshold=0.9, generated_at="2026-06-23T00:00:00Z")
        for key in (
            "corpus_size", "embedding_dim", "threshold", "num_pairs",
            "num_nodes_involved", "max_cosine", "mean_flagged_cosine",
            "cosine_percentiles", "generated_at",
        ):
            self.assertIn(key, stats)
        self.assertEqual(stats["corpus_size"], 3)
        self.assertEqual(stats["embedding_dim"], 2)
        self.assertEqual(stats["threshold"], 0.9)
        self.assertEqual(stats["generated_at"], "2026-06-23T00:00:00Z")
        self.assertEqual(set(stats["cosine_percentiles"].keys()), {"p50", "p90", "p99"})

    def test_generated_at_defaults_none(self):
        nodes = [_node("A", [1.0, 0.0]), _node("B", [1.0, 0.0])]
        _, stats = ca.cosine_pairs(nodes, threshold=0.5)
        self.assertIsNone(stats["generated_at"])

    def test_pairs_sorted_descending(self):
        # Three mutually-high pairs with distinct cosines; assert desc order.
        nodes = [
            _node("A", [1.0, 0.0, 0.0]),
            _node("B", [0.99, 0.14107, 0.0]),   # ~cos 0.99 with A
            _node("C", [0.9, 0.43589, 0.0]),     # ~cos 0.90 with A
        ]
        pairs, _ = ca.cosine_pairs(nodes, threshold=0.0)
        cosines = [p["cosine"] for p in pairs]
        self.assertEqual(cosines, sorted(cosines, reverse=True))

    def test_zero_norm_vector_skipped(self):
        nodes = [
            _node("ZERO", [0.0, 0.0, 0.0]),
            _node("A", [1.0, 0.0, 0.0]),
            _node("B", [1.0, 0.0, 0.0]),
        ]
        pairs, stats = ca.cosine_pairs(nodes, threshold=0.5)
        # Only the A/B pair survives; the zero vector never flags.
        self.assertEqual(stats["num_pairs"], 1)
        involved = {pairs[0]["a"], pairs[0]["b"]}
        self.assertNotIn("ZERO", involved)

    def test_empty_and_singleton_corpus(self):
        for corpus in ([], [_node("solo", [1.0, 2.0])]):
            pairs, stats = ca.cosine_pairs(corpus, threshold=0.5)
            self.assertEqual(pairs, [])
            self.assertEqual(stats["num_pairs"], 0)
            self.assertIsNone(stats["max_cosine"])
            self.assertIsNone(stats["mean_flagged_cosine"])


class PurePythonPathTest(unittest.TestCase):
    """Force the numpy-absent configuration by monkeypatching ca.np to None so
    cosine_pairs() routes through the stdlib fallback. Restored in tearDown so
    test ordering is irrelevant."""

    def setUp(self):
        self._saved_np = ca.np
        ca.np = None  # type: ignore[assignment]

    def tearDown(self):
        ca.np = self._saved_np  # type: ignore[assignment]

    def test_cosine_pairs_without_numpy(self):
        self.assertIsNone(ca.np)
        nodes = [
            _node("ENC-TSK-A", [1.0, 0.0, 0.0]),
            _node("ENC-TSK-B", [1.0, 0.0001, 0.0]),
            _node("ENC-ISS-C", [0.0, 1.0, 0.0]),
        ]
        pairs, stats = ca.cosine_pairs(nodes, threshold=0.95)
        self.assertEqual(stats["num_pairs"], 1)
        self.assertEqual({pairs[0]["a"], pairs[0]["b"]}, {"ENC-TSK-A", "ENC-TSK-B"})
        self.assertAlmostEqual(pairs[0]["cosine"], 1.0, places=6)

    def test_identical_cosine_one_without_numpy(self):
        nodes = [_node("A", [3.0, 4.0]), _node("B", [3.0, 4.0])]
        pairs, _ = ca.cosine_pairs(nodes, threshold=0.5)
        self.assertAlmostEqual(pairs[0]["cosine"], 1.0, places=9)


class HelperTest(unittest.TestCase):
    def test_percentile_interpolation(self):
        vals = [0.90, 0.92, 0.94, 0.96, 0.98]
        self.assertAlmostEqual(ca._percentile(vals, 50.0), 0.94, places=9)
        self.assertAlmostEqual(ca._percentile(vals, 0.0), 0.90, places=9)
        self.assertAlmostEqual(ca._percentile(vals, 100.0), 0.98, places=9)
        self.assertIsNone(ca._percentile([], 50.0))
        self.assertAlmostEqual(ca._percentile([0.5], 90.0), 0.5, places=9)

    def test_coerce_nodes_accepts_dict_and_list(self):
        n = {"record_id": "A", "record_type": "task", "embedding": [1.0]}
        self.assertEqual(ca._coerce_nodes({"nodes": [n]}), [n])
        self.assertEqual(ca._coerce_nodes([n]), [n])
        self.assertEqual(ca._coerce_nodes([n, "junk", 5]), [n])
        self.assertEqual(ca._coerce_nodes(None), [])

    def test_valid_vectors_filters_bad_embeddings(self):
        nodes = [
            _node("good", [1.0, 2.0]),
            {"record_id": "no_emb", "record_type": "task"},
            {"record_id": "empty", "record_type": "task", "embedding": []},
            {"record_id": "nonnum", "record_type": "task", "embedding": ["x", "y"]},
        ]
        kept, vecs = ca._valid_vectors(nodes)
        self.assertEqual([n["record_id"] for n in kept], ["good"])
        self.assertEqual(vecs, [[1.0, 2.0]])

    def test_pairs_to_jsonl_roundtrip(self):
        pairs = [{"a": "A", "b": "B", "a_type": "task", "b_type": "task", "cosine": 0.99}]
        text = ca._pairs_to_jsonl(pairs)
        lines = [ln for ln in text.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        import json as _json
        self.assertEqual(_json.loads(lines[0]), pairs[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
