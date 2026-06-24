"""Unit tests for ENC-TSK-I03 / ENC-FTR-082 AC-2 retry — symmetric vector re-rank.

Supersedes the ENC-TSK-H92 query-side test. Covers:
  - _transform_unit: W@v then L2-normalize (identity, known, degenerate, mismatch)
  - _hybrid_vector_ranks with encoding OFF (default) => byte-identical: ranks by the
    raw HNSW score and the Cypher does NOT request node.embedding
  - _hybrid_vector_ranks with encoding ON => candidates re-scored by
    cosine(W@q, W@emb) (symmetric) and re-ordered; the Cypher requests embeddings

Pure-Python: no Neo4j/Bedrock/numpy/network. Module globals + the transform cache
are saved in setUp and restored in tearDown.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


def _unit(v):
    n = sum(x * x for x in v) ** 0.5
    return [x / n for x in v]


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, rows, capture):
        self._rows = rows
        self._capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **kwargs):
        self._capture.append(cypher)  # record the Cypher for byte-identical assertions
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(self, rows):
        self._rows = rows
        self.cyphers = []

    def session(self):
        return _FakeSession(self._rows, self.cyphers)


def _row(rid, score, emb):
    return {"rid": rid, "score": score, "labels": ["Task"], "embedding": emb}


class TransformUnitTest(unittest.TestCase):
    def test_identity_normalizes(self):
        W = [[1.0, 0.0], [0.0, 1.0]]
        self.assertEqual(lf._transform_unit([3.0, 4.0], W, 2), [0.6, 0.8])

    def test_known_projection(self):
        # W zeroes coord 0, keeps coord 1.
        W = [[0.0, 0.0], [0.0, 1.0]]
        out = lf._transform_unit([5.0, 2.0], W, 2)
        self.assertAlmostEqual(out[0], 0.0, places=9)
        self.assertAlmostEqual(out[1], 1.0, places=9)

    def test_dim_mismatch_returns_none(self):
        self.assertIsNone(lf._transform_unit([1.0, 2.0, 3.0], [[1.0, 0.0], [0.0, 1.0]], 2))

    def test_none_input_returns_none(self):
        self.assertIsNone(lf._transform_unit(None, [[1.0]], 1))

    def test_degenerate_returns_none(self):
        # W maps the vector to the zero vector => no unit direction.
        self.assertIsNone(lf._transform_unit([1.0, 0.0], [[0.0, 0.0], [0.0, 0.0]], 2))


class VectorRerankTest(unittest.TestCase):
    def setUp(self):
        self._orig_enabled = lf._CORRELATION_ENCODING_ENABLED
        self._orig_uri = lf._CORRELATION_ENCODING_TRANSFORM_URI
        self._orig_cache = dict(lf._correlation_transform_cache)
        # Two near-duplicate candidates. Raw HNSW ranks B above A (0.95 > 0.90).
        self._rows = [
            _row("ENC-TSK-A", 0.90, [10.0, 1.0]),
            _row("ENC-TSK-B", 0.95, [1.0, -10.0]),
        ]

    def tearDown(self):
        lf._CORRELATION_ENCODING_ENABLED = self._orig_enabled
        lf._CORRELATION_ENCODING_TRANSFORM_URI = self._orig_uri
        lf._correlation_transform_cache.clear()
        lf._correlation_transform_cache.update(self._orig_cache)

    def _enable(self, W, dim):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"version": "h92.v1", "dim": dim, "alpha": 0.9, "rank": 1, "W": W}, fh)
        fh.close()
        lf._CORRELATION_ENCODING_ENABLED = True
        lf._CORRELATION_ENCODING_TRANSFORM_URI = fh.name
        lf._correlation_transform_cache.clear()
        lf._correlation_transform_cache.update({"loaded": False, "W": None, "dim": None})

    def test_disabled_is_byte_identical(self):
        lf._CORRELATION_ENCODING_ENABLED = False
        driver = _FakeDriver(self._rows)
        ranked = lf._hybrid_vector_ranks(driver, "enceladus", [3.0, 4.0], k_per_label=10,
                                         record_type_filter="task")
        # Ranks by raw HNSW score (B first), and the Cypher never requests embeddings.
        self.assertEqual([r["record_id"] for r in ranked], ["ENC-TSK-B", "ENC-TSK-A"])
        self.assertEqual(ranked[0]["score"], 0.95)
        # "$query_embedding" is always in the Cypher; the re-rank adds "AS embedding".
        self.assertTrue(driver.cyphers and all("AS embedding" not in c for c in driver.cyphers))

    def test_enabled_symmetric_rerank_reorders(self):
        # W = diag(0, 1): suppress the shared coord-0, keep coord-1.
        self._enable([[0.0, 0.0], [0.0, 1.0]], 2)
        driver = _FakeDriver(self._rows)
        q = [3.0, 4.0]
        ranked = lf._hybrid_vector_ranks(driver, "enceladus", q, k_per_label=10,
                                         record_type_filter="task")
        # Wq=[0,4]->unit[0,1]; A:[10,1]->W[0,1]->unit[0,1] => cos 1.0;
        # B:[1,-10]->W[0,-10]->unit[0,-1] => cos -1.0. So A now beats B.
        self.assertEqual([r["record_id"] for r in ranked], ["ENC-TSK-A", "ENC-TSK-B"])
        scores = {r["record_id"]: r["score"] for r in ranked}
        self.assertAlmostEqual(scores["ENC-TSK-A"], 1.0, places=9)
        self.assertAlmostEqual(scores["ENC-TSK-B"], -1.0, places=9)
        # The Cypher requested candidate embeddings for the symmetric re-score.
        self.assertTrue(any("AS embedding" in c for c in driver.cyphers))

    def test_enabled_dim_mismatch_falls_back(self):
        # Transform dim 3 but the query/candidates are dim 2 => no re-rank, HNSW order.
        self._enable([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], 3)
        driver = _FakeDriver(self._rows)
        ranked = lf._hybrid_vector_ranks(driver, "enceladus", [3.0, 4.0], k_per_label=10,
                                         record_type_filter="task")
        self.assertEqual([r["record_id"] for r in ranked], ["ENC-TSK-B", "ENC-TSK-A"])
        self.assertTrue(all("AS embedding" not in c for c in driver.cyphers))


if __name__ == "__main__":
    unittest.main()
