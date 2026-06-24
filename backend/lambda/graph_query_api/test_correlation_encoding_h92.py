"""Unit tests for ENC-TSK-H92 / ENC-FTR-082 AC-2 — flag-gated correlation-aware
(pseudoinverse-style) encoding apply on the hybrid-retrieval vector path.

Covers:
  - disabled (default) => byte-identical no-op (the AC-2 guarantee; same object)
  - enabled + identity transform => unit-normalized passthrough
  - enabled + known transform => expected normalize(W @ v)
  - dimension mismatch / malformed artifact => defensive no-op
  - _load_correlation_transform from a local file artifact

Pure-Python: no Neo4j, Bedrock, numpy, or network. Module globals are saved in
setUp and restored in tearDown so the tests cannot contaminate each other.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


def _write_transform(W, dim):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"version": "h92.v1", "dim": dim, "alpha": 0.7, "rank": 1, "W": W}, fh)
    fh.close()
    return fh.name


def _norm(v):
    return (sum(x * x for x in v)) ** 0.5


class CorrelationEncodingTest(unittest.TestCase):
    def setUp(self):
        self._orig_enabled = lf._CORRELATION_ENCODING_ENABLED
        self._orig_uri = lf._CORRELATION_ENCODING_TRANSFORM_URI
        self._orig_cache = dict(lf._correlation_transform_cache)

    def tearDown(self):
        lf._CORRELATION_ENCODING_ENABLED = self._orig_enabled
        lf._CORRELATION_ENCODING_TRANSFORM_URI = self._orig_uri
        lf._correlation_transform_cache.clear()
        lf._correlation_transform_cache.update(self._orig_cache)

    def _enable(self, W, dim):
        path = _write_transform(W, dim)
        lf._CORRELATION_ENCODING_ENABLED = True
        lf._CORRELATION_ENCODING_TRANSFORM_URI = path
        lf._correlation_transform_cache.clear()
        lf._correlation_transform_cache.update({"loaded": False, "W": None, "dim": None})
        return path

    def test_disabled_is_byte_identical_noop(self):
        lf._CORRELATION_ENCODING_ENABLED = False
        v = [0.3, 0.4, 0.5]
        out = lf._apply_correlation_encoding(v)
        self.assertIs(out, v)  # same object => byte-identical, zero overhead

    def test_disabled_even_with_uri_set(self):
        lf._CORRELATION_ENCODING_ENABLED = False
        lf._CORRELATION_ENCODING_TRANSFORM_URI = "/nonexistent.json"
        v = [1.0, 2.0, 3.0]
        self.assertIs(lf._apply_correlation_encoding(v), v)

    def test_enabled_identity_normalizes(self):
        self._enable([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], 3)
        out = lf._apply_correlation_encoding([3.0, 0.0, 0.0])
        self.assertAlmostEqual(_norm(out), 1.0, places=9)
        self.assertAlmostEqual(out[0], 1.0, places=9)

    def test_enabled_known_transform_suppresses_direction(self):
        # W zeroes the first coordinate (a "shared" direction), keeps the rest.
        self._enable([[0.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]], 3)
        out = lf._apply_correlation_encoding([0.6, 0.8, 0.0])
        # W @ v = [0, 0.8, 0]; normalized => [0, 1, 0]
        self.assertAlmostEqual(out[0], 0.0, places=9)
        self.assertAlmostEqual(out[1], 1.0, places=9)
        self.assertAlmostEqual(out[2], 0.0, places=9)

    def test_dimension_mismatch_is_noop(self):
        self._enable([[1.0, 0.0], [0.0, 1.0]], 2)  # dim-2 transform
        v = [1.0, 2.0, 3.0]  # dim-3 query
        self.assertIs(lf._apply_correlation_encoding(v), v)

    def test_malformed_artifact_is_noop(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"version": "h92.v1", "dim": 3}, fh)  # missing W
        fh.close()
        lf._CORRELATION_ENCODING_ENABLED = True
        lf._CORRELATION_ENCODING_TRANSFORM_URI = fh.name
        lf._correlation_transform_cache.clear()
        lf._correlation_transform_cache.update({"loaded": False, "W": None, "dim": None})
        v = [1.0, 2.0, 3.0]
        self.assertIs(lf._apply_correlation_encoding(v), v)

    def test_load_transform_from_file(self):
        self._enable([[1.0, 0.0], [0.0, 1.0]], 2)
        W, dim = lf._load_correlation_transform()
        self.assertEqual(dim, 2)
        self.assertEqual(W, [[1.0, 0.0], [0.0, 1.0]])

    def test_none_embedding_is_noop(self):
        self._enable([[1.0, 0.0], [0.0, 1.0]], 2)
        self.assertIsNone(lf._apply_correlation_encoding(None))


if __name__ == "__main__":
    unittest.main()
