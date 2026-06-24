#!/usr/bin/env python3
"""Unit tests for ENC-TSK-H92 offline fit (tools/fit_encoding_h92.py).

stdlib unittest (NOT pytest). Synthetic in-memory data only — no network, no S3,
no live corpus. A tempfile is used only to prove the written artifact round-trips
against the contract the in-Lambda apply step reads.

The synthetic corpus carries near-duplicate pairs (small angle, all sharing a
common dominant direction) plus unrelated vectors. The pairs list flags only the
near-duplicates. The decorrelation-efficacy test then asserts that applying ``W``
collapses the flagged pair's cosine more than an unrelated pair's — the proof
that the transform suppresses the shared mode.
"""

import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fit_encoding_h92 as fe  # noqa: E402

DIM = 8


def _node(rid, vec, rtype="task"):
    return {"record_id": rid, "record_type": rtype, fe.EMBEDDING_PROPERTY: list(vec)}


def _pair(a, b, cosine, a_type="task", b_type="task"):
    return {"a": a, "b": b, "a_type": a_type, "b_type": b_type, "cosine": float(cosine)}


def _unit(vec):
    v = np.asarray(vec, dtype=np.float64)
    n = np.linalg.norm(v)
    return v / n if n > 0 else v


def _apply(W, q):
    """Mirror the in-Lambda apply: q' = normalize(W @ q)."""
    qp = np.asarray(W, dtype=np.float64) @ _unit(q)
    return _unit(qp)


def _cos(a, b):
    return float(np.dot(_unit(a), _unit(b)))


def _synthetic_corpus():
    """A D=8 corpus.

    Shared direction e0 dominates two near-duplicate pairs:
      * (DUP-A1, DUP-A2): both heavy on e0 with a small distinctive tilt.
      * (DUP-B1, DUP-B2): same, a different small tilt — so e0 is the redundant
        mode the SVD will surface.
    Unrelated vectors live in other axes (e3..e6) and are NOT flagged.
    """
    def axis(i, scale=1.0):
        v = [0.0] * DIM
        v[i] = scale
        return v

    def mix(base_i, base_s, tilt_i, tilt_s):
        v = axis(base_i, base_s)
        v[tilt_i] += tilt_s
        return v

    nodes = [
        # Near-duplicate pair A: dominated by e0, tiny distinctive tilt on e1/e2.
        _node("DUP-A1", mix(0, 1.0, 1, 0.10)),
        _node("DUP-A2", mix(0, 1.0, 2, 0.10)),
        # Near-duplicate pair B: also dominated by e0, distinctive tilt on e1/e2.
        _node("DUP-B1", mix(0, 1.0, 1, 0.12)),
        _node("DUP-B2", mix(0, 1.0, 2, 0.12)),
        # Unrelated vectors — distinct axes, low mutual + low e0 overlap.
        _node("UNREL-X", axis(3, 1.0), "issue"),
        _node("UNREL-Y", axis(5, 1.0), "feature"),
        _node("UNREL-Z", mix(4, 1.0, 6, 0.10), "plan"),
    ]
    pairs = [
        _pair("DUP-A1", "DUP-A2", _cos(nodes[0][fe.EMBEDDING_PROPERTY],
                                       nodes[1][fe.EMBEDDING_PROPERTY])),
        _pair("DUP-B1", "DUP-B2", _cos(nodes[2][fe.EMBEDDING_PROPERTY],
                                       nodes[3][fe.EMBEDDING_PROPERTY])),
    ]
    return nodes, pairs


class PatternMatrixTest(unittest.TestCase):
    def test_pattern_matrix_uses_distinct_pair_endpoints(self):
        nodes, pairs = _synthetic_corpus()
        P, dim, used = fe.build_pattern_matrix(nodes, pairs)
        self.assertEqual(dim, DIM)
        # 4 distinct flagged endpoints; unrelated nodes excluded.
        self.assertEqual(P.shape, (4, DIM))
        self.assertEqual(set(used), {"DUP-A1", "DUP-A2", "DUP-B1", "DUP-B2"})
        # Rows are L2-normalized.
        norms = np.linalg.norm(P, axis=1)
        for n in norms:
            self.assertAlmostEqual(n, 1.0, places=9)

    def test_missing_endpoint_and_zero_norm_skipped(self):
        nodes = [
            _node("KEEP-1", [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.1]),
            _node("KEEP-2", [1.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
            _node("ZERO", [0.0] * DIM),
        ]
        pairs = [
            _pair("KEEP-1", "KEEP-2", 0.99),
            _pair("KEEP-1", "MISSING", 0.97),   # MISSING absent from corpus
            _pair("ZERO", "KEEP-2", 0.96),       # ZERO is zero-norm
        ]
        P, dim, used = fe.build_pattern_matrix(nodes, pairs)
        self.assertEqual(set(used), {"KEEP-1", "KEEP-2"})
        self.assertEqual(P.shape, (2, DIM))

    def test_no_usable_correlated_vector_raises(self):
        nodes = [_node("A", [1.0] + [0.0] * (DIM - 1))]
        pairs = [_pair("GHOST-1", "GHOST-2", 0.99)]  # neither in corpus
        with self.assertRaises(ValueError):
            fe.build_pattern_matrix(nodes, pairs)


class ChooseRankTest(unittest.TestCase):
    def test_rank_meets_energy_target(self):
        # Energy fractions: 0.81, 0.16, 0.03 -> 0.9 reached at r=2.
        sv = np.array([9.0, 4.0, math.sqrt(3.0)])
        r, captured = fe.choose_rank(sv, energy=0.9, max_rank=64)
        self.assertEqual(r, 2)
        self.assertGreaterEqual(captured, 0.9)

    def test_rank_capped_by_max_rank(self):
        sv = np.array([1.0, 1.0, 1.0, 1.0])  # equal energy; 0.9 needs all 4
        r, _ = fe.choose_rank(sv, energy=0.9, max_rank=2)
        self.assertEqual(r, 2)

    def test_rank_at_least_one_with_energy(self):
        sv = np.array([5.0, 0.0, 0.0])
        r, captured = fe.choose_rank(sv, energy=0.9, max_rank=64)
        self.assertEqual(r, 1)
        self.assertAlmostEqual(captured, 1.0, places=9)

    def test_zero_energy_matrix_rank_zero(self):
        sv = np.array([0.0, 0.0])
        r, captured = fe.choose_rank(sv, energy=0.9, max_rank=64)
        self.assertEqual(r, 0)
        self.assertEqual(captured, 0.0)


class TransformPropertiesTest(unittest.TestCase):
    def test_W_shape_finite_symmetric_eigenbounded(self):
        nodes, pairs = _synthetic_corpus()
        alpha = 0.7
        P, dim, _ = fe.build_pattern_matrix(nodes, pairs)
        W, rank, meta = fe.build_transform(P, dim, alpha=alpha, energy=0.9, max_rank=64)

        self.assertEqual(W.shape, (DIM, DIM))
        self.assertTrue(np.all(np.isfinite(W)))
        self.assertGreaterEqual(rank, 1)

        # Symmetric (W = I - alpha * sum v v^T is symmetric by construction).
        self.assertTrue(np.allclose(W, W.T, atol=1e-9))

        # Eigenvalues within [1 - alpha, 1] (use eigvalsh: W is symmetric).
        eps = 1e-9
        eig = np.linalg.eigvalsh(W)
        self.assertGreaterEqual(float(eig.min()), 1.0 - alpha - eps)
        self.assertLessEqual(float(eig.max()), 1.0 + eps)

        # Energy captured is a sane fraction; singular values recorded.
        self.assertGreater(meta["energy_captured"], 0.0)
        self.assertLessEqual(meta["energy_captured"], 1.0 + 1e-12)
        self.assertTrue(len(meta["top_singular_values"]) >= 1)

    def test_alpha_zero_is_identity(self):
        nodes, pairs = _synthetic_corpus()
        P, dim, _ = fe.build_pattern_matrix(nodes, pairs)
        W, _, _ = fe.build_transform(P, dim, alpha=0.0, energy=0.9, max_rank=64)
        self.assertTrue(np.allclose(W, np.eye(DIM), atol=1e-12))


class DecorrelationEfficacyTest(unittest.TestCase):
    """The substantive claim: applying W collapses a FLAGGED near-duplicate
    pair's cosine by more than it collapses an UNRELATED pair's cosine. This is
    synthetic data — a legitimate proof of the decorrelation effect, not a live
    corpus measurement.
    """

    def test_flagged_pair_decorrelated_more_than_unrelated(self):
        nodes, pairs = _synthetic_corpus()
        artifact = fe.fit_artifact(nodes, pairs, alpha=0.7, energy=0.9, max_rank=64)
        W = np.asarray(artifact["W"], dtype=np.float64)

        emb = {n["record_id"]: n[fe.EMBEDDING_PROPERTY] for n in nodes}

        # Flagged near-duplicate pair (shares the dominant e0 mode).
        a1, a2 = emb["DUP-A1"], emb["DUP-A2"]
        cos_flagged_before = _cos(a1, a2)
        cos_flagged_after = _cos(_apply(W, a1), _apply(W, a2))

        # Unrelated pair (orthogonal-ish axes, not flagged, no shared mode).
        u1, u2 = emb["UNREL-X"], emb["UNREL-Y"]
        cos_unrel_before = _cos(u1, u2)
        cos_unrel_after = _cos(_apply(W, u1), _apply(W, u2))

        drop_flagged = cos_flagged_before - cos_flagged_after
        drop_unrel = cos_unrel_before - cos_unrel_after

        # The flagged pair started highly correlated and must drop meaningfully.
        self.assertGreater(cos_flagged_before, 0.95)
        self.assertGreater(drop_flagged, 0.0)
        # And it must drop MORE than the unrelated pair (the decorrelation claim).
        self.assertGreater(drop_flagged, drop_unrel)

    def test_apply_reduces_flagged_cosine_strictly(self):
        nodes, pairs = _synthetic_corpus()
        artifact = fe.fit_artifact(nodes, pairs, alpha=0.7, energy=0.9, max_rank=64)
        W = np.asarray(artifact["W"], dtype=np.float64)
        emb = {n["record_id"]: n[fe.EMBEDDING_PROPERTY] for n in nodes}
        for a, b in (("DUP-A1", "DUP-A2"), ("DUP-B1", "DUP-B2")):
            before = _cos(emb[a], emb[b])
            after = _cos(_apply(W, emb[a]), _apply(W, emb[b]))
            self.assertLess(after, before)


class ArtifactContractTest(unittest.TestCase):
    def test_artifact_roundtrips_and_matches_contract(self):
        nodes, pairs = _synthetic_corpus()
        artifact = fe.fit_artifact(
            nodes, pairs, alpha=0.7, energy=0.9, max_rank=64,
            pairs_source="synthetic.jsonl", generated_at="2026-06-23T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "transform.json")
            written = fe.write_transform(artifact, out)
            self.assertEqual(written, out)
            with open(out, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)

        # Top-level contract keys + types.
        self.assertEqual(
            set(loaded.keys()),
            {"version", "dim", "alpha", "rank", "W", "fit_meta",
             "pairs_source", "generated_at"},
        )
        self.assertEqual(loaded["version"], "h92.v1")
        self.assertEqual(loaded["dim"], DIM)
        self.assertIsInstance(loaded["alpha"], float)
        self.assertEqual(loaded["alpha"], 0.7)
        self.assertIsInstance(loaded["rank"], int)
        self.assertGreaterEqual(loaded["rank"], 1)
        self.assertEqual(loaded["pairs_source"], "synthetic.jsonl")
        self.assertEqual(loaded["generated_at"], "2026-06-23T00:00:00Z")

        # W is dim x dim of finite floats.
        W = loaded["W"]
        self.assertIsInstance(W, list)
        self.assertEqual(len(W), DIM)
        for row in W:
            self.assertIsInstance(row, list)
            self.assertEqual(len(row), DIM)
            for x in row:
                self.assertIsInstance(x, float)
                self.assertTrue(math.isfinite(x))

        # fit_meta contract keys + types.
        fm = loaded["fit_meta"]
        self.assertEqual(
            set(fm.keys()),
            {"corpus_size", "correlated_set_size", "num_pairs",
             "energy_captured", "top_singular_values"},
        )
        self.assertEqual(fm["corpus_size"], len(nodes))
        self.assertEqual(fm["correlated_set_size"], 4)
        self.assertEqual(fm["num_pairs"], len(pairs))
        self.assertIsInstance(fm["energy_captured"], float)
        self.assertIsInstance(fm["top_singular_values"], list)
        self.assertGreaterEqual(len(fm["top_singular_values"]), 1)

    def test_generated_at_defaults_none(self):
        nodes, pairs = _synthetic_corpus()
        artifact = fe.fit_artifact(nodes, pairs)
        self.assertIsNone(artifact["generated_at"])

    def test_corpus_coercion_accepts_dict_and_list(self):
        n = _node("A", [1.0] + [0.0] * (DIM - 1))
        self.assertEqual(fe._coerce_nodes({"nodes": [n]}), [n])
        self.assertEqual(fe._coerce_nodes([n]), [n])
        self.assertEqual(fe._coerce_nodes([n, "junk", 5]), [n])
        self.assertEqual(fe._coerce_nodes(None), [])

    def test_invalid_alpha_and_energy_raise(self):
        nodes, pairs = _synthetic_corpus()
        with self.assertRaises(ValueError):
            fe.fit_artifact(nodes, pairs, alpha=1.5)
        with self.assertRaises(ValueError):
            fe.fit_artifact(nodes, pairs, energy=0.0)


class FileIOTest(unittest.TestCase):
    def test_load_corpus_and_pairs_from_disk(self):
        nodes, pairs = _synthetic_corpus()
        with tempfile.TemporaryDirectory() as td:
            corpus_path = Path(td) / "corpus.json"
            pairs_path = Path(td) / "pairs.jsonl"
            corpus_path.write_text(json.dumps({"nodes": nodes}), encoding="utf-8")
            pairs_path.write_text(
                "".join(json.dumps(p) + "\n" for p in pairs) + "\n",  # trailing blank line
                encoding="utf-8",
            )
            loaded_nodes = fe.load_corpus_from_file(str(corpus_path))
            loaded_pairs = fe.load_pairs_from_file(str(pairs_path))

        self.assertEqual(len(loaded_nodes), len(nodes))
        self.assertEqual(len(loaded_pairs), len(pairs))
        self.assertEqual(loaded_pairs[0]["a"], "DUP-A1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
