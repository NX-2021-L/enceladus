"""Unit tests for the GHN energy-descent update rule (ENC-TSK-I99 / FTR-104 Ph2 AC-3).

Exercises the pure math of benchmarks/ghn.py — no Neo4j / Bedrock / dataset:
  * softmax correctness + numerical stability.
  * psd_shift produces a PSD matrix (Gershgorin) with the right tau.
  * the CCCP energy-descent guarantee: E_GHN is MONOTONE NON-INCREASING across
    iterations (the core AC-3 property), on random instances.
  * convergence to a stationary distribution on the simplex.
  * graph coupling actually propagates activation to a graph-adjacent candidate
    (the multi-hop mechanism) vs the uncoupled (lambda_graph=0) baseline.
  * lambda_graph=0 reduces the ranking to the static Ph1 field ordering.
  * determinism / tie-break by the static field.
  * the GHN field is sourced from energy_function.compute_retrieval_energy so the
    two FTR-104 phases share one energy definition.
"""

from __future__ import annotations

import math
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks import ghn  # noqa: E402
import energy_function as ef  # noqa: E402


def _is_distribution(x, tol=1e-9):
    return abs(sum(x) - 1.0) < tol and all(v >= -tol for v in x)


class TestSoftmax(unittest.TestCase):
    def test_uniform_when_equal(self):
        out = ghn.softmax([2.0, 2.0, 2.0])
        for v in out:
            self.assertAlmostEqual(v, 1.0 / 3.0)

    def test_stable_with_large_values(self):
        out = ghn.softmax([1000.0, 1000.0])
        self.assertTrue(_is_distribution(out))
        self.assertAlmostEqual(out[0], 0.5)

    def test_monotone_in_logit(self):
        out = ghn.softmax([1.0, 2.0, 3.0])
        self.assertLess(out[0], out[1])
        self.assertLess(out[1], out[2])

    def test_empty(self):
        self.assertEqual(ghn.softmax([]), [])


class TestPSDShift(unittest.TestCase):
    def test_tau_is_max_row_sum(self):
        w = [[0.0, 0.9, 0.0],
             [0.9, 0.0, 0.6],
             [0.0, 0.6, 0.0]]
        w_psd, tau = ghn.psd_shift(w)
        self.assertAlmostEqual(tau, 1.5)  # row 1: 0.9 + 0.6
        # Diagonal lifted by tau, off-diagonal unchanged.
        self.assertAlmostEqual(w_psd[0][0], 1.5)
        self.assertAlmostEqual(w_psd[0][1], 0.9)

    def test_shifted_matrix_is_psd(self):
        rng = random.Random(7)
        n = 6
        w = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                if rng.random() < 0.5:
                    val = rng.uniform(0.1, 1.0)
                    w[i][j] = w[j][i] = val
        w_psd, tau = ghn.psd_shift(w)
        # PSD <=> x^T W_psd x >= 0 for random probe vectors.
        for _ in range(200):
            x = [rng.uniform(-1, 1) for _ in range(n)]
            quad = sum(x[i] * w_psd[i][j] * x[j] for i in range(n) for j in range(n))
            self.assertGreaterEqual(quad, -1e-9)

    def test_empty(self):
        w_psd, tau = ghn.psd_shift([])
        self.assertEqual(w_psd, [])
        self.assertEqual(tau, 0.0)


class TestEnergyDescent(unittest.TestCase):
    """The core AC-3 guarantee: monotone energy descent."""

    def _random_instance(self, rng, n):
        h = [rng.uniform(-1.0, 0.0) for _ in range(n)]  # fields are -E, so <= 0
        w = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                if rng.random() < 0.4:
                    val = rng.uniform(0.3, 1.0)
                    w[i][j] = w[j][i] = val
        return h, w

    def test_energy_monotone_non_increasing(self):
        rng = random.Random(101)
        for trial in range(40):
            n = rng.randint(3, 20)
            h, w = self._random_instance(rng, n)
            beta = rng.choice([1.0, 2.0, 4.0, 8.0])
            lam = rng.choice([0.25, 0.5, 1.0])
            res = ghn.ghn_descent(h, w, beta=beta, lambda_graph=lam, max_iters=60)
            trace = res.energy_trace
            for a, b in zip(trace, trace[1:]):
                # CCCP guarantee, with a tiny tolerance for float roundoff.
                self.assertLessEqual(b, a + 1e-9,
                                     msg=f"energy rose trial={trial} n={n} beta={beta} lam={lam}")

    def test_activation_stays_on_simplex(self):
        rng = random.Random(202)
        h, w = self._random_instance(rng, 12)
        res = ghn.ghn_descent(h, w, beta=4.0, lambda_graph=0.5, max_iters=60)
        self.assertTrue(_is_distribution(res.activation))

    def test_converges(self):
        rng = random.Random(303)
        h, w = self._random_instance(rng, 10)
        res = ghn.ghn_descent(h, w, beta=4.0, lambda_graph=0.5, max_iters=200, tol=1e-10)
        self.assertTrue(res.converged)

    def test_zero_coupling_matches_field_softmax(self):
        """lambda_graph=0 => activation is exactly softmax(beta*h) (no coupling)."""
        h = [-0.1, -0.5, -0.9, -0.2]
        w = [[0.0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(i + 1, 4):
                w[i][j] = w[j][i] = 0.7  # dense, but lambda_graph=0 nullifies it
        res = ghn.ghn_descent(h, w, beta=5.0, lambda_graph=0.0, max_iters=50)
        expected = ghn.softmax([5.0 * v for v in h])
        for a, b in zip(res.activation, expected):
            self.assertAlmostEqual(a, b, places=6)


class TestCouplingPropagation(unittest.TestCase):
    def test_coupling_boosts_adjacent_weak_candidate(self):
        """The multi-hop mechanism: a weak-field candidate adjacent to a strong-
        field candidate gains activation once graph coupling is switched on."""
        # 3 candidates: 0 strong field, 1 weak field but adjacent to 0, 2 weak & isolated.
        h = [-0.05, -0.8, -0.8]
        w = [[0.0, 1.0, 0.0],
             [1.0, 0.0, 0.0],
             [0.0, 0.0, 0.0]]
        no_coupling = ghn.ghn_descent(h, w, beta=6.0, lambda_graph=0.0, max_iters=80).activation
        with_coupling = ghn.ghn_descent(h, w, beta=6.0, lambda_graph=1.0, max_iters=80).activation
        # Candidate 1 (adjacent to the strong 0) must gain relative to the
        # isolated candidate 2 once coupling is on; without coupling they are equal.
        self.assertAlmostEqual(no_coupling[1], no_coupling[2], places=6)
        self.assertGreater(with_coupling[1], with_coupling[2])

    def test_rank_candidates_tie_break_uses_field(self):
        """Isolated near-zero-activation tail candidates are ordered by static field h."""
        # No edges => all activation from field; candidate with higher h ranks above.
        rids = ["A", "B", "C"]
        h = [-0.9, -0.1, -0.5]  # B best field, then C, then A
        w = [[0.0] * 3 for _ in range(3)]
        ranked, _ = ghn.rank_candidates(rids, h, w, beta=8.0, lambda_graph=0.5)
        order = [r["record_id"] for r in ranked]
        self.assertEqual(order, ["B", "C", "A"])

    def test_deterministic(self):
        rids = ["R1", "R2", "R3", "R4"]
        h = [-0.2, -0.3, -0.25, -0.9]
        w = [[0.0, 0.8, 0.0, 0.0],
             [0.8, 0.0, 0.5, 0.0],
             [0.0, 0.5, 0.0, 0.0],
             [0.0, 0.0, 0.0, 0.0]]
        a, _ = ghn.rank_candidates(rids, h, w, beta=7.0, lambda_graph=0.5)
        b, _ = ghn.rank_candidates(rids, h, w, beta=7.0, lambda_graph=0.5)
        self.assertEqual([x["record_id"] for x in a], [x["record_id"] for x in b])


class TestFieldSourcedFromPh1Energy(unittest.TestCase):
    def test_field_is_negated_ph1_energy(self):
        """The GHN field must be h = -E_Ph1, using the shared FTR-104 Ph1 energy
        (energy_function.compute_retrieval_energy) — one energy definition across
        both phases."""
        e = ef.compute_retrieval_energy(
            vector_score=0.9, graph_score=8.0, keyword_score=3.0,
            max_graph_score=10.0, max_keyword_score=3.0,
            graph_algorithm=ef.GDS_PAGERANK_SOURCE,
            lambda_graph=0.5, lambda_kw=0.25,
        )
        h_i = -e["retrieval_energy"]
        # E_vector=0.1, E_PPR=0.2, E_keyword=0.0 => E = 0.1 + 0.5*0.2 + 0.25*0 = 0.2
        self.assertAlmostEqual(e["retrieval_energy"], 0.2, places=6)
        self.assertAlmostEqual(h_i, -0.2, places=6)
        self.assertTrue(e["ppr_source_is_gds_pagerank"])


if __name__ == "__main__":
    unittest.main()
