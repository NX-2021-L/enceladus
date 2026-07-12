"""Unit tests for comp-percolation-monitor pure-math core (ENC-TSK-I88).

Network-free: exercises the degree statistics, Monte Carlo site-percolation
sweep, and second-derivative empirical-p_c detection against a deterministic
synthetic graph. No AWS or graph_query_api calls.

ENC-TSK-I91 (ENC-FTR-105 AC-7) adds tests for _fetch_graph's
spurious_attractor_rate pass-through (monkeypatching the internal
_graphsearch call rather than making a real HTTP request, same network-free
convention as the rest of this file).
"""

import os
import random
import unittest
from unittest import mock

os.environ.setdefault("GRAPH_QUERY_API_BASE", "https://example.invalid/api/v1/tracker/graphsearch")

import lambda_function as pm


def _ring_lattice(n, k):
    """k-regular ring lattice: each node joined to its k nearest neighbors."""
    edges = []
    half = k // 2
    for i in range(n):
        for j in range(1, half + 1):
            a, b = str(i), str((i + j) % n)
            lo, hi = min(a, b), max(a, b)
            edges.append((lo, hi))
    # dedupe
    return sorted(set(edges))


class DegreeStatsTest(unittest.TestCase):
    def test_regular_graph_degree_stats(self):
        # 4-regular ring: every degree is exactly 4, so <k>=4, <k^2>=16.
        n = 50
        edges = _ring_lattice(n, 4)
        stats = pm._degree_stats(n, edges)
        self.assertAlmostEqual(stats["mean_degree"], 4.0, places=6)
        self.assertAlmostEqual(stats["mean_degree_sq"], 16.0, places=6)
        # Molloy-Reed form used by AC-2: p_c = <k>/<k^2> = 4/16 = 0.25.
        self.assertAlmostEqual(stats["analytical_pc"], 0.25, places=6)
        self.assertTrue(0.01 <= stats["analytical_pc"] <= 0.99)

    def test_isolated_nodes_lower_mean_degree(self):
        # 10 connected (a triangle-ish chain) + 90 isolated nodes.
        edges = [("0", "1"), ("1", "2"), ("2", "3")]
        stats = pm._degree_stats(100, edges)
        # sum_k = 6 over 100 nodes => 0.06
        self.assertAlmostEqual(stats["mean_degree"], 0.06, places=6)

    def test_empty_graph(self):
        stats = pm._degree_stats(0, [])
        self.assertEqual(stats["analytical_pc"], 0.0)


class MonteCarloTest(unittest.TestCase):
    def test_lcc_ratio_monotone_nondecreasing_in_p(self):
        n = 200
        edges = _ring_lattice(n, 6)
        universe = sorted({v for e in edges for v in e})
        p_grid = pm._linspace(0.02, 0.95, 30)
        ratios = pm._monte_carlo_sweep(universe, edges, n, p_grid, trials=20, seed=7)
        self.assertEqual(len(ratios), 30)
        # Site percolation LCC ratio is ~monotone in p; allow small MC noise.
        for lo, hi in zip(ratios, ratios[1:]):
            self.assertLessEqual(lo, hi + 0.06)
        self.assertLess(ratios[0], 0.2)
        self.assertGreater(ratios[-1], 0.6)

    def test_empirical_pc_in_range(self):
        n = 200
        edges = _ring_lattice(n, 6)
        universe = sorted({v for e in edges for v in e})
        p_grid = pm._linspace(0.02, 0.60, 30)
        ratios = pm._monte_carlo_sweep(universe, edges, n, p_grid, trials=25, seed=11)
        pc = pm._empirical_pc(p_grid, ratios)
        self.assertGreaterEqual(pc, p_grid[0])
        self.assertLessEqual(pc, p_grid[-1])

    def test_empirical_pc_detects_sharp_onset(self):
        # Synthetic LCC curve: flat, sharp jump at index 10, then flat.
        p_grid = pm._linspace(0.0, 1.0, 21)
        ratios = [0.01] * 10 + [0.01, 0.5] + [0.9] * 9
        pc = pm._empirical_pc(p_grid, ratios)
        # Max positive curvature is at the foot of the jump (index 10).
        self.assertAlmostEqual(pc, p_grid[10], places=6)


class UnionFindTest(unittest.TestCase):
    def test_single_component(self):
        edges = [("a", "b"), ("b", "c"), ("c", "d")]
        ratio = pm._largest_component_ratio(edges, {"a", "b", "c", "d"}, 4, random.Random(0))
        self.assertAlmostEqual(ratio, 1.0, places=6)

    def test_fragmented(self):
        edges = [("a", "b"), ("c", "d")]
        ratio = pm._largest_component_ratio(edges, {"a", "b", "c", "d"}, 4, random.Random(0))
        self.assertAlmostEqual(ratio, 0.5, places=6)


class FetchGraphSpuriousAttractorRateTest(unittest.TestCase):
    """ENC-TSK-I91 (ENC-FTR-105 AC-7): spurious_attractor_rate pass-through
    from the adjacency endpoint's first page into _fetch_graph's return value."""

    def _single_page_body(self, extra=None):
        body = {
            "node_count": 2,
            "edge_count": 1,
            "edges": [{"s": "A", "t": "B"}],
            "has_more": False,
        }
        if extra:
            body.update(extra)
        return body

    def test_rate_passed_through_when_present(self):
        with mock.patch.object(pm, "_graphsearch", return_value=self._single_page_body(
            {"spurious_attractor_rate": 0.37}
        )):
            node_count, edges, rate, _entropy = pm._fetch_graph()
        self.assertEqual(node_count, 2)
        self.assertEqual(edges, [("A", "B")])
        self.assertAlmostEqual(rate, 0.37)

    def test_rate_is_none_when_key_absent(self):
        """Backward compatibility: an older graph_query_api deploy that
        predates ENC-TSK-I91 simply omits the key."""
        with mock.patch.object(pm, "_graphsearch", return_value=self._single_page_body()):
            _node_count, _edges, rate, _entropy = pm._fetch_graph()
        self.assertIsNone(rate)

    def test_rate_is_none_when_explicitly_null(self):
        with mock.patch.object(pm, "_graphsearch", return_value=self._single_page_body(
            {"spurious_attractor_rate": None}
        )):
            _node_count, _edges, rate, _entropy = pm._fetch_graph()
        self.assertIsNone(rate)

    def test_rate_taken_from_first_page_only(self):
        first = self._single_page_body({"spurious_attractor_rate": 0.6, "has_more": True, "next_offset": 1})
        second = {
            "node_count": 0,  # later pages don't repeat node_count/rate
            "edges": [{"s": "B", "t": "C"}],
            "has_more": False,
        }
        with mock.patch.object(pm, "_graphsearch", side_effect=[first, second]):
            node_count, edges, rate, _entropy = pm._fetch_graph()
        self.assertEqual(node_count, 2)
        self.assertEqual(edges, [("A", "B"), ("B", "C")])
        self.assertAlmostEqual(rate, 0.6)


class RhythmStanzaTests(unittest.TestCase):
    """ENC-TSK-N24: heavy-beat completion-stanza contract (tenant_invoker.py)."""

    def test_no_result_key_is_noop(self):
        from unittest import mock

        with mock.patch.object(pm.boto3, "client") as client:
            self.assertFalse(pm._write_rhythm_stanza({}, "completed", {}))
            client.assert_not_called()

    def test_result_key_writes_contract_stanza(self):
        import json
        from unittest import mock

        key = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20260712-000000/percolation_monitor.json"
        with mock.patch.object(pm.boto3, "client") as client:
            ok = pm._write_rhythm_stanza({"result_key": key}, "completed", {"analytical_pc": 0.31})
        self.assertTrue(ok)
        kwargs = client.return_value.put_object.call_args.kwargs
        self.assertEqual(kwargs["Bucket"], pm.RHYTHM_RESULTS_BUCKET)
        self.assertEqual(kwargs["Key"], key)
        stanza = json.loads(kwargs["Body"].decode("utf-8"))
        self.assertEqual(stanza["tenant"], "percolation_monitor")
        self.assertEqual(stanza["status"], "completed")
        self.assertIn("completed_at", stanza)
        self.assertEqual(stanza["detail"], {"analytical_pc": 0.31})

    def test_stanza_write_failure_never_raises(self):
        from unittest import mock

        with mock.patch.object(pm.boto3, "client", side_effect=RuntimeError("boom")):
            self.assertFalse(pm._write_rhythm_stanza({"result_key": "k"}, "failed", {}))


if __name__ == "__main__":
    unittest.main()
