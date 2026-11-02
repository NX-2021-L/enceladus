"""ENC-TSK-R80-0J (U4): lambda2 sampler must sample the giant component.

Regression for the 2026-10-27 outage: the default selection took the
alphabetically-first record_ids, so one zero-degree stub in the slice made the
induced subgraph disconnected and lambda2 identically 0 (discarded by the
ENC-ISS-554 guard => 0 publishes). Uses a mocked driver (no live Aura).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import graph_health_metric as ghm  # noqa: E402
import lambda_function as lf  # noqa: E402


class _Session:
    def __init__(self, adj, edges):
        self.adj, self.edges = adj, edges

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        if "AS seed" in cypher:
            best = max(
                ((len(v), -i, k) for i, (k, v) in enumerate(sorted(self.adj.items())) if v),
                default=None,
            )
            return [{"seed": best[2], "d": best[0]}] if best else []
        if "AS nbr" in cypher:
            out = set()
            for a in params["frontier"]:
                out.update(self.adj.get(a, ()))
            return [{"nbr": b} for b in sorted(out)]
        if "AS rid" in cypher:
            ids = sorted(self.adj)
            if "ids" in params:
                ids = [i for i in ids if i in set(params["ids"])]
            if "(n)-[]-()" in cypher:
                ids = [i for i in ids if self.adj[i]]
            return [{"rid": i} for i in ids[: params["limit"]]]
        if "AS s, b.record_id AS t" in cypher:
            ids = set(params["ids"])
            return [{"s": s, "t": t} for s, t in self.edges if s in ids and t in ids]
        return []


class _Driver:
    def __init__(self, edges, isolated=()):
        self.edges = edges
        self.adj = {}
        for s, t in edges:
            self.adj.setdefault(s, set()).add(t)
            self.adj.setdefault(t, set()).add(s)
        for v in isolated:
            self.adj.setdefault(v, set())

    def session(self):
        return _Session(self.adj, self.edges)


def _ring(prefix, n):
    return [(f"{prefix}{i:03d}", f"{prefix}{(i + 1) % n:03d}") for i in range(n)]


class GiantComponentSamplerTest(unittest.TestCase):
    def test_zero_degree_stub_does_not_zero_lambda2(self):
        # "AAA-STUB" sorts first and has no edges: the old sampler picked it up.
        driver = _Driver(_ring("N", 12) + _ring("Z", 4), isolated=["AAA-STUB"])
        sel = lf._laplacian_select_vertices(driver, "enceladus", {"limit": 500})
        self.assertNotIn("AAA-STUB", sel["ids"])
        self.assertEqual(sel["sampling"], "giant_component_bfs")
        self.assertEqual(sel["component_size"], 12)  # giant ring, not the 4-ring
        self.assertEqual(sel["component_coverage"], 1.0)
        res = ghm.compute_fiedler_value(driver, "enceladus", query_laplacian_fn=lf._query_laplacian)
        self.assertTrue(res["ok"], res)
        self.assertGreater(res["lambda2"], 1e-3)
        self.assertEqual(res["component_coverage"], 1.0)

    def test_capped_sample_is_connected_and_reports_partial_coverage(self):
        # 40-vertex ring capped at 10: BFS prefix must stay connected.
        driver = _Driver(_ring("R", 40), isolated=["AAA-STUB"])
        sel = lf._laplacian_select_vertices(driver, "enceladus", {"limit": 10})
        self.assertEqual(len(sel["ids"]), 10)
        self.assertEqual(sel["component_size"], 40)
        self.assertAlmostEqual(sel["component_coverage"], 0.25)
        res = ghm.compute_fiedler_value(driver, "enceladus", limit=10, query_laplacian_fn=lf._query_laplacian)
        self.assertTrue(res["ok"], res)
        self.assertGreater(res["lambda2"], 1e-9)
        self.assertAlmostEqual(res["component_coverage"], 0.25)

    def test_no_seed_falls_back_to_degree_filtered_ids(self):
        driver = _Driver([], isolated=["A", "B"])
        sel = lf._laplacian_select_vertices(driver, "enceladus", {"limit": 10})
        self.assertEqual(sel["ids"], [])
        self.assertEqual(sel["sampling"], "explicit_or_filtered")
        self.assertNotIn("component_coverage", sel)

    def test_explicit_ids_unchanged(self):
        driver = _Driver(_ring("N", 6))
        sel = lf._laplacian_select_vertices(driver, "enceladus", {"record_ids": "N000,N001"})
        self.assertEqual(sel["ids"], ["N000", "N001"])


if __name__ == "__main__":
    unittest.main()
