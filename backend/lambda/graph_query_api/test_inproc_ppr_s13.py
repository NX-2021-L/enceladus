"""ENC-TSK-S13 (PLN-103 W2.1 / N12 + N3): in-process push-PPR, projection cache,
GRAPH_SIGNAL_MODE selection and the Cypher-fallback hub hop bound."""

from __future__ import annotations

import os
import random
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import inproc_ppr as ip  # noqa: E402
import lambda_function as lf  # noqa: E402

W = {"IMPLEMENTS": 1.0, "RELATED_TO": 0.75, "CHILD_OF": 0.6}


def _toy_edges(n=60, m=220, seed=7):
    rng = random.Random(seed)
    types = list(W)
    rows = []
    for i in range(1, n):  # spanning chain keeps it connected
        rows.append((f"N{i}", f"N{rng.randrange(0, i)}", rng.choice(types), None))
    while len(rows) < m:
        a, b = rng.randrange(n), rng.randrange(n)
        if a != b:
            rows.append((f"N{a}", f"N{b}", rng.choice(types), rng.choice([None, 0.5, 1.0, 2.0])))
    return rows


class _Session:
    def __init__(self, rows, boom=False):
        self.rows, self.boom = rows, boom

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        if self.boom:
            raise RuntimeError("bolt down")
        return [{"src": s, "dst": d, "t": t, "fw": f} for s, d, t, f in self.rows]


class _Driver:
    def __init__(self, rows, boom=False):
        self.rows, self.boom, self.sessions = rows, boom, 0

    def session(self):
        self.sessions += 1
        return _Session(self.rows, self.boom)


class PushMatchesExact(unittest.TestCase):
    def _compare(self, proj, anchor, epsilon):
        exact = ip.exact_ppr(proj, [anchor])
        exact.pop(anchor)
        top = sorted(exact.items(), key=lambda kv: -kv[1])[:20]
        res = ip.push_ppr(proj, [anchor], 60, epsilon=epsilon)
        got = {r["record_id"]: r["score"] for r in res}
        l1 = sum(abs(got.get(k, 0.0) - v) for k, v in top)
        overlap = len({k for k, _ in top} & {r["record_id"] for r in res[:20]}) / 20.0
        return l1, overlap

    def test_push_ppr_matches_power_iteration_top20(self):
        # Push error is bounded by epsilon * volume, so exactness is asserted at a
        # tight epsilon on this tiny dense graph (vol ~ 1e3 would blow the 1e-3
        # bound at the production 1e-4); production epsilon is checked on ranking.
        proj = ip.build_projection(_toy_edges(), W, 0.4)
        vol = sum(proj.wdeg)
        for anchor in ("N0", "N17", "N42"):
            l1, _ = self._compare(proj, anchor, 1e-7)
            self.assertLess(l1, 1e-3, f"{anchor}: L1={l1}")
            l1_prod, overlap = self._compare(proj, anchor, ip.PPR_EPSILON_DEFAULT)
            self.assertLessEqual(l1_prod, ip.PPR_EPSILON_DEFAULT * vol)
            self.assertGreaterEqual(overlap, 0.85, f"{anchor}: top-20 overlap {overlap}")

    def test_anchor_excluded_and_unknown_anchor_empty(self):
        proj = ip.build_projection(_toy_edges(), W, 0.4)
        self.assertNotIn("N3", [r["record_id"] for r in ip.push_ppr(proj, ["N3"], 20)])
        self.assertEqual(ip.push_ppr(proj, ["NOPE"], 20), [])

    def test_edge_weight_is_type_times_flow_and_walk_is_undirected(self):
        proj = ip.build_projection([("A", "B", "IMPLEMENTS", 2.0), ("C", "A", "CHILD_OF", None)], W, 0.4)
        a = proj.index["A"]
        self.assertAlmostEqual(proj.wdeg[a], 2.0 + 0.6)
        self.assertEqual({r["record_id"] for r in ip.push_ppr(proj, ["B"], 5)}, {"A", "C"})


class CacheBehaviour(unittest.TestCase):
    def setUp(self):
        ip.reset_cache()

    def _get(self, drv, pid="enceladus"):
        return ip.get_projection(drv, pid, W, 0.4, "flow_weight")

    def test_load_once_then_hit_and_stats(self):
        drv = _Driver(_toy_edges())
        p1, p2 = self._get(drv), self._get(drv)
        self.assertIs(p1, p2)
        self.assertEqual(drv.sessions, 1)
        st = ip.cache_stats()
        self.assertEqual((st["nodes"], st["edges"]), (p1.n_nodes, p1.n_edges))
        self.assertGreater(st["approx_bytes"], 0)
        self.assertIsNotNone(st["loaded_at"])

    def test_ttl_expiry_reloads(self):
        drv = _Driver(_toy_edges())
        self._get(drv)
        with mock.patch.dict(os.environ, {"PPR_CACHE_TTL_S": "0"}):
            self._get(drv)
        self.assertEqual(drv.sessions, 2)

    def test_empty_cache_and_failed_or_empty_load_returns_none(self):
        self.assertIsNone(self._get(_Driver([], boom=False)))
        self.assertIsNone(self._get(_Driver(_toy_edges(), boom=True)))
        self.assertEqual(ip.cache_stats()["nodes"], 0)

    def test_failed_refresh_serves_stale(self):
        good = self._get(_Driver(_toy_edges()))
        with mock.patch.dict(os.environ, {"PPR_CACHE_TTL_S": "0"}):
            self.assertIs(self._get(_Driver(_toy_edges(), boom=True)), good)

    def test_empty_cache_falls_back_to_cypher_in_lambda(self):
        with mock.patch.object(lf.inproc_ppr, "get_projection", return_value=None):
            self.assertEqual(lf._hybrid_graph_ranks_inproc(mock.MagicMock(), "enceladus", "N1", 25), [])


class ModeSelection(unittest.TestCase):
    def _mode(self, env, params=None):
        with mock.patch.dict(os.environ, env, clear=False):
            for k in ("GRAPH_SIGNAL_MODE", "AWS_LAMBDA_FUNCTION_NAME"):
                if k not in env:
                    os.environ.pop(k, None)
            return lf._resolve_graph_signal_mode(params)

    def test_default_by_environment(self):
        self.assertEqual(self._mode({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api-gamma"}), "inproc_ppr")
        self.assertEqual(self._mode({"AWS_LAMBDA_FUNCTION_NAME": "devops-graph-query-api"}), "cypher_fallback")
        self.assertEqual(self._mode({}), "cypher_fallback")

    def test_env_override_wins(self):
        self.assertEqual(self._mode({"GRAPH_SIGNAL_MODE": "cypher_fallback",
                                     "AWS_LAMBDA_FUNCTION_NAME": "x-gamma"}), "cypher_fallback")
        self.assertEqual(self._mode({"GRAPH_SIGNAL_MODE": "inproc_ppr"}), "inproc_ppr")
        self.assertEqual(self._mode({"GRAPH_SIGNAL_MODE": "bogus"}), "cypher_fallback")

    def test_request_override(self):
        self.assertEqual(self._mode({}, {"graph_signal_mode": "inproc_ppr"}), "inproc_ppr")
        self.assertEqual(self._mode({"AWS_LAMBDA_FUNCTION_NAME": "x-gamma"},
                                    {"graph_signal_mode": "cypher_fallback"}), "cypher_fallback")

    def test_override_gate_strips_for_external_callers(self):
        src = Path(lf.__file__).read_text()
        gate = src[src.index('if "graph_signal_mode" in qs:'):]
        gate = gate[:gate.index("handler_fn = ") if "handler_fn = " in gate[:600] else 600]
        self.assertIn('caller_type"] in ("internal", "agent")', gate)
        self.assertIn('qs.pop("graph_signal_mode", None)', gate)


class _FakeDriver:
    def __init__(self, degree):
        self.degree, self.queries = degree, []

    def session(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        self.queries.append(cypher)
        outer = self

        class _R(list):
            def single(self_inner):
                return {"degree": outer.degree}
        return _R([]) if "count(r)" in cypher else _R()


class HubHopBound(unittest.TestCase):
    def _walk(self, degree):
        drv, info = _FakeDriver(degree), {}
        lf._hybrid_graph_ranks_cypher_fallback(drv, "enceladus", "A", 5, hop_info=info)
        return drv.queries[-1], info

    def test_hub_walks_two_hops(self):
        q, info = self._walk(lf.HUB_DEGREE_THRESHOLD + 1)
        self.assertIn("*1..2]", q)
        self.assertEqual(info["hop_bound"], 2)

    def test_leaf_and_threshold_walk_three_hops(self):
        for deg in (3, lf.HUB_DEGREE_THRESHOLD):
            q, info = self._walk(deg)
            self.assertIn("*1..3]", q)
            self.assertEqual(info["hop_bound"], 3)

    def test_precheck_failure_is_non_hub(self):
        drv = mock.MagicMock()
        drv.session.return_value.__enter__.return_value.run.side_effect = RuntimeError("x")
        info = {}
        lf._hybrid_graph_ranks_cypher_fallback(drv, "enceladus", "A", 5, hop_info=info)
        self.assertEqual(info["hop_bound"], 3)


if __name__ == "__main__":
    unittest.main()
