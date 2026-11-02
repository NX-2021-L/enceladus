"""ENC-TSK-S09 (PLN-103 W1.2 / N13): vector, graph and keyword signals run
concurrently inside `_query_hybrid`; telemetry contract and degradation unchanged."""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corroboration  # noqa: E402
import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402

PARAMS = {"query": "latency", "anchor_record_id": "ENC-TSK-001", "record_type": "task"}
_NODES = {
    rid: {"record_id": rid, "_labels": ["Task"], "project_id": "enceladus",
          "record_type": "task", "status": "open", "priority": "P1"}
    for rid in ("ENC-TSK-001", "ENC-TSK-002", "ENC-TSK-003")
}


def _slow(delay, value):
    def _fn(*a, **k):
        time.sleep(delay)
        return value
    return _fn


def _start(tc, vector=0.3, graph=0.3, keyword=0.3):
    thread_ids = tc.thread_ids = set()

    def _vec(*a, **k):
        thread_ids.add(threading.get_ident())
        time.sleep(vector)
        return [{"record_id": "ENC-TSK-001", "score": 0.9, "rank": 1}]

    patchers = [
        mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
        mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1, 0.2]),
        mock.patch.object(lf, "_hybrid_vector_ranks", side_effect=_vec),
        mock.patch.object(lf, "_hybrid_graph_ranks_gds_warm", return_value=[]),
        mock.patch.object(lf, "_check_gds_available", return_value=False),
        mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback", side_effect=_slow(
            graph, [{"record_id": "ENC-TSK-002", "score": 3.0, "rank": 1}])),
        mock.patch.object(lf, "_hybrid_keyword_ranks", side_effect=_slow(
            keyword, [{"record_id": "ENC-TSK-003", "score": 2.0, "rank": 1}])),
        mock.patch.object(lf.opensearch_keyword, "hybrid_keyword_ranks",
                          return_value=([], {}, "down")),
        mock.patch.object(lf, "_fetch_nodes_by_record_ids", return_value=dict(_NODES)),
        mock.patch.object(lf, "_reconstruct_pathway_edges", side_effect=lambda *a, **k: (
            lf._hybrid_telemetry_set(pathway_status="ok") or ([], [], []))),
        mock.patch.object(lf, "_emit_pathway_telemetry"),
        mock.patch.object(lf, "_maybe_emit_stigmergic_trace"),
        mock.patch.object(ef, "load_lambda_weights", return_value=(1.0, 0.1)),
        mock.patch.object(corroboration, "load_alpha", return_value=0.02),
    ]
    for p in patchers:
        p.start()
        tc.addCleanup(p.stop)


class TestSignalConcurrency(unittest.TestCase):
    def test_three_signals_overlap(self):
        _start(self)
        t0 = time.perf_counter()
        result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        wall = time.perf_counter() - t0
        self.assertLess(wall, 0.6, "signals must overlap (serial would be ~0.9s)")
        self.assertNotIn(threading.get_ident(), self.thread_ids)  # ran in a worker
        self.assertEqual(result["signal_availability"],
                         {"vector": True, "graph": True, "keyword": True})
        self.assertEqual({n["record_id"] for n in result["nodes"]},
                         {"ENC-TSK-001", "ENC-TSK-002", "ENC-TSK-003"})
        self.assertEqual(result["graph_algorithm"], "cypher_fallback")

    def test_telemetry_fields_per_signal(self):
        _start(self)
        t0 = time.perf_counter()
        result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        duration_ms = int((time.perf_counter() - t0) * 1000)
        audit = lf._graphsearch_audit_record({}, dict(PARAMS), "hybrid", "enceladus",
                                             result, duration_ms)
        for k in ("vector_ms", "graph_ms", "keyword_ms"):
            self.assertIsInstance(audit[k], int)
            self.assertGreaterEqual(audit[k], 250, k)
        self.assertEqual(audit["graph_candidates"], 1)
        self.assertEqual(audit["keyword_candidates"], 1)
        self.assertEqual(audit["graph_algorithm"], "cypher_fallback")
        self.assertLess(duration_ms, audit["vector_ms"] + audit["graph_ms"] + audit["keyword_ms"])

    def test_graph_timeout_degrades_graph_only(self):
        _start(self, graph=1.5)
        with mock.patch.object(lf, "_GRAPH_SIGNAL_DEADLINE_S", 0.4):
            t0 = time.perf_counter()
            result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
            wall = time.perf_counter() - t0
        self.assertLess(wall, 0.9)
        self.assertEqual(result["graph_algorithm"], "timeout")
        self.assertEqual(result["signal_availability"],
                         {"vector": True, "graph": False, "keyword": True})
        self.assertEqual({n["record_id"] for n in result["nodes"]},
                         {"ENC-TSK-001", "ENC-TSK-003"})
        audit = lf._graphsearch_audit_record({}, dict(PARAMS), "hybrid", "enceladus",
                                             result, int(wall * 1000))
        self.assertGreaterEqual(audit["graph_ms"], 350)
        self.assertEqual(audit["graph_algorithm"], "timeout")
        self.assertEqual(audit["graph_candidates"], 0)

    def test_graph_exception_degrades_graph_only(self):
        _start(self)
        with mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback",
                               side_effect=RuntimeError("boom")):
            result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        self.assertEqual(result["graph_algorithm"], "unavailable")
        self.assertTrue(result["signal_availability"]["vector"])
        self.assertTrue(result["signal_availability"]["keyword"])

    def test_vector_exception_propagates(self):
        _start(self)
        with mock.patch.object(lf, "_hybrid_vector_ranks", side_effect=RuntimeError("vec")):
            with self.assertRaises(RuntimeError):
                lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))

    def test_no_anchor_skips_graph(self):
        _start(self)
        result = lf._query_hybrid(mock.MagicMock(), "enceladus", {"query": "latency"})
        self.assertFalse(result["signal_availability"]["graph"])
        self.assertEqual(result["graph_algorithm"], "unavailable")


if __name__ == "__main__":
    unittest.main()
