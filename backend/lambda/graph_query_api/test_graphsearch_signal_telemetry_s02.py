"""ENC-TSK-S02 (PLN-103 W0.1 / N2): per-signal telemetry on the hybrid
`graphsearch_query` audit line; response body unchanged."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corroboration  # noqa: E402
import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402

TEN_FIELDS = {
    "vector_ms", "graph_ms", "keyword_ms", "facets_ms", "pathway_ms",
    "graph_candidates", "keyword_candidates", "graph_algorithm",
    "pathway_status", "query_hash",
}
_NODES = {
    "ENC-TSK-001": {"record_id": "ENC-TSK-001", "_labels": ["Task"], "project_id": "enceladus",
                    "record_type": "task", "status": "open", "priority": "P1"},
    "ENC-TSK-002": {"record_id": "ENC-TSK-002", "_labels": ["Task"], "project_id": "enceladus",
                    "record_type": "task", "status": "closed", "priority": "P1"},
}


def _start(tc, pathway=None):
    patchers = [
        mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
        mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1, 0.2]),
        mock.patch.object(lf, "_hybrid_vector_ranks", return_value=[
            {"record_id": "ENC-TSK-001", "score": 0.9, "rank": 1}]),
        mock.patch.object(lf, "_hybrid_graph_ranks_gds_warm", return_value=[]),
        mock.patch.object(lf, "_check_gds_available", return_value=False),
        mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback", return_value=[
            {"record_id": "ENC-TSK-002", "score": 3.0, "rank": 1},
            {"record_id": "ENC-TSK-001", "score": 2.0, "rank": 2}]),
        mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[
            {"record_id": "ENC-TSK-001", "score": 2.0, "rank": 1}]),
        mock.patch.object(lf.opensearch_keyword, "hybrid_keyword_ranks",
                          return_value=([], {}, "down")),
        mock.patch.object(lf, "_fetch_nodes_by_record_ids", return_value=dict(_NODES)),
        mock.patch.object(lf, "_reconstruct_pathway_edges",
                          side_effect=pathway or (lambda *a, **k: (
                              lf._hybrid_telemetry_set(pathway_status="ok") or ([], [], [])))),
        mock.patch.object(lf, "_emit_pathway_telemetry"),
        mock.patch.object(lf, "_maybe_emit_stigmergic_trace"),
        mock.patch.object(ef, "load_lambda_weights", return_value=(1.0, 0.1)),
        mock.patch.object(corroboration, "load_alpha", return_value=0.02),
    ]
    for p in patchers:
        p.start()
        tc.addCleanup(p.stop)


PARAMS = {"query": "latency", "anchor_record_id": "ENC-TSK-001", "record_type": "task"}


class TestSignalTelemetry(unittest.TestCase):
    def test_ten_fields_on_audit_line(self):
        _start(self)
        result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        audit = lf._graphsearch_audit_record(
            {}, dict(PARAMS), "hybrid", "enceladus", result, 12)
        self.assertTrue(TEN_FIELDS <= set(audit), TEN_FIELDS - set(audit))
        for k in ("vector_ms", "graph_ms", "keyword_ms", "facets_ms", "pathway_ms"):
            self.assertIsInstance(audit[k], int)
            self.assertGreaterEqual(audit[k], 0)
        self.assertEqual(audit["graph_candidates"], 2)
        self.assertEqual(audit["keyword_candidates"], 1)
        self.assertEqual(audit["graph_algorithm"], "cypher_fallback")
        self.assertEqual(audit["pathway_status"], "ok")
        expect = hashlib.sha256("\n".join(["latency", "ENC-TSK-001", "task"]).encode()).hexdigest()
        self.assertEqual(audit["query_hash"], expect)

    def test_response_shape_unchanged(self):
        _start(self)
        result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        self.assertFalse(TEN_FIELDS - {"graph_algorithm"} & set(result))
        for k in ("nodes", "edges", "paths", "summary", "signal_availability",
                  "graph_algorithm", "facets", "per_node_fusion", "pathway"):
            self.assertIn(k, result)
        self.assertEqual(result["graph_algorithm"], "cypher_fallback")

    def test_no_signals_path_defaults_skipped(self):
        _start(self)
        with mock.patch.object(lf, "_hybrid_vector_ranks", return_value=[]), \
                mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback", return_value=[]), \
                mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[]):
            result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        audit = lf._graphsearch_audit_record({}, dict(PARAMS), "hybrid", "enceladus", result, 1)
        self.assertTrue(TEN_FIELDS <= set(audit))
        self.assertEqual(audit["pathway_status"], "skipped")
        self.assertEqual(audit["graph_candidates"], 0)
        self.assertEqual(audit["graph_algorithm"], "unavailable")

    def test_graph_timeout_reported(self):
        _start(self)
        with mock.patch.object(lf, "_hybrid_graph_ranks_cypher_fallback",
                               side_effect=RuntimeError("boom")):
            result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
        audit = lf._graphsearch_audit_record({}, dict(PARAMS), "hybrid", "enceladus", result, 1)
        self.assertEqual(audit["graph_algorithm"], "unavailable")

    def test_telemetry_not_added_to_other_search_types(self):
        lf._hybrid_telemetry_begin("x")
        audit = lf._graphsearch_audit_record(
            {}, {"record_id": "ENC-TSK-001"}, "neighbors", "enceladus", {"nodes": []}, 1)
        self.assertFalse(TEN_FIELDS - {"graph_algorithm"} & set(audit))

    def test_take_does_not_leak(self):
        lf._hybrid_telemetry_begin("abc")
        self.assertEqual(lf._hybrid_telemetry_take()["query_hash"], "abc")
        self.assertIsNone(lf._hybrid_telemetry_take()["query_hash"])


class TestPathwayStatus(unittest.TestCase):
    def test_skipped_without_anchor(self):
        lf._hybrid_telemetry_begin("h")
        lf._reconstruct_pathway_edges(mock.MagicMock(), "enceladus", "", ["A"])
        self.assertEqual(lf._hybrid_telemetry_take()["pathway_status"], "skipped")

    def test_failed_on_driver_error(self):
        drv = mock.MagicMock()
        drv.session.side_effect = RuntimeError("down")
        lf._hybrid_telemetry_begin("h")
        lf._reconstruct_pathway_edges(drv, "enceladus", "ENC-TSK-001", ["ENC-TSK-002"])
        self.assertEqual(lf._hybrid_telemetry_take()["pathway_status"], "failed")

    def test_ok_on_success(self):
        drv = mock.MagicMock()
        drv.session.return_value.__enter__.return_value.run.return_value = []
        lf._hybrid_telemetry_begin("h")
        lf._reconstruct_pathway_edges(drv, "enceladus", "ENC-TSK-001", ["ENC-TSK-002"])
        self.assertEqual(lf._hybrid_telemetry_take()["pathway_status"], "ok")

    def test_timeout(self):
        drv = mock.MagicMock()
        drv.session.side_effect = lambda: __import__("time").sleep(0.5)
        lf._hybrid_telemetry_begin("h")
        with mock.patch.object(lf, "_PATHWAY_EDGE_DEADLINE_S", 0.05):
            lf._reconstruct_pathway_edges(drv, "enceladus", "ENC-TSK-001", ["ENC-TSK-002"])
        self.assertEqual(lf._hybrid_telemetry_take()["pathway_status"], "timeout")


if __name__ == "__main__":
    unittest.main()
