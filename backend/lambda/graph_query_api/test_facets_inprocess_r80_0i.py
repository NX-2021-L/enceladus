"""ENC-TSK-R80-0I (DOC-52FE56D6F529 U1): facets computed in-process over the fused
candidate set; no prod-to-gamma feed/corpus hop."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corroboration  # noqa: E402
import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402
import opensearch_keyword as okw  # noqa: E402

_NODES = {
    "ENC-TSK-001": {"record_id": "ENC-TSK-001", "_labels": ["Task"], "project_id": "enceladus",
                    "record_type": "task", "status": "open", "priority": "P1"},
    "ENC-TSK-002": {"record_id": "ENC-TSK-002", "_labels": ["Task"], "project_id": "enceladus",
                    "record_type": "task", "status": "closed", "priority": "P1"},
    "ENC-ISS-003": {"record_id": "ENC-ISS-003", "_labels": ["Issue"], "project_id": "enceladus",
                    "status": "open"},
}


class TestFacetsFromCandidates(unittest.TestCase):
    def test_counts_and_label_fallback(self):
        f = lf._facets_from_candidates(_NODES.values(), "enceladus")
        self.assertEqual(f["project_id"], {"enceladus": 3})
        self.assertEqual(f["record_type"], {"task": 2, "issue": 1})
        self.assertEqual(f["status"], {"open": 2, "closed": 1})
        self.assertEqual(f["priority"], {"P1": 2})

    def test_empty_set_keeps_all_fields(self):
        f = lf._facets_from_candidates([None], "enceladus")
        self.assertEqual(set(f), {"project_id", "record_type", "status", "priority"})
        self.assertTrue(all(v == {} for v in f.values()))


class TestHybridFacets(unittest.TestCase):
    def _start(self, vector, graph, keyword, nodes):
        patchers = [
            mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d),
            mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1, 0.2]),
            mock.patch.object(lf, "_hybrid_vector_ranks", return_value=vector),
            mock.patch.object(lf, "_hybrid_graph_ranks_gds_warm", return_value=graph),
            mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=keyword),
            mock.patch.object(lf, "_fetch_nodes_by_record_ids", return_value=nodes),
            mock.patch.object(lf, "_reconstruct_pathway_edges", return_value=([], [], [])),
            mock.patch.object(lf, "_emit_pathway_telemetry"),
            mock.patch.object(ef, "load_lambda_weights", return_value=(1.0, 0.1)),
            mock.patch.object(corroboration, "load_alpha", return_value=0.02),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def _run(self):
        return lf._query_hybrid(
            mock.MagicMock(), "enceladus", {"query": "facets", "anchor_record_id": "ENC-TSK-001"}
        )

    def test_facets_source_and_values_over_fused_set(self):
        self._start(
            [{"record_id": "ENC-TSK-001", "score": 0.9, "rank": 1},
             {"record_id": "ENC-ISS-003", "score": 0.5, "rank": 2}],
            [{"record_id": "ENC-TSK-002", "score": 3.0, "rank": 1}],
            [{"record_id": "ENC-TSK-001", "score": 2.0, "rank": 1}],
            dict(_NODES),
        )
        r = self._run()
        self.assertEqual(r["facets_source"], "fused_candidates")
        self.assertEqual(r["facets"]["record_type"], {"task": 2, "issue": 1})
        self.assertEqual(r["facets"]["status"], {"open": 2, "closed": 1})

    def test_facets_present_when_no_signals(self):
        self._start([], [], [], {})
        r = self._run()
        self.assertEqual(r["facets_source"], "fused_candidates")
        self.assertEqual(set(r["facets"]), {"project_id", "record_type", "status", "priority"})

    def test_facets_present_when_opensearch_down_and_no_outbound_http(self):
        self._start(
            [{"record_id": "ENC-TSK-001", "score": 0.9, "rank": 1}], [], [], dict(_NODES),
        )
        with mock.patch.object(
            okw, "hybrid_keyword_ranks", return_value=([], {}, "boom")
        ), mock.patch("urllib.request.urlopen", side_effect=AssertionError("outbound HTTP")):
            r = self._run()
        self.assertEqual(r["facets_source"], "fused_candidates")
        self.assertEqual(r["facets"]["status"], {"open": 1})

    def test_no_gamma_host_or_feed_hop_in_module_source(self):
        self.assertFalse(hasattr(okw, "FEED_API_BASE"))
        self.assertFalse(hasattr(okw, "fetch_feed_corpus_facets"))
        for mod in (okw, lf):
            self.assertNotIn("enceladus-gamma", Path(mod.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
