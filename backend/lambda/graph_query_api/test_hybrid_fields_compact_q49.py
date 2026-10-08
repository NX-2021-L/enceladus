"""ENC-TSK-Q49: hybrid fields=compact response projection tests."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402

TOP_N = 20


def _fake_hybrid_result(top_n: int = TOP_N):
    nodes, fusion = [], {}
    for i in range(1, top_n + 1):
        rid = f"ENC-TSK-{i:03d}"
        nodes.append({
            "record_id": rid, "record_type": "task", "title": f"T{i} " + "x" * 60,
            "status": "open", "updated_at": "2026-10-08T00:00:00Z",
            "category": "feature", "priority": "P2", "project_id": "enceladus",
            "created_at": "2026-01-01T00:00:00Z", "embedding_text_hash": "h" * 64,
            "is_placeholder": False, "_labels": ["Task"],
            "_fused_rank": i, "_fused_score": 0.01, "_per_signal_ranks": {"vector": i},
            "_corroboration_count": 2, "_b_corr": 0.1, "_final_score": 0.011, "_final_rank": i,
        })
    # 3 x top_n fusion entries (extras were fetched but trimmed from nodes).
    for i in range(1, top_n * 3 + 1):
        fusion[f"ENC-TSK-{i:03d}"] = {
            "fused_rank": i, "fused_score": 0.01, "per_signal_ranks": {"vector": i},
            "k_corr": 2, "b_corr": 0.1, "final_score": 0.011, "final_rank": i,
        }
    return {
        "nodes": nodes, "edges": [{"source": "a", "target": "b", "type": "RELATED_TO"}],
        "paths": [], "summary": "s", "query_cypher": "hybrid/multi-signal-rrf",
        "signal_availability": {"vector": True}, "graph_algorithm": "ppr", "rrf_k": 60,
        "embedding_coverage_sample": 1.0, "per_node_fusion": fusion,
        "fsrs_t3_threshold": 0.7, "edge_participation": {"x": 1},
        "pathway": {"node_sequence": []}, "facets": {"status": {}},
    }


def _call(**extra):
    qs = {"project_id": "enceladus", "search_type": "hybrid", "query": "q", "top_n": "20"}
    qs.update(extra)
    with mock.patch.object(lf, "_get_neo4j_driver", return_value=object()), \
         mock.patch.dict(lf.SEARCH_HANDLERS, {"hybrid": lambda d, p, q: _fake_hybrid_result()}):
        resp = lf._handle_search({"queryStringParameters": qs})
    return resp, json.loads(resp["body"])


class TestFieldsCompact(unittest.TestCase):
    def test_default_and_full_identical(self):
        r0, b0 = _call()
        r1, b1 = _call(fields="full")
        self.assertEqual(r0["statusCode"], 200)
        self.assertEqual(
            {k: v for k, v in b0.items() if k != "duration_ms"},
            {k: v for k, v in b1.items() if k != "duration_ms"},
        )
        self.assertEqual(len(b0["per_node_fusion"]), TOP_N * 3)
        self.assertIn("edges", b0)
        self.assertIn("category", b0["nodes"][0])
        self.assertIn("query_cypher", b0)

    def test_compact_projection(self):
        r, b = _call(fields="compact")
        self.assertEqual(r["statusCode"], 200)
        ids = [n["record_id"] for n in b["nodes"]]
        self.assertEqual(len(ids), TOP_N)
        self.assertEqual(set(b["per_node_fusion"]), set(ids))
        self.assertEqual(set(b["nodes"][0]), set(lf._COMPACT_NODE_KEYS))
        for dropped in ("edges", "paths", "pathway", "facets", "query_cypher", "edge_participation"):
            self.assertNotIn(dropped, b)
        for kept in ("signal_availability", "graph_algorithm", "rrf_k", "summary",
                     "embedding_coverage_sample", "fsrs_t3_threshold", "duration_ms"):
            self.assertIn(kept, b)

    def test_compact_is_much_smaller(self):
        _, full = _call()
        _, compact = _call(fields="compact")
        self.assertLess(len(json.dumps(compact)), len(json.dumps(full)) * 0.5)

    def test_unknown_fields_400(self):
        r, b = _call(fields="tiny")
        self.assertEqual(r["statusCode"], 400)
        self.assertIn("fields must be one of", json.dumps(b))


if __name__ == "__main__":
    unittest.main()
