"""Offline tests for tools/graphsearch_probe.py helpers (ENC-TSK-S02)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graphsearch_probe as gp  # noqa: E402

FULL = {"event": "graphsearch_query", "search_type": "hybrid", "duration_ms": 100, "vector_ms": 10,
        "graph_ms": 20, "keyword_ms": 5, "facets_ms": 1, "pathway_ms": 30, "graph_candidates": 40,
        "keyword_candidates": 3, "graph_algorithm": "cypher_fallback", "pathway_status": "ok",
        "query_hash": "ab", "edge_count": 2}


class ProbeHelpers(unittest.TestCase):
    def test_percentile_nearest_rank(self):
        v = list(range(1, 101))
        self.assertEqual(gp.percentile(v, 50), 50)
        self.assertEqual(gp.percentile(v, 95), 95)
        self.assertEqual(gp.percentile([7], 95), 7)
        self.assertIsNone(gp.percentile([], 50))

    def test_parse_audit(self):
        line = "[INFO]\t2026-11-02T00:00:00Z\treq\t" + json.dumps(FULL)
        self.assertEqual(gp.parse_audit(line)["vector_ms"], 10)
        wrapped = json.dumps({"level": "INFO", "message": json.dumps(FULL)})
        self.assertEqual(gp.parse_audit(wrapped)["graph_ms"], 20)
        self.assertIsNone(gp.parse_audit("no json here"))
        self.assertIsNone(gp.parse_audit("x {bad"))

    def test_aggregate(self):
        partial = dict(FULL, pathway_status="timeout", keyword_candidates=25, edge_count=0)
        del partial["facets_ms"]
        s = gp.aggregate([FULL, partial], top_n=20)
        self.assertEqual(s["n_audit_lines"], 2)
        self.assertEqual(s["fields_present_fraction"], 0.95)
        self.assertEqual(s["lines_with_all_fields"], 1)
        self.assertEqual(s["pathway_status"], {"ok": 1, "timeout": 1})
        self.assertEqual(s["frac_keyword_candidates_lt_top_n"], 0.5)
        self.assertEqual(s["frac_edge_count_gt0"], 0.5)
        self.assertEqual(s["vector_ms"], {"p50": 10, "p95": 10})
        self.assertEqual(gp.aggregate([], 20), {"n_audit_lines": 0})


if __name__ == "__main__":
    unittest.main()
