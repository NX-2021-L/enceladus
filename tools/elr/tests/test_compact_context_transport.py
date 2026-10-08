"""Offline tests for the ENC-TSK-Q54 transport switch (route vs Phase 1 compose)."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import elr_compact_context as cc

from .test_compact_context import FakeClient, _RECORD, hybrid_body, record_routes, run_verb

ARGV = ["--mode", "task", "--record-id", "ENC-TSK-Q33", "--top-n", "5"]


def route_body(hybrid: dict, **retrieval_extra) -> dict:
    section = {k: v for k, v in hybrid.items() if k not in ("success", "pathway", "edges", "paths")}
    retrieval = {
        "signals_present": ["vector", "graph", "keyword"],
        "signals_absent": {"graph": "gds_unavailable"},
        "intent_signature": hybrid["pathway"]["intent_signature"],
        "wave_id": hybrid["pathway"]["wave_id"],
        "pathway_edge_count": 0,
    }
    retrieval.update(retrieval_extra)
    return {
        "success": True,
        "schema": "elr.compact_context_digest",
        "fields": "full",
        "header": {"mode": "task", "anchor": "ENC-TSK-Q33", "query_head": "ui-v2 PWA: stop serving feed corp"},
        "retrieval": retrieval,
        "warnings": [],
        "sections": {
            "record_context": {"record": _RECORD},
            "governance": {"entity": "tracker.task"},
            "related_documents": {"documents": []},
            "hybrid_retrieval": section,
        },
    }


def routes(health, route, hybrid=None, gs_health=None, extra=None):
    r = record_routes(hybrid)
    r[("health", "")] = (200, health)
    if route is not None:
        r[("coordination", "/context/compact")] = route
    if gs_health is not None:
        r[("graph_query", "/health")] = (200, gs_health)
    r.update(extra or {})
    return r


CAP = {"governance_hash": "f" * 64, "tracker_capabilities": {"compact_context": True}}
NOCAP = {"governance_hash": "f" * 64, "tracker_capabilities": {}}


class TransportSwitchTests(unittest.TestCase):
    def test_health_true_makes_one_route_get_and_matches_phase1_digest(self):
        hb = hybrid_body(5)
        route_client = FakeClient(routes(CAP, (200, route_body(hb)), hb))
        compose_client = FakeClient(routes(NOCAP, None, hb))
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            rd, rc = run_verb(ARGV, route_client, t1)
            cd, cc_ = run_verb(ARGV, compose_client, t2)
            self.assertEqual((rc, cc_), (0, 0))
            calls = [c for c in route_client.calls if c[0] != "health"]
            self.assertEqual([(c[0], c[1]) for c in calls], [("coordination", "/context/compact")])
            self.assertEqual(calls[0][2]["fields"], "full")
            self.assertEqual(calls[0][2]["record_id"], "ENC-TSK-Q33")
            self.assertEqual(rd["retrieval"]["composer"], "route")
            self.assertEqual(cd["retrieval"]["composer"], "elr-1")
            self.assertEqual(rd["ranking"], cd["ranking"])
            for key in ("signals_present", "signals_absent", "candidates", "embedding_coverage_sample", "intent_signature", "graph_algorithm"):
                self.assertEqual(rd["retrieval"].get(key), cd["retrieval"].get(key), key)
            self.assertEqual(rd["governance_hash"], cd["governance_hash"])
            r_dir = Path(rd["header"]["root"]) / rd["header"]["run_id"]
            c_dir = Path(cd["header"]["root"]) / cd["header"]["run_id"]
            self.assertEqual((r_dir / rd["ids_file"]).read_text().splitlines(), (c_dir / cd["ids_file"]).read_text().splitlines())
            self.assertTrue((r_dir / "hybrid.json").exists() and (r_dir / "record.json").exists())
            self.assertEqual(json.loads((r_dir / "hybrid.json").read_text())["nodes"], hb["nodes"])
            self.assertFalse(any(c[0] in ("tracker", "graph_query") for c in route_client.calls))

    def test_health_false_or_absent_composes_phase1(self):
        for health in (NOCAP, {"governance_hash": "f" * 64}):
            client = FakeClient(routes(health, (200, route_body(hybrid_body(3)))))
            with tempfile.TemporaryDirectory() as tmp:
                digest, code = run_verb(ARGV, client, tmp)
            self.assertEqual(code, 0)
            self.assertEqual(digest["retrieval"]["composer"], "elr-1")
            self.assertFalse([c for c in client.calls if c[1] == "/context/compact"])

    def test_transport_compose_never_calls_route(self):
        client = FakeClient(routes(CAP, (200, route_body(hybrid_body(3)))))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV + ["--transport", "compose"], client, tmp)
        self.assertEqual(digest["retrieval"]["composer"], "elr-1")
        self.assertFalse([c for c in client.calls if c[1] == "/context/compact"])

    def test_route_500_falls_back_with_warning(self):
        client = FakeClient(routes(CAP, (500, {"error": "x"}), hybrid_body(3)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV, client, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(digest["retrieval"]["composer"], "elr-1")
        self.assertIn("route_fallback:http_500", digest["warnings"])
        self.assertEqual(len(digest["ranking"]), 3)

    def test_route_shape_drift_falls_back(self):
        bad = route_body(hybrid_body(3))
        bad["sections"]["hybrid_retrieval"]["nodes"][1].pop("_final_rank")
        client = FakeClient(routes(CAP, (200, bad), hybrid_body(3)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV, client, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(digest["retrieval"]["composer"], "elr-1")
        self.assertTrue(any(w.startswith("route_fallback:shape_drift") for w in digest["warnings"]))

    def test_explicit_route_transport_failure_exits_6(self):
        client = FakeClient(routes(NOCAP, (404, {})))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV + ["--transport", "route"], client, tmp)
        self.assertEqual(code, 6)
        self.assertIn("context_route_unavailable", digest["anomalies"])

    def test_fields_compact_requested_only_when_advertised(self):
        for gs, expect in (({"hybrid_fields_compact": True}, "compact"), ({"hybrid_fields_compact": False}, None), (None, None)):
            hb = hybrid_body(3)
            client = FakeClient(routes(NOCAP, None, hb, gs_health=gs))
            with tempfile.TemporaryDirectory() as tmp:
                digest, code = run_verb(ARGV, client, tmp)
                self.assertEqual(code, 0)
                (call,) = [c for c in client.calls if c[0] == "graph_query" and c[1] == ""]
                self.assertEqual(call[2].get("fields"), expect)
                run_dir = Path(digest["header"]["root"]) / digest["header"]["run_id"]
                self.assertEqual(json.loads((run_dir / "hybrid.json").read_text())["nodes"], hb["nodes"])

    def test_fields_compact_400_retries_without_it(self):
        hb = hybrid_body(3)
        seen = []

        def hybrid(query):
            seen.append(dict(query))
            return (400, {"error": "unknown"}) if query.get("fields") else (200, hb)

        client = FakeClient(routes(NOCAP, None, hb, gs_health={"hybrid_fields_compact": True}, extra={("graph_query", ""): hybrid}))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV, client, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(len(seen), 2)
        self.assertIn("hybrid_fields_compact_retry_full", digest["warnings"])

    def test_alpha_and_s_top_digest_keys_and_old_key_tolerated(self):
        hb = hybrid_body(3, corroboration_alpha=0.75, s_top=0.42)
        client = FakeClient(routes(NOCAP, None, hb))
        with tempfile.TemporaryDirectory() as tmp:
            digest, _ = run_verb(ARGV, client, tmp)
        self.assertEqual(digest["retrieval"]["alpha"], 0.75)
        self.assertEqual(digest["retrieval"]["s_top"], 0.42)
        self.assertNotIn("unexpected_hybrid_key:corroboration_alpha", digest.get("warnings", []))
        old = FakeClient(routes(NOCAP, None, hybrid_body(3, corroboration_weber_k=1.5)))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(ARGV, old, tmp)
        self.assertEqual(code, 0)
        self.assertEqual(digest["retrieval"]["weber_k"], 1.5)

    def test_route_digest_stays_within_budget(self):
        hb = hybrid_body(50)
        client = FakeClient(routes(CAP, (200, route_body(hb))))
        with tempfile.TemporaryDirectory() as tmp:
            digest, code = run_verb(["--mode", "task", "--record-id", "ENC-TSK-Q33", "--top-n", "50"], client, tmp)
        self.assertEqual(code, 0)
        self.assertLessEqual(digest["header"]["digest_bytes"], cc.digest_budget_bytes(50))


if __name__ == "__main__":
    unittest.main()
