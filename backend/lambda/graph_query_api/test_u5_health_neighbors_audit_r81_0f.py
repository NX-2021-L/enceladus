"""ENC-TSK-R81-0F (W1.6 U5): health graph mode truth, embedding strip, audit attribution."""
from __future__ import annotations

import json
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402

VEC = [0.0123456789] * 256


class _Node(dict):
    def __init__(self, record_id, **props):
        super().__init__(record_id=record_id, **props)
        self.labels = ["Task"]


class _Rows(list):
    def single(self):
        return {}

    def consume(self):
        return None


class _Session:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        return _Rows(self._rows)


class _Driver:
    def __init__(self, rows):
        self._rows = rows

    def session(self):
        return _Session(self._rows)


class HealthGraphModeTests(unittest.TestCase):
    def test_hard_disabled_is_cypher_fallback_even_with_plugin(self):
        with mock.patch.object(lf, "_GDS_HARD_DISABLED", True):
            m = lf._graph_operating_mode(True, {})
        self.assertEqual(m["mode"], "cypher_fallback")
        self.assertEqual(m["reason"], "policy_gds_hard_disabled")
        self.assertTrue(m["gds_plugin_present"])

    def test_plugin_present_not_disabled_is_gds_pagerank(self):
        with mock.patch.object(lf, "_GDS_HARD_DISABLED", False):
            warm = lf._graph_operating_mode(True, {"configured": True, "exists": True, "stale": False})
            cold = lf._graph_operating_mode(True, {"configured": False})
        self.assertEqual(warm["mode"], "gds_pagerank")
        self.assertEqual(warm["reason"], "standing_projection")
        self.assertEqual(cold["reason"], "per_query_projection")

    def test_plugin_absent_is_cypher_fallback(self):
        with mock.patch.object(lf, "_GDS_HARD_DISABLED", False):
            m = lf._graph_operating_mode(False, {})
        self.assertEqual(m["mode"], "cypher_fallback")

    def test_health_endpoint_reports_mode_not_presence(self):
        drv = _Driver([])
        with mock.patch.object(lf, "_get_neo4j_driver", return_value=drv), \
             mock.patch.object(lf, "_GDS_HARD_DISABLED", True), \
             mock.patch.object(lf, "_hybrid_keyword_ranks", return_value=[1]), \
             mock.patch.object(lf, "_compute_query_embedding", return_value=[0.1]), \
             mock.patch.object(lf, "_check_gds_available", return_value=True), \
             mock.patch.object(lf, "_standing_projection_status", return_value={"configured": False}):
            body = json.loads(lf._handle_health({})["body"])
        self.assertEqual(body["signals"]["graph"], "cypher_fallback")
        self.assertEqual(body["graph_mode"]["mode"], "cypher_fallback")
        self.assertTrue(body["signals"]["keyword"])


class EmbeddingStripTests(unittest.TestCase):
    def test_node_to_dict_strips_embedding_by_default(self):
        n = _Node("ENC-TSK-1", embedding=VEC, title="t")
        self.assertNotIn("embedding", lf._node_to_dict(n))
        self.assertIn("embedding", lf._node_to_dict(n, include_embedding=True))

    def test_neighbors_nodes_have_no_embedding_and_under_1kb(self):
        big = "x" * 5000
        start = _Node("ENC-TSK-1", embedding=VEC, title="start", description=big)
        nb = _Node("ENC-TSK-2", embedding=VEC, title="nb", description=big, intent=big, status="open")
        rows = [{"neighbor": nb, "start": start, "path_lists": [[{"type": "RELATED_TO", "start": "ENC-TSK-1", "end": "ENC-TSK-2"}]]}]
        out = lf._query_neighbors(_Driver(rows), "enceladus", {"record_id": "ENC-TSK-1"})
        self.assertEqual({n["record_id"] for n in out["nodes"]}, {"ENC-TSK-1", "ENC-TSK-2"})
        for n in out["nodes"]:
            self.assertNotIn("embedding", n)
            self.assertLess(len(json.dumps(n).encode()), 1024)
        nbn = [n for n in out["nodes"] if n["record_id"] == "ENC-TSK-2"][0]
        self.assertEqual(nbn["status"], "open")
        self.assertEqual(nbn["title"], "nb")

    def test_hybrid_bulk_fetch_still_gets_embeddings(self):
        src = Path(lf.__file__).read_text()
        self.assertIn('_node_to_dict(rec["n"], include_embedding=True)', src)

    def test_embeddings_for_route_unchanged(self):
        self.assertEqual(lf.EMBEDDING_EGRESS_SEARCH_TYPE, "embeddings_for")


class AuditAttributionTests(unittest.TestCase):
    def _record(self, event, qs, search_type="neighbors", nodes=None):
        res = {"nodes": nodes or [], "edges": [], "paths": [], "query_cypher": "q"}
        return lf._graphsearch_audit_record(event, qs, search_type, "enceladus", res, 5)

    def test_audit_has_record_id_and_internal_caller(self):
        with mock.patch.object(lf, "COORDINATION_INTERNAL_API_KEY", "k1"):
            rec = self._record({"headers": {"X-Coordination-Internal-Key": "k1", "X-Enceladus-Surface": "mentions_drift_audit"}},
                               {"record_id": "ENC-TSK-9", "session_id": "ENC-SES-0AA"})
        self.assertEqual(rec["record_id"], "ENC-TSK-9")
        self.assertEqual(rec["caller"], "mentions_drift_audit")
        self.assertEqual(rec["caller_type"], "internal")
        self.assertEqual(rec["session_id"], "ENC-SES-0AA")
        self.assertEqual(rec["event"], "graphsearch_query")

    def test_audit_jwt_caller(self):
        ev = {"requestContext": {"authorizer": {"jwt": {"claims": {"sub": "abc", "cognito:username": "io", "enc:agent_tier": "standard"}}}}}
        rec = self._record(ev, {"record_id": "R"})
        self.assertEqual((rec["caller"], rec["caller_type"]), ("io", "agent"))

    def test_audit_unknown_caller_never_raises(self):
        rec = self._record({}, {})
        self.assertEqual(rec["caller"], "unknown")
        self.assertEqual(rec["session_id"], "unassigned")

    def test_empty_neighbors_flag(self):
        empty = self._record({}, {"record_id": "A"}, nodes=[{"record_id": "A"}])
        full = self._record({}, {"record_id": "A"}, nodes=[{"record_id": "A"}, {"record_id": "B"}])
        self.assertTrue(empty["empty_neighbors"])
        self.assertFalse(full["empty_neighbors"])
        self.assertNotIn("empty_neighbors", self._record({}, {}, search_type="hybrid"))

    def test_handle_search_emits_audit_line(self):
        ev = {"queryStringParameters": {"project_id": "enceladus", "search_type": "neighbors", "record_id": "A"},
              "headers": {"x-enceladus-surface": "pwa"}}
        drv = _Driver([])
        with mock.patch.object(lf, "_get_neo4j_driver", return_value=drv), \
             mock.patch.object(lf, "_maybe_emit_stigmergic_trace"), \
             self.assertLogs(lf.logger, level=logging.INFO) as cm:
            lf._handle_search(ev)
        lines = [json.loads(m.split(":", 2)[-1]) for m in cm.output if "graphsearch_query" in m]
        self.assertEqual(lines[0]["record_id"], "A")
        self.assertEqual(lines[0]["surface"], "pwa")
        self.assertTrue(lines[0]["empty_neighbors"])


if __name__ == "__main__":
    unittest.main()
