"""ENC-FTR-082 Phase A tests for graph_query_api: pathway telemetry (AC-1),
edge participation (AC-10), and PATHWAY_TRAVERSED traversability (AC-6 site).

Pure unit tests — no live Neo4j/S3. The driver and S3 client are mocked.
"""
import json
import unittest
from unittest import mock


class TestPathwayAllowlist(unittest.TestCase):
    """AC-6 traversability site: edge registered for traversal, not for scoring."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_pathway_traversed_in_allowlist(self):
        self.assertIn("PATHWAY_TRAVERSED", self.lf._ALLOWED_EDGE_TYPES)

    def test_traversed_by_in_allowlist(self):
        self.assertIn("TRAVERSED_BY", self.lf._ALLOWED_EDGE_TYPES)

    def test_pathway_not_in_graph_edge_weights(self):
        # Phase A: a telemetry edge must NOT perturb the hybrid graph signal.
        self.assertNotIn("PATHWAY_TRAVERSED", self.lf.GRAPH_EDGE_WEIGHTS)
        self.assertNotIn("TRAVERSED_BY", self.lf.GRAPH_EDGE_WEIGHTS)


class TestIntentSignature(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_deterministic_and_prefixed(self):
        a = self.lf._derive_intent_signature("Find pathway", "ENC-FTR-082", "feature")
        b = self.lf._derive_intent_signature("Find pathway", "ENC-FTR-082", "feature")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("sha256:"))

    def test_normalization(self):
        # query case/space-insensitive; anchor uppercased
        a = self.lf._derive_intent_signature("  Find Pathway  ", "enc-ftr-082", "feature")
        b = self.lf._derive_intent_signature("find pathway", "ENC-FTR-082", "feature")
        self.assertEqual(a, b)

    def test_differs_on_intent(self):
        a = self.lf._derive_intent_signature("q1", "ENC-FTR-082", "feature")
        b = self.lf._derive_intent_signature("q2", "ENC-FTR-082", "feature")
        self.assertNotEqual(a, b)


class TestTelemetryRecord(unittest.TestCase):
    """AC-1 record carries the mandated fields; AC-10 participation is well-formed."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_record_shape(self):
        rec = self.lf._build_pathway_telemetry_record(
            wave_id="w1", intent_signature="sha256:x", project_id="enceladus",
            anchor_record_id="ENC-FTR-082",
            node_sequence=["ENC-FTR-082", "ENC-FTR-108"],
            edges_traversed=[{"edge_id": "e1", "type": "RELATED_TO",
                              "start": "ENC-FTR-082", "end": "ENC-FTR-108"}],
            edge_participation=[{"edge_id": "e1", "traversal_count": 1,
                                 "retrieval_outcome": "hit"}],
            result_count=1, graph_algorithm="gds_pagerank",
            signal_availability={"vector": True, "graph": True, "keyword": True},
        )
        for field in ("wave_id", "timestamp", "node_sequence", "edges_traversed",
                      "outcome", "intent_signature"):
            self.assertIn(field, rec)  # AC-1 mandated fields
        p = rec["edge_participation"][0]
        self.assertEqual(p["edge_id"], "e1")
        self.assertIn("traversal_count", p)
        self.assertIn("retrieval_outcome", p)
        self.assertEqual(rec["schema"], "enceladus.pathway.telemetry.v1")
        json.dumps(rec)  # must be JSON-serializable

    def test_default_wave_id(self):
        rec = self.lf._build_pathway_telemetry_record(
            wave_id="", intent_signature="sha256:x", project_id="enceladus",
            anchor_record_id=None, node_sequence=[], edges_traversed=[],
            edge_participation=[], result_count=0, graph_algorithm="unavailable",
            signal_availability={"vector": False, "graph": False, "keyword": False},
        )
        self.assertEqual(rec["wave_id"], "unassigned")


class TestEmitDegraded(unittest.TestCase):
    """AC-1: with no bucket, emit a CloudWatch log line and never raise."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_no_bucket_logs_and_no_raise(self):
        with mock.patch.object(self.lf, "PATHWAY_TELEMETRY_BUCKET", ""):
            with self.assertLogs(self.lf.logger, level="INFO") as cm:
                self.lf._emit_pathway_telemetry({"wave_id": "w1", "x": 1})
        self.assertTrue(any("PATHWAY_TELEMETRY" in line for line in cm.output))

    def test_s3_failure_falls_back_to_log(self):
        with mock.patch.object(self.lf, "PATHWAY_TELEMETRY_BUCKET", "some-bucket"):
            with mock.patch.object(self.lf, "_get_s3") as gs:
                gs.return_value.put_object.side_effect = RuntimeError("AccessDenied")
                with self.assertLogs(self.lf.logger, level="INFO") as cm:
                    self.lf._emit_pathway_telemetry({"wave_id": "w1"})
        self.assertTrue(any("PATHWAY_TELEMETRY" in line for line in cm.output))

    def test_never_raises_on_unserializable(self):
        class Weird:
            pass
        # Must not raise even with a non-trivially-serializable value.
        self.lf._emit_pathway_telemetry({"wave_id": "w1", "obj": Weird()})


class TestReconstructEdges(unittest.TestCase):
    """AC-1 edges_traversed/node_sequence + AC-10 participation, mocked driver."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_missing_anchor_returns_empty(self):
        edges, part, seq = self.lf._reconstruct_pathway_edges(None, "enceladus", "", ["ENC-X"])
        self.assertEqual((edges, part, seq), ([], [], []))

    def test_no_results_returns_anchor_seq(self):
        edges, part, seq = self.lf._reconstruct_pathway_edges(None, "enceladus", "ENC-A", [])
        self.assertEqual(edges, [])
        self.assertEqual(seq, ["ENC-A"])

    def _mock_driver(self, rows):
        sess = mock.MagicMock()
        sess.run.return_value = iter(rows)
        ctx = mock.MagicMock()
        ctx.__enter__.return_value = sess
        ctx.__exit__.return_value = False
        driver = mock.MagicMock()
        driver.session.return_value = ctx
        return driver

    def test_edges_and_participation(self):
        rows = [
            {"edge_id": "e1", "etype": "RELATED_TO", "s": "ENC-A", "e": "ENC-B"},
            {"edge_id": "e2", "etype": "PLAN_CONTAINS", "s": "ENC-B", "e": "ENC-C"},
        ]
        driver = self._mock_driver(rows)
        edges, part, seq = self.lf._reconstruct_pathway_edges(
            driver, "enceladus", "ENC-A", ["ENC-C"])
        self.assertEqual(len(edges), 2)
        self.assertEqual(edges[0]["edge_id"], "e1")
        outcomes = {p["edge_id"]: p["retrieval_outcome"] for p in part}
        self.assertEqual(outcomes["e2"], "hit")        # touches result ENC-C
        self.assertEqual(outcomes["e1"], "traversed")  # intermediate hop
        self.assertEqual(seq[0], "ENC-A")              # node_sequence anchored
        self.assertIn("ENC-C", seq)


if __name__ == "__main__":
    unittest.main()
