"""ENC-FTR-105 AC-7 / ENC-TSK-I91 tests for graph_query_api's adjacency-endpoint
spurious_attractor_rate enrichment.

Pure unit tests — no live Neo4j/AWS. The Neo4j driver and DynamoDB client are
mocked, mirroring the existing test_pathway_telemetry_ftr082.py /
test_graph_laplacian_ftr088.py conventions in this package.

Covers:
  - _recent_spurious_attractor_rate: averages non-null spurious_attractor_rate
    values from the project-timestamp-index GSI query, degrades to None on a
    missing table, an all-null result set, or a query failure.
  - _query_adjacency: surfaces spurious_attractor_rate on the first page
    (offset == 0) alongside node_count/edge_count, and omits it on later pages
    (mirroring the existing node_count/edge_count first-page-only contract).
"""
from __future__ import annotations

import unittest
from unittest import mock


class _FakeSingleResult:
    def __init__(self, value):
        self._value = value

    def single(self):
        return {"c": self._value}


class _FakeAdjacencySession:
    """Minimal Neo4j-session stand-in for _query_adjacency's three Cypher
    shapes: node count, edge count, and the (s, t) page."""

    def __init__(self, node_count, edges):
        self._node_count = node_count
        self._edges = edges

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        if "$project_id" in cypher:
            assert "project_id" in params, (
                f"cypher references $project_id but no project_id was bound: {cypher!r}"
            )
        if "RETURN count(n) AS c" in cypher:
            return _FakeSingleResult(self._node_count)
        if "RETURN count(DISTINCT" in cypher:
            return _FakeSingleResult(len(self._edges))
        if "RETURN s, t" in cypher:
            offset = params.get("offset", 0)
            limit = params.get("limit")
            page = self._edges[offset:offset + limit] if limit else self._edges[offset:]
            return [{"s": s, "t": t} for s, t in page]
        raise AssertionError(f"unexpected cypher in fake adjacency session: {cypher}")


class _FakeAdjacencyDriver:
    def __init__(self, node_count, edges):
        self._node_count = node_count
        self._edges = edges

    def session(self):
        return _FakeAdjacencySession(self._node_count, self._edges)


class TestRecentSpuriousAttractorRate(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_no_table_configured_returns_none(self):
        with mock.patch.object(self.lf, "DRIFT_TELEMETRY_TABLE", ""):
            self.assertIsNone(self.lf._recent_spurious_attractor_rate("enceladus"))

    def test_averages_non_null_values_and_skips_nulls(self):
        fake_response = {
            "Items": [
                {"spurious_attractor_rate": {"N": "0.2"}},
                {"spurious_attractor_rate": {"NULL": True}},
                {"spurious_attractor_rate": {"N": "0.4"}},
            ]
        }
        with mock.patch.object(self.lf, "DRIFT_TELEMETRY_TABLE", "enceladus-drift-telemetry-gamma"):
            with mock.patch.object(self.lf, "_get_dynamodb") as gd:
                gd.return_value.query.return_value = fake_response
                rate = self.lf._recent_spurious_attractor_rate("enceladus")
        self.assertAlmostEqual(rate, 0.3)
        gd.return_value.query.assert_called_once()
        kwargs = gd.return_value.query.call_args.kwargs
        self.assertEqual(kwargs["TableName"], "enceladus-drift-telemetry-gamma")
        self.assertEqual(kwargs["IndexName"], "project-timestamp-index")
        self.assertFalse(kwargs["ScanIndexForward"])

    def test_all_null_returns_none(self):
        fake_response = {"Items": [{"spurious_attractor_rate": {"NULL": True}}]}
        with mock.patch.object(self.lf, "DRIFT_TELEMETRY_TABLE", "t"):
            with mock.patch.object(self.lf, "_get_dynamodb") as gd:
                gd.return_value.query.return_value = fake_response
                self.assertIsNone(self.lf._recent_spurious_attractor_rate("enceladus"))

    def test_no_items_returns_none(self):
        with mock.patch.object(self.lf, "DRIFT_TELEMETRY_TABLE", "t"):
            with mock.patch.object(self.lf, "_get_dynamodb") as gd:
                gd.return_value.query.return_value = {"Items": []}
                self.assertIsNone(self.lf._recent_spurious_attractor_rate("enceladus"))

    def test_query_failure_degrades_to_none(self):
        with mock.patch.object(self.lf, "DRIFT_TELEMETRY_TABLE", "t"):
            with mock.patch.object(self.lf, "_get_dynamodb") as gd:
                gd.return_value.query.side_effect = RuntimeError("boom")
                self.assertIsNone(self.lf._recent_spurious_attractor_rate("enceladus"))


class TestAdjacencySpuriousAttractorEnrichment(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_first_page_includes_rate(self):
        driver = _FakeAdjacencyDriver(node_count=2, edges=[("A", "B")])
        with mock.patch.object(self.lf, "_recent_spurious_attractor_rate", return_value=0.42) as m:
            result = self.lf._query_adjacency(driver, "enceladus", {"offset": 0, "limit": 10})
        self.assertEqual(result["spurious_attractor_rate"], 0.42)
        m.assert_called_once_with("enceladus")

    def test_first_page_null_rate_passthrough(self):
        driver = _FakeAdjacencyDriver(node_count=0, edges=[])
        with mock.patch.object(self.lf, "_recent_spurious_attractor_rate", return_value=None):
            result = self.lf._query_adjacency(driver, "enceladus", {"offset": 0, "limit": 10})
        self.assertIn("spurious_attractor_rate", result)
        self.assertIsNone(result["spurious_attractor_rate"])

    def test_later_page_omits_rate(self):
        driver = _FakeAdjacencyDriver(node_count=2, edges=[("A", "B")])
        with mock.patch.object(self.lf, "_recent_spurious_attractor_rate") as m:
            result = self.lf._query_adjacency(driver, "enceladus", {"offset": 1, "limit": 10})
        self.assertNotIn("spurious_attractor_rate", result)
        self.assertNotIn("node_count", result)
        m.assert_not_called()


if __name__ == "__main__":
    unittest.main()
