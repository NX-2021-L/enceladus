"""Tests for ENC-TSK-L87: _query_neighbors cross-project edge visibility.

MENTIONS (and other) edges are legitimately cross-project -- graph_sync's
write path (_reconcile_mentions_edges) MERGEs edges by record_id only, with
no project_id restriction on the target. _query_neighbors previously
required `neighbor.project_id = $project_id`, silently hiding every
cross-project edge from every "neighbors" consumer (including
mentions_drift_audit), even though the edge was correctly written to Neo4j.
Only the START node should be project-scoped; that's the caller's actual
query intent (find neighbors OF this specific (project_id, record_id) pair).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class _FakeNode(dict):
    def __init__(self, record_id, labels, **props):
        super().__init__(record_id=record_id, **props)
        self.labels = labels


class _FakeRecord(dict):
    """Mimics a neo4j Record: supports both rec["k"] and rec.get("k")."""


class _FakeResult(list):
    pass


class _FakeSession:
    def __init__(self, rows, captured_cypher):
        self._rows = rows
        self._captured = captured_cypher

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        self._captured.append((cypher, params))
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(self, rows):
        self._rows = rows
        self.captured_cypher = []

    def session(self):
        return _FakeSession(self._rows, self.captured_cypher)


class TestQueryNeighborsCrossProject(unittest.TestCase):
    def test_cypher_does_not_restrict_neighbor_project_id(self):
        """The generated Cypher must scope the START node to project_id but
        must NOT filter neighbors by project_id -- that's the exact bug."""
        driver = _FakeDriver(rows=[])
        lf._query_neighbors(driver, "devops", {"record_id": "DVP-TSK-465"})
        cypher, params = driver.captured_cypher[0]
        self.assertIn("start.project_id = $project_id", cypher)
        self.assertNotIn("neighbor.project_id", cypher)

    def test_cross_project_neighbor_is_returned(self):
        """A devops-project source with an enceladus-project neighbor
        (e.g. a MENTIONS edge from a DVP task to an ENC feature) must be
        returned -- this is exactly the shape graph_sync's write path
        produces and mentions_drift_audit needs to be able to observe."""
        neighbor = _FakeNode("ENC-FTR-049", ["Feature"], project_id="enceladus", title="x")
        start = _FakeNode("DVP-TSK-465", ["Task"], project_id="devops", title="src")
        rec = _FakeRecord(
            neighbor=neighbor,
            start=start,
            edge_infos=[{"type": "MENTIONS", "start": "DVP-TSK-465", "end": "ENC-FTR-049"}],
        )
        driver = _FakeDriver(rows=[rec])
        result = lf._query_neighbors(driver, "devops", {
            "record_id": "DVP-TSK-465",
            "edge_types": "MENTIONS",
        })
        # ENC-TSK-P61: the start node now rides along; the cross-project
        # neighbor must still be present.
        ids = [n["record_id"] for n in result["nodes"]]
        self.assertIn("ENC-FTR-049", ids)
        self.assertIn("DVP-TSK-465", ids)
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["type"], "MENTIONS")

    def test_same_project_neighbor_still_works(self):
        """Non-regression: same-project neighbors (the common case) are
        unaffected by removing the over-restrictive filter."""
        neighbor = _FakeNode("ENC-TSK-B01", ["Task"], project_id="enceladus", title="y")
        rec = _FakeRecord(
            neighbor=neighbor,
            edge_infos=[{"type": "MENTIONS", "start": "ENC-TSK-A01", "end": "ENC-TSK-B01"}],
        )
        driver = _FakeDriver(rows=[rec])
        result = lf._query_neighbors(driver, "enceladus", {
            "record_id": "ENC-TSK-A01",
            "edge_types": "MENTIONS",
        })
        self.assertEqual(len(result["nodes"]), 1)
        self.assertEqual(result["nodes"][0]["record_id"], "ENC-TSK-B01")


class TestQueryNeighborsAllHops(unittest.TestCase):
    """ENC-TSK-P61 (ENC-ISS-715): every hop of every path is returned, and
    the start node rides along.

    The old projection kept only the LAST relationship of each path
    ([-1]) -- on a depth-2 plan graph that discarded the plan's own
    first-hop PLAN_CONTAINS edges while keeping the RELATED_TO tails,
    which is exactly the UAT R11 symptom (95 edges, zero PLAN_CONTAINS
    from the viewed plan)."""

    def test_all_hops_of_a_depth2_path_are_returned(self):
        plan = _FakeNode("ENC-PLN-082", ["Plan"], project_id="enceladus", title="Cutover")
        related = _FakeNode("ENC-ISS-648", ["Issue"], project_id="enceladus", title="issue")
        rec = _FakeRecord(
            neighbor=related,
            start=plan,
            edge_infos=[
                {"type": "PLAN_CONTAINS", "start": "ENC-PLN-082", "end": "ENC-TSK-O59"},
                {"type": "RELATED_TO", "start": "ENC-TSK-O59", "end": "ENC-ISS-648"},
            ],
        )
        driver = _FakeDriver(rows=[rec])
        result = lf._query_neighbors(driver, "enceladus", {
            "record_id": "ENC-PLN-082",
            "depth": 2,
        })
        types = sorted(e["type"] for e in result["edges"])
        self.assertEqual(types, ["PLAN_CONTAINS", "RELATED_TO"])
        first_hop = [e for e in result["edges"] if e["type"] == "PLAN_CONTAINS"][0]
        self.assertEqual(first_hop["start"], "ENC-PLN-082")

    def test_start_node_is_included_once(self):
        plan = _FakeNode("ENC-PLN-082", ["Plan"], project_id="enceladus", title="Cutover")
        t1 = _FakeNode("ENC-TSK-O59", ["Task"], project_id="enceladus", title="a")
        t2 = _FakeNode("ENC-TSK-P40", ["Task"], project_id="enceladus", title="b")
        rows = [
            _FakeRecord(neighbor=t1, start=plan,
                        edge_infos=[{"type": "PLAN_CONTAINS", "start": "ENC-PLN-082", "end": "ENC-TSK-O59"}]),
            _FakeRecord(neighbor=t2, start=plan,
                        edge_infos=[{"type": "PLAN_CONTAINS", "start": "ENC-PLN-082", "end": "ENC-TSK-P40"}]),
        ]
        driver = _FakeDriver(rows=rows)
        result = lf._query_neighbors(driver, "enceladus", {"record_id": "ENC-PLN-082"})
        ids = [n["record_id"] for n in result["nodes"]]
        self.assertEqual(ids.count("ENC-PLN-082"), 1)
        self.assertEqual(sorted(ids), ["ENC-PLN-082", "ENC-TSK-O59", "ENC-TSK-P40"])

    def test_shared_hops_are_deduplicated_across_paths(self):
        plan = _FakeNode("ENC-PLN-082", ["Plan"], project_id="enceladus", title="Cutover")
        t1 = _FakeNode("ENC-TSK-O59", ["Task"], project_id="enceladus", title="a")
        deep = _FakeNode("ENC-ISS-648", ["Issue"], project_id="enceladus", title="i")
        shared = {"type": "PLAN_CONTAINS", "start": "ENC-PLN-082", "end": "ENC-TSK-O59"}
        rows = [
            _FakeRecord(neighbor=t1, start=plan, edge_infos=[dict(shared)]),
            _FakeRecord(neighbor=deep, start=plan,
                        edge_infos=[dict(shared),
                                    {"type": "RELATED_TO", "start": "ENC-TSK-O59", "end": "ENC-ISS-648"}]),
        ]
        driver = _FakeDriver(rows=rows)
        result = lf._query_neighbors(driver, "enceladus", {"record_id": "ENC-PLN-082", "depth": 2})
        self.assertEqual(len(result["edges"]), 2)


if __name__ == "__main__":
    unittest.main()
