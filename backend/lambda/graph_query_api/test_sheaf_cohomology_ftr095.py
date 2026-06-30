"""Tests for ENC-FTR-095 / ENC-TSK-I90: Sheaf Laplacian H1 inconsistency detection.

Covers the acceptance criteria that are unit-testable without a live Neo4j:
  * AC-2: empty graph returns H1 = 0.
  * AC-3: two records with contradictory status linked by RELATED_TO produce H1 >= 1.
Plus structural invariants: consistent trees have H1 = 0, the contradictory
endpoints are reported as inconsistency_nodes, and the R^d stalk dimension scales
the cohomology dimension.
"""

import unittest

import sheaf_cohomology as sc


class TestContradictionPredicate(unittest.TestCase):
    def test_open_vs_closed_is_contradictory(self):
        self.assertTrue(sc.is_contradictory("open", "closed"))

    def test_same_status_not_contradictory(self):
        self.assertFalse(sc.is_contradictory("open", "open"))

    def test_empty_status_not_contradictory(self):
        self.assertFalse(sc.is_contradictory("", "closed"))
        self.assertFalse(sc.is_contradictory("open", None))

    def test_active_vs_terminal_heuristic(self):
        self.assertTrue(sc.is_contradictory("in-progress", "deployed"))
        self.assertTrue(sc.is_contradictory("superseded", "active"))

    def test_two_active_not_contradictory(self):
        self.assertFalse(sc.is_contradictory("open", "in-progress"))


class TestMatrixRank(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(sc._matrix_rank([], 0), 0)
        self.assertEqual(sc._matrix_rank([], 3), 0)

    def test_incidence_rank_connected(self):
        # Triangle incidence: 3 edges, 3 nodes, rank 2 (V - components).
        rows = [[-1, 1, 0], [0, -1, 1], [-1, 0, 1]]
        self.assertEqual(sc._matrix_rank(rows, 3), 2)

    def test_zero_rows_do_not_add_rank(self):
        rows = [[0, 0], [0, 0]]
        self.assertEqual(sc._matrix_rank(rows, 2), 0)


class TestSheafH1(unittest.TestCase):
    # ---- AC-2: empty graph -> H1 = 0 ----
    def test_empty_graph_h1_zero(self):
        result = sc.compute_sheaf_h1([], [])
        self.assertEqual(result["h1_dim"], 0)
        self.assertEqual(result["h1_structural"], 0)
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["edge_count"], 0)
        self.assertEqual(result["inconsistency_nodes"], [])
        self.assertIn("computation_ms", result)

    def test_nodes_no_edges_h1_zero(self):
        nodes = [
            {"record_id": "ENC-TSK-001", "status": "open"},
            {"record_id": "ENC-TSK-002", "status": "closed"},
        ]
        result = sc.compute_sheaf_h1(nodes, [])
        self.assertEqual(result["h1_dim"], 0)

    # ---- AC-3: planted inconsistency -> H1 >= 1 ----
    def test_planted_inconsistency_h1_at_least_one(self):
        nodes = [
            {"record_id": "ENC-TSK-100", "status": "open"},
            {"record_id": "ENC-TSK-101", "status": "closed"},
        ]
        edges = [{"start": "ENC-TSK-100", "end": "ENC-TSK-101", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertGreaterEqual(result["h1_dim"], 1)
        self.assertEqual(result["h1_structural"], 1)
        self.assertEqual(
            result["inconsistency_nodes"], ["ENC-TSK-100", "ENC-TSK-101"]
        )
        self.assertEqual(len(result["inconsistency_edges"]), 1)

    def test_consistent_edge_h1_zero(self):
        # Two records with the SAME status linked by RELATED_TO: a consistent
        # tree edge contributes to rank, leaving H1 = 0 (no inconsistency).
        nodes = [
            {"record_id": "ENC-TSK-200", "status": "open"},
            {"record_id": "ENC-TSK-201", "status": "open"},
        ]
        edges = [{"start": "ENC-TSK-200", "end": "ENC-TSK-201", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["h1_dim"], 0)
        self.assertEqual(result["inconsistency_nodes"], [])

    def test_stalk_dimension_scales_h1(self):
        # R^d stalks: a single inconsistent edge yields H1 = d.
        nodes = [
            {"record_id": "ENC-TSK-300", "status": "open"},
            {"record_id": "ENC-TSK-301", "status": "closed"},
        ]
        edges = [{"start": "ENC-TSK-300", "end": "ENC-TSK-301", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges, embedding_dim=4)
        self.assertEqual(result["embedding_dim"], 4)
        self.assertEqual(result["h1_dim"], 4)

    def test_embedding_dim_inferred_from_node_vectors(self):
        nodes = [
            {"record_id": "ENC-TSK-400", "status": "open", "embedding": [0.1, 0.2, 0.3]},
            {"record_id": "ENC-TSK-401", "status": "closed", "embedding": [0.4, 0.5, 0.6]},
        ]
        edges = [{"start": "ENC-TSK-400", "end": "ENC-TSK-401", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["embedding_dim"], 3)
        self.assertEqual(result["h1_dim"], 3)

    def test_consistent_cycle_is_topological_not_inconsistency(self):
        # A triangle of mutually-consistent records has betti_1 = 1 (a topological
        # loop) but no flagged inconsistency nodes.
        nodes = [
            {"record_id": "A", "status": "open"},
            {"record_id": "B", "status": "open"},
            {"record_id": "C", "status": "open"},
        ]
        edges = [
            {"start": "A", "end": "B", "type": "RELATED_TO"},
            {"start": "B", "end": "C", "type": "RELATED_TO"},
            {"start": "A", "end": "C", "type": "RELATED_TO"},
        ]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["betti_1"], 1)
        self.assertEqual(result["h1_structural"], 1)
        self.assertEqual(result["inconsistency_nodes"], [])

    def test_self_loop_skipped(self):
        nodes = [{"record_id": "ENC-TSK-500", "status": "open"}]
        edges = [{"start": "ENC-TSK-500", "end": "ENC-TSK-500", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["edge_count"], 0)
        self.assertEqual(result["h1_dim"], 0)

    def test_edge_to_unknown_node_ignored(self):
        nodes = [{"record_id": "ENC-TSK-600", "status": "open"}]
        edges = [{"start": "ENC-TSK-600", "end": "ENC-TSK-999", "type": "RELATED_TO"}]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["edge_count"], 0)
        self.assertEqual(result["h1_dim"], 0)

    def test_duplicate_undirected_edges_deduped(self):
        nodes = [
            {"record_id": "X", "status": "open"},
            {"record_id": "Y", "status": "closed"},
        ]
        edges = [
            {"start": "X", "end": "Y", "type": "RELATED_TO"},
            {"start": "Y", "end": "X", "type": "RELATED_TO"},
        ]
        result = sc.compute_sheaf_h1(nodes, edges)
        self.assertEqual(result["edge_count"], 1)
        self.assertEqual(result["h1_structural"], 1)


if __name__ == "__main__":
    unittest.main()
