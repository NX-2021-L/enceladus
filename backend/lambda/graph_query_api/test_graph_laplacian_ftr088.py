"""Unit tests for ENC-TSK-I81 / ENC-FTR-088 graph_laplacian read action.

Exercises the pure spectral logic of _query_laplacian against a mocked Neo4j
driver (no live AuraDB / Bedrock). Validates the acceptance contract:

  - returns adjacency_csr + fiedler_vector + eigenvalues + vertex_map (AC-1)
  - scipy.sparse.linalg.eigsh drives the normal path (AC-2)
  - the client can reconstruct L = D - A from adjacency_csr + degrees (AC-3)
  - no new edge types are introduced; edge_type_filter validates against the
    existing _ALLOWED_EDGE_TYPES set (AC-4)
  - on a 10-node subgraph: len(fiedler_vector) == len(vertex_map) and
    eigenvalues[0] < 0.001 (AC-5), including the edge-sparse worst case that the
    combinatorial default is chosen to survive.
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class _FakeResult(list):
    """A neo4j-result stand-in: an iterable of dict rows (dict supports both
    rec["k"] and rec.get("k"), matching the handler's access pattern)."""


class _FakeSession:
    def __init__(self, vertices, edges):
        self._vertices = vertices
        self._edges = edges

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        if "AS rid" in cypher:
            ids = list(self._vertices)
            if "n.record_id IN $ids" in cypher and "ids" in params:
                wanted = set(params["ids"])
                ids = [v for v in ids if v in wanted]
            limit = params.get("limit")
            if isinstance(limit, int):
                ids = ids[:limit]
            return _FakeResult({"rid": v} for v in ids)
        if "AS s, b.record_id AS t" in cypher:
            id_set = set(params.get("ids", []))
            rows = []
            for s, t in self._edges:
                if s in id_set and t in id_set:
                    rows.append({"s": s, "t": t})
            return _FakeResult(rows)
        return _FakeResult()


class _FakeDriver:
    def __init__(self, vertices, edges):
        self._vertices = vertices
        self._edges = edges

    def session(self):
        return _FakeSession(self._vertices, self._edges)


def _decode_csr(adjacency_csr):
    import numpy as np
    from scipy.sparse import csr_matrix

    data = np.frombuffer(base64.b64decode(adjacency_csr["data_b64"]), dtype="<f4")
    indices = np.frombuffer(base64.b64decode(adjacency_csr["indices_b64"]), dtype="<i4")
    indptr = np.frombuffer(base64.b64decode(adjacency_csr["indptr_b64"]), dtype="<i4")
    shape = tuple(adjacency_csr["shape"])
    return csr_matrix((data, indices, indptr), shape=shape)


def _path_graph(n):
    """0-1-2-...-(n-1): connected, so the combinatorial/normalized Laplacian both
    have a single zero eigenvalue."""
    vertices = [f"ENC-TSK-{i:03d}" for i in range(n)]
    edges = [(vertices[i], vertices[i + 1]) for i in range(n - 1)]
    return vertices, edges


class TestGraphLaplacian(unittest.TestCase):
    def test_ten_node_subgraph_ac1_ac5(self):
        vertices, edges = _path_graph(10)
        driver = _FakeDriver(vertices, edges)
        result = lf._query_laplacian(
            driver, "enceladus", {"record_ids": ",".join(vertices), "k": "3"}
        )
        self.assertNotIn("error", result)
        # AC-1: all four payload keys present.
        for key in ("adjacency_csr", "fiedler_vector", "eigenvalues", "vertex_map"):
            self.assertIn(key, result)
        # AC-5: 10-node subgraph contract.
        self.assertEqual(len(result["vertex_map"]), 10)
        self.assertEqual(len(result["fiedler_vector"]), len(result["vertex_map"]))
        self.assertLess(result["eigenvalues"][0], 0.001)
        # AC-2: the mandated eigsh path drives a non-trivial subgraph.
        self.assertEqual(result["laplacian"]["eig_method"], "eigsh_SA")
        self.assertEqual(len(result["eigenvalues"]), 3)

    def test_reconstruct_combinatorial_laplacian_ac3(self):
        import numpy as np

        vertices, edges = _path_graph(10)
        driver = _FakeDriver(vertices, edges)
        result = lf._query_laplacian(driver, "enceladus", {"record_ids": ",".join(vertices)})

        adjacency = _decode_csr(result["adjacency_csr"]).toarray()
        # Symmetric binary adjacency with the expected number of undirected edges.
        self.assertTrue(np.allclose(adjacency, adjacency.T))
        self.assertEqual(int(adjacency.sum()) // 2, 9)

        degrees = np.array(result["degrees"])
        self.assertTrue(np.allclose(degrees, adjacency.sum(axis=1)))

        # L = D - A; the constant vector is in the null space (L @ 1 == 0).
        laplacian = np.diag(degrees) - adjacency
        self.assertTrue(np.allclose(laplacian @ np.ones(10), np.zeros(10), atol=1e-9))

    def test_normalized_normalization_connected(self):
        vertices, edges = _path_graph(10)
        driver = _FakeDriver(vertices, edges)
        result = lf._query_laplacian(
            driver,
            "enceladus",
            {"record_ids": ",".join(vertices), "normalization": "normalized"},
        )
        self.assertEqual(result["laplacian"]["normalization"], "normalized")
        # Connected graph -> single zero eigenvalue in the normalized spectrum too.
        self.assertLess(result["eigenvalues"][0], 0.001)
        self.assertEqual(len(result["fiedler_vector"]), 10)

    def test_combinatorial_survives_edgeless_subgraph_ac5(self):
        # The worst case the combinatorial default is chosen for: 10 vertices, no
        # induced edges. Combinatorial L = 0 -> all eigenvalues 0 -> AC-5 holds.
        vertices = [f"ENC-ISS-{i:03d}" for i in range(10)]
        driver = _FakeDriver(vertices, edges=[])
        result = lf._query_laplacian(driver, "enceladus", {"record_ids": ",".join(vertices)})
        self.assertNotIn("error", result)
        self.assertEqual(len(result["vertex_map"]), 10)
        self.assertLess(result["eigenvalues"][0], 0.001)
        self.assertEqual(result["laplacian"]["edge_count"], 0)
        # Edgeless L = 0 routes cleanly to dense eigh (no ARPACK zero-start).
        self.assertEqual(result["laplacian"]["eig_method"], "dense_eigh")

    def test_invalid_edge_type_filter_ac4(self):
        vertices, edges = _path_graph(4)
        driver = _FakeDriver(vertices, edges)
        result = lf._query_laplacian(
            driver,
            "enceladus",
            {"record_ids": ",".join(vertices), "edge_type_filter": "NOT_A_REAL_EDGE"},
        )
        self.assertIn("error", result)
        self.assertIn("Invalid edge_type_filter", result["error"])

    def test_valid_edge_type_filter_uses_existing_types(self):
        # CHILD_OF is an existing edge type — must validate without error.
        vertices, edges = _path_graph(6)
        driver = _FakeDriver(vertices, edges)
        result = lf._query_laplacian(
            driver,
            "enceladus",
            {"record_ids": ",".join(vertices), "edge_type_filter": "CHILD_OF,RELATED_TO"},
        )
        self.assertNotIn("error", result)
        self.assertEqual(result["laplacian"]["edge_type_filter"], ["CHILD_OF", "RELATED_TO"])

    def test_too_few_vertices_errors(self):
        driver = _FakeDriver(["ENC-TSK-001"], edges=[])
        result = lf._query_laplacian(driver, "enceladus", {"record_ids": "ENC-TSK-001"})
        self.assertIn("error", result)
        self.assertIn("at least 2 vertices", result["error"])


if __name__ == "__main__":
    unittest.main()
