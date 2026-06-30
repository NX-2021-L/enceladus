"""ENC-FTR-087 Phase 1 tests — Wave-Close Drift Telemetry.

Pure unit tests; no live AWS. The DynamoDB client is a capturing fake so the
wave-close emission path is fully exercised offline. Covers task ACs:

  AC-1  d_centroid_L2 computed and written on every wave-close event.
  AC-2  d_spectral(H,V;k=3) computed via Fiedler subspaces (graph_laplacian hook
        + inline fallback) and written alongside d_centroid in the same record.
  AC-4  3 synthetic wave-close events -> 3 records, distinct wave_ids, monotonic
        timestamps.
  AC-5  spurious_attractor_rate + re_traversal_rate present as null stubs.
"""

import math
import unittest

import drift_telemetry as dt


class FakeDDB:
    """Captures put_item calls in order."""

    def __init__(self):
        self.items = []

    def put_item(self, TableName, Item):  # noqa: N803 — boto3 kwarg names
        self.items.append({"TableName": TableName, "Item": Item})


class TestCentroidDrift(unittest.TestCase):
    def test_centroid_mean(self):
        self.assertEqual(dt.compute_centroid([[0.0, 0.0], [2.0, 4.0]]), [1.0, 2.0])

    def test_l2_distance(self):
        self.assertAlmostEqual(dt.l2_distance([0.0, 0.0], [3.0, 4.0]), 5.0)

    def test_d_centroid_l2(self):
        h = [[1.0, 0.0], [1.0, 0.0]]   # centroid (1, 0)
        v = [[0.0, 0.0], [0.0, 0.0]]   # centroid (0, 0)
        self.assertAlmostEqual(dt.d_centroid_l2(h, v), 1.0)

    def test_identical_sets_zero_drift(self):
        s = [[0.5, 0.5, 0.5], [0.1, 0.2, 0.3]]
        self.assertAlmostEqual(dt.d_centroid_l2(s, s), 0.0)

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            dt.compute_centroid([])


class TestSpectralDrift(unittest.TestCase):
    def _path_graph(self, n):
        a = [[0.0] * n for _ in range(n)]
        for i in range(n - 1):
            a[i][i + 1] = a[i + 1][i] = 1.0
        return a

    def test_jacobi_matches_known_eigvals(self):
        # [[2,0],[0,5]] -> eigenvalues 2,5; eigenvectors axis-aligned.
        vals, _vecs = dt.jacobi_eigh([[2.0, 0.0], [0.0, 5.0]])
        self.assertAlmostEqual(vals[0], 2.0)
        self.assertAlmostEqual(vals[1], 5.0)

    def test_fiedler_subspace_orthonormal(self):
        cols = dt.fiedler_subspace(self._path_graph(5), k=3)
        self.assertEqual(len(cols), 3)
        for c in cols:
            self.assertAlmostEqual(math.sqrt(sum(x * x for x in c)), 1.0, places=6)

    def test_identical_graphs_zero_spectral(self):
        g = self._path_graph(6)
        d = dt.d_spectral(k=3, h_adjacency=g, v_adjacency=g)
        self.assertAlmostEqual(d, 0.0, places=6)

    def test_different_graphs_positive_spectral(self):
        path = self._path_graph(6)
        ring = self._path_graph(6)
        ring[0][5] = ring[5][0] = 1.0  # close the ring -> different topology
        d = dt.d_spectral(k=3, h_adjacency=path, v_adjacency=ring)
        self.assertGreater(d, 0.0)
        # Chordal distance over a rank-3 subspace is bounded by sqrt(3).
        self.assertLessEqual(d, math.sqrt(3) + 1e-9)

    def test_graph_laplacian_hook_is_used(self):
        """AC-2: d_spectral routes through the injected tracker.graph_laplacian
        hook when provided (ENC-FTR-088 accessor)."""
        calls = []

        def fake_laplacian(adjacency, k):
            calls.append((len(adjacency), k))
            return dt.fiedler_subspace(adjacency, k)

        g = self._path_graph(5)
        dt.d_spectral(k=3, h_adjacency=g, v_adjacency=g, laplacian_fn=fake_laplacian)
        self.assertEqual(len(calls), 2)  # invoked for H and V
        self.assertEqual(calls[0], (5, 3))


class TestRecordSchema(unittest.TestCase):
    def test_null_stubs_present(self):
        rec = dt.build_drift_record(
            wave_id="w1", project_id="enceladus",
            d_centroid_L2=0.4, d_spectral_value=0.2,
        )
        # AC-5: FTR-105 wiring slots default to null stubs.
        self.assertIsNone(rec["spurious_attractor_rate"])
        self.assertIsNone(rec["re_traversal_rate"])
        self.assertEqual(rec["schema"], dt.DRIFT_TELEMETRY_SCHEMA)
        self.assertEqual(rec["d_spectral_k"], 3)

    def test_ddb_marshalling(self):
        rec = dt.build_drift_record(
            wave_id="w1", project_id="enceladus",
            d_centroid_L2=0.4, d_spectral_value=None,
        )
        item = dt.to_ddb_item(rec)
        self.assertEqual(item["wave_id"], {"S": "w1"})
        self.assertEqual(item["d_centroid_L2"], {"N": repr(0.4)})
        # null metric + null stubs marshal to DynamoDB NULL.
        self.assertEqual(item["d_spectral"], {"NULL": True})
        self.assertEqual(item["spurious_attractor_rate"], {"NULL": True})


class TestThreeSyntheticWaveCloses(unittest.TestCase):
    """AC-1 + AC-2 + AC-4 + AC-5 end-to-end against a capturing fake DDB."""

    def _graph(self, n, extra_edge=None):
        a = [[0.0] * n for _ in range(n)]
        for i in range(n - 1):
            a[i][i + 1] = a[i + 1][i] = 1.0
        if extra_edge:
            i, j = extra_edge
            a[i][j] = a[j][i] = 1.0
        return a

    def test_three_waves_distinct_and_monotonic(self):
        ddb = FakeDDB()
        table = "enceladus-drift-telemetry-gamma"
        base = self._graph(6)
        for n in range(3):
            dt.compute_and_emit_wave_close_drift(
                ddb_client=ddb,
                table_name=table,
                project_id="enceladus",
                wave_id=f"wave-{n}",
                prev_wave_id=f"wave-{n - 1}" if n else None,
                h_embeddings=[[float(n), 0.0, 0.0], [float(n) + 1, 0.0, 0.0]],
                v_embeddings=[[0.0, 0.0, 0.0], [1.0, 0.0, 0.0]],
                h_adjacency=self._graph(6, extra_edge=(0, n + 2)),
                v_adjacency=base,
            )

        self.assertEqual(len(ddb.items), 3)
        wave_ids = [it["Item"]["wave_id"]["S"] for it in ddb.items]
        self.assertEqual(wave_ids, ["wave-0", "wave-1", "wave-2"])
        self.assertEqual(len(set(wave_ids)), 3)  # AC-4 distinct wave_ids

        timestamps = [it["Item"]["timestamp"]["S"] for it in ddb.items]
        self.assertEqual(timestamps, sorted(timestamps))  # AC-4 monotonic
        self.assertEqual(len(set(timestamps)), 3)          # strictly increasing

        for it in ddb.items:
            item = it["Item"]
            self.assertEqual(it["TableName"], table)
            self.assertIn("d_centroid_L2", item)            # AC-1 written
            self.assertEqual(set(item["d_centroid_L2"]), {"N"})
            self.assertIn("d_spectral", item)               # AC-2 written
            self.assertEqual(set(item["d_spectral"]), {"N"})
            self.assertEqual(item["project_id"], {"S": "enceladus"})
            # AC-5 null stubs persisted.
            self.assertEqual(item["spurious_attractor_rate"], {"NULL": True})
            self.assertEqual(item["re_traversal_rate"], {"NULL": True})

    def test_centroid_only_when_no_graph(self):
        ddb = FakeDDB()
        dt.compute_and_emit_wave_close_drift(
            ddb_client=ddb, table_name="t", project_id="enceladus", wave_id="w",
            h_embeddings=[[1.0, 1.0]], v_embeddings=[[0.0, 0.0]],
        )
        item = ddb.items[0]["Item"]
        self.assertEqual(set(item["d_centroid_L2"]), {"N"})   # centroid shipped
        self.assertEqual(item["d_spectral"], {"NULL": True})  # spectral deferred


if __name__ == "__main__":
    unittest.main()
