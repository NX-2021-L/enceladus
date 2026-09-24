#!/usr/bin/env python3
"""Unit tests for ENC-TSK-I05 duplicate-cluster detection (tools/dedup_cluster_i05.py).

stdlib unittest (NOT pytest), matching test_correlation_analysis_h91. Synthetic
in-memory data only — no network, no S3, no live corpus. Exercises:
  * the same-type same-project >= threshold edge rule (incl. the >= boundary),
  * union-find connected components (transitivity, singleton exclusion),
  * deterministic canonical selection across every signal level + tiebreak,
  * the ranking-signal helpers (lifecycle/age/evidence/inbound),
  * the cluster + summary shape and clusters.jsonl roundtrip,
  * the H91 pairs.jsonl reuse path,
  * the pure-Python (numpy-absent) graph path.
"""

import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dedup_cluster_i05 as dc  # noqa: E402


def _node(rid, vec, rtype="issue", project="enceladus"):
    return {
        "record_id": rid,
        "record_type": rtype,
        "project_id": project,
        dc.EMBEDDING_PROPERTY: list(vec),
    }


# ===========================================================================
# GRAPH layer — same-type same-project >= threshold edges
# ===========================================================================
class SimilarityEdgeTest(unittest.TestCase):
    def test_same_type_near_identical_makes_edge(self):
        nodes = [_node("ENC-ISS-A", [1.0, 0.0, 0.0]), _node("ENC-ISS-B", [1.0, 0.0001, 0.0])]
        edges = dc.similarity_edges(nodes, threshold=0.95)
        self.assertEqual(len(edges), 1)
        self.assertEqual({edges[0]["a"], edges[0]["b"]}, {"ENC-ISS-A", "ENC-ISS-B"})
        self.assertEqual(edges[0]["record_type"], "issue")
        self.assertGreaterEqual(edges[0]["cosine"], 0.95)

    def test_cross_type_identical_vectors_no_edge(self):
        # Identical embeddings but different record_type -> never an edge.
        nodes = [_node("ENC-ISS-A", [1.0, 2.0, 3.0], "issue"),
                 _node("ENC-TSK-B", [1.0, 2.0, 3.0], "task")]
        self.assertEqual(dc.similarity_edges(nodes, threshold=0.95), [])

    def test_cross_project_identical_vectors_no_edge(self):
        nodes = [_node("ENC-ISS-A", [1.0, 2.0, 3.0], "issue", project="enceladus"),
                 _node("ENC-ISS-B", [1.0, 2.0, 3.0], "issue", project="harrisonfamily")]
        self.assertEqual(dc.similarity_edges(nodes, threshold=0.95), [])

    def test_identical_vectors_flag_at_threshold(self):
        # Identical embeddings -> cosine ~1.0, comfortably flagged at 0.95.
        # (Exact >=-boundary inclusivity is asserted deterministically in
        # EdgesFromPairsTest where the cosine is an explicit value, not a
        # float-normalized self-dot that lands at 0.9999999999999999.)
        nodes = [_node("ENC-ISS-A", [2.0, 1.0]), _node("ENC-ISS-B", [2.0, 1.0])]
        edges = dc.similarity_edges(nodes, threshold=0.95)
        self.assertEqual(len(edges), 1)
        self.assertAlmostEqual(edges[0]["cosine"], 1.0, places=9)

    def test_below_threshold_excluded(self):
        nodes = [_node("ENC-ISS-A", [1.0, 0.0]), _node("ENC-ISS-B", [0.0, 1.0])]
        self.assertEqual(dc.similarity_edges(nodes, threshold=0.95), [])

    def test_edge_orientation_is_stable(self):
        # 'a' is always the lexicographically smaller id regardless of input order.
        nodes = [_node("ENC-ISS-Z", [1.0, 1.0]), _node("ENC-ISS-A", [1.0, 1.0])]
        edges = dc.similarity_edges(nodes, threshold=0.5)
        self.assertEqual(edges[0]["a"], "ENC-ISS-A")
        self.assertEqual(edges[0]["b"], "ENC-ISS-Z")

    def test_zero_norm_vector_never_edges(self):
        nodes = [_node("ZERO", [0.0, 0.0]), _node("ENC-ISS-A", [1.0, 0.0]),
                 _node("ENC-ISS-B", [1.0, 0.0])]
        edges = dc.similarity_edges(nodes, threshold=0.5)
        self.assertEqual(len(edges), 1)
        self.assertNotIn("ZERO", {edges[0]["a"], edges[0]["b"]})


# ===========================================================================
# COMPONENTS layer — union-find
# ===========================================================================
class ConnectedComponentsTest(unittest.TestCase):
    def test_chain_collapses_to_one_cluster(self):
        # A-B and B-C edges (no A-C edge) still form a single component {A,B,C}.
        edges = [{"a": "A", "b": "B", "cosine": 0.99},
                 {"a": "B", "b": "C", "cosine": 0.98}]
        comps = dc.connected_components(edges)
        self.assertEqual(comps, [["A", "B", "C"]])

    def test_disjoint_components(self):
        edges = [{"a": "A", "b": "B", "cosine": 0.99},
                 {"a": "X", "b": "Y", "cosine": 0.97},
                 {"a": "Y", "b": "Z", "cosine": 0.96}]
        comps = dc.connected_components(edges)
        # Sorted by size desc then smallest member: {X,Y,Z} before {A,B}.
        self.assertEqual(comps, [["X", "Y", "Z"], ["A", "B"]])

    def test_singletons_excluded(self):
        # A node never appears unless it has at least one edge; a lone edge pair
        # is size 2 (kept), but there are no size-1 components by construction.
        edges = [{"a": "A", "b": "B", "cosine": 0.99}]
        comps = dc.connected_components(edges)
        self.assertEqual(comps, [["A", "B"]])

    def test_no_edges_no_clusters(self):
        self.assertEqual(dc.connected_components([]), [])

    def test_members_sorted_ascending(self):
        edges = [{"a": "C", "b": "A", "cosine": 0.99}, {"a": "B", "b": "C", "cosine": 0.99}]
        self.assertEqual(dc.connected_components(edges), [["A", "B", "C"]])


# ===========================================================================
# CANONICAL selection — argmax over evidence > inbound > lifecycle > age > id
# ===========================================================================
class CanonicalSelectionTest(unittest.TestCase):
    def test_evidence_dominates(self):
        meta = {
            "A": {"evidence_score": 1.0, "inbound_edges": 99, "status": "open", "created_at": "2020-01-01T00:00:00Z"},
            "B": {"evidence_score": 5.0, "inbound_edges": 0, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
        }
        canonical, rationale = dc.select_canonical(["A", "B"], meta)
        self.assertEqual(canonical, "B")
        self.assertEqual(rationale["tiebreak"], "evidence")

    def test_inbound_breaks_evidence_tie(self):
        meta = {
            "A": {"evidence_score": 2.0, "inbound_edges": 1, "status": "closed", "created_at": "2020-01-01T00:00:00Z"},
            "B": {"evidence_score": 2.0, "inbound_edges": 7, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
        }
        canonical, rationale = dc.select_canonical(["A", "B"], meta)
        self.assertEqual(canonical, "B")
        self.assertEqual(rationale["tiebreak"], "inbound_edges")

    def test_lifecycle_breaks_evidence_and_inbound_tie(self):
        meta = {
            "A": {"evidence_score": 2.0, "inbound_edges": 3, "status": "open", "created_at": "2020-01-01T00:00:00Z"},
            "B": {"evidence_score": 2.0, "inbound_edges": 3, "status": "closed", "created_at": "2026-01-01T00:00:00Z"},
        }
        canonical, rationale = dc.select_canonical(["A", "B"], meta)
        self.assertEqual(canonical, "B")
        self.assertEqual(rationale["tiebreak"], "lifecycle")

    def test_age_breaks_remaining_tie_oldest_wins(self):
        meta = {
            "NEW": {"evidence_score": 2.0, "inbound_edges": 3, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
            "OLD": {"evidence_score": 2.0, "inbound_edges": 3, "status": "open", "created_at": "2020-01-01T00:00:00Z"},
        }
        canonical, rationale = dc.select_canonical(["NEW", "OLD"], meta)
        self.assertEqual(canonical, "OLD")
        self.assertEqual(rationale["tiebreak"], "age")

    def test_record_id_is_final_deterministic_tiebreak(self):
        # Fully-tied signals -> smallest record_id wins, deterministically.
        meta = {
            "ENC-ISS-ZZZ": {"evidence_score": 1.0, "inbound_edges": 1, "status": "open", "created_at": "2025-01-01T00:00:00Z"},
            "ENC-ISS-AAA": {"evidence_score": 1.0, "inbound_edges": 1, "status": "open", "created_at": "2025-01-01T00:00:00Z"},
        }
        canonical, rationale = dc.select_canonical(["ENC-ISS-ZZZ", "ENC-ISS-AAA"], meta)
        self.assertEqual(canonical, "ENC-ISS-AAA")
        self.assertEqual(rationale["tiebreak"], "record_id")

    def test_no_metadata_falls_back_to_record_id(self):
        canonical, rationale = dc.select_canonical(["ENC-ISS-B", "ENC-ISS-A", "ENC-ISS-C"], None)
        self.assertEqual(canonical, "ENC-ISS-A")
        self.assertFalse(rationale["has_metadata"])

    def test_selection_is_order_independent(self):
        meta = {
            "A": {"evidence_score": 1.0, "inbound_edges": 0, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
            "B": {"evidence_score": 9.0, "inbound_edges": 0, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
            "C": {"evidence_score": 3.0, "inbound_edges": 0, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
        }
        for order in (["A", "B", "C"], ["C", "B", "A"], ["B", "A", "C"]):
            self.assertEqual(dc.select_canonical(order, meta)[0], "B")

    def test_empty_member_list_raises(self):
        with self.assertRaises(ValueError):
            dc.select_canonical([], {})


# ===========================================================================
# Ranking-signal helpers
# ===========================================================================
class RankingHelperTest(unittest.TestCase):
    def test_lifecycle_rank_ordering(self):
        self.assertGreater(dc._lifecycle_rank("closed"), dc._lifecycle_rank("open"))
        self.assertGreater(dc._lifecycle_rank("merged-main"), dc._lifecycle_rank("in-progress"))
        self.assertEqual(dc._lifecycle_rank("CLOSED"), dc._lifecycle_rank("closed"))
        self.assertEqual(dc._lifecycle_rank("nonsense-status"), 0)
        self.assertEqual(dc._lifecycle_rank(None), 0)

    def test_age_epoch_older_is_smaller(self):
        self.assertLess(dc._age_epoch("2020-01-01T00:00:00Z"), dc._age_epoch("2026-01-01T00:00:00Z"))

    def test_age_epoch_handles_z_and_offset(self):
        self.assertAlmostEqual(
            dc._age_epoch("2026-01-01T00:00:00Z"),
            dc._age_epoch("2026-01-01T00:00:00+00:00"),
            places=6,
        )

    def test_age_epoch_missing_is_infinity(self):
        self.assertEqual(dc._age_epoch(None), math.inf)
        self.assertEqual(dc._age_epoch(""), math.inf)
        self.assertEqual(dc._age_epoch("not-a-date"), math.inf)

    def test_derive_evidence_score_weights(self):
        rec = {
            "acceptance_criteria": [
                {"evidence_acceptance": True, "evidence": "x"},   # +3
                {"evidence_acceptance": False, "evidence": "y"},  # +1
                {"evidence_acceptance": False, "evidence": ""},   # +0
                "legacy-string-criterion",                         # +0
            ],
            "resolution": "fixed in PR #1",                        # +2
            "description": "a description",                        # +0.5
        }
        self.assertAlmostEqual(dc.derive_evidence_score(rec), 6.5, places=9)

    def test_derive_evidence_score_empty(self):
        self.assertEqual(dc.derive_evidence_score({}), 0.0)

    def test_inbound_edges_counts_only_inbound(self):
        payload = {"edges": [
            {"source": "X", "target": "ME"},     # inbound -> +1
            {"from": "Y", "to": "ME"},            # inbound (alt keys) -> +1
            {"source": "ME", "target": "Z"},      # outbound -> 0
            {"source": "ME", "target": "ME"},     # self -> 0
            {"source": "W", "target": "OTHER"},   # unrelated -> 0
        ]}
        self.assertEqual(dc.inbound_edges_from_neighbors(payload, "ME"), 2)

    def test_inbound_edges_node_object_endpoints(self):
        payload = {"edges": [{"source": {"record_id": "X"}, "target": {"record_id": "ME"}}]}
        self.assertEqual(dc.inbound_edges_from_neighbors(payload, "ME"), 1)

    def test_inbound_edges_tolerates_garbage(self):
        self.assertEqual(dc.inbound_edges_from_neighbors(None, "ME"), 0)
        self.assertEqual(dc.inbound_edges_from_neighbors({}, "ME"), 0)
        self.assertEqual(dc.inbound_edges_from_neighbors({"edges": "nope"}, "ME"), 0)
        self.assertEqual(dc.inbound_edges_from_neighbors('{"edges":[]}', "ME"), 0)


# ===========================================================================
# Assembly — build_clusters end to end
# ===========================================================================
class BuildClustersTest(unittest.TestCase):
    def _corpus(self):
        # Two issue duplicates (A,B) + one unrelated issue (C) + a task pair
        # (T1,T2) that must NOT merge with the issues despite identical vectors.
        return [
            _node("ENC-ISS-A", [1.0, 0.0, 0.0], "issue"),
            _node("ENC-ISS-B", [1.0, 0.0005, 0.0], "issue"),
            _node("ENC-ISS-C", [0.0, 1.0, 0.0], "issue"),
            _node("ENC-TSK-T1", [1.0, 0.0, 0.0], "task"),
            _node("ENC-TSK-T2", [1.0, 0.0, 0.0], "task"),
        ]

    def test_clusters_partition_by_type(self):
        clusters, stats = dc.build_clusters(self._corpus(), threshold=0.95)
        self.assertEqual(stats["num_clusters"], 2)
        by_members = {tuple(c["members"]): c for c in clusters}
        self.assertIn(("ENC-ISS-A", "ENC-ISS-B"), by_members)
        self.assertIn(("ENC-TSK-T1", "ENC-TSK-T2"), by_members)
        # C is a singleton (not a duplicate) -> excluded.
        self.assertNotIn("ENC-ISS-C", [m for c in clusters for m in c["members"]])

    def test_cluster_shape_and_canonical(self):
        meta = {
            "ENC-ISS-A": {"evidence_score": 5.0, "inbound_edges": 2, "status": "closed", "created_at": "2024-01-01T00:00:00Z"},
            "ENC-ISS-B": {"evidence_score": 1.0, "inbound_edges": 0, "status": "open", "created_at": "2026-01-01T00:00:00Z"},
        }
        clusters, _ = dc.build_clusters(self._corpus(), threshold=0.95, metadata=meta)
        iss = next(c for c in clusters if c["record_type"] == "issue")
        self.assertEqual(set(iss.keys()), {
            "cluster_id", "record_type", "project_id", "size", "members",
            "canonical", "duplicates", "canonical_rationale", "edges",
            "max_cosine", "min_cosine", "mean_cosine",
        })
        self.assertEqual(iss["canonical"], "ENC-ISS-A")
        self.assertEqual(iss["duplicates"], ["ENC-ISS-B"])
        self.assertEqual(iss["project_id"], "enceladus")
        self.assertTrue(iss["cluster_id"].startswith(dc._CLUSTER_ID_PREFIX))
        self.assertEqual(len(iss["edges"]), 1)
        self.assertGreaterEqual(iss["max_cosine"], 0.95)

    def test_summary_stats_keys(self):
        clusters, stats = dc.build_clusters(self._corpus(), threshold=0.95,
                                            generated_at="2026-06-25T00:00:00Z")
        for key in ("corpus_size", "embedding_dim", "threshold", "num_edges",
                    "num_clusters", "num_records_in_clusters", "largest_cluster_size",
                    "cluster_size_histogram", "by_type", "metadata_coverage",
                    "generated_at"):
            self.assertIn(key, stats)
        self.assertEqual(stats["corpus_size"], 5)
        self.assertEqual(stats["embedding_dim"], 3)
        self.assertEqual(stats["generated_at"], "2026-06-25T00:00:00Z")
        self.assertEqual(stats["largest_cluster_size"], 2)
        self.assertEqual(stats["by_type"]["issue"]["clusters"], 1)

    def test_metadata_coverage_reported(self):
        meta = {"ENC-ISS-A": {"status": "closed", "created_at": "2024-01-01T00:00:00Z"}}
        _, stats = dc.build_clusters(self._corpus(), threshold=0.95, metadata=meta)
        cov = stats["metadata_coverage"]
        self.assertTrue(cov["metadata_supplied"])
        self.assertEqual(cov["records_with_metadata"], 1)

    def test_empty_corpus(self):
        clusters, stats = dc.build_clusters([], threshold=0.95)
        self.assertEqual(clusters, [])
        self.assertEqual(stats["num_clusters"], 0)
        self.assertEqual(stats["largest_cluster_size"], 0)


# ===========================================================================
# pairs.jsonl reuse path
# ===========================================================================
class EdgesFromPairsTest(unittest.TestCase):
    def test_same_type_pairs_kept_cross_type_dropped(self):
        pairs = [
            {"a": "ENC-ISS-A", "b": "ENC-ISS-B", "a_type": "issue", "b_type": "issue", "cosine": 0.99},
            {"a": "ENC-ISS-D", "b": "ENC-TSK-E", "a_type": "issue", "b_type": "task", "cosine": 0.999},
            {"a": "ENC-ISS-F", "b": "ENC-ISS-G", "a_type": "issue", "b_type": "issue", "cosine": 0.80},
        ]
        edges = dc.edges_from_pairs(pairs, threshold=0.95)
        self.assertEqual(len(edges), 1)
        self.assertEqual({edges[0]["a"], edges[0]["b"]}, {"ENC-ISS-A", "ENC-ISS-B"})

    def test_threshold_inclusive_at_exact_boundary(self):
        # cosine == threshold must be KEPT (>=); a strict-> rule would drop it.
        pairs = [{"a": "ENC-ISS-A", "b": "ENC-ISS-B", "a_type": "issue",
                  "b_type": "issue", "cosine": 0.95}]
        self.assertEqual(len(dc.edges_from_pairs(pairs, threshold=0.95)), 1)
        # And just below the boundary is dropped.
        pairs_below = [{"a": "ENC-ISS-A", "b": "ENC-ISS-B", "a_type": "issue",
                        "b_type": "issue", "cosine": 0.9499999}]
        self.assertEqual(dc.edges_from_pairs(pairs_below, threshold=0.95), [])

    def test_build_clusters_from_precomputed_edges(self):
        pairs = [
            {"a": "ENC-ISS-A", "b": "ENC-ISS-B", "a_type": "issue", "b_type": "issue", "cosine": 0.999},
            {"a": "ENC-ISS-B", "b": "ENC-ISS-C", "a_type": "issue", "b_type": "issue", "cosine": 0.998},
        ]
        edges = dc.edges_from_pairs(pairs, threshold=0.95)
        clusters, stats = dc.build_clusters(None, threshold=0.95, precomputed_edges=edges)
        self.assertEqual(stats["num_clusters"], 1)
        self.assertEqual(clusters[0]["members"], ["ENC-ISS-A", "ENC-ISS-B", "ENC-ISS-C"])
        self.assertIsNone(stats["corpus_size"])  # no corpus was read


# ===========================================================================
# SINK shape
# ===========================================================================
class SinkTest(unittest.TestCase):
    def test_clusters_to_jsonl_roundtrip(self):
        clusters = [{"cluster_id": "i05-cluster-0001", "members": ["A", "B"], "canonical": "A"}]
        text = dc._clusters_to_jsonl(clusters)
        lines = [ln for ln in text.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), clusters[0])

    def test_write_results_emits_local_files(self):
        clusters = [{"cluster_id": "i05-cluster-0001", "record_type": "issue",
                     "members": ["A", "B"], "canonical": "A", "size": 2}]
        stats = {"num_clusters": 1, "generated_at": None}
        with tempfile.TemporaryDirectory() as tmp:
            args = dc.build_parser().parse_args(["--out", tmp])
            summary = dc.write_results(clusters, stats, args)
            self.assertTrue((Path(tmp) / dc.CLUSTERS_FILENAME).exists())
            self.assertTrue((Path(tmp) / dc.SUMMARY_FILENAME).exists())
            self.assertIn("artifacts", summary)
            self.assertEqual(summary["artifacts"]["clusters_local"],
                             str(Path(tmp) / dc.CLUSTERS_FILENAME))


# ===========================================================================
# Pure-Python (numpy-absent) graph path
# ===========================================================================
class PurePythonPathTest(unittest.TestCase):
    def setUp(self):
        self._saved_np = dc.np
        dc.np = None  # type: ignore[assignment]

    def tearDown(self):
        dc.np = self._saved_np  # type: ignore[assignment]

    def test_edges_without_numpy(self):
        self.assertIsNone(dc.np)
        nodes = [_node("ENC-ISS-A", [1.0, 0.0, 0.0]), _node("ENC-ISS-B", [1.0, 0.0001, 0.0]),
                 _node("ENC-ISS-C", [0.0, 1.0, 0.0])]
        edges = dc.similarity_edges(nodes, threshold=0.95)
        self.assertEqual(len(edges), 1)
        self.assertEqual({edges[0]["a"], edges[0]["b"]}, {"ENC-ISS-A", "ENC-ISS-B"})

    def test_build_clusters_without_numpy(self):
        self.assertIsNone(dc.np)
        nodes = [_node("ENC-ISS-A", [1.0, 0.0]), _node("ENC-ISS-B", [1.0, 0.0]),
                 _node("ENC-ISS-C", [1.0, 0.0])]
        clusters, stats = dc.build_clusters(nodes, threshold=0.95)
        self.assertEqual(stats["num_clusters"], 1)
        self.assertEqual(clusters[0]["members"], ["ENC-ISS-A", "ENC-ISS-B", "ENC-ISS-C"])


# ===========================================================================
# DSU internals
# ===========================================================================
class DSUTest(unittest.TestCase):
    def test_union_find_basic(self):
        dsu = dc._DSU()
        dsu.union("A", "B")
        dsu.union("B", "C")
        self.assertEqual(dsu.find("A"), dsu.find("C"))
        dsu.union("X", "Y")
        self.assertNotEqual(dsu.find("A"), dsu.find("X"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
