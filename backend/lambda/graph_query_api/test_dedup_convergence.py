"""Unit tests for ENC-TSK-I10 (Dedup P6) convergence-probe math.

Exercises the pure convergence functions (DOC-DF651F07D5C2 §10) without Neo4j or
AWS, plus compute_graph_signals against a fake driver:
  - stock pairing + orientation-stable dedupe
  - percolation: connected components / LCC (→ 1 at convergence) / cluster count
  - flow: new-pair-per-window accounting
  - precision@1 recovery proxy
  - walk-back model-health loop + (1 - floor) breach predicate
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dedup_convergence as dc  # noqa: E402


class PairAndComponentTests(unittest.TestCase):
    def test_normalize_pair_orientation_stable(self):
        self.assertEqual(dc.normalize_pair("enc-iss-2", "ENC-ISS-1"), ("ENC-ISS-1", "ENC-ISS-2"))
        self.assertEqual(dc.normalize_pair("ENC-ISS-1", "enc-iss-2"), ("ENC-ISS-1", "ENC-ISS-2"))

    def test_connected_components_includes_isolated_nodes(self):
        nodes = ["A", "B", "C", "D"]
        pairs = [("A", "B")]
        comps = dc.connected_components(nodes, pairs)
        sizes = sorted(len(c) for c in comps)
        self.assertEqual(sizes, [1, 1, 2])  # A-B cluster, plus isolated C, D
        self.assertEqual(dc.largest_component_size(comps), 2)
        self.assertEqual(dc.count_nontrivial_components(comps), 1)

    def test_lcc_chains_transitive_cluster(self):
        # A-B, B-C, C-D forms one 4-node cluster (order-free union).
        comps = dc.connected_components(["A", "B", "C", "D"], [("A", "B"), ("C", "B"), ("D", "C")])
        self.assertEqual(dc.largest_component_size(comps), 4)
        self.assertEqual(dc.count_nontrivial_components(comps), 1)

    def test_converged_corpus_lcc_is_one(self):
        # No duplicate edges => every record is its own size-1 component => LCC 1.
        comps = dc.connected_components(["A", "B", "C"], [])
        self.assertEqual(dc.largest_component_size(comps), 1)
        self.assertEqual(dc.count_nontrivial_components(comps), 0)

    def test_empty_corpus_lcc_is_zero(self):
        self.assertEqual(dc.largest_component_size(dc.connected_components([], [])), 0)


class PrecisionRecoveryTests(unittest.TestCase):
    def test_proxy_full_when_no_twins(self):
        self.assertEqual(dc.precision_recovery_proxy(10, 10), 1.0)

    def test_proxy_zero_when_all_have_twins(self):
        self.assertEqual(dc.precision_recovery_proxy(0, 10), 0.0)

    def test_proxy_empty_corpus(self):
        self.assertEqual(dc.precision_recovery_proxy(0, 0), 1.0)

    def test_recovery_fraction_band(self):
        self.assertAlmostEqual(dc.recovery_fraction(dc.PRECISION_AT_1_BASELINE), 0.0)
        self.assertAlmostEqual(dc.recovery_fraction(dc.RECALL_CEILING), 1.0)
        mid = (dc.PRECISION_AT_1_BASELINE + dc.RECALL_CEILING) / 2
        self.assertAlmostEqual(dc.recovery_fraction(mid), 0.5)
        self.assertEqual(dc.recovery_fraction(0.0), 0.0)   # clamped low
        self.assertEqual(dc.recovery_fraction(1.0), 1.0)   # clamped high


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 6, 28, tzinfo=timezone.utc)

    def test_counts_only_recent_pairs(self):
        recent = (self.now - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        old = (self.now - timedelta(days=30)).isoformat().replace("+00:00", "Z")
        self.assertEqual(dc.count_new_pairs([recent, old, recent], self.now, 7), 2)

    def test_unparseable_ts_excluded(self):
        self.assertEqual(dc.count_new_pairs(["not-a-date", None], self.now, 7), 0)

    def test_zero_window(self):
        recent = self.now.isoformat().replace("+00:00", "Z")
        self.assertEqual(dc.count_new_pairs([recent], self.now, 0), 0)


class WalkBackHealthTests(unittest.TestCase):
    def test_rate_zero_without_merges_is_shadow(self):
        h = dc.walk_back_health(0, 0)
        self.assertEqual(h["walk_back_rate"], 0.0)
        self.assertFalse(h["breached_floor"])
        self.assertEqual(h["recommended_mode"], "shadow")  # no evidence => shadow
        self.assertFalse(h["has_evidence"])

    def test_clean_merges_stay_live(self):
        h = dc.walk_back_health(1000, 0, precision_floor=0.999)
        self.assertEqual(h["walk_back_rate"], 0.0)
        self.assertFalse(h["breached_floor"])
        self.assertEqual(h["recommended_mode"], "live")

    def test_breach_reenters_shadow(self):
        # floor 0.999 => breach threshold 0.001; 2/1000 = 0.002 > 0.001.
        h = dc.walk_back_health(1000, 2, precision_floor=0.999)
        self.assertAlmostEqual(h["walk_back_rate"], 0.002)
        self.assertTrue(h["breached_floor"])
        self.assertEqual(h["recommended_mode"], "shadow")

    def test_breaches_floor_predicate(self):
        self.assertTrue(dc.breaches_floor(0.01, 0.999))
        self.assertFalse(dc.breaches_floor(0.0005, 0.999))
        self.assertFalse(dc.breaches_floor(0.001, 0.999))  # equal is not a breach


# --- compute_graph_signals against a fake neo4j driver ---------------------

class _FakeSession:
    def __init__(self, driver):
        self._driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **params):
        # Pairs query carries an index_name; node query does not.
        if "index_name" in params:
            label = self._driver.index_to_label.get(params["index_name"])
            return list(self._driver.pair_rows.get(label, []))
        # Node query: parse the backtick-quoted label out of the MATCH clause.
        label = None
        for lbl in self._driver.node_rows:
            if f"(n:`{lbl}`)" in cypher:
                label = lbl
                break
        return list(self._driver.node_rows.get(label, []))


class _FakeDriver:
    def __init__(self, node_rows, pair_rows, index_to_label):
        self.node_rows = node_rows
        self.pair_rows = pair_rows
        self.index_to_label = index_to_label

    def session(self):
        return _FakeSession(self)


class ComputeGraphSignalsTests(unittest.TestCase):
    def test_end_to_end_snapshot(self):
        now = datetime(2026, 6, 28, tzinfo=timezone.utc)
        recent = (now - timedelta(days=2)).isoformat().replace("+00:00", "Z")
        old = (now - timedelta(days=90)).isoformat().replace("+00:00", "Z")
        # Issue corpus: 3 records; A-B are duplicates (recent), C is alone.
        node_rows = {
            "Issue": [{"rid": "ENC-ISS-1"}, {"rid": "ENC-ISS-2"}, {"rid": "ENC-ISS-3"}],
            "Task": [{"rid": "ENC-TSK-1"}, {"rid": "ENC-TSK-2"}],
        }
        pair_rows = {
            # directed hits both ways collapse to one undirected pair
            "Issue": [
                {"a": "ENC-ISS-1", "b": "ENC-ISS-2", "score": 0.999, "a_ts": recent, "b_ts": old},
                {"a": "ENC-ISS-2", "b": "ENC-ISS-1", "score": 0.999, "a_ts": old, "b_ts": recent},
            ],
            "Task": [],  # below threshold / no dupes
        }
        index_to_label = {"governed_issue_embedding": "Issue", "governed_task_embedding": "Task"}
        # Only query the two labels we populated.
        indexes = {"Issue": "governed_issue_embedding", "Task": "governed_task_embedding"}
        driver = _FakeDriver(node_rows, pair_rows, index_to_label)

        s = dc.compute_graph_signals(
            driver, "enceladus", now=now, label_vector_indexes=indexes, flow_window_days=7
        )
        self.assertEqual(s["stock_pairs"], 1)
        self.assertEqual(s["stock_pairs_by_type"], {"Issue": 1})
        self.assertEqual(s["embedded_record_count"], 5)
        self.assertEqual(s["duplicate_node_count"], 2)
        self.assertEqual(s["records_without_twin"], 3)
        self.assertEqual(s["new_duplicate_pairs"], 1)  # newest endpoint is recent
        self.assertEqual(s["lcc_size"], 2)             # the A-B cluster
        self.assertEqual(s["nontrivial_component_count"], 1)
        self.assertAlmostEqual(s["precision_at_1_recovery_proxy"], 3 / 5)
        self.assertEqual(s["precision_at_1_baseline"], dc.PRECISION_AT_1_BASELINE)
        self.assertEqual(s["recall_ceiling"], dc.RECALL_CEILING)

    def test_converged_corpus(self):
        now = datetime(2026, 6, 28, tzinfo=timezone.utc)
        node_rows = {"Issue": [{"rid": "ENC-ISS-1"}, {"rid": "ENC-ISS-2"}]}
        pair_rows = {"Issue": []}
        driver = _FakeDriver(node_rows, pair_rows, {"governed_issue_embedding": "Issue"})
        s = dc.compute_graph_signals(
            driver, "enceladus", now=now, label_vector_indexes={"Issue": "governed_issue_embedding"}
        )
        self.assertEqual(s["stock_pairs"], 0)
        self.assertEqual(s["lcc_size"], 1)  # percolation -> 1
        self.assertEqual(s["nontrivial_component_count"], 0)
        self.assertEqual(s["precision_at_1_recovery_proxy"], 1.0)


if __name__ == "__main__":
    unittest.main()
