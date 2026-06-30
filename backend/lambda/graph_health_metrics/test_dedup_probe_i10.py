"""Unit tests for ENC-TSK-I10 (Dedup P6) scheduled convergence probe.

Validates the graph_health_metrics dedup section without Neo4j/CloudWatch:
  - walk-back counter read sums datapoints and degrades to 0 on error
  - all five governed signals are published to DEDUP_NAMESPACE
  - the dedup probe is isolated: a dedup failure never breaks the base
    graph-health metrics path (handler still returns 200).
"""
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# The shared module is packaged in via .build_extras at deploy time; for local
# tests resolve it from its canonical owner (graph_query_api), appended LAST so
# it never shadows this dir's lambda_function.
sys.path.append(str(_HERE.parent / "graph_query_api"))
sys.path.insert(0, str(_HERE))

import lambda_function as lf  # noqa: E402


class _Sess:
    def __init__(self, driver):
        self._d = driver

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        if "RETURN count(n)" in cypher or "RETURN count(r)" in cypher or "orphans" in cypher:
            return _Single({"total": 0, "orphans": 0})
        if "index_name" in params:
            return list(self._d.pair_rows)
        return list(self._d.node_rows)


class _Single:
    def __init__(self, d):
        self._d = d

    def single(self):
        return self._d


class _Driver:
    def __init__(self, node_rows, pair_rows):
        self.node_rows = node_rows
        self.pair_rows = pair_rows

    def session(self):
        return _Sess(self)


class _FakeCloudWatch:
    def __init__(self, datapoints=None):
        self.put_calls = []
        self._datapoints = datapoints or {}

    def put_metric_data(self, Namespace, MetricData):
        self.put_calls.append({"namespace": Namespace, "data": MetricData})

    def get_metric_statistics(self, **kwargs):
        return {"Datapoints": self._datapoints.get(kwargs["MetricName"], [])}


class WalkBackCounterTests(unittest.TestCase):
    def test_sums_datapoints(self):
        cw = _FakeCloudWatch({"AutoMergeCount": [{"Sum": 10.0}, {"Sum": 5.0}], "WalkBackCount": [{"Sum": 1.0}]})
        lf.boto3 = _Boto(cw)
        counts = lf._read_walk_back_counts(30)
        self.assertEqual(counts, {"auto_merges": 15, "walk_backs": 1})

    def test_degrades_to_zero_on_error(self):
        class _Boom:
            def client(self, *_a, **_k):
                raise RuntimeError("no creds")

        lf.boto3 = _Boom()
        counts = lf._read_walk_back_counts(30)
        self.assertEqual(counts, {"auto_merges": 0, "walk_backs": 0})


class _Boto:
    def __init__(self, cw):
        self._cw = cw

    def client(self, name, *a, **k):
        return self._cw


class PublishTests(unittest.TestCase):
    def test_publishes_all_signals(self):
        cw = _FakeCloudWatch()
        lf.boto3 = _Boto(cw)
        signals = {
            "stock_pairs": 7,
            "precision_at_1_recovery_proxy": 0.6,
            "precision_at_1_recovery_fraction": 0.5,
            "precision_at_1_baseline": 0.3727,
            "recall_ceiling": 0.8242,
            "new_duplicate_pairs": 3,
            "lcc_size": 4,
            "nontrivial_component_count": 2,
            "embedded_record_count": 20,
            "walk_back": {"walk_back_rate": 0.002, "auto_merge_count": 1000,
                          "walk_back_count": 2, "breached_floor": True},
        }
        published = lf._publish_dedup_signals(signals)
        self.assertEqual(len(cw.put_calls), 1)
        self.assertEqual(cw.put_calls[0]["namespace"], lf.DEDUP_NAMESPACE)
        names = {m["MetricName"] for m in cw.put_calls[0]["data"]}
        for expected in (
            "DuplicatePairStock", "Precision1RecoveryProxy", "Precision1Baseline",
            "RecallCeiling", "NewDuplicateFlow", "DuplicateLCCSize",
            "NonTrivialComponentCount", "AutoMergeWalkBackRate", "WalkBackRateBreachedFloor",
        ):
            self.assertIn(expected, names)
        self.assertEqual(published["DuplicatePairStock"], 7.0)
        self.assertEqual(published["WalkBackRateBreachedFloor"], 1.0)


class HandlerIsolationTests(unittest.TestCase):
    def test_dedup_failure_does_not_break_base_metrics(self):
        cw = _FakeCloudWatch()
        lf.boto3 = _Boto(cw)
        # Base metrics compute against a driver whose count queries succeed.
        driver = _Driver(node_rows=[], pair_rows=[])
        lf._get_neo4j_driver = lambda: driver  # type: ignore

        # Force the dedup section to blow up after base metrics succeed.
        def _boom(_drv):
            raise RuntimeError("vector index missing")

        lf._compute_dedup_signals = _boom  # type: ignore

        resp = lf.handler({}, None)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["success"])
        self.assertFalse(body["dedup_convergence"]["published"])
        self.assertIn("error", body["dedup_convergence"])


if __name__ == "__main__":
    unittest.main()
