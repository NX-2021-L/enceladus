"""Unit tests for ENC-FTR-108 Phase 2 (ENC-TSK-J02) flow_weight refresh.

Exercises the pure-Python aggregation/formula/idempotency logic without a
live Neo4j or S3 -- driver and S3 client are fakes/mocks, matching the
conventions in test_standing_projection_ftr101.py and
test_pathway_telemetry_ftr082.py.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import flow_weight_refresh as fwr  # noqa: E402
import lambda_function as lf  # noqa: E402


class _FakeResult:
    def __init__(self, single=None, rows=None):
        self._single = single
        self._rows = rows if rows is not None else []

    def single(self):
        return self._single

    def __iter__(self):
        return iter(self._rows)

    def consume(self):
        return None


class _FakeSession:
    def __init__(self, driver):
        self._driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kw):
        return self._driver._respond(query, kw)


class _FakeDriver:
    """Records every Cypher call; lets a test script canned responses (e.g.
    watermark reads) and inspect what was written (e.g. reinforcement rows,
    decay touched-set)."""

    def __init__(self, watermark_response=None):
        self.calls = []
        self._watermark_response = watermark_response

    def session(self):
        return _FakeSession(self)

    def _respond(self, query, kw):
        self.calls.append((query, kw))
        if "last_watermark_epoch_ms" in query and "RETURN" in query:
            return _FakeResult(single=self._watermark_response)
        return _FakeResult()


class _FakeS3:
    """In-memory S3 stand-in: paginator over a fixed object list + get_object
    returning canned JSON bodies."""

    def __init__(self, objects, bodies):
        # objects: list of (key, datetime) : LastModified
        self._objects = objects
        self._bodies = bodies

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        contents = [{"Key": k, "LastModified": lm} for k, lm in self._objects]
        yield {"Contents": contents}

    def get_object(self, Bucket, Key):
        body = json.dumps(self._bodies[Key]).encode("utf-8")

        class _Body:
            def read(self_inner):
                return body

        return {"Body": _Body()}


def _dt(seconds_offset: int) -> dt.datetime:
    return dt.datetime(2026, 7, 1, 0, 0, 0, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=seconds_offset)


class TestWatermark(unittest.TestCase):
    def test_no_marker_defaults_zero(self):
        driver = _FakeDriver(watermark_response=None)
        self.assertEqual(fwr._get_watermark(driver), 0)

    def test_marker_read(self):
        driver = _FakeDriver(watermark_response={"wm": 12345})
        self.assertEqual(fwr._get_watermark(driver), 12345)

    def test_set_watermark_merges_shared_label(self):
        driver = _FakeDriver()
        fwr._set_watermark(driver, 999)
        query, kw = driver.calls[-1]
        self.assertIn(f"MERGE (m:{fwr.FLOW_WEIGHT_META_LABEL}", query)
        self.assertEqual(kw["name"], fwr.FLOW_WEIGHT_META_NAME)
        self.assertEqual(kw["epoch_ms"], 999)


class TestListAndAggregate(unittest.TestCase):
    def test_list_filters_and_sorts_by_last_modified(self):
        objects = [("b.jsonl", _dt(20)), ("a.jsonl", _dt(10)), ("old.jsonl", _dt(-100))]
        s3 = _FakeS3(objects, bodies={})
        since_ms = int(_dt(0).timestamp() * 1000)
        result = fwr._list_new_telemetry_objects(s3, "bucket", "prefix", since_ms, max_objects=100)
        self.assertEqual([k for k, _ in result], ["a.jsonl", "b.jsonl"])

    def test_list_caps_at_max_objects(self):
        objects = [(f"k{i}.jsonl", _dt(i)) for i in range(10)]
        s3 = _FakeS3(objects, bodies={})
        result = fwr._list_new_telemetry_objects(s3, "bucket", "prefix", 0, max_objects=3)
        self.assertEqual(len(result), 3)
        # oldest-first, so the cap keeps the earliest 3 (watermark only
        # advances to what was actually processed).
        self.assertEqual([k for k, _ in result], ["k0.jsonl", "k1.jsonl", "k2.jsonl"])

    def test_aggregate_sums_hit_traversal_counts_only(self):
        bodies = {
            "o1.jsonl": {"edge_participation": [
                {"edge_id": "e1", "traversal_count": 3, "retrieval_outcome": "hit"},
                {"edge_id": "e2", "traversal_count": 5, "retrieval_outcome": "traversed"},
            ]},
            "o2.jsonl": {"edge_participation": [
                {"edge_id": "e1", "traversal_count": 2, "retrieval_outcome": "hit"},
            ]},
        }
        s3 = _FakeS3([], bodies)
        objects = [("o1.jsonl", _dt(0)), ("o2.jsonl", _dt(1))]
        flow = fwr._aggregate_hit_flow(s3, "bucket", objects)
        self.assertEqual(flow, {"e1": 5})  # e2 excluded (not 'hit')

    def test_aggregate_skips_malformed_object(self):
        s3 = mock.MagicMock()
        s3.get_object.side_effect = RuntimeError("AccessDenied")
        flow = fwr._aggregate_hit_flow(s3, "bucket", [("bad.jsonl", _dt(0))])
        self.assertEqual(flow, {})


class TestBatchedWrites(unittest.TestCase):
    def test_reinforcement_is_single_unwind_batch_not_per_edge(self):
        driver = _FakeDriver()
        touched = fwr._apply_reinforcement(driver, {"e1": 2, "e2": 5}, delta=0.2, mu=0.2)
        self.assertEqual(set(touched), {"e1", "e2"})
        # Exactly one session.run call for the whole (small) batch -- not N.
        run_calls = [c for c in driver.calls if "UNWIND $rows" in c[0]]
        self.assertEqual(len(run_calls), 1)
        self.assertIn("elementId(r)", run_calls[0][0])

    def test_reinforcement_chunks_large_batches(self):
        driver = _FakeDriver()
        flow_by_edge = {f"e{i}": 1 for i in range(1250)}
        fwr._apply_reinforcement(driver, flow_by_edge, delta=0.2, mu=0.2, chunk_size=500)
        run_calls = [c for c in driver.calls if "UNWIND $rows" in c[0]]
        self.assertEqual(len(run_calls), 3)  # 500 + 500 + 250

    def test_reinforcement_noop_on_empty(self):
        driver = _FakeDriver()
        touched = fwr._apply_reinforcement(driver, {}, delta=0.2, mu=0.2)
        self.assertEqual(touched, [])
        self.assertEqual(driver.calls, [])

    def test_decay_is_single_statement_excluding_touched(self):
        driver = _FakeDriver()
        fwr._apply_decay(driver, touched_edge_ids=["e1"], mu=0.2, edge_types=["RELATED_TO", "CHILD_OF"])
        self.assertEqual(len(driver.calls), 1)
        query, kw = driver.calls[0]
        self.assertIn("NOT elementId(r) IN $touched", query)
        self.assertIn("RELATED_TO", query)
        self.assertIn("CHILD_OF", query)
        self.assertEqual(kw["touched"], ["e1"])
        self.assertEqual(kw["mu"], 0.2)

    def test_decay_noop_on_no_edge_types(self):
        driver = _FakeDriver()
        fwr._apply_decay(driver, touched_edge_ids=[], mu=0.2, edge_types=[])
        self.assertEqual(driver.calls, [])


class TestRunRefreshIdempotency(unittest.TestCase):
    """AC: running the same cycle twice with no new participation data must
    not change flow_weight further (no decay/reinforcement re-applied)."""

    def test_no_bucket_configured_is_noop(self):
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", ""):
            driver = _FakeDriver()
            s3 = mock.MagicMock()
            result = fwr.run_refresh(driver, s3, {})
        self.assertTrue(result["ok"])
        self.assertFalse(result["applied"])
        s3.get_paginator.assert_not_called()

    def test_second_call_with_no_new_telemetry_is_noop(self):
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "prefix"):
            watermark_ms = int(_dt(100).timestamp() * 1000)
            driver = _FakeDriver(watermark_response={"wm": watermark_ms})
            # Every object already older than the watermark -> nothing new.
            s3 = _FakeS3([("old.jsonl", _dt(50))], bodies={})
            result = fwr.run_refresh(driver, s3, {})
        self.assertTrue(result["ok"])
        self.assertFalse(result["applied"])
        # No SET was ever issued (only the watermark read happened).
        set_calls = [c for c in driver.calls if "SET r.flow_weight" in c[0]]
        self.assertEqual(set_calls, [])

    def test_first_call_with_new_telemetry_reinforces_and_decays(self):
        with mock.patch.object(lf, "PATHWAY_TELEMETRY_BUCKET", "bucket"), \
             mock.patch.object(lf, "PATHWAY_TELEMETRY_PREFIX", "prefix"):
            driver = _FakeDriver(watermark_response=None)
            bodies = {
                "o1.jsonl": {"edge_participation": [
                    {"edge_id": "e1", "traversal_count": 4, "retrieval_outcome": "hit"},
                ]},
            }
            s3 = _FakeS3([("o1.jsonl", _dt(10))], bodies)
            result = fwr.run_refresh(driver, s3, {})
        self.assertTrue(result["ok"])
        self.assertTrue(result["applied"])
        self.assertEqual(result["edges_reinforced"], 1)
        reinforce_calls = [c for c in driver.calls if "UNWIND $rows" in c[0]]
        decay_calls = [c for c in driver.calls if "NOT elementId(r) IN $touched" in c[0]]
        self.assertEqual(len(reinforce_calls), 1)
        self.assertEqual(len(decay_calls), 1)
        watermark_writes = [c for c in driver.calls if "last_watermark_epoch_ms = $epoch_ms" in c[0]]
        self.assertEqual(len(watermark_writes), 1)


class TestDecayConvergence(unittest.TestCase):
    """AC: an idle edge (zero traversal every cycle) decays under 1% of its
    start within ~21 wave-closes per mu=0.2 (DOC-88A8F4835811)."""

    def _simulate_idle_decay(self, start: float, mu: float, cycles: int) -> float:
        """Pure-formula simulation of N consecutive wave-closes with zero
        flow -- exercises the exact equation _apply_decay/_apply_reinforcement
        write into Cypher (flow=0 collapses the shared formula to *= (1-mu))."""
        value = start
        for _ in range(cycles):
            value = value + 0.0 * 0 - mu * value  # delta*flow term is 0 when idle
        return value

    def test_21_cycles_under_one_percent(self):
        start = 1.0
        end = self._simulate_idle_decay(start, mu=0.2, cycles=21)
        self.assertLess(end / start, 0.01)

    def test_20_cycles_not_yet_under_one_percent(self):
        # Sanity check the 21-cycle figure is the crossing point, not slack.
        start = 1.0
        end = self._simulate_idle_decay(start, mu=0.2, cycles=20)
        self.assertGreaterEqual(end / start, 0.01)

    def test_decay_cypher_pass_matches_formula_semantics(self):
        """The _apply_decay Cypher body must literally encode
        flow_weight * (1 - mu) for untouched edges -- assert the query text
        so a future refactor can't silently change the exponent/decay shape
        without failing this test."""
        driver = _FakeDriver()
        fwr._apply_decay(driver, touched_edge_ids=[], mu=0.2, edge_types=["RELATED_TO"])
        query, kw = driver.calls[0]
        self.assertIn("coalesce(r.flow_weight, $default) * (1 - $mu)", query)
        self.assertEqual(kw["default"], fwr.FLOW_WEIGHT_DEFAULT)

    def test_reinforcement_cypher_matches_doc88a8_formula(self):
        driver = _FakeDriver()
        fwr._apply_reinforcement(driver, {"e1": 1}, delta=0.2, mu=0.2)
        query, kw = driver.calls[0]
        self.assertIn(
            "SET r.flow_weight = coalesce(r.flow_weight, $default) "
            "  + $delta * row.flow - $mu * coalesce(r.flow_weight, $default)",
            query,
        )
        self.assertEqual(kw["delta"], 0.2)
        self.assertEqual(kw["mu"], 0.2)


class TestLambdaHandlerDispatch(unittest.TestCase):
    """AC-6-style traversability check for the invocation contract: the
    action='refresh_flow_weight' event must route to the new handler and NOT
    fall through to the FTR-101 refresh_projection handler."""

    def test_action_routes_before_generic_scheduled_event_fallback(self):
        with mock.patch.object(lf, "_handle_refresh_flow_weight", return_value={"ok": True}) as h1, \
             mock.patch.object(lf, "_handle_refresh_projection") as h2:
            result = lf.lambda_handler({"action": "refresh_flow_weight"}, None)
        h1.assert_called_once()
        h2.assert_not_called()
        self.assertEqual(result, {"ok": True})

    def test_generic_scheduled_event_still_routes_to_projection_refresh(self):
        with mock.patch.object(lf, "_handle_refresh_flow_weight") as h1, \
             mock.patch.object(lf, "_handle_refresh_projection", return_value={"ok": True}) as h2:
            result = lf.lambda_handler({"detail-type": "Scheduled Event"}, None)
        h1.assert_not_called()
        h2.assert_called_once()
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
