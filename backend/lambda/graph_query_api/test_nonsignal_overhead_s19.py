"""ENC-TSK-S19 (PLN-103 W2.3 / N15): non-signal stage timers, async telemetry
emits and the Bolt liveness TTL in graph_query_api."""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402
from test_signal_concurrency_s09 import PARAMS, _start  # noqa: E402


def _drain(timeout=2.0):
    end = time.time() + timeout
    while lf._ASYNC_EMIT_QUEUE.unfinished_tasks and time.time() < end:
        time.sleep(0.005)


class TestAsyncEmit(unittest.TestCase):
    def test_emit_does_not_block_and_swallows_exceptions(self):
        gate = threading.Event()
        ran = []

        def _slow():
            gate.wait(2)
            ran.append(1)

        def _boom():
            raise RuntimeError("boom")

        t0 = time.perf_counter()
        self.assertTrue(lf._emit_async(_slow))
        self.assertTrue(lf._emit_async(_boom))
        self.assertLess(time.perf_counter() - t0, 0.1)  # enqueue only
        gate.set()
        _drain()
        self.assertEqual(ran, [1])
        # worker survived the exception and still runs work
        self.assertTrue(lf._emit_async(lambda: ran.append(2)))
        _drain()
        self.assertEqual(ran, [1, 2])

    def test_queue_overflow_drops(self):
        gate = threading.Event()
        lf._emit_async(lambda: gate.wait(2))
        time.sleep(0.05)  # worker now holds the blocker
        results = [lf._emit_async(lambda: None) for _ in range(lf.ASYNC_EMIT_QUEUE_MAX + 5)]
        self.assertEqual(results.count(True), lf.ASYNC_EMIT_QUEUE_MAX)
        self.assertEqual(results.count(False), 5)
        gate.set()
        _drain()

    def test_hybrid_emit_off_request_path_and_audit_fields(self):
        _start(self, vector=0.0, graph=0.0, keyword=0.0)
        started = threading.Event()
        release = threading.Event()
        done = []

        def _slow_emit(record):
            started.set()
            release.wait(2)
            done.append(record)

        with mock.patch.object(lf, "_emit_pathway_telemetry", side_effect=_slow_emit):
            t0 = time.perf_counter()
            result = lf._query_hybrid(mock.MagicMock(), "enceladus", dict(PARAMS))
            wall = time.perf_counter() - t0
            self.assertLess(wall, 0.5)  # did not wait for the 2 s emit
            self.assertTrue(started.wait(1))
            audit = lf._graphsearch_audit_record({}, dict(PARAMS), "hybrid", "enceladus",
                                                 result, int(wall * 1000))
            for k in ("preflight_ms", "node_fetch_ms", "rank_cpu_ms", "emit_ms"):
                self.assertIn(k, audit)
                self.assertIsInstance(audit[k], int)
            self.assertLess(audit["emit_ms"], 100)
            self.assertNotIn("preflight_ms", result)  # response shape unchanged
            release.set()
            _drain()
        self.assertEqual(len(done), 1)


class TestDriverLivenessTTL(unittest.TestCase):
    def setUp(self):
        lf._invalidate_driver_liveness()
        self.addCleanup(lf._invalidate_driver_liveness)

    def test_skip_within_ttl_and_reverify_after(self):
        d = mock.MagicMock()
        with mock.patch.object(lf, "DRIVER_LIVENESS_TTL_S", 60.0):
            self.assertIs(lf._ensure_live_driver(d), d)
            self.assertIs(lf._ensure_live_driver(d), d)
            self.assertEqual(d.verify_connectivity.call_count, 1)
            lf._driver_verified = (id(d), time.time() - 61)
            self.assertIs(lf._ensure_live_driver(d), d)
            self.assertEqual(d.verify_connectivity.call_count, 2)

    def test_failure_rebuilds_and_clears_stamp(self):
        d = mock.MagicMock()
        d.verify_connectivity.side_effect = RuntimeError("dead")
        fresh = mock.MagicMock()
        with mock.patch.object(lf, "_rebuild_neo4j_driver", return_value=fresh) as rb:
            self.assertIs(lf._ensure_live_driver(d), fresh)
            rb.assert_called_once()
        lf._mark_driver_verified(fresh)
        lf._invalidate_driver_liveness()  # what _rebuild_neo4j_driver does
        fresh.verify_connectivity.reset_mock()
        lf._ensure_live_driver(fresh)
        fresh.verify_connectivity.assert_called_once()

    def test_ttl_zero_always_verifies(self):
        d = mock.MagicMock()
        with mock.patch.object(lf, "DRIVER_LIVENESS_TTL_S", 0.0):
            lf._ensure_live_driver(d)
            lf._ensure_live_driver(d)
        self.assertEqual(d.verify_connectivity.call_count, 2)


if __name__ == "__main__":
    unittest.main()
