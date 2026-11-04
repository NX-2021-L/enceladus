"""No-network tests: projection-lag poller and the burst cell (ENC-TSK-S46-0B)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import projection  # noqa: E402
import stats  # noqa: E402
import wire  # noqa: E402

GH = "a" * 64


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def mono(self):
        return self.t

    def sleep(self, s):
        self.t += s


def reader(clock, script):
    """script: list of (ok, payload) per call, last repeated. Receipt ms = 1000*clock + 5000."""
    calls = []

    def read(rid):
        i = min(len(calls), len(script) - 1)
        calls.append(rid)
        ok, payload = script[i]
        return ok, payload, 5000.0 + clock.t * 1000.0
    read.calls = calls
    return read


NOT = (True, {"record": {"projection_status": "pending"}})
YES = (True, {"record": {"projection_status": "projected"}})
FAIL = (False, {"error": "Unknown project prefix"})


class PollerTests(unittest.TestCase):
    def test_projected_on_third_poll(self):
        c = FakeClock()
        r = reader(c, [NOT, NOT, YES])
        out = projection.poll_projection(r, ["R-1"], 5000.0, 0.1, 60, c.sleep, c.mono)
        self.assertEqual(out["projection_polls"], 3)
        self.assertFalse(out["projection_timed_out"])
        self.assertAlmostEqual(out["projection_lag_ms"], 200.0)
        self.assertIsNone(out["projection_blocked_reason"])

    def test_never_projected_times_out(self):
        c = FakeClock()
        out = projection.poll_projection(reader(c, [NOT]), ["R-1"], 5000.0, 0.1, 1.0, c.sleep, c.mono)
        self.assertTrue(out["projection_timed_out"])
        self.assertIsNone(out["projection_lag_ms"])
        self.assertGreaterEqual(out["projection_polls"], 10)
        self.assertIsNone(out["projection_blocked_reason"])

    def test_read_unavailable(self):
        c = FakeClock()
        out = projection.poll_projection(reader(c, [FAIL]), ["R-1"], 5000.0, 0.1, 0.5, c.sleep, c.mono)
        self.assertTrue(out["projection_timed_out"])
        self.assertEqual(out["projection_blocked_reason"], "read_unavailable")

    def test_failures_then_projected_is_not_blocked(self):
        c = FakeClock()
        out = projection.poll_projection(reader(c, [FAIL, YES]), ["R-1"], 5000.0, 0.1, 60, c.sleep, c.mono)
        self.assertFalse(out["projection_timed_out"])
        self.assertIsNone(out["projection_blocked_reason"])

    def test_multi_record_lag_is_max(self):
        c = FakeClock()
        out = projection.poll_projection(reader(c, [YES]), ["A", "B"], 5000.0, 0.1, 60, c.sleep, c.mono)
        self.assertEqual(out["projection_polls"], 2)
        self.assertEqual(set(out["projection_lag_per_record_ms"]), {"A", "B"})

    def test_t_ack_parsing(self):
        self.assertEqual(projection.parse_t_ack_ms(1_700_000_000_123), 1_700_000_000_123.0)
        self.assertEqual(projection.parse_t_ack_ms(1_700_000_000), 1_700_000_000_000.0)
        self.assertAlmostEqual(projection.parse_t_ack_ms("2026-11-01T00:06:00.321Z"), 1793491560321.0)
        self.assertEqual(projection.extract_t_ack_ms({"x": 1}, 42.0), (42.0, "client_end_fallback"))

    def test_lag_applicability(self):
        self.assertTrue(projection.lag_applies("tracker_set"))
        self.assertTrue(projection.lag_applies("execute_10_chained"))
        self.assertFalse(projection.lag_applies("documents_put_2kb"))


class BurstTests(unittest.TestCase):
    POOL = [f"ZNC-TSK-{i:03d}" for i in range(1, 21)]

    def test_plan_and_payload_shape(self):
        tool, args = wire.build_operation("execute_20_independent_burst", "znc", self.POOL, GH)
        self.assertEqual(tool, "execute")
        steps = args["steps"]
        self.assertEqual(len(steps), 20)
        self.assertEqual({s["action"] for s in steps}, {"tracker.set"})
        self.assertEqual(len({s["arguments"]["record_id"] for s in steps}), 20)
        self.assertTrue(all(s["arguments"]["governance_hash"] == GH for s in steps))
        self.assertNotIn("execute_20_independent_burst", wire.OPERATIONS)  # default cells unchanged

    def test_needs_20_distinct(self):
        with self.assertRaises(ValueError):
            wire.build_operation("execute_20_independent_burst", "znc", self.POOL[:10], GH)

    def test_existing_20_independent_unchanged(self):
        _, args = wire.build_operation("execute_20_independent", "znc", self.POOL[:10], GH)
        self.assertEqual(len({s["arguments"]["record_id"] for s in args["steps"]}), 10)

    def test_blocked_on_tool_failure(self):
        tool, args = wire.build_operation("execute_20_independent_burst", "znc", self.POOL, GH)
        rec = {"ok": True, "payload": {"results": [{"success": False, "error": "Unknown project prefix"}]},
               "t_client_end": 1.0}
        projection.annotate_call(rec, "execute_20_independent_burst", tool, args, reader(FakeClock(), [YES]))
        self.assertEqual(rec["status"], "blocked")
        self.assertFalse(rec["ok"])
        self.assertIn("Unknown project prefix", rec["blocked_reason"])
        self.assertNotIn("projection_polls", rec)

    def test_burst_polls_all_20(self):
        tool, args = wire.build_operation("execute_20_independent_burst", "znc", self.POOL, GH)
        c = FakeClock()
        rec = {"ok": True, "payload": {"success": True, "t_ack": 5000}, "t_client_end": 5.0}
        projection.annotate_call(rec, "execute_20_independent_burst", tool, args, reader(c, [YES]), sleep=c.sleep)
        self.assertEqual(rec["projection_polls"], 20)
        self.assertEqual(len(rec["projection_lag_per_record_ms"]), 20)
        self.assertEqual(rec["t_ack_source"], "response")

    def test_summary_blocked_cell_and_lag_stats(self):
        base = {"operation": "execute_20_independent_burst", "arm": "long_lived_session", "series": "warm", "warmup": False}
        blocked = [dict(base, ok=False, status="blocked", blocked_reason="tool_failure: x") for _ in range(3)]
        s = projection.summarize_lag(blocked, 200)
        self.assertEqual(s["execute_20_independent_burst|long_lived_session|warm"]["status"], "blocked")
        good = [dict(base, operation="tracker_set", ok=True, projection_polls=2, projection_timed_out=False,
                     projection_lag_ms=float(100 + i)) for i in range(20)]
        s = projection.summarize_lag(good, 200)["tracker_set|long_lived_session|warm"]
        self.assertEqual(s["n"], 20)
        self.assertIn("p95_ci95", s)
        self.assertEqual(s["timed_out"], 0)


if __name__ == "__main__":
    unittest.main()
