"""Unit tests for INT-TSK-284 (WS-B2): graph-signal health-probe honesty.

Context (ENC-ISS-465/J41): GDS/AGA is hard-disabled (cost kill), so the ONLY
live leg of the hybrid graph signal in normal operation is the Cypher
fallback (_hybrid_graph_ranks_cypher_fallback, via _query_hybrid). Before this
fix, _handle_health's signals.graph checked GDS/AGA reachability ONLY
(_check_gds_available), so it permanently read False even while the query
path served real graph ranks via cypher_fallback — a red probe over a live
signal.

Exercises:
  - _check_graph_fallback_serviceable: structural Cypher-fallback probe,
    success/failure by whether the query executes (not row count)
  - _check_graph_serviceable: resolution order (GDS first, unless hard-
    disabled, else the fallback leg) + graph_mode vocabulary
      * GDS-disabled + Bolt-alive  -> (True, "cypher_fallback")
      * GDS-disabled + Bolt-dead   -> (False, "unavailable")
      * GDS-available              -> (True, "gds_pagerank"), fallback never
        consulted, and the probe never opens a session while hard-disabled
  - _standing_projection_status: additive retired/reason fields when
    unconfigured, without touching the existing configured/name keys
  - _handle_health: end-to-end payload carries graph_mode + honest
    signals.graph, and stays backward-compatible (only ADDS fields)

These tests do not require Neo4j or Bedrock — driver/session are faked.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

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

    def data(self):
        return self._rows


class _FakeSession:
    def __init__(self, responder):
        self._responder = responder

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kw):
        return self._responder(query, kw)


class _FakeDriver:
    """Routes every session.run() through a caller-supplied responder(query, kw)."""

    def __init__(self, responder):
        self._responder = responder

    def session(self):
        return _FakeSession(self._responder)


def _explode(_query, _kw):
    raise AssertionError("driver must not be used for this probe leg")


class _ProbeTestCase(unittest.TestCase):
    """Common setup: isolate the module-level GDS availability cache + flags
    so tests never leak state into each other (the cache has a 5-minute TTL
    and is keyed globally, not per-driver)."""

    def setUp(self):
        self._saved_hard_disabled = lf._GDS_HARD_DISABLED
        self._saved_probe_state = dict(lf._gds_probe_state)
        self._saved_prefix = lf._GDS_STANDING_PROJECTION_PREFIX
        lf._gds_probe_state["checked_at"] = 0.0
        lf._gds_probe_state["available"] = None

    def tearDown(self):
        lf._GDS_HARD_DISABLED = self._saved_hard_disabled
        lf._gds_probe_state.clear()
        lf._gds_probe_state.update(self._saved_probe_state)
        lf._GDS_STANDING_PROJECTION_PREFIX = self._saved_prefix


class CheckGraphFallbackServiceableTest(_ProbeTestCase):
    def test_succeeds_when_query_executes(self):
        def responder(query, kw):
            self.assertIn("$project_id", query)
            self.assertEqual(kw.get("project_id"), lf._HEALTH_PROBE_PROJECT)
            # Same relationship-type union + weighted-hop shape as the real
            # cypher-fallback query path.
            for edge_type in lf.GRAPH_EDGE_WEIGHTS:
                self.assertIn(edge_type, query)
            return _FakeResult(rows=[{"rid": "ENC-TSK-001", "path_score": 1.5}])

        self.assertTrue(lf._check_graph_fallback_serviceable(_FakeDriver(responder)))

    def test_succeeds_with_zero_rows_not_just_zero_errors(self):
        # An anchor with no neighbors within 3 hops (or an empty health-probe
        # project) is still a serviceable leg — success means the query
        # EXECUTED, not that it returned rows.
        def responder(_query, _kw):
            return _FakeResult(rows=[])

        self.assertTrue(lf._check_graph_fallback_serviceable(_FakeDriver(responder)))

    def test_fails_when_query_raises(self):
        def responder(_query, _kw):
            raise RuntimeError("bolt exploded")

        self.assertFalse(lf._check_graph_fallback_serviceable(_FakeDriver(responder)))

    def test_never_raises(self):
        def responder(_query, _kw):
            raise RuntimeError("boom")

        try:
            lf._check_graph_fallback_serviceable(_FakeDriver(responder))
        except Exception as exc:  # pragma: no cover - the assertion below is the real check
            self.fail(f"_check_graph_fallback_serviceable raised: {exc}")


class CheckGraphServiceableTest(_ProbeTestCase):
    def test_gds_disabled_bolt_alive_is_cypher_fallback(self):
        lf._GDS_HARD_DISABLED = True

        def responder(query, _kw):
            # GDS_HARD_DISABLED short-circuits _check_gds_available before it
            # ever touches the driver, so a gds.list() call here is a bug.
            self.assertNotIn("gds.list", query)
            return _FakeResult(rows=[{"rid": "ENC-TSK-001", "path_score": 1.0}])

        available, mode = lf._check_graph_serviceable(_FakeDriver(responder))
        self.assertTrue(available)
        self.assertEqual(mode, "cypher_fallback")

    def test_gds_disabled_bolt_dead_is_unavailable(self):
        lf._GDS_HARD_DISABLED = True

        def responder(query, _kw):
            self.assertNotIn("gds.list", query)
            raise RuntimeError("bolt connection dead")

        available, mode = lf._check_graph_serviceable(_FakeDriver(responder))
        self.assertFalse(available)
        self.assertEqual(mode, "unavailable")

    def test_gds_available_is_gds_pagerank_and_skips_fallback(self):
        lf._GDS_HARD_DISABLED = False

        def responder(query, _kw):
            if "gds.list" in query:
                return _FakeResult(rows=[{"name": "pageRank"}])
            # If GDS is available, the fallback probe must never be consulted.
            raise AssertionError("fallback probe must not run when GDS is available")

        available, mode = lf._check_graph_serviceable(_FakeDriver(responder))
        self.assertTrue(available)
        self.assertEqual(mode, "gds_pagerank")

    def test_never_starts_gds_session_while_hard_disabled(self):
        # Regression guard: even if the fallback probe itself fails, the
        # resolver must not have fallen through to a GDS/AGA call.
        lf._GDS_HARD_DISABLED = True
        calls = []

        def responder(query, _kw):
            calls.append(query)
            raise RuntimeError("fallback down too")

        lf._check_graph_serviceable(_FakeDriver(responder))
        self.assertTrue(all("gds." not in q for q in calls))


class StandingProjectionStatusRetirementTest(_ProbeTestCase):
    def test_reason_present_when_hard_disabled(self):
        lf._GDS_HARD_DISABLED = True
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        out = lf._standing_projection_status(_FakeDriver(_explode), "enceladus")
        # Existing shape preserved.
        self.assertFalse(out["configured"])
        self.assertIsNone(out["name"])
        # New, additive fields.
        self.assertTrue(out.get("retired"))
        self.assertIn("GDS_HARD_DISABLED", out.get("reason", ""))

    def test_reason_present_but_not_retired_when_merely_unset(self):
        lf._GDS_HARD_DISABLED = False
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        out = lf._standing_projection_status(_FakeDriver(_explode), "enceladus")
        self.assertFalse(out["configured"])
        self.assertIsNone(out["name"])
        self.assertNotIn("retired", out)
        self.assertIn("unset", out.get("reason", ""))


class HandleHealthEndToEndTest(_ProbeTestCase):
    def _install_driver(self, responder):
        self._saved_get_driver = lf._get_neo4j_driver
        lf._get_neo4j_driver = lambda: _FakeDriver(responder)

    def tearDown(self):
        if hasattr(self, "_saved_get_driver"):
            lf._get_neo4j_driver = self._saved_get_driver
        super().tearDown()

    def test_gds_disabled_cypher_fallback_alive_reports_graph_true(self):
        lf._GDS_HARD_DISABLED = True
        lf._GDS_STANDING_PROJECTION_PREFIX = ""

        def responder(query, _kw):
            if "RETURN 1 AS health" in query:
                return _FakeResult(single={"health": 1})
            if "gds.list" in query:
                raise AssertionError("must not probe GDS while hard-disabled")
            # keyword probe / cypher-fallback shape / anything else: succeed
            # with no rows so every individually-wrapped probe degrades
            # gracefully rather than raising.
            return _FakeResult(rows=[], single=None)

        self._install_driver(responder)
        resp = lf._handle_health({})
        payload = json.loads(resp["body"])

        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(payload["status"], "healthy")
        # Backward compatible: pre-existing keys still present.
        self.assertIn("signals", payload)
        self.assertIn("graph_projection", payload)
        # New field.
        self.assertIn("graph_mode", payload)
        self.assertEqual(payload["graph_mode"], "cypher_fallback")
        self.assertTrue(payload["signals"]["graph"])
        # Projection is honestly retired, not silently absent.
        self.assertFalse(payload["graph_projection"]["configured"])
        self.assertTrue(payload["graph_projection"].get("retired"))


if __name__ == "__main__":
    unittest.main()
