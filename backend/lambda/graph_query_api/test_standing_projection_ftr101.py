"""Unit tests for ENC-FTR-101 (Option B) pre-materialized standing projection.

Exercises the pure-Python logic without Neo4j:
  - standing-projection name derivation + env gating
  - NO-REGRESSION guarantees: with GDS_STANDING_PROJECTION_PREFIX unset, the
    warm path / refresh / status return inert results and NEVER touch a driver
  - warm-path record_id mapping + anchor exclusion (fake driver)
  - warm-path graceful fallback to [] on missing projection or any error
  - refresh entrypoint when the driver is unavailable

These tests do not require Neo4j or Bedrock.
"""
from __future__ import annotations

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
    def __init__(self, responder):
        self._responder = responder

    def session(self):
        return _FakeSession(self._responder)


class _ExplodingDriver:
    """Any use raises — proves a code path never touched the driver."""

    def session(self):  # pragma: no cover - must not be called
        raise AssertionError("driver must not be used when feature is unconfigured")


class StandingProjectionTest(unittest.TestCase):
    def setUp(self):
        self._saved_prefix = lf._GDS_STANDING_PROJECTION_PREFIX
        self._saved_weight = lf._GDS_WEIGHT_PROPERTY

    def tearDown(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = self._saved_prefix
        lf._GDS_WEIGHT_PROPERTY = self._saved_weight

    # ---- name derivation + gating -----------------------------------------

    def test_name_empty_when_unconfigured(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        self.assertEqual(lf._standing_projection_name("enceladus"), "")

    def test_name_derivation_lowercases_and_underscores(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = "Hybrid_Standing"
        self.assertEqual(
            lf._standing_projection_name("My-Project"),
            "hybrid_standing_my_project",
        )

    # ---- no-regression guarantees (unset prefix => inert, driver untouched) -

    def test_warm_returns_empty_and_skips_driver_when_unconfigured(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        out = lf._hybrid_graph_ranks_gds_warm(_ExplodingDriver(), "enceladus", "ENC-X", 20)
        self.assertEqual(out, [])

    def test_refresh_inert_when_unconfigured(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        out = lf._refresh_standing_projection(_ExplodingDriver(), "enceladus")
        self.assertFalse(out["refreshed"])
        self.assertIn("unset", out["reason"])

    def test_status_inert_when_unconfigured(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = ""
        out = lf._standing_projection_status(_ExplodingDriver(), "enceladus")
        self.assertFalse(out["configured"])
        self.assertIsNone(out["name"])

    # ---- warm path happy mapping + anchor exclusion -----------------------

    def test_warm_maps_rids_and_excludes_anchor(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = "hybrid_standing"
        lf._GDS_WEIGHT_PROPERTY = "weight"

        def responder(query, kw):
            if "gds.graph.exists" in query:
                return _FakeResult(single={"exists": True})
            if "RETURN id(a) AS nodeId" in query:
                return _FakeResult(single={"nodeId": 100})
            if "gds.pageRank.stream" in query:
                return _FakeResult(rows=[
                    {"nodeId": 1, "score": 0.9},
                    {"nodeId": 2, "score": 0.8},
                    {"nodeId": 100, "score": 1.0},  # the anchor itself
                ])
            if "id(n) IN $node_ids" in query:
                return _FakeResult(rows=[
                    {"nodeId": 1, "rid": "ENC-AAA"},
                    {"nodeId": 2, "rid": "ENC-BBB"},
                    {"nodeId": 100, "rid": "ENC-ANCHOR"},
                ])
            return _FakeResult()

        out = lf._hybrid_graph_ranks_gds_warm(_FakeDriver(responder), "enceladus", "ENC-ANCHOR", 20)
        self.assertEqual([r["record_id"] for r in out], ["ENC-AAA", "ENC-BBB"])
        self.assertEqual([r["rank"] for r in out], [1, 2])
        self.assertAlmostEqual(out[0]["score"], 0.9)

    def test_warm_returns_empty_when_projection_absent(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = "hybrid_standing"

        def responder(query, kw):
            if "gds.graph.exists" in query:
                return _FakeResult(single={"exists": False})
            return _FakeResult()

        out = lf._hybrid_graph_ranks_gds_warm(_FakeDriver(responder), "enceladus", "ENC-X", 20)
        self.assertEqual(out, [])

    def test_warm_returns_empty_on_error(self):
        lf._GDS_STANDING_PROJECTION_PREFIX = "hybrid_standing"

        def responder(query, kw):
            raise RuntimeError("bolt exploded")

        out = lf._hybrid_graph_ranks_gds_warm(_FakeDriver(responder), "enceladus", "ENC-X", 20)
        self.assertEqual(out, [])

    # ---- refresh entrypoint when driver unavailable -----------------------

    def test_handle_refresh_projection_no_driver(self):
        saved_get = lf._get_neo4j_driver
        saved_ensure = lf._ensure_live_driver
        try:
            lf._get_neo4j_driver = lambda: None
            lf._ensure_live_driver = lambda d: None
            out = lf._handle_refresh_projection({"project_id": "enceladus"})
            self.assertFalse(out["ok"])
            self.assertIn("error", out)
        finally:
            lf._get_neo4j_driver = saved_get
            lf._ensure_live_driver = saved_ensure


if __name__ == "__main__":
    unittest.main()
