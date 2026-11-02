"""ENC-TSK-S11 (PLN-103 N11): EMF metrics emitted for graphsearch_query audit records."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


def _emit(record, env=None):
    buf = io.StringIO()
    with mock.patch.dict(os.environ, env or {}, clear=False), redirect_stdout(buf):
        lf._emit_graphsearch_emf(record)
    out = buf.getvalue().strip()
    return json.loads(out) if out else None


class EmfTests(unittest.TestCase):
    def test_hybrid_shape(self):
        o = _emit({"search_type": "hybrid", "duration_ms": 2500, "pathway_status": "ok"})
        cwm = o["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual(cwm["Namespace"], "Enceladus/GraphSearch")
        self.assertEqual(cwm["Dimensions"], [["SearchType", "Environment"]])
        self.assertEqual([m["Name"] for m in cwm["Metrics"]], ["SearchDurationMs", "HybridPathwayFailed"])
        self.assertEqual(cwm["Metrics"][0]["Unit"], "Milliseconds")
        self.assertIsInstance(o["_aws"]["Timestamp"], int)
        self.assertEqual(o["SearchType"], "hybrid")
        self.assertEqual(o["SearchDurationMs"], 2500.0)

    def test_failed_maps_to_one_else_zero(self):
        self.assertEqual(_emit({"search_type": "hybrid", "duration_ms": 1, "pathway_status": "failed"})["HybridPathwayFailed"], 1)
        for st in ("ok", "skipped", "timeout", None):
            self.assertEqual(_emit({"search_type": "hybrid", "duration_ms": 1, "pathway_status": st})["HybridPathwayFailed"], 0)

    def test_neighbors_duration_only(self):
        o = _emit({"search_type": "neighbors", "duration_ms": 40})
        self.assertNotIn("HybridPathwayFailed", o)
        self.assertEqual([m["Name"] for m in o["_aws"]["CloudWatchMetrics"][0]["Metrics"]], ["SearchDurationMs"])

    def test_other_types_not_emitted(self):
        self.assertIsNone(_emit({"search_type": "keyword", "duration_ms": 5}))

    def test_kill_switch(self):
        self.assertIsNone(_emit({"search_type": "hybrid", "duration_ms": 1}, {"GRAPHSEARCH_EMF_ENABLED": "false"}))

    def test_exception_swallowed(self):
        with mock.patch.object(lf.json, "dumps", side_effect=RuntimeError("boom")):
            lf._emit_graphsearch_emf({"search_type": "hybrid", "duration_ms": 1})
        lf._emit_graphsearch_emf(None)  # AttributeError path


if __name__ == "__main__":
    unittest.main()
