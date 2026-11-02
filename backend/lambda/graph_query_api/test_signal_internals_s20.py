"""ENC-TSK-S20 (PLN-103 W2.4 / N16): concurrent per-label HNSW queries and keyword sub-timers."""

from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402

LABELS = list(lf.LABEL_VECTOR_INDEXES)
INDEX_TO_LABEL = {v: k for k, v in lf.LABEL_VECTOR_INDEXES.items()}


class _Rec(dict):
    pass


class _Session:
    def __init__(self, driver):
        self.d = driver

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        return self.d.handle(cypher, kw)


class _Driver:
    def __init__(self, data, barrier=None, fail=()):
        self.data, self.barrier, self.fail = data, barrier, set(fail)
        self.sessions = 0
        self.calls = []
        self.lock = threading.Lock()

    def session(self):
        with self.lock:
            self.sessions += 1
        return _Session(self)

    def handle(self, cypher, kw):
        label = INDEX_TO_LABEL[kw["index_name"]]
        with self.lock:
            self.calls.append((label, kw["k"]))
        if self.barrier is not None:
            self.barrier.wait(timeout=5)  # raises BrokenBarrierError if queries are sequential
        if label in self.fail:
            raise RuntimeError("index down")
        return [_Rec(rid=r, score=s) for r, s in self.data.get(label, [])]


DATA = {
    "Task": [("ENC-TSK-001", 0.9), ("ENC-TSK-002", 0.5)],
    "Issue": [("ENC-ISS-001", 0.8), ("ENC-TSK-002", 0.7)],  # dup of TSK-002, higher score here
    "Feature": [("ENC-FTR-001", 0.6)],
    "Plan": [], "Lesson": [("ENC-LSN-001", 0.4)], "Document": [("DOC-AAA", 0.95)],
}


class TestParallelVector(unittest.TestCase):
    def test_label_queries_run_concurrently(self):
        drv = _Driver(DATA, barrier=threading.Barrier(len(LABELS)))
        ranks = lf._hybrid_vector_ranks(drv, "enceladus", [0.1], k_per_label=7)
        self.assertEqual(sorted(c[0] for c in drv.calls), sorted(LABELS))
        self.assertTrue(ranks)

    def test_one_session_per_label_and_k_preserved(self):
        drv = _Driver(DATA)
        lf._hybrid_vector_ranks(drv, "enceladus", [0.1], k_per_label=13)
        self.assertEqual(drv.sessions, len(LABELS))
        self.assertTrue(all(k == 13 for _, k in drv.calls))

    def test_merge_order_and_dedup_match_sequential(self):
        ranks = lf._hybrid_vector_ranks(_Driver(DATA), "enceladus", [0.1], k_per_label=5)
        self.assertEqual([r["record_id"] for r in ranks],
                         ["DOC-AAA", "ENC-TSK-001", "ENC-ISS-001", "ENC-TSK-002", "ENC-FTR-001", "ENC-LSN-001"])
        self.assertEqual([r["rank"] for r in ranks], [1, 2, 3, 4, 5, 6])
        dup = next(r for r in ranks if r["record_id"] == "ENC-TSK-002")
        self.assertEqual((dup["score"], dup["label"]), (0.7, "Issue"))

    def test_failing_label_degrades_only_that_label(self):
        ranks = lf._hybrid_vector_ranks(_Driver(DATA, fail=("Document",)), "enceladus", [0.1], k_per_label=5)
        ids = [r["record_id"] for r in ranks]
        self.assertNotIn("DOC-AAA", ids)
        self.assertIn("ENC-TSK-001", ids)
        self.assertIn("ENC-ISS-001", ids)

    def test_record_type_filter_single_label(self):
        drv = _Driver(DATA)
        ranks = lf._hybrid_vector_ranks(drv, "enceladus", [0.1], k_per_label=5, record_type_filter="task")
        self.assertEqual([c[0] for c in drv.calls], ["Task"])
        self.assertEqual([r["record_id"] for r in ranks], ["ENC-TSK-001", "ENC-TSK-002"])


class _KwSession(_Session):
    def run(self, cypher, **kw):
        return self.d.handle(cypher, kw)


class _KwDriver:
    def __init__(self, ft_fail_all=False):
        self.ft_fail_all = ft_fail_all

    def session(self):
        return _KwSession(self)

    def handle(self, cypher, kw):
        if "fulltext" in cypher:
            if self.ft_fail_all:
                raise RuntimeError("no index")
            return [_Rec(rid="ENC-TSK-001", score=2.0), _Rec(rid="ENC-TSK-002", score=1.0)]
        return [_Rec(rid="ENC-TSK-003", score=3.0)]


class TestKeywordTimers(unittest.TestCase):
    def test_fulltext_path_timers(self):
        t = {}
        rows = lf._hybrid_keyword_ranks(_KwDriver(), "enceladus", "latency graph", top_n=5, timings=t)
        self.assertEqual(len(rows), 2)
        self.assertEqual(t["keyword_rows"], 2)
        self.assertEqual(t["keyword_fallback_ms"], 0)
        self.assertIsInstance(t["keyword_fulltext_ms"], int)

    def test_fallback_path_timers(self):
        t = {}
        rows = lf._hybrid_keyword_ranks(_KwDriver(ft_fail_all=True), "enceladus", "latency graph", top_n=5, timings=t)
        self.assertEqual([r["record_id"] for r in rows], ["ENC-TSK-003"])
        self.assertEqual(t["keyword_rows"], 1)
        self.assertGreaterEqual(t["keyword_fallback_ms"], 0)
        self.assertIn("keyword_fulltext_ms", t)

    def test_timings_optional(self):
        self.assertEqual(len(lf._hybrid_keyword_ranks(_KwDriver(), "enceladus", "latency", top_n=5)), 2)

    def test_audit_line_carries_keyword_fields_by_default(self):
        lf._hybrid_telemetry_begin("h")
        audit = lf._graphsearch_audit_record({}, {}, "hybrid", "enceladus", {"nodes": []}, 1)
        for k in ("keyword_fulltext_ms", "keyword_fallback_ms", "keyword_rows"):
            self.assertEqual(audit[k], 0)


if __name__ == "__main__":
    unittest.main()
