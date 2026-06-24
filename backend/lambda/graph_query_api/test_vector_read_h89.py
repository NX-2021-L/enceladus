"""Unit tests for ENC-TSK-H89 / ENC-FTR-082 AC-12 — governed bulk vector-read.

Exercises the dedicated, strip-EXEMPT, paginated _query_vector_read handler:
  - response shape {record_id, record_type, embedding}
  - pagination cursor (offset / limit / next_offset / has_more)
  - strip-exemption scope (vector_read returns embeddings; the hybrid wiring is
    untouched and still strips at lambda_function.py:1785-1788)
  - limit clamping, record_type scoping, driver-unavailable handling

Pure-Python: no Neo4j or Bedrock. The Bolt driver/session is faked and
_ensure_live_driver is patched to a pass-through so the fake driver flows through.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

# Ensure the Lambda module directory is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import lambda_function as lf  # noqa: E402


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher, **kwargs):
        # Emulate the DB honoring SKIP/LIMIT: the test preloads exactly the rows
        # the query would return for its (offset, limit+1) window.
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(self, rows):
        self._rows = rows

    def session(self):
        return _FakeSession(self._rows)


def _row(rid, label):
    return {"record_id": rid, "labels": [label], "embedding": [0.1, 0.2, 0.3]}


class VectorReadTest(unittest.TestCase):
    def setUp(self):
        # _ensure_live_driver pings the pool; bypass it so the fake driver flows through.
        self._patch = mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: d)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_registered_in_search_surface(self):
        self.assertIn("vector_read", lf.VALID_SEARCH_TYPES)
        self.assertIn("vector_read", lf.SEARCH_HANDLERS)
        self.assertIs(lf.SEARCH_HANDLERS["vector_read"], lf._query_vector_read)

    def test_strip_exemption_scope(self):
        # vector_read is the ONLY handler that returns embeddings; the hybrid
        # handler wiring is untouched and the strip property name is unchanged.
        self.assertIs(lf.SEARCH_HANDLERS["hybrid"], lf._query_hybrid)
        self.assertEqual(lf._EMBEDDING_PROPERTY, "embedding")
        driver = _FakeDriver([_row("ENC-TSK-001", "Task")])
        out = lf._query_vector_read(driver, "enceladus", {"limit": 10})
        self.assertEqual(len(out["nodes"]), 1)
        # Strip-EXEMPT: the raw embedding survives in the response.
        self.assertIn("embedding", out["nodes"][0])
        self.assertEqual(out["nodes"][0]["embedding"], [0.1, 0.2, 0.3])

    def test_response_shape(self):
        driver = _FakeDriver([_row("ENC-TSK-001", "Task"), _row("ENC-ISS-002", "Issue")])
        out = lf._query_vector_read(driver, "enceladus", {"limit": 10})
        self.assertEqual(out["query_cypher"], "vector_read/paginated")
        self.assertEqual(out["edges"], [])
        self.assertEqual(out["paths"], [])
        self.assertEqual(out["embedding_property"], "embedding")
        self.assertEqual(out["embedding_dim"], 3)
        node = out["nodes"][0]
        self.assertEqual(set(node.keys()), {"record_id", "record_type", "embedding"})
        self.assertEqual(node["record_id"], "ENC-TSK-001")
        self.assertEqual(node["record_type"], "task")
        self.assertEqual(out["nodes"][1]["record_type"], "issue")

    def test_pagination_has_more(self):
        # limit=2, DB returns limit+1=3 rows => has_more, page trimmed to 2.
        driver = _FakeDriver([
            _row("ENC-TSK-001", "Task"),
            _row("ENC-TSK-002", "Task"),
            _row("ENC-TSK-003", "Task"),
        ])
        out = lf._query_vector_read(driver, "enceladus", {"offset": 0, "limit": 2})
        self.assertEqual(out["pagination"]["returned"], 2)
        self.assertTrue(out["pagination"]["has_more"])
        self.assertEqual(out["pagination"]["next_offset"], 2)
        self.assertEqual(len(out["nodes"]), 2)

    def test_pagination_last_page(self):
        # limit=5, DB returns 3 (< limit+1) => no more pages.
        driver = _FakeDriver([
            _row("ENC-TSK-001", "Task"),
            _row("ENC-TSK-002", "Task"),
            _row("ENC-TSK-003", "Task"),
        ])
        out = lf._query_vector_read(driver, "enceladus", {"offset": 10, "limit": 5})
        self.assertEqual(out["pagination"]["returned"], 3)
        self.assertFalse(out["pagination"]["has_more"])
        self.assertIsNone(out["pagination"]["next_offset"])

    def test_limit_clamping(self):
        driver = _FakeDriver([])
        hi = lf._query_vector_read(driver, "enceladus", {"limit": 999999})
        self.assertEqual(hi["pagination"]["limit"], lf._VECTOR_READ_MAX_LIMIT)
        lo = lf._query_vector_read(driver, "enceladus", {"limit": -4})
        self.assertEqual(lo["pagination"]["limit"], 1)
        bad = lf._query_vector_read(driver, "enceladus", {"limit": "abc"})
        self.assertEqual(bad["pagination"]["limit"], lf._VECTOR_READ_DEFAULT_LIMIT)

    def test_record_type_filter_invalid(self):
        driver = _FakeDriver([])
        out = lf._query_vector_read(driver, "enceladus", {"record_type": "bogus"})
        self.assertIn("error", out)
        self.assertIn("record_type must be one of", out["error"])

    def test_record_type_filter_valid(self):
        driver = _FakeDriver([_row("ENC-PLN-001", "Plan")])
        out = lf._query_vector_read(driver, "enceladus", {"record_type": "plan"})
        self.assertNotIn("error", out)
        self.assertEqual(out["nodes"][0]["record_type"], "plan")

    def test_driver_unavailable(self):
        with mock.patch.object(lf, "_ensure_live_driver", side_effect=lambda d: None):
            out = lf._query_vector_read(object(), "enceladus", {})
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
