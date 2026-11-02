"""ENC-TSK-S08 (N1): pathway edge reconstruction excludes the anchor from targets."""
import logging
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import lambda_function as lf  # noqa: E402


class _Row(dict):
    pass


class _Session:
    def __init__(self, rows, calls):
        self._rows, self._calls = rows, calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **kw):
        self._calls.append((cypher, kw))
        return [_Row(edge_id=e, etype=t, s=s, e=en) for (e, t, s, en) in self._rows]


class _Driver:
    def __init__(self, rows):
        self.calls = []
        self._rows = rows

    def session(self):
        return _Session(self._rows, self.calls)


class PathwayAnchorS08(unittest.TestCase):
    def test_pathway_anchor_in_results(self):
        drv = _Driver([("e1", "RELATED_TO", "ENC-TSK-A", "ENC-TSK-B")])
        with self.assertLogs(lf.logger, level="DEBUG") as cm:
            lf.logger.debug("sentinel")
            edges, part, seq = lf._reconstruct_pathway_edges(
                drv, "enceladus", "ENC-TSK-A", ["ENC-TSK-A", "ENC-TSK-B"])
        self.assertTrue(edges)
        self.assertEqual(seq[0], "ENC-TSK-A")
        cypher, kw = drv.calls[0]
        self.assertNotIn("ENC-TSK-A", kw["rids"])
        self.assertEqual(kw["rids"], ["ENC-TSK-B"])
        self.assertIn("target.record_id <> $rid", cypher)
        self.assertFalse([r for r in cm.records if "failed" in r.getMessage()])

    def test_only_anchor_is_skipped(self):
        drv = _Driver([])
        edges, part, seq = lf._reconstruct_pathway_edges(
            drv, "enceladus", "ENC-TSK-A", ["ENC-TSK-A"])
        self.assertEqual((edges, part, seq), ([], [], ["ENC-TSK-A"]))
        self.assertEqual(drv.calls, [])


if __name__ == "__main__":
    unittest.main()
