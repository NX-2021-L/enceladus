"""ENC-TSK-S28-0E: graph_sync loop guard, conditional projection marker, version_seq idempotence.

Run: python3 -m pytest test_projection_s28_0e.py -q
"""
import unittest
from unittest.mock import MagicMock, patch

import lambda_function as lf


def _img(vseq, status="pending", **extra):
    img = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}, "record_type": {"S": "task"},
           "title": {"S": "t"}, "version_seq": {"N": str(vseq)}, "projection_status": {"S": status}}
    img.update(extra)
    return img


class LoopGuardTests(unittest.TestCase):
    def test_projection_only_diff_skipped(self):
        old = _img(5)
        new = _img(5, status="projected", projected_version_seq={"N": "5"}, t_projected={"N": "1"})
        self.assertTrue(lf._projection_only_diff(old, new))

    def test_real_change_not_skipped(self):
        old = _img(5)
        new = _img(6, status="projected", projected_version_seq={"N": "5"})
        self.assertFalse(lf._projection_only_diff(old, new))
        self.assertFalse(lf._projection_only_diff(None, new))
        self.assertFalse(lf._projection_only_diff(old, dict(old)))  # identical images: not a marker write

    def test_handler_skips_marker_write(self):
        rec = {"eventName": "MODIFY", "dynamodb": {"SequenceNumber": "1", "OldImage": _img(5),
               "NewImage": _img(5, status="projected", projected_version_seq={"N": "5"})}}
        with patch.object(lf, "_get_neo4j_driver", return_value=MagicMock()), \
             patch.object(lf, "_process_record") as proc:
            out = lf.handler({"Records": [rec]}, None)
        proc.assert_not_called()
        self.assertEqual(out["statusCode"], 200)


class MarkerKindTests(unittest.TestCase):
    """ENC-TSK-S47-0B: write_kind is a loop-guard attr, so governed->marker flips stay projection-only."""

    def test_write_kind_flip_is_projection_only(self):
        old = _img(5, write_kind={"S": "governed"})
        new = _img(5, status="projected", projected_version_seq={"N": "5"}, t_projected={"N": "1"},
                   write_kind={"S": "marker"})
        self.assertTrue(lf._projection_only_diff(old, new))
        legacy = _img(5)  # legacy item without the attribute
        self.assertTrue(lf._projection_only_diff(legacy, new))

    def test_governed_write_after_marker_is_not_projection_only(self):
        old = _img(5, status="projected", write_kind={"S": "marker"})
        new = _img(6, write_kind={"S": "governed"})
        self.assertFalse(lf._projection_only_diff(old, new))


class MarkProjectedTests(unittest.TestCase):
    def test_conditional_minimal_update(self):
        ddb = MagicMock()
        self.assertTrue(lf._mark_source_projected(_img(9), 9, ddb))
        kw = ddb.update_item.call_args.kwargs
        self.assertIn("projected_version_seq < :v", kw["ConditionExpression"])
        self.assertIn("version_seq = :v", kw["ConditionExpression"])
        self.assertEqual(kw["Key"], {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}})
        self.assertEqual(kw["UpdateExpression"],
                         "SET projection_status = :p, projected_version_seq = :v, t_projected = :t, write_kind = :wk")
        self.assertEqual(kw["ExpressionAttributeValues"][":wk"], {"S": "marker"})  # ENC-TSK-S47-0B

    def test_condition_failure_is_silent(self):
        ddb = MagicMock()
        err = Exception("x"); err.response = {"Error": {"Code": "ConditionalCheckFailedException"}}
        ddb.update_item.side_effect = err
        self.assertFalse(lf._mark_source_projected(_img(9), 9, ddb))


class IdempotenceTests(unittest.TestCase):
    def _run(self, images):
        """Feed images in order; the fake graph holds the stored version_seq."""
        state = {"v": None, "upserts": []}
        class Session:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def execute_read(s, fn): return state["v"]
            def execute_write(s, fn): return None
        driver = MagicMock(); driver.session.return_value = Session()
        def upsert(tx, record):
            state["v"] = int(record["version_seq"]); state["upserts"].append(state["v"])
        marks = []
        with patch.object(lf, "_upsert_node", side_effect=upsert), patch.object(lf, "_reconcile_edges"), \
             patch.object(lf, "_upsert_project_node"), patch.object(lf, "_project_mutated_edge"), \
             patch.object(lf, "_read_node_version_seq", side_effect=lambda tx, l, r: state["v"]), \
             patch.object(lf, "_mark_source_projected", side_effect=lambda img, v, ddb=None: marks.append(v)):
            session = Session()
            driver.session.return_value = session
            session.execute_write = lambda fn: fn(None)
            session.execute_read = lambda fn: fn(None)
            for vs in images:
                lf._process_record(driver, {"eventName": "MODIFY", "dynamodb": {"NewImage": _img(vs), "OldImage": _img(vs - 1)}})
        return state, marks

    def test_duplicate_and_out_of_order_yield_one_projection_at_highest(self):
        state, marks = self._run([7, 5, 7, 6])
        self.assertEqual(state["upserts"], [7])
        self.assertEqual(marks, [7])
        self.assertEqual(state["v"], 7)


if __name__ == "__main__":
    unittest.main()
