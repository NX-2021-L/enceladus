"""Tests for ENC-TSK-C72 / ENC-ISS-191: CHILD_OF parent projection.

Two invariants are exercised:

1. The CHILD_OF emission must accept the canonical ``parent`` attribute and
   also tolerate the historically-mixed ``parent_task_id`` / ``parent_id``
   aliases so legacy records still project correctly.
2. The emission must MERGE a label-correct placeholder Task for the parent
   before MERGEing the edge so CHILD_OF lands even when the parent has not
   yet been projected (the projection race that ENC-ISS-191 observed across
   all probed anchors).
"""
import unittest
from unittest.mock import MagicMock


class TestExtractTaskParentId(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_canonical_parent_attribute(self):
        rec = {"record_type": "task", "parent": "ENC-TSK-100"}
        self.assertEqual(self.lf._extract_task_parent_id(rec), "ENC-TSK-100")

    def test_parent_task_id_alias(self):
        rec = {"record_type": "task", "parent_task_id": "JAP-TSK-501"}
        self.assertEqual(self.lf._extract_task_parent_id(rec), "JAP-TSK-501")

    def test_parent_id_alias(self):
        rec = {"record_type": "task", "parent_id": "MJR-TSK-042"}
        self.assertEqual(self.lf._extract_task_parent_id(rec), "MJR-TSK-042")

    def test_canonical_wins_over_alias(self):
        rec = {
            "record_type": "task",
            "parent": "ENC-TSK-CANONICAL",
            "parent_task_id": "ENC-TSK-LEGACY",
            "parent_id": "ENC-TSK-OTHER",
        }
        self.assertEqual(
            self.lf._extract_task_parent_id(rec), "ENC-TSK-CANONICAL"
        )

    def test_composite_record_id_is_stripped(self):
        rec = {"record_type": "task", "parent": "task#ENC-TSK-200"}
        self.assertEqual(self.lf._extract_task_parent_id(rec), "ENC-TSK-200")

    def test_empty_string_falls_through_to_alias(self):
        rec = {
            "record_type": "task",
            "parent": "   ",
            "parent_task_id": "ENC-TSK-300",
        }
        self.assertEqual(self.lf._extract_task_parent_id(rec), "ENC-TSK-300")

    def test_no_parent_returns_empty(self):
        rec = {"record_type": "task"}
        self.assertEqual(self.lf._extract_task_parent_id(rec), "")


class TestChildOfPlaceholderMerge(unittest.TestCase):
    """CHILD_OF emission MERGEs a placeholder Task parent before the edge."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _run(self, record):
        tx = MagicMock()
        self.lf._reconcile_edges(tx, record)
        return tx

    def _calls(self, tx):
        return [str(c) for c in tx.run.call_args_list]

    def test_placeholder_and_edge_emitted_for_canonical_parent(self):
        tx = self._run({
            "record_type": "task",
            "record_id": "ENC-TSK-CHILD",
            "item_id": "ENC-TSK-CHILD",
            "parent": "ENC-TSK-PARENT",
        })
        calls = self._calls(tx)
        self.assertTrue(
            any(
                "MERGE (p:Task {record_id: $parent_id})" in c
                and "is_placeholder" in c
                for c in calls
            ),
            f"Expected Task placeholder MERGE for parent; calls were: {calls}",
        )
        self.assertTrue(
            any("MERGE (child)-[:CHILD_OF]->(parent)" in c for c in calls),
            f"Expected CHILD_OF edge MERGE; calls were: {calls}",
        )

    def test_placeholder_emitted_for_parent_task_id_alias(self):
        tx = self._run({
            "record_type": "task",
            "record_id": "JAP-TSK-LEGACY",
            "item_id": "JAP-TSK-LEGACY",
            "parent_task_id": "JAP-TSK-501",
        })
        calls = self._calls(tx)
        self.assertTrue(
            any("CHILD_OF" in c for c in calls),
            f"Expected CHILD_OF emission via parent_task_id alias; "
            f"calls were: {calls}",
        )

    def test_no_parent_attribute_emits_no_child_of(self):
        tx = self._run({
            "record_type": "task",
            "record_id": "ENC-TSK-ORPHAN",
            "item_id": "ENC-TSK-ORPHAN",
        })
        calls = self._calls(tx)
        self.assertFalse(
            any("CHILD_OF" in c for c in calls),
            f"Expected no CHILD_OF emission for orphan task; "
            f"calls were: {calls}",
        )

    def test_non_task_record_type_emits_no_child_of(self):
        tx = self._run({
            "record_type": "issue",
            "record_id": "ENC-ISS-100",
            "item_id": "ENC-ISS-100",
            "parent": "ENC-ISS-099",
        })
        calls = self._calls(tx)
        self.assertFalse(
            any("CHILD_OF" in c for c in calls),
            f"Issue parent must not project CHILD_OF; calls were: {calls}",
        )

    def test_parent_placeholder_ref_collected_for_prune(self):
        rec = {
            "record_type": "task",
            "record_id": "ENC-TSK-CHILD",
            "parent": "ENC-TSK-PARENT",
        }
        refs = self.lf._collect_placeholder_target_refs(rec)
        self.assertIn(("Task", "ENC-TSK-PARENT"), refs)

    def test_parent_placeholder_ref_collected_via_alias(self):
        rec = {
            "record_type": "task",
            "record_id": "JAP-TSK-LEGACY",
            "parent_task_id": "JAP-TSK-501",
        }
        refs = self.lf._collect_placeholder_target_refs(rec)
        self.assertIn(("Task", "JAP-TSK-501"), refs)


if __name__ == "__main__":
    unittest.main()
