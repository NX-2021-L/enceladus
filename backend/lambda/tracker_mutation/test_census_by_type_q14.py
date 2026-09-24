"""ENC-TSK-Q14-0C (O2.3): escalation second walk + by_type merge.

Covers the three scenarios named in o2_acs.md verbatim:
  (a) both walks complete -> by_type sums to count, excluded_types absent.
  (b) escalation budget forced to 0 -> excluded_types ['escalation'] AND
      count_truncated true (escalation rows excluded from count/pages).
  (c) type=task census omits the escalation walk entirely and by_type has
      only task.

Plus direct unit coverage of _census_escalation_walk itself (exhaustion +
page budget), mirroring the O2.1 (_census_walk) test shape.
"""
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _task_item(n, project_id="proj", status="open"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"task#TSK-{n:04d}"},
        "record_type": {"S": "task"},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
        "updated_at": {"S": "2026-09-23T00:00:00Z"},
    }


def _escalation_item(n, project_id="proj", status=None):
    item = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"escalation#ESC-{n:04d}"},
    }
    if status is not None:
        item["status"] = {"S": status}
    return item


class TestCensusEscalationWalk(unittest.TestCase):
    """Direct coverage of _census_escalation_walk (mirrors O2.1's shape)."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _walk(self, table, **kwargs):
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            return self.lf._census_escalation_walk("proj", **kwargs)

    def test_exhausts(self):
        items = [_escalation_item(n) for n in range(1, 121)]
        table = PagingTable(items, raw_page_size=50)

        result = self._walk(table, max_raw_pages=50)

        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["truncated_reason"])
        self.assertEqual(result["count"], 120)

    def test_page_budget_truncates(self):
        items = [_escalation_item(n) for n in range(1, 121)]
        table = PagingTable(items, raw_page_size=50)

        result = self._walk(table, max_raw_pages=1)

        self.assertFalse(result["exhausted"])
        self.assertEqual(result["truncated_reason"], "pages")
        self.assertEqual(result["count"], 50)

    def test_zero_budget_short_circuits_with_no_ddb_call(self):
        table = mock.MagicMock()
        table.query.side_effect = AssertionError("must not call ddb.query with zero budget")

        result = self._walk(table, max_raw_pages=0)

        self.assertFalse(result["exhausted"])
        self.assertEqual(result["truncated_reason"], "pages")
        self.assertEqual(result["count"], 0)
        table.query.assert_not_called()

    def test_status_filter_applies_inside_the_walk(self):
        """Review fix (ENC-TSK-Q14-0C): status_filter must reach the
        escalation walk's own FilterExpression, mirroring _census_walk."""
        items = [_escalation_item(n, status="requested") for n in range(1, 5)] + [
            _escalation_item(n, status="resolved") for n in range(5, 11)
        ]
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table, status_filter="requested", max_raw_pages=50)

        self.assertTrue(result["exhausted"])
        self.assertEqual(result["count"], 4)

    def test_no_status_filter_counts_every_status(self):
        items = [_escalation_item(n, status="requested") for n in range(1, 5)] + [
            _escalation_item(n, status="resolved") for n in range(5, 11)
        ]
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table, max_raw_pages=50)

        self.assertTrue(result["exhausted"])
        self.assertEqual(result["count"], 10)


class TestCensusCollect(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_both_walks_complete_by_type_sums_to_count(self):
        primary_table = PagingTable([_task_item(n) for n in range(1, 6)], raw_page_size=200)
        escalation_table = PagingTable([_escalation_item(n) for n in range(1, 4)], raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", side_effect=[primary_table, escalation_table]):
            result = self.lf._census_collect("proj")

        self.assertEqual(result["by_type"], {"task": 5, "escalation": 3})
        self.assertEqual(result["count"], sum(result["by_type"].values()))
        self.assertEqual(result["count"], 8)
        self.assertEqual(result["excluded_types"], [])
        self.assertFalse(result["count_truncated"])
        self.assertTrue(result["exhausted"])

    def test_escalation_budget_forced_to_zero_excludes_and_truncates(self):
        primary_table = PagingTable([_task_item(n) for n in range(1, 6)], raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", side_effect=[primary_table, RuntimeError("unused")]):
            result = self.lf._census_collect("proj", escalation_max_raw_pages=0)

        self.assertEqual(result["excluded_types"], ["escalation"])
        self.assertTrue(result["count_truncated"])
        # Escalation rows excluded from count/pages entirely when truncated.
        self.assertNotIn("escalation", result["by_type"])
        self.assertEqual(result["by_type"], {"task": 5})
        self.assertEqual(result["count"], 5)

    def test_status_filter_reaches_both_walks_no_type_filter(self):
        """Review fix (ENC-TSK-Q14-0C): a mixed (no `type`) census with a
        `status` filter must not silently mix a filtered task count with an
        unfiltered escalation count (AC Q14-0D)."""
        primary_table = PagingTable(
            [_task_item(n, status="open") for n in range(1, 4)]
            + [_task_item(n, status="closed") for n in range(4, 6)],
            raw_page_size=200,
        )
        escalation_table = PagingTable(
            [_escalation_item(n, status="open") for n in range(1, 5)]
            + [_escalation_item(n, status="resolved") for n in range(5, 11)],
            raw_page_size=200,
        )

        with mock.patch.object(self.lf, "_get_ddb", side_effect=[primary_table, escalation_table]):
            result = self.lf._census_collect("proj", status_filter="open")

        # Only the 3 open tasks + 4 open escalations should count -- not
        # all 3 open tasks + all 10 escalations regardless of status.
        self.assertEqual(result["by_type"], {"task": 3, "escalation": 4})
        self.assertEqual(result["count"], 7)
        self.assertEqual(result["excluded_types"], [])
        self.assertFalse(result["count_truncated"])

    def test_type_task_omits_escalation_walk_entirely(self):
        primary_table = PagingTable(
            [_task_item(n) for n in range(1, 4)]
            + [{**_task_item(n), "record_type": {"S": "issue"}} for n in range(4, 6)],
            raw_page_size=200,
        )

        with mock.patch.object(
            self.lf, "_get_ddb", side_effect=[primary_table, RuntimeError("must not be called")],
        ) as mocked:
            result = self.lf._census_collect("proj", record_type="task")

        self.assertEqual(mocked.call_count, 1, "escalation walk never calls _get_ddb")
        self.assertEqual(result["by_type"], {"task": 3})
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["excluded_types"], [])
        self.assertFalse(result["count_truncated"])


if __name__ == "__main__":
    unittest.main()
