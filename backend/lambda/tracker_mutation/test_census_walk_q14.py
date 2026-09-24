"""ENC-TSK-Q14-0A (O2.1): _census_walk bounded raw walk.

Drives _census_walk against fake_ddb_paging.PagingTable -- same real
Limit/ExclusiveStartKey/LastEvaluatedKey-walking fake the O1 (ENC-TSK-Q13)
pagination tests use -- covering the three acceptance criteria named in
o2_acs.md verbatim: exhaustion, the raw-page budget, and the wall-clock
budget. Counter rows are seeded alongside real rows to prove they never
leak into `rows`.
"""
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _base_item(n, project_id="proj", record_type="task", status="open"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"{record_type}#TSK-{n:04d}"},
        "record_type": {"S": record_type},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
        "updated_at": {"S": "2026-09-23T00:00:00Z"},
    }


def _counter_item(record_type, project_id="proj"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"counter#{record_type}"},
        "record_type": {"S": "counter"},
        "status": {"S": ""},
    }


class TestCensusWalk(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _walk(self, table, **kwargs):
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            return self.lf._census_walk("proj", **kwargs)

    def test_census_walk_exhausts(self):
        items = [_base_item(n) for n in range(1, 1201)]
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table, max_raw_pages=50)

        self.assertTrue(result["exhausted"])
        self.assertIsNone(result["truncated_reason"])
        self.assertEqual(len(result["rows"]), 1200)

    def test_census_walk_page_budget(self):
        items = [_base_item(n) for n in range(1, 1201)]
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table, max_raw_pages=2)

        self.assertFalse(result["exhausted"])
        self.assertEqual(result["truncated_reason"], "pages")
        # 2 raw pages walked at 200/page == 400 rows walked, no more, no less.
        self.assertEqual(len(result["rows"]), 400)
        self.assertEqual(len(table.calls), 2)

    def test_census_walk_time_budget(self):
        items = [_base_item(n) for n in range(1, 1201)]
        table = PagingTable(items, raw_page_size=200)

        # Clock ticks far past CENSUS_WALL_CLOCK_MS (default 6000ms) after
        # the very first raw page.
        ticks = iter([0.0, 100.0, 200.0])

        def fake_clock():
            return next(ticks, 200.0)

        result = self._walk(table, wall_clock_ms=6000, clock=fake_clock)

        self.assertFalse(result["exhausted"])
        self.assertEqual(result["truncated_reason"], "time")
        self.assertEqual(len(table.calls), 1, "budget trips right after the first raw page")

    def test_census_walk_excludes_counter_rows(self):
        items = [_counter_item("task")] + [_base_item(n) for n in range(1, 6)]
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table)

        self.assertTrue(result["exhausted"])
        self.assertEqual(len(result["rows"]), 5)
        for row in result["rows"]:
            self.assertFalse(row["record_id"].startswith("counter#"))

    def test_census_walk_gsi_branch_on_type_filter(self):
        items = (
            [_base_item(n, record_type="task") for n in range(1, 4)]
            + [_base_item(n, record_type="issue") for n in range(4, 7)]
        )
        table = PagingTable(items, raw_page_size=200)

        result = self._walk(table, record_type="task")

        self.assertEqual(result["branch"], "gsi")
        self.assertEqual(len(result["rows"]), 3)


if __name__ == "__main__":
    unittest.main()
