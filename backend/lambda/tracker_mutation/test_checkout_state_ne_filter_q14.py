"""ENC-TSK-Q14-0A (M36 tile/Feed invariant): `checkout_state_ne` query-param.

Rows whose checkout_state equals the given value are excluded INSIDE the
walk (DynamoDB FilterExpression: `attribute_not_exists(checkout_state) OR
checkout_state <> :csne`), applied IDENTICALLY in _handle_list_records
(plain list) and in the census primary walk (_census_walk) via the shared
_add_checkout_state_ne_filter helper -- so a census page cursor replayed
into the list route with the same checkout_state_ne yields the same
slices. The escalation walk is unaffected: escalation rows carry no
checkout_state attribute at all, so they are never excluded regardless of
the value given.
"""
import json
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _raw_item(n, project_id="proj", record_type="task", status="open", checkout_state=None):
    item = {
        "project_id": {"S": project_id},
        "record_id": {"S": f"{record_type}#ENC-TSK-{n:04d}"},
        "item_id": {"S": f"ENC-TSK-{n:04d}"},
        "record_type": {"S": record_type},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
        "updated_at": {"S": "2026-09-23T00:00:00Z"},
    }
    if checkout_state is not None:
        item["checkout_state"] = {"S": checkout_state}
    return item


def _escalation_item(n, project_id="proj", status="requested"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"escalation#ENC-ESC-{n:04d}"},
        "status": {"S": status},
    }


class TestListRecordsCheckoutStateNe(unittest.TestCase):
    """checkout_state_ne on the plain-list route (_handle_list_records)."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, table, **query_params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            return self.lf._handle_list_records("proj", query_params)

    def test_excludes_checked_out_rows_base_branch(self):
        items = (
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)]
            + [_raw_item(n) for n in range(4, 9)]  # no checkout_state attribute at all
        )
        table = PagingTable(items, raw_page_size=200)

        resp = self._call(table, checkout_state_ne="checked_out")
        body = json.loads(resp["body"])

        self.assertEqual(resp["statusCode"], 200)
        returned_ids = {r["item_id"] for r in body["records"]}
        self.assertEqual(returned_ids, {f"ENC-TSK-{n:04d}" for n in range(4, 9)})
        self.assertEqual(body["count"], 5)

    def test_rows_missing_checkout_state_attribute_always_pass(self):
        # No row in this project ever had checkout_state set -- attribute
        # simply absent everywhere. attribute_not_exists(checkout_state)
        # must pass all of them.
        items = [_raw_item(n) for n in range(1, 6)]
        table = PagingTable(items, raw_page_size=200)

        resp = self._call(table, checkout_state_ne="checked_out")
        body = json.loads(resp["body"])

        self.assertEqual(body["count"], 5)

    def test_other_checkout_state_values_pass(self):
        items = [
            _raw_item(1, checkout_state="checked_out"),
            _raw_item(2, checkout_state="checked_in"),
            _raw_item(3),
        ]
        table = PagingTable(items, raw_page_size=200)

        resp = self._call(table, checkout_state_ne="checked_out")
        body = json.loads(resp["body"])

        returned_ids = {r["item_id"] for r in body["records"]}
        self.assertEqual(returned_ids, {"ENC-TSK-0002", "ENC-TSK-0003"})

    def test_gsi_branch_also_excludes_checked_out_rows(self):
        items = [
            _raw_item(n, checkout_state="checked_out" if n <= 2 else None)
            for n in range(1, 6)
        ]
        table = PagingTable(items, raw_page_size=200)

        resp = self._call(table, type="task", checkout_state_ne="checked_out")
        body = json.loads(resp["body"])

        returned_ids = {r["item_id"] for r in body["records"]}
        self.assertEqual(returned_ids, {"ENC-TSK-0003", "ENC-TSK-0004", "ENC-TSK-0005"})

    def test_absent_param_is_unchanged_behaviour(self):
        items = (
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)]
            + [_raw_item(n) for n in range(4, 9)]
        )
        table = PagingTable(items, raw_page_size=200)

        resp = self._call(table)  # no checkout_state_ne at all
        body = json.loads(resp["body"])

        self.assertEqual(body["count"], 8, "every row returned -- filter never applied")


class TestCensusWalkCheckoutStateNe(unittest.TestCase):
    """checkout_state_ne on the census primary walk (_census_walk /
    _handle_list_census), plus the escalation-walk-unaffected invariant."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_census_walk_excludes_checked_out_rows(self):
        items = (
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)]
            + [_raw_item(n) for n in range(4, 9)]
        )
        table = PagingTable(items, raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            walk = self.lf._census_walk("proj", checkout_state_ne="checked_out")

        self.assertTrue(walk["exhausted"])
        returned_ids = {row["record_id"] for row in walk["rows"]}
        self.assertEqual(returned_ids, {f"task#ENC-TSK-{n:04d}" for n in range(4, 9)},
                         "walk['rows'] keeps the RAW record_id -- unaffected by ENC-TSK-Q27")

    def test_census_walk_absent_param_is_unchanged_behaviour(self):
        items = (
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)]
            + [_raw_item(n) for n in range(4, 9)]
        )
        table = PagingTable(items, raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            walk = self.lf._census_walk("proj")

        self.assertEqual(len(walk["rows"]), 8, "every row walked -- filter never applied")

    def test_handle_list_census_excludes_checked_out_rows(self):
        # _census_collect calls _get_ddb() once for the primary walk and
        # (when escalations are in scope) again for the escalation walk --
        # two separate PagingTable instances via side_effect, mirroring
        # test_census_by_type_q14.py's own mixed-walk tests.
        primary_table = PagingTable(
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)]
            + [_raw_item(n) for n in range(4, 9)],
            raw_page_size=200,
        )
        escalation_table = PagingTable([], raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", side_effect=[primary_table, escalation_table]):
            resp = self.lf._handle_list_census("proj", {"checkout_state_ne": "checked_out"})
        body = json.loads(resp["body"])

        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(body["count"], 5)
        self.assertEqual(set(body["ids"]), {f"ENC-TSK-{n:04d}" for n in range(4, 9)},
                         "ENC-TSK-Q27: payload ids are item ids, not raw record_ids")

    def test_escalation_walk_unaffected_by_checkout_state_ne(self):
        """D5/M36: escalations have no checkout_state -> never excluded,
        regardless of checkout_state_ne -- documented on _census_collect."""
        primary_table = PagingTable(
            [_raw_item(n, checkout_state="checked_out") for n in range(1, 4)],
            raw_page_size=200,
        )
        escalation_table = PagingTable([_escalation_item(n) for n in range(1, 5)], raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", side_effect=[primary_table, escalation_table]):
            resp = self.lf._handle_list_census("proj", {"checkout_state_ne": "checked_out"})
        body = json.loads(resp["body"])

        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(body["by_type"].get("escalation"), 4, "all 4 escalations counted")
        self.assertNotIn("task", body["by_type"], "all 3 task rows were checked_out -> excluded")


class TestCensusCursorReplayCheckoutStateNe(unittest.TestCase):
    """Cross-test (o2_acs.md style, mirrors test_census_pages_q14.py): a
    census page cursor replayed with the same checkout_state_ne into
    _handle_list_records returns exactly the next slice the census walk
    itself produced -- proving the two routes exclude identically."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_page_cursor_replay_yields_identical_slice(self):
        # 70 rows total; every 3rd is checked_out (excluded by both routes).
        items = [
            _raw_item(n, checkout_state="checked_out" if n % 3 == 0 else None)
            for n in range(1, 71)
        ]
        table = PagingTable(items, raw_page_size=200)
        surviving = [it for it in items if "checkout_state" not in it]

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            walk = self.lf._census_walk("proj", checkout_state_ne="checked_out")
        self.assertTrue(walk["exhausted"])
        rows = walk["rows"]
        self.assertEqual(len(rows), len(surviving))

        pages = self.lf._census_pages(rows, 30, walk["branch"])
        self.assertGreaterEqual(len(pages), 2)
        first_page_n = pages[0]["n"]

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            resp = self.lf._handle_list_records(
                "proj",
                {
                    "page_size": "30",
                    "next_cursor": pages[1]["cursor"],
                    "checkout_state_ne": "checked_out",
                },
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        returned_ids = [r["record_id"] for r in body["records"]]
        expected_ids = [r["record_id"] for r in rows[first_page_n:first_page_n + len(returned_ids)]]
        self.assertEqual(returned_ids, expected_ids)

    def test_page_cursor_replay_without_checkout_state_ne_diverges(self):
        """Sanity check for the cross-test above: replaying the SAME
        cursor WITHOUT checkout_state_ne resumes at a different, larger
        slice (checked_out rows re-enter the walk) -- proving the
        cross-test's match above is actually exercising the filter, not
        coincidental."""
        items = [
            _raw_item(n, checkout_state="checked_out" if n % 3 == 0 else None)
            for n in range(1, 71)
        ]
        table = PagingTable(items, raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            walk = self.lf._census_walk("proj", checkout_state_ne="checked_out")
        pages = self.lf._census_pages(walk["rows"], 30, walk["branch"])

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            resp = self.lf._handle_list_records(
                "proj", {"page_size": "30", "next_cursor": pages[1]["cursor"]},
            )
        body = json.loads(resp["body"])
        returned_ids = [r["record_id"] for r in body["records"]]

        # At least one checked_out row's record_id shows up once
        # checkout_state_ne is dropped, proving the filtered cross-test
        # above (which excludes all of them) is actually exercising the
        # filter, not coincidentally matching.
        checked_out_ids = {it["record_id"]["S"] for it in items if "checkout_state" in it}
        self.assertTrue(set(returned_ids) & checked_out_ids)


class TestPagingTableFilterExpressionOrGroup(unittest.TestCase):
    """Direct fake contract test (mirrors test_ddb_paging_fake_q13.py's
    style) for the widened FilterExpression evaluator: one parenthesized
    OR-group ANDed alongside a flat equality clause."""

    def test_attribute_not_exists_or_not_equal_combined_with_and(self):
        items = [
            {"project_id": {"S": "proj"}, "record_id": {"S": "task#1"},
             "record_type": {"S": "task"}, "status": {"S": "open"}},
            {"project_id": {"S": "proj"}, "record_id": {"S": "task#2"},
             "record_type": {"S": "task"}, "status": {"S": "open"},
             "checkout_state": {"S": "checked_out"}},
            {"project_id": {"S": "proj"}, "record_id": {"S": "task#3"},
             "record_type": {"S": "task"}, "status": {"S": "open"},
             "checkout_state": {"S": "checked_in"}},
        ]
        table = PagingTable(items, raw_page_size=200)
        resp = table.query(
            TableName="t",
            KeyConditionExpression="project_id = :pid",
            FilterExpression="#st = :st AND (attribute_not_exists(#cs) OR #cs <> :csne)",
            ExpressionAttributeNames={"#st": "status", "#cs": "checkout_state"},
            ExpressionAttributeValues={
                ":pid": {"S": "proj"}, ":st": {"S": "open"}, ":csne": {"S": "checked_out"},
            },
            Limit=200,
        )
        returned_ids = {it["record_id"]["S"] for it in resp["Items"]}
        self.assertEqual(returned_ids, {"task#1", "task#3"})


if __name__ == "__main__":
    unittest.main()
