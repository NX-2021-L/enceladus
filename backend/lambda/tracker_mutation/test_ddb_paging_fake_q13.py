"""ENC-TSK-Q13 (O1.4): fake_ddb_paging.PagingTable contract tests.

Standalone contract for the fake itself (no lambda_function involved) --
Limit/ExclusiveStartKey walking, LastEvaluatedKey presence exactly on
non-final pages, the base + GSI branch shapes, and FilterExpression applied
AFTER Limit (a raw page can return fewer -- including zero -- matching
Items than Limit while LastEvaluatedKey is still present).
"""
import unittest

from fake_ddb_paging import PagingTable


def _base_item(n, project_id="proj", status="open"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"task#TSK-{n:04d}"},
        "record_type": {"S": "task"},
        "status": {"S": status},
    }


class TestPagingTableContract(unittest.TestCase):
    def test_1000_items_limit_200_five_calls_lek_absent_only_last(self):
        items = [_base_item(n) for n in range(1, 1001)]
        table = PagingTable(items, raw_page_size=1000)  # doesn't further constrain Limit

        kwargs = {
            "TableName": "t",
            "KeyConditionExpression": "project_id = :pid",
            "ExpressionAttributeValues": {":pid": {"S": "proj"}},
            "Limit": 200,
        }
        seen_ids = []
        calls = 0
        while True:
            resp = table.query(**kwargs)
            seen_ids.extend(it["record_id"]["S"] for it in resp["Items"])
            calls += 1
            lek = resp.get("LastEvaluatedKey")
            if calls < 5:
                self.assertIsNotNone(lek, f"call {calls} should carry LastEvaluatedKey")
            if not lek:
                break
            self.assertLessEqual(calls, 5, "must not need more than 5 calls")
            kwargs["ExclusiveStartKey"] = lek

        self.assertEqual(calls, 5)
        self.assertEqual(len(seen_ids), 1000)
        self.assertEqual(len(set(seen_ids)), 1000, "no duplicates across raw pages")

    def test_gsi_branch_filters_by_record_type_and_key_carries_it(self):
        items = (
            [_base_item(n) for n in range(1, 6)]
            + [{**_base_item(n), "record_type": {"S": "issue"}} for n in range(6, 11)]
        )
        table = PagingTable(items, raw_page_size=3)
        kwargs = {
            "TableName": "t",
            "IndexName": "project-type-index",
            "KeyConditionExpression": "project_id = :pid AND record_type = :rtype",
            "ExpressionAttributeValues": {":pid": {"S": "proj"}, ":rtype": {"S": "task"}},
            "Limit": 3,
        }
        resp1 = table.query(**kwargs)
        self.assertEqual(len(resp1["Items"]), 3)
        self.assertIn("LastEvaluatedKey", resp1)
        self.assertIn("record_type", resp1["LastEvaluatedKey"], "GSI LEK carries record_type")

        kwargs["ExclusiveStartKey"] = resp1["LastEvaluatedKey"]
        resp2 = table.query(**kwargs)
        self.assertEqual(len(resp2["Items"]), 2, "only 5 task-type items total")
        self.assertNotIn("LastEvaluatedKey", resp2, "exhausted -- only task rows counted, not issue rows")

    def test_filter_expression_applied_after_limit_can_return_zero_matches_with_lek(self):
        # 100 closed rows (evaluated by Limit) followed by 1 open row beyond
        # this raw page -- Limit counts EVALUATED items, so a page entirely
        # of non-matching rows still reports LastEvaluatedKey.
        items = [_base_item(n, status="closed") for n in range(1, 101)] + [
            _base_item(101, status="open")
        ]
        table = PagingTable(items, raw_page_size=100)
        resp = table.query(
            TableName="t",
            KeyConditionExpression="project_id = :pid",
            FilterExpression="#st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":pid": {"S": "proj"}, ":st": {"S": "open"}},
            Limit=100,
        )
        self.assertEqual(resp["Items"], [], "0 matches on this raw page")
        self.assertIn("LastEvaluatedKey", resp, "more raw data exists beyond this page")


if __name__ == "__main__":
    unittest.main()
