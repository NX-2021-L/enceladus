"""ENC-TSK-Q13 (O1.2 + O1.4): _handle_list_records honest-cursor pagination.

Drives the rewritten accumulate loop (ENC-TSK-Q13-0B) against
fake_ddb_paging.PagingTable (ENC-TSK-Q13-0D), a real Limit/
ExclusiveStartKey/LastEvaluatedKey-walking fake -- not a scripted double --
so resuming via a next_cursor genuinely re-resolves a position in the fake
table rather than trusting pre-scripted responses. One PagingTable instance
is reused across the two (or more) handler calls in each scenario, mirroring
a single underlying table across separate requests.
"""
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _raw_item(n, project_id="proj", record_type="task", status="open"):
    rid = f"task#TSK-{n:03d}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": rid},
        "item_id": {"S": f"TSK-{n:03d}"},
        "record_type": {"S": record_type},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
    }


class TestListRecordsPagination(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, table, **query_params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            return self.lf._handle_list_records("proj", query_params)

    # -- test_list_mode_a: raw pages accumulate past page_size (50) over
    # 70 total matches -> two handler-level pages totalling 70, no
    # duplicates, no gaps. -----------------------------------------------
    def test_list_mode_a(self):
        items = [_raw_item(n) for n in range(1, 71)]
        table = PagingTable(items, raw_page_size=50)

        resp1 = self._call(table, page_size="50")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertEqual(len(body1["records"]), 50)
        self.assertIn("next_cursor", body1)
        self.assertNotIn("page_truncated", body1)
        self.assertEqual(len(table.calls), 2, "50 then 20 -- proof of >page_size needs a 2nd raw call")

        resp2 = self._call(table, page_size="50", next_cursor=body1["next_cursor"])
        body2 = _body(resp2)
        self.assertEqual(resp2["statusCode"], 200)
        self.assertEqual(len(body2["records"]), 20)
        self.assertNotIn("next_cursor", body2)

        all_ids = [r["item_id"] for r in body1["records"]] + [r["item_id"] for r in body2["records"]]
        self.assertEqual(len(all_ids), 70)
        self.assertEqual(len(set(all_ids)), 70, "no duplicates across pages")
        self.assertEqual(set(all_ids), {f"TSK-{n:03d}" for n in range(1, 71)}, "no gaps")

    # -- test_list_mode_b: seed 10*page_size non-matching rows before one
    # matching row -> the matching row is reachable by following cursors.
    # (PagingTable applies the status FilterExpression after Limit, so
    # every one of the first 10 raw pages evaluates 50 closed rows and
    # returns 0 Items while still advancing LastEvaluatedKey.) ----------
    def test_list_mode_b(self):
        items = [_raw_item(n, status="closed") for n in range(1, 501)] + [
            _raw_item(501, status="open")
        ]
        table = PagingTable(items, raw_page_size=50)

        resp1 = self._call(table, page_size="50", status="open")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertEqual(body1["records"], [])
        self.assertTrue(body1.get("page_truncated"))
        self.assertIn("next_cursor", body1)
        self.assertEqual(len(table.calls), 10, "raw-page budget is exactly 10")

        resp2 = self._call(table, page_size="50", status="open", next_cursor=body1["next_cursor"])
        body2 = _body(resp2)
        self.assertEqual(resp2["statusCode"], 200)
        self.assertEqual(len(body2["records"]), 1)
        self.assertEqual(body2["records"][0]["item_id"], "TSK-501")
        self.assertNotIn("next_cursor", body2)
        self.assertNotIn("page_truncated", body2)

    # -- test_list_mode_c: a page with no next_cursor is followed by an
    # empty page when the cursor is reconstructed manually. ------------
    def test_list_mode_c(self):
        items = [_raw_item(n) for n in range(1, 6)]
        table = PagingTable(items, raw_page_size=50)

        resp1 = self._call(table, page_size="50")
        body1 = _body(resp1)
        self.assertEqual(len(body1["records"]), 5)
        self.assertNotIn("next_cursor", body1, "fully exhausted -- no cursor")

        manual_cursor = self.lf._encode_list_cursor(
            self.lf._deser_item(items[-1]), "base",
        )
        resp2 = self._call(table, page_size="50", next_cursor=manual_cursor)
        body2 = _body(resp2)
        self.assertEqual(resp2["statusCode"], 200)
        self.assertEqual(body2["records"], [])
        self.assertNotIn("next_cursor", body2)

    # -- bonus: raw-page budget hit with SOME matches already accumulated
    # (<= page_size) still yields next_cursor from the last RETURNED item
    # (not the raw LastEvaluatedKey) plus page_truncated: true. Distinct
    # from mode_b, which covers the zero-matches-yet budget-hit path. ---
    def test_list_raw_page_budget_truncation_with_partial_matches(self):
        items = [_raw_item(n) for n in range(1, 6)] + [
            _raw_item(n, status="closed") for n in range(6, 551)
        ]
        table = PagingTable(items, raw_page_size=50)

        resp = self._call(table, page_size="50", status="open")
        body = _body(resp)
        self.assertEqual(len(body["records"]), 5)
        self.assertTrue(body.get("page_truncated"))
        self.assertIn("next_cursor", body)
        self.assertEqual(len(table.calls), 10, "raw-page budget is exactly 10")
        decoded = self.lf._decode_list_cursor(body["next_cursor"], "base")
        self.assertEqual(decoded["r"], "task#TSK-005", "cursor built from last RETURNED item")


def _body(resp):
    import json
    return json.loads(resp["body"])


if __name__ == "__main__":
    unittest.main()
