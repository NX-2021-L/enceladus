"""ENC-TSK-Q13 (O1.2): _handle_list_records honest-cursor pagination tests.

Drives the rewritten accumulate loop with a scripted ddb.query() double --
each call returns a pre-built (Items, LastEvaluatedKey) pair in order, so
these tests assert on _handle_list_records' own loop/cursor logic without
needing a real DynamoDB filter evaluator. (The general-purpose multi-page
fake with real Limit/ExclusiveStartKey/FilterExpression semantics --
fake_ddb_paging.PagingTable -- lands in the ENC-TSK-Q13-0D leaf and takes
over mode_a/mode_b's underlying fake there; the scenarios and assertions
here are unchanged by that swap.)
"""
import unittest
from unittest import mock


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


class _FakeDdb:
    """Scripted ddb.query() double: pops one (items, lek) pair per call."""

    def __init__(self, script):
        self._script = list(script)
        self.calls = []

    def query(self, **kwargs):
        self.calls.append(kwargs)
        if not self._script:
            raise AssertionError("query() called more times than scripted")
        items, lek = self._script.pop(0)
        resp = {"Items": items}
        if lek is not None:
            resp["LastEvaluatedKey"] = lek
        return resp


class TestListRecordsPagination(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, fake, **query_params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=fake):
            return self.lf._handle_list_records("proj", query_params)

    # -- test_list_mode_a: 30 matches on raw page 1 + 40 on raw page 2,
    # page_size 50 -> two pages totalling 70, no duplicates, no gaps. ----
    def test_list_mode_a(self):
        items_1_30 = [_raw_item(n) for n in range(1, 31)]
        items_31_70 = [_raw_item(n) for n in range(31, 71)]
        page1_lek = {"project_id": {"S": "proj"}, "record_id": {"S": "task#TSK-030"}}

        fake1 = _FakeDdb([
            (items_1_30, page1_lek),
            (items_31_70, None),  # DynamoDB's genuinely final raw page
        ])
        resp1 = self._call(fake1, page_size="50")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertEqual(len(body1["records"]), 50)
        self.assertIn("next_cursor", body1)
        self.assertNotIn("page_truncated", body1)
        self.assertEqual(len(fake1.calls), 2)

        fake2 = _FakeDdb([
            (items_31_70[-20:], None),  # remaining 20 items, exhausted
        ])
        resp2 = self._call(fake2, page_size="50", next_cursor=body1["next_cursor"])
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
    # (The 10 raw pages of non-matching rows are already filtered server
    # side by DynamoDB, per the FilterExpression-after-Limit contract, so
    # each of those Items lists is empty even though LastEvaluatedKey
    # advances.) --------------------------------------------------------
    def test_list_mode_b(self):
        page_lek = lambda k: {  # noqa: E731 - local helper, not exported
            "project_id": {"S": "proj"},
            "record_id": {"S": f"task#TSK-{k * 50:03d}"},
        }
        script = [([], page_lek(k)) for k in range(1, 11)]  # 10 raw pages, all filtered empty
        fake1 = _FakeDdb(script)
        resp1 = self._call(fake1, page_size="50", status="open")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertEqual(body1["records"], [])
        self.assertTrue(body1.get("page_truncated"))
        self.assertIn("next_cursor", body1)
        self.assertEqual(len(fake1.calls), 10, "raw-page budget is exactly 10")

        match_item = _raw_item(501, status="open")
        fake2 = _FakeDdb([([match_item], None)])
        resp2 = self._call(fake2, page_size="50", status="open", next_cursor=body1["next_cursor"])
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
        fake1 = _FakeDdb([(items, None)])
        resp1 = self._call(fake1, page_size="50")
        body1 = _body(resp1)
        self.assertEqual(len(body1["records"]), 5)
        self.assertNotIn("next_cursor", body1, "fully exhausted -- no cursor")

        last_raw = items[-1]
        manual_cursor = self.lf._encode_list_cursor(self.lf._deser_item(last_raw), "base")

        fake2 = _FakeDdb([([], None)])
        resp2 = self._call(fake2, page_size="50", next_cursor=manual_cursor)
        body2 = _body(resp2)
        self.assertEqual(resp2["statusCode"], 200)
        self.assertEqual(body2["records"], [])
        self.assertNotIn("next_cursor", body2)

    # -- bonus: raw-page budget hit with SOME matches already accumulated
    # (<= page_size) still yields next_cursor from the last RETURNED item
    # (not the raw LastEvaluatedKey) plus page_truncated: true. ---------
    def test_list_raw_page_budget_truncation_with_partial_matches(self):
        items_page = [_raw_item(n) for n in range(1, 6)]  # 5 matches on page 1
        empty_lek = lambda k: {  # noqa: E731
            "project_id": {"S": "proj"},
            "record_id": {"S": f"task#TSK-{k:03d}"},
        }
        script = [(items_page, empty_lek(1))] + [([], empty_lek(k)) for k in range(2, 11)]
        fake = _FakeDdb(script)
        resp = self._call(fake, page_size="50")
        body = _body(resp)
        self.assertEqual(len(body["records"]), 5)
        self.assertTrue(body.get("page_truncated"))
        self.assertIn("next_cursor", body)
        decoded = self.lf._decode_list_cursor(body["next_cursor"], "base")
        self.assertEqual(decoded["r"], "task#TSK-005", "cursor built from last RETURNED item")


def _body(resp):
    import json
    return json.loads(resp["body"])


if __name__ == "__main__":
    unittest.main()
