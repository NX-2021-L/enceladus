"""ENC-TSK-Q13-0A review fix: gsi-branch cursor replayed under a DIFFERENT
`type` filter must 400 CURSOR_BRANCH_MISMATCH, not silently decode.

Prior to this fix, `_decode_list_cursor`'s branch check only compared the
cursor's stored "b" ("base" vs "gsi") -- two gsi requests with different
`type` filters both compare equal on branch, so a cursor minted under
type=task and replayed under type=issue decoded successfully, then fed a
stale decoded['t']=="task" into ExclusiveStartKey.record_type while the
Query's own KeyConditionExpression equality value (:rtype) was "issue" --
two different values in the same ddb.query() call. Against the repo's
PagingTable fake this silently produced a falsely-exhausted 200 (an empty
page with no next_cursor) instead of the documented 400; against real
DynamoDB it would instead risk an opaque 500 via the route's generic
except-Exception handler. See governance_data_dictionary.json's existing
CURSOR_BRANCH_MISMATCH entry, which already documented this case before the
code implemented it.
"""
import json
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _raw_item(n, project_id="proj", record_type="task"):
    rid = f"{record_type}#TSK-{n:03d}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": rid},
        "item_id": {"S": f"TSK-{n:03d}"},
        "record_type": {"S": record_type},
        "status": {"S": "open"},
        "title": {"S": f"{record_type} {n}"},
    }


def _body(resp):
    return json.loads(resp["body"])


class TestDecodeListCursorGsiTypeMismatch(unittest.TestCase):
    """Unit-level: _decode_list_cursor itself."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_decode_raises_when_gsi_record_type_differs(self):
        token = self.lf._encode_list_cursor(
            {"project_id": "proj", "record_id": "task#TSK-001", "record_type": "task"},
            "gsi",
        )
        with self.assertRaises(self.lf.ListCursorBranchMismatch):
            self.lf._decode_list_cursor(token, "gsi", "issue")

    def test_decode_succeeds_when_gsi_record_type_matches(self):
        token = self.lf._encode_list_cursor(
            {"project_id": "proj", "record_id": "task#TSK-001", "record_type": "task"},
            "gsi",
        )
        decoded = self.lf._decode_list_cursor(token, "gsi", "task")
        self.assertEqual(decoded["t"], "task")

    def test_decode_skips_record_type_check_when_not_given(self):
        # Preserves the codec round-trip tests (test_list_cursor_codec_q13.py),
        # which never pass a record_type positional arg.
        token = self.lf._encode_list_cursor(
            {"project_id": "proj", "record_id": "task#TSK-001", "record_type": "task"},
            "gsi",
        )
        decoded = self.lf._decode_list_cursor(token, "gsi")
        self.assertEqual(decoded["t"], "task")


class TestHandleListRecordsGsiTypeMismatch(unittest.TestCase):
    """End-to-end through _handle_list_records against PagingTable."""

    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, table, **query_params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            return self.lf._handle_list_records("proj", query_params)

    def test_cursor_minted_under_one_type_replayed_under_another_is_400(self):
        items = [_raw_item(n, record_type="task") for n in range(1, 6)] + [
            _raw_item(n, record_type="issue") for n in range(1, 6)
        ]
        table = PagingTable(items, raw_page_size=50)

        resp1 = self._call(table, page_size="50", type="task")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertEqual(len(body1["records"]), 5)
        # Fully exhausted for type=task -> no cursor from the real walk;
        # mint one by hand the way a client legitimately could mid-walk
        # (page_size=1 would also produce this cursor from the handler).
        cursor = self.lf._encode_list_cursor(
            self.lf._deser_item(items[0]), "gsi",
        )

        resp2 = self._call(table, page_size="50", type="issue", next_cursor=cursor)
        body2 = _body(resp2)

        # Must NOT be a falsely-exhausted, silently-wrong 200 page.
        self.assertEqual(resp2["statusCode"], 400, body2)
        self.assertEqual(body2["error_envelope"]["code"], "CURSOR_BRANCH_MISMATCH")

    def test_cursor_minted_under_one_type_replayed_under_same_type_is_200(self):
        items = [_raw_item(n, record_type="task") for n in range(1, 8)]
        table = PagingTable(items, raw_page_size=50)

        resp1 = self._call(table, page_size="3", type="task")
        body1 = _body(resp1)
        self.assertEqual(resp1["statusCode"], 200)
        self.assertIn("next_cursor", body1)

        resp2 = self._call(table, page_size="3", type="task", next_cursor=body1["next_cursor"])
        body2 = _body(resp2)
        self.assertEqual(resp2["statusCode"], 200)
        self.assertEqual(len(body2["records"]), 3)


if __name__ == "__main__":
    unittest.main()
