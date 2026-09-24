"""ENC-TSK-Q14-0B (O2.2): _census_pages page anchor builder.

70 rows at page_size 50 -> two pages [n=50, n=20]; pages[1].cursor decodes
to rows[49]'s key; feeding that cursor to the O1.2 route
(_handle_list_records) returns exactly rows[50:70] -- the cross-test named
in o2_acs.md. first/last carry ONLY id, status, title.
"""
import json
import unittest
from unittest import mock

from fake_ddb_paging import PagingTable


def _raw_item(n, project_id="proj", record_type="task", status="open"):
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": f"{record_type}#TSK-{n:03d}"},
        "item_id": {"S": f"TSK-{n:03d}"},
        "record_type": {"S": record_type},
        "status": {"S": status},
        "title": {"S": f"Task {n}"},
        "updated_at": {"S": "2026-09-23T00:00:00Z"},
    }


class TestCensusPages(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_70_rows_page_size_50_anchors_and_cursor(self):
        items = [_raw_item(n) for n in range(1, 71)]
        table = PagingTable(items, raw_page_size=200)

        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            walk = self.lf._census_walk("proj")

        self.assertTrue(walk["exhausted"])
        rows = walk["rows"]
        self.assertEqual(len(rows), 70)

        pages = self.lf._census_pages(rows, 50, walk["branch"])

        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[0]["n"], 50)
        self.assertEqual(pages[1]["n"], 20)
        self.assertIsNone(pages[0]["cursor"])
        self.assertIsNotNone(pages[1]["cursor"])

        decoded = self.lf._decode_list_cursor(pages[1]["cursor"], walk["branch"])
        self.assertEqual(decoded["r"], rows[49]["record_id"])

        # first/last carry ONLY id, status, title.
        self.assertEqual(set(pages[0]["first"].keys()), {"id", "status", "title"})
        self.assertEqual(set(pages[0]["last"].keys()), {"id", "status", "title"})
        self.assertEqual(pages[0]["first"]["id"], rows[0]["record_id"])
        self.assertEqual(pages[0]["last"]["id"], rows[49]["record_id"])
        self.assertEqual(pages[1]["first"]["id"], rows[50]["record_id"])
        self.assertEqual(pages[1]["last"]["id"], rows[69]["record_id"])

        # Cross-test vs O1.2: feeding pages[1].cursor to _handle_list_records
        # (same underlying table) returns exactly rows[50:70].
        with mock.patch.object(self.lf, "_get_ddb", return_value=table):
            resp = self.lf._handle_list_records(
                "proj", {"page_size": "50", "next_cursor": pages[1]["cursor"]},
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        returned_ids = [r["record_id"] for r in body["records"]]
        expected_ids = [r["record_id"] for r in rows[50:70]]
        self.assertEqual(returned_ids, expected_ids)
        self.assertNotIn("next_cursor", body, "fully exhausted")

    def test_page_0_cursor_is_none(self):
        rows = [
            {"project_id": "proj", "record_id": "task#TSK-001", "record_type": "task",
             "status": "open", "title": "T1"},
        ]
        pages = self.lf._census_pages(rows, 50, "base")
        self.assertEqual(len(pages), 1)
        self.assertIsNone(pages[0]["cursor"])

    def test_exact_multiple_of_page_size_no_trailing_empty_page(self):
        rows = [
            {"project_id": "proj", "record_id": f"task#TSK-{n:03d}", "record_type": "task",
             "status": "open", "title": f"T{n}"}
            for n in range(1, 101)
        ]
        pages = self.lf._census_pages(rows, 50, "base")
        self.assertEqual(len(pages), 2)
        self.assertEqual([p["n"] for p in pages], [50, 50])


if __name__ == "__main__":
    unittest.main()
