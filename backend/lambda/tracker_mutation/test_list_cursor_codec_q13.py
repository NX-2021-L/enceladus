"""ENC-TSK-Q13 (O1.1): value-based cursor codec for _handle_list_records.

Covers _encode_list_cursor / _decode_list_cursor round-tripping for both
query branches ("base" table walk vs "gsi" project-type-index walk) and the
ListCursorBranchMismatch guard that stops a cursor minted on one branch from
being replayed against the other. No route behaviour is exercised here --
that lands with the _handle_list_records rewrite (O1.2/O1.3).
"""
import unittest


class TestListCursorCodec(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_round_trip_base_branch(self):
        item = {"project_id": "enceladus", "record_id": "task#ENC-TSK-Q13"}
        token = self.lf._encode_list_cursor(item, "base")
        decoded = self.lf._decode_list_cursor(token, "base")
        self.assertEqual(decoded["b"], "base")
        self.assertEqual(decoded["p"], "enceladus")
        self.assertEqual(decoded["r"], "task#ENC-TSK-Q13")
        self.assertNotIn("t", decoded)

    def test_round_trip_gsi_branch(self):
        item = {
            "project_id": "enceladus",
            "record_id": "task#ENC-TSK-Q13",
            "record_type": "task",
        }
        token = self.lf._encode_list_cursor(item, "gsi")
        decoded = self.lf._decode_list_cursor(token, "gsi")
        self.assertEqual(decoded["b"], "gsi")
        self.assertEqual(decoded["p"], "enceladus")
        self.assertEqual(decoded["r"], "task#ENC-TSK-Q13")
        self.assertEqual(decoded["t"], "task")

    def test_decode_gsi_token_on_base_branch_raises_mismatch(self):
        item = {
            "project_id": "enceladus",
            "record_id": "task#ENC-TSK-Q13",
            "record_type": "task",
        }
        token = self.lf._encode_list_cursor(item, "gsi")
        with self.assertRaises(self.lf.ListCursorBranchMismatch):
            self.lf._decode_list_cursor(token, "base")

    def test_decode_base_token_on_gsi_branch_raises_mismatch(self):
        item = {"project_id": "enceladus", "record_id": "task#ENC-TSK-Q13"}
        token = self.lf._encode_list_cursor(item, "base")
        with self.assertRaises(self.lf.ListCursorBranchMismatch):
            self.lf._decode_list_cursor(token, "gsi")

    def test_encode_rejects_unknown_branch(self):
        with self.assertRaises(ValueError):
            self.lf._encode_list_cursor({"project_id": "p", "record_id": "r"}, "bogus")


if __name__ == "__main__":
    unittest.main()
