"""ENC-TSK-Q13 (O1.3): _handle_list_records branch-mismatch cursor -> 400.

A next_cursor minted on one query branch (base table walk vs
project-type-index/"gsi" walk) is meaningless key material on the other --
ListCursorBranchMismatch (ENC-TSK-Q13-0A) must surface as a 400 with the
file's standard error_envelope shape, never a 500, and never be silently
reinterpreted against the wrong key schema.
"""
import unittest
from unittest import mock


class _UnreachableDdb:
    """query() must never be called once cursor decode has already failed."""

    def query(self, **kwargs):
        raise AssertionError("ddb.query() should not be reached on a branch mismatch")


class TestListCursorBranchMismatch400(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _call(self, **query_params):
        with mock.patch.object(self.lf, "_get_ddb", return_value=_UnreachableDdb()):
            return self.lf._handle_list_records("proj", query_params)

    def test_list_cursor_branch_mismatch_400(self):
        gsi_token = self.lf._encode_list_cursor(
            {"project_id": "proj", "record_id": "task#TSK-001", "record_type": "task"},
            "gsi",
        )
        # No "type" query param -> base branch; the cursor above was minted gsi.
        resp = self._call(page_size="50", next_cursor=gsi_token)
        self.assertEqual(resp["statusCode"], 400)
        import json
        body = json.loads(resp["body"])
        self.assertFalse(body["success"])
        env = body["error_envelope"]
        self.assertEqual(env["code"], "CURSOR_BRANCH_MISMATCH")
        self.assertFalse(env["retryable"])
        self.assertIn(
            "restart the walk without a cursor",
            " ".join(env["details"].get("recommended_next_actions", [])),
        )

    def test_list_cursor_branch_mismatch_400_reverse(self):
        base_token = self.lf._encode_list_cursor(
            {"project_id": "proj", "record_id": "task#TSK-001"}, "base",
        )
        # type=task is in _RECORD_TYPES -> gsi branch; the cursor was minted base.
        resp = self._call(page_size="50", type="task", next_cursor=base_token)
        self.assertEqual(resp["statusCode"], 400)
        import json
        body = json.loads(resp["body"])
        self.assertEqual(body["error_envelope"]["code"], "CURSOR_BRANCH_MISMATCH")

    def test_malformed_cursor_is_400_not_500(self):
        resp = self._call(page_size="50", next_cursor="not-valid-base64-json!!!")
        self.assertEqual(resp["statusCode"], 400)


if __name__ == "__main__":
    unittest.main()
