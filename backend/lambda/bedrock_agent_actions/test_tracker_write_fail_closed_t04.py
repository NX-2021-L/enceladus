"""test_tracker_write_fail_closed_t04.py -- the Bedrock agent surface must not write
the tracker (ENC-TSK-T04 / ENC-ISS-909 / ENC-ISS-911).

WHAT THIS GUARDS. Three handlers in this lambda wrote the tracker table directly and
none of them could enforce governance:

  * PUT  /tracker/{recordId}/status applied ANY status with no transition matrix, no
    dictionary legality check, no checkout/SCI ownership check and no expected-prior
    ConditionExpression. It could regress a closed record, skip an arc entirely, or
    overwrite a concurrent governed advance last-writer-wins. An FSM bypass
    (ENC-ISS-909) -- every other status writer in the system is gated, and the
    escalation path of ENC-FTR-121 exists precisely so an FSM-forbidden move needs
    io's approval.
  * POST /tracker/create minted its own record id from three digits of a random UUID
    -- a 1000-value space against a tracker already holding on the order of a
    thousand records -- and wrote it with an UNCONDITIONAL put_item. A collision did
    not fail; it replaced the colliding governed record in full, including status,
    history, acceptance_criteria, checkout state and version_seq (ENC-ISS-911, data
    loss), and it usurped server-side id allocation.
  * POST /tracker/{recordId}/log appended history ungoverned and unsequenced.

All three also stamped write_kind=governed while bypassing governance, which made the
DynamoDB-stream event-source filters carry writes no gate had approved.

They now fail closed. These tests pin the property that matters and is easy to lose in
a later refactor: the handlers must return a refusal AND must not touch DynamoDB at
all. The ddb stub therefore raises on every method, so any surviving write is a test
error rather than a silent pass.

Run: python3 -m pytest test_tracker_write_fail_closed_t04.py -q
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location(
    "bedrock_agent_actions_failclosed_t04", MODULE_PATH)
bl = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = bl
SPEC.loader.exec_module(bl)


class _ExplodingDdb:
    """Any DynamoDB access at all is a failure for a refused write."""

    def __getattr__(self, name):
        def _boom(*a, **kw):
            raise AssertionError(
                f"refused tracker write still called ddb.{name}() -- "
                "the handler must not touch DynamoDB")
        return _boom


class _ReadOnlyDdb:
    """Serves a tracker record for the read-path regression check."""

    def __init__(self):
        self.writes = 0

    _ROW = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": "task#ENC-TSK-1"},
        "item_id": {"S": "ENC-TSK-1"},
        "record_type": {"S": "task"},
        "title": {"S": "a task"},
        "status": {"S": "open"},
    }

    def scan(self, **kwargs):
        return {"Items": [self._ROW]}

    def query(self, **kwargs):
        return {"Items": [self._ROW]}

    def get_item(self, **kwargs):
        return {}

    def update_item(self, **kwargs):
        self.writes += 1
        raise AssertionError("read path performed a write")

    def put_item(self, **kwargs):
        self.writes += 1
        raise AssertionError("read path performed a write")


class RefusedTrackerWritesTests(unittest.TestCase):
    """Each write handler refuses, names the governed path, and writes nothing."""

    def setUp(self):
        self._p = patch.object(bl, "_get_ddb", return_value=_ExplodingDdb())
        self._p.start()
        self.addCleanup(self._p.stop)

    def _assert_refusal(self, result, expect_in_path, issue):
        self.assertIn("error", result, result)
        self.assertIn("refused_operation", result)
        self.assertEqual(issue, result["governance_reference"])
        self.assertIn(expect_in_path, result["governed_path"])
        # the refusal must point somewhere actionable, not just say no
        self.assertIn("MCP", result["governed_path"])
        self.assertIn("Refused", result["error"])

    def test_status_write_is_refused(self):
        result = bl._handle_tracker_status(
            [{"name": "recordId", "value": "ENC-TSK-1"}], {"status": "closed"})
        self._assert_refusal(result, "checkout.advance", "ENC-ISS-909")
        self.assertNotIn("success", result)

    def test_create_is_refused(self):
        result = bl._handle_tracker_create(
            {"project_id": "enceladus", "title": "x", "acceptance_criteria": ["a"]})
        self._assert_refusal(result, "tracker.create", "ENC-ISS-911")
        self.assertNotIn("item_id", result,
                         "a refused create must not hand back a minted id")

    def test_log_is_refused(self):
        result = bl._handle_tracker_log(
            [{"name": "recordId", "value": "ENC-TSK-1"}], {"description": "hello"})
        self._assert_refusal(result, "append_worklog", "ENC-ISS-909")
        self.assertNotIn("success", result)

    def test_refusal_is_independent_of_input(self):
        """No body shape can talk any of them into writing."""
        for status in ("closed", "open", "in-progress", "", "nonsense-status"):
            self.assertIn("error", bl._handle_tracker_status(
                [{"name": "recordId", "value": "ENC-TSK-1"}], {"status": status}))

    def test_router_refuses_the_three_write_paths(self):
        """Refusal holds through the real apiPath router, not just direct calls."""
        for path, method, body in (
            ("/tracker/{recordId}/status", "PUT", {"status": "closed"}),
            ("/tracker/create", "POST", {"project_id": "enceladus", "title": "x"}),
            ("/tracker/{recordId}/log", "POST", {"description": "hi"}),
        ):
            event = {
                "apiPath": path,
                "httpMethod": method,
                "parameters": [{"name": "recordId", "value": "ENC-TSK-1"}],
                "requestBody": {"content": {"application/json": {"properties": [
                    {"name": k, "value": v} for k, v in body.items()]}}},
            }
            resp = bl.handler(event, None)
            blob = str(resp)
            self.assertIn("Refused", blob, f"{method} {path} was not refused: {blob}")


class ReadPathStillWorksTests(unittest.TestCase):
    """The refusal must not have collaterally broken the read handlers."""

    def test_tracker_get_still_reads(self):
        with patch.object(bl, "_get_ddb", return_value=_ReadOnlyDdb()):
            result = bl._handle_tracker_get(
                [{"name": "recordId", "value": "ENC-TSK-1"}])
        self.assertNotIn("error", result, result)
        self.assertEqual("ENC-TSK-1", result.get("item_id"))


class NoTrackerWriteRemainsTests(unittest.TestCase):
    """Static fence: no write call against the tracker table anywhere in the module."""

    @classmethod
    def setUpClass(cls):
        cls.src = MODULE_PATH.read_text(encoding="utf-8")
        cls.lines = cls.src.split("\n")

    def test_no_ddb_write_targets_the_tracker_table(self):
        offenders = []
        for i, line in enumerate(self.lines, 1):
            if re.search(r"\.(update_item|put_item|delete_item|transact_write_items)\(",
                         line):
                window = "\n".join(self.lines[i - 1:i + 6])
                if "TRACKER_TABLE" in window:
                    offenders.append(f"line {i}: {line.strip()}")
        self.assertEqual([], offenders,
                         "a tracker-table write reappeared on this surface")

    def test_surface_no_longer_stamps_write_kind_in_code(self):
        """write_kind=governed was a mislabel here; only prose may mention it now.

        Tokenised rather than grepped: comments and string/docstring tokens are
        dropped, so a line-wrapped docstring that merely discusses write_kind cannot
        pass or fail this by accident -- only real code counts.
        """
        import io
        import tokenize
        offenders = []
        for tok in tokenize.generate_tokens(io.StringIO(self.src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            if tok.type == tokenize.NAME and tok.string == "write_kind":
                offenders.append(f"line {tok.start[0]}: {tok.line.strip()}")
        self.assertEqual([], offenders,
                         f"write_kind still referenced in code: {offenders}")

    def test_no_self_minted_record_id_remains(self):
        self.assertNotIn("uuid.uuid4().int", self.src,
                         "record-id minting from a random UUID reappeared "
                         "(ENC-ISS-911); id allocation belongs to the server")


if __name__ == "__main__":
    unittest.main()
