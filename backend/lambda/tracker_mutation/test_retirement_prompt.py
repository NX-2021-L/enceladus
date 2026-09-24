"""ENC-ISS-441 / ENC-TSK-J96: terminal-state retirement nudge (tracker mutation side).

Covers the _is_terminal_transition truth table (task closed, issue closed, feature
production/deprecated, plan complete) plus a full moto-backed status write proving the
retirement_prompt field lands in the success envelope and stays absent for non-terminal
writes. Reuses the ENC-TSK-J93 SCI-gate fixture (grandfathered session so the gate
passes without a token).
"""
import json
import unittest
from unittest import mock

import lambda_function as tm
from test_sci_gate import (  # noqa: F401 — shared moto fixture
    PRE_EPOCH_SESSION,
    PRE_EPOCH_TS,
    TrackerSciGateBase,
    _body,
)

_IO_PROMPT = (
    "Prompt the user if this session can now be retired, or retire the session if it "
    "is certain that the full scope of the current session assignment is complete."
)

# Captured at import (collection) time, before any test runs: the arc-walker test modules
# (h83/h85/h86) rebind these module seams in-place without restoration, so suite order
# would otherwise leak their fakes into the moto-backed envelope tests below.
_PRISTINE_SEAMS = {
    name: getattr(tm, name)
    for name in ("_get_events", "_get_record_raw", "_build_key", "_resolve_github_repo")
    if hasattr(tm, name)
}


class TerminalTransitionTruthTableTests(unittest.TestCase):
    def test_prompt_text_is_the_exact_io_specified_string(self):
        self.assertEqual(tm.RETIREMENT_PROMPT, _IO_PROMPT)

    def test_terminal_states_per_record_type(self):
        for record_type, value in (
            ("task", "closed"),
            ("issue", "closed"),
            ("feature", "production"),
            ("feature", "deprecated"),
            ("plan", "complete"),
        ):
            self.assertTrue(tm._is_terminal_transition(record_type, value), (record_type, value))

    def test_non_terminal_states_are_not_flagged(self):
        for record_type, value in (
            ("task", "in-progress"),
            ("task", "deploy-success"),
            ("issue", "in-progress"),
            ("feature", "completed"),
            ("feature", "in-progress"),
            ("plan", "started"),
            ("plan", "incomplete"),
            ("lesson", "closed"),
            ("", "closed"),
            ("task", ""),
            ("task", None),
        ):
            self.assertFalse(tm._is_terminal_transition(record_type, value), (record_type, value))

    def test_case_and_whitespace_are_normalized(self):
        self.assertTrue(tm._is_terminal_transition("Issue", " Closed "))


class RetirementPromptEnvelopeTests(TrackerSciGateBase):
    """Moto-backed status writes through _handle_update_field (grandfathered session)."""

    def setUp(self):
        super().setUp()
        # The arc-walker test modules rebind module seams (lf._get_ddb, _get_record_raw,
        # ...) without restoration; re-point them at this test's moto client / their
        # pristine originals so suite order can't leak fakes into these envelope tests.
        seams = dict(_PRISTINE_SEAMS)
        seams["_get_ddb"] = lambda: self.ddb
        for name, value in seams.items():
            patcher = mock.patch.object(tm, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def put_issue(self, item_id="ENC-ISS-941", status="in-progress"):
        self.ddb.put_item(
            TableName=tm.DYNAMODB_TABLE,
            Item={
                "project_id": {"S": "enceladus"},
                "record_id": {"S": f"issue#{item_id}"},
                "item_id": {"S": item_id},
                "record_type": {"S": "issue"},
                "status": {"S": status},
                "title": {"S": "retirement prompt test issue"},
                "history": {"L": []},
                "evidence": {"L": [{"M": {
                    "description": {"S": "test evidence"},
                    "steps_to_duplicate": {"L": [{"S": "step 1"}]},
                }}]},
            },
        )

    def _set_status(self, record_type, record_id, value):
        return tm._handle_update_field(
            "enceladus", record_type, record_id,
            _body(provider=PRE_EPOCH_SESSION, field="status", value=value),
        )

    def test_issue_closed_envelope_carries_prompt(self):
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        self.put_issue()
        resp = self._set_status("issue", "ENC-ISS-941", "closed")
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("retirement_prompt"), _IO_PROMPT)

    def test_non_terminal_status_write_has_no_prompt(self):
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        self.put_issue(item_id="ENC-ISS-942", status="open")
        resp = self._set_status("issue", "ENC-ISS-942", "in-progress")
        self.assertEqual(resp["statusCode"], 200)
        self.assertNotIn("retirement_prompt", json.loads(resp["body"]))

    def test_non_status_field_write_has_no_prompt(self):
        self.put_session(session_id=PRE_EPOCH_SESSION, created_at=PRE_EPOCH_TS)
        self.put_task(item_id="ENC-TSK-941")
        resp = tm._handle_update_field(
            "enceladus", "task", "ENC-TSK-941",
            _body(provider=PRE_EPOCH_SESSION, field="description", value="closed"),
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertNotIn("retirement_prompt", json.loads(resp["body"]))


if __name__ == "__main__":
    unittest.main()
