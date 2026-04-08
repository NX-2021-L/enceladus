"""test_acceptance_criteria_normalization.py — Regression tests for ENC-ISS-181.

Guards against the tracker.create acceptance_criteria corruption bug where
passing a list of dict-shaped AC entries caused str(dict) to be stored in the
description field (Python repr() output) instead of the plain text description.

Root cause fix (ENC-TSK-C50): _handle_create_record now delegates AC normalization
to _normalize_acceptance_criteria_value() — the same helper PATCH already uses —
and the write-serialization block consumes the already-structured dict list
instead of stringifying each entry.

These tests assert against the final DynamoDB Item shape the Lambda would write,
locking in the correct storage structure so the bug cannot regress silently.

Run: python3 -m pytest test_acceptance_criteria_normalization.py -v
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Load the Lambda module via importlib to avoid package-path issues.
sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "tracker_mutation_c50",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tracker_mutation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_create_body(record_type: str, acceptance_criteria, **extra):
    """Build the minimum required body for _handle_create_record."""
    body = {
        "title": f"Test {record_type} for ENC-ISS-181 regression",
        "category": "implementation" if record_type == "task" else "capability",
        "acceptance_criteria": acceptance_criteria,
    }
    if record_type == "feature":
        body["user_story"] = "As a tester I want coverage so regressions are caught."
    body.update(extra)
    return body


def _run_create(record_type: str, body: dict):
    """Invoke _handle_create_record with all external side effects mocked.

    Returns (response_dict, captured_put_item_kwargs_or_none).
    """
    put_item_mock = MagicMock()
    fake_ddb = MagicMock()
    fake_ddb.put_item = put_item_mock

    with patch.object(tracker_mutation, "_get_project_prefix", return_value="ENC"), \
         patch.object(tracker_mutation, "_get_prefix_map_cached", return_value={"ENC": "enceladus"}), \
         patch.object(tracker_mutation, "_get_ddb", return_value=fake_ddb), \
         patch.object(tracker_mutation, "_next_record_id", return_value="ENC-TSK-TST"):
        response = tracker_mutation._handle_create_record("enceladus", record_type, body)

    captured = None
    if put_item_mock.called:
        # Mock.call_args.kwargs is a dict; support both positional and kw forms.
        captured = put_item_mock.call_args.kwargs or dict(put_item_mock.call_args[1] or {})
    return response, captured


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class AcceptanceCriteriaNormalizationTests(unittest.TestCase):
    """ENC-ISS-181 regression guard — create path must match PATCH normalization."""

    def test_create_task_with_string_list_acs_stores_plain_descriptions(self):
        """Legacy path: list of plain strings survives as plain descriptions."""
        body = _make_create_body("task", ["First AC description", "Second AC description"])
        _, captured = _run_create("task", body)
        self.assertIsNotNone(captured, "put_item was not called — create rejected early")
        ac_list = captured["Item"]["acceptance_criteria"]["L"]
        self.assertEqual(len(ac_list), 2)
        self.assertEqual(ac_list[0]["M"]["description"]["S"], "First AC description")
        self.assertEqual(ac_list[1]["M"]["description"]["S"], "Second AC description")
        # Default evidence/evidence_acceptance when caller passes plain strings
        self.assertEqual(ac_list[0]["M"]["evidence"]["S"], "")
        self.assertFalse(ac_list[0]["M"]["evidence_acceptance"]["BOOL"])

    def test_create_task_with_dict_list_acs_extracts_description_field(self):
        """ENC-ISS-181 core regression: dict-shaped ACs must NOT be stringified.

        Before the fix this test would see description like:
            "{'description': 'AC-1: ...', 'evidence': '', 'evidence_acceptance': False}"
        After the fix, description must be the clean inner string.
        """
        dict_acs = [
            {"description": "AC-1: clean first criterion", "evidence": "", "evidence_acceptance": False},
            {"description": "AC-2: clean second criterion", "evidence": "", "evidence_acceptance": False},
        ]
        body = _make_create_body("task", dict_acs)
        _, captured = _run_create("task", body)
        self.assertIsNotNone(captured)
        ac_list = captured["Item"]["acceptance_criteria"]["L"]
        self.assertEqual(len(ac_list), 2)
        self.assertEqual(ac_list[0]["M"]["description"]["S"], "AC-1: clean first criterion")
        self.assertEqual(ac_list[1]["M"]["description"]["S"], "AC-2: clean second criterion")
        # Must NEVER contain the corruption signature
        for entry in ac_list:
            desc = entry["M"]["description"]["S"]
            self.assertFalse(
                desc.startswith("{'description':"),
                f"Corruption regression: description stored as dict repr: {desc[:80]}",
            )

    def test_create_task_with_dict_list_acs_preserves_preexisting_evidence(self):
        """If caller passes evidence/evidence_acceptance on create, they must be stored."""
        dict_acs = [
            {
                "description": "AC-1: already has evidence at create time",
                "evidence": "Pre-existing evidence text",
                "evidence_acceptance": True,
            },
        ]
        body = _make_create_body("task", dict_acs)
        _, captured = _run_create("task", body)
        self.assertIsNotNone(captured)
        ac = captured["Item"]["acceptance_criteria"]["L"][0]["M"]
        self.assertEqual(ac["description"]["S"], "AC-1: already has evidence at create time")
        self.assertEqual(ac["evidence"]["S"], "Pre-existing evidence text")
        self.assertTrue(ac["evidence_acceptance"]["BOOL"])

    def test_create_feature_with_dict_list_acs_extracts_description_field(self):
        """Feature create path must share the same dict-list normalization as tasks."""
        dict_acs = [
            {"description": "Feature AC-1 plain text", "evidence": "", "evidence_acceptance": False},
        ]
        body = _make_create_body("feature", dict_acs)
        _, captured = _run_create("feature", body)
        self.assertIsNotNone(captured)
        ac_list = captured["Item"]["acceptance_criteria"]["L"]
        self.assertEqual(ac_list[0]["M"]["description"]["S"], "Feature AC-1 plain text")
        self.assertFalse(ac_list[0]["M"]["description"]["S"].startswith("{'description':"))

    def test_create_task_rejects_dict_with_missing_description_key(self):
        """Dict ACs without a description key must fail validation, not silently store empty."""
        bad_acs = [{"evidence": "orphan evidence", "evidence_acceptance": False}]
        body = _make_create_body("task", bad_acs)
        response, captured = _run_create("task", body)
        self.assertEqual(response.get("statusCode"), 400)
        self.assertIn("description", (response.get("body") or ""))
        self.assertIsNone(captured, "put_item must not be called on validation failure")

    def test_create_task_rejects_empty_ac_list(self):
        """Empty acceptance_criteria list must reject task creation."""
        body = _make_create_body("task", [])
        response, captured = _run_create("task", body)
        self.assertEqual(response.get("statusCode"), 400)
        self.assertIn("acceptance_criteria", (response.get("body") or ""))
        self.assertIsNone(captured)

    def test_create_task_with_mixed_string_and_dict_acs(self):
        """A mixed list must normalize every entry to the same final shape."""
        mixed = [
            "Plain string AC",
            {"description": "Dict AC", "evidence": "", "evidence_acceptance": False},
        ]
        body = _make_create_body("task", mixed)
        _, captured = _run_create("task", body)
        self.assertIsNotNone(captured)
        ac_list = captured["Item"]["acceptance_criteria"]["L"]
        self.assertEqual(len(ac_list), 2)
        self.assertEqual(ac_list[0]["M"]["description"]["S"], "Plain string AC")
        self.assertEqual(ac_list[1]["M"]["description"]["S"], "Dict AC")
        for entry in ac_list:
            self.assertFalse(entry["M"]["description"]["S"].startswith("{'description':"))


if __name__ == "__main__":
    unittest.main()
