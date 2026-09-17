"""ENC-TSK-Q02 / ENC-ISS-777 — code_only closed-gate evidence normalization.

Verifies the closed gate for transition_type=code_only accepts the shapes
documented in _CODE_ON_MAIN_EVIDENCE_SCHEMA (an object, a bare 40-hex commit
sha string, or a note string alongside a top-level transition_evidence.commit_sha)
instead of rejecting everything that is not already a non-empty dict, and that
the rejection envelope for malformed input is internally consistent: the same
nested field path appears in details.required_fields,
details.required_evidence_schema.required_fields, and details.example_fix.

Also covers the no_code closed gate's rejection-envelope consistency (item 2
of the brief), which requires no behavior change to its accepted input (a
non-empty string).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

_SPEC = importlib.util.spec_from_file_location(
    "checkout_service_iss777",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_service
_SPEC.loader.exec_module(checkout_service)

_SHA_A = "a" * 40
_SHA_B = "b" * 40
_SHA_C = "c" * 40

_REQUIRED_PATH = "transition_evidence.code_on_main_evidence.commit_sha"
_NO_CODE_PATH = "transition_evidence.no_code_evidence"


def _code_only_task(**overrides):
    task = {
        "status": "merged-main",
        "transition_type": "code_only",
        "active_agent_session": True,
        "active_agent_session_id": "test-session",
        "components": ["comp-code"],
    }
    task.update(overrides)
    return task


def _no_code_task(**overrides):
    task = {
        "status": "coding-complete",
        "transition_type": "no_code",
        "active_agent_session": True,
        "active_agent_session_id": "test-session",
        "components": ["comp-docs"],
    }
    task.update(overrides)
    return task


def _walk(obj, *path):
    """Walk a dotted-path-style sequence of keys through nested dicts."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _assert_path_consistent(test, details, path_str):
    """Assert `path_str` shows up in required_fields, required_evidence_schema
    and example_fix in a structurally meaningful way (not just a substring)."""
    test.assertIn(path_str, details.get("required_fields", []))
    schema_required = details.get("required_evidence_schema", {}).get("required_fields", {})
    test.assertIn(path_str, schema_required)

    example_fix = details.get("example_fix", {})
    keys = path_str.split(".")
    # keys[0] is always "transition_evidence" — arguments.transition_evidence.<...>
    nested = _walk(example_fix, "arguments", *keys)
    test.assertIsNotNone(
        nested, f"expected example_fix.arguments.{'.'.join(keys)} to be present: {example_fix}"
    )


@patch.object(checkout_service, "_get_components_lifecycle",
              return_value={"comp-code": {"lifecycle_status": "active"}})
@patch.object(checkout_service, "_get_component_required_transition_types", return_value=set())
@patch.object(checkout_service, "_get_required_transition_type", return_value=None)
class CodeOnlyCloseSuccessTests(unittest.TestCase):
    """Each accepted shape must reach the tracker_mutation call (200)."""

    def _advance(self, code_on_main_evidence, extra_evidence=None, task_overrides=None):
        transition_evidence = {
            "owner": "me-jreese",
            "repo": "enceladus",
            "code_on_main_evidence": code_on_main_evidence,
        }
        if extra_evidence:
            transition_evidence.update(extra_evidence)
        task = _code_only_task(**(task_overrides or {}))
        updated = {**task, "status": "closed"}
        with patch.object(checkout_service, "_get_task", side_effect=[(200, task), (200, updated)]), \
             patch.object(checkout_service, "_validate_code_on_main_evidence", return_value=(True, "")) as mock_validate, \
             patch.object(checkout_service, "_set_task_field", return_value=(200, {"success": True})) as mock_set, \
             patch.object(checkout_service, "_release_task") as mock_release:
            resp = checkout_service._handle_advance(
                "enceladus",
                "ENC-TSK-CODEONLY",
                {
                    "target_status": "closed",
                    "provider": "test-session",
                    "transition_evidence": transition_evidence,
                },
            )
        return resp, mock_validate, mock_set, mock_release

    def test_object_evidence_succeeds(self, *_mocks):
        resp, mock_validate, mock_set, mock_release = self._advance({"commit_sha": _SHA_A})
        self.assertEqual(resp["statusCode"], 200)
        mock_validate.assert_called_once()
        stored = mock_set.call_args.kwargs["transition_evidence"]["code_on_main_evidence"]
        self.assertEqual(stored["commit_sha"], _SHA_A)
        mock_release.assert_called_once()

    def test_bare_40hex_string_succeeds(self, *_mocks):
        resp, mock_validate, mock_set, _release = self._advance(_SHA_A.upper())
        self.assertEqual(resp["statusCode"], 200)
        stored = mock_set.call_args.kwargs["transition_evidence"]["code_on_main_evidence"]
        self.assertEqual(stored["commit_sha"], _SHA_A)  # lowercased
        validated_obj = mock_validate.call_args.args[2]
        self.assertEqual(validated_obj["commit_sha"], _SHA_A)

    def test_note_string_with_top_level_commit_sha_succeeds(self, *_mocks):
        resp, mock_validate, mock_set, _release = self._advance(
            "Squashed and merged in #1234, verified manually.",
            extra_evidence={"commit_sha": _SHA_B},
        )
        self.assertEqual(resp["statusCode"], 200)
        stored = mock_set.call_args.kwargs["transition_evidence"]["code_on_main_evidence"]
        self.assertEqual(stored["commit_sha"], _SHA_B)
        self.assertEqual(stored["note"], "Squashed and merged in #1234, verified manually.")

    def test_dict_missing_commit_sha_plus_top_level_commit_sha_succeeds(self, *_mocks):
        resp, mock_validate, mock_set, _release = self._advance(
            {"note": "reviewed in PR"},
            extra_evidence={"commit_sha": _SHA_C},
        )
        self.assertEqual(resp["statusCode"], 200)
        stored = mock_set.call_args.kwargs["transition_evidence"]["code_on_main_evidence"]
        self.assertEqual(stored["commit_sha"], _SHA_C)
        self.assertEqual(stored["note"], "reviewed in PR")


@patch.object(checkout_service, "_get_components_lifecycle",
              return_value={"comp-code": {"lifecycle_status": "active"}})
@patch.object(checkout_service, "_get_component_required_transition_types", return_value=set())
@patch.object(checkout_service, "_get_required_transition_type", return_value=None)
class CodeOnlyCloseMalformedTests(unittest.TestCase):
    """Malformed code_on_main_evidence must 400 with a mutually consistent envelope."""

    def _advance(self, code_on_main_evidence, extra_evidence=None):
        transition_evidence = {
            "owner": "me-jreese",
            "repo": "enceladus",
            "code_on_main_evidence": code_on_main_evidence,
        }
        if extra_evidence:
            transition_evidence.update(extra_evidence)
        task = _code_only_task()
        with patch.object(checkout_service, "_get_task", return_value=(200, task)):
            resp = checkout_service._handle_advance(
                "enceladus",
                "ENC-TSK-CODEONLY",
                {
                    "target_status": "closed",
                    "provider": "test-session",
                    "transition_evidence": transition_evidence,
                },
            )
        return resp

    def _assert_malformed_400(self, resp):
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"])["error_envelope"]
        message = envelope["message"]
        self.assertIn("code_on_main_evidence", message)
        self.assertIn("40-hex", message)
        details = envelope["details"]
        _assert_path_consistent(self, details, _REQUIRED_PATH)
        return envelope

    def test_empty_string_rejected(self, *_mocks):
        self._assert_malformed_400(self._advance(""))

    def test_integer_rejected(self, *_mocks):
        self._assert_malformed_400(self._advance(12345))

    def test_string_without_sha_and_no_top_level_sha_rejected(self, *_mocks):
        self._assert_malformed_400(self._advance("not-a-sha"))

    def test_empty_object_rejected(self, *_mocks):
        self._assert_malformed_400(self._advance({}))


@patch.object(checkout_service, "_get_components_lifecycle",
              return_value={"comp-docs": {"lifecycle_status": "active"}})
@patch.object(checkout_service, "_get_component_required_transition_types", return_value=set())
@patch.object(checkout_service, "_get_required_transition_type", return_value=None)
class NoCodeCloseEnvelopeTests(unittest.TestCase):
    """no_code closed gate: unchanged accepted input, consistent rejection envelope."""

    def test_succeeds_with_non_empty_evidence_string(self, *_mocks):
        task = _no_code_task()
        updated = {**task, "status": "closed"}
        with patch.object(checkout_service, "_get_task", side_effect=[(200, task), (200, updated)]), \
             patch.object(checkout_service, "_set_task_field", return_value=(200, {"success": True})) as mock_set, \
             patch.object(checkout_service, "_release_task") as mock_release:
            resp = checkout_service._handle_advance(
                "enceladus",
                "ENC-TSK-NOCODE",
                {
                    "target_status": "closed",
                    "provider": "test-session",
                    "transition_evidence": {
                        "no_code_evidence": "Updated governance doc and confirmed agents can read it.",
                    },
                },
            )
        self.assertEqual(resp["statusCode"], 200)
        stored = mock_set.call_args.kwargs["transition_evidence"]["no_code_evidence"]
        self.assertEqual(stored, "Updated governance doc and confirmed agents can read it.")
        mock_release.assert_called_once()

    def test_fails_with_consistent_envelope_when_missing(self, *_mocks):
        task = _no_code_task()
        with patch.object(checkout_service, "_get_task", return_value=(200, task)):
            resp = checkout_service._handle_advance(
                "enceladus",
                "ENC-TSK-NOCODE",
                {
                    "target_status": "closed",
                    "provider": "test-session",
                    "transition_evidence": {},
                },
            )
        self.assertEqual(resp["statusCode"], 400)
        envelope = json.loads(resp["body"])["error_envelope"]
        details = envelope["details"]
        _assert_path_consistent(self, details, _NO_CODE_PATH)


if __name__ == "__main__":
    unittest.main()
