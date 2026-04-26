"""Tests for coordination_api._validate_lifecycle_transition (ENC-TSK-F40 AC[1a]).

Exercises the 8-status state machine transition validator:
- Every entry in the authoritative transition_table (DOC-546B896390EA §3.2)
  returns (True, None).
- Targets NOT in the table return LIFECYCLE_TRANSITION_UNMET with
  allowed_targets + remediation_guidance.
- Hard blocks (deprecated->development, archived->any) return
  LIFECYCLE_TRANSITION_UNMET independently of the table.
"""

import importlib.util
import os
import sys
import unittest


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


class LifecycleTransitionValidatorTests(unittest.TestCase):
    """ENC-TSK-F40 AC[1a] — 8-status state machine transition validator."""

    def setUp(self):
        # Clear the module-level cache so each test gets fresh behavior and
        # the fallback transition table drives validation deterministically.
        coordination_lambda._COMPONENT_TRANSITION_TABLE_CACHE = None

    def test_proposed_to_approved_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "proposed", "approved"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_proposed_to_archived_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "proposed", "archived"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_approved_to_designed_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "approved", "designed"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_designed_to_development_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "designed", "development"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_development_to_production_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "development", "production"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_production_to_code_red_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "production", "code-red"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_production_to_deprecated_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "production", "deprecated"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_code_red_to_production_is_valid(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "code-red", "production"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_deprecated_to_production_is_valid(self):
        """deprecated may restore to production per §3.2."""
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "deprecated", "production"
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    # --- Rejections ---

    def test_archived_to_approved_rejected_as_terminal(self):
        """archived->any is a HARD BLOCK per §3.2 (terminal, no recovery)."""
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "archived", "approved"
        )
        self.assertFalse(valid)
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "LIFECYCLE_TRANSITION_UNMET")
        self.assertEqual(err["details"]["reason"], "archived_is_terminal")
        self.assertEqual(err["details"]["allowed_targets"], [])

    def test_archived_to_archived_rejected_as_terminal(self):
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "archived", "production"
        )
        self.assertFalse(valid)
        self.assertIsNotNone(err)
        self.assertEqual(err["details"]["reason"], "archived_is_terminal")

    def test_deprecated_to_development_rejected_as_hard_block(self):
        """deprecated->development is a HARD BLOCK per §3.2 / DD-3.
        Version-fork (-v2/-v3) required."""
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "deprecated", "development"
        )
        self.assertFalse(valid)
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "LIFECYCLE_TRANSITION_UNMET")
        self.assertEqual(
            err["details"]["reason"], "hard_block_deprecated_to_development"
        )
        self.assertIn("-v2", err["details"]["remediation_guidance"])

    def test_approved_to_production_rejected_as_not_in_table(self):
        """Table enforces the single-step walk; skipping stages is rejected."""
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "approved", "production"
        )
        self.assertFalse(valid)
        self.assertIsNotNone(err)
        self.assertEqual(err["details"]["reason"], "transition_not_in_table")
        self.assertIn("designed", err["details"]["allowed_targets"])

    def test_proposed_to_designed_rejected_as_not_in_table(self):
        """approved is the mandatory intermediate hop."""
        valid, err = coordination_lambda._validate_lifecycle_transition(
            "proposed", "designed"
        )
        self.assertFalse(valid)
        self.assertEqual(err["details"]["reason"], "transition_not_in_table")


if __name__ == "__main__":
    unittest.main()
