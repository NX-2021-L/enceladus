"""Tests for ENC-TSK-H84 / ENC-FTR-111 — project deploy_policy field.

Covers AC-1: deploy_policy (enum ci_triggered / manual) exists on the project record, is
validated at create time, defaults to ci_triggered, and read-time defaulting "seeds" the
effective value for existing/legacy projects (including enceladus).

Pure-logic units — no AWS. _compute_days_since_active is stubbed so _enrich_project stays pure.
Runs under pytest (test_* discovery) and standalone (`python3 test_deploy_policy_h84.py`).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "project_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
ps = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ps)


class DeployPolicyValidationTests(unittest.TestCase):
    def _valid_body(self, **over):
        body = {"name": "demo", "prefix": "DMO", "summary": "a demo project"}
        body.update(over)
        return body

    def test_default_is_ci_triggered(self):
        data, err = ps._validate_create_input(self._valid_body())
        self.assertIsNone(err, err)
        self.assertEqual(data["deploy_policy"], "ci_triggered")

    def test_explicit_manual_accepted(self):
        data, err = ps._validate_create_input(self._valid_body(deploy_policy="manual"))
        self.assertIsNone(err, err)
        self.assertEqual(data["deploy_policy"], "manual")

    def test_case_insensitive_and_trimmed(self):
        data, err = ps._validate_create_input(self._valid_body(deploy_policy="  CI_Triggered "))
        self.assertIsNone(err, err)
        self.assertEqual(data["deploy_policy"], "ci_triggered")

    def test_invalid_value_rejected(self):
        data, err = ps._validate_create_input(self._valid_body(deploy_policy="rolling"))
        self.assertIsNone(data)
        self.assertIn("deploy_policy", err)


class DeployPolicyEnrichTests(unittest.TestCase):
    def setUp(self):
        self._orig = ps._compute_days_since_active
        ps._compute_days_since_active = lambda pid: None  # keep _enrich_project pure

    def tearDown(self):
        ps._compute_days_since_active = self._orig

    def test_existing_project_without_field_seeds_ci_triggered(self):
        # Legacy project record (e.g. enceladus predating the field) reads as the seeded default.
        out = ps._enrich_project({"project_id": "enceladus"})
        self.assertEqual(out["deploy_policy"], "ci_triggered")

    def test_explicit_manual_preserved(self):
        out = ps._enrich_project({"project_id": "x", "deploy_policy": "manual"})
        self.assertEqual(out["deploy_policy"], "manual")

    def test_unknown_stored_value_coerced_to_default(self):
        out = ps._enrich_project({"project_id": "x", "deploy_policy": "garbage"})
        self.assertEqual(out["deploy_policy"], "ci_triggered")


if __name__ == "__main__":
    unittest.main()
