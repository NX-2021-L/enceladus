#!/usr/bin/env python3
"""ENC-TSK-J40 AC-5 verification: a single-function change deploys only that
function, and a shared-layer change fans out to all. Mocks the `_run`
subprocess seam in compute_affected_targets.py -- no live git/gh/AWS calls.

Run: python3 tools/test_compute_affected_targets.py
"""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parent / "compute_affected_targets.py"
spec = importlib.util.spec_from_file_location("compute_affected_targets", MODULE_PATH)
cat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cat)


def _fake_run_factory(diff_lines, deployments_json="[]"):
    def _fake_run(cmd):
        if cmd[:2] == ["git", "diff"]:
            return "\n".join(diff_lines) + "\n"
        if cmd[:2] == ["gh", "api"] and "deployments?environment=" in cmd[2]:
            return deployments_json
        if cmd[:2] == ["gh", "api"] and "/statuses" in cmd[2]:
            return '[{"state": "success"}]'
        return None
    return _fake_run


class ComputeAffectedTargetsTest(unittest.TestCase):
    def test_single_function_change_is_narrow(self):
        with patch.object(cat, "_run", _fake_run_factory([
            "backend/lambda/tracker_mutation/lambda_function.py",
        ])):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertFalse(result["full_scope"], result["reason"])
        self.assertEqual(result["affected_functions"], ["tracker_mutation"])

    def test_multi_file_same_function_dedupes(self):
        with patch.object(cat, "_run", _fake_run_factory([
            "backend/lambda/tracker_mutation/lambda_function.py",
            "backend/lambda/tracker_mutation/helpers.py",
            "README.md",
        ])):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertFalse(result["full_scope"])
        self.assertEqual(result["affected_functions"], ["tracker_mutation"])

    def test_shared_layer_change_forces_full_scope(self):
        with patch.object(cat, "_run", _fake_run_factory([
            "backend/lambda/shared_layer/python/enceladus_shared/appconfig_flags.py",
            "backend/lambda/tracker_mutation/lambda_function.py",
        ])):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertTrue(result["full_scope"], result["reason"])

    def test_deploy_workflow_change_forces_full_scope(self):
        with patch.object(cat, "_run", _fake_run_factory([
            ".github/workflows/_deploy.yml",
        ])):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertTrue(result["full_scope"])

    def test_diff_failure_forces_full_scope(self):
        with patch.object(cat, "_run", lambda cmd: None):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertTrue(result["full_scope"])

    def test_no_prior_deployment_forces_full_scope(self):
        with patch.object(cat, "resolve_last_deployed_sha", lambda env, repo: None):
            result = cat.compute("v4-gamma", "org/repo", "headsha")
        self.assertTrue(result["full_scope"])

    def test_non_lambda_only_change_is_narrow_and_empty(self):
        with patch.object(cat, "_run", _fake_run_factory([
            "README.md",
            "docs/foo.md",
        ])):
            result = cat.compute("v4-gamma", "org/repo", "headsha", base_sha_override="basesha")
        self.assertFalse(result["full_scope"])
        self.assertEqual(result["affected_functions"], [])


if __name__ == "__main__":
    unittest.main()
