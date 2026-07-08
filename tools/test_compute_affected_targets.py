#!/usr/bin/env python3
"""ENC-TSK-J40 AC-5 verification: a single-function change deploys only that
function, and a shared-layer change fans out to all. Mocks the `_run`
subprocess seam in compute_affected_targets.py -- no live git/gh/AWS calls.

Run: python3 tools/test_compute_affected_targets.py
"""
import importlib.util
import json
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


class ResolveLastDeployedShaDiscriminatorTest(unittest.TestCase):
    """ENC-ISS-519: a CFN stack-deploy workflow's `environment: v4-gamma` job
    attribute makes GitHub Actions auto-create a Deployment + success status
    for the same environment/sha as _deploy.yml's own Lambda code-deploy --
    racing ahead of it. resolve_last_deployed_sha must never treat that
    raced, non-code-deploy record as evidence a real Lambda deploy happened."""

    @staticmethod
    def _fake_run(deployments, statuses_by_id, diff_lines=None):
        def _run(cmd):
            if cmd[:2] == ["gh", "api"] and "deployments?environment=" in cmd[2]:
                return json.dumps(deployments)
            if cmd[:2] == ["gh", "api"] and "/statuses" in cmd[2]:
                for dep_id, statuses in statuses_by_id.items():
                    if f"/deployments/{dep_id}/statuses" in cmd[2]:
                        return json.dumps(statuses)
                return "[]"
            if cmd[:2] == ["git", "diff"] and diff_lines is not None:
                return "\n".join(diff_lines) + "\n"
            return None
        return _run

    def test_skips_deployment_record_lacking_discriminator(self):
        # id=2 (no task, i.e. a GitHub-managed CFN environment deployment) is
        # newest and races ahead; id=1 carries the real code-deploy task.
        deployments = [
            {"id": 2, "sha": "racedsha"},
            {"id": 1, "sha": "realsha", "task": cat.LAMBDA_CODE_DEPLOY_TASK},
        ]
        statuses = {2: [{"state": "success"}], 1: [{"state": "success"}]}
        with patch.object(cat, "_run", self._fake_run(deployments, statuses)):
            sha = cat.resolve_last_deployed_sha("v4-gamma", "org/repo")
        self.assertEqual(sha, "realsha")

    def test_no_discriminated_record_forces_full_scope(self):
        # Only a raced, non-discriminated (CFN-auto-created) record exists --
        # never treat it as "a real deploy happened here"; fail-open.
        deployments = [{"id": 9, "sha": "cfnraced", "task": "deploy"}]
        statuses = {9: [{"state": "success"}]}
        with patch.object(cat, "_run", self._fake_run(deployments, statuses)):
            result = cat.compute("v4-gamma", "org/repo", "headsha")
        self.assertTrue(result["full_scope"], result["reason"])
        self.assertIn("no prior successful deployment", result["reason"])

    def test_base_sha_equals_head_short_circuit_only_from_real_code_deploy(self):
        # id=3 races in at head_sha with no discriminator (the ENC-ISS-519
        # bug case: base_sha == head_sha would wrongly short-circuit to
        # "nothing to diff" if this record were trusted). The real prior
        # code-deploy (id=2) sits at an older sha -- the resolver must skip
        # the raced head_sha record and diff against the real prior deploy.
        deployments = [
            {"id": 3, "sha": "headsha", "task": "deploy"},
            {"id": 2, "sha": "priorsha", "task": cat.LAMBDA_CODE_DEPLOY_TASK},
        ]
        statuses = {3: [{"state": "success"}], 2: [{"state": "success"}]}
        diff_lines = ["backend/lambda/tracker_mutation/lambda_function.py"]
        with patch.object(cat, "_run", self._fake_run(deployments, statuses, diff_lines)):
            result = cat.compute("v4-gamma", "org/repo", "headsha")
        self.assertFalse(result["full_scope"], result["reason"])
        self.assertEqual(result["base_sha"], "priorsha")
        self.assertEqual(result["affected_functions"], ["tracker_mutation"])

    def test_legit_same_sha_redeploy_noop_still_short_circuits(self):
        # A real code-deploy record (correct discriminator) already sits at
        # head_sha -- this IS legitimate "nothing to diff, already deployed
        # here" and must still short-circuit (candidate 3 must not become
        # fail-closed-to-full-scope for the true no-op case).
        deployments = [{"id": 1, "sha": "headsha", "task": cat.LAMBDA_CODE_DEPLOY_TASK}]
        statuses = {1: [{"state": "success"}]}
        with patch.object(cat, "_run", self._fake_run(deployments, statuses)):
            result = cat.compute("v4-gamma", "org/repo", "headsha")
        self.assertFalse(result["full_scope"], result["reason"])
        self.assertEqual(result["base_sha"], "headsha")
        self.assertEqual(result["affected_functions"], [])


if __name__ == "__main__":
    unittest.main()
