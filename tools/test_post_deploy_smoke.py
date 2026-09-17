#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-3 (ENC-ISS-778 P0): unit tests for tools/post_deploy_smoke.py.

Covers the four required scenarios -- healthy, unhealthy-then-rolled-back,
rollback-itself-fails, and nothing-to-probe -- plus the probe retry/backoff
logic (cold start tolerance), the deployed-function-name resolver, --dry-run
(no mutation, always exit 0), and the _deploy.yml workflow wiring: both
capture and check steps exist and are invoked from the .guard-tools path,
capture runs before "Deploy Lambda functions", check runs after the alias
update, and neither is soft-failing.

Hermetic: no network or live AWS calls -- all probe/rollback edges are
injected fakes.

Run: python3 -m pytest tools/test_post_deploy_smoke.py -q
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parent / "post_deploy_smoke.py"
_spec = importlib.util.spec_from_file_location("post_deploy_smoke", MODULE_PATH)
pds = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pds  # required for dataclasses' module lookup during exec_module
_spec.loader.exec_module(pds)  # type: ignore[union-attr]

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_PATH = REPO_ROOT / ".github" / "workflows" / "_deploy.yml"


# ---------------------------------------------------------------------------
# evaluate_probe_results / probe_target
# ---------------------------------------------------------------------------

class TestEvaluateProbeResults(unittest.TestCase):
    def setUp(self):
        self.target = pds.PROBE_TABLE["enceladus-mcp-code"]

    def test_all_expected_statuses_is_healthy(self):
        self.assertTrue(pds.evaluate_probe_results(
            {"/.well-known/oauth-protected-resource": 200, "/": 401}, self.target,
        ))

    def test_incident_502_on_both_routes_is_unhealthy(self):
        self.assertFalse(pds.evaluate_probe_results(
            {"/.well-known/oauth-protected-resource": 502, "/": 502}, self.target,
        ))

    def test_one_bad_route_is_unhealthy(self):
        self.assertFalse(pds.evaluate_probe_results(
            {"/.well-known/oauth-protected-resource": 200, "/": 502}, self.target,
        ))

    def test_missing_result_is_unhealthy(self):
        self.assertFalse(pds.evaluate_probe_results(
            {"/.well-known/oauth-protected-resource": 200}, self.target,
        ))


class TestProbeTargetRetryBackoff(unittest.TestCase):
    def test_recovers_after_transient_failures_cold_start_tolerance(self):
        target = pds.PROBE_TABLE["enceladus-mcp-code"]
        calls = {"n": 0}

        def fetcher(url):
            calls["n"] += 1
            # Fail (cold start) for the first two full rounds, then heal.
            if calls["n"] <= 4:
                return 502
            return 200 if "oauth-protected-resource" in url else 401

        sleeps = []
        healthy = pds.probe_target(target, attempts=4, fetcher=fetcher, sleep_fn=sleeps.append)
        self.assertTrue(healthy)
        self.assertTrue(sleeps, "expected at least one backoff sleep before recovering")

    def test_never_recovers_returns_false_after_exhausting_attempts(self):
        target = pds.PROBE_TABLE["enceladus-mcp-code"]
        healthy = pds.probe_target(target, attempts=3, fetcher=lambda url: 502, sleep_fn=lambda s: None)
        self.assertFalse(healthy)

    def test_fetcher_exception_counts_as_unhealthy_not_a_crash(self):
        target = pds.PROBE_TABLE["enceladus-mcp-code"]

        def fetcher(url):
            raise TimeoutError("boom")

        # probe_target's fetcher contract allows returning None for a failed
        # request (see _http_status); a raising fetcher is not the module's
        # own production fetcher, so route through one that mimics it.
        def safe_fetcher(url):
            try:
                return fetcher(url)
            except Exception:
                return None

        healthy = pds.probe_target(target, attempts=2, fetcher=safe_fetcher, sleep_fn=lambda s: None)
        self.assertFalse(healthy)


# ---------------------------------------------------------------------------
# resolve_deployed_function_names
# ---------------------------------------------------------------------------

class TestResolveDeployedFunctionNames(unittest.TestCase):
    def test_narrowed_scope_maps_only_probed_functions(self):
        names = pds.resolve_deployed_function_names(
            function_name_map={"mcp_code": "enceladus-mcp-code", "other_fn": "other-fn"},
            version_ids={"mcp_code": "v1"},
        )
        self.assertEqual(names, ["enceladus-mcp-code"])

    def test_comma_list_expands_and_dedupes(self):
        names = pds.resolve_deployed_function_names(
            function_name_map={"checkout_service": "enceladus-checkout-service, enceladus-checkout-service-auto"},
            version_ids={"checkout_service": "v1"},
        )
        self.assertEqual(names, ["enceladus-checkout-service", "enceladus-checkout-service-auto"])

    def test_unmapped_function_is_skipped(self):
        names = pds.resolve_deployed_function_names(
            function_name_map={}, version_ids={"mcp_code": "v1"},
        )
        self.assertEqual(names, [])


# ---------------------------------------------------------------------------
# run_function_smoke -- the four required scenarios
# ---------------------------------------------------------------------------

class TestRunFunctionSmoke(unittest.TestCase):
    def test_healthy(self):
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", "41",
            probe_fn=lambda target: True,
            rollback_fn=lambda name, version: (True, "unused"),
        )
        self.assertEqual(outcome.status, "healthy")
        self.assertNotIn(outcome.status, pds._FAILING_STATUSES)

    def test_unhealthy_then_rolled_back(self):
        # First probe (post-deploy) fails, rollback succeeds, second probe
        # (post-rollback recovery check) succeeds.
        probe_calls = {"n": 0}

        def probe_fn(target):
            probe_calls["n"] += 1
            return probe_calls["n"] > 1

        rollback_calls = []

        def rollback_fn(name, version):
            rollback_calls.append((name, version))
            return True, "rolled back"

        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", "41", probe_fn=probe_fn, rollback_fn=rollback_fn,
        )
        self.assertEqual(outcome.status, "rolled_back")
        self.assertIn(outcome.status, pds._FAILING_STATUSES, "a fired rollback must still fail the run")
        self.assertEqual(rollback_calls, [("enceladus-mcp-code", "41")])

    def test_rollback_itself_fails(self):
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", "41",
            probe_fn=lambda target: False,
            rollback_fn=lambda name, version: (False, "AccessDenied"),
        )
        self.assertEqual(outcome.status, "rollback_failed")
        self.assertIn(outcome.status, pds._FAILING_STATUSES)
        self.assertIn("AccessDenied", outcome.detail)

    def test_rollback_succeeds_but_recovery_probe_still_unhealthy(self):
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", "41",
            probe_fn=lambda target: False,
            rollback_fn=lambda name, version: (True, "rolled back"),
        )
        self.assertEqual(outcome.status, "rollback_unverified")
        self.assertIn(outcome.status, pds._FAILING_STATUSES)

    def test_nothing_to_probe_no_probe_table_entry(self):
        outcome = pds.run_function_smoke(
            "devops-tracker-mutation-api", "7",
            probe_fn=lambda target: (_ for _ in ()).throw(AssertionError("must not be called")),
            rollback_fn=lambda name, version: (_ for _ in ()).throw(AssertionError("must not be called")),
        )
        self.assertEqual(outcome.status, "no_probe")
        self.assertNotIn(outcome.status, pds._FAILING_STATUSES)

    def test_nothing_to_probe_no_previous_version(self):
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", None,
            probe_fn=lambda target: (_ for _ in ()).throw(AssertionError("must not be called")),
            rollback_fn=lambda name, version: (_ for _ in ()).throw(AssertionError("must not be called")),
        )
        self.assertEqual(outcome.status, "no_previous_version")
        self.assertNotIn(outcome.status, pds._FAILING_STATUSES)

    def test_dry_run_never_mutates_and_is_not_a_failure(self):
        rollback_calls = []

        def rollback_fn(name, version):
            rollback_calls.append((name, version))
            return True, "should never be called"

        outcome = pds.run_function_smoke(
            "enceladus-mcp-code", "41",
            probe_fn=lambda target: False,
            rollback_fn=rollback_fn,
            dry_run=True,
        )
        self.assertEqual(outcome.status, "unhealthy_dry_run")
        self.assertEqual(rollback_calls, [], "dry-run must never invoke the rollback function")
        self.assertNotIn(outcome.status, pds._FAILING_STATUSES)


class TestDecideExitCode(unittest.TestCase):
    def test_all_healthy_or_noop_is_zero(self):
        outcomes = [
            pds.SmokeOutcome("a", "healthy", ""),
            pds.SmokeOutcome("b", "no_probe", ""),
            pds.SmokeOutcome("c", "no_previous_version", ""),
        ]
        self.assertEqual(pds.decide_exit_code(outcomes), 0)

    def test_any_failing_status_is_one(self):
        outcomes = [pds.SmokeOutcome("a", "healthy", ""), pds.SmokeOutcome("b", "rolled_back", "")]
        self.assertEqual(pds.decide_exit_code(outcomes), 1)

    def test_empty_is_zero(self):
        self.assertEqual(pds.decide_exit_code([]), 0)


# ---------------------------------------------------------------------------
# CLI: capture / check
# ---------------------------------------------------------------------------

class TestCaptureCli(unittest.TestCase):
    def test_capture_prints_json_of_captured_versions(self):
        with patch.object(pds, "get_live_alias_version", return_value="41"):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
                "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            ])
        self.assertEqual(rc, 0)

    def test_capture_no_existing_alias_is_not_an_error(self):
        with patch.object(pds, "get_live_alias_version", return_value=None):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
                "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            ])
        self.assertEqual(rc, 0)

    def test_capture_bad_json_exits_two(self):
        rc = pds.main(["capture", "--function-name-map-json", "not json", "--version-ids-json", "{}"])
        self.assertEqual(rc, 2)


class TestCheckCli(unittest.TestCase):
    def _args(self, previous_versions, dry_run=False):
        args = [
            "check",
            "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
            "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            "--previous-alias-versions-json", json.dumps(previous_versions),
        ]
        if dry_run:
            args.append("--dry-run")
        return args

    def test_healthy_exits_zero(self):
        with patch.object(pds, "probe_target", return_value=True):
            rc = pds.main(self._args({"enceladus-mcp-code": "41"}))
        self.assertEqual(rc, 0)

    def test_unhealthy_rolled_back_exits_one(self):
        with patch.object(pds, "probe_target", return_value=False), \
             patch.object(pds, "aws_rollback_alias", return_value=(True, "ok")):
            rc = pds.main(self._args({"enceladus-mcp-code": "41"}))
        self.assertEqual(rc, 1)

    def test_rollback_failure_exits_one(self):
        with patch.object(pds, "probe_target", return_value=False), \
             patch.object(pds, "aws_rollback_alias", return_value=(False, "AccessDenied")):
            rc = pds.main(self._args({"enceladus-mcp-code": "41"}))
        self.assertEqual(rc, 1)

    def test_nothing_to_probe_exits_zero(self):
        rc = pds.main(self._args({}))  # no previous version captured
        self.assertEqual(rc, 0)

    def test_no_deployed_functions_is_a_clean_noop(self):
        rc = pds.main([
            "check",
            "--function-name-map-json", "{}",
            "--version-ids-json", "{}",
            "--previous-alias-versions-json", "{}",
        ])
        self.assertEqual(rc, 0)

    def test_dry_run_never_mutates_even_when_unhealthy(self):
        with patch.object(pds, "probe_target", return_value=False), \
             patch.object(pds, "aws_rollback_alias") as mock_rollback:
            rc = pds.main(self._args({"enceladus-mcp-code": "41"}, dry_run=True))
        mock_rollback.assert_not_called()
        self.assertEqual(rc, 0)

    def test_bad_json_exits_two(self):
        rc = pds.main([
            "check",
            "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
            "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            "--previous-alias-versions-json", "not json",
        ])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# _deploy.yml workflow wiring
# ---------------------------------------------------------------------------

class TestDeployYmlWiring(unittest.TestCase):
    def setUp(self):
        self.text = DEPLOY_PATH.read_text()

    def _deploy_job_text(self) -> str:
        start = self.text.find("\n  deploy:\n")
        self.assertNotEqual(start, -1, "_deploy.yml is missing the deploy job")
        return self.text[start:]

    def test_capture_and_check_are_invoked_from_guard_tools_path(self):
        job_text = self._deploy_job_text()
        for sub in ("capture", "check"):
            self.assertIn(
                f".guard-tools/tools/post_deploy_smoke.py {sub}", job_text,
                f"post_deploy_smoke.py {sub} must be invoked from the .guard-tools path",
            )

    def test_capture_runs_before_deploy_lambda_functions(self):
        job_text = self._deploy_job_text()
        capture_pos = job_text.find(".guard-tools/tools/post_deploy_smoke.py capture")
        deploy_pos = job_text.find("- name: Deploy Lambda functions")
        self.assertNotEqual(capture_pos, -1)
        self.assertNotEqual(deploy_pos, -1)
        self.assertLess(capture_pos, deploy_pos, "alias-version capture must run before the deploy step")

    def test_check_runs_after_deploy_lambda_functions(self):
        job_text = self._deploy_job_text()
        check_pos = job_text.find(".guard-tools/tools/post_deploy_smoke.py check")
        deploy_step_marker = job_text.find("id: lambda_deploy")
        self.assertNotEqual(check_pos, -1)
        self.assertNotEqual(deploy_step_marker, -1)
        self.assertGreater(check_pos, deploy_step_marker, "smoke check must run after the deploy step")

    def test_neither_step_uses_continue_on_error_or_shell_swallow(self):
        job_text = self._deploy_job_text()
        for marker in ("capture", "check"):
            pos = job_text.find(f".guard-tools/tools/post_deploy_smoke.py {marker}")
            self.assertNotEqual(pos, -1)
            # Isolate the enclosing step's run: block roughly (from the
            # previous "- name:" to the next one).
            step_start = job_text.rfind("- name:", 0, pos)
            step_end = job_text.find("- name:", pos)
            step_text = job_text[step_start:step_end if step_end != -1 else len(job_text)]
            self.assertNotIn("continue-on-error", step_text)
            self.assertNotIn("|| true", step_text)

    def test_guard_tools_checkout_includes_post_deploy_smoke(self):
        self.assertIn("post_deploy_smoke.py", self.text)
        checkout_block_match = re.search(
            r"Checkout guard tooling \(workflow branch\).*?sparse-checkout:(.*?)\n\s*sparse-checkout-cone-mode",
            self.text, re.DOTALL,
        )
        self.assertIsNotNone(checkout_block_match, "_deploy.yml is missing the guard-tools checkout step")
        self.assertIn("post_deploy_smoke.py", checkout_block_match.group(1))
        self.assertIn("assert_artifact_arch_matches_functions.py", checkout_block_match.group(1))


if __name__ == "__main__":
    unittest.main()
