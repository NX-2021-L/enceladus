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

    def test_gamma_env_variant_of_a_known_probed_function_is_distinct_from_no_probe(self):
        # ENC-TSK-Q05 review finding (major): main's own _deploy.yml
        # workflow_dispatch allows target_environment=v4-gamma, whose
        # deployed function name is "enceladus-mcp-code-gamma" --
        # PROBE_TABLE has no entry for that name. This must NOT report the
        # same "no_probe" status as a function that legitimately has no
        # health surface at all.
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code-gamma", "7",
            probe_fn=lambda target: (_ for _ in ()).throw(AssertionError("must not be called")),
            rollback_fn=lambda name, version: (_ for _ in ()).throw(AssertionError("must not be called")),
            environment_suffix="-gamma",
        )
        self.assertEqual(outcome.status, "no_probe_env_variant")
        self.assertNotEqual(outcome.status, "no_probe")
        self.assertNotIn(outcome.status, pds._FAILING_STATUSES)

    def test_unrelated_function_with_no_env_suffix_match_is_plain_no_probe(self):
        outcome = pds.run_function_smoke(
            "devops-tracker-mutation-api", "7",
            probe_fn=lambda target: (_ for _ in ()).throw(AssertionError("must not be called")),
            rollback_fn=lambda name, version: (_ for _ in ()).throw(AssertionError("must not be called")),
            environment_suffix="-gamma",
        )
        self.assertEqual(outcome.status, "no_probe")

    def test_env_variant_lookup_without_a_suffix_is_plain_no_probe(self):
        # No environment_suffix supplied (e.g. a v3-prod run) -> a name not
        # in PROBE_TABLE is a plain no_probe, never no_probe_env_variant.
        outcome = pds.run_function_smoke(
            "enceladus-mcp-code-gamma", "7",
            probe_fn=lambda target: (_ for _ in ()).throw(AssertionError("must not be called")),
            rollback_fn=lambda name, version: (_ for _ in ()).throw(AssertionError("must not be called")),
        )
        self.assertEqual(outcome.status, "no_probe")


class TestBaseFunctionName(unittest.TestCase):
    def test_strips_known_suffix(self):
        self.assertEqual(pds._base_function_name("enceladus-mcp-code-gamma", "-gamma"), "enceladus-mcp-code")

    def test_no_suffix_configured_returns_unchanged(self):
        self.assertEqual(pds._base_function_name("enceladus-mcp-code-gamma", ""), "enceladus-mcp-code-gamma")

    def test_name_not_ending_in_suffix_returns_unchanged(self):
        self.assertEqual(pds._base_function_name("enceladus-mcp-code", "-gamma"), "enceladus-mcp-code")

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
# get_live_alias_version / _run -- error discrimination + retry
# (ENC-TSK-Q05 review finding, critical)
# ---------------------------------------------------------------------------

class TestGetLiveAliasVersion(unittest.TestCase):
    def test_genuine_not_found_is_a_clean_bootstrap_case(self):
        with patch.object(
            pds, "_run",
            return_value=(None, "An error occurred (ResourceNotFoundException) when calling GetAlias"),
        ):
            version, err = pds.get_live_alias_version("enceladus-mcp-code", "us-west-2")
        self.assertIsNone(version)
        self.assertIsNone(err, "a genuine 'no alias yet' bootstrap case must not be reported as an error")

    def test_function_not_found_wording_is_also_a_clean_bootstrap_case(self):
        with patch.object(pds, "_run", return_value=(None, "Function not found: enceladus-mcp-code")):
            version, err = pds.get_live_alias_version("enceladus-mcp-code", "us-west-2")
        self.assertIsNone(version)
        self.assertIsNone(err)

    def test_transient_or_unexpected_error_is_NOT_collapsed_into_bootstrap(self):
        # This is the exact critical-finding scenario: a throttle/AccessDenied
        # /timeout must be reported as an ERROR, not silently treated the
        # same as "no alias yet".
        with patch.object(
            pds, "_run",
            return_value=(None, "An error occurred (ThrottlingException) when calling GetAlias"),
        ):
            version, err = pds.get_live_alias_version("enceladus-mcp-code", "us-west-2")
        self.assertIsNone(version)
        self.assertIsNotNone(err)
        self.assertIn("ThrottlingException", err)

    def test_found_returns_version_with_no_error(self):
        with patch.object(pds, "_run", return_value=(json.dumps({"FunctionVersion": "41"}), None)):
            version, err = pds.get_live_alias_version("enceladus-mcp-code", "us-west-2")
        self.assertEqual(version, "41")
        self.assertIsNone(err)

    def test_unparseable_output_is_an_error_not_a_silent_none(self):
        with patch.object(pds, "_run", return_value=("not json", None)):
            version, err = pds.get_live_alias_version("enceladus-mcp-code", "us-west-2")
        self.assertIsNone(version)
        self.assertIsNotNone(err, "unparseable get-alias output must not be treated as a clean bootstrap")


class TestRunRetry(unittest.TestCase):
    def _completed(self, returncode, stderr="", stdout="ok"):
        from types import SimpleNamespace
        return SimpleNamespace(returncode=returncode, stdout=stdout if returncode == 0 else "", stderr=stderr)

    def test_transient_error_is_retried_then_succeeds(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if len(calls) < 3:
                return self._completed(1, "An error occurred (ThrottlingException) when calling GetAlias")
            return self._completed(0)

        sleeps = []
        with patch.object(pds.subprocess, "run", side_effect=fake_run):
            out, err = pds._run(["aws", "lambda", "get-alias"], sleep_fn=sleeps.append)

        self.assertEqual(out, "ok")
        self.assertIsNone(err)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(sleeps), 2)

    def test_not_provisioned_error_is_not_retried(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return self._completed(1, "An error occurred (ResourceNotFoundException) when calling GetAlias")

        with patch.object(pds.subprocess, "run", side_effect=fake_run):
            out, err = pds._run(["aws", "lambda", "get-alias"], sleep_fn=lambda s: None)

        self.assertIsNone(out)
        self.assertIn("ResourceNotFoundException", err)
        self.assertEqual(len(calls), 1, "a genuine not-found is not transient and must not be retried")

    def test_non_transient_unexpected_error_is_not_retried(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return self._completed(1, "AccessDeniedException: not authorized")

        with patch.object(pds.subprocess, "run", side_effect=fake_run):
            out, err = pds._run(["aws", "lambda", "get-alias"], sleep_fn=lambda s: None)

        self.assertIsNone(out)
        self.assertIn("AccessDeniedException", err)
        self.assertEqual(len(calls), 1)


# ---------------------------------------------------------------------------
# run_capture -- (captured, errors) fail-closed contract
# (ENC-TSK-Q05 review finding, critical)
# ---------------------------------------------------------------------------

class TestRunCapture(unittest.TestCase):
    def test_all_clean_bootstrap_yields_empty_captured_and_no_errors(self):
        with patch.object(pds, "get_live_alias_version", return_value=(None, None)):
            captured, errors = pds.run_capture(
                {"mcp_code": "enceladus-mcp-code"}, {"mcp_code": "v1"}, "us-west-2",
            )
        self.assertEqual(captured, {})
        self.assertEqual(errors, {})

    def test_found_version_is_captured_with_no_errors(self):
        with patch.object(pds, "get_live_alias_version", return_value=("41", None)):
            captured, errors = pds.run_capture(
                {"mcp_code": "enceladus-mcp-code"}, {"mcp_code": "v1"}, "us-west-2",
            )
        self.assertEqual(captured, {"enceladus-mcp-code": "41"})
        self.assertEqual(errors, {})

    def test_unexpected_error_is_reported_and_not_captured(self):
        with patch.object(
            pds, "get_live_alias_version",
            return_value=(None, "An error occurred (ThrottlingException) when calling GetAlias"),
        ):
            captured, errors = pds.run_capture(
                {"mcp_code": "enceladus-mcp-code"}, {"mcp_code": "v1"}, "us-west-2",
            )
        self.assertEqual(captured, {})
        self.assertIn("enceladus-mcp-code", errors)


# ---------------------------------------------------------------------------
# CLI: capture / check
# ---------------------------------------------------------------------------

class TestCaptureCli(unittest.TestCase):
    def test_capture_prints_json_of_captured_versions(self):
        with patch.object(pds, "get_live_alias_version", return_value=("41", None)):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
                "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            ])
        self.assertEqual(rc, 0)

    def test_capture_no_existing_alias_is_not_an_error(self):
        with patch.object(pds, "get_live_alias_version", return_value=(None, None)):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
                "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            ])
        self.assertEqual(rc, 0)

    def test_capture_bad_json_exits_two(self):
        rc = pds.main(["capture", "--function-name-map-json", "not json", "--version-ids-json", "{}"])
        self.assertEqual(rc, 2)

    def test_capture_unexpected_aws_error_fails_closed_not_silent_bootstrap(self):
        # ENC-TSK-Q05 review finding (critical): a transient/unexpected AWS
        # error during capture must NOT be silently treated the same as a
        # genuine "no alias yet" bootstrap case -- it must fail the capture
        # step so the deploy never proceeds on an unverified alias state.
        with patch.object(
            pds, "get_live_alias_version",
            return_value=(None, "An error occurred (ThrottlingException) when calling GetAlias"),
        ):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code"}),
                "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            ])
        self.assertEqual(rc, 1, "an unexplained capture error must fail closed, not silently pass")

    def test_capture_mixed_success_and_error_still_fails_closed(self):
        def fake_get(name, region):
            if name == "enceladus-mcp-code":
                return "41", None
            return None, "AccessDeniedException: not authorized"

        with patch.object(pds, "get_live_alias_version", side_effect=fake_get):
            rc = pds.main([
                "capture",
                "--function-name-map-json", json.dumps({
                    "mcp_code": "enceladus-mcp-code", "other_fn": "other-fn",
                }),
                "--version-ids-json", json.dumps({"mcp_code": "v1", "other_fn": "v1"}),
            ])
        self.assertEqual(rc, 1, "one function's capture error must fail the whole step even if others succeeded")


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

    def test_gamma_env_variant_is_a_non_failing_but_distinct_outcome(self):
        # ENC-TSK-Q05 review finding (major): main's workflow_dispatch to
        # v4-gamma must not look identical to a fully-verified prod run.
        rc = pds.main([
            "check",
            "--function-name-map-json", json.dumps({"mcp_code": "enceladus-mcp-code-gamma"}),
            "--version-ids-json", json.dumps({"mcp_code": "v1"}),
            "--previous-alias-versions-json", json.dumps({"enceladus-mcp-code-gamma": "7"}),
            "--environment-suffix=-gamma",
        ])
        self.assertEqual(rc, 0, "no_probe_env_variant must not fail the run")

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

    def test_check_step_is_wired_with_environment_suffix(self):
        # ENC-TSK-Q05 review finding (major): without this, the check step
        # can never tell a gamma-named deployed function apart from a
        # function that legitimately has no probe entry at all.
        job_text = self._deploy_job_text()
        check_pos = job_text.find(".guard-tools/tools/post_deploy_smoke.py check")
        self.assertNotEqual(check_pos, -1)
        step_start = job_text.rfind("- name:", 0, check_pos)
        step_end = job_text.find("- name:", check_pos)
        step_text = job_text[step_start:step_end if step_end != -1 else len(job_text)]
        self.assertIn("ENVIRONMENT_SUFFIX", step_text)
        self.assertIn("--environment-suffix", step_text)


if __name__ == "__main__":
    unittest.main()
