#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-2 (ENC-ISS-778 P0): unit tests for
tools/assert_artifact_arch_matches_functions.py.

Covers the pure core (parse_key_prefix, evaluate_match, resolve_deploy_targets)
including the actual incident fixture -- an x86_64-py3.11 artifact prefix
against an arm64/python3.12 function must be reported as a mismatch -- plus
the CLI's fail-closed wiring via a mocked get_function_configuration(), and
(separately) the _deploy.yml workflow wiring itself: the guard step exists,
runs before "Deploy Lambda functions", is unconditional, has no
continue-on-error / `|| true`, and is invoked from the .guard-tools path.

Hermetic: no network or live AWS calls.

Run: python3 -m pytest tools/test_assert_artifact_arch_matches_functions.py -q
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parent / "assert_artifact_arch_matches_functions.py"
_spec = importlib.util.spec_from_file_location("assert_artifact_arch_matches_functions", MODULE_PATH)
aaf = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = aaf  # required for dataclasses' module lookup during exec_module
_spec.loader.exec_module(aaf)  # type: ignore[union-attr]

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_PATH = REPO_ROOT / ".github" / "workflows" / "_deploy.yml"


class TestParseKeyPrefix(unittest.TestCase):
    def test_simple_prefix(self):
        self.assertEqual(aaf.parse_key_prefix("lambda-artifacts/arm64-py3.12"), ("arm64", "3.12"))

    def test_x86_64_prefix(self):
        self.assertEqual(aaf.parse_key_prefix("lambda-artifacts/x86_64-py3.11"), ("x86_64", "3.11"))

    def test_trailing_slash_is_tolerated(self):
        self.assertEqual(aaf.parse_key_prefix("lambda-artifacts/arm64-py3.12/"), ("arm64", "3.12"))

    def test_bare_segment_with_no_path(self):
        self.assertEqual(aaf.parse_key_prefix("arm64-py3.12"), ("arm64", "3.12"))

    def test_unparseable_prefix_raises(self):
        with self.assertRaises(ValueError):
            aaf.parse_key_prefix("lambda-artifacts/not-a-valid-prefix")

    def test_missing_py_component_raises(self):
        with self.assertRaises(ValueError):
            aaf.parse_key_prefix("lambda-artifacts/arm64")


class TestEvaluateMatch(unittest.TestCase):
    def test_incident_fixture_x86_64_py311_artifact_vs_arm64_py312_function_is_mismatch(self):
        # ENC-ISS-778 P0: this exact combination is what shipped the 502.
        result = aaf.evaluate_match(
            "lambda-artifacts/x86_64-py3.11",
            architectures=["arm64"],
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("x86_64", result.reason)
        self.assertIn("arm64", result.reason)

    def test_matching_arch_and_runtime_passes(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=["arm64"],
            runtime="python3.12",
        )
        self.assertTrue(result.ok, result.reason)

    def test_case_insensitive_arch_match(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/ARM64-py3.12",
            architectures=["arm64"],
            runtime="python3.12",
        )
        self.assertTrue(result.ok, result.reason)

    def test_unparseable_prefix_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/garbage",
            architectures=["arm64"],
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("unparseable", result.reason)

    def test_missing_architectures_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=None,
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("Architectures", result.reason)

    def test_empty_architectures_list_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=[],
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("Architectures", result.reason)

    def test_multiple_architectures_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=["arm64", "x86_64"],
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("ambiguous", result.reason)

    def test_missing_runtime_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=["arm64"],
            runtime=None,
        )
        self.assertFalse(result.ok)
        self.assertIn("Runtime", result.reason)

    def test_non_python_runtime_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.12",
            architectures=["arm64"],
            runtime="nodejs20.x",
        )
        self.assertFalse(result.ok)
        self.assertIn("not a python runtime", result.reason)

    def test_python_version_mismatch_fails_closed(self):
        result = aaf.evaluate_match(
            "lambda-artifacts/arm64-py3.11",
            architectures=["arm64"],
            runtime="python3.12",
        )
        self.assertFalse(result.ok)
        self.assertIn("3.11", result.reason)
        self.assertIn("3.12", result.reason)


class TestResolveDeployTargets(unittest.TestCase):
    def test_only_functions_with_a_resolved_prefix_are_checked(self):
        targets = aaf.resolve_deploy_targets(
            function_name_map={"mcp_code": "enceladus-mcp-code", "other_fn": "other-fn"},
            key_prefixes={"mcp_code": "lambda-artifacts/arm64-py3.12"},
        )
        self.assertEqual(targets, [("mcp_code", "enceladus-mcp-code", "lambda-artifacts/arm64-py3.12")])

    def test_function_with_no_mapping_is_skipped(self):
        targets = aaf.resolve_deploy_targets(
            function_name_map={},
            key_prefixes={"mcp_code": "lambda-artifacts/arm64-py3.12"},
        )
        self.assertEqual(targets, [])

    def test_comma_list_expands_to_multiple_targets(self):
        targets = aaf.resolve_deploy_targets(
            function_name_map={"checkout_service": "enceladus-checkout-service,enceladus-checkout-service-auto"},
            key_prefixes={"checkout_service": "lambda-artifacts/arm64-py3.12"},
        )
        self.assertEqual(
            targets,
            [
                ("checkout_service", "enceladus-checkout-service", "lambda-artifacts/arm64-py3.12"),
                ("checkout_service", "enceladus-checkout-service-auto", "lambda-artifacts/arm64-py3.12"),
            ],
        )


class TestMainCli(unittest.TestCase):
    def _fn_map(self):
        return json.dumps({"mcp_code": "enceladus-mcp-code"})

    def _prefixes(self):
        return json.dumps({"mcp_code": "lambda-artifacts/arm64-py3.12"})

    def test_matching_function_exits_zero(self):
        with patch.object(
            aaf, "get_function_configuration",
            return_value=({"Architectures": ["arm64"], "Runtime": "python3.12"}, None),
        ):
            rc = aaf.main(["--function-name-map-json", self._fn_map(), "--key-prefixes-json", self._prefixes()])
        self.assertEqual(rc, 0)

    def test_incident_mismatch_exits_one(self):
        with patch.object(
            aaf, "get_function_configuration",
            return_value=({"Architectures": ["arm64"], "Runtime": "python3.12"}, None),
        ):
            rc = aaf.main([
                "--function-name-map-json", self._fn_map(),
                "--key-prefixes-json", json.dumps({"mcp_code": "lambda-artifacts/x86_64-py3.11"}),
            ])
        self.assertEqual(rc, 1)

    def test_not_provisioned_is_a_skip_not_a_failure(self):
        with patch.object(
            aaf, "get_function_configuration",
            return_value=(None, "An error occurred (ResourceNotFoundException) when calling ..."),
        ):
            rc = aaf.main(["--function-name-map-json", self._fn_map(), "--key-prefixes-json", self._prefixes()])
        self.assertEqual(rc, 0)

    def test_unreadable_configuration_for_other_reason_fails_closed(self):
        with patch.object(
            aaf, "get_function_configuration",
            return_value=(None, "AccessDeniedException: not authorized"),
        ):
            rc = aaf.main(["--function-name-map-json", self._fn_map(), "--key-prefixes-json", self._prefixes()])
        self.assertEqual(rc, 1)

    def test_no_targets_is_a_clean_noop(self):
        rc = aaf.main(["--function-name-map-json", "{}", "--key-prefixes-json", "{}"])
        self.assertEqual(rc, 0)

    def test_bad_json_input_exits_two(self):
        rc = aaf.main(["--function-name-map-json", "not json", "--key-prefixes-json", "{}"])
        self.assertEqual(rc, 2)


class TestDeployYmlWiring(unittest.TestCase):
    """Asserts the _deploy.yml wiring itself, independent of the script's
    own logic: the guard step must exist, run before "Deploy Lambda
    functions", be unconditional, never soft-fail, and be invoked from the
    .guard-tools sparse checkout (not the promoted tree's bare tools/ path)."""

    def setUp(self):
        self.text = DEPLOY_PATH.read_text()

    def test_deploy_yml_parses_as_yaml(self):
        import yaml
        with DEPLOY_PATH.open() as f:
            doc = yaml.safe_load(f)
        self.assertIsInstance(doc, dict)

    def _deploy_job_text(self) -> str:
        start = self.text.find("\n  deploy:\n")
        self.assertNotEqual(start, -1, "_deploy.yml is missing the deploy job")
        return self.text[start:]

    def test_guard_step_exists_and_is_invoked_from_guard_tools_path(self):
        job_text = self._deploy_job_text()
        invocation = re.search(
            r"python3\s+(\S+)/tools/assert_artifact_arch_matches_functions\.py",
            job_text,
        )
        self.assertIsNotNone(
            invocation,
            "_deploy.yml's deploy job is missing the "
            "assert_artifact_arch_matches_functions.py guard invocation",
        )
        self.assertEqual(
            invocation.group(1),
            ".guard-tools",
            "the guard must be invoked as .guard-tools/tools/"
            "assert_artifact_arch_matches_functions.py (workflow-branch "
            f"checkout), found prefix {invocation.group(1)!r} instead -- a bare "
            "tools/ path resolves against the PROMOTED tree, which does not "
            "carry this script",
        )

    def test_guard_step_runs_before_deploy_lambda_functions_step(self):
        job_text = self._deploy_job_text()
        guard_pos = job_text.find("assert_artifact_arch_matches_functions.py")
        deploy_step_pos = job_text.find("- name: Deploy Lambda functions")
        self.assertNotEqual(guard_pos, -1)
        self.assertNotEqual(deploy_step_pos, -1)
        self.assertLess(
            guard_pos, deploy_step_pos,
            "the architecture guard must run BEFORE 'Deploy Lambda functions', "
            "not after -- the whole point is to fail before any "
            "update-function-code call",
        )

    def test_guard_step_runs_after_aws_credentials_step(self):
        job_text = self._deploy_job_text()
        creds_pos = job_text.find("Configure AWS credentials (prod deploy role")
        guard_pos = job_text.find("assert_artifact_arch_matches_functions.py")
        self.assertNotEqual(creds_pos, -1)
        self.assertNotEqual(guard_pos, -1)
        self.assertLess(creds_pos, guard_pos)

    def test_guard_step_is_not_conditional_or_soft_failing(self):
        job_text = self._deploy_job_text()
        # Isolate the step block: from its "- name:" line to the next
        # top-level "- name:" line at the same indentation.
        step_match = re.search(
            r"( {6}- name:.*(?:arch|Arch).*guard.*\n(?: {8}.*\n)*)",
            job_text,
        )
        self.assertIsNotNone(step_match, "could not isolate the architecture guard step block")
        step_text = step_match.group(1)
        self.assertNotIn(
            "continue-on-error", step_text,
            "the architecture guard step must not use continue-on-error",
        )
        self.assertNotIn(
            "if:", step_text,
            "the architecture guard step must be unconditional (no 'if:')",
        )
        self.assertNotIn(
            "|| true", step_text,
            "the architecture guard invocation must not be able to swallow a "
            "nonzero exit via '|| true'",
        )

    def test_key_prefixes_output_is_wired_through_resolve_and_deploy(self):
        self.assertIn(
            "key_prefixes_json", self.text,
            "_deploy.yml must carry a key_prefixes_json resolve-job output "
            "for the architecture guard to consume",
        )
        # resolve job's outputs: block must declare it.
        outputs_match = re.search(r"outputs:\n((?: {6}\S.*\n)+)", self.text)
        self.assertIsNotNone(outputs_match, "could not find resolve job's outputs: block")
        self.assertIn("key_prefixes_json", outputs_match.group(1))
        # Existing outputs must be unchanged (spot-check a few names).
        for existing in (
            "commit_sha", "deploy_role_arn", "environment", "arch", "py_version",
            "canary_preference", "version_ids_json", "function_name_map_json",
            "environment_suffix", "codedeploy_app_name", "full_scope",
            "affected_functions_json",
        ):
            self.assertIn(existing, self.text)


if __name__ == "__main__":
    unittest.main()
