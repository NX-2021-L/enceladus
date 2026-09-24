#!/usr/bin/env python3
"""ENC-TSK-Q04 (ENC-ISS-778) regression test: mcp_code must resolve and build
under the arm64-py3.12 S3 key prefix -- matching its actual live v3-prod
Lambda runtime -- not the retired x86_64-py3.11 pin (ENC-ISS-494) that shipped
an x86_64 artifact to the arm64-only enceladus-mcp-code function and caused
the mcp.jreese.net prod 502 outage.

mcp_code's per-function override is intentional and expected to remain: its
runtime genuinely diverges from the v3-prod environment-wide arch/py declared
in envs/v3-prod.yaml (x86_64-py3.11, predating the ARM64 cutover). The ENC-
ISS-778 defect was the hardcoded x86_64-py3.11 *value*, not the existence of
a per-function branch.

Parses .github/workflows/_deploy.yml and .github/workflows/_build.yml as YAML
(structural validity) and asserts (via string/regex checks on the raw text,
since the payloads of interest live inside embedded shell/python `run:`
blocks that YAML parses as opaque scalars) that:
  - _deploy.yml no longer contains the literal "x86_64-py3.11" pin anywhere.
  - _deploy.yml's resolve probe and deploy python step each still carry a
    mcp_code-specific override, and that override resolves to arm64-py3.12.
  - _build.yml's mcp_code artifact key uses the arm64-py3.12 prefix.

Hermetic: no network, AWS, git, or subprocess calls.

Run: python3 tools/test_deploy_workflow_mcp_code_key.py
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_PATH = REPO_ROOT / ".github" / "workflows" / "_deploy.yml"
BUILD_PATH = REPO_ROOT / ".github" / "workflows" / "_build.yml"


class TestDeployWorkflowMcpCodeKey(unittest.TestCase):
    def setUp(self):
        self.deploy_text = DEPLOY_PATH.read_text()
        self.build_text = BUILD_PATH.read_text()

    def test_both_workflow_files_parse_as_yaml(self):
        for path in (DEPLOY_PATH, BUILD_PATH):
            with path.open() as f:
                doc = yaml.safe_load(f)
            self.assertIsInstance(doc, dict, f"{path} did not parse to a mapping")

    def test_deploy_yml_has_no_x86_64_py311_pin(self):
        self.assertNotIn(
            "x86_64-py3.11",
            self.deploy_text,
            "_deploy.yml still contains the retired ENC-ISS-494 x86_64-py3.11 "
            "literal pin for mcp_code",
        )

    def test_deploy_yml_resolve_step_mcp_code_branch_uses_arm64_py312(self):
        # mcp_code's live v3-prod runtime (arm64/python3.12) genuinely diverges
        # from the environment-wide arch/py, so a per-function override is
        # expected to remain in both the probe step and the deploy python
        # step -- it must resolve to arm64-py3.12, not the retired
        # x86_64-py3.11 value.
        self.assertRegex(
            self.deploy_text,
            r'\bfn\b.*==.*"mcp_code"',
            "_deploy.yml's resolve probe is missing the expected mcp_code "
            "per-function override branch",
        )
        match = re.search(
            r'MCP_CODE_KEY_PREFIX="\$\{\{[^}]*ARTIFACT_KEY_PREFIX[^}]*\}\}/([^"]+)"',
            self.deploy_text,
        )
        self.assertIsNotNone(
            match,
            "_deploy.yml is missing a MCP_CODE_KEY_PREFIX assignment in the "
            "resolve probe step",
        )
        self.assertEqual(
            match.group(1),
            "arm64-py3.12",
            "_deploy.yml's MCP_CODE_KEY_PREFIX must resolve to arm64-py3.12, "
            "matching mcp_code's actual live v3-prod runtime (ENC-ISS-778)",
        )

        deploy_match = re.search(
            r'mcp_code_prefix\s*=\s*"lambda-artifacts/([^"]+)"',
            self.deploy_text,
        )
        self.assertIsNotNone(
            deploy_match,
            "_deploy.yml's deploy python step is missing a mcp_code_prefix "
            "assignment",
        )
        self.assertEqual(
            deploy_match.group(1),
            "arm64-py3.12",
            "_deploy.yml's mcp_code_prefix must resolve to arm64-py3.12, "
            "matching mcp_code's actual live v3-prod runtime (ENC-ISS-778)",
        )
        self.assertIn(
            "fn_prefix = mcp_code_prefix if fn == 'mcp_code' else prefix",
            self.deploy_text,
            "_deploy.yml's deploy python step must select mcp_code_prefix "
            "only for mcp_code and fall back to the uniform prefix for "
            "every other function",
        )

    def test_build_yml_mcp_code_key_uses_arm64_py312_prefix(self):
        match = re.search(
            r'KEY="\$\{PREFIX\}/([^/"]+)/mcp_code-\$\{SHA\}\.zip"',
            self.build_text,
        )
        self.assertIsNotNone(
            match,
            "_build.yml's build-mcp-code job is missing the expected "
            "mcp_code-<sha>.zip S3 key assignment",
        )
        self.assertEqual(
            match.group(1),
            "arm64-py3.12",
            "_build.yml's mcp_code artifact key must use the arm64-py3.12 "
            "prefix to match the arm64/python3.12 enceladus-mcp-code runtime "
            "(ENC-ISS-778)",
        )

    def test_build_yml_mcp_code_job_targets_arm64_py312(self):
        self.assertNotIn(
            "x86_64-py3.11",
            self.build_text.split("build-mcp-code:", 1)[1]
            if "build-mcp-code:" in self.build_text
            else self.build_text,
            "build-mcp-code job still references the retired x86_64-py3.11 combo",
        )
        self.assertIn("ubuntu-24.04-arm", self.build_text)
        self.assertIn("manylinux2014_aarch64", self.build_text)


if __name__ == "__main__":
    unittest.main()
