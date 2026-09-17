#!/usr/bin/env python3
"""ENC-TSK-Q04 (ENC-ISS-778) regression test: mcp_code must resolve and build
under the same arch/py S3 key prefix as every other Lambda function, not the
retired x86_64-py3.11 pin (ENC-ISS-494) that shipped an x86_64 artifact to
the arm64-only enceladus-mcp-code function and caused the mcp.jreese.net
prod 502 outage.

Parses .github/workflows/_deploy.yml and .github/workflows/_build.yml as YAML
(structural validity) and asserts (via string/regex checks on the raw text,
since the payloads of interest live inside embedded shell/python `run:`
blocks that YAML parses as opaque scalars) that:
  - _deploy.yml no longer contains the literal "x86_64-py3.11" pin.
  - _deploy.yml's probe/resolve shell has no mcp_code-specific prefix branch.
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

    def test_deploy_yml_resolve_step_has_no_mcp_code_prefix_branch(self):
        # The old bug: an `if [[ "$fn" == "mcp_code" ]]` branch in the probe
        # loop that swapped in a fixed MCP_CODE_KEY_PREFIX. Neither the shell
        # conditional nor the dedicated variable name may remain anywhere in
        # the file (resolve step or deploy step).
        self.assertNotRegex(
            self.deploy_text,
            r'\bfn\b.*==.*"mcp_code"',
            "_deploy.yml still special-cases mcp_code by function name in a "
            "conditional (expected: uniform KEY_PREFIX/prefix for all functions)",
        )
        self.assertNotIn(
            "MCP_CODE_KEY_PREFIX",
            self.deploy_text,
            "_deploy.yml still defines a dedicated MCP_CODE_KEY_PREFIX variable",
        )
        self.assertNotIn(
            "mcp_code_prefix",
            self.deploy_text,
            "_deploy.yml still defines a dedicated mcp_code_prefix variable in "
            "the deploy python step",
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
