#!/usr/bin/env python3
"""ENC-TSK-Q09 (ENC-ISS-782 P0) regression tests.

ENC-ISS-778 (ENC-TSK-Q07) fixed the mcp_code two-producers race but left the
matrix `build` job in .github/workflows/_build.yml only ever special-casing
mcp_code: every OTHER function whose real handler is server.* (mcp_streamable,
mcp_streaming_gateway) or that v4/main packages the runtime for anyway
(coordination_api) fell through to the matrix job's generic per-function
build path -- source dir + pip deps only, no tools/enceladus-mcp-server/
copy. A v3-prod promote checks out a PROMOTED (v4/main) tree, which HAS
backend/lambda/mcp_streamable/ (a "from server import lambda_handler" build-
discovery shim) even though main's own tree does not -- so the matrix job's
`find backend/lambda -maxdepth 2 -name lambda_function.py` discovery step
picked it up and built it as an ordinary function. enceladus-mcp-streamable's
Function URL 502'd for three hours (02:18Z-05:35Z) because its zip had no
server.py.

The fix (AC-1/AC-2): a single shared list, tools/mcp_runtime_functions.txt,
read by BOTH the matrix job and the dedicated build-mcp-code job (via the
existing .guard-tools sparse checkout, extended to also fetch this file) --
so editing membership in one file keeps both build paths and the contents
guard in agreement, instead of the list being duplicated (and re-desync-able)
across jobs.

This test parses .github/workflows/_build.yml as YAML (structural validity)
and does string/regex checks on the raw text (embedded shell `run:` blocks
are opaque YAML scalars) to assert:
  (a) the shared list file exists and is read by both jobs via .guard-tools,
      never duplicated inline;
  (b) the matrix job's build loop packages the MCP runtime for a function
      gated on membership in that shared list (not a second hardcoded
      per-function condition);
  (c) the matrix job's build loop invokes the contents guard for functions
      in that list, with required entries derived from the SAME condition
      the copy step used (not a hardcoded --require list);
  (d) the matrix job has its own guard-tooling checkout, matching the
      build-mcp-code job's existing shape (ref: main, path: .guard-tools);
  (e) the build-mcp-code job cross-checks that mcp_code is still a member of
      the shared list.

Hermetic: no network, AWS, git, or subprocess calls.

Run: python3 -m pytest tools/test_build_workflow_mcp_runtime_packaging.py -q
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_PATH = REPO_ROOT / ".github" / "workflows" / "_build.yml"
RUNTIME_LIST_PATH = REPO_ROOT / "tools" / "mcp_runtime_functions.txt"


def _runtime_list_names(text: str) -> list:
    return [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


class TestSharedRuntimeFunctionsListFile(unittest.TestCase):
    def test_file_exists_and_is_not_empty(self):
        self.assertTrue(RUNTIME_LIST_PATH.is_file(), f"{RUNTIME_LIST_PATH} is missing")
        names = _runtime_list_names(RUNTIME_LIST_PATH.read_text())
        self.assertTrue(names, "tools/mcp_runtime_functions.txt has no function entries")

    def test_membership_matches_functions_with_a_server_star_handler_or_deliberate_parity_inclusion(self):
        names = set(_runtime_list_names(RUNTIME_LIST_PATH.read_text()))
        # mcp_code/mcp_streamable/mcp_streaming_gateway declare a server.*
        # handler (a build-discovery lambda_function.py shim that does
        # `from server import lambda_handler` / asgi_app.py's `from server
        # import app`); coordination_api is a deliberate parity inclusion
        # (see the file's own header comment and ENC-TSK-Q09's
        # design_decisions) even though its deployed Handler is
        # lambda_function.lambda_handler.
        self.assertEqual(
            names,
            {"mcp_code", "mcp_streamable", "mcp_streaming_gateway", "coordination_api"},
        )

    def test_no_duplicate_entries(self):
        names = _runtime_list_names(RUNTIME_LIST_PATH.read_text())
        self.assertEqual(len(names), len(set(names)), "duplicate function name(s) in the shared list")


class TestBuildWorkflowMcpRuntimePackaging(unittest.TestCase):
    def setUp(self):
        self.build_text = BUILD_PATH.read_text()

    def test_build_yml_parses_as_yaml(self):
        with BUILD_PATH.open() as f:
            doc = yaml.safe_load(f)
        self.assertIsInstance(doc, dict, f"{BUILD_PATH} did not parse to a mapping")

    def _matrix_build_loop_text(self) -> str:
        marker = "while IFS= read -r fn; do"
        start = self.build_text.find(marker)
        self.assertNotEqual(start, -1, "_build.yml is missing the matrix build job's per-function loop")
        end_marker = "done < /tmp/functions.txt"
        end = self.build_text.find(end_marker, start)
        self.assertNotEqual(end, -1, "_build.yml is missing the matrix build job's loop terminator")
        return self.build_text[start:end]

    def _matrix_build_upload_step_text(self) -> str:
        # The whole "Build + upload artifacts" step, including the
        # MCP_RUNTIME_FUNCTIONS setup that precedes the while loop.
        start = self.build_text.find("- name: Build + upload artifacts")
        self.assertNotEqual(start, -1, "_build.yml is missing the 'Build + upload artifacts' step")
        end = self.build_text.find("- name: Upload manifest as workflow artifact", start)
        self.assertNotEqual(end, -1, "_build.yml is missing the step after 'Build + upload artifacts'")
        return self.build_text[start:end]

    def _matrix_job_text(self) -> str:
        start = self.build_text.find("\n  build:\n")
        self.assertNotEqual(start, -1, "_build.yml is missing the matrix build job")
        end = self.build_text.find("\n  build-mcp-code:\n", start)
        self.assertNotEqual(end, -1, "_build.yml is missing the build-mcp-code job")
        return self.build_text[start:end]

    def _build_mcp_code_job_text(self) -> str:
        start = self.build_text.find("build-mcp-code:")
        self.assertNotEqual(start, -1, "_build.yml is missing the build-mcp-code job")
        return self.build_text[start:]

    # --- (d) matrix job has its own guard-tools checkout ---

    def test_matrix_job_has_a_guard_tools_checkout(self):
        job_text = self._matrix_job_text()
        step_match = re.search(
            r"- name:\s*Checkout guard tooling \(workflow branch\)\s*\n"
            r"\s*uses:\s*actions/checkout@v4\s*\n"
            r"\s*with:\s*\n"
            r"((?:\s{10,}\S.*\n?)+)",
            job_text,
        )
        self.assertIsNotNone(
            step_match,
            "_build.yml's matrix build job is missing the 'Checkout guard "
            "tooling (workflow branch)' step (ENC-TSK-Q09)",
        )
        with_block = step_match.group(1)
        self.assertRegex(with_block, r"ref:\s*main\b")
        self.assertNotIn("inputs.commit_sha", with_block)
        path_match = re.search(r"path:\s*(\S+)", with_block)
        self.assertIsNotNone(path_match)
        self.assertEqual(path_match.group(1), ".guard-tools")

        # Must run after the primary (promoted-tree) checkout.
        primary_pos = job_text.find("Checkout repo at requested SHA")
        guard_pos = job_text.find("Checkout guard tooling")
        self.assertNotEqual(primary_pos, -1)
        self.assertNotEqual(guard_pos, -1)
        self.assertLess(primary_pos, guard_pos)

    def test_matrix_job_guard_tools_checkout_fetches_both_files(self):
        job_text = self._matrix_job_text()
        step_start = job_text.find("Checkout guard tooling")
        self.assertNotEqual(step_start, -1)
        step_end = job_text.find("- name:", step_start + 1)
        step_text = job_text[step_start:step_end if step_end != -1 else len(job_text)]
        self.assertIn("tools/assert_lambda_artifact_contents.py", step_text)
        self.assertIn("tools/mcp_runtime_functions.txt", step_text)

    # --- (a)/(b) the shared list is read, not duplicated ---

    def test_matrix_build_loop_reads_the_shared_list_file(self):
        step_text = self._matrix_build_upload_step_text()
        self.assertIn(
            ".guard-tools/tools/mcp_runtime_functions.txt", step_text,
            "matrix job's build loop must read the shared list from the "
            "workflow-branch checkout, not a bare tools/ path (the "
            "promoted tree does not carry it)",
        )
        # Comment lines and blanks must be filtered when reading the list.
        self.assertIn("grep -v", step_text)

    def test_matrix_build_loop_has_a_needs_mcp_runtime_gate(self):
        loop_text = self._matrix_build_loop_text()
        self.assertIn(
            "needs_mcp_runtime", loop_text,
            "matrix build loop must gate MCP-runtime packaging on shared-"
            "list membership via a needs_mcp_runtime() check, not an inline "
            "per-function condition duplicating build-mcp-code's own list",
        )
        # It must not reintroduce a second hardcoded name list (the kind of
        # duplication AC-1 explicitly forbids) for any function OTHER than
        # the mcp_code skip (which is a deliberate, single, cited exception
        # -- see test_build_workflow_single_mcp_producer.py).
        other_names = ("coordination_api", "mcp_streamable", "mcp_streaming_gateway")
        for name in other_names:
            self.assertNotIn(
                f'"$fn" = "{name}"', loop_text,
                f"matrix build loop must not hardcode a hand-written "
                f'"$fn" = "{name}" condition -- membership must come from '
                f"the shared list file only",
            )

    def test_matrix_build_loop_still_skips_only_mcp_code_by_name(self):
        # The ONE legitimate hardcoded per-function name in the loop is the
        # mcp_code skip (build-mcp-code produces it instead) -- everything
        # else must be list-driven.
        loop_text = self._matrix_build_loop_text()
        quoted_names = re.findall(r'"\$fn"\s*=\s*"([a-zA-Z_][a-zA-Z0-9_]*)"', loop_text)
        case_names = re.findall(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\)\s*[^\n]*continue\s*;;', loop_text, re.MULTILINE)
        self.assertEqual(quoted_names, [])
        self.assertEqual(case_names, ["mcp_code"])

    # --- (c) the contents guard runs for every function in the list ---

    def test_matrix_build_loop_invokes_the_guard_gated_on_needs_mcp_runtime(self):
        loop_text = self._matrix_build_loop_text()
        guard_match = re.search(
            r"needs_mcp_runtime\s+\"\$fn\"\s*;\s*then\s*\n"
            r"(?:.*\n)*?"
            r"\s*python3\s+\.guard-tools/tools/assert_lambda_artifact_contents\.py",
            loop_text,
        )
        self.assertIsNotNone(
            guard_match,
            "matrix build loop must invoke the contents guard inside an "
            '`if needs_mcp_runtime "$fn"; then ... fi` block, not '
            "unconditionally or for mcp_code alone",
        )

    def test_matrix_guard_required_entries_are_derived_not_hardcoded(self):
        step_text = self._matrix_build_upload_step_text()
        # A hardcoded `--require server.py mcp_server/__init__.py` (always
        # both, regardless of whether the copy step actually copied
        # mcp_server/) would keep printing OK if the copy step regressed --
        # the exact failure mode a reviewer already caught on ENC-TSK-Q07.
        # The required-entries list must instead be built from a variable
        # that mirrors the copy step's own `[ -d tools/enceladus-mcp-server/
        # mcp_server ]` condition.
        self.assertIn("mcp_server_pkg_present", step_text)
        self.assertRegex(
            step_text,
            r'REQUIRE_ARGS=\(server\.py\)',
        )
        self.assertRegex(
            step_text,
            r'if\s*\[\s*"\$mcp_server_pkg_present"\s*=\s*"1"\s*\]',
        )
        # And that flag must itself be set from the same directory-existence
        # check the copy step already uses.
        occurrences = [
            m.start() for m in re.finditer(
                r"if \[ -d tools/enceladus-mcp-server/mcp_server \]; then", step_text
            )
        ]
        self.assertGreaterEqual(
            len(occurrences), 1,
            "expected the copy step's mcp_server/ existence check to be "
            "present (and to be what sets mcp_server_pkg_present=1)",
        )

    def test_guard_invocation_not_soft_failing_in_matrix_job(self):
        job_text = self._matrix_job_text()
        self.assertNotIn("continue-on-error", job_text)
        guard_pos = job_text.find("assert_lambda_artifact_contents.py")
        self.assertNotEqual(guard_pos, -1)
        guard_line_start = job_text.rfind("\n", 0, guard_pos)
        guard_line = job_text[guard_line_start:job_text.find("\n", guard_pos)]
        self.assertNotIn("|| true", guard_line)

    # --- (e) build-mcp-code job cross-checks the shared list ---

    def test_build_mcp_code_job_asserts_mcp_code_membership(self):
        job_text = self._build_mcp_code_job_text()
        self.assertIn("mcp_runtime_functions.txt", job_text)
        self.assertRegex(
            job_text,
            r'grep -qx "mcp_code" \.guard-tools/tools/mcp_runtime_functions\.txt',
            "build-mcp-code job must assert mcp_code is still a member of "
            "the shared list, so an edit that drops it there is caught at "
            "build time instead of the two jobs silently disagreeing again",
        )

    def test_build_mcp_code_job_still_not_soft_failing(self):
        # Regression guard: the new sanity check must not introduce
        # continue-on-error or a swallowed exit code.
        job_text = self._build_mcp_code_job_text()
        self.assertNotIn("continue-on-error", job_text)


if __name__ == "__main__":
    unittest.main()
