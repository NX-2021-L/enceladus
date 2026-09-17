#!/usr/bin/env python3
"""ENC-TSK-Q07 (ENC-ISS-778 P0 true root cause) regression test.

main's .github/workflows/_build.yml had TWO jobs that could both produce an
mcp_code artifact at the SAME S3 key
(<artifact_key_prefix>/<arch>-py<py>/mcp_code-<sha>.zip):

  1. The matrix `build` job, which discovers functions via
     `find backend/lambda -maxdepth 2 -name lambda_function.py` and builds
     each one as an ordinary function (source dir + pip deps only). Once a
     promoted tree has a backend/lambda/mcp_code/lambda_function.py shim,
     this job discovers and builds mcp_code too -- but WITHOUT
     tools/enceladus-mcp-server/server.py or mcp_server/, producing a zip
     that is missing server.lambda_handler and cannot serve.
  2. The standalone `build-mcp-code` job, which packages the real artifact
     from tools/enceladus-mcp-server/.

Before ENC-TSK-Q04, build-mcp-code wrote to x86_64-py3.11 so the two never
collided. Q04 correctly moved it to arm64-py3.12 -- exactly the matrix job's
row for that arch/py combination -- so the two jobs now race for the same S3
key, and whichever finishes last silently wins. This is what shipped an
unservable zip as prod version 40 (the Sev1 this task follows up on).

The fix: the matrix `build` job's per-function build loop explicitly skips
mcp_code, so build-mcp-code is the artifact's sole producer regardless of
whether backend/lambda/mcp_code/ ever grows a lambda_function.py.

This test parses .github/workflows/_build.yml as YAML (structural validity)
and then does string/regex checks on the raw text (the payloads of interest
live inside embedded shell `run:` blocks that YAML parses as opaque scalars)
to assert:
  (a) the matrix build job's build loop contains an explicit mcp_code skip
      that `continue`s before the srcdir build steps run, and
  (b) exactly one job (build-mcp-code) writes an mcp_code artifact S3 key.

Hermetic: no network, AWS, git, or subprocess calls.

Run: python3 -m pytest tools/test_build_workflow_single_mcp_producer.py -q
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_PATH = REPO_ROOT / ".github" / "workflows" / "_build.yml"


class TestBuildWorkflowSingleMcpProducer(unittest.TestCase):
    def setUp(self):
        self.build_text = BUILD_PATH.read_text()

    def test_build_yml_parses_as_yaml(self):
        with BUILD_PATH.open() as f:
            doc = yaml.safe_load(f)
        self.assertIsInstance(doc, dict, f"{BUILD_PATH} did not parse to a mapping")

    def _matrix_build_loop_text(self) -> str:
        # Isolate the matrix `build` job's per-function build loop from the
        # rest of the file, so assertions below can't accidentally match
        # something inside the separate build-mcp-code job.
        marker = "while IFS= read -r fn; do"
        start = self.build_text.find(marker)
        self.assertNotEqual(
            start, -1, "_build.yml is missing the matrix build job's per-function loop"
        )
        end_marker = "done < /tmp/functions.txt"
        end = self.build_text.find(end_marker, start)
        self.assertNotEqual(
            end, -1, "_build.yml is missing the matrix build job's loop terminator"
        )
        return self.build_text[start:end]

    def test_matrix_build_loop_explicitly_skips_mcp_code(self):
        loop_text = self._matrix_build_loop_text()

        # An explicit case/esac (or equivalent if-based) skip naming mcp_code,
        # matching the loop's existing skip style (`continue` on a match).
        match = re.search(
            r'case\s+"\$fn"\s+in\s*\n?\s*mcp_code\)\s*[^\n]*continue\s*;;',
            loop_text,
        )
        self.assertIsNotNone(
            match,
            "_build.yml's matrix build loop is missing an explicit "
            "`case \"$fn\" in mcp_code) ... continue ;; esac` skip "
            "(ENC-TSK-Q07 / ENC-ISS-778)",
        )

        # The skip must cite ENC-ISS-778 so the intent (single producer,
        # not a stale absence-of-lambda_function.py assumption) survives.
        self.assertIn(
            "ENC-ISS-778",
            loop_text,
            "_build.yml's matrix build loop mcp_code skip is missing an "
            "ENC-ISS-778 citation explaining why mcp_code is excluded",
        )

        # The skip must appear before the srcdir/build steps (i.e. before the
        # loop does any real work for $fn), not after -- otherwise it would
        # not actually prevent the matrix job from building mcp_code.
        skip_pos = match.start()
        srcdir_pos = loop_text.find('srcdir="backend/lambda/$fn"')
        self.assertNotEqual(srcdir_pos, -1, "matrix build loop is missing its srcdir assignment")
        self.assertLess(
            skip_pos,
            srcdir_pos,
            "the mcp_code skip must run before the loop builds backend/lambda/mcp_code",
        )

    def test_exactly_one_job_writes_an_mcp_code_artifact_key(self):
        # Every job that assembles an S3 key ending in `mcp_code-<sha>.zip`
        # (matrix job's per-function `${fn}-${sha}.zip` key when $fn ==
        # mcp_code would match this pattern too, which is exactly the
        # collision this test guards against) counts as an mcp_code
        # producer. There must be exactly one such key-construction site.
        key_patterns = [
            # matrix `build` job: key="...${fn}-${sha}.zip" -- only a
            # producer for mcp_code if the loop ever reaches fn=mcp_code,
            # which the skip above prevents. Counted as a *potential*
            # producer site so this test fails loudly if that skip pattern
            # (matched above) is ever removed while this key line remains.
            r'key="\$\{\{ inputs\.artifact_key_prefix \}\}/\$\{\{ matrix\.arch \}\}-py\$\{\{ matrix\.py_version \}\}/\$\{fn\}-\$\{sha\}\.zip"',
            # build-mcp-code job: KEY=".../mcp_code-${SHA}.zip"
            r'KEY="\$\{PREFIX\}/[^/"]+/mcp_code-\$\{SHA\}\.zip"',
        ]
        sites = [p for p in key_patterns if re.search(p, self.build_text)]
        # The matrix job's generic per-fn key template always exists (it's
        # used for every function); what must NOT exist is a live path that
        # reaches it for fn=mcp_code. We already proved the skip exists and
        # runs before any build work above, so here we assert the narrower,
        # decisive fact: exactly one job template is *specific* to the
        # mcp_code name.
        specific_mcp_code_key_sites = re.findall(
            r'KEY="[^\n"]*mcp_code-\$\{(?:SHA|sha)\}\.zip"', self.build_text
        )
        self.assertEqual(
            len(specific_mcp_code_key_sites),
            1,
            "_build.yml must have exactly one S3 KEY= assignment that writes "
            "a literal mcp_code-<sha>.zip key; found "
            f"{len(specific_mcp_code_key_sites)} (ENC-TSK-Q07 / ENC-ISS-778 "
            "single-producer invariant)",
        )
        # And that one site must live inside the build-mcp-code job.
        job_start = self.build_text.find("build-mcp-code:")
        self.assertNotEqual(job_start, -1, "_build.yml is missing the build-mcp-code job")
        key_pos = self.build_text.find('KEY="${PREFIX}/arm64-py3.12/mcp_code-${SHA}.zip"')
        self.assertNotEqual(
            key_pos,
            -1,
            "_build.yml is missing the expected build-mcp-code S3 KEY= assignment",
        )
        self.assertGreater(
            key_pos,
            job_start,
            "the mcp_code-<sha>.zip artifact key must be written inside the "
            "build-mcp-code job, not the matrix build job",
        )

    def _build_mcp_code_job_text(self) -> str:
        # Isolate the build-mcp-code job from the rest of the file (mirrors
        # the matrix-loop isolation helper above) so the guard-path
        # assertions below can't accidentally match something in the matrix
        # `build` job.
        start = self.build_text.find("build-mcp-code:")
        self.assertNotEqual(start, -1, "_build.yml is missing the build-mcp-code job")
        return self.build_text[start:]

    def test_guard_is_invoked_via_guard_tools_path_not_bare_tools_path(self):
        # ENC-TSK-Q07 follow-up 2 (ENC-ISS-778 P0, run 35178646448): a real
        # v3-prod promote checks out a PROMOTED (v4/main) tree in this job's
        # primary checkout, which does not contain
        # tools/assert_lambda_artifact_contents.py (that script exists only
        # on main). The guard MUST be invoked from the separate workflow-
        # branch checkout path (.guard-tools/tools/...), never from the bare
        # "tools/" path inside the primary checkout, or every promote fails
        # with "No such file or directory" and deploys nothing.
        job_text = self._build_mcp_code_job_text()

        guard_invocation = re.search(
            r"python3\s+(\S+)/tools/assert_lambda_artifact_contents\.py",
            job_text,
        )
        self.assertIsNotNone(
            guard_invocation,
            "_build.yml's build-mcp-code job is missing the "
            "assert_lambda_artifact_contents.py guard invocation",
        )
        self.assertEqual(
            guard_invocation.group(1),
            ".guard-tools",
            "the guard must be invoked as .guard-tools/tools/"
            "assert_lambda_artifact_contents.py (workflow-branch checkout), "
            f"found prefix {guard_invocation.group(1)!r} instead -- a bare "
            "tools/ path resolves against the PROMOTED tree and is absent "
            "there (ENC-TSK-Q07 follow-up 2)",
        )

        # Guard against a stale bare-path invocation existing anywhere in the
        # job on a non-comment line (excluding shell `#` comments and this
        # file's own explanatory prose, which legitimately quotes the bare
        # path when describing the failure mode).
        bare_invocation_lines = [
            line
            for line in job_text.splitlines()
            if "python3 tools/assert_lambda_artifact_contents.py" in line
            and not line.strip().startswith("#")
        ]
        self.assertEqual(
            bare_invocation_lines,
            [],
            "_build.yml's build-mcp-code job must not invoke the guard via "
            "the bare tools/ path on a live (non-comment) line -- that path "
            f"does not exist in a promoted (v4/main) checkout; found: {bare_invocation_lines!r}",
        )

    def test_guard_step_is_not_conditional_or_soft_failing(self):
        # The guard must run unconditionally on every promote. Making it
        # conditional on the script's existence (or otherwise letting the
        # step fail softly) would disable it exactly when it matters -- every
        # promote checks out a v4/main tree lacking the script by design.
        job_text = self._build_mcp_code_job_text()

        guard_pos = job_text.find("assert_lambda_artifact_contents.py")
        self.assertNotEqual(
            guard_pos, -1, "build-mcp-code job is missing the guard invocation"
        )

        # No existence check (e.g. `[ -f ... ] &&` / `if [ -f ... ]; then`)
        # gating the guard invocation line itself.
        guard_line_start = job_text.rfind("\n", 0, guard_pos)
        guard_line = job_text[guard_line_start:job_text.find("\n", guard_pos)]
        self.assertNotIn(
            "[ -f",
            guard_line,
            "the guard invocation must not be gated behind a file-existence "
            "check (that would disable it exactly when the promoted tree "
            "lacks the script, which is always)",
        )

        # No continue-on-error anywhere in the build-mcp-code job (the guard
        # step, and the job as a whole, must be allowed to fail the build).
        self.assertNotIn(
            "continue-on-error",
            job_text,
            "the build-mcp-code job (including its guard step) must not use "
            "continue-on-error -- the guard's whole purpose is to fail the "
            "build when the artifact is bad",
        )

        # The guard invocation must not be wrapped in a shell conditional
        # that would let a nonzero exit pass silently (e.g. `... || true`,
        # `if python3 ...; then`).
        self.assertNotIn("|| true", guard_line)
        self.assertNotRegex(
            guard_line,
            r"^\s*if\s+python3",
            "the guard invocation must not be wrapped in an `if` that could "
            "swallow a nonzero exit code",
        )

    def test_guard_tooling_checkout_pins_main_with_a_path(self):
        # The second checkout step must fetch the workflow's own branch
        # (main) — never the promoted commit_sha — into a distinct `path:`
        # subdirectory, so it can't clobber the primary (promoted-tree)
        # checkout the rest of the job depends on.
        job_text = self._build_mcp_code_job_text()

        step_match = re.search(
            r"- name:\s*Checkout guard tooling \(workflow branch\)\s*\n"
            r"\s*uses:\s*actions/checkout@v4\s*\n"
            r"\s*with:\s*\n"
            r"((?:\s{10,}\S.*\n?)+)",
            job_text,
        )
        self.assertIsNotNone(
            step_match,
            "_build.yml is missing the 'Checkout guard tooling (workflow "
            "branch)' step in the build-mcp-code job",
        )
        step_with_block = step_match.group(1)

        self.assertRegex(
            step_with_block,
            r"ref:\s*main\b",
            "the guard tooling checkout must pin ref: main (the workflow's "
            "own branch), not inputs.commit_sha (the promoted tree)",
        )
        self.assertNotIn(
            "inputs.commit_sha",
            step_with_block,
            "the guard tooling checkout must NOT use inputs.commit_sha -- "
            "that is exactly the promoted tree missing the guard script",
        )
        path_match = re.search(r"path:\s*(\S+)", step_with_block)
        self.assertIsNotNone(
            path_match,
            "the guard tooling checkout must specify a path: subdirectory "
            "so it cannot clobber the primary checkout's working tree",
        )
        self.assertEqual(
            path_match.group(1),
            ".guard-tools",
            "the guard tooling checkout's path: must be .guard-tools to "
            "match the guard invocation's .guard-tools/tools/... prefix",
        )

        # The second checkout step must come AFTER the primary (promoted-
        # tree) checkout in this job, not before.
        primary_checkout_pos = job_text.find("Checkout repo at requested SHA")
        second_checkout_pos = job_text.find("Checkout guard tooling")
        self.assertNotEqual(primary_checkout_pos, -1)
        self.assertNotEqual(second_checkout_pos, -1)
        self.assertLess(
            primary_checkout_pos,
            second_checkout_pos,
            "the guard tooling checkout must run after the primary "
            "promoted-tree checkout",
        )


if __name__ == "__main__":
    unittest.main()
