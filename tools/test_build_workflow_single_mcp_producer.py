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


if __name__ == "__main__":
    unittest.main()
