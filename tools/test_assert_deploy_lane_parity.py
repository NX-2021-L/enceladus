#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-4 (ENC-ISS-778 P0) tests for the deploy-lane parity guard.

ENC-ISS-778's first defect survived for months because main's and v4/main's
_deploy.yml / _build.yml had drifted and nothing compared them. A raw diff
is useless as a gate (the two lanes legitimately differ in trigger, checkout
shape, and job topology -- it would be red forever). tools/assert_deploy_lane_parity.py
instead compares named invariants. These tests use synthetic, minimal-but-
faithful fixture texts (modeled on the real .github/workflows/_deploy.yml and
_build.yml shapes) rather than the live files, so they exercise the parity
logic itself, independent of whatever the two lanes' real files say on any
given day (the real-file wiring is exercised separately, at the bottom of
this file, as a light structural smoke test).

Covers:
  - full parity (no divergences)
  - the real incident shape: a stale arch/py pin on one lane
    (mcp_code_prefix -> x86_64-py3.11)
  - the two-producers defect: a dedicated build job's pin collides with an
    un-skipped generic matrix row
  - mcp_code packaging-inputs drift: the mcp_server/ package reference
    silently dropped from one lane's packaging logic
  - the new workflow file parses and is present in tools/prod_gate_baseline.json

Hermetic: no network, AWS, or live git-ref calls (compute_divergences() is
pure; the one git_show()-touching test below only reads this repo's own
checked-out HEAD, no remote fetch).

Run: python3 -m pytest tools/test_assert_deploy_lane_parity.py -q
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml

from unittest.mock import patch

import assert_deploy_lane_parity as alp
from assert_deploy_lane_parity import (
    Divergence,
    compute_divergences,
    extract_dedicated_job_pins,
    extract_inline_runtime_condition_names,
    extract_matrix_arch_py_pairs,
    extract_matrix_skip_list,
    extract_mcp_code_packaging,
    extract_resolve_mcp_code_override,
    main,
    normalize_prefix_expr,
    normalize_override_value,
    resolve_mcp_runtime_function_names,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-lane-parity-guard.yml"
BASELINE_PATH = REPO_ROOT / "tools" / "prod_gate_baseline.json"


# ---------------------------------------------------------------------------
# Synthetic fixtures -- minimal but structurally faithful to the real files.
# `main` carries a dedicated build-mcp-code job + a matrix skip + per-function
# deploy overrides (main's actual current shape). `other` (standing in for
# v4/main) builds mcp_code inline in the generic matrix with no skip and no
# per-function override (v4/main's actual current shape) -- this pairing is
# itself the "in parity" baseline: two structurally different but
# behaviorally consistent lanes.
# ---------------------------------------------------------------------------

DEPLOY_MAIN = '''\
name: Deploy
on:
  workflow_call: {}
env:
  AWS_REGION: us-west-2
  ARTIFACT_BUCKET: jreese-net
  ARTIFACT_KEY_PREFIX: lambda-artifacts
jobs:
  resolve:
    steps:
      - name: Probe S3 for artifacts and collect VersionIds
        run: |
          KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/${ARCH}-py${PY}"
          MCP_CODE_KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12"
  deploy:
    steps:
      - name: Deploy Lambda functions
        run: |
          python3 -u - <<'PY'
          prefix = f"lambda-artifacts/{arch}-py{py}"
          mcp_code_prefix = "lambda-artifacts/arm64-py3.12"
          fn_prefix = mcp_code_prefix if fn == 'mcp_code' else prefix
          PY
'''

DEPLOY_OTHER = '''\
name: Deploy
on:
  workflow_call: {}
env:
  AWS_REGION: us-west-2
  ARTIFACT_BUCKET: jreese-net
  ARTIFACT_KEY_PREFIX: lambda-artifacts
jobs:
  resolve:
    steps:
      - name: Probe S3 for artifacts and collect VersionIds
        run: |
          KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/${ARCH}-py${PY}"
  deploy:
    steps:
      - name: Deploy Lambda functions
        run: |
          python3 -u - <<'PY'
          prefix = f"lambda-artifacts/{arch}-py{py}"
          PY
'''

BUILD_MAIN = '''\
name: Build
on:
  workflow_call:
    inputs:
      artifact_bucket:
        type: string
        default: "jreese-net"
      artifact_key_prefix:
        type: string
        default: "lambda-artifacts"
jobs:
  build:
    strategy:
      matrix:
        include:
          - arch: x86_64
            py_version: "3.11"
          - arch: arm64
            py_version: "3.12"
    steps:
      - name: Enumerate Lambdas to build
        run: |
          mapfile -t fns < <(find backend/lambda -maxdepth 2 -name lambda_function.py \\
            | sed -E 's|backend/lambda/([^/]+)/lambda_function.py|\\1|' | sort -u)
      - name: Build + upload artifacts
        run: |
          while IFS= read -r fn; do
            case "$fn" in
              mcp_code) echo "[skip] mcp_code - built by build-mcp-code (ENC-ISS-778)"; continue ;;
            esac
            srcdir="backend/lambda/$fn"
            key="${{ inputs.artifact_key_prefix }}/${{ matrix.arch }}-py${{ matrix.py_version }}/${fn}-${sha}.zip"
          done < /tmp/functions.txt
  build-mcp-code:
    steps:
      - name: Package enceladus-mcp-code
        run: |
          for py in tools/enceladus-mcp-server/*.py; do
            base=$(basename "$py")
            case "$base" in
              test_*) continue ;;
            esac
            cp "$py" "$BUILD/$base"
          done
          if [ -d tools/enceladus-mcp-server/mcp_server ]; then
            rsync -a --exclude='__pycache__' --exclude='*.pyc' \\
              tools/enceladus-mcp-server/mcp_server/ "$BUILD/mcp_server/"
          fi
          KEY="${PREFIX}/arm64-py3.12/mcp_code-${SHA}.zip"
'''

BUILD_OTHER = '''\
name: Build
on:
  workflow_call:
    inputs:
      artifact_bucket:
        type: string
        default: "jreese-net"
      artifact_key_prefix:
        type: string
        default: "lambda-artifacts"
jobs:
  build:
    strategy:
      matrix:
        include:
          - arch: x86_64
            py_version: "3.11"
          - arch: arm64
            py_version: "3.12"
    steps:
      - name: Enumerate Lambdas to build
        run: |
          mapfile -t fns < <(find backend/lambda -maxdepth 2 -name lambda_function.py \\
            | sed -E 's|backend/lambda/([^/]+)/lambda_function.py|\\1|' | sort -u)
      - name: Build + upload artifacts
        run: |
          while IFS= read -r fn; do
            srcdir="backend/lambda/$fn"
            if [ "$fn" = "mcp_code" ]; then
              for py in tools/enceladus-mcp-server/*.py; do
                base=$(basename "$py")
                case "$base" in
                  test_*) continue ;;
                esac
                cp "$py" "$workdir/$base"
              done
              rsync -a --exclude='__pycache__' --exclude='*.pyc' \\
                tools/enceladus-mcp-server/mcp_server/ "$workdir/mcp_server/"
            fi
            key="${{ inputs.artifact_key_prefix }}/${{ matrix.arch }}-py${{ matrix.py_version }}/${fn}-${sha}.zip"
          done < /tmp/functions.txt
'''


class TestFullParity(unittest.TestCase):
    """main (dedicated build-mcp-code job + skip + overrides) and other
    (mcp_code built inline in the generic matrix, no overrides) are
    STRUCTURALLY different but behaviorally consistent -- this must report
    zero divergences. This is the baseline every other test perturbs."""

    def test_no_divergences(self):
        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, BUILD_OTHER)
        self.assertEqual(
            divs, [],
            f"expected full parity but got: {[d.invariant for d in divs]}",
        )


class TestArchPrefixDivergence(unittest.TestCase):
    """The real ENC-ISS-778 incident shape: mcp_code's deploy-side override
    reverts to the retired x86_64-py3.11 pin while the build-side pin (and
    the resolve-side override) stay at arm64-py3.12."""

    def test_stale_deploy_side_pin_is_caught(self):
        bad_deploy = DEPLOY_MAIN.replace(
            'mcp_code_prefix = "lambda-artifacts/arm64-py3.12"',
            'mcp_code_prefix = "lambda-artifacts/x86_64-py3.11"',
        )
        self.assertNotEqual(bad_deploy, DEPLOY_MAIN, "fixture mutation did not apply")

        divs = compute_divergences(bad_deploy, DEPLOY_OTHER, BUILD_MAIN, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn(
            "mcp_code_override_resolve_vs_deploy_consistency", invariants,
            "resolve-vs-deploy self-consistency check did not fire on the "
            "stale x86_64-py3.11 deploy-side pin",
        )
        self.assertIn(
            "mcp_code_build_pin_vs_deploy_override_consistency", invariants,
            "build-pin-vs-deploy-override check did not fire on the stale "
            "x86_64-py3.11 deploy-side pin",
        )
        # This must be caught WITHOUT needing the other lane at all -- it is
        # a within-lane inconsistency, the same shape ENC-ISS-778 actually was.
        divs_no_other_lane_signal = compute_divergences(bad_deploy, bad_deploy, BUILD_MAIN, BUILD_MAIN)
        self.assertTrue(
            any(d.invariant == "mcp_code_build_pin_vs_deploy_override_consistency"
                for d in divs_no_other_lane_signal),
            "the stale pin must be caught even when both lanes carry the "
            "same (self-inconsistent) text",
        )

    def test_stale_resolve_side_pin_is_caught(self):
        bad_deploy = DEPLOY_MAIN.replace(
            'MCP_CODE_KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12"',
            'MCP_CODE_KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/x86_64-py3.11"',
        )
        self.assertNotEqual(bad_deploy, DEPLOY_MAIN, "fixture mutation did not apply")
        divs = compute_divergences(bad_deploy, DEPLOY_OTHER, BUILD_MAIN, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn("mcp_code_override_resolve_vs_deploy_consistency", invariants)

    def test_generic_prefix_hardcoded_on_one_lane_is_caught(self):
        # A lane that stops deriving KEY_PREFIX from ARCH/PY and hardcodes it
        # instead -- this would affect every function, not just mcp_code.
        bad_deploy = DEPLOY_MAIN.replace(
            'KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/${ARCH}-py${PY}"',
            'KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12"',
        )
        self.assertNotEqual(bad_deploy, DEPLOY_MAIN, "fixture mutation did not apply")
        divs = compute_divergences(bad_deploy, DEPLOY_OTHER, BUILD_MAIN, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn("resolve_key_prefix_generic_form", invariants)

    def test_cross_lane_override_value_disagreement_is_caught(self):
        # When BOTH lanes define a deploy-side override but disagree on the
        # value, that is caught too (forward-looking: today only main
        # defines this override, so this scenario is synthetic).
        other_with_bad_override = DEPLOY_OTHER.replace(
            "prefix = f\"lambda-artifacts/{arch}-py{py}\"\n",
            "prefix = f\"lambda-artifacts/{arch}-py{py}\"\n"
            '          mcp_code_prefix = "lambda-artifacts/x86_64-py3.11"\n',
        )
        self.assertNotEqual(other_with_bad_override, DEPLOY_OTHER)
        divs = compute_divergences(DEPLOY_MAIN, other_with_bad_override, BUILD_MAIN, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn("mcp_code_deploy_override_cross_lane_value", invariants)


class TestProducerCountDivergence(unittest.TestCase):
    """The two-producers defect: build-mcp-code's arm64-py3.12 pin collides
    with an un-skipped matrix row building mcp_code at the same key."""

    def test_removing_the_matrix_skip_is_caught(self):
        bad_build = BUILD_MAIN.replace(
            '            case "$fn" in\n'
            '              mcp_code) echo "[skip] mcp_code - built by build-mcp-code (ENC-ISS-778)"; continue ;;\n'
            '            esac\n',
            "",
        )
        self.assertNotEqual(bad_build, BUILD_MAIN, "fixture mutation did not apply")
        self.assertEqual(extract_matrix_skip_list(bad_build), [])

        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, bad_build, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn(
            "build_producer_collision", invariants,
            "removing the matrix skip must surface a producer collision for "
            "mcp_code@arm64-py3.12 (matrix job + build-mcp-code job both "
            "writing the same S3 key)",
        )
        collision_div = next(d for d in divs if d.invariant == "build_producer_collision")
        self.assertIn("mcp_code", collision_div.main_value)
        self.assertIn("arm64-py3.12", collision_div.main_value)

    def test_skip_without_a_covering_dedicated_job_is_caught(self):
        # A skip whose function is produced by NOBODY -- the "silently
        # deployed 0 functions" failure mode (ENC-TSK-Q07 follow-up).
        bad_build = BUILD_MAIN.replace(
            '  build-mcp-code:\n'
            '    steps:\n'
            '      - name: Package enceladus-mcp-code\n'
            '        run: |\n'
            '          for py in tools/enceladus-mcp-server/*.py; do\n'
            '            base=$(basename "$py")\n'
            '            case "$base" in\n'
            '              test_*) continue ;;\n'
            '            esac\n'
            '            cp "$py" "$BUILD/$base"\n'
            '          done\n'
            "          if [ -d tools/enceladus-mcp-server/mcp_server ]; then\n"
            "            rsync -a --exclude='__pycache__' --exclude='*.pyc' \\\n"
            '              tools/enceladus-mcp-server/mcp_server/ "$BUILD/mcp_server/"\n'
            "          fi\n"
            '          KEY="${PREFIX}/arm64-py3.12/mcp_code-${SHA}.zip"\n',
            "",
        )
        self.assertNotEqual(bad_build, BUILD_MAIN, "fixture mutation did not apply")
        self.assertEqual(extract_dedicated_job_pins(bad_build), {})
        self.assertEqual(extract_matrix_skip_list(bad_build), ["mcp_code"])

        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, bad_build, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn("build_skip_covered_by_dedicated_job", invariants)


class TestMcpCodePackagingInputsDivergence(unittest.TestCase):
    """mcp_code packaging inputs (tools/enceladus-mcp-server/*.py glob,
    test_* exclusion, mcp_server/ reference) must agree between lanes."""

    def test_dropping_mcp_server_reference_on_one_lane_is_caught(self):
        bad_build = BUILD_MAIN.replace(
            "          if [ -d tools/enceladus-mcp-server/mcp_server ]; then\n"
            "            rsync -a --exclude='__pycache__' --exclude='*.pyc' \\\n"
            '              tools/enceladus-mcp-server/mcp_server/ "$BUILD/mcp_server/"\n'
            "          fi\n",
            "",
        )
        self.assertNotEqual(bad_build, BUILD_MAIN, "fixture mutation did not apply")
        self.assertEqual(extract_mcp_code_packaging(bad_build)["mcp_server_ref"], "no")

        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, bad_build, BUILD_OTHER)
        invariants = {d.invariant for d in divs}
        self.assertIn("mcp_code_packaging_inputs", invariants)

    def test_dropping_test_exclusion_on_one_lane_is_caught(self):
        bad_build = BUILD_OTHER.replace(
            '                case "$base" in\n'
            "                  test_*) continue ;;\n"
            "                esac\n",
            "",
        )
        self.assertNotEqual(bad_build, BUILD_OTHER, "fixture mutation did not apply")

        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, bad_build)
        invariants = {d.invariant for d in divs}
        self.assertIn("mcp_code_packaging_inputs", invariants)

    def test_changing_the_glob_source_path_on_one_lane_is_caught(self):
        bad_build = BUILD_OTHER.replace(
            "tools/enceladus-mcp-server/*.py", "tools/mcp-server-legacy/*.py"
        )
        self.assertNotEqual(bad_build, BUILD_OTHER, "fixture mutation did not apply")

        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, bad_build)
        invariants = {d.invariant for d in divs}
        self.assertIn("mcp_code_packaging_inputs", invariants)


class TestMcpRuntimePackagedFunctionSetDivergence(unittest.TestCase):
    """ENC-TSK-Q09 AC-3: the packaging invariant must compare WHICH
    FUNCTIONS each lane packages the MCP server runtime for, not just a
    single glob-source signature (TestMcpCodePackagingInputsDivergence
    above). Fixture: the exact divergence ENC-ISS-782's investigation
    found -- v4/main's matrix job packages the runtime for four functions
    (mcp_code, coordination_api, mcp_streamable, mcp_streaming_gateway)
    inline; pre-ENC-TSK-Q09 main packaged it for mcp_code alone (the
    dedicated build-mcp-code job, no shared list file). This guard passed
    on the real lanes throughout the incident precisely because it never
    compared function SETS -- see test_pre_ac3_signature_check_alone_missed_it.
    """

    BUILD_OTHER_FOUR_FUNCTIONS = BUILD_OTHER.replace(
        'if [ "$fn" = "mcp_code" ]; then',
        'if [ "$fn" = "mcp_code" ] || [ "$fn" = "coordination_api" ] || '
        '[ "$fn" = "mcp_streamable" ] || [ "$fn" = "mcp_streaming_gateway" ]; then',
    )

    def test_fixture_mutation_applied_and_extracts_four_names(self):
        self.assertNotEqual(self.BUILD_OTHER_FOUR_FUNCTIONS, BUILD_OTHER)
        self.assertEqual(
            extract_inline_runtime_condition_names(self.BUILD_OTHER_FOUR_FUNCTIONS),
            ["mcp_code", "coordination_api", "mcp_streamable", "mcp_streaming_gateway"],
        )
        self.assertEqual(extract_inline_runtime_condition_names(BUILD_OTHER), ["mcp_code"])

    def test_pre_fix_main_vs_four_function_other_is_reported_with_missing_names(self):
        # main packages the runtime for mcp_code alone (BUILD_MAIN's
        # dedicated build-mcp-code job, no --main-runtime-functions-text
        # supplied -- the pre-ENC-TSK-Q09 shape with no shared list file).
        divs = compute_divergences(
            DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, self.BUILD_OTHER_FOUR_FUNCTIONS,
        )
        matches = [d for d in divs if d.invariant == "mcp_runtime_packaged_function_set"]
        self.assertEqual(len(matches), 1, "expected exactly one packaged-function-set divergence")
        d = matches[0]
        for fn in ("coordination_api", "mcp_streamable", "mcp_streaming_gateway"):
            self.assertIn(fn, d.summary, f"{fn} must be named in the divergence summary")
        self.assertIn("mcp_code", d.summary + d.main_value + d.other_value)

    def test_pre_ac3_signature_check_alone_missed_it(self):
        # extract_mcp_code_packaging()'s existing (c) signature comparison
        # -- glob source / test_* exclusion / mcp_server/ reference -- is
        # IDENTICAL for BUILD_MAIN and BUILD_OTHER_FOUR_FUNCTIONS (both
        # still glob tools/enceladus-mcp-server/*.py the same way); only the
        # WHICH-FUNCTIONS comparison this class adds catches the four-vs-one
        # divergence.
        self.assertEqual(
            extract_mcp_code_packaging(BUILD_MAIN),
            extract_mcp_code_packaging(self.BUILD_OTHER_FOUR_FUNCTIONS),
        )

    def test_post_ac1_main_list_matches_four_function_other_with_zero_divergence(self):
        # ENC-TSK-Q09 AC-1 lands main's shared list file
        # (tools/mcp_runtime_functions.txt) naming the same four functions
        # v4/main already packages inline. Once compute_divergences() is
        # given that file's content for main, the widened invariant must
        # report NOTHING for this function -- "must still pass once AC-1
        # lands" (ENC-TSK-Q09 AC-3).
        main_runtime_text = (
            "# comment lines and blanks must be ignored\n"
            "\n"
            "mcp_code\n"
            "coordination_api\n"
            "mcp_streamable\n"
            "mcp_streaming_gateway\n"
        )
        divs = compute_divergences(
            DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, self.BUILD_OTHER_FOUR_FUNCTIONS,
            main_runtime_functions_text=main_runtime_text,
        )
        matches = [d for d in divs if d.invariant == "mcp_runtime_packaged_function_set"]
        self.assertEqual(matches, [], "post-AC-1 main's shared list must match v4/main's four-function set")

    def test_full_parity_fixture_still_reports_nothing_with_the_new_invariant(self):
        # TestFullParity.test_no_divergences's baseline (mcp_code-only on
        # both sides) must remain divergence-free with this invariant added.
        divs = compute_divergences(DEPLOY_MAIN, DEPLOY_OTHER, BUILD_MAIN, BUILD_OTHER)
        matches = [d for d in divs if d.invariant == "mcp_runtime_packaged_function_set"]
        self.assertEqual(matches, [])


class TestSharedMcpRuntimeFunctionsFile(unittest.TestCase):
    """ENC-TSK-Q09 AC-1: tools/mcp_runtime_functions.txt is the single
    source of truth _build.yml's two jobs (and this guard) all read from --
    assert its real on-disk content directly, independent of any git_show()
    mocking or network access to the real origin/v4/main."""

    RUNTIME_FILE_PATH = REPO_ROOT / "tools" / "mcp_runtime_functions.txt"

    def test_file_exists_and_names_exactly_the_four_known_functions(self):
        text = self.RUNTIME_FILE_PATH.read_text()
        names = resolve_mcp_runtime_function_names("", text)
        self.assertEqual(
            sorted(names),
            sorted(["mcp_code", "coordination_api", "mcp_streamable", "mcp_streaming_gateway"]),
        )

    def test_mcp_code_is_a_member(self):
        # The build-mcp-code job's own sanity check (ENC-TSK-Q09) asserts
        # this at build time via `grep -qx`; assert it here too so a
        # regression is caught by the fast unit suite as well.
        names = resolve_mcp_runtime_function_names("", self.RUNTIME_FILE_PATH.read_text())
        self.assertIn("mcp_code", names)


class TestPureHelpers(unittest.TestCase):
    def test_normalize_prefix_expr_reduces_both_lane_spellings_identically(self):
        bash_form = normalize_prefix_expr("${{ env.ARTIFACT_KEY_PREFIX }}/${ARCH}-py${PY}")
        py_form = normalize_prefix_expr("lambda-artifacts/{arch}-py{py}")
        self.assertEqual(bash_form, "<BASE>/<ARCH>-py<PY>")
        self.assertEqual(py_form, "<BASE>/<ARCH>-py<PY>")
        self.assertEqual(bash_form, py_form)

    def test_normalize_override_value_strips_templated_base(self):
        self.assertEqual(
            normalize_override_value("${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12"),
            "arm64-py3.12",
        )
        self.assertEqual(
            normalize_override_value("lambda-artifacts/arm64-py3.12"),
            "arm64-py3.12",
        )
        self.assertIsNone(normalize_override_value(None))

    def test_extract_resolve_mcp_code_override_does_not_match_generic_key_prefix(self):
        # Regression guard for the \\bKEY_PREFIX\\b word-boundary matching:
        # MCP_CODE_KEY_PREFIX must not be mistaken for KEY_PREFIX or vice versa.
        text = (
            'KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/${ARCH}-py${PY}"\n'
            'MCP_CODE_KEY_PREFIX="${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12"\n'
        )
        self.assertEqual(
            extract_resolve_mcp_code_override(text),
            "${{ env.ARTIFACT_KEY_PREFIX }}/arm64-py3.12",
        )

    def test_extract_matrix_arch_py_pairs(self):
        pairs = extract_matrix_arch_py_pairs(BUILD_MAIN)
        self.assertEqual(pairs, [("x86_64", "3.11"), ("arm64", "3.12")])

    def test_divergence_render_shows_both_lane_labels(self):
        d = Divergence("some_invariant", "a summary", "main val", "other val")
        rendered = d.render("origin/v4/main")
        self.assertIn("main:", rendered)
        self.assertIn("origin/v4/main:", rendered)
        self.assertIn("main val", rendered)
        self.assertIn("other val", rendered)


class TestWorkflowFileAndBaseline(unittest.TestCase):
    def test_workflow_file_parses_as_yaml(self):
        with DEPLOY_WORKFLOW_PATH.open() as f:
            doc = yaml.safe_load(f)
        self.assertIsInstance(doc, dict, f"{DEPLOY_WORKFLOW_PATH} did not parse to a mapping")
        self.assertIn("jobs", doc)
        self.assertIn("validate", doc["jobs"])

    def test_workflow_has_pull_request_push_and_dispatch_triggers(self):
        text = DEPLOY_WORKFLOW_PATH.read_text()
        # PyYAML parses the bare `on:` key as the boolean True -- read the
        # trigger names from raw text instead of the parsed doc.
        self.assertIn("pull_request:", text)
        self.assertIn("push:", text)
        self.assertIn("workflow_dispatch:", text)

    def test_workflow_fetches_v4_main_before_running_the_guard(self):
        text = DEPLOY_WORKFLOW_PATH.read_text()
        fetch_pos = text.find("git fetch origin")
        guard_pos = text.find("python3 tools/assert_deploy_lane_parity.py")
        self.assertNotEqual(fetch_pos, -1, "workflow must explicitly fetch v4/main")
        self.assertNotEqual(guard_pos, -1, "workflow must invoke the guard script")
        self.assertIn("v4/main", text[fetch_pos:fetch_pos + 200])
        self.assertLess(
            fetch_pos, guard_pos,
            "v4/main must be fetched before the guard script runs (it reads "
            "origin/v4/main via `git show`)",
        )

    def test_workflow_permissions_are_read_only(self):
        with DEPLOY_WORKFLOW_PATH.open() as f:
            doc = yaml.safe_load(f)
        self.assertEqual(doc.get("permissions", {}).get("contents"), "read")

    def test_baseline_contains_the_new_workflow_entry(self):
        with BASELINE_PATH.open() as f:
            baseline = json.load(f)
        workflows = baseline["workflows"]
        self.assertIn(
            "deploy-lane-parity-guard.yml", workflows,
            "tools/prod_gate_baseline.json is missing the new workflow -- "
            "the prod-gate coverage guard FAILS CLOSED on any workflow file "
            "absent from this baseline",
        )
        entry = workflows["deploy-lane-parity-guard.yml"]
        self.assertEqual(entry["class"], "inert")
        self.assertIn("ENC-TSK-Q05", entry.get("notes", ""))
        self.assertIn("ENC-ISS-778", entry.get("notes", ""))

    def test_every_workflow_file_on_disk_is_in_the_baseline(self):
        # Light structural smoke test mirroring the coverage guard's own
        # fail-closed contract: this new file must not be the one exception.
        with BASELINE_PATH.open() as f:
            baseline = json.load(f)
        workflows_dir = REPO_ROOT / ".github" / "workflows"
        on_disk = {p.name for p in workflows_dir.glob("*.yml")}
        missing = on_disk - set(baseline["workflows"].keys())
        self.assertNotIn("deploy-lane-parity-guard.yml", missing)


class TestRealRepoFilesCurrentlyAgree(unittest.TestCase):
    """Light smoke test against this worktree's own on-disk files (no
    network / remote git calls): the extraction helpers must not raise, and
    main's own resolve-vs-deploy mcp_code override must currently be
    self-consistent (it was fixed by ENC-TSK-Q04/Q07, and AC-4 must not
    regress that)."""

    def test_main_own_files_parse_and_are_self_consistent(self):
        deploy_text = (REPO_ROOT / ".github" / "workflows" / "_deploy.yml").read_text()
        build_text = (REPO_ROOT / ".github" / "workflows" / "_build.yml").read_text()

        divs = compute_divergences(deploy_text, deploy_text, build_text, build_text)
        # Comparing main's own files against themselves must never report a
        # cross-lane divergence -- any finding here is a within-lane
        # self-inconsistency (or a bug in the extractor), not lane drift.
        self.assertEqual(
            divs, [],
            f"main's own _deploy.yml/_build.yml are not self-consistent: "
            f"{[d.invariant for d in divs]}",
        )

        override = extract_resolve_mcp_code_override(deploy_text)
        self.assertIsNotNone(override)
        self.assertEqual(normalize_override_value(override), "arm64-py3.12")


class TestMainCli(unittest.TestCase):
    """ENC-TSK-Q05 review finding (major): main() -- the ACTUAL CLI entry
    point deploy-lane-parity-guard.yml invokes -- had zero test coverage;
    every other test in this file exercises compute_divergences()/extract_*()
    directly. Two mutations of main() (silently returning 0 instead of 1 on
    an unreadable git ref, and swapping the main/other args passed to
    compute_divergences()) both went undetected by the full suite. These
    tests invoke main() itself, patching git_show() the way the sibling
    AC-2/AC-3 test files patch their own I/O edges, and use this worktree's
    REAL _deploy.yml/_build.yml as "main"'s own on-disk files so a fixture
    passing every extraction pattern doesn't have to be hand-built."""

    def setUp(self):
        self.real_deploy_path = REPO_ROOT / ".github" / "workflows" / "_deploy.yml"
        self.real_build_path = REPO_ROOT / ".github" / "workflows" / "_build.yml"
        self.real_runtime_path = REPO_ROOT / "tools" / "mcp_runtime_functions.txt"
        self.real_deploy_text = self.real_deploy_path.read_text()
        self.real_build_text = self.real_build_path.read_text()
        self.real_runtime_text = self.real_runtime_path.read_text()

    def _argv(self):
        return [
            "--other-ref", "fake-other-ref",
            "--deploy-path", str(self.real_deploy_path),
            "--build-path", str(self.real_build_path),
        ]

    def _fake_git_show(self, deploy_text=None, build_text=None, runtime_text=None):
        """A git_show() double that routes on path suffix, defaulting each
        of the three files "other" fetches to main's own real content (so
        "other" is byte-identical to "main" unless a test overrides one
        file) -- ENC-TSK-Q09 extends the original deploy/build-only double
        with the new tools/mcp_runtime_functions.txt fetch, which real
        v4/main does not have (see main()'s own graceful RuntimeError
        handling for that path); this double instead mirrors main's real
        list so lane-identical fixtures stay lane-identical across all
        three files, not just the original two."""
        deploy_text = self.real_deploy_text if deploy_text is None else deploy_text
        build_text = self.real_build_text if build_text is None else build_text
        runtime_text = self.real_runtime_text if runtime_text is None else runtime_text

        def _fake(ref, path):
            if path.endswith("_deploy.yml"):
                return deploy_text
            if path.endswith("mcp_runtime_functions.txt"):
                return runtime_text
            return build_text

        return _fake

    def test_no_divergences_exits_zero(self):
        # "other" lane's files are mocked to be byte-identical to main's own
        # -- every extract_*() comparison is therefore necessarily equal, so
        # this is a real exercise of main()'s wiring, not a hand-tuned fixture.
        with patch.object(alp, "git_show", side_effect=self._fake_git_show()):
            rc = main(self._argv())
        self.assertEqual(rc, 0)

    def test_a_real_divergence_exits_one_with_correct_main_vs_other_orientation(self):
        # Mutate ONE named invariant (ARTIFACT_BUCKET) in the "other" lane's
        # deploy text only -- everything else stays identical, so this is
        # attributable to exactly this one change.
        self.assertIn("ARTIFACT_BUCKET: jreese-net", self.real_deploy_text)
        other_deploy_text = self.real_deploy_text.replace(
            "ARTIFACT_BUCKET: jreese-net", "ARTIFACT_BUCKET: some-other-bucket",
        )

        with patch.object(
            alp, "git_show", side_effect=self._fake_git_show(deploy_text=other_deploy_text),
        ):
            rc = main(self._argv())
        self.assertEqual(rc, 1)

        # Re-derive the divergence directly to confirm main() reports it
        # with the correct main/other orientation -- this is exactly what
        # an argument-swap mutation in main()'s call to compute_divergences()
        # would get backwards (main_value and other_value would trade
        # places, and a real divergence could even disappear if the swap
        # happens to compare a lane against itself).
        divs = compute_divergences(self.real_deploy_text, other_deploy_text, self.real_build_text, self.real_build_text)
        bucket_divs = [d for d in divs if d.invariant == "deploy_env_constant:ARTIFACT_BUCKET"]
        self.assertEqual(len(bucket_divs), 1)
        self.assertIn("jreese-net", bucket_divs[0].main_value)
        self.assertIn("some-other-bucket", bucket_divs[0].other_value)

    def test_unreadable_other_ref_fails_closed_not_silently_skips(self):
        # The exact regression the finding calls out: `except RuntimeError:
        # return 0` instead of printing the error and returning 1 would pass
        # this test's inverse (asserting 0) -- assert the FAIL-CLOSED
        # contract explicitly.
        with patch.object(alp, "git_show", side_effect=RuntimeError("git show fake-other-ref:... failed")):
            rc = main(self._argv())
        self.assertEqual(
            rc, 1,
            "an unreadable other-lane ref must fail closed (exit 1), never silently skip (exit 0) -- "
            "'worse than no gate at all' per the module's own docstring",
        )

    def test_argv_parameter_is_honored_not_just_sys_argv(self):
        # main() must accept an explicit argv (like the sibling AC-2/AC-3
        # scripts' main()) so it is testable without mutating sys.argv.
        with patch.object(
            alp, "git_show", side_effect=self._fake_git_show(),
        ), patch.object(sys, "argv", ["assert_deploy_lane_parity.py"]):
            rc = main(self._argv())
        self.assertEqual(rc, 0, "main(argv) must parse the explicit argv, not fall back to sys.argv")


if __name__ == "__main__":
    unittest.main()
