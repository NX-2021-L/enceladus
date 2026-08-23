#!/usr/bin/env python3
"""Test fixtures for tools/verify_lambda_arch_parity.py.

ENC-TSK-D22 AC8: cover the new _validate_shared_layer_deploy_script() check
with both a known-bad case (the pre-fix script that produced ENC-ISS-198) and
a known-good case (the post-fix script that targets the consumer ABI fully).

Run from repo root:
    python3 -m unittest tools.test_verify_lambda_arch_parity -v
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_lambda_arch_parity as vlap  # noqa: E402


# The pre-ENC-TSK-D22 script. This is the exact form that produced ENC-ISS-198:
# RUNTIME hardcoded to python3.12, only --platform flag (no --python-version,
# no --abi), and no --compatible-architectures on the publish call.
KNOWN_BAD_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail
ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
LAYER_NAME="enceladus-shared${ENVIRONMENT_SUFFIX}"
RUNTIME="python3.12"

build_layer() {
    python3 -m pip install \\
        --platform manylinux2014_x86_64 \\
        --only-binary=:all: \\
        -r requirements.txt \\
        -t /tmp/build/python
}

publish_layer() {
    aws lambda publish-layer-version \\
        --layer-name "${LAYER_NAME}" \\
        --description "Enceladus shared utilities" \\
        --compatible-runtimes "${RUNTIME}" \\
        --zip-file "fileb://layer.zip"
}
"""

# The post-ENC-TSK-D22 script. All three pip flags present (--platform,
# --python-version, --abi), the prod build target is fully pinned, the
# publish call passes --compatible-architectures, and the comment block
# references ENC-ISS-198 so the historical precedent chain is documented.
KNOWN_GOOD_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail
ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
LAYER_NAME="enceladus-shared${ENVIRONMENT_SUFFIX}"

# ENC-ISS-198 / ENC-TSK-D22: build target is keyed off ENVIRONMENT_SUFFIX so
# prod (empty) builds against python3.11/x86_64 and gamma builds against
# python3.12/arm64.
if [[ -z "${ENVIRONMENT_SUFFIX}" ]]; then
    RUNTIME="python3.11"
    PYTHON_VERSION="3.11"
    PIP_ABI="cp311"
    PIP_PLATFORM="manylinux2014_x86_64"
    LAMBDA_ARCH="x86_64"
else
    RUNTIME="python3.12"
    PYTHON_VERSION="3.12"
    PIP_ABI="cp312"
    PIP_PLATFORM="manylinux2014_aarch64"
    LAMBDA_ARCH="arm64"
fi

build_layer() {
    # 🚨 THREE FLAGS, NOT ONE. See ENC-ISS-198 for the failure class.
    python3 -m pip install \\
        --platform "${PIP_PLATFORM}" \\
        --implementation cp \\
        --python-version "${PYTHON_VERSION}" \\
        --abi "${PIP_ABI}" \\
        --only-binary=:all: \\
        -r requirements.txt \\
        -t /tmp/build/python
}

publish_layer() {
    aws lambda publish-layer-version \\
        --layer-name "${LAYER_NAME}" \\
        --description "Enceladus shared utilities — built for ${RUNTIME} / ${LAMBDA_ARCH}" \\
        --compatible-runtimes "${RUNTIME}" \\
        --compatible-architectures "${LAMBDA_ARCH}" \\
        --zip-file "fileb://layer.zip"
}
"""


class TestSharedLayerDeployScriptValidator(unittest.TestCase):
    """ENC-TSK-D22 AC8 — known-good and known-bad cases for the H7 layer-ABI guard."""

    def _run_with_script(self, script_text: str) -> list[str]:
        """Write script_text to a tempfile, point SHARED_LAYER_DEPLOY at it, run validator."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(script_text)
            tmp_path = Path(fh.name)
        try:
            with mock.patch.object(vlap, "SHARED_LAYER_DEPLOY", tmp_path):
                return vlap._validate_shared_layer_deploy_script()
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_known_bad_pre_enc_iss_198_script_is_rejected(self):
        """The pre-fix script that produced ENC-ISS-198 must fail the guard."""
        errors = self._run_with_script(KNOWN_BAD_SCRIPT)
        self.assertGreater(
            len(errors), 0,
            "Pre-ENC-ISS-198 script must fail the guard but did not — guard is broken",
        )
        joined = "\n".join(errors)
        # The error must explicitly name the missing pip flags
        self.assertIn("--python-version", joined)
        self.assertIn("--abi", joined)
        # And explicitly call out the ENC-ISS-198 precedent
        self.assertIn("ENC-ISS-198", joined)

    def test_known_good_post_enc_tsk_d22_script_is_accepted(self):
        """The post-fix script must pass the guard cleanly."""
        errors = self._run_with_script(KNOWN_GOOD_SCRIPT)
        self.assertEqual(
            errors, [],
            f"Post-ENC-TSK-D22 script must pass the guard but produced errors:\n  "
            + "\n  ".join(errors),
        )

    def test_real_repo_script_passes_after_fix(self):
        """The actual on-disk shared_layer/deploy.sh in the worktree must pass.

        This is a smoke test against the repo's current state — if it fails,
        the fix to deploy.sh has been reverted or the validator is broken.
        """
        if not vlap.SHARED_LAYER_DEPLOY.is_file():
            self.skipTest(f"Real script not present at {vlap.SHARED_LAYER_DEPLOY}")
        errors = vlap._validate_shared_layer_deploy_script()
        self.assertEqual(
            errors, [],
            f"On-disk shared_layer/deploy.sh failed the guard:\n  "
            + "\n  ".join(errors),
        )

    def test_missing_compatible_architectures_is_rejected(self):
        """A script that omits --compatible-architectures on publish must fail."""
        bad = KNOWN_GOOD_SCRIPT.replace(
            '--compatible-architectures "${LAMBDA_ARCH}" \\\n        ',
            "",
        )
        errors = self._run_with_script(bad)
        self.assertTrue(
            any("--compatible-architectures" in e for e in errors),
            f"Script missing --compatible-architectures must fail with a clear "
            f"error message; got: {errors}",
        )

    def test_missing_enc_iss_198_marker_is_rejected(self):
        """A script that drops the ENC-ISS-198 marker comment must fail.

        This is part of the historical precedent chain enforcement: every layer
        build script must reference all three of ENC-ISS-041, ENC-ISS-044, and
        ENC-ISS-198 so the next maintainer understands why the three-flag form
        is non-negotiable.
        """
        bad = KNOWN_GOOD_SCRIPT.replace("ENC-ISS-198", "ENC-ISS-XXX")
        errors = self._run_with_script(bad)
        self.assertTrue(
            any("ENC-ISS-198" in e for e in errors),
            f"Script missing ENC-ISS-198 marker must fail; got: {errors}",
        )


# ---------------------------------------------------------------------------
# ENC-TSK-O83: structural selection + count-reconciliation coverage.
# ---------------------------------------------------------------------------

_TEMPLATE_HEADER = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"

# Defect 1 regression: a function whose Environment.Variables block is large
# enough that FunctionName/Runtime would have fallen outside the old
# 40-line forward scan window. The structural parser doesn't scan a window
# at all, so this must still be selected and evaluated.
_BIG_ENV_VARS = "\n".join(
    f"          VAR_{i:04d}: \"value-{i:04d}\"" for i in range(45)
)
TEMPLATE_BIG_ENV_FUNCTION = _TEMPLATE_HEADER + f"""\
  BigEnvFunction:
    Type: AWS::Lambda::Function
    Properties:
      Environment:
        Variables:
{_BIG_ENV_VARS}
      FunctionName: !Sub "big-env-function${{EnvironmentSuffix}}"
      Runtime: !If [IsGamma, python3.12, python3.11]
      Architectures:
        - !If [IsGamma, arm64, x86_64]
"""

# Defect 1 regression: a container-image function has no Runtime key at
# all. The old parser required `function_name and runtime_line` to emit a
# block, so this was silently dropped. It must now be selected (and, since
# it genuinely has no runtime to check, flagged rather than ignored).
TEMPLATE_CONTAINER_IMAGE_FUNCTION = _TEMPLATE_HEADER + """\
  ContainerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "container-fn${EnvironmentSuffix}"
      PackageType: Image
      Architectures:
        - !If [IsGamma, arm64, x86_64]
      Code:
        ImageUri: "123456789012.dkr.ecr.us-west-2.amazonaws.com/repo:latest"
"""

TEMPLATE_EMPTY_RESOURCES = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"

TEMPLATE_TWO_CLEAN_FUNCTIONS = _TEMPLATE_HEADER + """\
  FirstFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "first-fn${EnvironmentSuffix}"
      Runtime: !If [IsGamma, python3.12, python3.11]
      Architectures:
        - !If [IsGamma, arm64, x86_64]
  SecondFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "second-fn${EnvironmentSuffix}"
      Runtime: !If [IsGamma, python3.12, python3.11]
      Architectures:
        - !If [IsGamma, arm64, x86_64]
"""


def _write_template(text: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(text)
    return Path(fh.name)


class TestStructuralLambdaSelection(unittest.TestCase):
    """ENC-TSK-O83 Defect 1: structural YAML selection, not a 40-line window."""

    def _parse(self, text: str):
        path = _write_template(text)
        try:
            return vlap._parse_lambda_blocks(path)
        finally:
            path.unlink(missing_ok=True)

    def test_function_with_oversized_environment_block_is_selected(self):
        """A function whose Environment.Variables block exceeds 40 lines before
        FunctionName/Runtime must still be selected — no forward-scan window."""
        blocks = self._parse(TEMPLATE_BIG_ENV_FUNCTION)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].resource_name, "BigEnvFunction")
        self.assertEqual(blocks[0].function_name, "big-env-function")
        self.assertEqual(
            blocks[0].runtime, {"!If": ["IsGamma", "python3.12", "python3.11"]}
        )

    def test_container_image_function_without_runtime_is_selected(self):
        """A container-image function has no Runtime key. It must be selected
        (not silently dropped) even though it has nothing to check there —
        and the CFN validator must flag the missing Runtime explicitly."""
        blocks = self._parse(TEMPLATE_CONTAINER_IMAGE_FUNCTION)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].resource_name, "ContainerFunction")
        self.assertIsNone(blocks[0].runtime)

        errors = vlap._validate_cfn(blocks)
        self.assertTrue(
            any("missing Runtime" in e for e in errors),
            f"Expected a missing-Runtime error, got: {errors}",
        )

    def test_gamma_literal_function_is_selected_but_skipped_from_validation(self):
        """The one hardcoded -gamma FunctionName is selected structurally (it
        counts toward the census) but intentionally exempt from _validate_cfn."""
        text = _TEMPLATE_HEADER + """\
  GammaLiteralFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: enceladus-mcp-code-gamma
      Runtime: python3.12
      Architectures:
        - arm64
"""
        blocks = self._parse(text)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(vlap._validate_cfn(blocks), [])

    def test_hardcoded_architecture_is_rejected(self):
        text = _TEMPLATE_HEADER + """\
  BadArchFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "bad-arch-fn${EnvironmentSuffix}"
      Runtime: !If [IsGamma, python3.12, python3.11]
      Architectures:
        - arm64
"""
        blocks = self._parse(text)
        errors = vlap._validate_cfn(blocks)
        self.assertTrue(
            any("hardcoded Architectures=[arm64]" in e for e in errors), errors
        )

    def test_real_compute_template_is_selected_and_passes(self):
        """Smoke test against the real on-disk 02-compute.yaml."""
        if not vlap.COMPUTE_TEMPLATE.is_file():
            self.skipTest(f"Real template not present at {vlap.COMPUTE_TEMPLATE}")
        blocks = vlap._parse_lambda_blocks(vlap.COMPUTE_TEMPLATE)
        self.assertGreater(len(blocks), 0)
        self.assertEqual(vlap._validate_cfn(blocks), [])


class TestCountReconciliation(unittest.TestCase):
    """ENC-TSK-O83 Defect 2: the count-reconciliation assertion."""

    def test_matching_counts_produce_no_error(self):
        path = _write_template(TEMPLATE_TWO_CLEAN_FUNCTIONS)
        try:
            blocks = vlap._parse_lambda_blocks(path)
            self.assertEqual(len(blocks), 2)
            self.assertEqual(vlap._validate_resource_count_reconciliation(blocks, path), [])
        finally:
            path.unlink(missing_ok=True)

    def test_undercount_is_caught_and_named(self):
        """If the structural selector evaluates fewer resources than are
        declared, the reconciliation assertion must fail and name the gap —
        this is the actual defense against a silent-skip regression."""
        path = _write_template(TEMPLATE_TWO_CLEAN_FUNCTIONS)
        try:
            blocks = vlap._parse_lambda_blocks(path)
            truncated = blocks[:1]  # simulate a parser that dropped one function
            errors = vlap._validate_resource_count_reconciliation(truncated, path)
            self.assertTrue(errors, "Expected a reconciliation failure")
            joined = "\n".join(errors)
            self.assertIn("declared=2", joined)
            self.assertIn("evaluated=1", joined)
            dropped_name = (set(b.resource_name for b in blocks) - set(b.resource_name for b in truncated)).pop()
            self.assertIn(dropped_name, joined)
        finally:
            path.unlink(missing_ok=True)

    def test_empty_resources_block_fails_not_passes(self):
        """An empty Resources block must fail the guard end-to-end, not
        silently pass because there was 'nothing to check'."""
        path = _write_template(TEMPLATE_EMPTY_RESOURCES)
        try:
            with mock.patch.object(vlap, "COMPUTE_TEMPLATE", path), mock.patch.object(
                sys, "argv", ["verify_lambda_arch_parity.py"]
            ):
                rc = vlap.main()
            self.assertEqual(rc, 1, "Empty Resources block must fail the guard")
        finally:
            path.unlink(missing_ok=True)

    def test_real_manifest_and_template_counts_reconcile(self):
        """Locks in the ENC-TSK-O83 identity on the real repo state:
        declared_lambdas - gamma_skips == manifest_functions - cfn_managed_false.
        """
        if not vlap.COMPUTE_TEMPLATE.is_file() or not vlap.MANIFEST_PATH.is_file():
            self.skipTest("Real template/manifest not present")
        import json

        blocks = vlap._parse_lambda_blocks(vlap.COMPUTE_TEMPLATE)
        declared = vlap._count_declared_lambda_resources_by_text(vlap.COMPUTE_TEMPLATE)
        self.assertEqual(declared, len(blocks))

        gamma_skips = sum(1 for b in blocks if b.function_name.endswith("-gamma"))
        manifest = json.loads(vlap.MANIFEST_PATH.read_text(encoding="utf-8"))
        functions = manifest.get("functions", [])
        cfn_managed_false = sum(1 for f in functions if f.get("cfn_managed") is False)

        self.assertEqual(
            declared - gamma_skips,
            len(functions) - cfn_managed_false,
            "declared Lambda resources minus the -gamma skip must equal "
            "manifest functions minus cfn_managed:false entries",
        )


class TestManifestExpectationsAbsent(unittest.TestCase):
    """ENC-TSK-O83 Defect 3: absent manifest expectations must fail, not skip."""

    def _run_with_manifest(self, manifest_obj) -> list[str]:
        import json

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(manifest_obj, fh)
            tmp_path = Path(fh.name)
        try:
            with mock.patch.object(vlap, "MANIFEST_PATH", tmp_path):
                return vlap._validate_manifest_expectations()
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_manifest_missing_expectations_entirely_fails(self):
        """A manifest with no expected_architecture/expected_runtime keys at
        all (malformed/truncated) must fail, not silently return []."""
        errors = self._run_with_manifest({"functions": []})
        self.assertTrue(
            errors,
            "A manifest missing expectations entirely must fail the guard, "
            "not skip validation",
        )

    def test_manifest_with_correct_expectations_passes(self):
        errors = self._run_with_manifest(
            {
                "expected_architecture": {"prod": "x86_64", "gamma": "arm64"},
                "expected_runtime": {"prod": "python3.11", "gamma": "python3.12"},
                "functions": [],
            }
        )
        self.assertEqual(errors, [])

    def test_real_manifest_has_expectations(self):
        """Smoke test: the real on-disk manifest must carry both keys, or the
        guard would now (correctly) fail CI."""
        if not vlap.MANIFEST_PATH.is_file():
            self.skipTest(f"Real manifest not present at {vlap.MANIFEST_PATH}")
        errors = vlap._validate_manifest_expectations()
        self.assertEqual(errors, [])


# ---------------------------------------------------------------------------
# ENC-TSK-O82: two-class architecture_exceptions contract coverage.
# ---------------------------------------------------------------------------


class TestArchitectureExceptions(unittest.TestCase):
    """ENC-TSK-O82 AC-2: the guard reads both exception classes and passes
    only when every declared function either matches the plane's target
    architecture or appears on exactly one of the two exception lists."""

    def _run_with_manifest(self, manifest_obj, blocks) -> list[str]:
        import json

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(manifest_obj, fh)
            tmp_path = Path(fh.name)
        try:
            with mock.patch.object(vlap, "MANIFEST_PATH", tmp_path):
                return vlap._validate_architecture_exceptions(blocks)
        finally:
            tmp_path.unlink(missing_ok=True)

    @staticmethod
    def _block(name: str, architectures) -> "vlap.LambdaResource":
        return vlap.LambdaResource(
            resource_name=name.replace("-", "_").title().replace("_", "") + "Function",
            function_name=name,
            runtime={"!If": ["IsGamma", "python3.12", "python3.11"]},
            architectures=architectures,
            line_number=1,
        )

    def test_function_on_temporary_list_passes(self):
        """A hardcoded-x86_64 function named on the temporary list must pass
        even though it doesn't match the (hypothetical, arm64) prod target."""
        manifest = {
            "expected_architecture": {"prod": "arm64", "gamma": "arm64"},
            "architecture_exceptions": {
                "prod": {
                    "temporary": {
                        "x86_64": ["legacy-fn"],
                        "rationale": "test",
                        "terminal_state": "empty",
                        "ratchet": "may only shrink",
                    },
                    "permanent": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "stable",
                        "ratchet": "additions require an io ruling",
                    },
                }
            },
        }
        blocks = [self._block("legacy-fn", ["x86_64"])]
        errors = self._run_with_manifest(manifest, blocks)
        self.assertEqual(errors, [])

    def test_function_on_permanent_list_passes(self):
        """A hardcoded-x86_64 function named on the permanent list must pass
        even though it doesn't match the (hypothetical, arm64) prod target."""
        manifest = {
            "expected_architecture": {"prod": "arm64", "gamma": "arm64"},
            "architecture_exceptions": {
                "prod": {
                    "temporary": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "empty",
                        "ratchet": "may only shrink",
                    },
                    "permanent": {
                        "x86_64": ["snapstart-fn"],
                        "rationale": "test",
                        "terminal_state": "stable",
                        "ratchet": "additions require an io ruling",
                    },
                }
            },
        }
        blocks = [self._block("snapstart-fn", ["x86_64"])]
        errors = self._run_with_manifest(manifest, blocks)
        self.assertEqual(errors, [])

    def test_function_on_both_lists_fails(self):
        """A function on BOTH the temporary and permanent lists is a
        contradiction and must fail regardless of the target mismatch."""
        manifest = {
            "expected_architecture": {"prod": "arm64", "gamma": "arm64"},
            "architecture_exceptions": {
                "prod": {
                    "temporary": {
                        "x86_64": ["contradiction-fn"],
                        "rationale": "test",
                        "terminal_state": "empty",
                        "ratchet": "may only shrink",
                    },
                    "permanent": {
                        "x86_64": ["contradiction-fn"],
                        "rationale": "test",
                        "terminal_state": "stable",
                        "ratchet": "additions require an io ruling",
                    },
                }
            },
        }
        blocks = [self._block("contradiction-fn", ["x86_64"])]
        errors = self._run_with_manifest(manifest, blocks)
        self.assertTrue(errors, "A function on both exception lists must fail")
        self.assertTrue(
            any("BOTH" in e for e in errors),
            f"Expected a both-lists contradiction error, got: {errors}",
        )

    def test_function_on_neither_list_with_wrong_architecture_fails(self):
        """A function matching neither the target nor any exception list
        must fail."""
        manifest = {
            "expected_architecture": {"prod": "arm64", "gamma": "arm64"},
            "architecture_exceptions": {
                "prod": {
                    "temporary": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "empty",
                        "ratchet": "may only shrink",
                    },
                    "permanent": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "stable",
                        "ratchet": "additions require an io ruling",
                    },
                }
            },
        }
        blocks = [self._block("undeclared-fn", ["x86_64"])]
        errors = self._run_with_manifest(manifest, blocks)
        self.assertTrue(errors, "An unlisted, mismatched function must fail")
        self.assertTrue(
            any("not listed on either" in e for e in errors),
            f"Expected an unlisted-mismatch error, got: {errors}",
        )

    def test_function_matching_target_passes_regardless_of_lists(self):
        """A function whose resolved architecture already matches the plane's
        target passes outright -- exception-list membership is irrelevant."""
        manifest = {
            "expected_architecture": {"prod": "x86_64", "gamma": "arm64"},
            "architecture_exceptions": {
                "prod": {
                    "temporary": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "empty",
                        "ratchet": "may only shrink",
                    },
                    "permanent": {
                        "x86_64": [],
                        "rationale": "test",
                        "terminal_state": "stable",
                        "ratchet": "additions require an io ruling",
                    },
                }
            },
        }
        # The real IsGamma conditional pattern resolves prod to x86_64,
        # matching the target -- this is the shape every real function in
        # 02-compute.yaml uses today.
        blocks = [self._block("normal-fn", vlap.EXPECTED_ARCH_IF_LIST)]
        errors = self._run_with_manifest(manifest, blocks)
        self.assertEqual(errors, [])

    def test_real_manifest_and_template_pass_the_exceptions_contract(self):
        """Smoke test against the real repo state: expected_architecture.prod
        is unchanged at x86_64 (the Phase 5 flip is ENC-PLN-082's call, not
        this task's) and both exception classes are seeded empty, so every
        real function must pass via target match alone."""
        if not vlap.COMPUTE_TEMPLATE.is_file() or not vlap.MANIFEST_PATH.is_file():
            self.skipTest("Real template/manifest not present")
        blocks = vlap._parse_lambda_blocks(vlap.COMPUTE_TEMPLATE)
        errors = vlap._validate_architecture_exceptions(blocks)
        self.assertEqual(errors, [])

    def test_validate_cfn_defers_hardcoded_architecture_to_a_named_exception(self):
        """A hardcoded Architectures value that _validate_cfn would normally
        reject outright must be waved through when the function is named
        anywhere in the manifest's architecture_exceptions block -- the
        actual pass/fail call is _validate_architecture_exceptions's, not
        _validate_cfn's, once a function is a declared exception."""
        exceptions = {
            "prod": {
                "temporary": {"x86_64": ["legacy-fn"]},
                "permanent": {"x86_64": []},
            }
        }
        exempt_block = self._block("legacy-fn", ["x86_64"])
        errors = vlap._validate_cfn([exempt_block], architecture_exceptions=exceptions)
        self.assertEqual(
            errors, [],
            f"A named exception must not be rejected by _validate_cfn; got: {errors}",
        )

        # A function with the same hardcoded shape but NOT named anywhere is
        # still rejected exactly as before -- the deferral is name-scoped,
        # not a blanket relaxation of the hardcoded-architecture rule.
        unnamed_block = self._block("unnamed-fn", ["x86_64"])
        errors = vlap._validate_cfn([unnamed_block], architecture_exceptions=exceptions)
        self.assertTrue(
            any("hardcoded Architectures" in e for e in errors),
            f"An unnamed hardcoded-architecture function must still be rejected; got: {errors}",
        )

    def test_real_manifest_carries_two_class_structure(self):
        """Smoke test: the real on-disk manifest declares both exception
        classes with rationale/terminal_state/ratchet fields, and the
        permanent class is seeded empty per ENC-TSK-O72."""
        if not vlap.MANIFEST_PATH.is_file():
            self.skipTest(f"Real manifest not present at {vlap.MANIFEST_PATH}")
        import json

        manifest = json.loads(vlap.MANIFEST_PATH.read_text(encoding="utf-8"))
        exceptions = vlap._manifest_architecture_exceptions(manifest)
        prod = exceptions.get("prod", {})
        for cls in ("temporary", "permanent"):
            self.assertIn(cls, prod)
            for field in ("rationale", "terminal_state", "ratchet"):
                self.assertIn(field, prod[cls])
        self.assertEqual(
            prod["permanent"]["x86_64"], [],
            "ENC-TSK-O72 proved the permanent exception class seeds empty",
        )


# ---------------------------------------------------------------------------
# ENC-TSK-O84: monotonic ratchet (temporary) + permanent-class ruling gate.
#
# Both real exception lists are empty today (ENC-TSK-O82/O72), so the ratchet
# has nothing to bite on in the actual manifest -- these tests construct the
# failing and passing transitions synthetically, against diff_architecture_
# exceptions() directly, per the task's own instruction that "a passing run
# proves nothing" while both lists are empty.
# ---------------------------------------------------------------------------


class TestTemporaryClassRatchet(unittest.TestCase):
    """AC-1: a CI check fails when the temporary class grows relative to its
    baseline; shrinking (or no change) is always allowed."""

    @staticmethod
    def _exceptions(temp_x86_64, perm_x86_64=(), rationale="test"):
        return {
            "prod": {
                "temporary": {
                    "x86_64": list(temp_x86_64),
                    "rationale": rationale,
                    "terminal_state": "empty",
                    "ratchet": "may only shrink",
                },
                "permanent": {
                    "x86_64": list(perm_x86_64),
                    "rationale": rationale,
                    "terminal_state": "stable",
                    "ratchet": "additions require an io ruling",
                },
            }
        }

    def test_growth_fails(self):
        baseline = self._exceptions([])
        current = self._exceptions(["new-fn"])
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertTrue(errors, "A grown temporary class must fail")
        self.assertTrue(
            any("ratchet violation" in e and "new-fn" in e for e in errors),
            f"Expected a named ratchet-violation error, got: {errors}",
        )

    def test_growth_names_exactly_the_added_entries(self):
        baseline = self._exceptions(["already-there"])
        current = self._exceptions(["already-there", "brand-new-1", "brand-new-2"])
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(len(errors), 1)
        self.assertIn("brand-new-1", errors[0])
        self.assertIn("brand-new-2", errors[0])
        self.assertNotIn("already-there", errors[0])

    def test_shrink_passes(self):
        baseline = self._exceptions(["retiring-fn", "also-retiring"])
        current = self._exceptions(["retiring-fn"])
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])

    def test_unchanged_passes(self):
        baseline = self._exceptions(["steady-fn"])
        current = self._exceptions(["steady-fn"])
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])

    def test_shrink_to_empty_terminal_state_passes(self):
        baseline = self._exceptions(["last-one-out"])
        current = self._exceptions([])
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])

    def test_new_architecture_key_with_members_is_growth(self):
        """A baseline with no 'arm64' key at all is an implicit empty set --
        introducing architecture_exceptions.prod.temporary.arm64 with members
        is growth just as surely as adding to an existing x86_64 list."""
        baseline = {"prod": {"temporary": {"x86_64": [], "rationale": "t"}}}
        current = {
            "prod": {"temporary": {"x86_64": [], "arm64": ["sneaky-fn"], "rationale": "t"}}
        }
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertTrue(errors)
        self.assertTrue(any("arm64" in e and "sneaky-fn" in e for e in errors))

    def test_new_plane_with_temporary_members_is_growth(self):
        """A plane entirely absent from baseline (e.g. 'gamma' not yet
        declared) is an implicit empty exceptions set for that plane too."""
        baseline = {"prod": {"temporary": {"x86_64": [], "rationale": "t"}}}
        current = {
            "prod": {"temporary": {"x86_64": [], "rationale": "t"}},
            "gamma": {"temporary": {"x86_64": ["new-plane-fn"], "rationale": "t"}},
        }
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertTrue(errors)
        self.assertTrue(any("gamma" in e and "new-plane-fn" in e for e in errors))


class TestPermanentClassRulingGate(unittest.TestCase):
    """AC-2: additions to the permanent class must not pass silently -- they
    require a fresh 'io ruling: <RECORD-ID>' citation added to the same
    plane's permanent rationale in the same change."""

    @staticmethod
    def _exceptions(perm_x86_64, rationale):
        return {
            "prod": {
                "temporary": {
                    "x86_64": [],
                    "rationale": "unrelated",
                    "terminal_state": "empty",
                    "ratchet": "may only shrink",
                },
                "permanent": {
                    "x86_64": list(perm_x86_64),
                    "rationale": rationale,
                    "terminal_state": "stable",
                    "ratchet": "additions require an io ruling",
                },
            }
        }

    def test_growth_without_ruling_fails(self):
        baseline = self._exceptions([], "SnapStart-retained functions.")
        current = self._exceptions(["snapstart-fn"], "SnapStart-retained functions.")
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertTrue(errors, "An un-ruled permanent addition must surface")
        self.assertTrue(
            any("un-ruled addition" in e and "snapstart-fn" in e for e in errors),
            f"Expected a named un-ruled-addition error, got: {errors}",
        )

    def test_growth_with_fresh_ruling_passes(self):
        baseline = self._exceptions([], "SnapStart-retained functions.")
        current = self._exceptions(
            ["snapstart-fn"],
            "SnapStart-retained functions. io ruling: ENC-TSK-O99 approved "
            "retaining snapstart-fn on 2026-09-01.",
        )
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])

    def test_growth_with_stale_preexisting_ruling_still_fails(self):
        """A citation already present at baseline is not evidence of a
        ruling on THIS addition -- it must be freshly added in this diff, or
        one stale citation would silently cover every future addition."""
        stale_rationale = "Prior ruling. io ruling: ENC-TSK-O10 covered fn-a."
        baseline = self._exceptions(["fn-a"], stale_rationale)
        current = self._exceptions(["fn-a", "fn-b"], stale_rationale)
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertTrue(
            errors, "An unchanged, stale ruling citation must not cover a new addition"
        )
        self.assertTrue(any("fn-b" in e for e in errors))

    def test_shrink_requires_no_ruling(self):
        baseline = self._exceptions(["retiring-permanent-fn"], "test")
        current = self._exceptions([], "test")
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])

    def test_ruling_marker_is_case_insensitive(self):
        baseline = self._exceptions([], "test")
        current = self._exceptions(["fn"], "test. IO RULING: ENC-ISS-42 signed off.")
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(errors, [])


class TestArchitectureExceptionsRatchetMultiPlane(unittest.TestCase):
    """Both classes, and multiple planes, are evaluated independently in a
    single diff pass -- a violation in one does not mask or get masked by a
    clean or ruled change in another."""

    def test_temporary_growth_and_ruled_permanent_growth_are_independent(self):
        baseline = {
            "prod": {
                "temporary": {"x86_64": [], "rationale": "t"},
                "permanent": {"x86_64": [], "rationale": "p"},
            },
            "gamma": {
                "temporary": {"x86_64": [], "rationale": "t"},
                "permanent": {"x86_64": [], "rationale": "p"},
            },
        }
        current = {
            "prod": {
                # Unruled growth here -- must fail.
                "temporary": {"x86_64": ["unratcheted-fn"], "rationale": "t"},
                "permanent": {"x86_64": [], "rationale": "p"},
            },
            "gamma": {
                "temporary": {"x86_64": [], "rationale": "t"},
                # Ruled growth here -- must pass.
                "permanent": {
                    "x86_64": ["ruled-fn"],
                    "rationale": "p. io ruling: ENC-TSK-O55 approved.",
                },
            },
        }
        errors = vlap.diff_architecture_exceptions(baseline, current)
        self.assertEqual(len(errors), 1)
        self.assertIn("prod", errors[0])
        self.assertIn("unratcheted-fn", errors[0])
        self.assertNotIn("ruled-fn", " ".join(errors))


class TestGitBackedRatchetGlue(unittest.TestCase):
    """ENC-TSK-O84: exercise the git-show glue (_git_show_manifest_at_ref /
    _validate_architecture_exceptions_ratchet) against a disposable, isolated
    git repo, so these tests don't depend on this worktree's own history."""

    def _init_repo(self, tmp_path: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True
        )
        subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)

    def _commit_manifest(self, tmp_path: Path, manifest_path: Path, obj: dict, message: str) -> str:
        import json

        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(obj), encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=tmp_path, check=True)
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=tmp_path, capture_output=True, text=True, check=True
        ).stdout.strip()

    def test_git_show_reads_manifest_content_at_a_prior_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._init_repo(tmp_path)
            manifest_path = tmp_path / "infrastructure" / "lambda_workflow_manifest.json"
            base_sha = self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": []}}}},
                "base",
            )
            self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": ["new-fn"]}}}},
                "grow",
            )

            with mock.patch.object(vlap, "REPO_ROOT", tmp_path), mock.patch.object(
                vlap, "MANIFEST_PATH", manifest_path
            ):
                baseline = vlap._git_show_manifest_at_ref(base_sha)
                self.assertIsNotNone(baseline)
                self.assertEqual(
                    baseline["architecture_exceptions"]["prod"]["temporary"]["x86_64"], []
                )

    def test_end_to_end_ratchet_fails_across_real_git_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._init_repo(tmp_path)
            manifest_path = tmp_path / "infrastructure" / "lambda_workflow_manifest.json"
            base_sha = self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": []}}}},
                "base",
            )
            self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": ["new-fn"]}}}},
                "grow",
            )

            with mock.patch.object(vlap, "REPO_ROOT", tmp_path), mock.patch.object(
                vlap, "MANIFEST_PATH", manifest_path
            ):
                errors = vlap._validate_architecture_exceptions_ratchet(base_sha)
                self.assertTrue(errors)
                self.assertTrue(any("new-fn" in e for e in errors))

    def test_end_to_end_ratchet_passes_on_a_shrink(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._init_repo(tmp_path)
            manifest_path = tmp_path / "infrastructure" / "lambda_workflow_manifest.json"
            base_sha = self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": ["retiring-fn"]}}}},
                "base",
            )
            self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": []}}}},
                "shrink",
            )

            with mock.patch.object(vlap, "REPO_ROOT", tmp_path), mock.patch.object(
                vlap, "MANIFEST_PATH", manifest_path
            ):
                errors = vlap._validate_architecture_exceptions_ratchet(base_sha)
                self.assertEqual(errors, [])

    def test_unresolvable_base_ref_is_a_hard_failure_not_a_silent_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._init_repo(tmp_path)
            manifest_path = tmp_path / "infrastructure" / "lambda_workflow_manifest.json"
            self._commit_manifest(
                tmp_path,
                manifest_path,
                {"architecture_exceptions": {"prod": {"temporary": {"x86_64": []}}}},
                "base",
            )

            with mock.patch.object(vlap, "REPO_ROOT", tmp_path), mock.patch.object(
                vlap, "MANIFEST_PATH", manifest_path
            ):
                errors = vlap._validate_architecture_exceptions_ratchet(
                    "this-ref-does-not-exist"
                )
                self.assertTrue(
                    errors, "An unresolvable baseline must fail, not skip (ENC-TSK-O83)"
                )
                self.assertTrue(any("cannot evaluate" in e for e in errors))

    def test_real_repo_ratchet_is_clean_against_its_own_head(self):
        """Smoke test: diffing the real on-disk manifest against its own
        current HEAD must be a no-op pass (nothing changed)."""
        if not vlap.MANIFEST_PATH.is_file():
            self.skipTest(f"Real manifest not present at {vlap.MANIFEST_PATH}")
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=vlap.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0 or proc.stdout.strip() != "true":
            self.skipTest("Not running inside a git work tree")
        errors = vlap._validate_architecture_exceptions_ratchet("HEAD")
        self.assertEqual(errors, [])


# ---------------------------------------------------------------------------
# ENC-TSK-O87: build-invocation flag contract coverage.
#
# _validate_build_invocation_flags() is the guard that makes the aarch64
# wheel contract structural rather than a fact someone checked once. These
# tests prove it actually goes red when a flag is missing from either real
# build path, and green when all four are present — the same
# never-seen-red-is-not-evidence discipline as ENC-ISS-556 / the ENC-TSK-O87
# `tbb` negative control (observed failing at
# https://github.com/NX-2021-L/enceladus/actions/runs/32615808666).
# ---------------------------------------------------------------------------

# Minimal synthetic stand-in for the real _build.yml pip install step —
# same anchor text, same flags, same multi-line backslash-continuation
# shape, without dragging in the rest of the workflow.
GOOD_BUILD_YML_SNIPPET = """\
            python -m pip install \\
              --platform "${{ matrix.pip_platform }}" \\
              --implementation cp \\
              --python-version "${{ matrix.py_version }}" \\
              --only-binary=:all: \\
              --upgrade \\
              --target "$workdir" \\
              -r "$workdir/requirements.txt"
"""

# Minimal synthetic stand-in for the real package_lambda_artifact.sh
# invocation.
GOOD_PACKAGE_SCRIPT_SNIPPET = """\
  pip install \\
    --platform "${PIP_PLATFORM}" \\
    --python-version "${PIP_PYTHON_VERSION}" \\
    --abi "${PIP_ABI}" \\
    --implementation cp \\
    --only-binary=:all: \\
    -t "${BUILD_DIR}" \\
    -r "${LAMBDA_SRC}/requirements.txt" \\
    --quiet
"""


class TestBuildInvocationFlagsValidator(unittest.TestCase):
    """ENC-TSK-O87 — the aarch64 wheel contract must survive as code, not
    as a fact someone once verified by inspection."""

    def _run_with_files(self, build_yml_text: str, package_script_text: str) -> list[str]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(build_yml_text)
            build_path = Path(fh.name)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(package_script_text)
            script_path = Path(fh.name)
        try:
            with mock.patch.object(vlap, "BUILD_WORKFLOW_PATH", build_path), \
                 mock.patch.object(vlap, "PACKAGE_ARTIFACT_SCRIPT", script_path):
                return vlap._validate_build_invocation_flags()
        finally:
            build_path.unlink(missing_ok=True)
            script_path.unlink(missing_ok=True)

    def test_both_good_invocations_pass(self):
        errors = self._run_with_files(GOOD_BUILD_YML_SNIPPET, GOOD_PACKAGE_SCRIPT_SNIPPET)
        self.assertEqual(
            errors, [],
            f"Both known-good invocations must pass the guard but produced "
            f"errors:\n  " + "\n  ".join(errors),
        )

    def test_missing_only_binary_all_in_build_yml_is_rejected(self):
        """The ENC-TSK-O87 AC-2 negative control, as a permanent unit test:
        deleting --only-binary=:all: from _build.yml's invocation must turn
        the guard red."""
        bad = GOOD_BUILD_YML_SNIPPET.replace("--only-binary=:all: \\\n", "")
        errors = self._run_with_files(bad, GOOD_PACKAGE_SCRIPT_SNIPPET)
        self.assertTrue(
            any("_build.yml" in e and "--only-binary=:all:" in e for e in errors),
            f"Missing --only-binary=:all: in _build.yml must be caught; got: {errors}",
        )
        # The good package script must not also be flagged.
        self.assertFalse(
            any("package_lambda_artifact.sh" in e for e in errors),
            f"The unmodified package script must not be flagged; got: {errors}",
        )

    def test_missing_only_binary_all_in_package_script_is_rejected(self):
        bad = GOOD_PACKAGE_SCRIPT_SNIPPET.replace("--only-binary=:all: \\\n", "")
        errors = self._run_with_files(GOOD_BUILD_YML_SNIPPET, bad)
        self.assertTrue(
            any("package_lambda_artifact.sh" in e and "--only-binary=:all:" in e for e in errors),
            f"Missing --only-binary=:all: in package_lambda_artifact.sh must "
            f"be caught; got: {errors}",
        )
        self.assertFalse(
            any("_build.yml" in e for e in errors),
            f"The unmodified _build.yml must not be flagged; got: {errors}",
        )

    def test_missing_platform_flag_is_rejected(self):
        bad = GOOD_BUILD_YML_SNIPPET.replace('--platform "${{ matrix.pip_platform }}" \\\n', "")
        errors = self._run_with_files(bad, GOOD_PACKAGE_SCRIPT_SNIPPET)
        self.assertTrue(
            any("--platform" in e for e in errors),
            f"Missing --platform must be caught; got: {errors}",
        )

    def test_missing_python_version_flag_is_rejected(self):
        bad = GOOD_BUILD_YML_SNIPPET.replace(
            '--python-version "${{ matrix.py_version }}" \\\n', ""
        )
        errors = self._run_with_files(bad, GOOD_PACKAGE_SCRIPT_SNIPPET)
        self.assertTrue(
            any("--python-version" in e for e in errors),
            f"Missing --python-version must be caught; got: {errors}",
        )

    def test_missing_implementation_cp_flag_is_rejected(self):
        bad = GOOD_PACKAGE_SCRIPT_SNIPPET.replace("--implementation cp \\\n", "")
        errors = self._run_with_files(GOOD_BUILD_YML_SNIPPET, bad)
        self.assertTrue(
            any("--implementation cp" in e for e in errors),
            f"Missing --implementation cp must be caught; got: {errors}",
        )

    def test_missing_invocation_entirely_is_rejected(self):
        """If a build path stops installing via pip altogether (or the
        anchor text changes), the guard must fail loudly, not vacuously
        pass because there was nothing to find fault with."""
        errors = self._run_with_files(
            "# no pip install here anymore\n", GOOD_PACKAGE_SCRIPT_SNIPPET
        )
        self.assertTrue(
            any("_build.yml" in e and "no" in e.lower() for e in errors),
            f"A build path with no pip install invocation must fail, not "
            f"pass vacuously; got: {errors}",
        )

    def test_real_repo_paths_pass(self):
        """Smoke test against the actual on-disk _build.yml and
        package_lambda_artifact.sh. If this fails, either the contract
        regressed for real or the guard itself is broken."""
        if not vlap.BUILD_WORKFLOW_PATH.is_file() or not vlap.PACKAGE_ARTIFACT_SCRIPT.is_file():
            self.skipTest("Real build files not present in this checkout")
        errors = vlap._validate_build_invocation_flags()
        self.assertEqual(
            errors, [],
            f"On-disk build invocations failed the guard:\n  " + "\n  ".join(errors),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
