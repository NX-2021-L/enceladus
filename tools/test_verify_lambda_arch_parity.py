#!/usr/bin/env python3
"""Test fixtures for tools/verify_lambda_arch_parity.py.

ENC-TSK-D22 AC8: cover the new _validate_shared_layer_deploy_script() check
with both a known-bad case (the pre-fix script that produced ENC-ISS-198) and
a known-good case (the post-fix script that targets the consumer ABI fully).

Run from repo root:
    python3 -m unittest tools.test_verify_lambda_arch_parity -v
"""
from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
