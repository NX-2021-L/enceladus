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


if __name__ == "__main__":
    unittest.main(verbosity=2)
