#!/usr/bin/env python3
"""Self-tests for the pre-apply layer/function architecture coherence gate.

ENC-TSK-P40 AC-5 (negative control), AC-6 (positive control in the same run),
AC-7 (count reconciliation fails closed).

METHOD, and why it is shaped like this: modelled on
tools/test_synthetic_strip_proof.py -- mutate the REAL committed template IN
MEMORY, write the mutant to a TemporaryDirectory, assert a specific return code
and assert the failure is ATTRIBUTED to the right functions. No synthetic
fixture template is checked into the repo, so the controls can never drift away
from the artifact they are supposed to be protecting.

These tests are CREDENTIAL-FREE by construction (--offline --scope declared).
That is the point: ENC-ISS-696 is detectable from the governed closure alone, so
ci.yml can block it without AWS. The deploy lane additionally runs the gate with
credentials and --scope all, which covers the layers the closure does not
declare.

ENC-ISS-556 is the standing reason AC-5 exists at all: a gate never observed red
is not evidence that the gate works.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "tools" / "verify_layer_arch_coherence.py"
COMPUTE_REL = "infrastructure/cloudformation/02-compute.yaml"
COMPUTE = REPO_ROOT / COMPUTE_REL

# The AppConfig extension layer selector as it appears in the committed
# template AFTER ENC-TSK-Q22 (DOC-5368FE6515ED FR-12, Phase D) literalized
# it: a bare arm64-layer !Ref, no !If, no IsArm64. Architectures is ALSO
# already a bare `- arm64` post-Q22 (was `!If [IsArm64, arm64, x86_64]`
# under ENC-TSK-P40), so ENC-ISS-696's "collapse Architectures, forget the
# AppConfig selector" shape can only be reproduced now by mutating the
# selector back onto a reinstated, plane-bound IsArm64 -- see
# _mutate_to_iss696.
APPCFG_LAYER_REF = re.compile(r"^(\s*)- !Ref AppConfigExtensionLayerArnArm64\s*$", re.MULTILINE)


def _load_gate_module():
    """Import the gate as a module for unit-level assertions.

    MUST register in sys.modules BEFORE exec_module: the gate uses @dataclass,
    and dataclasses resolve field types via sys.modules[cls.__module__], which
    is None for an unregistered module. Same borrow pattern as
    verify_arm64_validation_harness.py uses for verify_lambda_package_arch.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location("_vlac_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run(*args: str) -> subprocess.CompletedProcess:
    """Run the gate credential-free so the tests are hermetic."""
    env = dict(os.environ)
    for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(k, None)
    return subprocess.run(
        [sys.executable, str(GATE), *args],
        capture_output=True, text=True, cwd=str(REPO_ROOT), env=env,
    )


class TestPositiveControl(unittest.TestCase):
    """AC-6: the committed template passes, so the gate is not merely failing everything."""

    def test_prod_plane_passes_on_the_committed_template(self):
        r = _run("--plane", "prod", "--offline", "--scope", "declared")
        self.assertEqual(r.returncode, 0, f"gate went red on the committed template:\n{r.stdout}\n{r.stderr}")
        self.assertIn("[SUCCESS]", r.stdout)

    def test_gamma_plane_passes_on_the_committed_template(self):
        r = _run("--plane", "gamma", "--offline", "--scope", "declared")
        self.assertEqual(r.returncode, 0, f"gate went red on gamma:\n{r.stdout}\n{r.stderr}")
        self.assertIn("[SUCCESS]", r.stdout)

    def test_out_of_scope_attachments_are_reported_not_silently_absorbed(self):
        r = _run("--plane", "prod", "--offline", "--scope", "declared")
        self.assertIn("OUT OF SCOPE", r.stdout)
        self.assertIn("NOT passes", r.stdout)


class TestNegativeControl(unittest.TestCase):
    """AC-5: reproduce ENC-ISS-696 exactly and require the gate to go red."""

    @staticmethod
    def _mutate_to_iss696() -> str:
        """Reproduce the ENC-ISS-696 shape against the POST-Q22 committed
        template: Architectures is already a bare `- arm64` literal (Phase D
        literalized it, so there is nothing left to collapse), while the
        AppConfig extension selector is put BACK onto a plane-bound IsArm64
        conditional -- i.e. the naive-collapse gap DOC-F3878E7260B6 section 3
        described, just with the two literalization passes (Architectures
        under ENC-TSK-P40/the cutover, the AppConfig selector under
        ENC-TSK-Q22) landing at different times instead of together. On the
        prod plane the reinstated selector then resolves to
        AWS-AppConfig-Extension:147, which declares CompatibleArchitectures
        ["x86_64"], against an arm64 function.

        ENC-TSK-P38 cutover / ENC-TSK-Q22 Phase D: the committed template no
        longer declares IsArm64 at all, under which the historical ISS-696
        condition (a selector whose condition is FALSE on prod, picking the
        x86-declared extension against arm64 functions) is no longer
        expressible. The mutant therefore reinstates the pre-cutover
        plane-bound IsArm64 definition AND re-wraps the (now bare) AppConfig
        selector !Ref in the old !If -- both in memory only -- so this
        control keeps reproducing the exact ISS-696 shape and the gate must
        keep biting on it."""
        text = COMPUTE.read_text()
        assert "IsArm64" not in text, (
            "committed template unexpectedly still declares IsArm64 -- "
            "ENC-TSK-Q22 Phase D literalization must have regressed"
        )
        mutant, m = re.subn(
            r"(?m)^(\s*)IsGamma: !Not \[!Equals \[!Ref EnvironmentSuffix, \"\"\]\]\s*$",
            r'\1IsGamma: !Not [!Equals [!Ref EnvironmentSuffix, ""]]\n'
            r'\1IsArm64: !Not [!Equals [!Ref EnvironmentSuffix, ""]]',
            text,
        )
        assert m == 1, (
            f"expected to reinstate exactly 1 pre-cutover IsArm64 definition "
            f"right after IsGamma, reinstated {m}"
        )
        mutant, n = APPCFG_LAYER_REF.subn(
            r"\1- !If [IsArm64, !Ref AppConfigExtensionLayerArnArm64, !Ref AppConfigExtensionLayerArnX86]",
            mutant,
        )
        assert n == 32, f"expected to re-wrap 32 AppConfig layer selectors, re-wrapped {n}"
        return mutant

    def test_arm64_function_with_x86_declared_layer_fails_the_gate(self):
        """ENC-TSK-Q22 changed WHY this goes red, not THAT it goes red. Phase D
        retired component_dependency_closure.json's appconfig-extension-x86
        entry (it was devops-governance-mart's only x86 dependency, and the
        x86 branch it declared is unreachable now that every AppConfig
        selector in the committed template is a bare arm64 !Ref) -- so
        --scope declared can no longer resolve AWS-AppConfig-Extension:147's
        architecture and attribute a per-function [FAIL] to it the way it did
        pre-Q22. AC-7 (fails-closed count reconciliation) is what catches the
        mutant instead: 32 functions carry a Layers attachment the reinstated
        IsArm64 conditional routes through, the declared-scope closure
        resolves zero of them, and a "zero attachments evaluated" run is
        exactly the vacuous-pass shape AC-7 exists to refuse."""
        mutant = self._mutate_to_iss696()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "02-compute.yaml"
            p.write_text(mutant)
            r = _run("--plane", "prod", "--offline", "--scope", "declared", "--template", str(p))

        self.assertEqual(r.returncode, 1, f"gate did NOT go red on the ENC-ISS-696 condition:\n{r.stdout}")
        fails = [l for l in r.stdout.splitlines() if l.startswith("[FAIL]")]
        self.assertEqual(len(fails), 1, f"expected 1 fail-closed reconciliation [FAIL], got {len(fails)}:\n{r.stdout}")
        self.assertIn("reconciliation", fails[0])
        self.assertIn("vacuous pass", "\n".join(r.stdout.splitlines()))

        # Still ATTRIBUTED: the AppConfig extension is why nothing resolved.
        self.assertIn("AWS-AppConfig-Extension:147", r.stdout)
        self.assertIn("reconciliation error", r.stdout)

    def test_the_negative_control_leaves_the_working_tree_untouched(self):
        """The mutation is in-memory only; the committed template must be unchanged."""
        before = COMPUTE.read_text()
        self._mutate_to_iss696()
        self.assertEqual(COMPUTE.read_text(), before)

    def test_gamma_is_unaffected_by_the_same_mutation(self):
        """Gamma already renders arm64 and already selects the -Arm64 extension, so the
        same mutation is a no-op there. If this ever fails, the mutation is hitting
        something other than the prod-plane conflation it is meant to model."""
        mutant = self._mutate_to_iss696()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "02-compute.yaml"
            p.write_text(mutant)
            r = _run("--plane", "gamma", "--offline", "--scope", "declared", "--template", str(p))
        self.assertEqual(r.returncode, 0, f"gamma should be unaffected:\n{r.stdout}")


class TestFailsClosed(unittest.TestCase):
    """AC-7: an enumeration that examines nothing is a failure, not a vacuous pass.

    This is the ENC-ISS-675 / ENC-ISS-677 defect class, and the whole point is
    that it must not be reproduced INSIDE the fix for it.
    """

    def test_template_with_zero_lambda_functions_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.yaml"
            p.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
            r = _run("--plane", "prod", "--offline", "--scope", "declared", "--template", str(p))
        self.assertEqual(r.returncode, 1, f"an empty template must not pass:\n{r.stdout}")
        self.assertIn("count reconciliation", r.stdout)

    def test_missing_template_is_an_environment_error_not_a_pass(self):
        r = _run("--plane", "prod", "--offline", "--template", "/nonexistent/nope.yaml")
        self.assertEqual(r.returncode, 2)


class TestRegimeSemantics(unittest.TestCase):
    """The two regimes are the reason a single posture is wrong -- assert both."""

    def test_declared_regime_is_terminal_and_never_overridden_by_content(self):
        vlac = _load_gate_module()

        class NeverInspect(vlac.LayerOracle):
            def native_object_architectures(self, arn):  # pragma: no cover - must not run
                raise AssertionError(
                    "content inspection was consulted for a DECLARED layer. The AppConfig "
                    "extension ships a bare ELF at extensions/AppConfigAgent and ZERO .so "
                    "files, so a .so-glob content check would call it architecture-neutral "
                    "and manufacture the exact vacuous pass ENC-ISS-696 is about."
                )

        arn = "arn:aws:lambda:us-west-2:359756378197:layer:AWS-AppConfig-Extension:147"
        oracle = NeverInspect(offline=True, closure={arn: "x86_64"})
        res = vlac.classify_pair(
            {"function_name": "fn", "logical_id": "Fn"}, "arm64", arn, oracle)
        self.assertEqual(res.state, vlac.FAIL)
        self.assertEqual(res.reason_code, "declared_mismatch")

    def test_undeclared_and_uninspectable_is_unknown_never_pass(self):
        vlac = _load_gate_module()

        oracle = vlac.LayerOracle(offline=True, closure={})
        res = vlac.classify_pair(
            {"function_name": "fn", "logical_id": "Fn"}, "arm64",
            "arn:aws:lambda:us-west-2:1:layer:mystery:1", oracle)
        self.assertEqual(res.state, vlac.UNKNOWN)
        self.assertNotEqual(res.state, vlac.PASS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
