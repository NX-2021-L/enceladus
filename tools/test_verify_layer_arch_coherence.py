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

# The architecture conditional as it appears in the committed template AFTER
# ENC-TSK-P40 repointed it onto IsArm64.
ARCH_IF = "- !If [IsArm64, arm64, x86_64]"


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
        """Collapse the architecture conditionals to bare arm64 while leaving the
        AppConfig extension selector on its condition -- i.e. perform the naive
        'collapse the 46' operation that DOC-F3878E7260B6 section 3 prescribed
        and that ENC-ISS-696 is about. On the prod plane the AppConfig selector
        then resolves to AWS-AppConfig-Extension:147, which declares
        CompatibleArchitectures ["x86_64"], against an arm64 function.

        ENC-TSK-P38: the cutover flipped the committed IsArm64 definition to an
        unconditional TRUE, under which the historical ISS-696 condition (a
        selector whose condition is FALSE on prod picking the x86-declared
        extension against arm64 functions) is no longer expressible. The mutant
        therefore ALSO reinstates the pre-cutover plane-bound definition -- in
        memory only -- so this control keeps reproducing the exact ISS-696
        shape and the gate must keep biting on it."""
        text = COMPUTE.read_text()
        mutant, n = re.subn(re.escape(ARCH_IF), "- arm64", text)
        assert n == 46, f"expected to collapse 46 architecture conditionals, collapsed {n}"
        mutant, m = re.subn(
            r'(?m)^(\s*)IsArm64: !Equals \["arm64", "arm64"\]\s*$',
            r'\1IsArm64: !Not [!Equals [!Ref EnvironmentSuffix, ""]]',
            mutant,
        )
        assert m == 1, (
            f"expected to reinstate exactly 1 pre-cutover IsArm64 definition "
            f"(anchored to line start, comments excluded), reinstated {m}"
        )
        return mutant

    def test_arm64_function_with_x86_declared_layer_fails_the_gate(self):
        mutant = self._mutate_to_iss696()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "02-compute.yaml"
            p.write_text(mutant)
            r = _run("--plane", "prod", "--offline", "--scope", "declared", "--template", str(p))

        self.assertEqual(r.returncode, 1, f"gate did NOT go red on the ENC-ISS-696 condition:\n{r.stdout}")
        fails = [l for l in r.stdout.splitlines() if l.startswith("[FAIL]")]
        self.assertEqual(len(fails), 26, f"expected 26 incoherent prod-plane attachments, got {len(fails)}")

        # The verdict must be ATTRIBUTED, not just a count.
        joined = "\n".join(fails)
        self.assertIn("AWS-AppConfig-Extension:147", joined)
        self.assertIn("declares ['x86_64']", joined)
        self.assertIn("devops-coordination-api", joined)

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
