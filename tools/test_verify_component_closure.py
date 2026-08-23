#!/usr/bin/env python3
"""ENC-TSK-P11 / ENC-ISS-666: tests for the Component Dependency Closure
primitive (tools/verify_component_closure.py).

Mirrors the positive-control discipline established by
tools/test_verify_devops_ownership_snapshot.py and
tools/test_cfn_deploy_role_reach_guard.py: a clean result on the real,
committed infrastructure/component_dependency_closure.json proves the file
is well-formed, but the point of this suite is the synthetic controls --
DOC-6EFD5DB32CD8's four verdicts (PASS, VIOLATION, NOT_APPLICABLE_ON_PLANE,
UNKNOWN) must never collapse into one another, a declared-but-absent
dependency must be CAUGHT (the AC-7 / ENC-ISS-672 shape), and a
STRUCTURALLY_ABSENT dependency must yield NOT_APPLICABLE_ON_PLANE rather
than silently passing or failing.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_component_closure as guard  # noqa: E402


def _minimal_closure() -> dict:
    """A minimal, fully valid synthetic closure -- independent of the real
    committed file, so these tests exercise the SHAPE contract, not today's
    specific component estate."""
    return {
        "enforced_dependency_kinds": ["bundled_module", "lambda_layer", "s3_bucket"],
        "known_open_gaps": [],
        "degradation_markers": [],
        "components": [
            {
                "name": "widget-component",
                "owning_repository": "NX-2021-L/enceladus",
                "deployed_by": ".github/workflows/_deploy.yml",
                "planes": ["prod", "gamma"],
                "dependencies": [
                    {
                        "id": "widget-layer",
                        "kind": "lambda_layer",
                        "owning_repository": "NX-2021-L/enceladus",
                        "layer_name": "widget-layer",
                        "plane_state": {
                            "prod": "PROVISIONED_ON_PLANE",
                            "gamma": "PROVISIONED_ON_PLANE",
                        },
                    },
                ],
            },
        ],
    }


class TestRealClosureFile(unittest.TestCase):
    """Positive control: the actual committed closure must be valid."""

    def test_real_closure_loads_and_validates(self):
        closure = guard.load_closure()
        errors = guard.validate_structure(closure)
        self.assertEqual(errors, [])

    def test_real_closure_has_at_least_three_components(self):
        closure = guard.load_closure()
        self.assertGreaterEqual(len(closure["components"]), 3)

    def test_real_closure_expresses_devops_io_devops_mcp_design_test(self):
        """ENC-TSK-P11's own acceptance test: owning_repository and
        declared_in must be able to disagree about which repo's canonical
        manifest names a component."""
        closure = guard.load_closure()
        component = next(
            c for c in closure["components"] if c["name"] == "devops-io-devops-mcp"
        )
        self.assertEqual(component["owning_repository"], "NX-2021-L/devops")
        self.assertNotIn("functions.yaml", component["declared_in"].split("--")[0])
        self.assertIn("ABSENT", component["declared_in"])

    def test_real_closure_ownership_predicate_reuses_p15_snapshot(self):
        closure = guard.load_closure()
        errors = guard.validate_devops_ownership(closure)
        self.assertEqual(errors, [])

    def test_cli_passes_on_real_tree(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_component_closure.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[SUCCESS]", result.stdout)
        self.assertIn("[UNKNOWN]", result.stdout)  # no --live in this invocation

    def test_cli_structurally_ok_without_live_or_base_ref(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_component_closure.py")],
            capture_output=True, text=True,
        )
        self.assertIn("--live not passed", result.stdout)
        self.assertIn("--base-ref not passed", result.stdout)


class TestStructuralValidation(unittest.TestCase):
    def test_minimal_valid_closure_passes(self):
        self.assertEqual(guard.validate_structure(_minimal_closure()), [])

    def test_missing_required_top_key_is_refused(self):
        closure = _minimal_closure()
        del closure["degradation_markers"]
        errors = guard.validate_structure(closure)
        self.assertTrue(any("degradation_markers" in e for e in errors))

    def test_empty_components_is_refused(self):
        closure = _minimal_closure()
        closure["components"] = []
        errors = guard.validate_structure(closure)
        self.assertTrue(any("components must be a non-empty array" in e for e in errors))

    def test_duplicate_component_name_is_refused(self):
        closure = _minimal_closure()
        closure["components"].append(copy.deepcopy(closure["components"][0]))
        errors = guard.validate_structure(closure)
        self.assertTrue(any("duplicate component name" in e for e in errors))

    def test_duplicate_dependency_id_is_refused(self):
        closure = _minimal_closure()
        dep = closure["components"][0]["dependencies"][0]
        closure["components"][0]["dependencies"].append(copy.deepcopy(dep))
        errors = guard.validate_structure(closure)
        self.assertTrue(any("duplicate dependency id" in e for e in errors))

    def test_invalid_dependency_kind_is_refused(self):
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0]["kind"] = "made_up_kind"
        errors = guard.validate_structure(closure)
        self.assertTrue(any("is not one of" in e for e in errors))

    def test_missing_plane_state_for_declared_plane_is_refused(self):
        closure = _minimal_closure()
        del closure["components"][0]["dependencies"][0]["plane_state"]["gamma"]
        errors = guard.validate_structure(closure)
        self.assertTrue(any("no plane_state declared for plane 'gamma'" in e for e in errors))

    def test_abbreviated_provisioned_enum_value_is_refused(self):
        """The addendum's own illustrative YAML says 'PROVISIONED'; this
        tool must not silently alias it to PROVISIONED_ON_PLANE."""
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0]["plane_state"]["prod"] = "PROVISIONED"
        errors = guard.validate_structure(closure)
        self.assertTrue(any("PROVISIONED_ON_PLANE" in e and "abbreviation" in e for e in errors))

    def test_structurally_absent_without_rationale_is_refused(self):
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0]["plane_state"]["gamma"] = "STRUCTURALLY_ABSENT"
        errors = guard.validate_structure(closure)
        self.assertTrue(any("absence_rationale" in e for e in errors))

    def test_structurally_absent_with_short_rationale_is_refused(self):
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0]["plane_state"]["gamma"] = "STRUCTURALLY_ABSENT"
        closure["components"][0]["dependencies"][0]["absence_rationale"] = "too short"
        errors = guard.validate_structure(closure)
        self.assertTrue(any("absence_rationale" in e for e in errors))

    def test_structurally_absent_with_real_rationale_passes(self):
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0]["plane_state"]["gamma"] = "STRUCTURALLY_ABSENT"
        closure["components"][0]["dependencies"][0]["absence_rationale"] = (
            "io ruling: this dependency will never exist on gamma, one EC2 host only."
        )
        self.assertEqual(guard.validate_structure(closure), [])

    def test_enforced_kind_not_in_enum_is_refused(self):
        closure = _minimal_closure()
        closure["enforced_dependency_kinds"].append("not_a_real_kind")
        errors = guard.validate_structure(closure)
        self.assertTrue(any("dependency_kind_enum" in e for e in errors))


class TestStructurallyAbsentControl(unittest.TestCase):
    """The design test the schema must pass, restated as a control: a
    STRUCTURALLY_ABSENT dependency must yield NOT_APPLICABLE_ON_PLANE,
    never a silent pass and never a failure -- even when its kind is
    enforced."""

    def test_structurally_absent_never_blocks_even_when_enforced(self):
        closure = _minimal_closure()
        dep = closure["components"][0]["dependencies"][0]
        self.assertIn(dep["kind"], closure["enforced_dependency_kinds"])
        dep["plane_state"]["gamma"] = "STRUCTURALLY_ABSENT"
        dep["absence_rationale"] = "io ruling: deliberate, permanent, will never exist on gamma."
        self.assertEqual(guard.validate_structure(closure), [])

        violations, findings = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertEqual(violations, [])
        gamma_findings = [f for f in findings if "[gamma]" in f]
        self.assertTrue(any(f.startswith("[NOT_APPLICABLE_ON_PLANE]") for f in gamma_findings))
        self.assertFalse(any(f.startswith("[PASS]") for f in gamma_findings))
        self.assertFalse(any(f.startswith("[VIOLATION]") for f in gamma_findings))
        self.assertFalse(any(f.startswith("[UNKNOWN]") for f in gamma_findings))

    def test_structurally_absent_is_never_live_checked(self):
        """validation_semantics: NOT_APPLICABLE_ON_PLANE means the checker
        must not attempt to disprove the declaration at runtime -- even in
        --live mode, and even if a live-check function is wired for the
        dependency's kind. Scoped to gamma-only (planes=['gamma']) so the
        mock -- which throws unconditionally -- proves absolutely no call
        reaches it, rather than merely surviving a prod-plane call that
        happens to precede the assertion."""
        closure = _minimal_closure()
        closure["components"][0]["planes"] = ["gamma"]
        dep = closure["components"][0]["dependencies"][0]
        dep["kind"] = "s3_bucket"
        dep["bucket_name"] = "does-not-matter"
        dep["plane_state"] = {"gamma": "STRUCTURALLY_ABSENT"}
        dep["absence_rationale"] = "io ruling: deliberate, permanent, will never exist on gamma."

        original = guard._LIVE_CHECKS.get("s3_bucket")
        guard._LIVE_CHECKS["s3_bucket"] = lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("live check must never run for a STRUCTURALLY_ABSENT plane")
        )
        try:
            violations, findings = guard.evaluate_closure(closure, live=True, region="us-west-2")
        finally:
            if original is not None:
                guard._LIVE_CHECKS["s3_bucket"] = original
        self.assertEqual(violations, [])
        self.assertTrue(any("[NOT_APPLICABLE_ON_PLANE]" in f and "[gamma]" in f for f in findings))


class TestDeclaredButAbsentPositiveControl(unittest.TestCase):
    """AC-7's own worked example, restated as a control: a declaration of
    PROVISIONED_ON_PLANE is not evidence of existence, and this tool must
    catch the gap when it can check cheaply (bundled_module, local) or when
    told to check live (--live)."""

    def test_bundled_module_missing_source_file_is_caught(self):
        closure = _minimal_closure()
        closure["components"][0]["dependencies"][0] = {
            "id": "phantom-module",
            "kind": "bundled_module",
            "owning_repository": "NX-2021-L/enceladus",
            "source_path": "backend/lambda/shared_layer/python/enceladus_shared/this_file_does_not_exist.py",
            "plane_state": {"prod": "PROVISIONED_ON_PLANE", "gamma": "PROVISIONED_ON_PLANE"},
        }
        self.assertEqual(guard.validate_structure(closure), [])

        violations, findings = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertTrue(violations, "declared-but-absent bundled_module must be a violation")
        self.assertTrue(any("does not exist on disk" in v for v in violations))
        self.assertTrue(any(f.startswith("[VIOLATION]") for f in findings))

    def test_bundled_module_present_on_disk_but_not_in_manifest_is_caught(self):
        """Existing file, but the .build_extras manifest that is supposed
        to bundle it doesn't actually list it -- a template declaration
        (source_path) is not evidence the bundling actually happens."""
        closure = _minimal_closure()
        real_file = "backend/lambda/shared_layer/python/enceladus_shared/warehouse_registration.py"
        self.assertTrue((REPO_ROOT / real_file).is_file())
        closure["components"][0]["dependencies"][0] = {
            "id": "unlisted-module",
            "kind": "bundled_module",
            "owning_repository": "NX-2021-L/enceladus",
            "source_path": real_file,
            "build_extras_manifest": "backend/lambda/checkout_service/.build_extras_does_not_exist",
            "plane_state": {"prod": "PROVISIONED_ON_PLANE", "gamma": "PROVISIONED_ON_PLANE"},
        }
        violations, _ = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertTrue(any("does not exist" in v for v in violations))

    def test_live_check_declared_present_actually_absent_is_caught(self):
        """The ENC-ISS-672 shape reproduced directly: declared
        PROVISIONED_ON_PLANE, live check says absent -- must be a VIOLATION
        when the dependency's kind is enforced, with --live passed."""
        closure = _minimal_closure()
        dep = closure["components"][0]["dependencies"][0]
        dep["kind"] = "s3_bucket"
        dep["bucket_name"] = "a-bucket-that-does-not-exist"
        self.assertIn("s3_bucket", closure["enforced_dependency_kinds"])

        original = guard._LIVE_CHECKS.get("s3_bucket")
        guard._LIVE_CHECKS["s3_bucket"] = lambda *_a, **_k: (
            "VIOLATION", "bucket does not exist live -- declared PROVISIONED_ON_PLANE, actually absent"
        )
        try:
            violations, findings = guard.evaluate_closure(closure, live=True, region="us-west-2")
        finally:
            if original is not None:
                guard._LIVE_CHECKS["s3_bucket"] = original
        self.assertTrue(violations, "a live-confirmed absence on an enforced kind must be a violation")
        self.assertTrue(any(f.startswith("[VIOLATION]") for f in findings))

    def test_live_check_absence_on_unenforced_kind_is_visible_but_not_blocking(self):
        """Fleet-wide in what it SEES, narrow in what it BLOCKS (AC-9): the
        same live-confirmed absence on a kind NOT in enforced_dependency_kinds
        must still print, but must not fail the run."""
        closure = _minimal_closure()
        closure["enforced_dependency_kinds"] = ["bundled_module"]  # drop lambda_layer
        dep = closure["components"][0]["dependencies"][0]
        dep["kind"] = "lambda_layer"
        dep["layer_name"] = "a-layer-that-does-not-exist"

        original = guard._LIVE_CHECKS.get("lambda_layer")
        guard._LIVE_CHECKS["lambda_layer"] = lambda *_a, **_k: ("VIOLATION", "absent live")
        try:
            violations, findings = guard.evaluate_closure(closure, live=True, region="us-west-2")
        finally:
            if original is not None:
                guard._LIVE_CHECKS["lambda_layer"] = original
        self.assertEqual(violations, [])
        self.assertTrue(any(f.startswith("[VIOLATION]") for f in findings))


class TestNotYetProvisionedGapHandling(unittest.TestCase):
    def test_untracked_gap_on_enforced_kind_blocking(self):
        closure = _minimal_closure()
        dep = closure["components"][0]["dependencies"][0]
        dep["plane_state"]["gamma"] = "NOT_YET_PROVISIONED"
        violations, findings = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertTrue(violations)
        self.assertTrue(any("UNTRACKED" in f for f in findings))

    def test_tracked_gap_on_enforced_kind_is_nonblocking(self):
        closure = _minimal_closure()
        dep = closure["components"][0]["dependencies"][0]
        dep["plane_state"]["gamma"] = "NOT_YET_PROVISIONED"
        closure["known_open_gaps"] = [{
            "component": "widget-component",
            "dependency_id": "widget-layer",
            "plane": "gamma",
            "reason": "tracked test gap",
            "tracker": "ENC-TSK-TEST",
            "recorded": "2026-08-23",
        }]
        violations, findings = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertEqual(violations, [])
        self.assertTrue(any(f.startswith("[GAP]") and "KNOWN" in f for f in findings))

    def test_stale_known_open_gap_entry_is_a_violation(self):
        """The ledger entry claims NOT_YET_PROVISIONED but the dependency is
        actually PROVISIONED_ON_PLANE -- same stale-exception discipline as
        tools/cfn_deploy_role_reach_guard.py."""
        closure = _minimal_closure()
        closure["known_open_gaps"] = [{
            "component": "widget-component",
            "dependency_id": "widget-layer",
            "plane": "gamma",
            "reason": "claims a gap that no longer exists",
            "tracker": "ENC-TSK-TEST",
            "recorded": "2026-08-23",
        }]
        # dependency plane_state stays PROVISIONED_ON_PLANE (default) -- the
        # ledger entry never fires.
        violations, _ = guard.evaluate_closure(closure, live=False, region="us-west-2")
        self.assertTrue(any("STALE known_open_gaps ENTRY" in v for v in violations))


class TestOwnershipPredicateReuse(unittest.TestCase):
    def test_devops_owned_component_absent_from_snapshot_is_refused(self):
        closure = _minimal_closure()
        closure["components"][0]["owning_repository"] = "NX-2021-L/devops"
        errors = guard.validate_devops_ownership(closure)
        self.assertTrue(any("not present" in e and "widget-component" in e for e in errors))

    def test_enceladus_owned_component_is_not_checked_against_devops_snapshot(self):
        closure = _minimal_closure()  # owning_repository stays NX-2021-L/enceladus
        errors = guard.validate_devops_ownership(closure)
        self.assertEqual(errors, [])


class TestRatchets(unittest.TestCase):
    def test_unresolvable_base_ref_is_a_hard_failure(self):
        closure = _minimal_closure()
        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: None
        try:
            errors = guard.validate_ratchets(closure, "unresolvable-ref")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertTrue(any("could not read" in e for e in errors))

    def test_git_show_returns_empty_baseline_sentinel_for_path_not_at_ref(self):
        """Unit-level proof of the stderr-marker distinction itself, using
        the REAL git binary against a ref that does exist (HEAD) but a path
        that (before this task's commit lands) does not."""
        import subprocess as _sp
        proc = _sp.run(
            ["git", "show", "HEAD:tools/definitely_not_a_real_file_xyz.json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(any(m in proc.stderr for m in guard._PATH_NOT_AT_REF_MARKERS))

    def test_bootstrap_baseline_produces_no_ratchet_violations(self):
        current = _minimal_closure()
        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: dict(guard._EMPTY_BASELINE)
        try:
            errors = guard.validate_ratchets(current, "pre-history-ref")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertEqual(errors, [])

    def test_enforced_kinds_shrink_is_refused(self):
        baseline = _minimal_closure()
        baseline["enforced_dependency_kinds"] = ["bundled_module", "lambda_layer", "s3_bucket"]
        current = _minimal_closure()
        current["enforced_dependency_kinds"] = ["bundled_module"]

        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: baseline
        try:
            errors = guard.validate_ratchets(current, "fake-base")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertTrue(any("SHRANK" in e for e in errors))

    def test_enforced_kinds_growth_is_allowed(self):
        baseline = _minimal_closure()
        baseline["enforced_dependency_kinds"] = ["bundled_module"]
        current = _minimal_closure()
        current["enforced_dependency_kinds"] = ["bundled_module", "lambda_layer", "s3_bucket"]

        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: baseline
        try:
            errors = guard.validate_ratchets(current, "fake-base")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertEqual(errors, [])

    def test_revert_orphan_unmarked_removal_is_refused(self):
        """ENC-TSK-O95 / ENC-ISS-666, reproduced directly: a dependency
        removed while the component still declares the affected plane, with
        no degradation_markers entry, must be a violation."""
        baseline = _minimal_closure()  # widget-layer present on prod+gamma
        current = _minimal_closure()
        current["components"][0]["dependencies"] = []  # dependency vanished
        # component still declares both planes -- orphaned, unmarked

        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: baseline
        try:
            errors = guard.validate_ratchets(current, "fake-base")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertTrue(any("REVERT-ORPHAN" in e for e in errors))

    def test_revert_orphan_marked_removal_is_allowed(self):
        baseline = _minimal_closure()
        current = _minimal_closure()
        current["components"][0]["dependencies"] = []
        current["degradation_markers"] = [{
            "component": "widget-component",
            "plane": "prod",
            "removed_dependency_id": "widget-layer",
            "reason": "layer retired, function no longer needs it",
            "tracker": "ENC-TSK-TEST",
            "recorded": "2026-08-23",
        }, {
            "component": "widget-component",
            "plane": "gamma",
            "removed_dependency_id": "widget-layer",
            "reason": "layer retired, function no longer needs it",
            "tracker": "ENC-TSK-TEST",
            "recorded": "2026-08-23",
        }]

        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: baseline
        try:
            errors = guard.validate_ratchets(current, "fake-base")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertEqual(errors, [])

    def test_revert_orphan_removal_with_plane_also_dropped_is_allowed(self):
        """If the component itself stops declaring the plane the removed
        dependency covered, there is no dependent left to orphan."""
        baseline = _minimal_closure()
        current = _minimal_closure()
        current["components"][0]["planes"] = []  # not realistic on its own
        current["components"][0]["dependencies"] = []

        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: baseline
        try:
            errors = guard.validate_ratchets(current, "fake-base")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertEqual(errors, [])

    def test_real_closure_ratchets_clean_against_itself(self):
        closure = guard.load_closure()
        original = guard._git_show_closure_at_ref
        guard._git_show_closure_at_ref = lambda ref: json.loads(json.dumps(closure))
        try:
            errors = guard.validate_ratchets(closure, "self")
        finally:
            guard._git_show_closure_at_ref = original
        self.assertEqual(errors, [])


class TestComponentCoverage(unittest.TestCase):
    """AC-6: enumeration is live-derived, reusing
    verify_lambda_arch_parity.py's _enumerate_live_lambda_functions rather
    than a third enumeration mechanism."""

    def test_unavailable_live_access_reports_unknown_not_a_pass(self):
        closure = _minimal_closure()
        original = guard._arch_parity._enumerate_live_lambda_functions
        guard._arch_parity._enumerate_live_lambda_functions = (
            lambda region="us-west-2": (None, "boto3 not available")
        )
        try:
            errors, status = guard._validate_component_coverage(closure, region="us-west-2")
        finally:
            guard._arch_parity._enumerate_live_lambda_functions = original
        self.assertEqual(errors, [])
        self.assertEqual(status, "UNKNOWN_NO_LIVE_ACCESS")

    def test_available_live_access_matches_declared_components(self):
        closure = _minimal_closure()
        original = guard._arch_parity._enumerate_live_lambda_functions
        guard._arch_parity._enumerate_live_lambda_functions = (
            lambda region="us-west-2": ({"widget-component-gamma", "unrelated-fn"}, "")
        )
        try:
            errors, status = guard._validate_component_coverage(closure, region="us-west-2")
        finally:
            guard._arch_parity._enumerate_live_lambda_functions = original
        self.assertEqual(errors, [])
        self.assertEqual(status, "RECONCILED")

    def test_reuses_the_same_function_object_as_arch_parity(self):
        """Structural proof this is not a re-implementation: the module
        attribute IS verify_lambda_arch_parity's own function."""
        import verify_lambda_arch_parity as arch_parity
        self.assertIs(guard._arch_parity, arch_parity)


class TestCliExitCodes(unittest.TestCase):
    def test_malformed_closure_exits_2(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{not valid json")
            path = Path(f.name)
        try:
            original_path = guard.CLOSURE_PATH
            guard.CLOSURE_PATH = path
            with self.assertRaises(SystemExit) as ctx:
                guard.load_closure(path)
            self.assertEqual(ctx.exception.code, 2)
        finally:
            guard.CLOSURE_PATH = original_path
            path.unlink()

    def test_missing_closure_exits_2(self):
        missing = REPO_ROOT / "tools" / "does_not_exist_component_closure.json"
        self.assertFalse(missing.is_file())
        with self.assertRaises(SystemExit) as ctx:
            guard.load_closure(missing)
        self.assertEqual(ctx.exception.code, 2)

    def test_structural_violation_is_detected_before_any_exit_code_decision(self):
        """The CLI's exit-1 path (main()) is a thin wrapper around
        validate_structure returning a non-empty list -- exercised directly
        here since CLOSURE_PATH is a fixed repo-relative path, not
        cwd-relative, so a temp-directory subprocess run would just read
        the real committed file instead of the synthetic broken one."""
        closure = _minimal_closure()
        del closure["components"][0]["dependencies"][0]["owning_repository"]
        errors = guard.validate_structure(closure)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
