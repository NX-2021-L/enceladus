#!/usr/bin/env python3
"""ENC-TSK-P15 / ENC-ISS-669: tests for the cross-plane ARN isolation sweep.

The positive control is the point of this module. A clean result on the real
templates proves nothing on its own -- ENC-ISS-660's own lesson was that
every existing guard was green on the PR that caused the incident. So this
suite plants a synthetic hazard shaped exactly like ProjectJsonSyncRule (a
plane-suffixed Name next to a hardcoded, unsuffixed, non-excepted target ARN)
in a template the real exceptions file knows nothing about, and asserts the
sweep refuses to pass it. The negative control then proves the real
templates -- and the three documented single-plane-by-design resource
families (Lambda::Url adoptions, CheckoutAutoScheduleRule) -- are clean.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_cross_plane_arn_isolation as guard  # noqa: E402


SYNTHETIC_HAZARD_TEMPLATE = """
Parameters:
  EnvironmentSuffix:
    Type: String
    Default: ""
Conditions:
  IsGamma: !Equals [!Ref EnvironmentSuffix, "-gamma"]
  IsProduction: !Equals [!Ref EnvironmentSuffix, ""]
Resources:
  # The planted hazard: Name is plane-suffixed (renders on gamma), Target is
  # a hardcoded literal ARN with no suffix and no matching declared
  # exception -- exactly the ProjectJsonSyncRule shape.
  SyntheticHazardRule:
    Type: AWS::Events::Rule
    Condition: IsGamma
    Properties:
      Name: !Sub "synthetic-hazard-schedule${EnvironmentSuffix}"
      State: ENABLED
      Targets:
        - Arn: !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:definitely-not-an-excepted-function"
          Id: synthetic-hazard-target

  # Negative control 1: target itself is plane-suffixed -- self-consistent.
  SyntheticSafeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub "synthetic-safe-schedule${EnvironmentSuffix}"
      State: ENABLED
      Targets:
        - Arn: !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:synthetic-safe-function${EnvironmentSuffix}"
          Id: synthetic-safe-target

  # Negative control 2: target resolved via GetAtt to a sibling resource --
  # cannot structurally cross planes, never flagged.
  SyntheticRefRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub "synthetic-ref-schedule${EnvironmentSuffix}"
      State: ENABLED
      Targets:
        - Arn: !GetAtt SyntheticFunction.Arn
          Id: synthetic-ref-target

  # Negative control 3: nothing about this resource is plane-templated at
  # all (mirrors CheckoutAutoScheduleRule) -- a fixed target next to it is
  # not a contradiction, so it is skipped rather than flagged.
  SyntheticLiteralRule:
    Type: AWS::Events::Rule
    Condition: IsProduction
    Properties:
      Name: synthetic-literal-adopted-rule
      State: ENABLED
      Targets:
        - Arn: !Sub "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:synthetic-literal-adopted-function"
          Id: synthetic-literal-target
"""


class TestSyntheticHazardIsDetected(unittest.TestCase):
    """Positive control: a planted hazard the sweep MUST catch."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.cfn_dir = Path(cls.tmpdir.name)
        (cls.cfn_dir / "synthetic.yaml").write_text(SYNTHETIC_HAZARD_TEMPLATE, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_hazard_is_flagged_as_violation(self):
        findings, tally, matched = guard.scan(
            cfn_dir=self.cfn_dir, templates=["synthetic.yaml"], exceptions={}
        )
        violations = [f for f in findings if f.state == "VIOLATION"]
        self.assertEqual(len(violations), 1, [f.line() for f in findings])
        self.assertEqual(violations[0].logical_id, "SyntheticHazardRule")
        self.assertIn("definitely-not-an-excepted-function", violations[0].arn)
        self.assertEqual(tally["violation"], 1)

    def test_negative_controls_in_the_same_template_are_not_flagged(self):
        """The synthetic template also proves the sweep does not cry wolf."""
        findings, tally, matched = guard.scan(
            cfn_dir=self.cfn_dir, templates=["synthetic.yaml"], exceptions={}
        )
        flagged_ids = {f.logical_id for f in findings}
        self.assertNotIn("SyntheticSafeRule", flagged_ids)
        self.assertNotIn("SyntheticRefRule", flagged_ids)
        self.assertNotIn("SyntheticLiteralRule", flagged_ids)
        self.assertEqual(tally["suffix_match"], 1)  # SyntheticSafeRule
        self.assertEqual(tally["dynamic_ref"], 1)  # SyntheticRefRule
        self.assertEqual(tally["skip_not_plane_context"], 1)  # SyntheticLiteralRule

    def test_declaring_an_exception_for_the_hazard_reclassifies_it(self):
        """Proves the exception path fires rather than silently vanishing."""
        exceptions = {
            ("synthetic.yaml", "SyntheticHazardRule", "Targets[0].Arn"): {
                "arn": "arn:aws:lambda:us-west-2:356364570033:function:definitely-not-an-excepted-function",
                "owning_repo": "some/other-repo",
                "ruling": "test ruling",
                "owner_record": "TEST-1",
            }
        }
        findings, tally, matched = guard.scan(
            cfn_dir=self.cfn_dir, templates=["synthetic.yaml"], exceptions=exceptions
        )
        self.assertEqual(tally["violation"], 0)
        self.assertEqual(tally["not_applicable_on_plane"], 1)
        excepted = [f for f in findings if f.state == "NOT_APPLICABLE_ON_PLANE"]
        self.assertEqual(len(excepted), 1)
        self.assertEqual(excepted[0].logical_id, "SyntheticHazardRule")
        self.assertIn(("synthetic.yaml", "SyntheticHazardRule", "Targets[0].Arn"), matched)

    def test_wrong_arn_in_exception_does_not_suppress_the_violation(self):
        """A stale/mistyped exception ARN must not silently swallow a real hazard."""
        exceptions = {
            ("synthetic.yaml", "SyntheticHazardRule", "Targets[0].Arn"): {
                "arn": "arn:aws:lambda:us-west-2:356364570033:function:some-other-name",
                "owning_repo": "some/other-repo",
                "ruling": "test ruling",
                "owner_record": "TEST-1",
            }
        }
        findings, tally, matched = guard.scan(
            cfn_dir=self.cfn_dir, templates=["synthetic.yaml"], exceptions=exceptions
        )
        self.assertEqual(tally["violation"], 1)
        self.assertEqual(matched, set())


class TestGuardOnRealTree(unittest.TestCase):
    """Negative control: the real templates, run through the actual CLI."""

    def test_current_templates_pass(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_cross_plane_arn_isolation.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[SUCCESS]", result.stdout)

    def test_coverage_is_reported_not_silent(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_cross_plane_arn_isolation.py")],
            capture_output=True,
            text=True,
        )
        self.assertIn("resources scanned (invoke-target-bearing types):", result.stdout)
        self.assertIn("skipped -- not a plane-suffixed context:", result.stdout)
        self.assertIn("dynamic ref (Ref/GetAtt/ImportValue, same-stack, trusted):", result.stdout)
        self.assertIn("recorded exceptions still in force:", result.stdout)

    def test_project_json_sync_rule_fires_as_not_applicable_on_plane(self):
        """The known real-world hazard must surface, not vanish, on the real tree."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_cross_plane_arn_isolation.py")],
            capture_output=True,
            text=True,
        )
        self.assertIn("NOT_APPLICABLE_ON_PLANE", result.stdout)
        self.assertIn("ProjectJsonSyncRule", result.stdout)
        self.assertIn("devops-json-to-parquet-transformer", result.stdout)
        self.assertIn("NX-2021-L/devops", result.stdout)

    def test_every_exception_names_an_owning_record(self):
        """Debt with nobody's name on it is how ENC-ISS-660-class hazards stay invisible."""
        exceptions = guard._load_exceptions()
        self.assertTrue(exceptions)
        for entry in exceptions.values():
            self.assertTrue(entry.get("owner_record"), entry)
            self.assertTrue(entry.get("owning_repo"), entry)
            self.assertTrue(entry.get("ruling"), entry)
            self.assertGreater(len(entry.get("reason", "")), 80, entry)

    def test_no_gamma_conditioned_resource_targets_a_hardcoded_literal(self):
        """The specific disaster class the ruling names: gamma writing into a fixed target."""
        exceptions = guard._load_exceptions()
        findings, tally, matched = guard.scan(exceptions=exceptions)
        for f in findings:
            if f.state != "VIOLATION":
                continue
            self.fail(f"Unexpected violation on the real tree: {f.line()} -- {f.detail}")


class TestHelpers(unittest.TestCase):
    def test_sub_text_extracts_scalar_and_list_form(self):
        self.assertEqual(guard._sub_text("plain-string"), "plain-string")
        self.assertEqual(guard._sub_text({"!Sub": "templated${X}"}), "templated${X}")
        self.assertEqual(guard._sub_text({"!Sub": ["templated${X}", {"X": "y"}]}), "templated${X}")
        self.assertIsNone(guard._sub_text({"!Ref": "Something"}))
        self.assertIsNone(guard._sub_text(None))

    def test_is_dynamic_ref_recognises_all_three_tags(self):
        self.assertTrue(guard._is_dynamic_ref({"!Ref": "X"}))
        self.assertTrue(guard._is_dynamic_ref({"!GetAtt": ["X", "Arn"]}))
        self.assertTrue(guard._is_dynamic_ref({"!ImportValue": "X"}))
        self.assertFalse(guard._is_dynamic_ref({"!Sub": "arn:aws:lambda:x"}))
        self.assertFalse(guard._is_dynamic_ref("plain-string"))

    def test_contains_env_suffix_token_searches_recursively(self):
        self.assertTrue(guard._contains_env_suffix_token("x${EnvironmentSuffix}"))
        self.assertTrue(guard._contains_env_suffix_token({"a": {"b": ["c", "x${EnvironmentSuffix}"]}}))
        self.assertFalse(guard._contains_env_suffix_token({"a": {"!Ref": "Something"}}))
        self.assertFalse(guard._contains_env_suffix_token(None))

    def test_resolve_property_paths_walks_dotted_and_indexed_segments(self):
        props = {"Target": {"Arn": "literal-arn"}}
        self.assertEqual(guard._resolve_property_paths(props, "Target.Arn"), [("Target.Arn", "literal-arn")])

        props = {"Targets": [{"Arn": "a1"}, {"Arn": "a2"}]}
        self.assertEqual(
            guard._resolve_property_paths(props, "Targets[].Arn"),
            [("Targets[0].Arn", "a1"), ("Targets[1].Arn", "a2")],
        )

        self.assertEqual(guard._resolve_property_paths({}, "Missing.Arn"), [])

    def test_resolve_pseudo_substitutes_account_and_region(self):
        rendered = guard._resolve_pseudo("arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:x")
        self.assertEqual(rendered, "arn:aws:lambda:us-west-2:356364570033:function:x")


if __name__ == "__main__":
    unittest.main()
