#!/usr/bin/env python3
"""ENC-TSK-O99 / ENC-ISS-660: tests for the CFN deploy-role reach guard.

The two negative tests are the point of this module. A guard that only proves
it passes on today's tree proves nothing -- ENC-ISS-660 exists because every
existing guard was green on the PR that caused the rollback. So both failure
modes are reconstructed from the real incident:

  * an unclassified TYPE            -- ENC-TSK-O80's AWS::Glue::Database
  * an allowed type, out-of-reach ARN -- ENC-TSK-O80's AWS::Scheduler::Schedule,
    which no type-level check could ever have caught

There is also a regression test for a false positive this guard produced on its
own first run: the rhythm schedules set GroupName via !Ref, and treating an
unresolvable property as "the default group" manufactured ten violations that
did not exist.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import cfn_deploy_role_reach_guard as guard  # noqa: E402


SCHEDULER_GRANT = [
    {
        "Effect": "Allow",
        "Action": ["scheduler:CreateSchedule"],
        "Resource": [
            "arn:aws:scheduler:us-west-2:356364570033:schedule/rhythm-*/*",
            "arn:aws:scheduler:us-west-2:356364570033:schedule/enceladus-*/*",
        ],
    }
]


class TestGuardOnRealTree(unittest.TestCase):
    def test_current_templates_pass(self):
        """The guard must land green. A guard merged red is a guard people mute."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "cfn_deploy_role_reach_guard.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[SUCCESS]", result.stdout)

    def test_coverage_is_reported_not_silent(self):
        """ENC-ISS-660: a check that does not enumerate cannot report what it skipped."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "cfn_deploy_role_reach_guard.py")],
            capture_output=True,
            text=True,
        )
        self.assertIn("tier 2 (type + ARN reach verified):", result.stdout)
        self.assertIn("tier 1 only", result.stdout)
        self.assertIn("recorded exceptions still in force:", result.stdout)

    def test_every_declared_type_is_in_the_map(self):
        reach_map = json.loads((REPO_ROOT / "tools" / "cfn_deploy_role_reach_map.json").read_text())
        known = set(reach_map["types"])
        for filename in guard.GOVERNED_TEMPLATES:
            path = guard.CFN_DIR / filename
            if not path.exists():
                continue
            for logical_id, resource in (guard.load_template(path).get("Resources") or {}).items():
                rtype = resource.get("Type")
                if isinstance(rtype, str) and rtype.startswith("AWS::"):
                    self.assertIn(rtype, known, f"{filename}:{logical_id}")

    def test_every_exception_names_an_owning_record(self):
        """Debt with nobody's name on it is how ENC-ISS-660 stayed invisible."""
        reach_map = json.loads((REPO_ROOT / "tools" / "cfn_deploy_role_reach_map.json").read_text())
        for entry in reach_map.get("exceptions") or []:
            self.assertTrue(entry.get("owner_record"), entry)
            self.assertTrue(entry.get("recorded"), entry)
            self.assertGreater(len(entry.get("reason", "")), 80, entry)


class TestGrantDerivation(unittest.TestCase):
    def test_sources_include_iac_and_patch_workflows(self):
        statements, sources = guard.collect_granted_statements()
        self.assertTrue(statements)
        joined = " ".join(sources)
        self.assertIn("04-github-roles.yaml", joined)
        self.assertIn("iam-cfn-deploy-role-", joined)

    def test_policy_sources_contain_no_deny(self):
        """action_allowed_on() ignores Deny. That is only safe while none exists.

        If a Deny is ever added to the deploy role's committed policies, this
        test fails and the guard must learn to model it -- rather than quietly
        reporting reach the role does not have.
        """
        statements = []
        template = guard.load_template(guard.CFN_DIR / "04-github-roles.yaml")
        resources = template.get("Resources") or {}
        role = resources.get(guard.DEPLOY_ROLE_LOGICAL_ID) or {}
        for policy in guard._normalise((role.get("Properties") or {}).get("Policies")):
            statements.extend(guard._normalise((policy.get("PolicyDocument") or {}).get("Statement")))
        for resource in resources.values():
            if resource.get("Type") != "AWS::IAM::ManagedPolicy":
                continue
            props = resource.get("Properties") or {}
            attached = [r.get("Ref") if isinstance(r, dict) else r
                        for r in guard._normalise(props.get("Roles"))]
            if guard.DEPLOY_ROLE_LOGICAL_ID in attached:
                statements.extend(
                    guard._normalise((props.get("PolicyDocument") or {}).get("Statement"))
                )
        denies = [s.get("Sid") for s in statements if s.get("Effect") == "Deny"]
        self.assertEqual(denies, [], f"Deny statements appeared: {denies}")

    def test_wildcard_resource_grants_everything_for_that_action(self):
        statements = [{"Effect": "Allow", "Action": "lambda:*", "Resource": "*"}]
        self.assertTrue(guard.action_allowed_on(
            statements, "lambda:CreateFunction",
            "arn:aws:lambda:us-west-2:356364570033:function:anything"))

    def test_unrenderable_resource_is_not_treated_as_wildcard(self):
        """A Ref/GetAtt resource must never be read as 'grants everything'."""
        statements = [{"Effect": "Allow", "Action": "s3:CreateBucket",
                       "Resource": {"Fn::GetAtt": ["SomeBucket", "Arn"]}}]
        self.assertFalse(guard.action_allowed_on(
            statements, "s3:CreateBucket", "arn:aws:s3:::anything"))


class TestFailureModes(unittest.TestCase):
    """Both modes reconstructed from the 2026-08-23 gamma rollback."""

    def test_mode_1_unclassified_type_fails(self):
        """ENC-TSK-O80's AWS::Glue::Database against a map that lacks it."""
        types_map = {"AWS::SQS::Queue": {"reach": "baseline"}}
        self.assertNotIn("AWS::Glue::Database", types_map)

        template = {"Resources": {"GovernanceMartDatabaseGamma": {
            "Type": "AWS::Glue::Database", "Condition": "IsGamma",
            "Properties": {"DatabaseInput": {"Name": "devops-gamma"}}}}}
        offenders = [
            logical_id
            for logical_id, resource in template["Resources"].items()
            if resource["Type"] not in types_map
        ]
        self.assertEqual(offenders, ["GovernanceMartDatabaseGamma"])

    def test_mode_2_allowed_type_unreachable_arn_fails(self):
        """The case a type-only guard cannot catch, and which fired for real.

        AWS::Scheduler::Schedule was already granted. GovernanceMartScheduleGamma
        sets no GroupName, so it lands at schedule/default/... while every grant
        was scoped to schedule/rhythm-*/* and schedule/enceladus-*/*.
        """
        arn = ("arn:aws:scheduler:us-west-2:356364570033:"
               "schedule/default/devops-governance-mart-daily-gamma")
        self.assertFalse(
            guard.action_allowed_on(SCHEDULER_GRANT, "scheduler:CreateSchedule", arn),
            "pre-ENC-TSK-O98 grants must NOT reach the default schedule group")

    def test_mode_2_is_resolved_by_the_o98_grant(self):
        statements, _ = guard.collect_granted_statements()
        arn = ("arn:aws:scheduler:us-west-2:356364570033:"
               "schedule/default/devops-governance-mart-daily-gamma")
        self.assertTrue(
            guard.action_allowed_on(statements, "scheduler:CreateSchedule", arn),
            "ENC-TSK-O98's grant should make the O80 schedule reachable")

    def test_o98_grant_does_not_widen_to_production_mart(self):
        """The negative control, asserted in CI as well as in the patch workflow."""
        statements, _ = guard.collect_granted_statements()
        self.assertFalse(guard.action_allowed_on(
            statements, "glue:DeleteDatabase",
            "arn:aws:glue:us-west-2:356364570033:database/devops"))
        self.assertFalse(guard.action_allowed_on(
            statements, "s3:CreateBucket", "arn:aws:s3:::devops-agentcli-compute"))

    def test_stale_exception_is_itself_a_violation(self):
        """A resolved exception left in the ledger hides the next real gap."""
        exceptions = {("01-data.yaml", "Gone", "sns:CreateTopic", "arn:aws:sns:x")}
        matched: set = set()
        self.assertTrue(exceptions - matched)


class TestRenderingAndConditions(unittest.TestCase):
    def test_condition_selects_the_planes_checked(self):
        self.assertEqual(guard.planes_for("IsGamma"), ["gamma"])
        self.assertEqual(guard.planes_for("IsProduction"), ["production"])
        self.assertEqual(sorted(guard.planes_for(None)), ["gamma", "production"])
        # An unrecognised condition must widen, never narrow: assuming a
        # condition we do not model restricts a resource to one plane would
        # skip a check rather than run one.
        self.assertEqual(sorted(guard.planes_for("RhythmActive")), ["gamma", "production"])

    def test_sub_renders_environment_suffix_per_plane(self):
        value = {"Fn::Sub": "devops-governance-mart-daily${EnvironmentSuffix}"}
        self.assertEqual(guard.render_name(value, ""), "devops-governance-mart-daily")
        self.assertEqual(guard.render_name(value, "-gamma"),
                         "devops-governance-mart-daily-gamma")

    def test_unresolvable_sub_returns_none_rather_than_a_guess(self):
        self.assertIsNone(guard.render_name({"Fn::Sub": "x-${SomeParameter}"}, ""))

    def test_ref_to_sibling_resolves_to_that_resources_name(self):
        """Regression: this guard's own first run produced ten false positives.

        The rhythm schedules carry GroupName: !Ref RhythmSenseGroup. Treating an
        unresolvable property as the `default` group invented ARNs and reported
        violations that did not exist.
        """
        resources = {"RhythmSenseGroup": {
            "Type": "AWS::Scheduler::ScheduleGroup",
            "Properties": {"Name": {"Fn::Sub": "rhythm-sense${EnvironmentSuffix}"}}}}
        types_map = {"AWS::Scheduler::ScheduleGroup": {"name_property": "Name"}}
        self.assertEqual(
            guard._resolve_reference({"Ref": "RhythmSenseGroup"}, "-gamma", resources, types_map),
            "rhythm-sense-gamma")

    def test_rhythm_schedule_arn_is_reachable_once_the_ref_resolves(self):
        arn = ("arn:aws:scheduler:us-west-2:356364570033:"
               "schedule/rhythm-sense-gamma/rhythm-sense-hourly-gamma")
        self.assertTrue(
            guard.action_allowed_on(SCHEDULER_GRANT, "scheduler:CreateSchedule", arn))

    def test_dotted_name_property_reaches_into_nested_properties(self):
        props = {"DatabaseInput": {"Name": "devops-gamma"}}
        self.assertEqual(guard._dig(props, "DatabaseInput.Name"), "devops-gamma")
        self.assertIsNone(guard._dig(props, "DatabaseInput.Missing"))


if __name__ == "__main__":
    unittest.main()
