"""ENC-TSK-R31 (C2.7): self-tests for the persistent-cost CI guard.

One positive (must flag) and one negative (must not flag) case per resource
type, plus the diff semantics (only ADDED logical ids), the label approval
path, CFN short-form tag parsing, and an end-to-end run against a throwaway
git repo. Also parses every real template as a smoke test.

Run: python3 -m unittest tools.test_cost_resource_guard -v
"""

import io
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from tools import cost_resource_guard as g

ROOT = Path(__file__).resolve().parent.parent


def tpl(logical_id, rtype, props=None, **extra):
    res = {"Type": rtype}
    if props is not None:
        res["Properties"] = props
    res.update(extra)
    return {"Resources": {logical_id: res}}


def flagged(template, base=None):
    return g.find_findings(base or {}, template, "t.yaml")


# (case name, resource type, properties, expect flagged)
CASES = [
    ("secret+", "AWS::SecretsManager::Secret", {"Name": "x"}, True),
    ("kms+", "AWS::KMS::Key", {"KeyPolicy": {}}, True),
    ("nat+", "AWS::EC2::NatGateway", {"SubnetId": "s"}, True),
    ("vpce_interface+", "AWS::EC2::VPCEndpoint", {"VpcEndpointType": "Interface"}, True),
    ("vpce_gateway-", "AWS::EC2::VPCEndpoint", {"VpcEndpointType": "Gateway"}, False),
    ("vpce_default-", "AWS::EC2::VPCEndpoint", {"ServiceName": "s3"}, False),
    ("instance+", "AWS::EC2::Instance", {"InstanceType": "t4g.micro"}, True),
    ("eip+", "AWS::EC2::EIP", {"Domain": "vpc"}, True),
    ("alarm+", "AWS::CloudWatch::Alarm", {"MetricName": "m"}, True),
    ("ddb+", "AWS::DynamoDB::Table", {"BillingMode": "PAY_PER_REQUEST"}, True),
    ("rule_rate_minutes+", "AWS::Events::Rule", {"ScheduleExpression": "rate(30 minutes)"}, True),
    ("rule_rate_hour+", "AWS::Events::Rule", {"ScheduleExpression": "rate(1 hour)"}, True),
    ("rule_cron_hourly+", "AWS::Events::Rule", {"ScheduleExpression": "cron(0 * * * ? *)"}, True),
    ("rule_cron_twice+", "AWS::Events::Rule", {"ScheduleExpression": "cron(0 6,18 * * ? *)"}, True),
    ("rule_daily_cron-", "AWS::Events::Rule", {"ScheduleExpression": "cron(0 3 * * ? *)"}, False),
    ("rule_rate_day-", "AWS::Events::Rule", {"ScheduleExpression": "rate(1 day)"}, False),
    ("rule_rate_24h-", "AWS::Events::Rule", {"ScheduleExpression": "rate(24 hours)"}, False),
    ("rule_pattern_only-", "AWS::Events::Rule", {"EventPattern": {"source": ["x"]}}, False),
    ("sched_rate+", "AWS::Scheduler::Schedule", {"ScheduleExpression": "rate(5 minutes)"}, True),
    ("sched_cron_daily-", "AWS::Scheduler::Schedule", {"ScheduleExpression": "cron(0 5 * * ? *)"}, False),
    ("sched_at-", "AWS::Scheduler::Schedule", {"ScheduleExpression": "at(2030-01-01T00:00:00)"}, False),
    ("s3_versioned_no_ncv+", "AWS::S3::Bucket",
     {"VersioningConfiguration": {"Status": "Enabled"}}, True),
    ("s3_versioned_other_rule+", "AWS::S3::Bucket",
     {"VersioningConfiguration": {"Status": "Enabled"},
      "LifecycleConfiguration": {"Rules": [{"Status": "Enabled", "ExpirationInDays": 30}]}}, True),
    ("s3_versioned_with_ncv-", "AWS::S3::Bucket",
     {"VersioningConfiguration": {"Status": "Enabled"},
      "LifecycleConfiguration": {"Rules": [
          {"Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]}}, False),
    ("s3_versioned_ncv_days-", "AWS::S3::Bucket",
     {"VersioningConfiguration": {"Status": "Enabled"},
      "LifecycleConfiguration": {"Rules": [
          {"Status": "Enabled", "NoncurrentVersionExpirationInDays": 30}]}}, False),
    ("s3_unversioned-", "AWS::S3::Bucket", {"BucketName": "b"}, False),
    ("s3_suspended-", "AWS::S3::Bucket", {"VersioningConfiguration": {"Status": "Suspended"}}, False),
    ("loggroup_no_retention+", "AWS::Logs::LogGroup", {"LogGroupName": "/x"}, True),
    ("loggroup_retention-", "AWS::Logs::LogGroup", {"LogGroupName": "/x", "RetentionInDays": 30}, False),
    ("loggroup_retention_ref-", "AWS::Logs::LogGroup", {"RetentionInDays": {"Ref": "Retention"}}, False),
    ("ecr_no_policy+", "AWS::ECR::Repository", {"RepositoryName": "r"}, True),
    ("ecr_policy-", "AWS::ECR::Repository",
     {"RepositoryName": "r", "LifecyclePolicy": {"LifecyclePolicyText": "{}"}}, False),
    ("lambda_active+", "AWS::Lambda::Function", {"TracingConfig": {"Mode": "Active"}}, True),
    ("lambda_if_gamma_active+", "AWS::Lambda::Function",
     {"TracingConfig": {"Mode": {"Fn::If": ["IsGamma", "Active", "PassThrough"]}}}, True),
    ("lambda_whole_if_gamma_active+", "AWS::Lambda::Function",
     {"TracingConfig": {"Fn::If": ["IsGamma", {"Mode": "Active"}, {"Mode": "PassThrough"}]}}, True),
    ("lambda_if_unknown_cond+", "AWS::Lambda::Function",
     {"TracingConfig": {"Mode": {"Fn::If": ["SomeFlag", "Active", "PassThrough"]}}}, True),
    ("lambda_passthrough-", "AWS::Lambda::Function", {"TracingConfig": {"Mode": "PassThrough"}}, False),
    ("lambda_if_gamma_passthrough-", "AWS::Lambda::Function",
     {"TracingConfig": {"Mode": {"Fn::If": ["IsGamma", "PassThrough", "Active"]}}}, False),
    ("lambda_no_tracing-", "AWS::Lambda::Function", {"Runtime": "python3.11"}, False),
    ("serverless_tracing_active+", "AWS::Serverless::Function", {"Tracing": "Active"}, True),
    ("serverless_passthrough-", "AWS::Serverless::Function", {"Tracing": "PassThrough"}, False),
    ("unrelated_type-", "AWS::IAM::Role", {"AssumeRolePolicyDocument": {}}, False),
]


class RuleCases(unittest.TestCase):
    def test_positive_and_negative_per_resource_type(self):
        for name, rtype, props, expect in CASES:
            with self.subTest(name):
                found = flagged(tpl("R", rtype, props))
                self.assertEqual(bool(found), expect, f"{name}: {found}")
                if expect:
                    self.assertEqual(found[0][1:3], ("R", rtype))

    def test_every_rule_has_a_positive_and_negative_case(self):
        covered_pos = {rt for _, rt, _, e in CASES if e}
        covered_neg = {rt for _, rt, _, e in CASES if not e}
        # always-flag types have no config-dependent negative; prove the negative via
        # the "not added" diff instead (see DiffSemantics).
        always = {"AWS::SecretsManager::Secret", "AWS::KMS::Key", "AWS::EC2::NatGateway",
                  "AWS::EC2::Instance", "AWS::EC2::EIP", "AWS::CloudWatch::Alarm",
                  "AWS::DynamoDB::Table"}
        self.assertEqual(set(g.RULES) - covered_pos, set())
        self.assertEqual(set(g.RULES) - covered_neg - always, set())

    def test_schedule_parser(self):
        f = g.schedule_faster_than_daily
        self.assertTrue(f("rate(59 minutes)"))
        self.assertTrue(f("rate(23 hours)"))
        self.assertFalse(f("rate(1 days)"))
        self.assertFalse(f("rate(1440 minutes)"))
        self.assertTrue(f("cron(*/15 * * * ? *)"))
        self.assertTrue(f("cron(0 0-5 * * ? *)"))
        self.assertTrue(f("cron(0,30 3 * * ? *)"))
        self.assertFalse(f("cron(15 10 ? * MON-FRI *)"))
        self.assertIsNone(f("cron(bogus)"))
        self.assertIsNone(f({"Ref": "X"}))

    def test_schedule_param_default_is_resolved(self):
        t = {"Parameters": {"Cadence": {"Type": "String", "Default": "rate(10 minutes)"}},
             "Resources": {"R": {"Type": "AWS::Events::Rule",
                                 "Properties": {"ScheduleExpression": {"Ref": "Cadence"}}}}}
        self.assertEqual(len(flagged(t)), 1)
        t["Parameters"]["Cadence"]["Default"] = "cron(0 3 * * ? *)"
        self.assertEqual(flagged(t), [])


class DiffSemantics(unittest.TestCase):
    def test_existing_resource_is_not_flagged(self):
        t = tpl("Alarm1", "AWS::CloudWatch::Alarm", {"MetricName": "m"})
        self.assertEqual(flagged(t, base=t), [])

    def test_modified_existing_resource_is_not_flagged(self):
        base = tpl("Alarm1", "AWS::CloudWatch::Alarm", {"MetricName": "m"})
        head = tpl("Alarm1", "AWS::CloudWatch::Alarm", {"MetricName": "other"})
        self.assertEqual(flagged(head, base=base), [])

    def test_only_added_ids_flagged(self):
        base = tpl("Alarm1", "AWS::CloudWatch::Alarm", {"MetricName": "m"})
        head = {"Resources": {**base["Resources"],
                              "Alarm2": {"Type": "AWS::CloudWatch::Alarm", "Properties": {}},
                              "Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}}}
        found = flagged(head, base=base)
        self.assertEqual([f[1] for f in found], ["Alarm2"])

    def test_new_template_flags_everything(self):
        self.assertEqual(len(flagged(tpl("K", "AWS::KMS::Key", {}))), 1)


class CfnTags(unittest.TestCase):
    YAML = """
Parameters:
  EnvironmentSuffix: {Type: String, Default: ""}
Conditions:
  IsGamma: !Not [!Equals [!Ref EnvironmentSuffix, ""]]
Resources:
  BadFn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "f${EnvironmentSuffix}"
      Role: !GetAtt Role.Arn
      TracingConfig:
        Mode: !If [IsGamma, Active, PassThrough]
  GoodFn:
    Type: AWS::Lambda::Function
    Properties:
      TracingConfig:
        Mode: !If [IsGamma, PassThrough, Active]
  Logs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/f${EnvironmentSuffix}"
"""

    def test_short_form_tags_parse_and_evaluate(self):
        t = g.load_template_text(self.YAML)
        ids = sorted(f[1] for f in flagged(t))
        self.assertEqual(ids, ["BadFn", "Logs"])

    def test_non_template_json_is_ignored(self):
        self.assertEqual(g.load_template_text('{"imports": [1, 2]}'), {})


class Cli(unittest.TestCase):
    def run_main(self, argv, env=None):
        buf = io.StringIO()
        with unittest.mock.patch.dict("os.environ", env or {}, clear=False), \
                unittest.mock.patch("sys.stdout", buf):
            rc = g.main(argv)
        return rc, buf.getvalue()

    def test_file_mode_fails_then_label_approves(self):
        with tempfile.TemporaryDirectory() as d:
            new = Path(d) / "new.yaml"
            new.write_text("Resources:\n  K:\n    Type: AWS::KMS::Key\n    Properties: {}\n")
            rc, out = self.run_main(["--head-file", str(new)], {"GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 1)
            self.assertEqual(out.count("FAIL "), 1)
            rc, out = self.run_main(["--head-file", str(new), "--cost-approved"], {"GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 0)
            self.assertIn("APPROVED", out)
            rc, _ = self.run_main(["--head-file", str(new)], {"COST_APPROVED": "true", "GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 0)

    def test_github_annotation_form(self):
        line = g.format_finding(("f.yaml", "K", "AWS::KMS::Key", "r"), annotate=True)
        self.assertTrue(line.startswith("::error file=f.yaml"))
        line = g.format_finding(("f.yaml", "K", "AWS::KMS::Key", "r"), annotate=True, approved=True)
        self.assertTrue(line.startswith("::notice file=f.yaml"))

    def test_git_mode_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                               cwd=d, check=True, capture_output=True)
            git("init", "-q", "-b", "main")
            infra = Path(d) / "infrastructure" / "cloudformation"
            infra.mkdir(parents=True)
            (infra / "a.yaml").write_text(
                "Resources:\n  Old:\n    Type: AWS::CloudWatch::Alarm\n    Properties: {}\n")
            (infra / "map.json").write_text('{"imports": []}')
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
            git("checkout", "-q", "-b", "pr")
            (infra / "a.yaml").write_text(
                "Resources:\n  Old:\n    Type: AWS::CloudWatch::Alarm\n    Properties: {}\n"
                "  New:\n    Type: AWS::DynamoDB::Table\n    Properties: {}\n"
                "  Fine:\n    Type: AWS::SQS::Queue\n    Properties: {}\n")
            (infra / "b.yaml").write_text(
                "Resources:\n  Grp:\n    Type: AWS::Logs::LogGroup\n    Properties: {}\n")
            (infra / "map.json").write_text('{"imports": [1]}')
            git("add", "-A")
            git("commit", "-q", "-m", "head")
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
            findings, warnings = g.diff_git(base, head, d)
            self.assertEqual(sorted((f[0].split("/")[-1], f[1]) for f in findings),
                             [("a.yaml", "New"), ("b.yaml", "Grp")])
            self.assertEqual(warnings, [])
            rc, out = self.run_main(["--base", base, "--head", head, "--repo-root", d],
                                    {"GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 1)
            self.assertEqual(out.count("FAIL "), 2)
            rc, _ = self.run_main(["--base", base, "--head", head, "--repo-root", d, "--cost-approved"],
                                  {"GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 0)
            rc, _ = self.run_main(["--base", head, "--head", head, "--repo-root", d], {"GITHUB_ACTIONS": ""})
            self.assertEqual(rc, 0)


class RealTemplates(unittest.TestCase):
    def test_every_real_template_parses_and_identity_diff_is_clean(self):
        paths = sorted((ROOT / "infrastructure" / "cloudformation").glob("*.yaml"))
        self.assertTrue(paths)
        for p in paths:
            with self.subTest(p.name):
                t = g.load_template_text(p.read_text())
                self.assertTrue(t, f"{p.name} did not parse as a template")
                self.assertEqual(g.find_findings(t, t, p.name), [])


if __name__ == "__main__":
    unittest.main()
