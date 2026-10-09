#!/usr/bin/env python3
"""Self-tests for tools/cfn_changeset_replacement_gate.sh (ENC-TSK-Q22, ENC-TSK-Q59).

Each case stubs the ``aws`` CLI on PATH with a script that prints a fixture
describe-change-set page, runs the gate, and checks its exit code. The fixtures
mirror the two live shapes that motivated ENC-PLN-097 rulings R7 and R8:

- R8 (benign): an Environment edit on a Lambda re-evaluates Events::Rule
  Targets (Replacement=False), which re-evaluates Lambda::Permission SourceArn
  (create-only, Replacement=Conditional). Gamma change-set 614bd143, 2026-10-09.
- R7 (refused): a Pipe FilterCriteria edit changes SourceParameters
  (Static/DirectModification, RequiresRecreation=Conditionally).

Usage:
    python3 tools/test_cfn_changeset_replacement_gate.py
"""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

GATE = pathlib.Path(__file__).resolve().parent / "cfn_changeset_replacement_gate.sh"


def change(logical_id, replacement, details, action="Modify"):
    return {
        "Type": "Resource",
        "ResourceChange": {
            "Action": action,
            "LogicalResourceId": logical_id,
            "Replacement": replacement,
            "Details": details,
        },
    }


def detail(name, requires, evaluation, source, causing=None):
    d = {
        "Target": {"Attribute": "Properties", "Name": name, "RequiresRecreation": requires},
        "Evaluation": evaluation,
        "ChangeSource": source,
    }
    if causing:
        d["CausingEntity"] = causing
    return d


def ripple(name, causing, requires="Always"):
    return detail(name, requires, "Dynamic", "ResourceAttribute", causing)


ENV_EDIT = detail("Environment", "Never", "Static", "DirectModification")

R8_RIPPLE = [
    change("CoordinationApiFunction", "False", [ENV_EDIT]),
    change("IdleSweepSchedule", "False", [ripple("Targets", "CoordinationApiFunction.Arn", "Never")]),
    change("IdleSweepPermission", "Conditional", [ripple("SourceArn", "IdleSweepSchedule.Arn")]),
    change("PollerRule", "False", [ripple("Targets", "CoordinationApiFunction.Arn", "Never")]),
    change("PollerPermission", "Conditional", [ripple("SourceArn", "PollerRule.Arn")]),
]

R7_STATIC = [
    change("TrackerToFeedPipe", "False", [detail("TargetParameters", "Never", "Static", "DirectModification")]),
    change(
        "TrackerToGraphPipe",
        "Conditional",
        [
            detail("TargetParameters", "Never", "Static", "DirectModification"),
            detail("SourceParameters", "Conditionally", "Static", "DirectModification"),
        ],
    ),
]


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fixture = os.path.join(self.tmp, "changes.json")
        stub = os.path.join(self.tmp, "aws")
        with open(stub, "w") as fh:
            fh.write('#!/usr/bin/env bash\ncat "$GATE_FIXTURE"\n')
        os.chmod(stub, 0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_gate(self, changes, acknowledge="false"):
        with open(self.fixture, "w") as fh:
            json.dump({"Changes": changes}, fh)
        env = dict(os.environ)
        env.update(
            {
                "PATH": f"{self.tmp}:{env.get('PATH', '')}",
                "GATE_FIXTURE": self.fixture,
                "AWS_REGION": "us-west-2",
            }
        )
        env.pop("GITHUB_STEP_SUMMARY", None)
        return subprocess.run(
            ["bash", str(GATE), "test-stack", "arn:test", acknowledge],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_no_changes_passes(self):
        self.assertEqual(self.run_gate([]).returncode, 0)

    def test_arn_ripple_from_non_replaced_resources_passes(self):
        res = self.run_gate(R8_RIPPLE)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("0 replacements", res.stdout)
        self.assertIn("IdleSweepPermission", res.stdout)  # listed as benign, not hidden

    def test_static_conditional_is_refused(self):
        res = self.run_gate(R7_STATIC)
        self.assertEqual(res.returncode, 1)
        self.assertIn("TrackerToGraphPipe", res.stdout)

    def test_ripple_from_replaced_resource_is_refused(self):
        changes = [
            change("Rule", "True", [detail("Name", "Always", "Static", "DirectModification")]),
            change("RulePermission", "Conditional", [ripple("SourceArn", "Rule.Arn")]),
        ]
        res = self.run_gate(changes)
        self.assertEqual(res.returncode, 1)
        self.assertIn("2 replacements", res.stdout)

    def test_ripple_on_non_arn_attribute_is_refused(self):
        changes = [
            change("Fn", "False", [ENV_EDIT]),
            change("Perm", "Conditional", [ripple("FunctionName", "FnVersion.Version")]),
        ]
        self.assertEqual(self.run_gate(changes).returncode, 1)

    def test_transitive_ripple_from_hard_conditional_is_refused(self):
        changes = [
            change("Pipe", "Conditional", [detail("SourceParameters", "Conditionally", "Static", "DirectModification")]),
            change("Downstream", "Conditional", [ripple("SourceArn", "Pipe.Arn")]),
        ]
        res = self.run_gate(changes)
        self.assertEqual(res.returncode, 1)
        self.assertIn("2 replacements", res.stdout)

    def test_removal_is_refused(self):
        changes = [change("Old", None, [], action="Remove")]
        self.assertEqual(self.run_gate(changes).returncode, 1)

    def test_acknowledge_allows_real_replacement(self):
        self.assertEqual(self.run_gate(R7_STATIC, acknowledge="true").returncode, 0)


if __name__ == "__main__":
    unittest.main()
