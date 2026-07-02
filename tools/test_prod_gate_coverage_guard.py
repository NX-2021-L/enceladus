"""ENC-TSK-J65: tests for the prod-gate coverage guard.

Happy path runs the guard against the REAL repo state (must be green -- that
is itself the invariant). The negative tests build synthetic fixtures in a
tempdir and prove the guard detects each violation class (the ENC-TSK-H22
synthetic-strip-proof pattern): an ungated prod-mutating workflow, an
unclassified workflow, and a rotted grace entry.

Run: python3 -m unittest tools.test_prod_gate_coverage_guard -v
"""

import json
import tempfile
import unittest
from pathlib import Path

from tools.prod_gate_coverage_guard import check

GATED_WF = """
on:
  push:
    branches: [main]
jobs:
  deploy:
    environment: v3-prod
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
"""

UNGATED_WF = """
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
"""

CONDITIONAL_WF = """
on:
  push:
jobs:
  apply:
    environment: ${{ startsWith(github.ref, 'refs/heads/v4/') && 'v4-gamma' || 'v3-prod' }}
    runs-on: ubuntu-latest
    steps:
      - run: echo apply
"""


class _Fixture:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.workflows = root / "workflows"
        self.workflows.mkdir()
        self.baseline = root / "baseline.json"

    def add_workflow(self, name, content):
        (self.workflows / name).write_text(content)

    def write_baseline(self, workflows):
        self.baseline.write_text(json.dumps({"workflows": workflows}))

    def check(self):
        return check(workflows_dir=self.workflows, baseline_path=self.baseline)


class HappyPathAgainstRealRepo(unittest.TestCase):
    def test_real_repo_state_is_green(self):
        violations = check()
        self.assertEqual(violations, [], f"guard must be green on the shipped repo state: {violations}")


class NegativeFixtures(unittest.TestCase):
    def test_ungated_prod_mutating_workflow_fails(self):
        fx = _Fixture()
        fx.add_workflow("bad-deploy.yml", UNGATED_WF)
        fx.write_baseline({
            "bad-deploy.yml": {"class": "prod-mutating", "gated_jobs": ["deploy"], "notes": ""},
        })
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("bad-deploy.yml", violations[0])
        self.assertIn("environment: v3-prod", violations[0])

    def test_unclassified_workflow_fails_closed(self):
        fx = _Fixture()
        fx.add_workflow("mystery.yml", GATED_WF)
        fx.write_baseline({})
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("mystery.yml", violations[0])
        self.assertIn("NOT in", violations[0])

    def test_prod_mutating_empty_gated_jobs_without_grace_fails(self):
        fx = _Fixture()
        fx.add_workflow("naked.yml", UNGATED_WF)
        fx.write_baseline({
            "naked.yml": {"class": "prod-mutating", "gated_jobs": [], "notes": "no grace here"},
        })
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("grace marker", violations[0])

    def test_grace_entry_is_tolerated_while_ungated(self):
        fx = _Fixture()
        fx.add_workflow("pending.yml", UNGATED_WF)
        fx.write_baseline({
            "pending.yml": {"class": "prod-mutating", "gated_jobs": [], "notes": "owned by ENC-TSK-J63"},
        })
        self.assertEqual(fx.check(), [])

    def test_rotted_grace_entry_fails(self):
        # workflow gained a gate but the baseline still lists it as grace
        fx = _Fixture()
        fx.add_workflow("promoted.yml", GATED_WF)
        fx.write_baseline({
            "promoted.yml": {"class": "prod-mutating", "gated_jobs": [], "notes": "owned by ENC-TSK-J63"},
        })
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("promote its baseline entry", violations[0])

    def test_conditional_without_v3_prod_in_expression_fails(self):
        fx = _Fixture()
        fx.add_workflow("cond.yml", CONDITIONAL_WF.replace("v3-prod", "production"))
        fx.write_baseline({
            "cond.yml": {"class": "conditional", "gated_jobs": ["apply"], "notes": ""},
        })
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("containing 'v3-prod'", violations[0])

    def test_conditional_with_v3_prod_passes(self):
        fx = _Fixture()
        fx.add_workflow("cond.yml", CONDITIONAL_WF)
        fx.write_baseline({
            "cond.yml": {"class": "conditional", "gated_jobs": ["apply"], "notes": ""},
        })
        self.assertEqual(fx.check(), [])

    def test_baseline_naming_missing_job_fails(self):
        fx = _Fixture()
        fx.add_workflow("drift.yml", GATED_WF)
        fx.write_baseline({
            "drift.yml": {"class": "prod-mutating", "gated_jobs": ["nonexistent"], "notes": ""},
        })
        violations = fx.check()
        self.assertEqual(len(violations), 1)
        self.assertIn("does not exist", violations[0])


if __name__ == "__main__":
    unittest.main()
