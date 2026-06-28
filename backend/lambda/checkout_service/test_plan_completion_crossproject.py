"""ENC-ISS-417: plan completion gate (ENC-TSK-A89) must resolve cross-project
objectives in their OWN project partition, with parity to plan.objectives_status.

Regression for: a plan (project=enceladus) whose objectives_set contains a CLOSED
cross-project task (e.g. INT-TSK-071, project=intelligence) could never complete,
because the gate looked the objective up in the plan's own (enceladus) partition and
got not_found.
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "checkout_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = checkout_lambda
_SPEC.loader.exec_module(checkout_lambda)


_PREFIX_SCAN = {
    "Items": [
        {"project_id": {"S": "enceladus"}, "prefix": {"S": "ENC"}},
        {"project_id": {"S": "intelligence"}, "prefix": {"S": "INT"}},
    ]
}


def _reset_prefix_cache():
    checkout_lambda._PREFIX_MAP_CACHE = None
    checkout_lambda._PREFIX_MAP_CACHE_AT = 0.0


class ProjectForRecordIdTests(unittest.TestCase):
    def setUp(self):
        _reset_prefix_cache()

    def test_resolves_prefix_to_project(self):
        with mock.patch.object(checkout_lambda._ddb, "scan", return_value=_PREFIX_SCAN):
            self.assertEqual(
                checkout_lambda._project_for_record_id("INT-TSK-071", "enceladus"),
                "intelligence",
            )
            self.assertEqual(
                checkout_lambda._project_for_record_id("ENC-TSK-A89", "enceladus"),
                "enceladus",
            )

    def test_unmapped_prefix_falls_back_to_default(self):
        with mock.patch.object(checkout_lambda._ddb, "scan", return_value=_PREFIX_SCAN):
            self.assertEqual(
                checkout_lambda._project_for_record_id("ZZZ-TSK-001", "enceladus"),
                "enceladus",
            )

    def test_scan_failure_falls_back_to_default(self):
        with mock.patch.object(checkout_lambda._ddb, "scan", side_effect=RuntimeError("boom")):
            self.assertEqual(
                checkout_lambda._project_for_record_id("INT-TSK-071", "enceladus"),
                "enceladus",
            )


class PlanCompletionGateCrossProjectTests(unittest.TestCase):
    def setUp(self):
        _reset_prefix_cache()

    def test_closed_crossproject_objective_passes_gate(self):
        """All objectives closed incl. a cross-project one -> gate returns None (pass)."""
        plan = {"objectives_set": ["ENC-TSK-100", "INT-TSK-071"]}
        seen_projects = {}

        def _fake_get_task(project, obj_id):
            seen_projects[obj_id] = project
            return 200, {"status": "closed"}

        with mock.patch.object(checkout_lambda._ddb, "scan", return_value=_PREFIX_SCAN), \
                mock.patch.object(checkout_lambda, "_get_task", side_effect=_fake_get_task):
            result = checkout_lambda._validate_plan_objectives_complete("enceladus", plan)

        self.assertIsNone(result)  # gate passes
        # cross-project objective was resolved in ITS project, not the plan's
        self.assertEqual(seen_projects["INT-TSK-071"], "intelligence")
        self.assertEqual(seen_projects["ENC-TSK-100"], "enceladus")

    def test_open_crossproject_objective_reports_real_status_not_notfound(self):
        plan = {"objectives_set": ["INT-TSK-071"]}

        def _fake_get_task(project, obj_id):
            return 200, {"status": "in-progress"}

        with mock.patch.object(checkout_lambda._ddb, "scan", return_value=_PREFIX_SCAN), \
                mock.patch.object(checkout_lambda, "_get_task", side_effect=_fake_get_task):
            result = checkout_lambda._validate_plan_objectives_complete("enceladus", plan)

        self.assertIsNotNone(result)  # gate blocks
        body = result.get("body", "") if isinstance(result, dict) else ""
        self.assertIn("in-progress", body)
        self.assertNotIn("not_found", body)


if __name__ == "__main__":
    unittest.main()
