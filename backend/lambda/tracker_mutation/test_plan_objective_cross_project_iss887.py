"""ENC-ISS-887 / ENC-TSK-R95: the plan completion gate reads each objective from its owning project.

ENC-PLN-102 (project enceladus) holds DVP-TSK-* objectives that live under project_id=devops;
the gate used the plan's project_id for every lookup and reported them NOT_FOUND.
"""
import unittest
from unittest import mock


def _ddb(items):
    """Fake DynamoDB whose get_item answers from {(project_id, record_id): status}."""
    ddb = mock.MagicMock()

    def get_item(TableName, Key, ConsistentRead):
        status = items.get((Key["project_id"]["S"], Key["record_id"]["S"]))
        return {"Item": {"status": {"S": status}}} if status is not None else {}

    ddb.get_item.side_effect = get_item
    return ddb


def _resolve(record_id):
    return {"DVP": "devops", "ENC": "enceladus"}.get(record_id.split("-")[0])


class TestPlanObjectiveStatus(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.items = {
            ("devops", "task#DVP-TSK-B87"): "closed",
            ("devops", "task#DVP-TSK-B90"): "in-progress",
            ("enceladus", "task#ENC-TSK-R84"): "Closed",
        }
        self._patches = [
            mock.patch.object(lf, "_get_ddb", return_value=_ddb(self.items)),
            mock.patch.object(lf, "_resolve_project_for_record_id", side_effect=_resolve),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_cross_project_closed_objective_is_found(self):
        self.assertEqual(self.lf._plan_objective_status("DVP-TSK-B87", "enceladus"), "closed")

    def test_cross_project_open_objective_reports_its_status(self):
        self.assertEqual(self.lf._plan_objective_status("DVP-TSK-B90", "enceladus"), "in-progress")

    def test_same_project_objective_is_lowercased(self):
        self.assertEqual(self.lf._plan_objective_status("ENC-TSK-R84", "enceladus"), "closed")

    def test_missing_objective_is_not_found(self):
        self.assertEqual(self.lf._plan_objective_status("DVP-TSK-ZZZ", "enceladus"), "NOT_FOUND")

    def test_unknown_prefix_falls_back_to_plan_project(self):
        self.items[("enceladus", "task#XYZ-TSK-001")] = "closed"
        self.assertEqual(self.lf._plan_objective_status("XYZ-TSK-001", "enceladus"), "closed")

    def test_lookup_error_is_check_failed(self):
        self.lf._get_ddb.return_value.get_item.side_effect = RuntimeError("boom")
        self.assertEqual(self.lf._plan_objective_status("DVP-TSK-B87", "enceladus"), "CHECK_FAILED")


if __name__ == "__main__":
    unittest.main()
