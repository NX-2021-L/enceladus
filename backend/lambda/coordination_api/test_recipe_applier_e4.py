"""DVP-TSK-968 part A: the hub's recipe_version applier delegates to the recipe service."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import coordination_lambda as coord  # noqa: E402


class RecipeApplierTests(unittest.TestCase):
    def test_registered_alongside_the_legacy_appliers(self):
        self.assertIn("recipe_version", coord._ESCALATION_APPLIERS)
        self.assertIn("deploy_arc_change", coord._ESCALATION_APPLIERS)

    def test_delegates_to_the_tracker_recipe_apply_route(self):
        esc = {"subject": json.dumps({"type": "recipe_version", "record_id": "DVP-REC-001", "version": "1.0.0"})}
        with mock.patch.object(coord, "_invoke_tracker_mutation_api",
                               return_value={"_status_code": 200, "status": "applied"}) as inv:
            out = coord._ESCALATION_APPLIERS["recipe_version"]("devops", "DVP-ESC-001", esc, "io-admin", {})
        self.assertEqual(out["status"], "applied")
        args, kwargs = inv.call_args
        self.assertEqual(args[:2], ("POST", "/api/v1/tracker/devops/recipe/DVP-REC-001/apply"))
        self.assertEqual(kwargs["body"]["escalation_id"], "DVP-ESC-001")
        self.assertEqual(kwargs["body"]["decider"], "io-admin")

    def test_missing_subject_is_refused_without_calling_the_tracker(self):
        with mock.patch.object(coord, "_invoke_tracker_mutation_api") as inv:
            out = coord._ESCALATION_APPLIERS["recipe_version"]("devops", "DVP-ESC-001", {}, "io-admin", {})
        self.assertEqual(out["_status_code"], 422)
        inv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
