"""DVP-TSK-968 part D / DVP-FTR-106 AC4: Recipe + RecipeRun graph projection (RP-0 s8), mocked stores."""
import json
import unittest
from unittest.mock import MagicMock, patch

NEW_EDGES = {
    "recipe-uses-tool": "RECIPE_USES_TOOL", "tool-used-by-recipe": "TOOL_USED_BY_RECIPE",
    "recipe-serves-project": "RECIPE_SERVES_PROJECT", "project-served-by-recipe": "PROJECT_SERVED_BY_RECIPE",
    "recipe-implements-feature": "RECIPE_IMPLEMENTS_FEATURE", "implemented-by-recipe": "IMPLEMENTED_BY_RECIPE",
    "run-instance-of-recipe": "RUN_INSTANCE_OF_RECIPE", "recipe-has-run": "RECIPE_HAS_RUN",
    "run-opened-escalation": "RUN_OPENED_ESCALATION", "escalation-opened-by-run": "ESCALATION_OPENED_BY_RUN",
}
HASH = "sha256:" + "a" * 64


def _calls(tx):
    return [(c.args[0], c.kwargs) for c in tx.run.call_args_list]


class TestMaps(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_edge_labels_registered(self):
        for rel, label in NEW_EDGES.items():
            self.assertEqual(self.lf.RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel), label)

    def test_labels_and_prefixes(self):
        self.assertEqual(self.lf.RECORD_TYPE_TO_LABEL["recipe"], "Recipe")
        self.assertEqual(self.lf.RECORD_TYPE_TO_LABEL["recipe_run"], "RecipeRun")
        self.assertEqual(self.lf._infer_label_from_id("DVP-REC-001"), "Recipe")
        self.assertEqual(self.lf._infer_label_from_id("DVP-RUN-014"), "RecipeRun")


class TestHeadProjection(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_head_node_and_edges(self):
        head = {"record_id": "recipe#DVP-REC-001", "record_kind": "head", "record_type": "recipe",
                "recipe_id": "DVP-REC-001", "name": "ship-it", "status": "published", "project_id": "devops",
                "tags": json.dumps(["a", "b"]), "project_ids": json.dumps(["devops", "enceladus"]),
                "related_feature_ids": json.dumps(["DVP-FTR-106"]), "latest_published": "1.0.0", "owner": "io"}
        tx = MagicMock()
        self.lf._project_recipe_head(tx, head)
        calls = _calls(tx)
        self.assertIn("MERGE (n:Recipe", calls[0][0])
        props = calls[0][1]["props"]
        self.assertEqual((props["title"], props["name"], props["status"], props["tags"]), ("ship-it", "ship-it", "published", ["a", "b"]))
        self.assertEqual(props["project_id"], "devops")
        serves = [k for q, k in calls if "RECIPE_SERVES_PROJECT]->(p)" in q]
        self.assertEqual({k["pid"] for k in serves}, {"devops", "enceladus"})
        feats = [k for q, k in calls if "RECIPE_IMPLEMENTS_FEATURE]->(f)" in q]
        self.assertEqual([k["fid"] for k in feats], ["DVP-FTR-106"])
        self.assertTrue(any("ON CREATE SET f.is_placeholder = true" in q for q, _ in calls))


class TestVersionProjection(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.definition = json.dumps({"steps": [
            {"id": "a", "action": "tracker.create"},
            {"id": "b", "type": "action", "action": "tracker.get", "compensate": {"action": "tracker.close"}},
            {"id": "g", "type": "gate", "gate": {}}]})

    def _ver(self, status):
        return {"record_id": "recipe#DVP-REC-001@1.0.0", "record_kind": "version", "record_type": "recipe",
                "recipe_id": "DVP-REC-001", "version": "1.0.0", "status": status, "project_id": "devops",
                "definition": self.definition}

    def test_tools_derived_from_actions_and_compensate(self):
        self.assertEqual(self.lf._recipe_tools(self.definition), ["tracker.close", "tracker.create", "tracker.get"])

    def test_published_version_merges_tool_edges_with_versions(self):
        tx = MagicMock()
        self.lf._project_recipe_version(tx, self._ver("published"))
        calls = _calls(tx)
        merges = [k for q, k in calls if "MERGE (t:Tool" in q]
        self.assertEqual({k["tool"] for k in merges}, {"tracker.close", "tracker.create", "tracker.get"})
        self.assertTrue(all(k["v"] == "1.0.0" for k in merges))
        self.assertTrue(any("e.versions" in q and "RECIPE_USES_TOOL" in q for q, _ in calls))
        self.assertTrue(any("TOOL_USED_BY_RECIPE" in q for q, _ in calls))

    def test_retired_version_only_removes_itself(self):
        tx = MagicMock()
        self.lf._project_recipe_version(tx, self._ver("retired"))
        calls = _calls(tx)
        self.assertFalse(any("MERGE (t:Tool" in q for q, _ in calls))
        drops = [k for q, k in calls if "DELETE e" in q]
        self.assertEqual(len(drops), 2)
        self.assertTrue(all(k["tools"] == [] and k["v"] == "1.0.0" for k in drops))


class TestRunProjection(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self.run = {"record_id": "recipe_run#DVP-RUN-001", "record_kind": "run", "run_id": "DVP-RUN-001",
                    "project_id": "devops", "status": "awaiting_gate", "started_by": "agent",
                    "recipe_ref": json.dumps({"recipe_id": "DVP-REC-001", "version": "1.0.0", "content_hash": HASH}),
                    "gate": {"step_id": "approve", "escalation_id": "DVP-ESC-007"},
                    "gate_history": [{"step_id": "first", "escalation_id": "DVP-ESC-003"}],
                    "steps": [{"id": "a", "result": {"secret": "x"}}], "inputs": {"k": "v"}, "outputs": {"o": 1}}

    def test_run_node_edges_and_no_step_results(self):
        tx = MagicMock()
        self.lf._project_recipe_run(tx, self.run)
        calls = _calls(tx)
        q0, k0 = calls[0]
        self.assertIn("MERGE (n:RecipeRun", q0)
        for banned in ("steps", "inputs", "outputs", "gate", "gate_history"):
            self.assertNotIn(banned, k0["props"])
        self.assertEqual((k0["props"]["status"], k0["gesc"], k0["gstep"]), ("awaiting_gate", "DVP-ESC-007", "approve"))
        inst = [k for q, k in calls if "RUN_INSTANCE_OF_RECIPE" in q]
        self.assertEqual((inst[0]["rec"], inst[0]["ver"], inst[0]["ch"]), ("DVP-REC-001", "1.0.0", HASH))
        esc = {k["eid"]: k["sid"] for q, k in calls if "RUN_OPENED_ESCALATION" in q}
        self.assertEqual(esc, {"DVP-ESC-003": "first", "DVP-ESC-007": "approve"})
        self.assertTrue(any("MERGE (x:Escalation" in q and "is_placeholder" in q for q, _ in calls))

    def test_resolved_gate_clears_current_gate_properties(self):
        tx = MagicMock()
        self.lf._project_recipe_run(tx, dict(self.run, gate=None, status="running"))
        k0 = _calls(tx)[0][1]
        self.assertIsNone(k0["gesc"])
        self.assertEqual(k0["props"]["status"], "running")


class TestDispatch(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_name_index_rows_not_projected(self):
        driver = MagicMock()
        row = {"record_type": "recipe", "record_kind": "name", "record_id": "recipe-name#ship-it"}
        self.assertFalse(self.lf._project_recipe_record(driver, row))
        driver.session.assert_not_called()

    def test_stream_run_row_without_record_type_routes_to_recipe_projection(self):
        image = {"record_id": {"S": "recipe_run#DVP-RUN-001"}, "project_id": {"S": "devops"},
                 "record_kind": {"S": "run"}, "status": {"S": "queued"}}
        with patch.object(self.lf, "_project_recipe_record", return_value=True) as proj:
            self.lf._process_record(MagicMock(), {"eventName": "INSERT", "dynamodb": {"NewImage": image}})
        self.assertEqual(proj.call_args.args[1]["record_type"], "recipe_run")


if __name__ == "__main__":
    unittest.main()
