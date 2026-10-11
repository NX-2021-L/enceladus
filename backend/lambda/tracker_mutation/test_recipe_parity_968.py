"""DVP-TSK-968 part D: relationship types and the stream-visible run stamp."""
import unittest

NEW = ["recipe-uses-tool", "tool-used-by-recipe", "recipe-serves-project", "project-served-by-recipe",
       "recipe-implements-feature", "implemented-by-recipe", "run-instance-of-recipe", "recipe-has-run",
       "run-opened-escalation", "escalation-opened-by-run"]


class TestRecipeParity(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_relationship_types_allowed(self):
        for rel in NEW:
            self.assertIn(rel, self.lf._RELATIONSHIP_TYPES)

    def test_run_rows_are_stamped_for_stream_consumers(self):
        run = {"record_id": "recipe_run#DVP-RUN-001", "record_kind": "run", "run_id": "DVP-RUN-001", "project_id": "devops",
               "recipe_ref": {"recipe_id": "DVP-REC-001", "version": "1.0.0"}, "status": "queued"}
        out = self.lf._recipe_to_ddb(run)
        self.assertEqual(out["record_type"], {"S": "recipe_run"})
        self.assertEqual(out["item_id"], {"S": "DVP-RUN-001"})
        self.assertIn("DVP-RUN-001", out["title"]["S"])
        self.assertNotIn("record_type", run)

    def test_head_rows_keep_their_type(self):
        head = {"record_id": "recipe#DVP-REC-001", "record_kind": "head", "record_type": "recipe", "project_id": "devops"}
        self.assertEqual(self.lf._recipe_to_ddb(head)["record_type"], {"S": "recipe"})


if __name__ == "__main__":
    unittest.main()
