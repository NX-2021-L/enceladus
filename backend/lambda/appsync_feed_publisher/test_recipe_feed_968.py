"""DVP-TSK-968 part D: recipe and recipe_run rows ride the AppSync feed with the standard envelope."""
import json
import unittest


def _rec(image, event="INSERT"):
    return {"eventName": event, "dynamodb": {"NewImage": image, "Keys": {"project_id": {"S": image["project_id"]["S"]},
            "record_id": image["record_id"]}, "ApproximateCreationDateTime": 1760000000.0}}


class TestRecipeFeed(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_recipe_head_event_envelope(self):
        payload = self.lf.build_event_payload(_rec({
            "record_id": {"S": "recipe#DVP-REC-001"}, "item_id": {"S": "DVP-REC-001"}, "record_type": {"S": "recipe"},
            "record_kind": {"S": "head"}, "project_id": {"S": "devops"}, "name": {"S": "ship-it"}}), 0)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["record_type"], "recipe")
        self.assertIn("DVP-REC-001", json.dumps(payload))
        self.assertIn("ship-it", json.dumps(payload))

    def test_run_row_without_stamp_is_classified_recipe_run(self):
        payload = self.lf.build_event_payload(_rec({
            "record_id": {"S": "recipe_run#DVP-RUN-001"}, "record_kind": {"S": "run"}, "project_id": {"S": "devops"},
            "status": {"S": "awaiting_gate"}}, "MODIFY"), 1)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["record_type"], "recipe_run")

    def test_name_index_rows_publish_nothing(self):
        self.assertIsNone(self.lf.build_event_payload(_rec({
            "record_id": {"S": "recipe-name#ship-it"}, "record_type": {"S": "recipe"}, "record_kind": {"S": "name"},
            "project_id": {"S": "devops"}, "name": {"S": "ship-it"}}), 0))


if __name__ == "__main__":
    unittest.main()
