"""ENC-ISS-543: close / checkout-release stream paths must MERGE terminal status."""
import unittest
from unittest.mock import MagicMock, patch


def _ddb_string(value: str) -> dict:
    return {"S": value}


def _task_new_image(status: str, *, include_status_typed: bool = True) -> dict:
    image = {
        "record_type": _ddb_string("task"),
        "record_id": _ddb_string("task#ENC-TSK-M27"),
        "project_id": _ddb_string("enceladus"),
        "title": _ddb_string("carrier"),
        "updated_at": _ddb_string("2026-07-12T10:10:59Z"),
        "active_agent_session": {"BOOL": False},
        "checkout_state": _ddb_string("checked_in"),
    }
    if include_status_typed:
        image["status"] = _ddb_string(status)
    return image


class TestCloseStatusProjectionIss543(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def test_coalesce_recovers_status_from_typed_new_image(self):
        new_image = _task_new_image("closed")
        # Simulate a deserialize gap: status missing from dict but present typed.
        record = {"record_type": "task", "record_id": "task#ENC-TSK-M27", "project_id": "enceladus"}
        merged = self.lf._coalesce_status_for_projection(record, {}, new_image, {})
        self.assertEqual(merged["status"], "closed")

    def test_coalesce_preserves_terminal_status_from_old_image_on_checkout_release(self):
        """Mechanism 3: checkout-release MODIFY may omit status in the deserialized
        dict; OldImage already carries the terminal status from the close write."""
        new_image = _task_new_image("closed", include_status_typed=False)
        old_image = _task_new_image("closed")
        old_record = self.lf._normalize_record_for_graph(self.lf._deser_image(old_image))
        record = self.lf._normalize_record_for_graph(self.lf._deser_image(new_image))
        merged = self.lf._coalesce_status_for_projection(record, old_record, new_image, old_image)
        self.assertEqual(merged["status"], "closed")

    def test_upsert_node_sets_status_explicitly(self):
        captured = {}

        def _capture_run(cypher, **params):
            captured["cypher"] = cypher
            captured["params"] = params

        tx = MagicMock()
        tx.run.side_effect = _capture_run
        record = {
            "record_type": "task",
            "record_id": "task#ENC-TSK-M27",
            "project_id": "enceladus",
            "title": "carrier",
            "status": "closed",
            "updated_at": "2026-07-12T10:11:00Z",
        }
        self.lf._upsert_node(tx, record)
        self.assertIn("SET n.status = $status_val", captured["cypher"])
        self.assertEqual(captured["params"]["status_val"], "closed")

    def test_terminal_status_detection(self):
        self.assertTrue(self.lf._is_terminal_status("closed"))
        self.assertTrue(self.lf._is_terminal_status("production"))
        self.assertFalse(self.lf._is_terminal_status("in-progress"))


if __name__ == "__main__":
    unittest.main()
