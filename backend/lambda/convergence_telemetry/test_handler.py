"""ENC-TSK-I82 AC-2: fan-out + event dispatch unit tests.

Covers the DynamoDB-stream fan-out (open-taxonomy fields category/priority/tags)
and the SQS increment dispatch wiring, without AWS.
"""

import json
import unittest

import lambda_function as lf
from counter_store import InMemoryCounterStore


def _stream_record(image, event_name="INSERT"):
    return {
        "eventSource": "aws:dynamodb",
        "eventName": event_name,
        "dynamodb": {"NewImage": image},
    }


class TestFanout(unittest.TestCase):
    def test_fanout_messages_for_open_taxonomy_fields(self):
        record = {
            "project_id": "enceladus",
            "record_type": "task",
            "record_id": "ENC-TSK-I82",
            "updated_at": "2026-06-28T13:00:00Z",
            "category": "Implementation",
            "priority": "P2",
            "tags": ["Backend", "infra"],
            "title": "ignored non-taxonomy field",
        }
        msgs = lf._fanout_messages(record)
        attrs = {(m["field"], m["canonical_value"]) for m in msgs}
        self.assertIn(("category", "implementation"), attrs)
        self.assertIn(("priority", "p2"), attrs)
        self.assertIn(("tags", "backend"), attrs)
        self.assertIn(("tags", "infra"), attrs)
        # Non-taxonomy fields are never counted.
        self.assertNotIn("title", {m["field"] for m in msgs})
        # attribute_name is the {project}#{type}#{field} partition.
        cat = next(m for m in msgs if m["field"] == "category")
        self.assertEqual(cat["attribute_name"], "enceladus#task#category")

    def test_dedup_id_is_deterministic_and_version_scoped(self):
        a = lf.make_dedup_id("ENC-TSK-1", "category", "implementation", "v1")
        b = lf.make_dedup_id("ENC-TSK-1", "category", "implementation", "v1")
        c = lf.make_dedup_id("ENC-TSK-1", "category", "implementation", "v2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_fanout_skips_records_missing_identity(self):
        self.assertEqual(lf._fanout_messages({"category": "implementation"}), [])

    def test_handle_fanout_sends_per_attribute_messages(self):
        sent = []

        class FakeSqs:
            def send_message(self, **kw):
                sent.append(kw)

        orig_sqs, orig_url = lf._sqs, lf.QUEUE_URL
        lf._sqs = FakeSqs()
        lf.QUEUE_URL = "https://sqs.example/q.fifo"
        try:
            event = {
                "Records": [
                    _stream_record(
                        {
                            "project_id": {"S": "enceladus"},
                            "record_type": {"S": "task"},
                            "record_id": {"S": "ENC-TSK-I82"},
                            "updated_at": {"S": "2026-06-28T13:00:00Z"},
                            "category": {"S": "Implementation"},
                            "priority": {"S": "P2"},
                        }
                    )
                ]
            }
            out = lf.handler(event)
        finally:
            lf._sqs, lf.QUEUE_URL = orig_sqs, orig_url

        self.assertEqual(out["fanned_out"], 2)
        groups = {m["MessageGroupId"] for m in sent}
        self.assertEqual(groups, {"enceladus#task#category", "enceladus#task#priority"})
        # Every message carries an explicit FIFO dedup id.
        self.assertTrue(all(m.get("MessageDeduplicationId") for m in sent))


class TestIncrementDispatch(unittest.TestCase):
    def test_handle_increment_idempotent_across_batch(self):
        store = InMemoryCounterStore()
        body = {
            "attribute_name": "enceladus#task#category",
            "canonical_value": "implementation",
            "dedup_id": "abc123",
            "observed_at": "2026-06-28T13:00:00Z",
            "author": "ENC-SES-00L",
        }
        lf.process_message(store, body)
        lf.process_message(store, body)  # duplicate dedup id
        self.assertEqual(store.get("enceladus#task#category", "implementation")["count"], 1)

    def test_handler_noop_on_empty(self):
        self.assertEqual(lf.handler({"Records": []})["status"], "noop")


if __name__ == "__main__":
    unittest.main()
