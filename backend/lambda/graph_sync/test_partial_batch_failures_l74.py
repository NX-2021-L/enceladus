"""Tests for ENC-TSK-L74: handler() reports batchItemFailures instead of
silently losing MENTIONS edges (and any other graph write) for records whose
processing raised, when they share a batch with a successful record."""
import json
import unittest
from unittest.mock import MagicMock, patch


class TestHandlerPartialBatchFailures(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf

    def _sqs_record(self, message_id, ok=True):
        body = {
            "dynamodb": {"Keys": {}, "NewImage": {}},
        } if ok else {"not": "a stream record shape that raises"}
        return {"messageId": message_id, "body": json.dumps(body)}

    def test_one_failure_in_batch_reports_only_that_message_id(self):
        good = self._sqs_record("msg-good")
        bad = self._sqs_record("msg-bad")
        event = {"Records": [good, bad]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=MagicMock()), \
             patch.object(self.lf, "_extract_stream_record", side_effect=[
                 {"dynamodb": {}}, {"dynamodb": {}},
             ]), \
             patch.object(self.lf, "_process_record", side_effect=[None, RuntimeError("boom")]):
            result = self.lf.handler(event, None)

        self.assertIn("batchItemFailures", result)
        self.assertEqual(result["batchItemFailures"], [{"itemIdentifier": "msg-bad"}])

    def test_all_success_returns_plain_200_no_failures(self):
        event = {"Records": [self._sqs_record("msg-1"), self._sqs_record("msg-2")]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=MagicMock()), \
             patch.object(self.lf, "_extract_stream_record", return_value={"dynamodb": {}}), \
             patch.object(self.lf, "_process_record", return_value=None):
            result = self.lf.handler(event, None)

        self.assertNotIn("batchItemFailures", result)
        self.assertEqual(result["statusCode"], 200)

    def test_neo4j_unavailable_fails_entire_batch_for_retry(self):
        event = {"Records": [self._sqs_record("msg-1"), self._sqs_record("msg-2")]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=None):
            result = self.lf.handler(event, None)

        self.assertIn("batchItemFailures", result)
        ids = {f["itemIdentifier"] for f in result["batchItemFailures"]}
        self.assertEqual(ids, {"msg-1", "msg-2"})

    def test_empty_records_returns_plain_200(self):
        result = self.lf.handler({"Records": []}, None)
        self.assertEqual(result, {"statusCode": 200, "body": "no records"})


if __name__ == "__main__":
    unittest.main()
