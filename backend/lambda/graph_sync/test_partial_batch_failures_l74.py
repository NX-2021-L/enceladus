"""Tests for ENC-TSK-L74: handler() reports batchItemFailures instead of
silently losing MENTIONS edges (and any other graph write) for records whose
processing raised, when they share a batch with a successful record.

ENC-TSK-L85: also covers the direct DynamoDB Streams EventSourceMapping event
shape (gamma), alongside the legacy SQS-wrapped shape (prod/v3), and the
correct SequenceNumber-vs-messageId failure-identifier semantics for each."""
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

    def _ddb_stream_record(self, sequence_number, event_name="INSERT"):
        """Native DynamoDB Streams ESM shape (no body/messageId wrapper)."""
        return {
            "eventID": "unused-not-the-failure-identifier",
            "eventName": event_name,
            "dynamodb": {
                "SequenceNumber": sequence_number,
                "Keys": {},
                "NewImage": {},
            },
        }

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

    def test_direct_ddb_stream_shape_classified_correctly(self):
        """ENC-TSK-L85: event.Records[] entries with no body/messageId are the
        raw stream record itself; failure identifier must be SequenceNumber,
        never eventID (the DynamoDB Streams ReportBatchItemFailures contract
        keys off SequenceNumber, not eventID)."""
        rec = self._ddb_stream_record("seq-1")
        source, identifier = self.lf._record_source_and_identifier(rec)
        self.assertEqual(source, "ddb_stream")
        self.assertEqual(identifier, "seq-1")

    def test_sqs_shape_still_classified_as_sqs(self):
        rec = self._sqs_record("msg-1")
        source, identifier = self.lf._record_source_and_identifier(rec)
        self.assertEqual(source, "sqs")
        self.assertEqual(identifier, "msg-1")

    def test_direct_ddb_stream_failure_reports_sequence_number(self):
        good = self._ddb_stream_record("seq-good")
        bad = self._ddb_stream_record("seq-bad")
        event = {"Records": [good, bad]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=MagicMock()), \
             patch.object(self.lf, "_process_record", side_effect=[None, RuntimeError("boom")]):
            result = self.lf.handler(event, None)

        self.assertIn("batchItemFailures", result)
        self.assertEqual(result["batchItemFailures"], [{"itemIdentifier": "seq-bad"}])

    def test_mixed_sqs_and_direct_ddb_stream_batch(self):
        """A rollback window can have both event sources wired simultaneously
        (old SQS trigger left enabled on prod/v3, new direct ESM on gamma) --
        handler must classify and process each record independently."""
        sqs_good = self._sqs_record("msg-good")
        ddb_good = self._ddb_stream_record("seq-good")
        event = {"Records": [sqs_good, ddb_good]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=MagicMock()), \
             patch.object(self.lf, "_extract_stream_record", return_value={"dynamodb": {}}), \
             patch.object(self.lf, "_process_record", return_value=None):
            result = self.lf.handler(event, None)

        self.assertNotIn("batchItemFailures", result)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(json.loads(result["body"])["processed"], 2)

    def test_neo4j_unavailable_fails_entire_batch_direct_ddb_stream_shape(self):
        event = {"Records": [self._ddb_stream_record("seq-1"), self._ddb_stream_record("seq-2")]}

        with patch.object(self.lf, "_get_neo4j_driver", return_value=None):
            result = self.lf.handler(event, None)

        self.assertIn("batchItemFailures", result)
        ids = {f["itemIdentifier"] for f in result["batchItemFailures"]}
        self.assertEqual(ids, {"seq-1", "seq-2"})


if __name__ == "__main__":
    unittest.main()
