"""ENC-TSK-S46-0A: feed_publisher feed lag clock (t_feed_published) on the [WRITE-AUDIT] line only.

Run: python3 -m pytest test_stage_timing_s46_0a.py -q
"""
import contextlib
import io
import json
import unittest
from unittest.mock import MagicMock, patch

import lambda_function as fp


def _record(message_id="m1", cid="corr-f", vseq=5):
    image = {"item_id": {"S": "ENC-TSK-2"}, "project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-2"},
             "version_seq": {"N": str(vseq)}, "t_ack": {"N": "1000"}, "correlation_id": {"S": cid}}
    return {"messageId": message_id, "attributes": {"ApproximateReceiveCount": "1"},
            "body": json.dumps({"eventName": "MODIFY", "dynamodb": {"NewImage": image}})}


class FeedLagClockTests(unittest.TestCase):
    def _run(self, mode, resp, records, ddb=None):
        buf = io.StringIO()
        with patch.object(fp, "FEED_PUBLISH_MODE", mode), \
                patch.object(fp, "_handle_per_batch", return_value=resp), \
                patch.object(fp, "_handle_mark", return_value=resp), \
                patch.object(fp, "_ddb_client", return_value=ddb or MagicMock()), \
                contextlib.redirect_stdout(buf):
            fp.handler({"Records": records}, None)
        return [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
                if l.startswith("[WRITE-AUDIT] ")]

    def test_projected_line_has_feed_clock_fields(self):
        with patch.object(fp, "_WA_COLD", True):
            lines = self._run("per_batch", {"batchItemFailures": []}, [_record("m1"), _record("m2", vseq=6)])
        l0, l1 = lines
        for key, typ in (("correlation_id", str), ("record_id", str), ("version_seq", int), ("t_ack", int),
                         ("t_batch_start", int), ("batch_position", int), ("cold_start", bool), ("publish_ms", float),
                         ("t_feed_published", int), ("batch_size", int)):
            self.assertIsInstance(l0[key], typ, key)
        self.assertEqual((l0["batch_position"], l1["batch_position"], l0["batch_size"]), (0, 1, 2))
        self.assertEqual((l0["cold_start"], l0["projection_phase"]), (True, "projected"))
        self.assertGreaterEqual(l0["t_feed_published"], l0["t_batch_start"])
        self.assertGreaterEqual(l0["publish_ms"], 0)
        self.assertEqual(l0["governed_lag_ms"], l0["t_projection_done"] - l0["t_ack"])  # alias unchanged
        for key in ("consumer", "attempt", "projection_phase"):
            self.assertIn(key, l0)

    def test_cold_only_first_invocation(self):
        with patch.object(fp, "_WA_COLD", True):
            a = self._run("per_batch", {"batchItemFailures": []}, [_record()])[0]
            b = self._run("per_batch", {"batchItemFailures": []}, [_record(vseq=9)])[0]
        self.assertEqual((a["cold_start"], b["cold_start"]), (True, False))

    def test_t_feed_published_never_written_to_the_item(self):
        ddb = MagicMock()
        lines = self._run("per_batch", {"batchItemFailures": []}, [_record()], ddb=ddb)
        self.assertIsNotNone(lines[0]["t_feed_published"])
        self.assertTrue(ddb.update_item.called)  # the version claim still happens
        for call in ddb.update_item.call_args_list:
            self.assertNotIn("t_feed_published", json.dumps(call.kwargs, default=str))
        self.assertNotIn("t_feed_published", fp.PROJECTION_ONLY_ATTRS)

    def test_failed_and_marked_records_have_no_feed_timestamp(self):
        failed = self._run("per_batch", {"batchItemFailures": [{"itemIdentifier": "m1"}]}, [_record()])[0]
        self.assertEqual((failed["attempt_outcome"], failed["t_feed_published"]), ("error", None))
        marked = self._run("coalesced", {"batchItemFailures": []}, [_record()])[0]
        self.assertEqual((marked["projection_phase"], marked["t_feed_published"], marked["publish_ms"]),
                         ("marked", None, None))


if __name__ == "__main__":
    unittest.main()
