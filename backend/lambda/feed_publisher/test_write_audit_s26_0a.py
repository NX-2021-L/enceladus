"""ENC-TSK-S26-0A: feed_publisher consumer [WRITE-AUDIT] line + governed_lag_ms EMF.

Run: python3 -m pytest test_write_audit_s26_0a.py -q
"""
import contextlib
import io
import json
import datetime as dt
import unittest
from unittest.mock import patch

import lambda_function as fp


def _ago(seconds):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record(message_id="m1", cid="corr-f", receive="2"):
    image = {"item_id": {"S": "ENC-TSK-2"}, "version_seq": {"N": "5"},
             "updated_at": {"S": _ago(2)}, "correlation_id": {"S": cid}}
    return {"messageId": message_id, "attributes": {"ApproximateReceiveCount": receive},
            "body": json.dumps({"eventName": "MODIFY", "dynamodb": {"Keys": {"record_id": {"S": "task#ENC-TSK-2"}},
                                                                   "NewImage": image}})}


class FeedPublisherWriteAuditTests(unittest.TestCase):
    def _run(self, mode, per_batch_resp, records):
        buf = io.StringIO()
        with patch.object(fp, "FEED_PUBLISH_MODE", mode), \
                patch.object(fp, "_handle_per_batch", return_value=per_batch_resp), \
                patch.object(fp, "_handle_mark", return_value=per_batch_resp), \
                contextlib.redirect_stdout(buf):
            fp.handler({"Records": records}, None)
        out = buf.getvalue().splitlines()
        lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in out if l.startswith("[WRITE-AUDIT] ")]
        emf = [json.loads(l) for l in out if l.startswith("{") and "_aws" in l]
        return lines, emf

    def test_published_batch_emits_line_and_governed_lag_metric(self):
        lines, emf = self._run("per_batch", {"batchItemFailures": []}, [_record()])
        line = lines[0]
        self.assertEqual((line["consumer"], line["correlation_id"], line["record_id"], line["version_seq"],
                          line["attempt"], line["projection_phase"]),
                         ("feed_publisher", "corr-f", "ENC-TSK-2", 5, 2, "projected"))
        self.assertEqual(line["governed_lag_ms"], line["t_projection_done"] - line["t_ack"])
        self.assertEqual(len(emf), 1)
        self.assertEqual(emf[0]["governed_lag_ms"], line["governed_lag_ms"])

    def test_failed_record_error_and_coalesced_mark_has_no_metric(self):
        lines, emf = self._run("per_batch", {"batchItemFailures": [{"itemIdentifier": "m1"}]}, [_record()])
        self.assertEqual((lines[0]["attempt_outcome"], emf), ("error", []))
        lines, emf = self._run("coalesced", {"batchItemFailures": []}, [_record()])
        self.assertEqual((lines[0]["projection_phase"], emf), ("marked", []))


if __name__ == "__main__":
    unittest.main()
