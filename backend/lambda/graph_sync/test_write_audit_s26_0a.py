"""ENC-TSK-S26-0A: graph_sync consumer [WRITE-AUDIT] line + governed_lag_ms EMF.

Run: python3 -m pytest test_write_audit_s26_0a.py -q
"""
import contextlib
import io
import json
import datetime as dt
import unittest
from unittest.mock import MagicMock, patch

import lambda_function as lf


def _ago(seconds):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _image(updated_at=None, **extra):
    updated_at = updated_at or _ago(2)
    img = {"item_id": {"S": "ENC-TSK-1"}, "record_id": {"S": "task#ENC-TSK-1"},
           "version_seq": {"N": "77"}, "updated_at": {"S": updated_at}}
    img.update({k: {"S": v} for k, v in extra.items()})
    return img


class GraphSyncWriteAuditTests(unittest.TestCase):
    def _run(self, records, process_side_effect=None):
        buf = io.StringIO()
        with patch.object(lf, "_get_neo4j_driver", return_value=MagicMock()), \
                patch.object(lf, "_process_record", side_effect=process_side_effect or [None] * len(records)), \
                contextlib.redirect_stdout(buf):
            lf.handler({"Records": records}, None)
        out = buf.getvalue().splitlines()
        lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in out if l.startswith("[WRITE-AUDIT] ")]
        emf = [json.loads(l) for l in out if l.startswith("{") and "_aws" in l]
        return lines, emf

    def test_line_and_single_emf_metric_with_lag(self):
        rec = {"messageId": "m1", "attributes": {"ApproximateReceiveCount": "3"}, "body": json.dumps(
            {"eventName": "MODIFY", "dynamodb": {"NewImage": _image(correlation_id="corr-g")}})}
        lines, emf = self._run([rec])
        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertEqual((line["consumer"], line["correlation_id"], line["record_id"], line["version_seq"]),
                         ("graph_sync", "corr-g", "ENC-TSK-1", 77))
        self.assertEqual((line["attempt"], line["lag_basis"], line["success"]), (3, "updated_at", True))
        self.assertEqual(line["governed_lag_ms"], line["t_projection_done"] - line["t_ack"])
        self.assertGreater(line["governed_lag_ms"], 0)
        self.assertEqual(len(emf), 1)
        m = emf[0]["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual((m["Namespace"], m["Dimensions"], [x["Name"] for x in m["Metrics"]]),
                         ("Enceladus/WritePath", [["tool"]], ["governed_lag_ms"]))
        self.assertEqual(emf[0]["tool"], "unknown")
        rec2 = {"messageId": "m2", "body": json.dumps({"eventName": "MODIFY", "dynamodb": {"NewImage": _image(
            correlation_id="corr-g", write_tool="documents.patch")}})}
        lines2, emf2 = self._run([rec2])
        self.assertEqual((lines2[0]["tool"], emf2[0]["tool"]), ("documents.patch", "documents.patch"))

    def test_t_ack_attribute_preferred_and_non_governed_skipped(self):
        gov = {"eventName": "INSERT", "dynamodb": {"NewImage": {**_image(), "t_ack": {"N": "1000"}}}}
        plain = {"eventName": "INSERT", "dynamodb": {"NewImage": {"item_id": {"S": "X"}}}}
        lines, _ = self._run([gov, plain])
        self.assertEqual(len(lines), 1)
        self.assertEqual((lines[0]["lag_basis"], lines[0]["t_ack"]), ("t_ack", 1000))
        self.assertEqual(lines[0]["attempt"], 1)

    def test_failed_record_emits_error_line_without_emf(self):
        rec = {"messageId": "m2", "body": json.dumps({"eventName": "MODIFY", "dynamodb": {"NewImage": _image()}})}
        lines, emf = self._run([rec], process_side_effect=[RuntimeError("boom")])
        self.assertEqual((lines[0]["attempt_outcome"], lines[0]["success"]), ("error", False))
        self.assertEqual(emf, [])


if __name__ == "__main__":
    unittest.main()
