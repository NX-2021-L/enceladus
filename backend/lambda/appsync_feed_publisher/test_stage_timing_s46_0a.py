"""ENC-TSK-S46-0A: appsync_feed_publisher per-record feed lag clock on a [WRITE-AUDIT] line.

Run: python3 -m pytest test_stage_timing_s46_0a.py -q
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "stage_timing_s46_0a_mod", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)


def _rec(seq, governed=True):
    img = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}, "item_id": {"S": "ENC-TSK-1"},
           "title": {"S": seq}}
    if governed:
        img.update({"version_seq": {"N": "5"}, "t_ack": {"N": "1000"}, "correlation_id": {"S": "corr-a"}})
    return {"eventName": "MODIFY", "eventSource": "aws:dynamodb", "eventID": "e" + seq,
            "dynamodb": {"SequenceNumber": seq, "NewImage": img}}


class AppsyncFeedClockTests(unittest.TestCase):
    def _run(self, records, publish=None):
        buf = io.StringIO()
        with patch.object(m, "build_event_payload", return_value={"eventId": "x", "action": "u", "channels": []}), \
                patch.object(m, "build_full_record_body", return_value=None), \
                patch.object(m, "publish_to_appsync", side_effect=publish or (lambda p, b=None: None)), \
                patch.object(m, "DRY_RUN", False), contextlib.redirect_stdout(buf):
            out = m.handler({"Records": records}, None)
        lines = [json.loads(l.split("[WRITE-AUDIT] ", 1)[1]) for l in buf.getvalue().splitlines()
                 if l.startswith("[WRITE-AUDIT] ")]
        return lines, out

    def test_published_line_fields_and_types(self):
        with patch.object(m, "_WA_COLD", True):
            lines, _ = self._run([_rec("1"), _rec("2"), _rec("3", governed=False)])
        self.assertEqual(len(lines), 2)  # non-governed record is silent
        l0, l1 = lines
        for key, typ in (("correlation_id", str), ("record_id", str), ("version_seq", int), ("t_ack", int),
                         ("t_batch_start", int), ("batch_position", int), ("cold_start", bool), ("publish_ms", float),
                         ("t_feed_published", int)):
            self.assertIsInstance(l0[key], typ, key)
        self.assertEqual((l0["consumer"], l0["batch_position"], l1["batch_position"]), ("appsync_feed_publisher", 0, 1))
        self.assertEqual((l0["cold_start"], l1["cold_start"]), (True, True))  # same invocation
        self.assertGreaterEqual(l0["t_feed_published"], l0["t_batch_start"])

    def test_failure_line_has_no_feed_timestamp(self):
        def boom(p, b=None):
            raise RuntimeError("down")
        lines, out = self._run([_rec("1")], publish=boom)
        self.assertEqual((lines[0]["success"], lines[0]["t_feed_published"], lines[0]["publish_ms"]), (False, None, None))
        self.assertEqual(out["batchItemFailures"], [{"itemIdentifier": "1"}])

    def test_marker_write_is_not_audited(self):
        old = _rec("1")["dynamodb"]["NewImage"]
        new = {**old, "projection_status": {"S": "projected"}}
        rec = {"eventName": "MODIFY", "dynamodb": {"SequenceNumber": "1", "OldImage": old, "NewImage": new}}
        lines, _ = self._run([rec])
        self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()
