"""ENC-TSK-S28-0E: projection-marker loop guard in governance_audit.

Run: python3 -m pytest test_loop_guard_s28_0e.py -q
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
sys.path.insert(0, os.path.dirname(__file__))
_spec = importlib.util.spec_from_file_location(
    "loop_guard_s28_0e_mod", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = m
_spec.loader.exec_module(m)


def _rec(old_extra, new_extra):
    base = {"project_id": {"S": "enceladus"}, "record_id": {"S": "task#ENC-TSK-1"}, "version_seq": {"N": "5"}}
    return {"eventName": "MODIFY", "eventSource": "aws:dynamodb", "eventID": "e1",
            "dynamodb": {"SequenceNumber": "1", "Keys": {"record_id": {"S": "task#ENC-TSK-1"}},
                         "OldImage": {**base, **old_extra}, "NewImage": {**base, **new_extra}}}


MARKER = _rec({}, {"projection_status": {"S": "projected"}, "projected_version_seq": {"N": "5"}})
REAL = _rec({}, {"title": {"S": "changed"}})


class LoopGuardTests(unittest.TestCase):
    def test_marker_detection(self):
        self.assertTrue(m._record_is_projection_marker(MARKER))
        self.assertFalse(m._record_is_projection_marker(REAL))

    def test_handler(self):
        with patch.object(m, "_check_write_source", return_value=None) as c:
            m.handler({"Records": [MARKER]}, None)
            c.assert_not_called()
            m.handler({"Records": [REAL]}, None)
            c.assert_called_once()


if __name__ == "__main__":
    unittest.main()
