"""ENC-TSK-S28-0D: convergence_telemetry fan-out ignores audit#/idem# rows."""
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")


def _load(name, filename="lambda_function.py"):
    here = pathlib.Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    spec = importlib.util.spec_from_file_location(name, here / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SkipMetaRowsTests(unittest.TestCase):
    def test_meta_rows_fan_out_nothing(self):
        lf = _load("convergence_telemetry_s28_0d")
        rec = lambda pk: {"eventName": "INSERT", "eventSource": "aws:dynamodb",
                          "dynamodb": {"Keys": {"project_id": {"S": pk}}, "NewImage": {"project_id": {"S": pk}, "category": {"S": "x"}}}}
        with patch.object(lf, "_get_sqs", return_value=MagicMock()), patch.object(lf, "_fanout_messages") as fan:
            out = lf.handler({"Records": [rec("audit#ENC-TSK-1"), rec("idem#enceladus#k")]}, None)
            fan.assert_not_called()
            self.assertEqual(out["fanned_out"], 0)
            fan.return_value = []
            lf.handler({"Records": [rec("enceladus")]}, None)
            fan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
