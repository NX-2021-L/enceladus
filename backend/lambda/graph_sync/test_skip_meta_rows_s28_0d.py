"""ENC-TSK-S28-0D: graph_sync ignores audit#/idem# rows, keeps ReportBatchItemFailures intact."""
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


def _rec(seq, pk):
    return {"eventName": "INSERT", "dynamodb": {"SequenceNumber": seq, "Keys": {"project_id": {"S": pk}, "record_id": {"S": "x"}},
                                                 "NewImage": {"project_id": {"S": pk}}}}


class SkipMetaRowsTests(unittest.TestCase):
    def test_audit_and_marker_rows_skipped_real_rows_still_processed_and_failures_reported(self):
        lf = _load("graph_sync_s28_0d")
        seen = []

        def process(_driver, rec):
            seen.append(rec["dynamodb"]["SequenceNumber"])
            if rec["dynamodb"]["SequenceNumber"] == "4":
                raise RuntimeError("boom")
        event = {"Records": [_rec("1", "audit#ENC-TSK-1"), _rec("2", "idem#enceladus#k"), _rec("3", "enceladus"), _rec("4", "enceladus")]}
        with patch.object(lf, "_get_neo4j_driver", return_value=object()), patch.object(lf, "_process_record", side_effect=process):
            resp = lf.handler(event, None)
        self.assertEqual(seen, ["3", "4"])
        self.assertEqual(resp, {"batchItemFailures": [{"itemIdentifier": "4"}]})


if __name__ == "__main__":
    unittest.main()
