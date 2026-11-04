"""ENC-TSK-S28-0D: opensearch_indexer never indexes audit#/idem# rows."""
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

import types

def _load(name, filename="lambda_function.py"):
    here = pathlib.Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    spec = importlib.util.spec_from_file_location(name, here / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SkipMetaRowsTests(unittest.TestCase):
    def test_meta_rows_produce_no_action_and_no_failure(self):
        if "boto3" not in sys.modules:
            fb = types.ModuleType("boto3"); fb.client = lambda *a, **k: None; sys.modules["boto3"] = fb
        if "botocore.exceptions" not in sys.modules:
            fe = types.ModuleType("botocore.exceptions"); fe.ClientError = Exception; sys.modules["botocore.exceptions"] = fe
        sys.modules["search_index_core"] = _load("search_index_core_s28_0d", "search_index_core.py")
        idx = _load("opensearch_indexer_s28_0d")

        def rec(seq, pk, name="INSERT"):
            return {"eventName": name, "dynamodb": {"SequenceNumber": seq, "Keys": {"project_id": {"S": pk}},
                                                     "NewImage": {"project_id": {"S": pk}, "record_type": {"S": "task"}}}}
        event = {"Records": [rec("1", "audit#ENC-TSK-1"), rec("2", "idem#enceladus#k"), rec("3", "audit#ENC-TSK-1", "REMOVE")]}
        with patch.object(idx, "_stream_record_to_action") as conv, patch.object(idx, "bulk_execute") as bulk:
            resp = idx.handler(event, None)
        conv.assert_not_called()
        bulk.assert_not_called()
        self.assertEqual(resp, {})


if __name__ == "__main__":
    unittest.main()
