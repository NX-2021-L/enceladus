"""ENC-TSK-S28-0D: appsync_feed_publisher never publishes audit#/idem# rows."""
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

os.environ.setdefault("APPSYNC_EVENTS_HTTP_ENDPOINT", "example.appsync-api.us-west-2.amazonaws.com")
os.environ.setdefault("APPSYNC_EVENTS_API_KEY", "test-key")
os.environ.setdefault("DRY_RUN", "true")

def _load(name, filename="lambda_function.py"):
    here = pathlib.Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    spec = importlib.util.spec_from_file_location(name, here / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SkipMetaRowsTests(unittest.TestCase):
    def test_meta_rows_skipped_before_payload_build(self):
        mod = _load("appsync_feed_publisher_s28_0d")
        rec = lambda seq, key: {"eventName": "INSERT", "dynamodb": {"SequenceNumber": seq, "Keys": {key[0]: {"S": key[1]}}}}
        event = {"Records": [rec("1", ("project_id", "audit#ENC-TSK-1")), rec("2", ("project_id", "idem#enceladus#k")),
                             rec("3", ("document_id", "audit#DOC-X#t#c"))]}
        with patch.object(mod, "build_event_payload") as build:
            resp = mod.handler(event, None)
        build.assert_not_called()
        self.assertEqual(resp.get("batchItemFailures", []), [])


if __name__ == "__main__":
    unittest.main()
