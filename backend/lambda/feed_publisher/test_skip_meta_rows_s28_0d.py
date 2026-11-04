"""ENC-TSK-S28-0D: feed_publisher consumes audit#/idem# rows without dirtying a phantom project."""
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


def _sqs(mid, pk, key_attr="project_id"):
    body = {"dynamodb": {"Keys": {key_attr: {"S": pk}}, "NewImage": {"project_id": {"S": pk}, "record_type": {"S": "task"},
                                                                       "updated_at": {"S": "2026-11-04T00:00:00Z"}}}}
    return {"messageId": mid, "body": json.dumps(body)}


class SkipMetaRowsTests(unittest.TestCase):
    def test_extractors_skip_meta_rows_but_keep_real_rows_and_failures(self):
        fp = _load("feed_publisher_s28_0d")
        event = {"Records": [_sqs("m1", "audit#ENC-TSK-1"), _sqs("m2", "idem#enceladus#k"), _sqs("m3", "enceladus"),
                             {"messageId": "m4", "body": "not json"}]}
        affected, failed = fp._extract_project_ids_and_failures_from_sqs_event(event)
        self.assertEqual(affected, {"enceladus"})
        self.assertEqual(failed, ["m4"])  # skipped rows are consumed, malformed ones still retried
        work, failed2 = fp._extract_mark_work(event)
        self.assertEqual(set(work), {"enceladus"})
        self.assertEqual(failed2, ["m4"])
        self.assertNotIn("audit#ENC-TSK-1", fp._extract_project_activity_from_sqs_event(event))


if __name__ == "__main__":
    unittest.main()
