"""ENC-TSK-S28-0D: governance_audit does not inspect audit#/idem# rows (no write_source by design)."""
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
    def test_meta_rows_never_reach_write_source_check(self):
        mod = _load("governance_audit_s28_0d")
        rec = lambda pk: {"eventName": "INSERT", "eventSource": "aws:dynamodb",
                          "dynamodb": {"Keys": {"project_id": {"S": pk}}, "NewImage": {"project_id": {"S": pk}}}}
        with patch.object(mod, "_check_write_source") as check:
            mod.handler({"Records": [rec("audit#ENC-TSK-1"), rec("idem#enceladus#k")]}, None)
            check.assert_not_called()
            mod.handler({"Records": [rec("enceladus")]}, None)
            check.assert_called_once()


if __name__ == "__main__":
    unittest.main()
