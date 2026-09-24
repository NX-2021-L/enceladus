"""Unit tests for devops-opensearch-backfill (ENC-TSK-L42)."""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


def _load_modules():
    if "boto3" not in sys.modules:
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = lambda *a, **k: None
        fake_boto3.resource = lambda *a, **k: None
        sys.modules["boto3"] = fake_boto3

    here = pathlib.Path(__file__).resolve().parent
    parent = here.parent / "opensearch_indexer"
    core_spec = importlib.util.spec_from_file_location("search_index_core", parent / "search_index_core.py")
    core = importlib.util.module_from_spec(core_spec)
    sys.modules["search_index_core"] = core
    core_spec.loader.exec_module(core)

    bf_spec = importlib.util.spec_from_file_location("opensearch_backfill_under_test", here / "lambda_function.py")
    backfill = importlib.util.module_from_spec(bf_spec)
    bf_spec.loader.exec_module(backfill)
    return core, backfill


CORE, BF = _load_modules()


class TestBuildIndexAction(unittest.TestCase):
    def test_tracker_task_action(self):
        record = {
            "project_id": "enceladus",
            "record_type": "task",
            "record_id": "ENC-TSK-L42",
            "title": "Backfill",
            "updated_at": "2026-07-05T04:00:00Z",
        }
        kind, payload = CORE.build_index_action(record, "records_v2")
        self.assertEqual(kind, "index")
        self.assertEqual(payload["meta"]["index"]["_index"], "records_v2")
        self.assertEqual(payload["meta"]["index"]["_id"], "enceladus#task#ENC-TSK-L42")
        self.assertEqual(payload["meta"]["index"]["version_type"], "external")


class TestBackfillHandler(unittest.TestCase):
    @patch.object(BF, "_iter_corpus")
    @patch.object(BF, "_flush_batch")
    def test_dry_run_counts_without_bulk(self, flush_batch, iter_corpus):
        flush_batch.return_value = (1, 0)
        iter_corpus.return_value = [
            (
                "tracker",
                {
                    "project_id": "enceladus",
                    "record_type": "task",
                    "record_id": "ENC-TSK-1",
                    "title": "A",
                    "updated_at": "2026-07-05T00:00:00Z",
                },
            ),
            ("tracker", {"project_id": "enceladus", "record_type": "reference", "record_id": "ref#1"}),
        ]
        result = BF.handler({"dry_run": True, "batch_size": 10}, None)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["indexed"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertTrue(result["dry_run"])
        flush_batch.assert_called_once()
        args, kwargs = flush_batch.call_args
        self.assertTrue(args[2])

    @patch.object(BF, "_iter_corpus")
    @patch.object(BF, "_flush_batch")
    def test_target_index_override(self, flush_batch, iter_corpus):
        flush_batch.return_value = (0, 0)
        iter_corpus.return_value = []
        result = BF.handler({"target_index": "records_v3"}, None)
        self.assertEqual(result["target_index"], "records_v3")


if __name__ == "__main__":
    unittest.main()
