"""Unit tests for devops-opensearch-indexer (ENC-TSK-L41)."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types
import unittest
from unittest.mock import patch


def _load_module(name: str, filename: str):
    if "boto3" not in sys.modules:
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = lambda *a, **k: None
        sys.modules["boto3"] = fake_boto3
    if "botocore.exceptions" not in sys.modules:
        fake_botocore = types.ModuleType("botocore.exceptions")
        fake_botocore.ClientError = Exception
        sys.modules["botocore.exceptions"] = fake_botocore

    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(name, here / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORE = _load_module("search_index_core_under_test", "search_index_core.py")
sys.modules["search_index_core"] = CORE
IDX = _load_module("opensearch_indexer_under_test", "lambda_function.py")


class TestRecordMapping(unittest.TestCase):
    def test_tracker_document_fields(self):
        record = {
            "project_id": "enceladus",
            "record_type": "task",
            "record_id": "task#ENC-TSK-123",
            "title": "Fix search",
            "description": "Details here",
            "status": "open",
            "priority": "P1",
            "tags": ["search"],
            "created_at": "2026-07-05T00:00:00Z",
            "updated_at": "2026-07-05T01:00:00Z",
        }
        doc = CORE._build_search_document(record)
        self.assertEqual(doc["title"], "Fix search")
        self.assertEqual(doc["version_seq"], CORE._parse_epoch_ms(record["updated_at"]))
        doc_id = CORE._stable_doc_id("enceladus", "task", record["record_id"])
        self.assertEqual(doc_id, "enceladus#task#ENC-TSK-123")

    def test_document_uses_full_description_as_body(self):
        record = {
            "document_id": "DOC-ABC",
            "record_type": "document",
            "project_id": "enceladus",
            "title": "Architecture note",
            "full_description": "Long body text",
            "status": "active",
            "updated_at": "2026-07-05T02:00:00Z",
        }
        doc = CORE._build_search_document(record)
        self.assertEqual(doc["body"], "Long body text")
        self.assertEqual(doc["record_type"], "document")

    def test_reference_records_skipped(self):
        self.assertIsNone(
            CORE._build_search_document(
                {"project_id": "enceladus", "record_type": "reference", "record_id": "ref#1"}
            )
        )


class TestStreamActions(unittest.TestCase):
    def test_modify_builds_index_action(self):
        stream = {
            "eventName": "MODIFY",
            "dynamodb": {
                "NewImage": {
                    "project_id": {"S": "enceladus"},
                    "record_type": {"S": "task"},
                    "record_id": {"S": "ENC-TSK-999"},
                    "title": {"S": "Hello"},
                    "updated_at": {"S": "2026-07-05T03:00:00Z"},
                }
            },
        }
        kind, payload = IDX._stream_record_to_action(stream)
        self.assertEqual(kind, "index")
        self.assertEqual(payload["meta"]["index"]["_id"], "enceladus#task#ENC-TSK-999")

    def test_remove_builds_delete_action(self):
        stream = {
            "eventName": "REMOVE",
            "dynamodb": {
                "Keys": {"document_id": {"S": "DOC-REMOVE-1"}},
                "OldImage": {
                    "document_id": {"S": "DOC-REMOVE-1"},
                    "record_type": {"S": "document"},
                    "project_id": {"S": "enceladus"},
                },
            },
        }
        kind, payload = IDX._stream_record_to_action(stream)
        self.assertEqual(kind, "delete")
        self.assertEqual(payload["meta"]["delete"]["_id"], "enceladus#document#DOC-REMOVE-1")


class TestHandler(unittest.TestCase):
    @patch.dict(
        CORE.__dict__,
        {"OPENSEARCH_ENDPOINT": "https://127.0.0.1:9200", "_admin_password": "secret"},
    )
    @patch.object(IDX, "bulk_execute")
    def test_report_batch_item_failures(self, bulk_execute):
        bulk_execute.return_value = [(500, {"error": "boom"})]
        event = {
            "Records": [
                {
                    "messageId": "good-1",
                    "body": json.dumps(
                        {
                            "eventName": "MODIFY",
                            "dynamodb": {
                                "NewImage": {
                                    "project_id": {"S": "enceladus"},
                                    "record_type": {"S": "task"},
                                    "record_id": {"S": "ENC-TSK-1"},
                                    "title": {"S": "A"},
                                    "updated_at": {"S": "2026-07-05T00:00:00Z"},
                                }
                            },
                        }
                    ),
                }
            ]
        }
        result = IDX.handler(event, None)
        self.assertEqual(result, {"batchItemFailures": [{"itemIdentifier": "good-1"}]})

    @patch.dict(
        CORE.__dict__,
        {"OPENSEARCH_ENDPOINT": "https://127.0.0.1:9200", "_admin_password": "secret"},
    )
    @patch.object(IDX, "bulk_execute")
    def test_version_conflict_is_success(self, bulk_execute):
        bulk_execute.return_value = [(409, {"error": {"type": "version_conflict_engine_exception"}})]
        event = {
            "Records": [
                {
                    "messageId": "ok-1",
                    "body": json.dumps(
                        {
                            "eventName": "MODIFY",
                            "dynamodb": {
                                "NewImage": {
                                    "project_id": {"S": "enceladus"},
                                    "record_type": {"S": "task"},
                                    "record_id": {"S": "ENC-TSK-2"},
                                    "title": {"S": "B"},
                                    "updated_at": {"S": "2026-07-05T00:00:00Z"},
                                }
                            },
                        }
                    ),
                }
            ]
        }
        result = IDX.handler(event, None)
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
