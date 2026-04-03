"""Unit tests for feed_publisher Lambda event parsing.

Focuses on stream-to-SQS payload parsing so both tracker and documents stream
events trigger feed regeneration for the correct project IDs.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "feed_publisher_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_publisher = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_publisher)


def _sqs_record(payload: dict | None = None, *, message_id: str = "msg-1", raw_body: str | None = None) -> dict:
    body = raw_body if raw_body is not None else json.dumps(payload or {})
    return {"messageId": message_id, "body": body}


def test_extract_project_ids_from_tracker_and_documents_events():
    tracker_payload = {
        "eventName": "MODIFY",
        "dynamodb": {
            "Keys": {"record_id": {"S": "task#ENC-TSK-001"}},
            "NewImage": {"project_id": {"S": "enceladus"}},
        },
    }
    documents_payload = {
        "eventName": "INSERT",
        "dynamodb": {
            "Keys": {"document_id": {"S": "DOC-ABC123"}},
            "NewImage": {"project_id": {"S": "devops"}},
        },
    }
    event = {
        "Records": [
            _sqs_record(tracker_payload),
            _sqs_record(documents_payload),
        ]
    }

    actual = feed_publisher._extract_project_ids_from_sqs_event(event)

    assert actual == {"enceladus", "devops"}


def test_extract_project_ids_falls_back_to_old_image():
    payload = {
        "eventName": "REMOVE",
        "dynamodb": {
            "OldImage": {"project_id": {"S": "enceladus"}},
        },
    }
    event = {"Records": [_sqs_record(payload)]}

    actual = feed_publisher._extract_project_ids_from_sqs_event(event)

    assert actual == {"enceladus"}


def test_extract_project_ids_ignores_malformed_records():
    event = {
        "Records": [
            {"body": "not-json"},
            _sqs_record({"eventName": "MODIFY", "dynamodb": {"NewImage": {}}}),
        ]
    }

    actual = feed_publisher._extract_project_ids_from_sqs_event(event)

    assert actual == set()


def test_handler_returns_batch_item_failures_for_malformed_records():
    event = {
        "Records": [
            _sqs_record(raw_body="not-json", message_id="bad-1"),
            _sqs_record(
                {
                    "eventName": "MODIFY",
                    "dynamodb": {"NewImage": {"project_id": {"S": "enceladus"}}},
                },
                message_id="good-1",
            ),
        ]
    }

    with patch.object(feed_publisher, "_all_project_entries", return_value=[]), patch.object(
        feed_publisher, "_ddb_client", return_value=MagicMock()
    ), patch.object(
        feed_publisher, "generate_mobile_feeds"
    ), patch.object(
        feed_publisher, "generate_documents_feed"
    ), patch.object(
        feed_publisher, "check_freshness_sla"
    ), patch.object(
        feed_publisher, "generate_reference_docs_from_s3"
    ), patch.object(
        feed_publisher, "publish_mobile_feeds_to_s3", return_value=[]
    ), patch.object(
        feed_publisher, "invalidate_mobile_cf", return_value="INV-1"
    ), patch.object(
        feed_publisher.boto3, "client", return_value=MagicMock()
    ):
        actual = feed_publisher.handler(event, None)

    assert actual == {"batchItemFailures": [{"itemIdentifier": "bad-1"}]}


def test_handler_marks_entire_batch_failed_when_global_generation_fails():
    event = {
        "Records": [
            _sqs_record(
                {
                    "eventName": "MODIFY",
                    "dynamodb": {"NewImage": {"project_id": {"S": "enceladus"}}},
                },
                message_id="msg-1",
            ),
            _sqs_record(
                {
                    "eventName": "INSERT",
                    "dynamodb": {"NewImage": {"project_id": {"S": "devops"}}},
                },
                message_id="msg-2",
            ),
        ]
    }

    with patch.object(feed_publisher, "_all_project_entries", return_value=[]), patch.object(
        feed_publisher, "_ddb_client", return_value=MagicMock()
    ), patch.object(
        feed_publisher, "generate_mobile_feeds", side_effect=RuntimeError("boom")
    ):
        actual = feed_publisher.handler(event, None)

    assert actual == {
        "batchItemFailures": [
            {"itemIdentifier": "msg-1"},
            {"itemIdentifier": "msg-2"},
        ]
    }
