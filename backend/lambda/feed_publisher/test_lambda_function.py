"""Unit tests for feed_publisher Lambda event parsing.

Focuses on stream-to-SQS payload parsing so both tracker and documents stream
events trigger feed regeneration for the correct project IDs.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "feed_publisher_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
feed_publisher = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(feed_publisher)


def _sqs_record(payload: dict) -> dict:
    return {"body": json.dumps(payload)}


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
