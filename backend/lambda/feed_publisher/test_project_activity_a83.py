"""DVP-TSK-A83 -- feed_publisher stamps projects.last_activity_at from tracker stream events.

Pins: one conditional UpdateItem per project per batch carrying the batch max; the monotonic
condition (and the project-row-must-exist guard against upserting a stub row); conditional
failures and any other write error are swallowed; documents events and reference rows never
count; the stamp happens before feed regeneration and survives a failed regeneration.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "feed_publisher_lambda_a83",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
fp = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(fp)


def _tracker(project, updated_at, *, record_type="task", record_id=None, event="MODIFY"):
    image = {"project_id": {"S": project}, "record_type": {"S": record_type}}
    if updated_at is not None:
        image["updated_at"] = {"S": updated_at}
    return {
        "eventName": event,
        "dynamodb": {
            "Keys": {"project_id": {"S": project}, "record_id": {"S": record_id or f"{record_type}#{project}-1"}},
            "NewImage": image,
        },
    }


def _document(project, updated_at):
    return {
        "eventName": "MODIFY",
        "dynamodb": {
            "Keys": {"document_id": {"S": "DOC-1"}},
            "NewImage": {"project_id": {"S": project}, "updated_at": {"S": updated_at}},
        },
    }


def _event(*payloads):
    return {
        "Records": [
            {"messageId": f"m{i}", "body": json.dumps(p)} for i, p in enumerate(payloads, start=1)
        ]
    }


def _cond_failed():
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")


def test_one_conditional_update_per_project_with_the_batch_max():
    event = _event(
        _tracker("alpha", "2026-10-12T01:00:00Z"),
        _tracker("beta", "2026-10-12T02:00:00Z"),
        _tracker("alpha", "2026-10-12T05:30:00Z"),  # newest for alpha
        _tracker("alpha", "2026-10-12T03:00:00Z"),
        _tracker("beta", "2026-10-12T02:00:01+00:00"),  # newest for beta, different format
        _tracker("beta", "2026-10-11T23:59:59Z"),
    )
    ddb = MagicMock()

    written = fp._record_project_activity(fp._extract_project_activity_from_sqs_event(event), ddb=ddb)

    assert written == 2
    assert ddb.update_item.call_count == 2
    by_project = {c.kwargs["Key"]["project_id"]["S"]: c.kwargs for c in ddb.update_item.call_args_list}
    assert set(by_project) == {"alpha", "beta"}
    assert by_project["alpha"]["ExpressionAttributeValues"] == {":ts": {"S": "2026-10-12T05:30:00Z"}}
    assert by_project["beta"]["ExpressionAttributeValues"] == {":ts": {"S": "2026-10-12T02:00:01Z"}}
    for kwargs in by_project.values():
        assert kwargs["TableName"] == fp.PROJECTS_TABLE
        assert kwargs["UpdateExpression"] == "SET last_activity_at = :ts"
        # monotonic max, and never upsert a stub row for a project that is not registered
        assert "attribute_not_exists(last_activity_at) OR last_activity_at < :ts" in kwargs["ConditionExpression"]
        assert kwargs["ConditionExpression"].startswith("attribute_exists(project_id)")


def test_timestamps_are_canonicalised_so_string_comparison_orders_correctly():
    activity = fp._extract_project_activity_from_sqs_event(
        _event(
            _tracker("alpha", "2026-10-12T09:00:00.250000+00:00"),
            _tracker("alpha", "2026-10-12T04:00:00-07:00"),  # = 11:00:00Z, the newest
            _tracker("beta", "2026-10-12T04:00:00"),  # naive -> UTC
        )
    )
    assert activity == {"alpha": "2026-10-12T11:00:00Z", "beta": "2026-10-12T04:00:00Z"}


def test_conditional_failure_is_swallowed_and_other_projects_still_written():
    ddb = MagicMock()
    ddb.update_item.side_effect = [_cond_failed(), None]

    written = fp._record_project_activity(
        {"alpha": "2026-10-12T05:00:00Z", "beta": "2026-10-12T06:00:00Z"}, ddb=ddb
    )

    assert ddb.update_item.call_count == 2
    assert written == 1


def test_other_write_errors_are_swallowed_too():
    ddb = MagicMock()
    ddb.update_item.side_effect = [
        ClientError({"Error": {"Code": "AccessDeniedException"}}, "UpdateItem"),
        RuntimeError("socket closed"),
    ]

    assert fp._record_project_activity({"a": "2026-10-12T05:00:00Z", "b": "2026-10-12T06:00:00Z"}, ddb=ddb) == 0
    assert ddb.update_item.call_count == 2


def test_documents_events_reference_rows_and_unusable_records_do_not_count():
    event = _event(
        _document("alpha", "2026-10-12T09:00:00Z"),
        _tracker("alpha", "2026-10-12T08:00:00Z", record_type="reference"),
        _tracker("alpha", None),  # no updated_at
        _tracker("alpha", "garbage"),
        _tracker("alpha", "2026-10-12T01:00:00Z"),  # the only countable record
    )
    removal = _tracker("beta", "2026-10-12T02:00:00Z", event="REMOVE")
    removal["dynamodb"]["OldImage"] = removal["dynamodb"].pop("NewImage")  # REMOVE has no NewImage
    event["Records"].append({"messageId": "rm", "body": json.dumps(removal)})
    event["Records"].append({"messageId": "bad", "body": "{not json"})
    event["Records"].append({"messageId": "list", "body": "[1, 2]"})
    activity = fp._extract_project_activity_from_sqs_event(event)
    assert activity == {"alpha": "2026-10-12T01:00:00Z"}  # a removal is not activity


def test_no_activity_means_no_client_and_no_calls():
    with patch.object(fp, "_ddb_client") as make_client:
        assert fp._record_project_activity({}) == 0
    make_client.assert_not_called()


def test_dry_run_writes_nothing():
    ddb = MagicMock()
    with patch.object(fp, "DRY_RUN", True):
        assert fp._record_project_activity({"alpha": "2026-10-12T01:00:00Z"}, ddb=ddb) == 0
    ddb.update_item.assert_not_called()


def test_handler_stamps_activity_before_regeneration_and_survives_its_failure():
    event = _event(
        _tracker("alpha", "2026-10-12T01:00:00Z"),
        _tracker("alpha", "2026-10-12T02:00:00Z"),
        _tracker("beta", "2026-10-12T03:00:00Z"),
        _document("alpha", "2026-10-12T23:00:00Z"),
    )
    ddb = MagicMock()
    with patch.object(fp, "_all_project_entries", return_value=[]), patch.object(
        fp, "_ddb_client", return_value=ddb
    ), patch.object(fp, "generate_mobile_feeds", side_effect=RuntimeError("boom")):
        actual = fp.handler(event, None)

    assert actual == {
        "batchItemFailures": [{"itemIdentifier": f"m{i}"} for i in range(1, 5)]
    }
    stamped = {
        c.kwargs["Key"]["project_id"]["S"]: c.kwargs["ExpressionAttributeValues"][":ts"]["S"]
        for c in ddb.update_item.call_args_list
    }
    assert stamped == {"alpha": "2026-10-12T02:00:00Z", "beta": "2026-10-12T03:00:00Z"}
    assert ddb.update_item.call_count == 2


def test_handler_does_not_fail_the_batch_when_the_stamp_blows_up():
    event = _event(_tracker("alpha", "2026-10-12T01:00:00Z"))
    ddb = MagicMock()
    ddb.update_item.side_effect = RuntimeError("ddb down")
    with patch.object(fp, "_all_project_entries", return_value=[]), patch.object(
        fp, "_ddb_client", return_value=ddb
    ), patch.object(fp, "generate_mobile_feeds"), patch.object(
        fp, "generate_documents_feed"
    ), patch.object(fp, "check_freshness_sla"), patch.object(
        fp, "generate_reference_docs_from_s3"
    ), patch.object(fp, "publish_mobile_feeds_to_s3", return_value=[]), patch.object(
        fp, "invalidate_mobile_cf", return_value="INV-1"
    ), patch.object(fp.boto3, "client", return_value=MagicMock()):
        actual = fp.handler(event, None)

    assert actual == {}
