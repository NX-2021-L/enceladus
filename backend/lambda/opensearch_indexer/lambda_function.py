#!/usr/bin/env python3
"""devops-opensearch-indexer — CDC indexer for B67 Search2.0 (ENC-TSK-L41).

ENC-TSK-L84: EventBridge Pipes with a DynamoDB Streams source were confirmed
account-wide non-functional (StateReason=No records processed, zero
throughput across 6 clean remediation attempts including a full delete+
recreate -- see ENC-ISS-497). CDC now runs via direct
AWS::Lambda::EventSourceMapping on the tracker and documents DynamoDB streams
(same pattern as the working AppSyncFeedTrackerStreamTrigger in
06-appsync-events.yaml). This handler accepts BOTH event shapes so the old
SQS-fed path (SearchIndexSqsTrigger, now disabled but not deleted) and the new
direct-stream path can coexist during rollback windows:
  - SQS-wrapped: event.Records[].body is a JSON string containing the raw
    DynamoDB stream record. Failure identifier = SQS messageId.
  - Direct DynamoDB Streams ESM: event.Records[] IS the raw stream record
    (eventName/dynamodb at the top level, no body/messageId). Failure
    identifier = dynamodb.SequenceNumber per the DynamoDB Streams
    ReportBatchItemFailures contract (NOT eventID).

Bulk-upserts tracker and document mutations into OpenSearch via the
records_write alias; REMOVE deletes by stable natural key.

Idempotency (interim until ENC-TSK-L27 version_seq):
  _id = {project_id}#{record_type}#{bare_record_id}
  external version = updated_at epoch milliseconds (version_seq field)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from search_index_core import (
    SKIP_RECORD_TYPES,
    _deser_image,
    _normalize_record,
    _stable_doc_id,
    bulk_execute,
    build_index_action,
    is_success_status,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

WRITE_ALIAS = os.environ.get("OPENSEARCH_WRITE_ALIAS", "records_write")


def _extract_remove_record_id(keys: Dict[str, Any], old_record: Dict[str, Any]) -> str:
    for key_name in ("record_id", "document_id"):
        typed = keys.get(key_name) or {}
        value = str(typed.get("S") or "").strip()
        if value:
            return value
    for key_name in ("record_id", "document_id"):
        value = str(old_record.get(key_name) or "").strip()
        if value:
            return value
    return ""


def _extract_stream_record(sqs_body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if isinstance(sqs_body, str):
        try:
            sqs_body = json.loads(sqs_body)
        except json.JSONDecodeError:
            return None
    if "dynamodb" in sqs_body:
        return sqs_body
    return sqs_body


def _record_source_and_identifier(raw_record: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Classify a Records[] entry as 'sqs' or 'ddb_stream' and return its
    ReportBatchItemFailures identifier (messageId for SQS, SequenceNumber for
    a direct DynamoDB Streams ESM)."""
    if "body" in raw_record or "messageId" in raw_record or "messageID" in raw_record:
        message_id = raw_record.get("messageId") or raw_record.get("messageID")
        return "sqs", message_id
    # Direct DynamoDB Streams ESM: the record itself has eventName/dynamodb.
    sequence_number = (raw_record.get("dynamodb") or {}).get("SequenceNumber")
    return "ddb_stream", sequence_number


def _stream_record_to_action(stream_record: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Return ('index', meta+doc) or ('delete', meta) or None to skip."""
    event_name = stream_record.get("eventName", "")
    dynamodb = stream_record.get("dynamodb", {})

    if event_name in ("INSERT", "MODIFY"):
        new_image = dynamodb.get("NewImage", {})
        if not new_image:
            return None
        record = _normalize_record(_deser_image(new_image))
        return build_index_action(record, WRITE_ALIAS)

    if event_name == "REMOVE":
        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record(_deser_image(old_image)) if old_image else {}
        raw_id = _extract_remove_record_id(dynamodb.get("Keys", {}), old_record)
        if not raw_id:
            return None
        record_type = str(old_record.get("record_type") or "").strip()
        if not record_type and old_record.get("document_id"):
            record_type = "document"
        if record_type in SKIP_RECORD_TYPES:
            return None
        project_id = str(old_record.get("project_id") or "").strip()
        if not project_id or not record_type:
            return None
        doc_id = _stable_doc_id(project_id, record_type, raw_id)
        meta = {"delete": {"_index": WRITE_ALIAS, "_id": doc_id}}
        return ("delete", {"meta": meta})

    return None


def _batch_failure_response(identifiers: List[str]) -> Dict[str, Any]:
    failures = []
    seen = set()
    for identifier in identifiers:
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        failures.append({"itemIdentifier": identifier})
    if not failures:
        return {}
    return {"batchItemFailures": failures}


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    records = event.get("Records") or []
    if not records:
        return {}

    failed_identifiers: List[str] = []
    bulk_actions: List[Tuple[str, Dict[str, Any]]] = []
    bulk_record_indexes: List[int] = []
    record_identifiers: List[Optional[str]] = []

    for idx, raw_record in enumerate(records):
        source, identifier = _record_source_and_identifier(raw_record)
        record_identifiers.append(identifier)
        try:
            if source == "sqs":
                body_raw = raw_record.get("body", "{}")
                body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
                stream_record = _extract_stream_record(body)
            else:
                stream_record = raw_record
            if not stream_record or "dynamodb" not in stream_record:
                continue
            action = _stream_record_to_action(stream_record)
            if action is not None:
                bulk_record_indexes.append(idx)
                bulk_actions.append(action)
        except Exception:
            logger.exception(
                "[ERROR] Failed to parse %s record identifier=%s", source, identifier
            )
            if identifier:
                failed_identifiers.append(identifier)

    if bulk_actions:
        try:
            bulk_results = bulk_execute(bulk_actions, WRITE_ALIAS)
            for bulk_idx, (status, _result) in enumerate(bulk_results):
                if is_success_status(status):
                    continue
                rec_idx = bulk_record_indexes[bulk_idx]
                identifier = record_identifiers[rec_idx]
                if identifier:
                    failed_identifiers.append(identifier)
        except Exception:
            logger.exception("[ERROR] OpenSearch bulk execute failed")
            for rec_idx in bulk_record_indexes:
                identifier = record_identifiers[rec_idx]
                if identifier:
                    failed_identifiers.append(identifier)

    logger.info(
        "[INFO] Batch complete: total=%d bulk=%d failures=%d",
        len(records),
        len(bulk_actions),
        len(failed_identifiers),
    )
    return _batch_failure_response(failed_identifiers)
