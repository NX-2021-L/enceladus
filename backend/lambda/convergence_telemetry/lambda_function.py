"""enceladus-convergence-telemetry Lambda (ENC-FTR-086 Ph1 / ENC-TSK-I82).

The Convergence Surface fan-out + increment Lambda. A single deployed function
serves two event sources, dispatched on ``eventSource``:

1. DynamoDB Stream (tracker table) -> FAN-OUT (AC-2)
   For each INSERT/MODIFY tracker record, canonicalize the open-taxonomy field
   values (category, priority, tags) and emit one SQS FIFO message per
   (attribute, canonical_value), partitioned by attribute_name (MessageGroupId)
   with a deterministic MessageDeduplicationId.

2. SQS FIFO (enceladus-convergence-telemetry-queue.fifo) -> INCREMENT (AC-5)
   Consume the fan-out messages and idempotently increment the canonical
   counters in the DynamoDB counter table, evicting the lowest-count entry when
   an attribute partition exceeds the 10k cap (AC-4).

D1 architectural separation (ENC-FTR-086): this Lambda has its own IAM role and
imports nothing from the governance Lambdas. The tracker mutation path never
waits on this Lambda — it is a fire-and-forget, read-only-derived telemetry
surface; failures here never affect governed writes.

Environment variables:
  CONVERGENCE_TABLE        DynamoDB counter table name
  CONVERGENCE_QUEUE_URL    SQS FIFO queue URL (fan-out target)
  CONVERGENCE_TTL_DAYS     Sliding TTL applied to expires_at (default 90)
  CONVERGENCE_CAP          Per-attribute capacity cap (default 10000)
  DYNAMODB_REGION          AWS region (default us-west-2)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from canonicalize import CANON_VERSION, OPEN_TAXONOMY_FIELDS, canonical_values
from counter_store import DEFAULT_CAP, record_observation

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

QUEUE_URL = os.environ.get("CONVERGENCE_QUEUE_URL", "")
TTL_DAYS = int(os.environ.get("CONVERGENCE_TTL_DAYS", "90"))
CAP = int(os.environ.get("CONVERGENCE_CAP", str(DEFAULT_CAP)))
IDEMPOTENCY_TTL_DAYS = int(os.environ.get("CONVERGENCE_IDEMPOTENCY_TTL_DAYS", "7"))

_sqs = None
_store = None


def _get_sqs():
    global _sqs
    if _sqs is None:
        import boto3

        region = os.environ.get("DYNAMODB_REGION") or os.environ.get("AWS_REGION", "us-west-2")
        _sqs = boto3.client("sqs", region_name=region)
    return _sqs


def _get_store():
    global _store
    if _store is None:
        from counter_store import DynamoCounterStore

        _store = DynamoCounterStore()
    return _store


# ---------------------------------------------------------------------------
# DynamoDB stream image helpers
# ---------------------------------------------------------------------------

def _deserialize_image(image: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DynamoDB stream NewImage (typed) to plain Python values."""
    from boto3.dynamodb.types import TypeDeserializer

    deser = TypeDeserializer()
    out: Dict[str, Any] = {}
    for key, typed in (image or {}).items():
        try:
            out[key] = deser.deserialize(typed)
        except Exception:  # pragma: no cover - defensive against odd attrs
            continue
    return out


def _extract_author(record: Dict[str, Any]) -> str:
    write_source = record.get("write_source")
    if isinstance(write_source, dict):
        provider = write_source.get("provider")
        if provider:
            return str(provider)
    return str(record.get("created_by") or "")


def make_dedup_id(record_id: str, field: str, canonical_value: str, version_token: str) -> str:
    """Deterministic dedup id for one (record-version, attribute, value) observation.

    Including ``version_token`` (the record's updated_at) means a later mutation
    of the same record counts as a new observation, while stream retries of the
    same record-version dedup to a single count.
    """
    raw = f"{record_id}|{field}|{canonical_value}|{version_token}|canon{CANON_VERSION}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _attribute_name(project_id: str, record_type: str, field: str) -> str:
    return f"{project_id}#{record_type}#{field}"


# ---------------------------------------------------------------------------
# Fan-out path (DynamoDB stream -> SQS FIFO)
# ---------------------------------------------------------------------------

def _fanout_messages(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the per-(attribute,value) fan-out messages for one tracker record."""
    project_id = str(record.get("project_id") or "")
    record_type = str(record.get("record_type") or "")
    record_id = str(record.get("record_id") or record.get("item_id") or "")
    version_token = str(record.get("updated_at") or record.get("sync_version") or "")
    author = _extract_author(record)

    if not (project_id and record_type and record_id):
        return []

    messages: List[Dict[str, Any]] = []
    for field in OPEN_TAXONOMY_FIELDS:
        if field not in record:
            continue
        for canon in canonical_values(record.get(field)):
            attribute_name = _attribute_name(project_id, record_type, field)
            dedup_id = make_dedup_id(record_id, field, canon, version_token)
            messages.append(
                {
                    "attribute_name": attribute_name,
                    "canonical_value": canon,
                    "project_id": project_id,
                    "record_type": record_type,
                    "record_id": record_id,
                    "field": field,
                    "author": author,
                    "observed_at": version_token,
                    "dedup_id": dedup_id,
                    "canon_version": CANON_VERSION,
                }
            )
    return messages


def _handle_fanout(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    sqs = _get_sqs()
    sent = 0
    for rec in records:
        if rec.get("eventName") not in ("INSERT", "MODIFY"):
            continue
        new_image = rec.get("dynamodb", {}).get("NewImage")
        if not new_image:
            continue
        plain = _deserialize_image(new_image)
        for msg in _fanout_messages(plain):
            if not QUEUE_URL:
                logger.warning("CONVERGENCE_QUEUE_URL unset; dropping fan-out message")
                continue
            sqs.send_message(
                QueueUrl=QUEUE_URL,
                MessageBody=json.dumps(msg),
                MessageGroupId=msg["attribute_name"],
                MessageDeduplicationId=msg["dedup_id"],
            )
            sent += 1
    logger.info("convergence fan-out: %d messages sent from %d records", sent, len(records))
    return {"fanned_out": sent, "source_records": len(records)}


# ---------------------------------------------------------------------------
# Increment path (SQS FIFO -> counter table)
# ---------------------------------------------------------------------------

def _expires_at(now_epoch: Optional[int] = None) -> int:
    base = now_epoch if now_epoch is not None else int(time.time())
    return base + TTL_DAYS * 86400


def _idem_expires_at(now_epoch: Optional[int] = None) -> int:
    base = now_epoch if now_epoch is not None else int(time.time())
    return base + IDEMPOTENCY_TTL_DAYS * 86400


def process_message(store, body: Dict[str, Any], now_epoch: Optional[int] = None) -> Dict[str, Any]:
    """Idempotently apply one fan-out message to the counter store."""
    return record_observation(
        store,
        body["attribute_name"],
        body["canonical_value"],
        dedup_id=body["dedup_id"],
        observed_at=str(body.get("observed_at") or ""),
        author=str(body.get("author") or ""),
        expires_at=_expires_at(now_epoch),
        cap=CAP,
    )


def _handle_increment(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    store = _get_store()
    failures: List[Dict[str, str]] = []
    for rec in records:
        message_id = rec.get("messageId", "")
        try:
            body = json.loads(rec.get("body") or "{}")
            process_message(store, body)
        except Exception:  # noqa: BLE001 - report to SQS for redrive, never crash batch
            logger.exception("convergence increment failed for message %s", message_id)
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    records = event.get("Records", []) if isinstance(event, dict) else []
    if not records:
        return {"status": "noop", "reason": "no records"}

    source = records[0].get("eventSource") or records[0].get("EventSource") or ""
    if source == "aws:sqs":
        return _handle_increment(records)
    if source == "aws:dynamodb":
        return _handle_fanout(records)

    logger.warning("convergence: unrecognized event source %r", source)
    return {"status": "noop", "reason": f"unrecognized source {source!r}"}
