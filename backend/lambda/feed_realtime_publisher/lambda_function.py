#!/usr/bin/env python3
"""devops-feed-realtime-publisher — DynamoDB Streams → AppSync Events publisher.

This is the real-time delta path required by ENC-TSK-B67 (PWA 2.0 Governance
Cockpit), complementing the existing SQS-FIFO → S3 snapshot pipeline
(``feed_publisher``) which is preserved as the cold-start source and WebSocket
fallback (AC-4). The two are complementary: S3 for snapshots, AppSync Events for
live sub-500ms deltas (DOC-E470AC8CE9A8 §2.1).

Pipeline (AC-2):

    DynamoDB Streams (NEW_AND_OLD_IMAGES on devops-project-tracker)
      → Event Source Mapping (BatchSize=1, MaximumBatchingWindowInSeconds=0,
        ReportBatchItemFailures=true)
      → this Lambda
      → build lightweight event payload (realtime_payload.build_event_payload)
      → HTTP POST to AppSync Events endpoint on channels:
          /feed/updates, /records/{recordId}, /projects/{projectId}

Both PWA mutations and MCP agent writes land in the same DynamoDB table and
therefore flow through the same Streams trigger — source-agnostic propagation
(AC-2 / AC-8).

Environment variables:
  APPSYNC_EVENTS_HTTP_ENDPOINT   AppSync Events HTTP endpoint
                                 (https://<id>.appsync-api.<region>.amazonaws.com/event)
  APPSYNC_EVENTS_API_KEY         API key for the Events API (x-api-key header)
  APPSYNC_REGION                 region (default: us-west-2) — for SigV4 if no key
  DRY_RUN                        "true" to skip the HTTP POST (unit/integration)
  MAX_SUMMARY_BYTES              soft cap for the payload (default 500, AC-23)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

try:
    from realtime_payload import (
        appsync_endpoint,
        build_event_payload,
        channels_for_event,
        payload_size_bytes,
    )
except ImportError as exc:  # pragma: no cover - import guard
    logger.error("realtime_payload not bundled in the Lambda package: %s", exc)
    raise

DRY_RUN = os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"}
APPSYNC_API_KEY = os.environ.get("APPSYNC_EVENTS_API_KEY", "")
MAX_PAYLOAD_BYTES = int(os.environ.get("MAX_SUMMARY_BYTES", "500"))

try:  # boto3 is only needed for the live HTTP POST; tests run without it.
    from boto3.dynamodb.types import TypeDeserializer

    _deserializer = TypeDeserializer()
except Exception:  # pragma: no cover - boto3 absent in pure unit context
    _deserializer = None


def _deserialize_image(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DynamoDB Streams typed image into a plain dict."""
    if not raw:
        return {}
    if _deserializer is not None:
        out: Dict[str, Any] = {}
        for key, val in raw.items():
            try:
                out[key] = _deserializer.deserialize(val)
            except Exception:
                out[key] = _shallow_unwrap(val)
        return out
    return {k: _shallow_unwrap(v) for k, v in raw.items()}


def _shallow_unwrap(val: Any) -> Any:
    """Minimal DynamoDB attribute-value unwrap (boto3-free fallback)."""
    if not isinstance(val, dict) or not val:
        return val
    tag, inner = next(iter(val.items()))
    if tag in ("S", "N"):
        return float(inner) if tag == "N" and _is_number(inner) else inner
    if tag == "BOOL":
        return bool(inner)
    if tag == "NULL":
        return None
    if tag == "L":
        return [_shallow_unwrap(x) for x in inner]
    if tag in ("SS", "NS"):
        return list(inner)
    if tag == "M":
        return {k: _shallow_unwrap(v) for k, v in inner.items()}
    return inner


def _is_number(s: Any) -> bool:
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False


def _post_to_appsync(channel: str, payload: Dict[str, Any]) -> None:
    """HTTP POST a single event to one AppSync Events channel.

    AppSync Events expects {"channel": "<name>", "events": ["<json string>"]}.
    """
    endpoint = appsync_endpoint()
    if DRY_RUN or not endpoint:
        logger.info("DRY_RUN/no-endpoint: would publish to %s: %s", channel, payload.get("eventId"))
        return

    import urllib.request

    body = json.dumps(
        {"channel": channel, "events": [json.dumps(payload, separators=(",", ":"))]}
    ).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if APPSYNC_API_KEY:
        headers["x-api-key"] = APPSYNC_API_KEY

    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        if resp.status >= 300:
            raise RuntimeError(f"AppSync publish failed: HTTP {resp.status}")


def process_record(record: Dict[str, Any], now_ms: int | None = None) -> Dict[str, Any]:
    """Build and publish the event payload for a single stream record.

    Returns a small result dict for logging/testing. Raises on publish failure
    so the caller can register a partial-batch failure.
    """
    ddb = record.get("dynamodb", {})
    new_image = _deserialize_image(ddb.get("NewImage", {}))
    old_image = _deserialize_image(ddb.get("OldImage", {}))
    approx_ms = None
    approx = ddb.get("ApproximateCreationDateTime")
    if approx is not None:
        try:
            approx_ms = int(float(approx) * 1000)
        except (TypeError, ValueError):
            approx_ms = None

    payload = build_event_payload(
        event_name=record.get("eventName", "MODIFY"),
        new_image=new_image,
        old_image=old_image,
        approx_creation_ms=approx_ms,
        now_ms=now_ms,
    )
    if payload is None:
        return {"skipped": True}

    size = payload_size_bytes(payload)
    if size > MAX_PAYLOAD_BYTES:
        logger.warning(
            "feed_realtime_publisher: payload %s exceeds %d bytes (%d) — publishing anyway",
            payload["eventId"], MAX_PAYLOAD_BYTES, size,
        )

    for channel in channels_for_event(payload):
        _post_to_appsync(channel, payload)

    return {"eventId": payload["eventId"], "recordId": payload["recordId"], "bytes": size}


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for the DynamoDB Streams trigger.

    Implements the ReportBatchItemFailures contract: a record that fails to
    publish is reported by its sequence number so the stream redelivers only the
    failed item rather than the whole batch.
    """
    records = event.get("Records", [])
    logger.info("feed_realtime_publisher: invoked records=%d dry_run=%s", len(records), DRY_RUN)

    failures: List[Dict[str, str]] = []
    published = 0
    for record in records:
        seq = record.get("dynamodb", {}).get("SequenceNumber", "")
        try:
            result = process_record(record)
            if not result.get("skipped"):
                published += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("feed_realtime_publisher: publish failed seq=%s: %s", seq, exc, exc_info=True)
            if seq:
                failures.append({"itemIdentifier": seq})

    logger.info("feed_realtime_publisher: published=%d failed=%d", published, len(failures))
    return {"batchItemFailures": failures}
