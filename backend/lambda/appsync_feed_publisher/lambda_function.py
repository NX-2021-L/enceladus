#!/usr/bin/env python3
"""devops-appsync-feed-publisher Lambda — AppSync Events real-time fan-out.

ENC-TSK-K20 (PWA 2.0 real-time foundation, B67 AC-10 / AC-23).

This is a DISTINCT Lambda from the v1 SQS->S3 mobile-feed publisher
(backend/lambda/feed_publisher/). It does NOT generate mobile feed JSON,
publish to S3, or invalidate CloudFront. Its sole job is to translate
DynamoDB Streams change records on `devops-project-tracker` into lightweight
real-time event payloads and POST them to the AppSync Events HTTP endpoint so
the PWA can subscribe to live record/project/global feeds.

Flow:
  DynamoDB Streams (devops-project-tracker, NEW_AND_OLD_IMAGES)
    -> This Lambda (direct EventSourceMapping, BatchSize=1)
    -> build lightweight event payload (server-pre-rendered summary)
    -> HTTP POST to AppSync Events on three channels:
         /feed/updates            (global firehose)
         /records/{recordId}      (per-record subscription)
         /projects/{projectId}    (per-project subscription)

Partial-batch failure:
  Returns the ReportBatchItemFailures contract
  {"batchItemFailures": [{"itemIdentifier": <sequenceNumber>}]} so only the
  failed stream records are retried (BatchSize=1 means at most one, but the
  contract is honored generally).

Cursor design (documented per AC):
  `cursor` is a monotonically-increasing integer intended to let a client
  order/deduplicate events and resume. It is derived from the stream record's
  ApproximateCreationDateTime in **epoch milliseconds**, then multiplied by
  1000 and offset by a per-batch counter (0..999) that increments in stream
  order. This yields a strictly increasing value within a batch even when two
  records share the same approximate creation millisecond, while remaining
  globally comparable across batches (millis dominate the low-order counter).
  It is best-effort monotonic, not a global sequence number — DynamoDB Streams
  does not expose one that is cheap to read here.

Auth:
  Two supported modes (env-selected):
    * API key   — header `X-Api-Key: $APPSYNC_EVENTS_API_KEY` (default here).
    * SigV4     — sign the request with the Lambda's execution-role creds for
                  IAM auth. This module documents the SigV4 alternative and
                  falls back to it when no API key is configured; the API-key
                  path is the primary path for gamma.

Environment variables:
  APPSYNC_EVENTS_HTTP_ENDPOINT   AppSync Events HTTP endpoint host or URL
                                 (e.g. abc123.appsync-api.us-west-2.amazonaws.com
                                 or https://.../event). REQUIRED to publish.
  APPSYNC_EVENTS_API_KEY         AppSync API key for X-Api-Key auth (optional;
                                 if unset, SigV4 is used).
  APPSYNC_EVENTS_REGION          Region for SigV4 signing (default: us-west-2).
  APPSYNC_EVENTS_TIMEOUT         HTTP timeout seconds (default: 5).
  DEFAULT_PROJECT_ID             Fallback project id if a record lacks one
                                 (default: enceladus).
  DRY_RUN                        "true" to skip the HTTP POST (unit/local runs).

Stdlib + boto3 only — NO new pip dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.types import TypeDeserializer

# ---------------------------------------------------------------------------
# Logging setup (structured, mirrors sibling Lambdas)
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

APPSYNC_EVENTS_HTTP_ENDPOINT = os.environ.get("APPSYNC_EVENTS_HTTP_ENDPOINT", "").strip()
APPSYNC_EVENTS_API_KEY = os.environ.get("APPSYNC_EVENTS_API_KEY", "").strip()
APPSYNC_EVENTS_REGION = os.environ.get("APPSYNC_EVENTS_REGION", "us-west-2").strip()
APPSYNC_EVENTS_TIMEOUT = float(os.environ.get("APPSYNC_EVENTS_TIMEOUT", "5") or "5")
DEFAULT_PROJECT_ID = os.environ.get("DEFAULT_PROJECT_ID", "enceladus").strip()
DRY_RUN = os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"}

# Terminal statuses that map an INSERT/MODIFY to action=closed.
TERMINAL_STATUSES = frozenset(
    {"closed", "deploy-success", "done", "complete", "completed", "resolved", "cancelled", "canceled"}
)

_deserializer = TypeDeserializer()

# ---------------------------------------------------------------------------
# UUID v7 generator (draft-ietf-uuidrev-rfc4122bis / RFC 9562 §5.7)
#
# Implemented inline to avoid a new pip dependency (Python 3.10/3.11 stdlib uuid
# has no uuid7). Layout:
#   48 bits  unix_ts_ms  (big-endian millisecond timestamp)
#    4 bits  version     (0b0111 = 7)
#   12 bits  rand_a
#    2 bits  variant     (0b10)
#   62 bits  rand_b
# Time-ordered: the leading 48 ms bits make lexical/byte order track creation
# time, which is exactly the monotonic-ish property the cursor + feed want.
# ---------------------------------------------------------------------------

import os as _os  # local alias for urandom; keeps top imports stdlib-only

_last_uuid7_ms = 0
_uuid7_seq = 0


def uuid7(ts_ms: Optional[int] = None) -> str:
    """Return a UUID v7 string, time-ordered by millisecond timestamp.

    Best-effort monotonic within a process: if called multiple times in the
    same millisecond, a per-ms sequence counter is folded into rand_a so the
    emitted ids keep increasing lexically. Not cryptographically strong; used
    for event identity/ordering, not security.
    """
    global _last_uuid7_ms, _uuid7_seq
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    if ts_ms == _last_uuid7_ms:
        _uuid7_seq = (_uuid7_seq + 1) & 0x0FFF
    else:
        _last_uuid7_ms = ts_ms
        _uuid7_seq = 0

    rand = int.from_bytes(_os.urandom(8), "big")
    # 48-bit timestamp
    ts_ms &= (1 << 48) - 1
    # rand_a: 12 bits — seed with the monotonic sub-ms sequence for ordering.
    rand_a = _uuid7_seq & 0x0FFF
    # rand_b: 62 bits from urandom.
    rand_b = rand & ((1 << 62) - 1)

    value = ts_ms << 80
    value |= 0x7 << 76  # version 7
    value |= rand_a << 64
    value |= 0b10 << 62  # variant
    value |= rand_b

    hexed = f"{value:032x}"
    return f"{hexed[0:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}"


# ---------------------------------------------------------------------------
# DynamoDB stream image helpers
# ---------------------------------------------------------------------------


def _deserialize_image(image: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert a raw DynamoDB stream image (typed attr map) to plain Python."""
    if not image:
        return {}
    out: Dict[str, Any] = {}
    for key, typed in image.items():
        try:
            out[key] = _deserializer.deserialize(typed)
        except Exception:  # noqa: BLE001 — tolerate odd attribute shapes
            out[key] = None
    return out


def _first_nonempty(*values: Any) -> str:
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


# ---------------------------------------------------------------------------
# Attribution: actorType / actorId inference from write_source
# ---------------------------------------------------------------------------

_AGENT_CHANNELS = frozenset({"mcp_server", "arc-walker"})


def infer_actor(image: Dict[str, Any]) -> Tuple[str, str]:
    """Return (actorType, actorId) for a record image.

    actorType is 'human' or 'agent', inferred from write_source:
      * provider matching ENC-SES-* (a minted session id) => 'agent'
      * channel in {mcp_server, arc-walker}                => 'agent'
      * a Cognito username/sub as provider                 => 'human'
      * default                                            => 'agent'
    actorId is the write_source.provider (falling back to updated_by / owner).
    """
    ws = image.get("write_source") or {}
    if not isinstance(ws, dict):
        ws = {}

    provider = _first_nonempty(ws.get("provider"))
    channel = _first_nonempty(ws.get("channel")).lower()
    actor_id = _first_nonempty(
        provider,
        image.get("updated_by"),
        image.get("owner"),
        image.get("assignee"),
    ) or "unknown"

    if provider.upper().startswith("ENC-SES-"):
        return "agent", actor_id
    if channel in _AGENT_CHANNELS:
        return "agent", actor_id
    if provider and not provider.upper().startswith("ENC-SES-"):
        # A non-session provider present on a human-facing channel => human.
        # (Cognito sub / username lands here.)
        if channel in {"", "mutation_api"}:
            return "human", actor_id
    return "agent", actor_id


# ---------------------------------------------------------------------------
# Action derivation
# ---------------------------------------------------------------------------


def derive_action(event_name: str, new_image: Dict[str, Any], old_image: Dict[str, Any]) -> str:
    """Derive a coarse action verb for the event.

      REMOVE                                   -> 'removed'
      INSERT                                   -> 'created'
      MODIFY into a terminal status            -> 'closed'
      MODIFY otherwise                         -> 'updated'
    """
    ev = (event_name or "").upper()
    if ev == "REMOVE":
        return "removed"
    if ev == "INSERT":
        return "created"

    new_status = _first_nonempty(new_image.get("status")).lower()
    old_status = _first_nonempty(old_image.get("status")).lower()
    if new_status in TERMINAL_STATUSES and new_status != old_status:
        return "closed"
    return "updated"


# ---------------------------------------------------------------------------
# Cursor derivation (documented in module docstring)
# ---------------------------------------------------------------------------


def derive_cursor(approx_creation_ms: Optional[int], batch_counter: int) -> int:
    """Monotonic-ish integer cursor: epoch-millis * 1000 + per-batch counter.

    approx_creation_ms comes from the stream record's
    ApproximateCreationDateTime (seconds, float) scaled to millis. batch_counter
    breaks ties for records sharing the same millisecond within one batch.
    """
    if approx_creation_ms is None:
        approx_creation_ms = int(time.time() * 1000)
    return approx_creation_ms * 1000 + (batch_counter % 1000)


# ---------------------------------------------------------------------------
# Payload construction (B67 AC-10 fields; AC-23 median <= 500 bytes)
# ---------------------------------------------------------------------------


def build_summary(actor_id: str, action: str, record_type: str, record_id: str, title: str) -> str:
    """Server-pre-rendered human-readable display string.

    e.g. "ENC-SES-00P closed task ENC-TSK-K20: AppSync FeedPublisher"
    """
    base = f"{actor_id} {action} {record_type} {record_id}"
    if title:
        return f"{base}: {title}"
    return base


def build_event_payload(record: Dict[str, Any], batch_counter: int) -> Optional[Dict[str, Any]]:
    """Build the lightweight AppSync event payload for one stream record.

    Returns None if the record cannot be resolved to a target (no recordId).
    Field set is EXACTLY the B67 AC-10 contract; raw DynamoDB item images are
    NOT inlined (AC-23 payload budget).
    """
    ddb = record.get("dynamodb", {}) or {}
    event_name = record.get("eventName", "")

    new_image = _deserialize_image(ddb.get("NewImage"))
    old_image = _deserialize_image(ddb.get("OldImage"))
    keys = _deserialize_image(ddb.get("Keys"))
    primary = new_image or old_image

    record_id = _first_nonempty(
        primary.get("record_id"),
        keys.get("record_id"),
        primary.get("id"),
    )
    if not record_id:
        return None

    # ENC-TSK-K74: the tracker's composite record_id ("task#ENC-TSK-004")
    # contains '#', which AppSync Events rejects as a channel segment
    # (400 Invalid Channel Format — verified live during K56 provisioning:
    # feed/updates and projects/{id} publish 200, records/task#... 400).
    # Use the bare item_id ("ENC-TSK-004") for the per-record channel, the
    # payload recordId, and the pre-rendered summary — this also matches the
    # ui-v2 client's /records/{recordId} subscription contract, which
    # subscribes with bare item ids from route params.
    item_id = _first_nonempty(
        primary.get("item_id"),
        record_id.split("#")[-1],
    )

    record_type = _first_nonempty(primary.get("record_type"), "record")
    project_id = _first_nonempty(primary.get("project_id"), keys.get("project_id")) or DEFAULT_PROJECT_ID
    title = _first_nonempty(primary.get("title"), primary.get("name"))

    action = derive_action(event_name, new_image, old_image)
    actor_type, actor_id = infer_actor(primary)

    # ApproximateCreationDateTime is epoch seconds (float).
    approx_secs = ddb.get("ApproximateCreationDateTime")
    approx_ms = int(float(approx_secs) * 1000) if approx_secs is not None else None
    cursor = derive_cursor(approx_ms, batch_counter)
    event_id = uuid7(approx_ms)

    summary = build_summary(actor_id, action, record_type, item_id, title)

    # Short-ish but readable keys; no raw item image inlined.
    payload: Dict[str, Any] = {
        "eventId": event_id,
        "recordId": item_id,
        "record_type": record_type,
        "action": action,
        "actorType": actor_type,
        "actorId": actor_id,
        "summary": summary,
        "cursor": cursor,
        "channels": [
            "/feed/updates",
            f"/records/{item_id}",
            f"/projects/{project_id}",
        ],
    }
    return payload


def channel_targets(payload: Dict[str, Any]) -> List[str]:
    return list(payload.get("channels", []))


def build_full_record_body(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Full record body for the /records/{recordId} channel only (ENC-TSK-L29).

    Returns the deserialized NewImage (current field values) for INSERT/MODIFY
    events so the client's Tier-1/Tier-2 mirror (ENC-TSK-L24) can upsert
    directly with no follow-up fetch. Returns None for REMOVE events (and when
    there is no NewImage) — the client instead reacts to the lightweight
    payload's action='removed' and marks a tombstone. Deliberately a SEPARATE
    function from build_event_payload so the /feed/updates and /projects/{id}
    channels (B67 AC-23 fixed ~500-byte budget) are never touched by this.
    """
    ddb = record.get("dynamodb", {}) or {}
    new_image = _deserialize_image(ddb.get("NewImage"))
    return new_image or None


# ---------------------------------------------------------------------------
# AppSync Events HTTP publish (stdlib urllib; SigV4 documented alternative)
# ---------------------------------------------------------------------------


def _json_default(obj: Any) -> Any:
    """json.dumps default= hook, applied to EVERY dumps call in this module.

    DynamoDB Stream Number (N) attributes deserialize to Decimal
    (boto3.dynamodb.types.TypeDeserializer) — json.dumps has no native
    Decimal support. Covers both the lightweight payload and the
    /records/{recordId} full_body payload (ENC-TSK-L29), since full_body is
    a full deserialized NewImage and Decimal can appear at any depth.

    Integral Decimals become int, not float — record IDs, counts, and
    versions must round-trip exactly, not drift into float representation.
    """
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def _endpoint_url() -> str:
    """Normalize APPSYNC_EVENTS_HTTP_ENDPOINT to a full /event POST URL."""
    ep = APPSYNC_EVENTS_HTTP_ENDPOINT
    if not ep:
        return ""
    if ep.startswith("http://") or ep.startswith("https://"):
        base = ep.rstrip("/")
    else:
        base = f"https://{ep.rstrip('/')}"
    if base.endswith("/event"):
        return base
    return f"{base}/event"


def _sigv4_headers(body: bytes, host: str) -> Dict[str, str]:
    """Build SigV4 auth headers for the AppSync Events endpoint (IAM auth).

    Used when no API key is configured. Signs with the Lambda execution-role
    credentials against service 'appsync'. This is the documented alternative
    to the X-Api-Key path.
    """
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    session = boto3.Session()
    creds = session.get_credentials()
    url = _endpoint_url()
    request = AWSRequest(method="POST", url=url, data=body, headers={"Content-Type": "application/json"})
    SigV4Auth(creds, "appsync", APPSYNC_EVENTS_REGION).add_auth(request)
    headers = dict(request.headers.items())
    headers.setdefault("host", host)
    return headers


def publish_to_appsync(payload: Dict[str, Any], full_body: Optional[Dict[str, Any]] = None) -> None:
    """POST one event as an AppSync Events publish frame to its channels.

    AppSync Events HTTP publish shape: {"channel": <path>, "events": [<json str>]}.
    We publish to each target channel (global, per-record, per-project). Raises
    on HTTP/transport failure so the caller can mark the record for retry.

    ENC-TSK-L29: when full_body is provided, the /records/{recordId} channel's
    event carries an additional "record" field with the complete current
    record body — /feed/updates and /projects/{id} always get the lightweight
    payload unchanged (AC-23 budget).
    """
    url = _endpoint_url()
    if not url:
        raise RuntimeError("APPSYNC_EVENTS_HTTP_ENDPOINT is not configured")

    host = url.split("://", 1)[-1].split("/", 1)[0]
    event_json = json.dumps(payload, separators=(",", ":"), default=_json_default)
    detail_event_json = (
        json.dumps({**payload, "record": full_body}, separators=(",", ":"), default=_json_default)
        if full_body is not None
        else event_json
    )

    for channel in channel_targets(payload):
        is_record_channel = channel.startswith("/records/")
        body_obj = {
            "channel": channel,
            "events": [detail_event_json if is_record_channel else event_json],
        }
        body = json.dumps(body_obj, separators=(",", ":"), default=_json_default).encode("utf-8")

        headers = {"Content-Type": "application/json", "host": host}
        if APPSYNC_EVENTS_API_KEY:
            headers["X-Api-Key"] = APPSYNC_EVENTS_API_KEY
        else:
            # No API key => IAM/SigV4 auth path.
            headers = _sigv4_headers(body, host)
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=APPSYNC_EVENTS_TIMEOUT) as resp:
            status = getattr(resp, "status", resp.getcode())
            if status >= 300:
                raise RuntimeError(f"AppSync publish to {channel} returned HTTP {status}")


# ---------------------------------------------------------------------------
# Partial-batch failure helper (ReportBatchItemFailures contract)
# ---------------------------------------------------------------------------


def _batch_failure_response(sequence_numbers: List[str]) -> Dict[str, Any]:
    failures = []
    seen = set()
    for seq in sequence_numbers:
        if not seq or seq in seen:
            continue
        seen.add(seq)
        failures.append({"itemIdentifier": seq})
    if not failures:
        return {}
    return {"batchItemFailures": failures}


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """DynamoDB Streams entry point.

    Processes each stream record independently; a per-record failure is
    collected and reported so only failed records are retried. Records with no
    resolvable recordId are skipped (not failed) since they can never succeed.
    """
    records = event.get("Records", []) or []
    logger.info(
        "appsync_feed_publisher: invoked records=%d dry_run=%s endpoint_set=%s",
        len(records),
        DRY_RUN,
        bool(APPSYNC_EVENTS_HTTP_ENDPOINT),
    )

    failed_sequence_numbers: List[str] = []
    published = 0
    skipped = 0

    for batch_counter, record in enumerate(records):
        seq = (record.get("dynamodb", {}) or {}).get("SequenceNumber") or record.get("eventID")
        try:
            payload = build_event_payload(record, batch_counter)
            if payload is None:
                skipped += 1
                logger.warning(
                    "appsync_feed_publisher: skipping record with no resolvable recordId (seq=%s)",
                    seq,
                )
                continue

            full_body = build_full_record_body(record)

            if DRY_RUN:
                logger.info(
                    "appsync_feed_publisher: DRY_RUN — would publish event=%s action=%s channels=%s "
                    "full_body=%s",
                    payload["eventId"],
                    payload["action"],
                    payload["channels"],
                    full_body is not None,
                )
            else:
                publish_to_appsync(payload, full_body)
            published += 1
        except Exception as exc:  # noqa: BLE001 — isolate per-record failure
            logger.error(
                "appsync_feed_publisher: record failed seq=%s: %s",
                seq,
                exc,
                exc_info=True,
            )
            if seq:
                failed_sequence_numbers.append(seq)

    logger.info(
        "appsync_feed_publisher: complete published=%d skipped=%d failed=%d",
        published,
        skipped,
        len(failed_sequence_numbers),
    )
    return _batch_failure_response(failed_sequence_numbers)
