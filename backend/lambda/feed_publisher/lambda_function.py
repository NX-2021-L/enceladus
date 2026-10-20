#!/usr/bin/env python3
"""devops-feed-publisher Lambda — Event-driven mobile feed publisher.

Triggered by SQS FIFO queue (devops-feed-publish-queue.fifo) which receives
events from EventBridge Pipes connected to DynamoDB Streams on the
devops-project-tracker and documents tables.

Flow:
  DynamoDB Streams → EventBridge Pipes → SQS FIFO (5-min visibility = debounce)
  → This Lambda → generate mobile feeds → publish to S3 → CloudFront invalidation
  → write analytics sync-stage JSON → SNS signal
  → per-project EventBridge events (Trino/Superset analytics pipeline)

The SQS FIFO visibility timeout acts as the debounce window: a message for a
given project stays invisible for 5 minutes; if more changes arrive during that
window, new messages queue up and are processed in the next cycle.

Message group ID = project_id ensures per-project ordering.

Environment variables:
  TRACKER_TABLE      DynamoDB table name (default: devops-project-tracker)
  TRACKER_REGION     DynamoDB region (default: us-west-2)
  FEED_BUCKET        S3 bucket for mobile feeds (default: jreese-net)
  FEED_PREFIX        S3 prefix for mobile feeds (default: mobile/v1)
  CF_DISTRIBUTION    CloudFront distribution ID (default: E2BOQXCW1TA6Y4)
  SNS_TOPIC          SNS topic ARN for sync signals
  EVENT_BUS          EventBridge bus name (default: default)
  ANALYTICS_BUCKET   S3 bucket for analytics sync-stage JSON (default: devops-agentcli-compute)
  ANALYTICS_REGION   AWS region for analytics bucket (default: us-west-2)
  PROJECTS_TABLE     DynamoDB table for project registry (default: projects)
  PROJECTS_REGION    AWS region for projects table (default: us-west-2)
  DRY_RUN            Set to "true" to skip S3/CF/SNS/EB writes (for testing)
  FEED_PUBLISH_MODE  per_batch (default; publish on every SQS batch) | coalesced
                     (ENC-TSK-R26: SQS batches only MARK the project dirty in
                     FEED_PUBLISH_STATE_TABLE; an EventBridge-driven SWEEP publishes)
  FEED_INVALIDATE    "true" (default) | "false": whether a publish ends with a
                     CloudFront CreateInvalidation (ENC-TSK-R26)
  FEED_PUBLISH_STATE_TABLE   MARK/SWEEP state table (default: enceladus-feed-publish-state)
  FEED_PUBLISH_STATE_REGION  region of that table (default: us-west-2)
  FEED_INCREMENTAL   "false" (default) | "true": SWEEP re-reads only the record keys the DynamoDB stream
                     reported changed (strongly consistent BatchGetItem) and merges them into a per-project
                     raw-item snapshot in S3, with a full re-read every FEED_FULL_REREAD_SECONDS (default
                     86400) and on any overflow / missing snapshot / merge error (ENC-TSK-R41, FR-22)
  FEED_CLAIM_GRACE_SECONDS   safety margin subtracted from a sweep's claim time before the
                     clear-dirty comparison (default: 5; covers GSI propagation lag)
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.types import TypeDeserializer

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Feed utils is bundled alongside this Lambda (same zip package)
# Import all generation / publication utilities from the shared module.
try:
    from feed_utils import (
        FeedProjectEntry,
        fetch_from_dynamodb,
        fetch_documents_from_dynamodb,
        generate_mobile_feeds,
        generate_documents_feed,
        check_freshness_sla,
        generate_reference_docs_from_s3,
        publish_mobile_feeds_to_s3,
        invalidate_mobile_cf,
        publish_sync_message,
        publish_eventbridge_event,
        write_analytics_sync_stage,
        group_project_items,
        query_project_items,
        batch_get_tracker_items,
        snapshot_encode,
        snapshot_decode,
        reset_read_units,
        read_units_total,
        DEFAULT_TRACKER_TABLE,
        DEFAULT_TRACKER_REGION,
        DEFAULT_DOCUMENTS_TABLE,
        DEFAULT_MOBILE_S3_BUCKET,
        DEFAULT_MOBILE_S3_PREFIX,
        DEFAULT_MOBILE_CF_DISTRIBUTION,
        DEFAULT_SNS_TOPIC,
        DEFAULT_EVENT_BUS,
        ANALYTICS_S3_BUCKET,
    )
except ImportError as exc:
    logger.error("feed_utils not found — ensure it is bundled in the Lambda package: %s", exc)
    raise

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", DEFAULT_TRACKER_TABLE)
TRACKER_REGION = os.environ.get("TRACKER_REGION", DEFAULT_TRACKER_REGION)
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", DEFAULT_DOCUMENTS_TABLE)
DOCUMENTS_REGION = os.environ.get("DOCUMENTS_REGION", "us-west-2")
FEED_BUCKET = os.environ.get("FEED_BUCKET", DEFAULT_MOBILE_S3_BUCKET)
FEED_PREFIX = os.environ.get("FEED_PREFIX", DEFAULT_MOBILE_S3_PREFIX)
CF_DISTRIBUTION = os.environ.get("CF_DISTRIBUTION", DEFAULT_MOBILE_CF_DISTRIBUTION)
# ENC-TSK-K98: gate the PUBLIC /mobile feed publish (+ its CF invalidation).
# Prod keeps publishing (default "true"). Gamma sets this "false" because the
# gamma /mobile/v1 objects are served PUBLICLY by the shared UI-origin cockpit
# CDN (a full-record data leak), and the ui-v2 cockpit now reads its cold-start
# snapshot from the AUTHENTICATED feed_query API (GET /api/v1/feed/tasks.json).
FEED_S3_PUBLISH_ENABLED = (
    os.environ.get("FEED_S3_PUBLISH_ENABLED", "true").strip().lower() != "false"
)
SNS_TOPIC = os.environ.get("SNS_TOPIC", DEFAULT_SNS_TOPIC)
EVENT_BUS = os.environ.get("EVENT_BUS", DEFAULT_EVENT_BUS)
ANALYTICS_BUCKET = os.environ.get("ANALYTICS_BUCKET", ANALYTICS_S3_BUCKET)
ANALYTICS_REGION = os.environ.get("ANALYTICS_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
PROJECTS_REGION = os.environ.get("PROJECTS_REGION", "us-west-2")
DRY_RUN = os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"}

# ENC-TSK-R26 (ENC-PLN-100 C2.1): trailing-edge coalescing of the snapshot publish.
#   per_batch  -> today's behavior, byte-identical: every SQS batch regenerates + publishes.
#   coalesced  -> the SQS path only MARKs projects dirty (feed-publish-state); a scheduled
#                 SWEEP performs the (existing, full) publish and clears dirty only if no
#                 write arrived after it claimed the project (trailing edge).
# Anything other than the literal "coalesced" resolves to per_batch (fail safe).
FEED_PUBLISH_MODE_PER_BATCH = "per_batch"
FEED_PUBLISH_MODE_COALESCED = "coalesced"


def _normalize_publish_mode(raw: Optional[str]) -> str:
    value = (raw or "").strip().lower()
    if value == FEED_PUBLISH_MODE_COALESCED:
        return FEED_PUBLISH_MODE_COALESCED
    if value and value != FEED_PUBLISH_MODE_PER_BATCH:
        logger.warning("feed_publisher: unknown FEED_PUBLISH_MODE=%r; using per_batch", raw)
    return FEED_PUBLISH_MODE_PER_BATCH


FEED_PUBLISH_MODE = _normalize_publish_mode(os.environ.get("FEED_PUBLISH_MODE"))
# Default true (today's behavior). Only the literal "false" disables the runtime invalidation.
FEED_INVALIDATE = os.environ.get("FEED_INVALIDATE", "true").strip().lower() != "false"
FEED_PUBLISH_STATE_TABLE = os.environ.get("FEED_PUBLISH_STATE_TABLE", "enceladus-feed-publish-state")
FEED_PUBLISH_STATE_REGION = os.environ.get("FEED_PUBLISH_STATE_REGION", TRACKER_REGION)
try:
    FEED_CLAIM_GRACE_SECONDS = max(0.0, float(os.environ.get("FEED_CLAIM_GRACE_SECONDS", "5")))
except ValueError:
    FEED_CLAIM_GRACE_SECONDS = 5.0
# ruling A3: plain max-age, no stale-while-revalidate. Applied only in coalesced mode;
# per_batch keeps feed_utils' existing header.
COALESCED_CACHE_CONTROL = "max-age=60"
SWEEP_ACTION = "feed_sweep"

# ENC-TSK-R34 (ENC-PLN-100 C3.1, BRD FR-20 / FR-21). Both flags default to "false" (today's behavior)
# and take effect ONLY in coalesced mode, so per_batch stays byte-identical whatever they say.
#   FEED_CONTENT_DIFF  SWEEP hashes every generated object (generated_at excluded) against a stored map
#                      and PUTs only what changed; analytics sync-stage writes (and their SNS/EventBridge
#                      signals) are skipped for a project whose records did not change.
#   FEED_GZIP          the JSON feed objects are stored gzip-compressed with Content-Encoding: gzip
#                      (reference/*.md are not). Every S3-API reader must decode (feed_utils.read_s3_object_bytes
#                      / ContentStore.read_bytes); HTTP readers via CloudFront decode transparently.
# The hash map lives on the existing FEED_PUBLISH_STATE_TABLE as one item (no new table).
OBJECT_HASHES_KEY = "__object_hashes__"


def _env_true(name: str) -> bool:
    return os.environ.get(name, "false").strip().lower() == "true"


FEED_CONTENT_DIFF = _env_true("FEED_CONTENT_DIFF")
FEED_GZIP = _env_true("FEED_GZIP")
try:
    # Self-healing: even when every hash matches, republish everything this often (out-of-band
    # object deletion/overwrite, a bucket restored from versioning). Mirrors FR-22's 24 h reconciliation.
    FEED_DIFF_REFRESH_SECONDS = max(0.0, float(os.environ.get("FEED_DIFF_REFRESH_SECONDS", "86400")))
except ValueError:
    FEED_DIFF_REFRESH_SECONDS = 86400.0


def _content_diff_active() -> bool:
    return FEED_CONTENT_DIFF and FEED_PUBLISH_MODE == FEED_PUBLISH_MODE_COALESCED


def _gzip_active() -> bool:
    return FEED_GZIP and FEED_PUBLISH_MODE == FEED_PUBLISH_MODE_COALESCED

# ENC-TSK-R41 (ENC-PLN-100 C4.1, BRD FR-22, ruling P100-R28). Incremental tracker re-read, coalesced SWEEP only,
# default "false" (today's behavior byte-for-byte).
#   MARK   adds the stream record keys to the project's state row in the SAME conditional UpdateItem:
#          ADD changed_ids (string set) and, for REMOVE events, removed_ids; more than FEED_INCREMENTAL_MAX_IDS
#          members (or a stream record whose key cannot be read) -> SET full_reread = true instead.
#   SWEEP  FEED_INCREMENTAL=true + a fresh snapshot + no full_reread -> BatchGetItem exactly the changed ids,
#          merge into the snapshot (a key that comes back absent is a deletion); otherwise a full re-read.
#          After a successful publish ONE conditional UpdateItem DELETEs only the ids it processed plus the
#          existing trailing-edge dirty clear, so an id a MARK adds during the publish survives.
#   The snapshot (raw DynamoDB items, gzip JSON) lives in the content bucket under feed-snapshots/v1/ and
#   carries its own full_read_at; a full re-read is forced when it is older than FEED_FULL_REREAD_SECONDS.
FEED_INCREMENTAL = _env_true("FEED_INCREMENTAL")
try:
    FEED_INCREMENTAL_MAX_IDS = max(1, int(os.environ.get("FEED_INCREMENTAL_MAX_IDS", "1000")))
except ValueError:
    FEED_INCREMENTAL_MAX_IDS = 1000
try:
    FEED_FULL_REREAD_SECONDS = max(0.0, float(os.environ.get("FEED_FULL_REREAD_SECONDS", "86400")))
except ValueError:
    FEED_FULL_REREAD_SECONDS = 86400.0
SNAPSHOT_BUCKET = os.environ.get("FEED_SNAPSHOT_BUCKET") or os.environ.get("CONTENT_BUCKET", "")
SNAPSHOT_PREFIX = "feed-snapshots/v1/"
# A snapshot whose saved_at is older than the state row's last_published_at by more than this was NOT
# refreshed by the latest publish (FEED_INCREMENTAL was off, a save failed, another writer published):
# the change ids it would merge are incomplete, so the SWEEP does a full re-read instead of trusting it.
SNAPSHOT_STALE_GRACE_SECONDS = 5.0
METRIC_NAMESPACE = "Enceladus/FeedPublisher"


def _incremental_active() -> bool:
    return (
        FEED_INCREMENTAL
        and FEED_PUBLISH_MODE == FEED_PUBLISH_MODE_COALESCED
        and not DRY_RUN
        and bool(SNAPSHOT_BUCKET)
    )


# Local temp directory for generated feed files (Lambda has /tmp writable)
FEED_TEMP_DIR = Path("/tmp/mobile-feeds/v1")

# ---------------------------------------------------------------------------
# DynamoDB helpers (inline — no dependency on project_json_sync.py)
# ---------------------------------------------------------------------------

_deserializer = TypeDeserializer()


def _ddb_client(region: str = TRACKER_REGION):
    return boto3.client(
        "dynamodb",
        region_name=region,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


def _deserialize(raw: Dict) -> Dict:
    return {k: _deserializer.deserialize(v) for k, v in raw.items()}


# ---------------------------------------------------------------------------
# Project discovery from DynamoDB
# ---------------------------------------------------------------------------

# Module-level cache for project entries from DynamoDB
_projects_cache: Optional[List[Dict[str, Any]]] = None
_projects_cache_at: float = 0.0
_PROJECTS_CACHE_TTL = 300.0  # 5-min cache


def _load_active_projects_from_ddb() -> List[Dict[str, Any]]:
    """Scan the projects DynamoDB table and return active projects.

    Filters out projects with status 'closed' or 'archived'.
    Uses a 5-min module-level cache for warm Lambda invocations.
    """
    global _projects_cache, _projects_cache_at
    import time
    now = time.time()

    if _projects_cache is not None and (now - _projects_cache_at) < _PROJECTS_CACHE_TTL:
        return _projects_cache

    try:
        ddb = boto3.client(
            "dynamodb",
            region_name=PROJECTS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
        items: List[Dict] = []
        resp = ddb.scan(TableName=PROJECTS_TABLE)
        items.extend(resp.get("Items", []))
        while resp.get("LastEvaluatedKey"):
            resp = ddb.scan(
                TableName=PROJECTS_TABLE,
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            items.extend(resp.get("Items", []))

        active = []
        excluded_statuses = {"closed", "archived"}
        for raw in items:
            status = raw.get("status", {}).get("S", "active")
            if status in excluded_statuses:
                continue
            active.append({
                "name": raw["project_id"]["S"],
                "prefix": raw.get("prefix", {}).get("S", ""),
                "status": status,
                "metadata": {},
            })

        _projects_cache = active
        _projects_cache_at = now
        logger.info("Loaded %d active projects from projects table", len(active))
        return active

    except (BotoCoreError, ClientError) as exc:
        logger.error("Failed to load projects from DynamoDB: %s", exc)
        if _projects_cache is not None:
            logger.warning("Using stale project cache")
            return _projects_cache
        raise


def _all_project_entries() -> List[FeedProjectEntry]:
    """Return FeedProjectEntry for all active projects from the projects table.

    In the Lambda context, path is set to a placeholder (no local filesystem),
    and generate_reference_docs_from_s3() is used instead of the filesystem variant.
    """
    projects = _load_active_projects_from_ddb()
    return [
        FeedProjectEntry(
            name=p["name"],
            prefix=p["prefix"],
            path=Path("/tmp"),  # not used in Lambda (no local ref docs)
            status=p["status"],
            metadata=p.get("metadata", {}),
        )
        for p in projects
    ]


# ---------------------------------------------------------------------------
# SQS event parsing — extract project IDs from DynamoDB stream records
# ---------------------------------------------------------------------------


def _extract_project_ids_and_failures_from_sqs_event(
    event: Dict[str, Any],
) -> Tuple[Set[str], List[str]]:
    """Parse SQS event records to find affected project IDs and failed messages."""
    affected: Set[str] = set()
    failed_message_ids: List[str] = []
    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            body = json.loads(record.get("body", "{}"))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse SQS record body as JSON")
            if message_id:
                failed_message_ids.append(message_id)
            continue

        # EventBridge Pipe forwards the DynamoDB stream record directly
        # Alternatively the body may already be parsed as the stream event
        ddb_record = body.get("dynamodb", body)
        found_project_id = False
        for image_key in ("NewImage", "OldImage"):
            image = ddb_record.get(image_key, {})
            if not image:
                continue
            project_id_attr = image.get("project_id", {})
            # DynamoDB typed format: {"S": "devops"}
            project_id = project_id_attr.get("S") or project_id_attr.get("s")
            if project_id:
                affected.add(project_id)
                found_project_id = True
                break
        if not found_project_id and message_id:
            logger.warning("Could not resolve project_id from SQS record body")
            failed_message_ids.append(message_id)

    logger.info("Affected project IDs from SQS event: %s", sorted(affected))
    return affected, failed_message_ids


def _extract_project_ids_from_sqs_event(event: Dict[str, Any]) -> Set[str]:
    """Backwards-compatible helper returning only the affected project IDs."""
    affected, _ = _extract_project_ids_and_failures_from_sqs_event(event)
    return affected


# ---------------------------------------------------------------------------
# DVP-TSK-A83: project activity stamp (projects.last_activity_at)
# ---------------------------------------------------------------------------
#
# project_service derives days_since_active from the newest updated_at across a project's
# tracker records. Computing that at read time costs a paginated project-type-index Query per
# project on every cold container. Instead this consumer, which already sees every tracker
# write via the stream -> pipe -> SQS path, keeps a monotonic max on the project row.
#
# Only TRACKER records count: the same queue also carries documents-table events (Keys has
# document_id, no record_id) and the pipe filter already drops record_type=reference rows.

ACTIVITY_ATTR = "last_activity_at"
_ACTIVITY_CONDITION = (
    "attribute_exists(project_id) AND "
    "(attribute_not_exists(last_activity_at) OR last_activity_at < :ts)"
)


def _normalize_activity_ts(value: Any) -> Optional[str]:
    """Canonical UTC 'YYYY-MM-DDTHH:MM:SSZ' form, so string comparison in the DynamoDB
    condition expression orders timestamps correctly. None when unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_project_activity_from_sqs_event(event: Dict[str, Any]) -> Dict[str, str]:
    """project_id -> newest tracker updated_at (canonical form) across the batch.

    Unparseable bodies, documents events, reference rows and records without a usable
    updated_at are skipped; this never raises."""
    newest: Dict[str, str] = {}
    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
            ddb_record = body.get("dynamodb", body)
            if "record_id" not in (ddb_record.get("Keys") or {}):
                continue  # documents-table event (keyed by document_id)
            image = ddb_record.get("NewImage") or {}
            record_type = (image.get("record_type") or {}).get("S")
            if not record_type or record_type == "reference":
                continue
            project_id = (image.get("project_id") or {}).get("S")
            ts = _normalize_activity_ts((image.get("updated_at") or {}).get("S"))
        except (AttributeError, TypeError, ValueError):
            continue
        if not project_id or not ts:
            continue
        if project_id not in newest or ts > newest[project_id]:
            newest[project_id] = ts
    return newest


def _record_project_activity(activity: Dict[str, str], ddb: Any = None) -> int:
    """One conditional UpdateItem per project: SET last_activity_at to the batch max, only when
    it is newer than the stored value (monotonic) and the project row exists (UpdateItem would
    otherwise upsert a stub row for an unregistered project_id).

    Best effort and never raises: a failed condition just means a newer value is already stored,
    and any other error is logged and left for the next write to repair. Returns the number of
    writes that landed."""
    if not activity or DRY_RUN:
        return 0
    client = ddb if ddb is not None else _ddb_client(PROJECTS_REGION)
    written = 0
    for project_id, ts in sorted(activity.items()):
        try:
            client.update_item(
                TableName=PROJECTS_TABLE,
                Key={"project_id": {"S": project_id}},
                UpdateExpression="SET last_activity_at = :ts",
                ConditionExpression=_ACTIVITY_CONDITION,
                ExpressionAttributeValues={":ts": {"S": ts}},
            )
            written += 1
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ConditionalCheckFailedException":
                logger.debug("last_activity_at: project=%s already >= %s (or not registered)", project_id, ts)
            else:
                logger.warning("last_activity_at: update failed project=%s code=%s", project_id, code)
        except Exception as exc:  # noqa: BLE001 - activity stamping must never fail the batch
            logger.warning("last_activity_at: update failed project=%s: %s", project_id, exc)
    return written


def _batch_failure_response(message_ids: List[str]) -> Dict[str, Any]:
    """Return the Lambda partial-batch failure contract for SQS triggers."""
    failures = []
    seen: Set[str] = set()
    for message_id in message_ids:
        if not message_id or message_id in seen:
            continue
        seen.add(message_id)
        failures.append({"itemIdentifier": message_id})
    if not failures:
        return {}
    return {"batchItemFailures": failures}


# ---------------------------------------------------------------------------
# GMF: deploy-pending feed (DOC-63420302EF65 §6.1)
# ---------------------------------------------------------------------------

DEPLOY_TABLE = os.environ.get("DEPLOY_TABLE", "devops-deployment-manager")


def _generate_deploy_pending_feed(
    generated_at: str, output_dir: Path, ddb,
) -> Path:
    """Generate deploy-pending.json with count of pending deployment decisions.

    This lightweight feed powers the DeployApprovalBanner in the PWA.
    It is polled by the banner component to determine whether to render.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Query for pending_approval deployment_decision records
    pending_count = 0
    oldest_created = ""
    oldest_title = ""
    try:
        kwargs = {
            "TableName": DEPLOY_TABLE,
            "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
            "FilterExpression": "#st = :pending",
            "ExpressionAttributeNames": {"#st": "status"},
            "ExpressionAttributeValues": {
                ":pid": {"S": "enceladus"},
                ":prefix": {"S": "decision#"},
                ":pending": {"S": "pending_approval"},
            },
            "Select": "COUNT",
        }
        resp = ddb.query(**kwargs)
        pending_count = resp.get("Count", 0)

        # If there are pending items, get the oldest for the banner summary
        if pending_count > 0:
            kwargs["Select"] = "ALL_ATTRIBUTES"
            kwargs["Limit"] = 1
            kwargs["ScanIndexForward"] = True
            detail_resp = ddb.query(**kwargs)
            items = detail_resp.get("Items", [])
            if items:
                item = items[0]
                oldest_created = item.get("created_at", {}).get("S", "")
                oldest_title = item.get("pr_title", {}).get("S", "")
    except Exception as exc:
        logger.warning("deploy-pending feed: DynamoDB query failed: %s", exc)

    payload = {
        "generated_at": generated_at,
        "version": "1.0",
        "pending_count": pending_count,
        "oldest_created_at": oldest_created,
        "oldest_pr_title": oldest_title,
    }

    out_path = output_dir / "deploy-pending.json"
    import json as _json
    out_path.write_text(_json.dumps(payload, separators=(",", ":")))
    logger.info(
        "feed_publisher: deploy-pending.json (pending_count=%d) -> %s",
        pending_count, out_path,
    )
    return out_path


# ---------------------------------------------------------------------------
# ENC-TSK-R26: MARK / SWEEP (coalesced publish)
# ---------------------------------------------------------------------------
#
# State lives in ONE stream-less on-demand table (ruling A2; it must never be a table whose
# stream feeds the pipe, or a MARK write would re-enter the queue and re-trigger MARK):
#
#   project item  pk project_id
#       dirty            BOOL   present only while the project owes a publish
#       dirty_since      S      ISO time of the first unpublished MARK
#       last_write_at    N      epoch microseconds, MONOTONIC max of MARK arrival times
#       claimed_at       N      epoch microseconds of the sweep claim that last took it
#       last_published_at S     ISO time of the last successful clear
#   lease item    pk "__sweep_lease__"  (lease_expires_at N, lease_owner S)
#
# Trailing-edge guarantee (the property ENC-ISS-543 taught us to protect): dirty is cleared
# ONLY by a conditional write that requires last_write_at <= (claimed_at - grace). A MARK that
# lands at any time after the claim bumps last_write_at past that cutoff, so the clear fails and
# the project stays dirty for the next sweep. last_write_at is the MARK's *processing* time
# (max'd with the event's own updated_at, clamped), which is always >= the write's commit time:
# a write is therefore either visible to the publish (its MARK preceded the claim, and the
# publish reads after the claim) or it keeps the project dirty.

_LEASE_KEY = "__sweep_lease__"
_LEASE_MARGIN_SECONDS = 30.0
_FUTURE_EVENT_CLAMP_US = 60 * 1_000_000

_MARK_UPDATE = (
    "SET dirty = :t, dirty_since = if_not_exists(dirty_since, :iso), last_write_at = :ts"
)
# Monotonic max: an out-of-order MARK must never move last_write_at backwards. A failed
# condition means a newer-or-equal MARK already landed (and set dirty), so it is a success.
_MARK_CONDITION = "attribute_not_exists(last_write_at) OR last_write_at <= :ts"

_LEASE_UPDATE = "SET lease_expires_at = :exp, lease_owner = :owner"
_LEASE_CONDITION = "attribute_not_exists(lease_expires_at) OR lease_expires_at < :now"
_LEASE_RELEASE_UPDATE = "REMOVE lease_expires_at, lease_owner"
_LEASE_RELEASE_CONDITION = "lease_owner = :owner"

_CLAIM_UPDATE = "SET claimed_at = :c, claim_owner = :owner"
_CLAIM_CONDITION = "dirty = :t"

_CLEAR_UPDATE = "REMOVE dirty, dirty_since SET last_published_at = :pub"
_CLEAR_CONDITION = "dirty = :t AND last_write_at <= :cutoff"


def _now_us() -> int:
    return int(time.time() * 1_000_000)


def _iso_from_us(us: int) -> str:
    return dt.datetime.fromtimestamp(us / 1_000_000, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_to_us(ts: Optional[str]) -> Optional[int]:
    """Canonical 'YYYY-MM-DDTHH:MM:SSZ' (see _normalize_activity_ts) -> epoch microseconds."""
    if not ts:
        return None
    try:
        parsed = dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None
    return int(parsed.timestamp() * 1_000_000)


def _is_condition_failure(exc: ClientError) -> bool:
    return exc.response.get("Error", {}).get("Code", "") == "ConditionalCheckFailedException"


def _stream_record_key(body: Dict[str, Any], ddb_record: Dict[str, Any]) -> Tuple[Optional[str], bool]:
    """(record_id, is_remove) of one stream record. record_id is "" for a row that is not a tracker
    row (a documents-table event: documents are always fully re-read, so no id is needed) and None
    when the key cannot be determined (the caller then forces a full re-read)."""
    keys = ddb_record.get("Keys")
    rid = (keys.get("record_id") or {}).get("S") if isinstance(keys, dict) else None
    if not rid:
        for image_key in ("NewImage", "OldImage"):
            image = ddb_record.get(image_key) or {}
            rid = (image.get("record_id") or {}).get("S") if isinstance(image, dict) else None
            if rid:
                break
    event_name = body.get("eventName") or ddb_record.get("eventName")
    is_remove = event_name == "REMOVE" or (not ddb_record.get("NewImage") and bool(ddb_record.get("OldImage")))
    if rid:
        return rid, is_remove
    if isinstance(keys, dict) and "document_id" in keys:
        return "", False
    for image_key in ("NewImage", "OldImage"):
        image = ddb_record.get(image_key) or {}
        if isinstance(image, dict) and "document_id" in image and "record_id" not in image:
            return "", False
    return None, False


def _extract_mark_work(event: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Parse an SQS batch for MARK: project_id -> {"message_ids": [...], "event_ts": newest
    event updated_at in canonical form or None}, plus message ids with no resolvable project.

    Every record resolves to a project or is reported failed, exactly like per_batch: a record is
    never silently consumed without leaving a dirty mark."""
    work: Dict[str, Dict[str, Any]] = {}
    failed: List[str] = []
    for record in event.get("Records", []):
        message_id = record.get("messageId")
        try:
            body = json.loads(record.get("body", "{}"))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse SQS record body as JSON")
            if message_id:
                failed.append(message_id)
            continue
        project_id = None
        event_ts = None
        record_key: Optional[str] = None
        is_remove = False
        track_ids = _incremental_active()
        if isinstance(body, dict):
            ddb_record = body.get("dynamodb", body)
            if isinstance(ddb_record, dict):
                if track_ids:
                    record_key, is_remove = _stream_record_key(body, ddb_record)
                # NewImage first; REMOVE events carry only OldImage and must mark dirty too.
                for image_key in ("NewImage", "OldImage"):
                    image = ddb_record.get(image_key) or {}
                    attr = image.get("project_id") or {}
                    candidate = attr.get("S") or attr.get("s") if isinstance(attr, dict) else None
                    if candidate:
                        project_id = candidate
                        updated = image.get("updated_at") or {}
                        event_ts = _normalize_activity_ts(updated.get("S") if isinstance(updated, dict) else None)
                        break
        if not project_id:
            logger.warning("Could not resolve project_id from SQS record body")
            if message_id:
                failed.append(message_id)
            continue
        entry = work.setdefault(project_id, {"message_ids": [], "event_ts": None})
        if track_ids:
            entry.setdefault("changed_ids", set())
            entry.setdefault("removed_ids", set())
            entry.setdefault("full", False)
            if record_key is None:
                entry["full"] = True  # an unreadable key must never become a silently missed record
            elif record_key:
                entry["changed_ids"].add(record_key)
                if is_remove:
                    entry["removed_ids"].add(record_key)
        if message_id:
            entry["message_ids"].append(message_id)
        if event_ts and (entry["event_ts"] is None or event_ts > entry["event_ts"]):
            entry["event_ts"] = event_ts
    return work, failed


_MARK_FALLBACK_UPDATE = "SET dirty = :t, dirty_since = if_not_exists(dirty_since, :iso)"


def _mark_with_ids(client: Any, project_id: str, entry: Dict[str, Any], now_us: int, ts_us: int) -> None:
    """The MARK of _mark_projects_dirty plus the change log (ENC-TSK-R41): still ONE conditional
    UpdateItem per project per batch on the happy path.

    * over FEED_INCREMENTAL_MAX_IDS ids in this batch, or an unreadable stream key -> SET full_reread
      (no ids added);
    * a MARK that loses the monotonic last_write_at condition is superseded for dirty, but its ids must
      still land, so it is re-applied unconditionally without touching last_write_at;
    * the set can also grow across batches, so the post-update size is checked and, if it crossed the cap,
      the sets are dropped in favour of full_reread."""
    changed = set(entry.get("changed_ids") or ())
    removed = set(entry.get("removed_ids") or ())
    full = bool(entry.get("full")) or len(changed | removed) > FEED_INCREMENTAL_MAX_IDS
    if full:
        changed, removed = set(), set()
    adds: List[str] = []
    values: Dict[str, Any] = {":t": {"BOOL": True}, ":iso": {"S": _iso_from_us(now_us)}}
    if changed:
        adds.append("changed_ids :ids")
        values[":ids"] = {"SS": sorted(changed)}
    if removed:
        adds.append("removed_ids :rids")
        values[":rids"] = {"SS": sorted(removed)}
    suffix = (", full_reread = :t" if full else "")
    add_clause = (" ADD " + ", ".join(adds)) if adds else ""
    kwargs: Dict[str, Any] = {
        "TableName": FEED_PUBLISH_STATE_TABLE,
        "Key": {"project_id": {"S": project_id}},
        "UpdateExpression": _MARK_UPDATE + suffix + add_clause,
        "ConditionExpression": _MARK_CONDITION,
        "ExpressionAttributeValues": dict(values, **{":ts": {"N": str(ts_us)}}),
    }
    if adds:
        kwargs["ReturnValues"] = "UPDATED_NEW"
    try:
        resp = client.update_item(**kwargs)
    except ClientError as exc:
        if not _is_condition_failure(exc) or not (adds or full):
            raise
        logger.debug("feed_publisher: MARK project=%s superseded; re-applying its change ids", project_id)
        kwargs.pop("ConditionExpression")
        kwargs["UpdateExpression"] = _MARK_FALLBACK_UPDATE + suffix + add_clause
        kwargs["ExpressionAttributeValues"] = dict(values)
        resp = client.update_item(**kwargs)
    attrs = (resp or {}).get("Attributes") or {}
    size = len((attrs.get("changed_ids") or {}).get("SS", [])) + len((attrs.get("removed_ids") or {}).get("SS", []))
    if size > FEED_INCREMENTAL_MAX_IDS:
        client.update_item(
            TableName=FEED_PUBLISH_STATE_TABLE,
            Key={"project_id": {"S": project_id}},
            UpdateExpression="SET full_reread = :t REMOVE changed_ids, removed_ids",
            ExpressionAttributeValues={":t": {"BOOL": True}},
        )


def _mark_projects_dirty(work: Dict[str, Dict[str, Any]], ddb: Any = None) -> List[str]:
    """ONE conditional UpdateItem per distinct project in the batch (FR-16).

    Returns the message ids whose MARK did NOT land, so the caller can hand them back to SQS
    (batchItemFailures). A MARK that cannot be recorded must be retried, never swallowed: a
    swallowed failure deletes the queue message and the write is gone (ENC-ISS-543)."""
    failed_ids: List[str] = []
    if not work:
        return failed_ids
    client = ddb if ddb is not None else _ddb_client(FEED_PUBLISH_STATE_REGION)
    for project_id in sorted(work):
        entry = work[project_id]
        now_us = _now_us()
        ts_us = now_us
        event_us = _ts_to_us(entry.get("event_ts"))
        if event_us is not None:
            ts_us = max(now_us, min(event_us, now_us + _FUTURE_EVENT_CLAMP_US))
        try:
            if "changed_ids" in entry and _incremental_active():
                _mark_with_ids(client, project_id, entry, now_us, ts_us)
            else:
                client.update_item(
                    TableName=FEED_PUBLISH_STATE_TABLE,
                    Key={"project_id": {"S": project_id}},
                    UpdateExpression=_MARK_UPDATE,
                    ConditionExpression=_MARK_CONDITION,
                    ExpressionAttributeValues={
                        ":t": {"BOOL": True},
                        ":iso": {"S": _iso_from_us(now_us)},
                        ":ts": {"N": str(ts_us)},
                    },
                )
        except ClientError as exc:
            if _is_condition_failure(exc):
                # A newer MARK already stored a later last_write_at (and set dirty).
                logger.debug("feed_publisher: MARK project=%s superseded by a newer mark", project_id)
                continue
            logger.error(
                "feed_publisher: MARK failed project=%s code=%s; returning %d message(s) to the queue",
                project_id, exc.response.get("Error", {}).get("Code", ""), len(entry["message_ids"]),
            )
            failed_ids.extend(entry["message_ids"])
        except Exception as exc:  # noqa: BLE001 - any MARK failure must return the messages
            logger.error(
                "feed_publisher: MARK failed project=%s: %s; returning %d message(s) to the queue",
                project_id, exc, len(entry["message_ids"]),
            )
            failed_ids.extend(entry["message_ids"])
    return failed_ids


def _handle_mark(event: Dict[str, Any]) -> Dict[str, Any]:
    """Coalesced SQS path: record dirty per project and return. No S3, no CloudFront, no
    re-read; the queue delivers (and FeedQueueLossAlarm counts) exactly as in per_batch."""
    records = event.get("Records", [])
    record_message_ids = [r.get("messageId") for r in records if r.get("messageId")]
    logger.info("feed_publisher: MARK invoked records=%d dry_run=%s", len(records), DRY_RUN)

    work, failed_message_ids = _extract_mark_work(event)
    logger.info("feed_publisher: MARK affected project IDs: %s", sorted(work))

    # DVP-TSK-A83: this consumer is the only thing stamping projects.last_activity_at, and the
    # MARK path consumes the same records, so the stamp must keep running here.
    try:
        _record_project_activity(_extract_project_activity_from_sqs_event(event))
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: last_activity_at stamping skipped: %s", exc)

    if DRY_RUN:
        logger.info("feed_publisher: DRY_RUN mode — MARK state writes suppressed")
        return _batch_failure_response(failed_message_ids)
    try:
        failed_message_ids = failed_message_ids + _mark_projects_dirty(work)
    except Exception as exc:  # noqa: BLE001
        logger.error("feed_publisher: MARK batch failed, marking all records for retry: %s", exc, exc_info=True)
        return _batch_failure_response(record_message_ids)
    return _batch_failure_response(failed_message_ids)


def _scan_dirty_projects(ddb: Any) -> List[str]:
    """project_ids currently dirty. A strongly consistent Scan of a table with one item per
    project (tens of items); the lease item has no `dirty` attribute and is filtered out."""
    dirty: List[str] = []
    kwargs: Dict[str, Any] = {
        "TableName": FEED_PUBLISH_STATE_TABLE,
        "FilterExpression": "dirty = :t",
        "ExpressionAttributeValues": {":t": {"BOOL": True}},
        "ProjectionExpression": "project_id",
        "ConsistentRead": True,
    }
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            pid = (item.get("project_id") or {}).get("S")
            if pid:
                dirty.append(pid)
        if not resp.get("LastEvaluatedKey"):
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return sorted(set(dirty))


def _acquire_sweep_lease(ddb: Any, owner: str, context: Any) -> bool:
    """Conditional claim of the sweep lease. False when another live sweep holds it."""
    remaining_s = 600.0
    getter = getattr(context, "get_remaining_time_in_millis", None)
    if callable(getter):
        try:
            remaining_s = float(getter()) / 1000.0
        except (TypeError, ValueError):
            pass
    now_us = _now_us()
    expires_us = now_us + int((remaining_s + _LEASE_MARGIN_SECONDS) * 1_000_000)
    try:
        ddb.update_item(
            TableName=FEED_PUBLISH_STATE_TABLE,
            Key={"project_id": {"S": _LEASE_KEY}},
            UpdateExpression=_LEASE_UPDATE,
            ConditionExpression=_LEASE_CONDITION,
            ExpressionAttributeValues={
                ":exp": {"N": str(expires_us)},
                ":owner": {"S": owner},
                ":now": {"N": str(now_us)},
            },
        )
        return True
    except ClientError as exc:
        if _is_condition_failure(exc):
            return False
        raise


def _release_sweep_lease(ddb: Any, owner: str) -> None:
    """Best effort: an unreleased lease just expires with the invocation's own deadline."""
    try:
        ddb.update_item(
            TableName=FEED_PUBLISH_STATE_TABLE,
            Key={"project_id": {"S": _LEASE_KEY}},
            UpdateExpression=_LEASE_RELEASE_UPDATE,
            ConditionExpression=_LEASE_RELEASE_CONDITION,
            ExpressionAttributeValues={":owner": {"S": owner}},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: sweep lease release skipped: %s", exc)


def _parse_state_row(attrs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not attrs:
        # No row came back with the claim: the change log is unknown, so the only safe plan is a full re-read.
        return {"changed": set(), "removed": set(), "full": True}
    return {
        "changed": set((attrs.get("changed_ids") or {}).get("SS") or []),
        "removed": set((attrs.get("removed_ids") or {}).get("SS") or []),
        "full": bool((attrs.get("full_reread") or {}).get("BOOL")),
    }


def _claim_dirty_projects(
    ddb: Any, dirty_projects: List[str], owner: str, rows_out: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, int]:
    """Stamp claimed_at on each still-dirty project. Returns project_id -> claimed_at (us).

    A project whose dirty flag was cleared since the scan is skipped (condition fails). Any
    other error propagates BEFORE anything is published, leaving every project dirty."""
    claims: Dict[str, int] = {}
    for project_id in dirty_projects:
        claimed_at = _now_us()
        claim_kwargs: Dict[str, Any] = {}
        if rows_out is not None:
            claim_kwargs["ReturnValues"] = "ALL_NEW"  # the change ids as of the claim = what this sweep owns
        try:
            resp = ddb.update_item(
                TableName=FEED_PUBLISH_STATE_TABLE,
                Key={"project_id": {"S": project_id}},
                UpdateExpression=_CLAIM_UPDATE,
                ConditionExpression=_CLAIM_CONDITION,
                ExpressionAttributeValues={
                    ":t": {"BOOL": True},
                    ":c": {"N": str(claimed_at)},
                    ":owner": {"S": owner},
                },
                **claim_kwargs,
            )
            if rows_out is not None:
                rows_out[project_id] = _parse_state_row((resp or {}).get("Attributes"))
        except ClientError as exc:
            if _is_condition_failure(exc):
                continue
            raise
        claims[project_id] = claimed_at
    return claims


def _clear_with_ids(
    ddb: Any, project_id: str, claimed_at: int, grace_us: int, generated_at: str, plan: Dict[str, Any],
) -> bool:
    """The trailing-edge clear of _clear_published as ONE conditional UpdateItem that also DELETEs only
    the change ids this sweep processed and REMOVEs full_reread when a full re-read honored it. Ids a MARK
    added after the claim are not in the processed set, so they survive (and that MARK also bumped
    last_write_at, so dirty stays). Raises ClientError on a lost condition exactly like the plain clear.

    Returns False when the clear succeeded but ids/full_reread remain (a late MARK whose last_write_at
    predates the cutoff): dirty is set again so the next sweep picks them up."""
    values: Dict[str, Any] = {
        ":t": {"BOOL": True},
        ":cutoff": {"N": str(claimed_at - grace_us)},
        ":pub": {"S": generated_at},
        ":wm": {"N": str(claimed_at)},
    }
    sets = ["last_published_at = :pub", "read_watermark = :wm"]
    removes = ["dirty", "dirty_since"]
    deletes: List[str] = []
    if plan.get("mode") == "full":
        sets.append("last_full_reread_at = :fr")
        values[":fr"] = {"N": str(int(plan.get("full_read_at") or time.time()))}
    if plan.get("full_honored"):
        removes.append("full_reread")
    if plan.get("processed_changed"):
        deletes.append("changed_ids :pc")
        values[":pc"] = {"SS": sorted(plan["processed_changed"])}
    if plan.get("processed_removed"):
        deletes.append("removed_ids :pr")
        values[":pr"] = {"SS": sorted(plan["processed_removed"])}
    expr = "REMOVE " + ", ".join(removes) + " SET " + ", ".join(sets)
    if deletes:
        expr += " DELETE " + ", ".join(deletes)
    resp = ddb.update_item(
        TableName=FEED_PUBLISH_STATE_TABLE,
        Key={"project_id": {"S": project_id}},
        UpdateExpression=expr,
        ConditionExpression=_CLEAR_CONDITION,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    attrs = (resp or {}).get("Attributes") or {}
    if attrs.get("changed_ids") or attrs.get("removed_ids") or attrs.get("full_reread"):
        logger.info("feed_publisher: project=%s has change ids left after the clear; marking dirty again", project_id)
        ddb.update_item(
            TableName=FEED_PUBLISH_STATE_TABLE,
            Key={"project_id": {"S": project_id}},
            UpdateExpression=_MARK_FALLBACK_UPDATE,
            ExpressionAttributeValues={":t": {"BOOL": True}, ":iso": {"S": _iso_from_us(_now_us())}},
        )
        return False
    return True


def _clear_published(
    ddb: Any, claims: Dict[str, int], result: "PublishResult", ctx: Optional["SweepContext"] = None,
) -> Tuple[List[str], List[str]]:
    """Trailing-edge clear. Returns (cleared, retained).

    Cleared only when the publish was clean for the project AND no MARK arrived after the claim
    (minus grace). Anything else stays dirty and is retried by the next sweep."""
    cleared: List[str] = []
    retained: List[str] = []
    grace_us = int(FEED_CLAIM_GRACE_SECONDS * 1_000_000)
    for project_id, claimed_at in sorted(claims.items()):
        if result.global_degraded or project_id in result.degraded_projects:
            logger.warning("feed_publisher: project=%s published degraded; staying dirty", project_id)
            retained.append(project_id)
            continue
        plan = ctx.plans.get(project_id) if (ctx is not None and ctx.incremental) else None
        try:
            if plan is not None and plan.get("mode"):
                if not _clear_with_ids(ddb, project_id, claimed_at, grace_us, result.generated_at, plan):
                    retained.append(project_id)
                    continue
            else:
                ddb.update_item(
                    TableName=FEED_PUBLISH_STATE_TABLE,
                    Key={"project_id": {"S": project_id}},
                    UpdateExpression=_CLEAR_UPDATE,
                    ConditionExpression=_CLEAR_CONDITION,
                    ExpressionAttributeValues={
                        ":t": {"BOOL": True},
                        ":cutoff": {"N": str(claimed_at - grace_us)},
                        ":pub": {"S": result.generated_at},
                    },
                )
            cleared.append(project_id)
        except ClientError as exc:
            if _is_condition_failure(exc):
                logger.info(
                    "feed_publisher: project=%s written during/after claim; staying dirty for next sweep",
                    project_id,
                )
            else:
                logger.error(
                    "feed_publisher: clear failed project=%s code=%s; staying dirty",
                    project_id, exc.response.get("Error", {}).get("Code", ""),
                )
            retained.append(project_id)
        except Exception as exc:  # noqa: BLE001 - a failed clear only costs an extra publish
            logger.error("feed_publisher: clear failed project=%s: %s; staying dirty", project_id, exc)
            retained.append(project_id)
    return cleared, retained


class SweepContext:
    """State shared between _handle_sweep and _publish_all for one SWEEP (set as the module-level
    _sweep_ctx so _publish_all keeps its single-argument signature). ``plans`` holds, per claimed
    project, the change ids owned by this sweep and what was done with them."""

    __slots__ = ("incremental", "plans", "modes", "snapshots", "bytes_published", "published_at")

    def __init__(self, incremental: bool) -> None:
        self.incremental = incremental
        # project_id -> epoch seconds of the state row's last_published_at; None = could not be read
        # (then no snapshot is trusted this sweep).
        self.published_at: Optional[Dict[str, float]] = None
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.modes: Dict[str, str] = {}
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.bytes_published = 0


_sweep_ctx: Optional[SweepContext] = None


def _scan_last_published(ddb: Any) -> Optional[Dict[str, float]]:
    """last_published_at (epoch seconds) of every project row, from one strongly consistent Scan of the
    small state table. None on any failure: an unreadable stamp means no snapshot can be vouched for."""
    out: Dict[str, float] = {}
    kwargs: Dict[str, Any] = {
        "TableName": FEED_PUBLISH_STATE_TABLE,
        "ProjectionExpression": "project_id, last_published_at",
        "ConsistentRead": True,
    }
    try:
        while True:
            resp = ddb.scan(**kwargs)
            for item in resp.get("Items", []):
                pid = (item.get("project_id") or {}).get("S")
                us = _ts_to_us((item.get("last_published_at") or {}).get("S"))
                if pid and us is not None:
                    out[pid] = us / 1_000_000
            if not resp.get("LastEvaluatedKey"):
                return out
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: last_published_at scan failed (%s); every project gets a full re-read", exc)
        return None


def _snapshot_s3():
    return boto3.client("s3", region_name=TRACKER_REGION)


def _snapshot_key(project: str) -> str:
    return f"{SNAPSHOT_PREFIX}{project}.json.gz"


def _load_snapshot(project: str) -> Optional[Dict[str, Any]]:
    """Prior per-project snapshot, or None (missing / unreadable / wrong project -> full re-read)."""
    try:
        body = _snapshot_s3().get_object(Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key(project))["Body"].read()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") not in ("NoSuchKey", "404"):
            logger.warning("feed_publisher: snapshot read failed project=%s: %s; full re-read", project, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: snapshot read failed project=%s: %s; full re-read", project, exc)
        return None
    snap = snapshot_decode(body, project)
    if snap is None:
        logger.warning("feed_publisher: snapshot for project=%s is invalid; full re-read", project)
    return snap


def _save_snapshot(project: str, items: Dict[str, Dict], full_read_at: float) -> bool:
    try:
        blob = snapshot_encode(project, items, full_read_at, time.time())
        _snapshot_s3().put_object(
            Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key(project), Body=blob, ContentType="application/gzip",
        )
        return True
    except Exception as exc:  # noqa: BLE001 - the project then stays dirty and keeps its ids
        logger.error("feed_publisher: snapshot save failed project=%s: %s; project stays dirty", project, exc)
        return False


def _apply_delta(items: Dict[str, Dict], changed: Set[str], removed: Set[str], project: str) -> bool:
    """Merge the current state of exactly the changed keys into ``items`` (in place): a key that
    exists is inserted/replaced, a key that comes back absent is a deletion. A record removed and then
    re-created inside the window therefore survives. True when anything actually changed."""
    wanted = set(changed) | set(removed)
    found = batch_get_tracker_items(project, sorted(wanted), TRACKER_TABLE, TRACKER_REGION)
    mutated = False
    for rid in wanted:
        raw = found.get(rid)
        if raw is None:
            if items.pop(rid, None) is not None:
                mutated = True
        elif items.get(rid) != raw:
            items[rid] = raw
            mutated = True
    return mutated


def _build_project_model(entry: FeedProjectEntry, ctx: SweepContext) -> Dict[str, Any]:
    """Per-project record model for one SWEEP when FEED_INCREMENTAL is on. Same shape as
    fetch_from_dynamodb returns. Records are ordered by record_id in every mode so an incremental merge and
    a full re-read of the same data are byte-identical."""
    name = entry.name
    plan = ctx.plans.get(name)
    changed: Set[str] = plan["changed"] if plan else set()
    removed: Set[str] = plan["removed"] if plan else set()
    overflow = len(changed | removed) > FEED_INCREMENTAL_MAX_IDS
    snap = _load_snapshot(name)
    now = time.time()
    fresh = snap is not None and (now - snap["full_read_at"]) < FEED_FULL_REREAD_SECONDS
    if snap is not None and fresh:
        published = ctx.published_at.get(name) if ctx.published_at is not None else None
        if ctx.published_at is None or (published is not None and snap["saved_at"] < published - SNAPSHOT_STALE_GRACE_SECONDS):
            logger.info(
                "feed_publisher: project=%s snapshot saved_at=%s predates last_published_at=%s; full re-read",
                name, snap["saved_at"], published,
            )
            fresh = False
    trusted = fresh and not (plan is not None and (plan["full"] or overflow))
    items: Optional[Dict[str, Dict]] = None
    mode = "full"
    full_read_at = now
    save = True
    if trusted:
        items = dict(snap["items"])
        full_read_at = snap["full_read_at"]
        if changed or removed:
            try:
                save = _apply_delta(items, changed, removed, name)
                mode = "incremental"
            except Exception as exc:  # noqa: BLE001 - any merge error self-heals with a full re-read
                logger.warning("feed_publisher: incremental merge failed project=%s: %s; full re-read", name, exc)
                items = None
        else:
            mode, save = "reuse", False
    if items is None:
        mode, full_read_at, save = "full", now, True
        items = query_project_items(name, TRACKER_TABLE, TRACKER_REGION)
        if plan is not None and not plan["full"] and not overflow and (changed or removed):
            # The GSI is eventually consistent; overlay the keys the stream reported with a strong read so
            # the snapshot a later incremental run trusts is never older than the writes it clears.
            try:
                _apply_delta(items, changed, removed, name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("feed_publisher: change-id overlay failed project=%s: %s", name, exc)
    # A project this sweep publishes (claimed -> its clear advances last_published_at) ALWAYS refreshes its
    # snapshot, even when the merge changed nothing, or the next sweep would see a stale saved_at.
    save = save or plan is not None
    ctx.modes[name] = mode
    ctx.snapshots[name] = {"items": items, "full_read_at": full_read_at, "save": save}
    if plan is not None:
        plan.update(
            mode=mode, full_read_at=full_read_at, processed_changed=set(changed), processed_removed=set(removed),
            full_honored=bool(mode == "full" and plan["full"]),
        )
    logger.info("feed_publisher: project=%s tracker model mode=%s records=%d ids=%d", name, mode, len(items), len(changed | removed))
    return group_project_items([items[k] for k in sorted(items)])


def _save_snapshots(ctx: SweepContext, degraded_projects: Set[str]) -> None:
    """Persist the snapshots the publish was built from. A failed save leaves the project dirty with
    its ids (the OLD snapshot plus those ids is still a correct merge input), never cleared."""
    for name, snap in sorted(ctx.snapshots.items()):
        if snap["save"] and not _save_snapshot(name, snap["items"], snap["full_read_at"]):
            degraded_projects.add(name)


def _emit_sweep_metrics(ctx: SweepContext) -> None:
    """One CloudWatch EMF record per published sweep so the median per-publish cost can be computed
    from production data (FR-9 N=2 decision). Always emitted in coalesced mode, flag on or off."""
    try:
        mode = "incremental" if (ctx.incremental and ctx.modes and "full" not in ctx.modes.values()) else "full"
        record = {
            "_aws": {
                "Timestamp": int(time.time() * 1000),
                "CloudWatchMetrics": [{
                    "Namespace": METRIC_NAMESPACE,
                    "Dimensions": [["Mode"], []],
                    "Metrics": [
                        {"Name": "FeedPublishBytes", "Unit": "Bytes"},
                        {"Name": "FeedPublishReadUnits", "Unit": "Count"},
                        {"Name": "FeedPublishMode", "Unit": "Count"},
                    ],
                }],
            },
            "Mode": mode,
            "FeedPublishBytes": int(ctx.bytes_published),
            "FeedPublishReadUnits": round(read_units_total(), 2),
            "FeedPublishMode": 1,
            "ProjectModes": dict(sorted(ctx.modes.items())),
        }
        print(json.dumps(record, separators=(",", ":")), flush=True)
    except Exception as exc:  # noqa: BLE001 - metrics never fail a sweep
        logger.warning("feed_publisher: EMF metric emission skipped: %s", exc)


def _uploaded_bytes(feed_dir: Path, prefix: str, keys: List[str], report: Dict[str, Any]) -> int:
    stored = report.get("stored_bytes") or {}
    total = 0
    for key in keys:
        try:
            if key in stored:
                total += int(stored[key])
                continue
            rel = key[len(prefix):].lstrip("/") if key.startswith(prefix) else key
            total += (feed_dir / rel).stat().st_size
        except Exception:  # noqa: BLE001
            continue
    return total


def _handle_sweep(context: Any) -> Dict[str, Any]:
    """Scheduled SWEEP: publish once for every dirty project, then clear dirty on the trailing edge."""
    if FEED_PUBLISH_MODE != FEED_PUBLISH_MODE_COALESCED:
        logger.info("feed_publisher: sweep ignored (FEED_PUBLISH_MODE=%s)", FEED_PUBLISH_MODE)
        return {"status": "skipped", "reason": "per_batch_mode"}
    ddb = _ddb_client(FEED_PUBLISH_STATE_REGION)
    dirty_projects = _scan_dirty_projects(ddb)
    if not dirty_projects:
        logger.info("feed_publisher: sweep idle (no dirty projects)")
        return {"status": "idle", "dirty": 0}
    if DRY_RUN:
        logger.info("feed_publisher: DRY_RUN sweep — would publish for %s", dirty_projects)
        return {"status": "dry_run", "dirty": len(dirty_projects)}

    owner = getattr(context, "aws_request_id", None) or f"sweep-{uuid.uuid4().hex[:12]}"
    if not _acquire_sweep_lease(ddb, owner, context):
        logger.info("feed_publisher: sweep skipped (lease held by another sweep)")
        return {"status": "skipped", "reason": "lease_held"}
    global _sweep_ctx
    incremental = _incremental_active()
    try:
        rows: Dict[str, Dict[str, Any]] = {}
        claims = _claim_dirty_projects(ddb, dirty_projects, owner, rows if incremental else None)
        if not claims:
            return {"status": "idle", "dirty": 0}
        ctx = SweepContext(incremental)
        if incremental:
            ctx.published_at = _scan_last_published(ddb)
            for pid in claims:
                row = rows.get(pid) or _parse_state_row(None)
                ctx.plans[pid] = {
                    "changed": row["changed"], "removed": row["removed"], "full": row["full"],
                    "mode": None, "processed_changed": set(), "processed_removed": set(),
                    "full_honored": False, "full_read_at": None,
                }
        # Fresh project list: a project registered since the warm-container cache was filled
        # must be in the publish, or clearing its dirty flag would drop its first writes.
        _reset_projects_cache()
        reset_read_units()
        _sweep_ctx = ctx
        try:
            result = _publish_all(set(claims))
        except Exception as exc:
            # Nothing is cleared: every claimed project stays dirty for the next sweep.
            logger.error("feed_publisher: sweep publish failed, projects stay dirty %s: %s",
                         sorted(claims), exc, exc_info=True)
            raise
        finally:
            _sweep_ctx = None
        cleared, retained = _clear_published(ddb, claims, result, ctx)
        _emit_sweep_metrics(ctx)
        logger.info(
            "feed_publisher: sweep complete generated_at=%s cleared=%s retained=%s",
            result.generated_at, cleared, retained,
        )
        return {
            "status": "published",
            "generated_at": result.generated_at,
            "cleared": cleared,
            "retained": retained,
        }
    finally:
        _release_sweep_lease(ddb, owner)


def _reset_projects_cache() -> None:
    global _projects_cache, _projects_cache_at
    _projects_cache = None
    _projects_cache_at = 0.0


# ---------------------------------------------------------------------------
# ENC-TSK-R34: object hash map (FR-20)
#
#   project_id  S   "__object_hashes__"          (the existing key schema; the dirty Scan filters it out)
#   hashes          M   {s3 key -> sha256}          mobile/v1 objects confirmed written or unchanged
#   fingerprint     S   publish target/encoding the hashes are valid for (bucket, prefix, store mode,
#                       gzip, cache-control): a change republishes everything
#   stage_hashes    M   {project -> sha256}         analytics sync-stage records last staged
#   stage_fingerprint S analytics bucket/region
#   refreshed_at    N   epoch seconds of the last FULL publish (forces one every 24 h)
#
# A hash is recorded only after its write returned, so a failed or partial publish leaves the missing
# entries absent and the next sweep rewrites them. Any failure reading the map degrades to "everything
# changed" (a full publish), never to a skipped write.
# ---------------------------------------------------------------------------


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _mobile_fingerprint(cache_control: Optional[str], gzip_on: bool) -> str:
    return _sha256_text(
        FEED_BUCKET,
        FEED_PREFIX,
        os.environ.get("CONTENT_STORE_MODE", "legacy"),
        os.environ.get("CONTENT_BUCKET", ""),
        os.environ.get("S3_ENV_PREFIX", ""),
        "gzip" if gzip_on else "identity",
        cache_control or "",
    )


def _stage_fingerprint() -> str:
    return _sha256_text(ANALYTICS_BUCKET, ANALYTICS_REGION)


def _stage_digest(project_data: Dict[str, Any]) -> Optional[str]:
    """Digest of the records a project's sync-stage write would contain; None if not computable."""
    try:
        payload = {a: project_data.get(a, []) for a in ("tasks", "issues", "features")}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    except Exception as exc:  # noqa: BLE001 - an unhashable record means "changed", never "skip"
        logger.warning("feed_publisher: sync-stage digest unavailable: %s", exc)
        return None


def _load_hash_state(ddb: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "hashes": {}, "fingerprint": None, "stage_hashes": {}, "stage_fingerprint": None, "refreshed_at": None,
    }
    try:
        resp = ddb.get_item(
            TableName=FEED_PUBLISH_STATE_TABLE, Key={"project_id": {"S": OBJECT_HASHES_KEY}}, ConsistentRead=True
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: object hash map unreadable, publishing everything: %s", exc)
        return state
    item = resp.get("Item") or {}
    for attr in ("hashes", "stage_hashes"):
        state[attr] = {k: v.get("S") for k, v in (item.get(attr, {}).get("M") or {}).items() if v.get("S")}
    for attr in ("fingerprint", "stage_fingerprint"):
        state[attr] = (item.get(attr) or {}).get("S")
    raw_ts = (item.get("refreshed_at") or {}).get("N")
    try:
        state["refreshed_at"] = float(raw_ts) if raw_ts is not None else None
    except ValueError:
        state["refreshed_at"] = None
    return state


def _save_hash_state(ddb: Any, *, refreshed_at: Optional[float] = None, **maps_and_fingerprints: Any) -> None:
    """SET only the supplied attributes (hashes/stage_hashes maps, fingerprint strings). Best effort:
    a failed save just means the next sweep republishes."""
    attrs: Dict[str, Dict[str, Any]] = {}
    for name, value in maps_and_fingerprints.items():
        if value is None:
            continue
        if isinstance(value, dict):
            attrs[name] = {"M": {str(k): {"S": str(v)} for k, v in value.items()}}
        else:
            attrs[name] = {"S": str(value)}
    if refreshed_at is not None:
        attrs["refreshed_at"] = {"N": str(int(refreshed_at))}
    if not attrs:
        return
    names = {f"#a{i}": k for i, k in enumerate(attrs)}
    values = {f":v{i}": attrs[k] for i, k in enumerate(attrs)}
    expr = "SET " + ", ".join(f"#a{i} = :v{i}" for i in range(len(attrs)))
    try:
        ddb.update_item(
            TableName=FEED_PUBLISH_STATE_TABLE,
            Key={"project_id": {"S": OBJECT_HASHES_KEY}},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: object hash map not saved (next sweep republishes): %s", exc)


# ---------------------------------------------------------------------------
# Full publish (shared by per_batch and SWEEP)
# ---------------------------------------------------------------------------


class PublishResult:
    """Outcome of one full publish. A plain class, not a dataclass: the test loaders exec this
    module without registering it in sys.modules, which breaks dataclass under
    `from __future__ import annotations`."""

    __slots__ = ("generated_at", "degraded_projects", "global_degraded")

    def __init__(self, generated_at: str, degraded_projects: Set[str], global_degraded: bool) -> None:
        self.generated_at = generated_at
        self.degraded_projects = degraded_projects
        self.global_degraded = global_degraded


def _publish_all(affected_projects: Set[str]) -> PublishResult:
    """Regenerate and publish the feeds for ALL projects (unchanged from the pre-R26 handler).

    Raises on a fatal failure (same as before); non-fatal sub-step failures are logged and
    swallowed exactly as before, except that data-bearing ones are reported on the result so
    the SWEEP keeps the affected projects dirty."""
    # 2. Fetch all project data from DynamoDB
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    all_entries = _all_project_entries()
    ddb = _ddb_client()
    all_project_data: Dict[str, Dict[str, Any]] = {}
    # ENC-TSK-R26: projects whose source read failed (the loops below publish an EMPTY
    # feed for them, as per_batch always has). The SWEEP must not clear dirty for these.
    degraded_projects: Set[str] = set()
    global_degraded = False
    # ENC-TSK-R41: set only by a coalesced SWEEP (None for per_batch and direct calls -> unchanged path).
    sweep = _sweep_ctx
    model_ctx = sweep if (sweep is not None and sweep.incremental) else None

    for entry in all_entries:
        try:
            if model_ctx is not None:
                all_project_data[entry.name] = _build_project_model(entry, model_ctx)
            else:
                all_project_data[entry.name] = fetch_from_dynamodb(
                    entry,
                    table=TRACKER_TABLE,
                    region=TRACKER_REGION,
                )
        except Exception as exc:
            logger.error("feed_publisher: DynamoDB fetch failed for project=%s: %s", entry.name, exc)
            degraded_projects.add(entry.name)
            all_project_data[entry.name] = {"tasks": [], "issues": [], "features": [], "lessons": [], "plans": []}

    # 2b. Fetch all document data from the documents DynamoDB table
    all_documents_data: Dict[str, List[Dict[str, Any]]] = {}
    for entry in all_entries:
        try:
            all_documents_data[entry.name] = fetch_documents_from_dynamodb(
                entry,
                table=DOCUMENTS_TABLE,
                region=DOCUMENTS_REGION,
            )
        except Exception as exc:
            logger.error("feed_publisher: documents DynamoDB fetch failed for project=%s: %s", entry.name, exc)
            degraded_projects.add(entry.name)
            all_documents_data[entry.name] = []

    # 3. Generate mobile feeds locally in /tmp
    feed_dir = FEED_TEMP_DIR
    # ENC-TSK-R34: FEED_GZIP (coalesced only) also minifies the JSON and splits tasks.json per project
    # behind an index manifest (tasks.json compressed is still > 5 MB, ruling A7). Off -> the exact
    # pre-R34 call, no extra kwargs.
    gzip_on = _gzip_active()
    mobile_gen_kwargs: Dict[str, Any] = (
        {"minify": True, "split_tasks": True, "key_prefix": FEED_PREFIX} if gzip_on else {}
    )
    documents_gen_kwargs: Dict[str, Any] = {"minify": True} if gzip_on else {}
    generate_mobile_feeds(all_entries, all_project_data, generated_at, feed_dir, **mobile_gen_kwargs)

    # 3a. Generate documents feed (separate from tracker feeds)
    try:
        generate_documents_feed(all_entries, all_documents_data, generated_at, feed_dir, **documents_gen_kwargs)
    except Exception as exc:
        logger.error("feed_publisher: generate_documents_feed failed: %s", exc)
        global_degraded = True
        # Non-fatal: tracker feeds are already generated

    # 3b. Generate deploy-pending feed (GMF notification banner — DOC-63420302EF65 §6.1)
    try:
        _generate_deploy_pending_feed(generated_at, feed_dir, ddb)
    except Exception as exc:
        logger.error("feed_publisher: generate_deploy_pending_feed failed: %s", exc)
        # Non-fatal: approval banner falls back to direct API polling

    # 3c. Freshness SLA check — warns if feeds lag behind source data
    check_freshness_sla(generated_at, all_project_data)

    # 4. Fetch reference docs from S3 (via DynamoDB metadata) and stage in /tmp/reference/
    try:
        s3_client = boto3.client("s3", region_name="us-east-1")
        generate_reference_docs_from_s3(all_entries, feed_dir, ddb, table=TRACKER_TABLE, s3_client=s3_client)
    except Exception as exc:
        logger.error("feed_publisher: generate_reference_docs_from_s3 failed: %s", exc)
        # Non-fatal: continue without reference docs

    # ENC-TSK-R34: content-hash diffing state (coalesced SWEEP only; flags default off).
    diff_active = _content_diff_active() and not DRY_RUN
    state_ddb: Any = None
    hash_state: Dict[str, Any] = {}
    full_refresh = False
    if diff_active:
        state_ddb = _ddb_client(FEED_PUBLISH_STATE_REGION)
        hash_state = _load_hash_state(state_ddb)
        last_full = hash_state.get("refreshed_at")
        full_refresh = last_full is None or (time.time() - last_full) >= FEED_DIFF_REFRESH_SECONDS
        if full_refresh:
            logger.info("feed_publisher: content-diff full refresh (no hash map or older than %ss)", FEED_DIFF_REFRESH_SECONDS)
    refreshed_at_kw: Dict[str, Any] = {"refreshed_at": time.time()} if full_refresh else {}

    # 5. Publish feed files to S3
    #
    # ENC-TSK-K98: skip on gamma (FEED_S3_PUBLISH_ENABLED=false) — the
    # /mobile/v1 objects are served PUBLICLY by the shared UI-origin cockpit
    # CDN, and the ui-v2 cockpit now reads its snapshot from the
    # authenticated feed_query API. Prod keeps publishing.
    if FEED_S3_PUBLISH_ENABLED:
        publish_kwargs: Dict[str, Any] = {}
        if FEED_PUBLISH_MODE == FEED_PUBLISH_MODE_COALESCED:
            # ENC-TSK-R26 (ruling A3): a 60 s TTL replaces invalidation; per_batch keeps
            # feed_utils' existing header (no kwarg passed -> identical call).
            publish_kwargs["cache_control"] = COALESCED_CACHE_CONTROL
        s3_report: Dict[str, Any] = {}
        mobile_fp = _mobile_fingerprint(publish_kwargs.get("cache_control"), gzip_on)
        if diff_active:
            same_target = hash_state.get("fingerprint") == mobile_fp
            publish_kwargs["previous_hashes"] = {} if (full_refresh or not same_target) else dict(hash_state["hashes"])
        if gzip_on:
            publish_kwargs["gzip_json"] = True
        if diff_active or gzip_on:
            publish_kwargs["report"] = s3_report
        try:
            uploaded_keys = publish_mobile_feeds_to_s3(
                feed_dir=feed_dir,
                bucket=FEED_BUCKET,
                s3_prefix=FEED_PREFIX,
                dry_run=DRY_RUN,
                **publish_kwargs,
            )
        finally:
            if diff_active and s3_report.get("hashes") is not None:
                # Persisted even when a later put raised: only confirmed objects are in the map.
                _save_hash_state(state_ddb, hashes=s3_report["hashes"], fingerprint=mobile_fp, **refreshed_at_kw)
        if sweep is not None:
            sweep.bytes_published += _uploaded_bytes(feed_dir, FEED_PREFIX, uploaded_keys, s3_report)
        logger.info("feed_publisher: published %d files to S3", len(uploaded_keys))
        if diff_active:
            logger.info(
                "feed_publisher: content-diff wrote %d object(s), skipped %d unchanged",
                len(uploaded_keys), len(s3_report.get("skipped", [])),
            )
        if s3_report.get("split_required"):
            logger.warning("feed_publisher: gzipped object(s) over the 5 MB split threshold: %s", s3_report["split_required"])
    else:
        uploaded_keys = []
        logger.info(
            "feed_publisher: PUBLIC /mobile S3 publish disabled "
            "(FEED_S3_PUBLISH_ENABLED=false); skipping write + CF invalidation"
        )

    # 5b. Write analytics sync-stage JSON for Trino/Superset pipeline
    analytics_stage_prefixes = {}  # project_name -> {artifact -> s3_prefix_uri}
    stage_fp = _stage_fingerprint()
    stage_prev: Dict[str, str] = (
        dict(hash_state.get("stage_hashes") or {})
        if diff_active and not full_refresh and hash_state.get("stage_fingerprint") == stage_fp
        else {}
    )
    new_stage_hashes: Dict[str, str] = {}
    try:
        for entry in all_entries:
            project_data = all_project_data.get(entry.name, {})
            digest = _stage_digest(project_data) if diff_active else None
            if digest is not None and stage_prev.get(entry.name) == digest:
                # ENC-TSK-R34 (FR-20): nothing in this project's records changed -> no sync-stage write.
                new_stage_hashes[entry.name] = digest
                continue
            stage_prefixes = write_analytics_sync_stage(
                project_name=entry.name,
                project_data=project_data,
                bucket=ANALYTICS_BUCKET,
                region=ANALYTICS_REGION,
                dry_run=DRY_RUN,
            )
            if stage_prefixes:
                analytics_stage_prefixes[entry.name] = stage_prefixes
            if digest is not None:
                new_stage_hashes[entry.name] = digest
        logger.info(
            "feed_publisher: wrote analytics sync-stage for %d projects",
            len(analytics_stage_prefixes),
        )
    except Exception as exc:
        logger.error("feed_publisher: analytics sync-stage write failed: %s", exc)
        # Non-fatal: mobile feeds are already published
    finally:
        if diff_active:
            # Only projects whose stage write returned (or was unchanged) are in the map.
            _save_hash_state(state_ddb, stage_hashes=new_stage_hashes, stage_fingerprint=stage_fp, **refreshed_at_kw)

    # 6. CloudFront invalidation (only when we actually published — K98).
    # ENC-TSK-R26: FEED_INVALIDATE=false drops the call; freshness then rides the object TTL.
    if FEED_S3_PUBLISH_ENABLED and not FEED_INVALIDATE:
        logger.info("feed_publisher: CloudFront invalidation disabled (FEED_INVALIDATE=false)")
    elif FEED_S3_PUBLISH_ENABLED:
        try:
            inv_id = invalidate_mobile_cf(
                distribution_id=CF_DISTRIBUTION,
                dry_run=DRY_RUN,
            )
            logger.info("feed_publisher: CF invalidation id=%s", inv_id)
        except Exception as exc:
            logger.error("feed_publisher: CloudFront invalidation failed: %s", exc)
            # Non-fatal: feeds are published even if invalidation fails

    # 7. SNS signal for Trino/Superset pipeline
    try:
        today = dt.date.today()
        # ENC-TSK-R34: with diffing on, signal only the projects that were actually (re)staged.
        sns_entries = [e for e in all_entries if e.name in analytics_stage_prefixes] if diff_active else all_entries
        for entry in sns_entries:
            publish_sync_message(
                project_name=entry.name,
                sync_date=today,
                artifact_names=["tasks", "issues", "features"],
                sns_topic=SNS_TOPIC,
                dry_run=DRY_RUN,
            )
    except Exception as exc:
        logger.error("feed_publisher: SNS publish failed: %s", exc)
        # Non-fatal

    # 8. Per-project EventBridge events for Trino/Superset pipeline
    for project_name, stage_prefixes in analytics_stage_prefixes.items():
        try:
            # Extract the ingest_ts suffix from the first stage_prefix URI
            first_prefix = next(iter(stage_prefixes.values()), "")
            sync_suffix = first_prefix.rstrip("/").split("ingest_ts=")[-1].split("/")[0] if "ingest_ts=" in first_prefix else ""
            eb_payload = {
                "project": project_name,
                "sync_date": dt.date.today().isoformat(),
                "artifacts": list(stage_prefixes.keys()),
                "stage_prefixes": stage_prefixes,
                "sync_run_id": f"{sync_suffix}-{project_name}",
                "sync_target_suffix": sync_suffix,
                "generated_at": generated_at,
            }
            publish_eventbridge_event(
                message=eb_payload,
                bus_name=EVENT_BUS,
                dry_run=DRY_RUN,
            )
        except Exception as exc:
            logger.error("feed_publisher: EventBridge publish failed for project=%s: %s", project_name, exc)
            # Non-fatal: continue with remaining projects

    if model_ctx is not None:
        _save_snapshots(model_ctx, degraded_projects)

    return PublishResult(
        generated_at=generated_at,
        degraded_projects=degraded_projects,
        global_degraded=global_degraded,
    )


# ---------------------------------------------------------------------------
# Main Lambda handler
# ---------------------------------------------------------------------------


def _is_sweep_event(event: Any) -> bool:
    return isinstance(event, dict) and "Records" not in event and event.get("action") == SWEEP_ACTION


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point.

    * EventBridge sweep event ({"action": "feed_sweep"}) -> SWEEP (coalesced mode only).
    * SQS event, FEED_PUBLISH_MODE=coalesced -> MARK (dirty flag only, no publish).
    * SQS event, FEED_PUBLISH_MODE=per_batch (default) -> regenerate and publish all feeds.
    """
    if _is_sweep_event(event):
        return _handle_sweep(context)
    if FEED_PUBLISH_MODE == FEED_PUBLISH_MODE_COALESCED:
        return _handle_mark(event)
    return _handle_per_batch(event)


def _handle_per_batch(event: Dict[str, Any]) -> Dict[str, Any]:
    """Receives SQS event → extracts affected project IDs → regenerates and publishes
    full mobile feeds for all projects (ensures consistency across feeds)."""
    logger.info(
        "feed_publisher: invoked records=%d dry_run=%s",
        len(event.get("Records", [])),
        DRY_RUN,
    )

    record_message_ids = [
        record.get("messageId")
        for record in event.get("Records", [])
        if record.get("messageId")
    ]

    if DRY_RUN:
        logger.info("feed_publisher: DRY_RUN mode — S3/CF/SNS/EB writes suppressed")

    # 1. Extract affected project IDs (informational — we always regenerate all projects)
    affected_projects, failed_message_ids = _extract_project_ids_and_failures_from_sqs_event(event)
    if not affected_projects:
        logger.warning("feed_publisher: no affected project IDs found in event; proceeding with full regeneration")

    # 1b. DVP-TSK-A83: stamp projects.last_activity_at before the (long) regeneration so a
    # slow or failing publish cannot delay it. Best effort; _record_project_activity never raises.
    try:
        _record_project_activity(_extract_project_activity_from_sqs_event(event))
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed_publisher: last_activity_at stamping skipped: %s", exc)

    try:
        result = _publish_all(affected_projects)
        logger.info(
            "feed_publisher: complete. generated_at=%s affected=%s",
            result.generated_at,
            sorted(affected_projects),
        )
        return _batch_failure_response(failed_message_ids)
    except Exception as exc:
        logger.error("feed_publisher: batch failed, marking all records for retry: %s", exc, exc_info=True)
        return _batch_failure_response(record_message_ids)
