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
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sys
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
# Main Lambda handler
# ---------------------------------------------------------------------------


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point.

    Receives SQS event → extracts affected project IDs → regenerates and publishes
    full mobile feeds for all projects (ensures consistency across feeds).
    """
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
        # 2. Fetch all project data from DynamoDB
        generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        all_entries = _all_project_entries()
        ddb = _ddb_client()
        all_project_data: Dict[str, Dict[str, Any]] = {}

        for entry in all_entries:
            try:
                all_project_data[entry.name] = fetch_from_dynamodb(
                    entry,
                    table=TRACKER_TABLE,
                    region=TRACKER_REGION,
                )
            except Exception as exc:
                logger.error("feed_publisher: DynamoDB fetch failed for project=%s: %s", entry.name, exc)
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
                all_documents_data[entry.name] = []

        # 3. Generate mobile feeds locally in /tmp
        feed_dir = FEED_TEMP_DIR
        generate_mobile_feeds(all_entries, all_project_data, generated_at, feed_dir)

        # 3a. Generate documents feed (separate from tracker feeds)
        try:
            generate_documents_feed(all_entries, all_documents_data, generated_at, feed_dir)
        except Exception as exc:
            logger.error("feed_publisher: generate_documents_feed failed: %s", exc)
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

        # 5. Publish feed files to S3
        #
        # ENC-TSK-K98: skip on gamma (FEED_S3_PUBLISH_ENABLED=false) — the
        # /mobile/v1 objects are served PUBLICLY by the shared UI-origin cockpit
        # CDN, and the ui-v2 cockpit now reads its snapshot from the
        # authenticated feed_query API. Prod keeps publishing.
        if FEED_S3_PUBLISH_ENABLED:
            uploaded_keys = publish_mobile_feeds_to_s3(
                feed_dir=feed_dir,
                bucket=FEED_BUCKET,
                s3_prefix=FEED_PREFIX,
                dry_run=DRY_RUN,
            )
            logger.info("feed_publisher: published %d files to S3", len(uploaded_keys))
        else:
            uploaded_keys = []
            logger.info(
                "feed_publisher: PUBLIC /mobile S3 publish disabled "
                "(FEED_S3_PUBLISH_ENABLED=false); skipping write + CF invalidation"
            )

        # 5b. Write analytics sync-stage JSON for Trino/Superset pipeline
        analytics_stage_prefixes = {}  # project_name -> {artifact -> s3_prefix_uri}
        try:
            for entry in all_entries:
                project_data = all_project_data.get(entry.name, {})
                stage_prefixes = write_analytics_sync_stage(
                    project_name=entry.name,
                    project_data=project_data,
                    bucket=ANALYTICS_BUCKET,
                    region=ANALYTICS_REGION,
                    dry_run=DRY_RUN,
                )
                if stage_prefixes:
                    analytics_stage_prefixes[entry.name] = stage_prefixes
            logger.info(
                "feed_publisher: wrote analytics sync-stage for %d projects",
                len(analytics_stage_prefixes),
            )
        except Exception as exc:
            logger.error("feed_publisher: analytics sync-stage write failed: %s", exc)
            # Non-fatal: mobile feeds are already published

        # 6. CloudFront invalidation (only when we actually published — K98)
        if FEED_S3_PUBLISH_ENABLED:
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
            for entry in all_entries:
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

        logger.info(
            "feed_publisher: complete. generated_at=%s affected=%s",
            generated_at,
            sorted(affected_projects),
        )
        return _batch_failure_response(failed_message_ids)
    except Exception as exc:
        logger.error("feed_publisher: batch failed, marking all records for retry: %s", exc, exc_info=True)
        return _batch_failure_response(record_message_ids)
