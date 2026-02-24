#!/usr/bin/env python3
"""devops-feed-publisher Lambda — Event-driven mobile feed publisher.

Triggered by SQS FIFO queue (devops-feed-publish-queue.fifo) which receives
events from an EventBridge Pipe connected to DynamoDB Streams on the
devops-project-tracker table.

Flow:
  DynamoDB Streams → EventBridge Pipe → SQS FIFO (5-min visibility = debounce)
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
from typing import Any, Dict, List, Optional, Set

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


def _extract_project_ids_from_sqs_event(event: Dict[str, Any]) -> Set[str]:
    """Parse SQS event records to find which project IDs were affected.

    Each SQS message body is a JSON-encoded DynamoDB Stream record (as forwarded
    by the EventBridge Pipe). We extract project_id from the DynamoDB image.
    """
    affected: Set[str] = set()
    for record in event.get("Records", []):
        try:
            body = json.loads(record.get("body", "{}"))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Could not parse SQS record body as JSON")
            continue

        # EventBridge Pipe forwards the DynamoDB stream record directly
        # Alternatively the body may already be parsed as the stream event
        ddb_record = body.get("dynamodb", body)
        for image_key in ("NewImage", "OldImage"):
            image = ddb_record.get(image_key, {})
            if not image:
                continue
            project_id_attr = image.get("project_id", {})
            # DynamoDB typed format: {"S": "devops"}
            project_id = project_id_attr.get("S") or project_id_attr.get("s")
            if project_id:
                affected.add(project_id)
                break

    logger.info("Affected project IDs from SQS event: %s", sorted(affected))
    return affected


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

    if DRY_RUN:
        logger.info("feed_publisher: DRY_RUN mode — S3/CF/SNS/EB writes suppressed")

    # 1. Extract affected project IDs (informational — we always regenerate all projects)
    affected_projects = _extract_project_ids_from_sqs_event(event)
    if not affected_projects:
        logger.warning("feed_publisher: no affected project IDs found in event; proceeding with full regeneration")

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
            all_project_data[entry.name] = {"tasks": [], "issues": [], "features": []}

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
    try:
        generate_mobile_feeds(all_entries, all_project_data, generated_at, feed_dir)
    except Exception as exc:
        logger.error("feed_publisher: generate_mobile_feeds failed: %s", exc)
        raise

    # 3a. Generate documents feed (separate from tracker feeds)
    try:
        generate_documents_feed(all_entries, all_documents_data, generated_at, feed_dir)
    except Exception as exc:
        logger.error("feed_publisher: generate_documents_feed failed: %s", exc)
        # Non-fatal: tracker feeds are already generated

    # 3b. Freshness SLA check — warns if feeds lag behind source data
    check_freshness_sla(generated_at, all_project_data)

    # 4. Fetch reference docs from S3 (via DynamoDB metadata) and stage in /tmp/reference/
    try:
        s3_client = boto3.client("s3", region_name="us-east-1")
        generate_reference_docs_from_s3(all_entries, feed_dir, ddb, table=TRACKER_TABLE, s3_client=s3_client)
    except Exception as exc:
        logger.error("feed_publisher: generate_reference_docs_from_s3 failed: %s", exc)
        # Non-fatal: continue without reference docs

    # 5. Publish feed files to S3
    try:
        uploaded_keys = publish_mobile_feeds_to_s3(
            feed_dir=feed_dir,
            bucket=FEED_BUCKET,
            s3_prefix=FEED_PREFIX,
            dry_run=DRY_RUN,
        )
        logger.info("feed_publisher: published %d files to S3", len(uploaded_keys))
    except Exception as exc:
        logger.error("feed_publisher: publish_mobile_feeds_to_s3 failed: %s", exc)
        raise

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

    # 6. CloudFront invalidation
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
    return {
        "statusCode": 200,
        "generated_at": generated_at,
        "affected_projects": sorted(affected_projects),
        "dry_run": DRY_RUN,
    }
