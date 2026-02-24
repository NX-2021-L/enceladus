"""Enceladus Governance Audit Lambda — DynamoDB Streams write-source anomaly detector.

Monitors DynamoDB Streams events from devops-project-tracker and alerts when
writes lack proper write_source attribution (ENC-ISS-009 Phase 1B).

Architecture:
  DynamoDB Streams (devops-project-tracker) -> EventBridge Pipe -> This Lambda
  This Lambda -> SNS (governance anomaly alerts)

Known write channels:
  - "mcp_server"   : Enceladus MCP server (governed, audited)
  - "tracker_cli"  : tracker.py CLI tool (human-supervised)
  - "mutation_api"  : Enceladus PWA mutation API (Cognito-authenticated)
  - "feed_publisher": devops-feed-publisher Lambda (automated pipeline)

Any write without write_source or with an unrecognized channel is flagged
as a potential governance bypass.

Related: ENC-ISS-009, ENC-TSK-454
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SNS_TOPIC_ARN = os.environ.get(
    "GOVERNANCE_ALERT_SNS_ARN",
    "arn:aws:sns:us-west-2:356364570033:devops-project-json-sync",
)
KNOWN_CHANNELS = frozenset({
    "mcp_server",
    "tracker_cli",
    "mutation_api",
    "feed_publisher",
})
# Record types to skip (metadata rows, not user-facing records)
SKIP_RECORD_TYPES = frozenset({"reference"})

_sns_client = None


def _get_sns():
    global _sns_client
    if _sns_client is None:
        import boto3
        _sns_client = boto3.client("sns", region_name="us-west-2")
    return _sns_client


# ---------------------------------------------------------------------------
# DynamoDB Stream event helpers
# ---------------------------------------------------------------------------

def _deser_attr(attr: Dict[str, Any]) -> Any:
    """Minimal DynamoDB attribute deserializer."""
    if "S" in attr:
        return attr["S"]
    if "N" in attr:
        return attr["N"]
    if "BOOL" in attr:
        return attr["BOOL"]
    if "NULL" in attr:
        return None
    if "M" in attr:
        return {k: _deser_attr(v) for k, v in attr["M"].items()}
    if "L" in attr:
        return [_deser_attr(item) for item in attr["L"]]
    return str(attr)


def _extract_image(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the NewImage from a DynamoDB Streams record."""
    dynamo = record.get("dynamodb", {})
    new_image = dynamo.get("NewImage")
    if not new_image:
        return None
    return {k: _deser_attr(v) for k, v in new_image.items()}


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

def _check_write_source(image: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Check if the write_source attribute is valid.

    Returns an anomaly dict if the write is suspicious, None if clean.
    """
    record_type = image.get("record_type", "")
    if record_type in SKIP_RECORD_TYPES:
        return None

    write_source = image.get("write_source")

    if write_source is None:
        return {
            "type": "MISSING_WRITE_SOURCE",
            "message": "DynamoDB write has no write_source attribute — potential governance bypass",
        }

    if isinstance(write_source, dict):
        channel = write_source.get("channel", "")
    elif isinstance(write_source, str):
        channel = write_source
    else:
        channel = str(write_source)

    if not channel:
        return {
            "type": "EMPTY_WRITE_SOURCE",
            "message": "write_source present but channel is empty — potential governance bypass",
        }

    if channel not in KNOWN_CHANNELS:
        return {
            "type": "UNKNOWN_CHANNEL",
            "message": f"write_source channel '{channel}' is not a recognized write path",
        }

    return None


# ---------------------------------------------------------------------------
# Alert publishing
# ---------------------------------------------------------------------------

def _publish_alert(
    anomaly: Dict[str, str],
    image: Dict[str, Any],
    event_name: str,
) -> None:
    """Publish a governance anomaly alert to SNS."""
    record_id = image.get("item_id") or image.get("record_id", "unknown")
    project_id = image.get("project_id", "unknown")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    alert = {
        "alert_type": "GOVERNANCE_WRITE_ANOMALY",
        "anomaly_type": anomaly["type"],
        "message": anomaly["message"],
        "record_id": record_id,
        "project_id": project_id,
        "event_name": event_name,
        "write_source": image.get("write_source"),
        "updated_at": image.get("updated_at", ""),
        "last_update_note": str(image.get("last_update_note", ""))[:200],
        "detected_at": now,
    }

    subject = f"[SECURITY] Governance bypass detected: {anomaly['type']} on {record_id}"

    try:
        _get_sns().publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=json.dumps(alert, indent=2),
            MessageAttributes={
                "alert_type": {
                    "DataType": "String",
                    "StringValue": "GOVERNANCE_WRITE_ANOMALY",
                },
            },
        )
        logger.info("[SECURITY] Alert published: %s on %s", anomaly["type"], record_id)
    except Exception as exc:
        logger.error("[ERROR] Failed to publish SNS alert: %s", exc)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Process DynamoDB Streams events and detect write-source anomalies.

    Supports both direct DynamoDB Streams trigger and SQS-wrapped events.
    """
    records: List[Dict[str, Any]] = []

    # Handle SQS-wrapped events (EventBridge Pipe -> SQS -> Lambda)
    if "Records" in event and event["Records"]:
        first = event["Records"][0]
        if first.get("eventSource") == "aws:sqs":
            for sqs_record in event["Records"]:
                body = json.loads(sqs_record.get("body", "{}"))
                if isinstance(body, list):
                    records.extend(body)
                elif isinstance(body, dict) and "dynamodb" in body:
                    records.append(body)
        elif first.get("eventSource") == "aws:dynamodb":
            records = event["Records"]

    total = len(records)
    anomalies = 0
    clean = 0

    for record in records:
        event_name = record.get("eventName", "")
        # Only inspect INSERT and MODIFY events (not REMOVE)
        if event_name not in ("INSERT", "MODIFY"):
            continue

        image = _extract_image(record)
        if not image:
            continue

        anomaly = _check_write_source(image)
        if anomaly:
            anomalies += 1
            _publish_alert(anomaly, image, event_name)
            logger.warning(
                "[SECURITY] %s: %s on %s/%s",
                anomaly["type"],
                anomaly["message"],
                image.get("project_id", "?"),
                image.get("item_id", image.get("record_id", "?")),
            )
        else:
            clean += 1

    result = {
        "processed": total,
        "clean": clean,
        "anomalies": anomalies,
    }
    logger.info("[END] Governance audit: %s", json.dumps(result))
    return result
