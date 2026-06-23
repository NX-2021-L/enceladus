"""stale_checkout_monitor — ENC-TSK-H51 (ENC-ISS-142 gate #3).

Scheduled detector for the Escalation Protocol (DOC-476D273C6566, "Checkout Service
Integration" #3): surface abandoned ownership so blocked work becomes visible without a
human having to notice. Read-only scan of the projects/tracker table for:

  1. Long-held active checkouts — checkout_state == "checked_out" and checked_out_at older
     than STALE_CHECKOUT_THRESHOLD_MINUTES (default 240 = 4h). (Trigger condition #2.)
  2. Stale in-progress tasks — status == "in-progress" whose last update is older than the
     same threshold without an advance or release. (Trigger condition #1.)

For each hit it emits a structured stale-checkout signal
{record_id, checked_out_by, checked_out_at, age_minutes, reason} as a JSON CloudWatch log
line (the governed, observable MVP signal) and returns the aggregate.

Trigger: EventBridge rule (rate(30 minutes) by default). Also handles ad-hoc invokes
(empty event) for on-demand scans.

Deliberately side-effect-free: it does NOT mutate the tracker or file issues. Escalation
routing (the L2/L3 record/log against the governing issue) is the operator/agent step per
the protocol; keeping the monitor read-only keeps the signal idempotent and avoids spam.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
REGION = os.environ.get("AWS_REGION", "us-west-2")
DEFAULT_THRESHOLD_MINUTES = 240  # 4h — DOC-476D273C6566 trigger conditions #1 and #2


def threshold_minutes() -> int:
    """Configurable via STALE_CHECKOUT_THRESHOLD_MINUTES; falls back to 4h."""
    raw = os.environ.get("STALE_CHECKOUT_THRESHOLD_MINUTES", "")
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_THRESHOLD_MINUTES
    return val if val > 0 else DEFAULT_THRESHOLD_MINUTES


def parse_iso(value: Any) -> Optional[datetime]:
    """Parse a tracker ISO-8601 timestamp (tolerates a trailing Z and naive values)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _age_minutes(ts: datetime, now: datetime) -> int:
    return int((now - ts).total_seconds() // 60)


def detect_stale(
    items: List[Dict[str, Any]], now: datetime, threshold: int
) -> List[Dict[str, Any]]:
    """Pure detection core (no AWS, fully unit-testable). One signal per stale task."""
    signals: List[Dict[str, Any]] = []
    for item in items:
        if item.get("record_type") != "task":
            continue
        record_id = item.get("item_id") or item.get("record_id") or ""
        checked_out_by = item.get("checked_out_by") or ""

        # (1) long-held active checkout
        if item.get("checkout_state") == "checked_out":
            ts = parse_iso(item.get("checked_out_at"))
            if ts is not None and _age_minutes(ts, now) >= threshold:
                signals.append(
                    {
                        "record_id": record_id,
                        "checked_out_by": checked_out_by,
                        "checked_out_at": item.get("checked_out_at"),
                        "age_minutes": _age_minutes(ts, now),
                        "reason": "long_held_checkout",
                        "threshold_minutes": threshold,
                    }
                )
                continue

        # (2) in-progress past the working-session threshold without advance/release
        if item.get("status") == "in-progress":
            ts = parse_iso(item.get("updated_at"))
            if ts is not None and _age_minutes(ts, now) >= threshold:
                signals.append(
                    {
                        "record_id": record_id,
                        "checked_out_by": checked_out_by,
                        "checked_out_at": item.get("checked_out_at"),
                        "age_minutes": _age_minutes(ts, now),
                        "reason": "stale_in_progress",
                        "threshold_minutes": threshold,
                    }
                )
    return signals


def _scan_task_records() -> List[Dict[str, Any]]:
    table = boto3.resource("dynamodb", region_name=REGION).Table(PROJECTS_TABLE)
    flt = Attr("record_type").eq("task") & (
        Attr("checkout_state").eq("checked_out") | Attr("status").eq("in-progress")
    )
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"FilterExpression": flt}
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def lambda_handler(event: Any, context: Any) -> Dict[str, Any]:
    threshold = threshold_minutes()
    now = datetime.now(timezone.utc)
    items = _scan_task_records()
    signals = detect_stale(items, now, threshold)
    for sig in signals:
        LOGGER.warning(json.dumps({"event": "stale_checkout_signal", **sig}))
    summary = {
        "event": "stale_checkout_scan_complete",
        "scanned": len(items),
        "stale": len(signals),
        "threshold_minutes": threshold,
        "checked_at": now.isoformat().replace("+00:00", "Z"),
    }
    LOGGER.info(json.dumps(summary))
    return {"summary": summary, "signals": signals}


# EventBridge target convention parity.
handler = lambda_handler
