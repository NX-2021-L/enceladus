#!/usr/bin/env python3
"""DVP-TSK-A83: one-pass backfill of projects.last_activity_at.

project_service.days_since_active reads the project row's ``last_activity_at`` (a monotonic max of
the tracker records' ``updated_at``, maintained by the feed_publisher stream consumer). Rows that
have never been touched since that consumer shipped -- dormant projects -- lack the attribute and
still pay a tracker Query on a cold project_service container. This script materialises the value
for every project from ONE pass over the tracker project-type-index.

READ-ONLY BY DEFAULT: without --apply it only reads (a projects Scan plus one paginated tracker
Query chain per project) and prints what it would write. With --apply it issues, per project, the
same conditional UpdateItem as the stream consumer:

    SET last_activity_at = :ts
    IF  attribute_exists(project_id)
        AND (attribute_not_exists(last_activity_at) OR last_activity_at < :ts)

so it is idempotent, never moves a value backwards, never overwrites a newer value the live
consumer wrote meanwhile, and never creates a stub row.

Usage:
    python3 tools/backfill_project_last_activity.py                       # dry run, prod
    python3 tools/backfill_project_last_activity.py --apply               # write
    python3 tools/backfill_project_last_activity.py \
        --projects-table projects-gamma --tracker-table devops-project-tracker-gamma
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from typing import Any, Dict, List, Optional

TRACKER_GSI = "project-type-index"
CONDITION = (
    "attribute_exists(project_id) AND "
    "(attribute_not_exists(last_activity_at) OR last_activity_at < :ts)"
)


def normalize_ts(value: Any) -> Optional[str]:
    """Canonical UTC 'YYYY-MM-DDTHH:MM:SSZ' (same form feed_publisher writes), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_projects(ddb, table: str) -> List[Dict[str, Optional[str]]]:
    """[{project_id, last_activity_at-or-None}] for every project row."""
    rows: List[Dict[str, Optional[str]]] = []
    kwargs: Dict[str, Any] = {"TableName": table, "ProjectionExpression": "project_id, last_activity_at"}
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            pid = item.get("project_id", {}).get("S")
            if pid:
                rows.append({"project_id": pid, "last_activity_at": item.get("last_activity_at", {}).get("S")})
        if not resp.get("LastEvaluatedKey"):
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def newest_tracker_ts(ddb, table: str, project_id: str) -> Optional[str]:
    """Newest updated_at over the project's tracker records (same set project_service queries)."""
    kwargs: Dict[str, Any] = {
        "TableName": table,
        "IndexName": TRACKER_GSI,
        "KeyConditionExpression": "project_id = :pid",
        "ExpressionAttributeValues": {":pid": {"S": project_id}},
        "ProjectionExpression": "updated_at",
    }
    newest: Optional[str] = None
    while True:
        resp = ddb.query(**kwargs)
        for item in resp.get("Items", []):
            ts = normalize_ts(item.get("updated_at", {}).get("S"))
            if ts and (newest is None or ts > newest):
                newest = ts
        if not resp.get("LastEvaluatedKey"):
            return newest
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def apply_one(ddb, table: str, project_id: str, ts: str) -> str:
    try:
        ddb.update_item(
            TableName=table,
            Key={"project_id": {"S": project_id}},
            UpdateExpression="SET last_activity_at = :ts",
            ConditionExpression=CONDITION,
            ExpressionAttributeValues={":ts": {"S": ts}},
        )
        return "written"
    except ddb.exceptions.ConditionalCheckFailedException:
        return "skipped (stored value already >= candidate)"


def run(ddb, projects_table: str, tracker_table: str, apply: bool, out=print) -> Dict[str, int]:
    counts = {"projects": 0, "no_tracker_records": 0, "would_write": 0, "written": 0, "skipped": 0}
    for row in scan_projects(ddb, projects_table):
        counts["projects"] += 1
        pid = row["project_id"]
        ts = newest_tracker_ts(ddb, tracker_table, pid)
        if ts is None:
            counts["no_tracker_records"] += 1
            out(f"  {pid}: no tracker records; nothing to write")
            continue
        stored = normalize_ts(row["last_activity_at"])
        if stored is not None and stored >= ts:
            counts["skipped"] += 1
            out(f"  {pid}: stored {stored} already >= tracker {ts}")
            continue
        if not apply:
            counts["would_write"] += 1
            out(f"  {pid}: would set last_activity_at {stored or '(absent)'} -> {ts}")
            continue
        result = apply_one(ddb, projects_table, pid, ts)
        counts["written" if result == "written" else "skipped"] += 1
        out(f"  {pid}: {result} ({ts})")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--projects-table", default="projects")
    parser.add_argument("--tracker-table", default="devops-project-tracker")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--profile", default=None, help="AWS profile (default: ambient credentials)")
    parser.add_argument("--apply", action="store_true", help="write last_activity_at (default: read-only dry run)")
    args = parser.parse_args()

    import boto3  # imported here so --help works without AWS deps installed

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ddb = session.client("dynamodb")
    mode = "APPLY" if args.apply else "DRY-RUN (read-only)"
    print(f"[INFO] last_activity_at backfill: projects={args.projects_table} "
          f"tracker={args.tracker_table} region={args.region} mode={mode}")
    counts = run(ddb, args.projects_table, args.tracker_table, args.apply)
    print(f"[OK] {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
