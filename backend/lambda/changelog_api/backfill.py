#!/usr/bin/env python3
"""backfill.py — One-time historical changelog backfill (ENC-FTR-033 Phase 8)

Reads workspace/backfill_manifest.json (produced by ENC-TSK-688 synthesis agent)
and writes deploy# records into the devops-deployment-manager DynamoDB table so the
changelog_api Lambda can serve historical data.

Usage:
    # Dry-run (default — shows what would be written, no DynamoDB writes):
    python3 backend/lambda/changelog_api/backfill.py

    # Live write:
    python3 backend/lambda/changelog_api/backfill.py --write

    # Custom manifest or table:
    python3 backend/lambda/changelog_api/backfill.py \\
        --manifest path/to/backfill_manifest.json \\
        --table devops-deployment-manager \\
        --region us-west-2 \\
        --write

    # Write only a specific project:
    python3 backend/lambda/changelog_api/backfill.py --write --project enceladus

Requires:
    - AWS credentials with dynamodb:PutItem + dynamodb:GetItem on devops-deployment-manager
    - boto3 (pip install boto3)

Related: ENC-FTR-033, ENC-TSK-687, ENC-TSK-688, ENC-TSK-689
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def _find_workspace() -> Path:
    """Walk up from this script until we find a sibling 'workspace/' directory."""
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        ws = p / "workspace"
        if ws.is_dir():
            return ws
    return Path("workspace")  # fallback: CWD-relative

DEFAULT_MANIFEST = _find_workspace() / "backfill_manifest.json"
DEFAULT_TABLE = "devops-deployment-manager"
DEFAULT_REGION = "us-west-2"


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _get_ddb(region: str):
    return boto3.client("dynamodb", region_name=region)


def _to_ddb(value: Any) -> Dict:
    """Convert a Python value to DynamoDB AttributeValue."""
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, (int, float)):
        return {"N": str(value)}
    if isinstance(value, list):
        if not value:
            return {"L": []}
        return {"L": [_to_ddb(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: _to_ddb(v) for k, v in value.items()}}
    return {"S": str(value)}


def _item_exists(ddb, table: str, project_id: str, record_id: str) -> bool:
    try:
        resp = ddb.get_item(
            TableName=table,
            Key={
                "project_id": {"S": project_id},
                "record_id": {"S": record_id},
            },
            ProjectionExpression="project_id",
        )
        return "Item" in resp
    except ClientError as e:
        print(f"  [WARN] get_item failed for {record_id}: {e}", file=sys.stderr)
        return False


def _put_item(ddb, table: str, item: Dict[str, Any]) -> bool:
    try:
        ddb.put_item(
            TableName=table,
            Item={k: _to_ddb(v) for k, v in item.items() if v is not None},
            ConditionExpression="attribute_not_exists(project_id)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False  # Already exists — skip silently (idempotent)
        raise


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def _make_record_id(entry: Dict) -> str:
    """Build the SK (record_id) for a manifest entry."""
    spec_id = entry.get("spec_id")
    if spec_id:
        return f"deploy#{spec_id}"
    # Synthetic SK for version.ts-sourced entries (no spec_id)
    version = entry["version"].replace(".", "-")
    source = entry.get("source", "backfill")
    return f"deploy#{source}-v{version}"


def _entry_to_ddb_item(entry: Dict) -> Dict[str, Any]:
    """Convert a manifest entry to the DynamoDB item shape the Lambda expects."""
    record_id = _make_record_id(entry)
    item: Dict[str, Any] = {
        "project_id": entry["project_id"],
        "record_id": record_id,
        "version": entry.get("version"),
        "previous_version": entry.get("previous_version"),
        "change_type": entry.get("change_type"),
        "deployed_at": entry.get("deployed_at"),
        "source": entry.get("source", "backfill"),
        "confidence": entry.get("confidence", "high"),
        "backfill": True,
    }
    # Optional fields — only set if non-null/non-empty
    if entry.get("summary"):
        item["release_summary"] = entry["summary"]
    if entry.get("changes"):
        item["changes"] = entry["changes"]
    if entry.get("spec_id"):
        item["spec_id"] = entry["spec_id"]
    if entry.get("related_record_ids"):
        item["related_record_ids"] = entry["related_record_ids"]
    if entry.get("component") and entry["component"] != "unknown":
        item["component"] = entry["component"]
    return item


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="ENC-FTR-033 historical changelog backfill")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                        help=f"Path to backfill_manifest.json (default: {DEFAULT_MANIFEST})")
    parser.add_argument("--table", default=DEFAULT_TABLE,
                        help=f"DynamoDB table name (default: {DEFAULT_TABLE})")
    parser.add_argument("--region", default=DEFAULT_REGION,
                        help=f"AWS region (default: {DEFAULT_REGION})")
    parser.add_argument("--project", default=None,
                        help="Only write entries for this project_id (default: all)")
    parser.add_argument("--write", action="store_true",
                        help="Actually write to DynamoDB (default: dry-run)")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[ERROR] Manifest not found: {manifest_path}", file=sys.stderr)
        print("  Run the Phase 8 synthesis agent first, or pass --manifest <path>", file=sys.stderr)
        return 1

    with open(manifest_path) as f:
        manifest = json.load(f)

    entries: List[Dict] = manifest.get("entries", [])
    if args.project:
        entries = [e for e in entries if e.get("project_id") == args.project]

    mode = "LIVE WRITE" if args.write else "DRY RUN"
    print(f"\n{'='*60}")
    print(f"  ENC-FTR-033 Changelog Backfill — {mode}")
    print(f"{'='*60}")
    print(f"  Manifest : {manifest_path}")
    print(f"  Table    : {args.table} ({args.region})")
    print(f"  Entries  : {len(entries)}")
    if args.project:
        print(f"  Filter   : project_id = {args.project!r}")
    print()

    if not args.write:
        print("  [DRY RUN] Pass --write to execute. Showing first 5 records:\n")

    ddb = _get_ddb(args.region) if args.write else None

    written = skipped = errors = 0

    for i, entry in enumerate(entries):
        item = _entry_to_ddb_item(entry)
        record_id = item["record_id"]
        project_id = item["project_id"]
        label = f"[{i+1:3d}/{len(entries)}] {project_id}/{record_id}"

        if not args.write:
            if i < 5:
                print(f"  {label}")
                print(f"           version={item.get('version')}  change_type={item.get('change_type')}  deployed_at={item.get('deployed_at')}")
            elif i == 5:
                print(f"  ... ({len(entries) - 5} more entries not shown)")
            continue

        # Check existence first to give informative skip messages
        if _item_exists(ddb, args.table, project_id, record_id):
            print(f"  SKIP  {label}  (already exists)")
            skipped += 1
            continue

        try:
            ok = _put_item(ddb, args.table, item)
            if ok:
                print(f"  WRITE {label}  v{item.get('version')} [{item.get('change_type')}]")
                written += 1
            else:
                print(f"  SKIP  {label}  (race condition — already exists)")
                skipped += 1
        except Exception as e:
            print(f"  ERROR {label}: {e}", file=sys.stderr)
            errors += 1

        # Polite pacing — avoid DynamoDB throttling
        time.sleep(0.05)

    print()
    if args.write:
        print(f"{'='*60}")
        print(f"  Written : {written}")
        print(f"  Skipped : {skipped}  (already existed)")
        print(f"  Errors  : {errors}")
        print(f"{'='*60}\n")
        if errors:
            print("[WARN] Some writes failed. Re-run to retry — the script is idempotent.")
            return 1
        print("[SUCCESS] Backfill complete.")
    else:
        print(f"{'='*60}")
        print(f"  Would write: {len(entries)} entries (skipping existence checks in dry-run)")
        print(f"  Re-run with --write to execute.")
        print(f"{'='*60}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
