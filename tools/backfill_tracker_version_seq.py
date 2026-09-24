#!/usr/bin/env python3
"""One-shot backfill of version_seq on tracker records (ENC-TSK-L27).

Usage:
  AWS_PROFILE=enceladus-agent python3 tools/backfill_tracker_version_seq.py \\
    --table devops-project-tracker-gamma [--dry-run]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend" / "lambda" / "shared_layer" / "python"))

from enceladus_shared.version_seq import FEED_SCOPE, allocate_version_seq, version_seq_attr  # noqa: E402

FEED_RECORD_TYPES = {"task", "issue", "feature", "lesson", "plan"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--table", required=True)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    ddb = boto3.client("dynamodb", region_name=args.region)
    updated = 0
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=args.table):
        for item in page.get("Items", []):
            record_type = (item.get("record_type") or {}).get("S", "")
            if record_type not in FEED_RECORD_TYPES:
                continue
            if item.get("version_seq"):
                continue
            seq = allocate_version_seq(ddb, args.table)
            key = {
                "project_id": item["project_id"],
                "record_id": item["record_id"],
            }
            if args.dry_run:
                print(f"would stamp {key} -> {seq}")
            else:
                ddb.update_item(
                    TableName=args.table,
                    Key=key,
                    UpdateExpression="SET version_seq = :vseq, feed_scope = :scope",
                    ExpressionAttributeValues={
                        ":vseq": version_seq_attr(seq)["version_seq"],
                        ":scope": {"S": FEED_SCOPE},
                    },
                )
            updated += 1
    print(f"backfill complete: {updated} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
