#!/usr/bin/env python3
"""
ENC-TSK-E57 AC8: Retroactive bypass logging for PLN-029 deploys.

Marks DPL records for PRs #351-356 (and #80) with bypass_reason to record
that these production deploys were approved via GitHub environment protection
rules rather than the Enceladus Deployment Manager PWA.

Usage (product-lead IAM only — agent-cli IAM denies DynamoDB writes):
    python3 tools/backfill_dpl_bypass_markers.py [--dry-run]

Idempotent: skips records that already have a bypass_reason field.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3

DEPLOY_TABLE = "devops-deployment-manager"
REGION = "us-west-2"
PROJECT_ID = "enceladus"

# PRs that traversed the GitHub environment approval bypass path
BYPASS_PR_NUMBERS = [80, 351, 352, 353, 354, 355, 356]
BYPASS_REASON = "github_environment_approval_bypass_pre_E57"


def main():
    parser = argparse.ArgumentParser(description="Backfill DPL bypass_reason markers")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without writing")
    args = parser.parse_args()

    ddb = boto3.client("dynamodb", region_name=REGION)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    updated = 0
    skipped = 0
    not_found = 0

    for pr_number in BYPASS_PR_NUMBERS:
        record_id = f"decision#ENC-DPL-{pr_number}"
        print(f"[INFO] Checking {record_id}...")

        resp = ddb.get_item(
            TableName=DEPLOY_TABLE,
            Key={
                "project_id": {"S": PROJECT_ID},
                "record_id": {"S": record_id},
            },
        )
        item = resp.get("Item")
        if not item:
            print(f"  [SKIP] No DPL record found for PR #{pr_number}")
            not_found += 1
            continue

        existing_reason = item.get("bypass_reason", {}).get("S", "")
        if existing_reason:
            print(f"  [SKIP] Already has bypass_reason: {existing_reason}")
            skipped += 1
            continue

        if args.dry_run:
            print(f"  [DRY-RUN] Would set bypass_reason={BYPASS_REASON}")
            updated += 1
            continue

        ddb.update_item(
            TableName=DEPLOY_TABLE,
            Key={
                "project_id": {"S": PROJECT_ID},
                "record_id": {"S": record_id},
            },
            UpdateExpression="SET bypass_reason = :br, bypass_logged_at = :bla, updated_at = :ua",
            ExpressionAttributeValues={
                ":br": {"S": BYPASS_REASON},
                ":bla": {"S": now},
                ":ua": {"S": now},
            },
            ConditionExpression="attribute_exists(project_id)",
        )
        print(f"  [SUCCESS] bypass_reason set on {record_id}")
        updated += 1

    print(f"\n[END] Updated: {updated}, Skipped: {skipped}, Not found: {not_found}")
    return 0 if not_found == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
