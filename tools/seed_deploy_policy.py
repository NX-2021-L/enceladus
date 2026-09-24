#!/usr/bin/env python3
"""ENC-TSK-H84 / ENC-FTR-111: idempotent backfill of project_service.deploy_policy.

Seeds the per-project ``deploy_policy`` attribute (enum ci_triggered / manual) on existing
records in the projects DynamoDB table. Every existing project is seeded to ``ci_triggered``
(the default and the AC-1 value for enceladus); the write is conditional on the attribute being
absent, so it is fully idempotent and NEVER overwrites a value a project already carries.

Why a standalone script (not an MCP/agent path): project_service exposes create + read only —
there is no governed PATCH route for an existing project record, and the ``enceladus-agent-cli``
IAM principal is denied all DynamoDB writes (agents.md §14). This backfill therefore runs under a
privileged session (io-dev-admin / product-lead terminal) AFTER the H84 PR merges and deploys.
Until it runs, read-time defaulting in project_service._enrich_project and
lifecycle_service._get_project_deploy_policy already make the effective value ci_triggered, so the
backfill only materializes the attribute on the stored record — behavior is correct either way.

Usage:
    python3 tools/seed_deploy_policy.py [--dry-run] [--table projects] [--region us-west-2]
                                        [--policy ci_triggered]

    # gamma stack:
    python3 tools/seed_deploy_policy.py --table projects-gamma

The script is safe to re-run: it scans the table, skips any record that already has a
``deploy_policy`` attribute, and sets the seed value on the rest via a conditional UpdateItem.
"""

from __future__ import annotations

import argparse
import sys

VALID_POLICIES = ("ci_triggered", "manual")


def _scan_project_ids(ddb, table: str) -> list[str]:
    ids: list[str] = []
    kwargs = {"TableName": table, "ProjectionExpression": "project_id, deploy_policy"}
    have_policy = 0
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            pid = item.get("project_id", {}).get("S")
            if not pid:
                continue
            if item.get("deploy_policy", {}).get("S"):
                have_policy += 1
                continue
            ids.append(pid)
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    print(f"[INFO] {len(ids)} project(s) need seeding; {have_policy} already carry deploy_policy.")
    return ids


def _seed_one(ddb, table: str, project_id: str, policy: str) -> str:
    """Conditional UpdateItem — only sets deploy_policy when absent (idempotent, non-destructive)."""
    try:
        ddb.update_item(
            TableName=table,
            Key={"project_id": {"S": project_id}},
            UpdateExpression="SET deploy_policy = :p",
            ConditionExpression="attribute_not_exists(deploy_policy)",
            ExpressionAttributeValues={":p": {"S": policy}},
        )
        return "seeded"
    except ddb.exceptions.ConditionalCheckFailedException:
        return "skipped (already set)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default="projects", help="projects table name (default: projects)")
    parser.add_argument("--region", default="us-west-2", help="AWS region (default: us-west-2)")
    parser.add_argument("--policy", default="ci_triggered", choices=VALID_POLICIES,
                        help="seed value for records missing deploy_policy (default: ci_triggered)")
    parser.add_argument("--dry-run", action="store_true", help="list what would change without writing")
    args = parser.parse_args()

    import boto3  # imported here so --help works without AWS deps installed

    ddb = boto3.client("dynamodb", region_name=args.region)
    print(f"[INFO] Backfilling deploy_policy='{args.policy}' on table '{args.table}' "
          f"(region {args.region}){' [DRY-RUN]' if args.dry_run else ''}.")

    to_seed = _scan_project_ids(ddb, args.table)
    seeded = 0
    for pid in to_seed:
        if args.dry_run:
            print(f"  would seed {pid} -> {args.policy}")
            continue
        result = _seed_one(ddb, args.table, pid, args.policy)
        print(f"  {pid}: {result}")
        if result == "seeded":
            seeded += 1

    if args.dry_run:
        print(f"[OK] DRY-RUN complete — {len(to_seed)} project(s) would be seeded.")
    else:
        print(f"[OK] Backfill complete — {seeded} project(s) seeded to '{args.policy}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
