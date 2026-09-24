#!/usr/bin/env python3
"""Copy existing rel# rows from devops-project-tracker to enceladus-relationships.

ENC-TSK-L13 (B65 Ph4). Idempotent: each PutItem uses
attribute_not_exists(record_id) so a second run against an already-copied
corpus reports skipped rows instead of overwriting.

Usage:

    python3 tools/relationship_table_backfill.py --env gamma [--dry-run] [--region us-west-2]

Emits JSON summary to stdout: {env, dry_run, scanned, copied, skipped, errors}.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Iterable, List

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("relationship_table_backfill")

_ENV_TO_TABLE_SUFFIX = {"prod": "", "gamma": "-gamma"}


def _tracker_table(env: str) -> str:
    return f"devops-project-tracker{_ENV_TO_TABLE_SUFFIX[env]}"


def _relationships_table(env: str) -> str:
    return f"enceladus-relationships{_ENV_TO_TABLE_SUFFIX[env]}"


def _scan_rel_rows(ddb, table_name: str) -> Iterable[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {
        "TableName": table_name,
        "FilterExpression": "begins_with(record_id, :rel_prefix)",
        "ExpressionAttributeValues": {":rel_prefix": {"S": "rel#"}},
    }
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            yield item
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _copy_item(
    ddb,
    dest_table: str,
    item: Dict[str, Any],
    *,
    dry_run: bool,
) -> str:
    sk = item.get("record_id", {}).get("S", "")
    if not sk.startswith("rel#"):
        return "skipped"
    if dry_run:
        return "copied"
    try:
        ddb.put_item(
            TableName=dest_table,
            Item=item,
            ConditionExpression="attribute_not_exists(record_id)",
        )
        return "copied"
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ConditionalCheckFailedException":
            return "skipped"
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env", choices=["prod", "gamma"], required=True)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--dry-run", action="store_true", help="Report only; make no writes.")
    parser.add_argument("--report-out", help="Also write the JSON summary to this file path.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    ddb = boto3.client("dynamodb", region_name=args.region)
    source_table = _tracker_table(args.env)
    dest_table = _relationships_table(args.env)

    scanned = 0
    copied = 0
    skipped = 0
    errors: List[str] = []

    logger.info(
        "Copying rel# rows %s -> %s (dry_run=%s)",
        source_table,
        dest_table,
        args.dry_run,
    )

    for item in _scan_rel_rows(ddb, source_table):
        scanned += 1
        try:
            outcome = _copy_item(ddb, dest_table, item, dry_run=args.dry_run)
        except ClientError as exc:
            sk = item.get("record_id", {}).get("S", "")
            errors.append(f"{sk}: {exc}")
            continue
        if outcome == "copied":
            copied += 1
        else:
            skipped += 1

    summary = {
        "env": args.env,
        "dry_run": args.dry_run,
        "source_table": source_table,
        "dest_table": dest_table,
        "scanned": scanned,
        "copied": copied,
        "skipped": skipped,
        "errors": errors,
    }

    output = json.dumps(summary, indent=2)
    print(output)
    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
        logger.info("Report written to %s", args.report_out)

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
