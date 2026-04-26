#!/usr/bin/env python3
"""Backfill `lifecycle_status=active` on pre-ENC-FTR-076 component-registry records.

ENC-TSK-E12 / ENC-FTR-076 Phase 5. Scans the `component-registry` DynamoDB
table; for any record lacking the `lifecycle_status` attribute, performs a
conditional `UpdateItem` setting it to `active`. Idempotent by conditional
expression — re-running after the first pass produces zero writes.

Usage:

    python3 tools/backfill_component_lifecycle.py \
        --env prod --project enceladus [--dry-run] [--region us-west-2]

Pre-E08, every component record was implicitly active. ENC-TSK-E08 introduced
the `lifecycle_status` field as part of the agent-proposable component
registry (proposed/approved/active/rejected/deprecated/archived). Existing
records still need the explicit `active` value so the E10 checkout-service
gate (also from FTR-076) treats them correctly. This script is the one-time
catch-up; new records written after E08 already carry `lifecycle_status`.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any, Dict, Iterable, List, Tuple

import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger("backfill_component_lifecycle")

_ENV_TO_TABLE_SUFFIX = {
    "prod": "",
    "gamma": "-gamma",
}


def _table_name(env: str) -> str:
    """Resolve the component-registry table name for the env."""
    suffix = _ENV_TO_TABLE_SUFFIX[env]
    return f"component-registry{suffix}"


def _scan_components(
    ddb, table_name: str, project_id: str
) -> Iterable[Dict[str, Any]]:
    """Yield every component record in `table_name` filtered to `project_id`."""
    kwargs: Dict[str, Any] = {
        "TableName": table_name,
        "FilterExpression": "project_id = :pid",
        "ExpressionAttributeValues": {":pid": {"S": project_id}},
    }
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            yield item
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last


def _classify(items: Iterable[Dict[str, Any]]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Split components into (needs_backfill, already_set) by lifecycle_status."""
    needs: List[str] = []
    already: List[Tuple[str, str]] = []
    for item in items:
        cid = item.get("component_id", {}).get("S", "")
        if not cid:
            continue
        ls = item.get("lifecycle_status", {}).get("S")
        if ls is None:
            needs.append(cid)
        else:
            already.append((cid, ls))
    return needs, already


def _backfill_one(ddb, table_name: str, component_id: str) -> bool:
    """Conditionally set lifecycle_status=active on `component_id`.

    Returns True when the write happened, False when the conditional check
    failed (record already had lifecycle_status set since classify time).
    """
    try:
        ddb.update_item(
            TableName=table_name,
            Key={"component_id": {"S": component_id}},
            UpdateExpression="SET lifecycle_status = :v",
            ConditionExpression="attribute_not_exists(lifecycle_status)",
            ExpressionAttributeValues={":v": {"S": "active"}},
        )
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return False
        raise


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Backfill lifecycle_status=active on legacy component-registry records (ENC-TSK-E12)."
    )
    p.add_argument("--env", required=True, choices=("prod", "gamma"),
                   help="Target environment.")
    p.add_argument("--project", required=True, help="project_id filter, e.g. 'enceladus'.")
    p.add_argument("--region", default="us-west-2", help="AWS region (default us-west-2).")
    p.add_argument("--dry-run", action="store_true",
                   help="Scan + classify only; no writes.")
    return p


def main(argv: List[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = _build_parser().parse_args(argv)

    table = _table_name(args.env)
    logger.info("env=%s project=%s table=%s region=%s dry_run=%s",
                args.env, args.project, table, args.region, args.dry_run)

    ddb = boto3.client("dynamodb", region_name=args.region)

    # Pre-state: classify
    items = list(_scan_components(ddb, table, args.project))
    needs, already = _classify(items)
    logger.info("[BEFORE] total=%d needs_backfill=%d already_set=%d",
                len(items), len(needs), len(already))
    if already:
        seen_states: Dict[str, int] = {}
        for _, ls in already:
            seen_states[ls] = seen_states.get(ls, 0) + 1
        logger.info("[BEFORE] lifecycle_status histogram (already-set): %s", seen_states)

    if args.dry_run:
        for cid in needs[:20]:
            logger.info("[DRY-RUN] would set lifecycle_status=active on %s", cid)
        if len(needs) > 20:
            logger.info("[DRY-RUN] ... and %d more", len(needs) - 20)
        logger.info("[DRY-RUN] no writes performed")
        return 0

    # Apply
    written = 0
    skipped = 0
    for cid in needs:
        if _backfill_one(ddb, table, cid):
            written += 1
            logger.info("[WRITE] %s lifecycle_status=active", cid)
        else:
            skipped += 1
            logger.info("[SKIP] %s already had lifecycle_status (race)", cid)

    # Post-state
    after_items = list(_scan_components(ddb, table, args.project))
    after_needs, after_already = _classify(after_items)
    logger.info("[AFTER] total=%d needs_backfill=%d already_set=%d",
                len(after_items), len(after_needs), len(after_already))
    logger.info("[SUMMARY] written=%d skipped=%d expected_remaining=0 actual_remaining=%d",
                written, skipped, len(after_needs))

    return 0 if len(after_needs) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
