#!/usr/bin/env python3
"""Backfill `item_id_provenance` on pre-ENC-TSK-L06 tracker records.

ENC-TSK-L06 / B63 Phase 2 AC-6 AC-5 (backfill verification). Scans the
`devops-project-tracker{-gamma}` DynamoDB table; for any record lacking the
`item_id_provenance` attribute, computes the HMAC-SHA256 signature over
`item_id||created_at||record_type` (the same formula the ID Service uses at
create time, backend/lambda/id_service/lambda_function.py:sign_provenance) and
performs a conditional UpdateItem to stamp it — mirroring the exact
scan+classify+conditional-write pattern of tools/backfill_component_lifecycle.py.

Records that CANNOT be signed (missing item_id, created_at, or record_type — or
matching the already-known, already-adjudicated quarantine list from ENC-FTR-069's
backfill audit, ENC-TSK-1291/ENC-TSK-1292) are left alone and reported separately
as documented quarantine exemptions, NOT backfilled with a fabricated signature.
Re-running after the first pass produces zero writes for the same dataset (the
conditional expression is idempotent).

Usage:

    python3 tools/backfill_item_id_provenance.py \\
        --env gamma --project enceladus --hmac-secret-arn <arn> [--dry-run] [--region us-west-2]

The --hmac-secret-arn is the SAME Secrets Manager secret ARN the ID Service reads
(HMAC_SECRET_ARN env var / infrastructure/cloudformation/02-compute.yaml
IdServiceHmacSecret) — this tool must run with an identity that has
secretsmanager:GetSecretValue on that secret plus dynamodb:Scan/UpdateItem on the
tracker table (NOT the enceladus-agent-cli identity, which is denied both; run this
as a privileged identity, e.g. io-dev-admin, exactly like other tools in this
directory that require live DynamoDB writes).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import sys
from typing import Any, Dict, Iterable, List, Tuple

import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger("backfill_item_id_provenance")

_ENV_TO_TABLE_SUFFIX = {
    "prod": "",
    "gamma": "-gamma",
}

# ENC-FTR-069 backfill audit (ENC-TSK-D29): the ONLY known malformed item_ids in
# production tracker, already adjudicated as an intentional quarantine (both records
# owned by privileged terminals, advanced through merged-main, kept as-is per
# documented rationale). Reused here verbatim rather than re-litigated — an item_id
# matching this list is reported as a documented quarantine exemption (AC-5), not
# treated as an unexpected backfill failure.
KNOWN_QUARANTINE_ITEM_IDS = {
    "ENC-TSK-1291",
    "ENC-TSK-1292",
}


def _table_name(env: str) -> str:
    suffix = _ENV_TO_TABLE_SUFFIX[env]
    return f"devops-project-tracker{suffix}"


def _sign_provenance(hmac_key: bytes, item_id: str, created_at: str, record_type: str) -> str:
    message = f"{item_id}||{created_at}||{record_type}".encode("utf-8")
    return hmac.new(hmac_key, message, hashlib.sha256).hexdigest()


def _get_hmac_key(secretsmanager, secret_arn: str) -> bytes:
    resp = secretsmanager.get_secret_value(SecretId=secret_arn)
    secret_string = resp.get("SecretString", "")
    try:
        parsed = json.loads(secret_string)
        if isinstance(parsed, dict) and "hmac_key" in parsed:
            secret_string = parsed["hmac_key"]
    except (ValueError, TypeError):
        pass
    return secret_string.encode("utf-8")


def _scan_tracker_records(ddb, table_name: str, project_id: str) -> Iterable[Dict[str, Any]]:
    """Yield every tracker record item in `table_name` filtered to `project_id`,
    excluding counter#* / rel# / non-record rows (those never carry item_id_provenance
    and are out of scope for this backfill)."""
    kwargs: Dict[str, Any] = {
        "TableName": table_name,
        "KeyConditionExpression": "project_id = :pid",
        "ExpressionAttributeValues": {":pid": {"S": project_id}},
    }
    while True:
        resp = ddb.query(**kwargs)
        for item in resp.get("Items", []):
            sk = item.get("record_id", {}).get("S", "")
            if "#" not in sk:
                continue
            prefix = sk.split("#", 1)[0]
            if prefix in ("counter", "rel"):
                continue
            yield item
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last


def _classify(
    items: Iterable[Dict[str, Any]],
) -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """Split records into (needs_backfill, already_set, quarantined).

    needs_backfill: list of {record_id (sk), item_id, created_at, record_type} dicts
                     with enough fields to compute + stamp a signature.
    already_set:    item_ids that already carry item_id_provenance.
    quarantined:    item_ids that are missing required fields OR match the known
                     ENC-FTR-069 quarantine list — reported, never fabricated.
    """
    needs: List[Dict[str, str]] = []
    already: List[str] = []
    quarantined: List[str] = []
    for item in items:
        sk = item.get("record_id", {}).get("S", "")
        item_id = item.get("item_id", {}).get("S", "")
        if item.get("item_id_provenance", {}).get("S"):
            already.append(item_id or sk)
            continue
        if item_id in KNOWN_QUARANTINE_ITEM_IDS:
            quarantined.append(item_id)
            continue
        created_at = item.get("created_at", {}).get("S", "")
        record_type = item.get("record_type", {}).get("S", "")
        if not (item_id and created_at and record_type):
            quarantined.append(item_id or sk)
            continue
        needs.append({
            "record_id": sk,
            "item_id": item_id,
            "created_at": created_at,
            "record_type": record_type,
        })
    return needs, already, quarantined


def _backfill_one(ddb, table_name: str, project_id: str, record: Dict[str, str], hmac_key: bytes) -> bool:
    """Conditionally stamp item_id_provenance on one record. Returns True when the write
    happened, False when the conditional check failed (record already had provenance set
    since classify time, e.g. a concurrent create)."""
    signature = _sign_provenance(hmac_key, record["item_id"], record["created_at"], record["record_type"])
    try:
        ddb.update_item(
            TableName=table_name,
            Key={
                "project_id": {"S": project_id},
                "record_id": {"S": record["record_id"]},
            },
            UpdateExpression="SET item_id_provenance = :v",
            ConditionExpression="attribute_not_exists(item_id_provenance)",
            ExpressionAttributeValues={":v": {"S": signature}},
        )
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return False
        raise


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Backfill item_id_provenance on legacy tracker records (ENC-TSK-L06 AC-5)."
    )
    p.add_argument("--env", required=True, choices=("prod", "gamma"), help="Target environment.")
    p.add_argument("--project", required=True, help="project_id filter, e.g. 'enceladus'.")
    p.add_argument("--hmac-secret-arn", required=True,
                   help="Secrets Manager ARN of the ID Service's HMAC signing secret.")
    p.add_argument("--region", default="us-west-2", help="AWS region (default us-west-2).")
    p.add_argument("--dry-run", action="store_true", help="Scan + classify only; no writes.")
    return p


def main(argv: List[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = _build_parser().parse_args(argv)

    table = _table_name(args.env)
    logger.info("env=%s project=%s table=%s region=%s dry_run=%s",
                args.env, args.project, table, args.region, args.dry_run)

    ddb = boto3.client("dynamodb", region_name=args.region)
    secretsmanager = boto3.client("secretsmanager", region_name=args.region)
    hmac_key = _get_hmac_key(secretsmanager, args.hmac_secret_arn)

    # Pre-state: classify
    items = list(_scan_tracker_records(ddb, table, args.project))
    needs, already, quarantined = _classify(items)
    logger.info("[BEFORE] total=%d needs_backfill=%d already_set=%d quarantined=%d",
                len(items), len(needs), len(already), len(quarantined))
    if quarantined:
        logger.info("[BEFORE] quarantined item_ids (documented exemption, ENC-FTR-069 + "
                    "missing-field cases, NOT backfilled): %s", sorted(quarantined))

    if args.dry_run:
        for rec in needs[:20]:
            logger.info("[DRY-RUN] would stamp item_id_provenance on %s", rec["item_id"])
        if len(needs) > 20:
            logger.info("[DRY-RUN] ... and %d more", len(needs) - 20)
        logger.info("[DRY-RUN] no writes performed")
        return 0

    # Apply
    written = 0
    skipped = 0
    for rec in needs:
        if _backfill_one(ddb, table, args.project, rec, hmac_key):
            written += 1
            logger.info("[WRITE] %s item_id_provenance stamped", rec["item_id"])
        else:
            skipped += 1
            logger.info("[SKIP] %s already had item_id_provenance (race)", rec["item_id"])

    # Post-state
    after_items = list(_scan_tracker_records(ddb, table, args.project))
    after_needs, after_already, after_quarantined = _classify(after_items)
    logger.info("[AFTER] total=%d needs_backfill=%d already_set=%d quarantined=%d",
                len(after_items), len(after_needs), len(after_already), len(after_quarantined))
    logger.info(
        "[SUMMARY] written=%d skipped=%d quarantined=%d expected_remaining=0 actual_remaining=%d",
        written, skipped, len(after_quarantined), len(after_needs),
    )

    # Success = every non-quarantined record now has provenance. Quarantined records are
    # an expected, documented steady state (AC-5's "or documented quarantine exemption").
    return 0 if len(after_needs) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
