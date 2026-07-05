#!/usr/bin/env python3
"""Idempotent bidirectional-relation backfill and scan-and-compare audit.

ENC-TSK-L07 (B63 Ph2 AC-7 / B65 Ph4 AC-5/AC-7). Scans `devops-project-tracker`
(all governed record types: task/issue/feature/lesson/plan) and
`devops-document-store`, finds every related_task_ids / related_issue_ids /
related_feature_ids / related_lesson_ids reference on a tracker record and
every related_items reference on a document, and verifies the reverse
pointer exists on the other side (related_<source_type>_ids on the target
tracker record, or related_document_ids on the target tracker record for a
document's related_items). Any missing reverse edge is backfilled with the
same conditional (contains-check) UpdateItem used by the live write paths in
tracker_mutation and document_api, so a second run against an already-fixed
corpus produces zero writes.

Usage:

    python3 tools/relation_backfill.py --env gamma [--dry-run] [--region us-west-2]

Emits a JSON summary to stdout: {scanned, unidirectional_found, fixed,
skipped_unresolvable, findings: [...]}. Pass --report-out to also write the
same summary to a file for attaching as governed evidence (ENC-TSK-L07 AC-5
requires the audit output be captured as a governed report document).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("relation_backfill")

_ENV_TO_TABLE_SUFFIX = {"prod": "", "gamma": "-gamma"}

_RELATION_ID_FIELDS = ("related_task_ids", "related_issue_ids", "related_feature_ids", "related_lesson_ids")
_TYPE_TO_SK_PREFIX = {"task": "task", "issue": "issue", "feature": "feature", "lesson": "lesson", "plan": "plan"}
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan"}


def _tracker_table(env: str) -> str:
    return f"devops-project-tracker{_ENV_TO_TABLE_SUFFIX[env]}"


def _document_table(env: str) -> str:
    # ENC-TSK-L07 AC-5 names "devops-document-store" but the live table is "documents"
    # (/"documents-gamma") -- verified via aws dynamodb list-tables 2026-07-05.
    return f"documents{_ENV_TO_TABLE_SUFFIX[env]}"


def _record_type_from_id(record_id: str) -> Optional[str]:
    parts = record_id.strip().upper().split("-")
    if len(parts) < 2:
        return None
    return _ID_SEGMENT_TO_TYPE.get(parts[1])


def _scan_table(ddb, table_name: str) -> Iterable[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {"TableName": table_name}
    while True:
        resp = ddb.scan(**kwargs)
        for item in resp.get("Items", []):
            yield item
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _str_list(item: Dict[str, Any], field: str) -> List[str]:
    return [s.get("S", "").strip().upper() for s in item.get(field, {}).get("L", []) if s.get("S", "").strip()]


def _fix_reverse_edge(
    ddb, table_name: str, project_id: str, sk: str, field: str, new_value: str, dry_run: bool
) -> str:
    """Conditionally append `new_value` to `field` on the record at (project_id, sk).
    Returns "fixed", "already_present", or "type_error" (pre-ENC-ISS-059 legacy
    scalar-typed field on the target — same class of issue tracker_mutation's
    _normalize_related_ids_value coerces on the live write path; logged and
    skipped here rather than crashing the whole scan)."""
    if dry_run:
        return "fixed"
    try:
        ddb.update_item(
            TableName=table_name,
            Key={"project_id": {"S": project_id}, "record_id": {"S": sk}},
            UpdateExpression=f"SET #f = list_append(if_not_exists(#f, :empty), :new)",
            ConditionExpression="attribute_not_exists(#f) OR NOT contains(#f, :val)",
            ExpressionAttributeNames={"#f": field},
            ExpressionAttributeValues={
                ":empty": {"L": []},
                ":new": {"L": [{"S": new_value}]},
                ":val": {"S": new_value},
            },
        )
        return "fixed"
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ConditionalCheckFailedException":
            return "already_present"  # no-op, not a failure
        if code == "ValidationException":
            logger.warning(
                "[ENC-ISS-059-class] %s.%s on %s/%s is a legacy non-list type — skipped, not fixed: %s",
                sk, field, table_name, project_id, exc,
            )
            return "type_error"
        raise


def _audit_tracker_relations(ddb, tracker_table: str, dry_run: bool) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    scanned = 0
    fixed = 0
    skipped = 0
    type_errors = 0

    # First pass: build an index of (project_id, sk) -> item so target lookups
    # don't need N extra GetItem calls per source edge.
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in _scan_table(ddb, tracker_table):
        pid = item.get("project_id", {}).get("S", "")
        sk = item.get("record_id", {}).get("S", "")
        index[(pid, sk)] = item
        scanned += 1

    for (pid, sk), item in index.items():
        if not sk.startswith(("task#", "issue#", "feature#", "lesson#")):
            continue
        source_type = sk.split("#", 1)[0]
        source_id = sk.split("#", 1)[1]
        for field in _RELATION_ID_FIELDS:
            for target_id in _str_list(item, field):
                target_type = _record_type_from_id(target_id)
                if target_type not in _TYPE_TO_SK_PREFIX:
                    skipped += 1
                    continue
                target_sk = f"{target_type}#{target_id}"
                target_item = index.get((pid, target_sk))
                if target_item is None:
                    skipped += 1
                    continue
                reverse_field = f"related_{source_type}_ids"
                if source_id in _str_list(target_item, reverse_field):
                    continue  # already bidirectional
                findings.append({
                    "source": f"{pid}:{sk}", "target": f"{pid}:{target_sk}",
                    "missing_reverse_field": reverse_field, "action": "backfill" if not dry_run else "would_backfill",
                })
                outcome = _fix_reverse_edge(ddb, tracker_table, pid, target_sk, reverse_field, source_id, dry_run)
                if outcome == "fixed":
                    fixed += 1
                elif outcome == "type_error":
                    type_errors += 1

    return {"scanned": scanned, "unidirectional_found": len(findings), "fixed": fixed,
            "type_errors": type_errors, "skipped_unresolvable": skipped, "findings": findings}


def _audit_document_relations(ddb, document_table: str, tracker_table: str, dry_run: bool) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    scanned = 0
    fixed = 0
    skipped = 0
    type_errors = 0

    tracker_index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in _scan_table(ddb, tracker_table):
        pid = item.get("project_id", {}).get("S", "")
        sk = item.get("record_id", {}).get("S", "")
        tracker_index[(pid, sk)] = item

    for doc in _scan_table(ddb, document_table):
        scanned += 1
        document_id = doc.get("document_id", {}).get("S", "")
        project_id = doc.get("project_id", {}).get("S", "")
        related_items = _str_list(doc, "related_items")
        for target_id in related_items:
            target_type = _record_type_from_id(target_id)
            if target_type not in _TYPE_TO_SK_PREFIX:
                skipped += 1
                continue
            target_sk = f"{target_type}#{target_id}"
            target_item = tracker_index.get((project_id, target_sk))
            if target_item is None:
                skipped += 1
                continue
            if document_id in _str_list(target_item, "related_document_ids"):
                continue
            findings.append({
                "source": f"document:{document_id}", "target": f"{project_id}:{target_sk}",
                "missing_reverse_field": "related_document_ids",
                "action": "backfill" if not dry_run else "would_backfill",
            })
            outcome = _fix_reverse_edge(ddb, tracker_table, project_id, target_sk, "related_document_ids", document_id, dry_run)
            if outcome == "fixed":
                fixed += 1
            elif outcome == "type_error":
                type_errors += 1

    return {"scanned": scanned, "unidirectional_found": len(findings), "fixed": fixed,
            "type_errors": type_errors, "skipped_unresolvable": skipped, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env", choices=["prod", "gamma"], required=True)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--dry-run", action="store_true", help="Report only; make no writes.")
    parser.add_argument("--report-out", help="Also write the JSON summary to this file path.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    ddb = boto3.client("dynamodb", region_name=args.region)
    tracker_table = _tracker_table(args.env)
    document_table = _document_table(args.env)

    logger.info("Auditing tracker-to-tracker relations in %s (dry_run=%s)", tracker_table, args.dry_run)
    tracker_result = _audit_tracker_relations(ddb, tracker_table, args.dry_run)

    logger.info("Auditing document-to-tracker relations in %s -> %s (dry_run=%s)", document_table, tracker_table, args.dry_run)
    doc_result = _audit_document_relations(ddb, document_table, tracker_table, args.dry_run)

    summary = {
        "env": args.env,
        "dry_run": args.dry_run,
        "tracker_relations": tracker_result,
        "document_relations": doc_result,
        "total_unidirectional_found": tracker_result["unidirectional_found"] + doc_result["unidirectional_found"],
        "total_fixed": tracker_result["fixed"] + doc_result["fixed"],
    }

    output = json.dumps(summary, indent=2)
    print(output)
    if args.report_out:
        with open(args.report_out, "w") as f:
            f.write(output + "\n")
        logger.info("Report written to %s", args.report_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
