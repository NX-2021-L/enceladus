#!/usr/bin/env python3
"""Governance analytics mart -- operator entry point.

BRD B3 (DVP-TSK-648 / DVP-TSK-649). This is the SAME code path the scheduled
Lambda runs (``backend/lambda/governance_mart/``), exposed as a CLI so the mart
can be built, inspected, and reconciled from a workstation without waiting for
a schedule. Sharing the path is the point: an operator command that reproduced
the projection separately would be a second opinion about the grain, and the
two would drift.

Modes::

    # Project everything and print row counts. Touches no AWS write API.
    python3 tools/governance_mart_refresh.py plan --profile product-lead

    # Full refresh: write Parquet + register the declared schema in Glue.
    python3 tools/governance_mart_refresh.py refresh --profile product-lead

    # Print the DECLARED schema the library will register for one table.
    python3 tools/governance_mart_refresh.py schema --table dim_record

    # Diff the live Glue catalog against the declaration. Read-only; exits
    # non-zero on any divergence. This is the conformance check CI and the
    # B6-R2 monitor want.
    python3 tools/governance_mart_refresh.py reconcile --profile product-lead
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Sequence

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO, "backend", "lambda", "shared_layer", "python"))
sys.path.insert(0, os.path.join(_REPO, "backend", "lambda", "governance_mart"))

from enceladus_shared.warehouse_registration import (  # noqa: E402
    ContractViolation,
    _normalized_catalog_view,
    build_contract,
)

from mart_project import build_all  # noqa: E402
from mart_refresh import MART_BUCKET, MART_DATABASE, MART_REGION, refresh_mart  # noqa: E402
from mart_schema import MART_PROJECT, MART_TABLE_ORDER, MART_TABLES  # noqa: E402
from mart_source import load_corpus  # noqa: E402


def _session(profile: Optional[str], region: str):
    import boto3

    return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)


def contract_for(table: str):
    spec = MART_TABLES[table]
    return build_contract(
        project=MART_PROJECT,
        table=table,
        columns=spec.columns,
        bucket=MART_BUCKET,
        database=MART_DATABASE,
        table_comment=spec.comment,
    )


def reconcile(glue_client) -> dict:
    """Diff every declared mart table against its live Glue registration."""
    results = []
    for name in MART_TABLE_ORDER:
        entry = {"table": name, "column_count": len(MART_TABLES[name].columns)}
        try:
            contract = contract_for(name)
        except ContractViolation as exc:
            entry["status"] = "REJECTED"
            entry["differences"] = {"build_contract": str(exc)}
            results.append(entry)
            continue
        entry["trino_identifier"] = contract.trino_identifier
        entry["location"] = contract.location
        try:
            live = glue_client.get_table(DatabaseName=MART_DATABASE, Name=name)["Table"]
        except glue_client.exceptions.EntityNotFoundException:
            entry["status"] = "MISSING"
            results.append(entry)
            continue
        want = _normalized_catalog_view(contract.glue_table_input())
        have = _normalized_catalog_view(live)
        differences = {
            field: {"library": want[field], "live": have[field]}
            for field in want
            if want[field] != have[field]
        }
        entry["status"] = "MATCH" if not differences else "DIVERGENT"
        if differences:
            entry["differences"] = differences
        results.append(entry)

    return {
        "database": MART_DATABASE,
        "bucket": MART_BUCKET,
        "table_count": len(results),
        "match": sum(1 for e in results if e["status"] == "MATCH"),
        "divergent": sum(1 for e in results if e["status"] == "DIVERGENT"),
        "missing": sum(1 for e in results if e["status"] == "MISSING"),
        "rejected": sum(1 for e in results if e["status"] == "REJECTED"),
        "tables": results,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["plan", "refresh", "schema", "reconcile"])
    parser.add_argument("--table", help="single table (schema mode), or restrict refresh")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default=MART_REGION)
    parser.add_argument("--last-day", help="daily-grain upper bound, YYYY-MM-DD")
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.mode == "schema":
        if not args.table:
            parser.error("--table is required in schema mode")
        print(json.dumps(contract_for(args.table).glue_table_input(), indent=2))
        return 0

    session = _session(args.profile, args.region)

    if args.mode == "reconcile":
        summary = reconcile(session.client("glue"))
        if args.json:
            print(json.dumps(summary, indent=2, default=str))
        else:
            print(
                "governance mart reconciliation: %d tables | %d match | %d divergent | %d missing | %d rejected"
                % (summary["table_count"], summary["match"], summary["divergent"],
                   summary["missing"], summary["rejected"])
            )
            for entry in summary["tables"]:
                marker = {"MATCH": "ok", "DIVERGENT": "DIFF", "MISSING": "MISSING", "REJECTED": "REJECT"}[entry["status"]]
                print("  %-8s %-26s cols=%d" % (marker, entry["table"], entry["column_count"]))
                for field, delta in (entry.get("differences") or {}).items():
                    print("           %s: library=%r live=%r" % (field, delta.get("library"), delta.get("live")))
        return 0 if summary["divergent"] == 0 and summary["rejected"] == 0 else 1

    last_day = datetime.strptime(args.last_day, "%Y-%m-%d").date() if args.last_day else None

    if args.mode == "plan":
        corpus = load_corpus(dynamodb_client=session.client("dynamodb"), region=args.region)
        projected = build_all(corpus, last_day=last_day)
        summary = {
            "source_counts": corpus.counts(),
            "tables": {name: len(rows) for name, rows in projected.items()},
        }
        print(json.dumps(summary, indent=2, default=str))
        return 0

    result = refresh_mart(
        tables=[args.table] if args.table else None,
        last_day=last_day,
        dynamodb_client=session.client("dynamodb"),
        s3_client=session.client("s3"),
        glue_client=session.client("glue"),
    )
    print(json.dumps(result.as_dict(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
