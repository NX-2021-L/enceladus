#!/usr/bin/env python3
"""Finance warehouse export on the B2-R2 shared registration library.

DVP-TSK-670 (BRD B2-R2 ``callers``). Finance is the FIRST caller and the
reference implementation the contract was derived from: it independently
arrived at the right shape -- Parquet at ``warehouse/finance/<table>/``, one
object per table, code-driven Glue registration, zero Trino config changes --
and this module makes the library the canonical form of what finance already
does, rather than a parallel second opinion about it.

Two modes:

    reconcile   Read the live ``finance`` Glue catalog and diff every table
                against the definition the shared library would produce from
                the same declared columns. Read-only. This is the check that
                keeps the library and the reference implementation honest with
                each other, and it is the mode CI and the B6-R2 monitor want.

    export      Project rows for one finance table through
                ``register_table()`` -- the call site the finance export job
                adopts in place of its own registration code.

Usage::

    python3 tools/warehouse_export_finance.py reconcile
    python3 tools/warehouse_export_finance.py reconcile --json
    python3 tools/warehouse_export_finance.py schema --table accounts

The finance system of record (T1) is SQLite in ``s3://finance-.../db/finance.db``
and lives in the ``NX-2021-L/finance`` repo. This module deliberately does NOT
reach into it: the reconciliation runs against the catalog, and ``export_table``
takes rows the caller already has. That keeps the contract check runnable from
this repo with read-only credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "backend",
        "lambda",
        "shared_layer",
        "python",
    ),
)

from enceladus_shared.warehouse_registration import (  # noqa: E402
    ColumnSpec,
    ContractViolation,
    RegistrationRecord,
    TableContract,
    _normalized_catalog_view,
    build_contract,
    register_table,
)

# ---------------------------------------------------------------------------
# Finance's live warehouse coordinates (verified 2026-08-07)
# ---------------------------------------------------------------------------

FINANCE_PROJECT = "finance"
FINANCE_BUCKET = "finance-356364570033-us-west-2"
FINANCE_DATABASE = "finance"
FINANCE_REGION = "us-west-2"

#: Finance's freshness stamp is CALLER-OWNED business data, not a warehouse
#: write stamp. Seventeen tables carry ``updated_at``; ``statements`` carries
#: ``ingested_at``. The library validates these rather than overwriting them
#: (``stamp_freshness=False``) -- stamping a warehouse write time over a
#: business timestamp would corrupt the column it was meant to describe.
FINANCE_FRESHNESS_COLUMNS = {"statements": "ingested_at"}
FINANCE_DEFAULT_FRESHNESS_COLUMN = "updated_at"


def freshness_column_for(table: str) -> str:
    return FINANCE_FRESHNESS_COLUMNS.get(table, FINANCE_DEFAULT_FRESHNESS_COLUMN)


def _glue_client(region: str = FINANCE_REGION, profile: Optional[str] = None):
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("glue", region_name=region)


# ---------------------------------------------------------------------------
# Schema declaration
# ---------------------------------------------------------------------------


def declared_columns_from_catalog(glue_client, table: str) -> List[ColumnSpec]:
    """Read finance's own declaration for one table out of the Glue catalog.

    This is not schema INFERENCE -- nothing is sampled from S3. It reads the
    declaration finance's export code already wrote, which is what makes the
    reconciliation a comparison between two declarations rather than between a
    declaration and a guess.
    """
    live = glue_client.get_table(DatabaseName=FINANCE_DATABASE, Name=table)["Table"]
    return [
        ColumnSpec(name=column["Name"], type=column["Type"])
        for column in live["StorageDescriptor"]["Columns"]
    ]


def contract_for(table: str, columns: Sequence[ColumnSpec]) -> TableContract:
    return build_contract(
        project=FINANCE_PROJECT,
        table=table,
        columns=columns,
        bucket=FINANCE_BUCKET,
        database=FINANCE_DATABASE,
        freshness_column=freshness_column_for(table),
    )


# ---------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------


def reconcile(glue_client) -> Dict[str, Any]:
    """Diff every live finance table against what the library would register."""
    tables: List[Dict[str, Any]] = []
    paginator = glue_client.get_paginator("get_tables")
    for page in paginator.paginate(DatabaseName=FINANCE_DATABASE):
        tables.extend(page["TableList"])

    results: List[Dict[str, Any]] = []
    for live in sorted(tables, key=lambda item: item["Name"]):
        table = live["Name"]
        columns = [
            ColumnSpec(name=column["Name"], type=column["Type"])
            for column in live["StorageDescriptor"]["Columns"]
        ]
        entry: Dict[str, Any] = {
            "table": table,
            "freshness_column": freshness_column_for(table),
            "column_count": len(columns),
        }
        try:
            contract = contract_for(table, columns)
        except ContractViolation as exc:
            entry["status"] = "REJECTED"
            entry["differences"] = {"build_contract": str(exc)}
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
        entry["trino_identifier"] = contract.trino_identifier
        entry["location"] = contract.location
        if differences:
            entry["differences"] = differences
        results.append(entry)

    summary = {
        "database": FINANCE_DATABASE,
        "bucket": FINANCE_BUCKET,
        "table_count": len(results),
        "match": sum(1 for entry in results if entry["status"] == "MATCH"),
        "divergent": sum(1 for entry in results if entry["status"] == "DIVERGENT"),
        "rejected": sum(1 for entry in results if entry["status"] == "REJECTED"),
        "tables": results,
    }
    return summary


# ---------------------------------------------------------------------------
# export -- the call site the finance export job adopts
# ---------------------------------------------------------------------------


def export_table(
    table: str,
    rows: Any,
    columns: Sequence[ColumnSpec],
    *,
    write_timestamp=None,
    s3_client=None,
    glue_client=None,
    dry_run: bool = False,
) -> Optional[RegistrationRecord]:
    """Export one finance table through the shared library.

    This is the whole point of B2-R2: the finance export job stops carrying its
    own Parquet-write plus Glue-registration code and calls this instead. The
    only finance-specific things here are the bucket, the database, and which
    column holds the freshness stamp -- everything else is the shared contract.
    """
    contract = contract_for(table, columns)
    if dry_run:
        return None
    return register_table(
        project=FINANCE_PROJECT,
        table=table,
        rows=rows,
        columns=columns,
        bucket=FINANCE_BUCKET,
        database=FINANCE_DATABASE,
        freshness_column=contract.freshness_column,
        # Finance owns its freshness column: validate, never overwrite.
        stamp_freshness=False,
        write_timestamp=write_timestamp,
        s3_client=s3_client,
        glue_client=glue_client,
        region=FINANCE_REGION,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["reconcile", "schema"])
    parser.add_argument("--table", help="table name (schema mode)")
    parser.add_argument("--profile", help="AWS profile")
    parser.add_argument("--region", default=FINANCE_REGION)
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    args = parser.parse_args(argv)

    glue_client = _glue_client(args.region, args.profile)

    if args.mode == "schema":
        if not args.table:
            parser.error("--table is required in schema mode")
        columns = declared_columns_from_catalog(glue_client, args.table)
        contract = contract_for(args.table, columns)
        print(json.dumps(contract.glue_table_input(), indent=2))
        return 0

    summary = reconcile(glue_client)
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(
            "finance reconciliation: %d tables | %d match | %d divergent | %d rejected"
            % (
                summary["table_count"],
                summary["match"],
                summary["divergent"],
                summary["rejected"],
            )
        )
        for entry in summary["tables"]:
            marker = {"MATCH": "ok", "DIVERGENT": "DIFF", "REJECTED": "REJECT"}[entry["status"]]
            print(
                "  %-6s %-22s cols=%-3d freshness=%s"
                % (marker, entry["table"], entry["column_count"], entry["freshness_column"])
            )
            for field, delta in (entry.get("differences") or {}).items():
                print("           %s: library=%r live=%r" % (field, delta.get("library"), delta.get("live")))
    return 0 if summary["divergent"] == 0 and summary["rejected"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
