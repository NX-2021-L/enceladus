"""The scheduled full-refresh path for the governance analytics mart.

BRD B3-R3 (DVP-TSK-649). The whole requirement, in one function:

    read the governed record store -> project to grain -> write Parquet ->
    register via the B2-R2 shared library

Every historical break pattern this plan exists to end is eliminated *by
construction* here rather than by monitoring:

``EventBridge per-mutation trigger``
    There is none. The only trigger is a SCHEDULE (daily minimum; a faster
    cadence changes nothing structurally, because each run rebuilds
    everything). Nothing in this path subscribes to a tracker mutation, so
    there is nothing to disable later -- the disable step that the legacy
    ``on-project-json-sync`` chain still needs simply has no counterpart.

``Crawler launcher / crawler``
    There is none. ``register_table`` writes a DECLARED schema through the
    Glue API (``DOC-5E35E14DAD05``). The schema is a value in
    ``mart_schema.py``, committed in the same change as the code that writes
    the data.

``Crawler concurrency``
    Unreachable: no crawler exists to race. Two overlapping refreshes converge
    on the same canonical key rather than corrupting a partition set.

``Partition explosion``
    Impossible: no table declares a partition key, and the library writes
    exactly one object per table at a constant key. File count tracks data
    size, never write count (``DOC-1E1EC5B7CE02``).

``Stale data that looks fresh``
    Structurally visible. Every fact table is at daily grain, so a refresh
    that stops running produces a series that STOPS DRAWING on the day it
    stopped, instead of a current-value tile that renders the last good number
    forever. A failure is legible as an absence, which is the OBJ-6 property.

The same function serves the Lambda handler and ``tools/governance_mart_refresh.py``,
so the scheduled path and the operator path cannot drift apart.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

try:  # pragma: no cover - depends on which path provides the library
    from enceladus_shared.warehouse_registration import register_table
except ImportError:  # pragma: no cover
    from warehouse_registration import register_table  # type: ignore

from mart_project import build_all
from mart_schema import MART_PROJECT, MART_TABLE_ORDER, MART_TABLES, assert_daily_grain
from mart_source import load_corpus

LOGGER = logging.getLogger(__name__)

__all__ = ["MART_BUCKET", "MART_DATABASE", "MART_REGION", "refresh_mart", "RefreshResult"]

#: The mart's T2 coordinates. `devops` owns the platform tier and the contract
#: (BRD B3-R4); the Glue database was created as a T0 onboarding action WITH a
#: LocationUri, per DOC-04AF8A02A8F7.
MART_BUCKET = os.environ.get("MART_BUCKET", "devops-agentcli-compute")
MART_DATABASE = os.environ.get("MART_DATABASE", "devops")
MART_REGION = os.environ.get("AWS_REGION", "us-west-2")


class RefreshResult:
    """What one refresh did, per table. Shaped for a log line and an assertion."""

    __slots__ = ("write_timestamp", "tables", "source_counts", "elapsed_seconds")

    def __init__(self, write_timestamp: datetime, source_counts: Dict[str, int]):
        self.write_timestamp = write_timestamp
        self.source_counts = source_counts
        self.tables: List[Dict[str, Any]] = []
        self.elapsed_seconds = 0.0

    def add(self, table: str, record) -> None:
        self.tables.append(
            {
                "table": table,
                "trino": "hive.%s.%s" % (MART_DATABASE, table),
                "rows": record.row_count,
                "bytes": record.byte_count,
                "files": record.file_count,
                "storage_changed": getattr(record, "storage_changed", None),
                "catalog_changed": getattr(record, "catalog_changed", None),
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "write_timestamp": self.write_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "database": MART_DATABASE,
            "bucket": MART_BUCKET,
            "source_counts": self.source_counts,
            "table_count": len(self.tables),
            "total_rows": sum(entry["rows"] for entry in self.tables),
            "total_bytes": sum(entry["bytes"] for entry in self.tables),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "tables": self.tables,
        }


def refresh_mart(
    *,
    tables: Optional[Sequence[str]] = None,
    last_day: Optional[date] = None,
    write_timestamp: Optional[datetime] = None,
    dynamodb_client=None,
    s3_client=None,
    glue_client=None,
    dry_run: bool = False,
) -> RefreshResult:
    """Rebuild the governance analytics mart in full.

    One ``write_timestamp`` is shared by all seven tables, so the mart has a
    single coherent freshness stamp per refresh -- which is what lets every
    chart display the freshness of its underlying table (B6-R3) without seven
    slightly different answers.
    """
    assert_daily_grain()
    started = time.time()
    if write_timestamp is None:
        write_timestamp = datetime.now(timezone.utc)
    if last_day is None:
        last_day = write_timestamp.date()
    wanted = list(tables) if tables else list(MART_TABLE_ORDER)
    unknown = [name for name in wanted if name not in MART_TABLES]
    if unknown:
        raise KeyError("not declared mart tables: %s" % ", ".join(unknown))

    LOGGER.info("[START] governance mart refresh | tables=%s last_day=%s", ",".join(wanted), last_day)
    corpus = load_corpus(dynamodb_client=dynamodb_client, region=MART_REGION)
    LOGGER.info("[INFO] governed corpus read: %s", corpus.counts())

    projected = build_all(corpus, last_day=last_day)
    result = RefreshResult(write_timestamp, corpus.counts())

    for name in wanted:
        rows = projected[name]
        table = MART_TABLES[name]
        LOGGER.info("[INFO] %s: %d rows projected", name, len(rows))
        if dry_run:
            result.tables.append({"table": name, "rows": len(rows), "bytes": 0, "files": 0, "dry_run": True})
            continue
        record = register_table(
            project=MART_PROJECT,
            table=name,
            rows=rows,
            columns=table.columns,
            bucket=MART_BUCKET,
            database=MART_DATABASE,
            table_comment=table.comment,
            # The mart is DERIVED data: the warehouse write time IS the
            # correct meaning of its freshness column, so the library owns it.
            stamp_freshness=True,
            write_timestamp=write_timestamp,
            s3_client=s3_client,
            glue_client=glue_client,
            region=MART_REGION,
        )
        result.add(name, record)
        LOGGER.info(
            "[SUCCESS] %s registered: rows=%d bytes=%d files=%d storage_changed=%s catalog_changed=%s",
            name, record.row_count, record.byte_count, record.file_count,
            getattr(record, "storage_changed", None), getattr(record, "catalog_changed", None),
        )

    result.elapsed_seconds = time.time() - started
    LOGGER.info("[END] governance mart refresh | %s", result.as_dict())
    return result
