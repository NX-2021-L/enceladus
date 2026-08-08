"""The health status surface: durable snapshots, and two queryable daily tables.

DVP-TSK-665 / BRD B6-R2 / DVP-PLN-001.

A health monitor that only writes CloudWatch logs is a monitor nobody reads. The
surface has three layers, and each exists for a reason the other two cannot
serve:

``platform-health/latest.json``
    Current state, one GetObject away. What an operator or another agent reads
    to answer "is the platform healthy right now" without running anything.

``platform-health/history/<observed_at>.json``
    Append-only snapshots. This is the SYSTEM OF RECORD (T1) for platform
    health, and its single writer is the scheduled Lambda -- the obligation-1
    requirement of DOC-F56858AFE749 met literally rather than waved at.

``hive.devops.fact_platform_health_daily`` / ``fact_table_freshness_daily``
    The warehouse projection (T2), rebuilt in full from the snapshot history on
    every run through the B2-R2 shared library. Nothing here hand-rolls Parquet
    or Glue, and nothing appends: file count tracks data size, never write count
    (DOC-1E1EC5B7CE02).

Both tables are at DAILY grain, and that is the whole point of task DVP-TSK-666.
A daily series that stops drawing is legible as a failure to any human glancing
at a chart. A single "last refreshed" value that persists is not -- it looks
exactly like a healthy value, which is how DVP-ISS-087 survived five months. The
grain is the belt-and-braces companion to the monitor: the monitor tells you,
and the shape of the chart tells you even if the monitor itself has stopped.

That last clause is the subtle one. If this Lambda dies, no issue is filed --
because the thing that files issues is what died. But the daily series stops
advancing, and a chart with a gap at today's date is visibly wrong. The
projection's failure is legible WITHOUT monitoring, which is the only kind of
check that survives its own outage.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from health_contract import SEVERITY_BREACH, WAREHOUSE_BUCKET
from health_finding import CheckResult, overall_severity

LOGGER = logging.getLogger(__name__)

SURFACE_PREFIX = "platform-health"
LATEST_KEY = "%s/latest.json" % SURFACE_PREFIX
HISTORY_PREFIX = "%s/history/" % SURFACE_PREFIX

HEALTH_PROJECT = "devops"
HEALTH_TABLE = "fact_platform_health_daily"
FRESHNESS_TABLE = "fact_table_freshness_daily"

#: How far back the daily projection reaches. Bounds both the history scan and
#: the table size; snapshots older than this stay in S3 and stay readable, they
#: simply stop being projected.
PROJECTION_WINDOW_DAYS = 400


# ---------------------------------------------------------------------------
# Layer 1 and 2 -- the JSON surface
# ---------------------------------------------------------------------------


def build_snapshot(
    results: Sequence[CheckResult],
    run_id: str,
    observed_at: str,
    emissions: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "observed_at": observed_at,
        "run_id": run_id,
        "overall_severity": overall_severity(results),
        "check_count": len(results),
        "breach_count": sum(
            1 for r in results for f in r.findings if f.severity == SEVERITY_BREACH
        ),
        "issues_emitted": list(emissions),
        "checks": [r.to_dict() for r in results],
    }


def write_snapshot(s3_client, snapshot: Dict[str, Any], bucket: str = WAREHOUSE_BUCKET) -> List[str]:
    """Write ``latest.json`` and the append-only history entry. Returns the keys."""
    payload = json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8")
    history_key = "%s%s.json" % (HISTORY_PREFIX, snapshot["observed_at"].replace(":", ""))
    written: List[str] = []
    for key in (LATEST_KEY, history_key):
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=payload,
            ContentType="application/json",
        )
        written.append("s3://%s/%s" % (bucket, key))
    return written


def load_history(
    s3_client, bucket: str = WAREHOUSE_BUCKET, limit_days: int = PROJECTION_WINDOW_DAYS
) -> List[Dict[str, Any]]:
    """Every snapshot in the projection window, oldest first.

    Reads the append-only history rather than accumulating state in the table
    itself. That is what lets the T2 projection be a full overwrite while the
    series it draws still stretches back in time.
    """
    keys: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": HISTORY_PREFIX}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3_client.list_objects_v2(**kwargs)
        keys.extend(e["Key"] for e in page.get("Contents", []) or [])
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
        if not token:
            break

    keys = sorted(keys)[-(limit_days * 24):]
    snapshots: List[Dict[str, Any]] = []
    for key in keys:
        try:
            body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
            snapshots.append(json.loads(body.decode("utf-8")))
        except Exception:  # noqa: BLE001
            LOGGER.exception("unreadable health snapshot %s -- skipping", key)
    return snapshots


# ---------------------------------------------------------------------------
# Layer 3 -- the daily-grain projection
# ---------------------------------------------------------------------------

HEALTH_COLUMNS = (
    ("health_day", "string", "UTC calendar day of the observation. The grain."),
    ("check_id", "string", "Check identifier, e.g. check_1_freshness."),
    ("severity", "string", "Worst severity the check reported that day."),
    ("subjects_examined", "int", "How many subjects the check actually looked at."),
    ("finding_count", "int", "Findings of any severity."),
    ("breach_count", "int", "Findings that filed or bumped a governed issue."),
    ("run_count", "int", "Monitor invocations contributing to this day."),
    ("observed_at", "string", "Timestamp of the last run contributing to this day."),
    ("ingest_ts", "string", "Mandatory freshness stamp (DOC-04AF8A02A8F7)."),
)

FRESHNESS_COLUMNS = (
    ("health_day", "string", "UTC calendar day of the observation. The grain."),
    ("table_identifier", "string", "Fully qualified Trino identifier."),
    ("database_name", "string", "Glue database."),
    ("table_name", "string", "Glue table."),
    ("age_hours", "double", "Hours since the table's last successful refresh."),
    ("sla_hours", "double", "Declared freshness SLA for this table."),
    ("stale", "int", "1 when age_hours exceeded sla_hours on this day."),
    ("row_count", "bigint", "Rows in the table at last refresh."),
    ("file_count", "int", "Objects on the table prefix at last refresh."),
    ("write_timestamp", "string", "The table's own last-write stamp."),
    ("observed_at", "string", "Timestamp of the last run contributing to this day."),
    ("ingest_ts", "string", "Mandatory freshness stamp (DOC-04AF8A02A8F7)."),
)


def _day_of(observed_at: str) -> str:
    return (observed_at or "")[:10]


def project_health_rows(snapshots: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """(health_day, check_id) -> the day's worst observation. Last run wins on ties."""
    by_key: Dict[Any, Dict[str, Any]] = {}
    for snapshot in snapshots:
        day = _day_of(snapshot.get("observed_at", ""))
        if not day:
            continue
        for check in snapshot.get("checks", []) or []:
            key = (day, check.get("check"))
            row = by_key.get(key)
            if row is None:
                row = {
                    "health_day": day,
                    "check_id": check.get("check"),
                    "severity": check.get("severity"),
                    "subjects_examined": int(check.get("subjects_examined") or 0),
                    "finding_count": int(check.get("finding_count") or 0),
                    "breach_count": int(check.get("breach_count") or 0),
                    "run_count": 0,
                    "observed_at": snapshot.get("observed_at"),
                }
                by_key[key] = row
            row["run_count"] += 1
            if snapshot.get("observed_at", "") >= (row["observed_at"] or ""):
                row["observed_at"] = snapshot.get("observed_at")
                row["severity"] = check.get("severity")
                row["subjects_examined"] = int(check.get("subjects_examined") or 0)
                row["finding_count"] = int(check.get("finding_count") or 0)
                row["breach_count"] = int(check.get("breach_count") or 0)
    return sorted(by_key.values(), key=lambda r: (r["health_day"], r["check_id"] or ""))


def project_freshness_rows(snapshots: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """(health_day, table) -> that day's last freshness observation.

    Sourced from check 1's ``detail.tables``, which carries every registered
    table whether or not it breached. A table that is healthy still draws a
    point, because a series that only appears when something is wrong cannot
    show you that it stopped.
    """
    by_key: Dict[Any, Dict[str, Any]] = {}
    for snapshot in snapshots:
        day = _day_of(snapshot.get("observed_at", ""))
        if not day:
            continue
        for check in snapshot.get("checks", []) or []:
            if check.get("check") != "check_1_freshness":
                continue
            for entry in (check.get("detail") or {}).get("tables", []) or []:
                identifier = entry.get("table") or ""
                if not identifier:
                    continue
                parts = identifier.split(".")
                database = parts[1] if len(parts) > 2 else ""
                table_name = parts[-1]
                age = entry.get("age_hours")
                sla = entry.get("sla_hours")
                key = (day, identifier)
                existing = by_key.get(key)
                observed_at = snapshot.get("observed_at")
                if existing is not None and (existing.get("observed_at") or "") > (observed_at or ""):
                    continue
                by_key[key] = {
                    "health_day": day,
                    "table_identifier": identifier,
                    "database_name": database,
                    "table_name": table_name,
                    "age_hours": float(age) if age is not None else None,
                    "sla_hours": float(sla) if sla is not None else None,
                    "stale": 1 if (age is not None and sla is not None and age > sla) else 0,
                    "row_count": entry.get("row_count"),
                    "file_count": entry.get("file_count"),
                    "write_timestamp": entry.get("write_timestamp"),
                    "observed_at": observed_at,
                }
    return sorted(
        by_key.values(), key=lambda r: (r["health_day"], r["table_identifier"])
    )


def publish_tables(
    s3_client,
    glue_client,
    snapshots: Sequence[Dict[str, Any]],
    bucket: str = WAREHOUSE_BUCKET,
    write_timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Full-refresh both daily tables through the B2-R2 shared library.

    Import is deferred and dual-pathed for the same reason ``governance_mart``
    does it: on the deployed function the module arrives vendored at the package
    root via ``.build_extras`` because the pinned shared layer predates it.
    """
    try:
        from enceladus_shared.warehouse_registration import ColumnSpec, register_table
    except ImportError:  # pragma: no cover - resolved by .build_extras on Lambda
        from warehouse_registration import ColumnSpec, register_table  # type: ignore

    stamp = write_timestamp or datetime.now(timezone.utc)
    published: Dict[str, Any] = {}

    for table, columns, rows in (
        (HEALTH_TABLE, HEALTH_COLUMNS, project_health_rows(snapshots)),
        (FRESHNESS_TABLE, FRESHNESS_COLUMNS, project_freshness_rows(snapshots)),
    ):
        record = register_table(
            project=HEALTH_PROJECT,
            table=table,
            rows=rows,
            columns=[ColumnSpec(name=n, type=t, comment=c) for n, t, c in columns],
            bucket=bucket,
            write_timestamp=stamp,
            table_comment=(
                "B6-R2 platform health, daily grain. Full-refreshed from the "
                "append-only snapshot history at s3://%s/%s (DVP-TSK-665)."
                % (bucket, HISTORY_PREFIX)
            ),
            s3_client=s3_client,
            glue_client=glue_client,
        )
        published[table] = {
            "rows": record.row_count,
            "bytes": record.byte_count,
            "files": record.file_count,
            "trino_identifier": record.trino_identifier,
            "write_timestamp": record.write_timestamp,
        }
    return published
