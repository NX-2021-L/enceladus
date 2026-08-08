"""Checks 1 and 5 -- freshness against a declared SLA, and full-refresh consistency.

DVP-TSK-694 / BRD B6-R2 / DVP-PLN-001.

These two checks exist because of DVP-ISS-087: a projection stopped refreshing
and nobody noticed for five months, because a frozen table still returns rows
and a chart drawn from it still looks correct. Nothing was broken in a way that
raised an error. The only observable difference between a healthy table and that
one was the AGE of its last write -- which no surface reported.

Both checks read the B2-R2 registration record
(``warehouse-registrations/<project>/<table>.json``) rather than re-listing the
table's data prefix. That is not a performance choice. The registration record
is written by the export job's own code path in the same transaction that wrote
the Parquet, so it says what the WRITER believes it did; a directory listing
says only what survived. When the two disagree the disagreement is itself the
finding, which is why check 1 also reconciles the record against the Glue
catalog rather than trusting either alone.

Three conditions are distinguished, and the distinction is the substance:

``stale``
    The record exists, the data exists, and ``write_timestamp`` is older than
    the declared SLA. The DVP-ISS-087 condition exactly.

``missing_catalog``
    A registration record exists but the Glue table does not. Data is being
    written that nothing can query -- a refresh job succeeding into a void.

``missing_data``
    A Glue table points at a prefix holding no objects. Every query against it
    returns zero rows, silently and successfully. This is the shape of
    DVP-ISS-096, where dashboard 4 lost 9 of 13 charts to three tables that do
    not exist, and it went undetected because a chart with no data renders as a
    chart, not as an error.

Check 5's violation is narrower than "file count went up". A table that
legitimately grew shows file count steady (a constant key overwritten) and BYTES
up. The signature of snapshot-per-mutation partitioning -- the DOC-1E1EC5B7CE02
failure -- is file count growing while bytes do NOT. Both forms are evaluated,
because a file count above the declared sharding constant is already a violation
regardless of what the bytes did.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from health_contract import (
    DEFAULT_FRESHNESS_SLA_HOURS,
    DEFAULT_SHARDING_CONSTANT,
    FRESHNESS_SLA_OVERRIDES,
    GOVERNED_DATABASES,
    SEVERITY_BREACH,
    SEVERITY_WARNING,
    SHARDING_CONSTANT_OVERRIDES,
)
from health_finding import CheckResult, Finding

LOGGER = logging.getLogger(__name__)

CHECK_1 = "check_1_freshness"
CHECK_5 = "check_5_full_refresh"

REGISTRATION_PREFIX = "warehouse-registrations"


# ---------------------------------------------------------------------------
# Reading the registration records
# ---------------------------------------------------------------------------


def list_registered_tables(s3_client, bucket: str, project: str) -> List[str]:
    """Table names holding a registration record under this project."""
    prefix = "%s/%s/" % (REGISTRATION_PREFIX, project)
    tables: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3_client.list_objects_v2(**kwargs)
        for entry in page.get("Contents", []) or []:
            key = entry["Key"]
            if key.endswith(".json"):
                tables.append(key[len(prefix):-len(".json")])
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
        if not token:
            break
    return sorted(tables)


def read_registration_record(
    s3_client, bucket: str, project: str, table: str
) -> Optional[Dict[str, Any]]:
    """One GetObject answers both check 1 and check 5. None when never registered."""
    key = "%s/%s/%s.json" % (REGISTRATION_PREFIX, project, table)
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        if _is_not_found(exc):
            return None
        raise
    return json.loads(response["Body"].read().decode("utf-8"))


def _is_not_found(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in ("404", "NoSuchKey", "NotFound") or "NoSuchKey" in str(exc)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def sla_hours_for(trino_identifier: str) -> float:
    return FRESHNESS_SLA_OVERRIDES.get(trino_identifier, DEFAULT_FRESHNESS_SLA_HOURS)


def sharding_constant_for(trino_identifier: str) -> int:
    return SHARDING_CONSTANT_OVERRIDES.get(trino_identifier, DEFAULT_SHARDING_CONSTANT)


def _prefix_object_count(s3_client, bucket: str, prefix: str) -> int:
    """Objects actually present under a table prefix. Used only to confirm ABSENCE.

    Check 1 and 5 take their measurements from the registration record; this is
    the reconciliation probe that distinguishes "the writer says it wrote" from
    "the bytes are there", and it is what catches the DVP-ISS-096 shape.
    """
    total = 0
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        page = s3_client.list_objects_v2(**kwargs)
        total += page.get("KeyCount", 0)
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
        if not token:
            break
    return total


# ---------------------------------------------------------------------------
# Check 1 -- freshness SLA
# ---------------------------------------------------------------------------


def check_freshness(
    s3_client,
    glue_client,
    now: Optional[datetime] = None,
    databases: Optional[Dict[str, Dict[str, Any]]] = None,
) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    databases = databases if databases is not None else GOVERNED_DATABASES
    result = CheckResult(
        check=CHECK_1,
        title="Freshness of every registered warehouse table against its declared SLA",
    )
    examined_detail: List[Dict[str, Any]] = []

    for database, spec in sorted(databases.items()):
        if spec.get("tier") != "warehouse":
            continue
        project, bucket = spec["project"], spec["bucket"]
        try:
            registered = list_registered_tables(s3_client, bucket, project)
        except Exception as exc:  # noqa: BLE001
            result.error = "could not list registration records for %s: %s" % (project, exc)
            LOGGER.exception("registration listing failed for %s", project)
            continue

        catalog_tables = _glue_table_names(glue_client, database)

        for table in registered:
            result.subjects_examined += 1
            trino_id = "hive.%s.%s" % (database, table)
            try:
                record = read_registration_record(s3_client, bucket, project, table)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("registration read failed for %s", trino_id)
                result.findings.append(
                    _record_unreadable_finding(trino_id, bucket, project, table, exc)
                )
                continue
            if record is None:
                continue

            sla = sla_hours_for(trino_id)
            written = _parse_timestamp(record.get("write_timestamp"))
            age_hours = (
                round((now - written).total_seconds() / 3600.0, 3) if written else None
            )
            examined_detail.append(
                {
                    "table": trino_id,
                    "write_timestamp": record.get("write_timestamp"),
                    "age_hours": age_hours,
                    "sla_hours": sla,
                    "row_count": record.get("row_count"),
                    "file_count": record.get("file_count"),
                    "write_seq": record.get("write_seq"),
                }
            )

            if written is None:
                result.findings.append(
                    Finding(
                        check=CHECK_1,
                        subject=trino_id,
                        severity=SEVERITY_BREACH,
                        kind="unparseable_freshness_stamp",
                        summary="%s carries no parseable write_timestamp" % trino_id,
                        observed={"write_timestamp": record.get("write_timestamp")},
                        expected={"format": "ISO-8601 UTC, e.g. 2026-08-08T00:53:12Z"},
                        steps_to_duplicate=[
                            "aws s3 cp s3://%s/%s/%s/%s.json - --profile product-lead"
                            % (bucket, REGISTRATION_PREFIX, project, table),
                        ],
                        remediation=(
                            "The export job wrote a registration record without a usable "
                            "freshness stamp. Age cannot be computed, so this table is "
                            "UNMONITORABLE for staleness until the writer is fixed."
                        ),
                        references=["DOC-F56858AFE749 obligation 4"],
                    )
                )
            elif age_hours is not None and age_hours > sla:
                result.findings.append(
                    Finding(
                        check=CHECK_1,
                        subject=trino_id,
                        severity=SEVERITY_BREACH,
                        kind="stale",
                        summary="%s is %.1fh stale against a %.0fh SLA"
                        % (trino_id, age_hours, sla),
                        observed={
                            "age_hours": age_hours,
                            "write_timestamp": record.get("write_timestamp"),
                            "write_seq": record.get("write_seq"),
                            "row_count": record.get("row_count"),
                        },
                        expected={"max_age_hours": sla},
                        steps_to_duplicate=[
                            "aws s3 cp s3://%s/%s/%s/%s.json - --profile product-lead "
                            "--region us-west-2 | python3 -c "
                            "\"import json,sys;print(json.load(sys.stdin)['write_timestamp'])\""
                            % (bucket, REGISTRATION_PREFIX, project, table),
                            "Compare that timestamp against now; the SLA is %.0f hours." % sla,
                        ],
                        remediation=(
                            "The scheduled refresh that owns this table has not completed "
                            "within its SLA. Check the owning job's most recent invocation "
                            "and its error, then re-run it. This is the DVP-ISS-087 "
                            "condition: the table still returns rows and still looks "
                            "correct, so nothing else will report it."
                        ),
                        references=["DVP-ISS-087", "DOC-F56858AFE749 obligation 4"],
                    )
                )

            if table not in catalog_tables:
                result.findings.append(
                    Finding(
                        check=CHECK_1,
                        subject=trino_id,
                        severity=SEVERITY_BREACH,
                        kind="missing_catalog",
                        summary="%s has a registration record but no Glue table" % trino_id,
                        observed={"glue_database": database, "glue_table_present": False},
                        expected={"glue_table_present": True},
                        steps_to_duplicate=[
                            "aws glue get-table --database-name %s --name %s "
                            "--profile product-lead --region us-west-2" % (database, table),
                        ],
                        remediation=(
                            "The export job is writing data that nothing can query. Either "
                            "the Glue registration half of register_table() failed, or the "
                            "table was dropped out of band. Re-run the export job -- "
                            "registration is idempotent."
                        ),
                        references=["DOC-F56858AFE749 obligation 3"],
                    )
                )
            else:
                location = record.get("location") or ""
                if location.startswith("s3://"):
                    data_bucket, _, data_prefix = location[5:].partition("/")
                    try:
                        objects = _prefix_object_count(s3_client, data_bucket, data_prefix)
                    except Exception:  # noqa: BLE001
                        objects = None
                    if objects == 0:
                        result.findings.append(
                            Finding(
                                check=CHECK_1,
                                subject=trino_id,
                                severity=SEVERITY_BREACH,
                                kind="missing_data",
                                summary="%s is registered and catalogued but its prefix is empty"
                                % trino_id,
                                observed={"location": location, "object_count": 0},
                                expected={"object_count_min": 1},
                                steps_to_duplicate=[
                                    "aws s3 ls %s --recursive --profile product-lead "
                                    "--region us-west-2" % location,
                                ],
                                remediation=(
                                    "Every query against this table returns zero rows, "
                                    "successfully and silently -- the DVP-ISS-096 shape, "
                                    "where a chart with no data renders as a chart rather "
                                    "than as an error. Re-run the owning export job."
                                ),
                                references=["DVP-ISS-096"],
                            )
                        )

    result.detail["tables"] = examined_detail
    return result


def _record_unreadable_finding(trino_id, bucket, project, table, exc) -> Finding:
    return Finding(
        check=CHECK_1,
        subject=trino_id,
        severity=SEVERITY_BREACH,
        kind="registration_record_unreadable",
        summary="%s registration record could not be read" % trino_id,
        observed={"error": str(exc)},
        expected={"readable": True},
        steps_to_duplicate=[
            "aws s3 cp s3://%s/%s/%s/%s.json - --profile product-lead"
            % (bucket, REGISTRATION_PREFIX, project, table),
        ],
        remediation=(
            "The monitor cannot determine this table's freshness at all. An "
            "unmonitorable table is reported as a breach rather than skipped, "
            "because a check that quietly drops its hardest subjects reports "
            "green for the wrong reason."
        ),
    )


def _glue_table_names(glue_client, database: str) -> set:
    names = set()
    token = None
    while True:
        kwargs: Dict[str, Any] = {"DatabaseName": database}
        if token:
            kwargs["NextToken"] = token
        try:
            page = glue_client.get_tables(**kwargs)
        except Exception:  # noqa: BLE001
            LOGGER.exception("get_tables failed for %s", database)
            return names
        for table in page.get("TableList", []) or []:
            names.add(table.get("Name"))
        token = page.get("NextToken")
        if not token:
            break
    return names


# ---------------------------------------------------------------------------
# Check 5 -- full-refresh consistency
# ---------------------------------------------------------------------------


def check_full_refresh(
    s3_client, databases: Optional[Dict[str, Dict[str, Any]]] = None
) -> CheckResult:
    databases = databases if databases is not None else GOVERNED_DATABASES
    result = CheckResult(
        check=CHECK_5,
        title="Warehouse file counts against full-refresh semantics",
    )
    examined_detail: List[Dict[str, Any]] = []

    for database, spec in sorted(databases.items()):
        if spec.get("tier") != "warehouse":
            continue
        project, bucket = spec["project"], spec["bucket"]
        try:
            registered = list_registered_tables(s3_client, bucket, project)
        except Exception as exc:  # noqa: BLE001
            result.error = "could not list registration records for %s: %s" % (project, exc)
            continue

        for table in registered:
            result.subjects_examined += 1
            trino_id = "hive.%s.%s" % (database, table)
            try:
                record = read_registration_record(s3_client, bucket, project, table)
            except Exception:  # noqa: BLE001
                LOGGER.exception("registration read failed for %s", trino_id)
                continue
            if record is None:
                continue

            sharding = sharding_constant_for(trino_id)
            violation = full_refresh_violation(record, sharding)
            examined_detail.append(
                {
                    "table": trino_id,
                    "file_count": record.get("file_count"),
                    "previous_file_count": record.get("previous_file_count"),
                    "byte_count": record.get("byte_count"),
                    "previous_byte_count": record.get("previous_byte_count"),
                    "sharding_constant": sharding,
                    "conformant": violation is None,
                }
            )
            if violation is None:
                continue

            kind, summary = violation
            result.findings.append(
                Finding(
                    check=CHECK_5,
                    subject=trino_id,
                    severity=SEVERITY_BREACH,
                    kind=kind,
                    summary=summary,
                    observed={
                        "file_count": record.get("file_count"),
                        "previous_file_count": record.get("previous_file_count"),
                        "byte_count": record.get("byte_count"),
                        "previous_byte_count": record.get("previous_byte_count"),
                        "write_seq": record.get("write_seq"),
                    },
                    expected={"file_count_max": sharding},
                    steps_to_duplicate=[
                        "aws s3 ls %s --recursive --profile product-lead --region us-west-2"
                        % (record.get("location") or ""),
                        "aws s3 cp s3://%s/%s/%s/%s.json - --profile product-lead"
                        % (bucket, REGISTRATION_PREFIX, project, table),
                    ],
                    remediation=(
                        "File count must track DATA SIZE, never write count. A count that "
                        "grows per refresh is snapshot-per-mutation partitioning, which "
                        "ends in partition explosion. Fix the export job to overwrite at a "
                        "constant key; do not raise the sharding constant to make the "
                        "check pass."
                    ),
                    references=["DOC-1E1EC5B7CE02", "DOC-F56858AFE749 obligation 2"],
                )
            )

    result.detail["tables"] = examined_detail
    return result


def full_refresh_violation(
    record: Dict[str, Any], sharding_constant: int = DEFAULT_SHARDING_CONSTANT
) -> Optional[Tuple[str, str]]:
    """(kind, summary) when the record violates full-refresh semantics, else None.

    Mirrors ``RegistrationRecord.full_refresh_violation`` in the B2-R2 shared
    library, but operates on the PERSISTED dict rather than the live dataclass --
    the monitor reads records written by other jobs, at other times, from a
    library version it does not control.
    """
    file_count = record.get("file_count")
    trino_id = record.get("trino_identifier") or record.get("table") or "<unknown>"
    if not isinstance(file_count, int):
        return None

    if file_count > sharding_constant:
        return (
            "file_count_exceeds_sharding_constant",
            "%s holds %d objects against a declared sharding constant of %d"
            % (trino_id, file_count, sharding_constant),
        )

    previous = record.get("previous_file_count")
    if isinstance(previous, int) and file_count > previous:
        previous_bytes = record.get("previous_byte_count") or 0
        byte_count = record.get("byte_count") or 0
        if byte_count <= previous_bytes:
            return (
                "file_count_grew_without_data",
                "%s file_count grew %d -> %d while byte_count did not (%d -> %d): "
                "the signature of snapshot-per-mutation partitioning"
                % (trino_id, previous, file_count, previous_bytes, byte_count),
            )
    return None
