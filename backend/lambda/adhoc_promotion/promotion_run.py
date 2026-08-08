"""Execute one promotion: quarantine in, governed table out.

DVP-TSK-687. BRD B5-R2 step 3.

The whole point of this module is what it does NOT contain. There is no Parquet
writer here, no ``create_table`` call, no S3 key spelled by hand, no Glue
``StorageDescriptor`` assembled locally. Every one of those lives in
``enceladus_shared.warehouse_registration`` and is reached through exactly one
function, ``register_table`` -- the same function the finance export job and the
governance mart call.

That is the criterion "the promoted table is indistinguishable from one produced
by a project export job", and it is satisfied structurally rather than by
inspection: the two paths are not similar, they are the same code. A promoted
table's S3 layout, Glue TableInput, Trino identifier, freshness column and
registration sidecar are all computed by the library from the contract, so there
is no local spelling that could drift from the export jobs' spelling.

Order of operations, and why:

    load (read-only)  ->  validate types  ->  coerce ALL rows (memory)  ->
    register_table  ->  registration record

Coercion completes in memory before a single AWS write is attempted. All-or-
nothing is therefore a property of the control flow rather than a rollback: there
is no path on which some rows are written and then a later row fails.

Provenance and freshness carry through rather than being regenerated. A governed
table that reported its own promotion time as its freshness would be claiming the
DATA is as fresh as the transform, which is false and would quietly mislead every
staleness check downstream. So the promoted table's ``ingest_ts`` is the
quarantined table's upload time, and the origin of the data is written into the
table comment where it survives independently of this run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

try:  # deployed: vendored flat by .build_extras
    from enceladus_shared.warehouse_registration import (
        ALLOWED_TYPE_PATTERN,
        DEFAULT_FRESHNESS_COLUMN,
        FRESHNESS_COLUMN_TYPE,
        ColumnSpec,
        ContractViolation,
        build_contract,
        register_table,
        utc_timestamp,
    )
except ImportError:  # pragma: no cover - import shim, see .build_extras
    from warehouse_registration import (  # type: ignore[no-redef]
        ALLOWED_TYPE_PATTERN,
        DEFAULT_FRESHNESS_COLUMN,
        FRESHNESS_COLUMN_TYPE,
        ColumnSpec,
        ContractViolation,
        build_contract,
        register_table,
        utc_timestamp,
    )

from promotion_coerce import PromotionCoercionError, coerce_rows
from promotion_plan import PLAN_SAMPLE_LIMIT, build_plan
from promotion_source import ADHOC_DATABASE, PromotionSourceError, load_quarantined_table

__all__ = [
    "WAREHOUSE_BUCKET",
    "PromotionRefused",
    "PromotionResult",
    "plan_promotion",
    "promote",
]

#: The governed warehouse bucket. Same bucket as the quarantine prefix, different
#: prefix -- ``warehouse/<project>/<table>/`` versus ``adhoc/<table>/``.
WAREHOUSE_BUCKET = os.environ.get("WAREHOUSE_BUCKET", "devops-agentcli-compute")


class PromotionRefused(Exception):
    """The request was rejected before any data was read or written."""


@dataclass
class PromotionResult:
    """What one successful promotion produced."""

    source_identifier: str
    target_identifier: str
    s3_uri: str
    row_count: int
    byte_count: int
    file_count: int
    write_timestamp: str
    freshness_value: str
    created: bool
    write_seq: int
    provenance: Dict[str, str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "promoted": True,
            "source": self.source_identifier,
            "target": self.target_identifier,
            "s3_uri": self.s3_uri,
            "row_count": self.row_count,
            "byte_count": self.byte_count,
            "file_count": self.file_count,
            "write_timestamp": self.write_timestamp,
            "freshness_value": self.freshness_value,
            "created": self.created,
            "write_seq": self.write_seq,
            "provenance": self.provenance,
        }


def _validate_target(project: str, table: str) -> None:
    """A promotion that stayed in quarantine would not be a promotion."""
    if (project or "").strip().lower() in ("adhoc", ADHOC_DATABASE.lower()):
        raise PromotionRefused(
            "target project %r is the quarantine namespace itself. Promotion moves a "
            "table OUT of hive.adhoc into a governed schema (DOC-FF843F9F0E2C); "
            "promoting into adhoc would be a no-op wearing a governance label." % project
        )
    if not table:
        raise PromotionRefused("a target table name is required")


def _validate_type_map(type_map: Mapping[str, str], freshness_column: str) -> Dict[str, str]:
    """Every declared type must be a legal SQL type before anything is read."""
    if not type_map:
        raise PromotionRefused(
            "no type map was submitted. Promotion is a declared, typed transform: io "
            "reviews the pre-populated map (DVP-TSK-685) and sends it back. There is no "
            "path in which the platform picks the types on io's behalf."
        )
    validated: Dict[str, str] = {}
    for column, declared in type_map.items():
        normalized = (declared or "").strip().lower()
        if not ALLOWED_TYPE_PATTERN.match(normalized):
            raise PromotionRefused(
                "column %r declares type %r, which is not a permitted SQL type. Declared "
                "types are SQL types, never pandas dtypes -- that distinction is the "
                "reason this transform exists." % (column, declared)
            )
        validated[column] = normalized

    if freshness_column not in validated:
        validated[freshness_column] = FRESHNESS_COLUMN_TYPE
    return validated


def _freshness_value(source, explicit: Optional[str]) -> str:
    """The DATA's arrival time, not this run's.

    Preference order: an explicit value io supplied, then the quarantined
    table's recorded upload time, then its catalog creation time. Falling back to
    "now" is last and is the only branch that loses information -- it is taken
    only when the source carries no timestamp at all.
    """
    if explicit:
        return explicit
    provenance = source.provenance()
    for key in ("uploaded_at", "upload_timestamp", "source_created_at"):
        value = provenance.get(key)
        if value:
            return str(value)
    return utc_timestamp()


def _table_comment(source, freshness: str) -> str:
    """Provenance, written where it outlives this invocation."""
    provenance = source.provenance()
    parts = [
        "Promoted from %s (BRD B5-R2, DOC-FF843F9F0E2C)." % source.trino_identifier,
        "source_location=%s" % source.location,
        "source_freshness=%s" % freshness,
    ]
    for key in ("uploaded_by", "upload_user", "superset_user", "source_file", "original_filename"):
        value = provenance.get(key)
        if value:
            parts.append("%s=%s" % (key, value))
    return " ".join(parts)


def plan_promotion(
    glue_client,
    s3_client,
    source_table: str,
    target_project: str,
    target_table: Optional[str] = None,
    database: str = ADHOC_DATABASE,
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
):
    """DVP-TSK-685: the pre-populated draft io reviews. Reads only."""
    _validate_target(target_project, target_table or source_table)
    source = load_quarantined_table(
        glue_client, s3_client, source_table, database, sample_limit=PLAN_SAMPLE_LIMIT
    )
    return build_plan(source, target_project, target_table, freshness_column)


def promote(
    glue_client,
    s3_client,
    source_table: str,
    target_project: str,
    type_map: Mapping[str, str],
    target_table: Optional[str] = None,
    database: str = ADHOC_DATABASE,
    bucket: str = "",
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
    freshness_value: Optional[str] = None,
    table_comment: str = "",
) -> PromotionResult:
    """DVP-TSK-686 + 687: coerce all-or-nothing, then write through the library."""
    target = target_table or source_table
    _validate_target(target_project, target)
    declared = _validate_type_map(type_map, freshness_column)

    # -- read the WHOLE table. A sampled all-or-nothing gate is not one. ------
    source = load_quarantined_table(glue_client, s3_client, source_table, database, sample_limit=None)

    # The freshness column is synthesized rather than declared by io, so it is
    # legitimately absent from the source when the quarantined table never had
    # one. Every OTHER column in the map must exist.
    unknown = [
        column
        for column in declared
        if column not in source.column_names and column != freshness_column
    ]
    if unknown:
        raise PromotionRefused(
            "the type map declares column(s) %s which do not exist in %s. Columns: %s"
            % (", ".join(sorted(unknown)), source.trino_identifier, ", ".join(source.column_names))
        )

    stamp = _freshness_value(source, freshness_value)

    # -- coerce everything in memory. Nothing has touched AWS yet. -----------
    coerced = coerce_rows(
        source.rows,
        declared,
        table=source.trino_identifier,
        freshness_column=freshness_column,
        freshness_value=stamp,
    )

    columns = [
        ColumnSpec(name=column, type=declared[column])
        for column in declared
        if column != freshness_column
    ]
    columns.append(
        ColumnSpec(
            name=freshness_column,
            type=FRESHNESS_COLUMN_TYPE,
            comment="upload time of the quarantined source, carried through on promotion",
        )
    )

    # -- validate against the warehouse contract BEFORE writing. -------------
    build_contract(
        project=target_project,
        table=target,
        columns=columns,
        bucket=bucket or WAREHOUSE_BUCKET,
        freshness_column=freshness_column,
    )

    record = register_table(
        project=target_project,
        table=target,
        rows=coerced,
        columns=columns,
        bucket=bucket or WAREHOUSE_BUCKET,
        freshness_column=freshness_column,
        table_comment=table_comment or _table_comment(source, stamp),
        stamp_freshness=False,  # the DATA's freshness, not the transform's
        s3_client=s3_client,
        glue_client=glue_client,
    )

    return PromotionResult(
        source_identifier=source.trino_identifier,
        target_identifier=record.trino_identifier,
        s3_uri=record.s3_uri,
        row_count=record.row_count,
        byte_count=record.byte_count,
        file_count=record.file_count,
        write_timestamp=record.write_timestamp,
        freshness_value=stamp,
        created=record.created,
        write_seq=record.write_seq,
        provenance=source.provenance(),
    )
