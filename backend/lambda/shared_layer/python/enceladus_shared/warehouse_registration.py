"""Enceladus warehouse (T2) contract and shared registration library.

BRD requirement B2-R2 (DOC-724C3695059F). Governed by:

  DOC-04AF8A02A8F7  Four-tier reference architecture (T0/T1/T2/T3)
  DOC-5E35E14DAD05  Prohibition on inferred schema discovery (no Glue crawlers)
  DOC-1E1EC5B7CE02  Full-refresh partitioning discipline

This module is the single sanctioned way for Enceladus code to put a table into
the governed warehouse. Its callers are:

  * project export jobs (``finance`` is the reference implementation and first caller)
  * the governance analytics mart refresh job (BRD B3)
  * project mart onboarding (BRD B4)
  * the ad-hoc promotion transform (BRD B5-R2)

Superset's native file-upload path is NOT a caller -- Superset owns its own
Trino DDL code path -- but it is held to the same conventions. Everything a
non-caller must agree with is exported here as a checkable constant or a
validator, so agreement can be enforced by configuration and permission rather
than by convention (BRD B2-R2 ``not_a_caller_but_equivalent``).

THE CONTRACT (fixed and published; changing any clause is a governed change)
---------------------------------------------------------------------------

Layout      ``s3://<bucket>/warehouse/<project>/<table>/data.parquet``
            Exactly one deterministic object key per table. The key is a
            constant, so a full refresh overwrites it in place and the file
            count is invariant at 1 regardless of how many times the export has
            run (DOC-1E1EC5B7CE02). File count tracks data size, never write
            count.
Format      Parquet, snappy compression, declared explicitly. Trino 414
            defaults to ORC when ``hive.storage-format`` is unset (BRD B2-R6),
            so the format is never inherited or assumed.
Registration
            DECLARED. The caller passes a schema; the library writes it to the
            Glue Data Catalog. A Glue crawler may never be the mechanism by
            which a table Trino serves gets its schema (DOC-5E35E14DAD05).
Refresh     Full-refresh overwrite per table. No snapshot-per-mutation
            partitioning. A table that genuinely exceeds the full-refresh
            envelope must carry a recorded per-table governed exception.
Required column
            Every table carries a freshness stamp -- MANDATORY, not optional.
            Default ``ingest_ts``. It must appear in the declared schema; the
            library injects the value on every row of every write.
Naming      project, table, and column identifiers are lowercase
            ``snake_case`` matching the patterns below. Mixed case is rejected
            rather than silently folded, because Glue folds and Trino does not,
            and the disagreement surfaces as a table that registers but will
            not select.
Addressing  ``hive.<project>.<table>``. The Glue database name is the project
            name with ``-`` folded to ``_``.
Types       Declared Hive/Trino SQL types from ``ALLOWED_TYPE_PATTERN``. Never
            pandas dtypes. ``DECIMAL`` is reachable here, which is exactly what
            the Superset upload dialog cannot offer (DOC-5E35E14DAD05) and
            therefore the reason the promotion transform (B5-R2) exists.

THE FUNCTION (semantics; implementation in this module)
-------------------------------------------------------

    register_table(
        *,
        project: str,
        table: str,
        rows: RowSource,               # list[dict] | pandas.DataFrame | pyarrow.Table
        columns: Sequence[ColumnSpec], # the DECLARED schema; never inferred
        bucket: str,
        database: str | None = None,
        freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
        write_timestamp: datetime | None = None,
        base_prefix: str = WAREHOUSE_PREFIX,
        table_comment: str = "",
        emit_record: bool = True,
        prune_stale: bool = False,
        s3_client=None,
        glue_client=None,
    ) -> RegistrationRecord

Inputs
    ``rows`` may be a list of mappings, a pandas ``DataFrame``, or a pyarrow
    ``Table``. Values are projected onto the DECLARED schema: a declared column
    absent from the data becomes NULL, and a data column absent from the
    declaration is dropped. Declaration wins, always -- that is what makes this
    a schema function rather than a schema estimator.

Output
    A ``RegistrationRecord`` carrying table identity, row count, byte count,
    file count, write timestamp, and content digest (BRD B2-R2 ``properties``).

Idempotency
    Deterministic in ``(rows, columns, write_timestamp)``. Two invocations with
    the same three produce byte-identical Parquet, so the second is a no-op: the
    library digests the candidate object, compares it to the object already at
    the canonical key, and skips the ``PutObject`` when they match
    (``storage_changed=False``). The Glue definition is likewise compared field
    by field and only written when it actually differs
    (``catalog_changed=False``). Repeated invocation therefore leaves both
    catalog and storage state unchanged, byte for byte.

    Note that ``write_timestamp`` defaults to "now", and the freshness stamp is
    part of the data -- so a caller who wants observable idempotency must pass
    an explicit ``write_timestamp``. This is deliberate: a scheduled refresh
    SHOULD produce a new freshness stamp, and a replay SHOULD NOT.

Failure behaviour (transactional in intent)
    1. Validation and Parquet serialization happen entirely in memory. A bad
       schema, a bad identifier, or an unencodable value raises before anything
       in S3 or Glue is touched.
    2. The data object is written first, as a single atomic ``PutObject``. S3
       PutObject is all-or-nothing, so a failed write leaves the previous
       generation of the table intact and readable.
    3. The catalog is written only after the data write has succeeded. A
       registered table therefore never points at absent or partial data. The
       reverse ordering failure -- catalog updated, data missing -- is
       unreachable by construction.
    4. If the catalog write fails, the data is present and the catalog still
       describes the previous generation. Queries return the previous schema
       over the new data rather than erroring on a missing prefix, and the
       raised ``CatalogWriteError`` names the table so the caller can retry.
       Retry is safe because step 2 is idempotent.

Exceptions
    All failures raised by this module derive from ``WarehouseContractError``.
    ``ContractViolation`` means the CALLER asked for something the contract
    forbids and no retry will help. ``StorageWriteError`` and
    ``CatalogWriteError`` mean an AWS call failed and retry is safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Contract constants. Everything the Superset upload path and the promotion
# transform must agree with is here, importable and checkable.
# ---------------------------------------------------------------------------

#: Base S3 prefix for the governed warehouse tier (T2).
WAREHOUSE_PREFIX = "warehouse"

#: The single deterministic object name under a table prefix. A constant key is
#: what makes full-refresh overwrite produce an invariant file count of 1.
DATA_OBJECT_NAME = "data.parquet"

#: Storage format. Declared explicitly, never inherited from Trino defaults.
STORAGE_FORMAT = "parquet"
PARQUET_COMPRESSION = "snappy"

#: Hive storage descriptor triple that Trino's hive connector reads Parquet
#: with. Matches the live ``finance`` production tables exactly.
HIVE_INPUT_FORMAT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
HIVE_OUTPUT_FORMAT = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
HIVE_SERDE_LIBRARY = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"

#: Trino catalog that fronts the Glue Data Catalog. Addressing is
#: ``<catalog>.<database>.<table>``.
TRINO_CATALOG = "hive"

#: Mandatory freshness stamp. T2 tables carry one; this is not optional.
DEFAULT_FRESHNESS_COLUMN = "ingest_ts"

#: Freshness stamps are ISO-8601 UTC strings, not Hive ``timestamp``. This
#: matches the live ``finance`` warehouse (``created_at``/``updated_at`` are
#: declared ``string``) and sidesteps the Parquet int96-vs-micros ambiguity that
#: makes Hive ``timestamp`` round-trip differently across writers.
FRESHNESS_COLUMN_TYPE = "string"

#: Types a freshness stamp may be declared as. ``string`` is the norm.
ALLOWED_FRESHNESS_TYPES = ("string", "timestamp", "date")

#: Glue table parameters. ``classification`` is what makes the table legible to
#: the rest of the Glue tooling; ``EXTERNAL`` keeps DROP from deleting data.
GLUE_TABLE_TYPE = "EXTERNAL_TABLE"
GLUE_TABLE_PARAMETERS = {"classification": STORAGE_FORMAT, "EXTERNAL": "TRUE"}

#: Identifier patterns. Lowercase only -- Glue folds identifiers and Trino does
#: not, so a mixed-case name registers and then fails to select.
PROJECT_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
TABLE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
COLUMN_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

#: Declared SQL types. Scalars, parameterised scalars, and the three complex
#: constructors. Never a pandas dtype.
ALLOWED_TYPE_PATTERN = re.compile(
    r"^(?:"
    r"boolean|tinyint|smallint|int|integer|bigint|float|real|double|"
    r"string|binary|date|timestamp|"
    r"decimal\(\s*\d{1,2}\s*,\s*\d{1,2}\s*\)|"
    r"varchar\(\s*\d{1,5}\s*\)|char\(\s*\d{1,3}\s*\)|"
    r"array<.+>|map<.+>|struct<.+>"
    r")$"
)

#: Column names that break Hive/Trino DDL or collide with the partition
#: machinery. Rejected up front rather than at query time.
RESERVED_COLUMN_NAMES = frozenset(
    {
        "table",
        "select",
        "from",
        "where",
        "group",
        "order",
        "by",
        "partition",
        "location",
        "timestamp",
        "date",
        "values",
        "exists",
        "current_date",
        "current_time",
        "current_timestamp",
    }
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class WarehouseContractError(Exception):
    """Base class for every failure this module raises."""


class ContractViolation(WarehouseContractError):
    """The caller asked for something the contract forbids. Retry will not help."""


class StorageWriteError(WarehouseContractError):
    """The S3 data write failed. The previous generation is intact; retry is safe."""


class CatalogWriteError(WarehouseContractError):
    """The Glue catalog write failed. Data is written; retry is safe and idempotent."""


# ---------------------------------------------------------------------------
# Declared schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnSpec:
    """One DECLARED column. Name and SQL type are both required.

    There is no inference path into this object. That is the point: the schema
    is a value the caller commits to in code and in a commit, not an estimate a
    crawler produced by sampling S3 (DOC-5E35E14DAD05).
    """

    name: str
    type: str
    comment: str = ""

    def validate(self) -> None:
        if not COLUMN_NAME_PATTERN.match(self.name or ""):
            raise ContractViolation(
                "column name %r violates the contract: must match %s "
                "(lowercase snake_case, leading letter)"
                % (self.name, COLUMN_NAME_PATTERN.pattern)
            )
        if self.name in RESERVED_COLUMN_NAMES:
            raise ContractViolation(
                "column name %r is reserved and would break Hive/Trino DDL" % self.name
            )
        normalized = (self.type or "").strip().lower()
        if not ALLOWED_TYPE_PATTERN.match(normalized):
            raise ContractViolation(
                "column %r declares type %r, which is not a permitted SQL type. "
                "Declared types are SQL types, never pandas dtypes." % (self.name, self.type)
            )

    def as_glue_column(self) -> Dict[str, str]:
        column: Dict[str, str] = {"Name": self.name, "Type": (self.type or "").strip().lower()}
        if self.comment:
            column["Comment"] = self.comment
        return column


# ---------------------------------------------------------------------------
# Table contract
# ---------------------------------------------------------------------------


def glue_database_for(project: str) -> str:
    """Glue database name for a project. Hyphens fold to underscores."""
    return project.replace("-", "_")


def validate_project_name(project: str) -> str:
    if not PROJECT_NAME_PATTERN.match(project or ""):
        raise ContractViolation(
            "project %r violates the contract: must match %s"
            % (project, PROJECT_NAME_PATTERN.pattern)
        )
    return project


def validate_table_name(table: str) -> str:
    if not TABLE_NAME_PATTERN.match(table or ""):
        raise ContractViolation(
            "table %r violates the contract: must match %s"
            % (table, TABLE_NAME_PATTERN.pattern)
        )
    return table


@dataclass(frozen=True)
class TableContract:
    """The fully resolved contract for one warehouse table.

    Constructing this object is what validates a caller's intent. Every derived
    address -- S3 prefix, S3 key, Glue location, Trino identifier -- is computed
    here from the constants above so that no caller can spell any of them
    differently.
    """

    project: str
    table: str
    bucket: str
    columns: Tuple[ColumnSpec, ...]
    database: str = ""
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN
    base_prefix: str = WAREHOUSE_PREFIX
    table_comment: str = ""

    def __post_init__(self) -> None:
        validate_project_name(self.project)
        validate_table_name(self.table)
        if not self.bucket:
            raise ContractViolation("bucket is required")
        if not self.columns:
            raise ContractViolation(
                "a declared schema is required; an empty column list would make this "
                "a schema estimator, which the contract prohibits"
            )

        seen = set()
        for column in self.columns:
            column.validate()
            if column.name in seen:
                raise ContractViolation("duplicate column %r in declared schema" % column.name)
            seen.add(column.name)

        if not COLUMN_NAME_PATTERN.match(self.freshness_column or ""):
            raise ContractViolation(
                "freshness column %r violates the column naming contract" % self.freshness_column
            )
        if self.freshness_column not in seen:
            raise ContractViolation(
                "declared schema for %s.%s is missing the mandatory freshness stamp column %r. "
                "Every T2 table carries one (DOC-04AF8A02A8F7)."
                % (self.project, self.table, self.freshness_column)
            )
        freshness_type = self.column_type(self.freshness_column)
        if freshness_type not in ALLOWED_FRESHNESS_TYPES:
            raise ContractViolation(
                "freshness column %r is declared %r; permitted types are %s"
                % (self.freshness_column, freshness_type, ", ".join(ALLOWED_FRESHNESS_TYPES))
            )

        if not self.database:
            object.__setattr__(self, "database", glue_database_for(self.project))

    # -- derived addresses -------------------------------------------------

    @property
    def column_names(self) -> Tuple[str, ...]:
        return tuple(column.name for column in self.columns)

    def column_type(self, name: str) -> str:
        for column in self.columns:
            if column.name == name:
                return (column.type or "").strip().lower()
        raise ContractViolation("column %r is not in the declared schema" % name)

    @property
    def s3_prefix(self) -> str:
        """``warehouse/<project>/<table>/`` -- always with a trailing slash."""
        return "%s/%s/%s/" % (self.base_prefix.strip("/"), self.project, self.table)

    @property
    def s3_key(self) -> str:
        """The one canonical data object key for this table."""
        return self.s3_prefix + DATA_OBJECT_NAME

    @property
    def s3_uri(self) -> str:
        return "s3://%s/%s" % (self.bucket, self.s3_key)

    @property
    def location(self) -> str:
        """Glue ``StorageDescriptor.Location`` -- the PREFIX, not the object."""
        return "s3://%s/%s" % (self.bucket, self.s3_prefix)

    @property
    def trino_identifier(self) -> str:
        """``hive.<project>.<table>`` -- how a Superset dataset addresses this."""
        return "%s.%s.%s" % (TRINO_CATALOG, self.database, self.table)

    @property
    def is_governed_layout(self) -> bool:
        """True when this table sits at the governed T2 prefix.

        ``base_prefix`` is overridable so tests and scratch probes can target an
        isolated prefix, but a governed table must be at ``warehouse/``. The
        registration record carries this flag so the B6-R2 monitor can flag a
        table that registered itself outside the contract layout.
        """
        return self.base_prefix.strip("/") == WAREHOUSE_PREFIX

    # -- catalog projection ------------------------------------------------

    def glue_table_input(self) -> Dict[str, Any]:
        """The Glue ``TableInput`` this contract declares.

        Deterministic: same contract in, same dict out, every time. This is the
        published storage-format declaration -- the Superset DDL path and the
        promotion transform are held against exactly this shape.
        """
        table_input: Dict[str, Any] = {
            "Name": self.table,
            "TableType": GLUE_TABLE_TYPE,
            "Parameters": dict(GLUE_TABLE_PARAMETERS),
            "StorageDescriptor": {
                "Columns": [column.as_glue_column() for column in self.columns],
                "Location": self.location,
                "InputFormat": HIVE_INPUT_FORMAT,
                "OutputFormat": HIVE_OUTPUT_FORMAT,
                "Compressed": False,
                "NumberOfBuckets": 0,
                "SerdeInfo": {
                    "SerializationLibrary": HIVE_SERDE_LIBRARY,
                    "Parameters": {"serialization.format": "1"},
                },
                "SortColumns": [],
                "StoredAsSubDirectories": False,
            },
            "PartitionKeys": [],
        }
        if self.table_comment:
            table_input["Description"] = self.table_comment
        return table_input


def build_contract(
    *,
    project: str,
    table: str,
    columns: Sequence[ColumnSpec],
    bucket: str,
    database: Optional[str] = None,
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
    base_prefix: str = WAREHOUSE_PREFIX,
    table_comment: str = "",
) -> TableContract:
    """Validate a caller's intent and resolve it to a ``TableContract``.

    Raises ``ContractViolation`` on any disagreement with the published
    conventions. Callers that only want to CHECK conformance -- the Superset
    path, the promotion transform, the B6-R2 monitor -- call this and discard
    the result rather than calling ``register_table``.
    """
    return TableContract(
        project=project,
        table=table,
        bucket=bucket,
        columns=tuple(columns),
        database=database or "",
        freshness_column=freshness_column,
        base_prefix=base_prefix,
        table_comment=table_comment,
    )


def columns_from_pairs(pairs: Sequence[Sequence[str]]) -> List[ColumnSpec]:
    """Convenience: ``[("id", "string"), ...]`` -> ``[ColumnSpec(...), ...]``."""
    return [ColumnSpec(name=str(pair[0]), type=str(pair[1])) for pair in pairs]


def freshness_column_spec(name: str = DEFAULT_FRESHNESS_COLUMN) -> ColumnSpec:
    """The mandatory freshness stamp, spelled the one sanctioned way."""
    return ColumnSpec(
        name=name,
        type=FRESHNESS_COLUMN_TYPE,
        comment="UTC ISO-8601 warehouse write timestamp (mandatory T2 freshness stamp)",
    )


def describe_contract() -> Dict[str, Any]:
    """Machine-readable statement of the published conventions.

    Emitted so a non-caller (Superset's DDL path, the promotion transform, the
    B6-R2 health monitor) can assert agreement against a value rather than
    against prose.
    """
    return {
        "layout": "s3://<bucket>/%s/<project>/<table>/%s" % (WAREHOUSE_PREFIX, DATA_OBJECT_NAME),
        "base_prefix": WAREHOUSE_PREFIX,
        "data_object_name": DATA_OBJECT_NAME,
        "storage_format": STORAGE_FORMAT,
        "compression": PARQUET_COMPRESSION,
        "input_format": HIVE_INPUT_FORMAT,
        "output_format": HIVE_OUTPUT_FORMAT,
        "serde": HIVE_SERDE_LIBRARY,
        "table_type": GLUE_TABLE_TYPE,
        "table_parameters": dict(GLUE_TABLE_PARAMETERS),
        "addressing": "%s.<project>.<table>" % TRINO_CATALOG,
        "refresh": "full-refresh overwrite; one object per table; file count invariant at 1",
        "registration": "declared schema written to Glue by this library; crawlers prohibited",
        "required_column": DEFAULT_FRESHNESS_COLUMN,
        "required_column_type": FRESHNESS_COLUMN_TYPE,
        "allowed_freshness_types": list(ALLOWED_FRESHNESS_TYPES),
        "project_name_pattern": PROJECT_NAME_PATTERN.pattern,
        "table_name_pattern": TABLE_NAME_PATTERN.pattern,
        "column_name_pattern": COLUMN_NAME_PATTERN.pattern,
        "allowed_type_pattern": ALLOWED_TYPE_PATTERN.pattern,
        "reserved_column_names": sorted(RESERVED_COLUMN_NAMES),
    }


__all__ = [
    "ALLOWED_FRESHNESS_TYPES",
    "ALLOWED_TYPE_PATTERN",
    "COLUMN_NAME_PATTERN",
    "DATA_OBJECT_NAME",
    "DEFAULT_FRESHNESS_COLUMN",
    "FRESHNESS_COLUMN_TYPE",
    "GLUE_TABLE_PARAMETERS",
    "GLUE_TABLE_TYPE",
    "HIVE_INPUT_FORMAT",
    "HIVE_OUTPUT_FORMAT",
    "HIVE_SERDE_LIBRARY",
    "PARQUET_COMPRESSION",
    "PROJECT_NAME_PATTERN",
    "RESERVED_COLUMN_NAMES",
    "STORAGE_FORMAT",
    "TABLE_NAME_PATTERN",
    "TRINO_CATALOG",
    "WAREHOUSE_PREFIX",
    "CatalogWriteError",
    "ColumnSpec",
    "ContractViolation",
    "StorageWriteError",
    "TableContract",
    "WarehouseContractError",
    "build_contract",
    "columns_from_pairs",
    "describe_contract",
    "freshness_column_spec",
    "glue_database_for",
    "validate_project_name",
    "validate_table_name",
]
