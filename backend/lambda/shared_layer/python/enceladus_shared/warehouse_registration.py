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

import hashlib
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import date as _date
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Contract constants. Everything the Superset upload path and the promotion
# transform must agree with is here, importable and checkable.
# ---------------------------------------------------------------------------

#: Base S3 prefix for the governed warehouse tier (T2).
WAREHOUSE_PREFIX = "warehouse"

#: The single deterministic object name under a table prefix. A constant key is
#: what makes full-refresh overwrite produce an invariant file count of 1.
DATA_OBJECT_NAME = "data.parquet"

#: Suffix that turns a table base prefix into its registration-record sibling:
#: ``warehouse/`` -> ``warehouse-registrations/``.
REGISTRATION_SUFFIX = "registrations"

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
    def registration_prefix(self) -> str:
        """Sibling of the table prefix, never a child of it.

        ``warehouse/`` -> ``warehouse-registrations/``. Derived from
        ``base_prefix`` rather than pinned to the bucket root, so a record always
        stays inside whatever namespace its table lives in -- which matters for
        the quarantine prefix, where escaping the namespace would defeat the
        isolation the quarantine exists to provide. A child prefix is not an
        option: everything under a table prefix is table data by definition, and
        a JSON sidecar there would be read as a corrupt Parquet file.
        """
        return "%s-%s" % (self.base_prefix.strip("/"), REGISTRATION_SUFFIX)

    @property
    def registration_key(self) -> str:
        return registration_record_key(self.project, self.table, self.registration_prefix)

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


# ---------------------------------------------------------------------------
# Row normalisation and Parquet serialization
#
# Everything below happens in memory. Nothing here touches S3 or Glue -- that
# separation is what makes step 1 of the failure contract true: a bad schema, a
# bad identifier, or an unencodable value raises before anything is written.
# ---------------------------------------------------------------------------

#: S3 object metadata key carrying the content digest. Used to make repeated
#: writes observably idempotent without downloading the object.
CONTENT_DIGEST_METADATA_KEY = "content-sha256"

_ISO_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_timestamp(moment: Optional[datetime] = None) -> str:
    """The one sanctioned freshness-stamp spelling: UTC ISO-8601, second grain.

    Second grain rather than microsecond is deliberate -- it keeps the stamp
    stable for callers that derive it once per refresh cycle, and a warehouse
    projection has never needed sub-second write resolution.
    """
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(_ISO_TIMESTAMP_FORMAT)


def _normalize_rows(rows: Any) -> List[Dict[str, Any]]:
    """Accept the three sanctioned row sources and return list-of-dict.

    Duck-typed on purpose: pandas and pyarrow are optional at import time, so
    the library is importable (and its contract checkable) in a Lambda that
    carries neither.
    """
    if rows is None:
        return []
    # pandas.DataFrame
    to_dict = getattr(rows, "to_dict", None)
    if to_dict is not None and hasattr(rows, "columns") and not isinstance(rows, Mapping):
        return list(to_dict(orient="records"))
    # pyarrow.Table
    to_pylist = getattr(rows, "to_pylist", None)
    if to_pylist is not None:
        return list(to_pylist())
    if isinstance(rows, Mapping):
        raise ContractViolation(
            "rows must be a sequence of mappings, a pandas DataFrame, or a pyarrow Table; "
            "a single mapping was passed"
        )
    if isinstance(rows, Iterable):
        normalized = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise ContractViolation("row %d is %s, expected a mapping" % (index, type(row).__name__))
            normalized.append(dict(row))
        return normalized
    raise ContractViolation("unsupported rows type %s" % type(rows).__name__)


def _decimal_params(sql_type: str) -> Tuple[int, int]:
    match = re.match(r"^decimal\(\s*(\d+)\s*,\s*(\d+)\s*\)$", sql_type)
    if not match:  # pragma: no cover - guarded by ALLOWED_TYPE_PATTERN
        raise ContractViolation("malformed decimal type %r" % sql_type)
    return int(match.group(1)), int(match.group(2))


def _arrow_type(sql_type: str):
    """Map a DECLARED SQL type to its Arrow type. No inference anywhere."""
    import pyarrow as pa  # local import: pyarrow is a heavy, optional dependency

    simple = {
        "boolean": pa.bool_(),
        "tinyint": pa.int8(),
        "smallint": pa.int16(),
        "int": pa.int32(),
        "integer": pa.int32(),
        "bigint": pa.int64(),
        "float": pa.float32(),
        "real": pa.float32(),
        "double": pa.float64(),
        "string": pa.string(),
        "binary": pa.binary(),
        "date": pa.date32(),
        "timestamp": pa.timestamp("us"),
    }
    if sql_type in simple:
        return simple[sql_type]
    if sql_type.startswith("decimal("):
        precision, scale = _decimal_params(sql_type)
        return pa.decimal128(precision, scale)
    if sql_type.startswith("varchar(") or sql_type.startswith("char("):
        return pa.string()
    raise ContractViolation(
        "type %r is declarable but not writable by this library. Flatten the column or "
        "declare it as `string` holding JSON." % sql_type
    )


def _coerce_value(column: str, sql_type: str, value: Any) -> Any:
    """Coerce one value to its DECLARED type, or raise naming the offender.

    All-or-nothing, in the same spirit as the B5-R2 promotion transform: a
    partially typed governed table is worse than no table.
    """
    if value is None:
        return None
    try:
        if sql_type == "boolean":
            return bool(value)
        if sql_type in ("tinyint", "smallint", "int", "integer", "bigint"):
            return int(value)
        if sql_type in ("float", "real", "double"):
            return float(value)
        if sql_type.startswith("decimal("):
            _, scale = _decimal_params(sql_type)
            decimal_value = value if isinstance(value, Decimal) else Decimal(str(value))
            return decimal_value.quantize(Decimal(1).scaleb(-scale))
        if sql_type == "date":
            if isinstance(value, datetime):
                return value.date()
            if isinstance(value, _date):
                return value
            return _date.fromisoformat(str(value)[:10])
        if sql_type == "timestamp":
            if isinstance(value, datetime):
                return value
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if sql_type == "binary":
            return value if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
        return str(value)
    except (TypeError, ValueError, ArithmeticError, InvalidOperation) as exc:
        raise ContractViolation(
            "value %r in column %r cannot be coerced to declared type %r: %s"
            % (value, column, sql_type, exc)
        )


def project_rows(
    contract: TableContract, rows: Sequence[Mapping[str, Any]], stamp: str
) -> Dict[str, List[Any]]:
    """Project raw rows onto the DECLARED schema. Declaration always wins.

    A declared column absent from the data becomes NULL. A data column absent
    from the declaration is dropped. That asymmetry is precisely what makes
    this a schema FUNCTION rather than a schema ESTIMATOR (DOC-5E35E14DAD05):
    the output shape depends only on the declaration, never on the sample.
    """
    projected: Dict[str, List[Any]] = {name: [] for name in contract.column_names}
    for row in rows:
        for column in contract.columns:
            if column.name == contract.freshness_column:
                raw = stamp
            else:
                raw = row.get(column.name)
            projected[column.name].append(
                _coerce_value(column.name, column.type.strip().lower(), raw)
            )
    return projected


def serialize_parquet(
    contract: TableContract, rows: Sequence[Mapping[str, Any]], stamp: str
) -> Tuple[bytes, int]:
    """Serialize rows to Parquet bytes in memory. Returns ``(payload, row_count)``.

    Deterministic: the Arrow schema comes from the declaration, the row order
    comes from the caller, and the freshness stamp is a single value applied
    uniformly -- so identical inputs produce byte-identical output.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    projected = project_rows(contract, rows, stamp)
    schema = pa.schema(
        [pa.field(column.name, _arrow_type(column.type.strip().lower())) for column in contract.columns]
    )
    try:
        arrow_table = pa.Table.from_pydict(projected, schema=schema)
    except (pa.ArrowInvalid, pa.ArrowTypeError, pa.ArrowNotImplementedError) as exc:
        raise ContractViolation("rows do not satisfy the declared schema: %s" % exc)

    sink = io.BytesIO()
    pq.write_table(arrow_table, sink, compression=PARQUET_COMPRESSION)
    return sink.getvalue(), arrow_table.num_rows


# ---------------------------------------------------------------------------
# AWS clients (lazy; boto3 is provided by the Lambda runtime)
# ---------------------------------------------------------------------------


def _default_client(service: str, region: Optional[str] = None):
    import boto3
    from botocore.config import Config

    return boto3.client(
        service,
        region_name=region or "us-west-2",
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )


# ---------------------------------------------------------------------------
# Storage: single atomic, idempotent object write
# ---------------------------------------------------------------------------


def _existing_digest(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        head = s3_client.head_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001 - botocore raises a dynamic class
        if _is_not_found(exc):
            return None
        raise StorageWriteError("head_object failed for s3://%s/%s: %s" % (bucket, key, exc))
    metadata = head.get("Metadata") or {}
    return metadata.get(CONTENT_DIGEST_METADATA_KEY)


def _is_not_found(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
    return code in ("404", "NoSuchKey", "NotFound", "EntityNotFoundException") or (
        exc.__class__.__name__ in ("EntityNotFoundException", "NoSuchKey", "ClientError404")
    )


def write_table_object(
    s3_client, contract: TableContract, payload: bytes, digest: str
) -> bool:
    """Write the one canonical object for this table. Returns ``storage_changed``.

    Full-refresh overwrite: the key is a constant, so this replaces the previous
    generation in place and the table's file count stays at 1 no matter how many
    refreshes have run (DOC-1E1EC5B7CE02). ``PutObject`` is atomic, so a failure
    leaves the previous generation intact and readable rather than truncated.
    """
    if _existing_digest(s3_client, contract.bucket, contract.s3_key) == digest:
        return False
    try:
        s3_client.put_object(
            Bucket=contract.bucket,
            Key=contract.s3_key,
            Body=payload,
            ContentType="application/octet-stream",
            ServerSideEncryption="AES256",
            Metadata={CONTENT_DIGEST_METADATA_KEY: digest},
        )
    except Exception as exc:  # noqa: BLE001
        raise StorageWriteError(
            "put_object failed for %s: %s. The previous generation of the table is "
            "intact; retry is safe." % (contract.s3_uri, exc)
        )
    return True


def list_table_objects(s3_client, contract: TableContract) -> List[Dict[str, Any]]:
    """Enumerate objects under the table prefix -- the B6-R2 check-1 primitive."""
    objects: List[Dict[str, Any]] = []
    token = None
    while True:
        kwargs = {"Bucket": contract.bucket, "Prefix": contract.s3_prefix}
        if token:
            kwargs["ContinuationToken"] = token
        response = s3_client.list_objects_v2(**kwargs)
        objects.extend(response.get("Contents") or [])
        if not response.get("IsTruncated"):
            break
        token = response.get("NextContinuationToken")
        if not token:
            break
    return objects


def prune_stale_objects(s3_client, contract: TableContract) -> List[str]:
    """Remove objects under the table prefix that are not the canonical key.

    Opt-in only (``prune_stale=True``), and scoped to this table's own prefix.
    Its single legitimate use is ADOPTING a legacy prefix that accumulated
    snapshot objects under the pre-contract pattern. A table written only by
    this library never needs it -- the constant key makes accumulation
    impossible in the first place.
    """
    stale = [
        obj["Key"]
        for obj in list_table_objects(s3_client, contract)
        if obj.get("Key") and obj["Key"] != contract.s3_key
    ]
    if not stale:
        return []
    for start in range(0, len(stale), 1000):
        batch = stale[start : start + 1000]
        s3_client.delete_objects(
            Bucket=contract.bucket,
            Delete={"Objects": [{"Key": key} for key in batch], "Quiet": True},
        )
    return stale


# ---------------------------------------------------------------------------
# Catalog: declared register-or-update
# ---------------------------------------------------------------------------


def _normalized_catalog_view(table_input: Mapping[str, Any]) -> Dict[str, Any]:
    """The comparable subset of a Glue table definition.

    Glue echoes back server-managed fields (CreateTime, VersionId, CatalogId,
    CreatedBy). Comparing those would make every run report a difference and
    turn a no-op into a write, so the comparison is restricted to the fields
    this contract actually declares.
    """
    storage = table_input.get("StorageDescriptor") or {}
    serde = storage.get("SerdeInfo") or {}
    parameters = table_input.get("Parameters") or {}
    return {
        "TableType": table_input.get("TableType"),
        "Parameters": {key: parameters.get(key) for key in sorted(GLUE_TABLE_PARAMETERS)},
        "Description": table_input.get("Description", ""),
        "Columns": [
            {
                "Name": column.get("Name"),
                "Type": (column.get("Type") or "").strip().lower(),
                "Comment": column.get("Comment", "") or "",
            }
            for column in (storage.get("Columns") or [])
        ],
        "Location": storage.get("Location"),
        "InputFormat": storage.get("InputFormat"),
        "OutputFormat": storage.get("OutputFormat"),
        "SerializationLibrary": serde.get("SerializationLibrary"),
        "SerdeParameters": dict(serde.get("Parameters") or {}),
        "PartitionKeys": [
            {"Name": key.get("Name"), "Type": key.get("Type")}
            for key in (table_input.get("PartitionKeys") or [])
        ],
    }


def register_or_update_glue_table(glue_client, contract: TableContract) -> Tuple[bool, bool]:
    """Write the DECLARED schema to the Glue Data Catalog.

    Returns ``(catalog_changed, created)``. Never invokes a crawler; there is
    no inference path here at all (DOC-5E35E14DAD05). Idempotent: an unchanged
    declaration produces no ``UpdateTable`` call.
    """
    table_input = contract.glue_table_input()
    desired = _normalized_catalog_view(table_input)

    existing = None
    try:
        existing = (glue_client.get_table(DatabaseName=contract.database, Name=contract.table) or {}).get(
            "Table"
        )
    except Exception as exc:  # noqa: BLE001
        if not _is_not_found(exc):
            raise CatalogWriteError(
                "get_table failed for %s: %s" % (contract.trino_identifier, exc)
            )

    if existing is None:
        try:
            glue_client.create_table(DatabaseName=contract.database, TableInput=table_input)
        except Exception as exc:  # noqa: BLE001
            raise CatalogWriteError(
                "create_table failed for %s: %s. Data is written; retry is safe and "
                "idempotent." % (contract.trino_identifier, exc)
            )
        return True, True

    if _normalized_catalog_view(existing) == desired:
        return False, False

    try:
        glue_client.update_table(DatabaseName=contract.database, TableInput=table_input)
    except Exception as exc:  # noqa: BLE001
        raise CatalogWriteError(
            "update_table failed for %s: %s. Data is written and the catalog still "
            "describes the previous generation; retry is safe."
            % (contract.trino_identifier, exc)
        )
    return True, False


# ---------------------------------------------------------------------------
# The registration record
# ---------------------------------------------------------------------------


#: Registration records for the governed warehouse. A SIBLING of the table tree,
#: never a child of it -- see ``TableContract.registration_prefix``.
REGISTRATION_PREFIX = "%s-%s" % (WAREHOUSE_PREFIX, REGISTRATION_SUFFIX)

#: Schema version of the emitted record, so the B6-R2 monitor can evolve with it.
REGISTRATION_RECORD_VERSION = 1

LOGGER = logging.getLogger(__name__)


def registration_record_key(project: str, table: str, prefix: str = REGISTRATION_PREFIX) -> str:
    """``warehouse-registrations/<project>/<table>.json`` -- latest generation only."""
    return "%s/%s/%s.json" % (prefix.strip("/"), project, table)


@dataclass
class RegistrationRecord:
    """What one invocation of ``register_table`` did (BRD B2-R2 ``properties``).

    Carries table, row count, byte count, and write timestamp -- and, because
    the B6-R2 health monitor compares SUCCESSIVE observations, it also carries
    the previous generation's counts and a monotonic ``write_seq``. That is what
    lets the monitor answer checks 1 and 5 from a single GetObject instead of
    re-listing S3 (DOC-1E1EC5B7CE02).
    """

    project: str
    table: str
    database: str
    trino_identifier: str
    s3_uri: str
    location: str
    row_count: int
    byte_count: int
    file_count: int
    write_timestamp: str
    content_sha256: str
    storage_changed: bool
    catalog_changed: bool
    created: bool
    governed_layout: bool
    pruned_objects: Tuple[str, ...] = ()
    prefix_byte_count: int = 0
    write_seq: int = 1
    previous_write_timestamp: str = ""
    previous_row_count: Optional[int] = None
    previous_byte_count: Optional[int] = None
    previous_file_count: Optional[int] = None
    previous_content_sha256: str = ""
    record_version: int = REGISTRATION_RECORD_VERSION

    #: Fields that describe the INVOCATION rather than the generation. They are
    #: returned to the caller and logged, but excluded from the persisted
    #: sidecar -- otherwise a no-op replay would still rewrite the record, and
    #: the record would become the one piece of state that idempotency misses.
    INVOCATION_FIELDS = ("storage_changed", "catalog_changed", "created", "pruned_objects")

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(self.__dict__)
        payload["pruned_objects"] = list(self.pruned_objects)
        return payload

    def generation_payload(self) -> Dict[str, Any]:
        """The persisted view: the state of the TABLE, not the outcome of the call."""
        return {
            key: value
            for key, value in self.to_dict().items()
            if key not in self.INVOCATION_FIELDS
        }

    # -- the two B6-R2 questions, answerable from this record alone ----------

    @property
    def bytes_per_file(self) -> float:
        """Mean object size. The signature check 5 is built on."""
        return float(self.prefix_byte_count) / self.file_count if self.file_count else 0.0

    def full_refresh_violation(self, sharding_constant: int = 1) -> Optional[str]:
        """B6-R2 check 4/5. Returns a reason string, or None when conformant.

        The violation this detects is the specific one: file count growing while
        bytes-per-file stays flat or shrinks, which is snapshot-per-mutation
        partitioning rather than genuine data growth. A table that legitimately
        got bigger shows file count steady and bytes UP.
        """
        if self.file_count > sharding_constant:
            return (
                "file_count=%d exceeds the declared sharding constant %d for %s; "
                "full-refresh overwrite should hold it invariant"
                % (self.file_count, sharding_constant, self.trino_identifier)
            )
        if self.previous_file_count is not None and self.file_count > self.previous_file_count:
            previous_bytes = self.previous_byte_count or 0
            if self.byte_count <= previous_bytes:
                return (
                    "file_count grew %d -> %d for %s while byte_count did not (%d -> %d): "
                    "the signature of snapshot-per-mutation partitioning"
                    % (
                        self.previous_file_count,
                        self.file_count,
                        self.trino_identifier,
                        previous_bytes,
                        self.byte_count,
                    )
                )
        return None


def read_registration_record(
    s3_client, bucket: str, project: str, table: str, prefix: str = REGISTRATION_PREFIX
) -> Optional[Dict[str, Any]]:
    """Fetch the latest registration record. The B6-R2 monitor's read path.

    One GetObject answers both the freshness question (check 1) and the
    file-count-versus-data-size question (check 5). Returns None when the table
    has never been registered by this library.
    """
    key = registration_record_key(project, table, prefix)
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
    except Exception as exc:  # noqa: BLE001
        if _is_not_found(exc):
            return None
        raise StorageWriteError("get_object failed for s3://%s/%s: %s" % (bucket, key, exc))
    return json.loads(response["Body"].read().decode("utf-8"))


def emit_registration_record(
    s3_client, bucket: str, record: RegistrationRecord, prefix: str = REGISTRATION_PREFIX
) -> str:
    """Persist the record and log it. Returns the key it was written to.

    Two channels on purpose: the S3 object is the durable signal the health
    monitor polls, and the structured log line is what makes a single refresh
    traceable in CloudWatch without a catalog round trip.
    """
    key = registration_record_key(record.project, record.table, prefix)
    payload = json.dumps(
        record.generation_payload(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=payload,
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
    except Exception as exc:  # noqa: BLE001
        raise StorageWriteError(
            "failed to emit the registration record to s3://%s/%s: %s. The table data and "
            "catalog are both written; retry is safe." % (bucket, key, exc)
        )
    LOGGER.info("warehouse_registration %s", json.dumps(record.to_dict(), sort_keys=True))
    return key


# ---------------------------------------------------------------------------
# The one function
# ---------------------------------------------------------------------------


def register_table(
    *,
    project: str,
    table: str,
    rows: Any,
    columns: Sequence[ColumnSpec],
    bucket: str,
    database: Optional[str] = None,
    freshness_column: str = DEFAULT_FRESHNESS_COLUMN,
    write_timestamp: Optional[datetime] = None,
    base_prefix: str = WAREHOUSE_PREFIX,
    table_comment: str = "",
    emit_record: bool = True,
    prune_stale: bool = False,
    s3_client: Any = None,
    glue_client: Any = None,
    region: Optional[str] = None,
) -> RegistrationRecord:
    """Write a table to the governed warehouse and register its declared schema.

    One idempotent, deterministic operation. See the module docstring for the
    full contract; the ordering below is the contract's transactional intent
    made literal:

        validate + serialize (memory)  ->  atomic PutObject  ->  Glue write

    Nothing reaches AWS until the payload is fully materialised, and the
    catalog is never written before the data it describes exists.
    """
    contract = build_contract(
        project=project,
        table=table,
        columns=columns,
        bucket=bucket,
        database=database,
        freshness_column=freshness_column,
        base_prefix=base_prefix,
        table_comment=table_comment,
    )

    # -- 1. in-memory: validate and serialize. Nothing has been touched yet. --
    stamp = utc_timestamp(write_timestamp)
    payload, row_count = serialize_parquet(contract, _normalize_rows(rows), stamp)
    digest = hashlib.sha256(payload).hexdigest()

    s3_client = s3_client or _default_client("s3", region)
    glue_client = glue_client or _default_client("glue", region)

    previous = read_registration_record(
        s3_client, contract.bucket, contract.project, contract.table, contract.registration_prefix
    )

    # -- 2. data first, as a single atomic overwrite of the canonical key. ----
    storage_changed = write_table_object(s3_client, contract, payload, digest)

    pruned: List[str] = []
    if prune_stale:
        pruned = prune_stale_objects(s3_client, contract)

    # -- 3. catalog only after the data it describes is known to exist. ------
    catalog_changed, created = register_or_update_glue_table(glue_client, contract)

    # -- 4. measure what is actually on the prefix, then emit the record. ----
    # Measured, not assumed: a file_count the library asserted would be useless
    # to the very check it exists to feed.
    stored = list_table_objects(s3_client, contract)

    # A GENERATION is a change to storage or catalog, not an invocation. A
    # replay that changed nothing must not advance write_seq or rewrite the
    # previous-generation fields -- otherwise the record would be the one piece
    # of state that a no-op still mutates, and "repeated invocation leaves
    # storage state unchanged" would stop being literally true.
    previous = previous or {}
    new_generation = storage_changed or catalog_changed
    if new_generation:
        write_seq = int(previous.get("write_seq") or 0) + 1
        prior = previous
    else:
        write_seq = int(previous.get("write_seq") or 1)
        prior = {
            "write_timestamp": previous.get("previous_write_timestamp") or "",
            "row_count": previous.get("previous_row_count"),
            "byte_count": previous.get("previous_byte_count"),
            "file_count": previous.get("previous_file_count"),
            "content_sha256": previous.get("previous_content_sha256") or "",
        }

    record = RegistrationRecord(
        project=contract.project,
        table=contract.table,
        database=contract.database,
        trino_identifier=contract.trino_identifier,
        s3_uri=contract.s3_uri,
        location=contract.location,
        row_count=row_count,
        byte_count=len(payload),
        file_count=len(stored),
        write_timestamp=stamp,
        content_sha256=digest,
        storage_changed=storage_changed,
        catalog_changed=catalog_changed,
        created=created,
        governed_layout=contract.is_governed_layout,
        pruned_objects=tuple(pruned),
        prefix_byte_count=sum(int(obj.get("Size") or 0) for obj in stored),
        write_seq=write_seq,
        previous_write_timestamp=prior.get("write_timestamp") or "",
        previous_row_count=prior.get("row_count"),
        previous_byte_count=prior.get("byte_count"),
        previous_file_count=prior.get("file_count"),
        previous_content_sha256=prior.get("content_sha256") or "",
    )

    if emit_record:
        emit_registration_record(
            s3_client, contract.bucket, record, contract.registration_prefix
        )

    return record


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
    "REGISTRATION_PREFIX",
    "REGISTRATION_RECORD_VERSION",
    "RESERVED_COLUMN_NAMES",
    "STORAGE_FORMAT",
    "TABLE_NAME_PATTERN",
    "TRINO_CATALOG",
    "WAREHOUSE_PREFIX",
    "CONTENT_DIGEST_METADATA_KEY",
    "CatalogWriteError",
    "ColumnSpec",
    "ContractViolation",
    "RegistrationRecord",
    "StorageWriteError",
    "TableContract",
    "WarehouseContractError",
    "build_contract",
    "columns_from_pairs",
    "describe_contract",
    "emit_registration_record",
    "freshness_column_spec",
    "glue_database_for",
    "list_table_objects",
    "project_rows",
    "read_registration_record",
    "registration_record_key",
    "prune_stale_objects",
    "register_or_update_glue_table",
    "register_table",
    "serialize_parquet",
    "utc_timestamp",
    "validate_project_name",
    "validate_table_name",
    "write_table_object",
]
