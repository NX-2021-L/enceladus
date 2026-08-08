"""Read one quarantined table out of ``hive.adhoc``.

BRD B5-R2, read half. ``promotion_plan`` proposes the types, ``promotion_coerce``
applies them, ``promotion_run`` writes through the B2-R2 shared library. Nothing
in this module writes anything.

The quarantine namespace is the Glue database ``adhoc`` at
``s3://devops-agentcli-compute/adhoc/`` (DVP-TSK-627, DOC-FF843F9F0E2C). A table
lands there from Superset's CSV upload dialog carrying whatever types
``pandas.read_csv`` inferred -- which is the whole reason promotion exists, since
that dialog cannot express ``DATE``, ``TIMESTAMP`` or ``DECIMAL`` at any level of
user diligence.

Two things are read, and the distinction matters:

``catalog``
    The Glue table definition. This is the DECLARED-but-inferred schema: the
    types Superset committed on io's behalf. It is the starting point of the
    pre-populated type map (DVP-TSK-685), never the finished one.

``rows``
    The actual Parquet data. Sampled for the plan, read whole for the promotion.
    Evidence is what upgrades a proposal from a guess to a proposal: this module
    exists so ``promotion_plan`` can say "every one of the 412 non-null values in
    this column parses as a date" rather than "the column is named ``order_date``
    so it is probably a date".
"""

from __future__ import annotations

import io
import os
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ADHOC_DATABASE",
    "ADHOC_BUCKET",
    "ADHOC_PREFIX",
    "PARQUET_SERDE_MARKER",
    "PromotionSourceError",
    "QuarantinedTable",
    "load_quarantined_table",
    "read_catalog_entry",
    "read_rows",
]

#: The quarantine namespace. Isolated Glue database, isolated S3 prefix; a
#: governed project never shares either (DOC-FF843F9F0E2C).
ADHOC_DATABASE = os.environ.get("ADHOC_DATABASE", "adhoc")
ADHOC_BUCKET = os.environ.get("ADHOC_BUCKET", "devops-agentcli-compute")
ADHOC_PREFIX = os.environ.get("ADHOC_PREFIX", "adhoc")

#: Both Trino catalogs declare ``hive.storage-format=PARQUET``, so a quarantined
#: table is Parquet by construction. A table that is not is a catalog anomaly
#: rather than a format this transform should quietly learn to read: promotion
#: reads exactly the format the platform declares it writes, and says so loudly
#: when that is not what it finds.
PARQUET_SERDE_MARKER = "parquet"

#: Glue table-parameter keys that have carried upload provenance in practice.
#: Read opportunistically -- Superset's upload path is not ours to change, so
#: this is a best-effort harvest rather than a contract we can enforce upstream.
_PROVENANCE_KEYS = (
    "uploaded_by",
    "uploaded_at",
    "upload_user",
    "upload_timestamp",
    "source_file",
    "original_filename",
    "superset_user",
    "comment",
)


class PromotionSourceError(Exception):
    """The quarantined table could not be read. Promotion never started."""


class QuarantinedTable:
    """One table in ``hive.adhoc``: its inferred schema, its data, its origin."""

    __slots__ = ("name", "database", "columns", "location", "parameters", "created_at", "rows")

    def __init__(
        self,
        name: str,
        database: str,
        columns: Sequence[Tuple[str, str]],
        location: str,
        parameters: Mapping[str, Any],
        created_at: str,
        rows: Sequence[Mapping[str, Any]],
    ):
        self.name = name
        self.database = database
        #: ``[(column_name, inferred_sql_type), ...]`` in catalog order.
        self.columns = [(str(n), str(t).strip().lower()) for n, t in columns]
        self.location = location
        self.parameters = dict(parameters or {})
        self.created_at = created_at
        self.rows = list(rows)

    @property
    def trino_identifier(self) -> str:
        return "hive.%s.%s" % (self.database, self.name)

    @property
    def column_names(self) -> Tuple[str, ...]:
        return tuple(name for name, _ in self.columns)

    def inferred_type(self, column: str) -> str:
        for name, sql_type in self.columns:
            if name == column:
                return sql_type
        raise PromotionSourceError("column %r is not in %s" % (column, self.trino_identifier))

    def values(self, column: str) -> Iterator[Any]:
        """Every non-null value in one column. The evidence a proposal rests on."""
        for row in self.rows:
            value = row.get(column)
            if value is not None:
                yield value

    def provenance(self) -> Dict[str, str]:
        """Who/what produced this table, as far as the catalog records it.

        Carried through to the governed table on promotion (DVP-TSK-687) so the
        promoted table can still answer "where did this come from" -- a governed
        table whose origin story stops at the promotion boundary would have
        laundered its provenance rather than preserved it.
        """
        harvested = {
            key: str(self.parameters[key])
            for key in _PROVENANCE_KEYS
            if self.parameters.get(key) not in (None, "")
        }
        harvested.setdefault("source_table", self.trino_identifier)
        harvested.setdefault("source_location", self.location)
        if self.created_at:
            harvested.setdefault("source_created_at", self.created_at)
        return harvested


def _stringify_created(value: Any) -> str:
    if not value:
        return ""
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        text = isoformat()
        return text.replace("+00:00", "Z")
    return str(value)


def read_catalog_entry(glue_client, table: str, database: str = ADHOC_DATABASE) -> Dict[str, Any]:
    """Fetch one Glue table definition from the quarantine database. Read-only."""
    try:
        response = glue_client.get_table(DatabaseName=database, Name=table)
    except Exception as exc:  # noqa: BLE001 - surface the catalog's own message
        raise PromotionSourceError(
            "cannot read %s.%s from the Glue catalog: %s" % (database, table, exc)
        )
    return response.get("Table") or {}


def _object_keys(s3_client, bucket: str, prefix: str) -> List[str]:
    keys: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        response = s3_client.list_objects_v2(**kwargs)
        for entry in response.get("Contents", []) or []:
            key = entry.get("Key") or ""
            if key.endswith("/") or int(entry.get("Size") or 0) == 0:
                continue
            keys.append(key)
        if not response.get("IsTruncated"):
            return sorted(keys)
        token = response.get("NextContinuationToken")


def _split_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri.startswith("s3://"):
        raise PromotionSourceError("location %r is not an s3:// URI" % uri)
    remainder = uri[len("s3://") :]
    bucket, _, key = remainder.partition("/")
    if not bucket:
        raise PromotionSourceError("location %r has no bucket" % uri)
    return bucket, key


def read_rows(s3_client, location: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read the quarantined table's Parquet data into plain Python rows.

    ``limit`` caps the read for the planning pass (DVP-TSK-685), which only needs
    enough evidence to propose types. Promotion itself passes ``None``: every row
    must be examined, because all-or-nothing coercion that only looked at the
    first thousand rows would be a sampling gate wearing an all-or-nothing label.
    """
    import pyarrow.parquet as pq

    bucket, key_prefix = _split_s3_uri(location)
    if key_prefix and not key_prefix.endswith("/"):
        key_prefix += "/"

    keys = _object_keys(s3_client, bucket, key_prefix)
    if not keys:
        raise PromotionSourceError(
            "no data objects under %s -- there is nothing to promote" % location
        )

    rows: List[Dict[str, Any]] = []
    for key in keys:
        try:
            body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
        except Exception as exc:  # noqa: BLE001
            raise PromotionSourceError("cannot read s3://%s/%s: %s" % (bucket, key, exc))
        try:
            table = pq.read_table(io.BytesIO(body))
        except Exception as exc:  # noqa: BLE001
            raise PromotionSourceError(
                "s3://%s/%s is not readable as Parquet (%s). The catalog declares "
                "PARQUET storage for this namespace; a non-Parquet object here is a "
                "catalog anomaly, not a format promotion should infer." % (bucket, key, exc)
            )
        rows.extend(table.to_pylist())
        if limit is not None and len(rows) >= limit:
            return rows[:limit]
    return rows


def load_quarantined_table(
    glue_client,
    s3_client,
    table: str,
    database: str = ADHOC_DATABASE,
    sample_limit: Optional[int] = None,
) -> QuarantinedTable:
    """Load one quarantined table -- catalog entry plus data -- in one call."""
    entry = read_catalog_entry(glue_client, table, database)
    storage = entry.get("StorageDescriptor") or {}
    columns = [
        (column.get("Name") or "", column.get("Type") or "")
        for column in storage.get("Columns") or []
    ]
    if not columns:
        raise PromotionSourceError(
            "%s.%s declares no columns; there is no inferred schema to pre-populate from"
            % (database, table)
        )

    serde = ((storage.get("SerdeInfo") or {}).get("SerializationLibrary") or "").lower()
    classification = str((entry.get("Parameters") or {}).get("classification") or "").lower()
    if PARQUET_SERDE_MARKER not in serde and PARQUET_SERDE_MARKER not in classification:
        raise PromotionSourceError(
            "%s.%s is stored as %r, not Parquet. Both Trino catalogs declare "
            "hive.storage-format=PARQUET, so this table did not arrive through the "
            "sanctioned upload path and promotion will not guess at its format."
            % (database, table, serde or classification or "unknown")
        )

    location = storage.get("Location") or ""
    if not location:
        raise PromotionSourceError("%s.%s has no StorageDescriptor.Location" % (database, table))

    rows = read_rows(s3_client, location, limit=sample_limit)
    return QuarantinedTable(
        name=table,
        database=database,
        columns=columns,
        location=location,
        parameters=entry.get("Parameters") or {},
        created_at=_stringify_created(entry.get("CreateTime")),
        rows=rows,
    )
