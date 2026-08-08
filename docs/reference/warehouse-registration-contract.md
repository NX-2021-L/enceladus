# Warehouse (T2) Registration Contract

**Requirement**: BRD B2-R2 (`DOC-724C3695059F` §6.2)
**Tracker**: DVP-TSK-644 (parent), DVP-TSK-667..671
**Governed by**: `DOC-04AF8A02A8F7` (four-tier architecture), `DOC-5E35E14DAD05` (crawler
prohibition), `DOC-1E1EC5B7CE02` (full-refresh partitioning discipline)
**Implementation**: `backend/lambda/shared_layer/python/enceladus_shared/warehouse_registration.py`

This is the published form of the conventions. It exists so that code paths which do **not** call
the library — Superset's native file upload, which reaches the catalog through its own Trino DDL —
can still be held against a fixed statement rather than against folklore.

Every clause below is also exported as an importable constant or validator. Prefer asserting
against `describe_contract()` over quoting this page.

---

## 1. Who calls it

| Caller | Requirement | Status |
| --- | --- | --- |
| Project export jobs (`finance` first) | B2-R2 | reference implementation; see `tools/warehouse_export_finance.py` |
| Governance analytics mart refresh job | B3-R3 | future caller |
| Project mart onboarding | B4 | future caller |
| Ad-hoc promotion transform | B5-R2 | future caller |
| **Superset native file upload** | B5-R3 | **not a caller** — owns its own Trino DDL path, held to the same conventions |

Superset uploads land in the isolated `hive.adhoc` quarantine namespace and are **untyped by
construction** (`pandas.read_csv` dtypes; `DECIMAL` is unreachable through that dialog). They
become governed tables only by passing through the B5-R2 promotion transform, which declares
types and calls this library. That asymmetry is the whole reason quarantine exists.

## 2. The contract

### 2.1 Layout

```
s3://<bucket>/warehouse/<project>/<table>/data.parquet
```

Exactly **one** object per table, at a **constant** key. This is what makes the file count
invariant: a full refresh overwrites the same key, so `file_count == 1` no matter how many times
the export has run. File count tracks data size, never write count (`DOC-1E1EC5B7CE02`).

Verified against production: all 18 `finance` warehouse tables hold exactly one object, named
`data.parquet`, sized in proportion to row volume.

### 2.2 Format

Parquet, snappy compression, **declared explicitly**. Trino 414 defaults to ORC when
`hive.storage-format` is unset (BRD B2-R6), so the format is never inherited.

The Glue storage descriptor is fixed:

| Field | Value |
| --- | --- |
| `TableType` | `EXTERNAL_TABLE` |
| `Parameters` | `{"classification": "parquet", "EXTERNAL": "TRUE"}` |
| `InputFormat` | `org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat` |
| `OutputFormat` | `org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat` |
| `SerializationLibrary` | `org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe` |
| `SerdeInfo.Parameters` | `{"serialization.format": "1"}` |
| `Location` | the table **prefix**, with trailing slash — not the object key |
| `PartitionKeys` | `[]` (see §2.5) |

### 2.3 Registration is DECLARED

The caller passes a schema. The library writes it. **A Glue crawler may never be the mechanism by
which a table Trino serves gets its schema** (`DOC-5E35E14DAD05`). There is no inference path into
`ColumnSpec` — that is deliberate.

Declared types are **SQL types, never pandas dtypes**:

```
boolean tinyint smallint int integer bigint float real double
string binary date timestamp
decimal(p,s) varchar(n) char(n)
array<...> map<...> struct<...>
```

`decimal(p,s)` being reachable here is the practical difference between this path and the Superset
upload dialog, where money necessarily becomes `DOUBLE`.

### 2.4 Naming

| Identifier | Pattern |
| --- | --- |
| project | `^[a-z][a-z0-9_]{0,62}$` |
| table | `^[a-z][a-z0-9_]{0,127}$` |
| column | `^[a-z][a-z0-9_]{0,127}$` |

Lowercase `snake_case` only. Mixed case is **rejected, not folded** — Glue folds identifiers and
Trino does not, and the disagreement surfaces later as a table that registers successfully and
then will not select.

Reserved column names (would break Hive/Trino DDL) are rejected up front:
`table select from where group order by partition location timestamp date values exists
current_date current_time current_timestamp`.

Addressing is `hive.<project>.<table>`. The Glue **database** name is the project name with `-`
folded to `_`.

> **Onboarding precondition (T0, once per project).** A Glue database must be created **with a
> `LocationUri`**, or `CREATE TABLE` against it fails with `HIVE_DATABASE_LOCATION_ERROR`.
> Table-level `StorageDescriptor.Location` does not substitute. Of the six live Glue databases,
> only `mjr_rd` and `adhoc` carry one. This library writes the catalog through the Glue API rather
> than through Trino DDL, so it is not itself blocked by a missing `LocationUri` — but any Superset
> or Trino DDL against that database will be. See `DOC-04AF8A02A8F7`.

### 2.5 Refresh

Full-refresh overwrite per table. No partition keys. No snapshot-per-mutation directories.

A table that genuinely exceeds the full-refresh envelope may petition for date partitioning with
**bounded retention**, as a recorded per-table governed exception — never a default, never silently
adopted (`DOC-1E1EC5B7CE02`).

### 2.6 Required column — the freshness stamp

**Every T2 table carries a freshness stamp. Mandatory, not optional.**

- Default name: `ingest_ts`
- Type: `string`, holding a UTC ISO-8601 timestamp
- The declared schema must contain it, or `build_contract()` raises
- The library stamps the value onto every row of every write

`string` rather than Hive `timestamp` is deliberate and matches production: the live `finance`
tables declare `created_at`/`updated_at` as `string`. Parquet's int96-vs-micros timestamp ambiguity
makes `timestamp` round-trip differently across writers; an ISO-8601 string does not.

## 3. The function

```python
register_table(
    *,
    project: str,
    table: str,
    rows,                          # list[dict] | pandas.DataFrame | pyarrow.Table
    columns: Sequence[ColumnSpec], # the DECLARED schema
    bucket: str,
    database: str | None = None,
    freshness_column: str = "ingest_ts",
    write_timestamp: datetime | None = None,
    base_prefix: str = "warehouse",
    table_comment: str = "",
    emit_record: bool = True,
    prune_stale: bool = False,
    s3_client=None,
    glue_client=None,
) -> RegistrationRecord
```

**Declaration wins.** A declared column absent from the data becomes NULL; a data column absent
from the declaration is dropped. That asymmetry is what makes this a schema *function* rather than
a schema *estimator*.

### 3.1 Idempotency

Deterministic in `(rows, columns, write_timestamp)`. Two invocations with the same three produce
byte-identical Parquet, so the second is a no-op:

- the candidate object is digested and compared to what is already at the canonical key —
  identical means no `PutObject` (`storage_changed=False`)
- the Glue definition is compared field by field — identical means no `UpdateTable`
  (`catalog_changed=False`)

`write_timestamp` defaults to now, and the freshness stamp is part of the data, so a caller
wanting observable idempotency passes an explicit `write_timestamp`. This is deliberate: a
scheduled refresh *should* produce a new stamp; a replay *should not*.

### 3.2 Failure behaviour — transactional in intent

1. Validation and Parquet serialization happen **entirely in memory**. A bad schema, a bad
   identifier, or an unencodable value raises before S3 or Glue is touched.
2. The data object is written first, as a single atomic `PutObject`. All-or-nothing: a failed
   write leaves the previous generation intact and readable.
3. The catalog is written **only after** the data write succeeds. A registered table therefore
   never points at absent or partial data — the failure mode the ordering exists to prevent is
   unreachable by construction.
4. If the catalog write fails, data is present and the catalog describes the previous generation.
   Queries return the previous schema over the new data rather than erroring on a missing prefix.
   Retry is safe because step 2 is idempotent.

| Exception | Meaning | Retry? |
| --- | --- | --- |
| `ContractViolation` | the caller asked for something the contract forbids | no |
| `StorageWriteError` | the S3 write failed; previous generation intact | yes |
| `CatalogWriteError` | the Glue write failed; data is written | yes |

### 3.3 The registration record

Every invocation emits a `RegistrationRecord`: table identity, row count, byte count, **measured**
file count, write timestamp, content digest, and the previous generation's counts. It is written to

```
s3://<bucket>/warehouse-registrations/<project>/<table>.json
```

a **sibling** of the warehouse tree, never a child of it — everything under a table prefix is table
data by definition, and a JSON sidecar there would be read as a corrupt Parquet file. The prefix is
derived from `base_prefix` (`warehouse/` → `warehouse-registrations/`), so a record always stays
inside whatever namespace its table lives in. That matters for the quarantine prefix, where
escaping the namespace would defeat the isolation quarantine exists to provide.

`file_count` is **measured** by listing the prefix, not asserted — a count the library merely
claimed would be useless to the check it exists to feed.

This makes the B6-R2 health monitor's checks 1 and 5 answerable from a **single `GetObject`, with
no S3 re-scan**:

| Check | Answered by |
| --- | --- |
| 1 — freshness | `write_timestamp` vs `previous_write_timestamp` |
| 5 — size vs count | `file_count` vs `previous_file_count`, against `byte_count` movement |

`RegistrationRecord.full_refresh_violation(sharding_constant=1)` implements the verdict directly:
it flags a file count above the declared sharding constant, and — the specific signature — a file
count that grew while bytes did not.

#### Generation vs invocation

A **generation** is a change to storage or catalog, not an invocation. A replay that changed
nothing does not advance `write_seq` or rewrite the previous-generation fields, and the persisted
sidecar excludes the invocation-scoped flags (`storage_changed`, `catalog_changed`, `created`,
`pruned_objects`) entirely. Those are returned to the caller and logged, but not stored — otherwise
the record would be the one piece of state that a no-op still mutates, and §3.1's guarantee would
stop being literally true.

## 4. Holding a non-caller against this

```python
from enceladus_shared.warehouse_registration import build_contract, describe_contract

# Raises ContractViolation if the intent disagrees with any clause above.
contract = build_contract(project=..., table=..., columns=..., bucket=...)

# Or assert against the machine-readable statement.
assert observed_serde == describe_contract()["serde"]
```

`build_contract()` performs the full validation and touches no AWS API, so the Superset path, the
promotion transform, and the B6-R2 monitor can all use it as a pure conformance check.
