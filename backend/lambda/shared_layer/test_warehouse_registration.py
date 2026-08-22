"""Tests for enceladus_shared.warehouse_registration (DVP-TSK-671, BRD B2-R2).

The library claims idempotency, determinism, full-refresh correctness, and a
transactional ordering. The entire warehouse contract rests on those claims, so
they are TESTED here rather than asserted in a docstring.

Run from the shared_layer directory:

    PYTHONPATH=python python3 -m unittest test_warehouse_registration -v

The S3 and Glue fakes below are deliberately hand-rolled rather than moto: the
tests need to inject failures at an exact call and count calls precisely, and
the fakes are small enough that they are easier to trust than a mock framework.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import sys
import unittest

sys.path.insert(0, "python")

from enceladus_shared.warehouse_registration import (  # noqa: E402
    DATA_OBJECT_NAME,
    RESERVED_COLUMN_NAMES,
    CatalogWriteError,
    ColumnSpec,
    ContractViolation,
    StorageWriteError,
    build_contract,
    columns_from_pairs,
    describe_contract,
    freshness_column_spec,
    register_table,
)

try:  # pyarrow is an optional heavy dependency; the contract half works without it
    import pyarrow  # noqa: F401
    import pyarrow.parquet as pq

    HAVE_PYARROW = True
except ImportError:  # pragma: no cover
    HAVE_PYARROW = False

needs_pyarrow = unittest.skipUnless(HAVE_PYARROW, "pyarrow is not installed")

BUCKET = "test-warehouse-bucket"
PROJECT = "testproj"
TABLE = "widgets"
DATABASE = "testproj"
PREFIX = "warehouse/%s/%s/" % (PROJECT, TABLE)
DATA_KEY = PREFIX + DATA_OBJECT_NAME
RECORD_KEY = "warehouse-registrations/%s/%s.json" % (PROJECT, TABLE)

COLUMNS = columns_from_pairs(
    [("id", "string"), ("amount", "decimal(18,2)"), ("qty", "bigint"), ("opened_date", "date")]
) + [freshness_column_spec()]

ROWS = [
    {"id": "a", "amount": "10.50", "qty": 3, "opened_date": "2026-01-02", "undeclared": "dropped"},
    {"id": "b", "amount": 2, "qty": None, "opened_date": None},
]

STAMP = dt.datetime(2026, 8, 7, 12, 0, 0, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _NotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "404"}}


class _GlueNotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "EntityNotFoundException"}}


class FakeS3:
    """Minimal in-memory S3 with per-key-kind call counting and fault injection."""

    def __init__(self, fail_data_put=False, fail_record_put=False):
        self.objects = {}
        self.data_puts = 0
        self.record_puts = 0
        self.fail_data_put = fail_data_put
        self.fail_record_put = fail_record_put

    @staticmethod
    def _is_data(key):
        return key.endswith(".parquet")

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise _NotFound()
        body, metadata = self.objects[(Bucket, Key)]
        return {"Metadata": metadata, "ContentLength": len(body)}

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise _NotFound()
        body, _ = self.objects[(Bucket, Key)]
        return {"Body": io.BytesIO(body)}

    def put_object(self, Bucket, Key, Body, **kwargs):
        if self._is_data(Key):
            if self.fail_data_put:
                raise RuntimeError("simulated S3 outage")
            self.data_puts += 1
        else:
            if self.fail_record_put:
                raise RuntimeError("simulated S3 outage")
            self.record_puts += 1
        self.objects[(Bucket, Key)] = (Body, kwargs.get("Metadata", {}))
        return {}

    def list_objects_v2(self, Bucket, Prefix, **kwargs):
        contents = [
            {"Key": key, "Size": len(value[0])}
            for (bucket, key), value in self.objects.items()
            if bucket == Bucket and key.startswith(Prefix)
        ]
        return {"Contents": contents, "IsTruncated": False}

    def delete_objects(self, Bucket, Delete):
        for entry in Delete["Objects"]:
            self.objects.pop((Bucket, entry["Key"]), None)
        return {}

    def keys_under(self, prefix):
        return sorted(key for (_, key) in self.objects if key.startswith(prefix))


class FakeGlue:
    def __init__(self, fail_create=False, fail_update=False):
        self.tables = {}
        self.create_calls = 0
        self.update_calls = 0
        self.fail_create = fail_create
        self.fail_update = fail_update

    def get_table(self, DatabaseName, Name):
        if (DatabaseName, Name) not in self.tables:
            raise _GlueNotFound()
        return {"Table": self.tables[(DatabaseName, Name)]}

    def create_table(self, DatabaseName, TableInput):
        if self.fail_create:
            raise RuntimeError("simulated Glue outage")
        self.create_calls += 1
        self.tables[(DatabaseName, TableInput["Name"])] = dict(TableInput)

    def update_table(self, DatabaseName, TableInput):
        if self.fail_update:
            raise RuntimeError("simulated Glue outage")
        self.update_calls += 1
        self.tables[(DatabaseName, TableInput["Name"])] = dict(TableInput)

    def column_names(self, database=DATABASE, table=TABLE):
        return [c["Name"] for c in self.tables[(database, table)]["StorageDescriptor"]["Columns"]]


def call(s3, glue, rows=ROWS, columns=COLUMNS, write_timestamp=STAMP, **kwargs):
    return register_table(
        project=PROJECT,
        table=TABLE,
        rows=rows,
        columns=columns,
        bucket=BUCKET,
        database=DATABASE,
        write_timestamp=write_timestamp,
        s3_client=s3,
        glue_client=glue,
        **kwargs
    )


def numbered_rows(count):
    return [
        {"id": "id-%05d" % i, "amount": "%d.25" % i, "qty": i, "opened_date": "2026-01-01"}
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Contract conventions (no pyarrow needed)
# ---------------------------------------------------------------------------


class ContractConventionTests(unittest.TestCase):
    def test_addresses_are_derived_not_spelled(self):
        contract = build_contract(project="finance", table="accounts", columns=COLUMNS, bucket="b")
        self.assertEqual(contract.s3_prefix, "warehouse/finance/accounts/")
        self.assertEqual(contract.s3_key, "warehouse/finance/accounts/data.parquet")
        self.assertEqual(contract.location, "s3://b/warehouse/finance/accounts/")
        self.assertEqual(contract.trino_identifier, "hive.finance.accounts")
        self.assertTrue(contract.is_governed_layout)

    def test_registration_prefix_is_a_sibling_not_a_child(self):
        contract = build_contract(project="finance", table="accounts", columns=COLUMNS, bucket="b")
        self.assertEqual(contract.registration_key, "warehouse-registrations/finance/accounts.json")
        self.assertFalse(contract.registration_key.startswith(contract.s3_prefix))

    def test_registration_prefix_follows_a_scratch_base_prefix(self):
        # A quarantine table's record must not escape the quarantine namespace.
        contract = build_contract(
            project="p", table="t", columns=COLUMNS, bucket="b", base_prefix="adhoc/scratch"
        )
        self.assertEqual(contract.registration_key, "adhoc/scratch-registrations/p/t.json")
        self.assertFalse(contract.is_governed_layout)

    def test_identifiers_are_rejected_not_folded(self):
        for kwargs in ({"project": "Finance"}, {"table": "Accounts"}):
            base = {"project": "finance", "table": "accounts", "columns": COLUMNS, "bucket": "b"}
            base.update(kwargs)
            with self.assertRaises(ContractViolation):
                build_contract(**base)

    def test_freshness_column_is_mandatory(self):
        with self.assertRaises(ContractViolation) as caught:
            build_contract(
                project="p", table="t", columns=columns_from_pairs([("id", "string")]), bucket="b"
            )
        self.assertIn("freshness stamp", str(caught.exception))

    def test_pandas_dtypes_are_not_sql_types(self):
        with self.assertRaises(ContractViolation) as caught:
            build_contract(
                project="p",
                table="t",
                columns=columns_from_pairs([("id", "int64")]) + [freshness_column_spec()],
                bucket="b",
            )
        self.assertIn("not a permitted SQL type", str(caught.exception))

    def test_decimal_is_reachable(self):
        # The type the Superset upload dialog cannot express; money depends on it.
        contract = build_contract(
            project="p",
            table="t",
            columns=columns_from_pairs([("amount", "decimal(18,2)")]) + [freshness_column_spec()],
            bucket="b",
        )
        self.assertEqual(contract.column_type("amount"), "decimal(18,2)")

    def test_reserved_words_are_trino_not_hive(self):
        # DVP-TSK-670: four live finance tables carry a `date` column that Trino
        # serves today. A list that rejected it would break the reference
        # implementation the contract was derived from.
        for permitted in ("date", "timestamp", "partition", "location"):
            self.assertNotIn(permitted, RESERVED_COLUMN_NAMES)
        for reserved in ("select", "from", "where", "table", "group"):
            self.assertIn(reserved, RESERVED_COLUMN_NAMES)

    def test_glue_table_input_matches_the_finance_production_shape(self):
        storage = build_contract(
            project="finance", table="accounts", columns=COLUMNS, bucket="b"
        ).glue_table_input()
        self.assertEqual(storage["TableType"], "EXTERNAL_TABLE")
        self.assertEqual(storage["Parameters"], {"classification": "parquet", "EXTERNAL": "TRUE"})
        self.assertEqual(storage["PartitionKeys"], [])
        descriptor = storage["StorageDescriptor"]
        self.assertEqual(
            descriptor["InputFormat"],
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
        )
        self.assertEqual(
            descriptor["OutputFormat"],
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
        )
        self.assertEqual(
            descriptor["SerdeInfo"]["SerializationLibrary"],
            "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
        )
        self.assertEqual(descriptor["SerdeInfo"]["Parameters"], {"serialization.format": "1"})

    def test_describe_contract_is_assertable_by_a_non_caller(self):
        described = describe_contract()
        self.assertEqual(described["storage_format"], "parquet")
        self.assertEqual(described["required_column"], "ingest_ts")
        self.assertEqual(described["data_object_name"], "data.parquet")
        self.assertIn("hive.", described["addressing"])


# ---------------------------------------------------------------------------
# AC 1 — idempotency
# ---------------------------------------------------------------------------


@needs_pyarrow
class IdempotencyTests(unittest.TestCase):
    def test_replay_leaves_catalog_and_storage_unchanged(self):
        s3, glue = FakeS3(), FakeGlue()
        first = call(s3, glue)
        data_before = s3.objects[(BUCKET, DATA_KEY)][0]
        record_before = s3.objects[(BUCKET, RECORD_KEY)][0]

        second = call(s3, glue)

        self.assertFalse(second.storage_changed)
        self.assertFalse(second.catalog_changed)
        self.assertEqual(s3.data_puts, 1, "a replay must not rewrite the data object")
        self.assertEqual(glue.create_calls, 1)
        self.assertEqual(glue.update_calls, 0, "a replay must not rewrite the catalog")
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(data_before, s3.objects[(BUCKET, DATA_KEY)][0])
        self.assertEqual(
            record_before,
            s3.objects[(BUCKET, RECORD_KEY)][0],
            "the registration record must not be the one piece of state a no-op mutates",
        )

    def test_determinism_across_independent_client_pairs(self):
        first = call(FakeS3(), FakeGlue())
        second = call(FakeS3(), FakeGlue())
        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.byte_count, second.byte_count)

    def test_a_new_write_timestamp_is_a_new_generation(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        later = call(s3, glue, write_timestamp=STAMP + dt.timedelta(hours=1))
        self.assertTrue(later.storage_changed)
        self.assertEqual(s3.data_puts, 2)
        self.assertEqual(later.write_seq, 2)


# ---------------------------------------------------------------------------
# AC 2 — full refresh
# ---------------------------------------------------------------------------


@needs_pyarrow
class FullRefreshTests(unittest.TestCase):
    def test_file_count_tracks_data_size_not_write_count(self):
        s3, glue = FakeS3(), FakeGlue()
        observations = []
        for index, count in enumerate((1, 5, 50, 500, 5000, 5000, 10)):
            record = call(
                s3,
                glue,
                rows=numbered_rows(count),
                write_timestamp=STAMP + dt.timedelta(minutes=index),
            )
            observations.append((count, record.file_count, record.byte_count))

        self.assertEqual(s3.keys_under(PREFIX), [DATA_KEY], "exactly one object, always")
        for _, file_count, _ in observations:
            self.assertEqual(file_count, 1, "file count must not track write count")

        by_rows = {rows: size for rows, _, size in observations}
        self.assertGreater(by_rows[5000], by_rows[500])
        self.assertGreater(by_rows[500], by_rows[50])
        self.assertLess(
            by_rows[10], by_rows[5000], "byte count must fall when the data shrinks"
        )

    def test_the_registration_record_detects_accumulation(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, rows=numbered_rows(10))
        healthy = call(
            s3,
            glue,
            rows=numbered_rows(1000),
            write_timestamp=STAMP + dt.timedelta(hours=1),
        )
        self.assertIsNone(
            healthy.full_refresh_violation(),
            "file count flat while bytes grow is the healthy signature",
        )

        accumulating = type(healthy)(**dict(healthy.to_dict(), **{
            "file_count": 4,
            "previous_file_count": 2,
            "byte_count": healthy.byte_count,
            "previous_byte_count": healthy.byte_count,
            "pruned_objects": (),
        }))
        self.assertIsNotNone(accumulating.full_refresh_violation())

    def test_prune_stale_adopts_a_legacy_prefix(self):
        s3, glue = FakeS3(), FakeGlue()
        s3.objects[(BUCKET, PREFIX + "part-0001.parquet")] = (b"legacy", {})
        s3.objects[(BUCKET, PREFIX + "part-0002.parquet")] = (b"legacy", {})

        record = call(s3, glue, prune_stale=True)

        self.assertEqual(len(record.pruned_objects), 2)
        self.assertEqual(s3.keys_under(PREFIX), [DATA_KEY])

    def test_declaration_wins_over_the_sample(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        table = pq.read_table(io.BytesIO(s3.objects[(BUCKET, DATA_KEY)][0]))
        self.assertNotIn("undeclared", table.schema.names)
        self.assertEqual(list(table.schema.names), [c.name for c in COLUMNS])
        self.assertEqual(str(table.schema.field("amount").type), "decimal128(18, 2)")


# ---------------------------------------------------------------------------
# AC 3 — schema evolution
# ---------------------------------------------------------------------------


@needs_pyarrow
class SchemaEvolutionTests(unittest.TestCase):
    def test_added_column_updates_rather_than_diverges(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        evolved = COLUMNS + [ColumnSpec(name="colour", type="varchar(32)")]

        record = call(s3, glue, columns=evolved)

        self.assertTrue(record.catalog_changed)
        self.assertFalse(record.created)
        self.assertEqual(glue.update_calls, 1)
        self.assertEqual(len(glue.tables), 1, "one table, updated — not a second table")
        self.assertIn("colour", glue.column_names())

    def test_removed_column_updates_the_definition(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        reduced = [c for c in COLUMNS if c.name != "qty"]

        call(s3, glue, columns=reduced)

        self.assertNotIn("qty", glue.column_names())
        self.assertEqual(len(glue.tables), 1)

    def test_retyped_column_updates_the_definition(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        retyped = [
            ColumnSpec(name="qty", type="int") if c.name == "qty" else c for c in COLUMNS
        ]

        call(s3, glue, columns=retyped)

        types = {
            c["Name"]: c["Type"]
            for c in glue.tables[(DATABASE, TABLE)]["StorageDescriptor"]["Columns"]
        }
        self.assertEqual(types["qty"], "int")

    def test_evolution_is_itself_idempotent(self):
        s3, glue = FakeS3(), FakeGlue()
        evolved = COLUMNS + [ColumnSpec(name="colour", type="varchar(32)")]
        call(s3, glue, columns=evolved)
        again = call(s3, glue, columns=evolved)
        self.assertFalse(again.catalog_changed)
        self.assertEqual(glue.update_calls, 0)


# ---------------------------------------------------------------------------
# AC 4 — failure paths
# ---------------------------------------------------------------------------


@needs_pyarrow
class FailurePathTests(unittest.TestCase):
    def test_failed_data_write_never_touches_the_catalog(self):
        s3, glue = FakeS3(fail_data_put=True), FakeGlue()
        with self.assertRaises(StorageWriteError):
            call(s3, glue)
        self.assertEqual(glue.create_calls, 0)
        self.assertEqual(glue.update_calls, 0)
        self.assertEqual(glue.tables, {}, "no registered table may point at absent data")

    def test_failed_catalog_write_leaves_nothing_pointing_at_the_data(self):
        s3, glue = FakeS3(), FakeGlue(fail_create=True)
        with self.assertRaises(CatalogWriteError):
            call(s3, glue)
        self.assertIn((BUCKET, DATA_KEY), s3.objects)
        self.assertEqual(glue.tables, {})

    def test_retry_after_a_catalog_failure_is_idempotent(self):
        s3, glue = FakeS3(), FakeGlue(fail_create=True)
        with self.assertRaises(CatalogWriteError):
            call(s3, glue)

        glue.fail_create = False
        record = call(s3, glue)

        self.assertFalse(record.storage_changed, "the data write must not be repeated")
        self.assertTrue(record.created)
        self.assertEqual(s3.data_puts, 1)

    def test_a_failed_update_leaves_the_previous_definition_intact(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        before = json.dumps(glue.tables[(DATABASE, TABLE)], sort_keys=True)

        glue.fail_update = True
        with self.assertRaises(CatalogWriteError):
            call(s3, glue, columns=COLUMNS + [ColumnSpec(name="colour", type="string")])

        self.assertEqual(json.dumps(glue.tables[(DATABASE, TABLE)], sort_keys=True), before)

    def test_validation_failures_reach_no_aws_call_at_all(self):
        for rows, columns in (
            (ROWS, columns_from_pairs([("id", "int64")]) + [freshness_column_spec()]),
            ([{"id": "a", "amount": "not-a-number", "qty": 1}], COLUMNS),
        ):
            s3, glue = FakeS3(), FakeGlue()
            with self.assertRaises(ContractViolation):
                call(s3, glue, rows=rows, columns=columns)
            self.assertEqual(s3.data_puts, 0)
            self.assertEqual(s3.record_puts, 0)
            self.assertEqual(glue.create_calls, 0)

    def test_a_failed_record_emission_is_reported_not_swallowed(self):
        s3, glue = FakeS3(fail_record_put=True), FakeGlue()
        with self.assertRaises(StorageWriteError):
            call(s3, glue)
        # Data and catalog are both complete; only the signal failed.
        self.assertIn((BUCKET, DATA_KEY), s3.objects)
        self.assertEqual(glue.create_calls, 1)


# ---------------------------------------------------------------------------
# Caller-owned freshness (DVP-TSK-670 reconciliation)
# ---------------------------------------------------------------------------


@needs_pyarrow
class CallerOwnedFreshnessTests(unittest.TestCase):
    COLUMNS = columns_from_pairs([("id", "string"), ("updated_at", "string")])

    def test_caller_owned_values_are_preserved_not_overwritten(self):
        s3, glue = FakeS3(), FakeGlue()
        register_table(
            project=PROJECT,
            table=TABLE,
            rows=[{"id": "a", "updated_at": "2026-01-01T00:00:00Z"}],
            columns=self.COLUMNS,
            bucket=BUCKET,
            database=DATABASE,
            freshness_column="updated_at",
            stamp_freshness=False,
            write_timestamp=STAMP,
            s3_client=s3,
            glue_client=glue,
        )
        table = pq.read_table(io.BytesIO(s3.objects[(BUCKET, DATA_KEY)][0]))
        self.assertEqual(table.to_pylist()[0]["updated_at"], "2026-01-01T00:00:00Z")

    def test_a_missing_caller_owned_value_is_rejected(self):
        s3, glue = FakeS3(), FakeGlue()
        with self.assertRaises(ContractViolation) as caught:
            register_table(
                project=PROJECT,
                table=TABLE,
                rows=[{"id": "a", "updated_at": "2026-01-01T00:00:00Z"}, {"id": "b"}],
                columns=self.COLUMNS,
                bucket=BUCKET,
                database=DATABASE,
                freshness_column="updated_at",
                stamp_freshness=False,
                write_timestamp=STAMP,
                s3_client=s3,
                glue_client=glue,
            )
        self.assertIn("row 1", str(caught.exception))
        self.assertEqual(s3.data_puts, 0)

    def test_library_owned_freshness_is_stamped(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue)
        table = pq.read_table(io.BytesIO(s3.objects[(BUCKET, DATA_KEY)][0]))
        stamps = {row["ingest_ts"] for row in table.to_pylist()}
        self.assertEqual(stamps, {"2026-08-07T12:00:00Z"})


if __name__ == "__main__":
    unittest.main()
