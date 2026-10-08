"""Observer-clock contract for enceladus_shared.warehouse_registration (DVP-TSK-765).

DVP-ISS-134: ``register_table()`` gated ``write_seq`` and every ``previous_*``
field behind a real generation (storage or catalog changed) but stamped
``write_timestamp`` unconditionally -- so a registration that changed nothing
still advanced the one field every freshness reader consults. The repair splits
the record's clock in two:

* ``write_timestamp``  -- the STATE clock; moves only with a new generation.
* ``last_verified_at`` -- the OBSERVATION clock; stamped on every invocation.

These tests pin both halves, in the same shape as the write_seq generation
tests (DVP-TSK-671): drive two consecutive ``register_table()`` calls through
hand-rolled S3/Glue fakes, then assert on the returned record AND on the
persisted sidecar the B6-R2 monitor actually reads.

Run from the shared_layer directory:

    PYTHONPATH=python python3 -m pytest test_warehouse_registration_observer_clock.py -v

The clock logic does not depend on the Parquet encoding, so every case runs
twice: once against a deterministic stand-in serializer built on the module's
own ``project_rows`` (always available -- pyarrow is not installed where this
suite usually runs), and once against the real pyarrow serializer when pyarrow
is importable.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))

from enceladus_shared import warehouse_registration as wr  # noqa: E402
from enceladus_shared.warehouse_registration import (  # noqa: E402
    DATA_OBJECT_NAME,
    REGISTRATION_RECORD_VERSION,
    columns_from_pairs,
    freshness_column_spec,
    register_table,
)

try:  # pyarrow is an optional heavy dependency; the stand-in covers its absence
    import pyarrow  # noqa: F401

    HAVE_PYARROW = True
except ImportError:  # pragma: no cover
    HAVE_PYARROW = False

needs_pyarrow = unittest.skipUnless(HAVE_PYARROW, "pyarrow is not installed")

BUCKET = "test-warehouse-bucket"
PROJECT = "testproj"
TABLE = "widgets"
DATABASE = "testproj"
DATA_KEY = "warehouse/%s/%s/%s" % (PROJECT, TABLE, DATA_OBJECT_NAME)
RECORD_KEY = "warehouse-registrations/%s/%s.json" % (PROJECT, TABLE)

#: Caller-owned freshness (finance's shape, ``stamp_freshness=False``): the
#: invocation clock is NOT part of the data, so a later invocation over the same
#: rows serializes to byte-identical content -- the exact DVP-ISS-134 case.
OWNED_COLUMNS = columns_from_pairs(
    [("id", "string"), ("qty", "bigint"), ("updated_at", "string")]
)
OWNED_ROWS = [
    {"id": "a", "qty": 3, "updated_at": "2026-01-01T00:00:00Z"},
    {"id": "b", "qty": 7, "updated_at": "2026-01-02T00:00:00Z"},
]
CHANGED_ROWS = OWNED_ROWS + [{"id": "c", "qty": 1, "updated_at": "2026-01-03T00:00:00Z"}]

#: Library-owned freshness (the default): the invocation clock IS in the data.
STAMPED_COLUMNS = columns_from_pairs([("id", "string")]) + [freshness_column_spec()]

T1 = dt.datetime(2026, 8, 7, 12, 0, 0, tzinfo=dt.timezone.utc)
T2 = T1 + dt.timedelta(hours=1)
T3 = T1 + dt.timedelta(hours=2)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Fakes (same shape as the DVP-TSK-671 fakes)
# ---------------------------------------------------------------------------


class _NotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "404"}}


class _GlueNotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "EntityNotFoundException"}}


class FakeS3:
    """Minimal in-memory S3 with per-key-kind call counting."""

    def __init__(self):
        self.objects = {}
        self.data_puts = 0
        self.record_puts = 0
        #: Fail the next sidecar PutObject: the data lands, the record does not.
        self.fail_next_record_put = False

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
        if Key.endswith(".parquet"):
            self.data_puts += 1
        else:
            if self.fail_next_record_put:
                self.fail_next_record_put = False
                raise RuntimeError("simulated sidecar PutObject failure")
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

    def sidecar(self):
        return json.loads(self.objects[(BUCKET, RECORD_KEY)][0].decode("utf-8"))

    def sidecar_bytes(self):
        return self.objects[(BUCKET, RECORD_KEY)][0]


class FakeGlue:
    def __init__(self):
        self.tables = {}
        self.create_calls = 0
        self.update_calls = 0

    def get_table(self, DatabaseName, Name):
        if (DatabaseName, Name) not in self.tables:
            raise _GlueNotFound()
        return {"Table": self.tables[(DatabaseName, Name)]}

    def create_table(self, DatabaseName, TableInput):
        self.create_calls += 1
        self.tables[(DatabaseName, TableInput["Name"])] = dict(TableInput)

    def update_table(self, DatabaseName, TableInput):
        self.update_calls += 1
        self.tables[(DatabaseName, TableInput["Name"])] = dict(TableInput)


def call(s3, glue, write_timestamp, rows=OWNED_ROWS, **kwargs):
    """Caller-owned freshness by default; override for the library-owned shape."""
    kwargs.setdefault("columns", OWNED_COLUMNS)
    kwargs.setdefault("freshness_column", "updated_at")
    kwargs.setdefault("stamp_freshness", False)
    return register_table(
        project=PROJECT,
        table=TABLE,
        rows=rows,
        bucket=BUCKET,
        database=DATABASE,
        write_timestamp=write_timestamp,
        s3_client=s3,
        glue_client=glue,
        **kwargs
    )


def _stand_in_serializer(contract, rows, stamp, stamp_freshness=True):
    """Deterministic, pyarrow-free replacement for ``serialize_parquet``.

    Uses the module's own ``project_rows`` -- so declaration, caller-owned
    freshness validation, and library-owned stamping are the REAL logic -- and
    only swaps the byte encoding: identical inputs give identical bytes, and the
    stamp reaches the bytes exactly when it reaches the data.
    """
    projected = wr.project_rows(contract, rows, stamp, stamp_freshness)
    payload = json.dumps(projected, sort_keys=True, default=str).encode("utf-8")
    return payload, len(rows)


# ---------------------------------------------------------------------------
# The contract, written once and run against both serializers
# ---------------------------------------------------------------------------


class _ObserverClockCases:
    def test_byte_identical_reregistration_holds_write_timestamp(self):
        """The DVP-ISS-134 case: same bytes, later clock."""
        s3, glue = FakeS3(), FakeGlue()
        first = call(s3, glue, T1)
        later = call(s3, glue, T2)

        self.assertFalse(later.storage_changed)
        self.assertFalse(later.catalog_changed)
        self.assertEqual(s3.data_puts, 1)
        self.assertEqual(later.content_sha256, first.content_sha256)
        self.assertEqual(later.write_seq, 1)
        # The state clock did NOT move ...
        self.assertEqual(first.write_timestamp, iso(T1))
        self.assertEqual(later.write_timestamp, iso(T1))
        # ... and the observation clock did.
        self.assertEqual(first.last_verified_at, iso(T1))
        self.assertEqual(later.last_verified_at, iso(T2))
        # The persisted sidecar is what the B6-R2 freshness check reads.
        sidecar = s3.sidecar()
        self.assertEqual(sidecar["write_timestamp"], iso(T1))
        self.assertEqual(sidecar["last_verified_at"], iso(T2))
        self.assertEqual(sidecar["write_seq"], 1)

    def test_a_real_content_change_advances_both_clocks(self):
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        later = call(s3, glue, T2, rows=CHANGED_ROWS)

        self.assertTrue(later.storage_changed)
        self.assertEqual(s3.data_puts, 2)
        self.assertEqual(later.write_seq, 2)
        self.assertEqual(later.write_timestamp, iso(T2))
        self.assertEqual(later.last_verified_at, iso(T2))
        self.assertEqual(later.previous_write_timestamp, iso(T1))
        sidecar = s3.sidecar()
        self.assertEqual(sidecar["write_timestamp"], iso(T2))
        self.assertEqual(sidecar["last_verified_at"], iso(T2))

    def test_a_no_op_after_a_change_holds_the_new_generation(self):
        """change -> no-op: write_timestamp and every previous_* field stay put."""
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        changed = call(s3, glue, T2, rows=CHANGED_ROWS)
        checked = call(s3, glue, T3, rows=CHANGED_ROWS)

        self.assertFalse(checked.storage_changed)
        self.assertEqual(checked.write_seq, changed.write_seq)
        self.assertEqual(checked.write_timestamp, iso(T2))
        self.assertEqual(checked.previous_write_timestamp, iso(T1))
        self.assertEqual(checked.previous_row_count, changed.previous_row_count)
        self.assertEqual(checked.last_verified_at, iso(T3))

    def test_a_catalog_only_change_is_a_generation(self):
        """Gated on storage OR catalog -- not on storage alone."""
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        later = call(s3, glue, T2, table_comment="re-described, same data")

        self.assertFalse(later.storage_changed)
        self.assertTrue(later.catalog_changed)
        self.assertEqual(glue.update_calls, 1)
        self.assertEqual(later.write_seq, 2)
        self.assertEqual(later.write_timestamp, iso(T2))
        self.assertEqual(later.last_verified_at, iso(T2))

    def test_library_owned_freshness_makes_a_new_clock_new_content(self):
        """With the stamp in the data, a later clock IS a content change."""
        s3, glue = FakeS3(), FakeGlue()
        rows = [{"id": "a"}, {"id": "b"}]
        call(s3, glue, T1, rows=rows, columns=STAMPED_COLUMNS,
             freshness_column="ingest_ts", stamp_freshness=True)
        later = call(s3, glue, T2, rows=rows, columns=STAMPED_COLUMNS,
                     freshness_column="ingest_ts", stamp_freshness=True)

        self.assertTrue(later.storage_changed)
        self.assertEqual(later.write_seq, 2)
        self.assertEqual(later.write_timestamp, iso(T2))
        self.assertEqual(later.last_verified_at, iso(T2))

    def test_an_empty_library_stamped_table_is_gated_on_content_not_flags(self):
        """Zero rows carry no stamp, so a later clock writes nothing new."""
        s3, glue = FakeS3(), FakeGlue()
        kwargs = dict(rows=[], columns=STAMPED_COLUMNS,
                      freshness_column="ingest_ts", stamp_freshness=True)
        call(s3, glue, T1, **kwargs)
        later = call(s3, glue, T2, **kwargs)

        self.assertFalse(later.storage_changed)
        self.assertEqual(later.write_timestamp, iso(T1))
        self.assertEqual(later.last_verified_at, iso(T2))

    def test_a_verbatim_replay_still_leaves_the_sidecar_byte_identical(self):
        """last_verified_at comes from the caller's clock, not a wall clock."""
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        before = s3.sidecar_bytes()
        replay = call(s3, glue, T1)

        self.assertFalse(replay.storage_changed)
        self.assertFalse(replay.catalog_changed)
        self.assertEqual(before, s3.sidecar_bytes())

    def test_a_version_one_sidecar_holds_write_timestamp_and_upgrades_in_place(self):
        """Upgrade path: a pre-DVP-TSK-765 record has no last_verified_at.

        The state clock is held; the record itself is rewritten as the current
        version with last_verified_at added.
        """
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        legacy = s3.sidecar()
        legacy.pop("last_verified_at")
        legacy["record_version"] = 1
        s3.objects[(BUCKET, RECORD_KEY)] = (json.dumps(legacy).encode("utf-8"), {})

        later = call(s3, glue, T2)

        self.assertFalse(later.storage_changed)
        self.assertEqual(later.write_timestamp, iso(T1))
        self.assertEqual(later.last_verified_at, iso(T2))
        sidecar = s3.sidecar()
        self.assertEqual(sidecar["record_version"], REGISTRATION_RECORD_VERSION)
        self.assertEqual(sidecar["write_timestamp"], iso(T1))
        self.assertEqual(sidecar["last_verified_at"], iso(T2))

    def test_a_retry_after_a_failed_sidecar_emit_records_the_new_generation(self):
        """Data landed, the record did not: the retry must not hold the old clock.

        Neither flag is set on the retry (the bytes and the catalog are already
        current), so only the digest mismatch against the prior record marks
        the generation. Without it the sidecar would describe the new content
        under the previous generation's write_timestamp and write_seq.
        """
        s3, glue = FakeS3(), FakeGlue()
        call(s3, glue, T1)
        s3.fail_next_record_put = True
        with self.assertRaises(wr.StorageWriteError):
            call(s3, glue, T2, rows=CHANGED_ROWS)
        self.assertEqual(s3.data_puts, 2)
        self.assertEqual(s3.sidecar()["write_timestamp"], iso(T1))

        retry = call(s3, glue, T3, rows=CHANGED_ROWS)

        self.assertFalse(retry.storage_changed)
        self.assertFalse(retry.catalog_changed)
        self.assertEqual(retry.write_seq, 2)
        self.assertEqual(retry.write_timestamp, iso(T3))
        self.assertEqual(retry.last_verified_at, iso(T3))
        self.assertEqual(retry.previous_write_timestamp, iso(T1))
        self.assertEqual(retry.previous_row_count, len(OWNED_ROWS))
        sidecar = s3.sidecar()
        self.assertEqual(sidecar["content_sha256"], retry.content_sha256)
        self.assertEqual(sidecar["row_count"], len(CHANGED_ROWS))
        self.assertEqual(sidecar["write_timestamp"], iso(T3))
        self.assertEqual(sidecar["write_seq"], 2)

    def test_current_data_without_a_prior_record_starts_at_generation_one(self):
        """No sidecar to hold: the digest rule and the no-op fallback agree."""
        s3, glue = FakeS3(), FakeGlue()
        first = call(s3, glue, T1)
        del s3.objects[(BUCKET, RECORD_KEY)]

        later = call(s3, glue, T2)

        self.assertFalse(later.storage_changed)
        self.assertFalse(later.catalog_changed)
        self.assertEqual(later.content_sha256, first.content_sha256)
        self.assertEqual(later.write_seq, 1)
        self.assertEqual(later.write_timestamp, iso(T2))
        self.assertEqual(later.last_verified_at, iso(T2))
        self.assertEqual(later.previous_write_timestamp, "")
        self.assertIsNone(later.previous_row_count)
        self.assertEqual(later.previous_content_sha256, "")

    def test_the_record_declares_its_schema_version(self):
        s3, glue = FakeS3(), FakeGlue()
        record = call(s3, glue, T1)
        self.assertEqual(REGISTRATION_RECORD_VERSION, 2)
        self.assertEqual(record.record_version, REGISTRATION_RECORD_VERSION)
        self.assertIn("last_verified_at", record.generation_payload())
        self.assertEqual(s3.sidecar()["record_version"], REGISTRATION_RECORD_VERSION)


class ObserverClockTests(_ObserverClockCases, unittest.TestCase):
    """Stand-in serializer: runs everywhere, pyarrow or not."""

    def setUp(self):
        patcher = mock.patch.object(wr, "serialize_parquet", _stand_in_serializer)
        patcher.start()
        self.addCleanup(patcher.stop)


@needs_pyarrow
class ObserverClockRealParquetTests(_ObserverClockCases, unittest.TestCase):
    """The same contract against the real Parquet bytes."""


if __name__ == "__main__":
    unittest.main()
