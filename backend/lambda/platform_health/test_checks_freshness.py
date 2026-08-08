"""Tests for B6-R2 checks 1 and 5 (DVP-TSK-694).

The cases that matter are the ones that distinguish a real violation from data
that merely grew. A test suite that only asserts "stale table is flagged" would
pass an implementation that flags every table, which is the failure mode that
makes monitors get muted.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from checks_freshness import (
    check_freshness,
    check_full_refresh,
    full_refresh_violation,
    list_registered_tables,
)
from health_finding import Finding

NOW = datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)

DATABASES = {"devops": {"project": "devops", "bucket": "test-bucket", "tier": "warehouse"}}


def _record(table, **overrides):
    base = {
        "project": "devops",
        "table": table,
        "database": "devops",
        "trino_identifier": "hive.devops.%s" % table,
        "location": "s3://test-bucket/warehouse/devops/%s/" % table,
        "s3_uri": "s3://test-bucket/warehouse/devops/%s/data.parquet" % table,
        "row_count": 100,
        "byte_count": 5000,
        "prefix_byte_count": 5000,
        "file_count": 1,
        "write_timestamp": "2026-08-08T06:00:00Z",
        "write_seq": 3,
        "previous_file_count": 1,
        "previous_byte_count": 4800,
        "governed_layout": True,
    }
    base.update(overrides)
    return base


class FakeS3:
    """Minimal S3 stand-in: registration records plus per-prefix object counts."""

    def __init__(self, records, prefix_counts=None):
        self.records = {r["table"]: r for r in records}
        self.prefix_counts = prefix_counts or {}

    def list_objects_v2(self, **kwargs):
        prefix = kwargs["Prefix"]
        if prefix.startswith("warehouse-registrations/"):
            contents = [
                {"Key": "warehouse-registrations/devops/%s.json" % t} for t in self.records
            ]
            return {"Contents": contents, "IsTruncated": False}
        count = self.prefix_counts.get(prefix, 1)
        return {"KeyCount": count, "IsTruncated": False}

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3 signature
        table = Key.rsplit("/", 1)[-1][: -len(".json")]
        record = self.records[table]
        body = json.dumps(record).encode("utf-8")

        class _Body:
            def read(self_inner):
                return body

        return {"Body": _Body()}


class FakeGlue:
    def __init__(self, tables):
        self.tables = tables

    def get_tables(self, **kwargs):
        return {"TableList": [{"Name": t} for t in self.tables]}


# ---------------------------------------------------------------------------
# Check 1
# ---------------------------------------------------------------------------


def test_fresh_table_produces_no_finding():
    s3 = FakeS3([_record("dim_record")])
    result = check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert result.subjects_examined == 1
    assert result.findings == []
    assert result.severity == "ok"


def test_table_past_sla_is_flagged_stale():
    stale_at = (NOW - timedelta(hours=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
    s3 = FakeS3([_record("dim_record", write_timestamp=stale_at)])
    result = check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert [f.kind for f in result.findings] == ["stale"]
    finding = result.findings[0]
    assert finding.severity == "breach"
    assert finding.observed["age_hours"] == pytest.approx(40.0, abs=0.01)
    assert finding.expected["max_age_hours"] == 26.0


def test_table_just_inside_sla_is_not_flagged():
    """25h against a 26h SLA is healthy. The boundary is where a noisy monitor
    starts filing issues nobody can act on."""
    fresh_at = (NOW - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
    s3 = FakeS3([_record("dim_record", write_timestamp=fresh_at)])
    result = check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert result.findings == []


def test_registered_table_absent_from_glue_is_flagged():
    s3 = FakeS3([_record("dim_record")])
    result = check_freshness(s3, FakeGlue([]), now=NOW, databases=DATABASES)
    assert [f.kind for f in result.findings] == ["missing_catalog"]


def test_catalogued_table_with_empty_prefix_is_flagged():
    """The DVP-ISS-096 shape: the table exists, the query succeeds, zero rows come
    back, and the chart renders as a chart rather than as an error."""
    s3 = FakeS3(
        [_record("dim_record")],
        prefix_counts={"warehouse/devops/dim_record/": 0},
    )
    result = check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert [f.kind for f in result.findings] == ["missing_data"]


def test_unparseable_stamp_is_a_breach_not_a_skip():
    s3 = FakeS3([_record("dim_record", write_timestamp="not-a-timestamp")])
    result = check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert [f.kind for f in result.findings] == ["unparseable_freshness_stamp"]


def test_check_reads_the_registration_record_not_the_data_prefix():
    """AC-3: the measurement comes from the B2-R2 record. The only listing calls
    permitted are the registration-record enumeration and the absence probe."""
    calls = []

    class RecordingS3(FakeS3):
        def list_objects_v2(self, **kwargs):
            calls.append(kwargs["Prefix"])
            return super().list_objects_v2(**kwargs)

    s3 = RecordingS3([_record("dim_record")])
    check_freshness(s3, FakeGlue(["dim_record"]), now=NOW, databases=DATABASES)
    assert calls[0] == "warehouse-registrations/devops/"
    assert all(
        c.startswith("warehouse-registrations/") or c == "warehouse/devops/dim_record/"
        for c in calls
    )


def test_list_registered_tables_paginates():
    class PagedS3:
        def __init__(self):
            self.calls = 0

        def list_objects_v2(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return {
                    "Contents": [{"Key": "warehouse-registrations/devops/a.json"}],
                    "IsTruncated": True,
                    "NextContinuationToken": "t",
                }
            return {
                "Contents": [{"Key": "warehouse-registrations/devops/b.json"}],
                "IsTruncated": False,
            }

    assert list_registered_tables(PagedS3(), "test-bucket", "devops") == ["a", "b"]


# ---------------------------------------------------------------------------
# Check 5
# ---------------------------------------------------------------------------


def test_single_object_table_is_conformant():
    assert full_refresh_violation(_record("dim_record")) is None


def test_file_count_above_sharding_constant_violates():
    kind, summary = full_refresh_violation(_record("dim_record", file_count=4))
    assert kind == "file_count_exceeds_sharding_constant"
    assert "4 objects" in summary


def test_growth_in_files_and_bytes_together_is_legitimate_growth():
    """The distinction check 5 exists to draw. A table that genuinely got bigger
    shows file count up AND bytes up; only bytes standing still while files climb
    is snapshot-per-mutation partitioning."""
    record = _record(
        "dim_record",
        file_count=3,
        previous_file_count=2,
        byte_count=9000,
        previous_byte_count=5000,
    )
    # File count rose 2 -> 3 but bytes rose 5000 -> 9000: real growth, not a
    # snapshot per write. The check must stay silent.
    assert full_refresh_violation(record, sharding_constant=4) is None


def test_files_grow_while_bytes_do_not_is_the_violation():
    record = _record(
        "dim_record",
        file_count=3,
        previous_file_count=2,
        byte_count=5000,
        previous_byte_count=5000,
    )
    kind, summary = full_refresh_violation(record, sharding_constant=4)
    assert kind == "file_count_grew_without_data"
    assert "snapshot-per-mutation" in summary


def test_check_full_refresh_flags_the_offending_table():
    s3 = FakeS3([_record("dim_record", file_count=7)])
    result = check_full_refresh(s3, databases=DATABASES)
    assert result.severity == "breach"
    assert result.findings[0].subject == "hive.devops.dim_record"
    assert result.findings[0].references == ["DOC-1E1EC5B7CE02", "DOC-F56858AFE749 obligation 2"]


# ---------------------------------------------------------------------------
# Finding identity
# ---------------------------------------------------------------------------


def test_signature_is_stable_across_a_worsening_measurement():
    """A table 27h stale on Monday and 51h stale on Tuesday is ONE unresolved
    finding. If the signature moved with the measurement, every run would open a
    new P1 -- the ENC-ISS-369..379 storm, reproduced."""
    a = Finding(check="check_1_freshness", subject="hive.devops.t", severity="breach",
                kind="stale", summary="x", observed={"age_hours": 27})
    b = Finding(check="check_1_freshness", subject="hive.devops.t", severity="breach",
                kind="stale", summary="y", observed={"age_hours": 51})
    assert a.signature == b.signature


def test_signature_changes_when_the_condition_changes_shape():
    a = Finding(check="check_1_freshness", subject="hive.devops.t", severity="breach",
                kind="stale", summary="x")
    b = Finding(check="check_1_freshness", subject="hive.devops.t", severity="breach",
                kind="missing_data", summary="x")
    assert a.signature != b.signature
