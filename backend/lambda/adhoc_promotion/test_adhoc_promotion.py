"""Contract tests for the ad-hoc promotion transform (DVP-TSK-661).

These are the CI enforcement of BRD B5-R2. The suite is organised by the task
that owns each guarantee, because each is a separate acceptance criterion:

``TestTypeMapPrePopulation``   DVP-TSK-685 -- promotion is a review, not authoring
``TestAllOrNothingCoercion``   DVP-TSK-686 -- one bad value fails the whole run
``TestGovernedOutput``         DVP-TSK-687 -- written through the shared library
``TestNoAgentConstraint``      DVP-TSK-688/689 -- D-4, enforced not documented

The fixture is ``adhoc_probe_01.csv`` as it actually lands in ``hive.adhoc``
through Superset's upload dialog: leading-zero zip codes preserved as text, a
literal ``NULL`` sitting in a column that is otherwise integers, and currency
that pandas could only ever hand over as a float. Those three are named in the
DVP-TSK-686 acceptance criteria and they are three genuinely different
mechanisms -- a silent lossy conversion, a raising conversion, and a type the
upload dialog cannot express at all -- so each is asserted separately.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "shared_layer",
        "python",
    ),
)

from enceladus_shared.warehouse_registration import (  # noqa: E402
    ALLOWED_TYPE_PATTERN,
    DATA_OBJECT_NAME,
    GLUE_TABLE_TYPE,
    HIVE_SERDE_LIBRARY,
    ColumnSpec,
    register_table,
)

import promotion_coerce  # noqa: E402
import promotion_plan  # noqa: E402
import promotion_run  # noqa: E402
import promotion_source  # noqa: E402
from lambda_function import lambda_handler  # noqa: E402
from promotion_coerce import PromotionCoercionError, coerce_rows, round_trips  # noqa: E402
from promotion_plan import build_plan, propose_column  # noqa: E402
from promotion_run import PromotionRefused, plan_promotion, promote  # noqa: E402
from promotion_source import QuarantinedTable, load_quarantined_table  # noqa: E402

BUCKET = "devops-agentcli-compute"
ADHOC_LOCATION = "s3://%s/adhoc/adhoc_probe_01/" % BUCKET

#: adhoc_probe_01.csv exactly as Superset's pandas path lands it. Note what the
#: INFERRED types are: everything that could carry a leading zero or a literal
#: NULL arrives as text, and money arrives as a float. None of DATE, TIMESTAMP or
#: DECIMAL appears, because the upload dialog cannot express them.
PROBE_COLUMNS = [
    ("customer_id", "string"),
    ("zip_code", "string"),
    ("order_date", "string"),
    ("order_ts", "string"),
    ("amount", "double"),
    ("qty", "string"),
    ("active", "string"),
]

PROBE_ROWS = [
    {
        "customer_id": "c-001",
        "zip_code": "01234",          # leading zero: DATA, not formatting
        "order_date": "2026-01-02",
        "order_ts": "2026-01-02T09:30:00Z",
        "amount": 1234.56,
        "qty": "12",
        "active": "true",
    },
    {
        "customer_id": "c-002",
        "zip_code": "90210",
        "order_date": "2026-03-14",
        "order_ts": "2026-03-14T17:05:12Z",
        "amount": 89.9,
        "qty": "NULL",                # literal NULL in an integer column
        "active": "false",
    },
    {
        "customer_id": "c-003",
        "zip_code": "02139",
        "order_date": "2026-06-30",
        "order_ts": "2026-06-30T23:59:59Z",
        "amount": 4.05,
        "qty": "7",
        "active": "true",
    },
]

UPLOAD_TIME = "2026-08-01T10:15:00Z"


# ---------------------------------------------------------------------------
# Fakes -- same shape as backend/lambda/shared_layer/test_warehouse_registration.py
# ---------------------------------------------------------------------------


class _NotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "404"}}


class _GlueNotFound(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "EntityNotFoundException"}}


def _probe_parquet() -> bytes:
    import pyarrow as pa
    import pyarrow.parquet as pq

    schema = pa.schema(
        [
            pa.field("customer_id", pa.string()),
            pa.field("zip_code", pa.string()),
            pa.field("order_date", pa.string()),
            pa.field("order_ts", pa.string()),
            pa.field("amount", pa.float64()),
            pa.field("qty", pa.string()),
            pa.field("active", pa.string()),
        ]
    )
    columns = {name: [row[name] for row in PROBE_ROWS] for name in schema.names}
    sink = io.BytesIO()
    pq.write_table(pa.Table.from_pydict(columns, schema=schema), sink)
    return sink.getvalue()


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.data_puts = 0
        self.record_puts = 0
        self.objects[(BUCKET, "adhoc/adhoc_probe_01/data.parquet")] = (_probe_parquet(), {})

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

    def keys_under(self, prefix):
        return sorted(key for (_, key) in self.objects if key.startswith(prefix))


class FakeGlue:
    def __init__(self):
        self.tables = {}
        self.create_calls = 0
        self.update_calls = 0
        self.tables[("adhoc", "adhoc_probe_01")] = {
            "Name": "adhoc_probe_01",
            "Parameters": {
                "classification": "parquet",
                "uploaded_by": "io",
                "uploaded_at": UPLOAD_TIME,
                "source_file": "adhoc_probe_01.csv",
            },
            "CreateTime": "2026-08-01T10:15:00Z",
            "StorageDescriptor": {
                "Columns": [{"Name": n, "Type": t} for n, t in PROBE_COLUMNS],
                "Location": ADHOC_LOCATION,
                "SerdeInfo": {"SerializationLibrary": HIVE_SERDE_LIBRARY},
            },
        }

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


@pytest.fixture()
def clients():
    return FakeGlue(), FakeS3()


@pytest.fixture()
def source(clients):
    glue, s3 = clients
    return load_quarantined_table(glue, s3, "adhoc_probe_01", "adhoc")


#: The map io would submit after reviewing the plan and correcting nothing that
#: matters: dates and money upgraded, the zip kept as text, and `qty` left as
#: text because a literal NULL lives in it.
REVIEWED_TYPE_MAP = {
    "customer_id": "string",
    "zip_code": "string",
    "order_date": "date",
    "order_ts": "timestamp",
    "amount": "decimal(12,2)",
    "qty": "string",
    "active": "boolean",
}


def _human(**extra):
    event = {"actor": {"kind": "human", "id": "io", "surface": "superset"}}
    event.update(extra)
    return event


# ---------------------------------------------------------------------------
# DVP-TSK-685 -- type-map pre-population, the R-6 mitigation
# ---------------------------------------------------------------------------


class TestTypeMapPrePopulation:
    def test_no_column_is_ever_blank(self, source):
        """The R-6 invariant, asserted directly.

        If any column arrived with an empty proposed type, promotion would be an
        authoring exercise for that column and io would be back to filling in a
        blank form -- the exact condition under which io keeps charting from
        quarantine forever.
        """
        plan = build_plan(source, "devops")
        assert plan.columns, "a plan with no columns cannot be reviewed"
        for proposal in plan.columns:
            assert proposal.proposed_type, "column %r arrived blank" % proposal.name
            assert proposal.reason, "column %r proposes a type with no stated reason" % proposal.name

    def test_accepting_the_draft_unedited_is_always_promotable(self, source):
        """Every fallback is a legal declared type, so the untouched plan works."""
        plan = build_plan(source, "devops")
        for column, declared in plan.type_map.items():
            assert ALLOWED_TYPE_PATTERN.match(declared), (
                "proposed type %r for %r is not a legal SQL type" % (declared, column)
            )

    def test_date_like_varchar_proposed_as_date(self, source):
        plan = {c.name: c for c in build_plan(source, "devops").columns}
        assert plan["order_date"].proposed_type == "date"
        assert plan["order_date"].upgraded is True
        assert "upload dialog" in plan["order_date"].reason

    def test_datetime_like_varchar_proposed_as_timestamp(self, source):
        plan = {c.name: c for c in build_plan(source, "devops").columns}
        assert plan["order_ts"].proposed_type == "timestamp"
        assert plan["order_ts"].upgraded is True

    def test_currency_double_proposed_as_decimal(self, source):
        """The type unreachable at the dialog at ANY level of user diligence."""
        plan = {c.name: c for c in build_plan(source, "devops").columns}
        proposal = plan["amount"]
        assert proposal.proposed_type.startswith("decimal("), proposal.proposed_type
        assert proposal.proposed_type.endswith(",2)"), "money is written at scale 2"
        assert proposal.upgraded is True
        assert proposal.inferred_type == "double"

    def test_leading_zero_column_kept_as_text_and_warned(self, source):
        """The silent-corruption case. int('01234') == 1234 and does not raise."""
        plan = {c.name: c for c in build_plan(source, "devops").columns}
        proposal = plan["zip_code"]
        assert proposal.proposed_type == "string"
        assert proposal.warning, "a lossy alternative must carry a warning"
        for alternative in proposal.alternatives:
            assert not alternative.startswith(("int", "bigint", "smallint", "tinyint")), (
                "an integer type must never be offered for a leading-zero column: %r"
                % alternative
            )

    def test_upgrade_withdrawn_on_a_single_counterexample(self):
        """One bad value withdraws the proposal. Evidence, not vibes."""
        good = propose_column("order_date", "string", ["2026-01-02", "2026-03-14"])
        assert good.proposed_type == "date"
        mixed = propose_column("order_date", "string", ["2026-01-02", "not a date"])
        assert mixed.proposed_type == "string"
        assert mixed.upgraded is False

    def test_shape_matching_non_dates_are_rejected(self):
        """2026-13-45 matches the regex and is not a date."""
        assert propose_column("d", "string", ["2026-13-45"]).proposed_type == "string"

    def test_empty_column_earns_no_upgrade(self):
        assert propose_column("order_date", "string", []).proposed_type == "string"

    def test_freshness_column_is_always_present_and_system_managed(self, source):
        plan = build_plan(source, "devops")
        freshness = [c for c in plan.columns if c.name == plan.freshness_column]
        assert len(freshness) == 1
        assert freshness[0].system_managed is True
        assert freshness[0].proposed_type == "string"

    def test_review_summary_reports_what_io_did_not_have_to_write(self, source):
        plan = build_plan(source, "devops")
        assert plan.upgrade_count >= 3  # order_date, order_ts, amount at minimum
        assert "blank" in plan.review_summary

    def test_plan_carries_samples_so_review_needs_no_sql_lab(self, source):
        plan = {c.name: c for c in build_plan(source, "devops").columns}
        assert plan["zip_code"].sample_values, "io must see real values beside the proposal"


# ---------------------------------------------------------------------------
# DVP-TSK-686 -- all-or-nothing coercion and offending-row reporting
# ---------------------------------------------------------------------------


class TestAllOrNothingCoercion:
    def test_declared_types_apply_including_date_timestamp_decimal(self):
        import datetime as dt
        from decimal import Decimal

        rows = coerce_rows(
            [PROBE_ROWS[0]],
            {"order_date": "date", "order_ts": "timestamp", "amount": "decimal(12,2)"},
            table="hive.adhoc.adhoc_probe_01",
        )
        assert rows[0]["order_date"] == dt.date(2026, 1, 2)
        assert isinstance(rows[0]["order_ts"], dt.datetime)
        assert rows[0]["amount"] == Decimal("1234.56")

    def test_leading_zero_to_int_is_reported_as_lossy(self):
        """Case 1: the coercion SUCCEEDS in Python and destroys the data."""
        assert int("01234") == 1234  # the whole problem, in one line
        with pytest.raises(PromotionCoercionError) as caught:
            coerce_rows(PROBE_ROWS, {"zip_code": "bigint"}, table="t")
        offenders = caught.value.offenders
        assert any(o.column == "zip_code" and o.lossy for o in offenders)
        assert any("01234" in o.raw_value for o in offenders)

    def test_literal_null_in_an_integer_column_is_reported(self):
        """Case 2: a raising coercion, plus the judgement we refuse to make."""
        with pytest.raises(PromotionCoercionError) as caught:
            coerce_rows(PROBE_ROWS, {"qty": "bigint"}, table="t")
        offenders = caught.value.offenders
        assert len(offenders) == 1
        assert offenders[0].column == "qty"
        assert offenders[0].raw_value == "NULL"
        assert offenders[0].row_number == 3  # 0-based row 1 -> CSV line 3

    def test_currency_requiring_decimal_coerces_cleanly(self):
        """Case 3: the type the dialog could not express, applied at promotion."""
        from decimal import Decimal

        rows = coerce_rows(PROBE_ROWS, {"amount": "decimal(12,2)"}, table="t")
        assert [r["amount"] for r in rows] == [
            Decimal("1234.56"),
            Decimal("89.90"),
            Decimal("4.05"),
        ]

    def test_decimal_trailing_zeros_are_notation_not_loss(self):
        """12.50 -> 12.5 must NOT be reported; 01234 -> 1234 must be."""
        from decimal import Decimal

        assert round_trips("12.50", Decimal("12.50"), "decimal(12,2)") is True
        assert round_trips("01234", 1234, "bigint") is False

    def test_all_offenders_are_reported_not_just_the_first(self):
        """One round trip must tell io everything that needs fixing."""
        with pytest.raises(PromotionCoercionError) as caught:
            coerce_rows(PROBE_ROWS, {"zip_code": "bigint", "qty": "bigint"}, table="t")
        columns = {o.column for o in caught.value.offenders}
        assert columns == {"zip_code", "qty"}
        # 01234 and 02139 are lossy; 90210 coerces cleanly; plus the literal NULL.
        assert caught.value.total == 3

    def test_offender_carries_the_full_four_part_identifier(self):
        with pytest.raises(PromotionCoercionError) as caught:
            coerce_rows(PROBE_ROWS, {"qty": "bigint"}, table="hive.adhoc.adhoc_probe_01")
        offender = caught.value.offenders[0]
        assert offender.table == "hive.adhoc.adhoc_probe_01"
        assert offender.column and offender.raw_value and offender.declared_type
        assert offender.row_index == 1

    def test_offender_report_is_capped_but_the_count_is_exact(self):
        rows = [{"z": "0%03d" % i} for i in range(200)]
        with pytest.raises(PromotionCoercionError) as caught:
            coerce_rows(rows, {"z": "bigint"}, table="t")
        assert caught.value.total == 200
        assert len(caught.value.offenders) == promotion_coerce.MAX_REPORTED_OFFENDERS
        assert caught.value.as_dict()["truncated"] is True

    def test_failure_returns_nothing_at_all(self):
        """There is no partial-success return value, by design."""
        with pytest.raises(PromotionCoercionError):
            coerce_rows(PROBE_ROWS, {"qty": "bigint", "amount": "decimal(12,2)"}, table="t")

    def test_reviewed_map_coerces_the_whole_probe_table(self):
        rows = coerce_rows(PROBE_ROWS, REVIEWED_TYPE_MAP, table="t")
        assert len(rows) == 3


# ---------------------------------------------------------------------------
# DVP-TSK-687 -- governed output through the B2-R2 shared library
# ---------------------------------------------------------------------------


class TestGovernedOutput:
    def _promote(self, glue, s3, **kwargs):
        return promote(
            glue,
            s3,
            source_table="adhoc_probe_01",
            target_project="devops",
            target_table="probe_promoted",
            type_map=REVIEWED_TYPE_MAP,
            bucket=BUCKET,
            **kwargs,
        )

    def test_writes_parquet_to_the_governed_prefix(self, clients):
        glue, s3 = clients
        result = self._promote(glue, s3)
        assert result.s3_uri == "s3://%s/warehouse/devops/probe_promoted/%s" % (
            BUCKET,
            DATA_OBJECT_NAME,
        )
        assert s3.keys_under("warehouse/devops/probe_promoted/") == [
            "warehouse/devops/probe_promoted/data.parquet"
        ]
        assert result.row_count == 3

    def test_registers_through_the_library_not_its_own_glue_code(self, clients):
        glue, s3 = clients
        self._promote(glue, s3)
        table = glue.tables[("devops", "probe_promoted")]
        assert table["TableType"] == GLUE_TABLE_TYPE
        assert (
            table["StorageDescriptor"]["SerdeInfo"]["SerializationLibrary"]
            == HIVE_SERDE_LIBRARY
        )
        assert table["PartitionKeys"] == []

    def test_the_three_unreachable_types_survive_into_the_catalog(self, clients):
        glue, s3 = clients
        self._promote(glue, s3)
        declared = {
            c["Name"]: c["Type"]
            for c in glue.tables[("devops", "probe_promoted")]["StorageDescriptor"]["Columns"]
        }
        assert declared["order_date"] == "date"
        assert declared["order_ts"] == "timestamp"
        assert declared["amount"] == "decimal(12,2)"

    def test_indistinguishable_from_a_project_export_job(self, clients):
        """Not 'similar to'. The same function, so the same bytes.

        A direct register_table call with the same declaration must produce a
        byte-identical Glue TableInput and the same S3 key. If promotion ever
        grew its own catalog spelling, this is the test that would fail.
        """
        glue, s3 = clients
        self._promote(glue, s3)
        promoted = glue.tables[("devops", "probe_promoted")]

        glue2, s32 = FakeGlue(), FakeS3()
        columns = [
            ColumnSpec(name=n, type=t) for n, t in REVIEWED_TYPE_MAP.items()
        ] + [
            ColumnSpec(
                name="ingest_ts",
                type="string",
                comment="upload time of the quarantined source, carried through on promotion",
            )
        ]
        register_table(
            project="devops",
            table="probe_promoted",
            rows=[dict(r, ingest_ts=UPLOAD_TIME) for r in PROBE_ROWS],
            columns=columns,
            bucket=BUCKET,
            stamp_freshness=False,
            table_comment=promoted.get("Description", ""),
            s3_client=s32,
            glue_client=glue2,
        )
        assert promoted == glue2.tables[("devops", "probe_promoted")]

    def test_freshness_is_the_data_arrival_time_not_the_run_time(self, clients):
        """A promoted table must not claim the data is as fresh as the transform."""
        glue, s3 = clients
        result = self._promote(glue, s3)
        assert result.freshness_value == UPLOAD_TIME
        assert result.freshness_value != result.write_timestamp

    def test_provenance_carries_through_to_the_governed_table(self, clients):
        glue, s3 = clients
        result = self._promote(glue, s3)
        description = glue.tables[("devops", "probe_promoted")]["Description"]
        assert "hive.adhoc.adhoc_probe_01" in description
        assert "adhoc_probe_01.csv" in description
        assert result.provenance["uploaded_by"] == "io"

    def test_a_failed_promotion_writes_absolutely_nothing(self, clients):
        """All-or-nothing is structural: AWS is never reached on the bad path."""
        glue, s3 = clients
        bad_map = dict(REVIEWED_TYPE_MAP, zip_code="bigint")
        with pytest.raises(PromotionCoercionError):
            promote(
                glue,
                s3,
                source_table="adhoc_probe_01",
                target_project="devops",
                target_table="probe_promoted",
                type_map=bad_map,
                bucket=BUCKET,
            )
        assert s3.data_puts == 0
        assert s3.record_puts == 0
        assert glue.create_calls == 0
        assert ("devops", "probe_promoted") not in glue.tables

    def test_promoting_back_into_quarantine_is_refused(self, clients):
        glue, s3 = clients
        with pytest.raises(PromotionRefused, match="quarantine"):
            promote(
                glue,
                s3,
                source_table="adhoc_probe_01",
                target_project="adhoc",
                type_map=REVIEWED_TYPE_MAP,
                bucket=BUCKET,
            )

    def test_pandas_dtypes_are_refused_as_declared_types(self, clients):
        glue, s3 = clients
        with pytest.raises(PromotionRefused, match="never pandas dtypes"):
            promote(
                glue,
                s3,
                source_table="adhoc_probe_01",
                target_project="devops",
                type_map={"amount": "float64"},
                bucket=BUCKET,
            )

    def test_an_empty_type_map_is_refused(self, clients):
        glue, s3 = clients
        with pytest.raises(PromotionRefused, match="no type map"):
            promote(
                glue,
                s3,
                source_table="adhoc_probe_01",
                target_project="devops",
                type_map={},
                bucket=BUCKET,
            )

    def test_promotion_reads_every_row_not_a_sample(self, clients):
        """A sampled all-or-nothing gate is not an all-or-nothing gate."""
        glue, s3 = clients
        captured = {}
        original = promotion_source.read_rows

        def spy(s3_client, location, limit=None):
            captured["limit"] = limit
            return original(s3_client, location, limit=limit)

        promotion_source.read_rows = spy
        try:
            self._promote(glue, s3)
        finally:
            promotion_source.read_rows = original
        assert captured["limit"] is None


# ---------------------------------------------------------------------------
# DVP-TSK-688 / 689 -- the D-4 no-agent constraint, enforced
# ---------------------------------------------------------------------------


class TestNoAgentConstraint:
    def test_an_agent_session_id_is_refused(self):
        response = lambda_handler(
            {
                "action": "plan",
                "source_table": "adhoc_probe_01",
                "target_project": "devops",
                "actor": {"kind": "human", "id": "ENC-SES-0C1", "surface": "superset"},
            },
            None,
        )
        assert response["statusCode"] == 403
        assert "agent session" in response["body"]["error"]

    def test_a_non_human_actor_is_refused(self):
        response = lambda_handler(
            {
                "action": "promote",
                "source_table": "adhoc_probe_01",
                "target_project": "devops",
                "actor": {"kind": "agent", "id": "some-agent"},
            },
            None,
        )
        assert response["statusCode"] == 403

    def test_a_missing_actor_is_refused(self):
        response = lambda_handler(
            {"action": "plan", "source_table": "adhoc_probe_01", "target_project": "devops"},
            None,
        )
        assert response["statusCode"] == 403

    def test_an_anonymous_human_is_refused(self):
        """Promotion is an attributable act."""
        response = lambda_handler(
            {
                "action": "plan",
                "source_table": "adhoc_probe_01",
                "target_project": "devops",
                "actor": {"kind": "human", "id": "", "surface": "superset"},
            },
            None,
        )
        assert response["statusCode"] == 403

    def test_only_sanctioned_surfaces_are_accepted(self):
        response = lambda_handler(
            _human(
                action="plan",
                source_table="adhoc_probe_01",
                target_project="devops",
            )
            | {"actor": {"kind": "human", "id": "io", "surface": "terminal"}},
            None,
        )
        assert response["statusCode"] == 403
        assert "sanctioned promotion surface" in response["body"]["error"]

    def test_the_refusal_happens_before_any_table_is_read(self, monkeypatch):
        """An agent must not even be able to use this as a read oracle."""
        called = {"read": False}

        def boom(*args, **kwargs):
            called["read"] = True
            raise AssertionError("the source table must not be read")

        monkeypatch.setattr(promotion_run, "plan_promotion", boom)
        response = lambda_handler(
            {
                "action": "plan",
                "source_table": "adhoc_probe_01",
                "target_project": "devops",
                "actor": {"kind": "agent", "id": "x"},
            },
            None,
        )
        assert response["statusCode"] == 403
        assert called["read"] is False
