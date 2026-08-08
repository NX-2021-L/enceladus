"""Conformance tests for the governance analytics mart (BRD B3).

These are contract tests, not coverage theatre. Each one asserts a clause that
a governed document states in prose, so that violating the prose fails CI:

* ``DOC-3391173F2A5C`` -- metadata only; the substitution test; daily grain on
  every fact table from the outset.
* ``DOC-04AF8A02A8F7`` -- T2 layout, Parquet, declared registration, the
  mandatory freshness stamp.
* ``DOC-5E35E14DAD05`` -- schema is DECLARED; nothing is inferred.
* ``DOC-1E1EC5B7CE02`` -- full refresh; no partition keys.

Run: ``python3 -m pytest backend/lambda/governance_mart/ -q``
No AWS credentials required -- every test runs against synthetic corpora or
pure declarations.
"""

from __future__ import annotations

import os
import sys
from datetime import date

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
sys.path.insert(0, os.path.join(_REPO, "backend", "lambda", "shared_layer", "python"))
sys.path.insert(0, _HERE)

from enceladus_shared.warehouse_registration import (  # noqa: E402
    DATA_OBJECT_NAME,
    STORAGE_FORMAT,
    build_contract,
)

import mart_project  # noqa: E402
import mart_schema  # noqa: E402
from mart_source import is_sentinel  # noqa: E402


MART_BUCKET = "devops-agentcli-compute"


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


def test_seven_tables_declared():
    """DVP-TSK-648 AC-1: all seven tables, named exactly as the BRD names them."""
    assert mart_schema.table_names() == [
        "dim_record",
        "fact_record_daily",
        "fact_record_transition",
        "dim_document",
        "fact_document_daily",
        "fact_session_daily",
        "fact_graph_health_daily",
    ]


def test_every_fact_table_carries_snapshot_date():
    """DVP-TSK-648 AC-2 / DOC-3391173F2A5C: daily grain is the INITIAL shape."""
    assert len(mart_schema.FACT_TABLES) == 5
    for name in mart_schema.FACT_TABLES:
        assert "snapshot_date" in mart_schema.MART_TABLES[name].column_names, name
    mart_schema.assert_daily_grain()


def test_every_table_carries_the_freshness_stamp():
    """DOC-04AF8A02A8F7: the freshness column is MANDATORY, not optional."""
    for name in mart_schema.table_names():
        assert mart_schema.FRESHNESS_COLUMN in mart_schema.MART_TABLES[name].column_names, name


@pytest.mark.parametrize("table", mart_schema.MART_TABLE_ORDER)
def test_declaration_satisfies_the_shared_contract(table):
    """Every declared table survives the B2-R2 library's own validation.

    ``build_contract`` touches no AWS API, so this is a pure conformance check
    of names, types, reserved words, and the freshness column.
    """
    contract = build_contract(
        project=mart_schema.MART_PROJECT,
        table=table,
        columns=mart_schema.columns_for(table),
        bucket=MART_BUCKET,
        database="devops",
    )
    assert contract.trino_identifier == "hive.devops.%s" % table
    assert contract.location == "s3://%s/warehouse/devops/%s/" % (MART_BUCKET, table)
    # One object per table at a CONSTANT key: this is what makes file count
    # invariant across refreshes (DOC-1E1EC5B7CE02).
    assert contract.s3_key == "warehouse/devops/%s/%s" % (table, DATA_OBJECT_NAME)
    assert contract.is_governed_layout


@pytest.mark.parametrize("table", mart_schema.MART_TABLE_ORDER)
def test_no_partition_keys(table):
    """DOC-1E1EC5B7CE02: full-refresh overwrite, so partition explosion is
    impossible by construction rather than by monitoring."""
    contract = build_contract(
        project=mart_schema.MART_PROJECT,
        table=table,
        columns=mart_schema.columns_for(table),
        bucket=MART_BUCKET,
        database="devops",
    )
    table_input = contract.glue_table_input()
    assert table_input["PartitionKeys"] == []
    assert table_input["Parameters"]["classification"] == STORAGE_FORMAT


# ---------------------------------------------------------------------------
# The substitution test -- DOC-3391173F2A5C, enforced
# ---------------------------------------------------------------------------

#: Column names that would reproduce what a record SAYS rather than what it IS.
#: Their appearance is itself the Risk R-4 drift signal, independent of any
#: size measurement -- so it is asserted here rather than left to a monitor.
_FORBIDDEN_SUBSTANCE_COLUMNS = frozenset(
    {
        "title", "description", "intent", "content", "body", "text",
        "acceptance_criteria", "criteria", "evidence", "worklog", "history",
        "notes", "technical_notes", "hypothesis", "user_story", "summary",
        "last_update_note", "compliance_warnings", "full_description",
        "claude_description", "prose", "comment",
    }
)


@pytest.mark.parametrize("table", mart_schema.MART_TABLE_ORDER)
def test_substitution_test_no_free_text_columns(table):
    """The standing test, applied mechanically to every declared column.

    'If a proposed column would let a reader substitute the mart for the record
    store, it does not belong.' A reader must be able to count, group, and
    trend -- and must NOT be able to reconstruct the record.
    """
    for name in mart_schema.MART_TABLES[table].column_names:
        assert name not in _FORBIDDEN_SUBSTANCE_COLUMNS, (
            "%s.%s reproduces record substance and violates the B3-R1 "
            "substitution test (DOC-3391173F2A5C)." % (table, name)
        )


def test_counts_not_contents_for_the_two_riskiest_sources():
    """Where substance was available, a COUNT was projected instead."""
    document_columns = mart_schema.MART_TABLES["dim_document"].column_names
    assert "compliance_warning_count" in document_columns
    assert "related_item_count" in document_columns
    assert "size_bytes" in document_columns  # how much, never what
    assert "content" not in document_columns
    # The transition table reads free-text history and emits only tokens.
    transition_columns = mart_schema.MART_TABLES["fact_record_transition"].column_names
    assert set(transition_columns) >= {"from_status", "to_status", "days_in_prior_status"}
    assert "description" not in transition_columns


# ---------------------------------------------------------------------------
# Projection behaviour
# ---------------------------------------------------------------------------


def _record(**overrides):
    base = {
        "project_id": "devops",
        "record_id": "task#DVP-TSK-001",
        "item_id": "DVP-TSK-001",
        "record_type": "task",
        "status": "closed",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-05T00:00:00Z",
        "history": [],
    }
    base.update(overrides)
    return base


class _Corpus:
    def __init__(self, records=None, documents=None, sessions=None, agent_types=None):
        self.records = records or []
        self.documents = documents or []
        self.sessions = sessions or []
        self.agent_types = agent_types or []
        self.coordination_requests = []

    @property
    def agent_type_index(self):
        return {entry["agent_type_id"]: entry for entry in self.agent_types}

    def counts(self):
        return {"records": len(self.records), "documents": len(self.documents)}


def test_extract_transitions_recovers_the_chain_and_discards_the_prose():
    record = _record(
        history=[
            {"timestamp": "2026-01-01T00:00:00Z", "status": "created", "description": "Created via tracker API: something"},
            {"timestamp": "2026-01-02T00:00:00Z", "status": "worklog", "description": "Field 'status' set to 'in-progress' [provider=ENC-SES-0AA]"},
            {"timestamp": "2026-01-03T12:00:00Z", "status": "worklog", "description": "Field 'status' set to 'coding-complete' [provider=ENC-SES-0AA]"},
            {"timestamp": "2026-01-05T00:00:00Z", "status": "worklog", "description": "Status changed to 'closed' by someone"},
        ]
    )
    transitions = mart_project.extract_transitions(record)
    assert [(t["from_status"], t["to_status"]) for t in transitions] == [
        ("open", "in-progress"),
        ("in-progress", "coding-complete"),
        ("coding-complete", "closed"),
    ]
    assert transitions[0]["days_in_prior_status"] == pytest.approx(1.0)
    assert transitions[1]["days_in_prior_status"] == pytest.approx(1.5)
    # The prose that carried the transition is nowhere in the output.
    for transition in transitions:
        assert "description" not in transition
        assert not any("provider" in str(value) for value in transition.values())


def test_repeated_status_is_not_a_transition():
    """Re-asserting a status would inflate throughput and zero out cycle time."""
    record = _record(
        history=[
            {"timestamp": "2026-01-02T00:00:00Z", "status": "worklog", "description": "Field 'status' set to 'in-progress'"},
            {"timestamp": "2026-01-02T01:00:00Z", "status": "worklog", "description": "Field 'status' set to 'in-progress'"},
        ]
    )
    assert len(mart_project.extract_transitions(record)) == 1


def test_underscored_legacy_status_folds_to_the_governed_form():
    record = _record(
        history=[{"timestamp": "2026-01-02T00:00:00Z", "status": "worklog", "description": "Field 'status' set to 'in_progress' via tracker.py"}]
    )
    assert mart_project.extract_transitions(record)[0]["to_status"] == "in-progress"


def test_ontology_completeness_matches_the_record_store_rubric():
    """Verified against the live API: DVP-TSK-648 scores 55/70 -> 79."""
    record = _record(
        record_type="task",
        title="B3-R2 - Define and build the seven mart tables",
        priority="P1",
        category="implementation",
        intent="BRD B3-R2.",
        acceptance_criteria=[{"description": "x", "evidence_acceptance": False}],
        parent="DVP-TSK-613",
    )
    assert mart_project.ontology_completeness_score(record) == 79


def test_fact_record_daily_is_one_row_per_record_per_day():
    """`record_count` must partition the record set: no double counting when
    several transitions land on the same day."""
    record = _record(
        status="closed",
        created_at="2026-01-01T00:00:00Z",
        history=[
            {"timestamp": "2026-01-02T01:00:00Z", "status": "worklog", "description": "Field 'status' set to 'in-progress'"},
            {"timestamp": "2026-01-02T09:00:00Z", "status": "worklog", "description": "Field 'status' set to 'closed'"},
        ],
    )
    rows = mart_project.build_fact_record_daily(_Corpus(records=[record]), date(2026, 1, 3))
    by_day = {}
    for row in rows:
        by_day.setdefault(row["snapshot_date"], 0)
        by_day[row["snapshot_date"]] += row["record_count"]
    assert by_day == {date(2026, 1, 1): 1, date(2026, 1, 2): 1, date(2026, 1, 3): 1}
    # The day holds its LAST status, and the closure is counted once.
    day_two = [r for r in rows if r["snapshot_date"] == date(2026, 1, 2)]
    assert len(day_two) == 1 and day_two[0]["status"] == "closed"
    assert sum(r["closed_count"] for r in rows) == 1
    assert sum(r["opened_count"] for r in rows) == 1


def test_fact_record_daily_series_stops_at_last_day():
    """OBJ-6: the series is bounded by the refresh, so a refresh that stops
    running produces a chart that stops drawing."""
    rows = mart_project.build_fact_record_daily(_Corpus(records=[_record()]), date(2026, 1, 3))
    assert max(row["snapshot_date"] for row in rows) == date(2026, 1, 3)


def test_graph_health_declares_awaiting_upstream_columns_as_null():
    """DVP-TSK-678 AC-3 / risk R-11: DEFINED NOW, populated incrementally."""
    corpus = _Corpus(
        records=[
            _record(item_id="DVP-TSK-001", created_at="2026-01-01T00:00:00Z", parent="DVP-TSK-002"),
            _record(item_id="DVP-TSK-002", created_at="2026-01-01T00:00:00Z"),
            _record(item_id="DVP-TSK-003", created_at="2026-01-01T00:00:00Z", parent="DVP-TSK-999"),
        ]
    )
    rows = mart_project.build_fact_graph_health_daily(corpus, date(2026, 1, 2))
    assert rows, "graph health must not be empty while it waits for upstream"
    latest = rows[-1]
    assert latest["node_count"] == 3
    assert latest["edge_count"] == 1          # 001 -> 002 resolves
    assert latest["unresolved_edge_count"] == 1  # 003 -> 999 dangles
    assert latest["orphan_node_count"] == 1   # 003 has no resolvable edge
    for column in ("hot_tier_fraction", "percolation_margin", "fiedler_value", "demand_centroid_drift"):
        assert column in latest, "%s must be DECLARED now, not deferred" % column
        assert latest[column] is None, "%s has no upstream yet and must be NULL" % column


def test_graph_health_columns_are_declared_in_the_schema():
    columns = mart_schema.MART_TABLES["fact_graph_health_daily"].column_names
    for column in ("hot_tier_fraction", "percolation_margin", "fiedler_value", "demand_centroid_drift"):
        assert column in columns


def test_session_daily_attributes_records_and_keeps_empty_sessions():
    corpus = _Corpus(
        records=[
            _record(
                item_id="DVP-TSK-001",
                project_id="devops",
                history=[{"timestamp": "2026-01-02T00:00:00Z", "status": "worklog", "description": "Agent session checkout by ENC-SES-0AA [provider=ENC-SES-0AA]"}],
            )
        ],
        sessions=[
            {"session_id": "ENC-SES-0AA", "agent_type_id": "ENC-AGT-005", "created_at": "2026-01-02T00:00:00Z"},
            {"session_id": "ENC-SES-0AB", "agent_type_id": "ENC-AGT-005", "created_at": "2026-01-02T00:00:00Z"},
        ],
        agent_types=[{"agent_type_id": "ENC-AGT-005", "surface": "claude_code_cli", "model": "claude-sonnet-5"}],
    )
    rows = mart_project.build_fact_session_daily(corpus)
    attributed = [r for r in rows if r["project_id"] == "devops"]
    unattributed = [r for r in rows if r["project_id"] == "unattributed"]
    assert attributed[0]["session_count"] == 1 and attributed[0]["records_touched"] == 1
    assert attributed[0]["agent_type"] == "claude_code_cli"
    assert attributed[0]["model"] == "claude-sonnet-5"
    assert unattributed[0]["session_count"] == 1, "an allocated session that wrote nothing is signal, not noise"


def test_dim_record_projects_identifiers_never_substance():
    record = _record(
        title="a title the mart must not carry",
        description="a description the mart must not carry",
        components=["comp-devops-trino"],
        checkout_count=2,
        closed_count=1,
        history=[{"timestamp": "2026-01-05T00:00:00Z", "status": "worklog", "description": "Field 'status' set to 'closed'"}],
    )
    row = mart_project.build_dim_record(_Corpus(records=[record]))[0]
    assert row["record_id"] == "DVP-TSK-001"
    assert row["closed_at"] == "2026-01-05T00:00:00Z"
    assert row["component_ids"] == '["comp-devops-trino"]'
    serialized = str(row)
    assert "a title the mart must not carry" not in serialized
    assert "a description the mart must not carry" not in serialized


def test_sentinel_rows_are_never_governed_records():
    assert is_sentinel({"session_id": "counter#ENC-SES"})
    assert is_sentinel({"agent_type_id": "counter#ENC-AGT"})
    assert is_sentinel({"record_type": "counter"})
    assert not is_sentinel({"record_id": "task#DVP-TSK-648", "record_type": "task"})


def test_terminal_status_vocabulary_is_case_folded():
    assert mart_project.is_terminal("closed")
    assert mart_project.is_terminal("Completed")
    assert not mart_project.is_terminal("in-progress")
    assert not mart_project.is_terminal(None)
