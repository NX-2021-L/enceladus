"""DECLARED schemas for the seven governance analytics mart tables.

BRD B3-R2 (``DOC-724C3695059F`` §6.3). Tracker: DVP-TSK-648 (parent),
DVP-TSK-672..678 (one task per table).

Governed by:

* ``DOC-3391173F2A5C`` — the mart grain contract. **METADATA ONLY.** The
  standing test is applied to every column below:

      If a proposed column would let a reader substitute the mart for the
      record store, it does not belong.

  A column that answers "how many", "how long", "what status", or "when"
  belongs. A column that reproduces what a record *says* — its title, its
  description, its intent, its acceptance-criteria text, its worklog prose, a
  document's content body — does not. **There is no free-text column in this
  module, and adding one is itself the Risk R-4 drift signal** (see the grain
  contract's "Drift detection signal"), independent of any size measurement.
* ``DOC-04AF8A02A8F7`` — four-tier architecture. These are T2 tables:
  ``s3://<bucket>/warehouse/devops/<table>/data.parquet``, Parquet, declared
  registration, addressed as ``hive.devops.<table>``.
* ``DOC-5E35E14DAD05`` — crawler prohibition. Every column here is DECLARED in
  code and committed. Nothing in this module is inferred from S3, and there is
  deliberately no code path by which it could be.
* ``DOC-1E1EC5B7CE02`` — full-refresh partitioning discipline. No table below
  declares a partition key. The refresh overwrites one object per table.

Why this is a module of data rather than DDL: the schema is a *value* the
B2-R2 shared library consumes (``register_table(columns=...)``), so the
declaration, the Glue registration, and the Parquet write are the same fact
expressed once. Changing a column here is a governed change to
``comp-devops-trino`` reviewed against the substitution test — never an
incidental edit folded into an unrelated ETL change.

**Daily grain is the initial shape, not a future upgrade.** Every one of the
five fact tables carries ``snapshot_date`` at daily grain from the outset
(the grain contract makes a coarser fact table non-conformant on its face).
That is what makes a refresh failure show up as a series that *stops drawing*
rather than a stale value that persists — the OBJ-6 failure mode, made
structural.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

# The shared B2-R2 library is imported from the Lambda layer when deployed and
# from the repo path when run as a tool. `.build_extras` flattens the module to
# the function root, so the vendored name has no package prefix -- the same
# guarded-import shape `tracker_mutation` uses for `appconfig_flags`.
try:  # pragma: no cover - exercised by whichever path is present
    from enceladus_shared.warehouse_registration import ColumnSpec
except ImportError:  # pragma: no cover
    from warehouse_registration import ColumnSpec  # type: ignore

__all__ = [
    "MART_PROJECT",
    "MART_TABLES",
    "FACT_TABLES",
    "DIMENSION_TABLES",
    "FRESHNESS_COLUMN",
    "SNAPSHOT_DATE_COLUMN",
    "columns_for",
    "table_names",
    "assert_daily_grain",
]

#: The mart is hosted by `devops` (io decision 2026-08-07, BRD B3-R4) and
#: addressed as `hive.devops.<table>`. `project_id` is a DATA column spanning
#: every governed project -- the refresh reads all projects, which is why the
#: new-project sync gap DVP-ISS-088 describes cannot recur here.
MART_PROJECT = "devops"

#: Library-owned freshness stamp (T2 mandatory column, DOC-04AF8A02A8F7).
#: The mart is DERIVED data, so the warehouse write time is the correct
#: meaning for this column and the library owns it (`stamp_freshness=True`).
#: This is the opposite of finance, whose `updated_at` is business data the
#: library must validate rather than overwrite.
FRESHNESS_COLUMN = "ingest_ts"

SNAPSHOT_DATE_COLUMN = "snapshot_date"

_INGEST_TS = ColumnSpec(
    name=FRESHNESS_COLUMN,
    type="string",
    comment="T2 freshness stamp: UTC ISO-8601 warehouse write time, library-owned.",
)

_SNAPSHOT_DATE = ColumnSpec(
    name=SNAPSHOT_DATE_COLUMN,
    type="date",
    comment="Daily grain key. One row per day per remaining grain column.",
)


# ---------------------------------------------------------------------------
# Table 1 -- dim_record (DVP-TSK-672)
# ---------------------------------------------------------------------------
#: Grain: one row per governed tracker record, CURRENT state.
#:
#: Substitution test: every column is an identifier, an enum, a count, or a
#: timestamp. `title`, `description`, `intent`, and `acceptance_criteria` text
#: are all deliberately absent -- they are what the record SAYS, and a reader
#: who wants them follows `record_id` back through `tracker.get`.
#:
#: Serves US-1 ("how many tasks exist for project=enceladus, with zero agent
#: sessions") as a single GROUP BY, with no agent session in the path at all.
DIM_RECORD: List[ColumnSpec] = [
    ColumnSpec("record_id", "string", "Governed record identifier, e.g. DVP-TSK-648. Follow this back to the record store for substance."),
    ColumnSpec("project_id", "string", "Owning project."),
    ColumnSpec("record_type", "string", "task | issue | feature | plan | lesson | escalation | relationship | reference."),
    ColumnSpec("status", "string", "Current lifecycle status, verbatim from the record store (not normalised -- fidelity over tidiness)."),
    ColumnSpec("priority", "string", "P0 | P1 | P2 | P3."),
    ColumnSpec("category", "string", "implementation | investigation | documentation | maintenance | validation."),
    ColumnSpec("parent_id", "string", "Parent record identifier, or empty."),
    ColumnSpec("component_ids", "string", "JSON array of registered component ids. Flattened to string because the library declares array<> writable-by-flattening only."),
    ColumnSpec("created_at", "string", "UTC ISO-8601 record creation time."),
    ColumnSpec("updated_at", "string", "UTC ISO-8601 last mutation time."),
    ColumnSpec("closed_at", "string", "UTC ISO-8601 time of the transition into a terminal status, or empty."),
    ColumnSpec("checkout_count", "int", "Server-side counter: successful agent checkouts."),
    ColumnSpec("closed_count", "int", "Server-side counter: transitions into closed."),
    ColumnSpec("ontology_completeness_score", "int", "0-100 ENC-FTR-011 ontology completeness, recomputed from the same rubric the record store applies."),
    ColumnSpec("transition_type", "string", "no_code | code_only | github_pr_deploy | lambda_deploy | web_deploy."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 2 -- fact_record_daily (DVP-TSK-673)
# ---------------------------------------------------------------------------
#: Grain: one row per (snapshot_date, project_id, record_type, status).
#:
#: This is the table the daily-grain rule exists for, and the structural
#: expression of OBJ-6: because every day is its own row, a refresh that stops
#: running produces a chart that STOPS DRAWING on the day it stopped. The
#: alternative shape -- a single current-value row per record -- would keep
#: rendering the last good number indefinitely and look healthy while being
#: arbitrarily stale. That is the exact failure DVP-ISS-087 describes.
#:
#: An aggregate grain, not one row per record per day: the counts are the
#: analytic product, and per-record daily rows would multiply the mart's byte
#: size against a record count that did not move -- the Risk R-4 divergence
#: signal, self-inflicted.
FACT_RECORD_DAILY: List[ColumnSpec] = [
    _SNAPSHOT_DATE,
    ColumnSpec("project_id", "string", "Owning project."),
    ColumnSpec("record_type", "string", "Record type."),
    ColumnSpec("status", "string", "Status held at the END of snapshot_date."),
    ColumnSpec("record_count", "int", "Records in this status at end of day."),
    ColumnSpec("opened_count", "int", "Records CREATED on this day that ended it in this status."),
    ColumnSpec("closed_count", "int", "Records that transitioned INTO a terminal status on this day."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 3 -- fact_record_transition (DVP-TSK-674)
# ---------------------------------------------------------------------------
#: Grain: one row per lifecycle transition.
#:
#: Sourced from the per-record `history` arrays -- the same corpus-with-history
#: extraction ENC-TSK-989 already performed -- rather than re-derived from a
#: second pass over the tracker. Note what is projected: the STATUS TOKENS and
#: the timing. The history entry's `description` prose that carries them is
#: read and discarded, never stored. That is the substitution test applied to
#: a source that is mostly free text.
#:
#: Serves cycle time (`days_in_prior_status` by `to_status`), time-in-status,
#: throughput (transitions per day), and stuck-record detection (records whose
#: latest transition is old and non-terminal).
FACT_RECORD_TRANSITION: List[ColumnSpec] = [
    ColumnSpec("record_id", "string", "Governed record identifier."),
    ColumnSpec("project_id", "string", "Owning project."),
    ColumnSpec("record_type", "string", "Record type."),
    ColumnSpec("from_status", "string", "Status held before this transition."),
    ColumnSpec("to_status", "string", "Status entered by this transition."),
    ColumnSpec("transitioned_at", "string", "UTC ISO-8601 transition time."),
    ColumnSpec("days_in_prior_status", "double", "Fractional days spent in from_status before this transition."),
    ColumnSpec("transition_type", "string", "The record's governed transition_type at extraction time."),
    _SNAPSHOT_DATE,
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 4 -- dim_document (DVP-TSK-675)
# ---------------------------------------------------------------------------
#: Grain: one row per docstore document.
#:
#: The substitution test applies with particular force here, because the
#: docstore's entire value is its content: `content`, `full_description`, and
#: `description` are absent by construction. `size_bytes` is the metadata
#: shadow of the body -- how much, never what. A reader who wants the body
#: calls `documents.get(document_id)`.
DIM_DOCUMENT: List[ColumnSpec] = [
    ColumnSpec("document_id", "string", "Governed document identifier, e.g. DOC-3391173F2A5C."),
    ColumnSpec("project_id", "string", "Owning project."),
    ColumnSpec("document_subtype", "string", "doc | handoff | coe | wave | idea | context-node | skill, or a legacy value."),
    ColumnSpec("subtypepattern", "string", "Self-learning emergent subtype, valid only when document_subtype='doc'."),
    ColumnSpec("status", "string", "Document status, e.g. active."),
    ColumnSpec("document_maturity_state", "string", "raw | compliant | contextualized | mature (GDMP)."),
    ColumnSpec("compliance_score", "int", "0-100, Lambda-computed at write time."),
    ColumnSpec("compliance_warning_count", "int", "COUNT of compliance warnings. The warning TEXT is deliberately not projected."),
    ColumnSpec("size_bytes", "bigint", "Body size in S3. The metadata shadow of content, never the content."),
    ColumnSpec("version", "int", "Monotonic document version."),
    ColumnSpec("related_item_count", "int", "COUNT of graph edges to tracker records and documents."),
    ColumnSpec("created_at", "string", "UTC ISO-8601 creation time."),
    ColumnSpec("updated_at", "string", "UTC ISO-8601 last write time."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 5 -- fact_document_daily (DVP-TSK-676)
# ---------------------------------------------------------------------------
#: Grain: one row per (snapshot_date, project_id, document_subtype,
#: document_maturity_state).
#:
#: Added when daily grain was adopted as a rule rather than a choice: the
#: docstore had exactly the same "current value that looks fresh forever"
#: exposure the tracker had, and the rule closes both or neither.
FACT_DOCUMENT_DAILY: List[ColumnSpec] = [
    _SNAPSHOT_DATE,
    ColumnSpec("project_id", "string", "Owning project."),
    ColumnSpec("document_subtype", "string", "Document subtype; 'unspecified' where the record carries none."),
    ColumnSpec("document_maturity_state", "string", "GDMP maturity; 'unspecified' where the record carries none."),
    ColumnSpec("document_count", "int", "Documents in existence at end of day in this bucket."),
    ColumnSpec("created_count", "int", "Documents CREATED on this day in this bucket."),
    ColumnSpec("mean_compliance_score", "double", "Mean compliance score across the bucket, or NULL when none carry one."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 6 -- fact_session_daily (DVP-TSK-677)
# ---------------------------------------------------------------------------
#: Grain: one row per (snapshot_date, project_id, agent_type, model).
#:
#: `model` is a DATA COLUMN describing observed agent sessions -- it records
#: which model was on the other end of governed work that actually happened.
#: It is not configuration and nothing reads it back as an instruction.
#:
#: `agent_type` carries `agent_types.surface` (claude_code_cli,
#: claude.ai-webui, eventbridge-scheduler, ...), joined from the session's
#: `agent_type_id`. The surface is the human-meaningful type name the
#: dashboard series needs; the id remains reachable through the record store.
FACT_SESSION_DAILY: List[ColumnSpec] = [
    _SNAPSHOT_DATE,
    ColumnSpec("project_id", "string", "Project the session's governed writes landed in; 'unattributed' when it touched no record."),
    ColumnSpec("agent_type", "string", "agent_types.surface for the session's agent_type_id."),
    ColumnSpec("model", "string", "Observed model for that agent type. A data column describing sessions, never configuration."),
    ColumnSpec("session_count", "int", "Distinct agent sessions created on this day in this bucket."),
    ColumnSpec("records_touched", "int", "Distinct governed records those sessions wrote to."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Table 7 -- fact_graph_health_daily (DVP-TSK-678)
# ---------------------------------------------------------------------------
#: Grain: one row per snapshot_date.
#:
#: The plan's mathematical anchor. ``DOC-E2379D980FA2`` names spectral graph
#: metrics as governance telemetry no dashboard exposes; this table is where
#: that telemetry becomes visible.
#:
#: **Risk R-11 discipline.** The last four columns have no upstream
#: computation today: `backend/lambda/graph_health_metrics` publishes
#: Neo4j-derived PROXIES to CloudWatch and says so in its own docstring
#: ("proxy metrics instead of native Fiedler λ₂ computation"), and a repo-wide
#: search for `fiedler_value`, `percolation_margin`, and
#: `demand_centroid_drift` returns nothing outside this module. They are
#: therefore DECLARED NOW and left NULL, to be populated incrementally as
#: ENC-FTR-063 / comp-percolation-monitor lands them -- not deferred to a
#: later schema change. A column added later is a governed schema change to a
#: live table plus a backfill; a column declared now and filled later is an
#: UPDATE. The metric computation itself is explicitly out of scope here
#: (DVP-TSK-678 AC-5): this table projects, it does not compute.
#:
#: The first four columns are computed today from the governed graph itself
#: (records + documents as nodes; parent, subtask, related-*, related_items
#: and informed_by as edges), so the table is never empty while it waits.
FACT_GRAPH_HEALTH_DAILY: List[ColumnSpec] = [
    _SNAPSHOT_DATE,
    ColumnSpec("node_count", "int", "Governed nodes in existence at end of day: tracker records plus docstore documents."),
    ColumnSpec("edge_count", "int", "Resolvable edges between existing nodes at end of day."),
    ColumnSpec("orphan_node_count", "int", "Existing nodes with no resolvable edge in either direction."),
    ColumnSpec("unresolved_edge_count", "int", "Declared edges whose target is not a known node -- the graph's dangling-reference signal."),
    ColumnSpec("hot_tier_fraction", "double", "AWAITING UPSTREAM (ENC-FTR-063). Declared now, populated incrementally."),
    ColumnSpec("percolation_margin", "double", "AWAITING UPSTREAM (comp-percolation-monitor). Declared now, populated incrementally."),
    ColumnSpec("fiedler_value", "double", "AWAITING UPSTREAM. Spectral algebraic connectivity (Laplacian lambda-2). Declared now, populated incrementally."),
    ColumnSpec("demand_centroid_drift", "double", "AWAITING UPSTREAM. Declared now, populated incrementally."),
    _INGEST_TS,
]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

#: Table name -> (declared columns, table comment). The single declaration the
#: refresh job, the Glue catalog, and the conformance test all read.
MART_TABLES: Dict[str, "MartTable"] = {}


class MartTable:
    """One declared mart table: its columns, its grain, and its owning task."""

    __slots__ = ("name", "columns", "grain", "task", "comment")

    def __init__(self, name: str, columns: Sequence[ColumnSpec], grain: Sequence[str], task: str, comment: str):
        self.name = name
        self.columns = list(columns)
        self.grain = list(grain)
        self.task = task
        self.comment = comment

    @property
    def column_names(self) -> List[str]:
        return [column.name for column in self.columns]

    @property
    def is_fact(self) -> bool:
        return self.name.startswith("fact_")

    def __repr__(self) -> str:  # pragma: no cover
        return "MartTable(%r, columns=%d, grain=%r)" % (self.name, len(self.columns), self.grain)


def _register(name: str, columns: Sequence[ColumnSpec], grain: Sequence[str], task: str, comment: str) -> None:
    MART_TABLES[name] = MartTable(name, columns, grain, task, comment)


_register(
    "dim_record", DIM_RECORD, ["record_id"], "DVP-TSK-672",
    "Governance analytics mart: one row per tracker record, current state. Metadata only (DOC-3391173F2A5C).",
)
_register(
    "fact_record_daily", FACT_RECORD_DAILY,
    ["snapshot_date", "project_id", "record_type", "status"], "DVP-TSK-673",
    "Governance analytics mart: daily record counts by project, type, and status.",
)
_register(
    "fact_record_transition", FACT_RECORD_TRANSITION,
    ["record_id", "transitioned_at", "to_status"], "DVP-TSK-674",
    "Governance analytics mart: one row per lifecycle transition, from the per-record history arrays.",
)
_register(
    "dim_document", DIM_DOCUMENT, ["document_id"], "DVP-TSK-675",
    "Governance analytics mart: one row per docstore document, current state. No document content.",
)
_register(
    "fact_document_daily", FACT_DOCUMENT_DAILY,
    ["snapshot_date", "project_id", "document_subtype", "document_maturity_state"], "DVP-TSK-676",
    "Governance analytics mart: daily document counts by project, subtype, and maturity.",
)
_register(
    "fact_session_daily", FACT_SESSION_DAILY,
    ["snapshot_date", "project_id", "agent_type", "model"], "DVP-TSK-677",
    "Governance analytics mart: daily agent session volume by project, agent type, and model.",
)
_register(
    "fact_graph_health_daily", FACT_GRAPH_HEALTH_DAILY,
    ["snapshot_date"], "DVP-TSK-678",
    "Governance analytics mart: daily governance graph health, including spectral columns declared ahead of their upstream.",
)

#: Deterministic build order: dimensions first, then facts. Nothing depends on
#: this ordering functionally -- each table is registered independently -- but a
#: stable order makes the refresh log diffable run over run.
MART_TABLE_ORDER = [
    "dim_record",
    "fact_record_daily",
    "fact_record_transition",
    "dim_document",
    "fact_document_daily",
    "fact_session_daily",
    "fact_graph_health_daily",
]

DIMENSION_TABLES = [name for name in MART_TABLE_ORDER if name.startswith("dim_")]
FACT_TABLES = [name for name in MART_TABLE_ORDER if name.startswith("fact_")]


def columns_for(table: str) -> List[ColumnSpec]:
    """Declared columns for one mart table."""
    try:
        return MART_TABLES[table].columns
    except KeyError:
        raise KeyError("%r is not a declared mart table. Declared: %s" % (table, ", ".join(MART_TABLE_ORDER)))


def table_names() -> List[str]:
    return list(MART_TABLE_ORDER)


def assert_daily_grain() -> None:
    """Every fact table carries `snapshot_date` at daily grain (DVP-TSK-648 AC-2).

    Raised as an assertion rather than left to review because the grain
    contract makes a coarser fact table non-conformant on its face: it "must be
    corrected before it is registered", so the check belongs in the path that
    registers it.
    """
    for name in FACT_TABLES:
        table = MART_TABLES[name]
        if SNAPSHOT_DATE_COLUMN not in table.column_names:
            raise AssertionError(
                "fact table %r does not declare %r. Every fact table carries daily grain "
                "from the outset (DOC-3391173F2A5C)." % (name, SNAPSHOT_DATE_COLUMN)
            )
        # The *_daily tables are AGGREGATES whose grain is led by the day, so a
        # missing leading snapshot_date there would mean the table was built at
        # a coarser grain -- the specific non-conformance the grain contract
        # says "must be corrected before it is registered".
        #
        # `fact_record_transition` is an EVENT table: its grain is one row per
        # lifecycle transition (DVP-TSK-674 AC-1), and it carries snapshot_date
        # as the day bucket that event fell in. Requiring the day to LEAD its
        # grain would force one row per record per day, which is a different
        # and worse table -- so the leading-key check is scoped to aggregates.
        if name.endswith("_daily") and table.grain[0] != SNAPSHOT_DATE_COLUMN:
            raise AssertionError(
                "daily aggregate %r does not lead its grain with %r." % (name, SNAPSHOT_DATE_COLUMN)
            )
    for name in MART_TABLE_ORDER:
        if FRESHNESS_COLUMN not in MART_TABLES[name].column_names:
            raise AssertionError(
                "table %r does not declare the mandatory T2 freshness column %r "
                "(DOC-04AF8A02A8F7)." % (name, FRESHNESS_COLUMN)
            )


assert_daily_grain()
