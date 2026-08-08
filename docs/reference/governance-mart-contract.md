# Governance Analytics Mart — Schema and Refresh Contract

**Requirement**: BRD B3-R1 / B3-R2 / B3-R3 / B3-R4 (`DOC-724C3695059F` §6.3)
**Tracker**: DVP-TSK-648 (parent), DVP-TSK-672..678 (one per table), DVP-TSK-649 (refresh job)
**Governed by**: `DOC-3391173F2A5C` (grain contract), `DOC-04AF8A02A8F7` (four-tier
architecture), `DOC-5E35E14DAD05` (crawler prohibition), `DOC-1E1EC5B7CE02` (full-refresh
partitioning discipline), `DOC-E2379D980FA2` (spectral graph metrics)
**Implementation**: `backend/lambda/governance_mart/`
**Operator entry point**: `tools/governance_mart_refresh.py`

The mart is a T2 warehouse projection of the governed record store, addressed as
`hive.devops.<table>`. It exists so that "how many", "how long", "what status", and "when"
are answerable at the cost of a glance, without a query against the record store and
without an agent session in the path.

---

## 1. The rule that decides every column

> **If a proposed column would let a reader substitute the mart for the record store, it
> does not belong.**

The mart holds **metadata only**: counts, statuses, durations, transitions, timestamps,
and identifiers — the shape of activity, never its substance. No record bodies, titles,
descriptions, intents, acceptance-criteria text, evidence strings, worklog prose, or
document content appears in any table below, and none ever will without a recorded
governed exception.

This is enforced, not merely asserted. `test_governance_mart.py` fails CI if any declared
column name appears in `_FORBIDDEN_SUBSTANCE_COLUMNS`, because per `DOC-3391173F2A5C` the
appearance of a free-text body column **is itself** the Risk R-4 drift signal, independent
of any size measurement. Size divergence is the corroborating measurement, and the
registration sidecar the shared library emits carries the byte and row counts the Phase 6
health monitor needs to compute it.

Anyone who needs the substance follows the identifier back through `tracker.get` or
`documents.get`. That is the whole design: the mart is a lens, not a mirror.

## 2. Daily grain is the initial shape

Every one of the five fact tables carries `snapshot_date` at daily grain **from the
outset**. This is not a future upgrade — a fact table built at a coarser grain (weekly
rollup, cumulative-only) does not satisfy the grain contract and must be corrected before
it is registered.

The reason is OBJ-6, and it is structural rather than procedural. A current-value table
renders its last good number forever: a pipeline that silently stopped three weeks ago
still produces a dashboard that looks healthy. A daily-grain series **stops drawing** on
the day the refresh stopped. The failure becomes an absence, and an absence is legible.

`assert_daily_grain()` runs at import time in `mart_schema.py`, so the declaration cannot
even load in a non-conformant state.

## 3. The seven tables

| Table | Grain | Task |
| --- | --- | --- |
| `dim_record` | one row per tracker record, current state | DVP-TSK-672 |
| `fact_record_daily` | `(snapshot_date, project_id, record_type, status)` | DVP-TSK-673 |
| `fact_record_transition` | one row per lifecycle transition | DVP-TSK-674 |
| `dim_document` | one row per docstore document | DVP-TSK-675 |
| `fact_document_daily` | `(snapshot_date, project_id, document_subtype, document_maturity_state)` | DVP-TSK-676 |
| `fact_session_daily` | `(snapshot_date, project_id, agent_type, model)` | DVP-TSK-677 |
| `fact_graph_health_daily` | one row per `snapshot_date` | DVP-TSK-678 |

The declared columns live in `backend/lambda/governance_mart/mart_schema.py` and are the
single source of truth — the Parquet write, the Glue registration, and the conformance
test all read the same list. Prefer asserting against `mart_schema.MART_TABLES` over
quoting this page.

`fact_record_transition` is an **event** table: its grain is one row per transition, and
`snapshot_date` is the day bucket that event fell into rather than the leading grain key.
The daily-grain assertion scopes its leading-key check to the `*_daily` aggregates for
exactly this reason — forcing the day to lead a transition table's grain would produce one
row per record per day, which is a different and worse table.

### 3.1 Where transitions come from

The tracker does **not** store status transitions structurally. `history[].status` is an
entry *kind* (`created` / `worklog`), and the transition itself lives inside the entry's
free-text `description`:

```
Field 'status' set to 'coding-complete' [provider=ENC-SES-0BV]
```

So `mart_project.extract_transitions()` parses that prose to recover two status tokens and
a timestamp, chains them into `(from_status, to_status)` pairs, computes
`days_in_prior_status` against the previous transition (or the record's creation time),
and **discards the prose**. What lands in the mart is
`('in-progress' → 'coding-complete', 0.123 days)`. What does not land is the sentence.

That is the substitution test applied to a source which is mostly free text, and it is the
sharpest illustration of the rule in the whole mart. It also re-homes the
corpus-with-history extraction ENC-TSK-989 already performed onto the contract, rather than
re-deriving it.

Two conventions the live corpus forced:

- A repeated assertion of the same status is **not** a transition. Counting it would
  inflate throughput and zero out cycle time.
- A legacy `tracker.py` wrote `in_progress`; underscores fold to the governed hyphenated
  form.

### 3.2 `fact_graph_health_daily` and the R-11 discipline

The first four columns — `node_count`, `edge_count`, `orphan_node_count`,
`unresolved_edge_count` — are computed today from the governed graph itself (records and
documents as nodes; `parent`, `subtask_ids`, `related_*_ids`, `related_items`, and
`informed_by` as edges).

The last four — `hot_tier_fraction`, `percolation_margin`, `fiedler_value`,
`demand_centroid_drift` — have **no upstream computation yet**.
`backend/lambda/graph_health_metrics` publishes Neo4j-derived *proxies* to CloudWatch and
says so in its own docstring ("proxy metrics instead of native Fiedler λ₂ computation"),
and a repo-wide search for those three metric names returns nothing outside the mart.

They are therefore **declared now and left NULL**, to be populated incrementally as
ENC-FTR-063 / `comp-percolation-monitor` lands them. This is risk R-11's mitigation stated
concretely: a column declared now and filled later is an `UPDATE`; a column added later is
a governed schema change against a live table plus a backfill plus every dashboard built
against the old shape. The metric computation itself is out of scope here — this table
**projects**, it does not compute.

### 3.3 Known type-1 dimension limitations, recorded rather than hidden

- `fact_document_daily` buckets by a document's **current** subtype and maturity across its
  whole lifetime, because the docstore keeps no maturity history. Document *production* per
  day is exact; maturity *movement* over time is readable only from the current
  distribution.
- `dim_record.status` is projected **verbatim**, not normalised. The live corpus carries
  `Completed`, `Complete`, and `complete` as distinct values. Folding them would be a
  judgement the mart is not entitled to make on the record store's behalf; fidelity wins
  over tidiness, and the divergence is itself a governance signal.

## 4. The refresh path

```
read the governed record store → project to grain → write Parquet → register via B2-R2
```

One function, `mart_refresh.refresh_mart()`, shared by the scheduled Lambda
(`backend/lambda/governance_mart/lambda_function.py`) and the operator CLI. Sharing the
path is deliberate: an operator command that reproduced the projection separately would be
a second opinion about the grain, and the two would drift.

Every historical break pattern is eliminated **by construction**, not by monitoring:

| Break pattern | Why it cannot occur here |
| --- | --- |
| EventBridge per-mutation trigger | There is none. The only trigger is a *schedule* (daily minimum). Nothing subscribes to a tracker mutation, so there is nothing to disable later. |
| Crawler / crawler launcher | There is none. `register_table` writes a DECLARED schema through the Glue API. The schema is a value in `mart_schema.py`, committed with the code that writes the data. |
| Crawler concurrency | Unreachable — no crawler exists to race. Two overlapping refreshes converge on the same canonical key. |
| Partition explosion | Impossible — no table declares a partition key, and the library writes exactly one object per table at a constant key. |
| Stale data that looks fresh | Structurally visible — daily grain means a stopped refresh stops the series. |
| New-project sync gap | Impossible — the refresh **scans all projects**. There is no per-project registration step to forget. |

A faster cadence than daily is permitted and changes nothing structurally, because each run
rebuilds every table from scratch.

**Failure is loud.** The handler re-raises rather than returning 200 on error. A refresh
that swallowed its own exception and reported success would recreate the silent-stop
failure mode the daily grain exists to expose — the series must stop drawing *and* the
invocation must fail, not one without the other.

## 5. Ownership (B3-R4)

- **devops** owns the platform tier (T0: Trino, Superset, Glue, the EC2 host) and **this
  contract**. Schema changes are governed changes to `comp-devops-trino`, reviewed against
  the substitution test in §1.
- **enceladus** owns the mart's **projection logic and schema** — `mart_schema.py` and
  `mart_project.py` — because the schema is a projection of the governance ontology
  (`ENC-FTR-053`) and must evolve with it. When the ontology gains a field worth counting,
  the mart's declaration is where that shows up.

The feature is hosted in `devops` for plan coherence (io decision, 2026-08-07) while
enceladus owns the projection. Recording the split here is the point: a future session
should not have to rediscover which side of the line a change falls on.

Prior work re-homed rather than re-derived: **ENC-TSK-989** (closed) already extracted the
corpus with history — `fact_record_transition` builds on that extraction shape instead of
performing a second pass. **ENC-TSK-C63** (coding-complete) already built a Trino analysis
path — the mart registers into that same `hive` catalog rather than standing up a parallel
query surface.

## 6. Onboarding precondition (T0, once)

The Glue database `devops` was created **with a `LocationUri`**
(`s3://devops-agentcli-compute/warehouse/devops/`) as a one-time platform-tier action.
Without it, `CREATE TABLE` through Trino fails with `HIVE_DATABASE_LOCATION_ERROR`;
table-level `StorageDescriptor.Location` does not substitute. The shared library writes the
catalog through the Glue API rather than Trino DDL, so it is not itself blocked — but any
Superset or Trino DDL against the database would be. See `DOC-04AF8A02A8F7`.

## 7. Verifying conformance

```bash
# Unit + contract tests. No AWS credentials required.
python3 -m pytest backend/lambda/governance_mart/ -q

# Diff the live Glue catalog against the declaration. Read-only, exits non-zero
# on divergence. This is the check CI and the B6-R2 monitor want.
python3 tools/governance_mart_refresh.py reconcile --profile product-lead

# Project everything and print row counts without writing.
python3 tools/governance_mart_refresh.py plan --profile product-lead
```

**Result (2026-08-08):** 7 tables, 7 match, 0 divergent, 0 missing, 0 rejected. 56,672 rows
across 503,147 bytes. Each table holds exactly one S3 object at
`warehouse/devops/<table>/data.parquet`, and `file_count` remained 1 across three
successive refreshes (`write_seq` 1 → 3) with `byte_count` unchanged — full-refresh
overwrite behaving correctly, file count tracking data size rather than write count.
