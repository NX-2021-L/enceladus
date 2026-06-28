# The Handoff Consolidation Engine

Enceladus has two memory substrates with very different time constants. **Handoff
documents** are the episodic buffer — the dense, session-scoped record of what one
agent did and what the next should know. **Lesson records** are semantic memory —
distilled, constitutionally-scored, append-only institutional knowledge. Between
them sat a gap: recurring patterns accumulated across many Handoffs that *no single
session ever inspected in aggregate*, and so were never promoted to durable
knowledge. The Handoff Consolidation Engine (HCE, `ENC-FTR-064` / `ENC-TSK-C08`) is
the hippocampal-replay analog that closes that gap.

## What it does

The HCE is a scheduled Lambda that runs a **scan → cluster → propose** cycle against
the Handoff corpus:

1. **Scan.** It reads Handoff and wave documents from the last lookback window
   (90 days by default) directly from DynamoDB — read-only, matching the
   `enceladus-agent-cli` security posture.
2. **Cluster.** Two primary extractors mine recurring structure:
   - **Co-citation frequency** — record pairs co-cited across multiple distinct
     *wave anchors* (not merely multiple documents from one wave) surface a
     recurring structural coupling.
   - **Error-class recurrence** — `ENC-ISS-NNN` references, `[ERROR]`/`[WARN]`
     tags, and `SevN` markers that recur across distinct waves surface a recurring
     failure mode.
3. **Propose.** Each qualifying pattern becomes a `LESSON CANDIDATE` document with
   structured evidence, written through the governed Document API. The HCE **never**
   promotes a candidate to a Lesson itself — promotion is an io-only
   `tracker.create_lesson` action. The engine only ever proposes.

A per-cycle deduplication guard hashes each candidate's source set so the same
pattern is not re-proposed on consecutive runs.

## The adaptive trigger

The EventBridge schedule is an *upper bound* on cadence, not an unconditional floor.
On each fire the engine counts how many new Handoffs accumulated since the last
cycle; if fewer than a threshold (`ADAPTIVE_TRIGGER_MIN_HANDOFFS`, default 3), it
skips the expensive cluster-and-propose work and returns cheaply. Consolidation
happens when there is genuinely new episodic material to consolidate — the way
memory replay is driven by accumulated experience rather than by the clock alone.

## FSRS-6 stability from recurrence

When a candidate is promoted, its initial FSRS-6 stability `S_0` should reflect how
strongly the pattern was corroborated. The HCE derives `S_0` from the recurrence
count with a strictly increasing, saturating map:

```
S_0(r) = floor + (ceil - floor) * (1 - exp(-growth * (r - 1)))
```

At a single occurrence (`r = 1`) `S_0` equals the floor — a normal new-Lesson
stability. As recurrence grows, `S_0` rises toward the ceiling with diminishing
returns. The invariant that matters (`ENC-TSK-C08` AC-5) is monotonic: **a pattern
that recurred across more sessions earns a higher initial stability**, so the
promoted Lesson decays more slowly and stays retrieval-visible longer.

## GDMP Stage 2 provenance

The same clustering that finds consolidation candidates also serves the Governed
Document Maturation Protocol (GDMP, `ENC-FTR-065`). For documents already in the
`compliant` state, the HCE finds siblings that share related-item references — a
lightweight co-citation proxy for semantic adjacency — and writes those siblings
as the document's `informed_by` ancestral context, advancing it from `compliant`
to `contextualized`. This is GDMP Stage 2: documents receive ancestral session
context via HCE semantic clustering, and the `INFORMED_BY` edges it implies become
first-class graph structure.

## Traversable provenance (OGTM)

Two new edge types make the consolidation provenance traversable end-to-end, per
the Ontological Graph Traversability Mandate (`ENC-FTR-066`):

- **`CONSOLIDATED_FROM`** — a Lesson candidate to each source Handoff it was
  consolidated from (inverse `CONSOLIDATES`).
- **`PROPOSED_BY`** — a candidate to its proposer, the HCE feature record
  (inverse `PROPOSES`).

These are emitted as document fields (`consolidated_from`, `proposed_by`) that
`graph_sync` projects to Neo4j, registered in the typed-relationship mapping, and
added to the `graph_query_api` edge allowlist — so they are queryable via
`tracker.graphsearch`. The chain *recurring pattern → candidate → source Handoffs →
the records those Handoffs handed off* is one connected, walkable subgraph.

## Where the code lives

- `backend/lambda/handoff_consolidation_engine/` — the engine (pure extractor /
  FSRS / clustering core plus the DynamoDB-read, Document-API-write handler).
- `backend/lambda/graph_sync/` — `CONSOLIDATED_FROM` / `PROPOSED_BY` edge projection
  and the relationship-type mapping.
- `backend/lambda/graph_query_api/` — the edge-type allowlist that gates graphsearch.
- `backend/lambda/document_api/` — persistence of the provenance fields.
- `infrastructure/cloudformation/02-compute.yaml` — the Lambda, its read-only role,
  the configurable EventBridge schedule, and the invoke permission.
