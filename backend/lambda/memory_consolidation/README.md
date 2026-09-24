# Memory Consolidation Lambda (ENC-FTR-096 Ph1 / ENC-TSK-I84)

Nightly EventBridge-triggered Lambda that closes the **episodic → semantic
consolidation gap** (DOC-E2379D980FA2 §4.1). Enceladus already has the
substrates — *Handoffs* are the episodic buffer and *Lessons* are semantic
memory — but no process that consolidates one into the other. This Lambda is
that process: it scans recent Handoff documents, finds recurring co-citation
patterns, and **drafts lesson-candidate documents** for later human (io) review.

It is strictly **propose-only**. It never promotes a Lesson, never mutates the
tracker, and never advances any lifecycle.

## Architecture

```
EventBridge rule  enceladus-memory-consolidation-nightly  (cron 0 2 * * ? *)
        │
        ▼
Memory Consolidation Lambda  (Python 3.11/3.12, 512 MB, 300 s)
        │   read Handoff docs (prior 24h) via documents project-updated-index
        │   put lesson-candidate drafts (DynamoDB documents + S3 agent-documents)
        ▼
DynamoDB `documents`  +  S3 `agent-documents/<project>/<DOC-id>.md`
```

CloudFormation resources live in `infrastructure/cloudformation/02-compute.yaml`:
`MemoryConsolidationFunction`, `MemoryConsolidationRole`,
`MemoryConsolidationSchedule`, `MemoryConsolidationPermission`. The build/deploy
matrix entry is registered in `infrastructure/lambda_workflow_manifest.json` and
`envs/v4-gamma.yaml`.

## Pattern extraction (co-citation clustering)

For each Handoff scanned in the lookback window the Lambda extracts the set of
governed ids it cites (from `related_items`, `source_record_id`, and id tokens
parsed from the title/description/body). Two records are **co-cited** when they
appear together in the same Handoff. A co-citation **qualifies** when it recurs
across at least `CONSOLIDATION_MIN_WAVES` (default **2**) distinct Handoffs.
Qualifying pairs are unioned (connected components) into clusters; each cluster
carries its member ids, the supporting Handoff DOC ids, and a frequency count.

## Lesson-candidate drafts

Each qualifying cluster becomes one draft document written to the docstore with:

| field | value |
|---|---|
| `document_subtype` | `lesson-candidate` |
| `subtypepattern` | `lesson-candidate` (document.doc graduation-pathway mirror) |
| `handoff_status` | `pending` |
| `status` | `draft` |
| `related_items` | the source Handoff DOC ids |
| `record_type` | `document` |
| `write_source.channel` | `memory_consolidation_lambda` |

The body is framed as abstracted, transferable **gist** (the pattern, not a
transcript fragment) so it survives pruning of any single source episode
(AC-9). The `document_id` is a deterministic hash of the cluster member
signature, so a recurring cluster re-uses the same draft instead of duplicating
on each nightly run (idempotent).

## io-approval gate (AC-4)

This Lambda makes **zero** `tracker.create`, `checkout.advance`, or
`lesson.promote` calls — it imports no client for any of them and logs an
`[IO-GATE]` audit line on every invocation. Promotion of a draft to a governed
Lesson requires an explicit io `tracker.create_lesson` call citing the draft
DOC as evidence. The gate is architecturally non-removable: a synthesizer
manufactures coherence (activation-synthesis), so candidate plausibility is
never self-certifying (Hopfield basin-shaping framing, AC-7).

## OGTM pre-flight (AC-5)

Lesson-candidate drafts are `record_type=document` with `related_items`, which
`graph_sync` projects to the **pre-existing** `RELATED_TO` edge type. This
feature introduces **no new edge type** and does **not** modify `graph_sync`.
`_ogtm_preflight()` asserts and logs this invariant on every run.

## Environment variables

| var | default | meaning |
|---|---|---|
| `DOCUMENTS_TABLE` | `documents` | docstore DynamoDB table |
| `PROJECT_UPDATED_INDEX` | `project-updated-index` | GSI (project_id, updated_at) |
| `S3_BUCKET` | `jreese-net` | document content bucket |
| `S3_PREFIX` | `agent-documents` | document content key prefix |
| `CONSOLIDATION_PROJECT_IDS` | `enceladus` | comma-separated project ids to scan |
| `CONSOLIDATION_LOOKBACK_HOURS` | `24` | scan window |
| `CONSOLIDATION_MIN_WAVES` | `2` | min distinct Handoffs for a qualifying pattern |

## Tests

```
python -m unittest backend.lambda.memory_consolidation.test_lambda_function -v
```

The tests cover co-citation extraction/clustering on seeded Handoffs, draft
payload shape, the io-approval gate audit, and the OGTM pre-flight — all without
AWS (pure functions).
