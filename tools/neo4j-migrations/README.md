ENC-TSK-B90 Neo4j Migrations

Cypher migration files for the Enceladus governed graph on Neo4j AuraDB.

Migrations are numbered sequentially (`NNN-description.cypher`). Each file is
idempotent (`IF NOT EXISTS` / `MERGE`) so re-running is safe.

The shared AuraDB instance backs both the prod `devops-graph-sync` Lambda and
the gamma `devops-graph-sync-gamma` Lambda (both Lambdas resolve
`NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials`; the parallel
`enceladus/neo4j/auradb-credentials-gamma` secret is not referenced by any
deployed Lambda). Apply migrations with care and confirm a recent
`enceladus-neo4j-backup-gamma` S3 snapshot exists before running.

## Running a migration

Two supported paths:

1. Via the `backfill_graph.py` helper (recommended; reuses the existing
   Secrets Manager and Neo4j driver plumbing):

   ```bash
   AWS_PROFILE=product-lead \
   NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
   python3 tools/backfill_graph.py --region us-west-2 \
     --run-migration tools/neo4j-migrations/001-hnsw-vector-indexes-governed-records.cypher
   ```

2. Directly via `cypher-shell` / Aura Browser by pasting the file contents.

After running a migration, capture the `SHOW VECTOR INDEXES` (or equivalent)
introspection output and attach it to the originating tracker task's
`live_validation_evidence` field.

## Governance

This directory is not under a registered component in the component registry
(ENC-FTR-041). Tasks that author or execute migrations should tag
`comp-neo4j-backup` as the semantic Neo4j-schema steward, or `comp-graph-sync`
when the migration is paired with a `graph_sync` Lambda change.
