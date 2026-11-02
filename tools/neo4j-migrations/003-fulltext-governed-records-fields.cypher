// ENC-TSK-S05 / ENC-TSK-S06 (ENC-PLN-103, ruling P103-R4) Neo4j sibling fulltext
// index over title + intent + description for the keyword signal
//
// graph_sync now projects `intent` (cap 1,000 chars) and `description` (cap 2,000
// chars) onto governed nodes (ENC-TSK-S05 / N5a). This migration adds a SIBLING
// index `governed_record_text_ft` so the keyword signal in graph_query_api can
// match the same text the vector signal embeds (title, intent, description).
//
// There is NO drop or recreate: `governed_record_title_ft` (migration 002,
// title only) stays in place and remains the rollback / fallback path.
//
// Labels and options match 002-fulltext-governed-records.cypher:
//   Task, Issue, Feature, Plan, Lesson, Document, Recipe, RecipeRun
// (002 sets no explicit analyzer/options, so the default analyzer is used.)
//
// Run ONLY after the graph_sync change is live and the one-time node backfill
// (ENC-TSK-S12) has populated intent/description; the index builds over existing
// data either way, but keyword recall is incomplete until the backfill runs.
//
// Idempotency: `IF NOT EXISTS`. Re-running is a no-op.
//
// Cost: indexes are included in the Aura instance. Cost class C1 (one-off
// migration run); small persistent storage.
//
// Verification:
//   SHOW FULLTEXT INDEXES YIELD name, state, labelsOrTypes, properties
//     WHERE name = 'governed_record_text_ft';
//
// ---------------------------------------------------------------------------

CREATE FULLTEXT INDEX governed_record_text_ft IF NOT EXISTS
FOR (n:Task|Issue|Feature|Plan|Lesson|Document|Recipe|RecipeRun)
ON EACH [n.title, n.intent, n.description];
