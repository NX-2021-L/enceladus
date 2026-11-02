// ENC-TSK-R81-0E Neo4j fulltext index (title only) for the keyword signal
//
// Creates ONE multi-label FULLTEXT index over the `title` property of the
// governed record labels that participate in hybrid retrieval, so the keyword
// signal in graph_query_api (`_hybrid_keyword_ranks`) can use
// `db.index.fulltext.queryNodes('governed_record_title_ft', ...)` instead of a
// per-token CONTAINS scan over every node (DOC-52FE56D6F529 U2, ruling D-1).
//
// Labels (match `label_map` in graph_query_api `_hybrid_keyword_ranks`):
//   Task, Issue, Feature, Plan, Lesson, Document, Recipe, RecipeRun
//
// TITLE ONLY (ruling D-1). `intent` and `description` are NOT projected onto
// prod graph nodes by graph_sync (Neo4j emitted UnknownPropertyKeyWarning for
// both), so they are deliberately excluded. If graph_sync later projects them,
// add a follow-up migration (003) rather than editing this one.
//
// Idempotency: `IF NOT EXISTS`. Re-running is a no-op.
//
// Cost: indexes are included in the Aura instance (a few MB at ~1% storage).
// Cost class C1 (one-off migration run); $0.00 persistent.
//
// Run (see README.md): backfill_graph.py --run-migration, cypher-shell, or the
// Aura Query tool. Additive and unused until graph_query_api ships the
// fulltext keyword path; the CONTAINS path remains the documented fallback.
//
// Verification:
//   SHOW FULLTEXT INDEXES YIELD name, state, labelsOrTypes, properties
//     WHERE name = 'governed_record_title_ft';
//
// ---------------------------------------------------------------------------

CREATE FULLTEXT INDEX governed_record_title_ft IF NOT EXISTS
FOR (n:Task|Issue|Feature|Plan|Lesson|Document|Recipe|RecipeRun)
ON EACH [n.title];
