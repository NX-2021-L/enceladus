// ENC-TSK-B90 Neo4j HNSW vector indexes for Titan V2 embeddings
//
// Creates per-label HNSW vector indexes on the `embedding` property for the
// six governed record types that participate in the Phase 1 hybrid retrieval
// corpus (ENC-TSK-B62 / ENC-FTR-062):
//
//   Task, Issue, Feature, Plan, Lesson, Document
//
// Labels intentionally excluded:
//   - Generation          (GMF metadata; not part of the retrieval corpus)
//   - Project             (side node; not a governed record)
//   - DeploymentDecision  (placeholder-only projection today)
//
// Index contract (mandated by ENC-TSK-B62 AC-2):
//   - dimensions             = 256
//   - similarity function    = cosine
//   - target property name   = embedding
//
// Amazon Titan Text Embeddings V2 (amazon.titan-embed-text-v2:0) supports 256
// via the `dimensions` invoke parameter. The ENC-TSK-B91 backfill worker MUST
// invoke the model with `dimensions=256` for produced vectors to match the
// indexes below. Any mismatch leaves the indexes live but unused.
//
// Idempotency: every statement uses `IF NOT EXISTS`. Re-running this file
// against an AuraDB that already has the indexes is a no-op.
//
// Prerequisite: Neo4j 5.11+ (native vector index support). All current
// AuraDB tiers (Free, Professional, Enterprise) meet this requirement as of
// 2024. If the target is older, these statements will fail cleanly with a
// syntax error and no index will be created.
//
// Operational notes:
//   - Vector indexes are non-disruptive: creating them does not affect
//     existing queries, and they sit unused until queried via
//     db.index.vector.queryNodes(...) or a CALL db.index.vector.* procedure.
//   - The shared prod+gamma AuraDB means running this migration affects
//     production reads too. Verified a recent enceladus-neo4j-backup-gamma
//     snapshot exists in s3://jreese-net/gamma/neo4j-backups/ before applying.
//
// Verification (run after applying):
//   SHOW VECTOR INDEXES
//     YIELD name, labelsOrTypes, properties, options
//     WHERE name STARTS WITH 'governed_';
//
// ---------------------------------------------------------------------------

CREATE VECTOR INDEX governed_task_embedding IF NOT EXISTS
FOR (n:Task) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};

CREATE VECTOR INDEX governed_issue_embedding IF NOT EXISTS
FOR (n:Issue) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};

CREATE VECTOR INDEX governed_feature_embedding IF NOT EXISTS
FOR (n:Feature) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};

CREATE VECTOR INDEX governed_plan_embedding IF NOT EXISTS
FOR (n:Plan) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};

CREATE VECTOR INDEX governed_lesson_embedding IF NOT EXISTS
FOR (n:Lesson) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};

CREATE VECTOR INDEX governed_document_embedding IF NOT EXISTS
FOR (n:Document) ON n.embedding
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 256,
    `vector.similarity_function`: 'cosine'
  }
};
