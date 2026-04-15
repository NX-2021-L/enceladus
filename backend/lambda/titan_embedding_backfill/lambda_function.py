"""devops-titan-embedding-backfill Lambda — Phase 1 corpus embedding backfill.

One-shot Lambda that scans the governed corpus, invokes Amazon Titan Text
Embeddings V2 per record, and writes the resulting 256-dim vectors to the
corresponding Neo4j node's `embedding` property. Feeds the HNSW vector
indexes created by ENC-TSK-B90 migration 001, which together unlock the
Phase 1 Hybrid Retrieval gate defined by ENC-TSK-B62 under ENC-PLN-006.

Architecture
------------
    DynamoDB scan (devops-project-tracker + documents)
        -> extract_embeddable_text() per record
        -> invoke_titan_v2_embedding()       (amazon.titan-embed-text-v2:0, 256 dim)
        -> write_embedding_to_neo4j()        (per-label SET n.embedding = $vec)
        -> count_embedding_coverage()        (per-label AC-1 verification)

Invocation
----------
- Trigger: manual (AWS CLI `aws lambda invoke`) or EventBridge rule.
- Input event (all optional):
    {
      "limit":   <int>   # Safety cap on records processed; default: unlimited.
      "labels":  [<str>] # Restrict to specific labels; default: all six.
      "dry_run": <bool>  # Scan + embed but skip Neo4j write; default: false.
      "skip_existing": <bool>  # Skip records that already have .embedding
                                 # set in Neo4j; default: true. Enables
                                 # resume-after-throttle semantics.
    }
- Output: coverage report per label plus a `done` flag:
    {
      "status": "ok",
      "coverage": {
        "Task":    {"total": N, "with_embedding": M, "pct": 0.xx},
        "Issue":   ...,
        ...
      },
      "processed": <int>,
      "skipped":   <int>,
      "errors":    <int>,
      "elapsed_seconds": <float>
    }

Governance
----------
- Component: comp-neo4j-backup (Neo4j-schema steward per B90 README).
- Transition type: github_pr_deploy (enforced by component registry).
- Lambda runtime: python3.11 (prod x86_64) / python3.12 (gamma arm64), mirroring
  the graph_sync + neo4j_backup Lambdas.
- IAM role grants: bedrock:InvokeModel on amazon.titan-embed-text-v2:0,
  dynamodb:Scan/Query on devops-project-tracker + documents,
  secretsmanager:GetSecretValue on enceladus/neo4j/auradb-credentials*.

Related: ENC-TSK-B62, ENC-TSK-B90, ENC-TSK-B94 (incremental counterpart).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Import embedding helpers. During Lambda packaging, deploy.sh copies
# backend/lambda/shared_layer/python/enceladus_shared/embedding.py into this
# directory as `embedding.py` (see deploy.sh::package_lambda). When the
# shared_layer becomes a proper Lambda layer attachment, this import can
# switch to `from enceladus_shared.embedding import ...` without any other
# changes to the Lambda body. B94 (sister task) reuses the same module.
# ---------------------------------------------------------------------------
try:
    # Preferred path: shared layer attached as /opt/python.
    from enceladus_shared.embedding import (  # type: ignore
        GOVERNED_VECTOR_INDEXES,
        RECORD_TYPE_TO_LABEL,
        EMBEDDING_PROPERTY,
        TITAN_V2_DIMENSIONS,
        count_embedding_coverage,
        extract_embeddable_text,
        invoke_titan_v2_embedding,
        write_embedding_to_neo4j,
    )
except ImportError:
    # Fallback path: local copy bundled by deploy.sh.
    from embedding import (  # type: ignore
        GOVERNED_VECTOR_INDEXES,
        RECORD_TYPE_TO_LABEL,
        EMBEDDING_PROPERTY,
        TITAN_V2_DIMENSIONS,
        count_embedding_coverage,
        extract_embeddable_text,
        invoke_titan_v2_embedding,
        write_embedding_to_neo4j,
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
DDB_REGION = os.environ.get("DDB_REGION", "us-west-2")
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-west-2")

# ---------------------------------------------------------------------------
# Lazy singletons (cold-start cached)
# ---------------------------------------------------------------------------

_ddb = None
_secretsmanager = None
_bedrock_runtime = None
_neo4j_driver = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        import boto3
        from botocore.config import Config
        _ddb = boto3.resource(
            "dynamodb",
            region_name=DDB_REGION,
            config=Config(retries={"max_attempts": 5, "mode": "standard"}),
        )
    return _ddb


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        from botocore.config import Config
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


def _get_bedrock_runtime():
    global _bedrock_runtime
    if _bedrock_runtime is None:
        import boto3
        from botocore.config import Config
        _bedrock_runtime = boto3.client(
            "bedrock-runtime",
            region_name=BEDROCK_REGION,
            # Bedrock throttles aggressively on full-corpus backfills. Let
            # botocore retry transient failures in addition to the explicit
            # backoff inside invoke_titan_v2_embedding.
            config=Config(
                retries={"max_attempts": 5, "mode": "adaptive"},
                read_timeout=30,
                connect_timeout=10,
            ),
        )
    return _bedrock_runtime


def _get_neo4j_credentials() -> Dict[str, str]:
    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=NEO4J_SECRET_NAME)
    return json.loads(resp["SecretString"])


def _get_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver is None:
        from neo4j import GraphDatabase
        creds = _get_neo4j_credentials()
        _neo4j_driver = GraphDatabase.driver(
            creds["NEO4J_URI"],
            auth=(creds.get("NEO4J_USERNAME", "neo4j"), creds["NEO4J_PASSWORD"]),
        )
    return _neo4j_driver


# ---------------------------------------------------------------------------
# Corpus iteration
# ---------------------------------------------------------------------------


def _bare_id(record_id: str) -> str:
    if not record_id:
        return ""
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def _iter_tracker_records() -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield (record_id, label, item) tuples from the tracker table.

    Filters out COUNTER-* placeholders and relationship tombstones.
    Labels are resolved via RECORD_TYPE_TO_LABEL so the caller does not
    need to know the mapping.
    """
    table = _get_ddb().Table(TRACKER_TABLE)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            record_id = str(item.get("record_id") or "")
            if not record_id or record_id.startswith("COUNTER-"):
                continue
            # Skip typed-relationship edge tombstones (rel# SK prefix).
            if record_id.startswith("rel#"):
                continue
            record_type = str(item.get("record_type") or "").lower()
            label = RECORD_TYPE_TO_LABEL.get(record_type)
            if not label:
                # Unknown record types (e.g. generation, deployment_decision)
                # aren't part of the Phase 1 corpus.
                continue
            yield _bare_id(record_id), label, item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def _iter_document_records() -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield (document_id, 'Document', item) tuples from the documents table."""
    table = _get_ddb().Table(DOCUMENTS_TABLE)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            document_id = str(item.get("document_id") or "")
            if not document_id:
                continue
            if str(item.get("status") or "active") != "active":
                # Skip tombstoned / archived documents.
                continue
            yield document_id, "Document", item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def _iter_corpus(
    allowed_labels: Optional[List[str]] = None,
) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield the full Phase 1 corpus, optionally filtered to a label subset."""
    allowed = set(allowed_labels) if allowed_labels else set(GOVERNED_VECTOR_INDEXES.keys())
    for record_id, label, item in _iter_tracker_records():
        if label in allowed:
            yield record_id, label, item
    if "Document" in allowed:
        for document_id, label, item in _iter_document_records():
            yield document_id, label, item


# ---------------------------------------------------------------------------
# Skip-existing helper (resume after throttling)
# ---------------------------------------------------------------------------


def _already_embedded(driver, record_id: str, label: str, project_id: Optional[str]) -> bool:
    """Return True when the Neo4j node already has an `embedding` property."""
    if label not in GOVERNED_VECTOR_INDEXES:
        return False
    if project_id:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id, project_id: $project_id}}) "
            f"RETURN n.{EMBEDDING_PROPERTY} IS NOT NULL AS has_embedding"
        )
        params = {"record_id": record_id, "project_id": project_id}
    else:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id}}) "
            f"RETURN n.{EMBEDDING_PROPERTY} IS NOT NULL AS has_embedding"
        )
        params = {"record_id": record_id}
    with driver.session() as session:
        row = session.run(cypher, **params).single()
        return bool(row and row["has_embedding"])


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """One-shot backfill entrypoint.

    See module docstring for event schema. Returns a coverage report and
    aggregate counters that the caller (CI smoke test or manual invocation)
    can feed into live_validation_evidence.
    """
    logger.info("[START] Titan V2 backfill Lambda invoked event=%s", json.dumps(event or {}))

    started_at = time.time()
    limit = int(event.get("limit") or 0) if event else 0
    dry_run = bool(event.get("dry_run")) if event else False
    skip_existing = bool(event.get("skip_existing", True)) if event else True
    requested_labels = event.get("labels") if event else None

    # Defensive: validate label allow-list up front so a typo fails fast.
    allowed_labels: Optional[List[str]] = None
    if requested_labels:
        if not isinstance(requested_labels, list) or not all(
            isinstance(x, str) for x in requested_labels
        ):
            raise ValueError("event.labels must be a list of strings")
        for label in requested_labels:
            if label not in GOVERNED_VECTOR_INDEXES:
                raise ValueError(
                    f"Unknown label '{label}'. Allowed: {sorted(GOVERNED_VECTOR_INDEXES.keys())}"
                )
        allowed_labels = requested_labels

    bedrock_rt = _get_bedrock_runtime()
    driver = _get_neo4j_driver() if not dry_run else None

    processed = 0
    skipped = 0
    errors = 0
    missing_node = 0
    per_label_processed: Dict[str, int] = {lbl: 0 for lbl in GOVERNED_VECTOR_INDEXES}

    for record_id, label, item in _iter_corpus(allowed_labels):
        if limit and processed + skipped + errors >= limit:
            logger.info("[INFO] Reached event.limit=%d; stopping scan", limit)
            break

        project_id = str(item.get("project_id") or "") or None

        # Skip records that already have an embedding (resume-friendly).
        if skip_existing and not dry_run and driver is not None:
            try:
                if _already_embedded(driver, record_id, label, project_id):
                    skipped += 1
                    continue
            except Exception as exc:  # noqa: BLE001 — defensive
                logger.warning(
                    "[WARN] skip-existing probe failed for %s:%s — %s",
                    label,
                    record_id,
                    exc,
                )

        text = extract_embeddable_text(item)
        if not text:
            logger.warning("[WARN] empty embeddable text for %s:%s — skipping", label, record_id)
            skipped += 1
            continue

        try:
            vector = invoke_titan_v2_embedding(bedrock_rt, text, dimensions=TITAN_V2_DIMENSIONS)
        except Exception as exc:  # noqa: BLE001 — defensive
            errors += 1
            logger.error(
                "[ERROR] Titan V2 invoke failed for %s:%s — %s: %s",
                label,
                record_id,
                type(exc).__name__,
                exc,
            )
            continue

        if dry_run or driver is None:
            processed += 1
            per_label_processed[label] = per_label_processed.get(label, 0) + 1
            continue

        try:
            wrote = write_embedding_to_neo4j(
                driver,
                record_id=record_id,
                label=label,
                embedding=vector,
                project_id=project_id,
            )
        except Exception as exc:  # noqa: BLE001 — defensive
            errors += 1
            logger.error(
                "[ERROR] Neo4j write failed for %s:%s — %s: %s",
                label,
                record_id,
                type(exc).__name__,
                exc,
            )
            continue

        if not wrote:
            missing_node += 1
            logger.warning(
                "[WARN] Neo4j node not found for %s:%s project_id=%s — graph_sync projection gap",
                label,
                record_id,
                project_id,
            )
            continue

        processed += 1
        per_label_processed[label] = per_label_processed.get(label, 0) + 1
        if processed % 25 == 0:
            logger.info(
                "[INFO] progress: processed=%d skipped=%d errors=%d missing_node=%d",
                processed,
                skipped,
                errors,
                missing_node,
            )

    # ------------------------------------------------------------------
    # Coverage report (AC-1 verification)
    # ------------------------------------------------------------------
    coverage: Dict[str, Dict[str, Any]] = {}
    if not dry_run and driver is not None:
        for label in GOVERNED_VECTOR_INDEXES:
            if allowed_labels and label not in allowed_labels:
                continue
            try:
                counts = count_embedding_coverage(driver, label)
                total = counts["total"]
                with_emb = counts["with_embedding"]
                pct = (with_emb / total) if total else 0.0
                coverage[label] = {
                    "total": total,
                    "with_embedding": with_emb,
                    "pct": round(pct, 4),
                    "meets_ac1_threshold": total == 0 or pct >= 0.95,
                }
            except Exception as exc:  # noqa: BLE001
                coverage[label] = {"error": f"{type(exc).__name__}: {exc}"}

    elapsed = time.time() - started_at
    result: Dict[str, Any] = {
        "status": "ok" if errors == 0 else "partial",
        "processed": processed,
        "skipped": skipped,
        "errors": errors,
        "missing_node": missing_node,
        "per_label_processed": per_label_processed,
        "coverage": coverage,
        "dry_run": dry_run,
        "elapsed_seconds": round(elapsed, 2),
        "model_id": "amazon.titan-embed-text-v2:0",
        "dimensions": TITAN_V2_DIMENSIONS,
    }
    logger.info("[END] Titan V2 backfill complete: %s", json.dumps(result, default=str))
    return result
