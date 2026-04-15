"""devops-titan-embedding-backfill Lambda — Phase 1 corpus embedding backfill.

One-shot Lambda that scans the governed corpus, invokes Amazon Titan Text
Embeddings V2 per record, and writes the resulting 256-dim vectors to the
corresponding Neo4j node's `embedding` property (plus `embedding_text_hash`
for resume semantics). Feeds the HNSW vector indexes created by ENC-TSK-B90
migration 001, which together unlock the Phase 1 Hybrid Retrieval gate
defined by ENC-TSK-B62 under ENC-PLN-006.

Parity with ENC-TSK-B94
-----------------------
This Lambda imports `build_embedding_text`, `hash_embedding_text`, and
`invoke_titan_v2` from the CANONICAL helper module at
`backend/lambda/graph_sync/embedding.py` (introduced by ENC-TSK-B94 when
wiring the incremental mutation-path embedding). The module is copied into
this Lambda's build by deploy.sh so both paths produce identical vectors
for identical text. Any contract change must happen upstream in
graph_sync/embedding.py; this Lambda does not fork the helper.

Architecture
------------
    DynamoDB scan (devops-project-tracker + documents)
      -> build_embedding_text()      (from graph_sync/embedding.py)
      -> hash_embedding_text()       (resume-friendly cache key)
      -> skip if node already has matching embedding_text_hash
      -> invoke_titan_v2()           (amazon.titan-embed-text-v2:0, 256 dim)
      -> write_embedding_to_neo4j()  (local Cypher MERGE helper)
      -> count_embedding_coverage()  (per-label AC-1 verification)

Invocation
----------
Agent-CLI IAM denies the required scopes; this Lambda must be invoked by a
product-lead terminal session (io-dev-admin) via
`aws lambda invoke --function-name devops-titan-embedding-backfill-gamma ...`
Live validation routing follows the ENC-TSK-B90 HANDOFF document pattern.

Event schema (all optional):
    {
      "limit":         <int>   — safety cap on records processed.
      "labels":        [<str>] — restrict to a label subset; default all six.
      "dry_run":       <bool>  — skip Neo4j writes; default false.
      "skip_existing": <bool>  — skip records whose embedding_text_hash matches;
                                 default true (enables resume after throttling).
    }

Response schema:
    {
      "status": "ok" | "partial",
      "processed": int,
      "skipped":   int,
      "errors":    int,
      "missing_node": int,
      "per_label_processed": {<Label>: int},
      "coverage": {
        <Label>: {total, with_embedding, pct, meets_ac1_threshold},
        ...
      },
      "dry_run": bool,
      "elapsed_seconds": float,
      "model_id": "amazon.titan-embed-text-v2:0",
      "dimensions": 256
    }

Related: ENC-TSK-B62, ENC-TSK-B90, ENC-TSK-B94, ENC-FTR-062, ENC-PLN-006.
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
# Import the ENC-TSK-B94 canonical helper module. deploy.sh copies
# backend/lambda/graph_sync/embedding.py into this Lambda's build dir as
# `embedding.py`, so a plain `from embedding import ...` resolves at runtime.
# We intentionally reuse invoke_titan_v2 directly rather than re-implementing
# it, to preserve vector parity with the incremental stream path.
# ---------------------------------------------------------------------------
from embedding import (  # type: ignore
    EMBEDDABLE_RECORD_TYPES,
    EMBEDDING_DIMENSIONS,
    EMBEDDING_HASH_PROPERTY,
    EMBEDDING_PROPERTY,
    TITAN_MODEL_ID,
    build_embedding_text,
    hash_embedding_text,
    invoke_titan_v2,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("TRACKER_TABLE", "devops-project-tracker")
DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
DDB_REGION = os.environ.get("DDB_REGION", "us-west-2")

# Record-type -> Neo4j node label mapping. Mirrors
# graph_sync.RECORD_TYPE_TO_LABEL so embeddings land on the same nodes the
# graph projection uses. The six labels indexed by B90 migration 001.
RECORD_TYPE_TO_LABEL: Dict[str, str] = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "plan": "Plan",
    "lesson": "Lesson",
    "document": "Document",
}

# Allow-list used for label validation before Cypher substitution.
ALLOWED_LABELS = set(RECORD_TYPE_TO_LABEL.values())


# ---------------------------------------------------------------------------
# Lazy singletons (cold-start cached)
# ---------------------------------------------------------------------------

_ddb = None
_secretsmanager = None
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
# ID helpers
# ---------------------------------------------------------------------------


def _bare_id(record_id: str) -> str:
    """Strip a `type#` prefix from a DynamoDB composite record_id."""
    if not record_id:
        return ""
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


# ---------------------------------------------------------------------------
# Corpus iteration
# ---------------------------------------------------------------------------


def _iter_tracker_records() -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield (bare_record_id, label, item) tuples from the tracker table.

    Filters out COUNTER-* placeholders and rel# typed-relationship tombstones.
    Unknown record types (e.g. generation, deployment_decision) are skipped
    because they are not part of the Phase 1 retrieval corpus.
    """
    table = _get_ddb().Table(TRACKER_TABLE)
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            record_id = str(item.get("record_id") or "")
            if not record_id or record_id.startswith("COUNTER-"):
                continue
            if record_id.startswith("rel#"):
                continue
            record_type = str(item.get("record_type") or "").lower()
            if record_type not in EMBEDDABLE_RECORD_TYPES:
                continue
            label = RECORD_TYPE_TO_LABEL.get(record_type)
            if not label:
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
                continue
            # Stamp record_type so build_embedding_text's
            # EMBEDDABLE_RECORD_TYPES gate passes (documents sometimes omit it
            # in older DynamoDB rows).
            if not item.get("record_type"):
                item["record_type"] = "document"
            yield document_id, "Document", item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key


def _iter_corpus(
    allowed_labels: Optional[List[str]] = None,
) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    """Yield the full Phase 1 corpus, optionally filtered to a label subset."""
    allowed = set(allowed_labels) if allowed_labels else set(ALLOWED_LABELS)
    for record_id, label, item in _iter_tracker_records():
        if label in allowed:
            yield record_id, label, item
    if "Document" in allowed:
        for document_id, label, item in _iter_document_records():
            yield document_id, label, item


# ---------------------------------------------------------------------------
# Neo4j helpers
# ---------------------------------------------------------------------------


def _probe_existing_hash(
    driver, record_id: str, label: str, project_id: Optional[str]
) -> Optional[str]:
    """Return the node's current `embedding_text_hash`, or None when absent.

    Returns None when:
      - label is unknown (rejected up front);
      - the node does not yet exist (projection lag);
      - the node exists but has no embedding_text_hash property.

    Callers use the returned hash to short-circuit re-embedding when the
    newly computed text hashes to the same value (matches B94 semantics).
    """
    if label not in ALLOWED_LABELS:
        return None
    if project_id:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id, project_id: $project_id}}) "
            f"RETURN n.{EMBEDDING_HASH_PROPERTY} AS hash LIMIT 1"
        )
        params = {"record_id": record_id, "project_id": project_id}
    else:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id}}) "
            f"RETURN n.{EMBEDDING_HASH_PROPERTY} AS hash LIMIT 1"
        )
        params = {"record_id": record_id}
    with driver.session() as session:
        row = session.run(cypher, **params).single()
        if row is None:
            return None
        value = row["hash"]
        return str(value) if value else None


def _write_embedding(
    driver,
    *,
    record_id: str,
    label: str,
    embedding: List[float],
    embedding_hash: str,
    project_id: Optional[str],
) -> bool:
    """MATCH + SET both embedding + embedding_text_hash on the Neo4j node.

    Returns True when a node was matched and updated; False when no node
    matches (the caller logs this as a projection gap — graph_sync is the
    sole node projector, so missing nodes indicate an ordering issue to
    surface, not an error to escalate).
    """
    if label not in ALLOWED_LABELS:
        raise ValueError(
            f"Refusing to write embedding to unknown label '{label}'. "
            f"Allowed: {sorted(ALLOWED_LABELS)}"
        )
    if project_id:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id, project_id: $project_id}}) "
            f"SET n.{EMBEDDING_PROPERTY} = $vec, "
            f"    n.{EMBEDDING_HASH_PROPERTY} = $h "
            "RETURN count(n) AS updated"
        )
        params = {
            "record_id": record_id,
            "project_id": project_id,
            "vec": embedding,
            "h": embedding_hash,
        }
    else:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id}}) "
            f"SET n.{EMBEDDING_PROPERTY} = $vec, "
            f"    n.{EMBEDDING_HASH_PROPERTY} = $h "
            "RETURN count(n) AS updated"
        )
        params = {"record_id": record_id, "vec": embedding, "h": embedding_hash}
    with driver.session() as session:
        row = session.run(cypher, **params).single()
        return bool(row and int(row["updated"]) > 0)


def _coverage_for_label(driver, label: str) -> Dict[str, int]:
    """Return {'total': N, 'with_embedding': M} for `label`.

    ENC-TSK-E06: excludes placeholder stub nodes (is_placeholder=true) from
    both numerator and denominator so coverage reflects the active corpus
    only. Placeholders are labeled target nodes created by graph_sync
    _reconcile_edges() placeholder MERGE when a typed-edge reference points
    at an ID with no backing DynamoDB record; they carry zero properties
    beyond record_id + is_placeholder.
    """
    if label not in ALLOWED_LABELS:
        raise ValueError(f"Unknown label '{label}'")
    cypher = (
        f"MATCH (n:{label}) "
        "WHERE n.is_placeholder IS NULL OR n.is_placeholder = false "
        f"RETURN count(n) AS total, count(n.{EMBEDDING_PROPERTY}) AS with_embedding"
    )
    with driver.session() as session:
        row = session.run(cypher).single()
        if row is None:
            return {"total": 0, "with_embedding": 0}
        return {
            "total": int(row["total"]),
            "with_embedding": int(row["with_embedding"]),
        }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _is_uat_probe(event: Dict[str, Any]) -> bool:
    """Return True when the invocation is the gamma UAT health probe.

    The tools/gamma_uat_suite.py Lambda-invoke check (ENC-PLN-020 / ENC-TSK-D19)
    sends `{"rawPath":"/__uat_probe__","requestContext":{"http":{"method":"GET"}},"headers":{}}`
    to every deployed Lambda and asserts no FunctionError / ImportModuleError
    with a 30-second timeout. For a scanner-style Lambda, running the real
    workflow would always exceed that timeout. Recognise the probe shape and
    return a lightweight health response so the deploy orchestration gates
    can validate import + handler wiring without triggering a backfill.
    """
    if not isinstance(event, dict):
        return False
    return str(event.get("rawPath") or "") == "/__uat_probe__"


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """One-shot backfill entrypoint. See module docstring for event / response."""
    logger.info("[START] Titan V2 backfill invoked event=%s", json.dumps(event or {}))

    # UAT health probe short-circuit (see _is_uat_probe docstring).
    if _is_uat_probe(event or {}):
        logger.info("[INFO] UAT probe detected; returning health response without scan")
        return {
            "status": "ok",
            "probe": "uat",
            "handler": "lambda_function.lambda_handler",
            "model_id": TITAN_MODEL_ID,
            "dimensions": EMBEDDING_DIMENSIONS,
            "helper_module": "embedding",
        }

    started_at = time.time()
    event = event or {}
    limit = int(event.get("limit") or 0)
    dry_run = bool(event.get("dry_run"))
    skip_existing = bool(event.get("skip_existing", True))
    requested_labels = event.get("labels")

    # Defensive: validate label allow-list up front.
    allowed_labels: Optional[List[str]] = None
    if requested_labels:
        if not isinstance(requested_labels, list) or not all(
            isinstance(x, str) for x in requested_labels
        ):
            raise ValueError("event.labels must be a list of strings")
        for label in requested_labels:
            if label not in ALLOWED_LABELS:
                raise ValueError(
                    f"Unknown label '{label}'. Allowed: {sorted(ALLOWED_LABELS)}"
                )
        allowed_labels = requested_labels

    driver = _get_neo4j_driver() if not dry_run else None

    processed = 0
    skipped = 0
    errors = 0
    missing_node = 0
    per_label_processed: Dict[str, int] = {lbl: 0 for lbl in ALLOWED_LABELS}

    for record_id, label, item in _iter_corpus(allowed_labels):
        if limit and processed + skipped + errors >= limit:
            logger.info("[INFO] Reached event.limit=%d; stopping scan", limit)
            break

        project_id = str(item.get("project_id") or "") or None

        # Build the canonical text using B94's extractor (parity contract).
        text = build_embedding_text(item)
        if not text:
            logger.warning("[WARN] empty embeddable text for %s:%s — skipping", label, record_id)
            skipped += 1
            continue

        text_hash = hash_embedding_text(text)

        # Resume path: skip records whose hash already matches. Matches B94
        # incremental semantics (no-op MODIFY skip).
        if skip_existing and not dry_run and driver is not None:
            try:
                existing_hash = _probe_existing_hash(driver, record_id, label, project_id)
                if existing_hash and existing_hash == text_hash:
                    skipped += 1
                    continue
            except Exception as exc:  # noqa: BLE001 — defensive
                logger.warning(
                    "[WARN] hash-probe failed for %s:%s — %s",
                    label,
                    record_id,
                    exc,
                )

        vector = invoke_titan_v2(text)
        if vector is None:
            errors += 1
            logger.error(
                "[ERROR] invoke_titan_v2 returned None for %s:%s",
                label,
                record_id,
            )
            continue

        if dry_run or driver is None:
            processed += 1
            per_label_processed[label] = per_label_processed.get(label, 0) + 1
            continue

        try:
            wrote = _write_embedding(
                driver,
                record_id=record_id,
                label=label,
                embedding=vector,
                embedding_hash=text_hash,
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
                "[WARN] Neo4j node not found for %s:%s project_id=%s — projection gap",
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

    # ---------------- Coverage report (AC-1) ----------------
    coverage: Dict[str, Dict[str, Any]] = {}
    if not dry_run and driver is not None:
        for label in ALLOWED_LABELS:
            if allowed_labels and label not in allowed_labels:
                continue
            try:
                counts = _coverage_for_label(driver, label)
                total = counts["total"]
                with_emb = counts["with_embedding"]
                pct = (with_emb / total) if total else 0.0
                coverage[label] = {
                    "total": total,
                    "with_embedding": with_emb,
                    "pct": round(pct, 4),
                    "meets_ac1_threshold": total == 0 or pct >= 0.95,
                }
            except Exception as exc:  # noqa: BLE001 — defensive
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
        "model_id": TITAN_MODEL_ID,
        "dimensions": EMBEDDING_DIMENSIONS,
    }
    logger.info("[END] Titan V2 backfill complete: %s", json.dumps(result, default=str))
    return result
