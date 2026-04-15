"""enceladus_shared.embedding — Titan V2 embedding helpers.

Shared helpers for generating and storing Amazon Titan Text Embeddings V2 vectors
on governed Enceladus records. Used by:

- ENC-TSK-B91 (titan_embedding_backfill Lambda) — full-corpus batch backfill
- ENC-TSK-B94 (incremental trigger on mutation) — expected consumer on landing

Contract (ENC-TSK-B62 Phase 1 Hybrid Retrieval gate, AC-2 via ENC-TSK-B90):

- Model:           amazon.titan-embed-text-v2:0
- Dimensions:      256
- Normalization:   true   (cosine similarity expects unit-norm inputs)
- Similarity fn:   cosine (matches governed_*_embedding HNSW indexes from B90)
- Target property: Neo4j node `.embedding` (per-label, per B90 migration 001)

The six governed node labels that participate in the Phase 1 retrieval corpus:
Task, Issue, Feature, Plan, Lesson, Document.

This module is deliberately narrow: it does NOT connect to DynamoDB, does NOT
open a Neo4j driver, and does NOT handle pagination. Callers own batching,
credential fetch, and driver lifecycle. See `invoke_titan_v2_embedding` and
`write_embedding_to_neo4j` for the per-record primitives and
`extract_embeddable_text` for the canonical embeddable-text extractor.

Part of ENC-TSK-B91.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase 1 contract constants — MUST match B90 HNSW index options.
# ---------------------------------------------------------------------------

TITAN_V2_MODEL_ID = "amazon.titan-embed-text-v2:0"
TITAN_V2_DIMENSIONS = 256
TITAN_V2_NORMALIZE = True
TITAN_V2_SIMILARITY = "cosine"

EMBEDDING_PROPERTY = "embedding"

# Per-label HNSW index names created by ENC-TSK-B90 migration 001. Kept here
# as a reference for callers that need to query indexes by name; the write
# path below does not reference them directly (Neo4j auto-routes writes to
# any matching vector index).
GOVERNED_VECTOR_INDEXES = {
    "Task": "governed_task_embedding",
    "Issue": "governed_issue_embedding",
    "Feature": "governed_feature_embedding",
    "Plan": "governed_plan_embedding",
    "Lesson": "governed_lesson_embedding",
    "Document": "governed_document_embedding",
}

# Record-type -> Neo4j node label mapping. Mirrors
# graph_sync.RECORD_TYPE_TO_LABEL so embeddings land on the same nodes the
# graph projection uses. Backfill callers pass `record_type` from the
# DynamoDB item; incremental callers can pass label directly.
RECORD_TYPE_TO_LABEL = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "plan": "Plan",
    "lesson": "Lesson",
    "document": "Document",
}

# Default invoke retry / backoff for Bedrock throttling. Conservative for
# full-corpus backfills — callers doing incremental single-record work can
# pass smaller values via `max_retries=1`.
DEFAULT_MAX_RETRIES = 5
DEFAULT_INITIAL_BACKOFF_SECONDS = 1.0

# Titan V2 input cap is 8000 tokens (~38000 chars). We truncate well below
# that at 20000 chars to leave headroom for future contract changes.
MAX_EMBEDDABLE_TEXT_CHARS = 20000


# ---------------------------------------------------------------------------
# Canonical embeddable-text extractor
# ---------------------------------------------------------------------------


def extract_embeddable_text(record: Dict[str, Any]) -> str:
    """Build the canonical embeddable text for a governed record.

    Concatenates title + intent + description (where present) with labelled
    separators so the semantic structure survives the embedding. Uses the
    same field names that the DynamoDB tracker and document_api produce,
    which mirrors what `get_compact_context` already surfaces for retrieval.

    The format is deliberately small and human-readable so that future
    upgrades (longer context, different field orders) can be audited by
    diffing the emitted strings.

    Parameters
    ----------
    record : dict
        The raw record item (DynamoDB deserialized or API response). Must
        contain at least one of {title, intent, description, summary}.

    Returns
    -------
    str
        Embeddable text, never empty. If no text fields are present, the
        record's ID and record_type are returned as a fallback so the
        record still lands in the corpus.
    """
    title = str(record.get("title") or "").strip()
    intent = str(record.get("intent") or "").strip()
    description = str(record.get("description") or "").strip()
    summary = str(record.get("summary") or "").strip()

    parts: List[str] = []
    if title:
        parts.append(f"Title: {title}")
    if intent:
        parts.append(f"Intent: {intent}")
    # Prefer description over summary when both exist; fall through to
    # summary so Document records (which often populate only `summary`)
    # still contribute text.
    if description:
        parts.append(f"Description: {description}")
    elif summary:
        parts.append(f"Summary: {summary}")

    if not parts:
        record_id = str(record.get("record_id") or record.get("document_id") or "").strip()
        record_type = str(record.get("record_type") or "").strip()
        fallback = f"{record_type or 'record'}: {record_id or 'unknown'}"
        return fallback[:MAX_EMBEDDABLE_TEXT_CHARS]

    text = "\n\n".join(parts)
    if len(text) > MAX_EMBEDDABLE_TEXT_CHARS:
        text = text[:MAX_EMBEDDABLE_TEXT_CHARS]
    return text


# ---------------------------------------------------------------------------
# Bedrock invoke
# ---------------------------------------------------------------------------


def invoke_titan_v2_embedding(
    bedrock_runtime,
    text: str,
    *,
    dimensions: int = TITAN_V2_DIMENSIONS,
    normalize: bool = TITAN_V2_NORMALIZE,
    max_retries: int = DEFAULT_MAX_RETRIES,
    initial_backoff_seconds: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
) -> List[float]:
    """Invoke Titan Text Embeddings V2 and return the embedding vector.

    Implements exponential backoff on ThrottlingException / ServiceUnavailable,
    which are common during full-corpus backfills. Returns the
    `float`-valued embedding list (`dimensions` elements) ready for
    `SET n.embedding = $vec`.

    Parameters
    ----------
    bedrock_runtime : botocore.client.BedrockRuntime
        A boto3 `bedrock-runtime` client (caller owns lifecycle).
    text : str
        The embeddable text. Callers should pass the output of
        `extract_embeddable_text` directly.
    dimensions : int
        Output dimension count. Must be 256, 512, or 1024; Phase 1 contract
        pins this to 256.
    normalize : bool
        When true, Titan returns a unit-norm vector (cosine similarity
        expects this).
    max_retries : int
        Exponential-backoff retry budget for throttling / transient errors.
    initial_backoff_seconds : float
        First-attempt sleep on throttling; doubled each retry.

    Returns
    -------
    list[float]
        Embedding vector of length `dimensions`.

    Raises
    ------
    ValueError
        If `text` is empty after stripping.
    RuntimeError
        If Bedrock returns a non-retryable error or the response shape is
        unexpected.
    Exception
        Propagates the final Bedrock exception after retries are exhausted.
    """
    if not text or not text.strip():
        raise ValueError("extract_embeddable_text returned empty; cannot invoke Titan V2")

    body = {
        "inputText": text,
        "dimensions": dimensions,
        "normalize": normalize,
    }

    last_exc: Optional[Exception] = None
    backoff = initial_backoff_seconds
    for attempt in range(max_retries):
        try:
            resp = bedrock_runtime.invoke_model(
                modelId=TITAN_V2_MODEL_ID,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body),
            )
            payload = json.loads(resp["body"].read())
            vector = payload.get("embedding")
            if not isinstance(vector, list) or len(vector) != dimensions:
                raise RuntimeError(
                    f"Unexpected Titan V2 response shape: got {type(vector).__name__} "
                    f"len={len(vector) if isinstance(vector, list) else 'n/a'}, "
                    f"expected list of {dimensions} floats"
                )
            return [float(x) for x in vector]
        except Exception as exc:  # noqa: BLE001 — boto3 raises a wide class
            last_exc = exc
            exc_name = type(exc).__name__
            # Retry only on transient / throttling errors. The client-side
            # name detection avoids depending on a botocore import here.
            retryable = exc_name in {
                "ThrottlingException",
                "ModelTimeoutException",
                "ServiceUnavailableException",
                "InternalServerException",
            } or "Throttl" in str(exc) or "503" in str(exc)
            if not retryable or attempt == max_retries - 1:
                logger.error(
                    "[ERROR] Titan V2 invoke failed (attempt %d/%d): %s: %s",
                    attempt + 1,
                    max_retries,
                    exc_name,
                    exc,
                )
                raise
            logger.warning(
                "[WARN] Titan V2 transient failure (attempt %d/%d): %s — sleeping %.1fs",
                attempt + 1,
                max_retries,
                exc_name,
                backoff,
            )
            time.sleep(backoff)
            backoff *= 2

    # Unreachable — the loop either returns or raises.
    raise RuntimeError(f"Titan V2 retry loop exited without result; last={last_exc}")


# ---------------------------------------------------------------------------
# Neo4j write
# ---------------------------------------------------------------------------


def _bare_id(record_id: str) -> str:
    """Strip a `type#` prefix from a DynamoDB composite record_id.

    Mirrors tools/backfill_graph.py._bare_id so Lambda write paths and the
    CLI helper agree on the canonical node-key form.
    """
    if not record_id:
        return ""
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def write_embedding_to_neo4j(
    driver,
    *,
    record_id: str,
    label: str,
    embedding: List[float],
    project_id: Optional[str] = None,
) -> bool:
    """MERGE the embedding property onto the Neo4j node for this record.

    Uses `MATCH ... SET n.embedding = $vec` so the write is a no-op when the
    node hasn't been projected yet (callers can retry or fall through to the
    next record). Does NOT create the node — graph_sync is the sole node
    projector.

    Parameters
    ----------
    driver : neo4j.Driver
        A connected Neo4j driver (caller owns lifecycle).
    record_id : str
        Bare record ID (`ENC-TSK-B91`) or composite DynamoDB form
        (`task#ENC-TSK-B91`) — this function strips the prefix.
    label : str
        Neo4j node label (`Task`, `Issue`, ... — see RECORD_TYPE_TO_LABEL).
        Passed into the Cypher via safe-string substitution; callers MUST
        validate against the allow-list before calling.
    embedding : list[float]
        The vector returned by `invoke_titan_v2_embedding`.
    project_id : str, optional
        When provided, the MATCH is narrowed to `n.project_id = $project_id`.
        Recommended — protects against cross-project ID collisions.

    Returns
    -------
    bool
        True when a node was updated, False when no matching node exists
        (caller can log this as a projection-gap warning).

    Raises
    ------
    ValueError
        If `label` is not in GOVERNED_VECTOR_INDEXES (write refused rather
        than opening a Cypher injection path).
    """
    if label not in GOVERNED_VECTOR_INDEXES:
        raise ValueError(
            f"Refusing to write embedding to unknown label '{label}'. "
            f"Allowed: {sorted(GOVERNED_VECTOR_INDEXES.keys())}"
        )

    bare = _bare_id(record_id)
    if not bare:
        raise ValueError("record_id is required for embedding write")

    # `label` is validated against an allow-list above — safe to f-string.
    if project_id:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id, project_id: $project_id}}) "
            f"SET n.{EMBEDDING_PROPERTY} = $vec "
            "RETURN count(n) AS updated"
        )
        params = {"record_id": bare, "project_id": project_id, "vec": embedding}
    else:
        cypher = (
            f"MATCH (n:{label} {{record_id: $record_id}}) "
            f"SET n.{EMBEDDING_PROPERTY} = $vec "
            "RETURN count(n) AS updated"
        )
        params = {"record_id": bare, "vec": embedding}

    with driver.session() as session:
        result = session.run(cypher, **params).single()
        updated = int(result["updated"]) if result else 0
    return updated > 0


# ---------------------------------------------------------------------------
# Coverage query helpers (used by live validation + health checks)
# ---------------------------------------------------------------------------


def count_embedding_coverage(driver, label: str) -> Dict[str, int]:
    """Return `{'total': N, 'with_embedding': M}` for the given label.

    Enables AC-1 coverage verification (>=95%) without a full graph dump.
    """
    if label not in GOVERNED_VECTOR_INDEXES:
        raise ValueError(
            f"Unknown label '{label}'. "
            f"Allowed: {sorted(GOVERNED_VECTOR_INDEXES.keys())}"
        )
    cypher = (
        f"MATCH (n:{label}) "
        "RETURN count(n) AS total, "
        f"count(n.{EMBEDDING_PROPERTY}) AS with_embedding"
    )
    with driver.session() as session:
        row = session.run(cypher).single()
        if row is None:
            return {"total": 0, "with_embedding": 0}
        return {
            "total": int(row["total"]),
            "with_embedding": int(row["with_embedding"]),
        }
