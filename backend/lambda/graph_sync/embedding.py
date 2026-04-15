"""Amazon Titan V2 incremental embedding helpers for graph_sync (ENC-TSK-B94).

Provides the text-extraction contract, Bedrock client accessor, and
`amazon.titan-embed-text-v2:0` invocation shape used to populate the
`embedding` property on Neo4j record nodes. The B91 batch backfill should
import the SAME helpers to guarantee parity between the continuous (stream)
and bulk (backfill) paths.

Contract (mandated by ENC-TSK-B62 AC-2 / ENC-TSK-B90):
  - model_id       = "amazon.titan-embed-text-v2:0"
  - dimensions     = 256
  - normalize      = True
  - property name  = "embedding"

Text contract (shared between B94 incremental and B91 backfill):
  `build_embedding_text(record)` concatenates the title-first, intent-second,
  description-third fields with double-newline separators, stripping blanks
  and deduping lines. The extractor is deliberately conservative: only
  fields guaranteed to exist across Task/Issue/Feature/Plan/Lesson/Document
  are consulted. Extending this contract later must be coordinated with
  B91 so vectors from the two paths remain comparable.

Latency budget notes (sync inline with try/except):
  - Titan V2 typical invoke time: 150-350ms cold, 80-180ms warm
  - Batch-1 single-record invocations only (input text size <10KB)
  - Wrapped in try/except in the caller so Bedrock failure never breaks
    the primary node+edge projection
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants (shared with B91 backfill)
# ---------------------------------------------------------------------------

TITAN_MODEL_ID = "amazon.titan-embed-text-v2:0"
EMBEDDING_DIMENSIONS = 256
EMBEDDING_NORMALIZE = True
EMBEDDING_PROPERTY = "embedding"
EMBEDDING_HASH_PROPERTY = "embedding_text_hash"

# Governed record types that participate in Phase 1 hybrid retrieval.
# Matches the six labels indexed by B90 migration 001.
EMBEDDABLE_RECORD_TYPES = {"task", "issue", "feature", "plan", "lesson", "document"}

# Bedrock runtime region. us-west-2 is the canonical Enceladus region;
# Titan V2 is available in us-west-2 per AWS region coverage.
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-west-2")

# Max input text chars. Titan V2 token limit is 8192 tokens (~32KB chars in
# English). We cap at 24KB to leave safety margin for multi-byte content.
MAX_INPUT_CHARS = 24_000

# ---------------------------------------------------------------------------
# Lazy Bedrock runtime client (cold-start cached)
# ---------------------------------------------------------------------------

_bedrock_runtime = None


def get_bedrock_runtime():
    """Return a lazily-created bedrock-runtime client, cached at module scope."""
    global _bedrock_runtime
    if _bedrock_runtime is None:
        import boto3
        from botocore.config import Config
        _bedrock_runtime = boto3.client(
            "bedrock-runtime",
            region_name=BEDROCK_REGION,
            config=Config(
                retries={"max_attempts": 3, "mode": "standard"},
                read_timeout=10,
                connect_timeout=5,
            ),
        )
    return _bedrock_runtime


# ---------------------------------------------------------------------------
# Text extraction (shared with B91 backfill)
# ---------------------------------------------------------------------------

def build_embedding_text(record: Dict[str, Any]) -> str:
    """Concatenate the canonical embedding text from a governed record.

    Order: title, intent, description. Each part is stripped, blanks are
    dropped, and lines are deduped so an accidental title=description copy
    does not waste context. The returned string is the exact input sent to
    Titan V2; downstream hashing uses it directly.

    The contract is intentionally narrow (three fields) so it works
    uniformly across Task/Issue/Feature/Plan/Lesson/Document without
    record-type branching. B91 backfill MUST call this same function.
    """
    if not isinstance(record, dict):
        return ""

    parts: List[str] = []
    seen: set = set()

    def _add(val: Any) -> None:
        if val is None:
            return
        text = str(val).strip()
        if not text:
            return
        if text in seen:
            return
        seen.add(text)
        parts.append(text)

    # Title is always first to anchor similarity on the short high-signal
    # field; intent is second because it captures the "why"; description is
    # third for bulk semantic content. user_story appended for features.
    _add(record.get("title"))
    _add(record.get("intent"))
    _add(record.get("description"))
    _add(record.get("user_story"))

    combined = "\n\n".join(parts)
    if len(combined) > MAX_INPUT_CHARS:
        combined = combined[:MAX_INPUT_CHARS]
    return combined


def hash_embedding_text(text: str) -> str:
    """Return a stable short hash of the embedding input text.

    Used to skip re-embedding on no-op MODIFY events (e.g. status transitions
    that do not change title/intent/description). Stored alongside the
    embedding as `embedding_text_hash` on the Neo4j node.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Bedrock invocation
# ---------------------------------------------------------------------------

def invoke_titan_v2(text: str) -> Optional[List[float]]:
    """Invoke `amazon.titan-embed-text-v2:0` with the Phase 1 contract.

    Returns a 256-float list on success or None on any failure. Callers
    MUST handle None gracefully (log + skip; never raise).
    """
    if not text:
        return None

    try:
        client = get_bedrock_runtime()
    except Exception:
        logger.exception("[ERROR] Failed to instantiate Bedrock runtime client")
        return None

    request_body = {
        "inputText": text,
        "dimensions": EMBEDDING_DIMENSIONS,
        "normalize": EMBEDDING_NORMALIZE,
    }

    try:
        resp = client.invoke_model(
            modelId=TITAN_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body),
        )
    except Exception:
        logger.exception("[ERROR] Bedrock invoke_model failed for model=%s", TITAN_MODEL_ID)
        return None

    try:
        payload = json.loads(resp["body"].read())
    except Exception:
        logger.exception("[ERROR] Failed to parse Bedrock response body")
        return None

    embedding = payload.get("embedding")
    if not isinstance(embedding, list) or len(embedding) != EMBEDDING_DIMENSIONS:
        logger.error(
            "[ERROR] Bedrock response missing or malformed 'embedding' "
            "(type=%s len=%s expected=%d)",
            type(embedding).__name__,
            len(embedding) if isinstance(embedding, list) else "n/a",
            EMBEDDING_DIMENSIONS,
        )
        return None

    return embedding


# ---------------------------------------------------------------------------
# Public embedding entry-point for graph_sync
# ---------------------------------------------------------------------------

def compute_embedding_for_record(
    record: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build text, check cache against hash, invoke Titan V2 if needed.

    Returns a dict of {embedding: [...256 floats...], embedding_text_hash: str}
    when a fresh embedding is produced, or None when nothing should be
    written (empty text, non-embeddable record, or Bedrock failure).

    The caller supplies the existing hash via the record dict under key
    `_existing_embedding_hash` to short-circuit no-op MODIFY events. If the
    hash matches the newly-computed one, this function returns None (skip).
    """
    record_type = record.get("record_type", "")
    if record_type not in EMBEDDABLE_RECORD_TYPES:
        return None

    text = build_embedding_text(record)
    if not text:
        return None

    text_hash = hash_embedding_text(text)
    existing_hash = record.get("_existing_embedding_hash") or ""
    if existing_hash and existing_hash == text_hash:
        # No-op MODIFY: title/intent/description unchanged, skip Bedrock call.
        return None

    embedding = invoke_titan_v2(text)
    if embedding is None:
        return None

    return {
        EMBEDDING_PROPERTY: embedding,
        EMBEDDING_HASH_PROPERTY: text_hash,
    }
