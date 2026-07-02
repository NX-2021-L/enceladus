"""intent_classifier.py — Session-init proactive intent classifier (ENC-FTR-084 Phase 1).

ENC-TSK-I93. Inference-only Titan V2 nearest-neighbor intent prediction for the
coordination_api session-init path.

Given the first-turn request text and session metadata, this module:
  1. Embeds the first-turn text with `amazon.titan-embed-text-v2:0` (256-dim,
     normalized) — the SAME contract as backend/lambda/graph_sync/embedding.py so
     the query vector lives in the same space as the governed corpus embeddings.
  2. Finds the nearest-neighbor governed records by cosine similarity and returns
     a `predicted_entelechy` = {node_ids: list[str], confidence: float}.
  3. Honors an optional `applied_entelechy_override`: when io supplies it the
     classifier prediction is still computed and logged, but the applied value is
     the io-supplied override (override wins — AC-2).

SCOPE GUARD (AC-5): The classify path is INFERENCE-ONLY for training writes.
Trained record boosts are read from versioned S3 snapshots (FTR-084 Ph2 /
ENC-TSK-K02); mutation runs only in intent_training.py on the scheduled
EventBridge path. `INFERENCE_ONLY`/`TRAINING_ENABLED` below are asserted by
the unit-test suite.

OGTM note (AC-4): Phase 1 returns predictions inline and introduces NO new edge
type, record type, or relational field. The Ontological Graph Traversability
Mandate (ENC-FTR-066) therefore has nothing to validate for this task. A future
phase that persists a PREDICTS edge from a session to its predicted records MUST
complete all four OGTM gates (graph_sync reconcile + label map, graph_query_api
_ALLOWED_EDGE_TYPES, and live E2E traversal) before advancing.

Corpus sourcing: the canonical "Titan V2 nearest-neighbor" primitive
(`cosine_similarity` + `rank_neighbors`) operates on a raw-embedding corpus of
{record_id, embedding} pairs. In production the raw-embedding egress is the
FTR-089 deliverable; until it lands, the default neighbor provider delegates the
vector search to the already-deployed graph vector index via the graph_query_api
hybrid endpoint. Both providers are pluggable so the classifier is fully unit
testable without any network or AWS dependency.
"""

from __future__ import annotations

import json
import logging
import math
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Contract constants (shared with graph_sync/embedding.py)
# ---------------------------------------------------------------------------

TITAN_MODEL_ID = "amazon.titan-embed-text-v2:0"
EMBEDDING_DIMENSIONS = 256
EMBEDDING_NORMALIZE = True
BEDROCK_REGION = os.environ.get("BEDROCK_REGION", "us-west-2")

# Inference-only scope guard markers (asserted by the test suite — AC-5).
INFERENCE_ONLY = True
TRAINING_ENABLED = False

# Default nearest-neighbor breadth.
DEFAULT_TOP_K = 5
MAX_TOP_K = 25
MAX_INPUT_CHARS = 24_000

# graph_query_api endpoint used by the default neighbor provider until the
# FTR-089 raw-embedding egress lands. Empty => provider degrades to no neighbors
# (the classifier never raises; session-init must never be blocked by inference).
GRAPH_QUERY_API_URL = os.environ.get("GRAPH_QUERY_API_URL", "").strip()
GRAPH_QUERY_API_TIMEOUT_S = float(os.environ.get("GRAPH_QUERY_API_TIMEOUT_S", "8"))

_SSL_CTX = ssl.create_default_context()

# Lazy bedrock-runtime client (cold-start cached).
_bedrock_runtime = None


# ---------------------------------------------------------------------------
# Titan V2 embedding (default embed_fn)
# ---------------------------------------------------------------------------

def _get_bedrock_runtime():
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


def embed_query_text(text: str) -> Optional[List[float]]:
    """Embed query text with Titan V2 (256-dim, normalized). None on any failure.

    Mirrors backend/lambda/graph_sync/embedding.py::invoke_titan_v2 so the query
    vector is comparable to the governed corpus embeddings. Never raises.
    """
    if not text:
        return None
    text = text[:MAX_INPUT_CHARS]
    try:
        client = _get_bedrock_runtime()
    except Exception:
        logger.exception("[ERROR] intent_classifier: failed to build bedrock-runtime client")
        return None

    body = {
        "inputText": text,
        "dimensions": EMBEDDING_DIMENSIONS,
        "normalize": EMBEDDING_NORMALIZE,
    }
    try:
        resp = client.invoke_model(
            modelId=TITAN_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )
        payload = json.loads(resp["body"].read())
    except Exception:
        logger.exception("[ERROR] intent_classifier: Titan V2 invoke failed")
        return None

    embedding = payload.get("embedding")
    if not isinstance(embedding, list) or len(embedding) != EMBEDDING_DIMENSIONS:
        logger.error(
            "[ERROR] intent_classifier: malformed Titan response (len=%s)",
            len(embedding) if isinstance(embedding, list) else "n/a",
        )
        return None
    return [float(x) for x in embedding]


# ---------------------------------------------------------------------------
# Nearest-neighbor primitives (canonical Titan V2 cosine NN — pure, testable)
# ---------------------------------------------------------------------------

def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity in [-1, 1]; 0.0 for degenerate/empty/mismatched inputs."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        xf = float(x)
        yf = float(y)
        dot += xf * yf
        na += xf * xf
        nb += yf * yf
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def _calibrate(cosine: float) -> float:
    """Map cosine [-1, 1] to a [0, 1] similarity score."""
    score = (cosine + 1.0) / 2.0
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score


def rank_neighbors(
    query_embedding: Sequence[float],
    corpus: Sequence[Dict[str, Any]],
    top_k: int = DEFAULT_TOP_K,
) -> List[Dict[str, Any]]:
    """Rank a raw-embedding corpus by cosine similarity to the query embedding.

    `corpus` is a sequence of {"record_id": str, "embedding": [floats]} dicts.
    Returns the top_k as [{"record_id", "similarity" (cosine), "score" ([0,1])}]
    sorted by descending similarity. This is the canonical Titan V2
    nearest-neighbor primitive (and the FTR-089 raw-egress consumption path).
    """
    if not query_embedding or top_k <= 0:
        return []
    scored: List[Dict[str, Any]] = []
    for entry in corpus or []:
        if not isinstance(entry, dict):
            continue
        rid = str(entry.get("record_id") or "").strip()
        emb = entry.get("embedding")
        if not rid or not isinstance(emb, (list, tuple)):
            continue
        cos = cosine_similarity(query_embedding, emb)
        scored.append({"record_id": rid, "similarity": cos, "score": _calibrate(cos)})
    scored.sort(key=lambda d: d["similarity"], reverse=True)
    return scored[:top_k]


def make_corpus_neighbor_provider(
    corpus: Sequence[Dict[str, Any]],
) -> Callable[[str, Optional[Sequence[float]], int, str], List[Dict[str, Any]]]:
    """Build a neighbor provider backed by an in-memory raw-embedding corpus.

    This is the production path once FTR-089 raw-embedding egress is wired, and
    the path exercised by the unit tests. Requires a query embedding.
    """

    def _provider(
        query_text: str,
        query_embedding: Optional[Sequence[float]],
        top_k: int,
        project_id: str,
    ) -> List[Dict[str, Any]]:
        if not query_embedding:
            return []
        return [
            {"record_id": n["record_id"], "score": n["score"]}
            for n in rank_neighbors(query_embedding, corpus, top_k)
        ]

    return _provider


def graph_query_hybrid_provider(
    query_text: str,
    query_embedding: Optional[Sequence[float]],
    top_k: int,
    project_id: str,
) -> List[Dict[str, Any]]:
    """Default neighbor provider: delegate vector NN to the deployed graph index.

    Calls the graph_query_api hybrid search (which itself runs Titan V2 vector
    nearest-neighbor over the governed corpus). Returns ranked
    [{"record_id", "score"}] with scores min-max normalized to [0, 1]. Best
    effort: any failure (unset URL, network, HTTP error) returns [] so that
    session-init inference degrades gracefully and never raises.
    """
    if not GRAPH_QUERY_API_URL or not query_text:
        return []
    payload = {
        "search_type": "hybrid",
        "project_id": project_id,
        "query": query_text,
        "top_n": max(1, min(int(top_k or DEFAULT_TOP_K), MAX_TOP_K)),
    }
    try:
        req = urllib.request.Request(
            url=GRAPH_QUERY_API_URL,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=GRAPH_QUERY_API_TIMEOUT_S, context=_SSL_CTX) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
    except Exception as exc:  # noqa: BLE001 — best-effort inference, never raise
        logger.warning("intent_classifier: graph_query hybrid neighbor lookup failed: %s", exc)
        return []

    nodes = body.get("nodes")
    if not isinstance(nodes, list):
        result = body.get("result") if isinstance(body.get("result"), dict) else {}
        nodes = result.get("nodes") if isinstance(result, dict) else None
    if not isinstance(nodes, list):
        return []

    raw: List[Tuple[str, float]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        rid = str(node.get("record_id") or node.get("id") or "").strip()
        if not rid:
            continue
        score = node.get("_fused_score")
        if score is None:
            score = node.get("score")
        try:
            raw.append((rid, float(score)))
        except (TypeError, ValueError):
            raw.append((rid, 0.0))

    if not raw:
        return []
    scores = [s for _, s in raw]
    hi = max(scores)
    lo = min(scores)
    span = hi - lo
    out: List[Dict[str, Any]] = []
    for rid, s in raw[: max(1, min(int(top_k or DEFAULT_TOP_K), MAX_TOP_K))]:
        norm = 1.0 if span <= 0 else (s - lo) / span
        out.append({"record_id": rid, "score": norm})
    return out


# ---------------------------------------------------------------------------
# Override normalization
# ---------------------------------------------------------------------------

def normalize_override(override: Any) -> Optional[List[str]]:
    """Normalize an applied_entelechy_override into a list[str] of node_ids.

    Accepts a list of ids, a single id string, or a dict carrying a
    `node_ids` list. Returns None when no usable override is supplied (empty
    list/str/dict all normalize to None so the classifier prediction is used).
    """
    if override is None:
        return None
    if isinstance(override, str):
        rid = override.strip()
        return [rid] if rid else None
    if isinstance(override, dict):
        return normalize_override(override.get("node_ids"))
    if isinstance(override, (list, tuple)):
        ids = [str(x).strip() for x in override if str(x).strip()]
        return ids or None
    return None


# ---------------------------------------------------------------------------
# Classifier entry point
# ---------------------------------------------------------------------------

def classify_session_intent(
    first_turn_text: str,
    session_metadata: Optional[Dict[str, Any]] = None,
    *,
    applied_entelechy_override: Any = None,
    top_k: int = DEFAULT_TOP_K,
    project_id: str = "enceladus",
    embed_fn: Optional[Callable[[str], Optional[List[float]]]] = None,
    neighbor_provider: Optional[
        Callable[[str, Optional[Sequence[float]], int, str], List[Dict[str, Any]]]
    ] = None,
    record_boosts: Optional[Dict[str, float]] = None,
    load_trained_boosts: bool = True,
) -> Dict[str, Any]:
    """Predict session-init intent (𝔈) and resolve the applied entelechy.

    Returns a dict with:
      predicted_entelechy: {node_ids: [str], confidence: float}  (always the
        classifier's own prediction — logged even when overridden)
      applied_entelechy:   {node_ids: [str], confidence: float, source: str}
      override_applied:    bool
      neighbors, query_embedding_dim, model_id, inference_only, ...

    Pure-inference. `embed_fn` defaults to Titan V2; `neighbor_provider` defaults
    to the graph_query_api hybrid vector search. Both are injectable for tests.
    """
    text = (first_turn_text or "").strip()
    metadata = session_metadata if isinstance(session_metadata, dict) else {}
    try:
        top_k = int(top_k)
    except (TypeError, ValueError):
        top_k = DEFAULT_TOP_K
    top_k = max(1, min(top_k, MAX_TOP_K))

    embed = embed_fn or embed_query_text
    provider = neighbor_provider or graph_query_hybrid_provider

    query_embedding: Optional[List[float]] = None
    if text:
        try:
            query_embedding = embed(text)
        except Exception:  # noqa: BLE001 — inference must never raise upstream
            logger.exception("[ERROR] intent_classifier: embed_fn raised")
            query_embedding = None

    neighbors: List[Dict[str, Any]] = []
    if text:
        try:
            neighbors = provider(text, query_embedding, top_k, project_id) or []
        except Exception:  # noqa: BLE001
            logger.exception("[ERROR] intent_classifier: neighbor_provider raised")
            neighbors = []

    boosts = record_boosts
    if boosts is None and load_trained_boosts:
        try:
            import intent_training as _intent_training

            boosts = _intent_training.load_inference_record_boosts()
        except Exception:  # noqa: BLE001
            boosts = {}
    if boosts:
        try:
            import intent_training as _intent_training

            neighbors = _intent_training.apply_record_boosts_to_neighbors(neighbors, boosts)
        except Exception:  # noqa: BLE001
            pass

    node_ids: List[str] = []
    for n in neighbors:
        rid = str((n or {}).get("record_id") or "").strip()
        if rid and rid not in node_ids:
            node_ids.append(rid)

    confidence = 0.0
    if neighbors:
        try:
            confidence = float(neighbors[0].get("score") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

    predicted_entelechy = {"node_ids": node_ids, "confidence": round(confidence, 6)}

    override_ids = normalize_override(applied_entelechy_override)
    if override_ids is not None:
        # io override wins; classifier prediction is computed + logged, not applied.
        applied_entelechy = {
            "node_ids": override_ids,
            "confidence": 1.0,
            "source": "io_override",
        }
        override_applied = True
        logger.info(
            "[INFO] intent_classifier: applied_entelechy_override active "
            "(override=%s overrode predicted=%s)",
            override_ids,
            node_ids,
        )
    else:
        applied_entelechy = {
            "node_ids": list(node_ids),
            "confidence": predicted_entelechy["confidence"],
            "source": "classifier",
        }
        override_applied = False

    return {
        "predicted_entelechy": predicted_entelechy,
        "applied_entelechy": applied_entelechy,
        "override_applied": override_applied,
        "neighbors": neighbors,
        "query_embedding_dim": len(query_embedding) if query_embedding else 0,
        "model_id": TITAN_MODEL_ID,
        "project_id": project_id,
        "inference_only": INFERENCE_ONLY,
        "session_metadata_keys": sorted(metadata.keys()),
    }
