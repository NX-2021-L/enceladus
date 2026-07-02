"""Offline signal computation for the GHN-vs-RRF benchmark (ENC-TSK-I99).

Produces the same three-signal inputs the production hybrid path produces
(vector cosine, graph PPR, keyword), but computed OFFLINE against the synthetic
corpus so no Neo4j / Bedrock / GDS is required. Each stand-in is documented
against the production analogue it mimics:

  * vector  -> lambda_function._hybrid_vector_ranks (Neo4j HNSW cosine over
               Titan-v2 embeddings). STAND-IN: cosine similarity between
               deterministic hashed bag-of-tokens vectors. Non-negative vectors
               => cosine in [0, 1], matching the calibrated range
               energy_function.energy_component expects for E_vector.
  * graph   -> lambda_function._hybrid_graph_ranks_gds (Personalized PageRank,
               damping 0.85, from an anchor node). STAND-IN: power-iteration PPR
               with PPR_DAMPING_FACTOR from lambda_function, personalized on the
               anchor doc (top vector hit, mimicking anchor_record_id selection).
  * keyword -> lambda_function._hybrid_keyword_ranks (token-weighted CONTAINS).
               STAND-IN: shared-token overlap count, question vs doc.

The candidate set is the union of each signal's top-N (mimicking
HYBRID_SIGNAL_TOP_N), and the candidate-candidate coupling matrix W uses the
production per-edge-type weights (lambda_function.GRAPH_EDGE_WEIGHTS).
"""

from __future__ import annotations

import hashlib
import math
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Import the production module read-only for PPR damping + edge weights.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import lambda_function as lf  # noqa: E402

from .synthetic_multihop import Dataset, Question  # noqa: E402

_EMBED_DIM = 256  # matches the governed corpus's 256-float Titan-v2 blob


# ---------------------------------------------------------------------------
# Vector stand-in: deterministic hashed bag-of-tokens embedding + cosine
# ---------------------------------------------------------------------------

def _embed(tokens: Sequence[str]) -> List[float]:
    """Deterministic hashed term-frequency embedding (a documented stand-in for
    a real Titan-v2 sentence embedding). Each token is hashed to a dimension and
    contributes +1; the vector is L2-normalized. Non-negative by construction,
    so cosine(q, d) in [0, 1]."""
    vec = [0.0] * _EMBED_DIM
    for tok in tokens:
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        vec[h % _EMBED_DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    # Both already unit-normalized; clamp for float safety.
    return max(0.0, min(1.0, dot))


# ---------------------------------------------------------------------------
# Keyword stand-in: shared-token overlap
# ---------------------------------------------------------------------------

def _keyword_score(q_tokens: Sequence[str], doc_tokens: Sequence[str]) -> float:
    qs = set(q_tokens)
    if not qs:
        return 0.0
    doc_counts: Dict[str, int] = {}
    for t in doc_tokens:
        if t in qs:
            doc_counts[t] = doc_counts.get(t, 0) + 1
    # Sum of tf for query tokens present in the doc (mimics CONTAINS tf scoring).
    return float(sum(doc_counts.values()))


# ---------------------------------------------------------------------------
# Graph PPR stand-in: power-iteration personalized PageRank
# ---------------------------------------------------------------------------

def _build_adjacency(
    doc_ids: Sequence[str],
    edges: Sequence[Tuple[str, str, str]],
    weighted: bool = True,
) -> Dict[str, Dict[str, float]]:
    """Undirected weighted adjacency over the given doc_ids. Edge weight uses the
    production GRAPH_EDGE_WEIGHTS per edge-type (fallback default otherwise)."""
    idset = set(doc_ids)
    adj: Dict[str, Dict[str, float]] = {d: {} for d in doc_ids}
    for a, b, etype in edges:
        if a not in idset or b not in idset:
            continue
        w = 1.0
        if weighted:
            w = lf.GRAPH_EDGE_WEIGHTS.get(etype, lf.GRAPH_FALLBACK_DEFAULT_WEIGHT)
        adj[a][b] = adj[a].get(b, 0.0) + w
        adj[b][a] = adj[b].get(a, 0.0) + w
    return adj


def _personalized_pagerank(
    doc_ids: Sequence[str],
    adj: Dict[str, Dict[str, float]],
    anchor: str,
    damping: float,
    max_iter: int = 50,
    tol: float = 1e-9,
) -> Dict[str, float]:
    """Weighted personalized PageRank with restart to `anchor` (damping matches
    lambda_function.PPR_DAMPING_FACTOR). Returns {doc_id: score}."""
    n = len(doc_ids)
    if n == 0:
        return {}
    if anchor not in adj:
        anchor = doc_ids[0]
    rank = {d: (1.0 if d == anchor else 0.0) for d in doc_ids}
    teleport = {d: (1.0 if d == anchor else 0.0) for d in doc_ids}
    out_w = {d: sum(adj[d].values()) for d in doc_ids}
    for _ in range(max_iter):
        new = {d: (1.0 - damping) * teleport[d] for d in doc_ids}
        for d in doc_ids:
            if out_w[d] <= 0:
                # Dangling node: mass returns to teleport (anchor).
                new[anchor] += damping * rank[d]
                continue
            share = damping * rank[d] / out_w[d]
            for nbr, w in adj[d].items():
                new[nbr] += share * w
        delta = sum(abs(new[d] - rank[d]) for d in doc_ids)
        rank = new
        if delta < tol:
            break
    return rank


# ---------------------------------------------------------------------------
# Per-query signal assembly
# ---------------------------------------------------------------------------

class QuerySignals:
    """All per-query signal artifacts shared by RRF and GHN so the comparison is
    apples-to-apples (identical upstream signals; only the fusion differs)."""

    __slots__ = (
        "candidate_ids", "vector_by_rid", "keyword_by_rid", "graph_by_rid",
        "max_graph", "max_keyword", "adjacency",
    )

    def __init__(self, candidate_ids, vector_by_rid, keyword_by_rid,
                 graph_by_rid, max_graph, max_keyword, adjacency):
        self.candidate_ids = candidate_ids
        self.vector_by_rid = vector_by_rid
        self.keyword_by_rid = keyword_by_rid
        self.graph_by_rid = graph_by_rid
        self.max_graph = max_graph
        self.max_keyword = max_keyword
        self.adjacency = adjacency


def compute_query_signals(
    ds: Dataset,
    question: Question,
    *,
    top_n: int = 25,
    damping: Optional[float] = None,
) -> QuerySignals:
    """Compute vector/keyword/graph signals for one question over the corpus and
    assemble the fused candidate set + coupling adjacency.

    top_n mirrors lambda_function.HYBRID_SIGNAL_TOP_N (per-signal depth). damping
    defaults to lambda_function.PPR_DAMPING_FACTOR.
    """
    if damping is None:
        damping = lf.PPR_DAMPING_FACTOR

    q_emb = _embed(question.text_tokens)
    doc_ids = list(ds.documents.keys())

    # Vector + keyword over the whole corpus.
    vec_scores: Dict[str, float] = {}
    kw_scores: Dict[str, float] = {}
    for did, doc in ds.documents.items():
        vec_scores[did] = _cosine(q_emb, _embed(doc.tokens))
        kw_scores[did] = _keyword_score(question.text_tokens, doc.tokens)

    vec_top = sorted(vec_scores.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    kw_top = sorted(kw_scores.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    # Graph anchor = top vector hit (mimics how a live query supplies
    # anchor_record_id: the best direct match seeds the graph walk).
    anchor = vec_top[0][0] if vec_top else doc_ids[0]
    full_adj = _build_adjacency(doc_ids, ds.edges, weighted=True)
    ppr = _personalized_pagerank(doc_ids, full_adj, anchor, damping)
    graph_top = sorted(ppr.items(), key=lambda kv: kv[1], reverse=True)[:top_n]

    # Candidate set = union of the three top-N lists (production behavior:
    # a record enters RRF if any signal surfaced it).
    candidate_ids: List[str] = []
    seen = set()
    for rid, _ in vec_top + graph_top + kw_top:
        if rid not in seen:
            seen.add(rid)
            candidate_ids.append(rid)

    vector_by_rid = {rid: vec_scores[rid] for rid in candidate_ids}
    keyword_by_rid = {rid: kw_scores[rid] for rid in candidate_ids}
    graph_by_rid = {rid: ppr[rid] for rid in candidate_ids}
    max_graph = max((v for _, v in graph_top), default=0.0)
    max_keyword = max((v for _, v in kw_top), default=0.0)

    # Candidate-candidate coupling adjacency (subgraph over the candidate set).
    adjacency = _build_adjacency(candidate_ids, ds.edges, weighted=True)

    return QuerySignals(
        candidate_ids=candidate_ids,
        vector_by_rid=vector_by_rid,
        keyword_by_rid=keyword_by_rid,
        graph_by_rid=graph_by_rid,
        max_graph=max_graph,
        max_keyword=max_keyword,
        adjacency=adjacency,
    )


def rrf_signal_dict(sig: QuerySignals) -> Dict[str, List[Dict[str, object]]]:
    """Shape the three signals as lambda_function._rrf_fuse expects: a dict of
    signal_name -> [{record_id, score, rank}] with per-signal ranks."""
    def _ranked(score_map: Dict[str, float]) -> List[Dict[str, object]]:
        ordered = sorted(score_map.items(), key=lambda kv: kv[1], reverse=True)
        return [
            {"record_id": rid, "score": s, "rank": i}
            for i, (rid, s) in enumerate(ordered, start=1)
            if s > 0.0  # a zero-score candidate did not truly rank in that signal
        ]
    return {
        "vector": _ranked(sig.vector_by_rid),
        "graph": _ranked(sig.graph_by_rid),
        "keyword": _ranked(sig.keyword_by_rid),
    }


def coupling_matrix(sig: QuerySignals) -> List[List[float]]:
    """Dense symmetric NxN candidate-candidate weighted adjacency (zero diagonal)
    for the GHN coupling term, ordered to match sig.candidate_ids."""
    ids = sig.candidate_ids
    idx = {rid: i for i, rid in enumerate(ids)}
    n = len(ids)
    w = [[0.0] * n for _ in range(n)]
    for a in ids:
        for b, weight in sig.adjacency[a].items():
            if b in idx and a != b:
                w[idx[a]][idx[b]] = weight
    return w
