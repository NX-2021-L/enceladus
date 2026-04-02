"""Context Node scoring engine for mathematically-optimized context assembly.

ENC-FTR-050: Governed Context Node Primitive.
All functions in this module are gated behind ENABLE_CONTEXT_NODES feature flag.
When flag is False, none of this code is invoked.

Implements:
- AC3: Multi-signal scoring with configurable weights and exponential freshness decay
- AC4: Greedy knapsack packer with value/cost ratio sorting and grouped knapsack
- AC5: PPR integration stub using typed edge weights (requires Neo4j graph index)
- AC8: RRF combining keyword match and semantic similarity
"""
import math
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

# --- Scoring weights (governance-configurable via coordination_api config) ---

DEFAULT_WEIGHTS = {
    "w1_relevance": 0.35,
    "w2_freshness": 0.25,
    "w3_importance": 0.25,
    "w4_cost_penalty": 0.15,
}

# --- Staleness half-lives in seconds (type-specific defaults per OWL ontology) ---

HALF_LIFE_SECONDS = {
    "task": 604800,       # 7 days
    "issue": 259200,      # 3 days
    "feature": 2592000,   # 30 days
    "document": 7776000,  # 90 days
}

# --- PPR edge weight defaults (from OWL ontology) ---

PPR_EDGE_WEIGHTS = {
    "BLOCKS": 1.0,
    "BLOCKED_BY": 1.0,
    "DEPENDS_ON": 0.8,
    "DEPENDED_ON_BY": 0.8,
    "IMPLEMENTS": 0.7,
    "ADDRESSES": 0.7,
    "CHILD_OF": 0.6,
    "PARENT_OF": 0.6,
    "RELATES_TO": 0.3,
    "RELATED_TO": 0.3,
    "BELONGS_TO": 0.1,
}

# --- RRF constant ---

RRF_K = 60


# ============================================================================
# AC3: Multi-signal scoring function
# ============================================================================

def compute_freshness(updated_at_iso: str, record_type: str,
                      half_life_override: Optional[int] = None,
                      now: Optional[float] = None) -> float:
    """Exponential freshness decay: freshness = exp(-ln(2) * age / half_life).

    Args:
        updated_at_iso: ISO 8601 timestamp of last update.
        record_type: One of 'task', 'issue', 'feature', 'document'.
        half_life_override: Optional override for half-life in seconds.
        now: Optional current time as Unix timestamp (for testing).

    Returns:
        Freshness score in [0.0, 1.0]. 1.0 = just updated, 0.0 = very stale.
    """
    if now is None:
        now = time.time()

    try:
        from datetime import datetime, timezone
        if updated_at_iso.endswith("Z"):
            updated_at_iso = updated_at_iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(updated_at_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        updated_epoch = dt.timestamp()
    except (ValueError, TypeError):
        return 0.5  # neutral fallback

    age_seconds = max(0, now - updated_epoch)
    half_life = half_life_override or HALF_LIFE_SECONDS.get(record_type, 604800)

    return math.exp(-math.log(2) * age_seconds / half_life)


def compute_score(relevance: float, freshness: float, importance: float,
                  token_cost: int, max_token_cost: int,
                  weights: Optional[Dict[str, float]] = None) -> float:
    """Multi-signal composite score for context node ranking.

    final_score = w1*relevance + w2*freshness + w3*importance - w4*cost_penalty
    where cost_penalty = token_cost / max_token_cost (normalized)

    Args:
        relevance: Query-dependent relevance [0.0, 1.0] (from RRF).
        freshness: Temporal freshness [0.0, 1.0] (from compute_freshness).
        importance: Structural importance [0.0, 1.0] (from PPR).
        token_cost: Token count for this node.
        max_token_cost: Maximum token cost across all candidate nodes.
        weights: Optional weight overrides (governance-configurable).

    Returns:
        Composite score (can be negative if cost_penalty dominates).
    """
    w = weights or DEFAULT_WEIGHTS
    cost_penalty = token_cost / max(max_token_cost, 1)

    return (
        w.get("w1_relevance", 0.35) * relevance
        + w.get("w2_freshness", 0.25) * freshness
        + w.get("w3_importance", 0.25) * importance
        - w.get("w4_cost_penalty", 0.15) * cost_penalty
    )


# ============================================================================
# AC4: Greedy knapsack packer
# ============================================================================

class ContextNodeItem:
    """A candidate item for the knapsack packer."""

    __slots__ = ("node_id", "token_cost", "score", "value_density",
                 "group_id", "data")

    def __init__(self, node_id: str, token_cost: int, score: float,
                 group_id: Optional[str] = None, data: Optional[Dict] = None):
        self.node_id = node_id
        self.token_cost = max(token_cost, 1)
        self.score = score
        self.value_density = score / self.token_cost
        self.group_id = group_id
        self.data = data or {}


def greedy_knapsack(items: Sequence[ContextNodeItem],
                    budget: int) -> Tuple[List[ContextNodeItem],
                                          List[ContextNodeItem],
                                          Dict[str, Any]]:
    """Greedy knapsack packer sorting by value/token_cost ratio.

    Supports grouped knapsack: items sharing a group_id are packed
    atomically (all or nothing). Groups are scored by average density.

    Args:
        items: Candidate context node items with scores and costs.
        budget: Token budget W = context_limit - prompt - reserved_response.

    Returns:
        Tuple of (included, excluded, manifest) where manifest contains
        packing statistics.
    """
    if not items:
        return [], [], {"tokens_used": 0, "tokens_budget": budget,
                        "packing_efficiency": 0.0, "items_included": 0,
                        "items_excluded": 0}

    # Group items by group_id (None = each item is its own singleton group)
    groups: Dict[str, List[ContextNodeItem]] = {}
    _singleton_counter = 0
    for item in items:
        if item.group_id is not None:
            groups.setdefault(item.group_id, []).append(item)
        else:
            groups[f"_singleton_{_singleton_counter}"] = [item]
            _singleton_counter += 1

    # Score each group by average value density, total cost
    group_entries = []
    for gid, members in groups.items():
        total_cost = sum(m.token_cost for m in members)
        avg_density = sum(m.value_density for m in members) / len(members)
        group_entries.append((avg_density, total_cost, gid, members))

    # Sort by density descending
    group_entries.sort(key=lambda x: x[0], reverse=True)

    included: List[ContextNodeItem] = []
    excluded: List[ContextNodeItem] = []
    tokens_used = 0

    for avg_density, total_cost, gid, members in group_entries:
        if tokens_used + total_cost <= budget:
            included.extend(members)
            tokens_used += total_cost
        else:
            excluded.extend(members)

    efficiency = tokens_used / max(budget, 1)

    manifest = {
        "tokens_used": tokens_used,
        "tokens_budget": budget,
        "packing_efficiency": round(efficiency, 4),
        "items_included": len(included),
        "items_excluded": len(excluded),
    }

    return included, excluded, manifest


# ============================================================================
# AC5: PPR integration stub (requires Neo4j graph index)
# ============================================================================

def compute_ppr_importance(seed_record_id: str,
                           candidate_record_ids: List[str],
                           graph_healthy: bool = False,
                           edge_weights: Optional[Dict[str, float]] = None
                           ) -> Dict[str, float]:
    """Compute structural importance via Personalized PageRank.

    When graph index is unavailable, returns neutral 0.5 for all candidates.
    When available, queries Neo4j for PPR scores seeded from the current
    task/issue with typed edge weights.

    Args:
        seed_record_id: The current task/issue to seed PPR from.
        candidate_record_ids: Record IDs to score.
        graph_healthy: Whether the Neo4j graph index is available.
        edge_weights: Optional edge type weight overrides.

    Returns:
        Dict mapping record_id -> importance score [0.0, 1.0].
    """
    weights = edge_weights or PPR_EDGE_WEIGHTS

    if not graph_healthy:
        # Fallback: neutral importance when graph unavailable
        return {rid: 0.5 for rid in candidate_record_ids}

    # TODO: Implement actual Neo4j PPR query when graph is healthy.
    # For now, return neutral scores. Full implementation requires:
    # 1. Neo4j APOC `algo.pageRank.stream` or custom Cypher PPR
    # 2. Typed edge weight matrix passed as relationship weights
    # 3. Seed node = seed_record_id with restart probability = 0.85
    # 4. Normalize scores to [0, 1] range
    return {rid: 0.5 for rid in candidate_record_ids}


# ============================================================================
# AC8: Reciprocal Rank Fusion (RRF)
# ============================================================================

def compute_rrf(keyword_rankings: Dict[str, int],
                similarity_rankings: Optional[Dict[str, int]] = None,
                k: int = RRF_K) -> Dict[str, float]:
    """Reciprocal Rank Fusion combining keyword match and semantic similarity.

    RRF_score(d) = sum(1 / (k + rank_r(d))) for each ranking r

    Args:
        keyword_rankings: Dict mapping record_id -> rank (1-based).
        similarity_rankings: Optional dict mapping record_id -> rank.
            If None, only keyword rankings are used.
        k: RRF constant (default 60, standard value from literature).

    Returns:
        Dict mapping record_id -> RRF score (higher is better).
    """
    scores: Dict[str, float] = {}

    all_ids = set(keyword_rankings.keys())
    if similarity_rankings:
        all_ids |= set(similarity_rankings.keys())

    max_rank = len(all_ids) + 1  # default rank for missing entries

    for rid in all_ids:
        kw_rank = keyword_rankings.get(rid, max_rank)
        score = 1.0 / (k + kw_rank)

        if similarity_rankings is not None:
            sim_rank = similarity_rankings.get(rid, max_rank)
            score += 1.0 / (k + sim_rank)

        scores[rid] = score

    # Normalize to [0, 1]
    if scores:
        max_score = max(scores.values())
        if max_score > 0:
            scores = {rid: s / max_score for rid, s in scores.items()}

    return scores


# ============================================================================
# Convenience: full scoring pipeline
# ============================================================================

def score_candidates(candidates: List[Dict[str, Any]],
                     query: str,
                     seed_record_id: str,
                     budget: int,
                     graph_healthy: bool = False,
                     weights: Optional[Dict[str, float]] = None,
                     now: Optional[float] = None
                     ) -> Tuple[List[Dict], List[Dict], Dict[str, Any]]:
    """Full scoring pipeline: RRF -> freshness -> PPR -> score -> knapsack.

    Args:
        candidates: List of dicts with keys: record_id, title, token_cost,
            record_type, updated_at, and optionally other fields.
        query: Search query for keyword relevance ranking.
        seed_record_id: Current task/issue for PPR seeding.
        budget: Token budget for context assembly.
        graph_healthy: Whether Neo4j graph index is available.
        weights: Optional scoring weight overrides.
        now: Optional current time for freshness computation.

    Returns:
        Tuple of (included_items, excluded_items, assembly_manifest).
    """
    if not candidates:
        return [], [], {"tokens_used": 0, "tokens_budget": budget,
                        "packing_efficiency": 0.0, "items_included": 0,
                        "items_excluded": 0}

    # Step 1: Keyword relevance ranking (simple title match)
    query_lower = query.lower()
    keyword_scored = []
    for c in candidates:
        title = (c.get("title") or "").lower()
        rid = c.get("record_id", "")
        # Simple scoring: exact match > contains > partial
        if query_lower in title:
            keyword_scored.append((rid, len(query_lower) / max(len(title), 1)))
        elif any(w in title for w in query_lower.split()):
            keyword_scored.append((rid, 0.3))
        else:
            keyword_scored.append((rid, 0.1))

    keyword_scored.sort(key=lambda x: x[1], reverse=True)
    keyword_rankings = {rid: rank + 1 for rank, (rid, _) in enumerate(keyword_scored)}

    # Step 2: RRF (keyword only for now; semantic similarity TBD)
    rrf_scores = compute_rrf(keyword_rankings)

    # Step 3: PPR importance
    candidate_ids = [c.get("record_id", "") for c in candidates]
    ppr_scores = compute_ppr_importance(seed_record_id, candidate_ids, graph_healthy)

    # Step 4: Freshness
    freshness_scores = {}
    for c in candidates:
        rid = c.get("record_id", "")
        freshness_scores[rid] = compute_freshness(
            c.get("updated_at", ""), c.get("record_type", "task"), now=now
        )

    # Step 5: Compute composite scores
    max_token_cost = max((c.get("token_cost", 100) for c in candidates), default=100)

    items = []
    for c in candidates:
        rid = c.get("record_id", "")
        token_cost = c.get("token_cost", 100)
        score = compute_score(
            relevance=rrf_scores.get(rid, 0.0),
            freshness=freshness_scores.get(rid, 0.5),
            importance=ppr_scores.get(rid, 0.5),
            token_cost=token_cost,
            max_token_cost=max_token_cost,
            weights=weights,
        )
        items.append(ContextNodeItem(
            node_id=f"CN-{rid}",
            token_cost=token_cost,
            score=score,
            group_id=c.get("group_id"),
            data=c,
        ))

    # Step 6: Greedy knapsack
    included, excluded, manifest = greedy_knapsack(items, budget)

    included_data = [{"node_id": i.node_id, "score": round(i.score, 4),
                      "token_cost": i.token_cost, "value_density": round(i.value_density, 6),
                      **i.data} for i in included]
    excluded_data = [{"node_id": i.node_id, "score": round(i.score, 4),
                      "token_cost": i.token_cost, **i.data} for i in excluded]

    return included_data, excluded_data, manifest
