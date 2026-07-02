"""ENC-FTR-108 Ph3 (ENC-TSK-J03) — Shannon entropy over flow_weight distribution.

Computed nightly from live Neo4j relationship properties; a decreasing trend
indicates convergence toward usage geometry (FTR-108 AC-5).
"""
from __future__ import annotations

import math
from typing import Iterable, List, Sequence


def shannon_entropy(weights: Sequence[float], *, bins: int = 0) -> float:
    """Normalized Shannon entropy H in [0, 1] over non-negative weights.

    When *bins* > 0, weights are histogram-binned first (stabilizes entropy
  against near-duplicate floats). With bins=0 (default), treats each weight as
    its own category after rounding to 6 decimal places.
    """
    if not weights:
        return 0.0
    vals = [max(0.0, float(w)) for w in weights]
    total = sum(vals)
    if total <= 0:
        return 0.0

    if bins and bins > 1:
        lo, hi = min(vals), max(vals)
        if hi <= lo:
            return 0.0
        width = (hi - lo) / bins
        counts = [0] * bins
        for v in vals:
            idx = min(bins - 1, int((v - lo) / width))
            counts[idx] += 1
        probs = [c / len(vals) for c in counts if c > 0]
    else:
        rounded = [round(v, 6) for v in vals]
        freq: dict[float, int] = {}
        for v in rounded:
            freq[v] = freq.get(v, 0) + 1
        n = len(rounded)
        probs = [c / n for c in freq.values()]

    h = -sum(p * math.log(p) for p in probs if p > 0)
    k = len(probs)
    if k <= 1:
        return 0.0
    return h / math.log(k)


def fetch_flow_weights_cypher() -> str:
    """Cypher fragment returning one row per relationship flow_weight."""
    return (
        "MATCH (a)-[r]-(b) "
        "WHERE a.project_id = $project_id AND b.project_id = $project_id "
        "AND NOT 'Project' IN labels(a) AND NOT 'Project' IN labels(b) "
        "AND coalesce(a.is_placeholder, false) = false "
        "AND coalesce(b.is_placeholder, false) = false "
        "AND a.record_id IS NOT NULL AND b.record_id IS NOT NULL "
        "RETURN coalesce(r.flow_weight, 1.0) AS fw"
    )


def compute_from_session(session, project_id: str) -> dict:
    """Query Neo4j and return {entropy, edge_count, sample_size}."""
    rows = session.run(fetch_flow_weights_cypher(), project_id=project_id)
    weights: List[float] = [float(r["fw"]) for r in rows]
    return {
        "flow_weight_entropy": shannon_entropy(weights),
        "flow_weight_edge_count": len(weights),
    }
