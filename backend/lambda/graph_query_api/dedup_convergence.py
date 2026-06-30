"""ENC-TSK-I10 (Dedup P6) — Telemetry & convergence probe shared module.

Pure, dependency-light convergence math for the duplicate-dedup track
(DOC-DF651F07D5C2 §10). Owned by graph_query_api; copied into
graph_health_metrics via ``.build_extras`` so the daily scheduled probe and the
on-demand graphsearch read action compute byte-identical signals (the same
cross-Lambda sharing precedent as graph_sync/embedding.py).

The five governed signals (DOC-DF651F07D5C2 §10):

1. **Stock** — same-type, same-project duplicate-pair count (cosine ≥ τ),
   trending to floor as the backlog drains.
2. **Precision@1 recovery** — vs the 0.3727 baseline toward the ~0.8242 recall
   ceiling. The labeled self-retrieval eval (DOC-4F1F5B99AAED) is not
   reproducible inside a scheduled Lambda, so the probe emits the static
   baseline + ceiling references and a live **recovery proxy**: the fraction of
   embedded same-type records that have NO surviving near-duplicate twin
   (cosine ≥ τ) among non-superseded peers. As twins are superseded the proxy
   climbs toward 1.0, tracking the same quantity the eval measures (one item no
   longer loses its #1 slot to its own twin, §3).
3. **Flow** — new same-type duplicate pairs per window (a pair counts as new
   when its more-recent endpoint was created within the window). Backlog
   cleanup alone is Sisyphean against live inflow.
4. **Percolation** — largest-connected-component (LCC) size of the same-type
   duplicate graph, plus the non-trivial component count. Isolated records are
   size-1 components, so a fully converged corpus (no surviving duplicate edge)
   has LCC → 1: one node per concept, driven below the giant-component
   percolation threshold.
5. **Walk-back rate** — the production auto-merge walk-back rate; the live
   certificate-precision estimate. The certificate is miscalibrated and the
   model-health loop must re-enter shadow when the rate breaches (1 − floor).

All functions are pure (stdlib only). Cypher orchestration takes a neo4j
``driver`` exposing ``.session()`` as a context manager; sessions expose
``.run(cypher, **params)`` yielding mapping rows. This keeps the heavy math unit
testable without a live AuraDB.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

# --- Convergence constants (DOC-DF651F07D5C2 §2/§10) -----------------------

#: Self-retrieval precision@1 measured on the gamma near-duplicate eval before
#: any dedup (DOC-4F1F5B99AAED). The signal the whole track exists to recover.
PRECISION_AT_1_BASELINE = 0.3727

#: recall@10 ceiling on the same eval — the true item is in the top-10 ~82% of
#: the time, so this is the practical ceiling precision@1 can recover toward.
RECALL_CEILING = 0.8242

#: Recall instrument for duplicate detection (§9 step 1): cosine ≥ this is a
#: candidate near-duplicate. Confirmed identity is the certainty model's job.
DEFAULT_COSINE_THRESHOLD = 0.95

#: Certificate precision floor (§4.3). Walk-back rate breaching (1 − floor)
#: means the certificate is miscalibrated → re-enter shadow (§10 model-health).
DEFAULT_PRECISION_FLOOR = 0.999

#: Flow accounting window — "new duplicate pairs per week" (§10 flow).
DEFAULT_FLOW_WINDOW_DAYS = 7

#: Walk-back rate accounting window for the model-health loop.
DEFAULT_WALKBACK_WINDOW_DAYS = 30

#: Per-node KNN fan-out when extracting near-duplicate pairs from the vector
#: index. A dense duplicate cluster (mean degree ≈ 15, §2) needs k > degree.
DEFAULT_VECTOR_TOP_K = 25

#: Per-label HNSW vector indexes (ENC-TSK-B90). Mirrors graph_query_api's
#: LABEL_VECTOR_INDEXES; passed in by callers but defaulted here so the probe
#: and the read action cannot drift.
DEFAULT_LABEL_VECTOR_INDEXES: Dict[str, str] = {
    "Task": "governed_task_embedding",
    "Issue": "governed_issue_embedding",
    "Feature": "governed_feature_embedding",
    "Plan": "governed_plan_embedding",
    "Lesson": "governed_lesson_embedding",
    "Document": "governed_document_embedding",
}


# --- Pure helpers ----------------------------------------------------------

def normalize_pair(a: str, b: str) -> Tuple[str, str]:
    """Orientation-stable pair key (uppercased, lexicographically ordered).

    Matches the I05/I06/I09 ``_dedup_pair_key`` convention so a directed KNN
    hit (a→b) and its mirror (b→a) collapse to one undirected duplicate edge.
    """
    a2, b2 = str(a).strip().upper(), str(b).strip().upper()
    return (a2, b2) if a2 <= b2 else (b2, a2)


def connected_components(
    nodes: Iterable[str], pairs: Iterable[Tuple[str, str]]
) -> List[Set[str]]:
    """Union-find connected components over the duplicate graph.

    ``nodes`` is the full participating corpus (so isolated records surface as
    size-1 components — required for the percolation → 1 reading); ``pairs`` are
    the undirected duplicate edges. Order-free and idempotent (§9 step 2).
    """
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        # Path compression.
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for n in nodes:
        find(str(n).strip().upper())
    for a, b in pairs:
        ua, ub = str(a).strip().upper(), str(b).strip().upper()
        find(ua)
        find(ub)
        union(ua, ub)

    groups: Dict[str, Set[str]] = {}
    for node in list(parent.keys()):
        groups.setdefault(find(node), set()).add(node)
    return list(groups.values())


def largest_component_size(components: Sequence[Set[str]]) -> int:
    """LCC size. 0 for an empty corpus; 1 once fully converged (no edges)."""
    return max((len(c) for c in components), default=0)


def count_nontrivial_components(components: Sequence[Set[str]]) -> int:
    """Count clusters of size ≥ 2 — the duplicate clusters still to collapse."""
    return sum(1 for c in components if len(c) >= 2)


def precision_recovery_proxy(records_without_twin: int, total_records: int) -> float:
    """Live precision@1 recovery proxy: fraction of records with no surviving
    same-type near-duplicate twin. 1.0 for an empty/converged corpus."""
    if total_records <= 0:
        return 1.0
    return max(0.0, min(1.0, records_without_twin / total_records))


def recovery_fraction(
    value: float, baseline: float = PRECISION_AT_1_BASELINE, ceiling: float = RECALL_CEILING
) -> float:
    """Normalized progress of ``value`` from ``baseline`` (0.0) to ``ceiling``
    (1.0). Convenient for graphing recovery; clamped to [0, 1]."""
    span = ceiling - baseline
    if span <= 0:
        return 0.0
    return max(0.0, min(1.0, (value - baseline) / span))


def walk_back_rate(auto_merges: int, walk_backs: int) -> float:
    """Production auto-merge walk-back rate = walk_backs / auto_merges.

    0.0 when no auto-merges have been observed (the certificate has produced no
    outcomes yet — the system is in shadow by construction)."""
    if auto_merges <= 0:
        return 0.0
    return max(0.0, min(1.0, walk_backs / auto_merges))


def breaches_floor(rate: float, precision_floor: float = DEFAULT_PRECISION_FLOOR) -> bool:
    """Model-health predicate (§10): the certificate is miscalibrated when the
    walk-back rate exceeds (1 − floor). True ⇒ tighten thresholds / re-enter
    shadow."""
    return rate > (1.0 - precision_floor)


def walk_back_health(
    auto_merges: int, walk_backs: int, precision_floor: float = DEFAULT_PRECISION_FLOOR
) -> Dict[str, Any]:
    """Assemble the walk-back model-health loop snapshot (§10).

    ``recommended_mode`` is 'shadow' when the loop has breached the floor (or
    when there is no evidence yet, the safe default), else 'live'.
    """
    rate = walk_back_rate(auto_merges, walk_backs)
    breach = breaches_floor(rate, precision_floor)
    has_evidence = auto_merges > 0
    return {
        "auto_merge_count": int(auto_merges),
        "walk_back_count": int(walk_backs),
        "walk_back_rate": rate,
        "precision_floor": precision_floor,
        "breach_threshold": 1.0 - precision_floor,
        "breached_floor": breach,
        "recommended_mode": "live" if (has_evidence and not breach) else "shadow",
        "has_evidence": has_evidence,
    }


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (tolerating a trailing 'Z') to aware UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def count_new_pairs(
    pair_newest_ts: Iterable[Any], now: datetime, window_days: float
) -> int:
    """Flow: count duplicate pairs whose newest endpoint was created within the
    trailing ``window_days`` of ``now`` (§10 flow). Unparseable timestamps are
    treated as outside the window (conservative — never inflates inflow)."""
    if window_days <= 0:
        return 0
    cutoff_seconds = window_days * 86400.0
    count = 0
    for ts in pair_newest_ts:
        dt = _parse_ts(ts)
        if dt is None:
            continue
        age = (now - dt).total_seconds()
        if 0 <= age <= cutoff_seconds:
            count += 1
    return count


# --- Neo4j orchestration (driver-bound; thin) ------------------------------

# All embedded, non-superseded records of one label in a project. Defines the
# percolation node set (so isolated records are size-1 components).
_NODES_CYPHER = (
    "MATCH (n:`{label}`) "
    "WHERE n.project_id = $project_id "
    "AND n.superseded_by IS NULL "
    "AND n.embedding IS NOT NULL "
    "RETURN n.record_id AS rid"
)

# Per-node KNN over the label's HNSW index → near-duplicate directed hits.
# Excludes self, cross-project, and superseded twins (mirrors the I07 retrieval
# exclusion at graph_query_api lambda_function.py). One CALL per source row.
_PAIRS_CYPHER = (
    "MATCH (n:`{label}`) "
    "WHERE n.project_id = $project_id "
    "AND n.superseded_by IS NULL "
    "AND n.embedding IS NOT NULL "
    "CALL db.index.vector.queryNodes($index_name, $k, n.embedding) "
    "YIELD node AS m, score "
    "WHERE m.record_id <> n.record_id "
    "AND m.project_id = $project_id "
    "AND m.superseded_by IS NULL "
    "AND score >= $threshold "
    "RETURN n.record_id AS a, m.record_id AS b, score AS score, "
    "n.created_at AS a_ts, m.created_at AS b_ts"
)


def _newest_ts(a_ts: Any, b_ts: Any) -> Any:
    """Return the more-recent of two timestamps (for flow accounting)."""
    da, db = _parse_ts(a_ts), _parse_ts(b_ts)
    if da is None:
        return b_ts
    if db is None:
        return a_ts
    return a_ts if da >= db else b_ts


def compute_graph_signals(
    driver: Any,
    project_id: str,
    *,
    cosine_threshold: float = DEFAULT_COSINE_THRESHOLD,
    flow_window_days: float = DEFAULT_FLOW_WINDOW_DAYS,
    now: Optional[datetime] = None,
    label_vector_indexes: Optional[Mapping[str, str]] = None,
    vector_top_k: int = DEFAULT_VECTOR_TOP_K,
) -> Dict[str, Any]:
    """Compute the four graph-derived convergence signals (stock / precision@1
    recovery proxy / flow / percolation) over the live Neo4j projection.

    Pure of any AWS dependency; the walk-back model-health loop is layered on by
    the scheduled probe via :func:`walk_back_health`.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    indexes = dict(label_vector_indexes or DEFAULT_LABEL_VECTOR_INDEXES)

    all_nodes: Set[str] = set()
    nodes_by_type: Dict[str, int] = {}
    pair_score: Dict[Tuple[str, str], float] = {}
    pair_newest: Dict[Tuple[str, str], Any] = {}
    pair_label: Dict[Tuple[str, str], str] = {}

    for label, index_name in indexes.items():
        # Node set for this label.
        node_cypher = _NODES_CYPHER.format(label=label)
        label_nodes: Set[str] = set()
        with driver.session() as session:
            for row in session.run(node_cypher, project_id=project_id):
                rid = row.get("rid") if hasattr(row, "get") else row["rid"]
                if rid:
                    rid_u = str(rid).strip().upper()
                    label_nodes.add(rid_u)
                    all_nodes.add(rid_u)
        nodes_by_type[label] = len(label_nodes)
        if not label_nodes:
            continue

        # Near-duplicate pairs for this label.
        pair_cypher = _PAIRS_CYPHER.format(label=label)
        with driver.session() as session:
            rows = session.run(
                pair_cypher,
                project_id=project_id,
                index_name=index_name,
                k=int(vector_top_k),
                threshold=float(cosine_threshold),
            )
            for row in rows:
                get = row.get if hasattr(row, "get") else row.__getitem__
                a, b = get("a"), get("b")
                if not a or not b:
                    continue
                key = normalize_pair(a, b)
                score = float(get("score") or 0.0)
                if key not in pair_score or score > pair_score[key]:
                    pair_score[key] = score
                    pair_newest[key] = _newest_ts(get("a_ts"), get("b_ts"))
                    pair_label[key] = label

    pairs = list(pair_score.keys())
    duplicate_nodes: Set[str] = set()
    for a, b in pairs:
        duplicate_nodes.add(a)
        duplicate_nodes.add(b)

    components = connected_components(all_nodes, pairs)
    total_records = len(all_nodes)
    records_without_twin = total_records - len(duplicate_nodes)
    proxy = precision_recovery_proxy(records_without_twin, total_records)

    stock_by_type: Dict[str, int] = {}
    for key, label in pair_label.items():
        stock_by_type[label] = stock_by_type.get(label, 0) + 1

    return {
        "project_id": project_id,
        "cosine_threshold": float(cosine_threshold),
        "embedded_record_count": total_records,
        "embedded_record_count_by_type": nodes_by_type,
        "stock_pairs": len(pairs),
        "stock_pairs_by_type": stock_by_type,
        "duplicate_node_count": len(duplicate_nodes),
        "records_without_twin": records_without_twin,
        "flow_window_days": float(flow_window_days),
        "new_duplicate_pairs": count_new_pairs(
            pair_newest.values(), now, flow_window_days
        ),
        "lcc_size": largest_component_size(components),
        "nontrivial_component_count": count_nontrivial_components(components),
        "precision_at_1_baseline": PRECISION_AT_1_BASELINE,
        "recall_ceiling": RECALL_CEILING,
        "precision_at_1_recovery_proxy": proxy,
        "precision_at_1_recovery_fraction": recovery_fraction(
            # Map the proxy (a fraction in [0,1]) onto the eval scale so the
            # recovery is comparable to the baseline→ceiling band: at full
            # convergence (proxy=1) the live precision should approach ceiling.
            PRECISION_AT_1_BASELINE + proxy * (RECALL_CEILING - PRECISION_AT_1_BASELINE)
        ),
        "computed_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
