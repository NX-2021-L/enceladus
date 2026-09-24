#!/usr/bin/env python3
"""ENC-TSK-I05 — Duplicate-cluster detection over the Enceladus ``n.embedding``
corpus.

Phase 2 of the PLN-052 dedup track. After on-retrieval correlation *encoding*
(ENC-TSK-H92 query-side, ENC-TSK-I03 symmetric re-rank) failed to clear the +5%
recall bar, the residual near-duplicate mass measured by ENC-TSK-H91 (2281
issue/issue + 209 task/task pairs at mean cosine 0.9998) is better addressed by
*deduplication* than by further encoding. This script turns that pairwise signal
into actionable duplicate **clusters** with a single **canonical suggestion**
per cluster.

It is a strictly **mutation-free** analysis tool: it reads the governed corpus,
computes, and writes local (+ optional S3) result artifacts. It performs NO
tracker writes and proposes nothing to the governed store — a human or a later
governed task decides what to do with the suggestions.

Pipeline (READ -> GRAPH -> COMPONENTS -> CANONICAL -> SINK):

  READ      The embedding corpus is read via the ENC-TSK-H89 / ENC-FTR-082 AC-12
            ``vector_read`` contract, reusing the ENC-TSK-H91 loaders verbatim
            (``correlation_analysis_h91.load_corpus``) so there is a single
            governed read path. Each node is
            ``{"record_id", "record_type", "embedding": [float, ...]}``; this
            script additionally stamps ``project_id`` from the read scope so the
            graph builder can enforce the same-project edge rule. As an
            efficiency alternative, ``--source pairs`` ingests an H91
            ``pairs.jsonl`` directly as the edge set (no corpus re-read / no
            cosine recompute).

  GRAPH     ``similarity_edges(nodes, threshold)`` groups nodes by
            ``(project_id, record_type)`` and, within each group only, flags
            pairs whose cosine is >= ``threshold`` (default 0.95). Same-type +
            same-project is therefore structural, not a post-filter, and the
            O(n^2) pairwise cost collapses to the sum of per-group squares.
            numpy is used when importable (``Xn @ Xn.T``) with a pure-Python
            (``math`` only) fallback. Note the H91 *pair* analysis used a strict
            ``>`` flag; the I05 *graph* edge rule is ``>=`` to match the AC text
            "the >=0.95 ... cosine graph".

  COMPONENTS ``connected_components(edges)`` runs union-find (DSU) over the
            flagged edges. Each connected component with >= 2 members is one
            duplicate cluster. Singletons are not duplicates and are dropped.

  CANONICAL ``select_canonical(members, metadata)`` picks one deterministic
            canonical record per cluster by argmax over, in priority order,
            ``(evidence, inbound-edges, lifecycle, age)`` — richest evidence
            first, then most graph-referenced, then most lifecycle-settled, then
            oldest (the original). ``record_id`` is the final lexicographic
            tiebreak so the choice is fully deterministic even when every signal
            ties. The four ranking signals are NOT carried by ``vector_read``
            (it returns only record_id/type/embedding), so they come from an
            optional per-record ``metadata`` map (``--metadata``); without it the
            canonical degrades gracefully to the deterministic record_id tiebreak
            and a ``metadata_coverage`` warning is surfaced in the summary.

  SINK      ``write_results`` mirrors the H91 sink: ALWAYS writes
            ``clusters.jsonl`` + ``summary.json`` to the local ``--out`` dir and
            emits one structured ``DEDUP_RESULTS {json-summary}`` stdout line
            (the CloudWatch-degraded mirror); when ``DEDUP_RESULTS_BUCKET`` is
            set it ALSO best-effort PUTs both files to S3. An S3 failure never
            aborts the local write.

clusters.jsonl schema (one JSON object per line, sorted by size desc then
max-cosine desc):

    {"cluster_id": "i05-cluster-0001",
     "record_type": <type>, "project_id": <project>,
     "size": <int>, "members": [<record_id>, ...],
     "canonical": <record_id>, "duplicates": [<record_id>, ...],
     "canonical_rationale": {"evidence": <float>, "inbound_edges": <int>,
                             "lifecycle_rank": <int>, "lifecycle_status": <str>,
                             "created_at": <str|null>, "tiebreak": <str>,
                             "has_metadata": <bool>},
     "edges": [{"a": <record_id>, "b": <record_id>, "cosine": <float>}, ...],
     "max_cosine": <float>, "min_cosine": <float>, "mean_cosine": <float>}
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Reuse the ENC-TSK-H91 corpus read + cosine helpers verbatim so there is a
# single governed vector_read path. The script lives in tools/ alongside it, so
# the sibling import resolves both when run as ``python tools/dedup_cluster_i05``
# (tools/ is sys.path[0]) and from the unit tests (which insert tools/ on path).
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
import correlation_analysis_h91 as h91  # noqa: E402

# numpy is re-exported from h91 so the unit tests can monkeypatch a single
# module attribute (``dc.np = None``) to force the pure-Python graph path, the
# same idiom test_correlation_analysis_h91 uses.
np = h91.np

EMBEDDING_PROPERTY = h91.EMBEDDING_PROPERTY

DEFAULT_PROJECT_ID = h91.DEFAULT_PROJECT_ID
DEFAULT_THRESHOLD = 0.95
DEFAULT_PAGE_LIMIT = h91.DEFAULT_PAGE_LIMIT
DEFAULT_OUT_DIR = "./i05_results"
DEFAULT_GAMMA_FUNCTION = h91.DEFAULT_GAMMA_FUNCTION

# S3 sink env contract (mirrors H91 / PATHWAY_TELEMETRY_BUCKET).
RESULTS_BUCKET_ENV = "DEDUP_RESULTS_BUCKET"
RESULTS_PREFIX_ENV = "DEDUP_RESULTS_PREFIX"
DEFAULT_RESULTS_PREFIX = "dedup-clusters-i05"

CLUSTERS_FILENAME = "clusters.jsonl"
SUMMARY_FILENAME = "summary.json"

_CLUSTER_ID_PREFIX = "i05-cluster-"


# ===========================================================================
# CANONICAL ranking signals
# ===========================================================================
# Lifecycle ordinal: a more lifecycle-settled record is the better canonical
# anchor (tertiary signal, per the AC priority order). Covers task / issue /
# feature / plan / lesson terminal + intermediate statuses. Unknown -> 0. The
# absolute values are arbitrary; only their relative order matters.
LIFECYCLE_RANK: Dict[str, int] = {
    # terminal / settled
    "closed": 100,
    "deployed": 100,
    "production": 100,
    "complete": 100,
    "accepted": 95,
    "merged-main": 90,
    "deploy-success": 85,
    "deploy-init": 80,
    "active": 70,
    # mid-flight code arc
    "pr": 60,
    "pushed": 60,
    "committed": 55,
    "coding-complete": 50,
    "coding-updates": 45,
    # early
    "in-progress": 30,
    "started": 30,
    "drafted": 20,
    "open": 10,
    "incomplete": 5,
}


def _lifecycle_rank(status: Optional[str]) -> int:
    """Ordinal lifecycle rank for a status string (case-insensitive). Higher is
    more settled; unknown / empty -> 0."""
    if not status:
        return 0
    return LIFECYCLE_RANK.get(str(status).strip().lower(), 0)


def _age_epoch(created_at: Optional[str]) -> float:
    """Parse an ISO-8601 ``created_at`` into a UTC epoch (seconds). Returns
    ``+inf`` when missing/unparseable so an unknown-age record is treated as the
    *newest* — i.e. it never wins the "oldest is canonical" age signal on the
    strength of a missing timestamp.
    """
    if not created_at or not isinstance(created_at, str):
        return math.inf
    text = created_at.strip()
    if not text:
        return math.inf
    # Normalize a trailing 'Z' to an explicit UTC offset for fromisoformat.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        import datetime as _dt
        dt = _dt.datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return math.inf


def derive_evidence_score(record: Dict[str, Any]) -> float:
    """Evidence-richness heuristic for a tracker record (loader helper).

    Higher means a more evidence-backed record and thus a better canonical
    anchor. Weighting (documented, deterministic):
      * +3 per acceptance criterion with ``evidence_acceptance`` true,
      * +1 per acceptance criterion carrying non-empty ``evidence`` text,
      * +2 when a non-empty ``resolution`` is present (resolved issues),
      * +0.5 when a non-empty ``intent``/``description`` is present.
    A bare string criterion (legacy) contributes 0 — it gates nothing.
    """
    score = 0.0
    for crit in record.get("acceptance_criteria") or []:
        if isinstance(crit, dict):
            if crit.get("evidence_acceptance"):
                score += 3.0
            elif str(crit.get("evidence") or "").strip():
                score += 1.0
    if str(record.get("resolution") or "").strip():
        score += 2.0
    if str(record.get("intent") or record.get("description") or "").strip():
        score += 0.5
    return score


def inbound_edges_from_neighbors(payload: Any, record_id: str) -> int:
    """Count inbound governed graph edges for ``record_id`` from a graphsearch
    ``neighbors`` payload (loader helper).

    Tolerates the edge-shape variants the graph_query_api emits: the destination
    endpoint may be keyed ``target``/``to``/``dst``/``end`` and the source
    ``source``/``from``/``src``/``start``. An edge counts as inbound when its
    destination is ``record_id`` and its source is some other record.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return 0
    if not isinstance(payload, dict):
        return 0
    edges = payload.get("edges")
    if not isinstance(edges, list):
        return 0

    def _endpoint(edge: Dict[str, Any], keys: Sequence[str]) -> str:
        for k in keys:
            val = edge.get(k)
            if isinstance(val, dict):  # node object rather than a bare id
                val = val.get("record_id") or val.get("id")
            if isinstance(val, str) and val:
                return val
        return ""

    count = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        dst = _endpoint(edge, ("target", "to", "dst", "end", "end_id"))
        src = _endpoint(edge, ("source", "from", "src", "start", "start_id"))
        if dst == record_id and src and src != record_id:
            count += 1
    return count


def _record_meta(metadata: Optional[Dict[str, Any]], record_id: str) -> Dict[str, Any]:
    """Normalize the per-record metadata entry into the ranking signal tuple
    source. Missing entries degrade to zeros / unknown age."""
    raw = (metadata or {}).get(record_id) or {}
    if not isinstance(raw, dict):
        raw = {}
    # evidence_score may be supplied precomputed by the loader, else derived from
    # the embedded record fields, else 0.
    if "evidence_score" in raw:
        try:
            evidence = float(raw.get("evidence_score") or 0.0)
        except (TypeError, ValueError):
            evidence = 0.0
    else:
        evidence = derive_evidence_score(raw)
    try:
        inbound = int(raw.get("inbound_edges") or 0)
    except (TypeError, ValueError):
        inbound = 0
    status = raw.get("status")
    created_at = raw.get("created_at")
    return {
        "evidence": evidence,
        "inbound_edges": inbound,
        "lifecycle_rank": _lifecycle_rank(status),
        "lifecycle_status": (str(status).strip().lower() if status else None),
        "created_at": created_at if isinstance(created_at, str) else None,
        "age_epoch": _age_epoch(created_at),
        "has_metadata": bool(raw),
    }


def select_canonical(member_ids: Sequence[str],
                     metadata: Optional[Dict[str, Any]] = None
                     ) -> Tuple[str, Dict[str, Any]]:
    """Deterministically pick the canonical record for a cluster.

    argmax priority (AC order): evidence > inbound-edges > lifecycle > age
    (oldest wins). ``record_id`` ascending is the final tiebreak, so the result
    is total and reproducible even when all four signals tie (e.g. no metadata).

    Returns ``(canonical_id, rationale)`` where rationale carries the winning
    record's signals plus a ``tiebreak`` note describing what decided it.
    """
    if not member_ids:
        raise ValueError("select_canonical requires a non-empty member list")

    scored: List[Tuple[Tuple[float, int, int, float, str], str, Dict[str, Any]]] = []
    for rid in member_ids:
        m = _record_meta(metadata, rid)
        # Sort key ascending: negate the "higher wins" signals and use +age_epoch
        # (smaller epoch = older = wins) and record_id ascending as final key.
        key = (
            -m["evidence"],
            -m["inbound_edges"],
            -m["lifecycle_rank"],
            m["age_epoch"],
            rid,
        )
        scored.append((key, rid, m))
    scored.sort(key=lambda t: t[0])

    _, canonical_id, winner = scored[0]
    tiebreak = _explain_tiebreak(scored)
    rationale = {
        "evidence": winner["evidence"],
        "inbound_edges": winner["inbound_edges"],
        "lifecycle_rank": winner["lifecycle_rank"],
        "lifecycle_status": winner["lifecycle_status"],
        "created_at": winner["created_at"],
        "has_metadata": winner["has_metadata"],
        "tiebreak": tiebreak,
    }
    return canonical_id, rationale


def _explain_tiebreak(scored: Sequence[Tuple[Tuple[float, int, int, float, str], str, Dict[str, Any]]]) -> str:
    """Describe which signal separated the winner from the runner-up — useful
    audit context in the emitted rationale."""
    if len(scored) < 2:
        return "sole_member"
    win, run = scored[0][0], scored[1][0]
    labels = ("evidence", "inbound_edges", "lifecycle", "age")
    for idx, label in enumerate(labels):
        if win[idx] != run[idx]:
            return label
    return "record_id"


# ===========================================================================
# GRAPH layer — same-type same-project cosine edges
# ===========================================================================
def _group_key(node: Dict[str, Any], default_project: str) -> Tuple[str, str]:
    """Partition key enforcing the same-project + same-type edge rule. The
    ``vector_read`` payload omits ``project_id`` (it is a query-scope param, not
    a node field), so fall back to the read scope's project."""
    project = node.get("project_id") or default_project or ""
    rtype = node.get("record_type") or ""
    return (str(project), str(rtype))


def _edges_for_group_numpy(group_nodes: List[Dict[str, Any]],
                           vectors: List[List[float]],
                           threshold: float) -> List[Dict[str, Any]]:
    """Vectorized within-group upper-triangle cosine, flagging entries >=
    ``threshold``. Zero-norm rows normalize to the zero vector (cosine 0, never
    flagged)."""
    X = np.asarray(vectors, dtype=np.float64)
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    safe = np.where(norms == 0.0, 1.0, norms)
    Xn = X / safe
    Xn[(norms == 0.0).ravel()] = 0.0
    sims = Xn @ Xn.T

    iu, ju = np.triu_indices(len(vectors), k=1)
    if iu.size == 0:
        return []
    sims_pairs = sims[iu, ju]
    mask = sims_pairs >= threshold
    edges: List[Dict[str, Any]] = []
    for i, j, c in zip(iu[mask].tolist(), ju[mask].tolist(), sims_pairs[mask].tolist()):
        edges.append(_edge_record(group_nodes[i], group_nodes[j], float(c)))
    return edges


def _edges_for_group_python(group_nodes: List[Dict[str, Any]],
                            vectors: List[List[float]],
                            threshold: float) -> List[Dict[str, Any]]:
    """Pure-Python within-group cosine fallback (numpy absent). Pre-normalizes
    once; zero-norm vectors are skipped."""
    unit: List[Optional[List[float]]] = []
    for vec in vectors:
        norm = math.sqrt(sum(x * x for x in vec))
        unit.append(None if norm == 0.0 else [x / norm for x in vec])

    edges: List[Dict[str, Any]] = []
    n = len(unit)
    for i in range(n):
        ui = unit[i]
        if ui is None:
            continue
        for j in range(i + 1, n):
            uj = unit[j]
            if uj is None:
                continue
            cos = sum(a * b for a, b in zip(ui, uj))
            if cos >= threshold:
                edges.append(_edge_record(group_nodes[i], group_nodes[j], float(cos)))
    return edges


def _edge_record(a: Dict[str, Any], b: Dict[str, Any], cosine: float) -> Dict[str, Any]:
    """One flagged same-type same-project cosine edge. ``a`` is the
    lexicographically smaller record_id so edges are orientation-stable."""
    aid, bid = a.get("record_id"), b.get("record_id")
    if aid is not None and bid is not None and str(bid) < str(aid):
        a, b = b, a
        aid, bid = bid, aid
    return {
        "a": aid,
        "b": bid,
        "record_type": a.get("record_type"),
        "project_id": a.get("project_id"),
        "cosine": cosine,
    }


def similarity_edges(nodes: Sequence[Dict[str, Any]], threshold: float,
                     default_project: str = DEFAULT_PROJECT_ID) -> List[Dict[str, Any]]:
    """Build the same-type same-project >= ``threshold`` cosine edge set.

    Nodes are partitioned by ``(project_id, record_type)``; cosine is computed
    only within a partition, so cross-type and cross-project pairs can never
    produce an edge. numpy is used when importable, else the pure-Python path.
    """
    # Reuse H91's embedding validation (drops missing/empty/non-numeric vectors).
    kept_nodes, vectors = h91._valid_vectors(nodes)

    # Bucket parallel (node, vector) by partition key.
    groups: Dict[Tuple[str, str], Tuple[List[Dict[str, Any]], List[List[float]]]] = {}
    for node, vec in zip(kept_nodes, vectors):
        gk = _group_key(node, default_project)
        bucket = groups.setdefault(gk, ([], []))
        bucket[0].append(node)
        bucket[1].append(vec)

    edges: List[Dict[str, Any]] = []
    for (_proj, _rtype), (group_nodes, group_vectors) in groups.items():
        if len(group_vectors) < 2:
            continue
        # Drop ragged vectors that disagree with the group's modal dim so the
        # numpy matrix build cannot raise on a jagged corpus (mirrors H91).
        dim = len(group_vectors[0])
        filtered = [(nd, v) for nd, v in zip(group_nodes, group_vectors) if len(v) == dim]
        group_nodes = [nd for nd, _ in filtered]
        group_vectors = [v for _, v in filtered]
        if len(group_vectors) < 2:
            continue
        if np is not None:
            edges.extend(_edges_for_group_numpy(group_nodes, group_vectors, threshold))
        else:
            edges.extend(_edges_for_group_python(group_nodes, group_vectors, threshold))

    edges.sort(key=lambda e: e["cosine"], reverse=True)
    return edges


def edges_from_pairs(pairs: Sequence[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
    """Build the I05 edge set from an H91 ``pairs.jsonl`` record list: keep only
    same-type pairs with cosine >= ``threshold``. This is the ``--source pairs``
    reuse path (no corpus re-read / no cosine recompute)."""
    edges: List[Dict[str, Any]] = []
    for p in pairs:
        if not isinstance(p, dict):
            continue
        a, b = p.get("a"), p.get("b")
        if not a or not b:
            continue
        a_type, b_type = p.get("a_type"), p.get("b_type")
        if a_type != b_type:
            continue
        try:
            cosine = float(p.get("cosine"))
        except (TypeError, ValueError):
            continue
        if cosine < threshold:
            continue
        # Reuse the orientation-stable edge builder.
        edges.append(_edge_record(
            {"record_id": a, "record_type": a_type, "project_id": p.get("project_id")},
            {"record_id": b, "record_type": b_type, "project_id": p.get("project_id")},
            cosine,
        ))
    edges.sort(key=lambda e: e["cosine"], reverse=True)
    return edges


# ===========================================================================
# COMPONENTS layer — union-find over the flagged edges
# ===========================================================================
class _DSU:
    """Minimal disjoint-set (union by rank + path compression)."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}
        self.rank: Dict[str, int] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        self.rank.setdefault(x, 0)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        # Path compression.
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def connected_components(edges: Sequence[Dict[str, Any]]) -> List[List[str]]:
    """Connected components (size >= 2) over the flagged edge set, via union-find.

    Returns a list of member-id lists, each sorted ascending; the outer list is
    sorted by size desc then by smallest member id, for deterministic output.
    Singletons (records with no >= threshold same-type neighbor) are excluded —
    they are not duplicates.
    """
    dsu = _DSU()
    for e in edges:
        a, b = e.get("a"), e.get("b")
        if a and b:
            dsu.union(str(a), str(b))

    comps: Dict[str, List[str]] = {}
    for node in list(dsu.parent.keys()):
        comps.setdefault(dsu.find(node), []).append(node)

    clusters = [sorted(members) for members in comps.values() if len(members) >= 2]
    clusters.sort(key=lambda members: (-len(members), members[0]))
    return clusters


# ===========================================================================
# Assembly — clusters + summary
# ===========================================================================
def build_clusters(nodes: Optional[Sequence[Dict[str, Any]]],
                   threshold: float,
                   metadata: Optional[Dict[str, Any]] = None,
                   default_project: str = DEFAULT_PROJECT_ID,
                   precomputed_edges: Optional[Sequence[Dict[str, Any]]] = None,
                   generated_at: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """End-to-end COMPUTE: edges -> components -> per-cluster canonical + stats.

    Pass either ``nodes`` (compute the cosine graph) or ``precomputed_edges``
    (e.g. from an H91 pairs.jsonl). ``generated_at`` is threaded through into
    stats verbatim; this function never reads the clock.
    """
    if precomputed_edges is not None:
        edges = list(precomputed_edges)
        corpus_size = None
        embedding_dim = None
    else:
        edges = similarity_edges(nodes or [], threshold, default_project=default_project)
        kept_nodes, vectors = h91._valid_vectors(nodes or [])
        corpus_size = len(kept_nodes)
        embedding_dim = len(vectors[0]) if vectors else None

    # Index edges by the unordered member pair for fast intra-cluster lookup.
    edges_by_member: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges:
        for endpoint in (e.get("a"), e.get("b")):
            if endpoint:
                edges_by_member.setdefault(str(endpoint), []).append(e)

    components = connected_components(edges)

    clusters: List[Dict[str, Any]] = []
    for idx, members in enumerate(components, start=1):
        member_set = set(members)
        # The edges fully inside this cluster (dedup by id-pair).
        seen: set = set()
        cluster_edges: List[Dict[str, Any]] = []
        for member in members:
            for e in edges_by_member.get(member, ()):
                a, b = str(e.get("a")), str(e.get("b"))
                if a in member_set and b in member_set:
                    pair_key = (a, b) if a < b else (b, a)
                    if pair_key in seen:
                        continue
                    seen.add(pair_key)
                    cluster_edges.append({"a": e["a"], "b": e["b"], "cosine": e["cosine"]})
        cluster_edges.sort(key=lambda e: e["cosine"], reverse=True)

        canonical, rationale = select_canonical(members, metadata)

        cosines = [e["cosine"] for e in cluster_edges]
        # record_type/project for the cluster: derived from an edge (homogeneous
        # by construction) or the node metadata.
        rtype = cluster_edges[0].get("record_type") if cluster_edges else None
        if rtype is None and edges:
            for e in edges_by_member.get(members[0], ()):
                rtype = e.get("record_type")
                break
        proj = None
        for e in edges_by_member.get(members[0], ()):
            proj = e.get("project_id")
            break

        clusters.append({
            "cluster_id": f"{_CLUSTER_ID_PREFIX}{idx:04d}",
            "record_type": rtype,
            "project_id": proj or default_project,
            "size": len(members),
            "members": members,
            "canonical": canonical,
            "duplicates": [m for m in members if m != canonical],
            "canonical_rationale": rationale,
            "edges": cluster_edges,
            "max_cosine": max(cosines) if cosines else None,
            "min_cosine": min(cosines) if cosines else None,
            "mean_cosine": (sum(cosines) / len(cosines)) if cosines else None,
        })

    stats = _summary_stats(
        clusters, edges, threshold, corpus_size, embedding_dim,
        metadata, generated_at,
    )
    return clusters, stats


def _summary_stats(clusters: Sequence[Dict[str, Any]], edges: Sequence[Dict[str, Any]],
                   threshold: float, corpus_size: Optional[int], embedding_dim: Optional[int],
                   metadata: Optional[Dict[str, Any]], generated_at: Optional[str]) -> Dict[str, Any]:
    records_in_clusters = sorted({m for c in clusters for m in c["members"]})
    size_hist: Dict[str, int] = {}
    by_type: Dict[str, Dict[str, int]] = {}
    for c in clusters:
        size_hist[str(c["size"])] = size_hist.get(str(c["size"]), 0) + 1
        bt = by_type.setdefault(str(c["record_type"]), {"clusters": 0, "records": 0})
        bt["clusters"] += 1
        bt["records"] += c["size"]

    with_meta = sum(1 for r in records_in_clusters if (metadata or {}).get(r)) if metadata else 0
    return {
        "corpus_size": corpus_size,
        "embedding_dim": embedding_dim,
        "threshold": threshold,
        "num_edges": len(edges),
        "num_clusters": len(clusters),
        "num_records_in_clusters": len(records_in_clusters),
        "largest_cluster_size": max((c["size"] for c in clusters), default=0),
        "cluster_size_histogram": dict(sorted(size_hist.items(), key=lambda kv: int(kv[0]))),
        "by_type": by_type,
        "metadata_coverage": {
            "metadata_supplied": bool(metadata),
            "records_in_clusters": len(records_in_clusters),
            "records_with_metadata": with_meta,
        },
        "generated_at": generated_at,
    }


# ===========================================================================
# Metadata loaders (the canonical-ranking signals; vector_read omits them)
# ===========================================================================
def load_metadata_from_file(path: str) -> Dict[str, Any]:
    """Load a per-record metadata map ``{record_id: {status, created_at,
    evidence_score?|acceptance_criteria?, inbound_edges?}}`` from a local JSON
    file. The source exercised by the unit tests."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("metadata file must be a JSON object keyed by record_id")
    return data


def load_metadata_from_mcp(record_ids: Sequence[str],
                           search_fn: Optional[Callable] = None,
                           project_id: str = DEFAULT_PROJECT_ID) -> Dict[str, Any]:
    """Enrich the clustered record_ids with the four canonical-ranking signals
    via the MCP code-mode ``search`` surface.

    DEFENSIVE / NOT unit-tested against live MCP (mirrors H91's live loaders).
    For each record it reads ``tracker.get`` (status, created_at, evidence) and
    ``tracker.graphsearch`` neighbors (inbound edge count). ``search_fn`` is the
    injected ``search(action, arguments)`` callable; without it an import shim is
    attempted and otherwise a clear error is raised.
    """
    if search_fn is None:  # pragma: no cover - environment-specific shim
        try:
            from enceladus_mcp import search as search_fn  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "no MCP `search` callable available; pass search_fn= or run the "
                "enrichment from a session where the MCP code-mode surface is bound"
            ) from exc

    def _unwrap(result: Any) -> Dict[str, Any]:
        if isinstance(result, str):
            result = json.loads(result)
        if not isinstance(result, dict):
            return {}
        # Peel the code-mode envelope ({success, result: {...}}).
        for key in ("result", "record", "data", "body"):
            inner = result.get(key)
            if isinstance(inner, dict):
                result = inner
        return result

    metadata: Dict[str, Any] = {}
    for rid in record_ids:  # pragma: no cover - live MCP only
        entry: Dict[str, Any] = {}
        try:
            rec = _unwrap(search_fn(action="tracker.get", arguments={"record_id": rid}))
            entry["status"] = rec.get("status")
            entry["created_at"] = rec.get("created_at")
            entry["evidence_score"] = derive_evidence_score(rec)
        except Exception as exc:
            print(f"[WARNING] tracker.get failed for {rid}: {exc}", file=sys.stderr)
        try:
            neighbors = _unwrap(search_fn(
                action="tracker.graphsearch",
                arguments={"search_type": "neighbors", "project_id": project_id,
                           "record_id": rid, "direction": "in"},
            ))
            entry["inbound_edges"] = inbound_edges_from_neighbors(neighbors, rid)
        except Exception as exc:
            print(f"[WARNING] neighbors failed for {rid}: {exc}", file=sys.stderr)
        metadata[rid] = entry
    return metadata


# ===========================================================================
# SINK layer — mirror H91's local + best-effort S3 + stdout-degraded sink
# ===========================================================================
def _clusters_to_jsonl(clusters: Sequence[Dict[str, Any]]) -> str:
    return "".join(json.dumps(c, default=str) + "\n" for c in clusters)


def write_results(clusters: Sequence[Dict[str, Any]], stats: Dict[str, Any],
                  args: argparse.Namespace) -> Dict[str, Any]:
    """SINK entrypoint. ALWAYS writes ``clusters.jsonl`` + ``summary.json`` to
    ``--out`` and emits one ``DEDUP_RESULTS {json}`` stdout line. When
    ``DEDUP_RESULTS_BUCKET`` is set, ALSO best-effort PUTs both files to S3; an
    S3 failure is caught and never aborts the local write."""
    out_dir = getattr(args, "out", DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    clusters_path = os.path.join(out_dir, CLUSTERS_FILENAME)
    summary_path = os.path.join(out_dir, SUMMARY_FILENAME)

    clusters_body = _clusters_to_jsonl(clusters)
    summary_obj = dict(stats)

    with open(clusters_path, "w", encoding="utf-8") as fh:
        fh.write(clusters_body)

    bucket = os.environ.get(RESULTS_BUCKET_ENV, "").strip()
    prefix = (os.environ.get(RESULTS_PREFIX_ENV, DEFAULT_RESULTS_PREFIX).strip()
              or DEFAULT_RESULTS_PREFIX).rstrip("/")
    s3_uris: Dict[str, str] = {}
    if bucket:
        try:
            client = h91._get_s3()
            clusters_key = f"{prefix}/{CLUSTERS_FILENAME}"
            summary_key = f"{prefix}/{SUMMARY_FILENAME}"
            client.put_object(
                Bucket=bucket, Key=clusters_key,
                Body=clusters_body.encode("utf-8"),
                ContentType="application/x-ndjson",
            )
            s3_uris = {
                "clusters": f"s3://{bucket}/{clusters_key}",
                "summary": f"s3://{bucket}/{summary_key}",
            }
        except Exception as exc:
            print(f"[WARNING] dedup results S3 put failed ({exc}); local write retained",
                  file=sys.stderr)
            s3_uris = {}

    summary_obj["artifacts"] = {
        "clusters_local": clusters_path,
        "summary_local": summary_path,
        **({"clusters_s3": s3_uris["clusters"], "summary_s3": s3_uris["summary"]} if s3_uris else {}),
    }

    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary_obj, fh, indent=2, default=str)

    if bucket and s3_uris:
        try:
            client = h91._get_s3()
            client.put_object(
                Bucket=bucket, Key=f"{prefix}/{SUMMARY_FILENAME}",
                Body=json.dumps(summary_obj, default=str).encode("utf-8"),
                ContentType="application/json",
            )
        except Exception as exc:
            print(f"[WARNING] dedup summary S3 put failed ({exc}); local summary retained",
                  file=sys.stderr)

    print("DEDUP_RESULTS " + json.dumps(summary_obj, default=str))
    return summary_obj


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dedup_cluster_i05",
        description=(
            "ENC-TSK-I05 duplicate-cluster detection over the Enceladus "
            "n.embedding corpus: same-type same-project >=0.95 cosine graph -> "
            "connected components -> deterministic canonical suggestion. "
            "Mutation-free; reads via the ENC-TSK-H89/H91 vector_read path."
        ),
    )
    p.add_argument("--source", choices=["gamma", "mcp", "file", "pairs"], default="gamma",
                   help="Corpus read surface, or 'pairs' to ingest an H91 pairs.jsonl edge set.")
    p.add_argument("--input", default=None,
                   help="Path for --source file (corpus JSON) or --source pairs (pairs.jsonl).")
    p.add_argument("--metadata", default=None,
                   help="Optional JSON file of per-record canonical-ranking signals "
                        "{record_id: {status, created_at, evidence_score?, inbound_edges?}}.")
    p.add_argument("--project-id", dest="project_id", default=DEFAULT_PROJECT_ID,
                   help="Project id to read / default partition (default: enceladus).")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                   help="Edge if cosine >= this within a (project,type) group (default: 0.95).")
    p.add_argument("--page-limit", dest="page_limit", type=int, default=DEFAULT_PAGE_LIMIT,
                   help="vector_read page size (default: 200).")
    p.add_argument("--out", default=DEFAULT_OUT_DIR,
                   help="Local output directory (default: ./i05_results).")
    p.add_argument("--gamma-function", dest="gamma_function", default=DEFAULT_GAMMA_FUNCTION,
                   help="Gamma graph-query Lambda name (default: devops-graph-query-api-gamma).")
    p.add_argument("--generated-at", dest="generated_at", default=None,
                   help="Optional ISO timestamp stamped into stats.generated_at.")
    return p


def _load_edges_or_nodes(args: argparse.Namespace) -> Tuple[Optional[List[Dict[str, Any]]], Optional[List[Dict[str, Any]]]]:
    """Resolve the READ layer into either (nodes, None) for the compute-graph
    path or (None, precomputed_edges) for the --source pairs path."""
    if args.source == "pairs":
        if not args.input:
            raise ValueError("--input PATH (an H91 pairs.jsonl) is required for --source pairs")
        pairs: List[Dict[str, Any]] = []
        with open(args.input, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    pairs.append(json.loads(line))
        return None, edges_from_pairs(pairs, args.threshold)

    nodes = h91.load_corpus(args)
    # Stamp the read-scope project onto nodes lacking it so the partition rule
    # can enforce same-project (vector_read payloads omit project_id).
    for n in nodes:
        n.setdefault("project_id", args.project_id)
    return nodes, None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        nodes, precomputed_edges = _load_edges_or_nodes(args)
    except Exception as exc:
        print(f"[ERROR] corpus/edge read failed (source={args.source}): {exc}", file=sys.stderr)
        return 2

    metadata: Optional[Dict[str, Any]] = None
    if args.metadata:
        try:
            metadata = load_metadata_from_file(args.metadata)
        except Exception as exc:
            print(f"[ERROR] metadata read failed ({args.metadata}): {exc}", file=sys.stderr)
            return 2

    if precomputed_edges is not None:
        print(f"[INFO] ingested {len(precomputed_edges)} same-type edges from pairs "
              f"(threshold={args.threshold})", file=sys.stderr)
    else:
        print(f"[INFO] loaded {len(nodes or [])} nodes from source={args.source}; "
              f"threshold={args.threshold}", file=sys.stderr)

    clusters, stats = build_clusters(
        nodes, args.threshold, metadata=metadata,
        default_project=args.project_id,
        precomputed_edges=precomputed_edges,
        generated_at=args.generated_at,
    )
    write_results(clusters, stats, args)

    print(f"[SUCCESS] {stats['num_clusters']} duplicate clusters over "
          f"{stats['num_records_in_clusters']} records "
          f"(largest={stats['largest_cluster_size']}, edges={stats['num_edges']})",
          file=sys.stderr)
    if metadata is None and clusters:
        print("[WARNING] no --metadata supplied; canonical suggestions fell back to the "
              "deterministic record_id tiebreak (evidence/inbound/lifecycle/age unknown)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
