"""ENC-TSK-S13 (PLN-103 W2.1 / N12): in-process Personalized PageRank.

The graph signal's cost on the Cypher walk grows with the anchor's neighbourhood
(a hub walks *1..3 over most of the graph). This module loads the project's edge
list ONCE per cache TTL (one Cypher, about 11k nodes / 51k relationships, a few MB
over Bolt) into a compact int-indexed adjacency and scores anchors with the
Andersen-Chung-Lang forward push, so a hub costs about what a leaf costs.

Semantics mirror ``_hybrid_graph_ranks_cypher_fallback``:
  * the walk is UNDIRECTED (each relationship contributes both directions);
  * the edge weight is ``GRAPH_EDGE_WEIGHTS[type] * coalesce(flow_weight, 1.0)``
    (``default_weight`` for a type absent from the table);
  * the anchor itself is never returned.

Pure Python, no third-party imports. The Neo4j driver is injected, so the module
does not import ``lambda_function`` (no import cycle).
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from array import array
from collections import deque
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

PPR_ALPHA_DEFAULT = 0.15      # teleport probability = 1 - PPR_DAMPING_FACTOR (0.85)
PPR_EPSILON_DEFAULT = 1e-4    # push residual threshold, degree-normalised


def _cache_ttl_s() -> float:
    try:
        return float(os.environ.get("PPR_CACHE_TTL_S", "600"))
    except ValueError:
        return 600.0


class Projection:
    """Immutable CSR adjacency. ``indptr[i]:indptr[i+1]`` slices ``indices``/``weights``."""

    __slots__ = ("ids", "index", "indptr", "indices", "weights", "wdeg", "n_edges", "loaded_at")

    def __init__(self, ids, index, indptr, indices, weights, wdeg, n_edges, loaded_at):
        self.ids = ids
        self.index = index
        self.indptr = indptr
        self.indices = indices
        self.weights = weights
        self.wdeg = wdeg
        self.n_edges = n_edges
        self.loaded_at = loaded_at

    @property
    def n_nodes(self) -> int:
        return len(self.ids)

    def approx_bytes(self) -> int:
        total = 0
        for arr in (self.indptr, self.indices, self.weights, self.wdeg):
            total += arr.buffer_info()[1] * arr.itemsize
        # id strings + the id->index dict (shallow estimate; dominated by the strings).
        total += sum(sys.getsizeof(s) for s in self.ids)
        total += sys.getsizeof(self.index) + sys.getsizeof(self.ids)
        return total


def build_projection(
    edges: Iterable[Sequence[Any]],
    edge_weights: Mapping[str, float],
    default_weight: float,
    now: Optional[float] = None,
) -> Projection:
    """Build the symmetric CSR from ``(src, dst, type, flow_weight)`` rows."""
    index: Dict[str, int] = {}
    ids: List[str] = []
    src_l = array("i")
    dst_l = array("i")
    w_l = array("d")

    def _idx(rid: str) -> int:
        i = index.get(rid)
        if i is None:
            i = len(ids)
            index[rid] = i
            ids.append(rid)
        return i

    n_edges = 0
    for row in edges:
        src, dst, etype, fw = row[0], row[1], row[2], row[3]
        if not src or not dst or src == dst:
            continue
        try:
            fwv = 1.0 if fw is None else float(fw)
        except (TypeError, ValueError):
            fwv = 1.0
        w = float(edge_weights.get(etype, default_weight)) * fwv
        if w <= 0.0:
            continue
        a, b = _idx(src), _idx(dst)
        src_l.append(a)
        dst_l.append(b)
        w_l.append(w)
        n_edges += 1

    n = len(ids)
    counts = array("i", [0]) * (n + 1)
    for a, b in zip(src_l, dst_l):
        counts[a + 1] += 1
        counts[b + 1] += 1
    for i in range(n):
        counts[i + 1] += counts[i]
    indptr = counts
    fill = array("i", indptr[:n]) if n else array("i")
    indices = array("i", [0]) * (2 * n_edges)
    weights = array("d", [0.0]) * (2 * n_edges)
    wdeg = array("d", [0.0]) * n
    for a, b, w in zip(src_l, dst_l, w_l):
        pa = fill[a]
        indices[pa] = b
        weights[pa] = w
        fill[a] = pa + 1
        pb = fill[b]
        indices[pb] = a
        weights[pb] = w
        fill[b] = pb + 1
        wdeg[a] += w
        wdeg[b] += w
    return Projection(ids, index, indptr, indices, weights, wdeg, n_edges,
                      time.time() if now is None else now)


def push_ppr(
    proj: Projection,
    anchors: Sequence[str],
    top_k: int,
    alpha: float = PPR_ALPHA_DEFAULT,
    epsilon: float = PPR_EPSILON_DEFAULT,
    include_anchors: bool = False,
) -> List[Dict[str, Any]]:
    """Andersen-Chung-Lang forward push from ``anchors`` (uniform seed mass).

    A node ``u`` is pushed while ``r[u] >= epsilon * wdeg[u]``: ``alpha * r[u]``
    settles into ``p[u]`` and ``(1 - alpha) * r[u]`` spreads over the neighbours
    in proportion to edge weight. Returns ``[{record_id, score, rank}]`` for the
    ``top_k`` highest ``p`` (anchors excluded unless ``include_anchors``); ``[]``
    when no anchor is in the projection.
    """
    seeds = [proj.index[a] for a in anchors if a in proj.index]
    if not seeds:
        return []
    seeds = list(dict.fromkeys(seeds))
    indptr, indices, weights, wdeg = proj.indptr, proj.indices, proj.weights, proj.wdeg
    p: Dict[int, float] = {}
    r: Dict[int, float] = {s: 1.0 / len(seeds) for s in seeds}
    queue = deque(seeds)
    queued = set(seeds)
    keep = 1.0 - alpha
    while queue:
        u = queue.popleft()
        queued.discard(u)
        ru = r.get(u, 0.0)
        du = wdeg[u]
        if du <= 0.0:
            # Isolated node: all mass settles locally (no outgoing walk).
            p[u] = p.get(u, 0.0) + ru
            r[u] = 0.0
            continue
        if ru < epsilon * du:
            continue
        p[u] = p.get(u, 0.0) + alpha * ru
        r[u] = 0.0
        spread = keep * ru / du
        for k in range(indptr[u], indptr[u + 1]):
            v = indices[k]
            rv = r.get(v, 0.0) + spread * weights[k]
            r[v] = rv
            if v not in queued and rv >= epsilon * wdeg[v]:
                queue.append(v)
                queued.add(v)
    if not include_anchors:
        for s in seeds:
            p.pop(s, None)
    top = sorted(p.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
    return [
        {"record_id": proj.ids[i], "score": float(score), "rank": rank}
        for rank, (i, score) in enumerate(top, start=1) if score > 0.0
    ]


def exact_ppr(proj: Projection, anchors: Sequence[str], alpha: float = PPR_ALPHA_DEFAULT,
              iterations: int = 200) -> Dict[str, float]:
    """Power-iteration reference (tests / offline checks only; O(iterations * edges))."""
    seeds = [proj.index[a] for a in anchors if a in proj.index]
    n = proj.n_nodes
    s = [0.0] * n
    for i in seeds:
        s[i] = 1.0 / len(seeds)
    x = list(s)
    for _ in range(iterations):
        nx = [alpha * v for v in s]
        for u in range(n):
            if x[u] == 0.0 or proj.wdeg[u] <= 0.0:
                continue
            share = (1.0 - alpha) * x[u] / proj.wdeg[u]
            for k in range(proj.indptr[u], proj.indptr[u + 1]):
                nx[proj.indices[k]] += share * proj.weights[k]
        x = nx
    return {proj.ids[i]: x[i] for i in range(n)}


# ---------------------------------------------------------------------------
# Per-project cache (lazy TTL refresh, single-flight load)
# ---------------------------------------------------------------------------

_CACHE: Dict[str, Projection] = {}
_CACHE_LOCK = threading.Lock()


def reset_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def _load_edges(driver, project_id: str, edge_types: Sequence[str], flow_property: str) -> List[Sequence[Any]]:
    cypher = (
        f"MATCH (s)-[r:{'|'.join(edge_types)}]->(d) "
        f"WHERE s.project_id = $project_id AND d.project_id = $project_id "
        f"AND s.record_id IS NOT NULL AND d.record_id IS NOT NULL "
        f"RETURN s.record_id AS src, d.record_id AS dst, type(r) AS t, "
        f"coalesce(r.{flow_property}, 1.0) AS fw"
    )
    rows: List[Sequence[Any]] = []
    with driver.session() as session:
        for rec in session.run(cypher, project_id=project_id):
            rows.append((rec["src"], rec["dst"], rec["t"], rec["fw"]))
    return rows


def get_projection(
    driver,
    project_id: str,
    edge_weights: Mapping[str, float],
    default_weight: float,
    flow_property: str,
) -> Optional[Projection]:
    """Return a usable projection, loading/refreshing it when absent or past the TTL.

    Never raises. A refresh failure keeps serving the stale projection; with no
    projection at all it returns None so the caller falls back to the Cypher walk.
    """
    ttl = _cache_ttl_s()
    cur = _CACHE.get(project_id)
    if cur is not None and (time.time() - cur.loaded_at) < ttl:
        return cur
    with _CACHE_LOCK:
        cur = _CACHE.get(project_id)
        if cur is not None and (time.time() - cur.loaded_at) < ttl:
            return cur  # another thread refreshed while we waited
        if driver is None:
            return cur
        try:
            t0 = time.perf_counter()
            rows = _load_edges(driver, project_id, list(edge_weights.keys()), flow_property)
            proj = build_projection(rows, edge_weights, default_weight)
        except Exception:
            logger.exception("[ERROR] inproc_ppr projection load failed for %s", project_id)
            return cur
        if proj.n_edges == 0:
            logger.warning("[WARNING] inproc_ppr projection for %s is empty — not caching", project_id)
            return cur
        _CACHE[project_id] = proj
        logger.info(
            "[INFO] inproc_ppr projection loaded project=%s nodes=%d edges=%d bytes~%d in %dms",
            project_id, proj.n_nodes, proj.n_edges, proj.approx_bytes(),
            int((time.perf_counter() - t0) * 1000),
        )
        return proj


def cache_stats() -> Dict[str, Any]:
    """Aggregate and per-project cache figures (nodes, edges, approx bytes, loaded_at)."""
    projects = {
        pid: {"nodes": pr.n_nodes, "edges": pr.n_edges, "approx_bytes": pr.approx_bytes(),
              "loaded_at": pr.loaded_at}
        for pid, pr in list(_CACHE.items())
    }
    return {
        "projects": projects,
        "nodes": sum(v["nodes"] for v in projects.values()),
        "edges": sum(v["edges"] for v in projects.values()),
        "approx_bytes": sum(v["approx_bytes"] for v in projects.values()),
        "loaded_at": max((v["loaded_at"] for v in projects.values()), default=None),
        "ttl_s": _cache_ttl_s(),
    }
