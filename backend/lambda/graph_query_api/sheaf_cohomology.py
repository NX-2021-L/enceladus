"""Sheaf Laplacian H1 inconsistency detection (ENC-FTR-095 / ENC-TSK-I90).

Pure-Python cellular-sheaf cohomology over a tracker subgraph. The module is
intentionally dependency-free (no numpy/scipy) so it bundles cleanly into the
graph_query_api Lambda and is deterministic under unit test.

Model
-----
Given a graph G = (V, E) read from the governed Neo4j projection:

  * Stalks: each node v carries a stalk F(v) = R^d, where d is the embedding
    dimension (length of the node's ``embedding`` vector; defaults to 1 when no
    embeddings are present). This mirrors FTR-088 ``tracker.graph_laplacian``:
    the signed incidence matrix B is the scalar skeleton and the sheaf operators
    are the d-fold block lift B (x) I_d.
  * Restriction maps: identity I_d on "shared" (consistent) edges. When the two
    endpoints of an edge carry *contradictory* status fields the gluing fails and
    the restriction maps are zeroed (the edge can no longer be made coherent),
    leaving a free 1-cochain on that edge.
  * Coboundary delta_0 : C^0 -> C^1 with (delta_0 x)_e = F_{e<-head} x_head -
    F_{e<-tail} x_tail. With identity/zero restriction maps this is exactly the
    signed incidence matrix B (consistent edges) with zeroed rows (inconsistent
    edges).
  * Sheaf Laplacian on 1-cochains (the graph is a 1-complex, so there are no
    2-cells and the up-Laplacian vanishes): L_1 = delta_0 delta_0^T. By the
    rank-nullity theorem the first cohomology dimension is

        dim H^1 = dim C^1 - rank(delta_0) = (E - rank(B)) * d

    Because every restriction map is a scalar multiple of I_d, the operator is
    the Kronecker lift of the scalar skeleton, so we compute rank on the scalar
    incidence matrix and multiply by d (exact, and avoids materialising the
    (E*d) x (V*d) matrix). The structural term ``E - rank(B)`` counts inconsistent
    edges plus genuine topological 1-cycles.

H^1 = 0 for an empty graph and for any tree of consistent edges; a single
contradictory edge between two records contributes a full stalk's worth of
first cohomology, so H^1 >= 1.
"""

from __future__ import annotations

import time
from fractions import Fraction
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Status contradiction predicate
# ---------------------------------------------------------------------------
# Two directly-related records are "contradictory" when one asserts the work is
# terminal/complete while the other asserts it is still live, or when the pair is
# an explicit mutually-exclusive lifecycle pair. This is a heuristic over the
# governed tracker.task status enum (see governance dictionary tracker.task) and
# is deliberately conservative: same status, empty status, or unknown statuses
# never register as contradictions.

_ACTIVE_STATUSES = frozenset({
    "open", "in-progress", "in progress", "coding-complete", "committed",
    "pr", "coding-updates", "active", "draft", "proposed", "in-review",
})

_TERMINAL_STATUSES = frozenset({
    "closed", "deployed", "deploy-success", "merged-main", "superseded",
    "archived", "done", "complete", "completed", "production",
})

# Explicit symmetric contradictory pairs (lower-cased), beyond the
# active-vs-terminal heuristic above.
_EXPLICIT_CONTRADICTORY_PAIRS = frozenset({
    frozenset({"open", "closed"}),
    frozenset({"active", "superseded"}),
    frozenset({"active", "archived"}),
    frozenset({"open", "deployed"}),
    frozenset({"in-progress", "closed"}),
    frozenset({"blocked", "deploy-success"}),
})


def is_contradictory(status_a: Optional[str], status_b: Optional[str]) -> bool:
    """Return True when two adjacent records hold contradictory status fields."""
    a = (status_a or "").strip().lower()
    b = (status_b or "").strip().lower()
    if not a or not b or a == b:
        return False
    pair = frozenset({a, b})
    if pair in _EXPLICIT_CONTRADICTORY_PAIRS:
        return True
    if (a in _ACTIVE_STATUSES and b in _TERMINAL_STATUSES) or (
        b in _ACTIVE_STATUSES and a in _TERMINAL_STATUSES
    ):
        return True
    return False


# ---------------------------------------------------------------------------
# Exact integer matrix rank (fraction-based Gaussian elimination)
# ---------------------------------------------------------------------------

def _matrix_rank(rows: Sequence[Sequence[float]], ncols: int) -> int:
    """Exact rank of a small matrix using Fraction arithmetic.

    Incidence-matrix entries live in {-1, 0, 1}, so Fraction elimination is exact
    (no floating-point rank ambiguity) and fast for the MAX_RESULTS-bounded
    subgraphs the graph_query_api returns.
    """
    if ncols <= 0:
        return 0
    matrix: List[List[Fraction]] = [
        [Fraction(value) for value in row] for row in rows if row
    ]
    if not matrix:
        return 0

    nrows = len(matrix)
    rank = 0
    pivot_row = 0
    for col in range(ncols):
        sel = None
        for r in range(pivot_row, nrows):
            if matrix[r][col] != 0:
                sel = r
                break
        if sel is None:
            continue
        matrix[pivot_row], matrix[sel] = matrix[sel], matrix[pivot_row]
        pivot_val = matrix[pivot_row][col]
        for r in range(nrows):
            if r != pivot_row and matrix[r][col] != 0:
                factor = matrix[r][col] / pivot_val
                pivot_ref = matrix[pivot_row]
                target = matrix[r]
                matrix[r] = [target[c] - factor * pivot_ref[c] for c in range(ncols)]
        pivot_row += 1
        rank += 1
        if pivot_row == nrows:
            break
    return rank


# ---------------------------------------------------------------------------
# Subgraph normalisation helpers
# ---------------------------------------------------------------------------

def _node_record_id(node: Dict[str, Any]) -> str:
    return str(node.get("record_id") or node.get("id") or "").strip()


def _node_status(node: Dict[str, Any]) -> str:
    return str(node.get("status") or "").strip()


def _embedding_dim(node: Dict[str, Any]) -> Optional[int]:
    emb = node.get("embedding")
    if isinstance(emb, (list, tuple)) and emb:
        return len(emb)
    return None


def _edge_endpoints(edge: Dict[str, Any]) -> Tuple[str, str, str]:
    start = edge.get("start") or edge.get("source") or edge.get("from") or ""
    end = edge.get("end") or edge.get("target") or edge.get("to") or ""
    etype = str(edge.get("type") or edge.get("rel_type") or "").strip().upper()
    return str(start).strip(), str(end).strip(), etype


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_sheaf_h1(
    nodes: Sequence[Dict[str, Any]],
    edges: Sequence[Dict[str, Any]],
    embedding_dim: Optional[int] = None,
    contradiction_fn: Callable[[Optional[str], Optional[str]], bool] = is_contradictory,
) -> Dict[str, Any]:
    """Compute the first sheaf cohomology dimension of a tracker subgraph.

    Args:
        nodes: list of node dicts (each with ``record_id`` and optional
            ``status`` / ``embedding``).
        edges: list of edge dicts (``start``/``end``/``type``).
        embedding_dim: explicit stalk dimension d; when None it is inferred from
            node ``embedding`` lengths (falling back to 1).
        contradiction_fn: predicate ``(status_a, status_b) -> bool`` flagging an
            inconsistent edge.

    Returns a dict with ``h1_dim`` (the headline scalar), ``h1_structural``,
    ``inconsistency_nodes``, ``inconsistency_edges``, ``embedding_dim``,
    ``node_count``, ``edge_count``, ``betti_1`` and ``computation_ms``.
    """
    started = time.perf_counter()

    index: Dict[str, int] = {}
    status_by_id: Dict[str, str] = {}
    inferred_dims: List[int] = []
    for node in nodes:
        rid = _node_record_id(node)
        if not rid:
            continue
        if rid not in index:
            index[rid] = len(index)
            status_by_id[rid] = _node_status(node)
        dim = _embedding_dim(node)
        if dim:
            inferred_dims.append(dim)

    vertex_count = len(index)

    if embedding_dim is not None:
        stalk_dim = int(embedding_dim)
    elif inferred_dims:
        stalk_dim = max(inferred_dims)
    else:
        stalk_dim = 1
    if stalk_dim < 1:
        stalk_dim = 1

    incidence_rows: List[List[int]] = []
    inconsistency_nodes: List[str] = []
    inconsistency_node_set: set = set()
    inconsistency_edges: List[Dict[str, str]] = []
    consistent_rows: List[List[int]] = []
    seen_edges: set = set()
    edge_count = 0

    for edge in edges:
        start, end, etype = _edge_endpoints(edge)
        if start not in index or end not in index:
            continue
        if start == end:
            # Self-loops are degenerate 1-cells; skip to avoid spurious cohomology.
            continue
        canon = (min(start, end), max(start, end), etype)
        if canon in seen_edges:
            continue
        seen_edges.add(canon)
        edge_count += 1

        contradictory = bool(contradiction_fn(status_by_id.get(start), status_by_id.get(end)))
        row = [0] * vertex_count
        if contradictory:
            inconsistency_edges.append({"start": start, "end": end, "type": etype})
            for endpoint in (start, end):
                if endpoint not in inconsistency_node_set:
                    inconsistency_node_set.add(endpoint)
                    inconsistency_nodes.append(endpoint)
            # Zeroed restriction maps -> all-zero coboundary row.
            incidence_rows.append(row)
        else:
            row[index[start]] = -1
            row[index[end]] = 1
            incidence_rows.append(row)
            consistent_rows.append(row)

    total_edges = len(incidence_rows)
    rank_full = _matrix_rank(incidence_rows, vertex_count)
    structural_h1 = total_edges - rank_full

    # betti_1 = topological 1-cycles among consistent edges only (diagnostic).
    rank_consistent = _matrix_rank(consistent_rows, vertex_count)
    betti_1 = len(consistent_rows) - rank_consistent

    h1_dim = structural_h1 * stalk_dim
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return {
        "h1_dim": int(h1_dim),
        "h1_structural": int(structural_h1),
        "betti_1": int(betti_1),
        "embedding_dim": int(stalk_dim),
        "node_count": int(vertex_count),
        "edge_count": int(edge_count),
        "incidence_rank": int(rank_full),
        "inconsistency_nodes": sorted(inconsistency_nodes),
        "inconsistency_edges": inconsistency_edges,
        "computation_ms": round(elapsed_ms, 3),
    }
