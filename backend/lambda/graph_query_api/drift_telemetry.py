"""ENC-FTR-087 Phase 1 — Wave-Close Drift Telemetry.

Computes two per-wave drift metrics on every wave-close event and persists one
record per wave to the ``enceladus-drift-telemetry`` DynamoDB time-series table
(per-project series via the ``project-timestamp-index`` GSI):

  * ``d_centroid_L2`` (F13 Definition F13.5) — the L2 distance between the mean
    Titan V2 embedding of the H (hot-tier / current) record set and the mean
    embedding of the V (full / prior) record set. Measures how far the demand
    centroid has drifted across the wave.

  * ``d_spectral`` (F13 Definition F13.4) — the Grassmannian chordal distance
    between the top-k Fiedler subspaces of two graph Laplacians (H vs V). The
    Fiedler subspace is obtained from ``tracker.graph_laplacian`` (ENC-FTR-088)
    when a ``laplacian_fn`` hook is injected, otherwise computed inline from the
    supplied adjacency via a self-contained symmetric eigensolver (Jacobi).

The schema carries ``spurious_attractor_rate`` and ``re_traversal_rate`` as
explicit null stubs — the wiring points for ENC-FTR-105 (Spurious-Attractor /
Hallucination Telemetry, AC-7/AC-8) which will populate them in a later phase.

This module is pure-Python and dependency-free (no numpy, no boto3 import at
module load). The DynamoDB client is dependency-injected so the wave-close path
is unit-testable without AWS. OGTM (ENC-FTR-066): drift telemetry writes a
DynamoDB time series only — it introduces NO new Neo4j edge type — so the OGTM
edge-traversability gate is not applicable (mirrors the FTR-082 pathway
telemetry precedent).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

# Schema version stamped on every emitted record.
DRIFT_TELEMETRY_SCHEMA = "enceladus.drift.telemetry.v1"

# Default Fiedler-subspace dimension for d_spectral (AC: d_spectral(H,V;k=3)).
DEFAULT_SPECTRAL_K = 3

Vector = Sequence[float]
Matrix = Sequence[Sequence[float]]


# ---------------------------------------------------------------------------
# d_centroid_L2 — demand-centroid drift (F13.5)
# ---------------------------------------------------------------------------

def compute_centroid(vectors: Sequence[Vector]) -> List[float]:
    """Mean (element-wise) of a non-empty set of equal-length vectors.

    Raises ValueError on an empty set or ragged dimensions so a malformed
    wave-close payload fails loud rather than emitting a meaningless centroid.
    """
    if not vectors:
        raise ValueError("compute_centroid requires at least one vector")
    dim = len(vectors[0])
    if dim == 0:
        raise ValueError("compute_centroid requires non-empty vectors")
    acc = [0.0] * dim
    for vec in vectors:
        if len(vec) != dim:
            raise ValueError("compute_centroid requires uniform vector dimension")
        for i, component in enumerate(vec):
            acc[i] += float(component)
    n = float(len(vectors))
    return [c / n for c in acc]


def l2_distance(a: Vector, b: Vector) -> float:
    """Euclidean (L2) distance between two equal-length vectors."""
    if len(a) != len(b):
        raise ValueError("l2_distance requires equal-length vectors")
    return math.sqrt(sum((float(x) - float(y)) ** 2 for x, y in zip(a, b)))


def d_centroid_l2(h_embeddings: Sequence[Vector],
                  v_embeddings: Sequence[Vector]) -> float:
    """F13.5 — L2 distance between the mean embedding of the H set and the mean
    embedding of the V set."""
    return l2_distance(compute_centroid(h_embeddings), compute_centroid(v_embeddings))


# ---------------------------------------------------------------------------
# d_spectral — Grassmannian chordal distance over top-k Fiedler subspace (F13.4)
# ---------------------------------------------------------------------------

def normalized_laplacian(adjacency: Matrix) -> List[List[float]]:
    """Symmetric normalized graph Laplacian L = I - D^-1/2 A D^-1/2.

    Isolated nodes (degree 0) contribute an identity row/column (their D^-1/2 is
    taken as 0), keeping L well-defined and symmetric.
    """
    n = len(adjacency)
    for row in adjacency:
        if len(row) != n:
            raise ValueError("normalized_laplacian requires a square adjacency matrix")
    degrees = [sum(float(adjacency[i][j]) for j in range(n)) for i in range(n)]
    dinv_sqrt = [(1.0 / math.sqrt(d)) if d > 0 else 0.0 for d in degrees]
    lap: List[List[float]] = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            norm = dinv_sqrt[i] * dinv_sqrt[j] * float(adjacency[i][j])
            lap[i][j] = (1.0 if i == j else 0.0) - norm
    # Symmetrize to wash out floating-point asymmetry from the product above.
    for i in range(n):
        for j in range(i + 1, n):
            avg = 0.5 * (lap[i][j] + lap[j][i])
            lap[i][j] = lap[j][i] = avg
    return lap


def jacobi_eigh(matrix: Matrix, max_sweeps: int = 100,
                tol: float = 1e-12) -> tuple[List[float], List[List[float]]]:
    """Eigen-decomposition of a real symmetric matrix via cyclic Jacobi rotation.

    Returns (eigenvalues, eigenvectors) where eigenvectors is column-major:
    ``eigenvectors[i][c]`` is component i of the c-th eigenvector. Suitable for
    the small dense Laplacians produced by a wave's record set. Eigenpairs are
    returned sorted by ascending eigenvalue.
    """
    n = len(matrix)
    a = [[float(matrix[i][j]) for j in range(n)] for i in range(n)]
    # Eigenvector accumulator starts as identity.
    v = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    if n == 1:
        return [a[0][0]], [[1.0]]

    for _ in range(max_sweeps):
        off = 0.0
        for p in range(n):
            for q in range(p + 1, n):
                off += a[p][q] * a[p][q]
        if off <= tol:
            break
        for p in range(n):
            for q in range(p + 1, n):
                apq = a[p][q]
                if abs(apq) <= tol:
                    continue
                app = a[p][p]
                aqq = a[q][q]
                phi = 0.5 * math.atan2(2.0 * apq, aqq - app)
                c = math.cos(phi)
                s = math.sin(phi)
                for k in range(n):
                    akp = a[k][p]
                    akq = a[k][q]
                    a[k][p] = c * akp - s * akq
                    a[k][q] = s * akp + c * akq
                for k in range(n):
                    apk = a[p][k]
                    aqk = a[q][k]
                    a[p][k] = c * apk - s * aqk
                    a[q][k] = s * apk + c * aqk
                for k in range(n):
                    vkp = v[k][p]
                    vkq = v[k][q]
                    v[k][p] = c * vkp - s * vkq
                    v[k][q] = s * vkp + c * vkq

    eigvals = [a[i][i] for i in range(n)]
    order = sorted(range(n), key=lambda idx: eigvals[idx])
    sorted_vals = [eigvals[i] for i in order]
    sorted_vecs = [[v[row][i] for i in order] for row in range(n)]
    return sorted_vals, sorted_vecs


def fiedler_subspace(adjacency: Matrix, k: int = DEFAULT_SPECTRAL_K) -> List[List[float]]:
    """Top-k Fiedler subspace of a graph (F13.4): the k eigenvectors of the
    symmetric normalized Laplacian with the smallest *non-trivial* eigenvalues
    (skipping the single trivial near-zero eigenpair).

    Returns a column-major orthonormal basis: ``columns[c]`` is the c-th basis
    vector of length n. Requires n >= k + 1.
    """
    if k < 1:
        raise ValueError("fiedler_subspace requires k >= 1")
    n = len(adjacency)
    if n < k + 1:
        raise ValueError(
            f"fiedler_subspace requires at least k+1={k + 1} nodes, got {n}"
        )
    lap = normalized_laplacian(adjacency)
    _vals, vecs = jacobi_eigh(lap)
    # Skip index 0 (the trivial eigenpair) and take the next k eigenvectors.
    columns: List[List[float]] = []
    for c in range(1, k + 1):
        columns.append([vecs[row][c] for row in range(n)])
    return columns


def _frobenius_inner_sq(u_cols: Sequence[Vector], v_cols: Sequence[Vector]) -> float:
    """||U^T V||_F^2 for column-major orthonormal bases U and V over the same
    ambient dimension."""
    total = 0.0
    for u in u_cols:
        for v in v_cols:
            dot = sum(float(a) * float(b) for a, b in zip(u, v))
            total += dot * dot
    return total


def grassmann_chordal_distance(u_cols: Sequence[Vector],
                               v_cols: Sequence[Vector]) -> float:
    """F13.4 Grassmannian chordal distance between two k-dimensional subspaces
    given as column-major orthonormal bases of the same ambient dimension:

        d_chordal(U, V) = sqrt( k - ||U^T V||_F^2 )

    Numerically clamped to >= 0 to absorb floating-point overshoot.
    """
    if not u_cols or not v_cols:
        raise ValueError("grassmann_chordal_distance requires non-empty bases")
    if len(u_cols) != len(v_cols):
        raise ValueError("grassmann_chordal_distance requires equal subspace rank")
    ambient = len(u_cols[0])
    for col in list(u_cols) + list(v_cols):
        if len(col) != ambient:
            raise ValueError(
                "grassmann_chordal_distance requires a common ambient dimension"
            )
    k = len(u_cols)
    overlap = _frobenius_inner_sq(u_cols, v_cols)
    return math.sqrt(max(0.0, k - overlap))


def d_spectral(
    *,
    k: int = DEFAULT_SPECTRAL_K,
    h_fiedler: Optional[Sequence[Vector]] = None,
    v_fiedler: Optional[Sequence[Vector]] = None,
    h_adjacency: Optional[Matrix] = None,
    v_adjacency: Optional[Matrix] = None,
    laplacian_fn: Optional[Callable[[Matrix, int], Sequence[Vector]]] = None,
) -> float:
    """d_spectral(H, V; k) — Grassmannian chordal distance between the top-k
    Fiedler subspaces of H and V.

    Resolution order for each subspace:
      1. Precomputed ``*_fiedler`` orthonormal column bases, if supplied.
      2. ``laplacian_fn(adjacency, k)`` hook — the ENC-FTR-088 ``tracker.
         graph_laplacian`` Fiedler-eigenvector accessor when injected.
      3. Inline ``fiedler_subspace(adjacency, k)`` self-contained fallback.
    """
    def _resolve(fiedler, adjacency, label):
        if fiedler is not None:
            return fiedler
        if adjacency is None:
            raise ValueError(f"d_spectral requires {label} fiedler vectors or adjacency")
        if laplacian_fn is not None:
            return laplacian_fn(adjacency, k)
        return fiedler_subspace(adjacency, k)

    u_cols = _resolve(h_fiedler, h_adjacency, "H")
    v_cols = _resolve(v_fiedler, v_adjacency, "V")
    return grassmann_chordal_distance(u_cols, v_cols)


# ---------------------------------------------------------------------------
# Record assembly + DynamoDB emission
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """UTC ISO-8601 timestamp with microsecond precision (strictly increasing
    across rapid successive calls, so a per-project series stays monotonic)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_drift_record(
    *,
    wave_id: str,
    project_id: str,
    d_centroid_L2: Optional[float],
    d_spectral_value: Optional[float],
    k: int = DEFAULT_SPECTRAL_K,
    prev_wave_id: Optional[str] = None,
    n_h: Optional[int] = None,
    n_v: Optional[int] = None,
    timestamp: Optional[str] = None,
    spurious_attractor_rate: Optional[float] = None,
    re_traversal_rate: Optional[float] = None,
) -> Dict[str, Any]:
    """Assemble the canonical wave-close drift record.

    ``spurious_attractor_rate`` and ``re_traversal_rate`` default to None (null
    stubs) — the ENC-FTR-105 wiring slots.
    """
    if not wave_id:
        raise ValueError("build_drift_record requires a wave_id")
    if not project_id:
        raise ValueError("build_drift_record requires a project_id")
    return {
        "schema": DRIFT_TELEMETRY_SCHEMA,
        "wave_id": wave_id,
        "project_id": project_id,
        "timestamp": timestamp or _utc_now_iso(),
        "d_centroid_L2": d_centroid_L2,
        "d_spectral": d_spectral_value,
        "d_spectral_k": k,
        "prev_wave_id": prev_wave_id,
        "n_h": n_h,
        "n_v": n_v,
        # ENC-FTR-105 wiring slots — null stubs in Phase 1.
        "spurious_attractor_rate": spurious_attractor_rate,
        "re_traversal_rate": re_traversal_rate,
    }


def _to_attribute_value(value: Any) -> Dict[str, Any]:
    """Marshal a Python scalar into a DynamoDB low-level AttributeValue.

    Numbers are stored as DynamoDB N (string-encoded, avoiding any float/Decimal
    coupling); None becomes a NULL attribute (the FTR-105 stub representation);
    booleans become BOOL; everything else is stringified to S.
    """
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, (int, float)):
        return {"N": repr(value) if isinstance(value, float) else str(value)}
    return {"S": str(value)}


def to_ddb_item(record: Dict[str, Any]) -> Dict[str, Any]:
    """Marshal a drift record dict into a DynamoDB low-level ``Item`` map."""
    return {key: _to_attribute_value(val) for key, val in record.items()}


def emit_drift_record(ddb_client: Any, table_name: str,
                      record: Dict[str, Any]) -> Dict[str, Any]:
    """Persist one wave-close drift record via ``put_item`` on the supplied
    low-level DynamoDB client. The client is injected so the wave-close path is
    testable without AWS."""
    if not table_name:
        raise ValueError("emit_drift_record requires a table_name")
    item = to_ddb_item(record)
    ddb_client.put_item(TableName=table_name, Item=item)
    return record


def compute_and_emit_wave_close_drift(
    *,
    ddb_client: Any,
    table_name: str,
    project_id: str,
    wave_id: str,
    prev_wave_id: Optional[str] = None,
    h_embeddings: Optional[Sequence[Vector]] = None,
    v_embeddings: Optional[Sequence[Vector]] = None,
    h_adjacency: Optional[Matrix] = None,
    v_adjacency: Optional[Matrix] = None,
    h_fiedler: Optional[Sequence[Vector]] = None,
    v_fiedler: Optional[Sequence[Vector]] = None,
    k: int = DEFAULT_SPECTRAL_K,
    laplacian_fn: Optional[Callable[[Matrix, int], Sequence[Vector]]] = None,
    timestamp: Optional[str] = None,
    spurious_attractor_rate: Optional[float] = None,
    re_traversal_rate: Optional[float] = None,
) -> Dict[str, Any]:
    """End-to-end wave-close handler: compute d_centroid_L2 + d_spectral and
    persist a single record to the drift-telemetry table.

    Either metric independently degrades to ``None`` (rather than raising) when
    its inputs are absent — d_centroid may ship ahead of d_spectral per the
    ENC-FTR-087 dependency note (gated on tracker.graph_laplacian / ENC-FTR-088).
    """
    d_cent: Optional[float] = None
    if h_embeddings and v_embeddings:
        d_cent = d_centroid_l2(h_embeddings, v_embeddings)

    d_spec: Optional[float] = None
    have_spectral = (h_fiedler is not None and v_fiedler is not None) or (
        h_adjacency is not None and v_adjacency is not None
    )
    if have_spectral:
        d_spec = d_spectral(
            k=k,
            h_fiedler=h_fiedler,
            v_fiedler=v_fiedler,
            h_adjacency=h_adjacency,
            v_adjacency=v_adjacency,
            laplacian_fn=laplacian_fn,
        )

    record = build_drift_record(
        wave_id=wave_id,
        project_id=project_id,
        d_centroid_L2=d_cent,
        d_spectral_value=d_spec,
        k=k,
        prev_wave_id=prev_wave_id,
        n_h=len(h_embeddings) if h_embeddings is not None else None,
        n_v=len(v_embeddings) if v_embeddings is not None else None,
        timestamp=timestamp,
        spurious_attractor_rate=spurious_attractor_rate,
        re_traversal_rate=re_traversal_rate,
    )
    emit_drift_record(ddb_client, table_name, record)
    return record
