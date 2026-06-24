#!/usr/bin/env python3
"""ENC-TSK-H92 — OFFLINE FIT of a Moore-Penrose pseudoinverse-style de-correlating
encoding (ENC-TSK-H34 AC-2).

This is the OFFLINE half of a two-part encoding. It consumes:

  * the corpus embeddings (the H91 / vector_read node shape
    ``{"record_id", "record_type", "embedding": [float, ...]}``), and
  * the high-correlation pair set ``pairs.jsonl`` emitted by ENC-TSK-H91
    (one JSON object per line: ``{"a", "b", "a_type", "b_type", "cosine"}``),

and emits a single stored linear-transform artifact ``transform.json``. An
in-Lambda apply step (written separately) loads that artifact and computes
``q' = normalize(W @ q)`` in pure Python on the retrieval path, suppressing the
shared directions of near-duplicate embedding pairs to reduce Hebbian crosstalk.

Math (pseudoinverse-style decorrelation)
----------------------------------------
1. Build the "correlated pattern matrix" ``P`` (shape ``m x D``): the
   L2-normalized embeddings of the DISTINCT nodes appearing in ANY high-
   correlation pair. Pair endpoints missing from the corpus, and zero-norm
   vectors, are skipped.
2. SVD ``P = U S Vt`` (``numpy.linalg.svd``, ``full_matrices=False``). The right
   singular vectors ``Vt[k]`` are the principal directions of the correlated
   set; large singular values mark shared / redundant directions.
3. Choose rank ``r`` = the smallest number of top directions whose cumulative
   squared-singular-value energy reaches ``--energy`` (default 0.9), capped at
   ``--max-rank`` (default 64) and at ``min(m, D)``.
4. De-correlating transform::

       W = I - alpha * sum_{k=1..r} v_k v_k^T

   where ``v_k = Vt[k]`` (unit row) and ``alpha = --alpha`` (default 0.7). This
   is the bounded, retrieval-path form of the Personnaz pseudoinverse rule: it
   attenuates the dominant shared modes (the Moore-Penrose Σ⁺ analog) so that
   retrieval favors the distinctive component of near-duplicates. ``W`` is
   symmetric with eigenvalues in ``[1 - alpha, 1]``.

numpy is hard-required here: this fit runs in an offline tools venv, NEVER in the
Lambda. The Lambda apply path is pure Python and only reads ``W`` as a plain
``D x D`` list of lists of finite floats.

The artifact contract is documented in ``write_transform`` / ``build_artifact``.
``--generated-at`` is the ONLY source of a timestamp; ``datetime.now()`` is never
called (at import or runtime) — the field is left ``None`` when not supplied.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Contract constants — mirror the H91 / vector_read node shape and pair schema.
# ---------------------------------------------------------------------------
EMBEDDING_PROPERTY = "embedding"
ARTIFACT_VERSION = "h92.v1"

DEFAULT_ALPHA = 0.7
DEFAULT_ENERGY = 0.9
DEFAULT_MAX_RANK = 64
DEFAULT_OUT = "./transform.json"


# ===========================================================================
# READ layer — corpus + pairs loaders
# ===========================================================================
def _coerce_nodes(payload: Any) -> List[Dict[str, Any]]:
    """Accept either ``{"nodes": [...]}`` or a bare list of node dicts (the
    H91 / vector_read corpus shapes). Non-dict members are dropped.
    """
    if isinstance(payload, dict):
        raw = payload.get("nodes", [])
    elif isinstance(payload, list):
        raw = payload
    else:
        return []
    return [n for n in raw if isinstance(n, dict)]


def load_corpus_from_file(path: str) -> List[Dict[str, Any]]:
    """Load the corpus from a JSON file (``{"nodes":[...]}`` or a bare list)."""
    with open(path, "r", encoding="utf-8") as fh:
        return _coerce_nodes(json.load(fh))


def load_pairs_from_file(path: str) -> List[Dict[str, Any]]:
    """Load the H91 ``pairs.jsonl`` (one JSON object per line). Blank lines are
    skipped; only objects carrying both an ``a`` and a ``b`` endpoint are kept.
    """
    pairs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("a") is not None and obj.get("b") is not None:
                pairs.append(obj)
    return pairs


def correlated_record_ids(pairs: Sequence[Dict[str, Any]]) -> List[str]:
    """The DISTINCT record_ids appearing in any high-correlation pair, in stable
    first-seen order (so the pattern matrix is deterministic given the pairs).
    """
    seen: Dict[str, None] = {}
    for p in pairs:
        for key in ("a", "b"):
            rid = p.get(key)
            if rid is not None and rid not in seen:
                seen[rid] = None
    return list(seen.keys())


# ===========================================================================
# COMPUTE layer
# ===========================================================================
def _normalize_rows(mat: np.ndarray) -> np.ndarray:
    """L2-normalize each row; zero-norm rows are left as zero rows."""
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    safe = np.where(norms > 0.0, norms, 1.0)
    return mat / safe


def build_pattern_matrix(
    nodes: Sequence[Dict[str, Any]],
    pairs: Sequence[Dict[str, Any]],
) -> Tuple[np.ndarray, int, List[str]]:
    """Assemble the correlated pattern matrix ``P`` (shape ``m x D``).

    Rows are the L2-normalized embeddings of the DISTINCT nodes that appear in
    any pair. Endpoints missing from the corpus are skipped; zero-norm vectors
    are skipped; only embeddings matching the modal dimension ``D`` are kept.

    Returns ``(P, D, used_ids)`` where ``used_ids`` is the parallel list of the
    record_ids actually contributing a row. Raises ``ValueError`` when no usable
    correlated vector remains (caller surfaces this to the user).
    """
    by_id: Dict[str, List[float]] = {}
    for n in nodes:
        rid = n.get("record_id")
        emb = n.get(EMBEDDING_PROPERTY)
        if rid is None or not emb or not isinstance(emb, (list, tuple)):
            continue
        try:
            vec = [float(x) for x in emb]
        except (TypeError, ValueError):
            continue
        if vec:
            by_id[rid] = vec  # last write wins on duplicate record_ids

    if not by_id:
        raise ValueError("corpus contains no usable numeric embeddings")

    # Modal embedding dimension across the corpus — the canonical D.
    dims: Dict[int, int] = {}
    for vec in by_id.values():
        dims[len(vec)] = dims.get(len(vec), 0) + 1
    dim = max(dims.items(), key=lambda kv: (kv[1], kv[0]))[0]

    rows: List[List[float]] = []
    used_ids: List[str] = []
    for rid in correlated_record_ids(pairs):
        vec = by_id.get(rid)
        if vec is None or len(vec) != dim:
            continue
        if not any(abs(x) > 0.0 for x in vec):  # zero-norm vector
            continue
        rows.append(vec)
        used_ids.append(rid)

    if not rows:
        raise ValueError(
            "no correlated pair endpoint resolved to a usable corpus embedding"
        )

    P = _normalize_rows(np.asarray(rows, dtype=np.float64))
    return P, dim, used_ids


def choose_rank(
    singular_values: np.ndarray,
    energy: float,
    max_rank: int,
) -> Tuple[int, float]:
    """Pick the rank ``r`` = smallest count of leading directions whose cumulative
    squared-singular-value energy reaches ``energy``, capped at ``max_rank`` and
    at ``len(singular_values)``.

    Returns ``(r, captured)`` where ``captured`` is the fraction of total squared
    energy held by the chosen ``r`` directions. ``r >= 1`` whenever any nonzero
    singular value exists.
    """
    sv = np.asarray(singular_values, dtype=np.float64)
    sq = sv ** 2
    total = float(sq.sum())
    available = int(sv.shape[0])
    cap = max(0, min(int(max_rank), available))
    if total <= 0.0 or cap == 0:
        return 0, 0.0

    cum = np.cumsum(sq)
    target = float(energy) * total
    r = available
    for k in range(1, available + 1):
        if cum[k - 1] >= target:
            r = k
            break
    r = max(1, min(r, cap))
    captured = float(cum[r - 1] / total)
    return r, captured


def build_transform(
    P: np.ndarray,
    dim: int,
    alpha: float,
    energy: float,
    max_rank: int,
) -> Tuple[np.ndarray, int, Dict[str, Any]]:
    """Core fit. Given the correlated pattern matrix ``P`` (``m x D``), compute
    the de-correlating transform ``W = I - alpha * sum_k v_k v_k^T`` over the
    top-``r`` right singular vectors.

    Returns ``(W, r, svd_meta)`` where ``W`` is ``D x D``, symmetric, with
    eigenvalues in ``[1 - alpha, 1]``. ``svd_meta`` carries ``energy_captured``
    and the leading singular values for the artifact ``fit_meta``.
    """
    # full_matrices=False: Vt has shape (min(m, D), D); rows are unit directions.
    _U, S, Vt = np.linalg.svd(P, full_matrices=False)
    r, captured = choose_rank(S, energy, max_rank)

    W = np.eye(dim, dtype=np.float64)
    for k in range(r):
        v = Vt[k]
        nrm = float(np.linalg.norm(v))
        if nrm <= 0.0:
            continue
        v = v / nrm  # defensive re-normalization (SVD rows are already unit)
        W = W - alpha * np.outer(v, v)

    svd_meta = {
        "energy_captured": captured,
        "top_singular_values": [float(x) for x in S[: max(r, 1)].tolist()],
    }
    return W, r, svd_meta


def _finite_matrix_to_lists(W: np.ndarray) -> List[List[float]]:
    """Convert ``W`` to nested plain-``float`` lists, asserting all entries are
    finite (the Lambda apply path requires a clean ``D x D`` list-of-lists).
    """
    if not np.all(np.isfinite(W)):
        raise ValueError("transform W contains non-finite entries")
    return [[float(x) for x in row] for row in W.tolist()]


# ===========================================================================
# Artifact assembly + SINK
# ===========================================================================
def build_artifact(
    W: np.ndarray,
    dim: int,
    alpha: float,
    rank: int,
    fit_meta: Dict[str, Any],
    pairs_source: str,
    generated_at: Optional[str],
) -> Dict[str, Any]:
    """Assemble the ``transform.json`` payload (the in-Lambda apply contract).

    Schema::

        {
          "version": "h92.v1",
          "dim": <int D>,
          "alpha": <float in [0, 1]>,
          "rank": <int r>,
          "W": [[float, ... D], ... D],         # row-major D x D
          "fit_meta": {"corpus_size", "correlated_set_size", "num_pairs",
                       "energy_captured", "top_singular_values"},
          "pairs_source": "<path or note>",
          "generated_at": <null or ISO string>
        }
    """
    return {
        "version": ARTIFACT_VERSION,
        "dim": int(dim),
        "alpha": float(alpha),
        "rank": int(rank),
        "W": _finite_matrix_to_lists(W),
        "fit_meta": fit_meta,
        "pairs_source": pairs_source,
        "generated_at": generated_at,
    }


def fit_artifact(
    nodes: Sequence[Dict[str, Any]],
    pairs: Sequence[Dict[str, Any]],
    *,
    alpha: float = DEFAULT_ALPHA,
    energy: float = DEFAULT_ENERGY,
    max_rank: int = DEFAULT_MAX_RANK,
    pairs_source: str = "<in-memory>",
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """End-to-end fit: corpus + pairs -> ``transform.json`` dict (not written).

    This is the single entrypoint the unit test and ``main`` both drive, so the
    artifact emitted offline is byte-for-byte the one ``main`` writes.
    """
    if not 0.0 <= alpha <= 1.0:
        raise ValueError(f"--alpha must be in [0, 1]; got {alpha!r}")
    if not 0.0 < energy <= 1.0:
        raise ValueError(f"--energy must be in (0, 1]; got {energy!r}")

    P, dim, used_ids = build_pattern_matrix(nodes, pairs)
    W, rank, svd_meta = build_transform(P, dim, alpha, energy, max_rank)

    fit_meta = {
        "corpus_size": int(len(nodes)),
        "correlated_set_size": int(len(used_ids)),
        "num_pairs": int(len(pairs)),
        "energy_captured": svd_meta["energy_captured"],
        "top_singular_values": svd_meta["top_singular_values"],
    }
    return build_artifact(
        W, dim, alpha, rank, fit_meta, pairs_source, generated_at
    )


def write_transform(artifact: Dict[str, Any], out_path: str) -> str:
    """SINK. Write the artifact to ``out_path`` as pretty JSON. Returns the path
    written. Creates parent directories as needed.
    """
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2, sort_keys=False)
        fh.write("\n")
    return out_path


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fit_encoding_h92",
        description=(
            "Offline fit of the H92 pseudoinverse-style de-correlating "
            "transform. Emits transform.json for the in-Lambda apply step."
        ),
    )
    p.add_argument(
        "--corpus", required=True,
        help="Path to corpus JSON ({\"nodes\":[...]} or a bare node list).",
    )
    p.add_argument(
        "--pairs", required=True,
        help="Path to the H91 pairs.jsonl (one JSON object per line).",
    )
    p.add_argument(
        "--alpha", type=float, default=DEFAULT_ALPHA,
        help="Decorrelation strength in [0, 1] (default %(default)s).",
    )
    p.add_argument(
        "--energy", type=float, default=DEFAULT_ENERGY,
        help="Cumulative squared-singular-value energy target in (0, 1] "
             "(default %(default)s).",
    )
    p.add_argument(
        "--max-rank", type=int, default=DEFAULT_MAX_RANK,
        help="Maximum number of suppressed shared directions "
             "(default %(default)s).",
    )
    p.add_argument(
        "--out", default=DEFAULT_OUT,
        help="Output artifact path (default %(default)s).",
    )
    p.add_argument(
        "--generated-at", default=None,
        help="Optional ISO-8601 timestamp recorded in the artifact. "
             "datetime.now() is NEVER called; left null when omitted.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    nodes = load_corpus_from_file(args.corpus)
    pairs = load_pairs_from_file(args.pairs)

    artifact = fit_artifact(
        nodes,
        pairs,
        alpha=args.alpha,
        energy=args.energy,
        max_rank=args.max_rank,
        pairs_source=args.pairs,
        generated_at=args.generated_at,
    )
    out_path = write_transform(artifact, args.out)

    fm = artifact["fit_meta"]
    print(
        "[H92] fit complete: "
        f"dim={artifact['dim']} alpha={artifact['alpha']} rank={artifact['rank']} "
        f"corpus={fm['corpus_size']} correlated_set={fm['correlated_set_size']} "
        f"pairs={fm['num_pairs']} energy_captured={fm['energy_captured']:.4f} "
        f"-> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
