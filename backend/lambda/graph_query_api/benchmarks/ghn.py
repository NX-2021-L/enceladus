"""Graph-Hopfield-Network (GHN) reference energy-descent scorer.

ENC-TSK-I99 / ENC-FTR-104 Ph2 AC-3. EVALUATION-ONLY reference implementation —
this is NOT wired into the production retrieval path. It is an *alternate*
scoring path benchmarked head-to-head against the production RRF fusion
(``lambda_function._rrf_fuse``) in run_benchmark.py.

Relationship to Ph1 (ENC-TSK-I98 / energy_function.py)
------------------------------------------------------
Ph1 defined a *static, per-candidate* retrieval energy

    E(x)_i = E_vector_i + lambda_graph * E_PPR_i + lambda_kw * E_keyword_i        (Ph1)

which is a disagreement score (lower = better). Ph1's E(x) has no coupling
between candidates — each candidate's energy is independent of the others, so
it cannot propagate relevance mass across graph hops. That is exactly the
signal a *modern Hopfield network* (Ramsauer et al. 2020, "Hopfield Networks is
All You Need") adds and exactly what multi-hop QA needs: a bridge/2nd-hop
supporting fact whose own vector/keyword similarity to the question is weak, but
which is graph-adjacent to a strongly-matching 1st-hop fact, should accumulate
activation from that neighbour.

Ph2 promotes the Ph1 static energy to a coupled Hopfield energy over an
activation distribution x on the candidate simplex (x_i >= 0, sum_i x_i = 1):

    E_GHN(x) = - sum_i h_i x_i                       (align with Ph1 field)
               - (lambda_graph / 2) * xᵀ W_psd x     (graph associative coupling)
               + (1 / beta) * sum_i x_i ln x_i        (entropic / temperature term)

where
  * h_i = - E(x)_i   is the per-candidate external field: the *negated* Ph1
    energy (Ph1 low-energy == high field == attractive). h is computed by
    energy_function.compute_retrieval_energy (imported read-only), so the two
    phases share one energy definition and one pair of lambda weights.
  * W is the symmetric candidate-candidate weighted graph adjacency built from
    the same per-edge-type weights the production graph signal uses
    (lambda_function.GRAPH_EDGE_WEIGHTS). W_ij > 0 iff candidates i, j are
    joined by a governed edge (optionally within 2 hops, with decay).
  * W_psd = W + tau*I with tau = max_i sum_j W_ij (Gershgorin bound; W has zero
    diagonal and is non-negative, so every eigenvalue lies in [-tau, tau] and
    W_psd is positive-semidefinite). See "Why the PSD shift" below.
  * beta > 0 is the inverse temperature (Hopfield separation / storage sharpness).

Energy-descent update rule (the AC-3 deliverable)
-------------------------------------------------
    x^{t+1}_i = softmax_i( beta * ( h_i + lambda_graph * (W_psd x^t)_i ) )

This is the exact concave-convex procedure (CCCP) step for E_GHN under the split
E_GHN = E_vex + E_cave with
    E_vex(x)  = (1/beta) sum x_i ln x_i - sum h_i x_i        (convex on the simplex)
    E_cave(x) = -(lambda_graph/2) xᵀ W_psd x                 (concave, since W_psd is PSD)
CCCP solves  grad E_vex(x^{t+1}) = -grad E_cave(x^t), i.e.
    (1/beta)(ln x_i + 1) - h_i = lambda_graph (W_psd x^t)_i + c
whose simplex-constrained solution is the softmax above. CCCP guarantees
    E_GHN(x^{t+1}) <= E_GHN(x^t)   for every step
(monotone energy descent), which test_ghn.py asserts numerically. The iterate
converges to a stationary activation distribution; candidates are ranked by
final activation x_i (descending).

Why the PSD shift
-----------------
W (adjacency) is symmetric but generally indefinite, so -(lambda_graph/2) xᵀW x
is not concave and the plain softmax step is not a guaranteed descent step.
Adding tau*I makes W_psd PSD, restoring the CCCP descent guarantee. The shift
adds a uniform self-coupling lambda_graph*tau*x_i to every candidate's field —
a rank-preserving "rich get richer" sharpening identical across candidates — so
it does not distort the *relative* graph message-passing structure that
distinguishes multi-hop-reachable candidates. It only affects the temperature at
which the network sharpens, which beta already controls.

Pure-Python, dependency-free (no numpy) to match the energy_function.py /
drift_telemetry.py precedent in this package and keep the unit tests runnable
with no third-party install. Candidate sets are small (tens to low hundreds), so
the O(iters * N^2) dense update is negligible.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "DEFAULT_BETA",
    "DEFAULT_MAX_ITERS",
    "DEFAULT_TOL",
    "softmax",
    "psd_shift",
    "ghn_energy",
    "ghn_descent",
    "rank_candidates",
    "GHNResult",
]

# Inverse temperature. Chosen so the softmax meaningfully separates candidates
# whose Ph1 fields differ by O(0.1) (a typical E(x) gap) without collapsing to a
# one-hot argmax in a single step (which would defeat multi-hop propagation).
DEFAULT_BETA: float = 8.0
DEFAULT_MAX_ITERS: int = 50
DEFAULT_TOL: float = 1e-9
# Activation quantum for tie detection in rank_candidates: activations closer
# than this are treated as tied and fall through to the static-field secondary
# key. ~1e-6 is well above float noise yet far below the smallest meaningful
# activation gap the softmax produces for a differentiated candidate.
ACTIVATION_TIE_EPS: float = 1e-6


def softmax(logits: Sequence[float]) -> List[float]:
    """Numerically-stable softmax over a 1-D sequence. Returns a probability
    distribution (non-negative, sums to 1). Empty input -> empty list."""
    if not logits:
        return []
    m = max(logits)
    exps = [math.exp(v - m) for v in logits]
    z = sum(exps)
    if z <= 0.0:  # degenerate; fall back to uniform
        n = len(logits)
        return [1.0 / n] * n
    return [e / z for e in exps]


def _matvec(mat: Sequence[Sequence[float]], vec: Sequence[float]) -> List[float]:
    return [sum(row[j] * vec[j] for j in range(len(vec))) for row in mat]


def psd_shift(w: Sequence[Sequence[float]]) -> Tuple[List[List[float]], float]:
    """Return (W_psd, tau) where W_psd = W + tau*I is positive-semidefinite.

    tau = max row sum of |W| (Gershgorin). W is expected symmetric with zero
    diagonal and non-negative entries; every eigenvalue then lies in [-tau, tau]
    so W + tau*I >= 0. tau == 0 (no edges) leaves W unchanged.
    """
    n = len(w)
    if n == 0:
        return [], 0.0
    tau = 0.0
    for i in range(n):
        row_sum = sum(abs(w[i][j]) for j in range(n))
        if row_sum > tau:
            tau = row_sum
    w_psd = [[w[i][j] + (tau if i == j else 0.0) for j in range(n)] for i in range(n)]
    return w_psd, tau


def ghn_energy(
    x: Sequence[float],
    h: Sequence[float],
    w_psd: Sequence[Sequence[float]],
    beta: float,
    lambda_graph: float,
) -> float:
    """Evaluate E_GHN(x) (see module docstring). Uses W_psd (already PSD-shifted).
    The entropy term uses x_i ln x_i with the x_i == 0 limit taken as 0."""
    field_term = -sum(h_i * x_i for h_i, x_i in zip(h, x))
    wx = _matvec(w_psd, x)
    coupling_term = -0.5 * lambda_graph * sum(x_i * wx_i for x_i, wx_i in zip(x, wx))
    entropy_term = 0.0
    for x_i in x:
        if x_i > 0.0:
            entropy_term += x_i * math.log(x_i)
    entropy_term /= beta
    return field_term + coupling_term + entropy_term


class GHNResult:
    """Outcome of a GHN energy descent."""

    __slots__ = ("activation", "energy_trace", "iterations", "converged", "tau")

    def __init__(
        self,
        activation: List[float],
        energy_trace: List[float],
        iterations: int,
        converged: bool,
        tau: float,
    ) -> None:
        self.activation = activation
        self.energy_trace = energy_trace
        self.iterations = iterations
        self.converged = converged
        self.tau = tau


def ghn_descent(
    h: Sequence[float],
    w: Sequence[Sequence[float]],
    *,
    beta: float = DEFAULT_BETA,
    lambda_graph: float = 0.5,
    max_iters: int = DEFAULT_MAX_ITERS,
    tol: float = DEFAULT_TOL,
    x0: Optional[Sequence[float]] = None,
) -> GHNResult:
    """Run the graph-coupled Hopfield energy descent.

    Args:
      h:            per-candidate external field (h_i = -E_Ph1(x)_i), length N.
      w:            NxN symmetric non-negative adjacency (zero diagonal).
      beta:         inverse temperature.
      lambda_graph: graph coupling strength (reuses the FTR-104 lambda_graph).
      max_iters:    hard cap on CCCP iterations.
      tol:          L1 convergence tolerance on the activation update.
      x0:           optional initial distribution; defaults to field-seeded
                    softmax(beta*h) so a zero-coupling run reproduces the pure
                    Ph1 ranking exactly on iteration 0.

    Returns a GHNResult with the final activation distribution, the per-iteration
    energy trace (monotone non-increasing by the CCCP guarantee), the iteration
    count, whether it converged within tol, and the PSD shift tau used.
    """
    n = len(h)
    if n == 0:
        return GHNResult([], [], 0, True, 0.0)

    w_psd, tau = psd_shift(w)

    if x0 is not None:
        x = list(x0)
    else:
        # Field-seeded start: with lambda_graph == 0 (no coupling) this makes the
        # ranking identical to sorting by the Ph1 field h, i.e. GHN with the graph
        # term switched off reduces to the Ph1 static-energy ranking.
        x = softmax([beta * h_i for h_i in h])

    energy_trace = [ghn_energy(x, h, w_psd, beta, lambda_graph)]
    converged = False
    iterations = 0
    for iterations in range(1, max_iters + 1):
        wx = _matvec(w_psd, x)
        logits = [beta * (h[i] + lambda_graph * wx[i]) for i in range(n)]
        x_next = softmax(logits)
        delta = sum(abs(a - b) for a, b in zip(x_next, x))
        x = x_next
        energy_trace.append(ghn_energy(x, h, w_psd, beta, lambda_graph))
        if delta < tol:
            converged = True
            break

    return GHNResult(x, energy_trace, iterations, converged, tau)


def rank_candidates(
    record_ids: Sequence[str],
    h: Sequence[float],
    w: Sequence[Sequence[float]],
    *,
    beta: float = DEFAULT_BETA,
    lambda_graph: float = 0.5,
    max_iters: int = DEFAULT_MAX_ITERS,
    tol: float = DEFAULT_TOL,
) -> Tuple[List[Dict[str, object]], GHNResult]:
    """Run the descent and return candidates ordered by final activation.

    Returns (ranked, result) where ranked is a list of
    {record_id, activation, rank} dicts sorted by activation descending (rank 1
    = highest activation), and result is the raw GHNResult (energy trace etc.).

    Ranking tie-break — IMPORTANT (documented in README §Findings): the energy
    descent concentrates activation mass on the coupled high-field basin, so many
    weakly-coupled TAIL candidates converge to numerically-indistinguishable
    near-zero activations. Ordering those by raw activation alone is arbitrary and
    collapses the deep-recall tail. We therefore break activation ties by the
    static Ph1 field ``h_i`` (= -E_Ph1(x)_i): "where the coupled dynamics have not
    differentiated two candidates, defer to their static per-candidate energy
    ranking." Activations are quantized to ACTIVATION_TIE_EPS before comparison so
    genuine ties fall through to the field key. This preserves the early-recall
    gain from graph coupling AND the deep-recall coverage of the static signal.
    Final key: (-quantized_activation, -h_i, original_index, record_id).
    """
    result = ghn_descent(
        h, w, beta=beta, lambda_graph=lambda_graph, max_iters=max_iters, tol=tol,
    )
    indexed = list(zip(record_ids, result.activation))

    def _sort_key(i: int):
        rid, act = indexed[i]
        act_q = round(act / ACTIVATION_TIE_EPS)
        return (-act_q, -h[i], i, rid)

    order = sorted(range(len(indexed)), key=_sort_key)
    ranked: List[Dict[str, object]] = []
    for rank, idx in enumerate(order, start=1):
        rid, act = indexed[idx]
        ranked.append({"record_id": rid, "activation": act, "rank": rank})
    return ranked, result
