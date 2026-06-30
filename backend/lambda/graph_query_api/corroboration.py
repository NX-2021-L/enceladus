"""Dispersion/Corroboration Weber-law bonus term (ENC-FTR-110 Ph1 / ENC-TSK-I92).

Defines a fifth scoring signal layered on top of ``lambda_function._rrf_fuse``'s
four-signal (vector/graph/keyword/PPR) Reciprocal Rank Fusion: a per-candidate
**corroboration bonus** ``B_corr(x)`` that rewards a candidate for having other,
*genuinely independent* records in the same result set that also point at it —
while explicitly refusing credit for near-duplicate records propping each
other up.

Why a separate "dispersion constraint" is needed
--------------------------------------------------
Naively, "how many other results are similar to this one" is a cheap proxy for
corroboration. But a cluster of near-identical records (e.g. five copies of the
same Lesson re-embedded after minor edits) would inflate that count without
adding any independent evidence — they are one opinion wearing five hats. This
module instead counts **corroborators**: other records that are (a) similar
enough to the candidate to support it, AND (b) pairwise distinct from every
other counted corroborator (pairwise cosine distance >= ``DISPERSION_MIN_
DISTANCE``). Two near-duplicates competing for the same corroborator slot only
ever contribute one corroborator between them — see ``count_corroborators``.

Term definitions
-----------------
  * ``k_corr(x)`` — the corroborator count for candidate x: the size of the
    largest subset of "similar-to-x" records (cosine similarity to x >=
    ``DEFAULT_SIMILARITY_THRESHOLD``) such that every pair within that subset
    has pairwise cosine distance >= ``DISPERSION_MIN_DISTANCE`` (0.3). Computed
    via a deterministic greedy packing (``count_corroborators``): candidates
    similar to x are considered most-similar-to-x first, and a candidate is
    accepted only if it is sufficiently dispersed (distance >= 0.3) from every
    already-accepted corroborator. This is the practical, polynomial-time
    reading of "pairwise distinct from each other" — an exact maximum
    independent set is NP-hard in general, but result sets here are bounded
    (``HYBRID_SIGNAL_TOP_N`` * fan-out, at most a few dozen candidates per
    call), and the greedy packing is exact for the test scenarios this module
    is built against (a single near-duplicate cluster, or a handful of
    genuinely dispersed corroborators).
  * ``B_corr(x) = Weber_k * ln(1 + k_corr(x)) / ln(1 + k_max)`` — a
    Weber-Fechner-law-style logarithmic diminishing-returns curve: the jump
    from 0 -> 1 corroborator matters far more than 5 -> 6. ``k_max`` is the
    largest ``k_corr`` observed across the candidates fused in *this call*
    (the same call-relative normalization convention ``energy_function`` uses
    for ``E_PPR`` / ``E_keyword`` — see that module's docstring), so the best-
    corroborated candidate in a given result set always receives the full
    ``Weber_k`` bonus and ``k_max == 0`` (nobody in this call has any
    corroboration) degrades to ``B_corr == 0.0`` for everyone rather than a
    division by zero.

This is a *bonus*, not an RRF term: it is not folded into the ``1/(k+rank)``
reciprocal-rank sum ``_rrf_fuse`` computes (that sum is exercised by exact-value
assertions in ``test_hybrid_retrieval.py`` and must not change), and it is not
a penalty. ``lambda_function._query_hybrid`` adds it on top of each candidate's
already-fused RRF ``fused_score`` to produce a ``final_score`` — see the
"Wiring" banner in that function for the integration point. The hedge this
buys (ENC-FTR-110 AC-4): a single high-RRF candidate with zero independent
corroboration can be outranked, post-bonus, by a moderately-ranked candidate
that several genuinely distinct records independently point at — exactly the
spurious-attractor case this signal exists to dampen.

Weber_k (configurable, AppConfig-backed)
------------------------------------------
``Weber_k`` is resolved at call time via ``load_weber_k()``, mirroring the
AppConfig-with-env-var-fallback idiom already used by
``backend/lambda/coordination_api/budget_hierarchy.py``
(``_appconfig_budget_config`` / ``load_scale_budgets``) and
``energy_function.load_lambda_weights``:

  1. AppConfig ``corroboration-function`` configuration profile key
     ``weber_k`` (via the AppConfig Lambda extension at ``localhost:2772``).
  2. Environment variable ``CORROBORATION_WEBER_K``.
  3. Hard-coded default ``DEFAULT_WEBER_K`` (0.3).

This module is pure-Python and dependency-free (no numpy, no boto3 import at
module load), matching the ``energy_function`` / ``drift_telemetry`` /
``dedup_convergence`` precedent in this package, so it is importable in unit
tests without AWS and bundles into the Lambda zip with no new dependency.

OGTM (ENC-FTR-110 AC-5): this module is pure compute plus a config read, over
candidate records ``lambda_function._query_hybrid`` has already fetched. It
introduces NO new tracker record type, relational field, edge type, or graph
node; performs NO Neo4j writes; and adds no new DDB table.
"""

from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Sequence

__all__ = [
    "CORROBORATION_SCHEMA",
    "DEFAULT_WEBER_K",
    "DEFAULT_SIMILARITY_THRESHOLD",
    "DISPERSION_MIN_DISTANCE",
    "load_weber_k",
    "cosine_similarity",
    "cosine_distance",
    "count_corroborators",
    "compute_corroboration_counts",
    "weber_bonus",
    "compute_bonuses",
]

# Schema tag for the corroboration breakdown, additive-sibling to
# energy_function.ENERGY_SCHEMA — surfaced for observability, not yet consumed
# by any downstream telemetry contract.
CORROBORATION_SCHEMA = "enceladus.retrieval.corroboration.v1"

# Hard-coded fallback default for Weber_k (see module docstring).
DEFAULT_WEBER_K: float = 0.3

# "High vector similarity to it" floor (module docstring term 1): a record
# below this cosine similarity to the candidate is not considered supporting
# evidence at all, dispersion aside. Deliberately looser than dedup_
# convergence.DEFAULT_COSINE_THRESHOLD (0.95, near-duplicate identity) — that
# constant answers "is this the same record"; this one answers "is this
# record independently pointing at the same answer," a lower bar.
DEFAULT_SIMILARITY_THRESHOLD: float = 0.80

# The dispersion constraint (ENC-FTR-110 AC-2): two records count as
# corroborating each other only if their pairwise cosine distance is >= this
# value. Fixed per the AC, not AppConfig-tunable like Weber_k.
DISPERSION_MIN_DISTANCE: float = 0.3


# ---------------------------------------------------------------------------
# AppConfig-backed configurable Weber_k
# ---------------------------------------------------------------------------

def _appconfig_corroboration_config() -> Dict[str, object]:
    """Best-effort read of the corroboration-function config from the
    AppConfig Lambda extension (localhost:2772). Returns {} on any failure so
    the caller falls back to the env var / hard-coded default. Mirrors
    ``energy_function._appconfig_energy_config`` /
    ``coordination_api.budget_hierarchy._appconfig_budget_config`` but
    targets a dedicated ``corroboration-function`` configuration profile
    (env-overridable)."""
    port = os.environ.get("AWS_APPCONFIG_EXTENSION_HTTP_PORT", "2772")
    app = os.environ.get("APPCONFIG_APPLICATION", "enceladus")
    env = os.environ.get("APPCONFIG_ENVIRONMENT", "production")
    cfg = os.environ.get("CORROBORATION_FUNCTION_APPCONFIG_CONFIGURATION", "corroboration-function")
    url = f"http://localhost:{port}/applications/{app}/environments/{env}/configurations/{cfg}"
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:  # noqa: S310 — localhost extension
            data = json.loads(resp.read())
        return data if isinstance(data, dict) else {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def load_weber_k() -> float:
    """Resolve ``Weber_k`` at runtime.

    Resolution order, highest precedence first:
      1. AppConfig ``corroboration-function`` configuration profile key
         ``weber_k``.
      2. Environment variable ``CORROBORATION_WEBER_K``.
      3. Hard-coded default (``DEFAULT_WEBER_K``).

    Always returns a non-negative float so the caller never has to handle a
    partial/invalid config.
    """
    appconfig = _appconfig_corroboration_config()
    raw = appconfig.get("weber_k")
    if raw is None:
        raw = os.environ.get("CORROBORATION_WEBER_K")
    try:
        value = float(raw) if raw is not None else DEFAULT_WEBER_K
    except (TypeError, ValueError):
        value = DEFAULT_WEBER_K
    if value < 0.0:
        value = DEFAULT_WEBER_K
    return value


# ---------------------------------------------------------------------------
# Pairwise cosine similarity / distance (pure stdlib)
# ---------------------------------------------------------------------------

def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> Optional[float]:
    """Cosine similarity between two equal-length vectors.

    Returns ``None`` (rather than raising) on a dimension mismatch or a
    zero-norm vector — both are "cannot compare" cases for a record missing or
    carrying a degenerate embedding, and the caller (``count_corroborators``)
    treats ``None`` as "not similar enough to corroborate," never as an error.
    """
    if not a or not b or len(a) != len(b):
        return None
    dot = sum(float(x) * float(y) for x, y in zip(a, b))
    norm_a = math.sqrt(sum(float(x) * float(x) for x in a))
    norm_b = math.sqrt(sum(float(y) * float(y) for y in b))
    if norm_a <= 0.0 or norm_b <= 0.0:
        return None
    sim = dot / (norm_a * norm_b)
    # Clamp for floating-point overshoot beyond the mathematical [-1, 1] range.
    return max(-1.0, min(1.0, sim))


def cosine_distance(a: Sequence[float], b: Sequence[float]) -> Optional[float]:
    """``1.0 - cosine_similarity(a, b)``; ``None`` propagates (see
    ``cosine_similarity``)."""
    sim = cosine_similarity(a, b)
    if sim is None:
        return None
    return 1.0 - sim


# ---------------------------------------------------------------------------
# Corroborator counting (dispersion-constrained)
# ---------------------------------------------------------------------------

def count_corroborators(
    candidate_id: str,
    candidate_embedding: Optional[Sequence[float]],
    pool: Dict[str, Sequence[float]],
    *,
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    dispersion_min_distance: float = DISPERSION_MIN_DISTANCE,
) -> int:
    """k_corr(candidate) — count of dispersion-constrained corroborators.

    ``pool`` maps every OTHER candidate's record_id to its embedding (the
    candidate itself must already be excluded by the caller — see
    ``compute_corroboration_counts``). Returns 0 immediately if the candidate
    has no usable embedding (ENC-FTR-110 AC-5 graceful degrade: a record with
    no embedding gets no corroboration credit, never a crash).

    Algorithm (deterministic greedy packing — see module docstring for why
    this is the practical reading of "pairwise distinct from each other"):
      1. Filter ``pool`` to records with cosine similarity to the candidate
         >= ``similarity_threshold`` ("similar enough to support it").
      2. Sort that similar pool by similarity to the candidate, descending
         (ties broken by record_id for determinism), so the strongest
         supporting evidence is considered first.
      3. Walk the sorted list, greedily accepting a record as a corroborator
         only if its cosine distance to EVERY already-accepted corroborator
         is >= ``dispersion_min_distance``. A record that is a near-duplicate
         of an already-accepted corroborator is skipped — it adds no
         independent evidence (ENC-FTR-110 AC-2).
    Returns the count of accepted corroborators.
    """
    if not candidate_embedding:
        return 0

    similar: List[tuple] = []
    for rid, emb in pool.items():
        if rid == candidate_id or not emb:
            continue
        sim = cosine_similarity(candidate_embedding, emb)
        if sim is not None and sim >= similarity_threshold:
            similar.append((sim, rid, emb))

    # Most similar to the candidate first; record_id as a deterministic
    # tie-breaker so the result never depends on dict/set iteration order.
    similar.sort(key=lambda t: (-t[0], t[1]))

    accepted: List[Sequence[float]] = []
    for _sim, _rid, emb in similar:
        if all(
            (cosine_distance(emb, other) or 0.0) >= dispersion_min_distance
            for other in accepted
        ):
            accepted.append(emb)

    return len(accepted)


def compute_corroboration_counts(
    embeddings_by_rid: Dict[str, Sequence[float]],
    *,
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    dispersion_min_distance: float = DISPERSION_MIN_DISTANCE,
) -> Dict[str, int]:
    """k_corr for every candidate in ``embeddings_by_rid`` (one result set).

    Records with no embedding are included in the output with k_corr == 0
    (so callers can rely on every candidate id being present) but never
    contribute to another candidate's corroborator count (excluded from the
    similarity pool automatically — ``cosine_similarity`` returns ``None`` for
    falsy/missing embeddings).
    """
    counts: Dict[str, int] = {}
    for rid, emb in embeddings_by_rid.items():
        counts[rid] = count_corroborators(
            rid, emb, embeddings_by_rid,
            similarity_threshold=similarity_threshold,
            dispersion_min_distance=dispersion_min_distance,
        )
    return counts


# ---------------------------------------------------------------------------
# B_corr(x) — the Weber-Fechner bonus
# ---------------------------------------------------------------------------

def weber_bonus(k_corr: int, k_max: int, weber_k: float = DEFAULT_WEBER_K) -> float:
    """B_corr(x) = Weber_k * ln(1 + k_corr) / ln(1 + k_max).

    Call-relative normalization (mirrors ``energy_function``'s E_PPR/
    E_keyword convention): the best-corroborated candidate in this call's
    result set (``k_corr == k_max``) always receives the full ``Weber_k``
    bonus. When ``k_max <= 0`` (no candidate in this call has any
    corroboration), the bonus is 0.0 for everyone rather than a division by
    zero — there is nothing to normalize against.
    """
    if k_max is None or k_max <= 0 or k_corr is None or k_corr <= 0:
        return 0.0
    k_corr = max(0, int(k_corr))
    k_max = max(0, int(k_max))
    return weber_k * math.log1p(k_corr) / math.log1p(k_max)


def compute_bonuses(
    counts: Dict[str, int],
    *,
    weber_k: Optional[float] = None,
) -> Dict[str, Dict[str, float]]:
    """B_corr breakdown for every candidate in ``counts`` (one result set).

    Returns ``{record_id: {"schema", "k_corr", "k_max", "weber_k", "b_corr"}}``
    so a caller (or a unit test) can inspect the full provenance of each
    bonus, not just its final value.
    """
    if weber_k is None:
        weber_k = load_weber_k()
    k_max = max(counts.values()) if counts else 0
    out: Dict[str, Dict[str, float]] = {}
    for rid, k_corr in counts.items():
        out[rid] = {
            "schema": CORROBORATION_SCHEMA,
            "k_corr": k_corr,
            "k_max": k_max,
            "weber_k": weber_k,
            "b_corr": weber_bonus(k_corr, k_max, weber_k),
        }
    return out
