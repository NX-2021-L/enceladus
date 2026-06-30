"""Per-retrieval energy function E(x) (ENC-FTR-104 Phase 1 / ENC-TSK-I98).

Defines the retrieval energy

    E(x) = E_vector + lambda_graph * E_PPR + lambda_kw * E_keyword

evaluated once per candidate record returned by ``graph_query_api``'s hybrid
retrieval path (``lambda_function._query_hybrid``). E(x) is a *disagreement /
low-confidence* score: 0.0 means a candidate sits exactly at the best-observed
position on every signal that scored it; larger values mean it is further from
that ideal. This is the inverse convention of the existing RRF fused_score
(higher fused_score = better) — energy is deliberately the dual quantity so it
composes additively across signals the way a physical energy/Hamiltonian does,
and so the existing ENC-FTR-105 AC-7 consumer
(``drift_telemetry.compute_spurious_attractor_rate``) can keep its
"energy crosses a ceiling -> spurious attractor" framing: a high E(x) is a
high-energy / low-confidence basin.

Term definitions
-----------------
  * ``E_vector`` — ``1.0 - vector_score`` where ``vector_score`` is the
    candidate's Neo4j HNSW cosine-similarity score from the vector signal
    (``lambda_function._hybrid_vector_ranks``), already calibrated to [0, 1]
    by construction (Neo4j cosine similarity range), so no further
    normalization is applied. Absent vector signal -> maximal energy (1.0):
    a candidate with no vector support gets no benefit of the doubt.
  * ``E_PPR`` — ``1.0 - (graph_score / max_graph_score)`` where
    ``graph_score`` is the candidate's Personalized PageRank score (FTR-101
    standing-projection ``gds_pagerank`` source preferred; ``cypher_fallback``
    proxy only when the standing projection / per-query GDS path are both
    unavailable) and ``max_graph_score`` is the top PPR score *within this
    call's* ranked graph candidates. PPR scores are not calibrated to a fixed
    range the way cosine similarity is, so they are normalized call-relative:
    the best graph candidate in the current result set always contributes
    E_PPR = 0.0. Absent graph signal -> maximal energy (1.0).
  * ``E_keyword`` — ``1.0 - (keyword_score / max_keyword_score)``, the same
    call-relative normalization as E_PPR, applied to the token-weighted
    keyword score (``lambda_function._hybrid_keyword_ranks``). Absent keyword
    signal -> maximal energy (1.0).

Every caller of ``compute_retrieval_energy`` must pass the ``graph_algorithm``
tag the hybrid pipeline already produces (``"gds_pagerank"``,
``"cypher_fallback"``, ``"timeout"``, or ``"unavailable"``) so a unit test (or
a downstream consumer) can assert which PPR source actually fed E_PPR for a
given record — FTR-104 AC-2 requires E_PPR to be sourced from the FTR-101
standing AGA projection, not the Cypher proxy, whenever the standing
projection is live.

Lambda weights (configurable, AppConfig-backed)
------------------------------------------------
``lambda_graph`` and ``lambda_kw`` are resolved at call time via
``load_lambda_weights()``, mirroring the AppConfig-with-env-var-fallback
resolution idiom already used by
``backend/lambda/coordination_api/budget_hierarchy.py``
(``_appconfig_budget_config`` / ``load_scale_budgets``):

  1. AppConfig ``energy-function`` configuration profile keys
     ``lambda_graph`` / ``lambda_kw`` (via the AppConfig Lambda extension at
     ``localhost:2772``).
  2. Environment variables ``ENERGY_LAMBDA_GRAPH`` / ``ENERGY_LAMBDA_KW``.
  3. Hard-coded defaults ``DEFAULT_LAMBDA_GRAPH`` / ``DEFAULT_LAMBDA_KW``.

Weight convention (documented + asserted in tests): E_vector's coefficient is
a fixed, implicit 1.0 — the vector/cosine signal is the primary precision@1
channel (DOC-DF651F07D5C2 SS3 dedup precision work singles it out as the
signal the superseded-by filter protects). ``lambda_graph`` and ``lambda_kw``
are *secondary-signal dampers* relative to that fixed unit weight, each
independently bounded to (0.0, 1.0] so neither secondary signal can ever
out-weigh the primary vector signal on its own. ``total_weight()`` reports
the documented total ``1.0 + lambda_graph + lambda_kw`` for this convention;
it is not required (and is not expected) to normalize to 1.0 — BHC-style
telemetry in this codebase already prefers independent floors/dampers over
convex-combination normalization (see ``budget_hierarchy.ALERT_LADDER``).

Defaults: ``lambda_graph = 0.5`` (PPR is a strong but secondary corroborating
signal — half the weight of the primary vector signal) and ``lambda_kw = 0.25``
(keyword/CONTAINS scoring is the weakest, noisiest signal of the three per the
ENC-ISS-310/ENC-TSK-G97 tokenization fix notes in
``lambda_function._hybrid_keyword_ranks``, so it is damped hardest).

Worked example
---------------
A candidate with vector_score=0.92 (best vector candidate this call, so its
own normalization is moot for E_vector — E_vector is absolute, not
call-relative), graph_score=8.0 against max_graph_score=10.0, and
keyword_score=3.0 against max_keyword_score=3.0 (the top keyword candidate),
under the defaults (lambda_graph=0.5, lambda_kw=0.25):

    E_vector  = 1.0 - 0.92        = 0.08
    E_PPR     = 1.0 - 8.0/10.0    = 0.20
    E_keyword = 1.0 - 3.0/3.0     = 0.00
    E(x) = 0.08 + 0.5*0.20 + 0.25*0.00 = 0.18

This module is pure-Python and dependency-free (no numpy, no boto3 import at
module load), matching the ``drift_telemetry`` / ``sheaf_cohomology`` /
``dedup_convergence`` precedent in this package, so it is importable in unit
tests without AWS and bundles into the Lambda zip with no new dependency.

OGTM (ENC-FTR-066): this module is pure compute plus a config read. It
introduces NO new tracker record type, relational field, edge type, or graph
node, and does not touch graph_sync.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "ENERGY_SCHEMA",
    "DEFAULT_LAMBDA_GRAPH",
    "DEFAULT_LAMBDA_KW",
    "GDS_PAGERANK_SOURCE",
    "CYPHER_FALLBACK_SOURCE",
    "load_lambda_weights",
    "total_weight",
    "energy_component",
    "compute_energy",
    "compute_retrieval_energy",
    "build_retrieval_record",
]

# Schema tag stamped onto the energy fields appended to pathway telemetry /
# hybrid-response payloads (additive sibling to drift_telemetry's
# DRIFT_TELEMETRY_SCHEMA and the pathway-telemetry "enceladus.pathway.
# telemetry.v1" schema — this is not a replacement for either).
ENERGY_SCHEMA = "enceladus.retrieval.energy.v1"

# FTR-101 AC-2: the only PPR source E_PPR is allowed to silently trust as
# "standing AGA graph projection" per the AC-2 sourcing requirement.
GDS_PAGERANK_SOURCE = "gds_pagerank"
CYPHER_FALLBACK_SOURCE = "cypher_fallback"

# Hard-coded fallback defaults (see module docstring "Weight convention").
DEFAULT_LAMBDA_GRAPH: float = 0.5
DEFAULT_LAMBDA_KW: float = 0.25


# ---------------------------------------------------------------------------
# AppConfig-backed configurable lambda weights
# ---------------------------------------------------------------------------

def _appconfig_energy_config() -> Dict[str, object]:
    """Best-effort read of the energy-function config from the AppConfig
    Lambda extension (localhost:2772). Returns {} on any failure so the
    caller falls back to env vars / hard-coded defaults. Mirrors
    ``coordination_api.budget_hierarchy._appconfig_budget_config`` but
    targets a dedicated ``energy-function`` configuration profile
    (env-overridable)."""
    port = os.environ.get("AWS_APPCONFIG_EXTENSION_HTTP_PORT", "2772")
    app = os.environ.get("APPCONFIG_APPLICATION", "enceladus")
    env = os.environ.get("APPCONFIG_ENVIRONMENT", "production")
    cfg = os.environ.get("ENERGY_FUNCTION_APPCONFIG_CONFIGURATION", "energy-function")
    url = f"http://localhost:{port}/applications/{app}/environments/{env}/configurations/{cfg}"
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:  # noqa: S310 — localhost extension
            data = json.loads(resp.read())
        return data if isinstance(data, dict) else {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def _resolve_weight(appconfig: Dict[str, object], key: str, env_var: str,
                    default: float) -> float:
    raw = appconfig.get(key)
    if raw is None:
        raw = os.environ.get(env_var)
    try:
        value = float(raw) if raw is not None else default
    except (TypeError, ValueError):
        value = default
    if value < 0.0:
        value = default
    return value


def load_lambda_weights() -> Tuple[float, float]:
    """Resolve (lambda_graph, lambda_kw) at runtime.

    Resolution order, per weight, highest precedence first:
      1. AppConfig ``energy-function`` configuration profile keys
         ``lambda_graph`` / ``lambda_kw``.
      2. Environment variables ``ENERGY_LAMBDA_GRAPH`` / ``ENERGY_LAMBDA_KW``.
      3. Hard-coded defaults (``DEFAULT_LAMBDA_GRAPH`` / ``DEFAULT_LAMBDA_KW``).

    Always returns a pair of non-negative floats so the caller never has to
    handle a partial/invalid config.
    """
    appconfig = _appconfig_energy_config()
    lambda_graph = _resolve_weight(
        appconfig, "lambda_graph", "ENERGY_LAMBDA_GRAPH", DEFAULT_LAMBDA_GRAPH,
    )
    lambda_kw = _resolve_weight(
        appconfig, "lambda_kw", "ENERGY_LAMBDA_KW", DEFAULT_LAMBDA_KW,
    )
    return lambda_graph, lambda_kw


def total_weight(lambda_graph: float, lambda_kw: float) -> float:
    """Documented weight-normalization convention (see module docstring
    "Weight convention"): the fixed implicit E_vector coefficient (1.0) plus
    the two configurable secondary-signal dampers. Not a convex combination —
    this codebase prefers independent per-term dampers (mirroring
    ``budget_hierarchy.ALERT_LADDER``'s independent floors) over normalized
    probability weights."""
    return 1.0 + lambda_graph + lambda_kw


# ---------------------------------------------------------------------------
# E(x) and its three components
# ---------------------------------------------------------------------------

def energy_component(score: Optional[float], max_score: Optional[float], *,
                     already_normalized: bool = False) -> float:
    """One energy term: ``1.0 - normalized_score``, clamped to [0.0, 1.0].

    When ``already_normalized`` is True, ``score`` is treated as already
    living in [0, 1] (the vector/cosine signal) and used directly. Otherwise
    it is normalized call-relative against ``max_score`` (the PPR/keyword
    convention — see module docstring). Returns 1.0 (maximal energy) when
    ``score`` is None, or when normalization is impossible (``max_score`` is
    None/<=0) — an absent or unscorable signal gets no benefit of the doubt.
    """
    if score is None:
        return 1.0
    if already_normalized:
        normalized = float(score)
    else:
        if max_score is None or max_score <= 0:
            return 1.0
        normalized = float(score) / float(max_score)
    normalized = max(0.0, min(1.0, normalized))
    return 1.0 - normalized


def compute_energy(e_vector: float, e_ppr: float, e_keyword: float, *,
                   lambda_graph: Optional[float] = None,
                   lambda_kw: Optional[float] = None) -> float:
    """E(x) = E_vector + lambda_graph * E_PPR + lambda_kw * E_keyword.

    ``lambda_graph``/``lambda_kw`` default to ``load_lambda_weights()`` when
    omitted, so a caller that has already resolved the weights once per
    request (recommended — avoids re-probing AppConfig per candidate) can
    pass them through explicitly.
    """
    if lambda_graph is None or lambda_kw is None:
        resolved_graph, resolved_kw = load_lambda_weights()
        if lambda_graph is None:
            lambda_graph = resolved_graph
        if lambda_kw is None:
            lambda_kw = resolved_kw
    return float(e_vector) + float(lambda_graph) * float(e_ppr) + float(lambda_kw) * float(e_keyword)


def compute_retrieval_energy(
    *,
    vector_score: Optional[float],
    graph_score: Optional[float],
    keyword_score: Optional[float],
    max_graph_score: Optional[float],
    max_keyword_score: Optional[float],
    graph_algorithm: str,
    lambda_graph: Optional[float] = None,
    lambda_kw: Optional[float] = None,
) -> Dict[str, Any]:
    """Compute E(x) for one retrieval candidate from its raw per-signal
    scores, returning the full component breakdown plus the
    ``graph_algorithm`` provenance tag (FTR-104 AC-2: callers/tests can assert
    ``graph_algorithm == "gds_pagerank"`` to verify E_PPR came from the FTR-101
    standing AGA projection rather than the ``cypher_fallback`` proxy).
    """
    if lambda_graph is None or lambda_kw is None:
        resolved_graph, resolved_kw = load_lambda_weights()
        lambda_graph = resolved_graph if lambda_graph is None else lambda_graph
        lambda_kw = resolved_kw if lambda_kw is None else lambda_kw

    e_vector = energy_component(vector_score, None, already_normalized=True)
    e_ppr = energy_component(graph_score, max_graph_score)
    e_keyword = energy_component(keyword_score, max_keyword_score)
    energy = compute_energy(e_vector, e_ppr, e_keyword,
                            lambda_graph=lambda_graph, lambda_kw=lambda_kw)
    return {
        "schema": ENERGY_SCHEMA,
        "retrieval_energy": energy,
        "E_vector": e_vector,
        "E_PPR": e_ppr,
        "E_keyword": e_keyword,
        "lambda_graph": lambda_graph,
        "lambda_kw": lambda_kw,
        "graph_algorithm": graph_algorithm,
        "ppr_source_is_gds_pagerank": graph_algorithm == GDS_PAGERANK_SOURCE,
    }


def build_retrieval_record(record_id: str, energy: Dict[str, Any]) -> Dict[str, Any]:
    """Shape one ``retrieval_records[]`` entry for the ENC-FTR-105 AC-7
    consumer contract (``drift_telemetry.compute_spurious_attractor_rate``
    reads ``record_id`` + ``avg_retrieval_energy`` or ``retrieval_energy``).
    Carries the full energy breakdown additively so a downstream caller does
    not have to re-derive it."""
    return {
        "record_id": record_id,
        "avg_retrieval_energy": energy["retrieval_energy"],
        "retrieval_energy": energy["retrieval_energy"],
        "E_vector": energy["E_vector"],
        "E_PPR": energy["E_PPR"],
        "E_keyword": energy["E_keyword"],
        "graph_algorithm": energy["graph_algorithm"],
    }
