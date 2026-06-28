"""budget_hierarchy.py — Budget Hierarchy Controller (ENC-FTR-083 Phase 1, ENC-TSK-I86).

Implements the Budget Hierarchy Controller primitive described in
DOC-C6584044BEEB (Primitive 2 + Definition 5), grounded in the two governed
research artifacts:

  * DOC-18D2337D7E1F (ENC-TSK-F11) — RG fixed points of the budget recurrence,
    Banach-iteration solver, super-stability on the interior triple.
  * DOC-1E5E505CB51A (ENC-TSK-F15) — coupled information-bottleneck scheduling,
    logarithmic cognitive-temperature (beta) schedule anchored at beta_0 = 8.0.

Acceptance criteria implemented here (ENC-TSK-I86):

  * AC-1: Four canonical scale budgets (session / wave / project / corpus),
    readable by coordination_api at runtime from AppConfig (with env-var
    override and hard-coded F11 fixed-point-tuple defaults as the fallback).
  * AC-2: Banach-iteration solver over the top-down RG budget recurrence that
    converges in <= 1 effective pass on the interior regime.
  * AC-3: Logarithmic beta-schedule with beta_0 = 8.0.
  * AC-5: ``log_session_budget_allocation`` emits the per-session budget
    allocation at DEBUG level; called from coordination_api session init.

OGTM (AC-4): this module is pure compute + a config read. It introduces NO new
tracker record type, relational field, edge type, or graph node, and does not
touch graph_sync. It depends only on the Python standard library so it adds no
deployment dependency and is importable in unit tests without AWS.
"""
from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request
from typing import Dict, List, Sequence, Tuple

__all__ = [
    "SCALES",
    "DEFAULT_SCALE_BUDGETS_TOKENS",
    "DEFAULT_BETA_0",
    "DEFAULT_SOLVER_CALIBRATION",
    "load_scale_budgets",
    "beta_schedule",
    "beta_for_budget",
    "beta_tuple",
    "local_optimum",
    "recurrence_step",
    "find_fixed_point",
    "l2_norm_delta",
    "log_session_budget_allocation",
]

# ---------------------------------------------------------------------------
# Canonical scales (top-down nesting: session ⊂ wave ⊂ project ⊂ corpus)
# ---------------------------------------------------------------------------
SCALES: Tuple[str, str, str, str] = ("session", "wave", "project", "corpus")

# AC-1: four canonical per-scale token budgets. These are the F11
# fixed-point-tuple defaults restated in token units for the v4 admission
# controller (ENC-TSK-I86 acceptance contract). They are the fallback the
# runtime resolver returns when neither AppConfig nor env vars provide an
# override, so coordination_api always has a readable budget vector.
DEFAULT_SCALE_BUDGETS_TOKENS: Dict[str, int] = {
    "session": 200_000,
    "wave": 50_000,
    "project": 500_000,
    "corpus": 2_000_000,
}

# AC-3: session-scale sharpness anchor for the logarithmic beta-schedule.
DEFAULT_BETA_0: float = 8.0

# Logarithmic cooling coefficient for the step-indexed beta-schedule. Calibrated
# so the schedule descends from beta_0 = 8.0 at the session anchor (t = 0) to
# ~3.33 at the t = 10 reference depth, matching the F15 logarithmic profile
# (DOC-1E5E505CB51A): beta(10) = 8 / (1 + 0.585 * ln(11)) ≈ 3.329.
_LOG_BETA_DECAY: float = 0.585

# AC-2: default solver calibration anchored to the DOC-18D2337D7E1F reference
# point (16 TB mature-state corpus). Index order matches SCALES
# (0=session, 1=wave, 2=project, 3=corpus). This calibration sits in the
# interior regime, where the recurrence is super-stable and converges in one
# top-down pass.
DEFAULT_SOLVER_CALIBRATION: Dict[str, object] = {
    "s": [1.50, 1.30, 1.15, 1.05],          # Zipf-Mandelbrot intent exponents
    "T": [1.0, 1.5, 2.0, 2.5],              # cognitive temperatures per scale
    "c": [1.0, 0.5, 0.25, 0.125],           # per-node cost
    "lam": [1.0e-4, 5.0e-5, 2.0e-5, 1.0e-5],  # cost-penalty coefficients
    "k_anchor": 2.0e8,                       # corpus hot-tier node-count anchor
}


# ---------------------------------------------------------------------------
# AC-1 — runtime-readable four-scale budget config
# ---------------------------------------------------------------------------
def _appconfig_budget_config() -> Dict[str, object]:
    """Best-effort read of the budget-hierarchy config from the AppConfig
    Lambda extension (localhost:2772). Returns {} on any failure so the caller
    falls back to env vars / hard-coded defaults. Mirrors the resolution
    pattern of enceladus_shared.appconfig_flags but targets a dedicated
    ``budget-hierarchy`` configuration profile (env-overridable)."""
    port = os.environ.get("AWS_APPCONFIG_EXTENSION_HTTP_PORT", "2772")
    app = os.environ.get("APPCONFIG_APPLICATION", "enceladus")
    env = os.environ.get("APPCONFIG_ENVIRONMENT", "production")
    cfg = os.environ.get("BUDGET_HIERARCHY_APPCONFIG_CONFIGURATION", "budget-hierarchy")
    url = f"http://localhost:{port}/applications/{app}/environments/{env}/configurations/{cfg}"
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:  # noqa: S310 — localhost extension
            data = json.loads(resp.read())
        return data if isinstance(data, dict) else {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


def load_scale_budgets() -> Dict[str, int]:
    """Resolve the four-scale token budget vector at runtime.

    Resolution order, per scale, highest precedence first:
      1. AppConfig ``budget-hierarchy`` profile key ``budget_<scale>_tokens``.
      2. Environment variable ``BUDGET_<SCALE>_TOKENS``.
      3. Hard-coded F11 fixed-point-tuple default (DEFAULT_SCALE_BUDGETS_TOKENS).

    Always returns a complete, positive budget for every canonical scale so the
    caller never has to handle a partial config.
    """
    appconfig = _appconfig_budget_config()
    budgets: Dict[str, int] = {}
    for scale in SCALES:
        raw = appconfig.get(f"budget_{scale}_tokens")
        if raw is None:
            raw = os.environ.get(f"BUDGET_{scale.upper()}_TOKENS")
        try:
            value = int(raw) if raw is not None else DEFAULT_SCALE_BUDGETS_TOKENS[scale]
        except (TypeError, ValueError):
            value = DEFAULT_SCALE_BUDGETS_TOKENS[scale]
        if value <= 0:
            value = DEFAULT_SCALE_BUDGETS_TOKENS[scale]
        budgets[scale] = value
    return budgets


# ---------------------------------------------------------------------------
# AC-3 — logarithmic beta-schedule (cognitive-temperature / retrieval-sharpness)
# ---------------------------------------------------------------------------
def beta_schedule(t: float, beta_0: float = DEFAULT_BETA_0) -> float:
    """Step-indexed logarithmic beta-schedule.

    beta(t) = beta_0 / (1 + _LOG_BETA_DECAY * ln(1 + t))

    Monotonically decreasing in t (hotter / more exploratory as scope widens).
    beta(0) = beta_0 (= 8.0 by default); beta(10) ≈ 3.33 — the F15 reference
    cooling depth.
    """
    if t < 0:
        raise ValueError("beta-schedule step t must be non-negative")
    return beta_0 / (1.0 + _LOG_BETA_DECAY * math.log1p(t))


def beta_for_budget(b_n: float, b_session: float, beta_0: float = DEFAULT_BETA_0) -> float:
    """Canonical budget-ratio beta from F15 (DOC-1E5E505CB51A):

    beta_n = beta_0 / ln((B_n / B_session) + e - 1)

    At the session scale (B_n == B_session) the ratio is 1 and the denominator
    is ln(e) = 1, so beta_session == beta_0.
    """
    if b_session <= 0:
        raise ValueError("session budget must be positive")
    ratio = float(b_n) / float(b_session)
    return beta_0 / math.log(ratio + math.e - 1.0)


def beta_tuple(budgets: Dict[str, int], beta_0: float = DEFAULT_BETA_0) -> Dict[str, float]:
    """Per-scale cognitive-temperature tuple derived from the budget vector via
    the canonical F15 budget-ratio schedule."""
    b_session = budgets["session"]
    return {scale: beta_for_budget(budgets[scale], b_session, beta_0) for scale in SCALES}


# ---------------------------------------------------------------------------
# AC-2 — Banach-iteration fixed-point solver over the RG budget recurrence
# ---------------------------------------------------------------------------
def _stationarity(k: float, s: float, T: float, c: float, lam: float) -> float:
    """dF/dk of the free-energy objective (DOC-18D2337D7E1F eq. star):

    (s - 1) * k^{-s} + T / k - lam * c

    Strictly monotone decreasing in k, so it has at most one positive root.
    """
    return (s - 1.0) * k ** (-s) + T / k - lam * c


def local_optimum(
    s: float, T: float, c: float, lam: float, k_max: float,
    tol: float = 1e-9, max_iter: int = 200,
) -> Tuple[float, bool]:
    """Unconstrained scale-n free-energy optimum, clipped to the parent ceiling.

    Returns ``(k_star, binding)``. If the stationarity derivative is still
    positive at the parent ceiling the child saturates it (binding regime);
    otherwise the unique interior root is found by bisection (the pure-Python
    stand-in for scipy.optimize.brentq, O(log 1/eps) per scale, no third-party
    dependency).
    """
    if _stationarity(k_max, s, T, c, lam) > 0:
        return k_max, True

    lo, hi = 1.0, float(k_max)
    f_lo = _stationarity(lo, s, T, c, lam)
    mid = 0.5 * (lo + hi)
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        f_mid = _stationarity(mid, s, T, c, lam)
        if abs(f_mid) < 1e-12 or (hi - lo) < tol * max(1.0, mid):
            break
        if (f_lo > 0) == (f_mid > 0):
            lo, f_lo = mid, f_mid
        else:
            hi = mid
    return mid, False


def recurrence_step(
    k: Sequence[float],
    s: Sequence[float],
    T: Sequence[float],
    c: Sequence[float],
    lam: Sequence[float],
    k_anchor: float,
) -> List[float]:
    """One application of the top-down RG recurrence operator.

    The corpus anchor (index 3) is pinned; each interior child is solved
    against its immediate parent ceiling, coarse-to-fine (project, wave,
    session). The recurrence is triangular, which is what makes it converge in
    a single effective pass.
    """
    k_new = [float(x) for x in k]
    k_new[3] = float(k_anchor)
    for n in (2, 1, 0):
        k_new[n], _ = local_optimum(s[n], T[n], c[n], lam[n], k_new[n + 1])
    return k_new


def l2_norm_delta(a: Sequence[float], b: Sequence[float]) -> float:
    """Euclidean norm of (a - b)."""
    return math.sqrt(sum((float(a[i]) - float(b[i])) ** 2 for i in range(len(a))))


def find_fixed_point(
    s: Sequence[float],
    T: Sequence[float],
    c: Sequence[float],
    lam: Sequence[float],
    k_anchor: float,
    max_iter: int = 50,
    tol: float = 1e-9,
) -> Tuple[List[float], int]:
    """Banach iteration of the top-down recurrence from the all-anchor seed.

    Returns ``(k_star, iterations)``. On the interior regime the interior block
    of the recurrence Jacobian is nilpotent (spectral radius 0), so the fixed
    point is reached after one top-down solve pass; the convergence check then
    confirms it on the following pass.
    """
    k = [float(k_anchor)] * 4
    iterations = 0
    for it in range(max_iter):
        k_new = recurrence_step(k, s, T, c, lam, k_anchor)
        iterations = it + 1
        rel = max(abs((k_new[i] - k[i]) / max(abs(k[i]), 1.0)) for i in range(4))
        if rel < tol:
            return k_new, iterations
        k = k_new
    return k, iterations


# ---------------------------------------------------------------------------
# AC-5 — session-init budget allocation logging
# ---------------------------------------------------------------------------
def log_session_budget_allocation(
    logger,
    *,
    request_id: str = "",
    project_id: str = "",
    beta_0: float = DEFAULT_BETA_0,
) -> Dict[str, object]:
    """Emit the per-session budget allocation at DEBUG and return it.

    Called from coordination_api on every session init (coordination request
    intake). Resolves the runtime four-scale budget vector (AC-1) and the
    per-scale cognitive-temperature tuple (AC-3) and logs them. Best-effort:
    callers should not let a logging failure break session init.
    """
    budgets = load_scale_budgets()
    betas = beta_tuple(budgets, beta_0)
    logger.debug(
        "[BUDGET] session-init allocation request_id=%s project_id=%s "
        "scales_tokens=%s beta_0=%.4f betas=%s",
        request_id,
        project_id,
        budgets,
        beta_0,
        {scale: round(value, 4) for scale, value in betas.items()},
    )
    return {"scales_tokens": budgets, "beta_0": beta_0, "betas": betas}
