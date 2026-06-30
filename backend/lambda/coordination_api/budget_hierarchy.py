"""budget_hierarchy.py — Budget Hierarchy Controller (ENC-FTR-083).

Phase 1 (ENC-TSK-I86): four-scale budget config + Banach RG-recurrence solver +
logarithmic beta-schedule + session-init allocation logging.

Phase 2 (ENC-TSK-I87, AC-4..AC-7): operational control surface layered on the
Phase 1 admission math — five-level corpus alert ladder wired to SNS, a
wave-close drift monitor, an emergency mid-wave admission path that writes a
wave-budget-extension record to the enceladus-drift-telemetry sink, and
corpus-scale token-usage telemetry emitted as the CloudWatch metric
Enceladus/BudgetController/CorpusTokenUsage (ENC-ISS-265 closure evidence). See
the "Phase 2" banner below for the per-AC mapping.

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
import time
import uuid
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

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
    # --- Phase 2 (ENC-TSK-I87) ---
    "ALERT_LADDER",
    "ALERT_LEVELS",
    "MIN_PUBLISH_RANK",
    "DRIFT_INF_NORM_THRESHOLD",
    "CLOUDWATCH_NAMESPACE",
    "CORPUS_TOKEN_USAGE_METRIC",
    "DEFAULT_DRIFT_TELEMETRY_TABLE",
    "classify_alert_level",
    "corpus_utilization",
    "inf_norm_delta",
    "publish_corpus_alert",
    "emit_corpus_token_usage_metric",
    "evaluate_corpus_budget",
    "WaveBudgetDriftMonitor",
    "emergency_wave_admission",
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


# ===========================================================================
# Phase 2 (ENC-FTR-083 AC-4..AC-7, ENC-TSK-I87)
#
# Builds the operational control surface on top of the Phase 1 admission math:
#   * AC-4: five-level corpus-budget alert ladder wired to SNS.
#   * AC-5: wave-close drift monitor that triggers recalibration on
#     ||s_new - s_old||_inf > 0.1.
#   * AC-6: emergency mid-wave admission with a wave-budget-extension record
#     written to the enceladus-drift-telemetry sink.
#   * AC-7 / ENC-ISS-265: corpus-scale token-usage telemetry emitted as the
#     CloudWatch metric Enceladus/BudgetController/CorpusTokenUsage, measured
#     against the PPR-informed hot-tier baseline.
#
# OGTM (ENC-FTR-066): every primitive here is pure compute plus best-effort
# emission to existing AWS telemetry surfaces (SNS / CloudWatch / a DynamoDB
# telemetry sink). It introduces NO new tracker record type, relational field,
# graph node, or edge type, and never touches graph_sync — so it adds no new
# ontology edge to keep traversable. boto3 is imported lazily and every emit is
# wrapped so a missing client, missing topic/table, or transient AWS failure
# degrades to a structured CloudWatch log line and never raises into the
# caller's request path (mirrors the graph_query_api.pathway_telemetry S3->log
# degradation contract).
# ===========================================================================

# AC-4: five-level alert ladder. Each rung is (level_name, utilization_floor).
# Ordered ascending by floor; classification returns the highest rung whose
# floor the corpus utilization has crossed. A utilization of 0.72 crosses the
# NOTICE floor (0.70) but not WARNING (0.85), so it classifies as NOTICE.
ALERT_LADDER: Tuple[Tuple[str, float], ...] = (
    ("NORMAL", 0.50),
    ("NOTICE", 0.70),
    ("WARNING", 0.85),
    ("CRITICAL", 0.95),
    ("FRAGMENTED", 1.00),
)

# Level-name -> rank (0 == NORMAL, 4 == FRAGMENTED). Higher rank == more severe.
ALERT_LEVELS: Dict[str, int] = {name: rank for rank, (name, _floor) in enumerate(ALERT_LADDER)}

# Minimum rank that warrants an SNS publish. NORMAL (rank 0, 50-70% utilization)
# is healthy headroom and is logged only; NOTICE (rank 1) and above publish.
MIN_PUBLISH_RANK: int = ALERT_LEVELS["NOTICE"]

# AC-5: wave-close drift recalibration threshold on the infinity-norm of the
# delta between two consecutive wave-close budget (utilization) vectors. The
# trigger is strict greater-than, so a delta of exactly 0.10 does NOT recalibrate
# while 0.12 does.
DRIFT_INF_NORM_THRESHOLD: float = 0.10

# AC-7 / ENC-ISS-265: corpus token-usage CloudWatch metric coordinates.
CLOUDWATCH_NAMESPACE: str = "Enceladus/BudgetController"
CORPUS_TOKEN_USAGE_METRIC: str = "CorpusTokenUsage"

# AC-6: DynamoDB telemetry sink for wave-budget-extension records.
DEFAULT_DRIFT_TELEMETRY_TABLE: str = "enceladus-drift-telemetry"


def _aws_region() -> Optional[str]:
    return os.environ.get("DYNAMODB_REGION") or os.environ.get("AWS_REGION")


def _boto3_client(service: str):
    """Lazily build a boto3 client. boto3 is always present in the Lambda
    runtime; importing it lazily keeps this module importable in a plain
    unit-test environment (where clients are injected instead)."""
    import boto3  # noqa: PLC0415 — lazy import so unit tests need no boto3

    return boto3.client(service, region_name=_aws_region())


# ---------------------------------------------------------------------------
# AC-4 — five-level corpus-budget alert ladder wired to SNS
# ---------------------------------------------------------------------------
def corpus_utilization(used_tokens: float, budgets: Optional[Dict[str, int]] = None) -> float:
    """Fraction of the corpus token budget consumed (>= 0.0; may exceed 1.0)."""
    if budgets is None:
        budgets = load_scale_budgets()
    corpus_budget = float(budgets["corpus"])
    if corpus_budget <= 0:
        raise ValueError("corpus budget must be positive")
    return max(0.0, float(used_tokens) / corpus_budget)


def classify_alert_level(utilization: float) -> Optional[Dict[str, object]]:
    """Map a corpus utilization fraction onto the five-level alert ladder.

    Returns ``{"level", "rank", "floor", "utilization"}`` for the highest rung
    whose floor the utilization has crossed, or ``None`` when utilization is
    below the NORMAL floor (healthy, sub-50% — nothing to report).
    """
    matched: Optional[Tuple[str, float, int]] = None
    for rank, (name, floor) in enumerate(ALERT_LADDER):
        if utilization >= floor:
            matched = (name, floor, rank)
        else:
            break
    if matched is None:
        return None
    name, floor, rank = matched
    return {"level": name, "rank": rank, "floor": floor, "utilization": float(utilization)}


def publish_corpus_alert(
    level: Dict[str, object],
    *,
    used_tokens: float,
    budgets: Dict[str, int],
    logger,
    sns_client=None,
    topic_arn: Optional[str] = None,
    project_id: str = "",
    request_id: str = "",
) -> Dict[str, object]:
    """Publish a corpus-budget alert to SNS (best-effort) and always log it.

    The structured ``[BUDGET][ALERT]`` log line is the CloudWatch-Logs evidence
    surface for AC-4 (verifiable on a test invocation even when no SNS topic is
    configured). The SNS publish is fired only when the rung rank is at or above
    MIN_PUBLISH_RANK (NOTICE) and a topic ARN is resolvable; any failure is
    logged and swallowed.
    """
    payload = {
        "event_type": "budget.corpus_alert",
        "level": level["level"],
        "rank": level["rank"],
        "floor": level["floor"],
        "utilization": round(float(level["utilization"]), 6),
        "corpus_used_tokens": int(used_tokens),
        "corpus_budget_tokens": int(budgets["corpus"]),
        "project_id": project_id,
        "request_id": request_id,
    }
    # AC-4 CloudWatch-Logs evidence line (always emitted).
    logger.info("[BUDGET][ALERT] %s", json.dumps(payload, sort_keys=True))

    published = False
    message_id = ""
    if int(level["rank"]) < MIN_PUBLISH_RANK:
        return {**payload, "published": published, "sns_message_id": message_id}

    arn = topic_arn or os.environ.get("BUDGET_ALERT_SNS_TOPIC_ARN") or os.environ.get(
        "DEAD_LETTER_SNS_TOPIC_ARN", ""
    )
    if not arn:
        logger.info(
            "[BUDGET][ALERT] no SNS topic configured (BUDGET_ALERT_SNS_TOPIC_ARN); "
            "level=%s logged only",
            level["level"],
        )
        return {**payload, "published": published, "sns_message_id": message_id}

    try:
        client = sns_client or _boto3_client("sns")
        resp = client.publish(
            TopicArn=arn,
            Subject=f"Budget {level['level']}: corpus at {payload['utilization']:.0%}",
            Message=json.dumps(payload, sort_keys=True),
        )
        published = True
        message_id = str(resp.get("MessageId", "")) if isinstance(resp, dict) else ""
    except Exception as exc:  # noqa: BLE001 — alerting must never break the caller
        logger.warning("[BUDGET][ALERT] SNS publish failed level=%s: %s", level["level"], exc)
    return {**payload, "published": published, "sns_message_id": message_id}


# ---------------------------------------------------------------------------
# AC-7 / ENC-ISS-265 — corpus token-usage CloudWatch metric
# ---------------------------------------------------------------------------
def emit_corpus_token_usage_metric(
    used_tokens: float,
    *,
    logger,
    budgets: Optional[Dict[str, int]] = None,
    ppr_baseline_tokens: Optional[float] = None,
    cloudwatch_client=None,
    project_id: str = "",
) -> Dict[str, object]:
    """Emit the corpus token-usage telemetry to CloudWatch (best-effort).

    Publishes the metric ``Enceladus/BudgetController/CorpusTokenUsage`` (unit:
    Count == tokens) plus, when a PPR-informed hot-tier baseline is supplied (or
    resolvable from ``BUDGET_CORPUS_PPR_BASELINE_TOKENS``), the ratio metric
    ``CorpusTokenUsageVsBaseline`` (used / baseline). This is the ENC-ISS-265
    closure evidence: corpus-scale usage measured against the PPR-informed
    baseline rather than assumed. Always logs the values for CloudWatch-Logs
    confirmation; the put_metric_data call is swallowed on failure.
    """
    if budgets is None:
        budgets = load_scale_budgets()
    if ppr_baseline_tokens is None:
        raw = os.environ.get("BUDGET_CORPUS_PPR_BASELINE_TOKENS")
        try:
            ppr_baseline_tokens = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            ppr_baseline_tokens = None

    util = corpus_utilization(used_tokens, budgets)
    vs_baseline: Optional[float] = None
    if ppr_baseline_tokens and ppr_baseline_tokens > 0:
        vs_baseline = float(used_tokens) / float(ppr_baseline_tokens)

    record = {
        "metric_namespace": CLOUDWATCH_NAMESPACE,
        "metric_name": CORPUS_TOKEN_USAGE_METRIC,
        "corpus_used_tokens": int(used_tokens),
        "corpus_budget_tokens": int(budgets["corpus"]),
        "corpus_utilization": round(util, 6),
        "ppr_baseline_tokens": int(ppr_baseline_tokens) if ppr_baseline_tokens else None,
        "used_vs_ppr_baseline": round(vs_baseline, 6) if vs_baseline is not None else None,
        "project_id": project_id,
    }
    logger.info("[BUDGET][CORPUS-TELEMETRY] %s", json.dumps(record, sort_keys=True))

    metric_data: List[Dict[str, object]] = [
        {
            "MetricName": CORPUS_TOKEN_USAGE_METRIC,
            "Value": float(used_tokens),
            "Unit": "Count",
            "Dimensions": [{"Name": "ProjectId", "Value": project_id or "enceladus"}],
        }
    ]
    if vs_baseline is not None:
        metric_data.append(
            {
                "MetricName": "CorpusTokenUsageVsBaseline",
                "Value": float(vs_baseline),
                "Unit": "None",
                "Dimensions": [{"Name": "ProjectId", "Value": project_id or "enceladus"}],
            }
        )

    emitted = False
    try:
        client = cloudwatch_client or _boto3_client("cloudwatch")
        client.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=metric_data)
        emitted = True
    except Exception as exc:  # noqa: BLE001 — telemetry must never break the caller
        logger.warning("[BUDGET][CORPUS-TELEMETRY] put_metric_data failed: %s", exc)
    return {**record, "emitted": emitted}


def evaluate_corpus_budget(
    logger,
    *,
    used_tokens: Optional[float] = None,
    budgets: Optional[Dict[str, int]] = None,
    sns_client=None,
    cloudwatch_client=None,
    topic_arn: Optional[str] = None,
    ppr_baseline_tokens: Optional[float] = None,
    emit_metric: bool = True,
    project_id: str = "",
    request_id: str = "",
) -> Optional[Dict[str, object]]:
    """End-to-end corpus-budget evaluation: classify -> alert -> telemetry.

    ``used_tokens`` may be passed explicitly (the recommended path) or resolved
    from the ``BUDGET_CORPUS_USED_TOKENS`` env / AppConfig signal so the same
    code path is exercisable by a direct test invocation. Returns ``None`` (a
    no-op) when no corpus-usage signal is available, so wiring this into
    session-init is safe and silent in the common case.
    """
    if budgets is None:
        budgets = load_scale_budgets()
    if used_tokens is None:
        appconfig = _appconfig_budget_config()
        raw = appconfig.get("corpus_used_tokens")
        if raw is None:
            raw = os.environ.get("BUDGET_CORPUS_USED_TOKENS")
        try:
            used_tokens = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            used_tokens = None
    if used_tokens is None:
        return None

    util = corpus_utilization(used_tokens, budgets)
    level = classify_alert_level(util)
    alert_result: Optional[Dict[str, object]] = None
    if level is not None:
        alert_result = publish_corpus_alert(
            level,
            used_tokens=used_tokens,
            budgets=budgets,
            logger=logger,
            sns_client=sns_client,
            topic_arn=topic_arn,
            project_id=project_id,
            request_id=request_id,
        )

    telemetry_result: Optional[Dict[str, object]] = None
    if emit_metric:
        telemetry_result = emit_corpus_token_usage_metric(
            used_tokens,
            logger=logger,
            budgets=budgets,
            ppr_baseline_tokens=ppr_baseline_tokens,
            cloudwatch_client=cloudwatch_client,
            project_id=project_id,
        )

    return {
        "corpus_used_tokens": int(used_tokens),
        "corpus_utilization": round(util, 6),
        "level": level,
        "alert": alert_result,
        "telemetry": telemetry_result,
    }


# ---------------------------------------------------------------------------
# AC-5 — wave-close budget-drift monitor
# ---------------------------------------------------------------------------
def inf_norm_delta(a: Sequence[float], b: Sequence[float]) -> float:
    """Infinity-norm (max absolute component) of (a - b)."""
    if len(a) != len(b):
        raise ValueError("vectors must have equal length for the infinity-norm delta")
    return max(abs(float(a[i]) - float(b[i])) for i in range(len(a))) if a else 0.0


class WaveBudgetDriftMonitor:
    """Tracks consecutive wave-close budget (utilization) vectors and flags a
    recalibration when the infinity-norm of the delta between two consecutive
    vectors exceeds DRIFT_INF_NORM_THRESHOLD (default 0.1, strict greater-than).

    Stateless across waves except for the single previous vector it retains, so
    a Lambda can keep one instance per warm container or reconstruct it from the
    last-persisted wave-close vector.
    """

    def __init__(self, threshold: float = DRIFT_INF_NORM_THRESHOLD, logger=None) -> None:
        self.threshold = float(threshold)
        self.logger = logger
        self._previous: Optional[List[float]] = None

    def observe_wave_close(
        self, budget_vector: Sequence[float], *, wave_id: str = ""
    ) -> Dict[str, object]:
        """Record a wave-close budget vector and report whether recalibration
        is triggered relative to the immediately preceding wave-close vector.

        On the first observation there is no predecessor, so ``recalibrate`` is
        False and ``drift`` is None. When recalibration triggers, a structured
        ``[BUDGET][DRIFT]`` recalibration log entry is emitted (AC-5 evidence).
        """
        current = [float(x) for x in budget_vector]
        result: Dict[str, object] = {
            "wave_id": wave_id,
            "vector": current,
            "previous": self._previous,
            "drift": None,
            "threshold": self.threshold,
            "recalibrate": False,
        }
        if self._previous is not None:
            drift = inf_norm_delta(current, self._previous)
            recalibrate = drift > self.threshold
            result["drift"] = round(drift, 6)
            result["recalibrate"] = recalibrate
            if recalibrate and self.logger is not None:
                self.logger.warning(
                    "[BUDGET][DRIFT] recalibration triggered wave_id=%s "
                    "inf_norm=%.6f threshold=%.6f prev=%s curr=%s",
                    wave_id,
                    drift,
                    self.threshold,
                    self._previous,
                    current,
                )
        self._previous = current
        return result


# ---------------------------------------------------------------------------
# AC-6 — emergency mid-wave admission (wave-budget extension)
# ---------------------------------------------------------------------------
def emergency_wave_admission(
    *,
    logger,
    session_id: str,
    wave_id: str,
    requested_tokens: int,
    wave_used_tokens: int,
    wave_budget_tokens: Optional[int] = None,
    reason: str = "cache_miss",
    extension_factor: float = 0.25,
    budgets: Optional[Dict[str, int]] = None,
    dynamodb_client=None,
    table_name: Optional[str] = None,
    project_id: str = "",
) -> Dict[str, object]:
    """Grant a temporary wave-budget extension for a forced mid-wave cache-miss
    and write a wave-budget-extension record to the drift-telemetry sink.

    A forced cache-miss mid-wave can push ``wave_used + requested`` past the
    wave budget; rather than hard-rejecting (which would strand an in-flight
    wave), the controller grants a bounded extension (``extension_factor`` of
    the wave budget, at least the overflow) and records it. The record is
    written to the ``enceladus-drift-telemetry`` DynamoDB table when configured;
    otherwise it degrades to a structured ``[BUDGET][EMERGENCY-ADMISSION]``
    CloudWatch log line. Always returns the extension record.
    """
    if budgets is None:
        budgets = load_scale_budgets()
    if wave_budget_tokens is None:
        wave_budget_tokens = int(budgets["wave"])

    projected = int(wave_used_tokens) + int(requested_tokens)
    overflow = max(0, projected - int(wave_budget_tokens))
    floor_extension = int(math.ceil(extension_factor * float(wave_budget_tokens)))
    granted_extension = max(overflow, floor_extension) if overflow > 0 else 0
    extended_budget = int(wave_budget_tokens) + granted_extension

    record = {
        "telemetry_id": str(uuid.uuid4()),
        "record_type": "wave_budget_extension",
        "schema": "enceladus.budget.wave_extension.v1",
        "session_id": session_id,
        "wave_id": wave_id,
        "project_id": project_id or "enceladus",
        "reason": reason,
        "requested_tokens": int(requested_tokens),
        "wave_used_tokens": int(wave_used_tokens),
        "wave_budget_tokens": int(wave_budget_tokens),
        "overflow_tokens": int(overflow),
        "granted_extension_tokens": int(granted_extension),
        "extended_wave_budget_tokens": int(extended_budget),
        "admitted": True,
        "ts": int(time.time()),
    }

    table = table_name or os.environ.get("DRIFT_TELEMETRY_TABLE", DEFAULT_DRIFT_TELEMETRY_TABLE)
    persisted = False
    if table:
        try:
            client = dynamodb_client or _boto3_client("dynamodb")
            client.put_item(TableName=table, Item=_to_dynamodb_item(record))
            persisted = True
        except Exception as exc:  # noqa: BLE001 — admission must never break mid-wave
            logger.warning(
                "[BUDGET][EMERGENCY-ADMISSION] drift-telemetry write failed wave_id=%s: %s",
                wave_id,
                exc,
            )
    # Always log (CloudWatch-Logs evidence + degraded sink when table absent).
    logger.warning(
        "[BUDGET][EMERGENCY-ADMISSION] %s",
        json.dumps({**record, "persisted": persisted, "table": table}, sort_keys=True),
    )
    return {**record, "persisted": persisted, "table": table}


def _to_dynamodb_item(record: Dict[str, object]) -> Dict[str, Dict[str, str]]:
    """Marshal a flat record into the DynamoDB low-level attribute-value shape.

    Only the scalar types this module emits (str / int / bool) are handled."""
    item: Dict[str, Dict[str, str]] = {}
    for key, value in record.items():
        if isinstance(value, bool):
            item[key] = {"BOOL": value}
        elif isinstance(value, int):
            item[key] = {"N": str(value)}
        elif value is None:
            item[key] = {"NULL": True}
        else:
            item[key] = {"S": str(value)}
    return item
