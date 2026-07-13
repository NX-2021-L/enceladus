"""comp-percolation-monitor — nightly percolation-threshold telemetry Lambda.

ENC-TSK-I88 / ENC-FTR-085 (ENC-PLN-006 v4/gamma). Produces an authoritative
nightly measurement of the knowledge-graph percolation threshold p_c, feeding the
Budget Hierarchy Controller's corpus-scale percolation-margin alert ladder
(DOC-C6584044BEEB Primitive 4).

Two estimates are computed every run. They deliberately measure DIFFERENT
features of the percolation transition and are NOT expected to coincide — see
the "Why analytical and empirical differ" note below (ENC-TSK-N51).

  * Analytical p_c (Molloy-Reed). On the configuration model a giant component
    exists iff <k^2>/<k> > 2. The critical occupation probability reported here is
    p_c = <k> / <k^2>, computed directly from the live degree sequence (task AC-2).
    This is the THERMODYNAMIC-LIMIT (N→∞), locally-tree-like EMERGENCE threshold:
    the occupation fraction at which a macroscopic component first appears.

  * Empirical p_c (Monte Carlo site percolation, susceptibility-peak estimator).
    Each node is occupied with probability p; an edge is active iff both endpoints
    are occupied. Over a grid of MC_NUM_P p-values, MC_TRIALS trials measure the
    mean largest-connected-component (LCC) ratio AND the mean second-largest-cluster
    ratio at each p. Empirical p_c is the p that MAXIMIZES the mean second-largest
    cluster ratio — the finite-size percolation susceptibility peak, the standard
    stable estimator of the transition location (ENC-TSK-N51). The legacy
    argmax-of-second-derivative-of-LCC estimate is retained for continuity as
    ``empirical_pc_curvature`` but is NOT the primary signal: it has a high,
    n-insensitive variance floor (2nd-difference argmax amplifies MC noise) and
    on a smeared heavy-tailed transition it floats on tail noise regardless of
    trial count. The susceptibility peak resolves p_c to within one grid cell at
    MC_TRIALS≈160 (SE ∝ 1/√n crosses the 0.02 grid spacing there).

Why analytical and empirical differ (ENC-TSK-N51 verdict). On a real, finite
(N ~ 10^3), clustered, degree-correlated governance graph the two numbers sit an
order of magnitude apart (empirical ~0.1–0.3, analytical ~0.02–0.06) BY DESIGN,
not because of drift or a bug: (1) analytical is the N→∞ emergence threshold,
while the finite graph's LCC does not visibly lift off until ~3–4× that value
(finite-size scaling); and (2) the empirical estimator locates the susceptibility
peak / dominance region of the transition, which sits above emergence. A large
gap is therefore EXPECTED and stable; a sudden CHANGE in either series — not the
gap itself — is the drift signal worth alerting on.

OGTM (task AC-5): the graph is read EXCLUSIVELY through the graph_query_api
read endpoint (search_type=adjacency). The Lambda performs no direct Neo4j
connection and no graph writes, and introduces no new edge type. Results are
written to the enceladus-percolation-telemetry DynamoDB table and emitted as
CloudWatch metrics under the Enceladus/Percolation namespace.

ENC-TSK-I91 (ENC-FTR-105 AC-7): the DynamoDB row additionally carries a
nullable ``spurious_attractor_rate`` field alongside analytical_pc/empirical_pc
-- a recent-average aggregate read verbatim off the same adjacency response
this Lambda already consumes (graph_query_api computes it from the
enceladus-drift-telemetry table; see _fetch_graph). This is a
backward-compatible schema addition: an older graph_query_api deploy that
predates this field simply omits the key, and the row writes None.

Environment variables:
  GRAPH_QUERY_API_BASE          graphsearch endpoint base URL (read surface)
  COORDINATION_INTERNAL_API_KEY service-to-service key for graph_query_api auth
  PERCOLATION_TABLE             DynamoDB telemetry table name
  CLOUDWATCH_NAMESPACE          metric namespace (default: Enceladus/Percolation)
  PROJECT_ID                    graph project scope (default: enceladus)
  AWS_REGION                    region (provided by the Lambda runtime)
  MC_TRIALS                     Monte Carlo trials per p-value (default: 160 —
                                ENC-TSK-N51: the SE of the susceptibility-peak
                                estimator crosses the 0.02 p-grid resolution here;
                                more trials buy nothing without a finer p-grid)
  MC_NUM_P                      number of p-values in the sweep (default: 30)
  MC_P_MIN / MC_P_MAX           sweep range (defaults: 0.02 / 0.60)
  ADJACENCY_PAGE_LIMIT          edges per graph_query_api page (default: 20000)
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as _urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-west-2")
GRAPH_QUERY_API_BASE = os.environ.get("GRAPH_QUERY_API_BASE", "").rstrip("/")
INTERNAL_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
PERCOLATION_TABLE = os.environ.get("PERCOLATION_TABLE", "enceladus-percolation-telemetry")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/Percolation")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")

MC_TRIALS = int(os.environ.get("MC_TRIALS", "160"))
MC_NUM_P = int(os.environ.get("MC_NUM_P", "30"))
MC_P_MIN = float(os.environ.get("MC_P_MIN", "0.02"))
MC_P_MAX = float(os.environ.get("MC_P_MAX", "0.60"))
ADJACENCY_PAGE_LIMIT = int(os.environ.get("ADJACENCY_PAGE_LIMIT", "20000"))

_HTTP_TIMEOUT_S = 30
_MAX_PAGES = 1000  # hard ceiling so a pagination bug can never loop forever


# ---------------------------------------------------------------------------
# Graph read (graph_query_api endpoint only — task AC-5 / OGTM)
# ---------------------------------------------------------------------------

def _graphsearch(params: Dict[str, Any]) -> Dict[str, Any]:
    if not GRAPH_QUERY_API_BASE:
        raise RuntimeError("GRAPH_QUERY_API_BASE is not configured")
    url = f"{GRAPH_QUERY_API_BASE}?{urlencode(params)}"
    req = _urllib_request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "X-Coordination-Internal-Key": INTERNAL_KEY,
        },
    )
    try:
        with _urllib_request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
            raw = resp.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "ignore")
        raise RuntimeError(f"graph_query_api HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"graph_query_api unreachable: {exc}") from exc
    body = json.loads(raw) if raw else {}
    if not body.get("success", False):
        raise RuntimeError(f"graph_query_api error: {body.get('error', body)}")
    return body


def _fetch_graph() -> Tuple[int, List[Tuple[str, str]], Optional[float], Optional[float]]:
    """Page the adjacency export; return (node_count, edge_list, spurious_attractor_rate, flow_weight_entropy).

    node_count is the total number of governed nodes (including isolated ones),
    so LCC ratios and degree means are taken relative to the whole graph.

    spurious_attractor_rate (ENC-FTR-105 AC-7 / ENC-TSK-I91) is read verbatim
    from the first adjacency page's optional ``spurious_attractor_rate`` key --
    a best-effort recent-average aggregate that graph_query_api itself computes
    from the enceladus-drift-telemetry table (this Lambda never touches that
    table directly, preserving the AC-5 "graph read EXCLUSIVELY through
    graph_query_api" OGTM contract and requiring no new IAM grant for this
    Lambda's role). None when the key is absent (an older graph_query_api
    deploy that predates ENC-TSK-I91) or when graph_query_api itself had no
    recent rate to report -- both degrade silently, never raising.

    flow_weight_entropy (ENC-FTR-108 AC-5 / ENC-TSK-J03) is likewise read from
    the first adjacency page when graph_query_api provides it; None otherwise.
    """
    edges: List[Tuple[str, str]] = []
    node_count = 0
    spurious_attractor_rate: Optional[float] = None
    flow_weight_entropy: Optional[float] = None
    offset = 0
    for page_idx in range(_MAX_PAGES):
        body = _graphsearch({
            "project_id": PROJECT_ID,
            "search_type": "adjacency",
            "offset": offset,
            "limit": ADJACENCY_PAGE_LIMIT,
        })
        if offset == 0:
            node_count = int(body.get("node_count", 0) or 0)
            raw_rate = body.get("spurious_attractor_rate")
            spurious_attractor_rate = float(raw_rate) if raw_rate is not None else None
            raw_entropy = body.get("flow_weight_entropy")
            flow_weight_entropy = float(raw_entropy) if raw_entropy is not None else None
        for e in body.get("edges", []):
            s, t = e.get("s"), e.get("t")
            if s and t and s != t:
                edges.append((s, t))
        if not body.get("has_more"):
            break
        next_offset = body.get("next_offset")
        offset = int(next_offset) if next_offset is not None else offset + ADJACENCY_PAGE_LIMIT
    else:
        logger.warning("[WARNING] adjacency pagination hit _MAX_PAGES=%d ceiling", _MAX_PAGES)
    logger.info(
        "[INFO] Graph read: node_count=%d edge_count=%d spurious_attractor_rate=%s flow_weight_entropy=%s",
        node_count, len(edges), spurious_attractor_rate, flow_weight_entropy,
    )
    return node_count, edges, spurious_attractor_rate, flow_weight_entropy


# ---------------------------------------------------------------------------
# Analytical p_c — Molloy-Reed (task AC-2)
# ---------------------------------------------------------------------------

def _degree_stats(node_count: int, edges: List[Tuple[str, str]]) -> Dict[str, float]:
    """Compute <k> and <k^2> over the full node set (isolated nodes have k=0)."""
    degree: Dict[str, int] = {}
    for s, t in edges:
        degree[s] = degree.get(s, 0) + 1
        degree[t] = degree.get(t, 0) + 1

    n = max(node_count, len(degree))  # defensive: never divide by an undercount
    if n <= 0:
        return {"mean_degree": 0.0, "mean_degree_sq": 0.0, "analytical_pc": 0.0}

    sum_k = sum(degree.values())  # = 2 * |E|
    sum_k2 = sum(d * d for d in degree.values())
    mean_degree = sum_k / n
    mean_degree_sq = sum_k2 / n
    analytical_pc = (mean_degree / mean_degree_sq) if mean_degree_sq > 0 else 0.0
    return {
        "mean_degree": mean_degree,
        "mean_degree_sq": mean_degree_sq,
        "analytical_pc": analytical_pc,
    }


# ---------------------------------------------------------------------------
# Empirical p_c — Monte Carlo site percolation (task AC-3)
# ---------------------------------------------------------------------------

class _UnionFind:
    __slots__ = ("parent", "size")

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}
        self.size: Dict[str, int] = {}

    def add(self, x: str) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.size[x] = 1

    def find(self, x: str) -> str:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]


def _largest_component_ratio(
    edges: List[Tuple[str, str]], occupied: set, n_total: int, rng: random.Random
) -> float:
    """LCC size (as a fraction of n_total) of the subgraph induced by occupied nodes."""
    if n_total <= 0:
        return 0.0
    uf = _UnionFind()
    for s, t in edges:
        if s in occupied and t in occupied:
            uf.add(s)
            uf.add(t)
            uf.union(s, t)
    largest = max(uf.size.values()) if uf.size else (1 if occupied else 0)
    return largest / n_total


def _component_ratios(
    edges: List[Tuple[str, str]], occupied: set, n_total: int
) -> Tuple[float, float]:
    """(largest, second-largest) component sizes as fractions of n_total.

    ENC-TSK-N51: the second-largest cluster is the percolation-susceptibility
    proxy — it peaks at the transition, giving a low-variance p_c estimator that
    (unlike the argmax-of-second-derivative of the LCC curve) is stable at modest
    trial counts. Computed in a single union-find pass, so this is essentially
    free relative to the existing LCC-only sweep.
    """
    if n_total <= 0:
        return 0.0, 0.0
    uf = _UnionFind()
    for s, t in edges:
        if s in occupied and t in occupied:
            uf.add(s)
            uf.add(t)
            uf.union(s, t)
    if not uf.size:
        # no active edge: every occupied node is its own singleton component
        return (1.0 / n_total if occupied else 0.0), 0.0
    # collapse to per-root component sizes; uf.size is only reliable at roots, so
    # re-derive cluster sizes by find()-grouping every participating node.
    root_sizes: Dict[str, int] = {}
    for node in uf.parent:
        r = uf.find(node)
        root_sizes[r] = root_sizes.get(r, 0) + 1
    ordered = sorted(root_sizes.values(), reverse=True)
    largest = ordered[0]
    second = ordered[1] if len(ordered) > 1 else 0
    return largest / n_total, second / n_total


def _monte_carlo_sweep(
    node_universe: List[str],
    edges: List[Tuple[str, str]],
    n_total: int,
    p_grid: List[float],
    trials: int,
    seed: int = 12345,
) -> List[float]:
    """Mean LCC ratio at each p, averaged over `trials` site-percolation draws."""
    rng = random.Random(seed)
    lcc_ratios: List[float] = []
    for p in p_grid:
        acc = 0.0
        for _ in range(trials):
            occupied = {v for v in node_universe if rng.random() < p}
            acc += _largest_component_ratio(edges, occupied, n_total, rng)
        lcc_ratios.append(acc / trials if trials > 0 else 0.0)
    return lcc_ratios


def _monte_carlo_sweep_full(
    node_universe: List[str],
    edges: List[Tuple[str, str]],
    n_total: int,
    p_grid: List[float],
    trials: int,
    seed: int = 12345,
) -> Tuple[List[float], List[float]]:
    """Mean (LCC ratio, second-largest-cluster ratio) at each p over `trials`.

    ENC-TSK-N51: extends _monte_carlo_sweep to also return the susceptibility
    proxy (second-largest cluster). Same occupation model and RNG walk, one
    union-find pass per trial — the second curve is nearly free. The LCC curve it
    returns is identical in methodology to _monte_carlo_sweep (retained for the
    legacy curvature estimate and its unit tests).
    """
    rng = random.Random(seed)
    lcc_ratios: List[float] = []
    second_ratios: List[float] = []
    for p in p_grid:
        acc1 = 0.0
        acc2 = 0.0
        for _ in range(trials):
            occupied = {v for v in node_universe if rng.random() < p}
            largest, second = _component_ratios(edges, occupied, n_total)
            acc1 += largest
            acc2 += second
        lcc_ratios.append(acc1 / trials if trials > 0 else 0.0)
        second_ratios.append(acc2 / trials if trials > 0 else 0.0)
    return lcc_ratios, second_ratios


def _empirical_pc(p_grid: List[float], lcc_ratios: List[float]) -> float:
    """p that maximizes the discrete second derivative of the LCC-ratio curve.

    LEGACY estimator (retained as empirical_pc_curvature). ENC-TSK-N51 found this
    has a high, trial-count-insensitive variance floor (2nd-difference argmax
    amplifies Monte-Carlo noise ~6x) and floats on tail noise on smeared
    heavy-tailed transitions. Prefer _empirical_pc_susceptibility for the primary
    signal.
    """
    if len(p_grid) < 3:
        return p_grid[len(p_grid) // 2] if p_grid else 0.0
    best_idx = 1
    best_d2 = float("-inf")
    for i in range(1, len(lcc_ratios) - 1):
        d2 = lcc_ratios[i + 1] - 2.0 * lcc_ratios[i] + lcc_ratios[i - 1]
        if d2 > best_d2:
            best_d2 = d2
            best_idx = i
    return p_grid[best_idx]


def _empirical_pc_susceptibility(p_grid: List[float], second_ratios: List[float]) -> float:
    """p that maximizes the mean second-largest-cluster ratio (susceptibility peak).

    ENC-TSK-N51 primary empirical estimator. The second-largest cluster is
    maximal at the percolation transition (it is consumed by the giant component
    above threshold), so its argmax is a low-variance, finite-size-consistent
    estimate of p_c. Stable to within one p-grid cell at MC_TRIALS≈160, versus the
    legacy curvature estimator whose spread stays ~0.1 even at n=1280.
    """
    if not p_grid or not second_ratios:
        return 0.0
    best_idx = max(range(len(second_ratios)), key=lambda i: second_ratios[i])
    return p_grid[best_idx]


def _linspace(lo: float, hi: float, n: int) -> List[float]:
    if n <= 1:
        return [lo]
    step = (hi - lo) / (n - 1)
    return [lo + step * i for i in range(n)]


# ---------------------------------------------------------------------------
# Persistence — DynamoDB + CloudWatch
# ---------------------------------------------------------------------------

def _write_ddb(row: Dict[str, Any]) -> None:
    table = boto3.resource("dynamodb", region_name=REGION).Table(PERCOLATION_TABLE)
    # Decimal round-trip so floats are accepted by DynamoDB.
    item = json.loads(json.dumps(row), parse_float=Decimal)
    table.put_item(Item=item)
    logger.info("[SUCCESS] Wrote percolation telemetry row pk=%s to %s", row.get("pk"), PERCOLATION_TABLE)


def _publish_cloudwatch(
    analytical_pc: float,
    empirical_pc: float,
    mean_degree: float,
    flow_weight_entropy: Optional[float] = None,
    empirical_pc_curvature: Optional[float] = None,
) -> None:
    cw = boto3.client("cloudwatch", region_name=REGION)
    now = datetime.now(timezone.utc)
    dims = [{"Name": "ProjectId", "Value": PROJECT_ID}]
    metric_data = [
        {"MetricName": "analytical_pc", "Value": float(analytical_pc), "Unit": "None", "Timestamp": now, "Dimensions": dims},
        {"MetricName": "empirical_pc", "Value": float(empirical_pc), "Unit": "None", "Timestamp": now, "Dimensions": dims},
        {"MetricName": "mean_degree", "Value": float(mean_degree), "Unit": "None", "Timestamp": now, "Dimensions": dims},
    ]
    # ENC-TSK-N51: keep publishing the legacy curvature estimate so the flatten
    # (its variance dropping once the estimator/trial-count change lands) is
    # visible against the new stable empirical_pc series.
    if empirical_pc_curvature is not None:
        metric_data.append({
            "MetricName": "empirical_pc_curvature",
            "Value": float(empirical_pc_curvature),
            "Unit": "None",
            "Timestamp": now,
            "Dimensions": dims,
        })
    if flow_weight_entropy is not None:
        metric_data.append({
            "MetricName": "flow_weight_entropy",
            "Value": float(flow_weight_entropy),
            "Unit": "None",
            "Timestamp": now,
            "Dimensions": dims,
        })
    cw.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=metric_data)
    logger.info(
        "[SUCCESS] Published Enceladus/Percolation metrics: analytical_pc=%.5f empirical_pc=%.5f mean_degree=%.4f flow_weight_entropy=%s",
        analytical_pc, empirical_pc, mean_degree, flow_weight_entropy,
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

# --- ENC-TSK-N24: rhythm heavy-beat completion-stanza contract --------------
# When invoked as a rhythm tenant (backend/lambda/rhythm_cycle/tenant_invoker
# .py), the invoke payload carries ``result_key`` — the exact S3 key this
# tenant must write its completion stanza to. Scheduled EventBridge invokes
# carry no result_key and skip the write. Stanza shape mirrors
# tenant_invoker.write_completion_stanza; a write failure is logged, never
# raised — the beat's silent-tenant detection treats a missing stanza as
# silence, which is the honest signal.

RHYTHM_TENANT_NAME = "percolation_monitor"
RHYTHM_RESULTS_BUCKET = os.environ.get("RHYTHM_RESULTS_BUCKET", "jreese-net")


def _write_rhythm_stanza(event: Any, status: str, detail: Optional[Dict[str, Any]] = None) -> bool:
    result_key = str((event or {}).get("result_key") or "").strip() if isinstance(event, dict) else ""
    if not result_key:
        return False
    body = {
        "tenant": RHYTHM_TENANT_NAME,
        "status": status,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail or {},
    }
    try:
        boto3.client("s3", region_name=REGION).put_object(
            Bucket=RHYTHM_RESULTS_BUCKET,
            Key=result_key,
            Body=json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        return True
    except Exception as exc:  # noqa: BLE001 — stanza failure must never break the run
        logger.warning("[ERROR] rhythm stanza write failed key=%s: %s", result_key, exc)
        return False


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point: run the percolation measurement, then honor the rhythm
    completion-stanza contract when invoked as a heavy-beat tenant
    (ENC-TSK-N24)."""
    try:
        resp = _run_percolation(event, context)
    except Exception:
        _write_rhythm_stanza(event, "failed", {})
        raise
    try:
        body = json.loads(resp.get("body") or "{}")
    except (TypeError, ValueError):
        body = {}
    status = "completed" if resp.get("statusCode") == 200 else "failed"
    detail = {"statusCode": resp.get("statusCode")}
    detail.update(
        {k: body.get(k) for k in ("analytical_pc", "empirical_pc", "node_count", "edge_count") if k in body}
    )
    _write_rhythm_stanza(event, status, detail)
    return resp


def _run_percolation(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("[START] Percolation monitor: project=%s table=%s", PROJECT_ID, PERCOLATION_TABLE)
    started = time.time()

    try:
        node_count, edges, spurious_attractor_rate, flow_weight_entropy = _fetch_graph()
        stats = _degree_stats(node_count, edges)
        analytical_pc = stats["analytical_pc"]
        mean_degree = stats["mean_degree"]

        node_universe = sorted({v for e in edges for v in e})
        n_total = max(node_count, len(node_universe))

        p_grid = _linspace(MC_P_MIN, MC_P_MAX, MC_NUM_P)
        lcc_ratios, second_ratios = _monte_carlo_sweep_full(
            node_universe, edges, n_total, p_grid, MC_TRIALS
        )
        # ENC-TSK-N51: primary empirical p_c is the low-variance susceptibility
        # peak. The legacy curvature estimate is retained for series continuity
        # and audit, but is not the alerting signal.
        empirical_pc = _empirical_pc_susceptibility(p_grid, second_ratios)
        empirical_pc_curvature = _empirical_pc(p_grid, lcc_ratios)

        computed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        date_str = computed_at[:10]
        row = {
            "pk": f"date#{date_str}",
            "project_id": PROJECT_ID,
            "computed_at": computed_at,
            "node_count": n_total,
            "edge_count": len(edges),
            "mean_degree": mean_degree,
            "mean_degree_sq": stats["mean_degree_sq"],
            "analytical_pc": analytical_pc,
            # ENC-TSK-N51: empirical_pc is now the susceptibility-peak estimate
            # (stable). The legacy argmax-2nd-derivative estimate is preserved as
            # empirical_pc_curvature so the historical series stays comparable and
            # the estimator change is auditable. empirical_pc_method names the
            # active estimator for downstream consumers.
            "empirical_pc": empirical_pc,
            "empirical_pc_curvature": empirical_pc_curvature,
            "empirical_pc_method": "susceptibility_peak",
            "sweep_second_cluster_ratio": [round(r, 6) for r in second_ratios],
            # ENC-FTR-105 AC-7 / ENC-TSK-I91: nullable, backward-compatible
            # schema addition -- recent spurious_attractor_rate aggregate
            # sourced from graph_query_api's adjacency response (see
            # _fetch_graph). None on an older graph_query_api deploy or when
            # no recent drift-telemetry record carries a non-null rate.
            "spurious_attractor_rate": spurious_attractor_rate,
            "flow_weight_entropy": flow_weight_entropy,
            "mc_trials": MC_TRIALS,
            "mc_num_p": MC_NUM_P,
            "sweep_p": [round(p, 6) for p in p_grid],
            "sweep_lcc_ratio": [round(r, 6) for r in lcc_ratios],
            "duration_ms": int((time.time() - started) * 1000),
        }

        analytical_in_range = 0.01 <= analytical_pc <= 0.99
        if not analytical_in_range:
            logger.warning(
                "[WARNING] analytical_pc=%.6f outside expected [0.01, 0.99] range "
                "(mean_degree=%.4f mean_degree_sq=%.4f node_count=%d edge_count=%d)",
                analytical_pc, mean_degree, stats["mean_degree_sq"], n_total, len(edges),
            )
        row["analytical_pc_in_range"] = analytical_in_range

        _write_ddb(row)
        _publish_cloudwatch(
            analytical_pc, empirical_pc, mean_degree, flow_weight_entropy,
            empirical_pc_curvature=empirical_pc_curvature,
        )

        logger.info(
            "[END] node_count=%d edge_count=%d analytical_pc=%.5f empirical_pc=%.5f "
            "empirical_pc_curvature=%.5f (method=susceptibility_peak) in %dms",
            n_total, len(edges), analytical_pc, empirical_pc, empirical_pc_curvature,
            row["duration_ms"],
        )
        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "node_count": n_total,
                "edge_count": len(edges),
                "mean_degree": round(mean_degree, 6),
                "analytical_pc": round(analytical_pc, 6),
                "empirical_pc": round(empirical_pc, 6),
                "empirical_pc_curvature": round(empirical_pc_curvature, 6),
                "empirical_pc_method": "susceptibility_peak",
                "analytical_pc_in_range": analytical_in_range,
                "spurious_attractor_rate": (
                    round(spurious_attractor_rate, 6) if spurious_attractor_rate is not None else None
                ),
            }),
        }
    except Exception as exc:
        logger.error("[ERROR] Percolation monitor failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"success": False, "error": str(exc)})}
