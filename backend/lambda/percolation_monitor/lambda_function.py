"""comp-percolation-monitor — nightly percolation-threshold telemetry Lambda.

ENC-TSK-I88 / ENC-FTR-085 (ENC-PLN-006 v4/gamma). Produces an authoritative
nightly measurement of the knowledge-graph percolation threshold p_c, feeding the
Budget Hierarchy Controller's corpus-scale percolation-margin alert ladder
(DOC-C6584044BEEB Primitive 4).

Two independent estimates are computed every run:

  * Analytical p_c (Molloy-Reed). On the configuration model a giant component
    exists iff <k^2>/<k> > 2. The critical occupation probability reported here is
    p_c = <k> / <k^2>, computed directly from the live degree sequence (task AC-2).

  * Empirical p_c (Monte Carlo site percolation). Each node is occupied with
    probability p; an edge is active iff both endpoints are occupied. For a grid
    of 30 p-values the mean largest-connected-component (LCC) ratio is measured
    over several trials, and p_c is taken as the p that maximizes the discrete
    second derivative of the LCC-ratio curve — the percolation onset (task AC-3).

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
  MC_TRIALS                     Monte Carlo trials per p-value (default: 40)
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

MC_TRIALS = int(os.environ.get("MC_TRIALS", "40"))
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


def _fetch_graph() -> Tuple[int, List[Tuple[str, str]], Optional[float]]:
    """Page the adjacency export; return (node_count, edge_list, spurious_attractor_rate).

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
    """
    edges: List[Tuple[str, str]] = []
    node_count = 0
    spurious_attractor_rate: Optional[float] = None
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
        "[INFO] Graph read: node_count=%d edge_count=%d spurious_attractor_rate=%s",
        node_count, len(edges), spurious_attractor_rate,
    )
    return node_count, edges, spurious_attractor_rate


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


def _empirical_pc(p_grid: List[float], lcc_ratios: List[float]) -> float:
    """p that maximizes the discrete second derivative of the LCC-ratio curve."""
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


def _publish_cloudwatch(analytical_pc: float, empirical_pc: float, mean_degree: float) -> None:
    cw = boto3.client("cloudwatch", region_name=REGION)
    now = datetime.now(timezone.utc)
    dims = [{"Name": "ProjectId", "Value": PROJECT_ID}]
    metric_data = [
        {"MetricName": "analytical_pc", "Value": float(analytical_pc), "Unit": "None", "Timestamp": now, "Dimensions": dims},
        {"MetricName": "empirical_pc", "Value": float(empirical_pc), "Unit": "None", "Timestamp": now, "Dimensions": dims},
        {"MetricName": "mean_degree", "Value": float(mean_degree), "Unit": "None", "Timestamp": now, "Dimensions": dims},
    ]
    cw.put_metric_data(Namespace=CLOUDWATCH_NAMESPACE, MetricData=metric_data)
    logger.info(
        "[SUCCESS] Published Enceladus/Percolation metrics: analytical_pc=%.5f empirical_pc=%.5f mean_degree=%.4f",
        analytical_pc, empirical_pc, mean_degree,
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("[START] Percolation monitor: project=%s table=%s", PROJECT_ID, PERCOLATION_TABLE)
    started = time.time()

    try:
        node_count, edges, spurious_attractor_rate = _fetch_graph()
        stats = _degree_stats(node_count, edges)
        analytical_pc = stats["analytical_pc"]
        mean_degree = stats["mean_degree"]

        node_universe = sorted({v for e in edges for v in e})
        n_total = max(node_count, len(node_universe))

        p_grid = _linspace(MC_P_MIN, MC_P_MAX, MC_NUM_P)
        lcc_ratios = _monte_carlo_sweep(node_universe, edges, n_total, p_grid, MC_TRIALS)
        empirical_pc = _empirical_pc(p_grid, lcc_ratios)

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
            "empirical_pc": empirical_pc,
            # ENC-FTR-105 AC-7 / ENC-TSK-I91: nullable, backward-compatible
            # schema addition -- recent spurious_attractor_rate aggregate
            # sourced from graph_query_api's adjacency response (see
            # _fetch_graph). None on an older graph_query_api deploy or when
            # no recent drift-telemetry record carries a non-null rate.
            "spurious_attractor_rate": spurious_attractor_rate,
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
        _publish_cloudwatch(analytical_pc, empirical_pc, mean_degree)

        logger.info(
            "[END] node_count=%d edge_count=%d analytical_pc=%.5f empirical_pc=%.5f in %dms",
            n_total, len(edges), analytical_pc, empirical_pc, row["duration_ms"],
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
                "analytical_pc_in_range": analytical_in_range,
                "spurious_attractor_rate": (
                    round(spurious_attractor_rate, 6) if spurious_attractor_rate is not None else None
                ),
            }),
        }
    except Exception as exc:
        logger.error("[ERROR] Percolation monitor failed: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"success": False, "error": str(exc)})}
