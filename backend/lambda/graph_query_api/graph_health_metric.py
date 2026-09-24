"""ENC-TSK-K43 (B66 Phase-5, gamma re-delivery of ENC-TSK-C10) -- Fiedler
lambda-2 GraphHealth CloudWatch metric.

Publishes the graph's algebraic connectivity (the Fiedler value, lambda-2 --
the smallest *non-trivial* eigenvalue of the graph Laplacian) to CloudWatch
under the ``Enceladus/GraphHealth`` namespace, as the primary structural
health signal for the extended-mind substrate (DOC-A3D0CDF91CE9 Q3.3).

ISS-465 GDS cost-kill compliance: this module computes lambda-2 EXCLUSIVELY
via the existing FTR-088 ``_query_laplacian`` CSR/Fiedler path in
lambda_function.py -- an ad-hoc, per-invocation scipy.sparse.linalg.eigsh (or
dense numpy.linalg.eigh fallback) computation over an induced subgraph. It
never touches Neo4j GDS / Aura Graph Analytics (gds.graph.project, an AGA
session, or any standing/materialized graph catalog projection) and is NOT
gated by _GDS_HARD_DISABLED -- that flag only governs the separate ENC-FTR-101
standing-projection code path used by hybrid retrieval's graph signal. The two
paths are architecturally distinct; this module only ever calls the former.

Invocation contract (mirrors the FTR-101 _handle_refresh_projection / FTR-108
_handle_refresh_flow_weight pattern in lambda_function.py -- same Lambda, same
file layout, action-dispatched):

    lambda_handler(event, context) with event like
        {"action": "publish_graph_health"}                      # full defaults
        {"action": "publish_graph_health", "project_id": "...",
         "limit": 500, "k": 3}                                  # overrides

EventBridge wiring: a scheduled rule Input carrying the JSON above, mirroring
prod_health_monitor's 15-minute cadence (05-monitoring.yaml
HealthProbeScheduleRule). The CFN rule for this task targets the existing
devops-graph-query-api Lambda (no new function), consistent with the
ParityDriftDailyScheduleRule precedent of pointing a schedule's Input at an
existing multi-action Lambda.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# CloudWatch namespace + metric name (AC-1).
GRAPH_HEALTH_NAMESPACE = "Enceladus/GraphHealth"
FIEDLER_METRIC_NAME = "FiedlerValue"

# Default project + vertex cap for the scheduled probe. Mirrors
# _HEALTH_PROBE_PROJECT (ENC-ISS-312) -- the canonical project this Lambda's
# other scheduled/health probes already default to.
DEFAULT_PROJECT_ID = "enceladus"
DEFAULT_VERTEX_LIMIT = 500
DEFAULT_K = 3

# CloudWatch PutMetricData accepts at most 20 MetricDatum entries per call.
_CLOUDWATCH_BATCH_SIZE = 20

# ENC-ISS-554: floor below which a computed eigenvalue is treated as
# degenerate rather than a trustworthy positive lambda2. eigsh/eigh on an
# INDUCED SUBGRAPH capped at LAPLACIAN_MAX_VERTICES vertices can legitimately
# compute a near-zero second eigenvalue when the cap truncates the true graph
# short (real neighbors of a selected vertex fall outside the sample, leaving
# it isolated within the induced subgraph even though it is well-connected in
# the full graph) -- a real number, not an exception or a hardcoded default,
# but not a trustworthy reading of the full graph's algebraic connectivity
# either. Treating any lambda2 at or below this floor as ok=False (rather
# than a confident zero) is the quarantine.
_LAMBDA2_DEGENERATE_EPSILON = 1e-9


def compute_fiedler_value(
    driver: Any,
    project_id: str,
    *,
    query_laplacian_fn,
    limit: int = DEFAULT_VERTEX_LIMIT,
    k: int = DEFAULT_K,
    vertex_set_query: str = "",
    edge_type_filter: str = "",
) -> Dict[str, Any]:
    """Derive lambda-2 (the Fiedler value) via the FTR-088 CSR/Fiedler path.

    ``query_laplacian_fn`` is dependency-injected (the caller passes
    lambda_function._query_laplacian) so this module never imports the parent
    package -- it stays a plain, independently unit-testable function. The
    Laplacian handler's eigenvalues are returned ascending with eigenvalues[0]
    the trivial (~0) eigenpair for a connected graph, so eigenvalues[1] is
    lambda-2 whenever k >= 2 -- request-side k is bumped to 2 for that reason.

    Returns {"ok": True, "lambda2": float, "n": int, "eig_method": str, ...}
    on success, or {"ok": False, "error": str} on any resolution failure
    (empty vertex set, <2 vertices, disconnected-graph degenerate spectrum,
    etc.) -- never raises, so a bad probe cannot break the caller's publish
    loop.
    """
    req_k = max(2, k)
    result = query_laplacian_fn(
        driver,
        project_id,
        {
            "k": req_k,
            "limit": limit,
            "vertex_set_query": vertex_set_query,
            "edge_type_filter": edge_type_filter,
            "normalization": "combinatorial",
        },
    )
    if "error" in result:
        return {"ok": False, "error": result["error"], "project_id": project_id}

    eigenvalues: List[float] = result.get("eigenvalues") or []
    if len(eigenvalues) < 2:
        return {
            "ok": False,
            "error": f"graph_laplacian returned {len(eigenvalues)} eigenvalue(s); need >= 2 for lambda2",
            "project_id": project_id,
        }

    lambda2 = float(eigenvalues[1])
    laplacian_meta = result.get("laplacian") or {}
    n = laplacian_meta.get("n")

    if lambda2 <= _LAMBDA2_DEGENERATE_EPSILON:
        # ENC-ISS-554 quarantine: a degenerate lambda2 must never be reported
        # as ok=True. Distinguish (for the error message only -- both cases
        # return ok=False identically) a capped/non-representative sample
        # from a full vertex set that came back genuinely disconnected.
        capped = isinstance(n, int) and isinstance(limit, int) and n >= limit
        if capped:
            reason = (
                f"lambda2={lambda2!r} is degenerate for an induced subgraph capped at "
                f"n={n} vertices (limit={limit}); this is very likely a sampling artifact "
                "-- the vertex cap truncates the corpus, stranding real neighbors outside "
                "the sample and producing spurious isolated components even though the "
                "full graph is connected -- not a measurement of the full graph's "
                "algebraic connectivity"
            )
            invalid_reason = "sample_capped_degenerate"
        else:
            reason = (
                f"lambda2={lambda2!r} is degenerate for a full (uncapped, n={n}) vertex "
                "set; this would indicate genuine full-graph disconnection and needs "
                "manual review rather than being published as a routine reading"
            )
            invalid_reason = "genuine_disconnection_suspected"
        return {
            "ok": False,
            "error": reason,
            "invalid_reason": invalid_reason,
            "lambda2_raw": lambda2,
            "n": n,
            "limit": limit,
            "project_id": project_id,
        }

    return {
        "ok": True,
        "lambda2": lambda2,
        "lambda0": float(eigenvalues[0]),
        "n": n,
        "edge_count": laplacian_meta.get("edge_count"),
        "eig_method": laplacian_meta.get("eig_method"),
        "normalization": laplacian_meta.get("normalization"),
        "project_id": project_id,
    }


def build_fiedler_metric_datum(fiedler_result: Dict[str, Any], *, timestamp=None) -> Dict[str, Any]:
    """Assemble one CloudWatch MetricDatum for a successful compute_fiedler_value result."""
    if timestamp is None:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc)
    return {
        "MetricName": FIEDLER_METRIC_NAME,
        "Value": fiedler_result["lambda2"],
        "Unit": "None",
        "Timestamp": timestamp,
        "Dimensions": [
            {"Name": "ProjectId", "Value": fiedler_result.get("project_id") or DEFAULT_PROJECT_ID},
        ],
    }


def publish_metric_data(cw_client: Any, metric_data: List[Dict[str, Any]]) -> int:
    """PutMetricData in batches of <= 20 (CloudWatch's per-call cap). Returns
    the number of datapoints published. Empty input is a no-op (returns 0)."""
    published = 0
    for i in range(0, len(metric_data), _CLOUDWATCH_BATCH_SIZE):
        batch = metric_data[i:i + _CLOUDWATCH_BATCH_SIZE]
        cw_client.put_metric_data(Namespace=GRAPH_HEALTH_NAMESPACE, MetricData=batch)
        published += len(batch)
    return published


def run_publish_graph_health(
    driver: Any,
    cw_client: Any,
    *,
    query_laplacian_fn,
    project_ids: Optional[List[str]] = None,
    limit: int = DEFAULT_VERTEX_LIMIT,
    k: int = DEFAULT_K,
) -> Dict[str, Any]:
    """End-to-end: compute lambda-2 per project (FTR-088 CSR/Fiedler path,
    ISS-465-compliant -- no GDS) and publish each as one CloudWatch datapoint
    to Enceladus/GraphHealth. Never raises -- per-project failures are
    collected in ``results`` so one bad project cannot blank the whole probe.
    """
    projects = project_ids or [DEFAULT_PROJECT_ID]
    results: List[Dict[str, Any]] = []
    metric_data: List[Dict[str, Any]] = []

    for project_id in projects:
        fiedler = compute_fiedler_value(
            driver, project_id, query_laplacian_fn=query_laplacian_fn, limit=limit, k=k,
        )
        results.append(fiedler)
        if fiedler.get("ok"):
            metric_data.append(build_fiedler_metric_datum(fiedler))
        else:
            logger.warning(
                "[WARNING] GraphHealth lambda2 probe failed for project_id=%s: %s",
                project_id, fiedler.get("error"),
            )

    published = publish_metric_data(cw_client, metric_data) if metric_data else 0
    ok = published > 0
    logger.info(
        "[%s] GraphHealth publish: %d/%d project(s) published to %s",
        "SUCCESS" if ok else "WARNING", published, len(projects), GRAPH_HEALTH_NAMESPACE,
    )
    return {"ok": ok, "published": published, "namespace": GRAPH_HEALTH_NAMESPACE, "results": results}


def handle_publish_graph_health(
    event: Dict[str, Any],
    *,
    get_driver_fn,
    get_cloudwatch_fn,
    query_laplacian_fn,
) -> Dict[str, Any]:
    """EventBridge / direct-invoke entrypoint (action='publish_graph_health').

    Mirrors _handle_refresh_projection's/_handle_refresh_flow_weight's
    dependency-injection contract: the caller (lambda_function.lambda_handler)
    passes its own driver/cloudwatch-client/getter and the FTR-088
    _query_laplacian function, so this module has no import-time coupling to
    lambda_function.py and stays independently unit-testable.
    """
    driver = get_driver_fn()
    if driver is None:
        return {"ok": False, "error": "neo4j driver unavailable"}
    cw_client = get_cloudwatch_fn()
    project_ids = event.get("project_ids") or ([event["project_id"]] if event.get("project_id") else None)
    limit = int(event.get("limit", DEFAULT_VERTEX_LIMIT) or DEFAULT_VERTEX_LIMIT)
    k = int(event.get("k", DEFAULT_K) or DEFAULT_K)
    return run_publish_graph_health(
        driver, cw_client,
        query_laplacian_fn=query_laplacian_fn,
        project_ids=project_ids,
        limit=limit,
        k=k,
    )
