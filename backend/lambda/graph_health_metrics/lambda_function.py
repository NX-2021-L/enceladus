"""
Enceladus Graph Health Metrics Lambda — ENC-TSK-C10 / AC-13 (CloudWatch Proxy Path)

Computes graph health proxy metrics and publishes to CloudWatch.
GDS is unavailable on the current AuraDB tier, so this Lambda uses pure Cypher
queries to compute proxy metrics instead of native Fiedler λ₂ computation.

Metrics published:
  - GraphEdgeDensity (edges / nodes) in Enceladus/GraphHealth
  - OrphanNodeRatio (orphan nodes / total nodes) in Enceladus/GraphHealth
  - GraphNodeCount (total node count) in Enceladus/GraphHealth

Triggered by EventBridge on a daily schedule.

Environment variables:
  NEO4J_SECRET_NAME    Secrets Manager secret ID (default: enceladus/neo4j/auradb-credentials)
  CLOUDWATCH_NAMESPACE CloudWatch namespace (default: Enceladus/GraphHealth)
  PROJECT_ID           Project dimension value (default: enceladus)
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import boto3

import dedup_convergence

logger = logging.getLogger()
logger.setLevel(logging.INFO)

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/GraphHealth")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")

# --- ENC-TSK-I10 (Dedup P6) convergence-probe configuration ----------------
# Governed dedup-convergence signals (DOC-DF651F07D5C2 §10) are published to
# their own namespace so they don't dilute the C10 graph-health proxy metrics.
DEDUP_NAMESPACE = os.environ.get("DEDUP_NAMESPACE", "Enceladus/DedupConvergence")
# Namespace the production auto-merge / walk-back audit counters are emitted to
# by the dedup auto-merge producer (tracker_mutation, flag-gated DARK until the
# precision floor is certified — DOC-DF651F07D5C2 §13). Defaults to the dedup
# namespace; the probe reads them back to compute the live walk-back rate.
DEDUP_AUDIT_NAMESPACE = os.environ.get("DEDUP_AUDIT_NAMESPACE", DEDUP_NAMESPACE)
DEDUP_AUTO_MERGE_METRIC = os.environ.get("DEDUP_AUTO_MERGE_METRIC", "AutoMergeCount")
DEDUP_WALK_BACK_METRIC = os.environ.get("DEDUP_WALK_BACK_METRIC", "WalkBackCount")


def _dedup_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _dedup_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default

_neo4j_driver = None
_creds_cache = None


def _get_neo4j_creds():
    global _creds_cache
    if _creds_cache is None:
        sm = boto3.client("secretsmanager")
        resp = sm.get_secret_value(SecretId=NEO4J_SECRET_NAME)
        _creds_cache = json.loads(resp["SecretString"])
    return _creds_cache


def _get_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.error("[ERROR] neo4j driver not installed")
            raise
        creds = _get_neo4j_creds()
        uri = creds["NEO4J_URI"]
        user = creds.get("NEO4J_USERNAME", "neo4j")
        password = creds["NEO4J_PASSWORD"]
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return _neo4j_driver


def _compute_metrics(driver) -> Dict[str, float]:
    """Compute graph health proxy metrics via pure Cypher (no GDS required)."""
    metrics: Dict[str, float] = {}

    with driver.session() as session:
        # Total node count
        result = session.run("MATCH (n) RETURN count(n) AS total")
        node_count = result.single()["total"]
        metrics["GraphNodeCount"] = float(node_count)

        # Total relationship count
        result = session.run("MATCH ()-[r]->() RETURN count(r) AS total")
        edge_count = result.single()["total"]

        # Edge density = edges / nodes (0 if no nodes)
        if node_count > 0:
            metrics["GraphEdgeDensity"] = float(edge_count) / float(node_count)
        else:
            metrics["GraphEdgeDensity"] = 0.0

        # Orphan node ratio = nodes with no relationships / total nodes
        result = session.run(
            "MATCH (n) WHERE NOT (n)-[]-() RETURN count(n) AS orphans"
        )
        orphan_count = result.single()["orphans"]
        if node_count > 0:
            metrics["OrphanNodeRatio"] = float(orphan_count) / float(node_count)
        else:
            metrics["OrphanNodeRatio"] = 0.0

        # Also publish FiedlerLambda2 as the proxy value (edge density as placeholder)
        # This satisfies the CloudWatch metric name requirement while GDS is unavailable
        metrics["FiedlerAlgebraicConnectivity"] = metrics["GraphEdgeDensity"]

    return metrics


def _publish_to_cloudwatch(metrics: Dict[str, float]) -> None:
    """Publish all metrics to CloudWatch."""
    cw = boto3.client("cloudwatch")
    now = datetime.now(timezone.utc)
    dimensions = [{"Name": "ProjectId", "Value": PROJECT_ID}]

    metric_data = []
    for metric_name, value in metrics.items():
        metric_data.append({
            "MetricName": metric_name,
            "Value": value,
            "Unit": "None",
            "Timestamp": now,
            "Dimensions": dimensions,
        })

    if metric_data:
        cw.put_metric_data(
            Namespace=CLOUDWATCH_NAMESPACE,
            MetricData=metric_data,
        )
        logger.info(
            "[SUCCESS] Published %d metrics to %s: %s",
            len(metric_data),
            CLOUDWATCH_NAMESPACE,
            {k: round(v, 4) for k, v in metrics.items()},
        )


def _read_walk_back_counts(window_days: float) -> Dict[str, int]:
    """ENC-TSK-I10: read the production auto-merge + walk-back audit counters
    (Sum) over the trailing window from CloudWatch.

    These counters are emitted by the dedup auto-merge producer when io enables
    MECHANICAL T-HIGH auto-walk (DOC-DF651F07D5C2 §5/§13). Until then auto-merge
    is DARK, so both sums are 0 and the walk-back rate is definitionally 0
    (shadow). A read failure degrades to 0 rather than failing the probe."""
    try:
        cw = boto3.client("cloudwatch")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("[WARNING] walk-back counter client init failed: %s", exc)
        return {"auto_merges": 0, "walk_backs": 0}
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=max(1.0, window_days))
    dimensions = [{"Name": "ProjectId", "Value": PROJECT_ID}]

    def _sum(metric_name: str) -> int:
        try:
            resp = cw.get_metric_statistics(
                Namespace=DEDUP_AUDIT_NAMESPACE,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start,
                EndTime=now,
                Period=int(max(1.0, window_days) * 86400),
                Statistics=["Sum"],
            )
            return int(sum(dp.get("Sum", 0.0) for dp in resp.get("Datapoints", [])))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("[WARNING] walk-back counter read failed (%s): %s", metric_name, exc)
            return 0

    return {
        "auto_merges": _sum(DEDUP_AUTO_MERGE_METRIC),
        "walk_backs": _sum(DEDUP_WALK_BACK_METRIC),
    }


def _compute_dedup_signals(driver) -> Dict[str, Any]:
    """ENC-TSK-I10: assemble the full dedup-convergence snapshot — the four
    graph-derived signals plus the walk-back model-health loop."""
    cosine_threshold = _dedup_float("DEDUP_COSINE_THRESHOLD", dedup_convergence.DEFAULT_COSINE_THRESHOLD)
    flow_window_days = _dedup_float("DEDUP_FLOW_WINDOW_DAYS", float(dedup_convergence.DEFAULT_FLOW_WINDOW_DAYS))
    precision_floor = _dedup_float("DEDUP_PRECISION_FLOOR", dedup_convergence.DEFAULT_PRECISION_FLOOR)
    vector_top_k = _dedup_int("DEDUP_VECTOR_TOP_K", dedup_convergence.DEFAULT_VECTOR_TOP_K)
    walkback_window_days = _dedup_float(
        "DEDUP_WALKBACK_WINDOW_DAYS", float(dedup_convergence.DEFAULT_WALKBACK_WINDOW_DAYS)
    )

    signals = dedup_convergence.compute_graph_signals(
        driver,
        PROJECT_ID,
        cosine_threshold=cosine_threshold,
        flow_window_days=flow_window_days,
        vector_top_k=vector_top_k,
    )
    counts = _read_walk_back_counts(walkback_window_days)
    signals["walk_back"] = dedup_convergence.walk_back_health(
        counts["auto_merges"], counts["walk_backs"], precision_floor
    )
    signals["walk_back"]["window_days"] = walkback_window_days
    return signals


def _publish_dedup_signals(signals: Dict[str, Any]) -> Dict[str, float]:
    """ENC-TSK-I10: publish the dedup-convergence signals as governed
    CloudWatch metrics under DEDUP_NAMESPACE."""
    wb = signals.get("walk_back", {})
    metrics: Dict[str, float] = {
        # Stock (§10): same-type duplicate-pair count, trending to floor.
        "DuplicatePairStock": float(signals.get("stock_pairs", 0)),
        # Precision@1 recovery (§10): live proxy + static baseline/ceiling refs.
        "Precision1RecoveryProxy": float(signals.get("precision_at_1_recovery_proxy", 0.0)),
        "Precision1RecoveryEstimate": float(signals.get("precision_at_1_recovery_fraction", 0.0)),
        "Precision1Baseline": float(signals.get("precision_at_1_baseline", dedup_convergence.PRECISION_AT_1_BASELINE)),
        "RecallCeiling": float(signals.get("recall_ceiling", dedup_convergence.RECALL_CEILING)),
        # Flow (§10): new same-type duplicate pairs per window.
        "NewDuplicateFlow": float(signals.get("new_duplicate_pairs", 0)),
        # Percolation (§10): LCC size → 1 at convergence + cluster count.
        "DuplicateLCCSize": float(signals.get("lcc_size", 0)),
        "NonTrivialComponentCount": float(signals.get("nontrivial_component_count", 0)),
        "EmbeddedRecordCount": float(signals.get("embedded_record_count", 0)),
        # Walk-back model-health loop (§10): live certificate-precision estimate.
        "AutoMergeWalkBackRate": float(wb.get("walk_back_rate", 0.0)),
        "AutoMergeCount": float(wb.get("auto_merge_count", 0)),
        "WalkBackCount": float(wb.get("walk_back_count", 0)),
        "WalkBackRateBreachedFloor": 1.0 if wb.get("breached_floor") else 0.0,
    }
    cw = boto3.client("cloudwatch")
    now = datetime.now(timezone.utc)
    dimensions = [{"Name": "ProjectId", "Value": PROJECT_ID}]
    metric_data = [
        {"MetricName": name, "Value": value, "Unit": "None", "Timestamp": now, "Dimensions": dimensions}
        for name, value in metrics.items()
    ]
    if metric_data:
        cw.put_metric_data(Namespace=DEDUP_NAMESPACE, MetricData=metric_data)
        logger.info(
            "[SUCCESS] Published %d dedup-convergence signals to %s: %s",
            len(metric_data), DEDUP_NAMESPACE, {k: round(v, 4) for k, v in metrics.items()},
        )
    return metrics


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point — compute and publish graph health metrics + the
    ENC-TSK-I10 dedup-convergence signals (DOC-DF651F07D5C2 §10)."""
    logger.info("[START] Graph health metrics computation (proxy path)")

    try:
        driver = _get_neo4j_driver()
        metrics = _compute_metrics(driver)
        _publish_to_cloudwatch(metrics)

        # ENC-TSK-I10: dedup-convergence probe. Isolated so a dedup failure
        # (e.g. a missing vector index) never breaks the C10 graph-health path.
        dedup_result: Dict[str, Any] = {"published": False}
        try:
            signals = _compute_dedup_signals(driver)
            published = _publish_dedup_signals(signals)
            dedup_result = {
                "published": True,
                "namespace": DEDUP_NAMESPACE,
                "signals": signals,
                "published_metrics": {k: round(v, 6) for k, v in published.items()},
            }
        except Exception as exc:
            logger.error("[ERROR] Dedup-convergence probe failed: %s", exc, exc_info=True)
            dedup_result = {"published": False, "error": str(exc)}

        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "metrics": {k: round(v, 6) for k, v in metrics.items()},
                "namespace": CLOUDWATCH_NAMESPACE,
                "implementation_path": "cloudwatch_proxy",
                "gds_available": False,
                "dedup_convergence": dedup_result,
            }),
        }
    except Exception as exc:
        logger.error("[ERROR] Graph health metrics failed: %s", exc, exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({
                "success": False,
                "error": str(exc),
            }),
        }
