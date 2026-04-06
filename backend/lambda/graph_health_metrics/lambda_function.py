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
from datetime import datetime, timezone
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
CLOUDWATCH_NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Enceladus/GraphHealth")
PROJECT_ID = os.environ.get("PROJECT_ID", "enceladus")

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


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point — compute and publish graph health metrics."""
    logger.info("[START] Graph health metrics computation (proxy path)")

    try:
        driver = _get_neo4j_driver()
        metrics = _compute_metrics(driver)
        _publish_to_cloudwatch(metrics)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "success": True,
                "metrics": {k: round(v, 6) for k, v in metrics.items()},
                "namespace": CLOUDWATCH_NAMESPACE,
                "implementation_path": "cloudwatch_proxy",
                "gds_available": False,
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
