"""Neo4j AuraDB graph snapshot to S3.

Connects to Neo4j via bolt, exports all nodes and relationships as JSON,
uploads to S3. Runs daily via EventBridge schedule.

Restore path: tools/backfill_graph.py re-projects from DynamoDB (source of truth).
"""
import boto3
import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_secretsmanager = None
_neo4j_creds = None


def _get_secrets():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=os.environ.get("SECRETS_REGION", "us-west-2"),
        )
    return _secretsmanager


def _get_neo4j_credentials():
    global _neo4j_creds
    if _neo4j_creds is None:
        secret_name = os.environ.get(
            "NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials"
        )
        resp = _get_secrets().get_secret_value(SecretId=secret_name)
        _neo4j_creds = json.loads(resp["SecretString"])
    return _neo4j_creds


def _export_graph(driver):
    """Export all nodes and relationships from Neo4j as JSON."""
    nodes = []
    relationships = []

    with driver.session() as session:
        # Export all nodes
        result = session.run(
            "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props"
        )
        for record in result:
            nodes.append({
                "labels": record["labels"],
                "properties": record["props"],
            })

        # Export all relationships
        result = session.run(
            "MATCH (a)-[r]->(b) "
            "RETURN type(r) AS type, properties(r) AS props, "
            "properties(a).record_id AS source_id, "
            "properties(b).record_id AS target_id, "
            "labels(a) AS source_labels, labels(b) AS target_labels"
        )
        for record in result:
            relationships.append({
                "type": record["type"],
                "properties": record["props"],
                "source_id": record["source_id"],
                "target_id": record["target_id"],
                "source_labels": record["source_labels"],
                "target_labels": record["target_labels"],
            })

    return {"nodes": nodes, "relationships": relationships}


def lambda_handler(event, context):
    """Export Neo4j graph snapshot to S3."""
    from neo4j import GraphDatabase

    s3_bucket = os.environ.get("S3_BUCKET", "jreese-net")
    s3_prefix = os.environ.get("S3_PREFIX", "neo4j-backups/")
    region = os.environ.get("AWS_REGION", "us-west-2")

    start_time = time.time()
    now = datetime.now(timezone.utc)
    date_path = now.strftime("%Y/%m/%d")
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")

    logger.info("[START] Neo4j graph snapshot export")

    # Connect to Neo4j
    creds = _get_neo4j_credentials()
    driver = GraphDatabase.driver(
        creds["NEO4J_URI"],
        auth=(creds.get("NEO4J_USERNAME", "neo4j"), creds["NEO4J_PASSWORD"]),
    )

    try:
        # Verify connectivity
        driver.verify_connectivity()
        logger.info("[INFO] Neo4j connection verified")

        # Export graph
        graph_data = _export_graph(driver)
        node_count = len(graph_data["nodes"])
        rel_count = len(graph_data["relationships"])
        logger.info(
            "[INFO] Exported %d nodes, %d relationships", node_count, rel_count
        )

        # Add metadata
        graph_data["metadata"] = {
            "exported_at": now.isoformat(),
            "node_count": node_count,
            "relationship_count": rel_count,
            "source": "neo4j-backup-lambda",
            "neo4j_uri": creds["NEO4J_URI"],
            "restore_instructions": (
                "Primary: python tools/backfill_graph.py --region us-west-2 "
                "(rebuilds from DynamoDB source of truth, ~5-10 min). "
                "This S3 snapshot is for audit reference."
            ),
        }

        # Upload to S3
        s3 = boto3.client("s3", region_name=region)
        s3_key = f"{s3_prefix}{date_path}/neo4j-snapshot-{timestamp}.json"

        s3.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=json.dumps(graph_data, default=str, indent=2),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

        elapsed = time.time() - start_time
        logger.info(
            "[SUCCESS] Snapshot uploaded to s3://%s/%s (%d nodes, %d rels, %.1fs)",
            s3_bucket, s3_key, node_count, rel_count, elapsed,
        )

        return {
            "statusCode": 200,
            "s3_bucket": s3_bucket,
            "s3_key": s3_key,
            "node_count": node_count,
            "relationship_count": rel_count,
            "elapsed_seconds": round(elapsed, 1),
        }

    finally:
        driver.close()
