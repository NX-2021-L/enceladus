"""devops-graph-sync Lambda -- DynamoDB stream consumer for Neo4j AuraDB graph index.

Triggered by SQS FIFO queue (devops-graph-sync-queue.fifo) which receives
events from an EventBridge Pipe connected to the devops-project-tracker
DynamoDB Stream.

Flow:
  DynamoDB Streams -> EventBridge Pipe -> SQS FIFO -> This Lambda
  -> MERGE/DELETE Cypher operations against AuraDB Free

The graph is a READ-ONLY derived index. DynamoDB remains the sole source
of truth. Graph unavailability does NOT affect tracker mutations.

Node labels: Task, Issue, Feature, Project
Edge types: CHILD_OF, RELATED_TO, BELONGS_TO, ADDRESSES, IMPLEMENTS
           + ENC-FTR-049 typed edges: BLOCKS, BLOCKED_BY, DUPLICATES, DUPLICATED_BY,
             RELATES_TO, PARENT_OF, CHILD_OF_TYPED, DEPENDS_ON, DEPENDED_ON_BY,
             CLONES, CLONED_BY, AFFECTS, AFFECTED_BY, TESTS, TESTED_BY,
             CONSUMES_FROM, PRODUCES_FOR

Environment variables:
  NEO4J_SECRET_NAME    Secrets Manager secret ID (default: enceladus/neo4j/auradb-credentials)
  SECRETS_REGION       AWS region for Secrets Manager (default: us-west-2)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")

# ---------------------------------------------------------------------------
# Lazy singletons (cold-start cached)
# ---------------------------------------------------------------------------

_neo4j_driver = None
_secretsmanager = None


def _get_secretsmanager():
    global _secretsmanager
    if _secretsmanager is None:
        import boto3
        from botocore.config import Config
        _secretsmanager = boto3.client(
            "secretsmanager",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _secretsmanager


def _get_neo4j_credentials() -> Dict[str, str]:
    sm = _get_secretsmanager()
    resp = sm.get_secret_value(SecretId=NEO4J_SECRET_NAME)
    return json.loads(resp["SecretString"])


def _get_neo4j_driver():
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
        except ImportError:
            logger.error("[ERROR] neo4j driver not installed")
            return None
        creds = _get_neo4j_credentials()
        uri = creds["NEO4J_URI"]
        user = creds.get("NEO4J_USERNAME", "neo4j")
        password = creds["NEO4J_PASSWORD"]
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return _neo4j_driver


# ---------------------------------------------------------------------------
# DynamoDB deserialization
# ---------------------------------------------------------------------------

def _deser_value(ddb_val: Dict) -> Any:
    """Deserialize a single DynamoDB-typed value."""
    if "S" in ddb_val:
        return ddb_val["S"]
    if "N" in ddb_val:
        return ddb_val["N"]
    if "BOOL" in ddb_val:
        return ddb_val["BOOL"]
    if "NULL" in ddb_val:
        return None
    if "L" in ddb_val:
        return [_deser_value(v) for v in ddb_val["L"]]
    if "M" in ddb_val:
        return {k: _deser_value(v) for k, v in ddb_val["M"].items()}
    if "SS" in ddb_val:
        return list(ddb_val["SS"])
    return str(ddb_val)


def _deser_image(image: Dict) -> Dict[str, Any]:
    """Deserialize a DynamoDB stream NewImage/OldImage dict."""
    return {k: _deser_value(v) for k, v in image.items()}


# ---------------------------------------------------------------------------
# Graph schema constants
# ---------------------------------------------------------------------------

RECORD_TYPE_TO_LABEL = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
}

def _bare_id(record_id: str) -> str:
    """Strip 'type#' prefix from composite DynamoDB record_id.

    DynamoDB record_id: 'task#ENC-TSK-890' -> 'ENC-TSK-890'
    Bare IDs pass through unchanged.
    """
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


# Properties to copy from DynamoDB record to Neo4j node
NODE_PROPERTIES = [
    "record_id", "project_id", "title", "status", "priority",
    "category", "updated_at", "created_at",
]


# ---------------------------------------------------------------------------
# Cypher operations
# ---------------------------------------------------------------------------

def _upsert_node(tx, record: Dict[str, Any]) -> None:
    """MERGE a node by record_id (bare format) and set properties."""
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label:
        return

    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    if not record_id:
        return

    props = {k: record.get(k) for k in NODE_PROPERTIES if record.get(k) is not None}
    props["record_id"] = record_id

    cypher = (
        f"MERGE (n:{label} {{record_id: $record_id}}) "
        "SET n += $props"
    )
    tx.run(cypher, record_id=record_id, props=props)


def _upsert_project_node(tx, project_id: str) -> None:
    """Ensure a :Project node exists."""
    tx.run(
        "MERGE (p:Project {project_id: $pid})",
        pid=project_id,
    )


def _reconcile_edges(tx, record: Dict[str, Any]) -> None:
    """Delete existing edges for node then re-create from record fields."""
    record_id = _bare_id(record.get("record_id", record.get("item_id", "")))
    record_type = record.get("record_type", "")
    label = RECORD_TYPE_TO_LABEL.get(record_type)
    if not label or not record_id:
        return

    # Remove all outgoing relationships so we can re-create from current state
    tx.run(
        f"MATCH (n:{label}) WHERE n.record_id = $rid "
        "OPTIONAL MATCH (n)-[r]->() DELETE r",
        rid=record_id,
    )
    # Also remove incoming RELATED_TO since we'll re-create from current state
    tx.run(
        f"MATCH (n:{label}) WHERE n.record_id = $rid "
        "OPTIONAL MATCH ()-[r:RELATED_TO]->(n) DELETE r",
        rid=record_id,
    )

    project_id = record.get("project_id", "")

    # BELONGS_TO -> Project
    if project_id:
        tx.run(
            f"MATCH (n:{label}), (p:Project) "
            "WHERE n.record_id = $rid AND p.project_id = $pid "
            "MERGE (n)-[:BELONGS_TO]->(p)",
            rid=record_id, pid=project_id,
        )

    # CHILD_OF -> parent Task
    parent = _bare_id(record.get("parent", ""))
    if parent and record_type == "task":
        tx.run(
            "MATCH (child:Task), (parent:Task) "
            "WHERE child.record_id = $child_id AND parent.record_id = $parent_id "
            "MERGE (child)-[:CHILD_OF]->(parent)",
            child_id=record_id, parent_id=parent,
        )

    # RELATED_TO from related_task_ids (single directed edge, not bidirectional)
    for related_id in record.get("related_task_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Task) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )

    # RELATED_TO from related_issue_ids + ADDRESSES (Task->Issue)
    for related_id in record.get("related_issue_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Issue) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task), (i:Issue) "
                "WHERE t.record_id = $tid AND i.record_id = $iid "
                "MERGE (t)-[:ADDRESSES]->(i)",
                tid=record_id, iid=related_id,
            )

    # RELATED_TO from related_feature_ids + IMPLEMENTS (Task->Feature)
    for related_id in record.get("related_feature_ids", []) or []:
        related_id = _bare_id(related_id) if related_id else ""
        if not related_id:
            continue
        tx.run(
            f"MATCH (a:{label}), (b:Feature) "
            "WHERE a.record_id = $aid AND b.record_id = $bid "
            "MERGE (a)-[:RELATED_TO]->(b)",
            aid=record_id, bid=related_id,
        )
        if record_type == "task":
            tx.run(
                "MATCH (t:Task), (f:Feature) "
                "WHERE t.record_id = $tid AND f.record_id = $fid "
                "MERGE (t)-[:IMPLEMENTS]->(f)",
                tid=record_id, fid=related_id,
            )


# ---------------------------------------------------------------------------
# Typed Relationship Edge Projection (ENC-FTR-049)
# ---------------------------------------------------------------------------

RELATIONSHIP_TYPE_TO_EDGE_LABEL = {
    "blocks": "BLOCKS", "blocked-by": "BLOCKED_BY",
    "duplicates": "DUPLICATES", "duplicated-by": "DUPLICATED_BY",
    "relates-to": "RELATES_TO",
    "parent-of": "PARENT_OF", "child-of": "CHILD_OF_TYPED",
    "depends-on": "DEPENDS_ON", "depended-on-by": "DEPENDED_ON_BY",
    "clones": "CLONES", "cloned-by": "CLONED_BY",
    "affects": "AFFECTS", "affected-by": "AFFECTED_BY",
    "tests": "TESTS", "tested-by": "TESTED_BY",
    "consumes-from": "CONSUMES_FROM", "produces-for": "PRODUCES_FOR",
}


def _upsert_relationship_edge(tx, record: Dict[str, Any]) -> None:
    """MERGE a typed relationship edge with properties from a DynamoDB relationship record."""
    rel_type = record.get("relationship_type", "")
    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    source_id = _bare_id(record.get("source_id", ""))
    target_id = _bare_id(record.get("target_id", ""))
    if not source_id or not target_id:
        return

    props = {}
    for key in ("weight", "confidence", "reason", "provenance", "is_inverse", "created_at"):
        val = record.get(key)
        if val is not None:
            props[key] = float(val) if key in ("weight", "confidence") else val

    cypher = (
        f"MATCH (s {{record_id: $source_id}}), (t {{record_id: $target_id}}) "
        f"MERGE (s)-[r:{edge_label} {{source_id: $source_id, target_id: $target_id}}]->(t) "
        "SET r += $props"
    )
    tx.run(cypher, source_id=source_id, target_id=target_id, props=props)


def _delete_relationship_edge(tx, record_id_sk: str) -> None:
    """Delete a typed relationship edge from Neo4j using the DynamoDB SK."""
    parts = record_id_sk.split("#")
    if len(parts) < 4 or parts[0] != "rel":
        return
    source_id = parts[1]
    rel_type = parts[2]
    target_id = parts[3]

    edge_label = RELATIONSHIP_TYPE_TO_EDGE_LABEL.get(rel_type)
    if not edge_label:
        return

    cypher = (
        f"MATCH (s {{record_id: $source_id}})-[r:{edge_label}]->(t {{record_id: $target_id}}) "
        "DELETE r"
    )
    tx.run(cypher, source_id=source_id, target_id=target_id)


def _delete_node(tx, record_id: str) -> None:
    """DETACH DELETE a node by record_id across all labels."""
    for label in RECORD_TYPE_TO_LABEL.values():
        tx.run(
            f"MATCH (n:{label} {{record_id: $rid}}) DETACH DELETE n",
            rid=record_id,
        )


# ---------------------------------------------------------------------------
# SQS event processing
# ---------------------------------------------------------------------------

def _extract_stream_record(sqs_body: Dict) -> Optional[Dict]:
    """Extract the DynamoDB stream record from an SQS message body."""
    # EventBridge Pipe wraps stream records in the SQS body
    if "dynamodb" in sqs_body:
        return sqs_body
    # Sometimes the body is double-wrapped
    if isinstance(sqs_body, str):
        try:
            return json.loads(sqs_body)
        except (json.JSONDecodeError, TypeError):
            return None
    return sqs_body


def _process_record(driver, stream_record: Dict) -> None:
    """Process a single DynamoDB stream record."""
    event_name = stream_record.get("eventName", "")
    dynamodb = stream_record.get("dynamodb", {})

    if event_name in ("INSERT", "MODIFY"):
        new_image = dynamodb.get("NewImage", {})
        if not new_image:
            return

        record = _deser_image(new_image)
        record_type = record.get("record_type", "")

        # ENC-FTR-049: Handle typed relationship records
        if record_type == "relationship":
            with driver.session() as session:
                session.execute_write(lambda tx: _upsert_relationship_edge(tx, record))
            logger.info(
                "[INFO] Synced relationship %s -> %s (%s, event=%s)",
                record.get("source_id", ""), record.get("target_id", ""),
                record.get("relationship_type", ""), event_name,
            )
            return

        # Skip non-entity records
        if record_type not in RECORD_TYPE_TO_LABEL:
            return

        # Skip COUNTER records
        record_id = record.get("record_id", record.get("item_id", ""))
        if record_id and record_id.startswith("COUNTER-"):
            return

        with driver.session() as session:
            # Ensure project node exists
            project_id = record.get("project_id", "")
            if project_id:
                session.execute_write(lambda tx: _upsert_project_node(tx, project_id))

            session.execute_write(lambda tx: _upsert_node(tx, record))
            session.execute_write(lambda tx: _reconcile_edges(tx, record))

        logger.info(
            "[INFO] Synced %s %s (event=%s, project=%s)",
            record_type, record_id, event_name, record.get("project_id", ""),
        )

    elif event_name == "REMOVE":
        keys = dynamodb.get("Keys", {})
        record_id_val = keys.get("record_id", {}).get("S", "")
        if not record_id_val:
            return

        # ENC-FTR-049: Handle relationship record removal
        if record_id_val.startswith("rel#"):
            with driver.session() as session:
                session.execute_write(lambda tx: _delete_relationship_edge(tx, record_id_val))
            logger.info("[INFO] Deleted relationship edge %s (event=REMOVE)", record_id_val)
            return

        # Extract the actual item_id from the record_id key
        # DynamoDB record_id format: "task#ENC-TSK-123" or bare "ENC-TSK-123"
        item_id = record_id_val.split("#", 1)[-1] if "#" in record_id_val else record_id_val

        with driver.session() as session:
            session.execute_write(lambda tx: _delete_node(tx, item_id))

        logger.info("[INFO] Deleted node %s (event=REMOVE)", item_id)


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """SQS-triggered handler. Processes DynamoDB stream records from EventBridge Pipe."""
    records = event.get("Records", [])
    if not records:
        return {"statusCode": 200, "body": "no records"}

    driver = _get_neo4j_driver()
    if driver is None:
        logger.error("[ERROR] Neo4j driver unavailable; returning success to avoid infinite SQS retry")
        return {"statusCode": 200, "body": "neo4j unavailable - skipping"}

    processed = 0
    errors = 0

    for sqs_record in records:
        try:
            body = sqs_record.get("body", "{}")
            if isinstance(body, str):
                body = json.loads(body)

            stream_record = _extract_stream_record(body)
            if stream_record and "dynamodb" in stream_record:
                _process_record(driver, stream_record)
                processed += 1
        except Exception:
            errors += 1
            logger.exception("[ERROR] Failed to process SQS record")
            # Don't re-raise; let the batch continue.
            # Failed messages will be retried via SQS visibility timeout
            # and eventually land in DLQ after maxReceiveCount.

    logger.info("[INFO] Batch complete: processed=%d, errors=%d, total=%d", processed, errors, len(records))

    # If ALL records failed, raise to trigger SQS retry for the batch
    if errors > 0 and processed == 0:
        raise RuntimeError(f"All {errors} records in batch failed")

    return {"statusCode": 200, "body": json.dumps({"processed": processed, "errors": errors})}
