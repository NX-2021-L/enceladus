#!/usr/bin/env python3
"""Backfill Neo4j graph index from DynamoDB tracker table.

Scans devops-project-tracker, creates nodes and edges in Neo4j AuraDB.
Uses MERGE for idempotent upserts. Filters out COUNTER-* records.

Usage:
    NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
    python3 tools/backfill_graph.py --region us-west-2
"""
import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

# AuraDB Free tier limits
FREE_TIER_NODE_LIMIT = 50_000
FREE_TIER_RELATIONSHIP_LIMIT = 175_000

RECORD_TYPE_TO_LABEL = {
    "task": "Task",
    "issue": "Issue",
    "feature": "Feature",
    "project": "Project",
}


def get_neo4j_credentials(secret_name: str, region: str) -> Dict[str, str]:
    client = boto3.client("secretsmanager", region_name=region)
    resp = client.get_secret_value(SecretId=secret_name)
    return json.loads(resp["SecretString"])


def get_neo4j_driver(creds: Dict[str, str]):
    from neo4j import GraphDatabase
    return GraphDatabase.driver(
        creds["NEO4J_URI"],
        auth=(creds["NEO4J_USERNAME"], creds["NEO4J_PASSWORD"]),
    )


def scan_tracker_table(region: str, table_name: str = "devops-project-tracker"):
    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(table_name)
    kwargs: Dict[str, Any] = {}
    total = 0
    while True:
        resp = table.scan(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            record_id = item.get("record_id", "")
            if record_id.startswith("COUNTER-"):
                continue
            yield item
            total += 1
            if total % 100 == 0:
                logger.info("[INFO] Scanned %d records so far", total)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    logger.info("[INFO] Total records scanned: %d", total)


def determine_label(record: Dict[str, Any]) -> Optional[str]:
    record_id = record.get("record_id", "")
    record_type = record.get("record_type", "")
    if record_type in RECORD_TYPE_TO_LABEL:
        return RECORD_TYPE_TO_LABEL[record_type]
    parts = record_id.split("-")
    if len(parts) >= 3:
        type_part = parts[1].lower()
        if type_part == "tsk":
            return "Task"
        elif type_part == "iss":
            return "Issue"
        elif type_part == "ftr":
            return "Feature"
        elif type_part == "prj":
            return "Project"
    return "Task"


def merge_node(tx, record: Dict[str, Any], label: str):
    record_id = record.get("record_id", "")
    project_id = record.get("project_id", "")
    props = {
        "record_id": record_id,
        "project_id": project_id,
        "title": record.get("title", ""),
        "status": record.get("status", ""),
        "priority": record.get("priority", ""),
        "record_type": record.get("record_type", ""),
        "updated_at": record.get("updated_at", ""),
    }
    query = f"""
    MERGE (n:{label} {{record_id: $record_id}})
    SET n.project_id = $project_id,
        n.title = $title,
        n.status = $status,
        n.priority = $priority,
        n.record_type = $record_type,
        n.updated_at = $updated_at
    """
    tx.run(query, **props)


def reconcile_edges(tx, record: Dict[str, Any]):
    record_id = record.get("record_id", "")
    project_id = record.get("project_id", "")

    # CHILD_OF: child -> parent
    parent = record.get("parent", "")
    if parent:
        tx.run(
            """
            MATCH (child {record_id: $child_id, project_id: $project_id})
            MATCH (parent {record_id: $parent_id, project_id: $project_id})
            MERGE (child)-[:CHILD_OF]->(parent)
            """,
            child_id=record_id, parent_id=parent, project_id=project_id,
        )

    # BELONGS_TO: record -> project node (if project node exists)
    if project_id:
        tx.run(
            """
            MATCH (n {record_id: $record_id, project_id: $project_id})
            MATCH (p:Project {project_id: $project_id})
            MERGE (n)-[:BELONGS_TO]->(p)
            """,
            record_id=record_id, project_id=project_id,
        )

    # RELATED_TO: from related_ids
    related_ids = record.get("related_ids", []) or []
    if isinstance(related_ids, str):
        related_ids = [related_ids]
    for rid in related_ids:
        if rid:
            tx.run(
                """
                MATCH (a {record_id: $a_id, project_id: $project_id})
                MATCH (b {record_id: $b_id, project_id: $project_id})
                MERGE (a)-[:RELATED_TO]-(b)
                """,
                a_id=record_id, b_id=rid, project_id=project_id,
            )

    # ADDRESSES: task -> issue (from related_issue_ids)
    related_issue_ids = record.get("related_issue_ids", []) or []
    if isinstance(related_issue_ids, str):
        related_issue_ids = [related_issue_ids]
    for iid in related_issue_ids:
        if iid:
            tx.run(
                """
                MATCH (t {record_id: $task_id, project_id: $project_id})
                MATCH (i {record_id: $issue_id, project_id: $project_id})
                MERGE (t)-[:ADDRESSES]->(i)
                """,
                task_id=record_id, issue_id=iid, project_id=project_id,
            )

    # IMPLEMENTS: task -> feature (from related_feature_ids)
    related_feature_ids = record.get("related_feature_ids", []) or []
    if isinstance(related_feature_ids, str):
        related_feature_ids = [related_feature_ids]
    for fid in related_feature_ids:
        if fid:
            tx.run(
                """
                MATCH (t {record_id: $task_id, project_id: $project_id})
                MATCH (f {record_id: $feature_id, project_id: $project_id})
                MERGE (t)-[:IMPLEMENTS]->(f)
                """,
                task_id=record_id, feature_id=fid, project_id=project_id,
            )


def report_counts(driver):
    with driver.session() as session:
        node_count = session.run("MATCH (n) RETURN count(n) AS cnt").single()["cnt"]
        edge_count = session.run("MATCH ()-[r]->() RETURN count(r) AS cnt").single()["cnt"]
    logger.info("[INFO] Graph node count: %d / %d (%.1f%% of free tier)",
                node_count, FREE_TIER_NODE_LIMIT,
                100 * node_count / FREE_TIER_NODE_LIMIT)
    logger.info("[INFO] Graph relationship count: %d / %d (%.1f%% of free tier)",
                edge_count, FREE_TIER_RELATIONSHIP_LIMIT,
                100 * edge_count / FREE_TIER_RELATIONSHIP_LIMIT)
    return node_count, edge_count


def main():
    parser = argparse.ArgumentParser(description="Backfill Neo4j graph from DynamoDB tracker table")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--table", default="devops-project-tracker")
    parser.add_argument("--secret-name", default=None,
                        help="Secrets Manager secret name (default: env NEO4J_SECRET_NAME)")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, no graph writes")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    secret_name = args.secret_name or os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")

    logger.info("[START] Backfill graph from %s (region=%s)", args.table, args.region)

    records = list(scan_tracker_table(args.region, args.table))
    logger.info("[INFO] Loaded %d records (excluding COUNTER-*)", len(records))

    if args.dry_run:
        logger.info("[END] Dry run complete — %d records would be backfilled", len(records))
        return

    logger.info("[INFO] Connecting to Neo4j...")
    creds = get_neo4j_credentials(secret_name, args.region)
    driver = get_neo4j_driver(creds)

    # Phase 1: Create all nodes
    logger.info("[START] Creating nodes...")
    start = time.time()
    with driver.session() as session:
        for i, record in enumerate(records, 1):
            label = determine_label(record)
            session.execute_write(merge_node, record, label)
            if i % 100 == 0:
                logger.info("[INFO] Nodes created: %d / %d", i, len(records))
    logger.info("[END] Nodes created in %.1fs", time.time() - start)

    # Phase 2: Reconcile all edges
    logger.info("[START] Reconciling edges...")
    start = time.time()
    with driver.session() as session:
        for i, record in enumerate(records, 1):
            session.execute_write(reconcile_edges, record)
            if i % 100 == 0:
                logger.info("[INFO] Edges reconciled: %d / %d", i, len(records))
    logger.info("[END] Edges reconciled in %.1fs", time.time() - start)

    node_count, edge_count = report_counts(driver)
    driver.close()

    logger.info("[SUCCESS] Backfill complete: %d nodes, %d relationships", node_count, edge_count)


if __name__ == "__main__":
    main()
