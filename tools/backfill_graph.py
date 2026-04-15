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


def _bare_id(record_id: str) -> str:
    """Strip the 'type#' prefix from a composite DynamoDB record_id.

    DynamoDB stores record_ids as 'task#ENC-TSK-890' but related fields
    and user queries use bare IDs like 'ENC-TSK-890'.
    """
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


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
    record_id = _bare_id(record.get("record_id", ""))
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
    record_id = _bare_id(record.get("record_id", ""))
    project_id = record.get("project_id", "")

    # CHILD_OF: child -> parent
    parent = _bare_id(record.get("parent", ""))
    if parent:
        tx.run(
            "MATCH (child), (parent) "
            "WHERE child.record_id = $child_id AND child.project_id = $project_id "
            "AND parent.record_id = $parent_id AND parent.project_id = $project_id "
            "MERGE (child)-[:CHILD_OF]->(parent)",
            child_id=record_id, parent_id=parent, project_id=project_id,
        )

    # BELONGS_TO: record -> project node (if project node exists)
    if project_id:
        tx.run(
            "MATCH (n), (p:Project) "
            "WHERE n.record_id = $record_id AND n.project_id = $project_id "
            "AND p.project_id = $project_id "
            "MERGE (n)-[:BELONGS_TO]->(p)",
            record_id=record_id, project_id=project_id,
        )

    # RELATED_TO: from related_task_ids
    related_task_ids = record.get("related_task_ids", []) or []
    if isinstance(related_task_ids, str):
        related_task_ids = [related_task_ids]
    for rid in related_task_ids:
        rid = _bare_id(rid) if rid else ""
        if rid:
            tx.run(
                "MATCH (a), (b) "
                "WHERE a.record_id = $a_id AND a.project_id = $project_id "
                "AND b.record_id = $b_id AND b.project_id = $project_id "
                "MERGE (a)-[:RELATED_TO]->(b)",
                a_id=record_id, b_id=rid, project_id=project_id,
            )

    # RELATED_TO + ADDRESSES: from related_issue_ids
    related_issue_ids = record.get("related_issue_ids", []) or []
    if isinstance(related_issue_ids, str):
        related_issue_ids = [related_issue_ids]
    for iid in related_issue_ids:
        iid = _bare_id(iid) if iid else ""
        if iid:
            tx.run(
                "MATCH (a), (b) "
                "WHERE a.record_id = $a_id AND a.project_id = $project_id "
                "AND b.record_id = $b_id AND b.project_id = $project_id "
                "MERGE (a)-[:RELATED_TO]->(b)",
                a_id=record_id, b_id=iid, project_id=project_id,
            )
            tx.run(
                "MATCH (t), (i) "
                "WHERE t.record_id = $task_id AND t.project_id = $project_id "
                "AND i.record_id = $issue_id AND i.project_id = $project_id "
                "MERGE (t)-[:ADDRESSES]->(i)",
                task_id=record_id, issue_id=iid, project_id=project_id,
            )

    # RELATED_TO + IMPLEMENTS: from related_feature_ids
    related_feature_ids = record.get("related_feature_ids", []) or []
    if isinstance(related_feature_ids, str):
        related_feature_ids = [related_feature_ids]
    for fid in related_feature_ids:
        fid = _bare_id(fid) if fid else ""
        if fid:
            tx.run(
                "MATCH (a), (b) "
                "WHERE a.record_id = $a_id AND a.project_id = $project_id "
                "AND b.record_id = $b_id AND b.project_id = $project_id "
                "MERGE (a)-[:RELATED_TO]->(b)",
                a_id=record_id, b_id=fid, project_id=project_id,
            )
            tx.run(
                "MATCH (t), (f) "
                "WHERE t.record_id = $task_id AND t.project_id = $project_id "
                "AND f.record_id = $feature_id AND f.project_id = $project_id "
                "MERGE (t)-[:IMPLEMENTS]->(f)",
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


def _split_cypher_statements(text: str) -> List[str]:
    """Split a .cypher file into individual statements.

    Strips `//` line comments before splitting on `;`. Ignores trailing
    whitespace-only fragments. Does not attempt to honor semicolons inside
    string literals -- the migration files under tools/neo4j-migrations/ do
    not use them, and this helper is not a general-purpose Cypher parser.
    """
    scrubbed_lines = []
    for line in text.splitlines():
        comment_at = line.find("//")
        if comment_at >= 0:
            line = line[:comment_at]
        scrubbed_lines.append(line)
    blob = "\n".join(scrubbed_lines)
    statements = []
    for chunk in blob.split(";"):
        chunk = chunk.strip()
        if chunk:
            statements.append(chunk)
    return statements


def run_migration_file(driver, path: str) -> int:
    """Run each Cypher statement in `path` against the Neo4j driver.

    Returns the count of statements executed. Each statement runs in its own
    auto-commit transaction (migrations are expected to use `IF NOT EXISTS`
    for idempotency, not transactional rollback).
    """
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    statements = _split_cypher_statements(text)
    if not statements:
        logger.warning("[WARN] No executable statements in %s", path)
        return 0
    logger.info("[START] Running migration %s (%d statements)", path, len(statements))
    with driver.session() as session:
        for i, stmt in enumerate(statements, 1):
            preview = " ".join(stmt.split())[:80]
            logger.info("[INFO] [%d/%d] %s", i, len(statements), preview)
            session.run(stmt).consume()
    logger.info("[END] Migration complete: %d statements applied", len(statements))
    return len(statements)


def show_vector_indexes(driver) -> List[Dict[str, Any]]:
    """Return all vector indexes currently defined on the Neo4j instance."""
    with driver.session() as session:
        result = session.run(
            "SHOW VECTOR INDEXES "
            "YIELD name, state, labelsOrTypes, properties, options"
        )
        rows = [dict(record) for record in result]
    logger.info("[INFO] %d vector index(es) found", len(rows))
    for row in rows:
        index_config = (row.get("options") or {}).get("indexConfig") or {}
        dim = index_config.get("vector.dimensions")
        sim = index_config.get("vector.similarity_function")
        logger.info(
            "[INFO]   - %s state=%s labels=%s props=%s dim=%s sim=%s",
            row.get("name"),
            row.get("state"),
            row.get("labelsOrTypes"),
            row.get("properties"),
            dim,
            sim,
        )
    return rows


def main():
    parser = argparse.ArgumentParser(description="Backfill Neo4j graph from DynamoDB tracker table")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--table", default="devops-project-tracker")
    parser.add_argument("--secret-name", default=None,
                        help="Secrets Manager secret name (default: env NEO4J_SECRET_NAME)")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, no graph writes")
    parser.add_argument("--run-migration", default=None,
                        help="Path to a .cypher migration file; when set, runs only the migration "
                             "and exits (no DynamoDB scan, no backfill). See "
                             "tools/neo4j-migrations/ for managed migrations.")
    parser.add_argument("--verify-vector-indexes", action="store_true",
                        help="Run SHOW VECTOR INDEXES and print each index's name, state, "
                             "labels, properties, and (dimensions, similarity_function). "
                             "Implies skip-backfill; exits after printing.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)

    secret_name = args.secret_name or os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")

    # Migration / verification fast paths -- run before the DynamoDB scan and
    # exit without touching the tracker table or backfilling any records.
    if args.run_migration or args.verify_vector_indexes:
        logger.info("[INFO] Connecting to Neo4j (secret=%s, region=%s)...",
                    secret_name, args.region)
        creds = get_neo4j_credentials(secret_name, args.region)
        driver = get_neo4j_driver(creds)
        try:
            if args.run_migration:
                run_migration_file(driver, args.run_migration)
            if args.verify_vector_indexes:
                show_vector_indexes(driver)
        finally:
            driver.close()
        return

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
