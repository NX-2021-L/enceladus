#!/usr/bin/env python3
"""Backfill Neo4j graph index from DynamoDB tracker + document tables.

Replays the current ``graph_sync`` node and edge projection logic against the
authoritative DynamoDB corpus so parity repairs do not fork the live contract.
Supports optional graph wipe before replay to remove historical phantom nodes.

Usage:
    NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
    python3 tools/backfill_graph.py --region us-west-2
"""
import argparse
import importlib.util
import json
import logging
import os
import pathlib
import sys
import time
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)

# AuraDB Free tier limits
FREE_TIER_NODE_LIMIT = 50_000
FREE_TIER_RELATIONSHIP_LIMIT = 175_000


def _load_graph_sync_module():
    """Load the canonical graph_sync implementation for parity replays."""
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    graph_sync_dir = repo_root / "backend" / "lambda" / "graph_sync"
    if str(graph_sync_dir) not in sys.path:
        sys.path.insert(0, str(graph_sync_dir))
    spec = importlib.util.spec_from_file_location(
        "enceladus_graph_sync_backfill_module",
        graph_sync_dir / "lambda_function.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


GS = _load_graph_sync_module()
RECORD_TYPE_TO_LABEL = GS.RECORD_TYPE_TO_LABEL


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


def scan_table(region: str, table_name: str):
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
    logger.info("[INFO] Total records scanned from %s: %d", table_name, total)


def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Apply graph_sync's identity normalization to scanned DynamoDB rows."""
    normalized = GS._normalize_record_for_graph(dict(record))
    if normalized.get("document_id") and not normalized.get("record_type"):
        normalized["record_type"] = "document"
    return normalized


def _load_projection_records(
    region: str,
    tracker_table: str,
    documents_table: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for item in scan_table(region, tracker_table):
        records.append(_normalize_record(item))
    for item in scan_table(region, documents_table):
        records.append(_normalize_record(item))
    return records


def _is_entity_record(record: Dict[str, Any]) -> bool:
    return str(record.get("record_type") or "").strip() in RECORD_TYPE_TO_LABEL


def _is_relationship_record(record: Dict[str, Any]) -> bool:
    return str(record.get("record_type") or "").strip() == "relationship"


def _wipe_graph(driver) -> None:
    """Clear the existing graph before replaying projection state."""
    with driver.session() as session:
        summary = session.run("MATCH (n) DETACH DELETE n").consume()
    counters = summary.counters
    logger.info(
        "[INFO] Cleared graph: nodes_deleted=%s relationships_deleted=%s",
        counters.nodes_deleted,
        counters.relationships_deleted,
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
    parser = argparse.ArgumentParser(description="Backfill Neo4j graph from governed DynamoDB tables")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--tracker-table", default="devops-project-tracker")
    parser.add_argument("--documents-table", default="documents")
    parser.add_argument("--secret-name", default=None,
                        help="Secrets Manager secret name (default: env NEO4J_SECRET_NAME)")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, no graph writes")
    parser.add_argument("--wipe-existing", action="store_true",
                        help="DETACH DELETE the current graph before replaying projection state")
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

    logger.info(
        "[START] Backfill graph from %s + %s (region=%s)",
        args.tracker_table,
        args.documents_table,
        args.region,
    )

    records = _load_projection_records(args.region, args.tracker_table, args.documents_table)
    entity_records = [record for record in records if _is_entity_record(record)]
    relationship_records = [record for record in records if _is_relationship_record(record)]
    logger.info(
        "[INFO] Loaded %d entity records and %d relationship records",
        len(entity_records),
        len(relationship_records),
    )

    if args.dry_run:
        logger.info(
            "[END] Dry run complete — %d entity rows and %d relationship rows would be replayed",
            len(entity_records),
            len(relationship_records),
        )
        return

    logger.info("[INFO] Connecting to Neo4j...")
    creds = get_neo4j_credentials(secret_name, args.region)
    driver = get_neo4j_driver(creds)

    if args.wipe_existing:
        _wipe_graph(driver)

    # Phase 1: Create all nodes
    logger.info("[START] Creating nodes...")
    start = time.time()
    with driver.session() as session:
        for i, record in enumerate(entity_records, 1):
            project_id = str(record.get("project_id") or "").strip()
            if project_id:
                session.execute_write(GS._upsert_project_node, project_id)
            session.execute_write(GS._upsert_node, record)
            if i % 100 == 0:
                logger.info("[INFO] Nodes created: %d / %d", i, len(entity_records))
    logger.info("[END] Nodes created in %.1fs", time.time() - start)

    # Phase 2: Reconcile all edges
    logger.info("[START] Reconciling edges...")
    start = time.time()
    with driver.session() as session:
        for i, record in enumerate(entity_records, 1):
            session.execute_write(GS._reconcile_edges, record)
            if i % 100 == 0:
                logger.info("[INFO] Entity edges reconciled: %d / %d", i, len(entity_records))
        for i, record in enumerate(relationship_records, 1):
            if str(record.get("status") or "").strip() == "archived":
                session.execute_write(GS._delete_relationship_edge, record.get("record_id", ""))
            else:
                session.execute_write(GS._upsert_relationship_edge, record)
            if i % 100 == 0:
                logger.info(
                    "[INFO] Relationship edges reconciled: %d / %d",
                    i,
                    len(relationship_records),
                )
    logger.info("[END] Edges reconciled in %.1fs", time.time() - start)

    node_count, edge_count = report_counts(driver)
    driver.close()

    logger.info("[SUCCESS] Backfill complete: %d nodes, %d relationships", node_count, edge_count)


if __name__ == "__main__":
    main()
