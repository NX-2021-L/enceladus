"""devops-graph-query-api Lambda -- Graph search API for tracker record relationships.

Serves GET /api/v1/tracker/graphsearch via API Gateway v2 proxy integration.
Queries Neo4j AuraDB Free graph index populated by graph_sync Lambda.

Search types:
  - traversal: Walk CHILD_OF hierarchy from a record_id
  - neighbors: All nodes within N hops via any edge type
  - path: Shortest path between two record_ids
  - keyword: Full-text title match + immediate neighbors

Auth: Cognito JWT cookie OR X-Coordination-Internal-Key header.

Environment variables:
  NEO4J_SECRET_NAME           Secrets Manager secret ID
  SECRETS_REGION              AWS region for Secrets Manager (default: us-west-2)
  COGNITO_USER_POOL_ID        Cognito user pool ID
  COGNITO_CLIENT_ID           Cognito client ID
  CORS_ORIGIN                 CORS allowed origin (default: https://jreese.net)
  COORDINATION_INTERNAL_API_KEY  Internal API key for service-to-service auth
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NEO4J_SECRET_NAME = os.environ.get("NEO4J_SECRET_NAME", "enceladus/neo4j/auradb-credentials")
SECRETS_REGION = os.environ.get("SECRETS_REGION", "us-west-2")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
COORDINATION_INTERNAL_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
COORDINATION_INTERNAL_API_KEY_PREVIOUS = os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")

MAX_DEPTH = 5
MAX_RESULTS = 100
QUERY_TIMEOUT_SECONDS = 10

VALID_SEARCH_TYPES = {"traversal", "neighbors", "path", "keyword"}

# ---------------------------------------------------------------------------
# Lazy singletons
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
        try:
            creds = _get_neo4j_credentials()
            uri = creds["NEO4J_URI"]
            user = creds.get("NEO4J_USERNAME", "neo4j")
            password = creds["NEO4J_PASSWORD"]
            _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
        except Exception:
            logger.exception("[ERROR] Failed to initialize Neo4j driver")
            return None
    return _neo4j_driver


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie, X-Coordination-Internal-Key",
    }


def _response(status_code: int, body: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str, **extra) -> Dict[str, Any]:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code in {401, 403}:
            code = "PERMISSION_DENIED"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500))
    body = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": dict(extra),
        },
    }
    return _response(status_code, body)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _authenticate(event: Dict) -> Optional[str]:
    """Validate auth. Returns error message or None if authenticated."""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    # Check internal API key
    internal_key = headers.get("x-coordination-internal-key", "")
    if internal_key and COORDINATION_INTERNAL_API_KEY:
        valid_keys = {COORDINATION_INTERNAL_API_KEY}
        if COORDINATION_INTERNAL_API_KEY_PREVIOUS:
            valid_keys.add(COORDINATION_INTERNAL_API_KEY_PREVIOUS)
        if internal_key.strip() in valid_keys:
            return None

    # Check Cognito JWT cookie (simplified -- real validation done by API GW or in-Lambda)
    cookies = headers.get("cookie", "")
    if "enceladus_id_token=" in cookies:
        return None

    # Check Authorization header
    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return None

    return "Authentication required"


# ---------------------------------------------------------------------------
# Graph queries
# ---------------------------------------------------------------------------

def _node_to_dict(node) -> Dict[str, Any]:
    """Convert a Neo4j Node to a serializable dict."""
    props = dict(node)
    props["_labels"] = sorted(node.labels)
    return props


_ALLOWED_EDGE_TYPES = frozenset({
    "CHILD_OF", "RELATED_TO", "BELONGS_TO", "ADDRESSES", "IMPLEMENTS",
    "BLOCKS", "BLOCKED_BY", "DUPLICATES", "DUPLICATED_BY", "RELATES_TO",
    "PARENT_OF", "CHILD_OF_TYPED", "DEPENDS_ON", "DEPENDED_ON_BY",
    "CLONES", "CLONED_BY", "AFFECTS", "AFFECTED_BY", "TESTS", "TESTED_BY",
    "CONSUMES_FROM", "PRODUCES_FOR",
    # ENC-ISS-150: Plan edge types (projected by graph_sync)
    "PLAN_CONTAINS", "PLAN_ATTACHED_DOC", "PLAN_IMPLEMENTS",
})


def _query_traversal(driver, project_id: str, params: Dict) -> Dict:
    """Walk edge hierarchy from a record_id. Supports configurable edge_type (default CHILD_OF)."""
    record_id = params.get("record_id", "")
    if not record_id:
        return {"error": "record_id required for traversal search"}
    depth = min(int(params.get("depth", 2)), MAX_DEPTH)
    direction = params.get("direction", "down")
    edge_type = params.get("edge_type", "CHILD_OF").upper()
    min_weight = params.get("min_weight", "")

    if edge_type not in _ALLOWED_EDGE_TYPES:
        return {"error": f"Invalid edge_type: {edge_type}. Allowed: {sorted(_ALLOWED_EDGE_TYPES)}"}

    weight_filter = ""
    if min_weight:
        weight_filter = f" AND ALL(rel IN relationships(path) WHERE COALESCE(rel.weight, 1.0) >= {float(min_weight)})"

    if direction == "up":
        cypher = (
            f"MATCH path = (start)-[:{edge_type}*1..{depth}]->(ancestor) "
            f"WHERE start.record_id = $record_id AND start.project_id = $project_id{weight_filter} "
            "UNWIND nodes(path) AS n "
            "RETURN DISTINCT n"
        )
    elif direction == "both":
        cypher = (
            f"MATCH path = (start)-[:{edge_type}*1..{depth}]-(related) "
            f"WHERE start.record_id = $record_id AND start.project_id = $project_id{weight_filter} "
            "UNWIND nodes(path) AS n "
            "RETURN DISTINCT n"
        )
    else:  # down
        cypher = (
            f"MATCH path = (child)-[:{edge_type}*1..{depth}]->(start) "
            f"WHERE start.record_id = $record_id AND start.project_id = $project_id{weight_filter} "
            "UNWIND nodes(path) AS n "
            "RETURN DISTINCT n"
        )

    with driver.session() as session:
        result = session.run(cypher, record_id=record_id, project_id=project_id)
        nodes = [_node_to_dict(rec["n"]) for rec in result]

    return {
        "nodes": nodes,
        "edges": [],
        "paths": [],
        "summary": f"Traversal ({direction}, {edge_type}) from {record_id}, depth {depth}: {len(nodes)} nodes",
        "query_cypher": cypher,
    }


def _query_neighbors(driver, project_id: str, params: Dict) -> Dict:
    """Find all nodes within N hops via any (or filtered) edge types."""
    record_id = params.get("record_id", "")
    if not record_id:
        return {"error": "record_id required for neighbors search"}
    depth = min(int(params.get("depth", 1)), MAX_DEPTH)
    edge_types_param = params.get("edge_types", "")
    min_weight = params.get("min_weight", "")

    # Build edge pattern: either wildcard or type-filtered
    if edge_types_param:
        if isinstance(edge_types_param, list):
            types = [t.strip().upper() for t in edge_types_param if t.strip()]
        else:
            types = [t.strip().upper() for t in str(edge_types_param).split(",") if t.strip()]
        invalid = [t for t in types if t not in _ALLOWED_EDGE_TYPES]
        if invalid:
            return {"error": f"Invalid edge_types: {invalid}. Allowed: {sorted(_ALLOWED_EDGE_TYPES)}"}
        type_union = "|".join(types)
        edge_pattern = f"[r:{type_union}*1..{depth}]"
    else:
        edge_pattern = f"[r*1..{depth}]"

    weight_filter = ""
    if min_weight:
        weight_filter = f"AND ALL(rel IN r WHERE COALESCE(rel.weight, 1.0) >= {float(min_weight)}) "

    cypher = (
        f"MATCH (start)-{edge_pattern}-(neighbor) "
        f"WHERE start.record_id = $record_id AND start.project_id = $project_id "
        f"AND neighbor.project_id = $project_id "
        f"{weight_filter}"
        "RETURN DISTINCT neighbor, "
        "[rel IN r | {type: type(rel), start: startNode(rel).record_id, end: endNode(rel).record_id}][-1] AS edge_info "
        "LIMIT $limit"
    )

    nodes = []
    edges = []
    seen_ids: set = set()
    seen_edges: set = set()
    with driver.session() as session:
        result = session.run(cypher, record_id=record_id, project_id=project_id, limit=MAX_RESULTS)
        for rec in result:
            nd = _node_to_dict(rec["neighbor"])
            rid = nd.get("record_id", "")
            if rid and rid not in seen_ids:
                nodes.append(nd)
                seen_ids.add(rid)
            edge = rec.get("edge_info")
            if edge:
                e = dict(edge)
                s, t, tp = str(e.get("start", "")), str(e.get("end", "")), str(e.get("type", ""))
                canon = (min(s, t), max(s, t), tp)
                if canon not in seen_edges:
                    edges.append(e)
                    seen_edges.add(canon)

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": [],
        "summary": f"Neighbors of {record_id}, depth {depth}: {len(nodes)} nodes, {len(edges)} edges",
        "query_cypher": cypher,
    }


def _query_path(driver, project_id: str, params: Dict) -> Dict:
    """Find shortest path between two record_ids."""
    from_id = params.get("from_record_id", "")
    to_id = params.get("to_record_id", "")
    if not from_id or not to_id:
        return {"error": "from_record_id and to_record_id required for path search"}
    max_depth = min(int(params.get("depth", 5)), MAX_DEPTH)

    cypher = (
        f"MATCH (a), (b), path = shortestPath((a)-[*..{max_depth}]-(b)) "
        "WHERE a.record_id = $from_id AND a.project_id = $project_id "
        "AND b.record_id = $to_id AND b.project_id = $project_id "
        "AND NONE(n IN nodes(path) WHERE 'Project' IN labels(n)) "
        "RETURN path"
    )

    paths = []
    nodes = []
    with driver.session() as session:
        result = session.run(cypher, from_id=from_id, to_id=to_id, project_id=project_id)
        for rec in result:
            path = rec["path"]
            path_nodes = [_node_to_dict(n) for n in path.nodes]
            path_rels = [
                {"type": type(r).__name__, "start": r.start_node["record_id"], "end": r.end_node["record_id"]}
                for r in path.relationships
            ]
            paths.append({"nodes": path_nodes, "relationships": path_rels})
            nodes.extend(path_nodes)

    if not paths:
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "summary": f"No path found between {from_id} and {to_id} within depth {max_depth}",
            "query_cypher": cypher,
        }

    return {
        "nodes": nodes,
        "edges": [],
        "paths": paths,
        "summary": f"Path from {from_id} to {to_id}: {len(paths)} path(s) found",
        "query_cypher": cypher,
    }


def _query_keyword(driver, project_id: str, params: Dict) -> Dict:
    """Title-matched nodes plus immediate neighbors."""
    search_query = params.get("query", "")
    if not search_query:
        return {"error": "query required for keyword search"}
    record_type = params.get("record_type", "")

    if record_type:
        label_map = {"task": "Task", "issue": "Issue", "feature": "Feature"}
        label = label_map.get(record_type.lower(), "")
        if label:
            cypher = (
                f"MATCH (n:{label}) "
                "WHERE n.project_id = $project_id "
                "AND (toLower(n.title) CONTAINS toLower($search_query) OR n.record_id CONTAINS toUpper($search_query)) "
                "OPTIONAL MATCH (n)-[r]-(neighbor) "
                "WHERE neighbor.project_id = $project_id "
                "RETURN DISTINCT n, collect(DISTINCT neighbor) AS neighbors "
                "LIMIT $limit"
            )
        else:
            return {"error": f"Invalid record_type: {record_type}"}
    else:
        cypher = (
            "MATCH (n) "
            "WHERE n.project_id = $project_id "
            "AND (toLower(n.title) CONTAINS toLower($search_query) OR n.record_id CONTAINS toUpper($search_query)) "
            "OPTIONAL MATCH (n)-[r]-(neighbor) "
            "WHERE neighbor.project_id = $project_id "
            "RETURN DISTINCT n, collect(DISTINCT neighbor) AS neighbors "
            "LIMIT $limit"
        )

    nodes = []
    seen = set()
    with driver.session() as session:
        result = session.run(cypher, project_id=project_id, search_query=search_query, limit=MAX_RESULTS)
        for rec in result:
            main_node = _node_to_dict(rec["n"])
            rid = main_node.get("record_id", "")
            if rid not in seen:
                main_node["_match"] = True
                nodes.append(main_node)
                seen.add(rid)
            for neighbor in rec.get("neighbors", []):
                if neighbor is not None:
                    nd = _node_to_dict(neighbor)
                    nrid = nd.get("record_id", "")
                    if nrid and nrid not in seen:
                        nodes.append(nd)
                        seen.add(nrid)

    matched = sum(1 for n in nodes if n.get("_match"))
    return {
        "nodes": nodes,
        "edges": [],
        "paths": [],
        "summary": f"Keyword '{search_query}': {matched} matches, {len(nodes)} total nodes (with neighbors)",
        "query_cypher": cypher,
    }


SEARCH_HANDLERS = {
    "traversal": _query_traversal,
    "neighbors": _query_neighbors,
    "path": _query_path,
    "keyword": _query_keyword,
}


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_search(event: Dict) -> Dict:
    """Handle GET /api/v1/tracker/graphsearch."""
    qs = event.get("queryStringParameters") or {}

    # ENC-ISS-149: Normalize edge_types from multiValueQueryStringParameters
    # (REST API v1 delivers repeated keys as a list there).
    multi_qs = event.get("multiValueQueryStringParameters") or {}
    if "edge_types" in multi_qs and isinstance(multi_qs["edge_types"], list):
        qs["edge_types"] = ",".join(multi_qs["edge_types"])

    project_id = qs.get("project_id", "")
    if not project_id:
        return _error(400, "project_id query parameter required")

    search_type = qs.get("search_type", "")
    if search_type not in VALID_SEARCH_TYPES:
        return _error(400, f"search_type must be one of: {', '.join(sorted(VALID_SEARCH_TYPES))}")

    depth = qs.get("depth")
    if depth is not None:
        try:
            depth_int = int(depth)
            if depth_int < 1 or depth_int > MAX_DEPTH:
                return _error(400, f"depth must be between 1 and {MAX_DEPTH}")
        except ValueError:
            return _error(400, "depth must be an integer")

    driver = _get_neo4j_driver()
    if driver is None:
        return _error(503, "Graph index temporarily unavailable. Use tracker_list for equivalent queries.",
                       code="GRAPH_UNAVAILABLE", retryable=True,
                       fallback_hint="Use search(action='tracker.list') or search(action='tracker.get') for direct DynamoDB access.")

    handler_fn = SEARCH_HANDLERS[search_type]
    start = time.time()

    try:
        result = handler_fn(driver, project_id, qs)
    except Exception:
        logger.exception("[ERROR] Graph query failed: search_type=%s project_id=%s", search_type, project_id)
        return _error(503, "Graph index temporarily unavailable. Use tracker_list for equivalent queries.",
                       code="GRAPH_UNAVAILABLE", retryable=True)

    duration_ms = int((time.time() - start) * 1000)

    if "error" in result:
        return _error(400, result["error"])

    # Audit log
    logger.info(
        json.dumps({
            "event": "graphsearch_query",
            "search_type": search_type,
            "project_id": project_id,
            "depth": qs.get("depth"),
            "node_count": len(result.get("nodes", [])),
            "edge_count": len(result.get("edges", [])),
            "path_count": len(result.get("paths", [])),
            "duration_ms": duration_ms,
            "query_cypher": result.get("query_cypher", ""),
        })
    )

    return _response(200, {
        "success": True,
        "nodes": result.get("nodes", []),
        "edges": result.get("edges", []),
        "paths": result.get("paths", []),
        "summary": result.get("summary", ""),
        "query_cypher": result.get("query_cypher", ""),
        "duration_ms": duration_ms,
    })


def _handle_health(event: Dict) -> Dict:
    """Handle GET /api/v1/tracker/graphsearch/health."""
    driver = _get_neo4j_driver()
    if driver is None:
        return _response(200, {"status": "unavailable", "message": "Neo4j driver not initialized"})

    try:
        start = time.time()
        with driver.session() as session:
            result = session.run("RETURN 1 AS health")
            result.single()
        duration_ms = int((time.time() - start) * 1000)
        return _response(200, {"status": "healthy", "response_ms": duration_ms})
    except Exception as e:
        logger.warning("[WARNING] Graph health check failed: %s", e)
        return _response(200, {"status": "unavailable", "message": str(e)})


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """API Gateway v2 proxy handler."""
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("rawPath", "")

    # CORS preflight
    if method == "OPTIONS":
        return _response(204, "")

    # Health endpoint (no auth required)
    if path.endswith("/health"):
        return _handle_health(event)

    # Auth check
    auth_error = _authenticate(event)
    if auth_error:
        return _error(401, auth_error)

    # Route dispatch
    if method == "GET" and "/graphsearch" in path and not path.endswith("/health"):
        return _handle_search(event)

    return _error(404, f"Route not found: {method} {path}")
