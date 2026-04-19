"""devops-graph-query-api Lambda -- Graph search API for tracker record relationships.

Serves GET /api/v1/tracker/graphsearch via API Gateway v2 proxy integration.
Queries Neo4j AuraDB Free graph index populated by graph_sync Lambda.

Search types:
  - traversal: Walk CHILD_OF hierarchy from a record_id
  - neighbors: All nodes within N hops via any edge type
  - path: Shortest path between two record_ids
  - keyword: Full-text title match + immediate neighbors
  - hybrid:   ENC-TSK-B92 Phase 1 three-signal hybrid scoring
              (vector cosine via HNSW + graph PPR/fallback + keyword) combined
              with Reciprocal Rank Fusion (k=60). Backward-compat fallback
              when embeddings are sparse or GDS unavailable.

Auth: Cognito JWT cookie OR X-Coordination-Internal-Key header.

Environment variables:
  NEO4J_SECRET_NAME           Secrets Manager secret ID
  SECRETS_REGION              AWS region for Secrets Manager (default: us-west-2)
  COGNITO_USER_POOL_ID        Cognito user pool ID
  COGNITO_CLIENT_ID           Cognito client ID
  CORS_ORIGIN                 CORS allowed origin (default: https://jreese.net)
  COORDINATION_INTERNAL_API_KEY  Internal API key for service-to-service auth
  BEDROCK_REGION              AWS region for Bedrock (default: us-west-2)
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

VALID_SEARCH_TYPES = {"traversal", "neighbors", "path", "keyword", "hybrid"}

# ---------------------------------------------------------------------------
# ENC-TSK-B92 Phase 1 hybrid retrieval constants
# ---------------------------------------------------------------------------

# Reciprocal Rank Fusion exponent offset (per ENC-TSK-B62 description).
# score = Σ 1 / (RRF_K + rank_i) over signals where the record appears.
RRF_K = 60

# Per-signal top-N depth to consider when fusing ranks.
HYBRID_SIGNAL_TOP_N = 25

# Per-relationship-type weights for the graph PPR / fallback signal.
# Order per LSN-029 / B93: IMPLEMENTS > ADDRESSES > RELATED_TO > LEARNED_FROM
# > CHILD_OF > PLAN_CONTAINS > BELONGS_TO. Weights are multiplicative on the
# PPR edge contribution and identical across fallback edge-walk scoring.
GRAPH_EDGE_WEIGHTS: Dict[str, float] = {
    "IMPLEMENTS": 1.00,
    "ADDRESSES": 0.90,
    "INVESTIGATES": 0.85,
    "INVESTIGATED_BY": 0.85,
    "RELATED_TO": 0.75,
    "LEARNED_FROM": 0.70,
    "HANDS_OFF": 0.65,
    "CHILD_OF": 0.60,
    "PLAN_CONTAINS": 0.55,
    "TRACKS_WAVE_OF": 0.50,
    "HAS_WAVE_DOC": 0.50,
    "BELONGS_TO": 0.30,
}
GRAPH_FALLBACK_DEFAULT_WEIGHT = 0.40

# Per-label HNSW index name template (matches B90 migration 001).
LABEL_VECTOR_INDEXES: Dict[str, str] = {
    "Task": "governed_task_embedding",
    "Issue": "governed_issue_embedding",
    "Feature": "governed_feature_embedding",
    "Plan": "governed_plan_embedding",
    "Lesson": "governed_lesson_embedding",
    "Document": "governed_document_embedding",
}

# FSRS-6 retrieval-invisible threshold for Lesson records (B62 scope item #4).
# Lessons with stability S < T3 are suppressed from default context unless the
# caller passes include_below_threshold=true. The canonical FSRS-6 field name
# is "stability"; fallback to resonance_score when stability is absent
# (pre-FSRS-6 lesson records), matching the ENC-LSN-029 scoring convention.
FSRS_T3_THRESHOLD = 0.7

# Graph damping factor per LSN-029 implementation contract.
PPR_DAMPING_FACTOR = 0.85
PPR_MAX_ITERATIONS = 25

# Cache the GDS availability probe so every hybrid call does not re-probe.
_GDS_PROBE_CACHE_TTL_SECONDS = 300
_gds_probe_state: Dict[str, Any] = {"checked_at": 0.0, "available": None}

# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_neo4j_driver = None
_secretsmanager = None

# ENC-TSK-F36 / ENC-ISS-268 / DOC-D4CB8048798B — Bolt driver pool config.
# NAT Gateway silently drops idle TCP flows at 350s; setting
# max_connection_lifetime=300 forces proactive socket recycling below that
# window so the cached pool never hands the caller a half-open socket. The
# ~48s warm-invocation hang observed in ENC-ISS-268 was Bolt connection
# acquisition blocking on such a dead socket before retrying. keep_alive
# enables TCP keepalives, connection_acquisition_timeout caps the wait, and
# max_connection_pool_size avoids unbounded growth under fan-out.
_NEO4J_MAX_CONNECTION_LIFETIME_S = 300
_NEO4J_CONNECTION_ACQUISITION_TIMEOUT_S = 120
_NEO4J_MAX_CONNECTION_POOL_SIZE = 20


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
            _neo4j_driver = GraphDatabase.driver(
                uri,
                auth=(user, password),
                max_connection_lifetime=_NEO4J_MAX_CONNECTION_LIFETIME_S,
                connection_acquisition_timeout=_NEO4J_CONNECTION_ACQUISITION_TIMEOUT_S,
                max_connection_pool_size=_NEO4J_MAX_CONNECTION_POOL_SIZE,
                keep_alive=True,
            )
        except Exception:
            logger.exception("[ERROR] Failed to initialize Neo4j driver")
            return None
    return _neo4j_driver


def _rebuild_neo4j_driver():
    """Close the cached Bolt driver and rebuild it.

    Invoked when verify_connectivity() fails, indicating the cached pool is
    holding dead TCP sockets (typical after a Lambda container freeze that
    exceeded the NAT 350s idle-kill window). Does not touch server-side
    state; the AuraDB session and AGA compute instance are unaffected.
    """
    global _neo4j_driver
    if _neo4j_driver is not None:
        try:
            _neo4j_driver.close()
        except Exception:
            logger.warning("[WARNING] Bolt driver close raised during rebuild", exc_info=True)
    _neo4j_driver = None
    return _get_neo4j_driver()


def _ensure_live_driver(driver):
    """Probe the Bolt pool and rebuild on failure.

    Returns a driver with at least one proven-live connection, or None if
    rebuild also failed. Cheap on the happy path (one round-trip); only
    rebuilds when the pool has decayed.
    """
    if driver is None:
        return _get_neo4j_driver()
    try:
        driver.verify_connectivity()
        return driver
    except Exception as exc:
        logger.warning(
            "[WARNING] Bolt pool verify_connectivity failed (%s) — rebuilding driver",
            exc,
        )
        return _rebuild_neo4j_driver()


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
    # ENC-TSK-983: Lesson edge types
    "LEARNED_FROM", "TEACHES", "SUPERSEDES", "SUPERSEDED_BY",
    # ENC-FTR-061: Handoff edge types
    "HANDS_OFF", "HANDED_OFF_BY",
    # ENC-TSK-960: Coordination dispatch edge types
    "DISPATCHES", "DISPATCHED_BY",
    # ENC-FTR-076 / ENC-TSK-E08: Component proposal provenance
    "COMPONENT_PROPOSED_BY",
    "PROPOSES_COMPONENT",
    # ENC-PLN-014 / ENC-FTR-065: Document edge types
    "DOC_ATTACHED_TO_PLAN",  # inverse of PLAN_ATTACHED_DOC
    "INFORMED_BY",            # GDMP provenance (Document -> Document)
    "INFORMS",                # inverse GDMP provenance
    # ENC-FTR-077: Docstore subtype edges
    "INVESTIGATES",           # Document (coe) -> Issue/Task
    "INVESTIGATED_BY",        # Issue/Task -> Document (coe)
    "TRACKS_WAVE_OF",         # Document (wave) -> Plan
    "HAS_WAVE_DOC",           # Plan -> Document (wave)
    # GMF: Generational Metabolism Framework (DOC-63420302EF65 §8.2)
    "SUCCEEDS",               # Generation -> Generation (lineage)
    "BELONGS_TO_GENERATION",  # Feature -> Generation
    "SYNTHESIZED_IN",         # Lesson -> Chapter document
    "SEEDS_THESIS_OF",        # Chapter document -> Generation
    "ADVANCES_GENERATION",    # DeploymentDecision -> Generation
    "TARGETS_GENERATION",     # Task/Lesson -> Generation
    "EXECUTES_WITHIN",        # Plan -> Generation
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


# ---------------------------------------------------------------------------
# ENC-TSK-B92 Phase 1: Three-signal hybrid retrieval
# ---------------------------------------------------------------------------
# Implements vector (HNSW cosine) + graph (PPR or Cypher fallback) + keyword
# (full-text title/description) ranking, combined via Reciprocal Rank Fusion
# (k=60). Backward-compatible: when target records lack embeddings the vector
# rank is empty and RRF degrades to graph + keyword only. When GDS is not
# available, graph signal degrades to native-Cypher edge-walk scoring using
# per-relationship-type weights per LSN-029.
#
# FSRS-6 Lesson post-filter (B62 scope #3/#4): Lessons below the T3 retrieval-
# invisible threshold (stability < 0.7) are suppressed from the fused result
# unless include_below_threshold=true is passed.


def _check_gds_available(driver) -> bool:
    """Probe gamma AuraDB for the GDS plugin. Cached for 5 minutes.

    Returns True if CALL gds.list() succeeds; False otherwise. Never raises.
    """
    import time as _time
    now = _time.time()
    if (
        _gds_probe_state["available"] is not None
        and (now - _gds_probe_state["checked_at"]) < _GDS_PROBE_CACHE_TTL_SECONDS
    ):
        return bool(_gds_probe_state["available"])

    available = False
    try:
        with driver.session() as session:
            session.run("CALL gds.list() YIELD name RETURN name LIMIT 1").consume()
        available = True
    except Exception as exc:
        logger.info("[INFO] GDS plugin not available on AuraDB: %s", exc)
        available = False

    _gds_probe_state["checked_at"] = now
    _gds_probe_state["available"] = available
    return available


def _compute_query_embedding(query_text: str) -> Optional[List[float]]:
    """Invoke Titan V2 via the canonical graph_sync/embedding.py contract.

    Import is deferred so the module can be packaged into the Lambda zip by
    deploy.sh alongside the lambda_function.py entry point.
    """
    try:
        import embedding as _embedding
    except Exception:
        logger.warning("[WARNING] embedding module unavailable — vector signal will be empty")
        return None
    try:
        return _embedding.invoke_titan_v2(query_text)
    except Exception:
        logger.exception("[ERROR] query embedding failed")
        return None


def _hybrid_vector_ranks(
    driver,
    project_id: str,
    query_embedding: List[float],
    k_per_label: int,
    record_type_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query each per-label HNSW index and return a merged ranked list.

    Returns a list of {record_id, score, label, rank} dicts sorted by score
    desc. Each label contributes up to k_per_label candidates; duplicates
    (same record_id across labels) are kept by highest score.
    """
    # Scope to a single label when record_type is set.
    if record_type_filter:
        label = record_type_filter.capitalize()
        labels_to_query = [label] if label in LABEL_VECTOR_INDEXES else []
    else:
        labels_to_query = list(LABEL_VECTOR_INDEXES.keys())

    by_rid: Dict[str, Dict[str, Any]] = {}
    for label in labels_to_query:
        index_name = LABEL_VECTOR_INDEXES[label]
        cypher = (
            "CALL db.index.vector.queryNodes($index_name, $k, $query_embedding) "
            "YIELD node, score "
            "WHERE node.project_id = $project_id "
            "RETURN node.record_id AS rid, score, labels(node) AS labels"
        )
        try:
            with driver.session() as session:
                result = session.run(
                    cypher,
                    index_name=index_name,
                    k=k_per_label,
                    query_embedding=query_embedding,
                    project_id=project_id,
                )
                for rec in result:
                    rid = rec.get("rid")
                    if not rid:
                        continue
                    score = float(rec.get("score") or 0.0)
                    prev = by_rid.get(rid)
                    if prev is None or score > prev["score"]:
                        by_rid[rid] = {
                            "record_id": rid,
                            "score": score,
                            "label": label,
                        }
        except Exception as exc:
            # Index missing or unreachable — log and continue with other labels.
            logger.warning("[WARNING] vector index %s query failed: %s", index_name, exc)

    ranked = sorted(by_rid.values(), key=lambda d: d["score"], reverse=True)
    for idx, item in enumerate(ranked, start=1):
        item["rank"] = idx
    return ranked


def _hybrid_graph_ranks_gds(
    driver,
    project_id: str,
    anchor_record_id: str,
    top_n: int,
) -> List[Dict[str, Any]]:
    """Personalized PageRank via GDS per LSN-029 contract.

    Uses gds.pageRank.stream with the anchor record as the personalization
    source, damping=0.85, maxIterations=25, per-relationship-type weight
    projection. Never persists state (no gds.pageRank.write).
    """
    # Build a named graph projection on the fly. Projection name includes a
    # per-invocation random suffix so concurrent calls for the same anchor do
    # not collide on gds.graph.drop / gds.graph.project. Without the suffix,
    # two Lambdas fan-out on the same anchor would race and one would fail
    # with FlightRuntimeException: INVALID_ARGUMENT: There's already a job
    # running with jobId ... (DOC-D4CB8048798B §Concurrency Hazards). GDS
    # auto-cleans anonymous projections; we still drop on completion for
    # safety, now scoped to this invocation's unique name.
    _proj_suffix = os.urandom(4).hex()
    projection_name = (
        f"hybrid_{project_id}_{anchor_record_id}_{_proj_suffix}".replace("-", "_").lower()
    )

    # Build the edge-weight CASE for per-type weights.
    weight_case_parts = []
    for edge_type, weight in GRAPH_EDGE_WEIGHTS.items():
        weight_case_parts.append(f"WHEN '{edge_type}' THEN {weight}")
    weight_case_sql = (
        "CASE type(r) " + " ".join(weight_case_parts)
        + f" ELSE {GRAPH_FALLBACK_DEFAULT_WEIGHT} END"
    )

    edge_union = "|".join(list(GRAPH_EDGE_WEIGHTS.keys()))

    ranked: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            # Drop any prior projection with this name.
            session.run(
                f"CALL gds.graph.exists($name) YIELD exists "
                f"WITH exists WHERE exists "
                f"CALL gds.graph.drop($name) YIELD graphName RETURN graphName",
                name=projection_name,
            ).consume()

            # Create the projection with weighted edges.
            # ENC-ISS-265 Problem C: the live instance is Aura Graph Analytics
            # (Sessions-based GDS compute plane), not in-process AuraDB-Pro GDS.
            # AGA requires the caller to pass {memory: '<size>'} (auto-create
            # session) or {sessionId: '<id>'} on every gds.graph.project call.
            # The governed corpus is currently <10k nodes / <50k edges; 2GB is
            # the documented smallest viable session. Subsequent calls within
            # the same query session (gds.graph.exists/drop, gds.pageRank.stream)
            # inherit the session and do NOT need to re-specify memory.
            session.run(
                f"""
                MATCH (src) WHERE src.project_id = $project_id
                OPTIONAL MATCH (src)-[r:{edge_union}]->(tgt)
                WHERE tgt IS NOT NULL AND tgt.project_id = $project_id
                WITH gds.graph.project(
                    $name,
                    src,
                    tgt,
                    {{relationshipProperties: {{weight: {weight_case_sql}}}}},
                    {{memory: '2GB'}}
                ) AS g
                RETURN g.graphName
                """,
                name=projection_name,
                project_id=project_id,
            ).consume()

            # Resolve the anchor node id.
            anchor_rec = session.run(
                "MATCH (a) WHERE a.record_id = $rid AND a.project_id = $project_id "
                "RETURN id(a) AS nodeId LIMIT 1",
                rid=anchor_record_id,
                project_id=project_id,
            ).single()
            if anchor_rec is None or anchor_rec.get("nodeId") is None:
                return []

            # ENC-ISS-265 Problem C.2: gds.util.asNode is not supported under
            # the AGA Sessions API surface, and the projection above does not
            # expose record_id as a node property anyway. Return raw (nodeId,
            # score) from pageRank.stream, then resolve record_ids via a
            # single follow-up MATCH that hits the main DB (not the session
            # projection). Preserves score order; one extra roundtrip.
            stream_result = session.run(
                """
                CALL gds.pageRank.stream(
                    $name,
                    {
                        sourceNodes: [$anchorId],
                        dampingFactor: $damping,
                        maxIterations: $maxIter,
                        relationshipWeightProperty: 'weight'
                    }
                )
                YIELD nodeId, score
                RETURN nodeId, score
                ORDER BY score DESC
                LIMIT $limit
                """,
                name=projection_name,
                anchorId=anchor_rec["nodeId"],
                damping=PPR_DAMPING_FACTOR,
                maxIter=PPR_MAX_ITERATIONS,
                limit=top_n,
            )
            node_rows: List[tuple] = [(r.get("nodeId"), float(r.get("score") or 0.0)) for r in stream_result]
            if not node_rows:
                ranked = []
            else:
                node_ids = [nid for nid, _ in node_rows if nid is not None]
                rid_map: Dict[int, str] = {}
                if node_ids:
                    resolved = session.run(
                        "MATCH (n) WHERE id(n) IN $node_ids "
                        "RETURN id(n) AS nodeId, n.record_id AS rid",
                        node_ids=node_ids,
                    )
                    for rec in resolved:
                        rid = rec.get("rid")
                        nid = rec.get("nodeId")
                        if rid and nid is not None:
                            rid_map[nid] = rid
                rank_counter = 0
                for nid, score in node_rows:
                    rid = rid_map.get(nid)
                    if not rid or rid == anchor_record_id:
                        continue
                    rank_counter += 1
                    ranked.append({
                        "record_id": rid,
                        "score": score,
                        "rank": rank_counter,
                    })

            # Clean up projection.
            session.run(
                "CALL gds.graph.drop($name, false) YIELD graphName RETURN graphName",
                name=projection_name,
            ).consume()
    except Exception as exc:
        logger.warning("[WARNING] GDS PPR query failed: %s — falling back to Cypher", exc)
        return []

    return ranked


def _hybrid_graph_ranks_cypher_fallback(
    driver,
    project_id: str,
    anchor_record_id: str,
    top_n: int,
) -> List[Dict[str, Any]]:
    """Fallback graph-signal scoring using native Cypher weighted hop sum.

    Approximates PPR by summing per-relationship-type weights across the
    shortest accumulation of hops from the anchor within depth 3. Each
    neighbor's score = Σ hop_weight * decay^distance over all edges reaching
    it from the anchor (capped).
    """
    edge_union = "|".join(list(GRAPH_EDGE_WEIGHTS.keys()))
    # Decay factor across hop distance — mimics the damping behavior of PPR.
    decay = PPR_DAMPING_FACTOR

    # Cypher-side weight CASE for edge types.
    weight_case_parts = []
    for edge_type, weight in GRAPH_EDGE_WEIGHTS.items():
        weight_case_parts.append(f"WHEN '{edge_type}' THEN {weight}")
    weight_case_sql = (
        "CASE type(rel) " + " ".join(weight_case_parts)
        + f" ELSE {GRAPH_FALLBACK_DEFAULT_WEIGHT} END"
    )

    cypher = (
        f"MATCH path = (anchor)-[:{edge_union}*1..3]-(neighbor) "
        f"WHERE anchor.record_id = $rid AND anchor.project_id = $project_id "
        f"AND neighbor.project_id = $project_id "
        f"AND neighbor.record_id <> $rid "
        f"WITH neighbor, path, "
        f"  reduce(s = 0.0, rel IN relationships(path) | s + {weight_case_sql}) "
        f"  * ({decay} ^ length(path)) AS path_score "
        f"WITH neighbor.record_id AS rid, sum(path_score) AS score "
        f"RETURN rid, score ORDER BY score DESC LIMIT $limit"
    )
    ranked: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            result = session.run(
                cypher, rid=anchor_record_id, project_id=project_id, limit=top_n,
            )
            for idx, rec in enumerate(result, start=1):
                rid = rec.get("rid")
                if not rid:
                    continue
                ranked.append({
                    "record_id": rid,
                    "score": float(rec.get("score") or 0.0),
                    "rank": idx,
                })
    except Exception:
        logger.exception("[ERROR] Cypher fallback graph-signal scoring failed")
        return []
    return ranked


def _hybrid_keyword_ranks(
    driver,
    project_id: str,
    query_text: str,
    top_n: int,
    record_type_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Keyword signal via case-insensitive title/description/intent contains.

    Uses a scoring tiebreaker: title match scores higher than description
    match. Graceful when the fulltext index is absent — falls back to
    CONTAINS which is correct (though slower) on a <1k-node corpus.
    """
    if not query_text:
        return []

    label_filter = ""
    if record_type_filter:
        label_map = {
            "task": "Task",
            "issue": "Issue",
            "feature": "Feature",
            "plan": "Plan",
            "lesson": "Lesson",
            "document": "Document",
        }
        label = label_map.get(record_type_filter.lower())
        if label:
            label_filter = f":{label}"

    cypher = (
        f"MATCH (n{label_filter}) "
        "WHERE n.project_id = $project_id "
        "AND ("
        "  toLower(coalesce(n.title, '')) CONTAINS toLower($q) OR "
        "  toLower(coalesce(n.intent, '')) CONTAINS toLower($q) OR "
        "  toLower(coalesce(n.description, '')) CONTAINS toLower($q)"
        ") "
        "WITH n, "
        "  CASE WHEN toLower(coalesce(n.title, '')) CONTAINS toLower($q) THEN 3.0 ELSE 0.0 END + "
        "  CASE WHEN toLower(coalesce(n.intent, '')) CONTAINS toLower($q) THEN 2.0 ELSE 0.0 END + "
        "  CASE WHEN toLower(coalesce(n.description, '')) CONTAINS toLower($q) THEN 1.0 ELSE 0.0 END "
        "  AS score "
        "WHERE score > 0.0 "
        "RETURN n.record_id AS rid, score ORDER BY score DESC LIMIT $limit"
    )
    ranked: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            result = session.run(cypher, project_id=project_id, q=query_text, limit=top_n)
            for idx, rec in enumerate(result, start=1):
                rid = rec.get("rid")
                if not rid:
                    continue
                ranked.append({
                    "record_id": rid,
                    "score": float(rec.get("score") or 0.0),
                    "rank": idx,
                })
    except Exception:
        logger.exception("[ERROR] keyword signal scoring failed")
        return []
    return ranked


def _rrf_fuse(
    signals: Dict[str, List[Dict[str, Any]]],
    k: int = RRF_K,
) -> List[Dict[str, Any]]:
    """Reciprocal Rank Fusion across named signals.

    Each signal contributes 1/(k + rank) to a record's fused score. Records
    not present in a signal contribute 0 from that signal (no-contribution).
    Returns a sorted list of {record_id, fused_score, per_signal_ranks} dicts.
    """
    fused: Dict[str, Dict[str, Any]] = {}
    for signal_name, items in signals.items():
        for item in items:
            rid = item.get("record_id")
            rank = item.get("rank")
            if not rid or rank is None:
                continue
            entry = fused.setdefault(
                rid,
                {
                    "record_id": rid,
                    "fused_score": 0.0,
                    "per_signal_ranks": {},
                    "per_signal_scores": {},
                },
            )
            entry["fused_score"] += 1.0 / (k + rank)
            entry["per_signal_ranks"][signal_name] = rank
            entry["per_signal_scores"][signal_name] = item.get("score")
    ordered = sorted(fused.values(), key=lambda d: d["fused_score"], reverse=True)
    for idx, item in enumerate(ordered, start=1):
        item["fused_rank"] = idx
    return ordered


def _fetch_nodes_by_record_ids(
    driver,
    project_id: str,
    record_ids: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Bulk-fetch full node payloads for a list of record_ids. Single query."""
    if not record_ids:
        return {}
    cypher = (
        "MATCH (n) WHERE n.project_id = $project_id "
        "AND n.record_id IN $rids RETURN n"
    )
    out: Dict[str, Dict[str, Any]] = {}
    try:
        with driver.session() as session:
            result = session.run(cypher, project_id=project_id, rids=record_ids)
            for rec in result:
                nd = _node_to_dict(rec["n"])
                rid = nd.get("record_id")
                if rid:
                    out[rid] = nd
    except Exception:
        logger.exception("[ERROR] bulk node fetch failed")
    return out


def _apply_fsrs_t3_filter(
    nodes: List[Dict[str, Any]],
    include_below_threshold: bool,
    t3: float = FSRS_T3_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Suppress Lessons with stability < T3 unless include_below_threshold.

    Reads `stability` when present (canonical FSRS-6 field); falls back to
    `resonance_score` (pre-FSRS-6 Lesson convention, per LSN-029). Tags each
    Lesson node with a `_below_t3` marker so callers can see what was
    filtered.
    """
    if include_below_threshold:
        # Still tag the nodes so the caller can distinguish.
        for node in nodes:
            labels = node.get("_labels") or []
            if "Lesson" in labels:
                s = node.get("stability")
                if s is None:
                    s = node.get("resonance_score")
                node["_fsrs_stability"] = s
                node["_below_t3"] = bool(s is not None and float(s) < t3)
        return nodes

    filtered: List[Dict[str, Any]] = []
    for node in nodes:
        labels = node.get("_labels") or []
        if "Lesson" in labels:
            s = node.get("stability")
            if s is None:
                s = node.get("resonance_score")
            try:
                s_val = float(s) if s is not None else None
            except (TypeError, ValueError):
                s_val = None
            node["_fsrs_stability"] = s_val
            if s_val is not None and s_val < t3:
                node["_below_t3"] = True
                continue
            node["_below_t3"] = False
        filtered.append(node)
    return filtered


def _query_hybrid(driver, project_id: str, params: Dict) -> Dict:
    """Phase 1 hybrid retrieval: vector + graph + keyword fused via RRF.

    Query parameters:
      query            Text query (required for vector + keyword signals).
      anchor_record_id Graph anchor node (required for graph signal).
      record_type      Optional filter (task/issue/feature/plan/lesson/document).
      top_n            Final result count (default 20, max 50).
      include_below_threshold  When "true", includes Lessons below T3.

    Response contract:
      {
        "nodes":             [...ordered by fused score...],
        "edges":             [],
        "paths":             [],
        "summary":           "Hybrid: N nodes (vector=V, graph=G, keyword=K)",
        "query_cypher":      "<hybrid-multi-query marker>",
        "signal_availability": {vector: bool, graph: bool, keyword: bool},
        "graph_algorithm":   "gds_pagerank" | "cypher_fallback" | "unavailable",
        "rrf_k":             60,
        "embedding_coverage_sample": {covered: N, total_ranked: N},
        "per_node_fusion":   {record_id: {fused_rank, per_signal_ranks}}
      }
    """
    query_text = str(params.get("query", "")).strip()
    anchor_record_id = str(params.get("anchor_record_id", "")).strip()
    record_type_filter = params.get("record_type") or None
    try:
        top_n = int(params.get("top_n", 20))
    except (TypeError, ValueError):
        top_n = 20
    top_n = max(1, min(top_n, 50))
    include_below_threshold = str(params.get("include_below_threshold", "")).lower() == "true"

    # At least one of query or anchor_record_id is required.
    if not query_text and not anchor_record_id:
        return {"error": "hybrid search requires at least one of: query, anchor_record_id"}

    # ENC-TSK-F36 / ENC-ISS-268 / DOC-D4CB8048798B — verify the cached Bolt
    # pool is live before dispatching to any of the three signal functions.
    # After a Lambda container freeze that exceeded the NAT 350s idle-kill
    # window, the cached driver holds half-open sockets that will block
    # ~48s on the first write before raising ServiceUnavailable. One cheap
    # round-trip here avoids per-signal rediscovery of the dead pool and
    # ensures all three signals (vector, graph, keyword) share a live
    # driver. On failure, rebuild rebinds the module-global so subsequent
    # handler invocations also pick up the fresh pool.
    driver = _ensure_live_driver(driver)
    if driver is None:
        return {"error": "neo4j driver unavailable after rebuild attempt"}

    # ---- Vector signal -----------------------------------------------------
    vector_ranks: List[Dict[str, Any]] = []
    vector_available = False
    if query_text:
        query_embedding = _compute_query_embedding(query_text)
        if query_embedding is not None:
            vector_ranks = _hybrid_vector_ranks(
                driver,
                project_id,
                query_embedding,
                k_per_label=HYBRID_SIGNAL_TOP_N,
                record_type_filter=record_type_filter,
            )
            vector_available = True
        else:
            logger.info("[INFO] vector signal skipped — embedding computation unavailable")

    # ---- Graph signal ------------------------------------------------------
    graph_ranks: List[Dict[str, Any]] = []
    graph_available = False
    graph_algorithm = "unavailable"
    if anchor_record_id:
        if _check_gds_available(driver):
            graph_ranks = _hybrid_graph_ranks_gds(
                driver, project_id, anchor_record_id, top_n=HYBRID_SIGNAL_TOP_N,
            )
            if graph_ranks:
                graph_algorithm = "gds_pagerank"
                graph_available = True
        # Fall back to Cypher if GDS unavailable OR returned empty.
        if not graph_available:
            graph_ranks = _hybrid_graph_ranks_cypher_fallback(
                driver, project_id, anchor_record_id, top_n=HYBRID_SIGNAL_TOP_N,
            )
            if graph_ranks:
                graph_algorithm = "cypher_fallback"
                graph_available = True

    # ---- Keyword signal ----------------------------------------------------
    keyword_ranks: List[Dict[str, Any]] = []
    keyword_available = False
    if query_text:
        keyword_ranks = _hybrid_keyword_ranks(
            driver,
            project_id,
            query_text,
            top_n=HYBRID_SIGNAL_TOP_N,
            record_type_filter=record_type_filter,
        )
        keyword_available = bool(keyword_ranks)

    # ---- RRF fusion --------------------------------------------------------
    signals: Dict[str, List[Dict[str, Any]]] = {}
    if vector_ranks:
        signals["vector"] = vector_ranks
    if graph_ranks:
        signals["graph"] = graph_ranks
    if keyword_ranks:
        signals["keyword"] = keyword_ranks

    if not signals:
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "summary": "No signals returned candidates. "
                       "(vector=0, graph=0, keyword=0) — try a broader query or verify anchor is in the graph.",
            "query_cypher": "hybrid/no-signals",
            "signal_availability": {
                "vector": vector_available,
                "graph": graph_available,
                "keyword": keyword_available,
            },
            "graph_algorithm": graph_algorithm,
            "rrf_k": RRF_K,
        }

    fused = _rrf_fuse(signals, k=RRF_K)
    # Cap to top_n + generous buffer so FSRS-6 T3 suppression doesn't starve results.
    fetch_size = min(len(fused), top_n * 3)
    top_fused = fused[:fetch_size]

    # ---- Resolve full node payloads ---------------------------------------
    top_rids = [item["record_id"] for item in top_fused]
    node_by_rid = _fetch_nodes_by_record_ids(driver, project_id, top_rids)

    # Ordered list of nodes matching the fused ranking.
    nodes: List[Dict[str, Any]] = []
    embedding_covered = 0
    per_node_fusion: Dict[str, Any] = {}
    for item in top_fused:
        rid = item["record_id"]
        node = node_by_rid.get(rid)
        if not node:
            # Record is in Neo4j but missing from bulk fetch (rare race); skip.
            continue
        # Annotate with fusion metadata for observability.
        node["_fused_rank"] = item["fused_rank"]
        node["_fused_score"] = item["fused_score"]
        node["_per_signal_ranks"] = item["per_signal_ranks"]
        if node.get(_EMBEDDING_PROPERTY):
            embedding_covered += 1
            # Drop the 256-float blob from the response to keep payloads small.
            node = {k: v for k, v in node.items() if k != _EMBEDDING_PROPERTY}
        per_node_fusion[rid] = {
            "fused_rank": item["fused_rank"],
            "fused_score": item["fused_score"],
            "per_signal_ranks": item["per_signal_ranks"],
        }
        nodes.append(node)

    # ---- FSRS-6 / T3 Lesson post-filter -----------------------------------
    nodes = _apply_fsrs_t3_filter(nodes, include_below_threshold=include_below_threshold)

    # Trim to final top_n after T3 suppression.
    nodes = nodes[:top_n]

    summary = (
        f"Hybrid: {len(nodes)} nodes "
        f"(vector={len(vector_ranks)}, graph={len(graph_ranks)}, keyword={len(keyword_ranks)}; "
        f"graph_algo={graph_algorithm}; embedded={embedding_covered}/{len(top_fused)})"
    )

    return {
        "nodes": nodes,
        "edges": [],
        "paths": [],
        "summary": summary,
        "query_cypher": "hybrid/multi-signal-rrf",
        "signal_availability": {
            "vector": vector_available,
            "graph": graph_available,
            "keyword": keyword_available,
        },
        "graph_algorithm": graph_algorithm,
        "rrf_k": RRF_K,
        "embedding_coverage_sample": {
            "covered": embedding_covered,
            "total_ranked": len(top_fused),
        },
        "per_node_fusion": per_node_fusion,
        "fsrs_t3_threshold": FSRS_T3_THRESHOLD,
        "include_below_threshold": include_below_threshold,
    }


# Embedding property name must mirror graph_sync/embedding.py EMBEDDING_PROPERTY
# without forcing an import at module load time (deploy packages the helper at
# the top level, so the import is deferred to _compute_query_embedding).
_EMBEDDING_PROPERTY = "embedding"


SEARCH_HANDLERS = {
    "traversal": _query_traversal,
    "neighbors": _query_neighbors,
    "path": _query_path,
    "keyword": _query_keyword,
    "hybrid": _query_hybrid,
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

    response_body: Dict[str, Any] = {
        "success": True,
        "nodes": result.get("nodes", []),
        "edges": result.get("edges", []),
        "paths": result.get("paths", []),
        "summary": result.get("summary", ""),
        "query_cypher": result.get("query_cypher", ""),
        "duration_ms": duration_ms,
    }
    # ENC-TSK-B92: hybrid-specific observability fields passed through verbatim.
    for hybrid_key in (
        "signal_availability",
        "graph_algorithm",
        "rrf_k",
        "embedding_coverage_sample",
        "per_node_fusion",
        "fsrs_t3_threshold",
        "include_below_threshold",
    ):
        if hybrid_key in result:
            response_body[hybrid_key] = result[hybrid_key]
    return _response(200, response_body)


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
