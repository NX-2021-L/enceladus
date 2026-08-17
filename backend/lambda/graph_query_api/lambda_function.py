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

import concurrent.futures
import hashlib
import json
import logging
import os
import time
import uuid
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

VALID_SEARCH_TYPES = {"traversal", "neighbors", "path", "keyword", "hybrid", "vector_read"}

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

# ENC-ISS-311 / ENC-TSK-G98: hard wall-clock budget for the anchored graph signal.
# Per-query Aura Graph Analytics session creation (gds.graph.project {memory:'2GB'})
# can exceed the synchronous read budget; bounding it here degrades the graph signal
# to empty instead of timing out the whole hybrid response (RRF fuses whatever
# signals return). The performant fix (pre-materialized projection) is a follow-up.
_GRAPH_SIGNAL_DEADLINE_S = 8.0

# ENC-ISS-312 / ENC-TSK-G99: canned inputs for the functional health probe.
_HEALTH_PROBE_PROJECT = "enceladus"
_HEALTH_PROBE_TOKEN = "governance"

# ENC-FTR-101 (Option B) — pre-materialized standing projection config.
# DOC-6EFD5DB32CD8 Rev 11/14 + io field guide DOC-D4CB8048798B. When
# GDS_STANDING_PROJECTION_PREFIX is unset the feature is OFF and every warm-path
# call returns immediately, so the request path behaves exactly as before
# (per-query gds.graph.project then Cypher proxy under the deadline). When set,
# an out-of-band refresher (_handle_refresh_projection, EventBridge-scheduled)
# maintains a single standing named projection that the request path queries
# warm. GDS_WEIGHT_PROPERTY selects the relationship weight used by pageRank
# ('weight' today; flips to 'flow_weight' once ENC-FTR-108 writes adaptive
# weights into the slot this projection initializes to 1.0).
_GDS_STANDING_PROJECTION_PREFIX = os.environ.get("GDS_STANDING_PROJECTION_PREFIX", "").strip()
_GDS_HARD_DISABLED = os.environ.get("GDS_HARD_DISABLED", "").strip().lower() in ("1", "true", "yes", "on")  # ENC-ISS-465/J41: hard-disable AGA/GDS -> cypher_fallback (kills Graph Analytics Serverless cost)
_GDS_SESSION_MEMORY = os.environ.get("GDS_SESSION_MEMORY", "2GB").strip() or "2GB"
_GDS_WEIGHT_PROPERTY = os.environ.get("GDS_WEIGHT_PROPERTY", "weight").strip() or "weight"
_GDS_FLOW_WEIGHT_PROPERTY = "flow_weight"
_GDS_PROJECTION_META_LABEL = "GdsProjectionMeta"
try:
    _GDS_PROJECTION_MAX_AGE_S = int(os.environ.get("GDS_PROJECTION_MAX_AGE_S", "3600"))
except (TypeError, ValueError):
    _GDS_PROJECTION_MAX_AGE_S = 3600

# ENC-FTR-082 Phase A (AC-1): raw pathway-telemetry sink. When PATHWAY_TELEMETRY_BUCKET
# is set (Wave 2 CFN grants s3:PutObject + injects the env vars) each hybrid call
# appends one JSONL object under s3://{bucket}/{prefix}/wave_id=<wid>/<ts>-<uuid>.jsonl.
# Until then the emitter degrades to a structured CloudWatch log line
# ('PATHWAY_TELEMETRY {json}') via the already-granted logs:PutLogEvents — so the
# Wave-1 code deploy is safe before the IAM/env wave lands. It never raises into the
# request path.
PATHWAY_TELEMETRY_BUCKET = os.environ.get("PATHWAY_TELEMETRY_BUCKET", "").strip()
PATHWAY_TELEMETRY_PREFIX = (
    os.environ.get("PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry").strip()
    or "pathway-telemetry"
)
# Bounded wall-clock budget for the supplementary edge-reconstruction walk (AC-1
# edges_traversed / AC-10 edge_participation). Smaller than the graph-signal budget
# so telemetry can never add the full _GRAPH_SIGNAL_DEADLINE_S to a response again.
try:
    _PATHWAY_EDGE_DEADLINE_S = float(os.environ.get("PATHWAY_EDGE_DEADLINE_S", "2.0"))
except (TypeError, ValueError):
    _PATHWAY_EDGE_DEADLINE_S = 2.0

# ENC-TSK-H89 (ENC-FTR-082 AC-12): governed bulk vector-read path config. A
# dedicated, strip-EXEMPT pagination over the n.embedding corpus for downstream
# correlation analysis (ENC-TSK-H34 AC-1). Latency-bounded by its own wall-clock
# deadline + server-side SKIP/LIMIT so a large page can never extend or perturb
# the hybrid retrieval request path. The hybrid path keeps stripping embeddings
# (_query_hybrid); ONLY this path returns the raw vector.
try:
    _VECTOR_READ_DEADLINE_S = float(os.environ.get("VECTOR_READ_DEADLINE_S", "10.0"))
except (TypeError, ValueError):
    _VECTOR_READ_DEADLINE_S = 10.0
_VECTOR_READ_DEFAULT_LIMIT = 200
_VECTOR_READ_MAX_LIMIT = 1000

# ENC-TSK-H92 (ENC-FTR-082 AC-2): flag-gated correlation-aware (pseudoinverse-
# style) encoding. OFF by default => byte-identical hybrid retrieval. When
# CORRELATION_ENCODING_ENABLED is truthy AND a transform artifact is configured,
# the offline-fit de-correlating transform W (tools/fit_encoding_h92.py, fit from
# the ENC-TSK-H91 high-correlation pairs) at CORRELATION_ENCODING_TRANSFORM_URI
# (local path or s3://) is applied to the query embedding before the HNSW vector
# search, suppressing the shared directions of near-duplicate pairs (reduced
# Hebbian crosstalk). No numpy in-Lambda — a pure-Python matrix-vector product.
_CORRELATION_ENCODING_ENABLED = (
    os.environ.get("CORRELATION_ENCODING_ENABLED", "").strip().lower()
    in ("1", "true", "yes", "on")
)
_CORRELATION_ENCODING_TRANSFORM_URI = os.environ.get("CORRELATION_ENCODING_TRANSFORM_URI", "").strip()
_correlation_transform_cache: Dict[str, Any] = {"loaded": False, "W": None, "dim": None}

_s3 = None


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


def _get_s3():
    """Lazy S3 client for the AC-1 pathway-telemetry sink. Tight timeouts + a single
    attempt so a slow/unavailable S3 cannot materially extend the hybrid response;
    the caller (_emit_pathway_telemetry) catches and suppresses all errors."""
    global _s3
    if _s3 is None:
        import boto3
        from botocore.config import Config
        _s3 = boto3.client(
            "s3",
            region_name=SECRETS_REGION,
            config=Config(
                connect_timeout=1,
                read_timeout=2,
                retries={"max_attempts": 1, "mode": "standard"},
            ),
        )
    return _s3


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
    # ENC-FTR-076 v2 / ENC-TSK-F45: Component-task lifecycle edges (OGTM registration)
    "DESIGNS",                # Component -> Task
    "DESIGNED_BY",            # Task -> Component
    # IMPLEMENTS already registered above (generic Task->Feature); also used for Component->Task
    "IMPLEMENTED_BY",         # Task -> Component
    "DEPLOYS",                # Component -> Task
    "DEPLOYED_BY",            # Task -> Component
    # ENC-FTR-098 / ENC-TSK-G35: MENTIONS edge auto-extracted from prose by
    # graph_sync._reconcile_mentions_edges(). Properties: source ('auto_mention'
    # | 'backfill' | 'audit_recompute'), extracted_from_field. See dictionary
    # entity graph_sync.mentions_extraction for the full extraction contract.
    "MENTIONS",
    # ENC-FTR-082 Phase A / AC-6 (OGTM): Pathway-telemetry traversal edge.
    # Registered for traversability (tracker.graphsearch edge_types=['PATHWAY_TRAVERSED'])
    # but deliberately NOT added to GRAPH_EDGE_WEIGHTS — a telemetry edge must not
    # perturb hybrid retrieval scoring in Phase A (the weighted overlay is AC-2).
    # Materialized via the ENC-FTR-049 relationship-record path and projected by
    # graph_sync RELATIONSHIP_TYPE_TO_EDGE_LABEL; labels must stay byte-identical
    # across both lambdas (ENC-ISS-178).
    "PATHWAY_TRAVERSED",
    "TRAVERSED_BY",
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
    if _GDS_HARD_DISABLED:
        return False  # ENC-ISS-465/J41: force cypher_fallback; never create an AGA session
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

    ENC-TSK-I03 (ENC-FTR-082 AC-2 retry): when the correlation-aware encoding is
    enabled (a valid h92.v1 transform W loads), HNSW recall still uses the RAW
    query embedding, then every candidate is RE-SCORED symmetrically by
    cosine(W·q, W·emb) — the de-correlating transform applied to BOTH sides — so a
    near-duplicate's distinctive residual decides rank. Disabled (or transform
    absent / dim-mismatch) => the HNSW cosine score is used unchanged, so the
    Cypher and the ranking are byte-identical to the pre-encoding behavior.
    """
    # Load the transform ONCE. When the encoding is off this returns (None, None)
    # immediately, rerank stays False, and the hot path is byte-identical.
    rerank_W, rerank_dim = _load_correlation_transform()
    rerank = rerank_W is not None and rerank_dim == len(query_embedding)
    wq = _transform_unit(query_embedding, rerank_W, rerank_dim) if rerank else None
    if rerank and wq is None:
        rerank = False  # degenerate transformed query — fall back to HNSW score

    # Scope to a single label when record_type is set.
    if record_type_filter:
        label = record_type_filter.capitalize()
        labels_to_query = [label] if label in LABEL_VECTOR_INDEXES else []
    else:
        labels_to_query = list(LABEL_VECTOR_INDEXES.keys())

    emb_return = f", node.{_EMBEDDING_PROPERTY} AS embedding" if rerank else ""
    by_rid: Dict[str, Dict[str, Any]] = {}
    for label in labels_to_query:
        index_name = LABEL_VECTOR_INDEXES[label]
        cypher = (
            "CALL db.index.vector.queryNodes($index_name, $k, $query_embedding) "
            "YIELD node, score "
            "WHERE node.project_id = $project_id "
            f"RETURN node.record_id AS rid, score, labels(node) AS labels{emb_return}"
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
                    if rerank:
                        # Symmetric re-score: cosine of the unit-normalized
                        # W·q and W·emb. Falls back to the HNSW score if this
                        # candidate's embedding is absent/degenerate.
                        we = _transform_unit(rec.get("embedding"), rerank_W, rerank_dim)
                        if we is not None:
                            score = sum(a * b for a, b in zip(wq, we))
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


# ---------------------------------------------------------------------------
# ENC-FTR-101 (Option B) — pre-materialized standing projection
# ---------------------------------------------------------------------------
# DOC-6EFD5DB32CD8 Rev 11/14 + io field guide DOC-D4CB8048798B. _hybrid_graph_
# ranks_gds provisions a fresh Aura Graph Analytics session (gds.graph.project
# {memory:'2GB'}) on every anchored request (~50s p95). Option B maintains ONE
# standing named projection refreshed OUT OF BAND (single writer:
# _handle_refresh_projection on an EventBridge schedule) so the request path only
# reattaches and runs gds.pageRank.stream against the warm projection.
#
# Defensive contract: the request path NEVER projects. When the projection is
# unconfigured / missing / errors, the warm path returns [] and the caller falls
# back to the existing per-query path (then the Cypher proxy) under the
# _GRAPH_SIGNAL_DEADLINE_S budget. No regression when GDS_STANDING_PROJECTION_
# PREFIX is unset.


def _standing_projection_name(project_id: str) -> str:
    """Stable per-project standing-projection name, or '' when the feature is
    unconfigured (GDS_STANDING_PROJECTION_PREFIX unset)."""
    if not _GDS_STANDING_PROJECTION_PREFIX:
        return ""
    return f"{_GDS_STANDING_PROJECTION_PREFIX}_{project_id}".replace("-", "_").lower()


def _hybrid_graph_ranks_gds_warm(
    driver,
    project_id: str,
    anchor_record_id: str,
    top_n: int,
) -> List[Dict[str, Any]]:
    """Personalized PageRank against the PRE-MATERIALIZED standing projection
    (ENC-FTR-101 Option B). Read-only: reattaches and runs gds.pageRank.stream
    against a projection built out of band — it NEVER calls gds.graph.project,
    so it cannot hit the per-query AGA session-creation cost nor the
    FlightRuntimeException same-graph-name race. Returns [] (so the caller falls
    back to the per-query path) when the projection is unconfigured, absent, or
    on any error. Never raises.
    """
    graph_name = _standing_projection_name(project_id)
    if not graph_name:
        return []
    ranked: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            exists_rec = session.run(
                "CALL gds.graph.exists($name) YIELD exists RETURN exists",
                name=graph_name,
            ).single()
            if not exists_rec or not exists_rec.get("exists"):
                return []

            anchor_rec = session.run(
                "MATCH (a) WHERE a.record_id = $rid AND a.project_id = $project_id "
                "RETURN id(a) AS nodeId LIMIT 1",
                rid=anchor_record_id,
                project_id=project_id,
            ).single()
            if anchor_rec is None or anchor_rec.get("nodeId") is None:
                return []

            # Mirror _hybrid_graph_ranks_gds' two-step resolution: stream raw
            # (nodeId, score) from the projection, then resolve record_ids via a
            # follow-up MATCH on the main DB (gds.util.asNode is unsupported under
            # the AGA Sessions surface and the projection carries no record_id).
            stream_result = session.run(
                """
                CALL gds.pageRank.stream(
                    $name,
                    {
                        sourceNodes: [$anchorId],
                        dampingFactor: $damping,
                        maxIterations: $maxIter,
                        relationshipWeightProperty: $weightProp
                    }
                )
                YIELD nodeId, score
                RETURN nodeId, score
                ORDER BY score DESC
                LIMIT $limit
                """,
                name=graph_name,
                anchorId=anchor_rec["nodeId"],
                damping=PPR_DAMPING_FACTOR,
                maxIter=PPR_MAX_ITERATIONS,
                weightProp=_GDS_WEIGHT_PROPERTY,
                limit=top_n,
            )
            node_rows = [(r.get("nodeId"), float(r.get("score") or 0.0)) for r in stream_result]
            if not node_rows:
                return []

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
                ranked.append({"record_id": rid, "score": score, "rank": rank_counter})
    except Exception as exc:
        logger.warning(
            "[WARNING] warm standing-projection PPR failed for %s — falling back: %s",
            graph_name, exc,
        )
        return []
    return ranked


def _refresh_standing_projection(driver, project_id: str) -> Dict[str, Any]:
    """(Re)build the standing named projection for one project (ENC-FTR-101
    Option B, single writer). Invoked OUT OF BAND by _handle_refresh_projection
    — never from the request path — so the FlightRuntimeException
    'already a job running' same-graph-name race (DOC-D4CB8048798B, Concurrency
    Hazards) cannot occur. Drops any prior projection of the same name, projects
    the project's nodes/edges with BOTH a per-type 'weight' and a flow_weight=1.0
    slot (ENC-FTR-101 AC-5), then stamps a GdsProjectionMeta marker carrying the
    last-refresh epoch for staleness telemetry (AC-3). Never raises.
    """
    if _GDS_HARD_DISABLED:
        return {"refreshed": False, "reason": "GDS_HARD_DISABLED", "project_id": project_id}
    graph_name = _standing_projection_name(project_id)
    if not graph_name:
        return {"refreshed": False, "reason": "GDS_STANDING_PROJECTION_PREFIX unset", "project_id": project_id}

    weight_case_parts = [f"WHEN '{etype}' THEN {w}" for etype, w in GRAPH_EDGE_WEIGHTS.items()]
    weight_case_sql = (
        "CASE type(r) " + " ".join(weight_case_parts) + f" ELSE {GRAPH_FALLBACK_DEFAULT_WEIGHT} END"
    )
    edge_union = "|".join(list(GRAPH_EDGE_WEIGHTS.keys()))
    result: Dict[str, Any] = {"project_id": project_id, "graph_name": graph_name}
    try:
        with driver.session() as session:
            # Drop any prior projection of this name (idempotent rebuild). Meta
            # marker nodes are excluded from the projection node set below.
            session.run(
                "CALL gds.graph.exists($name) YIELD exists "
                "WITH exists WHERE exists "
                "CALL gds.graph.drop($name) YIELD graphName RETURN graphName",
                name=graph_name,
            ).consume()

            proj = session.run(
                f"""
                MATCH (src) WHERE src.project_id = $project_id AND NOT src:{_GDS_PROJECTION_META_LABEL}
                OPTIONAL MATCH (src)-[r:{edge_union}]->(tgt)
                WHERE tgt IS NOT NULL AND tgt.project_id = $project_id
                WITH gds.graph.project(
                    $name,
                    src,
                    tgt,
                    {{relationshipProperties: {{weight: {weight_case_sql}, {_GDS_FLOW_WEIGHT_PROPERTY}: 1.0}}}},
                    {{memory: $memory}}
                ) AS g
                RETURN g.graphName AS graphName, g.nodeCount AS nodeCount, g.relationshipCount AS relationshipCount
                """,
                name=graph_name,
                project_id=project_id,
                memory=_GDS_SESSION_MEMORY,
            ).single()
            if proj is not None:
                result["node_count"] = proj.get("nodeCount")
                result["relationship_count"] = proj.get("relationshipCount")

            # Stamp the last-refresh marker for staleness telemetry (AC-3).
            session.run(
                f"MERGE (m:{_GDS_PROJECTION_META_LABEL} {{name: $name}}) "
                f"SET m.last_refresh = datetime(), m.last_refresh_epoch_ms = timestamp(), "
                f"m.weight_property = $weight_prop",
                name=graph_name,
                weight_prop=_GDS_WEIGHT_PROPERTY,
            ).consume()
        result["refreshed"] = True
        logger.info(
            "[SUCCESS] ENC-FTR-101 standing projection %s refreshed (nodes=%s, rels=%s)",
            graph_name, result.get("node_count"), result.get("relationship_count"),
        )
    except Exception as exc:
        logger.exception("[ERROR] standing projection refresh failed for %s", graph_name)
        result["refreshed"] = False
        result["error"] = str(exc)
    return result


def _standing_projection_status(driver, project_id: str) -> Dict[str, Any]:
    """Standing-projection existence + last-refresh age for health/observability
    (ENC-FTR-101 AC-3). Never raises."""
    graph_name = _standing_projection_name(project_id)
    status: Dict[str, Any] = {"configured": bool(graph_name), "name": graph_name or None}
    if not graph_name:
        return status
    try:
        with driver.session() as session:
            exists_rec = session.run(
                "CALL gds.graph.exists($name) YIELD exists RETURN exists",
                name=graph_name,
            ).single()
            status["exists"] = bool(exists_rec and exists_rec.get("exists"))
            meta = session.run(
                f"MATCH (m:{_GDS_PROJECTION_META_LABEL} {{name: $name}}) "
                f"RETURN m.last_refresh AS last_refresh, m.last_refresh_epoch_ms AS lr_ms, "
                f"timestamp() AS now_ms",
                name=graph_name,
            ).single()
            if meta and meta.get("lr_ms") is not None:
                lr = meta.get("last_refresh")
                status["last_refresh"] = str(lr) if lr is not None else None
                age = max(0, int((meta.get("now_ms") - meta.get("lr_ms")) // 1000))
                status["age_seconds"] = age
                status["stale"] = age > _GDS_PROJECTION_MAX_AGE_S
            else:
                status["last_refresh"] = None
                status["stale"] = True
            status["max_age_seconds"] = _GDS_PROJECTION_MAX_AGE_S
    except Exception as exc:
        logger.warning("[WARNING] standing projection status probe failed: %s", exc)
        status["error"] = str(exc)
    return status


def _handle_refresh_projection(event: Dict) -> Dict[str, Any]:
    """Out-of-band standing-projection refresh entrypoint (ENC-FTR-101 Option B).
    Invoked by an EventBridge scheduled rule or a direct Lambda invoke (single
    writer); NOT exposed on the public API Gateway route. Refreshes
    event['project_ids'] (list) or event['project_id'] (str), defaulting to the
    health-probe project.
    """
    driver = _ensure_live_driver(_get_neo4j_driver())
    if driver is None:
        return {"ok": False, "error": "neo4j driver unavailable after rebuild attempt"}
    project_ids = event.get("project_ids") or [event.get("project_id") or _HEALTH_PROBE_PROJECT]
    results = [_refresh_standing_projection(driver, pid) for pid in project_ids]
    return {"ok": all(r.get("refreshed") for r in results), "results": results}


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

    # ENC-ISS-310 / ENC-TSK-G97: tokenize the query instead of matching the whole
    # phrase. The previous `field CONTAINS toLower($q)` over the entire query string
    # only matched when a field contained the full phrase verbatim, so keyword recall
    # collapsed to zero for multi-word topic queries. Split into tokens and score each
    # node by per-token field-weighted CONTAINS (title 3 / intent 2 / description 1),
    # summed across tokens so records matching more terms rank higher.
    tokens: List[str] = []
    _seen_tokens = set()
    for _tok in query_text.lower().split():
        _tok = _tok.strip()
        if len(_tok) < 2 or _tok in _seen_tokens:
            continue
        _seen_tokens.add(_tok)
        tokens.append(_tok)
    if not tokens:
        return []

    cypher = (
        f"MATCH (n{label_filter}) "
        "WHERE n.project_id = $project_id "
        "AND ANY(t IN $tokens WHERE "
        "  toLower(coalesce(n.title, '')) CONTAINS t "
        "  OR toLower(coalesce(n.intent, '')) CONTAINS t "
        "  OR toLower(coalesce(n.description, '')) CONTAINS t) "
        "WITH n, reduce(s = 0.0, t IN $tokens | s "
        "  + (CASE WHEN toLower(coalesce(n.title, '')) CONTAINS t THEN 3.0 ELSE 0.0 END) "
        "  + (CASE WHEN toLower(coalesce(n.intent, '')) CONTAINS t THEN 2.0 ELSE 0.0 END) "
        "  + (CASE WHEN toLower(coalesce(n.description, '')) CONTAINS t THEN 1.0 ELSE 0.0 END) "
        ") AS score "
        "WHERE score > 0.0 "
        "RETURN n.record_id AS rid, score ORDER BY score DESC LIMIT $limit"
    )
    ranked: List[Dict[str, Any]] = []
    try:
        with driver.session() as session:
            result = session.run(cypher, project_id=project_id, tokens=tokens, limit=top_n)
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


# ---------------------------------------------------------------------------
# ENC-FTR-082 Phase A — Pathway telemetry (AC-1), edge participation (AC-10)
# ---------------------------------------------------------------------------

# Edge types eligible for pathway reconstruction: the same weighted topology the
# graph signal walks — NOT the telemetry edges themselves (PATHWAY_TRAVERSED is
# intentionally absent from GRAPH_EDGE_WEIGHTS so it is never reconstructed here).
_PATHWAY_WALK_EDGE_UNION = "|".join(GRAPH_EDGE_WEIGHTS.keys())


def _derive_intent_signature(query_text: str, anchor_record_id: str,
                             record_type: Optional[str]) -> str:
    """Deterministic intent fingerprint for AC-1 telemetry when the caller does not
    supply an explicit intent_signature. Stable across identical retrieval intents
    so ENC-FTR-108 can cluster pathways by intent."""
    norm = "\n".join([
        (query_text or "").strip().lower(),
        (anchor_record_id or "").strip().upper(),
        (record_type or "").strip().lower(),
    ])
    return "sha256:" + hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _reconstruct_pathway_edges(driver, project_id, anchor_record_id, result_rids):
    """AC-1 (edges_traversed + node_sequence) and AC-10 (edge_participation).

    The hybrid graph signal (GDS pageRank / warm projection) returns ranked nodes
    only — no edges. To honestly surface which graph edges participated in producing
    the result set, run one bounded shortestPath walk from the anchor to each
    resolved result node over the weighted edge topology and reconstruct the
    relationships. Bounded by _PATHWAY_EDGE_DEADLINE_S in a worker thread; returns
    empty structures on missing anchor / timeout / any error and NEVER raises into
    the request path or perturbs the already-computed RRF result.

    Returns: (edges_traversed, edge_participation, node_sequence)
    """
    if not anchor_record_id or not result_rids:
        return [], [], ([anchor_record_id] if anchor_record_id else [])

    result_set = set(result_rids)

    def _walk():
        cypher = (
            "MATCH (anchor {record_id: $rid, project_id: $pid}) "
            "MATCH (target) WHERE target.record_id IN $rids AND target.project_id = $pid "
            f"MATCH path = shortestPath((anchor)-[:{_PATHWAY_WALK_EDGE_UNION}*1..3]-(target)) "
            "UNWIND relationships(path) AS rel "
            "WITH DISTINCT elementId(rel) AS edge_id, type(rel) AS etype, "
            "     startNode(rel).record_id AS s, endNode(rel).record_id AS e "
            "RETURN edge_id, etype, s, e"
        )
        rows = []
        with driver.session() as session:
            res = session.run(cypher, rid=anchor_record_id, pid=project_id,
                              rids=list(result_rids))
            for r in res:
                rows.append((r["edge_id"], r["etype"], r["s"], r["e"]))
        return rows

    _pex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        rows = _pex.submit(_walk).result(timeout=_PATHWAY_EDGE_DEADLINE_S)
    except concurrent.futures.TimeoutError:
        logger.warning(
            "[WARNING] pathway edge reconstruction exceeded %.1fs for anchor=%s — "
            "emitting empty edge telemetry", _PATHWAY_EDGE_DEADLINE_S, anchor_record_id,
        )
        return [], [], [anchor_record_id]
    except Exception:
        logger.warning("[WARNING] pathway edge reconstruction failed", exc_info=True)
        return [], [], [anchor_record_id]
    finally:
        _pex.shutdown(wait=False)

    edges_traversed: List[Dict[str, Any]] = []
    participation: Dict[str, Dict[str, Any]] = {}
    node_sequence: List[str] = [anchor_record_id]
    seen_nodes = {anchor_record_id}
    for edge_id, etype, s, e in rows:
        edges_traversed.append({"edge_id": edge_id, "type": etype, "start": s, "end": e})
        outcome = "hit" if (s in result_set or e in result_set) else "traversed"
        agg = participation.get(edge_id)
        if agg is None:
            participation[edge_id] = {
                "edge_id": edge_id,
                "traversal_count": 1,
                "retrieval_outcome": outcome,
            }
        else:
            agg["traversal_count"] += 1
            if outcome == "hit":
                agg["retrieval_outcome"] = "hit"
        for rid in (s, e):
            if rid and rid not in seen_nodes:
                seen_nodes.add(rid)
                node_sequence.append(rid)

    return edges_traversed, list(participation.values()), node_sequence


def _build_pathway_telemetry_record(*, wave_id, intent_signature, project_id,
                                    anchor_record_id, node_sequence, edges_traversed,
                                    edge_participation, result_count, graph_algorithm,
                                    signal_availability) -> Dict[str, Any]:
    """Assemble the AC-1 raw telemetry record (also carries the AC-10 edge
    participation list). This field set IS the ENC-FTR-108 AC-4 input contract."""
    return {
        "schema": "enceladus.pathway.telemetry.v1",
        "wave_id": wave_id or "unassigned",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intent_signature": intent_signature,
        "project_id": project_id,
        "anchor_record_id": anchor_record_id or None,
        "node_sequence": node_sequence,
        "edges_traversed": edges_traversed,
        "edge_participation": edge_participation,
        "outcome": {
            "result_count": result_count,
            "graph_algorithm": graph_algorithm,
            "signal_availability": signal_availability,
        },
    }


def _emit_pathway_telemetry(record: Dict[str, Any]) -> None:
    """AC-1 sink. Append one JSONL telemetry object to S3 partitioned by wave_id
    when PATHWAY_TELEMETRY_BUCKET is configured; otherwise emit a structured
    CloudWatch log line (logs:PutLogEvents is already granted). Fully defensive —
    never raises into the request path."""
    try:
        line = json.dumps(record, default=str)
        if PATHWAY_TELEMETRY_BUCKET:
            try:
                wid = str(record.get("wave_id") or "unassigned").replace("/", "_") or "unassigned"
                key = (
                    f"{PATHWAY_TELEMETRY_PREFIX}/wave_id={wid}/"
                    f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex}.jsonl"
                )
                _get_s3().put_object(
                    Bucket=PATHWAY_TELEMETRY_BUCKET,
                    Key=key,
                    Body=line.encode("utf-8"),
                    ContentType="application/x-ndjson",
                )
                return
            except Exception as exc:
                logger.warning(
                    "[WARNING] pathway telemetry S3 put failed (%s); CloudWatch fallback", exc,
                )
        logger.info("PATHWAY_TELEMETRY %s", line)
    except Exception:
        logger.exception("[ERROR] pathway telemetry emit failed (suppressed)")


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

    # ENC-FTR-082 Phase A (AC-1): optional pathway-telemetry provenance. Backward
    # compatible — both default to empty; intent_signature is derived deterministically
    # when absent so every hybrid call carries a stable intent fingerprint.
    wave_id = str(params.get("wave_id", "")).strip()
    intent_signature = str(params.get("intent_signature", "")).strip()
    if not intent_signature:
        intent_signature = _derive_intent_signature(query_text, anchor_record_id, record_type_filter)

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
            # ENC-TSK-I03 (ENC-FTR-082 AC-2 retry): the RAW query drives HNSW
            # recall; the flag-gated correlation-aware encoding is applied
            # SYMMETRICALLY as a candidate re-rank inside _hybrid_vector_ranks
            # (cosine(W·q, W·emb)), not as a query-side pre-HNSW transform — the
            # query-side variant (ENC-TSK-H92) measured net-negative (precision@1
            # -0.9%) because it compared W·q against an un-transformed index.
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
        # ENC-ISS-311 / ENC-TSK-G98: the GDS path builds a per-query Aura Graph
        # Analytics session (gds.graph.project {memory:'2GB'}) whose creation can
        # blow past the synchronous read budget and hang the whole hybrid response.
        # Run the graph signal under a hard wall-clock deadline; on timeout degrade
        # to an empty graph signal (graph_algorithm='timeout') so vector+keyword
        # still return via RRF. The worker thread is abandoned on timeout (shutdown
        # wait=False) — the Bolt call finishes/errors in the background without
        # blocking the handler.
        def _graph_signal():
            # ENC-FTR-101 (Option B): try the warm standing projection first
            # (reattach + gds.pageRank.stream; no per-query projection build). On
            # miss/unconfigured/error it returns [] and we fall back to the
            # per-query path, then the Cypher proxy — all under the deadline.
            warm_ranks = _hybrid_graph_ranks_gds_warm(
                driver, project_id, anchor_record_id, top_n=HYBRID_SIGNAL_TOP_N,
            )
            if warm_ranks:
                return warm_ranks, "gds_pagerank"
            if _check_gds_available(driver):
                gds_ranks = _hybrid_graph_ranks_gds(
                    driver, project_id, anchor_record_id, top_n=HYBRID_SIGNAL_TOP_N,
                )
                if gds_ranks:
                    return gds_ranks, "gds_pagerank"
            cypher_ranks = _hybrid_graph_ranks_cypher_fallback(
                driver, project_id, anchor_record_id, top_n=HYBRID_SIGNAL_TOP_N,
            )
            if cypher_ranks:
                return cypher_ranks, "cypher_fallback"
            return [], "unavailable"

        _gex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            graph_ranks, graph_algorithm = _gex.submit(_graph_signal).result(
                timeout=_GRAPH_SIGNAL_DEADLINE_S
            )
            graph_available = bool(graph_ranks)
        except concurrent.futures.TimeoutError:
            logger.warning(
                "[WARNING] graph signal exceeded %.1fs deadline for anchor=%s — "
                "degrading to vector+keyword", _GRAPH_SIGNAL_DEADLINE_S, anchor_record_id,
            )
            graph_ranks, graph_available, graph_algorithm = [], False, "timeout"
        except Exception:
            logger.exception("[ERROR] graph signal computation failed")
            graph_ranks, graph_available, graph_algorithm = [], False, "unavailable"
        finally:
            _gex.shutdown(wait=False)

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
        _sig_avail = {
            "vector": vector_available,
            "graph": graph_available,
            "keyword": keyword_available,
        }
        # AC-1: emit telemetry even for zero-result retrievals (no edges/nodes).
        _emit_pathway_telemetry(_build_pathway_telemetry_record(
            wave_id=wave_id, intent_signature=intent_signature, project_id=project_id,
            anchor_record_id=anchor_record_id, node_sequence=[], edges_traversed=[],
            edge_participation=[], result_count=0, graph_algorithm=graph_algorithm,
            signal_availability=_sig_avail,
        ))
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "edge_participation": [],
            "pathway": {
                "node_sequence": [], "edge_count": 0,
                "intent_signature": intent_signature, "wave_id": wave_id or "unassigned",
            },
            "summary": "No signals returned candidates. "
                       "(vector=0, graph=0, keyword=0) — try a broader query or verify anchor is in the graph.",
            "query_cypher": "hybrid/no-signals",
            "signal_availability": _sig_avail,
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

    # ENC-FTR-082 Phase A (AC-1 edges_traversed/node_sequence, AC-10 participation):
    # reconstruct the graph edges connecting the anchor to the resolved result set.
    # Bounded + fully degradable; never perturbs `nodes`/RRF above.
    result_rids = [n.get("record_id") for n in nodes if n.get("record_id")]
    edges_traversed, edge_participation, node_sequence = _reconstruct_pathway_edges(
        driver, project_id, anchor_record_id, result_rids,
    )

    summary = (
        f"Hybrid: {len(nodes)} nodes "
        f"(vector={len(vector_ranks)}, graph={len(graph_ranks)}, keyword={len(keyword_ranks)}; "
        f"graph_algo={graph_algorithm}; embedded={embedding_covered}/{len(top_fused)})"
    )

    _sig_avail = {
        "vector": vector_available,
        "graph": graph_available,
        "keyword": keyword_available,
    }

    # AC-1: emit the raw pathway-telemetry record (S3 append log when configured,
    # else CloudWatch fallback). Carries the AC-10 edge_participation list.
    _emit_pathway_telemetry(_build_pathway_telemetry_record(
        wave_id=wave_id, intent_signature=intent_signature, project_id=project_id,
        anchor_record_id=anchor_record_id, node_sequence=node_sequence,
        edges_traversed=edges_traversed, edge_participation=edge_participation,
        result_count=len(nodes), graph_algorithm=graph_algorithm,
        signal_availability=_sig_avail,
    ))

    return {
        "nodes": nodes,
        "edges": edges_traversed,
        "paths": [],
        "edge_participation": edge_participation,
        "pathway": {
            "node_sequence": node_sequence,
            "edge_count": len(edges_traversed),
            "intent_signature": intent_signature,
            "wave_id": wave_id or "unassigned",
        },
        "summary": summary,
        "query_cypher": "hybrid/multi-signal-rrf",
        "signal_availability": _sig_avail,
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


def _load_correlation_transform():
    """ENC-TSK-H92: lazy-load the offline-fit de-correlating transform W (h92.v1
    artifact). Returns (W, dim) or (None, None), cached after the first attempt.
    Fully defensive — any failure disables the encoding (returns None) and is
    logged, never raised into the request path."""
    if not _CORRELATION_ENCODING_ENABLED or not _CORRELATION_ENCODING_TRANSFORM_URI:
        return None, None
    if _correlation_transform_cache["loaded"]:
        return _correlation_transform_cache["W"], _correlation_transform_cache["dim"]
    W = None
    dim = None
    try:
        uri = _CORRELATION_ENCODING_TRANSFORM_URI
        if uri.startswith("s3://"):
            bucket, _, key = uri[5:].partition("/")
            body = _get_s3().get_object(Bucket=bucket, Key=key)["Body"].read()
            artifact = json.loads(body)
        else:
            with open(uri, "r", encoding="utf-8") as fh:
                artifact = json.load(fh)
        W = artifact.get("W")
        dim = int(artifact.get("dim") or (len(W) if W else 0))
        if not W or dim <= 0 or len(W) != dim:
            logger.warning("[WARNING] correlation transform malformed; encoding disabled")
            W, dim = None, None
    except Exception:
        logger.exception("[ERROR] correlation transform load failed; encoding disabled")
        W, dim = None, None
    _correlation_transform_cache.update({"loaded": True, "W": W, "dim": dim})
    return W, dim


def _transform_unit(vec, W, dim):
    """ENC-TSK-I03 (ENC-FTR-082 AC-2 retry): pure-Python W·vec then L2-normalize to
    a unit vector; returns None on a missing/degenerate input. Used by the
    symmetric vector re-rank in _hybrid_vector_ranks for BOTH the query and each
    candidate embedding, so cosine(W·q, W·emb) reduces to a dot product of the two
    returned unit vectors. Assumes W is a loaded dim×dim matrix; no numpy."""
    if vec is None or len(vec) != dim:
        return None
    out = [0.0] * dim
    for i in range(dim):
        row = W[i]
        acc = 0.0
        for j in range(dim):
            acc += row[j] * vec[j]
        out[i] = acc
    norm = sum(x * x for x in out) ** 0.5
    if norm <= 0.0:
        return None
    return [x / norm for x in out]


def _query_vector_read(driver, project_id: str, params: Dict) -> Dict:
    """ENC-TSK-H89 / ENC-FTR-082 AC-12 — governed bulk vector-read over the
    n.embedding corpus.

    A dedicated, strip-EXEMPT, paginated read of node embeddings for downstream
    correlation analysis (ENC-TSK-H34 AC-1). This is the ONLY graphsearch path
    that returns the raw n.embedding vector; the hybrid retrieval path
    (_query_hybrid) keeps stripping it (lambda_function.py:1785-1788). The read is
    latency-bounded by a dedicated wall-clock deadline and server-side SKIP/LIMIT
    pagination so a large page can never extend or perturb the hybrid request
    path. Backward compatible: this handler is only reached for
    search_type=vector_read, so the hybrid/other paths are unchanged.

    Query parameters:
      project_id    (required; validated by _handle_search)
      offset        Pagination cursor; default 0.
      limit         Page size; default 200, clamped to [1, 1000].
      record_type   Optional label filter (task/issue/feature/plan/lesson/document).

    Response contract:
      {
        "nodes":   [{record_id, record_type, embedding:[...float]}],
        "edges":   [], "paths": [],
        "pagination": {offset, limit, returned, next_offset|null, has_more},
        "embedding_property": "embedding",
        "embedding_dim": <int|null>,
        "summary": "...",
        "query_cypher": "vector_read/paginated",
      }
    """
    # ---- Parse + clamp pagination -----------------------------------------
    try:
        offset = int(params.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, offset)
    try:
        limit = int(params.get("limit", _VECTOR_READ_DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = _VECTOR_READ_DEFAULT_LIMIT
    limit = max(1, min(limit, _VECTOR_READ_MAX_LIMIT))

    record_type_filter = params.get("record_type") or None

    # Reuse the live-pool guard so a frozen container's half-open Bolt socket
    # cannot stall this read (mirrors _query_hybrid).
    driver = _ensure_live_driver(driver)
    if driver is None:
        return {"error": "neo4j driver unavailable after rebuild attempt"}

    # Optional single-label scope; otherwise read across the embedded corpus.
    label_clause = ""
    if record_type_filter:
        label = str(record_type_filter).capitalize()
        if label not in LABEL_VECTOR_INDEXES:
            valid = ", ".join(sorted(k.lower() for k in LABEL_VECTOR_INDEXES))
            return {"error": f"record_type must be one of: {valid}"}
        label_clause = f":{label}"

    # Stable record_id ordering => deterministic SKIP/LIMIT pages across calls.
    # Fetch limit+1 to detect has_more without a second round-trip.
    cypher = (
        f"MATCH (n{label_clause}) "
        f"WHERE n.project_id = $project_id AND n.{_EMBEDDING_PROPERTY} IS NOT NULL "
        f"RETURN n.record_id AS record_id, labels(n) AS labels, "
        f"n.{_EMBEDDING_PROPERTY} AS embedding "
        "ORDER BY n.record_id "
        "SKIP $offset LIMIT $limit"
    )

    def _read():
        rows: List[Dict[str, Any]] = []
        with driver.session() as session:
            result = session.run(
                cypher,
                project_id=project_id,
                offset=offset,
                limit=limit + 1,
            )
            for rec in result:
                rid = rec.get("record_id")
                if not rid:
                    continue
                labels = rec.get("labels") or []
                embedding = rec.get("embedding")
                rows.append({
                    "record_id": rid,
                    "record_type": labels[0].lower() if labels else "",
                    _EMBEDDING_PROPERTY: list(embedding) if embedding is not None else None,
                })
        return rows

    # Latency-bound the read on a worker thread; abandon on timeout so a slow
    # page can never hang the handler (mirrors the hybrid graph-signal pattern).
    _vex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        rows = _vex.submit(_read).result(timeout=_VECTOR_READ_DEADLINE_S)
    except concurrent.futures.TimeoutError:
        logger.warning(
            "[WARNING] vector_read exceeded %.1fs deadline (offset=%s limit=%s) — reduce limit",
            _VECTOR_READ_DEADLINE_S, offset, limit,
        )
        return {"error": f"vector_read exceeded {_VECTOR_READ_DEADLINE_S:.0f}s deadline; reduce limit"}
    except Exception:
        logger.exception("[ERROR] vector_read query failed (offset=%s limit=%s)", offset, limit)
        return {"error": "vector_read query failed"}
    finally:
        _vex.shutdown(wait=False)

    has_more = len(rows) > limit
    page = rows[:limit]
    next_offset = offset + limit if has_more else None
    embedding_dim = (
        len(page[0][_EMBEDDING_PROPERTY])
        if page and page[0].get(_EMBEDDING_PROPERTY) is not None
        else None
    )

    return {
        "nodes": page,
        "edges": [],
        "paths": [],
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(page),
            "next_offset": next_offset,
            "has_more": has_more,
        },
        "embedding_property": _EMBEDDING_PROPERTY,
        "embedding_dim": embedding_dim,
        "summary": (
            f"Vector-read: {len(page)} nodes "
            f"(offset={offset}, limit={limit}, has_more={str(has_more).lower()}; "
            f"dim={embedding_dim}; record_type={record_type_filter or 'all'})"
        ),
        "query_cypher": "vector_read/paginated",
    }


SEARCH_HANDLERS = {
    "traversal": _query_traversal,
    "neighbors": _query_neighbors,
    "path": _query_path,
    "keyword": _query_keyword,
    "hybrid": _query_hybrid,
    "vector_read": _query_vector_read,
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
    # ENC-FTR-082 Phase A: edge_participation (AC-10) + pathway summary (AC-1).
    for hybrid_key in (
        "signal_availability",
        "graph_algorithm",
        "rrf_k",
        "embedding_coverage_sample",
        "per_node_fusion",
        "fsrs_t3_threshold",
        "include_below_threshold",
        "edge_participation",
        "pathway",
        # ENC-TSK-I03 / ENC-ISS-404: vector_read pagination + embedding metadata
        # must survive the response envelope so --source gamma can paginate. They
        # were dropped here, leaving has_more only inside the summary string and
        # the gamma reader stuck on page 1 (200 of 2899 nodes).
        "pagination",
        "embedding_property",
        "embedding_dim",
    ):
        if hybrid_key in result:
            response_body[hybrid_key] = result[hybrid_key]
    return _response(200, response_body)


def _handle_health(event: Dict) -> Dict:
    """Handle GET /api/v1/tracker/graphsearch/health.

    ENC-ISS-312 / ENC-TSK-G99: beyond the Bolt liveness ping, run a cheap
    functional probe and report per-signal availability (vector/graph/keyword)
    so a green health can no longer mask a dead retrieval pipeline — the failure
    mode that hid the ENC-ISS-304 vector outage for weeks. Probes are wrapped
    individually so one failing signal never fails the whole health response.
    """
    driver = _get_neo4j_driver()
    if driver is None:
        return _response(200, {"status": "unavailable", "message": "Neo4j driver not initialized"})

    try:
        start = time.time()
        with driver.session() as session:
            session.run("RETURN 1 AS health").single()

        signals = {"vector": False, "graph": False, "keyword": False}
        # keyword: a known-common token must return at least one hit.
        try:
            kw = _hybrid_keyword_ranks(driver, _HEALTH_PROBE_PROJECT, _HEALTH_PROBE_TOKEN, top_n=1)
            signals["keyword"] = bool(kw)
        except Exception:
            logger.warning("[WARNING] health keyword probe failed", exc_info=True)
        # vector: the query-side embedding must be computable (module + Bedrock).
        try:
            signals["vector"] = _compute_query_embedding(_HEALTH_PROBE_TOKEN) is not None
        except Exception:
            logger.warning("[WARNING] health vector probe failed", exc_info=True)
        # graph: GDS/AGA plugin reachable (cheap CALL gds.list; no projection build).
        try:
            signals["graph"] = _check_gds_available(driver)
        except Exception:
            logger.warning("[WARNING] health graph probe failed", exc_info=True)

        # ENC-FTR-101 (Option B): standing-projection existence + staleness (AC-3).
        # Bounded + observable so a stale/missing warm projection is visible here
        # while the request path still degrades gracefully to the deadline path.
        graph_projection = {"configured": bool(_GDS_STANDING_PROJECTION_PREFIX)}
        try:
            graph_projection = _standing_projection_status(driver, _HEALTH_PROBE_PROJECT)
        except Exception:
            logger.warning("[WARNING] health standing-projection probe failed", exc_info=True)

        duration_ms = int((time.time() - start) * 1000)
        return _response(200, {
            "status": "healthy",
            "response_ms": duration_ms,
            "signals": signals,
            "graph_projection": graph_projection,
        })
    except Exception as e:
        logger.warning("[WARNING] Graph health check failed: %s", e)
        return _response(200, {"status": "unavailable", "message": str(e)})


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """API Gateway v2 proxy handler."""
    # ENC-FTR-101 (Option B): out-of-band standing-projection refresh. EventBridge
    # scheduled events / direct invokes carry action='refresh_projection' (and lack
    # the API Gateway requestContext), so detect them before the HTTP routing below.
    if isinstance(event, dict) and (
        event.get("action") == "refresh_projection"
        or event.get("detail-type") == "Scheduled Event"
        or event.get("source") == "aws.events"
    ):
        return _handle_refresh_projection(event)

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
