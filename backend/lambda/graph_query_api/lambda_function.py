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
  OPENSEARCH_ENDPOINT            Gamma OpenSearch HTTPS URL (ENC-TSK-L43)
  OPENSEARCH_READ_ALIAS          Read alias (records_read)
  OPENSEARCH_SECRET_NAME         Secrets Manager secret for query user
  OPENSEARCH_USERNAME            OpenSearch security-plugin username (query)
  FEED_API_BASE                  Base URL for feed/corpus facet fallback
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

import corroboration
import dedup_convergence
import energy_function
import opensearch_keyword

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ENC-FTR-095 / ENC-TSK-I90: sheaf Laplacian H1 inconsistency detection. The
# module is co-located in this Lambda package (no .build_extras entry needed) and
# is pure-Python (no numpy/scipy), so the import is unconditional but guarded so a
# packaging slip degrades the one search_type rather than the whole function.
try:  # pragma: no cover - import guard
    import sheaf_cohomology as _sheaf_cohomology
except Exception:  # pragma: no cover - import guard
    _sheaf_cohomology = None
    logger.warning("[WARNING] sheaf_cohomology module unavailable — sheaf_cohomology search_type disabled")

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

VALID_SEARCH_TYPES = {"adjacency", "dedup_convergence", "hybrid", "keyword", "laplacian", "neighbors", "path", "sheaf_cohomology", "traversal"}

# ENC-TSK-I88 (ENC-FTR-085 comp-percolation-monitor): bounded page sizes for the
# read-only adjacency export consumed by the nightly percolation Lambda. Mirrors
# the vector_read pagination discipline — large corpora stream across several
# calls so a single response never exceeds the API Gateway payload cap.
ADJACENCY_DEFAULT_LIMIT = 5000
ADJACENCY_MAX_LIMIT = 20000

# ---------------------------------------------------------------------------
# ENC-FTR-089 / ENC-TSK-I89 — tracker.embeddings_for raw-embedding egress
# ---------------------------------------------------------------------------
# Research-only egress of the stored Amazon Titan Text Embeddings V2 vectors
# (256-dim, L2-normalized) that graph_sync/embedding.py writes onto record
# nodes under the `embedding` property. This is an IAM-scoped read: it exposes
# raw model vectors, so it is gated to the internal service key and admin-tier
# (io-dev-admin) Cognito tokens only — standard/elevated/observe agent tokens
# are rejected with 403. It introduces NO new edge types or graph nodes and
# does not touch graph_sync (OGTM AC-4): it reads the existing Titan V2
# vectors in place. Callers stack the returned vectors into an (N x 256)
# matrix and compute np.mean(matrix, axis=0) as a demand-centroid / Fréchet
# barycenter approximation (FTR-084 / FTR-087).
EMBEDDING_EGRESS_SEARCH_TYPE = "embeddings_for"
EMBEDDING_EGRESS_DIMENSIONS = 256
EMBEDDING_EGRESS_MODEL_ID = "amazon.titan-embed-text-v2:0"
MAX_EMBEDDING_EGRESS_RECORD_IDS = 100

# Admin-tier authorization tokens. `enc:agent_tier` is the governed claim the
# ENC-FTR-074 pre-token Lambda stamps onto M2M access tokens (admin > elevated
# > standard > observe); `io-dev-admin` is the product-lead Cognito group on
# human/admin identities. Either one (or the internal service key) authorizes
# raw-embedding egress.
_EGRESS_ADMIN_AGENT_TIER = "admin"
_EGRESS_ADMIN_COGNITO_GROUP = "io-dev-admin"

# ENC-TSK-I81 / ENC-FTR-088: graph_laplacian read action bounds.
# A vertex-set query resolves an induced subgraph whose (sparse) Laplacian
# spectrum is computed via scipy.sparse.linalg.eigsh. Cap the vertex count so a
# pathological query can never build an O(n^2) dense fallback large enough to
# blow the 180s SLO / Lambda memory; eigsh on the CSR operator stays cheap well
# past this bound but the dense small-n fallback must not.
LAPLACIAN_MAX_VERTICES = 500
LAPLACIAN_DEFAULT_K = 3

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
# ENC-TSK-J03: PPR/PageRank reads flow_weight (not static type weight) when set.
_GDS_PPR_WEIGHT_PROPERTY = (
    os.environ.get("GDS_PPR_WEIGHT_PROPERTY", _GDS_FLOW_WEIGHT_PROPERTY).strip()
    or _GDS_FLOW_WEIGHT_PROPERTY
)
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

# ENC-FTR-087 Phase 1 — wave-close drift telemetry sink. When DRIFT_TELEMETRY_TABLE
# is set (01-data.yaml provisions the table; 02-compute.yaml grants PutItem + injects
# the env var) each wave-close event writes one d_centroid_L2 + d_spectral record to
# the per-project DynamoDB time series (queryable via the project-timestamp-index GSI).
DRIFT_TELEMETRY_TABLE = os.environ.get("DRIFT_TELEMETRY_TABLE", "").strip()

# ENC-FTR-109 / ENC-TSK-K05 — stigmergic exploration trace sink (telemetry-only).
STIGMERGIC_TRACE_TABLE = os.environ.get("STIGMERGIC_TRACE_TABLE", "").strip()

_s3 = None
_dynamodb = None
_cloudwatch = None


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


def _get_dynamodb():
    """Lazy low-level DynamoDB client for the ENC-FTR-087 wave-close drift sink."""
    global _dynamodb
    if _dynamodb is None:
        import boto3
        from botocore.config import Config
        _dynamodb = boto3.client(
            "dynamodb",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _dynamodb


def _get_cloudwatch():
    """Lazy CloudWatch client for the ENC-TSK-K43 GraphHealth lambda2 metric
    publisher (mirrors _get_dynamodb / _get_s3 lazy-singleton convention)."""
    global _cloudwatch
    if _cloudwatch is None:
        import boto3
        from botocore.config import Config
        _cloudwatch = boto3.client(
            "cloudwatch",
            region_name=SECRETS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _cloudwatch


_SPURIOUS_ATTRACTOR_RECENT_LIMIT = 5


def _recent_spurious_attractor_rate(project_id: str) -> Optional[float]:
    """ENC-TSK-I91 (ENC-FTR-105 AC-7) — best-effort mean of the most recent
    non-null spurious_attractor_rate values for a project.

    Read-only Query against the project-timestamp-index GSI on the existing
    enceladus-drift-telemetry table — the same IAM grant ENC-TSK-I85 already
    provisioned for the wave-close write path (DriftTelemetryTableAccess /
    dynamodb:Query), so this adds no new infrastructure. Surfaced on the
    adjacency search_type (ENC-FTR-085 / ENC-TSK-I88) so the nightly
    percolation-monitor Lambda — which reads the graph exclusively through this
    endpoint — can fold a recent spurious_attractor_rate aggregate into its own
    telemetry without gaining a new DynamoDB grant of its own.

    Returns None (rather than raising) on any failure, missing table config, or
    when no recent record carries a non-null rate, so this enrichment can never
    break the adjacency page it rides along on.
    """
    if not DRIFT_TELEMETRY_TABLE:
        return None
    try:
        resp = _get_dynamodb().query(
            TableName=DRIFT_TELEMETRY_TABLE,
            IndexName="project-timestamp-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": project_id}},
            ScanIndexForward=False,
            Limit=_SPURIOUS_ATTRACTOR_RECENT_LIMIT,
        )
    except Exception:  # noqa: BLE001 — enrichment must never break adjacency reads
        logger.warning(
            "[WARNING] recent spurious_attractor_rate lookup failed project_id=%s",
            project_id, exc_info=True,
        )
        return None

    values: List[float] = []
    for item in resp.get("Items", []):
        n = item.get("spurious_attractor_rate", {}).get("N")
        if n is None:
            continue
        try:
            values.append(float(n))
        except (TypeError, ValueError):
            continue
    if not values:
        return None
    return sum(values) / len(values)


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

def _has_enceladus_id_token(event: Dict) -> bool:
    """True when the request carries an enceladus_id_token cookie (header or APIGW v2 array)."""
    headers = event.get("headers") or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    cookie_parts = [
        part.strip()
        for part in cookie_header.split(";")
        if isinstance(part, str) and part.strip()
    ]
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(
            part.strip()
            for part in event_cookies
            if isinstance(part, str) and part.strip()
        )
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())
    return any(part.startswith("enceladus_id_token=") for part in cookie_parts)


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

    # Cognito session cookie — APIGW HTTP API v2 may pass cookies via event.cookies[].
    if _has_enceladus_id_token(event):
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
    # ENC-TSK-C08 / ENC-FTR-064 (OGTM): Handoff Consolidation Engine provenance
    # edges. CONSOLIDATED_FROM: Lesson-candidate Document -> source Handoff
    # Documents. PROPOSED_BY: candidate -> proposer (the HCE feature/agent).
    # Field-projected by graph_sync from the candidate's consolidated_from /
    # proposed_by fields; labels must stay byte-identical across both lambdas.
    "CONSOLIDATED_FROM", "CONSOLIDATES",
    "PROPOSED_BY", "PROPOSES",
    "TRAVERSED_BY",
    # ENC-TSK-J04 / ENC-FTR-074 Ph3: agent identity/session/credential lifecycle edges.
    # Projected by graph_sync from the agent-store streams (_reconcile_agent_edges /
    # _project_mutated_edge). Registered here so tracker.graphsearch edge_types=[...]
    # queries traverse them; labels are byte-identical to graph_sync
    # RELATIONSHIP_TYPE_TO_EDGE_LABEL values (ENC-ISS-178 drift guard).
    "AUTHENTICATED_AS",   # AgentSession -> AgentIdentity
    "OWNED_BY",           # AgentCredential -> AgentIdentity
    "DERIVED_FROM",       # AgentCredential -> parent AgentCredential (rotation lineage)
    "TRIGGERED_BY",       # AgentSession -> triggering session/routine
    "MUTATED",            # AgentSession -> any record it wrote (write_source.provider)
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
# ENC-TSK-I81 / ENC-FTR-088: graph Laplacian read action
# ---------------------------------------------------------------------------
# Resolves a vertex set (keyword query or explicit record_ids), materializes the
# induced subgraph adjacency over EXISTING typed edges (no new edge types — OGTM
# N/A, AC-4), and computes the smallest-k Laplacian eigenpairs via
# scipy.sparse.linalg.eigsh (AC-2). Returns a CSR adjacency (base64 float32 data
# + base64 int32 indices/indptr), the Fiedler vector, the k smallest eigenvalues,
# the degree vector, and an index->record_id vertex_map. From adjacency_csr +
# degrees a client reconstructs L = D - A (combinatorial) or the symmetric
# normalized Laplacian L_sym = I - D^{-1/2} A D^{-1/2} — the spectral object the
# Wave-Close Drift Telemetry d_spectral measurement consumes (ENC-FTR-087, AC-3).
#
# The DEFAULT normalization is combinatorial (L = D - A): its smallest eigenvalue
# is identically 0 for ANY graph (the constant vector is always in the null
# space), so eigenvalues[0] < 0.001 holds even for an edge-sparse / disconnected
# 10-node subgraph (AC-5). normalization='normalized' is offered as an opt-in for
# scale-invariant spectral comparison.


def _b64_array(arr, np_dtype: str) -> str:
    """Base64-encode a numpy array's raw little-endian bytes for compact, lossless
    transport of CSR components (AC-1 adjacency_csr 'base64 float32' contract)."""
    import base64
    import numpy as np
    return base64.b64encode(
        np.ascontiguousarray(arr, dtype=np_dtype).tobytes()
    ).decode("ascii")


def _laplacian_select_vertices(driver, project_id: str, params: Dict) -> Dict:
    """Resolve the ordered vertex set for the induced subgraph.

    Selection precedence: explicit record_ids (comma list) -> keyword
    vertex_set_query (title/record_id CONTAINS) -> all project nodes. Placeholder
    nodes (ENC-TSK-E06 is_placeholder) are excluded so edge-target stubs never
    enter the spectrum. Returns {ids, query_cypher} or {error}.
    """
    try:
        limit = int(params.get("limit", LAPLACIAN_MAX_VERTICES) or LAPLACIAN_MAX_VERTICES)
    except (TypeError, ValueError):
        return {"error": "limit must be an integer"}
    limit = max(2, min(limit, LAPLACIAN_MAX_VERTICES))

    record_ids_param = params.get("record_ids", "")
    vertex_set_query = (params.get("vertex_set_query", "") or "").strip()

    explicit_ids: List[str] = []
    if record_ids_param:
        if isinstance(record_ids_param, list):
            explicit_ids = [str(x).strip() for x in record_ids_param if str(x).strip()]
        else:
            explicit_ids = [x.strip() for x in str(record_ids_param).split(",") if x.strip()]

    if explicit_ids:
        cypher = (
            "MATCH (n) "
            "WHERE n.project_id = $project_id AND n.record_id IN $ids "
            "AND coalesce(n.is_placeholder, false) = false "
            "RETURN DISTINCT n.record_id AS rid ORDER BY rid LIMIT $limit"
        )
        run_params = {"project_id": project_id, "ids": explicit_ids, "limit": limit}
    elif vertex_set_query:
        cypher = (
            "MATCH (n) "
            "WHERE n.project_id = $project_id "
            "AND coalesce(n.is_placeholder, false) = false "
            "AND (toLower(coalesce(n.title, '')) CONTAINS toLower($q) "
            "OR n.record_id CONTAINS toUpper($q)) "
            "RETURN DISTINCT n.record_id AS rid ORDER BY rid LIMIT $limit"
        )
        run_params = {"project_id": project_id, "q": vertex_set_query, "limit": limit}
    else:
        cypher = (
            "MATCH (n) "
            "WHERE n.project_id = $project_id "
            "AND coalesce(n.is_placeholder, false) = false "
            "RETURN DISTINCT n.record_id AS rid ORDER BY rid LIMIT $limit"
        )
        run_params = {"project_id": project_id, "limit": limit}

    with driver.session() as session:
        result = session.run(cypher, **run_params)
        ids = [rec["rid"] for rec in result if rec.get("rid")]
    return {"ids": ids, "query_cypher": cypher}


def _query_laplacian(driver, project_id: str, params: Dict) -> Dict:
    """Compute the induced-subgraph Laplacian spectrum (ENC-FTR-088).

    Params: vertex_set_query | record_ids (selection), edge_type_filter
    (restrict adjacency to existing edge types), k (smallest eigenpairs,
    default 3), limit, normalization ('combinatorial' default | 'normalized').
    """
    # --- parameters ---
    try:
        k = int(params.get("k", LAPLACIAN_DEFAULT_K) or LAPLACIAN_DEFAULT_K)
    except (TypeError, ValueError):
        return {"error": "k must be an integer"}
    if k < 1:
        return {"error": "k must be >= 1"}

    normalization = (params.get("normalization", "combinatorial") or "combinatorial").strip().lower()
    if normalization not in {"combinatorial", "normalized"}:
        return {"error": "normalization must be 'combinatorial' or 'normalized'"}

    edge_type_filter = params.get("edge_type_filter", "")
    etypes: List[str] = []
    if edge_type_filter:
        if isinstance(edge_type_filter, list):
            etypes = [t.strip().upper() for t in edge_type_filter if str(t).strip()]
        else:
            etypes = [t.strip().upper() for t in str(edge_type_filter).split(",") if t.strip()]
        invalid = [t for t in etypes if t not in _ALLOWED_EDGE_TYPES]
        if invalid:
            return {"error": f"Invalid edge_type_filter: {invalid}. Allowed: {sorted(_ALLOWED_EDGE_TYPES)}"}

    # --- vertex set ---
    selection = _laplacian_select_vertices(driver, project_id, params)
    if "error" in selection:
        return selection
    ids: List[str] = selection["ids"]
    n = len(ids)
    if n < 2:
        return {
            "error": (
                f"Laplacian requires at least 2 vertices; vertex set resolved {n}. "
                "Broaden vertex_set_query, pass more record_ids, or raise limit."
            )
        }
    idx = {rid: i for i, rid in enumerate(ids)}

    # --- induced-subgraph edges over EXISTING edge types (no new edge types) ---
    if etypes:
        edge_cypher = (
            "MATCH (a)-[r]-(b) "
            "WHERE a.project_id = $project_id AND b.project_id = $project_id "
            "AND a.record_id IN $ids AND b.record_id IN $ids AND type(r) IN $etypes "
            "RETURN DISTINCT a.record_id AS s, b.record_id AS t"
        )
        edge_run = {"project_id": project_id, "ids": ids, "etypes": etypes}
    else:
        edge_cypher = (
            "MATCH (a)-[r]-(b) "
            "WHERE a.project_id = $project_id AND b.project_id = $project_id "
            "AND a.record_id IN $ids AND b.record_id IN $ids "
            "RETURN DISTINCT a.record_id AS s, b.record_id AS t"
        )
        edge_run = {"project_id": project_id, "ids": ids}

    pairs: set = set()  # unordered {(i, j) : i < j} — binary, undirected adjacency
    with driver.session() as session:
        result = session.run(edge_cypher, **edge_run)
        for rec in result:
            s, t = rec.get("s"), rec.get("t")
            if s is None or t is None or s == t:
                continue
            i, j = idx.get(s), idx.get(t)
            if i is None or j is None:
                continue
            pairs.add((min(i, j), max(i, j)))

    # --- sparse Laplacian + smallest-k eigenpairs via scipy.sparse.linalg.eigsh ---
    import numpy as np
    from scipy.sparse import csr_matrix, diags
    from scipy.sparse.linalg import eigsh

    rows: List[int] = []
    cols: List[int] = []
    data: List[float] = []
    for (i, j) in pairs:
        rows.extend((i, j))
        cols.extend((j, i))
        data.extend((1.0, 1.0))
    adjacency = csr_matrix((data, (rows, cols)), shape=(n, n), dtype="float64")
    adjacency.sum_duplicates()
    adjacency.sort_indices()

    degrees = np.asarray(adjacency.sum(axis=1)).ravel()

    if normalization == "normalized":
        with np.errstate(divide="ignore", invalid="ignore"):
            d_inv_sqrt = 1.0 / np.sqrt(degrees)
        d_inv_sqrt[~np.isfinite(d_inv_sqrt)] = 0.0  # isolated vertices -> 0
        d_mat = diags(d_inv_sqrt)
        laplacian = (diags(np.ones(n)) - (d_mat @ adjacency @ d_mat)).tocsr()
        formula = "L_sym = I - D^(-1/2) A D^(-1/2)"
    else:
        laplacian = (diags(degrees) - adjacency).tocsr()
        formula = "L = D - A"

    k_req = min(k, n)
    want = min(max(k_req, 2), n)  # at least 2 so the Fiedler vector (index 1) exists

    # eigsh (ARPACK) requires 0 < want < n and is unstable for tiny / near-full
    # spectra; it also rejects an all-zero operator ("Starting vector is zero"),
    # which is exactly the edgeless-subgraph case (L = 0). Fall back to dense eigh
    # for those, and on any convergence failure. The mandated
    # scipy.sparse.linalg.eigsh drives the normal path (e.g. the AC-5 10-node
    # subgraph). A deterministic start vector keeps repeated calls reproducible.
    if n <= 3 or want >= n or laplacian.nnz == 0:
        evals, evecs = np.linalg.eigh(laplacian.toarray())
        eig_method = "dense_eigh"
    else:
        try:
            v0 = np.random.default_rng(0).standard_normal(n)
            evals, evecs = eigsh(laplacian, k=want, which="SA", v0=v0)
            eig_method = "eigsh_SA"
        except Exception:
            logger.warning("[WARNING] eigsh failed; dense eigh fallback", exc_info=True)
            evals, evecs = np.linalg.eigh(laplacian.toarray())
            eig_method = "dense_eigh_fallback"

    order = np.argsort(evals)
    evals = evals[order]
    evecs = evecs[:, order]

    eigenvalues = [float(x) for x in evals[:k_req]]
    fiedler = np.asarray(evecs[:, 1]).ravel()
    fiedler_vector = [float(x) for x in fiedler]

    adjacency_csr = {
        "encoding": "base64",
        "byte_order": "little",
        "dtype": {"data": "float32", "indices": "int32", "indptr": "int32"},
        "shape": [n, n],
        "nnz": int(adjacency.nnz),
        "data_b64": _b64_array(adjacency.data, "<f4"),
        "indices_b64": _b64_array(adjacency.indices, "<i4"),
        "indptr_b64": _b64_array(adjacency.indptr, "<i4"),
    }

    lambda0 = eigenvalues[0] if eigenvalues else float("nan")
    return {
        "nodes": [],
        "edges": [],
        "paths": [],
        "vertex_map": ids,
        "adjacency_csr": adjacency_csr,
        "degrees": [float(x) for x in degrees],
        "eigenvalues": eigenvalues,
        "fiedler_vector": fiedler_vector,
        "laplacian": {
            "n": n,
            "k": k_req,
            "edge_count": len(pairs),
            "normalization": normalization,
            "formula": formula,
            "weighted": False,
            "eig_method": eig_method,
            "edge_type_filter": etypes or None,
            "reconstruct": (
                "A = scipy.sparse.csr_matrix((b64decode(data_b64,float32), "
                "b64decode(indices_b64,int32), b64decode(indptr_b64,int32)), shape); "
                "D = diag(A.sum(axis=1)); combinatorial L = D - A; "
                "normalized L_sym = D^(-1/2) (D - A) D^(-1/2)."
            ),
        },
        "summary": (
            f"Laplacian ({normalization}) over {n} vertices, {len(pairs)} edges; "
            f"{len(eigenvalues)} smallest eigenvalues (lambda0={lambda0:.6g}), "
            f"Fiedler dim {len(fiedler_vector)} via {eig_method}"
        ),
        "query_cypher": f"{selection['query_cypher']} ;; {edge_cypher}",
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
            # ENC-TSK-I07 (Dedup P3): exclude superseded duplicates from the vector
            # recall signal so a twin no longer competes with its canonical — the
            # central precision@1 fix (DOC-DF651F07D5C2 §3).
            "AND node.superseded_by IS NULL "
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
                    {{relationshipProperties: {{weight: {weight_case_sql}, {_GDS_FLOW_WEIGHT_PROPERTY}: coalesce(r.{_GDS_FLOW_WEIGHT_PROPERTY}, 1.0)}}}},
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
                        relationshipWeightProperty: $weightProp
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
                weightProp=_GDS_PPR_WEIGHT_PROPERTY,
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
        f"  reduce(s = 0.0, rel IN relationships(path) | "
        f"    s + ({weight_case_sql}) * coalesce(rel.{_GDS_FLOW_WEIGHT_PROPERTY}, 1.0)) "
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
                weightProp=_GDS_PPR_WEIGHT_PROPERTY,
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
    the project's nodes/edges with BOTH a per-type 'weight' and a flow_weight
    property read from each relationship (ENC-TSK-J03 / FTR-108 Ph3), then stamps
    a GdsProjectionMeta marker carrying the
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
                    {{relationshipProperties: {{weight: {weight_case_sql}, {_GDS_FLOW_WEIGHT_PROPERTY}: coalesce(r.{_GDS_FLOW_WEIGHT_PROPERTY}, 1.0)}}}},
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


def _handle_refresh_flow_weight(event: Dict) -> Dict[str, Any]:
    """ENC-FTR-108 Ph2 (ENC-TSK-J02) out-of-band flow_weight refresh entrypoint.
    Mirrors _handle_refresh_projection's contract: invoked by an EventBridge
    scheduled/wave-close rule or a direct Lambda invoke carrying
    action='refresh_flow_weight' (dispatched in lambda_handler below); NOT
    exposed on the public API Gateway route. Delegates to flow_weight_refresh.
    run_refresh, which reads FTR-082's existing edge_participation telemetry
    from S3 and writes the Tero current-reinforcement law onto existing
    relationships in batched, watermarked Cypher. See flow_weight_refresh.py
    for the full design (delta/mu defaults, watermark storage, idempotency).
    """
    try:
        import flow_weight_refresh as _fwr
    except Exception:
        logger.exception("[ERROR] flow_weight_refresh module unavailable")
        return {"ok": False, "error": "flow_weight_refresh module unavailable"}
    driver = _ensure_live_driver(_get_neo4j_driver())
    if driver is None:
        return {"ok": False, "error": "neo4j driver unavailable after rebuild attempt"}
    return _fwr.run_refresh(driver, _get_s3(), event)


def _handle_publish_graph_health(event: Dict) -> Dict[str, Any]:
    """ENC-TSK-K43 (B66 Ph5, gamma re-delivery of ENC-TSK-C10) out-of-band
    Fiedler lambda-2 GraphHealth metric publisher entrypoint. Mirrors
    _handle_refresh_projection's/_handle_refresh_flow_weight's contract:
    invoked by an EventBridge scheduled rule or a direct Lambda invoke
    carrying action='publish_graph_health' (dispatched in lambda_handler
    below); NOT exposed on the public API Gateway route. Delegates to
    graph_health_metric, which computes lambda2 exclusively via the existing
    FTR-088 _query_laplacian CSR/Fiedler path (ISS-465: no GDS projection —
    see graph_health_metric.py module docstring) and publishes it to the
    Enceladus/GraphHealth CloudWatch namespace.
    """
    try:
        import graph_health_metric as _ghm
    except Exception:
        logger.exception("[ERROR] graph_health_metric module unavailable")
        return {"ok": False, "error": "graph_health_metric module unavailable"}
    return _ghm.handle_publish_graph_health(
        event,
        get_driver_fn=lambda: _ensure_live_driver(_get_neo4j_driver()),
        get_cloudwatch_fn=_get_cloudwatch,
        query_laplacian_fn=_query_laplacian,
    )


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
        # ENC-TSK-I07 (Dedup P3): retire superseded records from active retrieval.
        # A superseded duplicate must not surface alongside (or compete for
        # precision@1 with) its canonical. `superseded_by` is set only on
        # superseded nodes (graph_sync NODE_PROPERTIES); audit access is via a
        # direct record fetch, not retrieval. Reversible: un-supersession clears
        # the property and the node becomes retrieval-eligible again.
        "AND n.superseded_by IS NULL "
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
                                    signal_availability, retrieval_records=None,
                                    lambda_graph=None, lambda_kw=None) -> Dict[str, Any]:
    """Assemble the AC-1 raw telemetry record (also carries the AC-10 edge
    participation list). This field set IS the ENC-FTR-108 AC-4 input contract.

    ENC-TSK-J01 (FTR-108 Ph1, design-only): edge_participation[].edge_id entries
    with retrieval_outcome == "hit" are the Ph1 source of truth for "did edge e
    participate in a successful retrieval this wave" -- the flow(e, t) signal in
    the Tero current-reinforcement contract (DOC-88A8F4835811). No flow_weight
    write path exists yet; that is Ph2, gated on an OGTM preflight not yet run.

    ENC-TSK-I98 (ENC-FTR-104 Ph1 AC-2): additive ``energy`` block carrying the
    per-record E(x) breakdown (``energy_function.build_retrieval_record``
    shape) computed for this hybrid call, plus the lambda weights used to
    compute it. ``retrieval_records``/``lambda_graph``/``lambda_kw`` all
    default to None/empty so existing callers (and the pre-I98 telemetry
    schema) are unaffected — no rename/removal of any existing field.
    """
    record = {
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
    if retrieval_records is not None or lambda_graph is not None or lambda_kw is not None:
        record["energy"] = {
            "schema": energy_function.ENERGY_SCHEMA,
            "lambda_graph": lambda_graph,
            "lambda_kw": lambda_kw,
            "records": retrieval_records or [],
        }
    return record


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


def _emit_stigmergic_trace(record: Dict[str, Any]) -> None:
    """ENC-FTR-109 / ENC-TSK-K05 sink. Persist one trace to DynamoDB when configured;
    otherwise emit a structured CloudWatch line. Never raises into the request path."""
    try:
        line = json.dumps(record, default=str)
        if STIGMERGIC_TRACE_TABLE:
            try:
                import stigmergic_trace

                stigmergic_trace.emit_stigmergic_trace(
                    _get_dynamodb(), STIGMERGIC_TRACE_TABLE, record,
                )
                return
            except Exception as exc:
                logger.warning(
                    "[WARNING] stigmergic trace DDB put failed (%s); CloudWatch fallback",
                    exc,
                )
        logger.info("STIGMERGIC_TRACE %s", line)
    except Exception:
        logger.exception("[ERROR] stigmergic trace emit failed (suppressed)")


def _session_id_from_params(params: Dict[str, Any]) -> str:
    for key in ("session_id", "agent_session_id", "wave_id"):
        value = str(params.get(key) or "").strip()
        if value:
            return value
    return "unassigned"


def _maybe_emit_stigmergic_trace(
    *,
    project_id: str,
    params: Dict[str, Any],
    event_type: str,
    result: Dict[str, Any],
    outcome_signal: Dict[str, Any],
) -> None:
    """Build and emit one stigmergic trace record (telemetry-only)."""
    try:
        import stigmergic_trace

        record = stigmergic_trace.build_trace_record(
            project_id=project_id,
            session_id=_session_id_from_params(params),
            event_type=event_type,
            record_id_path=stigmergic_trace.record_id_path_from_graph_result(result),
            outcome_signal=outcome_signal,
        )
        _emit_stigmergic_trace(record)
    except Exception:
        logger.exception("[ERROR] stigmergic trace build failed (suppressed)")


def _query_hybrid(driver, project_id: str, params: Dict) -> Dict:
    """Phase 1 hybrid retrieval: vector + graph + keyword fused via RRF.

    Query parameters:
      query            Text query (required for vector + keyword signals).
      anchor_record_id Graph anchor node (required for graph signal).
      record_type      Optional filter (task/issue/feature/plan/lesson/document).
      top_n            Final result count (default 20, max 50).
      include_below_threshold  When "true", includes Lessons below T3.
      include_energy   When "true", each node carries energy_score +
                       energy_breakdown (FTR-104 Ph3 / ENC-TSK-J52). Default off.

    Response contract:
      {
        "nodes":             [...ordered by final score (fused RRF score +
                              ENC-TSK-I92 dispersion/corroboration bonus)...],
        "edges":             [],
        "paths":             [],
        "summary":           "Hybrid: N nodes (vector=V, graph=G, keyword=K)",
        "query_cypher":      "<hybrid-multi-query marker>",
        "signal_availability": {vector: bool, graph: bool, keyword: bool},
        "graph_algorithm":   "gds_pagerank" | "cypher_fallback" | "unavailable",
        "rrf_k":             60,
        "embedding_coverage_sample": {covered: N, total_ranked: N},
        "per_node_fusion":   {record_id: {fused_rank, per_signal_ranks, ...,
                              k_corr, b_corr, final_score, final_rank}},
        "corroboration_weber_k": 0.3,
      }

    ENC-TSK-I92 (ENC-FTR-110 Ph1): each candidate's pure-RRF `fused_score`
    (vector/graph/keyword/PPR fused via `_rrf_fuse`) is augmented with a fifth,
    additive corroboration bonus B_corr — see the `corroboration` module and
    the "ENC-TSK-I92" banner below — to produce `final_score`, which is what
    `nodes`/`per_node_fusion` are actually ordered by. `fused_score`/
    `fused_rank` remain the unmodified pure-RRF values throughout.
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
    include_energy = str(params.get("include_energy", "")).lower() == "true"

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

    # ENC-TSK-I98 (ENC-FTR-104 Ph1 AC-2): resolve the energy-function lambda
    # weights once per call (not once per candidate) so a single hybrid call
    # never re-probes AppConfig more than once.
    energy_lambda_graph, energy_lambda_kw = energy_function.load_lambda_weights()

    # ENC-TSK-I92 (ENC-FTR-110 Ph1): resolve the corroboration Weber_k bonus
    # weight once per call, same one-AppConfig-probe-per-call discipline as
    # the energy lambda weights above.
    corroboration_weber_k = corroboration.load_weber_k()

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

    # ---- Keyword signal (ENC-TSK-L43: OpenSearch primary, Neo4j fallback) --
    keyword_ranks: List[Dict[str, Any]] = []
    keyword_available = False
    keyword_source = "unavailable"
    facets: Dict[str, Dict[str, int]] = {}
    facets_source: Optional[str] = None
    if query_text:
        os_ranks, os_facets, os_err = opensearch_keyword.hybrid_keyword_ranks(
            project_id,
            query_text,
            top_n=HYBRID_SIGNAL_TOP_N,
            record_type_filter=record_type_filter,
        )
        if os_err is None:
            keyword_ranks = os_ranks
            keyword_available = bool(keyword_ranks)
            keyword_source = "opensearch"
            facets = os_facets
            facets_source = "opensearch"
        else:
            logger.warning(
                "[WARNING] OpenSearch keyword arm unavailable (%s) — Neo4j fallback",
                os_err,
            )
            keyword_ranks = _hybrid_keyword_ranks(
                driver,
                project_id,
                query_text,
                top_n=HYBRID_SIGNAL_TOP_N,
                record_type_filter=record_type_filter,
            )
            keyword_available = bool(keyword_ranks)
            keyword_source = "neo4j_fallback"
            fallback_facets, fb_err = opensearch_keyword.fetch_feed_corpus_facets(
                project_id=project_id,
                query_text=query_text,
                record_type_filter=record_type_filter,
            )
            if fallback_facets:
                facets = fallback_facets
                facets_source = "feed_corpus"
            elif fb_err:
                logger.warning("[WARNING] feed/corpus facet fallback failed: %s", fb_err)

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
        # ENC-TSK-I98: lambda weights are still logged even with zero candidates
        # so the AppConfig-resolved values used for this call are auditable.
        _emit_pathway_telemetry(_build_pathway_telemetry_record(
            wave_id=wave_id, intent_signature=intent_signature, project_id=project_id,
            anchor_record_id=anchor_record_id, node_sequence=[], edges_traversed=[],
            edge_participation=[], result_count=0, graph_algorithm=graph_algorithm,
            signal_availability=_sig_avail, retrieval_records=[],
            lambda_graph=energy_lambda_graph, lambda_kw=energy_lambda_kw,
        ))
        _maybe_emit_stigmergic_trace(
            project_id=project_id,
            params=params,
            event_type="retrieval",
            result={"pathway": {"node_sequence": []}, "nodes": []},
            outcome_signal={
                "result_count": 0,
                "graph_algorithm": graph_algorithm,
                "signal_availability": _sig_avail,
            },
        )
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
            # ENC-TSK-I98 (ENC-FTR-104 Ph1): per-retrieval energy telemetry —
            # empty when no candidates were fused, but the lambda weights used
            # for this call are still surfaced for observability.
            "retrieval_records": [],
            "energy_lambda_weights": {
                "lambda_graph": energy_lambda_graph, "lambda_kw": energy_lambda_kw,
            },
            # ENC-TSK-I92 (ENC-FTR-110 Ph1): the Weber_k bonus weight used for
            # this call, surfaced even with zero candidates for observability
            # parity with energy_lambda_weights above.
            "corroboration_weber_k": corroboration_weber_k,
            "facets": facets,
            "facets_source": facets_source,
            "keyword_source": keyword_source,
        }

    fused = _rrf_fuse(signals, k=RRF_K)
    # Cap to top_n + generous buffer so FSRS-6 T3 suppression doesn't starve results.
    fetch_size = min(len(fused), top_n * 3)
    top_fused = fused[:fetch_size]

    # ---- Resolve full node payloads ---------------------------------------
    top_rids = [item["record_id"] for item in top_fused]
    node_by_rid = _fetch_nodes_by_record_ids(driver, project_id, top_rids)

    # ENC-TSK-I98 (ENC-FTR-104 Ph1 AC-1/AC-2): per-candidate energy function
    # E(x) = E_vector + lambda_graph*E_PPR + lambda_kw*E_keyword, computed from
    # this call's own vector/graph/keyword signals — no new signal sources.
    # graph_score/keyword_score are normalized call-relative against the top
    # score in their respective ranked signal list (vector is already [0,1]
    # cosine similarity, so it needs no re-normalization). graph_algorithm is
    # threaded through unchanged so a unit test can assert E_PPR was sourced
    # from the FTR-101 standing AGA projection ("gds_pagerank") rather than the
    # "cypher_fallback" proxy.
    _max_graph_score = graph_ranks[0]["score"] if graph_ranks else None
    _max_keyword_score = keyword_ranks[0]["score"] if keyword_ranks else None
    energy_by_rid: Dict[str, Dict[str, Any]] = {}
    for item in top_fused:
        rid = item["record_id"]
        sig_scores = item.get("per_signal_scores") or {}
        energy_by_rid[rid] = energy_function.compute_retrieval_energy(
            vector_score=sig_scores.get("vector"),
            graph_score=sig_scores.get("graph"),
            keyword_score=sig_scores.get("keyword"),
            max_graph_score=_max_graph_score,
            max_keyword_score=_max_keyword_score,
            graph_algorithm=graph_algorithm,
            lambda_graph=energy_lambda_graph,
            lambda_kw=energy_lambda_kw,
        )

    # ENC-TSK-I92 (ENC-FTR-110 Ph1): dispersion/corroboration Weber-law bonus —
    # a fifth scoring signal, layered on top of (not folded into) the 4-signal
    # RRF sum above. For each candidate, count corroborators: other candidates
    # in this SAME result set that are similar enough to it (cosine similarity
    # >= corroboration.DEFAULT_SIMILARITY_THRESHOLD) AND pairwise dispersed
    # from each other (cosine distance >= corroboration.DISPERSION_MIN_
    # DISTANCE), so a cluster of near-duplicate records never counts as more
    # than one independent corroborator (the "dispersion constraint" —
    # corroboration.count_corroborators). B_corr is a bonus, not an RRF term:
    # it is added on top of each candidate's already-fused RRF fused_score to
    # produce final_score, and is never folded into _rrf_fuse's 1/(k+rank) sum
    # — that sum is exact-value-asserted by test_hybrid_retrieval.py and must
    # stay pure RRF. Degrades to a no-op (B_corr == 0.0 for everyone, final_
    # score == fused_score) when no candidate in this call carries a usable
    # embedding, so this is fully backward compatible with callers/tests that
    # never populate the embedding property.
    embeddings_by_rid = {
        rid: node_by_rid[rid].get(_EMBEDDING_PROPERTY)
        for rid in top_rids
        if node_by_rid.get(rid) and node_by_rid[rid].get(_EMBEDDING_PROPERTY)
    }
    corroboration_counts = corroboration.compute_corroboration_counts(embeddings_by_rid)
    corroboration_bonuses = corroboration.compute_bonuses(
        corroboration_counts, weber_k=corroboration_weber_k,
    )
    for item in top_fused:
        rid = item["record_id"]
        bonus = corroboration_bonuses.get(rid)
        item["k_corr"] = bonus["k_corr"] if bonus else 0
        item["b_corr"] = bonus["b_corr"] if bonus else 0.0
        item["final_score"] = item["fused_score"] + item["b_corr"]

    # Re-rank by final_score (RRF fused_score + corroboration bonus), NOT
    # fused_score alone, so a candidate several genuinely-distinct records
    # independently corroborate can outrank a single high-RRF candidate with
    # zero independent corroboration (ENC-FTR-110 AC-4 — the spurious-
    # attractor hedge this signal exists to provide). fused_rank/fused_score
    # above are left untouched (the pure-RRF values); only presentation order
    # — and the node-level final_rank/final_score below — reflect the bonus.
    # Python's sort is stable, so when every candidate's b_corr is 0.0 (no
    # embeddings / no corroboration anywhere in this call) the RRF order from
    # _rrf_fuse is preserved exactly.
    top_fused.sort(key=lambda d: d["final_score"], reverse=True)
    for idx, item in enumerate(top_fused, start=1):
        item["final_rank"] = idx

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
        energy_payload = energy_by_rid[rid]
        if include_energy:
            node["energy_score"] = energy_payload["retrieval_energy"]
            node["energy_breakdown"] = {
                "E_vector": energy_payload["E_vector"],
                "E_PPR": energy_payload["E_PPR"],
                "E_keyword": energy_payload["E_keyword"],
                "lambda_graph": energy_payload["lambda_graph"],
                "lambda_kw": energy_payload["lambda_kw"],
                "graph_algorithm": energy_payload["graph_algorithm"],
            }
            node["_retrieval_energy"] = energy_payload["retrieval_energy"]
        # ENC-TSK-I92 (ENC-FTR-110 Ph1): corroboration count + Weber bonus +
        # the bonus-adjusted final_score/final_rank (see banner above).
        node["_corroboration_count"] = item["k_corr"]
        node["_b_corr"] = item["b_corr"]
        node["_final_score"] = item["final_score"]
        node["_final_rank"] = item["final_rank"]
        if node.get(_EMBEDDING_PROPERTY):
            embedding_covered += 1
            # Drop the 256-float blob from the response to keep payloads small.
            node = {k: v for k, v in node.items() if k != _EMBEDDING_PROPERTY}
        per_node_fusion[rid] = {
            "fused_rank": item["fused_rank"],
            "fused_score": item["fused_score"],
            "per_signal_ranks": item["per_signal_ranks"],
            "k_corr": item["k_corr"],
            "b_corr": item["b_corr"],
            "final_score": item["final_score"],
            "final_rank": item["final_rank"],
        }
        if include_energy:
            per_node_fusion[rid]["retrieval_energy"] = energy_payload["retrieval_energy"]
            per_node_fusion[rid]["energy_breakdown"] = node.get("energy_breakdown")
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

    # ENC-TSK-I98 (ENC-FTR-104 Ph1 AC-1/AC-5): the wave-close `retrieval_records`
    # shape consumed by drift_telemetry.compute_spurious_attractor_rate
    # (ENC-FTR-105 AC-7 / ENC-TSK-I91) — one entry per FINAL returned node
    # (post T3-filter/top_n trim), each carrying retrieval_energy/
    # avg_retrieval_energy plus the full component breakdown. graph_query_api
    # does not itself assemble/dispatch the wave-close event (no caller in
    # this package builds the multi-call wave aggregate and invokes
    # action="wave_close_drift" — that orchestration lives outside this
    # Lambda); this is the producer-side payload such a caller forwards
    # verbatim into retrieval_records.
    retrieval_records = [
        energy_function.build_retrieval_record(rid, energy_by_rid[rid])
        for rid in result_rids if rid in energy_by_rid
    ]

    # AC-1: emit the raw pathway-telemetry record (S3 append log when configured,
    # else CloudWatch fallback). Carries the AC-10 edge_participation list.
    # ENC-TSK-I98: additively carries the per-record energy breakdown (AC-2)
    # alongside everything FTR-082 already logs here.
    _emit_pathway_telemetry(_build_pathway_telemetry_record(
        wave_id=wave_id, intent_signature=intent_signature, project_id=project_id,
        anchor_record_id=anchor_record_id, node_sequence=node_sequence,
        edges_traversed=edges_traversed, edge_participation=edge_participation,
        result_count=len(nodes), graph_algorithm=graph_algorithm,
        signal_availability=_sig_avail, retrieval_records=retrieval_records,
        lambda_graph=energy_lambda_graph, lambda_kw=energy_lambda_kw,
    ))
    _maybe_emit_stigmergic_trace(
        project_id=project_id,
        params=params,
        event_type="retrieval",
        result={
            "pathway": {"node_sequence": node_sequence},
            "nodes": nodes,
            "edges": edges_traversed,
        },
        outcome_signal={
            "result_count": len(nodes),
            "graph_algorithm": graph_algorithm,
            "signal_availability": _sig_avail,
        },
    )

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
        # ENC-TSK-I98 (ENC-FTR-104 Ph1): per-retrieval energy telemetry, ready
        # to be forwarded as `retrieval_records` on a wave-close event.
        "retrieval_records": retrieval_records,
        "energy_lambda_weights": {
            "lambda_graph": energy_lambda_graph, "lambda_kw": energy_lambda_kw,
        },
        # ENC-TSK-I92 (ENC-FTR-110 Ph1): Weber_k bonus weight used for this
        # call's corroboration bonus (see per_node_fusion[*].b_corr/k_corr and
        # nodes[*]._b_corr/_corroboration_count/_final_score/_final_rank).
        "corroboration_weber_k": corroboration_weber_k,
        "facets": facets,
        "facets_source": facets_source,
        "keyword_source": keyword_source,
    }
# without forcing an import at module load time (deploy packages the helper at
# the top level, so the import is deferred to _compute_query_embedding).
_EMBEDDING_PROPERTY = "embedding"


def _query_adjacency(driver, project_id: str, params: Dict) -> Dict:
    """Return the project-scoped undirected simple-graph adjacency (ENC-TSK-I88).

    Read-only structural export for offline analytics — specifically the
    comp-percolation-monitor nightly Lambda (ENC-FTR-085), which needs the live
    degree sequence (Molloy-Reed) and an edge list (Monte Carlo site-percolation
    sweep). It matches every edge label without filtering, introduces NO new edge
    type, and performs no writes, so OGTM (ENC-FTR-066) is N/A — mirroring the
    vector_read exemption (graph_query_api.vector_read).

    Project ('Project') container nodes and placeholder edge-target stubs
    (is_placeholder, ENC-TSK-E06) are excluded so degree statistics reflect only
    real governed records. Each undirected pair is emitted once (a.record_id <
    b.record_id also drops self-loops), deduplicated to a simple graph across
    multiple parallel edge types. Pagination is via offset/limit over a stable
    (s, t) ordering; node_count/edge_count totals are returned on the first page
    (offset == 0) so the caller can size the corpus before streaming.

    The first page also carries ``spurious_attractor_rate`` (ENC-FTR-105 AC-7 /
    ENC-TSK-I91) — a best-effort mean over the project's most recent
    drift-telemetry records (see ``_recent_spurious_attractor_rate``), null when
    unavailable. This is a read of an existing telemetry sink, not a new edge
    type or graph write, so it does not change the OGTM analysis above.
    """
    try:
        offset = int(params.get("offset", 0) or 0)
    except (TypeError, ValueError):
        return {"error": "offset must be an integer"}
    try:
        limit = int(params.get("limit", ADJACENCY_DEFAULT_LIMIT) or ADJACENCY_DEFAULT_LIMIT)
    except (TypeError, ValueError):
        return {"error": "limit must be an integer"}
    if offset < 0:
        return {"error": "offset must be >= 0"}
    if limit < 1 or limit > ADJACENCY_MAX_LIMIT:
        return {"error": f"limit must be between 1 and {ADJACENCY_MAX_LIMIT}"}

    node_filter = (
        "n.project_id = $project_id "
        "AND NOT 'Project' IN labels(n) "
        "AND coalesce(n.is_placeholder, false) = false "
        "AND n.record_id IS NOT NULL"
    )
    edge_match = (
        "MATCH (a)-[r]-(b) "
        "WHERE a.project_id = $project_id AND b.project_id = $project_id "
        "AND NOT 'Project' IN labels(a) AND NOT 'Project' IN labels(b) "
        "AND coalesce(a.is_placeholder, false) = false "
        "AND coalesce(b.is_placeholder, false) = false "
        "AND a.record_id IS NOT NULL AND b.record_id IS NOT NULL "
        "AND a.record_id < b.record_id "
    )

    edges: List[Dict[str, str]] = []
    node_count: Optional[int] = None
    edge_count: Optional[int] = None
    with driver.session() as session:
        if offset == 0:
            node_count = int(
                session.run(
                    f"MATCH (n) WHERE {node_filter} RETURN count(n) AS c"
                ).single()["c"]
            )
            edge_count = int(
                session.run(
                    f"{edge_match} "
                    "RETURN count(DISTINCT [a.record_id, b.record_id]) AS c"
                ).single()["c"]
            )
        page = session.run(
            f"{edge_match} "
            "WITH DISTINCT a.record_id AS s, b.record_id AS t "
            "ORDER BY s, t "
            "SKIP $offset LIMIT $limit "
            "RETURN s, t",
            project_id=project_id,
            offset=offset,
            limit=limit,
        )
        for rec in page:
            edges.append({"s": rec["s"], "t": rec["t"]})

    returned = len(edges)
    has_more = returned == limit
    result: Dict[str, Any] = {
        "nodes": [],
        "edges": edges,
        "paths": [],
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "has_more": has_more,
        "next_offset": (offset + returned) if has_more else None,
        "summary": f"Adjacency page for {project_id}: {returned} edges (offset {offset}, has_more={has_more})",
        "query_cypher": "adjacency",
    }
    if node_count is not None:
        result["node_count"] = node_count
        result["edge_count"] = edge_count
        result["spurious_attractor_rate"] = _recent_spurious_attractor_rate(project_id)
        try:
            import flow_weight_entropy as _fwe
            with driver.session() as entropy_session:
                entropy_info = _fwe.compute_from_session(entropy_session, project_id)
            result.update(entropy_info)
        except Exception:  # noqa: BLE001 — enrichment must never break adjacency reads
            logger.warning(
                "[WARNING] flow_weight_entropy enrichment failed project_id=%s",
                project_id,
                exc_info=True,
            )
    return result
# ---------------------------------------------------------------------------
# ENC-FTR-095 / ENC-TSK-I90: Sheaf Laplacian H1 inconsistency detection
# ---------------------------------------------------------------------------

def _query_sheaf_cohomology(driver, project_id: str, params: Dict) -> Dict:
    """Compute the first sheaf cohomology dimension over a tracker subgraph.

    Reads the existing governed graph (nodes + edges) via Cypher and builds a
    cellular sheaf with R^d stalks (d = embedding dim) and identity restriction
    maps on consistent edges; contradictory-status edges zero their restriction
    maps, producing first cohomology. No writes, no new edge types (OGTM-safe).

    Optional ``vertex_set_query`` restricts the computation to the connected
    subgraph around an anchor record_id; otherwise the whole project graph is
    used (bounded by MAX_RESULTS nodes).
    """
    if _sheaf_cohomology is None:
        return {"error": "sheaf_cohomology module unavailable"}

    vertex_set_query = str(params.get("vertex_set_query", "") or "").strip()

    node_projection = (
        "RETURN n.record_id AS record_id, n.status AS status, "
        "CASE WHEN n.embedding IS NULL THEN 0 ELSE size(n.embedding) END AS embedding_dim "
        "LIMIT $limit"
    )
    if vertex_set_query:
        node_cypher = (
            "MATCH (start) WHERE start.project_id = $project_id "
            "AND start.record_id = $anchor "
            "OPTIONAL MATCH (start)-[*1..3]-(m) WHERE m.project_id = $project_id "
            "WITH collect(DISTINCT start) + collect(DISTINCT m) AS ns "
            "UNWIND ns AS n WITH DISTINCT n "
            "WHERE n IS NOT NULL AND NOT 'Project' IN labels(n) "
            + node_projection
        )
        node_params: Dict[str, Any] = {
            "project_id": project_id,
            "anchor": vertex_set_query.upper(),
            "limit": MAX_RESULTS,
        }
    else:
        node_cypher = (
            "MATCH (n) WHERE n.project_id = $project_id "
            "AND NOT 'Project' IN labels(n) AND n.record_id IS NOT NULL "
            + node_projection
        )
        node_params = {"project_id": project_id, "limit": MAX_RESULTS}

    nodes: List[Dict[str, Any]] = []
    node_ids: List[str] = []
    embedding_dims: List[int] = []
    with driver.session() as session:
        for rec in session.run(node_cypher, **node_params):
            rid = rec.get("record_id")
            if not rid:
                continue
            emb_dim = int(rec.get("embedding_dim") or 0)
            nodes.append({"record_id": rid, "status": rec.get("status") or ""})
            node_ids.append(rid)
            if emb_dim > 0:
                embedding_dims.append(emb_dim)

        edges: List[Dict[str, Any]] = []
        if node_ids:
            edge_cypher = (
                "MATCH (a)-[r]->(b) "
                "WHERE a.project_id = $project_id AND b.project_id = $project_id "
                "AND a.record_id IN $ids AND b.record_id IN $ids "
                "RETURN startNode(r).record_id AS start, endNode(r).record_id AS end, "
                "type(r) AS type LIMIT $limit"
            )
            for rec in session.run(
                edge_cypher, project_id=project_id, ids=node_ids, limit=MAX_RESULTS * 10
            ):
                edges.append({
                    "start": rec.get("start"),
                    "end": rec.get("end"),
                    "type": rec.get("type"),
                })

    embedding_dim = max(embedding_dims) if embedding_dims else 1
    result = _sheaf_cohomology.compute_sheaf_h1(nodes, edges, embedding_dim=embedding_dim)

    return {
        "nodes": [],
        "edges": [],
        "paths": [],
        "h1_dim": result["h1_dim"],
        "h1_structural": result["h1_structural"],
        "betti_1": result["betti_1"],
        "embedding_dim": result["embedding_dim"],
        "node_count": result["node_count"],
        "edge_count": result["edge_count"],
        "incidence_rank": result["incidence_rank"],
        "inconsistency_nodes": result["inconsistency_nodes"],
        "inconsistency_edges": result["inconsistency_edges"],
        "computation_ms": result["computation_ms"],
        "summary": (
            f"Sheaf H1: dim={result['h1_dim']} (structural={result['h1_structural']}, "
            f"stalk_dim={result['embedding_dim']}) over {result['node_count']} nodes / "
            f"{result['edge_count']} edges; {len(result['inconsistency_nodes'])} inconsistency node(s)"
        ),
        "query_cypher": node_cypher,
    }
def _query_dedup_convergence(driver, project_id: str, params: Dict) -> Dict:
    """ENC-TSK-I10 (Dedup P6): on-demand duplicate-dedup convergence snapshot
    (DOC-DF651F07D5C2 §10). Read-only; mutation-free.

    Computes the four graph-derived signals — duplicate-pair stock, the
    precision@1 recovery proxy (vs the 0.3727 baseline / ~0.8242 ceiling), new
    duplicate flow per window, and the same-type duplicate graph's LCC
    (percolation → 1) — over the live Neo4j projection. The production
    auto-merge walk-back rate is layered on by the scheduled probe
    (graph_health_metrics) from the audit-feed counters; it is not derivable
    from the graph projection (supersession provenance is not a node property),
    so this read surface returns the graph signals only.

    Query params (all optional): cosine_threshold, flow_window_days,
    vector_top_k.
    """
    def _flt(name: str, default: float) -> float:
        try:
            return float(params.get(name, default))
        except (TypeError, ValueError):
            return default

    def _intp(name: str, default: int) -> int:
        try:
            return max(1, int(params.get(name, default)))
        except (TypeError, ValueError):
            return default

    cosine_threshold = _flt("cosine_threshold", dedup_convergence.DEFAULT_COSINE_THRESHOLD)
    if not (0.0 <= cosine_threshold <= 1.0):
        return {"error": "cosine_threshold must be in [0, 1]."}
    flow_window_days = _flt("flow_window_days", float(dedup_convergence.DEFAULT_FLOW_WINDOW_DAYS))
    vector_top_k = _intp("vector_top_k", dedup_convergence.DEFAULT_VECTOR_TOP_K)

    signals = dedup_convergence.compute_graph_signals(
        driver,
        project_id,
        cosine_threshold=cosine_threshold,
        flow_window_days=flow_window_days,
        label_vector_indexes=LABEL_VECTOR_INDEXES,
        vector_top_k=vector_top_k,
    )
    # _handle_search audits node/edge/path counts; keep those keys present.
    return {"nodes": [], "edges": [], "paths": [], "convergence": signals}


SEARCH_HANDLERS = {
    "traversal": _query_traversal,
    "neighbors": _query_neighbors,
    "path": _query_path,
    "keyword": _query_keyword,
    "hybrid": _query_hybrid,
    "adjacency": _query_adjacency,
        "sheaf_cohomology": _query_sheaf_cohomology,
    "dedup_convergence": _query_dedup_convergence,
    "laplacian": _query_laplacian,
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

    if search_type != "hybrid":
        _maybe_emit_stigmergic_trace(
            project_id=project_id,
            params=qs,
            event_type="traversal",
            result=result,
            outcome_signal={
                "search_type": search_type,
                "node_count": len(result.get("nodes", [])),
                "edge_count": len(result.get("edges", [])),
                "path_count": len(result.get("paths", [])),
                "duration_ms": duration_ms,
            },
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
        "facets",
        "facets_source",
        "keyword_source",
        # ENC-TSK-I88: adjacency export pagination + corpus-size fields.
        "node_count",
        "edge_count",
        "offset",
        "limit",
        "returned",
        "has_more",
        "next_offset",
                # ENC-FTR-095 / ENC-TSK-I90: sheaf_cohomology observability fields.
        "h1_dim",
        "h1_structural",
        "betti_1",
        "embedding_dim",
        "node_count",
        "edge_count",
        "incidence_rank",
        "inconsistency_nodes",
        "inconsistency_edges",
        "computation_ms",
        "convergence",
        # ENC-TSK-I81 / ENC-FTR-088: graph_laplacian response fields.
        "vertex_map",
        "adjacency_csr",
        "degrees",
        "eigenvalues",
        "fiedler_vector",
        "laplacian",
    ):
        if hybrid_key in result:
            response_body[hybrid_key] = result[hybrid_key]
    return _response(200, response_body)


# ---------------------------------------------------------------------------
# ENC-FTR-089 / ENC-TSK-I89 — raw-embedding egress (admin-scoped)
# ---------------------------------------------------------------------------

def _extract_egress_token(headers: Dict[str, str]) -> str:
    """Pull a JWT from the Authorization bearer header or the auth cookies."""
    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[len("Bearer "):].strip()
    cookie = headers.get("cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        for cookie_name in ("enceladus_id_token=", "enceladus_access_token="):
            if part.startswith(cookie_name):
                return part[len(cookie_name):].strip()
    return ""


def _decode_jwt_claims(token: str) -> Dict[str, Any]:
    """Best-effort decode of a JWT payload segment.

    Signature verification is delegated to the API Gateway JWT authorizer
    (ENC-FTR-074 Ph2 / ENC-TSK-I80) — this only reads the governed tier claim
    for egress gating on the gamma research plane, mirroring the existing
    in-Lambda auth posture where cryptographic validation is performed at the
    edge. Returns an empty dict on any malformed input.
    """
    try:
        segments = token.split(".")
        if len(segments) < 2:
            return {}
        import base64

        payload = segments[1]
        payload += "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        claims = json.loads(decoded.decode("utf-8"))
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _egress_jwt_claims(event: Dict) -> Dict[str, Any]:
    """Resolve verified JWT claims, preferring authorizer-injected context."""
    request_context = event.get("requestContext") or {}
    authorizer = request_context.get("authorizer") or {}
    jwt_context = authorizer.get("jwt") or {}
    claims = jwt_context.get("claims")
    if isinstance(claims, dict) and claims:
        return claims
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = _extract_egress_token(headers)
    if not token:
        return {}
    return _decode_jwt_claims(token)


def _authorize_embedding_egress(event: Dict) -> Optional[str]:
    """Authorize raw-embedding egress. Returns None if allowed, else a reason.

    Accepted principals:
      - the internal service key (X-Coordination-Internal-Key), used by the MCP
        server's governed forward path;
      - Cognito tokens carrying enc:agent_tier == 'admin' OR the io-dev-admin
        group.
    Standard / elevated / observe agent tokens (and anonymous callers) are
    rejected so the caller can be answered with HTTP 403 (ENC-FTR-089 AC-2).
    """
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    internal_key = headers.get("x-coordination-internal-key", "")
    if internal_key and COORDINATION_INTERNAL_API_KEY:
        valid_keys = {COORDINATION_INTERNAL_API_KEY}
        if COORDINATION_INTERNAL_API_KEY_PREVIOUS:
            valid_keys.add(COORDINATION_INTERNAL_API_KEY_PREVIOUS)
        if internal_key.strip() in valid_keys:
            return None

    claims = _egress_jwt_claims(event)
    tier = str(claims.get("enc:agent_tier") or "").strip().lower()
    if tier == _EGRESS_ADMIN_AGENT_TIER:
        return None

    raw_groups = claims.get("cognito:groups") or []
    if isinstance(raw_groups, str):
        raw_groups = raw_groups.replace(",", " ").split()
    groups = {str(g).strip().lower() for g in raw_groups if str(g).strip()}
    if _EGRESS_ADMIN_COGNITO_GROUP in groups:
        return None

    return (
        "Raw-embedding egress requires the internal service key or an "
        "admin-tier (io-dev-admin) Cognito token."
    )


def _parse_egress_record_ids(event: Dict) -> List[str]:
    """Parse and de-duplicate record_ids from query params (csv or multiValue)."""
    qs = event.get("queryStringParameters") or {}
    multi_qs = event.get("multiValueQueryStringParameters") or {}

    raw_ids: List[str] = []
    if isinstance(multi_qs.get("record_ids"), list):
        for value in multi_qs["record_ids"]:
            raw_ids.extend(str(value).split(","))
    else:
        raw_ids.extend(str(qs.get("record_ids", "")).split(","))
    # Tolerate the singular form for ergonomic single-record calls.
    if not any(r.strip() for r in raw_ids) and qs.get("record_id"):
        raw_ids = str(qs.get("record_id")).split(",")

    seen: set = set()
    ordered: List[str] = []
    for candidate in raw_ids:
        record_id = candidate.strip()
        if record_id and record_id not in seen:
            seen.add(record_id)
            ordered.append(record_id)
    return ordered


def _handle_embeddings_for(event: Dict) -> Dict:
    """Handle GET /api/v1/tracker/graphsearch?search_type=embeddings_for.

    ENC-FTR-089 / ENC-TSK-I89. Returns the stored Titan V2 embedding vector
    (256-dim float32, L2-normalized) for each requested record_id. Operates
    over the existing `embedding` node property written by graph_sync — no new
    edge types or graph nodes are introduced (OGTM AC-4).
    """
    auth_failure = _authorize_embedding_egress(event)
    if auth_failure is not None:
        return _error(403, auth_failure, code="PERMISSION_DENIED")

    qs = event.get("queryStringParameters") or {}
    project_id = qs.get("project_id", "")
    if not project_id:
        return _error(400, "project_id query parameter required")

    record_ids = _parse_egress_record_ids(event)
    if not record_ids:
        return _error(400, "record_ids query parameter required (comma-separated record IDs)")
    if len(record_ids) > MAX_EMBEDDING_EGRESS_RECORD_IDS:
        return _error(
            400,
            f"record_ids exceeds the maximum of {MAX_EMBEDDING_EGRESS_RECORD_IDS} per request",
        )

    driver = _ensure_live_driver(_get_neo4j_driver())
    if driver is None:
        return _error(503, "Graph index temporarily unavailable. Use tracker_list for equivalent queries.",
                      code="GRAPH_UNAVAILABLE", retryable=True)

    cypher = (
        "MATCH (n) WHERE n.project_id = $project_id AND n.record_id IN $record_ids "
        f"RETURN n.record_id AS record_id, n.`{_EMBEDDING_PROPERTY}` AS embedding, "
        "labels(n) AS labels"
    )

    start = time.time()
    found: Dict[str, Dict[str, Any]] = {}
    try:
        with driver.session() as session:
            result = session.run(cypher, project_id=project_id, record_ids=record_ids)
            for record in result:
                rid = record["record_id"]
                if rid is None:
                    continue
                embedding = record["embedding"]
                # A record_id should resolve to one node; if a stale duplicate
                # exists, keep the first row that carries a usable vector.
                existing = found.get(rid)
                if existing is not None and existing.get("embedding") is not None:
                    continue
                found[rid] = {
                    "embedding": list(embedding) if embedding is not None else None,
                    "labels": sorted(record["labels"]) if record["labels"] else [],
                }
    except Exception:
        logger.exception("[ERROR] embeddings_for query failed: project_id=%s", project_id)
        return _error(503, "Graph index temporarily unavailable. Use tracker_list for equivalent queries.",
                      code="GRAPH_UNAVAILABLE", retryable=True)

    duration_ms = int((time.time() - start) * 1000)

    embeddings: List[Dict[str, Any]] = []
    missing: List[str] = []
    for rid in record_ids:
        entry = found.get(rid)
        vector = entry.get("embedding") if entry else None
        if isinstance(vector, list) and len(vector) == EMBEDDING_EGRESS_DIMENSIONS:
            embeddings.append({
                "record_id": rid,
                "embedding": vector,
                "dimension": len(vector),
                "labels": entry.get("labels", []),
            })
        else:
            missing.append(rid)

    # Row-aligned (N x 256) matrix of only the resolved vectors so a client can
    # call np.mean(matrix, axis=0) directly for the demand-centroid / Fréchet
    # barycenter approximation (ENC-FTR-089 AC-3).
    matrix = [item["embedding"] for item in embeddings]

    logger.info(
        json.dumps({
            "event": "embeddings_for_query",
            "project_id": project_id,
            "requested_count": len(record_ids),
            "returned_count": len(embeddings),
            "missing_count": len(missing),
            "duration_ms": duration_ms,
        })
    )

    return _response(200, {
        "success": True,
        "model_id": EMBEDDING_EGRESS_MODEL_ID,
        "dimension": EMBEDDING_EGRESS_DIMENSIONS,
        "normalize": True,
        "requested_count": len(record_ids),
        "returned_count": len(embeddings),
        "embeddings": embeddings,
        "matrix": matrix,
        "missing": missing,
        "duration_ms": duration_ms,
        # ENC-FTR-089 AC-3: response-schema documentation for centroid use.
        "response_schema": {
            "embeddings": "Array of {record_id, embedding: float[256], dimension, labels}; "
                          "row-order matches the requested record_ids minus any in `missing`.",
            "matrix": "N x 256 float matrix of the resolved vectors (embeddings[*].embedding). "
                      "Compute the demand centroid / Fréchet barycenter approximation as "
                      "np.mean(np.asarray(matrix), axis=0); valid because Titan V2 vectors are "
                      "L2-normalized so the Euclidean mean approximates the spherical barycenter.",
            "missing": "record_ids with no graph node or no stored embedding (excluded from matrix).",
        },
    })


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

def _handle_wave_close_drift(event: Dict[str, Any]) -> Dict[str, Any]:
    """ENC-FTR-087 Phase 1 wave-close drift emission (direct-invoke action).

    Payload (event) fields:
      project_id (required), wave_id (required), prev_wave_id (optional),
      h_embeddings / v_embeddings (lists of equal-length float vectors) for
      d_centroid_L2, and one of {h_fiedler/v_fiedler} or {h_adjacency/v_adjacency}
      for d_spectral. Both metrics degrade to null when their inputs are absent
      (d_centroid may ship ahead of d_spectral per ENC-FTR-087 / ENC-FTR-088).
      retrieval_records (ENC-FTR-105 AC-7 / ENC-TSK-I91, optional) — the wave's
      retrieval records (each carrying retrieval_energy / avg_retrieval_energy)
      from which spurious_attractor_rate is computed; an explicit
      spurious_attractor_rate field, if present, takes precedence over it.

    Returns the emitted record. Never raises into the caller for a malformed
    payload — returns a structured 400 instead.
    """
    import drift_telemetry

    project_id = str(event.get("project_id", "")).strip()
    wave_id = str(event.get("wave_id", "")).strip()
    if not project_id or not wave_id:
        return _error(400, "wave_close_drift requires project_id and wave_id")
    if not DRIFT_TELEMETRY_TABLE:
        return _error(503, "DRIFT_TELEMETRY_TABLE is not configured")

    k = event.get("k", drift_telemetry.DEFAULT_SPECTRAL_K)
    try:
        record = drift_telemetry.compute_and_emit_wave_close_drift(
            ddb_client=_get_dynamodb(),
            table_name=DRIFT_TELEMETRY_TABLE,
            project_id=project_id,
            wave_id=wave_id,
            prev_wave_id=event.get("prev_wave_id"),
            h_embeddings=event.get("h_embeddings"),
            v_embeddings=event.get("v_embeddings"),
            h_adjacency=event.get("h_adjacency"),
            v_adjacency=event.get("v_adjacency"),
            h_fiedler=event.get("h_fiedler"),
            v_fiedler=event.get("v_fiedler"),
            k=int(k),
            retrieval_records=event.get("retrieval_records"),
            spurious_attractor_rate=event.get("spurious_attractor_rate"),
            re_traversal_rate=event.get("re_traversal_rate"),
        )
    except ValueError as exc:
        return _error(400, f"wave_close_drift payload error: {exc}")
    except Exception as exc:  # noqa: BLE001 — emission failures must not crash the invoke
        logger.exception("[ERROR] wave_close_drift emission failed")
        return _error(500, f"wave_close_drift emission failed: {exc}")
    return _response(200, {"emitted": record})


def _iter_wave_pathway_telemetry_records(wave_id: str) -> tuple[List[Dict[str, Any]], int, int]:
    """ENC-TSK-J90 — read back every pathway-telemetry object emitted for a wave.

    Lists ``s3://{PATHWAY_TELEMETRY_BUCKET}/{PATHWAY_TELEMETRY_PREFIX}/wave_id=<wid>/``
    (the exact partition ``_emit_pathway_telemetry`` writes to) via a paginated
    ``list_objects_v2`` and parses each object's body. Each object holds one JSON
    telemetry record per line (the emitter writes a single line today, but the
    ``.jsonl`` / ``application/x-ndjson`` contract permits multiple, so we parse
    line-by-line defensively). Blank lines and individually malformed lines are
    skipped rather than aborting the whole wave.

    Returns ``(records, objects_seen, objects_failed)`` where ``records`` is the
    flat list of every parsed telemetry record. Fully defensive: on any S3 error
    (bucket unset, list/get failure) it degrades to ``([], 0, 0)`` / partial
    results rather than raising, mirroring ``_emit_pathway_telemetry``'s
    "never crash the request path" philosophy — while still reporting the counts
    so the caller can be transparent about how much telemetry it actually saw.
    """
    records: List[Dict[str, Any]] = []
    objects_seen = 0
    objects_failed = 0
    if not PATHWAY_TELEMETRY_BUCKET:
        return records, objects_seen, objects_failed

    wid = str(wave_id or "unassigned").replace("/", "_") or "unassigned"
    prefix = f"{PATHWAY_TELEMETRY_PREFIX}/wave_id={wid}/"
    try:
        s3 = _get_s3()
        paginator = s3.get_paginator("list_objects_v2")
        keys: List[str] = []
        for page in paginator.paginate(Bucket=PATHWAY_TELEMETRY_BUCKET, Prefix=prefix):
            for obj in page.get("Contents", []) or []:
                key = obj.get("Key")
                if key:
                    keys.append(key)
    except Exception:
        logger.exception("[ERROR] close_wave list_objects_v2 failed (degrading to empty)")
        return records, objects_seen, objects_failed

    for key in keys:
        objects_seen += 1
        try:
            resp = s3.get_object(Bucket=PATHWAY_TELEMETRY_BUCKET, Key=key)
            body = resp["Body"].read()
            if isinstance(body, bytes):
                body = body.decode("utf-8")
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except (ValueError, TypeError):
                    logger.warning("[WARNING] close_wave: skipping malformed JSONL line in %s", key)
        except Exception:
            objects_failed += 1
            logger.warning("[WARNING] close_wave: failed to read telemetry object %s", key, exc_info=True)

    return records, objects_seen, objects_failed


def _handle_close_wave(event: Dict[str, Any]) -> Dict[str, Any]:
    """ENC-TSK-J90 (ENC-FTR-105 AC-7 / ENC-FTR-087) — wave-close orchestrator.

    Reads back the per-wave pathway-telemetry JSONL objects that every
    ``_query_hybrid`` call appended to S3 (``_emit_pathway_telemetry``),
    aggregates their ``energy.records[]`` arrays (the
    ``energy_function.build_retrieval_record`` shape carrying
    ``avg_retrieval_energy`` / ``retrieval_energy``) into one combined
    ``retrieval_records`` list for the wave, and drives the existing
    ``drift_telemetry.compute_and_emit_wave_close_drift`` with it — closing the
    gap where nothing fed real telemetry into ``spurious_attractor_rate``.

    Payload (event) fields:
      project_id (required), wave_id (required), prev_wave_id (optional).

    Scope: only the ``spurious_attractor_rate`` (retrieval_records) path.
    ``d_centroid_L2`` / ``d_spectral`` intentionally degrade to null here — this
    handler sources no embeddings/adjacency (per the drift_telemetry independent-
    degrade contract). OGTM: reads S3 + writes an existing DynamoDB series only;
    no new Neo4j edge type or node label is introduced.

    Empty-wave / S3-unavailable degrade cleanly: the aggregated list is empty and
    ``compute_spurious_attractor_rate`` returns its null-stub value. The response
    reports ``objects_seen`` / ``records_aggregated`` for transparency rather than
    pretending telemetry existed.
    """
    import drift_telemetry

    project_id = str(event.get("project_id", "")).strip()
    wave_id = str(event.get("wave_id", "")).strip()
    if not project_id or not wave_id:
        return _error(400, "close_wave requires project_id and wave_id")
    if not DRIFT_TELEMETRY_TABLE:
        return _error(503, "DRIFT_TELEMETRY_TABLE is not configured")

    telemetry_records, objects_seen, objects_failed = _iter_wave_pathway_telemetry_records(wave_id)

    combined_records: List[Dict[str, Any]] = []
    for rec in telemetry_records:
        if not isinstance(rec, dict):
            continue
        energy = rec.get("energy") or {}
        if not isinstance(energy, dict):
            continue
        for er in energy.get("records") or []:
            if isinstance(er, dict):
                combined_records.append(er)

    try:
        record = drift_telemetry.compute_and_emit_wave_close_drift(
            ddb_client=_get_dynamodb(),
            table_name=DRIFT_TELEMETRY_TABLE,
            project_id=project_id,
            wave_id=wave_id,
            prev_wave_id=event.get("prev_wave_id"),
            retrieval_records=combined_records,
        )
    except ValueError as exc:
        return _error(400, f"close_wave payload error: {exc}")
    except Exception as exc:  # noqa: BLE001 — emission failures must not crash the invoke
        logger.exception("[ERROR] close_wave emission failed")
        return _error(500, f"close_wave emission failed: {exc}")

    return _response(200, {
        "emitted": record,
        "wave_id": wave_id,
        "project_id": project_id,
        "objects_seen": objects_seen,
        "objects_failed": objects_failed,
        "records_aggregated": len(combined_records),
    })


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """API Gateway v2 proxy handler."""
    # ENC-FTR-087 Phase 1: wave-close drift emission via direct invoke / event.
    if isinstance(event, dict) and event.get("action") == "wave_close_drift":
        return _handle_wave_close_drift(event)

    # ENC-TSK-J90 (ENC-FTR-105 AC-7): wave-close orchestrator — reads back the
    # wave's pathway-telemetry JSONL from S3, aggregates energy.records[] into a
    # combined retrieval_records list, and drives compute_and_emit_wave_close_drift
    # (feeding spurious_attractor_rate with real telemetry). Checked before the
    # generic Scheduled-Event fallback below.
    if isinstance(event, dict) and event.get("action") == "close_wave":
        return _handle_close_wave(event)

    # ENC-FTR-108 Ph2 (ENC-TSK-J02): out-of-band flow_weight refresh. Checked
    # before the generic aws.events/Scheduled-Event fallback below so an
    # explicit action='refresh_flow_weight' invoke (or EventBridge rule Input)
    # never falls through to the FTR-101 projection-refresh handler.
    if isinstance(event, dict) and event.get("action") == "refresh_flow_weight":
        return _handle_refresh_flow_weight(event)

    # ENC-TSK-K43 (B66 Ph5): out-of-band Fiedler lambda-2 GraphHealth metric
    # publish. Checked before the generic aws.events/Scheduled-Event fallback
    # below (same reasoning as refresh_flow_weight above) so an explicit
    # action='publish_graph_health' invoke (or EventBridge rule Input) never
    # falls through to the FTR-101 projection-refresh handler.
    if isinstance(event, dict) and event.get("action") == "publish_graph_health":
        return _handle_publish_graph_health(event)

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
        qs = event.get("queryStringParameters") or {}
        # ENC-FTR-089 / ENC-TSK-I89: admin-scoped raw-embedding egress shares the
        # graphsearch route via search_type=embeddings_for (no new API Gateway
        # route or CFN change); the handler enforces its own stricter admin gate.
        if (qs.get("search_type") or "") == EMBEDDING_EGRESS_SEARCH_TYPE:
            return _handle_embeddings_for(event)
        return _handle_search(event)

    return _error(404, f"Route not found: {method} {path}")
