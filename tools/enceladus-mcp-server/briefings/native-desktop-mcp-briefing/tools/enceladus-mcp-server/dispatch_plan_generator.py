#!/usr/bin/env python3
"""Dispatch-Plan Generator — governance-first plan generation for coordination requests.

Implements the dispatch layer (v0.3 contract §6.1.2) and dispatch-heuristics.md.
Called by the initialization agent session to transform intake-qualified coordination
requests into executable dispatch plans.

Architecture:
  Coordination API -> (EventBridge or Step Function) -> Init Agent Session
    -> THIS MODULE (via MCP tool or direct import) -> dispatch-plan JSON -> Orchestrator

The generator follows the mandatory governance-first initialization sequence:
  1. Load governance files (agents.md, agents/*)
  2. Compute governance_hash
  3. Test Enceladus connections (DynamoDB, S3, API Gateway)
  4. Load dispatch parameters (coordination request, project metadata, active dispatches)
  5. Apply heuristics from dispatch-heuristics.md
  6. Generate dispatch-plan conforming to strict schema
  7. Validate dispatch-plan against quality gates
  8. Return dispatch-plan

Related: DVP-TSK-252, DVP-FTR-023, DVP-TSK-250
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("dispatch_plan_generator")

# ---------------------------------------------------------------------------
# Constants — mirror server.py for consistency
# ---------------------------------------------------------------------------

TRACKER_TABLE = os.environ.get("ENCELADUS_TRACKER_TABLE", "devops-project-tracker")
PROJECTS_TABLE = os.environ.get("ENCELADUS_PROJECTS_TABLE", "projects")
DOCUMENTS_TABLE = os.environ.get("ENCELADUS_DOCUMENTS_TABLE", "documents")
COORDINATION_TABLE = os.environ.get("ENCELADUS_COORDINATION_TABLE", "coordination-requests")
DEPLOY_TABLE = os.environ.get("ENCELADUS_DEPLOY_TABLE", "devops-deployment-manager")
AWS_REGION = os.environ.get("ENCELADUS_REGION", "us-west-2")
S3_BUCKET = os.environ.get("ENCELADUS_S3_BUCKET", "jreese-net")
GOVERNANCE_PROJECT_ID = os.environ.get("ENCELADUS_GOVERNANCE_PROJECT_ID", "devops")
GOVERNANCE_KEYWORD = os.environ.get("ENCELADUS_GOVERNANCE_KEYWORD", "governance-file")
S3_GOVERNANCE_PREFIX = os.environ.get("ENCELADUS_S3_GOVERNANCE_PREFIX", "governance/live")

COORDINATION_API_BASE = os.environ.get(
    "ENCELADUS_COORDINATION_API_BASE",
    "https://jreese.net/api/v1/coordination",
)

PLAN_VERSION = "0.3.0"

# Callback endpoint template — filled per-dispatch
CALLBACK_ENDPOINT_TEMPLATE = os.environ.get(
    "ENCELADUS_CALLBACK_ENDPOINT",
    "https://jreese.net/api/v1/coordination/requests/{request_id}/callback",
)
CALLBACK_TOKEN_TTL_MINUTES = int(os.environ.get("ENCELADUS_CALLBACK_TOKEN_TTL", "120"))

# ---------------------------------------------------------------------------
# Provider Registry (from dispatch-heuristics.md §2.1)
# ---------------------------------------------------------------------------

VALID_PROVIDERS = {"openai_codex", "claude_agent_sdk", "aws_native", "aws_bedrock_agent"}

# Project-Provider affinity map (dispatch-heuristics.md §2.3)
PROJECT_PROVIDER_AFFINITY: Dict[str, str] = {
    "devops": "claude_agent_sdk",
    "harrisonfamily": "openai_codex",
    "mod": "openai_codex",
    "agentharmony": "claude_agent_sdk",
}
DEFAULT_PROVIDER = "claude_agent_sdk"

# Provider -> execution mode mapping
PROVIDER_EXECUTION_MODES: Dict[str, str] = {
    "openai_codex": "codex_full_auto",
    "claude_agent_sdk": "claude_agent_sdk",
    "aws_native": "aws_step_function",
    "aws_bedrock_agent": "bedrock_agent",
}

# Task-type classification keywords (dispatch-heuristics.md §2.4)
_CODE_KEYWORDS = {
    "implement", "code", "refactor", "feature", "build", "create", "add",
    "fix", "patch", "migrate", "port", "write code", "component", "endpoint",
    "function", "module", "class", "template",
}
_ARCHITECTURE_KEYWORDS = {
    "architecture", "design", "contract", "document", "spec", "plan",
    "analyze", "review", "audit", "strategy", "schema", "evaluate",
    "investigate", "diagnose", "root cause",
}
_INFRASTRUCTURE_KEYWORDS = {
    "deploy", "provision", "infrastructure", "cloudformation", "terraform",
    "lambda", "glue", "pipeline", "s3", "dynamodb", "ecs", "ecr",
    "step function", "eventbridge", "sqs", "sns",
}
_TEST_KEYWORDS = {
    "test", "tests", "spec", "coverage", "assertion", "unittest", "pytest", "jest",
    "e2e", "integration test", "unit test", "write test", "test suite",
}
_TRACKER_KEYWORDS = {
    "tracker", "crud", "bulk update", "batch", "update records",
    "close tasks", "create tasks",
}
_BEDROCK_AGENT_KEYWORDS = {
    "bedrock", "knowledge base", "rag", "retrieval", "aws orchestration",
    "multi-step aws", "service integration", "bedrock agent",
}

# Single-session capacity estimates (dispatch-heuristics.md §3.3)
PROVIDER_CAPACITY: Dict[str, Dict[str, int]] = {
    "openai_codex": {"max_outcomes": 5, "max_duration_min": 30, "max_files": 25},
    "claude_agent_sdk": {"max_outcomes": 8, "max_duration_min": 45, "max_files": 15},
    "aws_native": {"max_outcomes": 15, "max_duration_min": 15},
    "aws_bedrock_agent": {"max_outcomes": 3, "max_duration_min": 20},
}

# Concurrency limits (dispatch-heuristics.md §4.1)
CONCURRENCY_LIMITS = {
    "per_project": 2,
    "per_provider_openai_codex": 2,
    "per_provider_claude_agent_sdk": 3,
    "per_provider_aws_native": 5,
    "per_provider_aws_bedrock_agent": 3,
    "global": 6,
}

# Provider failover order (dispatch-heuristics.md §5.3)
PROVIDER_FAILOVER: Dict[str, Optional[str]] = {
    "openai_codex": "claude_agent_sdk",
    "claude_agent_sdk": "openai_codex",
    "aws_native": None,
    "aws_bedrock_agent": "claude_agent_sdk",
}

# Retry limits (dispatch-heuristics.md §5.1)
DEFAULT_MAX_RETRIES = 3
DISPATCH_TIMEOUT_BOUNDS = (5, 120)  # min, max minutes


# ---------------------------------------------------------------------------
# Agent Manifest Loading (ENC-FTR-015 — ontology-driven dispatch)
# ---------------------------------------------------------------------------

_MANIFEST: Optional[Dict[str, Any]] = None


def load_agent_manifest(manifest_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load agent manifest from local file.

    Falls back to None if file not found or invalid JSON, allowing
    hardcoded constants to serve as fallback.

    Args:
        manifest_path: Path to agent-manifest.json. If None, uses the
            default location relative to this file's parent directory.

    Returns:
        Parsed manifest dict, or None if unavailable.
    """
    if manifest_path is None:
        # Default: <repo_root>/agent-manifest.json
        manifest_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "agent-manifest.json",
        )
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
        # Basic structural validation
        if not isinstance(manifest, dict) or "agents" not in manifest:
            logger.warning("Manifest at %s missing 'agents' key — using hardcoded defaults", manifest_path)
            return None
        agents = manifest["agents"]
        if not isinstance(agents, list) or len(agents) == 0:
            logger.warning("Manifest at %s has empty agents list — using hardcoded defaults", manifest_path)
            return None
        # Validate each agent has required dispatch fields
        for agent in agents:
            if not all(k in agent for k in ("task_type", "keywords", "provider_affinity")):
                logger.warning(
                    "Agent '%s' missing dispatch fields — using hardcoded defaults",
                    agent.get("name", "unknown"),
                )
                return None
        logger.info("Loaded agent manifest v%s with %d agents from %s",
                     manifest.get("version", "?"), len(agents), manifest_path)
        return manifest
    except FileNotFoundError:
        logger.warning("Agent manifest not found at %s — using hardcoded defaults", manifest_path)
        return None
    except json.JSONDecodeError as exc:
        logger.warning("Agent manifest at %s is not valid JSON: %s — using hardcoded defaults", manifest_path, exc)
        return None


def _get_manifest() -> Optional[Dict[str, Any]]:
    """Return cached manifest, loading on first call."""
    global _MANIFEST
    if _MANIFEST is None:
        _MANIFEST = load_agent_manifest()
    return _MANIFEST


def _reset_manifest_cache() -> None:
    """Reset the manifest cache (used in tests)."""
    global _MANIFEST
    _MANIFEST = None


# ---------------------------------------------------------------------------
# Lazy boto3
# ---------------------------------------------------------------------------

_ddb_client = None
_s3_client = None

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    _BOTO_AVAILABLE = True
except ImportError:
    _BOTO_AVAILABLE = False


def _get_ddb():
    global _ddb_client
    if _ddb_client is None:
        if not _BOTO_AVAILABLE:
            raise RuntimeError("boto3 is not installed")
        _ddb_client = boto3.client(
            "dynamodb", region_name=AWS_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "adaptive"}),
        )
    return _ddb_client


def _get_s3():
    global _s3_client
    if _s3_client is None:
        if not _BOTO_AVAILABLE:
            raise RuntimeError("boto3 is not installed")
        _s3_client = boto3.client("s3", region_name=AWS_REGION)
    return _s3_client


def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _deser_val(v: Dict) -> Any:
    if "S" in v:
        return v["S"]
    if "N" in v:
        n = v["N"]
        return int(n) if "." not in n else float(n)
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "L" in v:
        return [_deser_val(i) for i in v["L"]]
    if "M" in v:
        return {k: _deser_val(val) for k, val in v["M"].items()}
    if "SS" in v:
        return list(v["SS"])
    if "NS" in v:
        return [int(n) if "." not in n else float(n) for n in v["NS"]]
    return str(v)


def _deser_item(item: Dict) -> Dict[str, Any]:
    return {k: _deser_val(v) for k, v in item.items()}


# ---------------------------------------------------------------------------
# Step 1: Governance Hash
# ---------------------------------------------------------------------------


def _uri_from_file_name(name: str) -> Optional[str]:
    """Map a governance file name to its governance:// URI."""
    fn = str(name or "").strip()
    if fn == "agents.md":
        return "governance://agents.md"
    if fn.startswith("agents/"):
        return f"governance://{fn}"
    return None


def _governance_catalog_from_s3() -> Dict[str, Dict[str, Any]]:
    """Build governance catalog from deterministic S3 prefix (ENC-TSK-474)."""
    try:
        s3 = _get_s3()
        prefix = S3_GOVERNANCE_PREFIX.rstrip("/") + "/"
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
        objects = list(resp.get("Contents", []))
        while resp.get("IsTruncated"):
            resp = s3.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=prefix,
                ContinuationToken=resp["NextContinuationToken"],
            )
            objects.extend(resp.get("Contents", []))
    except Exception as exc:
        logger.warning("S3 governance listing failed: %s", exc)
        return {}

    catalog: Dict[str, Dict[str, Any]] = {}
    for obj in objects:
        s3_key = obj["Key"]
        rel_path = s3_key[len(prefix):]
        if not rel_path or rel_path.endswith("/"):
            continue
        uri = _uri_from_file_name(rel_path)
        if not uri:
            continue
        try:
            content_resp = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
            content = content_resp["Body"].read()
            content_hash = hashlib.sha256(content).hexdigest()
        except Exception as exc:
            logger.warning("Failed to read governance file s3://%s/%s: %s", S3_BUCKET, s3_key, exc)
            continue
        catalog[uri] = {"content_hash": content_hash}

    return catalog


def _governance_catalog_from_docstore() -> Dict[str, Dict[str, Any]]:
    """Legacy: build governance catalog from docstore DynamoDB scan."""
    ddb = _get_ddb()
    resp = ddb.query(
        TableName=DOCUMENTS_TABLE,
        IndexName="project-updated-index",
        KeyConditionExpression="project_id = :pid",
        ExpressionAttributeValues={":pid": _ser_s(GOVERNANCE_PROJECT_ID)},
        ScanIndexForward=False,
    )
    items = list(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = ddb.query(
            TableName=DOCUMENTS_TABLE,
            IndexName="project-updated-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": _ser_s(GOVERNANCE_PROJECT_ID)},
            ScanIndexForward=False,
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))

    selected: Dict[str, Dict[str, Any]] = {}
    for raw in items:
        doc = _deser_item(raw)
        if str(doc.get("status") or "").lower() != "active":
            continue
        keywords = [str(k).strip().lower() for k in doc.get("keywords") or [] if str(k).strip()]
        if GOVERNANCE_KEYWORD and GOVERNANCE_KEYWORD.lower() not in keywords:
            continue
        uri = _uri_from_file_name(str(doc.get("file_name") or ""))
        if not uri:
            continue
        existing = selected.get(uri)
        if existing and str(existing.get("updated_at") or "") >= str(doc.get("updated_at") or ""):
            continue
        selected[uri] = doc

    return selected


def compute_governance_hash() -> str:
    """SHA-256 of governance resources — two-tier resolution (ENC-TSK-474).

    Primary: deterministic S3 prefix (governance/live/).
    Fallback: legacy docstore DynamoDB scan.
    """
    catalog = _governance_catalog_from_s3()

    if not catalog:
        logger.warning(
            "No governance files at s3://%s/%s/ — falling back to docstore scan.",
            S3_BUCKET, S3_GOVERNANCE_PREFIX,
        )
        catalog = _governance_catalog_from_docstore()

    h = hashlib.sha256()
    if not catalog:
        h.update(b"enceladus-governance-docstore-empty")
        return h.hexdigest()

    for uri in sorted(catalog.keys()):
        content_hash = str(catalog[uri].get("content_hash") or "").strip()
        if not content_hash:
            # Fallback: read S3 content (docstore path) or hash document_id
            s3_key = str(catalog[uri].get("s3_key") or "").strip()
            if s3_key:
                try:
                    resp = _get_s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
                    content_hash = hashlib.sha256(resp["Body"].read()).hexdigest()
                except Exception:
                    content_hash = hashlib.sha256(
                        str(catalog[uri].get("document_id") or "").encode("utf-8")
                    ).hexdigest()
            else:
                content_hash = hashlib.sha256(
                    str(catalog[uri].get("document_id") or "").encode("utf-8")
                ).hexdigest()
        h.update(uri.encode("utf-8"))
        h.update(b"\n")
        h.update(content_hash.encode("utf-8"))
        h.update(b"\n")

    return h.hexdigest()


# ---------------------------------------------------------------------------
# Step 2: Connection Health
# ---------------------------------------------------------------------------


def test_connection_health() -> Dict[str, str]:
    """Test connectivity to DynamoDB, S3, and API Gateway."""
    health: Dict[str, str] = {}

    # DynamoDB
    try:
        ddb = _get_ddb()
        ddb.describe_table(TableName=TRACKER_TABLE)
        health["dynamodb"] = "ok"
    except Exception as exc:
        logger.warning("DynamoDB health check failed: %s", exc)
        health["dynamodb"] = "unreachable"

    # S3 — use list_objects_v2 with prefix instead of head_bucket (ec2-role lacks HeadBucket)
    try:
        s3 = _get_s3()
        s3.list_objects_v2(Bucket=S3_BUCKET, Prefix="mobile/v1/", MaxKeys=1)
        health["s3"] = "ok"
    except Exception as exc:
        logger.warning("S3 health check failed: %s", exc)
        health["s3"] = "unreachable"

    # API Gateway
    try:
        url = f"{COORDINATION_API_BASE}/capabilities"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                health["api_gateway"] = "ok"
            else:
                health["api_gateway"] = "degraded"
    except Exception as exc:
        logger.warning("API Gateway health check failed: %s", exc)
        health["api_gateway"] = "unreachable"

    return health


# ---------------------------------------------------------------------------
# Step 3: Load Dispatch Parameters
# ---------------------------------------------------------------------------


def load_coordination_request(request_id: str) -> Dict[str, Any]:
    """Fetch coordination request from DynamoDB."""
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=COORDINATION_TABLE,
        Key={"request_id": _ser_s(request_id)},
    )
    item = resp.get("Item")
    if not item:
        raise ValueError(f"Coordination request '{request_id}' not found")
    return _deser_item(item)


def load_project_metadata(project_id: str) -> Dict[str, Any]:
    """Fetch project metadata from projects table."""
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=PROJECTS_TABLE,
        Key={"project_id": _ser_s(project_id)},
    )
    item = resp.get("Item")
    if not item:
        raise ValueError(f"Project '{project_id}' not found")
    return _deser_item(item)


def load_deployment_state(project_id: str) -> str:
    """Check if project deployment is ACTIVE or PAUSED."""
    ddb = _get_ddb()
    resp = ddb.get_item(
        TableName=DEPLOY_TABLE,
        Key={
            "project_id": _ser_s(project_id),
            "record_id": _ser_s("STATE"),
        },
    )
    item = resp.get("Item")
    if not item:
        return "ACTIVE"  # default if no state record
    state_item = _deser_item(item)
    return state_item.get("state", "ACTIVE")


def query_active_dispatches(project_id: str) -> List[Dict[str, Any]]:
    """Query coordination-requests table for active dispatches on this project.

    Returns requests in 'dispatching' or 'running' state for the given project_id.
    """
    ddb = _get_ddb()
    active_requests: List[Dict[str, Any]] = []

    # Scan coordination-requests for active states on this project
    # (In production, a GSI on project_id + state would be more efficient)
    for state in ("dispatching", "running"):
        try:
            resp = ddb.scan(
                TableName=COORDINATION_TABLE,
                FilterExpression="project_id = :pid AND #st = :state",
                ExpressionAttributeValues={
                    ":pid": _ser_s(project_id),
                    ":state": _ser_s(state),
                },
                ExpressionAttributeNames={"#st": "state"},
                ProjectionExpression="request_id, project_id, #st, related_record_ids, dispatch_plan",
            )
            for item in resp.get("Items", []):
                active_requests.append(_deser_item(item))
        except Exception as exc:
            logger.warning("Failed to query active dispatches for state %s: %s", state, exc)

    return active_requests


# ---------------------------------------------------------------------------
# Step 4: Heuristic Classification
# ---------------------------------------------------------------------------


def classify_outcome(outcome_text: str) -> str:
    """Classify an outcome string into a task type using keyword analysis.

    Uses agent manifest keywords if available (ENC-FTR-015 ontology-driven dispatch),
    falling back to hardcoded keyword sets if the manifest cannot be loaded.

    Returns: 'code', 'architecture', 'infrastructure', 'test', 'tracker_crud', 'bedrock_agent'
    """
    manifest = _get_manifest()
    if manifest and manifest.get("agents"):
        return _classify_from_manifest(outcome_text, manifest["agents"])
    return _classify_from_hardcoded(outcome_text)


def _classify_from_manifest(outcome_text: str, agents: List[Dict[str, Any]]) -> str:
    """Classify outcome using manifest agent keyword sets."""
    lower = outcome_text.lower()
    scores: Dict[str, int] = {}
    for agent in agents:
        task_type = agent["task_type"]
        score = sum(1 for kw in agent.get("keywords", []) if kw in lower)
        scores[task_type] = scores.get(task_type, 0) + score
    if not scores:
        return "code"
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "code"


def _classify_from_hardcoded(outcome_text: str) -> str:
    """Classify outcome using hardcoded keyword sets (fallback)."""
    lower = outcome_text.lower()

    # Score each category
    scores: Dict[str, int] = {
        "code": 0,
        "architecture": 0,
        "infrastructure": 0,
        "test": 0,
        "tracker_crud": 0,
        "bedrock_agent": 0,
    }

    for kw in _CODE_KEYWORDS:
        if kw in lower:
            scores["code"] += 1
    for kw in _ARCHITECTURE_KEYWORDS:
        if kw in lower:
            scores["architecture"] += 1
    for kw in _INFRASTRUCTURE_KEYWORDS:
        if kw in lower:
            scores["infrastructure"] += 1
    for kw in _TEST_KEYWORDS:
        if kw in lower:
            scores["test"] += 1
    for kw in _TRACKER_KEYWORDS:
        if kw in lower:
            scores["tracker_crud"] += 1
    for kw in _BEDROCK_AGENT_KEYWORDS:
        if kw in lower:
            scores["bedrock_agent"] += 1

    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "code"  # default to code if no keywords match
    return best


def select_provider_for_task_type(task_type: str) -> str:
    """Map task type to recommended provider (dispatch-heuristics.md §2.4).

    Uses agent manifest provider_affinity if available (ENC-FTR-015),
    falling back to hardcoded mapping.
    """
    manifest = _get_manifest()
    if manifest and manifest.get("agents"):
        for agent in manifest["agents"]:
            if agent.get("task_type") == task_type:
                return agent.get("provider_affinity", DEFAULT_PROVIDER)
    # Hardcoded fallback
    _HARDCODED_TASK_TYPE_MAPPING = {
        "code": "openai_codex",
        "architecture": "claude_agent_sdk",
        "infrastructure": "aws_native",
        "test": "openai_codex",
        "tracker_crud": "aws_native",
        "bedrock_agent": "aws_bedrock_agent",
    }
    return _HARDCODED_TASK_TYPE_MAPPING.get(task_type, DEFAULT_PROVIDER)


def select_provider(
    outcomes: List[str],
    project_id: str,
    preferred_provider: Optional[str] = None,
    connection_health: Optional[Dict[str, str]] = None,
) -> Tuple[str, str]:
    """Select provider using priority criteria (dispatch-heuristics.md §2.2).

    Returns: (provider, rationale_fragment)
    """
    # 0. If requestor specified, use that (if valid and available)
    if preferred_provider and preferred_provider in VALID_PROVIDERS:
        return preferred_provider, f"Requestor specified preferred_provider='{preferred_provider}'"

    # 1. Task-type affinity — classify all outcomes, pick dominant type
    type_counts: Dict[str, int] = {}
    for outcome in outcomes:
        t = classify_outcome(outcome)
        type_counts[t] = type_counts.get(t, 0) + 1

    dominant_type = max(type_counts, key=lambda k: type_counts[k])
    is_mixed = len(type_counts) > 1

    if not is_mixed:
        provider = select_provider_for_task_type(dominant_type)
        rationale = f"All outcomes classified as '{dominant_type}' -> provider '{provider}' (task-type affinity §2.4)"
    else:
        # Mixed — check project affinity as tiebreaker
        provider = PROJECT_PROVIDER_AFFINITY.get(project_id, DEFAULT_PROVIDER)
        type_summary = ", ".join(f"{t}={c}" for t, c in sorted(type_counts.items()))
        rationale = (
            f"Mixed outcome types ({type_summary}); "
            f"project affinity for '{project_id}' -> provider '{provider}' (§2.3)"
        )

    # 5. Availability check
    if connection_health:
        # If chosen provider relies on API and it's unreachable, failover
        # aws_native needs DynamoDB; codex/claude need API Gateway (for callback)
        if provider in ("openai_codex", "claude_agent_sdk"):
            if connection_health.get("api_gateway") == "unreachable":
                fallback = PROVIDER_FAILOVER.get(provider)
                if fallback:
                    rationale += f"; API Gateway unreachable, failover to '{fallback}' (§2.2.5)"
                    provider = fallback

    return provider, rationale


# ---------------------------------------------------------------------------
# Step 5: Decomposition
# ---------------------------------------------------------------------------


def should_decompose(
    outcomes: List[str],
    provider: str,
    constraints: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Determine if outcomes should be decomposed into multiple dispatches.

    Returns: (should_decompose, strategy)
    """
    # Check explicit constraint
    if constraints and constraints.get("decomposition") == "single":
        return False, "single"

    capacity = PROVIDER_CAPACITY.get(provider, PROVIDER_CAPACITY["claude_agent_sdk"])
    max_outcomes = capacity["max_outcomes"]

    if len(outcomes) > max_outcomes:
        return True, "parallel"

    # Check if outcomes span different task types -> decompose
    types = {classify_outcome(o) for o in outcomes}
    provider_types = {select_provider_for_task_type(t) for t in types}

    if len(provider_types) > 1:
        # Outcomes need different providers
        return True, "parallel"

    return False, "single"


def decompose_outcomes(
    outcomes: List[str],
    project_id: str,
    preferred_provider: Optional[str],
    connection_health: Optional[Dict[str, str]],
    constraints: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Decompose outcomes into dispatch groups.

    Each group has: provider, execution_mode, outcomes, sequence_order.
    """
    # First, classify each outcome
    classified: List[Tuple[str, str, str]] = []  # (outcome, task_type, provider)
    for outcome in outcomes:
        task_type = classify_outcome(outcome)
        if preferred_provider and preferred_provider in VALID_PROVIDERS:
            prov = preferred_provider
        else:
            prov = select_provider_for_task_type(task_type)
        classified.append((outcome, task_type, prov))

    # Group by provider
    groups: Dict[str, List[str]] = {}
    for outcome, _task_type, provider in classified:
        groups.setdefault(provider, []).append(outcome)

    # Check capacity limits per provider and split if needed
    dispatch_groups: List[Dict[str, Any]] = []
    sequence_order = 0

    for provider, provider_outcomes in groups.items():
        capacity = PROVIDER_CAPACITY.get(provider, PROVIDER_CAPACITY["claude_agent_sdk"])
        max_outcomes = capacity["max_outcomes"]

        # Split into chunks if over capacity
        chunks = [
            provider_outcomes[i:i + max_outcomes]
            for i in range(0, len(provider_outcomes), max_outcomes)
        ]

        for chunk in chunks:
            exec_mode = PROVIDER_EXECUTION_MODES.get(provider, "preflight")
            dispatch_groups.append({
                "provider": provider,
                "execution_mode": exec_mode,
                "outcomes": chunk,
                "sequence_order": sequence_order,
            })

        # All groups at the same level are parallel (same sequence_order)
        # Only increment if there's a dependency (not implemented yet in v0.3.0)

    # If single group, keep sequence_order=0
    # If multiple groups with same provider, they're parallel (same sequence_order)
    # In the future, dependencies would create sequential ordering

    return dispatch_groups


# ---------------------------------------------------------------------------
# Step 6: Conflict Detection (dispatch-heuristics.md §4.2)
# ---------------------------------------------------------------------------


def detect_conflicts(
    project_id: str,
    related_record_ids: List[str],
    active_dispatches: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Detect conflicts with active dispatches.

    Returns list of conflict descriptions.
    """
    conflicts: List[Dict[str, str]] = []

    if not active_dispatches:
        return conflicts

    for active in active_dispatches:
        active_id = active.get("request_id", "unknown")
        active_related = active.get("related_record_ids", [])
        if isinstance(active_related, str):
            active_related = [r.strip() for r in active_related.split(",") if r.strip()]

        # Check for overlapping record IDs
        overlap = set(related_record_ids) & set(active_related)
        if overlap:
            conflicts.append({
                "type": "record_overlap",
                "active_request_id": active_id,
                "overlapping_records": sorted(overlap),
                "resolution": "queue_after",
            })

    return conflicts


def check_concurrency(
    project_id: str,
    provider: str,
    active_dispatches: List[Dict[str, Any]],
    planned_dispatch_count: int,
) -> Tuple[bool, str]:
    """Check if adding dispatches would exceed concurrency limits.

    Returns: (within_limits, message)
    """
    # Count active dispatches per project
    project_active = len([d for d in active_dispatches if d.get("project_id") == project_id])

    if project_active + planned_dispatch_count > CONCURRENCY_LIMITS["per_project"]:
        return False, (
            f"Project '{project_id}' would exceed per-project limit "
            f"({project_active} active + {planned_dispatch_count} planned > "
            f"{CONCURRENCY_LIMITS['per_project']})"
        )

    # Count active dispatches per provider (approximate — we don't track provider per dispatch in table yet)
    provider_limit_key = f"per_provider_{provider}"
    provider_limit = CONCURRENCY_LIMITS.get(provider_limit_key, 3)

    # Global limit
    total_active = len(active_dispatches)
    if total_active + planned_dispatch_count > CONCURRENCY_LIMITS["global"]:
        return False, (
            f"Global concurrent dispatch limit would be exceeded "
            f"({total_active} active + {planned_dispatch_count} planned > "
            f"{CONCURRENCY_LIMITS['global']})"
        )

    return True, "Concurrency within limits"


# ---------------------------------------------------------------------------
# Step 7: Feed Subscription Auto-Linking (dispatch-heuristics.md §8)
# ---------------------------------------------------------------------------


def compute_feed_subscription(
    related_record_ids: List[str],
    requestor_session_id: Optional[str],
    estimated_duration_minutes: int,
) -> Optional[Dict[str, Any]]:
    """Compute feed subscription configuration if applicable.

    dispatch-heuristics.md §8.1: Auto-subscribe requestor to updates on
    related_record_ids if requestor_session_id is present.
    """
    if not requestor_session_id or not related_record_ids:
        return None

    # Duration: estimated_duration * 2, floor 30, ceiling 1440
    duration = max(30, min(1440, estimated_duration_minutes * 2))

    return {
        "auto_subscribe": True,
        "item_ids": related_record_ids,
        "duration_minutes": duration,
    }


# ---------------------------------------------------------------------------
# Step 8: Dispatch-Plan Assembly
# ---------------------------------------------------------------------------


def estimate_duration(
    dispatch_groups: List[Dict[str, Any]],
) -> int:
    """Estimate total duration in minutes based on provider capacity estimates."""
    if not dispatch_groups:
        return 15

    # For parallel dispatches (same sequence_order), duration is max of group durations
    # For sequential, it's the sum
    order_groups: Dict[int, List[Dict]] = {}
    for g in dispatch_groups:
        order = g.get("sequence_order", 0)
        order_groups.setdefault(order, []).append(g)

    total_duration = 0
    for _order, groups in sorted(order_groups.items()):
        max_group_duration = 0
        for g in groups:
            provider = g["provider"]
            capacity = PROVIDER_CAPACITY.get(provider, PROVIDER_CAPACITY["claude_agent_sdk"])
            num_outcomes = len(g.get("outcomes", []))
            # Linear estimate: (num_outcomes / max_outcomes) * max_duration
            max_out = capacity["max_outcomes"]
            max_dur = capacity["max_duration_min"]
            est = max(5, int((num_outcomes / max_out) * max_dur))
            max_group_duration = max(max_group_duration, est)
        total_duration += max_group_duration

    return total_duration


def build_dispatch_plan(
    request_id: str,
    project_id: str,
    outcomes: List[str],
    governance_hash: str,
    connection_health: Dict[str, str],
    dispatch_groups: List[Dict[str, Any]],
    rationale: str,
    decomposition: str,
    estimated_duration_minutes: int,
    related_record_ids: List[str],
    requestor_session_id: Optional[str],
    rollback_policy: Optional[Dict[str, Any]] = None,
    source_request_ids: Optional[List[str]] = None,
    constraints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the dispatch-plan JSON conforming to v0.3 contract schema."""
    plan_id = str(uuid.uuid4())
    now = _now_z()

    dispatches: List[Dict[str, Any]] = []
    for group in dispatch_groups:
        dispatch_id = str(uuid.uuid4())
        provider = group["provider"]
        timeout_min = group.get("timeout_minutes")
        if timeout_min is None:
            capacity = PROVIDER_CAPACITY.get(provider, PROVIDER_CAPACITY["claude_agent_sdk"])
            timeout_min = capacity["max_duration_min"]
        # Clamp timeout to bounds
        timeout_min = max(DISPATCH_TIMEOUT_BOUNDS[0], min(DISPATCH_TIMEOUT_BOUNDS[1], timeout_min))

        # Feed subscription
        feed_sub = compute_feed_subscription(
            related_record_ids=related_record_ids,
            requestor_session_id=requestor_session_id,
            estimated_duration_minutes=estimated_duration_minutes,
        )

        dispatch_entry: Dict[str, Any] = {
            "dispatch_id": dispatch_id,
            "sequence_order": group.get("sequence_order", 0),
            "provider": provider,
            "execution_mode": group.get("execution_mode", "preflight"),
            "outcomes": group.get("outcomes", []),
            "constraints": constraints or {},
            "provider_config": {
                "model": group.get("model"),
                "thread_id": group.get("thread_id"),
                "fork_from_thread_id": group.get("fork_from_thread_id"),
                "max_turns": group.get("max_turns"),
                "timeout_minutes": timeout_min,
            },
            "callback_config": {
                "endpoint": CALLBACK_ENDPOINT_TEMPLATE.format(request_id=request_id),
                "auth_method": "token",
                "token_ttl_minutes": CALLBACK_TOKEN_TTL_MINUTES,
            },
        }

        if feed_sub:
            dispatch_entry["feed_subscription"] = feed_sub

        # Bedrock-specific provider config (DVP-TSK-335)
        if provider == "aws_bedrock_agent":
            dispatch_entry["provider_config"]["bedrock_config"] = {
                "foundation_model_id": group.get("foundation_model_id"),
                "agent_instruction": group.get("agent_instruction"),
                "action_group_lambda_arn": group.get("action_group_lambda_arn"),
                "knowledge_base_id": group.get("knowledge_base_id"),
                "retain_agent": group.get("retain_agent", False),
                "idle_session_ttl_seconds": group.get("idle_session_ttl_seconds", 300),
            }

        dispatches.append(dispatch_entry)

    # Rollback policy
    if rollback_policy is None:
        rollback_policy = {
            "on_partial_failure": "continue",
            "max_retries_per_dispatch": DEFAULT_MAX_RETRIES,
        }

    plan: Dict[str, Any] = {
        "plan_id": plan_id,
        "plan_version": PLAN_VERSION,
        "source_request_ids": source_request_ids or [request_id],
        "project_id": project_id,
        "generated_at": now,
        "governance_hash": governance_hash,
        "connection_health": connection_health,
        "strategy": {
            "rationale": rationale[:1000],  # cap at 1000 chars per schema
            "decomposition": decomposition,
            "estimated_duration_minutes": estimated_duration_minutes,
        },
        "dispatches": dispatches,
        "rollback_policy": rollback_policy,
    }

    return plan


# ---------------------------------------------------------------------------
# Step 9: Quality Gate Validation (dispatch-heuristics.md §7)
# ---------------------------------------------------------------------------


class QualityGateError(Exception):
    """Raised when a dispatch-plan fails quality gate validation."""
    def __init__(self, gate: str, message: str):
        self.gate = gate
        super().__init__(f"Quality gate '{gate}' failed: {message}")


def validate_dispatch_plan(
    plan: Dict[str, Any],
    original_outcomes: List[str],
) -> List[str]:
    """Validate dispatch-plan against quality gates.

    Returns list of warnings (empty = all gates passed).
    Raises QualityGateError for hard failures.
    """
    warnings: List[str] = []

    # Gate 1: Schema compliance (structural check)
    required_top = {
        "plan_id", "plan_version", "source_request_ids", "project_id",
        "generated_at", "governance_hash", "connection_health", "strategy",
        "dispatches", "rollback_policy",
    }
    missing_top = required_top - set(plan.keys())
    if missing_top:
        raise QualityGateError("schema_compliance", f"Missing required fields: {sorted(missing_top)}")

    # Gate 2: Governance hash present
    gov_hash = plan.get("governance_hash", "")
    if not gov_hash or len(gov_hash) < 32:
        raise QualityGateError("governance_hash", "governance_hash is empty or too short")

    # Gate 3: Connection health minimum — DynamoDB must be ok
    conn_health = plan.get("connection_health", {})
    if conn_health.get("dynamodb") != "ok":
        raise QualityGateError(
            "connection_health",
            f"DynamoDB is {conn_health.get('dynamodb', 'unknown')} — must be 'ok'",
        )

    # Gate 4: Concurrency within limits
    dispatches = plan.get("dispatches", [])
    if len(dispatches) > CONCURRENCY_LIMITS["global"]:
        raise QualityGateError(
            "concurrency",
            f"{len(dispatches)} dispatches exceeds global limit of {CONCURRENCY_LIMITS['global']}",
        )

    # Gate 5: All outcomes mapped
    plan_outcomes: set = set()
    for d in dispatches:
        for o in d.get("outcomes", []):
            plan_outcomes.add(o)
    missing_outcomes = set(original_outcomes) - plan_outcomes
    if missing_outcomes:
        raise QualityGateError(
            "outcomes_mapped",
            f"{len(missing_outcomes)} outcomes not mapped to any dispatch: {list(missing_outcomes)[:3]}...",
        )

    # Gate 6: Provider validity
    for d in dispatches:
        prov = d.get("provider")
        if prov not in VALID_PROVIDERS:
            raise QualityGateError("provider_validity", f"Unknown provider '{prov}'")

    # Gate 7: Timeout bounds
    for d in dispatches:
        timeout = d.get("provider_config", {}).get("timeout_minutes")
        if timeout is not None:
            if timeout < DISPATCH_TIMEOUT_BOUNDS[0]:
                warnings.append(
                    f"Dispatch {d.get('dispatch_id')}: timeout {timeout} clamped to minimum {DISPATCH_TIMEOUT_BOUNDS[0]}"
                )
            elif timeout > DISPATCH_TIMEOUT_BOUNDS[1]:
                warnings.append(
                    f"Dispatch {d.get('dispatch_id')}: timeout {timeout} clamped to maximum {DISPATCH_TIMEOUT_BOUNDS[1]}"
                )

    # Gate 8: Callback configured
    for d in dispatches:
        cb = d.get("callback_config", {})
        if not cb.get("endpoint"):
            raise QualityGateError(
                "callback_configured",
                f"Dispatch {d.get('dispatch_id')} has no callback endpoint",
            )

    return warnings


# ---------------------------------------------------------------------------
# Main Entry Point: generate_dispatch_plan
# ---------------------------------------------------------------------------


def generate_dispatch_plan(
    request_id: str,
    override_plan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate a complete dispatch-plan for a coordination request.

    This is the main entry point implementing the governance-first initialization
    sequence from dispatch-heuristics.md §6.1.

    Args:
        request_id: The coordination request ID to generate a plan for.
        override_plan: Optional pre-built plan that bypasses auto-generation.

    Returns:
        Dict containing the dispatch-plan JSON.

    Raises:
        QualityGateError: If the generated plan fails quality gate validation.
        ValueError: If the coordination request is invalid or not found.
    """
    logger.info("[START] Dispatch-plan generation for request %s", request_id)

    # --- Step 1: Governance hash ---
    gov_hash = compute_governance_hash()
    logger.info("[INFO] Governance hash: %s", gov_hash[:16])

    # --- Step 2: Connection health ---
    conn_health = test_connection_health()
    logger.info("[INFO] Connection health: %s", json.dumps(conn_health))

    # Quality gate: DynamoDB must be reachable
    if conn_health.get("dynamodb") != "ok":
        raise QualityGateError(
            "connection_health",
            "DynamoDB is unreachable — cannot proceed with dispatch-plan generation",
        )

    # --- Step 3: Load dispatch parameters ---
    request = load_coordination_request(request_id)
    project_id = request.get("project_id", "")
    outcomes = request.get("outcomes", [])
    if isinstance(outcomes, str):
        outcomes = [o.strip() for o in outcomes.split(",") if o.strip()]
    constraints = request.get("constraints") or {}
    related_record_ids = request.get("related_record_ids", [])
    if isinstance(related_record_ids, str):
        related_record_ids = [r.strip() for r in related_record_ids.split(",") if r.strip()]
    requestor_session_id = request.get("requestor_session_id")
    source_request_ids = request.get("source_requests") or [request_id]

    # Provider preferences from request
    provider_prefs = request.get("provider_preferences") or request.get("provider_session") or {}
    preferred_provider = provider_prefs.get("preferred_provider")
    execution_mode_override = request.get("execution_mode")

    if not outcomes:
        raise ValueError(f"Coordination request '{request_id}' has no outcomes defined")

    logger.info("[INFO] Request loaded: project=%s, outcomes=%d", project_id, len(outcomes))

    # Load project metadata
    project_meta = load_project_metadata(project_id)
    logger.info("[INFO] Project metadata loaded for '%s'", project_id)

    # Check deployment state (dispatch-heuristics.md §4.2.3)
    deploy_state = load_deployment_state(project_id)
    logger.info("[INFO] Deployment state for '%s': %s", project_id, deploy_state)

    # Query active dispatches for conflict detection
    active_dispatches = query_active_dispatches(project_id)
    logger.info("[INFO] Active dispatches for project: %d", len(active_dispatches))

    # --- Step 4: Handle override plan ---
    if override_plan:
        logger.info("[INFO] Using dispatch_plan_override — skipping heuristic generation")
        # Still validate the override
        override_plan["governance_hash"] = gov_hash
        override_plan["connection_health"] = conn_health
        override_plan["generated_at"] = _now_z()
        warnings = validate_dispatch_plan(override_plan, outcomes)
        if warnings:
            logger.warning("[WARNING] Override plan warnings: %s", warnings)
        logger.info("[SUCCESS] Override dispatch-plan validated")
        return override_plan

    # --- Step 5: Apply heuristics ---

    # 5a: Provider selection
    provider, provider_rationale = select_provider(
        outcomes=outcomes,
        project_id=project_id,
        preferred_provider=preferred_provider,
        connection_health=conn_health,
    )
    logger.info("[INFO] Provider selected: %s — %s", provider, provider_rationale)

    # 5b: Decomposition decision
    needs_decomp, decomposition = should_decompose(outcomes, provider, constraints)
    logger.info("[INFO] Decomposition: needs=%s, strategy=%s", needs_decomp, decomposition)

    # 5c: Build dispatch groups
    if needs_decomp:
        dispatch_groups = decompose_outcomes(
            outcomes=outcomes,
            project_id=project_id,
            preferred_provider=preferred_provider,
            connection_health=conn_health,
            constraints=constraints,
        )
        if len(dispatch_groups) > 1:
            decomposition = "parallel"
        logger.info("[INFO] Decomposed into %d dispatch groups", len(dispatch_groups))
    else:
        exec_mode = execution_mode_override or PROVIDER_EXECUTION_MODES.get(provider, "preflight")
        dispatch_groups = [{
            "provider": provider,
            "execution_mode": exec_mode,
            "outcomes": outcomes,
            "sequence_order": 0,
            "thread_id": provider_prefs.get("thread_id"),
            "fork_from_thread_id": provider_prefs.get("fork_from_thread_id"),
            "model": provider_prefs.get("model"),
        }]

    # 5d: Conflict detection
    conflicts = detect_conflicts(project_id, related_record_ids, active_dispatches)
    conflict_rationale = ""
    if conflicts:
        conflict_details = "; ".join(
            f"overlap with {c['active_request_id']} on {c['overlapping_records']}"
            for c in conflicts
        )
        conflict_rationale = f" Conflicts detected: {conflict_details}. Dispatches queued after active."
        # Adjust sequence_order for conflicting dispatches
        for g in dispatch_groups:
            g["sequence_order"] = g.get("sequence_order", 0) + 1
        logger.warning("[WARNING] Conflicts detected: %s", conflict_rationale)

    # 5e: Concurrency check
    within_limits, concurrency_msg = check_concurrency(
        project_id, provider, active_dispatches, len(dispatch_groups)
    )
    concurrency_rationale = ""
    if not within_limits:
        concurrency_rationale = f" Concurrency: {concurrency_msg}."
        logger.warning("[WARNING] Concurrency limit: %s", concurrency_msg)

    # 5f: Deployment state guard
    deploy_rationale = ""
    if deploy_state == "PAUSED":
        # Filter out infrastructure-type dispatches
        filtered_groups = []
        for g in dispatch_groups:
            has_infra = any(
                classify_outcome(o) == "infrastructure" for o in g.get("outcomes", [])
            )
            if has_infra:
                deploy_rationale = " Deployment is PAUSED — infrastructure dispatches excluded."
                logger.info("[INFO] Excluding infrastructure dispatch (deployment PAUSED)")
            else:
                filtered_groups.append(g)
        dispatch_groups = filtered_groups or dispatch_groups  # keep at least one

    # --- Step 6: Estimate duration ---
    estimated_duration = estimate_duration(dispatch_groups)

    # --- Step 7: Assemble rationale ---
    rationale = provider_rationale + conflict_rationale + concurrency_rationale + deploy_rationale

    # --- Step 8: Build plan ---
    plan = build_dispatch_plan(
        request_id=request_id,
        project_id=project_id,
        outcomes=outcomes,
        governance_hash=gov_hash,
        connection_health=conn_health,
        dispatch_groups=dispatch_groups,
        rationale=rationale,
        decomposition=decomposition,
        estimated_duration_minutes=estimated_duration,
        related_record_ids=related_record_ids,
        requestor_session_id=requestor_session_id,
        source_request_ids=source_request_ids,
        constraints=constraints,
    )

    # --- Step 9: Validate against quality gates ---
    warnings = validate_dispatch_plan(plan, outcomes)
    if warnings:
        logger.warning("[WARNING] Plan validation warnings: %s", warnings)
        plan["_validation_warnings"] = warnings

    logger.info(
        "[SUCCESS] Dispatch-plan generated: plan_id=%s, dispatches=%d, est_duration=%d min",
        plan["plan_id"], len(plan["dispatches"]), estimated_duration,
    )

    return plan


# ---------------------------------------------------------------------------
# CLI entry point for testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")

    if len(sys.argv) < 2:
        print("Usage: python dispatch_plan_generator.py <request_id>", file=sys.stderr)
        print("       python dispatch_plan_generator.py --dry-run <project_id> <outcomes...>", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--dry-run":
        # Dry run mode: generate a plan without a real coordination request
        if len(sys.argv) < 4:
            print("Usage: --dry-run <project_id> <outcome1> [outcome2] ...", file=sys.stderr)
            sys.exit(1)
        project_id = sys.argv[2]
        outcomes = sys.argv[3:]

        gov_hash = compute_governance_hash()
        conn_health = test_connection_health()

        provider, rationale = select_provider(outcomes, project_id, connection_health=conn_health)
        needs_decomp, decomposition = should_decompose(outcomes, provider)

        if needs_decomp:
            groups = decompose_outcomes(outcomes, project_id, None, conn_health)
        else:
            groups = [{
                "provider": provider,
                "execution_mode": PROVIDER_EXECUTION_MODES.get(provider, "preflight"),
                "outcomes": outcomes,
                "sequence_order": 0,
            }]

        estimated = estimate_duration(groups)

        plan = build_dispatch_plan(
            request_id="dry-run-" + str(uuid.uuid4())[:8],
            project_id=project_id,
            outcomes=outcomes,
            governance_hash=gov_hash,
            connection_health=conn_health,
            dispatch_groups=groups,
            rationale=rationale,
            decomposition=decomposition,
            estimated_duration_minutes=estimated,
            related_record_ids=[],
            requestor_session_id=None,
        )

        warnings = validate_dispatch_plan(plan, outcomes)
        if warnings:
            plan["_validation_warnings"] = warnings

        print(json.dumps(plan, indent=2))
    else:
        # Real mode: generate from coordination request
        request_id = sys.argv[1]
        plan = generate_dispatch_plan(request_id)
        print(json.dumps(plan, indent=2))
