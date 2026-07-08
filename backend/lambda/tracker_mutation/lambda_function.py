"""tracker_mutation/lambda_function.py — Full Tracker CRUD API

Lambda API for the Enceladus project tracker. Serves both the PWA UI (Cognito JWT)
and the MCP server (X-Coordination-Internal-Key).

Routes (via API Gateway):
  GET    /api/v1/tracker/pending-updates                          — pending updates
  GET    /api/v1/tracker/{project}                                — list records
  GET    /api/v1/tracker/{project}/{type}/{id}                    — get record
  POST   /api/v1/tracker/{project}/{type}                         — create record
  PATCH  /api/v1/tracker/{project}/{type}/{id}                    — update field / PWA action
  POST   /api/v1/tracker/{project}/{type}/{id}/log                — append worklog
  POST   /api/v1/tracker/{project}/{type}/{id}/checkout           — session checkout
  DELETE /api/v1/tracker/{project}/{type}/{id}/checkout            — session release
  POST   /api/v1/tracker/{project}/{type}/{id}/acceptance-evidence — set evidence
  POST   /api/v1/tracker/{project}/relationship                    — create typed edge
  DELETE /api/v1/tracker/{project}/relationship                    — delete typed edge
  GET    /api/v1/tracker/{project}/relationship                    — list typed edges
  OPTIONS *                                                        — CORS preflight

Auth:
  1. X-Coordination-Internal-Key header (service-to-service, MCP server)
  2. enceladus_id_token cookie (Cognito JWT, PWA users)

Environment variables:
  DYNAMODB_TABLE          default: devops-project-tracker
  DYNAMODB_REGION         default: us-west-2
  PROJECTS_TABLE          default: projects
  COGNITO_USER_POOL_ID    us-east-1_b2D0V3E1k
  COGNITO_CLIENT_ID       6q607dk3liirhtecgps7hifmlk
  COORDINATION_INTERNAL_API_KEY  (service auth key)
  CHECKOUT_TOKENS_TABLE   default: enceladus-checkout-tokens (SCI gate, ENC-ISS-441)
  AGENT_SESSIONS_TABLE    default: agent-sessions (SCI gate, ENC-ISS-441)
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.parse
import urllib.request
from urllib.parse import unquote

import boto3

# ENC-TSK-H08 (F63): resolve feature flags from AppConfig with env-var fallback,
# mirroring coordination_api. The appconfig_flags submodule ships only in shared
# layer :10. ENC-TSK-H28: import defensively so a function still on :7 (e.g. gamma
# pending the layer heal, ENC-ISS-197) degrades to the env-var fallback instead of
# ImportError-bricking the whole Lambda at module load (ENC-LSN-053 resilience class).
try:
    from enceladus_shared.appconfig_flags import flag as _appconfig_flag
except ImportError:  # layer :7 lacks appconfig_flags — fall back to a direct env read
    def _appconfig_flag(name, *, env_fallback=None, default=False):
        raw = os.environ.get(env_fallback, "") if env_fallback else ""
        return raw.strip().lower() == "true" if raw != "" else bool(default)
try:
    from enceladus_shared.version_seq import allocate_version_seq, version_seq_attr, version_seq_update_clause

    _VERSION_SEQ_AVAILABLE = True
except ImportError:
    try:
        from version_seq_util import allocate_version_seq, version_seq_attr, version_seq_update_clause

        _VERSION_SEQ_AVAILABLE = True
    except ImportError:
        _VERSION_SEQ_AVAILABLE = False
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from transition_type_matrix import (
    MATRIX_VERSION,
    CLOSED_EVIDENCE,
    DEPLOY_SUCCESS_EVIDENCE,
    IMMUTABLE_TRANSITION_TYPES,
    STRICTNESS_RANK,
    VALID_TRANSITION_TYPES,
    get_deploy_success_gate,
    is_immutable_type,
)

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    _JWT_AVAILABLE = True
except Exception:  # noqa: BLE001 — also catches RuntimeError/OSError from cffi backend ABI mismatch
    # ENC-ISS-198 / ENC-TSK-D22: log the import failure so operators can
    # diagnose PyJWT/cryptography ABI mismatches in CloudWatch instead of
    # chasing the downstream HTTP 401 "JWT library not available in Lambda
    # package" message. Historical incidents in this failure class:
    # ENC-ISS-041, ENC-ISS-044, ENC-ISS-198. logger is not yet defined at
    # module-load time, so use logging.getLogger(__name__) directly.
    import logging as _enc_iss_198_logging
    _enc_iss_198_logging.getLogger(__name__).exception(
        "PyJWT import failed at module load — Cognito auth will be disabled "
        "(ENC-ISS-198: usually a shared-layer .so ABI mismatch with the function runtime)"
    )
    _JWT_AVAILABLE = False


def _normalize_api_keys(*raw_values: str) -> tuple[str, ...]:
    """Return deduplicated, non-empty key values from scalar/csv env sources."""
    keys: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not raw:
            continue
        for part in str(raw).split(","):
            key = part.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            keys.append(key)
    return tuple(keys)


def _first_nonempty_env(*names: str) -> str:
    for name in names:
        value = str(os.environ.get(name, "")).strip()
        if value:
            return value
    return ""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COORDINATION_INTERNAL_API_KEY = _first_nonempty_env(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
)
COORDINATION_INTERNAL_API_KEY_PREVIOUS = _first_nonempty_env(
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY_PREVIOUS",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS",
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
)
COORDINATION_INTERNAL_API_KEYS = _normalize_api_keys(
    os.environ.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS", ""),
    os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEYS", ""),
    os.environ.get("COORDINATION_INTERNAL_API_KEYS", ""),
    COORDINATION_INTERNAL_API_KEY,
    COORDINATION_INTERNAL_API_KEY_PREVIOUS,
)
_INTERNAL_SCOPE_MAP_RAW = (
    os.environ.get("COORDINATION_INTERNAL_API_KEY_SCOPES", "")
    or os.environ.get("ENCELADUS_INTERNAL_API_KEY_SCOPES", "")
).strip()
GITHUB_INTEGRATION_API_BASE = os.environ.get("GITHUB_INTEGRATION_API_BASE", "")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "https://jreese.net")
# ENC-FTR-037: checkout service gate key — only checkout_service Lambda may change task status
CHECKOUT_SERVICE_KEY = os.environ.get("CHECKOUT_SERVICE_KEY", "")
# ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate stores. SCI tokens (minted
# by coordination_api agent.claim, ENC-TSK-J92) live in the checkout-tokens
# table; the grandfather-epoch check and last_activity_at touch read the
# agent-sessions store (ENC-FTR-117 / ENC-TSK-I37).
CHECKOUT_TOKENS_TABLE = os.environ.get("CHECKOUT_TOKENS_TABLE", "enceladus-checkout-tokens")
AGENT_SESSIONS_TABLE = os.environ.get("AGENT_SESSIONS_TABLE", "agent-sessions")
MAX_NOTE_LENGTH = 2000
# ENC-FTR-052: Governed Lesson Primitive — feature flag
# ENC-TSK-H08 (F63): AppConfig is the source of truth (env_fallback preserves legacy/local behavior)
ENABLE_LESSON_PRIMITIVE = _appconfig_flag("enable_lesson_primitive", env_fallback="ENABLE_LESSON_PRIMITIVE")

# ---------------------------------------------------------------------------
# ENC-TSK-H46 / B63 Phase 2A — Lifecycle Service extraction.
# When enable_lifecycle_service_extraction is ON, the standalone Lifecycle Service is the SOLE
# authority for transition_type_matrix validation, STRICTNESS_RANK enforcement, and subtask gates
# on task status transitions. Invocation is synchronous and FAIL-CLOSED: any invoke failure rejects
# the transition (no inline fallback). The inline validators below are retained ONLY as the
# flag-OFF rollback path (ENC-TSK-H46 AC #3). Flag is read at request time so an AppConfig toggle
# takes effect (and rolls back) without a redeploy.
# ---------------------------------------------------------------------------
LIFECYCLE_SERVICE_FUNCTION = os.environ.get("LIFECYCLE_SERVICE_FUNCTION", "")
_lambda_client = None


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client(
            "lambda",
            region_name=DYNAMODB_REGION,
            config=Config(
                retries={"max_attempts": 2, "mode": "standard"},
                read_timeout=5,
                connect_timeout=2,
            ),
        )
    return _lambda_client


def _lifecycle_service_enabled() -> bool:
    """Read the AppConfig flag at request time (independent toggle + rollback, ENC-TSK-H46 AC #3)."""
    return _appconfig_flag("enable_lifecycle_service_extraction", env_fallback="ENABLE_LIFECYCLE_SERVICE")


def _arc_walker_enabled() -> bool:
    """ENC-TSK-H85 / ENC-FTR-111 Phase 1 — the Universal Arc-Walker is behind its OWN independent
    feature flag, read at request time so it toggles (and rolls back) without a redeploy. It is
    deliberately separate from enable_lifecycle_service_extraction: the validation extraction (H46)
    and the synchronous mechanical walk (this task) graduate independently (DOC-078C57FC1BE6 §11)."""
    return _appconfig_flag("enable_arc_walker", env_fallback="ENABLE_ARC_WALKER")


def _invoke_lifecycle_action(payload: dict):
    """Synchronously invoke the Lifecycle Service for an arbitrary action and return its raw verdict
    dict, or None on ANY failure. Unlike _invoke_lifecycle_service this does NOT require an ``allow``
    key, so it serves the ENC-TSK-H85 arc-walker which consumes the evaluate_auto_walk verdict
    (auto_walkable / gate_class / matrix_version) in addition to validate_transition."""
    fn = LIFECYCLE_SERVICE_FUNCTION
    if not fn:
        logger.error("[H85] LIFECYCLE_SERVICE_FUNCTION not configured; arc-walk skipped")
        return None
    try:
        resp = _get_lambda_client().invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        if resp.get("FunctionError"):
            logger.error("[H85] Lifecycle Service FunctionError=%s", resp.get("FunctionError"))
            return None
        body = resp.get("Payload")
        raw = body.read() if hasattr(body, "read") else body
        verdict = json.loads(raw)
        if not isinstance(verdict, dict):
            logger.error("[H85] Lifecycle Service returned malformed verdict: %r", verdict)
            return None
        return verdict
    except Exception as exc:  # noqa: BLE001
        logger.error("[H85] Lifecycle Service invoke failed: %s", exc)
        return None


def _invoke_lifecycle_service(payload: dict):
    """Synchronously invoke the Lifecycle Service and return its verdict dict, or None on ANY
    failure (function not configured, invoke error, FunctionError, malformed verdict). Returning
    None signals the caller to FAIL CLOSED — there is no inline fallback when the flag is ON
    (ENC-TSK-H46 AC #2)."""
    fn = LIFECYCLE_SERVICE_FUNCTION
    if not fn:
        logger.error("[H46] LIFECYCLE_SERVICE_FUNCTION not configured; failing closed")
        return None
    try:
        resp = _get_lambda_client().invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        if resp.get("FunctionError"):
            logger.error("[H46] Lifecycle Service FunctionError=%s", resp.get("FunctionError"))
            return None
        body = resp.get("Payload")
        raw = body.read() if hasattr(body, "read") else body
        verdict = json.loads(raw)
        if not isinstance(verdict, dict) or "allow" not in verdict:
            logger.error("[H46] Lifecycle Service returned malformed verdict: %r", verdict)
            return None
        return verdict
    except Exception as exc:  # noqa: BLE001
        logger.error("[H46] Lifecycle Service invoke failed: %s", exc)
        return None

# ---------------------------------------------------------------------------
# ENC-TSK-L06 / B63 Phase 2 AC-6 — ID Service extraction.
# When enable_id_service_extraction is ON, the standalone ID Service is the SOLE authority
# for record-ID allocation (counter items now live in a dedicated enceladus-id-counters
# table that only the ID Service's IAM role can touch — AC-0), the idempotency-key
# contract, and HMAC provenance signing. Invocation is synchronous and FAIL-CLOSED,
# mirroring the Lifecycle Service (H46) posture exactly: any invoke failure REJECTS the
# create — there is no inline fallback to a different generation path when the flag is ON
# (an ID-generation failure silently falling back would defeat the IAM isolation
# property). The inline _next_record_id()/_encode_base36() path below (which still reads/
# writes legacy counter#* rows in THIS table) is retained ONLY as the flag-OFF rollback
# (zero-behavior-change deploy, matching the H46/H47 precedent).
# ---------------------------------------------------------------------------
ID_SERVICE_FUNCTION = os.environ.get("ID_SERVICE_FUNCTION", "")


def _id_service_enabled() -> bool:
    """Read the AppConfig flag at request time (independent toggle + rollback, ENC-TSK-L06)."""
    return _appconfig_flag("enable_id_service_extraction", env_fallback="ENABLE_ID_SERVICE")


def _invoke_id_service(payload: dict):
    """Synchronously invoke the ID Service and return its verdict dict, or None on ANY
    failure (function not configured, invoke error, FunctionError, malformed verdict).
    Returning None signals the caller to FAIL CLOSED — there is no inline fallback when the
    flag is ON (ENC-TSK-L06, mirrors ENC-TSK-H46 AC #2)."""
    fn = ID_SERVICE_FUNCTION
    if not fn:
        logger.error("[L06] ID_SERVICE_FUNCTION not configured; failing closed")
        return None
    try:
        resp = _get_lambda_client().invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        if resp.get("FunctionError"):
            logger.error("[L06] ID Service FunctionError=%s", resp.get("FunctionError"))
            return None
        body = resp.get("Payload")
        raw = body.read() if hasattr(body, "read") else body
        verdict = json.loads(raw)
        if not isinstance(verdict, dict) or "allow" not in verdict:
            logger.error("[L06] ID Service returned malformed verdict: %r", verdict)
            return None
        return verdict
    except Exception as exc:  # noqa: BLE001
        logger.error("[L06] ID Service invoke failed: %s", exc)
        return None


def _record_id_boundary_violation(body: dict, record_type: str, field: str) -> None:
    """ENC-TSK-L06 AC-4: best-effort trust-score feedback on an ID_BOUNDARY_VIOLATION reject.
    Fires the ID Service's record_violation action (fire-and-forget style — failures are
    logged and swallowed, matching the Scoring Service SNS-publish failure-isolation
    precedent: the 400 rejection to the caller is the source of truth and must never be
    blocked or altered by a violation-logging side-channel issue)."""
    if not ID_SERVICE_FUNCTION:
        return
    try:
        ws = _normalize_write_source(body)
        caller_identity = ws.get("provider") or "unknown"
        _get_lambda_client().invoke(
            FunctionName=ID_SERVICE_FUNCTION,
            InvocationType="Event",  # fire-and-forget; never blocks the 400 response
            Payload=json.dumps({
                "action": "record_violation",
                "caller_identity": caller_identity,
                "record_type": record_type,
                "detail": f"forbidden field '{field}' present in create payload",
            }).encode("utf-8"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("[L06] ID boundary violation trust-score notify failed: %s", exc)

# ---------------------------------------------------------------------------
# ENC-TSK-H47 / B63 Phase 2B — Scoring Service extraction.
# When enable_scoring_service_extraction is ON, the standalone, SNS-triggered Scoring Service is the
# SOLE owner of lesson constitutional scoring: tracker_mutation writes the lesson with
# scoring_status='pending' (skipping the inline pillar_composite/resonance computation) and publishes
# a {lesson.scoring.requested} message to the lesson-scoring SNS topic; the Scoring Service computes
# the scores asynchronously and flips scoring_status -> 'scored'. When OFF (default), the inline
# scoring below runs exactly as before and the lesson is written already-scored — that is the
# zero-behavior-change rollback path (ENC-TSK-H47 AC #3). Unlike the synchronous, FAIL-CLOSED
# Lifecycle Service (H46), this path is async and best-effort about the SNS publish: the lesson
# write is the source of truth and is never blocked by a notification-side-channel failure (a
# missed publish leaves the lesson scoring_status='pending' for a re-drive, never an unscored task
# CRUD failure). The flag is read at request time so an AppConfig toggle takes effect — and rolls
# back — without a redeploy.
# ---------------------------------------------------------------------------
LESSON_SCORING_TOPIC_ARN = os.environ.get("LESSON_SCORING_TOPIC_ARN", "")
_sns_client = None


def _get_sns():
    global _sns_client
    if _sns_client is None:
        _sns_client = boto3.client(
            "sns",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 2, "mode": "standard"}),
        )
    return _sns_client


def _scoring_service_enabled() -> bool:
    """Read the AppConfig flag at request time (independent toggle + rollback, ENC-TSK-H47 AC #3)."""
    return _appconfig_flag("enable_scoring_service_extraction", env_fallback="ENABLE_SCORING_SERVICE")


def _publish_lesson_scoring_request(project_id: str, record_id: str, item_id: str,
                                    pillar_scores: Dict[str, float]) -> bool:
    """Publish a {lesson.scoring.requested} SNS message so the Scoring Service can score the lesson
    asynchronously. Best-effort: returns True on publish, False otherwise. Failures are logged and
    swallowed — the lesson DynamoDB write is the source of truth and must never be blocked by an SNS
    side-channel failure (the lesson simply stays scoring_status='pending' until a re-drive)."""
    if not LESSON_SCORING_TOPIC_ARN:
        logger.error("[H47] LESSON_SCORING_TOPIC_ARN not configured; lesson %s left scoring_status=pending", record_id)
        return False
    payload = {
        "event_type": "lesson.scoring.requested",
        "schema_version": 1,
        "project_id": project_id,
        "record_id": record_id,
        "item_id": item_id,
        "pillar_scores": pillar_scores,
    }
    try:
        _get_sns().publish(
            TopicArn=LESSON_SCORING_TOPIC_ARN,
            Subject=f"Lesson scoring requested: {item_id}"[:100],
            Message=json.dumps(payload),
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("[H47] lesson scoring SNS publish failed for %s: %s", record_id, exc)
        return False

# Valid record types and their closed/default statuses
_RECORD_TYPES = {"task", "issue", "feature", "lesson", "plan", "generation"}
_CLOSED_STATUS = {"task": "closed", "issue": "closed", "feature": "completed", "lesson": "archived", "plan": "complete", "generation": "archived"}
_DEFAULT_STATUS = {"task": "open", "issue": "open", "feature": "planned", "lesson": "draft", "plan": "drafted", "generation": "drafted"}
_TRACKER_TYPE_SUFFIX = {"task": "TSK", "issue": "ISS", "feature": "FTR", "lesson": "LSN", "plan": "PLN", "generation": "GEN", "escalation": "ESC"}
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan", "GEN": "generation", "ESC": "escalation"}

# Category validation per record type
_VALID_CATEGORIES = {
    "feature": {"epic", "capability", "enhancement", "infrastructure"},
    "task": {"implementation", "investigation", "documentation", "maintenance", "validation"},
    "issue": {"bug", "debt", "risk", "security", "performance"},
    "lesson": {"pattern", "failure_mode", "resolution_pathway", "opportunity", "principle", "intention"},
    "plan": {"strategic", "tactical", "operational", "remediation"},
    "generation": {"platform"},
}
_VALID_PRIORITIES = ("P0", "P1", "P2", "P3")
# ENC-ISS-145: Use canonical matrix as sole source of truth for transition types and strictness.
# Local duplicates removed — all references now point to transition_type_matrix imports.
_VALID_TRANSITION_TYPES = tuple(sorted(VALID_TRANSITION_TYPES))
_STRICTNESS_RANK = STRICTNESS_RANK

# Status transition rules — strictly sequential, one step forward only (ENC-FTR-022)
# ENC-FTR-035: 'deployed' replaced by deploy-init / deploy-success + coding-updates re-entry arc.
# Forward path: ... merged-main → deploy-init → deploy-success → closed
# Re-entry arc:  deploy-success → coding-updates → coding-complete → ... → deploy-init
# Migration arc: deployed → deploy-success (ENC-TSK-704: migrates legacy 'deployed' tasks; remove after migration)
_VALID_TRANSITIONS = {
    "feature": {
        "planned": {"in-progress"},
        "in-progress": {"completed"},
        "completed": {"production"},
        "production": {"deprecated"},
    },
    "task": {
        "open": {"in-progress"},
        "in-progress": {"coding-complete"},
        "coding-complete": {"committed"},
        "committed": {"pr"},
        "pr": {"merged-main"},
        # backward-compat: tasks with legacy status "pushed" are treated as "pr" on read
        "merged-main": {"deploy-init"},
        "deploy-init": {"deploy-success"},
        "deploy-success": {"closed", "coding-updates"},
        "coding-updates": {"coding-complete"},
        "deployed": {"deploy-success"},  # ENC-TSK-704 migration arc — remove after all deployed→deploy-success migration completes
    },
    "issue": {
        "open": {"in-progress", "closed"},
        "in-progress": {"closed"},
    },
    "lesson": {
        "draft": {"proposed"},
        "proposed": {"accepted"},
        "accepted": {"active"},
        "active": {"superseded", "archived"},
        "superseded": {"archived"},
    },
    "plan": {
        "drafted": {"started"},
        "started": {"complete", "incomplete"},
        "incomplete": {"started"},
    },
}

# Backward (revert) transitions — allowed only with transition_evidence.revert_reason
_REVERT_TRANSITIONS = {
    "feature": {
        "in-progress": {"planned"},
        "completed": {"in-progress"},
        "production": {"completed"},
        "deprecated": {"production"},
    },
    "task": {
        "in-progress": {"open"},
        "coding-complete": {"in-progress"},
        "committed": {"coding-complete"},
        "pr": {"committed"},
        "merged-main": {"pr"},
        "deploy-init": {"merged-main"},
        "coding-updates": {"deploy-success"},
    },
    "issue": {
        "in-progress": {"open"},
    },
    "lesson": {
        "proposed": {"draft"},
        "accepted": {"proposed"},
        "active": {"accepted"},
    },
    "plan": {
        "started": {"incomplete"},
    },
}

# ---------------------------------------------------------------------------
# ENC-FTR-121 / ENC-TSK-J68 — Escalations: Human-Gated Mutation Override
# Surface (DOC-5B888FCA43B8), Phase 1: entity + request/read surface.
#
# Escalation items live in the EXISTING tracker table (record_id =
# "escalation#ENC-ESC-…"; no new table or GSI — Channel B purity). They are
# deliberately NOT a member of _RECORD_TYPES: the generic record CRUD,
# checkout, lifecycle, and tracker.set surfaces cannot touch them. The
# escalation FSM below is enforced normally — escalations are not themselves
# escalatable (§5.2). ENC-ESC IDs are minted by _next_record_id via the
# "escalation" entry in _TRACKER_TYPE_SUFFIX (ID Boundary Rule holds).
# ---------------------------------------------------------------------------
ENABLE_ESCALATION_PRIMITIVE = _appconfig_flag(
    "enable_escalation_primitive",
    env_fallback="ENABLE_ESCALATION_PRIMITIVE",
    default=True,
)

# §5.2 escalation status lifecycle. `failed` is terminal: a corrective
# request is a NEW escalation (exactly-once semantics stay trivial).
_ESCALATION_FSM = {
    "requested": {"approved", "denied", "denied_with_guidance"},
    "approved": {"applying"},
    "applying": {"applied", "failed"},
    "denied": set(),
    "denied_with_guidance": set(),
    "applied": set(),
    "failed": set(),
}
_ESCALATION_STATUSES = set(_ESCALATION_FSM.keys())
_ESCALATION_TARGET_TYPES = {"task", "issue", "feature"}


def _statuses_for_record_type(record_type: str) -> set:
    """Full dictionary-legal status universe for a record type.

    Derived from the normal transition graph (keys ∪ targets) plus the
    create-time default and the ENC-FTR-115 `superseded` alt-terminal.
    Used by direct_state_override validation, which checks status LEGALITY
    only — path legality is deliberately unchecked (§5.3): the path is
    precisely what io's approval overrides.
    """
    graph = _VALID_TRANSITIONS.get(record_type, {})
    statuses = set(graph.keys())
    for targets in graph.values():
        statuses |= set(targets)
    default_status = _DEFAULT_STATUS.get(record_type)
    if default_status:
        statuses.add(default_status)
    if record_type in ("task", "issue", "lesson"):
        statuses.add("superseded")
    return statuses


def _validate_deploy_arc_change_payload(payload: Dict, target_record_type: str) -> str:
    """§5.3 handler 1: request-time validation for deploy_arc_change."""
    if target_record_type != "task":
        return (
            "deploy_arc_change targets must be task records; "
            f"'{target_record_type}' records have no deploy arc."
        )
    new_arc = str(payload.get("new_deploy_arc_type") or "").strip()
    if not new_arc:
        return "Field 'payload.new_deploy_arc_type' is required for deploy_arc_change."
    if new_arc not in VALID_TRANSITION_TYPES:
        return (
            f"Invalid new_deploy_arc_type '{new_arc}'. "
            f"Allowed: {sorted(VALID_TRANSITION_TYPES)}"
        )
    return ""


def _validate_direct_state_override_payload(payload: Dict, target_record_type: str) -> str:
    """§5.3 handler 2: request-time validation for direct_state_override.

    Confirms target_status is dictionary-legal for the record type. Path
    legality is deliberately NOT checked here — that is what io approval
    overrides.
    """
    target_status = str(payload.get("target_status") or "").strip()
    if not target_status:
        return "Field 'payload.target_status' is required for direct_state_override."
    legal = _statuses_for_record_type(target_record_type)
    if target_status not in legal:
        return (
            f"Invalid target_status '{target_status}' for record type "
            f"'{target_record_type}'. Allowed: {sorted(legal)}"
        )
    field_values = payload.get("field_values")
    if field_values is not None and not isinstance(field_values, dict):
        return "Field 'payload.field_values' must be an object when supplied."
    return ""


def _escalation_waivable_fields(target: Dict, target_status: str) -> list:
    """Required-for-state fields the waiver sentinel covers (§5.6).

    Derived from the canonical transition matrix gate contracts: the fields a
    record landing in target_status would normally have to prove. Fields the
    escalation payload supplies (or the record already carries) are written
    verbatim; the rest get the escalation_waived sentinel — never silent null.
    """
    record_type = str(target.get("record_type") or "")
    arc = str(target.get("transition_type") or "github_pr_deploy")
    fields = []
    if record_type == "task":
        if target_status == "committed":
            fields.append("commit_sha")
        elif target_status == "deploy-success":
            gate = DEPLOY_SUCCESS_EVIDENCE.get(arc)
            if gate:
                fields.append(gate["evidence_key"])
        elif target_status == "closed":
            gate = CLOSED_EVIDENCE.get(arc)
            if gate:
                fields.append(gate["evidence_key"])
    elif record_type == "issue" and target_status == "closed":
        fields.append("evidence")
    return fields


def _escalation_waiver_sentinel(escalation_id: str, now: str) -> Dict:
    """§5.6 sentinel in DynamoDB attribute shape: known-absent by human decision."""
    return {"M": {
        "escalation_waived": {"BOOL": True},
        "escalation_id": {"S": escalation_id},
        "waived_at": {"S": now},
    }}


def _escalation_provenance_note(escalation: Dict, before: Dict, after: Dict,
                                waived: list) -> str:
    """Structured worklog description for the target record (§5.5 step 6)."""
    requested_by = escalation.get("requested_by") or {}
    approved_by = escalation.get("approved_by") or {}
    approver = approved_by.get("email") or approved_by.get("sub") or "io"
    return (
        f"[ESCALATION-APPLIED] {escalation.get('item_id')} "
        f"({escalation.get('mutation_type')}) "
        f"requested_by={requested_by.get('session_id', 'unknown')} "
        f"approved_by={approver} "
        f"before={json.dumps(before, default=str)} "
        f"after={json.dumps(after, default=str)} "
        f"waived={json.dumps(waived)}"
    )


def _apply_deploy_arc_change(project_id: str, escalation: Dict, target: Dict) -> Dict:
    """§5.3 handler 1 apply: rewrite the task's deploy arc in place.

    Single atomic UpdateItem. Checkout fields are deliberately untouched — an
    active checkout survives. checkout_transition_type (the arc snapshot the
    checkout service gates against) is rewritten alongside transition_type
    when present, which is what recomputes the remaining-lifecycle
    expectations. The ENC-FTR-060 sealing validator in _handle_update_field
    is NOT modified — this dedicated entry point applies io's approved
    override with escalation provenance as a write precondition.
    """
    new_arc = str((escalation.get("payload") or {}).get("new_deploy_arc_type") or "").strip()
    if new_arc not in VALID_TRANSITION_TYPES:
        raise ValueError(f"payload.new_deploy_arc_type '{new_arc}' is not a legal arc type")
    target_sk = f"{target.get('record_type')}#{target.get('item_id')}"
    escalation_id = str(escalation.get("item_id") or "")
    now = _now_z()
    before = {
        "transition_type": target.get("transition_type"),
        "checkout_transition_type": target.get("checkout_transition_type"),
        "checkout_state": target.get("checkout_state"),
    }
    after = {
        "transition_type": new_arc,
        "checkout_transition_type": new_arc if target.get("checkout_transition_type") else target.get("checkout_transition_type"),
        "checkout_state": target.get("checkout_state"),
    }
    note = _escalation_provenance_note(escalation, before, after, [])

    update_parts = [
        "#tt = :arc",
        "updated_at = :now",
        "last_update_note = :note",
        "sync_version = if_not_exists(sync_version, :zero) + :one",
        "history = list_append(if_not_exists(history, :empty), :hentry)",
        "escalation_provenance = list_append(if_not_exists(escalation_provenance, :empty), :esc)",
    ]
    names = {"#tt": "transition_type"}
    values = {
        ":arc": _ser_s(new_arc),
        ":now": _ser_s(now),
        ":note": _ser_s(f"Deploy arc changed via escalation {escalation_id}"),
        ":zero": {"N": "0"},
        ":one": {"N": "1"},
        ":empty": {"L": []},
        ":hentry": {"L": [{"M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(note),
        }}]},
        ":esc": {"L": [_ser_s(escalation_id)]},
    }
    if target.get("checkout_transition_type"):
        update_parts.append("checkout_transition_type = :arc")

    _get_ddb().update_item(
        TableName=DYNAMODB_TABLE,
        Key={"project_id": _ser_s(project_id), "record_id": _ser_s(target_sk)},
        UpdateExpression="SET " + ", ".join(update_parts),
        ConditionExpression="attribute_exists(record_id)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    return {"before": before, "after": after, "waived_fields": []}


def _apply_direct_state_override(project_id: str, escalation: Dict, target: Dict) -> Dict:
    """§5.3 handler 2 apply: land the record in target_status regardless of
    path legality, with supplied field_values verbatim and §5.6 waiver
    sentinels on every unsupplied required-for-state field. Closures set
    escalated_closure=true (ENC-FTR-118 metric filter) and, for tasks,
    increment closed_count for organic-gate parity. Single atomic UpdateItem —
    a handler exception leaves the target untouched (no-partial-write).
    """
    payload = escalation.get("payload") or {}
    target_status = str(payload.get("target_status") or "").strip()
    field_values = payload.get("field_values") or {}
    if not target_status:
        raise ValueError("payload.target_status is required")
    record_type = str(target.get("record_type") or "")
    if target_status not in _statuses_for_record_type(record_type):
        raise ValueError(
            f"target_status '{target_status}' is not dictionary-legal for {record_type}")

    target_sk = f"{record_type}#{target.get('item_id')}"
    escalation_id = str(escalation.get("item_id") or "")
    now = _now_z()
    before = {"status": target.get("status")}
    waivable = _escalation_waivable_fields(target, target_status)
    waived = [
        field for field in waivable
        if field not in field_values and not target.get(field)
    ]
    is_closure = target_status == _CLOSED_STATUS.get(record_type, "closed")
    after = {"status": target_status, "field_values": sorted(field_values.keys()),
             "escalated_closure": is_closure}
    note = _escalation_provenance_note(escalation, before, after, waived)

    update_parts = [
        "#st = :target_status",
        "updated_at = :now",
        "last_update_note = :note",
        "sync_version = if_not_exists(sync_version, :zero) + :one",
        "history = list_append(if_not_exists(history, :empty), :hentry)",
        "escalation_provenance = list_append(if_not_exists(escalation_provenance, :empty), :esc)",
    ]
    names = {"#st": "status"}
    values = {
        ":target_status": _ser_s(target_status),
        ":now": _ser_s(now),
        ":note": _ser_s(f"Status override to '{target_status}' via escalation {escalation_id}"),
        ":zero": {"N": "0"},
        ":one": {"N": "1"},
        ":empty": {"L": []},
        ":hentry": {"L": [{"M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("worklog"),
            "description": _ser_s(note),
        }}]},
        ":esc": {"L": [_ser_s(escalation_id)]},
    }
    for index, (field, value) in enumerate(sorted(field_values.items())):
        name_key = f"#fv{index}"
        value_key = f":fv{index}"
        update_parts.append(f"{name_key} = {value_key}")
        names[name_key] = str(field)
        values[value_key] = _ser_value(value)
    for index, field in enumerate(waived):
        name_key = f"#wv{index}"
        value_key = f":wv{index}"
        update_parts.append(f"{name_key} = {value_key}")
        names[name_key] = field
        values[value_key] = _escalation_waiver_sentinel(escalation_id, now)
    update_expression = "SET " + ", ".join(update_parts)
    if is_closure:
        update_parts.append("escalated_closure = :esc_closure")
        values[":esc_closure"] = {"BOOL": True}
        update_expression = "SET " + ", ".join(update_parts)
        if record_type == "task":
            update_expression += " ADD closed_count :one_count"
            values[":one_count"] = {"N": "1"}

    _get_ddb().update_item(
        TableName=DYNAMODB_TABLE,
        Key={"project_id": _ser_s(project_id), "record_id": _ser_s(target_sk)},
        UpdateExpression=update_expression,
        ConditionExpression="attribute_exists(record_id)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    return {"before": before, "after": after, "waived_fields": waived}


# §5.3 mutation handler registry (v4-shaped). Each handler grows three
# functions across the feature: validate_payload (request time, Ph1/ENC-TSK-J68),
# render_diff (approval time, Ph3/ENC-TSK-J70), and apply (invoked ONLY by
# applyEscalatedMutation after io approval, Ph2/ENC-TSK-J69). Adding a third
# mutation type is a registry entry plus handler, not an architectural change.
_ESCALATION_MUTATION_HANDLERS = {
    "deploy_arc_change": {
        "validate_payload": _validate_deploy_arc_change_payload,
        "apply": _apply_deploy_arc_change,
    },
    "direct_state_override": {
        "validate_payload": _validate_direct_state_override_payload,
        "apply": _apply_direct_state_override,
    },
}


# ENC-FTR-076 / ENC-TSK-E08: Component lifecycle transitions.
# Components are registered in the component-registry table (separate from
# the tracker). These maps colocate the lifecycle rules with the other
# record-type transition maps following the ENC-FTR-052 Lesson precedent so
# future validators can share a single source of truth. The coordination_api
# handler enforces these maps; tracker_mutation retains them for parity with
# subsequent lifecycle-gating work.
_VALID_COMPONENT_LIFECYCLE_TRANSITIONS = {
    "proposed": {"approved", "rejected"},
    "approved": {"active", "archived"},
    "active": {"deprecated", "archived"},
    "rejected": set(),          # terminal
    "deprecated": {"archived"},
    "archived": set(),          # terminal
}

_REVERT_COMPONENT_LIFECYCLE_TRANSITIONS = {
    "approved": {"proposed"},
    "active": {"approved"},
    "deprecated": {"active"},
}

# ---------------------------------------------------------------------------
# ENC-FTR-054: Constitutional scoring (canonical: coordination_api/lambda_function.py:7247-7350)
# Pure functions copied here so every write path gets atomic scoring during PutItem.
# ---------------------------------------------------------------------------

_LESSON_PILLAR_WEIGHTS = {
    "efficiency": 0.25,
    "human_protection": 0.30,
    "intention": 0.20,
    "alignment": 0.25,
}

_VIBE_BOARD_ANCHORS = {
    "convergence": 0.12, "will": 0.10, "flow": 0.10, "play": 0.08,
    "surrender": 0.10, "force": 0.08, "balance": 0.12, "love": 0.10,
    "resonance": 0.12, "telemetry": 0.08,
}

_REQUIRED_PILLARS = {"efficiency", "human_protection", "intention", "alignment"}

# ENC-TSK-D77: Gate thresholds for lesson status transitions.
# Each target status specifies minimum metric values a lesson must meet.
_LESSON_TRANSITION_GATES = {
    "proposed": {"min_evidence_chain": 1},
    "accepted": {"min_pillar_composite": 0.4, "min_resonance": 0.3},
    "active": {
        "min_pillar_composite": 0.6,
        "min_resonance": 0.5,
        "min_confidence": 0.6,
        "min_evidence_chain": 2,
    },
}


def _compute_lesson_pillar_composite(pillar_scores):
    """Weighted pillar composite: 0.25*eff + 0.30*hp + 0.20*int + 0.25*aln."""
    composite = 0.0
    for pillar, weight in _LESSON_PILLAR_WEIGHTS.items():
        composite += weight * max(0.0, min(1.0, float(pillar_scores.get(pillar, 0.0))))
    return round(composite, 4)


def _compute_resonance_score(pillar_scores, anchor_alignments=None):
    """Vibe board resonance with anti-pattern penalties. Returns [0.0, 1.0]."""
    if anchor_alignments:
        raw = sum(w * max(0.0, min(1.0, float(anchor_alignments.get(word, 0.0))))
                  for word, w in _VIBE_BOARD_ANCHORS.items())
    else:
        eff = float(pillar_scores.get("efficiency", 0.0))
        hp = float(pillar_scores.get("human_protection", 0.0))
        intent = float(pillar_scores.get("intention", 0.0))
        align = float(pillar_scores.get("alignment", 0.0))
        anchor_alignments = {
            "convergence": (eff + align) / 2, "will": intent,
            "flow": (eff + intent) / 2, "play": align * 0.8,
            "surrender": hp * 0.9, "force": eff * 0.7,
            "balance": (eff + hp + intent + align) / 4, "love": hp,
            "resonance": align, "telemetry": (intent + eff) / 2,
        }
        raw = sum(w * max(0.0, min(1.0, anchor_alignments.get(word, 0.0)))
                  for word, w in _VIBE_BOARD_ANCHORS.items())

    # Anti-pattern penalties
    if float(anchor_alignments.get("force", 0)) > 0.7 and float(anchor_alignments.get("surrender", 0)) < 0.3:
        raw *= 0.5
    if float(anchor_alignments.get("will", 0)) > 0.7 and float(anchor_alignments.get("flow", 0)) < 0.3:
        raw *= 0.7
    if float(pillar_scores.get("efficiency", 0)) > 0.8 and float(anchor_alignments.get("love", 0)) < 0.2:
        raw *= 0.6
    if float(anchor_alignments.get("convergence", 0)) > 0.8 and float(anchor_alignments.get("play", 0)) < 0.2:
        raw *= 0.8

    return round(max(0.0, min(1.0, raw)), 4)


def _validate_pillar_scores(raw_pillar_scores, record_type="lesson"):
    """Validate pillar_scores dict. Returns (parsed_dict, error_response_or_None)."""
    if not isinstance(raw_pillar_scores, dict):
        return None, _tracker_create_validation_error(
            "Lesson creation requires 'pillar_scores' (object with efficiency, human_protection, intention, alignment, each in [0.0, 1.0]).",
            record_type=record_type,
            missing_required_fields=["pillar_scores"],
            governed_rules=[
                f"Pillar scores must be float in [0.0, 1.0]. Required pillars: {sorted(_LESSON_PILLAR_WEIGHTS.keys())}.",
                f"Gate thresholds: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                "pillar_scores is required on lesson creation (ENC-FTR-054).",
            ],
        )
    missing = _REQUIRED_PILLARS - set(raw_pillar_scores.keys())
    if missing:
        return None, _tracker_create_validation_error(
            f"pillar_scores missing required keys: {sorted(missing)}. All four pillars are required.",
            record_type=record_type,
            governed_rules=[
                f"Pillar scores must be float in [0.0, 1.0]. Required pillars: {sorted(_LESSON_PILLAR_WEIGHTS.keys())}.",
                f"Gate thresholds: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                "pillar_scores must include: efficiency, human_protection, intention, alignment.",
            ],
        )
    parsed = {}
    for pillar in _REQUIRED_PILLARS:
        try:
            val = float(raw_pillar_scores[pillar])
        except (TypeError, ValueError):
            return None, _tracker_create_validation_error(
                f"pillar_scores.{pillar} must be a number in [0.0, 1.0]. Got: {raw_pillar_scores[pillar]!r}",
                record_type=record_type,
                governed_rules=[
                    f"Pillar scores must be float in [0.0, 1.0]. Required pillars: {sorted(_LESSON_PILLAR_WEIGHTS.keys())}.",
                    f"Gate thresholds: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                    f"pillar_scores.{pillar} must be numeric in [0.0, 1.0].",
                ],
            )
        if val < 0.0 or val > 1.0:
            return None, _tracker_create_validation_error(
                f"pillar_scores.{pillar} = {val} is out of range [0.0, 1.0].",
                record_type=record_type,
                governed_rules=[
                    f"Pillar scores must be float in [0.0, 1.0]. Required pillars: {sorted(_LESSON_PILLAR_WEIGHTS.keys())}.",
                    f"Gate thresholds: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                    f"pillar_scores.{pillar} must be in [0.0, 1.0].",
                ],
            )
        parsed[pillar] = val
    if all(v == 0.0 for v in parsed.values()):
        return None, _tracker_create_validation_error(
            "All pillar_scores are zero. At least one pillar must be > 0 for constitutional evaluation.",
            record_type=record_type,
            governed_rules=[
                f"Pillar scores must be float in [0.0, 1.0]. Required pillars: {sorted(_LESSON_PILLAR_WEIGHTS.keys())}.",
                f"Gate thresholds: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                "At least one pillar score must be > 0 (ENC-FTR-054 AC1).",
            ],
        )
    return parsed, None


# EventBridge event config for reopen notifications
EVENT_BUS = os.environ.get("EVENT_BUS", "default")
EVENT_SOURCE = "enceladus.tracker"
# ENC-FTR-121 Ph5 / ENC-TSK-J72: SNS topic for io's escalation email (§5.8).
# Reuses the existing devops-feed-alerts topic (subject-prefixed [ESCALATION]);
# empty/unset ARN disables publishing (logged skip — never fails the write).
ESCALATION_ALERTS_TOPIC_ARN = os.environ.get("ESCALATION_ALERTS_TOPIC_ARN", "")
EVENT_DETAIL_TYPE_REOPENED = "record.status.reopened"
# ENC-FTR-111 / ENC-TSK-H83: Artifact-Genesis telemetry for an auto_walk_opt_out latch
# (feeds ENC-TSK-B66 / the T5 ARC_WALK telemetry consumer).
EVENT_DETAIL_TYPE_OPT_OUT_LATCHED = "record.auto_walk_opt_out.latched"
# ENC-FTR-111 / ENC-TSK-H86 (T5): the matching CLEAR-side telemetry. DOC-078C57FC1BE6 §10 requires
# BOTH opt_out latch AND clear events to feed the ENC-TSK-B66 observability dashboard. The latch
# (auto-set on a human walk-back, H83) emits EVENT_DETAIL_TYPE_OPT_OUT_LATCHED; an explicit
# human/agent tracker.set(auto_walk_opt_out=...) emits latched-or-cleared via _emit_opt_out_state_event.
EVENT_DETAIL_TYPE_OPT_OUT_CLEARED = "record.auto_walk_opt_out.cleared"
# ENC-TSK-I09 (Dedup P5): io-reviewable audit feed for every MECHANICAL arc-walker
# auto-merge. One event streams per certificate-certified T-HIGH supersession the
# walker executes (DOC-DF651F07D5C2 §8 — the kill-switch + audit-feed rail).
EVENT_DETAIL_TYPE_AUTO_MERGED = "record.dedup.auto_merged"
# ENC-TSK-H85 / ENC-FTR-111 Phase 1: Artifact-Genesis audit feed for every MECHANICAL gate the
# synchronous inline arc-walker crosses on its own (DOC-078C57FC1BE6 §8/§10 — no silent mutations).
EVENT_DETAIL_TYPE_ARC_WALK = "record.arc_walk.advanced"

# ENC-FTR-111 / ENC-TSK-H83 — Universal Arc-Walker circuit breaker.
# Reserved write_source identity the (future, FTR-111 Phase 1 core / T4) arc-walker writes under.
# The walker may observe a latched circuit breaker, but is STRUCTURALLY forbidden from CLEARING it.
ARC_WALKER_ACTOR = "system:arc-walker"

# Task lifecycle ordinal ranks — mirror of lifecycle_service.STATUS_RANK / checkout_service.
# Used to classify a human task transition as non-forward (regression). 'coding-updates' is the
# deploy-success re-entry case and has no forward rank; it is handled explicitly.
_TASK_STATUS_RANK: Dict[str, int] = {
    "open": 0, "in-progress": 1, "coding-complete": 2, "committed": 3, "pr": 4,
    "merged-main": 5, "deploy-init": 6, "deploy-success": 7, "closed": 8,
}

# Type segment mapping for SK construction
_TYPE_SEG_TO_SK_PREFIX = {"task": "task", "issue": "issue", "feature": "feature", "lesson": "lesson", "plan": "plan"}

# Counter management
_TRACKER_COUNTER_PREFIX = "counter#"
_TRACKER_CREATE_MAX_ATTEMPTS = 32

# Relation fields
_RELATION_ID_FIELDS = {"related_task_ids", "related_issue_ids", "related_feature_ids"}

# ENC-TSK-F41 / DOC-546B896390EA §5: server-side-only counter fields on task
# records. Incremented atomically by the tracker lifecycle handler (closed_count
# on every task->closed transition; checkout_count on every successful
# checkout.task). Never writable by agent / io / coordination callers — any
# direct PATCH or create attempt is rejected with HTTP 400 RESERVED_FIELD.
# Feeds the FTR-076 v2 edge-immutability gates (DESIGNS / IMPLEMENTS).
_F41_RESERVED_COUNTER_FIELDS = frozenset({"closed_count", "checkout_count"})

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# AWS clients (lazy init)
# ---------------------------------------------------------------------------

_ddb = None
_events_client = None


def _get_ddb():
    global _ddb
    if _ddb is None:
        _ddb = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb


def _stamp_version_seq_on_create_item(item: Dict[str, Dict[str, str]]) -> None:
    if not _VERSION_SEQ_AVAILABLE:
        return
    seq = allocate_version_seq(_get_ddb(), DYNAMODB_TABLE)
    item.update(version_seq_attr(seq))


def _version_seq_update_parts() -> Tuple[str, Dict[str, Dict[str, str]]]:
    if not _VERSION_SEQ_AVAILABLE:
        return "", {}
    seq = allocate_version_seq(_get_ddb(), DYNAMODB_TABLE)
    return version_seq_update_clause(seq)


def _get_events():
    global _events_client
    if _events_client is None:
        _events_client = boto3.client("events")
    return _events_client


_sns_client = None


def _get_sns():
    global _sns_client
    if _sns_client is None:
        _sns_client = boto3.client("sns", region_name=DYNAMODB_REGION)
    return _sns_client


def _notify_escalation_event(kind: str, escalation_id: str, target_record_id: str,
                             mutation_type: str, session_id: str, note: str = "") -> None:
    """§5.8 io notification: best-effort SNS publish, failure-isolated by contract.

    An SNS error (or an unset topic ARN) is logged and swallowed — notification
    must never fail the escalation write. Subject is [ESCALATION]-prefixed for
    inbox routing; expected volume is tens/month, inside the SNS email free
    tier (sub-dollar budget).
    """
    if not ESCALATION_ALERTS_TOPIC_ARN:
        logger.info("escalation notify skipped (%s %s): ESCALATION_ALERTS_TOPIC_ARN unset",
                    kind, escalation_id)
        return
    try:
        lines = [
            f"Escalation {kind}: {escalation_id}",
            f"Target: {target_record_id}",
            f"Mutation: {mutation_type}",
            f"Requested by: {session_id}",
        ]
        if note:
            lines.append(f"Note: {note[:500]}")
        lines.append("Review queue: PWA menu → Escalations")
        _get_sns().publish(
            TopicArn=ESCALATION_ALERTS_TOPIC_ARN,
            Subject=f"[ESCALATION] {kind}: {escalation_id} ({mutation_type})"[:100],
            Message="\n".join(lines),
        )
    except Exception as exc:  # noqa: BLE001 — §5.8 failure isolation
        logger.error("escalation notify failed (%s %s): %s", kind, escalation_id, exc)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _now_z() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ser_s(val: str) -> Dict:
    return {"S": str(val)}


def _ser_value(val: Any) -> Dict:
    """Serialize supported Python values to DynamoDB typed format."""
    if isinstance(val, dict):
        return {"M": {str(k): _ser_value(v) for k, v in val.items()}}
    if isinstance(val, list):
        return {"L": [_ser_value(v) for v in val]}
    if isinstance(val, bool):
        return {"BOOL": val}
    if isinstance(val, (int, float)):
        return {"N": str(val)}
    if val is None:
        return {"NULL": True}
    return _ser_s(str(val))


def _deser_val(v: Dict) -> Any:
    """Deserialize a single DynamoDB attribute value."""
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
    """Deserialize a full DynamoDB item."""
    return {k: _deser_val(v) for k, v in item.items()}


def _normalize_write_source(body: dict, claims: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Normalize write_source payload from PWA and MCP clients.

    Supports both nested write_source maps and legacy top-level provider fields.
    When JWT claims are available, defaults provider to claims.sub for user-attributed writes.
    """
    if not isinstance(body, dict):
        return {
            "channel": "mutation_api",
            "provider": "",
            "dispatch_id": "",
            "coordination_request_id": "",
        }

    raw_ws = body.get("write_source")
    ws = raw_ws if isinstance(raw_ws, dict) else {}
    auth_mode = str(claims.get("auth_mode", "")) if isinstance(claims, dict) else ""

    channel = str(ws.get("channel") or "").strip()
    if not channel:
        channel = "mcp_server" if auth_mode == "internal-key" else "mutation_api"

    provider = str(ws.get("provider") or body.get("provider") or "").strip()
    if not provider and isinstance(claims, dict):
        provider = str(claims.get("sub") or "").strip()

    dispatch_id = str(ws.get("dispatch_id") or body.get("dispatch_id") or "").strip()
    coordination_request_id = str(
        ws.get("coordination_request_id") or body.get("coordination_request_id") or ""
    ).strip()

    normalized = {
        "channel": channel,
        "provider": provider,
        "dispatch_id": dispatch_id,
        "coordination_request_id": coordination_request_id,
    }
    body["write_source"] = normalized
    return normalized


def _build_write_source(body: dict) -> Dict[str, Any]:
    """Build a structured write_source map for DynamoDB attribution."""
    ws = _normalize_write_source(body)
    return {
        "M": {
            "channel": _ser_s(ws.get("channel", "mutation_api")),
            "provider": _ser_s(ws.get("provider", "")),
            "dispatch_id": _ser_s(ws.get("dispatch_id", "")),
            "coordination_request_id": _ser_s(ws.get("coordination_request_id", "")),
            "timestamp": _ser_s(_now_z()),
        }
    }


def _write_source_note_suffix(body: dict) -> str:
    """Build optional suffix for last_update_note with provider context."""
    ws = _normalize_write_source(body)
    provider = ws.get("provider", "")
    dispatch_id = ws.get("dispatch_id", "")
    parts = []
    if provider:
        parts.append(f"provider={provider}")
    if dispatch_id:
        parts.append(f"dispatch={dispatch_id}")
    return f" [{', '.join(parts)}]" if parts else ""


def _is_conditional_check_failed(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


# ---------------------------------------------------------------------------
# SCI enforcement gate (ENC-ISS-441 Phase 3 / ENC-TSK-J93)
#
# Agent-origin mutations — requests presenting a minted ENC-SES-NNN id as
# write_source.provider — must carry a valid Session Claim ID (`sci` in the
# request body). SCI tokens are minted by coordination_api agent.claim
# (ENC-TSK-J92) into CHECKOUT_TOKENS_TABLE. Non-agent identities (github,
# system:arc-walker, Cognito subs/usernames, coordination_dispatch, ...) are
# out of gate scope and pass through unchanged, as do requests bearing
# X-Checkout-Service-Key: the checkout_service runs the same gate at its own
# edge (ENC-FTR-037 chain) and does not forward `sci` downstream.
# ---------------------------------------------------------------------------

# ENC-ISS-441 Ph3 ship date; sessions created before this instant are
# grandfathered and mutate without an SCI. Deliberately a module-level
# constant, NOT an env var — out-of-band env vars get stripped by full-env
# deploys (PLN-047 / ENC-LSN-053 Sev1 class).
SCI_ENFORCEMENT_EPOCH = "2026-07-02T12:00:00Z"

# ENC-ISS-441 / ENC-TSK-J96: terminal-state retirement nudge (part 3 of the io-designed
# session retirement lifecycle). Injected verbatim into terminal-state success envelopes;
# the acting agent either retires its session autonomously (scope exhausted) or surfaces
# the prompt to io. Exact io-specified text from the ENC-ISS-441 worklog.
RETIREMENT_PROMPT = (
    "Prompt the user if this session can now be retired, or retire the session if it "
    "is certain that the full scope of the current session assignment is complete."
)

# Final lifecycle states per record type (io design decision on ENC-ISS-441: task closed,
# issue closed, feature production/deprecated, plan complete). 'superseded' is set only by
# the supersession op, not a direct status write, so it never reaches this map.
_TERMINAL_STATUSES_BY_TYPE = {
    "task": {"closed"},
    "issue": {"closed"},
    "feature": {"production", "deprecated"},
    "plan": {"complete"},
}


def _is_terminal_transition(record_type: Any, value: Any) -> bool:
    """True when a status write lands a record in its final lifecycle state (ENC-TSK-J96)."""
    return (
        str(value or "").strip().lower()
        in _TERMINAL_STATUSES_BY_TYPE.get(str(record_type or "").strip().lower(), set())
    )


# J92 token shape: pk = "SCI-{uuid4_hex}"
_SCI_TOKEN_RE = re.compile(r"^SCI-[0-9a-f]{32}$")
# I37 minted session ids: ENC-SES-NNN (base-36, uppercase)
_AGENT_SESSION_ID_RE = re.compile(r"^ENC-SES-[0-9A-Z]+$")

_SCI_REMEDIATION = (
    "Obtain a Session Claim ID via coordination agent.claim (register->claim "
    "handshake, ENC-FTR-117 / ENC-ISS-441) and pass it as 'sci' on this request."
)


def _sci_error(failure_mode: str, message: str) -> Dict:
    """Build the 403 rejection envelope for an SCI gate failure (ENC-ISS-441)."""
    logger.warning("[ERROR] SCI gate rejection (%s): %s", failure_mode, message)
    return _error(
        403,
        f"{message} {_SCI_REMEDIATION}",
        code="SCI_REQUIRED",
        sci_failure_mode=failure_mode,
        remediation=_SCI_REMEDIATION,
    )


def _lookup_sci(sci_id: str) -> Optional[Dict]:
    """Look up the full SCI token item (J92 shape) from the checkout-tokens table."""
    try:
        resp = _get_ddb().get_item(
            TableName=CHECKOUT_TOKENS_TABLE,
            Key={"pk": {"S": sci_id}},
        )
    except Exception as exc:
        logger.warning("SCI token lookup failed for %s: %s", sci_id, exc)
        return None
    item = resp.get("Item")
    if not item:
        return None
    ttl_raw = item.get("ttl", {}).get("N")
    try:
        ttl_val = int(float(ttl_raw)) if ttl_raw is not None else 0
    except (TypeError, ValueError):
        ttl_val = 0
    return {
        "token_id": item.get("pk", {}).get("S", ""),
        "token_type": item.get("token_type", {}).get("S", ""),
        "session_id": item.get("session_id", {}).get("S", ""),
        "revoked": bool(item.get("revoked", {}).get("BOOL", False)),
        "ttl": ttl_val,
    }


def _get_agent_session(session_id: str) -> Optional[Dict]:
    """Fetch an agent-session record (ENC-FTR-117 store; key session_id)."""
    try:
        resp = _get_ddb().get_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
        )
    except Exception as exc:
        logger.warning("Agent-session lookup failed for %s: %s", session_id, exc)
        return None
    item = resp.get("Item")
    if not item:
        return None
    return {
        "session_id": item.get("session_id", {}).get("S", ""),
        "created_at": item.get("created_at", {}).get("S", ""),
        "status": item.get("status", {}).get("S", ""),
    }


def _touch_session_activity(session_id: str) -> None:
    """Refresh the session's last_activity_at + updated_at heartbeat (J83 pattern,
    extended by ENC-TSK-L35 to also stamp ``updated_at`` so the SES record's
    updated-time bumps on every session-requiring call, matching the
    updated_at convention every other tracker record type already exposes).

    Conditional on the session still being live (allocated/claimed); a retired
    or vanished session is a silent no-op — the touch must NEVER fail the
    mutation it rides on (ENC-ISS-441 / ENC-TSK-J93).
    """
    try:
        _get_ddb().update_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
            UpdateExpression="SET last_activity_at = :now, updated_at = :now",
            ConditionExpression=(
                "attribute_exists(session_id) AND (#st = :allocated OR #st = :claimed)"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":now": {"S": _now_z()},
                ":allocated": {"S": "allocated"},
                ":claimed": {"S": "claimed"},
            },
        )
    except Exception as exc:  # noqa: BLE001 — touch is best-effort by contract
        if _is_conditional_check_failed(exc):
            logger.info(
                "[INFO] last_activity_at touch skipped for %s (session not live)",
                session_id,
            )
        else:
            logger.warning(
                "[ERROR] last_activity_at touch failed for %s (continuing): %s",
                session_id, exc,
            )


def _validate_sci_gate(session_id: str, sci: Any) -> Optional[Dict]:
    """SCI enforcement gate (ENC-ISS-441 Phase 3 / ENC-TSK-J93).

    Callers invoke this only when ``session_id`` matches _AGENT_SESSION_ID_RE.
    Returns None when the mutation may proceed (grandfathered session or valid
    SCI), else the 403 rejection response naming the specific failure mode.

    ENC-TSK-L35: the session heartbeat/updated_at touch now happens in
    ``_sci_gate_for_request`` (the sole caller) BEFORE this function runs, so
    it fires unconditionally — including for grandfathered sessions and
    checkout-service-exempt requests that never reach this function at all.
    """
    # Step 1: the session must exist — a fabricated ENC-SES id must not bypass
    # the gate (fail closed).
    session = _get_agent_session(session_id)
    if session is None:
        return _sci_error(
            "unknown_session",
            f"Agent session '{session_id}' is not a registered session; "
            "mutation rejected (fail-closed).",
        )

    # Step 2: grandfather epoch gate — sessions created before the Phase 3
    # ship instant pass without an SCI (skip token validation entirely).
    # created_at uses the shared "%Y-%m-%dT%H:%M:%SZ" format, so lexicographic
    # comparison is a correct chronological compare (see agent_id_alloc).
    created_at = str(session.get("created_at") or "").strip()
    if created_at and created_at < SCI_ENFORCEMENT_EPOCH:
        return None

    # Step 3: token validation.
    sci_id = str(sci or "").strip()
    if not sci_id:
        return _sci_error(
            "missing_sci",
            f"Agent session '{session_id}' presented no Session Claim ID (sci); "
            "agent-origin mutations require a valid SCI.",
        )
    if not _SCI_TOKEN_RE.match(sci_id):
        return _sci_error(
            "unknown_sci",
            f"'{sci_id}' is not a valid Session Claim ID "
            "(expected format SCI-{32 hex chars}).",
        )
    token = _lookup_sci(sci_id)
    if token is None:
        return _sci_error(
            "unknown_sci",
            f"Session Claim ID '{sci_id}' is not recognized.",
        )
    if token.get("token_type") != "SCI":
        return _sci_error(
            "wrong_token_type",
            f"Token '{sci_id}' has token_type '{token.get('token_type')}'; "
            "only SCI tokens authorize agent-origin mutations.",
        )
    if token.get("revoked"):
        return _sci_error(
            "revoked_sci",
            f"Session Claim ID '{sci_id}' has been revoked.",
        )
    # DynamoDB native TTL deletion may lag, so also enforce expiry here.
    if int(token.get("ttl") or 0) <= int(time.time()):
        return _sci_error(
            "expired_sci",
            f"Session Claim ID '{sci_id}' has expired.",
        )
    if token.get("session_id") != session_id:
        return _sci_error(
            "session_mismatch",
            f"Session Claim ID '{sci_id}' is bound to session "
            f"'{token.get('session_id')}', not '{session_id}'.",
        )

    # Valid SCI. The heartbeat/updated_at touch already ran at
    # _sci_gate_for_request entry (ENC-TSK-L35), so no further touch here.
    return None


def _sci_gate_for_request(body: Dict, event: Optional[Dict]) -> Optional[Dict]:
    """Run the SCI gate for a mutation request when it is agent-origin.

    Agent-origin means write_source.provider is a minted ENC-SES id. Everything
    else — internal-key writes under legacy providers (github, user, ...),
    Cognito writes (provider defaults to claims.sub), EventBridge/system writes
    (system:arc-walker) — is out of gate scope and passes through unchanged.
    Requests bearing X-Checkout-Service-Key are exempt: checkout_service runs
    the identical gate at its own edge and the ENC-FTR-037 chain does not
    forward `sci` (same trust model / rollout semantics as the FTR-037 status
    gate, including permissive mode while CHECKOUT_SERVICE_KEY is unset).

    ENC-TSK-L35: every agent-origin session-requiring call reaching this
    function bumps the session's own last_activity_at/updated_at, UNCONDITIONALLY
    — before the checkout-service exemption and before any SCI/grandfather
    outcome — so the SES record's updated-time reflects every session-requiring
    call it makes across every record type routed through this shared
    mutation Lambda (task/issue/feature/lesson/plan/generation).
    """
    ws = _normalize_write_source(body)
    session_id = str(ws.get("provider", "")).strip()
    if not _AGENT_SESSION_ID_RE.match(session_id):
        return None
    _touch_session_activity(session_id)
    if _is_checkout_service_request(event):
        return None
    return _validate_sci_gate(session_id, body.get("sci"))


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_jwks_cache: Dict[str, Any] = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600.0

# Project validation cache
_project_cache: Dict[str, bool] = {}
_project_cache_at: float = 0.0
_PROJECT_CACHE_TTL = 300.0


def _parse_internal_scope_map(raw: str) -> Dict[str, set[str]]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Invalid COORDINATION_INTERNAL_API_KEY_SCOPES JSON; ignoring scoped auth map")
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: Dict[str, set[str]] = {}
    for key, value in parsed.items():
        token = str(key or "").strip()
        if not token:
            continue
        scopes: set[str] = set()
        if isinstance(value, list):
            items = value
        else:
            items = str(value).split(",")
        for item in items:
            scope = str(item or "").strip().lower()
            if scope:
                scopes.add(scope)
        if scopes:
            out[token] = scopes
    return out


INTERNAL_API_KEY_SCOPES = _parse_internal_scope_map(_INTERNAL_SCOPE_MAP_RAW)


def _scope_match(granted: str, required: str) -> bool:
    if granted in {"*", "all"}:
        return True
    if granted == required:
        return True
    if granted.endswith("*"):
        return required.startswith(granted[:-1])
    return False


def _internal_key_has_scopes(internal_key: str, required_scopes: Optional[List[str]]) -> bool:
    if not required_scopes:
        return True
    if not INTERNAL_API_KEY_SCOPES:
        return True
    granted = INTERNAL_API_KEY_SCOPES.get(internal_key) or INTERNAL_API_KEY_SCOPES.get("*") or set()
    if not granted:
        return False
    for required in required_scopes:
        req = str(required or "").strip().lower()
        if req and not any(_scope_match(g, req) for g in granted):
            return False
    return True


def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    if not COGNITO_USER_POOL_ID:
        raise ValueError("COGNITO_USER_POOL_ID not set")
    region = COGNITO_USER_POOL_ID.split("_")[0]
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    )
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read())
    new_cache: Dict[str, Any] = {}
    for key_data in data.get("keys", []):
        kid = key_data["kid"]
        if not _JWT_AVAILABLE:
            new_cache[kid] = key_data
        else:
            new_cache[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))
    _jwks_cache = new_cache
    _jwks_fetched_at = now
    return _jwks_cache


def _verify_token(token: str) -> Dict[str, Any]:
    if not _JWT_AVAILABLE:
        raise ValueError("JWT library not available in Lambda package")
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise ValueError(f"Invalid token header: {exc}") from exc
    kid = header.get("kid")
    alg = header.get("alg", "RS256")
    if alg != "RS256":
        raise ValueError(f"Unexpected token algorithm: {alg}")
    keys = _get_jwks()
    pub_key = keys.get(kid)
    if pub_key is None:
        raise ValueError("Token key ID not found in JWKS")
    try:
        claims = jwt.decode(
            token, pub_key, algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID, options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please sign in again.")
    except jwt.InvalidAudienceError:
        raise ValueError("Token audience mismatch.")
    except jwt.PyJWTError as exc:
        raise ValueError(f"Token validation failed: {exc}") from exc
    return claims


def _extract_if_match(event: Optional[Dict]) -> Optional[str]:
    """Extract the If-Match header value (ENC-TSK-L47 revision-conflict contract).

    Returns the raw revision token as a string (quotes stripped per ETag convention),
    or None if the header is absent. Absence means "no concurrency check requested" —
    callers must preserve today's unconditional-write behavior in that case.
    """
    if not event:
        return None
    headers = event.get("headers") or {}
    raw = headers.get("if-match") or headers.get("If-Match")
    if raw is None:
        return None
    raw = str(raw).strip()
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        raw = raw[1:-1]
    return raw or None


def _is_checkout_service_request(event: Optional[Dict]) -> bool:
    """Return True if request carries the CHECKOUT_SERVICE_KEY header (ENC-FTR-037).

    The checkout_service Lambda presents this key so tracker_mutation can allow
    status transitions that would otherwise be blocked for direct callers.
    If CHECKOUT_SERVICE_KEY is not configured, this gate is permissive (returns True)
    to allow graceful rollout before the key is deployed.
    """
    if not CHECKOUT_SERVICE_KEY:
        # Key not yet configured — permissive mode until checkout_service is deployed
        return True
    if not event:
        return False
    headers = event.get("headers") or {}
    presented = (
        headers.get("x-checkout-service-key")
        or headers.get("X-Checkout-Service-Key")
        or ""
    )
    return bool(presented and presented == CHECKOUT_SERVICE_KEY)


def _extract_token(event: Dict) -> Optional[str]:
    """Extract enceladus_id_token from Cookie header or API Gateway v2 cookies."""
    headers = event.get("headers") or {}
    cookie_parts = []
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    if cookie_header:
        cookie_parts.extend(part.strip() for part in cookie_header.split(";") if part.strip())
    event_cookies = event.get("cookies") or []
    if isinstance(event_cookies, list):
        cookie_parts.extend(part.strip() for part in event_cookies if isinstance(part, str) and part.strip())
    elif isinstance(event_cookies, str) and event_cookies.strip():
        cookie_parts.append(event_cookies.strip())
    for part in cookie_parts:
        if not part.startswith("enceladus_id_token="):
            continue
        return unquote(part[len("enceladus_id_token="):])
    return None


def _authenticate(event: Dict, required_scopes: Optional[List[str]] = None) -> Tuple[Optional[Dict], Optional[Dict]]:
    """Authenticate via internal API key or Cognito JWT.

    Returns (claims, None) on success or (None, error_response) on failure.
    """
    headers = event.get("headers") or {}

    # Try internal API key first
    internal_key = (
        headers.get("x-coordination-internal-key")
        or headers.get("X-Coordination-Internal-Key")
        or ""
    )
    if internal_key and COORDINATION_INTERNAL_API_KEYS and internal_key in COORDINATION_INTERNAL_API_KEYS:
        if not _internal_key_has_scopes(internal_key, required_scopes):
            return None, _error(403, "Forbidden: internal key scope is insufficient for this operation.")
        return {"auth_mode": "internal-key"}, None

    # Fall back to Cognito JWT
    token = _extract_token(event)
    if not token:
        return None, _error(401, "Authentication required. Please sign in or provide API key.")
    try:
        claims = _verify_token(token)
        return claims, None
    except ValueError as exc:
        logger.warning("auth failed: %s", exc)
        return None, _error(401, str(exc))


# ---------------------------------------------------------------------------
# Project validation (fail-open)
# ---------------------------------------------------------------------------

def _validate_project_exists(project_id: str) -> Optional[str]:
    global _project_cache, _project_cache_at
    now = time.time()
    if (now - _project_cache_at) >= _PROJECT_CACHE_TTL:
        _project_cache = {}
        _project_cache_at = now
    if project_id in _project_cache:
        return None if _project_cache[project_id] else (
            f"Project '{project_id}' is not registered."
        )
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="project_id",
        )
        exists = "Item" in resp
        _project_cache[project_id] = exists
        if not exists:
            return f"Project '{project_id}' is not registered."
        return None
    except Exception as exc:
        logger.warning("project validation failed (fail-open): %s", exc)
        return None


def _get_project_prefix(project_id: str) -> Optional[str]:
    """Get prefix for a project from the projects table."""
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="prefix",
        )
        item = resp.get("Item")
        if item:
            return item.get("prefix", {}).get("S")
        return None
    except Exception:
        return None


def _parse_github_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse owner and repo from a GitHub URL like https://github.com/OWNER/REPO."""
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$', url)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _resolve_github_repo(project_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the GitHub owner/repo for a project from the projects table.

    Checks the project's ``repo`` field first. If absent, checks the parent
    (one level), then children that list this project as parent.

    Returns (owner, repo) or (None, None) if unresolvable.
    """
    try:
        ddb = _get_ddb()
        resp = ddb.get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": project_id}},
            ProjectionExpression="repo, parent",
        )
        item = resp.get("Item")
        if not item:
            return None, None

        repo_url = item.get("repo", {}).get("S", "")
        if repo_url:
            return _parse_github_url(repo_url)

        # Walk up to parent (one level)
        parent_id = item.get("parent", {}).get("S", "")
        if parent_id:
            try:
                resp2 = ddb.get_item(
                    TableName=PROJECTS_TABLE,
                    Key={"project_id": {"S": parent_id}},
                    ProjectionExpression="repo",
                )
                item2 = resp2.get("Item")
                if item2:
                    repo_url2 = item2.get("repo", {}).get("S", "")
                    if repo_url2:
                        return _parse_github_url(repo_url2)
            except Exception as exc:
                logger.warning("Failed to look up parent project '%s': %s", parent_id, exc)

        # Check children that list this project as parent
        try:
            scan_resp = ddb.scan(
                TableName=PROJECTS_TABLE,
                FilterExpression="parent = :pid",
                ExpressionAttributeValues={":pid": {"S": project_id}},
                ProjectionExpression="repo",
            )
            for child in scan_resp.get("Items", []):
                child_repo = child.get("repo", {}).get("S", "")
                if child_repo:
                    return _parse_github_url(child_repo)
        except Exception as exc:
            logger.warning("Failed to scan child projects for '%s': %s", project_id, exc)

        return None, None
    except Exception as exc:
        logger.warning("Failed to resolve GitHub repo for project '%s': %s", project_id, exc)
        return None, None


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def _build_key(project_id: str, record_type: str, record_id: str) -> Dict[str, Dict]:
    """Build the DynamoDB primary key for a record."""
    prefix = _TYPE_SEG_TO_SK_PREFIX[record_type]
    sk = f"{prefix}#{record_id.upper()}"
    return {
        "project_id": {"S": project_id},
        "record_id": {"S": sk},
    }


def _get_record_full(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """GetItem with ConsistentRead. Returns full deserialized item or None."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    resp = ddb.get_item(TableName=DYNAMODB_TABLE, Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if item is None:
        return None
    return _deser_item(item)


# ENC-ISS-509: gamma runs its own physically-separate tracker table
# (devops-project-tracker-gamma per EnvironmentSuffix, infrastructure/cloudformation/
# 02-compute.yaml TrackerMutationFunction). It is seeded once and not continuously
# synced from the canonical governed table, so recently-created records (e.g. ones
# minted via the prod MCP connector moments ago) 404 on gamma's PWA detail route even
# though tracker.get resolves them fine against the canonical table. This is a
# read-only, GET-detail-only fallback: on a gamma-table miss, do a single GetItem
# against the canonical table so the detail page can render. Never used for writes
# or list/search — those keep gamma's isolated data plane untouched.
_CANONICAL_TRACKER_TABLE = "devops-project-tracker"


def _get_record_full_with_gamma_fallback(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """As _get_record_full, but on gamma a local miss falls back to a read-only
    GetItem against the canonical (prod) tracker table. No-op on prod (DYNAMODB_TABLE
    already equals _CANONICAL_TRACKER_TABLE there, so the fallback branch is skipped)."""
    item = _get_record_full(project_id, record_type, record_id)
    if item is not None:
        return item
    if DYNAMODB_TABLE == _CANONICAL_TRACKER_TABLE:
        return None
    try:
        ddb = _get_ddb()
        key = _build_key(project_id, record_type, record_id)
        resp = ddb.get_item(TableName=_CANONICAL_TRACKER_TABLE, Key=key, ConsistentRead=True)
        fallback_item = resp.get("Item")
    except ClientError as exc:
        logger.warning("[ISS-509] gamma canonical-table fallback read failed for %s: %s", record_id, exc)
        return None
    if fallback_item is None:
        return None
    logger.info("[ISS-509] gamma miss on %s; served from canonical table fallback", record_id)
    return _deser_item(fallback_item)


def _get_record_raw(project_id: str, record_type: str, record_id: str) -> Optional[Dict]:
    """GetItem with ConsistentRead. Returns raw DynamoDB item or None."""
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    resp = ddb.get_item(TableName=DYNAMODB_TABLE, Key=key, ConsistentRead=True)
    return resp.get("Item")


def _classify_related_ids(related_ids: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rid in related_ids:
        rid_u = rid.strip().upper()
        parts = rid_u.split("-")
        if len(parts) < 2:
            continue
        type_seg = parts[1]
        rtype = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan"}.get(type_seg)
        if not rtype:
            continue
        field = f"related_{rtype}_ids"
        out.setdefault(field, []).append(rid_u)
    return out


# ---------------------------------------------------------------------------
# Sequence encoding (ENC-ISS-132: alphanumeric rollover after 999)
# ---------------------------------------------------------------------------

_SEQUENCE_CAPACITY = 3573  # 999 numeric + 2574 alphanumeric (A01-Z99)
_BASE36_CAPACITY = 46655   # ZZZ in base-36 (ENC-FTR-056)

_BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _b36_to_str(v: int) -> str:
    """Convert a base-36 value (0-46655) to a 3-char string. Internal helper."""
    r = []
    for _ in range(3):
        r.append(_BASE36_CHARS[v % 36])
        v //= 36
    return "".join(reversed(r))


def _str_to_b36(s: str) -> int:
    """Convert a 3-char base-36 string to an integer. Internal helper."""
    result = 0
    for ch in s:
        idx = _BASE36_CHARS.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid base-36 character {ch!r} in sequence {s!r}")
        result = result * 36 + idx
    return result


def _is_legacy_pattern(s: str) -> bool:
    """Check if a 3-char string matches a legacy encoding pattern."""
    if s.isdigit():
        return True
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        num = int(s[1:])
        if 1 <= num <= 99:
            return True
    return False


# Precompute the extended-range mapping table at module load time.
# Maps index (0-43081) -> base-36 value for non-legacy 3-char strings.
# Reverse map: base-36 value -> counter value (3574 + index).
_EXT_B36_TO_COUNTER: dict = {}  # base-36 int value -> counter int
_EXT_COUNTER_TO_B36: list = []  # index -> base-36 int value

def _init_extended_tables():
    idx = 0
    for v in range(46656):
        s = _b36_to_str(v)
        if not _is_legacy_pattern(s):
            _EXT_COUNTER_TO_B36.append(v)
            _EXT_B36_TO_COUNTER[v] = 3574 + idx
            idx += 1

_init_extended_tables()


def _encode_base36(n: int) -> str:
    """Encode a non-negative integer into a 3-char sequence (ENC-FTR-056).

    Encoding scheme preserves backward compatibility:
    - 0-999:     zero-padded decimal ('000'-'999') — matches legacy format
    - 1000-3573: legacy alphanumeric ('A01'-'Z99') — matches legacy format
    - 3574-46655: mapped to non-legacy 3-char base-36 strings via lookup table

    Total capacity: 46,656 per record type per project.
    >=46656 -> ValueError (capacity exhausted)
    """
    if n < 0:
        raise ValueError(f"Counter must be >= 0, got {n}")
    if n > _BASE36_CAPACITY:
        raise ValueError(
            f"Base-36 capacity exhausted at counter {n}. "
            f"Maximum is {_BASE36_CAPACITY} per record type per project."
        )
    # Legacy numeric range: 0-999
    if n <= 999:
        return str(n).zfill(3)
    # Legacy alphanumeric range: 1000-3573
    offset = n - 1000
    letter_index = offset // 99
    number = (offset % 99) + 1
    if letter_index <= 25:
        return chr(65 + letter_index) + str(number).zfill(2)
    # Extended range: 3574-46655 -> non-legacy base-36 string via table
    ext_idx = n - 3574
    return _b36_to_str(_EXT_COUNTER_TO_B36[ext_idx])


def _decode_base36(s: str) -> int:
    """Decode a sequence string back into an integer (ENC-FTR-056).

    Handles all formats in priority order:
    1. Legacy numeric (all digits): parse as decimal integer
    2. Legacy alphanumeric (letter + 2 digits, A01-Z99): decode as legacy
    3. Extended base-36 (non-legacy 3-char strings): decode via lookup table
    4. Longer strings: parse as plain integer (legacy overflow)
    """
    if not s:
        raise ValueError("Empty sequence")
    s = s.upper()
    # Legacy numeric (all digits, including 4+ digit overflow IDs)
    if s.isdigit():
        return int(s)
    # Legacy alphanumeric A01-Z99: single letter followed by exactly 2 digits
    if len(s) == 3 and s[0].isalpha() and s[1:].isdigit():
        letter_index = ord(s[0]) - 65
        number = int(s[1:])
        if 0 <= letter_index <= 25 and 1 <= number <= 99:
            return 1000 + (letter_index * 99) + (number - 1)
    # Extended base-36: look up in the reverse table
    try:
        b36_val = _str_to_b36(s)
    except ValueError:
        raise ValueError(f"Invalid sequence: {s!r}")
    counter = _EXT_B36_TO_COUNTER.get(b36_val)
    if counter is not None:
        return counter
    raise ValueError(f"Invalid sequence: {s!r}")


def _format_sequence(counter: int) -> str:
    """Encode an integer counter into a 3-char record ID sequence.

    Now uses base-36 encoding (ENC-FTR-056). Counter starts at 1.
    Legacy compatibility: counters 1-999 still produce '001'-'999'.
    """
    if counter < 1:
        raise ValueError(f"Counter must be >= 1, got {counter}")
    return _encode_base36(counter)


def _parse_sequence(seq: str) -> int:
    """Decode a record ID sequence back into an integer counter.

    Delegates to _decode_base36 which handles legacy numeric, A01-Z99, and base-36 formats.
    """
    return _decode_base36(seq)


# ---------------------------------------------------------------------------
# Counter management for record creation
# ---------------------------------------------------------------------------

def _max_existing_number(project_id: str, record_type: str) -> int:
    """Scan all records to find the highest numeric suffix (fallback for missing counter)."""
    ddb = _get_ddb()
    kwargs: Dict[str, Any] = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :rtype_prefix)",
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":rtype_prefix": _ser_s(f"{record_type}#"),
        },
        "ProjectionExpression": "record_id",
    }
    max_num = 0
    while True:
        query_resp = ddb.query(**kwargs)
        for item in query_resp.get("Items", []):
            sk = item.get("record_id", {}).get("S", "")
            human_id = sk.split("#", 1)[1] if "#" in sk else sk
            parts = human_id.split("-")
            if len(parts) >= 3:
                try:
                    max_num = max(max_num, _decode_base36(parts[-1]))
                except ValueError:
                    pass
        last_key = query_resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return max_num


def _next_record_id(project_id: str, prefix: str, record_type: str) -> str:
    """Allocate the next sequential record ID using an atomic counter."""
    ddb = _get_ddb()
    type_suffix = _TRACKER_TYPE_SUFFIX.get(record_type, "TSK")
    counter_key = {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(f"{_TRACKER_COUNTER_PREFIX}{record_type}"),
    }

    counter_item = ddb.get_item(
        TableName=DYNAMODB_TABLE, Key=counter_key, ConsistentRead=True,
    ).get("Item")

    seed_num = 0
    if not counter_item:
        seed_num = _max_existing_number(project_id, record_type)

    now = _now_z()
    update_resp = ddb.update_item(
        TableName=DYNAMODB_TABLE,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :seed) + :one, "
            "updated_at = :now, "
            "created_at = if_not_exists(created_at, :now), "
            "record_type = if_not_exists(record_type, :counter_type), "
            "item_id = if_not_exists(item_id, :counter_item_id)"
        ),
        ExpressionAttributeValues={
            ":seed": {"N": str(seed_num)},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":counter_type": _ser_s("counter"),
            ":counter_item_id": _ser_s(f"COUNTER-{record_type.upper()}"),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    next_num = int(attrs.get("next_num", {"N": str(seed_num + 1)}).get("N", str(seed_num + 1)))
    return f"{prefix}-{type_suffix}-{_encode_base36(next_num)}"


_SUBTASK_SUFFIX_CAPACITY = 260  # 10 digits * 26 letters = 260 sub-tasks per parent


def _next_subtask_suffix(project_id: str, parent_root_id: str) -> str:
    """Allocate the next sub-task suffix for a parent task (ENC-FTR-056).

    Uses a per-parent atomic counter: key {project_id, counter#subtask#{parent_root_id}}.
    Counter n -> suffix: digit = n // 26, letter = chr('A' + n % 26).
    Returns 2-char string like '0A', '0B', ..., '0Z', '1A', ..., '9Z'.
    Raises ValueError at n >= 260.
    """
    ddb = _get_ddb()
    counter_key = {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(f"{_TRACKER_COUNTER_PREFIX}subtask#{parent_root_id}"),
    }

    now = _now_z()
    update_resp = ddb.update_item(
        TableName=DYNAMODB_TABLE,
        Key=counter_key,
        UpdateExpression=(
            "SET next_num = if_not_exists(next_num, :seed) + :one, "
            "updated_at = :now, "
            "created_at = if_not_exists(created_at, :now), "
            "record_type = if_not_exists(record_type, :counter_type), "
            "item_id = if_not_exists(item_id, :counter_item_id)"
        ),
        ExpressionAttributeValues={
            ":seed": {"N": "0"},
            ":one": {"N": "1"},
            ":now": _ser_s(now),
            ":counter_type": _ser_s("counter"),
            ":counter_item_id": _ser_s(f"COUNTER-SUBTASK-{parent_root_id}"),
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = update_resp.get("Attributes", {})
    # next_num starts at 1 after first increment; subtract 1 for zero-based suffix
    n = int(attrs.get("next_num", {"N": "1"}).get("N", "1")) - 1

    if n >= _SUBTASK_SUFFIX_CAPACITY:
        raise ValueError(
            f"Sub-task capacity exhausted for parent {parent_root_id}. "
            f"Maximum is {_SUBTASK_SUFFIX_CAPACITY} sub-tasks per parent."
        )

    digit = n // 26
    letter = chr(ord("A") + n % 26)
    return f"{digit}{letter}"


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": CORS_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Cookie, X-Coordination-Internal-Key",
        "Access-Control-Allow-Credentials": "true",
    }


def _response(status_code: int, body: Any) -> Dict:
    return {
        "statusCode": status_code,
        "headers": {**_cors_headers(), "Content-Type": "application/json"},
        "body": json.dumps(body, default=str),
    }


def _error(status_code: int, message: str, **extra) -> Dict:
    code = str(extra.pop("code", "") or "").strip().upper()
    if not code:
        if status_code == 400:
            code = "INVALID_INPUT"
        elif status_code == 401:
            code = "PERMISSION_DENIED"
        elif status_code == 403:
            code = "PERMISSION_DENIED"
        elif status_code == 404:
            code = "NOT_FOUND"
        elif status_code == 409:
            code = "CONFLICT"
        elif status_code >= 500:
            code = "INTERNAL_ERROR"
        else:
            code = "INTERNAL_ERROR"
    retryable = bool(extra.pop("retryable", status_code >= 500))
    details = dict(extra)
    body = {
        "success": False,
        "error": message,
        "error_envelope": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": details,
        },
    }
    body.update(details)
    return _response(status_code, body)


def _strictness_rank_table() -> List[Dict[str, Any]]:
    return [
        {"transition_type": name, "rank": _STRICTNESS_RANK[name]}
        for name in sorted(_VALID_TRANSITION_TYPES, key=lambda item: (_STRICTNESS_RANK[item], item))
    ]


def _tracker_create_validation_error(
    message: str,
    *,
    record_type: str,
    missing_required_fields: Optional[List[str]] = None,
    governed_rules: Optional[List[str]] = None,
    example_fix: Optional[Dict[str, Any]] = None,
) -> Dict:
    return _error(
        400,
        message,
        record_type=record_type,
        missing_required_fields=missing_required_fields or [],
        governed_rules=governed_rules or [],
        allowed_values={
            "priority": list(_VALID_PRIORITIES),
            "category": sorted(_VALID_CATEGORIES.get(record_type, set())),
        },
        example_fix=example_fix or {
            "tool": "tracker_create",
            "arguments": {
                "project_id": "<project_id>",
                "record_type": record_type,
                "title": "<title>",
                "governance_hash": "<governance_hash>",
            },
        },
    )


def _tracker_field_validation_error(
    message: str,
    *,
    field: str,
    record_id: str = "",
    record_type: str = "",
    expected_type: str = "",
    expected_format: str = "",
    allowed_values: Optional[List[str]] = None,
    governed_rules: Optional[List[str]] = None,
    example_fix: Optional[Dict[str, Any]] = None,
) -> Dict:
    details: Dict[str, Any] = {
        "field": field,
        "record_id": record_id or None,
        "record_type": record_type or None,
        "expected_type": expected_type or None,
        "expected_format": expected_format or None,
        "allowed_values": allowed_values or None,
        "governed_rules": governed_rules or [],
        "example_fix": example_fix or {
            "tool": "tracker_set",
            "arguments": {
                "record_id": record_id or "<record_id>",
                "field": field,
                "value": "<valid-value>",
                "governance_hash": "<governance_hash>",
            },
        },
    }
    if field == "transition_type":
        details["strictness_rank"] = _strictness_rank_table()
    clean_details = {
        key: value
        for key, value in details.items()
        if value not in (None, "", [], {})
    }
    return _error(400, message, **clean_details)


# ---------------------------------------------------------------------------
# EventBridge (reopen events)
# ---------------------------------------------------------------------------

def _emit_reopen_event(project_id, record_type, record_id, previous_status, new_status, reopened_at):
    detail = {
        "project_id": project_id, "record_type": record_type,
        "record_id": record_id, "previous_status": previous_status,
        "new_status": new_status, "reopened_at": reopened_at,
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": EVENT_DETAIL_TYPE_REOPENED,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:
        logger.error("EventBridge put_events failed: %s", exc)


# ---------------------------------------------------------------------------
# ENC-FTR-111 / ENC-TSK-H83 — Universal Arc-Walker circuit breaker (auto_walk_opt_out)
# ---------------------------------------------------------------------------
def _coerce_bool(val: Any) -> bool:
    """Coerce a JSON/string/numeric/bool input to a real Python bool (for DynamoDB BOOL storage).
    MCP/JSON callers may send the string 'false', which is truthy if stored verbatim."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    return str(val).strip().lower() in ("true", "1", "yes", "on")


def _is_human_request(claims: Optional[Dict]) -> bool:
    """A human (Cognito) request, as opposed to an internal-key / agent request. ENC-TSK-H83:
    the auto_walk_opt_out latch fires only on human-initiated non-forward transitions."""
    return bool(claims) and claims.get("auth_mode") != "internal-key"


def _human_actor(claims: Optional[Dict]) -> str:
    """Best-effort human identity for audit attribution."""
    if not claims:
        return "unknown_user"
    return claims.get("cognito:username") or claims.get("sub") or "unknown_user"


def _is_task_non_forward(current_status: str, target_status: str) -> Tuple[bool, str]:
    """ENC-TSK-H83: classify a task status change as non-forward. Returns (is_non_forward, reason).
    A regression is a backward move by ordinal rank; 'coding-updates' is the deploy-success
    re-entry case (it has no forward rank). Same-status and forward moves return (False, '')."""
    cur = (current_status or "").strip().lower()
    tgt = (target_status or "").strip().lower()
    if not tgt or tgt == cur:
        return False, ""
    if tgt == "coding-updates":
        return True, "coding-updates re-entry"
    cur_rank = _TASK_STATUS_RANK.get(cur)
    tgt_rank = _TASK_STATUS_RANK.get(tgt)
    if cur_rank is not None and tgt_rank is not None and tgt_rank < cur_rank:
        return True, "regression"
    return False, ""


def _opt_out_latch_history_entry(now: str, latched_by: str, from_status: str,
                                 to_status: str, reason: str) -> Dict:
    """Build the Artifact-Genesis history entry recorded on an auto_walk_opt_out latch (AC-2/AC-4).
    No silent mutations: every latch is accompanied by this governed audit entry."""
    msg = (
        f"[ARC-WALKER][OPT-OUT-LATCH] auto_walk_opt_out latched true: human {latched_by} "
        f"non-forward transition {from_status or '?'} -> {to_status} ({reason}). The Universal "
        f"Arc-Walker (ENC-FTR-111) will not auto-advance this record until the latch is cleared."
    )
    return {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(msg),
    }}


def _emit_opt_out_latch_event(project_id: str, record_type: str, record_id: str,
                              from_status: str, to_status: str, reason: str,
                              latched_by: str) -> None:
    """Emit the Artifact-Genesis telemetry event for an auto_walk_opt_out latch (best-effort)."""
    detail = {
        "project_id": project_id, "record_type": record_type, "record_id": record_id,
        "event": "auto_walk_opt_out_latched", "advanced_by": ARC_WALKER_ACTOR,
        "latched_by": latched_by, "trigger": reason,
        "from_status": from_status, "to_status": to_status, "latched_at": _now_z(),
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": EVENT_DETAIL_TYPE_OPT_OUT_LATCHED,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:
        logger.error("opt_out latch event emit failed: %s", exc)


def _opt_out_state_history_entry(now: str, latched: bool, actor: str) -> Dict:
    """ENC-TSK-H86 (T5): Artifact-Genesis history entry for an EXPLICIT (human/agent) set or clear
    of auto_walk_opt_out via tracker.set. Carries an [ARC-WALKER][OPT-OUT-SET|OPT-OUT-CLEAR] marker
    so the read-only convergence/telemetry probe (arc_walk_metrics) can count latch/clear events
    from record history. The auto-latch path (H83) records its own [OPT-OUT-LATCH] entry."""
    marker = "OPT-OUT-SET" if latched else "OPT-OUT-CLEAR"
    verb = "latched true" if latched else "cleared (set false)"
    msg = (
        f"[ARC-WALKER][{marker}] auto_walk_opt_out {verb} by {actor or 'unknown'}. "
        f"The Universal Arc-Walker (ENC-FTR-111) "
        + ("will not auto-advance this record while the latch is set."
           if latched else "may auto-advance this record across mechanical gates again.")
    )
    return {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"), "description": _ser_s(msg),
    }}


def _emit_opt_out_state_event(project_id: str, record_type: str, record_id: str,
                              latched: bool, actor: str) -> None:
    """ENC-TSK-H86 (T5) / ENC-FTR-111 AC-6: emit the opt_out latch-or-clear telemetry event for an
    EXPLICIT tracker.set of auto_walk_opt_out (the H83 auto-latch path emits its own latch event).
    Both latch and clear feed the ENC-TSK-B66 observability dashboard. Best-effort — a telemetry
    failure never rolls back the already-committed field write."""
    detail = {
        "project_id": project_id, "record_type": record_type, "record_id": record_id,
        "event": "auto_walk_opt_out_latched" if latched else "auto_walk_opt_out_cleared",
        "advanced_by": ARC_WALKER_ACTOR, "actor": actor or "unknown",
        "latched": bool(latched), "trigger": "explicit_set" if latched else "explicit_clear",
        "changed_at": _now_z(),
    }
    detail_type = EVENT_DETAIL_TYPE_OPT_OUT_LATCHED if latched else EVENT_DETAIL_TYPE_OPT_OUT_CLEARED
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": detail_type,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:  # noqa: BLE001
        logger.error("opt_out state event emit failed: %s", exc)


def _emit_auto_merge_event(project_id: str, record_type: str, superseded_id: str,
                           canonical_id: str, cluster_id: Optional[str], cosine: Any,
                           calibrated_prob: Any, precision_lcb: Any) -> None:
    """ENC-TSK-I09: stream one MECHANICAL auto-merge to the io-reviewable audit feed
    (DOC-DF651F07D5C2 §8). Best-effort — a telemetry failure never rolls back the
    (already-committed, reversible) supersession."""
    detail = {
        "project_id": project_id, "record_type": record_type,
        "event": "dedup_auto_merged", "advanced_by": ARC_WALKER_ACTOR,
        "superseded_id": superseded_id, "canonical_id": canonical_id,
        "cluster_id": cluster_id, "cosine": cosine,
        "calibrated_prob": calibrated_prob, "precision_lcb": precision_lcb,
        "reversible": True, "merged_at": _now_z(),
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": EVENT_DETAIL_TYPE_AUTO_MERGED,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:
        logger.error("auto-merge audit event emit failed: %s", exc)


# ---------------------------------------------------------------------------
# ENC-TSK-H85 / ENC-FTR-111 Phase 1 — Universal Arc-Walker: synchronous inline mechanical walk.
#
# After any successful FORWARD task advance, the walker loops forward across the Phase-1 MECHANICAL
# gates in the SAME Lambda invocation before returning (DOC-078C57FC1BE6 §6.1). Phase 1 covers
# exactly two legs (§3.1 / §11):
#   - <deploy-arc>|merged-main -> deploy-init  (auto-walkable only on ci_triggered projects; O-2)
#   - code_only|merged-main    -> closed       (reuses the stored commit_sha + a GitHub compare)
#
# Eligibility is decided SOLELY by the Lifecycle Service evaluate_auto_walk verdict (gate_class
# MECHANICAL + the deploy_policy O-2 qualifier) — NEVER from evidence-field emptiness (§7.2, the
# "coding-complete trap"). The walk honors the auto_walk_opt_out latch (§7.4), pins the matrix
# version (§8), integrity-checks checkout_transition_type (B07/B08 → 409 halt), performs each step
# as an idempotent conditional write (advance iff status == expected_prior), halts at the first
# attestation / opt-out / gate-fail boundary, and emits an Artifact-Genesis record per crossing.
# The walker writes under write_source=system:arc-walker and can NEVER clear the opt-out latch.
# ---------------------------------------------------------------------------
_ARC_WALK_MAX_STEPS = 8  # safety depth cap (§9 cascade-runaway mitigation); Phase 1 needs <= 1.
_ARC_WALK_DEPLOY_ARC_TYPES = frozenset({"github_pr_deploy", "lambda_deploy", "web_deploy"})


def _arc_walk_next_candidate(transition_type: str, current_status: str) -> Optional[str]:
    """Propose the single forward status the Phase-1 arc-walker would attempt from current_status,
    or None when there is no Phase-1 MECHANICAL leg out of current_status. This only PROPOSES a
    target; the authoritative mechanical/deploy_policy eligibility ruling is the Lifecycle Service
    evaluate_auto_walk verdict (DOC-078C57FC1BE6 §3.1/§11)."""
    tt = (transition_type or "github_pr_deploy").strip().lower()
    cur = (current_status or "").strip().lower()
    if cur == "merged-main":
        if tt == "code_only":
            return "closed"
        if tt in _ARC_WALK_DEPLOY_ARC_TYPES:
            return "deploy-init"
    return None


def _arc_walk_compare_commit_to_main(owner: str, repo: str, sha: str) -> Tuple[bool, str]:
    """code_only|closed is MECHANICAL because the system already holds the commit_sha (the agent
    supplied it at `committed`); the gate's only action is a system-run GitHub compare confirming the
    commit is an ancestor of main (DOC-078C57FC1BE6 §3.1). Routed through github_integration (the
    GitHub external-fact surface); tracker_mutation never calls GitHub directly."""
    if not GITHUB_INTEGRATION_API_BASE:
        logger.warning("[H85] GITHUB_INTEGRATION_API_BASE not set; cannot compare %s to main", sha)
        return False, "github_integration_unconfigured"
    url = (
        f"{GITHUB_INTEGRATION_API_BASE}/commits/compare-main"
        f"?owner={urllib.parse.quote(owner)}"
        f"&repo={urllib.parse.quote(repo)}"
        f"&sha={urllib.parse.quote(sha)}"
    )
    req = urllib.request.Request(url, method="GET", headers={
        "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("valid"):
                return True, str(data.get("status", "ancestor"))
            return False, str(data.get("reason", "not_ancestor_of_main"))
    except Exception as exc:  # noqa: BLE001
        logger.error("[H85] commit compare-main call failed: %s", exc)
        return False, f"compare_service_error: {exc}"


def _arc_walk_history_entry(now: str, from_status: str, to_status: str, gate_class: Optional[str],
                            derivation: str, matrix_version: Any) -> Dict:
    """Artifact-Genesis history entry for one auto-walk crossing (DOC-078C57FC1BE6 §8 — no silent
    mutations). Carries advanced_by, the gate crossed + its class, the derivation, the matrix ref,
    and the trigger (sync)."""
    msg = (
        f"[ARC-WALKER][AUTO-ADVANCE] {from_status or '?'} -> {to_status} "
        f"(gate_class={gate_class}, trigger=sync, matrix_version={matrix_version}). "
        f"{derivation} advanced_by={ARC_WALKER_ACTOR}."
    )
    return {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"), "description": _ser_s(msg),
    }}


def _emit_arc_walk_event(project_id: str, record_id: str, from_status: str, to_status: str,
                         gate_class: Optional[str], derivation: str, matrix_version: Any,
                         latency_ms: int) -> None:
    """Emit the ARC_WALK Artifact-Genesis telemetry event (DOC-078C57FC1BE6 §10). Best-effort — a
    telemetry failure never rolls back the (already-committed) conditional advance."""
    detail = {
        "project_id": project_id, "record_type": "task", "record_id": record_id,
        "event": "arc_walk_advanced", "advanced_by": ARC_WALKER_ACTOR,
        "from_status": from_status, "to_status": to_status, "gate_class": gate_class,
        "derivation": derivation, "trigger": "sync", "matrix_version": matrix_version,
        "latency_ms": latency_ms, "advanced_at": _now_z(),
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE, "DetailType": EVENT_DETAIL_TYPE_ARC_WALK,
            "Detail": json.dumps(detail), "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:  # noqa: BLE001
        logger.error("arc_walk event emit failed: %s", exc)


def _arc_walk_after_advance(project_id: str, record_id: str, item_data: Dict,
                            landed_status: str) -> Dict:
    """ENC-TSK-H85 / ENC-FTR-111 Phase 1 (T4) — drive the synchronous inline mechanical walk.

    Called after a successful forward task advance committed to `landed_status`. Loops forward across
    the Phase-1 mechanical gates, halting at the first attestation / opt-out / gate-fail boundary.
    Returns a structured summary (never raises into the caller's response). NEVER fails the agent's
    original advance — the walk is a pure optimization on top of an already-committed transition."""
    transition_type = (item_data.get("transition_type") or "github_pr_deploy").strip().lower()
    checkout_tt = (item_data.get("checkout_transition_type") or "").strip().lower()
    opt_out = _coerce_bool(item_data.get("auto_walk_opt_out", False))
    commit_sha = (item_data.get("commit_sha") or "").strip().lower()
    subtask_ids = item_data.get("subtask_ids") or []

    pinned_raw = item_data.get("checkout_matrix_version")
    try:
        pinned_matrix = int(pinned_raw) if pinned_raw not in (None, "") else MATRIX_VERSION
    except (TypeError, ValueError):
        pinned_matrix = MATRIX_VERSION

    summary: Dict[str, Any] = {"walked": [], "trigger": "sync", "matrix_version": pinned_matrix}

    # §7.4 opt-out circuit breaker: a latched record is demoted to ATTESTATION. The walker halts
    # before ANY evaluation or write and can never clear the latch (ENC-TSK-H83).
    if opt_out:
        summary["halted_reason"] = "opt_out_latched"
        return summary

    # §8 transition_type integrity (B07/B08): a mismatch between the type stamped at checkout and the
    # live type is a governance-integrity violation — halt with 409 exactly as an agent advance would.
    if checkout_tt and checkout_tt != transition_type:
        summary["halted_reason"] = "transition_type_integrity_409"
        summary["halt_status"] = 409
        summary["checkout_transition_type"] = checkout_tt
        summary["current_transition_type"] = transition_type
        return summary

    ddb = _get_ddb()
    key = _build_key(project_id, "task", record_id)
    current = (landed_status or "").strip().lower()

    for _ in range(_ARC_WALK_MAX_STEPS):
        target = _arc_walk_next_candidate(transition_type, current)
        if target is None:
            # No outgoing mechanical leg — the next gate is attestation / external-fact / terminal.
            summary["halted_reason"] = "no_mechanical_gate"
            break

        step_start = dt.datetime.utcnow()

        # (1) Eligibility — authoritative MECHANICAL + deploy_policy (O-2) verdict from the service.
        verdict = _invoke_lifecycle_action({
            "action": "evaluate_auto_walk",
            "transition_type": transition_type,
            "target_status": target,
            "project_id": project_id,
        })
        if verdict is None:
            summary["halted_reason"] = "lifecycle_service_unavailable"
            break
        gate_class = verdict.get("gate_class")
        # §8 matrix pinning: never auto-cross under a matrix version other than the pinned one.
        v_matrix = verdict.get("matrix_version")
        if v_matrix is not None and int(v_matrix) != int(pinned_matrix):
            summary["halted_reason"] = "matrix_version_mismatch"
            summary["service_matrix_version"] = v_matrix
            break
        if not verdict.get("auto_walkable"):
            # First attestation / external-fact / manual-deploy boundary — halt (§7).
            summary["halted_reason"] = verdict.get("reason") or f"gate_not_auto_walkable:{gate_class}"
            summary["gate_class"] = gate_class
            break

        # (2) Legality — reuse the full Lifecycle Service gate set (transition validity + subtask gate
        # + evidence shape). code_only|closed evidence is the stored commit_sha the agent already gave.
        evidence: Dict[str, Any] = {}
        if target == "closed" and transition_type == "code_only":
            evidence = {"code_on_main_evidence": {"commit_sha": commit_sha}}
        legal = _invoke_lifecycle_action({
            "action": "validate_transition",
            "project_id": project_id, "record_id": record_id, "record_type": "task",
            "current_status": current, "target_status": target,
            "transition_type": transition_type, "transition_evidence": evidence,
            "subtask_ids": subtask_ids, "is_checkout_service_request": True,
        })
        if legal is None:
            summary["halted_reason"] = "lifecycle_service_unavailable"
            break
        if not legal.get("allow"):
            err = legal.get("error") or {}
            summary["halted_reason"] = f"gate_fail:{err.get('code', 'INVALID')}"
            break

        # (3) Per-leg derivation + extra evidence persistence.
        extra_set = ""
        extra_vals: Dict[str, Any] = {}
        add_clause = ""
        if target == "closed" and transition_type == "code_only":
            if not re.match(r"^[0-9a-f]{40}$", commit_sha):
                summary["halted_reason"] = "gate_fail:missing_commit_sha"
                break
            owner, repo = _resolve_github_repo(project_id)
            if not owner or not repo:
                summary["halted_reason"] = "gate_fail:repo_unresolved"
                break
            ok, why = _arc_walk_compare_commit_to_main(owner, repo, commit_sha)
            if not ok:
                summary["halted_reason"] = f"gate_fail:compare:{why}"
                break
            derivation = (
                f"code_only|closed reuses commit_sha {commit_sha[:12]} (supplied at committed) and a "
                f"system-run GitHub compare confirmed it is an ancestor of main ({why})."
            )
            extra_set = ", code_on_main_evidence = :coe"
            extra_vals[":coe"] = {"M": {
                "commit_sha": _ser_s(commit_sha), "github_verified": {"BOOL": True},
            }}
            add_clause = " ADD closed_count :one"
        else:
            derivation = (
                "deploy-init records an initiation timestamp; on a ci_triggered project the merge "
                "entails initiation (ruling O-2) — no new external-world claim is introduced."
            )

        # (4) Idempotent conditional write: advance iff status == expected_prior (§8 idempotency).
        now2 = _now_z()
        hentry = _arc_walk_history_entry(now2, current, target, gate_class, derivation, pinned_matrix)
        note = f"[ARC-WALKER] auto-advanced {current} -> {target} (system:arc-walker)"
        ws_av = {"M": {
            "channel": _ser_s(ARC_WALKER_ACTOR), "provider": _ser_s(ARC_WALKER_ACTOR),
            "dispatch_id": _ser_s(""), "coordination_request_id": _ser_s(""),
            "timestamp": _ser_s(now2),
        }}
        update_expr = (
            "SET #s = :next, updated_at = :now, last_update_note = :note, write_source = :wsrc, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "history = list_append(if_not_exists(history, :empty), :hentry)"
            + extra_set + add_clause
        )
        attr_vals = {
            ":next": _ser_s(target), ":now": _ser_s(now2), ":note": _ser_s(note), ":wsrc": ws_av,
            ":zero": {"N": "0"}, ":one": {"N": "1"},
            ":hentry": {"L": [hentry]}, ":empty": {"L": []},
            ":expected": _ser_s(current),
        }
        attr_vals.update(extra_vals)
        try:
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=update_expr,
                ConditionExpression="#s = :expected",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues=attr_vals,
            )
        except ClientError as exc:
            if _is_conditional_check_failed(exc):
                # A concurrent advance moved the record off expected_prior. The conditional write is
                # the idempotency guard (§8/§9): no double-step, no lost update — halt cleanly.
                summary["halted_reason"] = "concurrent_advance"
                break
            logger.error("[H85] arc-walk conditional write failed: %s", exc)
            summary["halted_reason"] = "write_error"
            break
        except Exception as exc:  # noqa: BLE001
            logger.error("[H85] arc-walk write error: %s", exc)
            summary["halted_reason"] = "write_error"
            break

        latency_ms = int((dt.datetime.utcnow() - step_start).total_seconds() * 1000)
        _emit_arc_walk_event(project_id, record_id, current, target, gate_class,
                             derivation, pinned_matrix, latency_ms)
        summary["walked"].append({
            "from": current, "to": target, "gate_class": gate_class,
            "derivation": derivation, "matrix_version": pinned_matrix, "latency_ms": latency_ms,
        })
        current = target
    else:
        # Loop exhausted the depth cap without an explicit halt (should be unreachable in Phase 1).
        summary.setdefault("halted_reason", "max_steps_reached")

    summary["final_status"] = current
    return summary


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

def _handle_get_record(project_id: str, record_type: str, record_id: str) -> Dict:
    """GET /{project}/{type}/{id} — return full deserialized record."""
    try:
        item = _get_record_full_with_gamma_fallback(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if item is None:
        return _error(404, f"Record not found: {record_id}")

    id_key = f"{record_type}_id"
    # _deser_item exposes item_id; feed_query maps that to {type}_id. Align GET
    # responses so record_extensions can resolve the canonical id (ENC-TSK-K26).
    canonical_id = str(item.get(id_key) or item.get("item_id") or record_id or "")
    if canonical_id and not item.get(id_key):
        item[id_key] = canonical_id
    try:
        from record_extensions import (
            attach_record_extensions,
            query_typed_relationships_for_projects,
        )

        def _ddb_str(raw: Dict, key: str) -> str:
            val = raw.get(key, {})
            return val.get("S", "") if isinstance(val, dict) else ""

        def _ddb_float(raw: Dict, key: str) -> float:
            val = raw.get(key, {})
            try:
                return float(val.get("N", "0"))
            except (TypeError, ValueError):
                return 0.0

        edges_by_source = query_typed_relationships_for_projects(
            _get_ddb(),
            DYNAMODB_TABLE,
            [project_id],
            ddb_str=_ddb_str,
            ddb_float=_ddb_float,
        )
        attach_record_extensions([item], id_key, record_type, edges_by_source)
    except Exception as exc:
        logger.warning("Failed to attach record extensions for %s: %s", record_id, exc)

    return _response(200, {"success": True, "record": item})


def _handle_list_records(project_id: str, query_params: Dict) -> Dict:
    """GET /{project} — list records with optional type/status filters.

    ENC-TSK-F56 §6: paginated to prevent Lambda 413 on response-too-large.
    Lambda max response is 6MB; a project with 700+ records regularly exceeded
    that. Caps at page_size (default 50, max 200) and returns next_cursor when
    more records remain. Prior behavior exhausted LastEvaluatedKey and returned
    everything, causing the pre-existing 413 surfaced during the 2026-04-20
    io-override session.
    """
    ddb = _get_ddb()
    record_type = query_params.get("type", "")
    status_filter = query_params.get("status", "")
    try:
        page_size = max(1, min(int(query_params.get("page_size", "50")), 200))
    except (TypeError, ValueError):
        page_size = 50
    cursor = query_params.get("next_cursor", "")

    try:
        if record_type and record_type in _RECORD_TYPES:
            # Query using GSI
            kwargs: Dict[str, Any] = {
                "TableName": DYNAMODB_TABLE,
                "IndexName": "project-type-index",
                "KeyConditionExpression": "project_id = :pid AND record_type = :rtype",
                "ExpressionAttributeValues": {
                    ":pid": _ser_s(project_id),
                    ":rtype": _ser_s(record_type),
                },
                "Limit": page_size,
            }
            if status_filter:
                kwargs["FilterExpression"] = "#st = :st"
                kwargs["ExpressionAttributeNames"] = {"#st": "status"}
                kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)
        else:
            # Query all records for project
            kwargs = {
                "TableName": DYNAMODB_TABLE,
                "KeyConditionExpression": "project_id = :pid",
                "ExpressionAttributeValues": {":pid": _ser_s(project_id)},
                "Limit": page_size,
            }
            filter_parts = []
            expr_names: Dict[str, str] = {}
            if status_filter:
                filter_parts.append("#st = :st")
                expr_names["#st"] = "status"
                kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)
            if record_type:
                filter_parts.append("record_type = :rtype")
                kwargs["ExpressionAttributeValues"][":rtype"] = _ser_s(record_type)
            if filter_parts:
                kwargs["FilterExpression"] = " AND ".join(filter_parts)
            if expr_names:
                kwargs["ExpressionAttributeNames"] = expr_names

        if cursor:
            try:
                import base64
                kwargs["ExclusiveStartKey"] = json.loads(
                    base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
                )
            except Exception:
                return _error(400, "Invalid next_cursor")

        items: List[Dict[str, Any]] = []
        next_cursor = ""
        # Accumulate up to page_size post-filter items. DDB Limit caps the
        # pre-filter scan, so we may need multiple pages to fill page_size when
        # a FilterExpression is applied. Bound the loop to prevent runaway.
        max_pages = 10
        while len(items) < page_size and max_pages > 0:
            resp = ddb.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
            max_pages -= 1
            if len(items) >= page_size:
                # Encode cursor for caller
                import base64
                next_cursor = base64.urlsafe_b64encode(
                    json.dumps(last_key).encode("utf-8")
                ).decode("ascii")
                break

        # Trim to page_size exactly
        items = items[:page_size]

        # Deserialize and filter out counter records
        records = []
        for raw in items:
            item = _deser_item(raw)
            if item.get("record_type") == "counter":
                continue
            records.append(item)

        payload: Dict[str, Any] = {
            "success": True,
            "records": records,
            "count": len(records),
            "page_size": page_size,
        }
        if next_cursor:
            payload["next_cursor"] = next_cursor
        return _response(200, payload)

    except Exception as exc:
        logger.error("list failed: %s", exc)
        return _error(500, "Database query failed.")


def _handle_pending_updates(query_params: Dict) -> Dict:
    """GET /pending-updates — list records with non-empty update notes."""
    ddb = _get_ddb()
    project_id = query_params.get("project", "")
    scan_all = query_params.get("all", "").lower() in ("true", "1", "yes")

    try:
        if project_id and not scan_all:
            kwargs: Dict[str, Any] = {
                "TableName": DYNAMODB_TABLE,
                "KeyConditionExpression": "project_id = :pid",
                "FilterExpression": "attribute_exists(#upd) AND #upd <> :empty AND record_type <> :counter",
                "ExpressionAttributeNames": {"#upd": "update"},
                "ExpressionAttributeValues": {
                    ":pid": _ser_s(project_id),
                    ":empty": _ser_s(""),
                    ":counter": _ser_s("counter"),
                },
            }
            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                if not resp.get("LastEvaluatedKey"):
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        else:
            kwargs = {
                "TableName": DYNAMODB_TABLE,
                "FilterExpression": "attribute_exists(#upd) AND #upd <> :empty AND record_type <> :counter",
                "ExpressionAttributeNames": {"#upd": "update"},
                "ExpressionAttributeValues": {
                    ":empty": _ser_s(""),
                    ":counter": _ser_s("counter"),
                },
            }
            items = []
            while True:
                resp = ddb.scan(**kwargs)
                items.extend(resp.get("Items", []))
                if not resp.get("LastEvaluatedKey"):
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

        records = [_deser_item(raw) for raw in items]
        return _response(200, {"success": True, "records": records, "count": len(records)})

    except Exception as exc:
        logger.error("pending_updates failed: %s", exc)
        return _error(500, "Database query failed.")


# ---------------------------------------------------------------------------
# ENC-FTR-056: Hierarchical Sub-Task ID Decision Layer
# ---------------------------------------------------------------------------
# _should_use_hierarchical_id() heuristic rules (advisory — not yet enforced):
#
# 1. Caller explicitly sets is_child=True and parent_task_id — always use
#    hierarchical ID generation (_next_subtask_suffix).
# 2. If a coordination dispatch creates tasks under a feature's primary_task,
#    it MAY set is_child=True to create sub-tasks rather than siblings.
# 3. When the agent plan-capture protocol creates a task tree, the root task
#    uses _next_record_id() and child tasks use is_child=True with the root
#    as parent_task_id.
# 4. Manual / PWA-created tasks default to is_child=False (standard IDs).
# 5. Sub-task IDs are only valid for record_type="task". Attempting is_child
#    on features, issues, or lessons returns a 400 validation error.
# 6. The parent_task_id may itself be a sub-task (ENC-TSK-001-0A), but the
#    parent_root used for counter scoping is always the 3-segment root
#    (ENC-TSK-001), keeping all children flat under the same root.
# ---------------------------------------------------------------------------


def _handle_create_record(
    project_id: str,
    record_type: str,
    body: Dict,
    event: Optional[Dict] = None,
) -> Dict:
    """POST /{project}/{type} — create a new tracker record."""
    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate — agent-origin record
    # creation (write_source.provider is a minted ENC-SES id) requires a valid
    # Session Claim ID before any validation or minting occurs. Non-agent
    # providers (github, system:arc-walker, Cognito subs, ...) pass unchanged.
    _sci_err = _sci_gate_for_request(body, event)
    if _sci_err:
        return _sci_err

    title = body.get("title", "").strip()
    if not title:
        return _tracker_create_validation_error(
            "Field 'title' is required.",
            record_type=record_type,
            missing_required_fields=["title"],
        )

    # ENC-TSK-F41 / DOC-546B896390EA §5: reject create-time writes to the
    # server-side-only counter fields before any other validation. closed_count
    # and checkout_count are stamped to 0 below for task records and incremented
    # exclusively by the tracker lifecycle handler. Guard runs early so client
    # attempts to seed these fields fail fast with HTTP 400 RESERVED_FIELD
    # rather than being silently dropped after the project-prefix lookup.
    for _f41_field in _F41_RESERVED_COUNTER_FIELDS:
        if _f41_field in body:
            return _error(
                400,
                (
                    f"Field '{_f41_field}' is server-side only and must not be "
                    f"supplied at create time. It is initialized to 0 and "
                    f"incremented by the tracker lifecycle handler."
                ),
                code="RESERVED_FIELD",
                field=_f41_field,
                reason="server_side_only",
                rule_citation="ENC-TSK-F41 / DOC-546B896390EA §5",
            )

    priority = body.get("priority")
    description = str(body.get("description") or "")
    assigned_to = str(body.get("assigned_to") or "")
    status = str(body.get("status") or _DEFAULT_STATUS.get(record_type, "open"))
    severity = str(body.get("severity") or "")
    hypothesis = str(body.get("hypothesis") or "")
    technical_notes = str(body.get("technical_notes") or "")
    location_hint = str(body.get("location_hint") or "")
    success_metrics = body.get("success_metrics") or []
    related_str = body.get("related", "")
    user_story = str(body.get("user_story") or "").strip()
    category = str(body.get("category") or "").strip()
    intent = str(body.get("intent") or "").strip()
    evidence = body.get("evidence") or []
    primary_task = str(body.get("primary_task") or "").strip()
    coordination = body.get("coordination", False)
    coordination_request_id = str(body.get("coordination_request_id") or "").strip()
    dispatch_id = str(body.get("dispatch_id") or "").strip()
    is_child = bool(body.get("is_child", False))
    parent_task_id = str(body.get("parent_task_id") or "").strip()
    # ENC-TSK-L06 AC-1: optional client-supplied idempotency key. A retry with the same
    # key returns the SAME record_id instead of allocating a new one (ID Service contract;
    # inert when enable_id_service_extraction is OFF).
    idempotency_key = str(body.get("idempotency_key") or "").strip()
    # ENC-TSK-C26 / ENC-ISS-175: read transition_type at create time so the
    # create-time-only sealed values (no_code, code_only per ENC-FTR-060) can
    # actually be applied. Field-level immutability is enforced separately by
    # the tracker.set handler at the field == "transition_type" branch.
    transition_type = str(body.get("transition_type") or "").strip().lower()

    # ENC-FTR-056: Validate is_child / parent_task_id pairing
    if is_child and not parent_task_id:
        return _tracker_create_validation_error(
            "is_child=true requires parent_task_id.",
            record_type=record_type,
            missing_required_fields=["parent_task_id"],
            governed_rules=["is_child=true requires parent_task_id to generate hierarchical ID."],
        )
    if not is_child and parent_task_id:
        return _tracker_create_validation_error(
            "parent_task_id provided without is_child=true.",
            record_type=record_type,
            governed_rules=["parent_task_id is only valid when is_child=true."],
        )
    if is_child and record_type != "task":
        return _tracker_create_validation_error(
            f"is_child is only valid for task records, not {record_type}.",
            record_type=record_type,
            governed_rules=["Hierarchical sub-task IDs are only supported for task records."],
        )
    if is_child and parent_task_id and "-TSK-" not in parent_task_id.upper():
        return _tracker_create_validation_error(
            f"parent_task_id must reference a task ID (contains -TSK-). Got: '{parent_task_id}'.",
            record_type=record_type,
            governed_rules=["parent_task_id must reference an existing task ID containing -TSK-."],
        )

    if dispatch_id:
        coordination = True
    if coordination and not coordination_request_id:
        return _tracker_create_validation_error(
            "coordination=true requires coordination_request_id.",
            record_type=record_type,
            missing_required_fields=["coordination_request_id"],
            governed_rules=["coordination=true requires coordination_request_id."],
        )

    # Acceptance criteria normalization.
    # ENC-ISS-181 / ENC-TSK-C50: Delegate to _normalize_acceptance_criteria_value()
    # so the CREATE path handles the same input shapes as PATCH — plain strings,
    # list-of-dicts with description/evidence/evidence_acceptance, and JSON-stringified
    # arrays. The previous `[str(x).strip() for x in raw_ac]` collapsed dict entries
    # to their Python repr() form and wrote that garbage into the description field.
    raw_ac = body.get("acceptance_criteria")
    acceptance_criteria: List[Any] = []
    if raw_ac not in (None, ""):
        normalized_ac, ac_err = _normalize_acceptance_criteria_value(record_type, raw_ac)
        if ac_err:
            return _tracker_create_validation_error(
                ac_err,
                record_type=record_type,
                missing_required_fields=["acceptance_criteria"],
                governed_rules=[ac_err],
            )
        acceptance_criteria = normalized_ac or []

    # Validation per record type
    if record_type == "task" and not acceptance_criteria:
        return _tracker_create_validation_error(
            "Task creation requires acceptance_criteria (min 1).",
            record_type=record_type,
            missing_required_fields=["acceptance_criteria"],
            governed_rules=["acceptance_criteria must contain at least one non-empty string for tasks."],
        )

    if record_type == "feature":
        if not user_story:
            return _tracker_create_validation_error(
                "Feature creation requires user_story.",
                record_type=record_type,
                missing_required_fields=["user_story"],
            )
        if not acceptance_criteria:
            return _tracker_create_validation_error(
                "Feature creation requires acceptance_criteria (min 1).",
                record_type=record_type,
                missing_required_fields=["acceptance_criteria"],
                governed_rules=["acceptance_criteria must contain at least one criterion for features."],
            )

    if record_type == "issue":
        if not isinstance(evidence, list) or len(evidence) == 0:
            return _tracker_create_validation_error(
                "Issue creation requires evidence (min 1 entry with description + steps_to_duplicate).",
                record_type=record_type,
                missing_required_fields=["evidence"],
                governed_rules=["evidence must contain at least one object with description and steps_to_duplicate."],
            )
        for i, ev in enumerate(evidence):
            if not isinstance(ev, dict):
                return _tracker_create_validation_error(
                    f"evidence[{i}] must be an object.",
                    record_type=record_type,
                    governed_rules=["Each evidence entry must be a JSON object."],
                )
            if not ev.get("description", "").strip():
                return _tracker_create_validation_error(
                    f"evidence[{i}].description is required.",
                    record_type=record_type,
                    missing_required_fields=[f"evidence[{i}].description"],
                )
            steps = ev.get("steps_to_duplicate")
            if not isinstance(steps, list) or len(steps) == 0:
                return _tracker_create_validation_error(
                    f"evidence[{i}].steps_to_duplicate requires at least one step.",
                    record_type=record_type,
                    missing_required_fields=[f"evidence[{i}].steps_to_duplicate"],
                    governed_rules=["steps_to_duplicate must be a non-empty array of reproduction steps."],
                )
        # ENC-TSK-805 / ENC-ISS-105: Soft-warn (not hard-block) on missing location context.
        # MCP clients may not yet expose hypothesis/technical_notes/location_hint params;
        # hard 400 blocks issue creation entirely. Ontology scoring already penalizes missing fields.
        location_context_warnings: List[str] = []
        if not hypothesis and not technical_notes:
            location_context_warnings.append(
                "Issue missing hypothesis and technical_notes — investigation efficiency may be reduced (ENC-TSK-805)."
            )
        if not location_hint:
            location_context_warnings.append(
                "Issue missing location_hint — suspected code paths for investigation (ENC-TSK-805)."
            )

    # ENC-FTR-052: Lesson record validation
    if record_type == "lesson":
        if not ENABLE_LESSON_PRIMITIVE:
            return _error(400, "Lesson records are disabled. Set ENABLE_LESSON_PRIMITIVE=true to enable.")
        observation = str(body.get("observation") or "").strip()
        insight = str(body.get("insight") or "").strip()
        evidence_chain = body.get("evidence_chain")
        analysis_reference = str(body.get("analysis_reference") or "").strip()
        provenance = str(body.get("provenance") or "agent").strip()
        if not observation:
            return _tracker_create_validation_error(
                "Lesson creation requires 'observation' (what was observed in the data). This field is immutable after creation.",
                record_type=record_type,
                missing_required_fields=["observation"],
                governed_rules=["observation is required and immutable after create (ENC-FTR-052)."],
            )
        if not insight:
            return _tracker_create_validation_error(
                "Lesson creation requires 'insight' (what was learned from the observation).",
                record_type=record_type,
                missing_required_fields=["insight"],
                governed_rules=["insight is required on lesson creation."],
            )
        if not isinstance(evidence_chain, list) or len(evidence_chain) == 0:
            return _tracker_create_validation_error(
                "Lesson creation requires 'evidence_chain' (array of tracker record IDs, min 1).",
                record_type=record_type,
                missing_required_fields=["evidence_chain"],
                governed_rules=[
                    "Lesson records require evidence_chain (min 1 entry for 'proposed' status).",
                    f"Gate thresholds by target status: {json.dumps(_LESSON_TRANSITION_GATES, indent=None)}",
                ],
            )
        for i, eid in enumerate(evidence_chain):
            if not isinstance(eid, str) or not eid.strip():
                return _tracker_create_validation_error(
                    f"evidence_chain[{i}] must be a non-empty string (tracker record ID).",
                    record_type=record_type,
                    governed_rules=["Each evidence_chain entry must be a non-empty tracker record ID."],
                )
        _VALID_LESSON_PROVENANCE = ("agent", "human", "mining", "system")
        if provenance not in _VALID_LESSON_PROVENANCE:
            return _tracker_create_validation_error(
                f"Invalid provenance '{provenance}'. Allowed: {list(_VALID_LESSON_PROVENANCE)}",
                record_type=record_type,
                governed_rules=["provenance must be one of: agent, human, mining, system."],
            )
        # ENC-FTR-054: Require and validate pillar_scores for server-side scoring
        parsed_pillar_scores, pillar_err = _validate_pillar_scores(body.get("pillar_scores"), record_type)
        if pillar_err:
            return pillar_err

    # ENC-FTR-058: Plan-specific validation
    plan_objectives_set = []
    plan_attached_documents = []
    plan_related_feature_id = ""
    if record_type == "plan":
        raw_objectives = body.get("objectives_set") or body.get("objectives") or []
        if isinstance(raw_objectives, list):
            for i, obj_id in enumerate(raw_objectives):
                if not isinstance(obj_id, str) or not obj_id.strip():
                    return _tracker_create_validation_error(
                        f"objectives_set[{i}] must be a non-empty string (record ID).",
                        record_type=record_type,
                        governed_rules=["Each objective must be a valid tracker record ID (task/issue/feature)."],
                    )
            plan_objectives_set = [o.strip() for o in raw_objectives if o.strip()]
        raw_docs = body.get("attached_documents") or []
        if isinstance(raw_docs, list):
            plan_attached_documents = [d.strip() for d in raw_docs if isinstance(d, str) and d.strip()]
        plan_related_feature_id = str(body.get("related_feature_id") or "").strip()

    if primary_task:
        if record_type not in ("feature", "issue"):
            return _tracker_create_validation_error(
                f"primary_task is only valid on feature/issue records, not {record_type}.",
                record_type=record_type,
                governed_rules=["primary_task is only accepted for feature and issue records."],
            )
        if "-TSK-" not in primary_task:
            return _tracker_create_validation_error(
                f"primary_task must reference a task ID (contains -TSK-). Got: '{primary_task}'.",
                record_type=record_type,
                governed_rules=["primary_task must reference an existing task ID containing -TSK-."],
            )

    if priority and priority not in _VALID_PRIORITIES:
        return _tracker_create_validation_error(
            f"Invalid priority '{priority}'. Allowed: {list(_VALID_PRIORITIES)}",
            record_type=record_type,
            governed_rules=["priority must be one of the governed enum values."],
        )
    if category and category not in _VALID_CATEGORIES.get(record_type, set()):
        return _tracker_create_validation_error(
            f"Invalid category '{category}' for {record_type}. Allowed: {sorted(_VALID_CATEGORIES.get(record_type, set()))}",
            record_type=record_type,
            governed_rules=["category must match the governed enum set for the record type."],
        )
    # ENC-TSK-C26 / ENC-ISS-175: validate transition_type at create time.
    # Only valid for tasks; reject unknown values with a clear 400 instead of
    # silently dropping (which previously stranded no_code/code_only intent).
    if transition_type:
        if record_type != "task":
            return _tracker_create_validation_error(
                f"transition_type is only valid for task records, not {record_type}.",
                record_type=record_type,
                governed_rules=["transition_type selects a task lifecycle arc and is only meaningful on tasks."],
            )
        if transition_type not in _VALID_TRANSITION_TYPES:
            return _tracker_create_validation_error(
                f"Invalid transition_type '{transition_type}'. Allowed: {list(_VALID_TRANSITION_TYPES)}",
                record_type=record_type,
                governed_rules=["transition_type must be one of the governed enum values."],
            )

    category_warning = ""

    # Resolve project prefix
    prefix = _get_project_prefix(project_id)
    if not prefix:
        return _error(404, f"Project '{project_id}' not found or has no prefix.")

    ddb = _get_ddb()
    now = _now_z()
    note_suffix = _write_source_note_suffix(body)

    # Build the DynamoDB item
    item: Dict[str, Any] = {
        "project_id": _ser_s(project_id),
        "record_type": _ser_s(record_type),
        "title": _ser_s(title),
        "status": _ser_s(status),
        "sync_version": {"N": "1"},
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "coordination": {"BOOL": bool(coordination)},
        "write_source": _build_write_source(body),
        "history": {"L": [{"M": {
            "timestamp": _ser_s(now),
            "status": _ser_s("created"),
            "description": _ser_s(f"Created via tracker API{note_suffix}: {title}"),
        }}]},
    }
    # ENC-FTR-111 / ENC-TSK-H83: the auto_walk_opt_out circuit breaker exists on
    # task/issue/feature/plan and defaults false. An explicit create-time value
    # (MCP denylist passthrough) is honored and coerced to a real BOOL.
    if record_type in ("task", "issue", "feature", "plan"):
        item["auto_walk_opt_out"] = {"BOOL": _coerce_bool(body.get("auto_walk_opt_out", False))}
    if coordination_request_id:
        item["coordination_request_id"] = _ser_s(coordination_request_id)
    if description:
        item["description"] = _ser_s(description)
    if priority:
        item["priority"] = _ser_s(priority)
    if assigned_to:
        item["assigned_to"] = _ser_s(assigned_to)
    if record_type == "issue":
        if severity:
            item["severity"] = _ser_s(severity)
        if hypothesis:
            item["hypothesis"] = _ser_s(hypothesis)
        if technical_notes:
            item["technical_notes"] = _ser_s(technical_notes)
        if location_hint:
            item["location_hint"] = _ser_s(location_hint)
    if record_type == "feature" and isinstance(success_metrics, list) and success_metrics:
        item["success_metrics"] = {"L": [_ser_s(str(x)) for x in success_metrics if str(x).strip()]}

    # Acceptance criteria
    if acceptance_criteria:
        if record_type in ("feature", "task"):
            # ENC-FTR-048: features and tasks both use structured AC with evidence tracking.
            # ENC-ISS-181 / ENC-TSK-C50: acceptance_criteria has already been normalized
            # above into a list of dicts {description, evidence, evidence_acceptance} by
            # _normalize_acceptance_criteria_value(). Consume the structured form directly
            # instead of stringifying — the previous `_ser_s(ac)` path wrote repr(dict) into
            # the description column whenever callers passed dict-shaped AC entries.
            ac_items = [{"M": {
                "description": _ser_s(ac["description"]),
                "evidence": _ser_s(ac.get("evidence", "") or ""),
                "evidence_acceptance": {"BOOL": bool(ac.get("evidence_acceptance", False))},
            }} for ac in acceptance_criteria]
            item["acceptance_criteria"] = {"L": ac_items}
        else:
            item["acceptance_criteria"] = {"L": [_ser_s(x) for x in acceptance_criteria]}

    # Ontology fields
    if record_type == "feature" and user_story:
        item["user_story"] = _ser_s(user_story)
    if record_type == "issue" and evidence:
        ev_items = []
        for ev in evidence:
            ev_map: Dict[str, Any] = {
                "description": _ser_s(str(ev.get("description", ""))),
                "steps_to_duplicate": {"L": [_ser_s(str(s)) for s in ev.get("steps_to_duplicate", [])]},
            }
            if ev.get("observed_by"):
                ev_map["observed_by"] = _ser_s(str(ev["observed_by"]))
            if ev.get("timestamp"):
                ev_map["timestamp"] = _ser_s(str(ev["timestamp"]))
            ev_items.append({"M": ev_map})
        item["evidence"] = {"L": ev_items}
    if record_type == "task":
        item["active_agent_session"] = {"BOOL": False}
        item["active_agent_session_id"] = _ser_s("")
        item["active_agent_session_parent"] = {"BOOL": False}
        # ENC-TSK-C26 / ENC-ISS-175: persist transition_type at create time so the
        # sealed values (no_code, code_only) can actually take effect.
        if transition_type:
            item["transition_type"] = _ser_s(transition_type)
        # ENC-TSK-F76 / ENC-ISS-289: persist components at create time so agent
        # checkouts don't require a follow-up tracker.set to satisfy the
        # ENC-FTR-041 component-enforcement check at the first advance gate.
        # Accepts list or JSON-stringified list (same coercion as tracker.set
        # via the ENC-ISS-059 pattern).
        raw_components = body.get("components")
        if raw_components is not None:
            if isinstance(raw_components, str):
                try:
                    raw_components = json.loads(raw_components)
                except (TypeError, ValueError):
                    raw_components = [raw_components] if raw_components.strip() else []
            if isinstance(raw_components, list):
                component_ids = [
                    str(c).strip() for c in raw_components if str(c).strip()
                ]
                if component_ids:
                    item["components"] = {
                        "L": [_ser_s(c) for c in component_ids]
                    }
        # ENC-TSK-F41 / DOC-546B896390EA §5: stamp FTR-076 v2 counter defaults.
        # closed_count and checkout_count are server-side only (reserved against
        # caller writes above) and start at 0. They are incremented atomically
        # by the tracker lifecycle handler on state transitions.
        item["closed_count"] = {"N": "0"}
        item["checkout_count"] = {"N": "0"}
    # ENC-FTR-052: Lesson-specific fields
    if record_type == "lesson":
        item["observation"] = _ser_s(observation)
        item["insight"] = _ser_s(insight)
        item["evidence_chain"] = {"L": [_ser_s(eid.strip()) for eid in evidence_chain]}
        item["provenance"] = _ser_s(provenance)
        item["confidence"] = {"N": str(body.get("confidence", 0.5))}
        # ENC-FTR-054: Constitutional scores. ENC-TSK-H47 / B63 Phase 2B: when the Scoring Service
        # is ON, defer the computation to the async SNS-triggered service — store only the validated
        # pillar_scores and mark scoring_status='pending'; the service computes pillar_composite +
        # resonance_score and flips scoring_status -> 'scored'. When OFF (rollback), score inline
        # exactly as before and mark scoring_status='scored' (the lesson is born already scored).
        item["pillar_scores"] = {"M": {k: {"N": str(v)} for k, v in parsed_pillar_scores.items()}}
        if _scoring_service_enabled():
            item["scoring_status"] = {"S": "pending"}
        else:
            pillar_composite = _compute_lesson_pillar_composite(parsed_pillar_scores)
            resonance_score = _compute_resonance_score(parsed_pillar_scores)
            item["resonance_score"] = {"N": str(resonance_score)}
            item["pillar_composite"] = {"N": str(pillar_composite)}
            item["scoring_status"] = {"S": "scored"}
        item["extensions"] = {"L": []}
        item["lesson_version"] = {"N": "1"}
        if analysis_reference:
            item["analysis_reference"] = _ser_s(analysis_reference)
    # ENC-FTR-058: Plan-specific fields
    if record_type == "plan":
        item["objectives_set"] = {"L": [_ser_s(o) for o in plan_objectives_set]}
        item["attached_documents"] = {"L": [_ser_s(d) for d in plan_attached_documents]}
        if plan_related_feature_id:
            item["related_feature_id"] = _ser_s(plan_related_feature_id)
        item["checkout_state"] = _ser_s("")
        item["checked_out_by"] = _ser_s("")
        item["checked_out_at"] = _ser_s("")
    if category:
        item["category"] = _ser_s(category)
    if intent:
        item["intent"] = _ser_s(intent)
    if primary_task and record_type in ("feature", "issue"):
        item["primary_task"] = _ser_s(primary_task)
    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        for field_name, ids in _classify_related_ids(related_ids).items():
            if ids:
                item[field_name] = {"L": [_ser_s(i) for i in ids]}

    # ENC-ISS-132 / ENC-TSK-L06 AC-3: Reject externally-provided record IDs — IDs are
    # generated server-side only. AC-4: every rejection here also feeds the ID Service's
    # per-caller trust-score violation counter (best-effort, fire-and-forget — the 400
    # rejection itself never depends on or is delayed by the notify call).
    for forbidden_field in ("item_id", "record_id", "item_id_provenance"):
        if body.get(forbidden_field):
            _record_id_boundary_violation(body, record_type, forbidden_field)
            return _error(
                400,
                f"Field '{forbidden_field}' must not be provided — record IDs and their provenance "
                f"are generated server-side.",
                code="ID_BOUNDARY_VIOLATION",
            )
    # ENC-TSK-F41 reserved-counter-field guard runs at the top of this handler
    # (before project prefix lookup) so body-level seed attempts fail fast.

    # ENC-TSK-L06 / B63 Phase 2 AC-6: when enable_id_service_extraction is ON, the standalone
    # ID Service is the SOLE authority for record-ID allocation, the idempotency-key contract,
    # and HMAC provenance signing. FAIL-CLOSED — an invoke failure rejects the create; the
    # inline counter-based allocation below runs only as the flag-OFF rollback path.
    item_id_provenance: str = ""
    if _id_service_enabled():
        ws = _normalize_write_source(body)
        _id_verdict = _invoke_id_service({
            "action": "allocate",
            "project_id": project_id,
            "prefix": prefix,
            "record_type": record_type,
            "idempotency_key": idempotency_key,
            "is_child": is_child,
            "parent_task_id": parent_task_id,
            "created_at": now,
            "caller_identity": ws.get("provider") or "",
        })
        if _id_verdict is None:
            return _error(
                503,
                "ID Service unavailable; create rejected (fail-closed, ENC-TSK-L06). "
                "Retry shortly, or disable the enable_id_service_extraction flag to fall "
                "back to inline allocation.",
                code="ID_SERVICE_UNAVAILABLE",
                retryable=True,
            )
        if not _id_verdict.get("allow"):
            _id_err = _id_verdict.get("error") or {}
            return _error(
                int(_id_err.get("status", 400) or 400),
                _id_err.get("message", "ID Service rejected the allocation."),
                code=_id_err.get("code", "INVALID_INPUT"),
            )
        new_id = _id_verdict["record_id"]
        item_id_provenance = _id_verdict.get("item_id_provenance", "")
        if is_child and parent_task_id:
            item["parent"] = _ser_s(parent_task_id.upper())
        sk = f"{record_type}#{new_id}"
        item["record_id"] = _ser_s(sk)
        item["item_id"] = _ser_s(new_id)
        if item_id_provenance:
            item["item_id_provenance"] = _ser_s(item_id_provenance)
        _stamp_version_seq_on_create_item(item)
        try:
            ddb.put_item(
                TableName=DYNAMODB_TABLE, Item=item,
                ConditionExpression="attribute_not_exists(record_id)",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("create failed (ID Service path): %s", exc)
            return _error(500, "Database write failed.")
        # Falls through to the shared post-write continuation below (lesson scoring publish,
        # parent subtask_ids update, bidirectional relationships, response construction) —
        # identical for both the ID-Service and inline-rollback allocation paths.
    else:
        # --- Flag-OFF rollback path: inline counter-based allocation (unchanged from pre-L06) ---
        try:
            for attempt in range(1, _TRACKER_CREATE_MAX_ATTEMPTS + 1):
                if is_child and parent_task_id:
                    # ENC-FTR-056: Generate hierarchical sub-task ID
                    parent_upper = parent_task_id.upper()
                    parent_parts = parent_upper.split("-")
                    parent_root = "-".join(parent_parts[:3])  # PREFIX-TSK-CCC
                    suffix = _next_subtask_suffix(project_id, parent_root)
                    new_id = f"{parent_root}-{suffix}"
                    item["parent"] = _ser_s(parent_upper)
                else:
                    new_id = _next_record_id(project_id, prefix, record_type)
                sk = f"{record_type}#{new_id}"
                item["record_id"] = _ser_s(sk)
                item["item_id"] = _ser_s(new_id)
                _stamp_version_seq_on_create_item(item)
                try:
                    ddb.put_item(
                        TableName=DYNAMODB_TABLE, Item=item,
                        ConditionExpression="attribute_not_exists(record_id)",
                    )
                    break
                except ClientError as exc:
                    if _is_conditional_check_failed(exc) and attempt < _TRACKER_CREATE_MAX_ATTEMPTS:
                        continue
                    raise
            else:
                return _error(500, f"Failed to allocate unique record ID after {_TRACKER_CREATE_MAX_ATTEMPTS} attempts.")
        except ValueError as ve:
            # Sub-task capacity exhausted
            logger.error("create failed (capacity): %s", ve)
            return _error(400, str(ve))
        except Exception as exc:
            logger.error("create failed: %s", exc)
            return _error(500, "Database write failed.")

    # ENC-TSK-H47 / B63 Phase 2B: a lesson written with scoring_status='pending' (flag ON) needs the
    # async Scoring Service kicked off. Publish AFTER the write succeeds (the lesson is the source of
    # truth) and best-effort — a failed publish leaves the lesson scoring_status='pending' for a
    # re-drive, never a failed create. No-op when the flag is OFF (inline scoring already ran).
    if record_type == "lesson" and _scoring_service_enabled():
        _publish_lesson_scoring_request(project_id, sk, new_id, parsed_pillar_scores)

    # ENC-FTR-056: Update parent record's subtask_ids list
    if is_child and parent_task_id:
        try:
            parent_upper = parent_task_id.upper()
            parent_parts = parent_upper.split("-")
            parent_root = "-".join(parent_parts[:3])
            parent_type_seg = parent_parts[1] if len(parent_parts) >= 2 else "TSK"
            parent_type = _ID_SEGMENT_TO_TYPE.get(parent_type_seg, "task")
            parent_sk = f"{parent_type}#{parent_upper}"
            ddb.update_item(
                TableName=DYNAMODB_TABLE,
                Key={
                    "project_id": _ser_s(project_id),
                    "record_id": _ser_s(parent_sk),
                },
                UpdateExpression=(
                    "SET subtask_ids = list_append(if_not_exists(subtask_ids, :empty_list), :new_child), "
                    "updated_at = :now"
                ),
                ExpressionAttributeValues={
                    ":empty_list": {"L": []},
                    ":new_child": {"L": [_ser_s(new_id)]},
                    ":now": _ser_s(_now_z()),
                },
            )
        except Exception as exc:
            logger.warning("Failed to update parent subtask_ids for %s: %s", parent_task_id, exc)

    # Best-effort bidirectional relationships
    bidi_warnings = []
    if related_str:
        related_ids = [r.strip() for r in related_str.split(",") if r.strip()]
        inverse_field = f"related_{record_type}_ids"
        for target_id in related_ids:
            try:
                target_id_upper = target_id.upper()
                target_parts = target_id_upper.split("-")
                if len(target_parts) < 3 or len(target_parts) > 4:
                    continue
                target_type_seg = target_parts[1]
                target_type = _ID_SEGMENT_TO_TYPE.get(target_type_seg)
                if not target_type:
                    continue
                # We need target's project_id — try looking it up from the prefix
                target_prefix_map = _get_prefix_map_cached()
                target_project = target_prefix_map.get(target_parts[0])
                if not target_project:
                    continue
                target_key = _build_key(target_project, target_type, target_id_upper)
                ddb.update_item(
                    TableName=DYNAMODB_TABLE, Key=target_key,
                    UpdateExpression="SET #rel = list_append(if_not_exists(#rel, :empty), :new_id)",
                    ExpressionAttributeNames={"#rel": inverse_field},
                    ExpressionAttributeValues={
                        ":new_id": {"L": [_ser_s(new_id)]},
                        ":empty": {"L": []},
                    },
                    ConditionExpression="attribute_exists(record_id)",
                )
            except Exception as exc:
                bidi_warnings.append(f"Could not add inverse relationship on {target_id}: {exc}")

    result: Dict[str, Any] = {"success": True, "record_id": new_id, "created_at": now}
    if category_warning:
        result["warning"] = category_warning
    if bidi_warnings:
        result["bidi_warnings"] = bidi_warnings
    # ENC-ISS-105: surface location context warnings without blocking creation
    if record_type == "issue" and location_context_warnings:
        result["location_context_warnings"] = location_context_warnings
    return _response(201, result)


# Prefix map cache for bidirectional relationships
_prefix_map_cache: Optional[Dict[str, str]] = None
_prefix_map_cache_at: float = 0.0


def _get_prefix_map_cached() -> Dict[str, str]:
    global _prefix_map_cache, _prefix_map_cache_at
    now = time.time()
    if _prefix_map_cache is not None and (now - _prefix_map_cache_at) < 300.0:
        return _prefix_map_cache
    try:
        ddb = _get_ddb()
        resp = ddb.scan(
            TableName=PROJECTS_TABLE,
            ProjectionExpression="project_id, prefix",
        )
        mapping = {}
        for item in resp.get("Items", []):
            pid = item.get("project_id", {}).get("S", "")
            pfx = item.get("prefix", {}).get("S", "")
            if pid and pfx:
                mapping[pfx] = pid
        _prefix_map_cache = mapping
        _prefix_map_cache_at = now
        return mapping
    except Exception:
        return _prefix_map_cache or {}


# ---------------------------------------------------------------------------
# Lifecycle governance helpers (ENC-FTR-022)
# ---------------------------------------------------------------------------


def _validate_commit_via_github(owner: str, repo: str, sha: str) -> Tuple[bool, str]:
    """Call github_integration Lambda's /commits/validate endpoint."""
    if not GITHUB_INTEGRATION_API_BASE:
        logger.warning("GITHUB_INTEGRATION_API_BASE not set; skipping commit validation")
        return True, "validation_skipped"
    url = (
        f"{GITHUB_INTEGRATION_API_BASE}/commits/validate"
        f"?owner={urllib.parse.quote(owner)}"
        f"&repo={urllib.parse.quote(repo)}"
        f"&sha={urllib.parse.quote(sha)}"
    )
    req = urllib.request.Request(url, method="GET", headers={
        "X-Coordination-Internal-Key": COORDINATION_INTERNAL_API_KEY,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("valid"):
                return True, data.get("message", "")
            return False, data.get("reason", "commit_not_found")
    except Exception as exc:
        logger.error("Commit validation call failed: %s", exc)
        return False, f"validation_service_error: {exc}"


def _query_all_project_tasks(project_id: str) -> List[Dict]:
    """Query all task records for a project. Returns deserialized items."""
    ddb = _get_ddb()
    items: List[Dict] = []
    kwargs = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": {"S": project_id},
            ":prefix": {"S": "task#"},
        },
        "ProjectionExpression": "record_id, item_id, #s, parent",
        "ExpressionAttributeNames": {"#s": "status"},
    }
    while True:
        resp = ddb.query(**kwargs)
        for raw in resp.get("Items", []):
            items.append(_deser_item(raw))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items


# ENC-TSK-726: Required fields on a GitHub Actions Jobs API response object.
# Source: GET /repos/{owner}/{repo}/actions/jobs/{job_id}
_DEPLOY_EVIDENCE_REQUIRED_FIELDS = (
    "id", "name", "run_id", "head_sha", "status", "conclusion", "started_at", "completed_at"
)


def _is_valid_iso8601(value: str) -> bool:
    """Return True if value is a valid ISO 8601 datetime string (e.g. 2026-03-01T18:21:57Z).

    Accepts both trailing-Z and offset forms (+00:00).  Matches the tracker
    timestamp convention used for updated_at / created_at fields.
    Requires the 'T' date/time separator — date-only strings (e.g. 2026-03-01) are rejected.
    """
    if not value or "T" not in value:
        return False
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


def _validate_deploy_evidence(deploy_evidence) -> Optional[str]:
    """Validate deploy_evidence is a structured GitHub Actions Jobs API payload.

    Source API: GET /repos/{owner}/{repo}/actions/jobs/{job_id}
    Required fields: id, name, run_id, head_sha, status, conclusion, started_at, completed_at
    Value assertions:
      - status  must equal "completed"
      - conclusion must equal "success"
    Datetime fields (started_at, completed_at) must be valid ISO 8601 strings.

    Returns None if valid, or an error string describing the first violation.
    """
    if not deploy_evidence:
        return (
            "Cannot transition to 'deploy-success': transition_evidence.deploy_evidence required. "
            "Must be a GitHub Actions Jobs API response object "
            "(GET /repos/{owner}/{repo}/actions/jobs/{job_id})."
        )
    if not isinstance(deploy_evidence, dict):
        return (
            "Cannot transition to 'deploy-success': transition_evidence.deploy_evidence must be "
            "a structured object (GitHub Actions Jobs API response), not a plain string. "
            f"Required fields: {', '.join(_DEPLOY_EVIDENCE_REQUIRED_FIELDS)}."
        )
    missing = [
        f for f in _DEPLOY_EVIDENCE_REQUIRED_FIELDS
        if f not in deploy_evidence
        or deploy_evidence[f] is None
        or str(deploy_evidence[f]).strip() == ""
    ]
    if missing:
        return (
            f"Cannot transition to 'deploy-success': deploy_evidence missing required "
            f"GitHub Actions Jobs API field(s): {', '.join(missing)}. "
            "Source: GET /repos/{owner}/{repo}/actions/jobs/{job_id}."
        )
    head_sha = str(deploy_evidence.get("head_sha", "")).strip()
    if not re.match(r"^[0-9a-f]{40}$", head_sha.lower()):
        return (
            "Cannot transition to 'deploy-success': deploy_evidence.head_sha must be "
            f"a 40-character hex SHA. Got: '{deploy_evidence.get('head_sha')}'."
        )
    status_val = str(deploy_evidence.get("status", "")).strip().lower()
    if status_val != "completed":
        return (
            f"Cannot transition to 'deploy-success': deploy_evidence.status must be 'completed'. "
            f"Got: '{deploy_evidence.get('status')}'. "
            "Job must have reached a terminal completed state before evidence is accepted."
        )
    conclusion_val = str(deploy_evidence.get("conclusion", "")).strip().lower()
    if conclusion_val != "success":
        return (
            f"Cannot transition to 'deploy-success': deploy_evidence.conclusion must be 'success'. "
            f"Got: '{deploy_evidence.get('conclusion')}'. "
            "Only GitHub Actions jobs with conclusion=success qualify as deploy evidence."
        )
    for dt_field in ("started_at", "completed_at"):
        val = str(deploy_evidence.get(dt_field, "")).strip()
        if not _is_valid_iso8601(val):
            return (
                f"Cannot transition to 'deploy-success': deploy_evidence.{dt_field} must be "
                f"a valid ISO 8601 datetime (e.g. 2026-03-01T18:21:57Z). Got: '{val}'."
            )
    return None


def _validate_web_deploy_evidence(web_deploy_evidence) -> Optional[str]:
    """Validate web_deploy_evidence for static/CloudFront deployments (ENC-ISS-144).

    Required fields: url (HTTPS), http_status (200), checked_at (ISO 8601).
    Returns None if valid, or an error string describing the first violation.
    """
    if not web_deploy_evidence:
        return (
            "Cannot transition to 'deploy-success': transition_evidence.web_deploy_evidence required "
            "for web_deploy tasks. Must contain {url, http_status, checked_at}."
        )
    if not isinstance(web_deploy_evidence, dict):
        return (
            "Cannot transition to 'deploy-success': transition_evidence.web_deploy_evidence must be "
            "a structured object with url, http_status, checked_at."
        )
    url = str(web_deploy_evidence.get("url", "")).strip()
    if not url.startswith("https://"):
        return (
            f"Cannot transition to 'deploy-success': web_deploy_evidence.url must start with "
            f"'https://'. Got: '{url}'."
        )
    http_status = web_deploy_evidence.get("http_status")
    try:
        http_status_int = int(http_status)
    except (TypeError, ValueError):
        http_status_int = -1
    if http_status_int != 200:
        return (
            f"Cannot transition to 'deploy-success': web_deploy_evidence.http_status must be 200. "
            f"Got: '{http_status}'."
        )
    checked_at = str(web_deploy_evidence.get("checked_at", "")).strip()
    if not _is_valid_iso8601(checked_at):
        return (
            f"Cannot transition to 'deploy-success': web_deploy_evidence.checked_at must be "
            f"a valid ISO 8601 datetime with T separator. Got: '{checked_at}'."
        )
    return None


def _validate_lambda_deploy_evidence(lambda_deploy_evidence) -> Optional[str]:
    """Validate lambda_deploy_evidence for Lambda function deployments (ENC-FTR-059, ENC-ISS-162).

    Accepts two shapes:
    1. Simplified 4-field schema (governance.dictionary): {function_name, version, updated_at, status}
       - status must be 'Success'
       - updated_at must be ISO 8601 with 'T' separator
    2. Full AWS GetFunctionConfiguration response: {FunctionArn, FunctionName, Version, ...}
       - State must be 'Active', LastUpdateStatus must be 'Successful'

    Shape is auto-detected by presence of 'function_name' (simplified) vs 'FunctionArn' (full AWS).
    Returns None if valid, or an error string describing the first violation.
    """
    if not lambda_deploy_evidence:
        return (
            "Cannot transition to 'deploy-success': "
            "transition_evidence.lambda_deploy_evidence required for lambda_deploy tasks. "
            "Accepts simplified {function_name, version, updated_at, status} or full AWS GetFunctionConfiguration."
        )
    if not isinstance(lambda_deploy_evidence, dict):
        return (
            "Cannot transition to 'deploy-success': "
            "transition_evidence.lambda_deploy_evidence must be a structured object."
        )

    # ENC-ISS-162: Auto-detect schema shape — simplified (lowercase) vs full AWS (PascalCase)
    if lambda_deploy_evidence.get("function_name") or not lambda_deploy_evidence.get("FunctionArn"):
        # Simplified 4-field schema: {function_name, version, updated_at, status}
        return _validate_lambda_deploy_evidence_simplified(lambda_deploy_evidence)

    # Full AWS GetFunctionConfiguration shape
    return _validate_lambda_deploy_evidence_full(lambda_deploy_evidence)


def _validate_lambda_deploy_evidence_simplified(evidence: dict) -> Optional[str]:
    """Validate simplified lambda_deploy_evidence: {function_name, version, updated_at, status}."""
    function_name = (evidence.get("function_name") or "").strip()
    if not function_name:
        return "lambda_deploy_evidence.function_name is required"

    version = (evidence.get("version") or "").strip()
    if not version:
        return "lambda_deploy_evidence.version is required"

    updated_at = (evidence.get("updated_at") or "").strip()
    if not updated_at:
        return "lambda_deploy_evidence.updated_at is required"
    if "T" not in updated_at:
        return (
            f"lambda_deploy_evidence.updated_at must be ISO 8601 with 'T' separator, "
            f"got: '{updated_at}'"
        )
    try:
        dt.datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        return f"lambda_deploy_evidence.updated_at is not a valid ISO 8601 timestamp: {exc}"

    status = (evidence.get("status") or "").strip()
    if not status:
        return "lambda_deploy_evidence.status is required"
    if status != "Success":
        return f"lambda_deploy_evidence.status must be 'Success', got: '{status}'"

    return None


def _validate_lambda_deploy_evidence_full(evidence: dict) -> Optional[str]:
    """Validate full AWS GetFunctionConfiguration lambda_deploy_evidence."""
    required = (
        "FunctionArn", "FunctionName", "Version", "CodeSha256", "CodeSize",
        "ConfigSha256", "LastModified", "RevisionId", "State", "LastUpdateStatus",
    )
    missing = [f for f in required if not evidence.get(f)]
    if missing:
        return (
            f"Cannot transition to 'deploy-success': lambda_deploy_evidence missing "
            f"required field(s): {', '.join(missing)}. "
            "Source: AWS Lambda GetFunctionConfiguration after UpdateFunctionCode with Publish=true."
        )
    state = str(evidence.get("State", "")).strip()
    if state != "Active":
        return (
            f"Cannot transition to 'deploy-success': lambda_deploy_evidence.State must be "
            f"'Active'. Got: '{state}'. Poll until Active before submitting evidence."
        )
    update_status = str(evidence.get("LastUpdateStatus", "")).strip()
    if update_status != "Successful":
        return (
            f"Cannot transition to 'deploy-success': lambda_deploy_evidence.LastUpdateStatus "
            f"must be 'Successful'. Got: '{update_status}'."
        )
    return None


# ENC-FTR-059: Matrix-driven deploy-success validator registry for tracker mutation.
# Maps transition_type → (evidence_key, validator_fn, format_description).
_DEPLOY_SUCCESS_VALIDATORS: Dict[str, tuple] = {
    "github_pr_deploy": (
        "deploy_evidence",
        _validate_deploy_evidence,
        "transition_evidence.deploy_evidence with id, name, run_id, head_sha, status, conclusion, started_at, completed_at",
    ),
    "lambda_deploy": (
        "lambda_deploy_evidence",
        _validate_lambda_deploy_evidence,
        "transition_evidence.lambda_deploy_evidence: simplified {function_name, version, updated_at, status=Success} or full AWS {FunctionArn, FunctionName, Version, State=Active, LastUpdateStatus=Successful}",
    ),
    "web_deploy": (
        "web_deploy_evidence",
        _validate_web_deploy_evidence,
        "transition_evidence.web_deploy_evidence with url, http_status, checked_at",
    ),
}


def _validate_feature_production_gate(project_id: str, feature_data: Dict) -> Optional[Dict]:
    """Enforce: feature -> production requires >=1 child task, all deploy-success/closed recursively."""
    primary = (feature_data.get("primary_task") or "").strip()
    related = feature_data.get("related_task_ids") or []
    root_ids: set = set()
    if primary:
        root_ids.add(primary)
    for r in related:
        rid = r.strip() if isinstance(r, str) else ""
        if rid:
            root_ids.add(rid)

    if not root_ids:
        return _error(400,
            "Cannot transition to 'production': feature has no child tasks. "
            "Set primary_task or related_task_ids first.")

    all_tasks = _query_all_project_tasks(project_id)
    task_map = {t.get("item_id", ""): t for t in all_tasks}

    # Build parent -> children graph
    parent_children: Dict[str, List[str]] = {}
    for t in all_tasks:
        p = (t.get("parent") or "").strip()
        if p:
            parent_children.setdefault(p, []).append(t.get("item_id", ""))

    # BFS: expand root_ids through parent->child relationships
    visited: set = set()
    queue = list(root_ids)
    while queue:
        tid = queue.pop(0)
        if tid in visited:
            continue
        visited.add(tid)
        for child_id in parent_children.get(tid, []):
            queue.append(child_id)

    # Check all visited tasks are deployed or closed
    not_ready = []
    for tid in sorted(visited):
        task = task_map.get(tid)
        if not task:
            not_ready.append(f"{tid} (not_found)")
            continue
        status = (task.get("status") or "unknown").strip().lower()
        if status not in ("deploy-success", "closed"):
            not_ready.append(f"{tid} ({status})")

    if not_ready:
        return _error(400,
            f"Cannot transition to 'production': "
            f"{len(not_ready)} task(s) not deploy-success/closed:\n"
            + "\n".join(not_ready[:20]))
    return None


def _normalize_acceptance_criterion(entry: Any, index: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalize one acceptance criterion to governed map form (features and tasks)."""
    if isinstance(entry, dict):
        description = str(entry.get("description") or "").strip()
        if not description:
            return None, (
                f"acceptance_criteria[{index}] requires a non-empty 'description' field."
            )
        evidence = str(entry.get("evidence") or "")
        evidence_acceptance = bool(entry.get("evidence_acceptance", False))
        return {
            "description": description,
            "evidence": evidence,
            "evidence_acceptance": evidence_acceptance,
        }, None

    description = str(entry).strip()
    if not description:
        return None, (
            f"acceptance_criteria[{index}] must be a non-empty string or object."
        )
    return {
        "description": description,
        "evidence": "",
        "evidence_acceptance": False,
    }, None


def _normalize_acceptance_criteria_value(record_type: str, raw_value: Any) -> Tuple[Optional[List[Any]], Optional[str]]:
    """Normalize PATCH acceptance_criteria payloads, including JSON-stringified arrays."""
    parsed_value = raw_value

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return None, "acceptance_criteria must not be empty."
        if stripped[0] in "[{":
            try:
                parsed_value = json.loads(stripped)
            except json.JSONDecodeError:
                parsed_value = stripped
        else:
            parsed_value = stripped

    if isinstance(parsed_value, dict):
        parsed_list: List[Any] = [parsed_value]
    elif isinstance(parsed_value, list):
        parsed_list = parsed_value
    else:
        parsed_list = [parsed_value]

    if record_type in ("feature", "task"):
        # ENC-FTR-048: features and tasks both use structured acceptance criteria.
        # Pre-filter empty string entries for backward compatibility (tasks previously
        # silently dropped empties; features reject them — preserve both behaviors).
        normalized_criteria: List[Dict[str, Any]] = []
        for idx, entry in enumerate(parsed_list):
            # Skip empty strings silently (backward compat with old task string-list path)
            if isinstance(entry, str) and not entry.strip():
                continue
            normalized, error = _normalize_acceptance_criterion(entry, idx)
            if error:
                return None, error
            normalized_criteria.append(normalized)
        if not normalized_criteria:
            return None, f"{record_type.capitalize()} acceptance_criteria requires at least one criterion."
        return normalized_criteria, None

    normalized_list = [str(x).strip() for x in parsed_list if str(x).strip()]
    if not normalized_list:
        return None, "acceptance_criteria requires at least one non-empty criterion."
    return normalized_list, None


def _normalize_evidence_value(raw_value: Any) -> Tuple[Optional[List[Any]], Optional[str]]:
    """Normalize PATCH evidence payloads, including JSON-stringified arrays.

    ENC-TSK-783 / ENC-ISS-099: Evidence written via tracker_set (MCP) may arrive as a
    JSON string instead of a parsed list, which would be stored as DynamoDB {"S": ...}
    and later crash the PWA with 'evidence.map is not a function'.
    This function coerces string payloads to the proper List type and validates structure.
    """
    parsed_value = raw_value

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return None, "evidence must not be empty."
        if stripped[0] in "[{":
            try:
                parsed_value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return None, f"evidence string is not valid JSON: {exc}"
        else:
            return None, "evidence must be a JSON array of evidence objects."

    if isinstance(parsed_value, dict):
        parsed_list: List[Any] = [parsed_value]
    elif isinstance(parsed_value, list):
        parsed_list = parsed_value
    else:
        return None, "evidence must be a list of evidence objects."

    if not parsed_list:
        return None, "evidence requires at least one entry."

    for i, ev in enumerate(parsed_list):
        if not isinstance(ev, dict):
            return None, f"evidence[{i}] must be an object."
        if not ev.get("description", "").strip():
            return None, f"evidence[{i}].description is required."
        steps = ev.get("steps_to_duplicate")
        if not isinstance(steps, list) or len(steps) == 0:
            return None, f"evidence[{i}].steps_to_duplicate requires at least one step."

    return parsed_list, None


def _apply_reverse_relation_edges(
    project_id: str,
    record_type: str,
    record_id: str,
    field: str,
    old_ids: Optional[List[str]],
    new_ids: Optional[List[str]],
) -> None:
    """ENC-TSK-L07 (B63 AC-7 / B65 AC-5/AC-7): mirror newly-added related_*_ids
    onto each target's reverse field so cross-references are bidirectional.

    Reverse field on the target is always related_{source_record_type}_ids —
    symmetric to how the source stores related_{target_record_type}_ids.
    Each target write is an independently atomic conditional append
    (contains-check as the DynamoDB ConditionExpression); a target that
    already carries the back-reference is a silent no-op (idempotent), and a
    missing/unknown target is skipped without failing the primary write,
    which has already committed by the time this runs.
    """
    old_set = set(old_ids or [])
    added = [rid.strip().upper() for rid in (new_ids or []) if rid and rid.strip().upper() not in old_set]
    if not added:
        return
    reverse_field = f"related_{record_type}_ids"
    if reverse_field not in _RELATION_ID_FIELDS:
        return
    ddb = _get_ddb()
    now = _now_z()
    for target_id in added:
        target_type = _record_type_from_id(target_id)
        if target_type not in _TYPE_SEG_TO_SK_PREFIX:
            continue
        try:
            target_key = _build_key(project_id, target_type, target_id)
            ddb.update_item(
                TableName=DYNAMODB_TABLE,
                Key=target_key,
                UpdateExpression=(
                    "SET #rf = list_append(if_not_exists(#rf, :empty), :new), updated_at = :now"
                ),
                ConditionExpression="attribute_not_exists(#rf) OR NOT contains(#rf, :rid)",
                ExpressionAttributeNames={"#rf": reverse_field},
                ExpressionAttributeValues={
                    ":empty": {"L": []},
                    ":new": {"L": [_ser_s(record_id.strip().upper())]},
                    ":rid": _ser_s(record_id.strip().upper()),
                    ":now": _ser_s(now),
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                continue  # target already carries the back-reference — idempotent no-op
            logger.warning(
                "[ENC-TSK-L07] reverse edge write failed %s.%s -> %s: %s",
                record_id, reverse_field, target_id, exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[ENC-TSK-L07] reverse edge write failed %s.%s -> %s: %s",
                record_id, reverse_field, target_id, exc,
            )


def _normalize_related_ids_value(raw_value: Any) -> Tuple[Optional[List[str]], Optional[str]]:
    """Normalize PATCH related_*_ids payloads, including JSON-stringified arrays.

    ENC-ISS-059: related_task_ids / related_issue_ids / related_feature_ids written
    via tracker_set (MCP) may arrive as a JSON string (e.g. '["ENC-TSK-100"]') instead
    of a parsed list, which would be stored as DynamoDB {"S": ...} instead of {"L": [...]}.
    This function coerces string payloads to the proper List[str] type.
    """
    parsed_value = raw_value

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if not stripped:
            return [], None
        if stripped[0] == "[":
            try:
                parsed_value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return None, f"related_*_ids string is not valid JSON: {exc}"
        else:
            # Single bare ID string — wrap in a list
            parsed_value = [stripped]

    if isinstance(parsed_value, list):
        normalized = [str(x).strip() for x in parsed_value if str(x).strip()]
        return normalized, None

    return None, "related_*_ids must be a list of record ID strings."


def _apply_user_initiated_advance(
    project_id: str,
    record_type: str,
    record_id: str,
    body: Dict,
    item_data: Dict,
    claims: Optional[Dict],
) -> Dict:
    """Apply a user-initiated status advance (ENC-ISS-092).

    Cognito-only: rejected with HTTP 403 if called with an internal API key.
    Borrow-and-restore: temporarily takes checkout ownership as the Cognito username,
    applies the status change, then restores the prior agent checkout (or releases if
    the task was not previously checked out; always releases on close).
    """
    # Auth check: Cognito only — internal API key is explicitly rejected
    if not claims or claims.get("auth_mode") == "internal-key":
        return _error(
            403,
            "user_initiated transitions require Cognito authentication. "
            "This path is reserved for UI use and cannot be accessed via internal API keys.",
        )

    # Extract Cognito username for audit trail
    cognito_user = (
        claims.get("cognito:username")
        or claims.get("sub")
        or "unknown_user"
    )

    # Require non-empty user_note (documents why the human overrode the lifecycle)
    transition_evidence = body.get("transition_evidence") or {}
    user_note = (transition_evidence.get("user_note") or "").strip()
    if not user_note:
        return _error(400, "transition_evidence.user_note is required for user_initiated transitions.")

    # Target status
    value = body.get("value", "")
    new_lower = str(value).strip().lower()
    if not new_lower:
        return _error(400, "Field 'value' (target status) is required.")

    # Validate target status is a known task status
    all_task_statuses = {
        "open", "in-progress", "coding-complete", "committed", "pr",
        "merged-main", "deploy-init", "deploy-success", "coding-updates",
        "deployed", "closed",
    }
    if new_lower not in all_task_statuses:
        return _error(400, f"Unknown target status '{value}' for task.")

    # Capture current checkout state before borrowing
    was_checked_out = bool(item_data.get("active_agent_session", False))
    previous_session_id = str(item_data.get("active_agent_session_id", "")).strip()

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)
    now = _now_z()

    # Step 1: Temporarily take ownership as the Cognito user (borrow)
    ddb.update_item(
        TableName=DYNAMODB_TABLE, Key=key,
        UpdateExpression=(
            "SET active_agent_session = :t, active_agent_session_id = :aid, "
            "checkout_state = :checked_out, updated_at = :now"
        ),
        ExpressionAttributeValues={
            ":t": {"BOOL": True}, ":aid": _ser_s(cognito_user),
            ":checked_out": _ser_s("checked_out"), ":now": _ser_s(now),
        },
    )

    # Step 2: Apply status change with enriched evidence stamped for audit
    enriched_evidence = {
        **(transition_evidence if isinstance(transition_evidence, dict) else {}),
        "user_initiated": True,
        "user_note": user_note,
        "initiated_by": cognito_user,
        "initiated_at": now,
    }
    note_text = (
        f"[USER-INITIATED] Status changed to '{new_lower}' by {cognito_user}. "
        f"Note: {user_note}"
    )
    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(note_text),
    }}
    evidence_json = json.dumps(enriched_evidence, separators=(",", ":"))

    # ENC-FTR-111 / ENC-TSK-H83: a human non-forward transition (regression or coding-updates
    # re-entry) auto-latches the auto_walk_opt_out circuit breaker and records an Artifact-Genesis
    # audit entry. This is the human path for tasks; the arc-walker can never clear the result.
    cur_status_nf = (item_data.get("status") or "").strip().lower()
    latch_nf, latch_reason = _is_task_non_forward(cur_status_nf, new_lower)
    hentry_list = [history_entry]
    if latch_nf:
        hentry_list.append(_opt_out_latch_history_entry(
            now, cognito_user, cur_status_nf, new_lower, latch_reason))

    # ENC-TSK-F41 / DOC-546B896390EA §5: even on the Cognito user-initiated
    # human-override path, closed_count must be incremented when the target
    # status is 'closed'. Atomic with the status SET so the FTR-076 v2 DESIGNS
    # gate observes the counter the instant the transition commits.
    ui_update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "transition_evidence = :te, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
        "history = list_append(if_not_exists(history, :empty), :hentry)"
    )
    if latch_nf:
        ui_update_expr += ", auto_walk_opt_out = :optout"
    if new_lower == "closed":
        ui_update_expr += " ADD closed_count :one"
    ui_attr_values = {
        ":val": _ser_value(new_lower), ":now": _ser_s(now),
        ":note": _ser_s(note_text), ":te": _ser_s(evidence_json),
        ":zero": {"N": "0"}, ":one": {"N": "1"},
        ":hentry": {"L": hentry_list}, ":empty": {"L": []},
    }
    if latch_nf:
        ui_attr_values[":optout"] = {"BOOL": True}
    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=ui_update_expr,
            ExpressionAttributeNames={"#fld": "status"},
            ExpressionAttributeValues=ui_attr_values,
        )
    except Exception as exc:
        logger.error("user_initiated status update failed: %s", exc)
        return _error(500, "Database write failed.")
    if latch_nf:
        _emit_opt_out_latch_event(
            project_id, record_type, record_id, cur_status_nf, new_lower, latch_reason, cognito_user)

    # Step 3: Restore or release checkout (borrow-and-restore)
    if new_lower == "closed":
        # Always release on close — closed tasks must not remain checked out
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                "SET active_agent_session = :f, active_agent_session_id = :empty_s, "
                "checkout_state = :checked_in, checked_in_by = :cib, checked_in_at = :now, "
                "updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":f": {"BOOL": False}, ":empty_s": _ser_s(""),
                ":checked_in": _ser_s("checked_in"), ":cib": _ser_s(cognito_user),
                ":now": _ser_s(now),
            },
        )
    elif was_checked_out and previous_session_id and previous_session_id != cognito_user:
        # Restore previous agent's checkout so in-flight work is not disrupted
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression="SET active_agent_session_id = :prev_id, updated_at = :now",
            ExpressionAttributeValues={
                ":prev_id": _ser_s(previous_session_id), ":now": _ser_s(now),
            },
        )
    else:
        # Task was not checked out before — release our temporary borrow
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                "SET active_agent_session = :f, active_agent_session_id = :empty_s, "
                "checkout_state = :checked_in, checked_in_by = :cib, checked_in_at = :now, "
                "updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":f": {"BOOL": False}, ":empty_s": _ser_s(""),
                ":checked_in": _ser_s("checked_in"), ":cib": _ser_s(cognito_user),
                ":now": _ser_s(now),
            },
        )

    return _response(200, {
        "success": True,
        "record_id": record_id,
        "field": "status",
        "value": new_lower,
        "updated_status": new_lower,
        "user_initiated": True,
        "initiated_by": cognito_user,
        "updated_at": now,
    })


def _handle_update_field(
    project_id: str,
    record_type: str,
    record_id: str,
    body: Dict,
    event: Optional[Dict] = None,
    claims: Optional[Dict] = None,
) -> Dict:
    """PATCH /{project}/{type}/{id} — update a single field on a record.

    Body: {"field": "status", "value": "in-progress", "write_source": {...}}
    Also supports legacy PWA actions: {"action": "close|note|reopen", "note": "..."}

    ENC-FTR-037: Task status changes require X-Checkout-Service-Key (checkout_service only).
    """
    # Detect PWA action vs MCP field update
    action = body.get("action")
    if action:
        return _handle_pwa_action(project_id, record_type, record_id, body, action)

    _normalize_write_source(body)

    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate. Agent-origin field
    # updates (write_source.provider is a minted ENC-SES id) must present a
    # valid Session Claim ID BEFORE any state mutation below (user-initiated
    # advance, checkout/release branch, generic field write). Checkout-service
    # requests are exempt — the identical gate already ran at that edge.
    _sci_err = _sci_gate_for_request(body, event)
    if _sci_err:
        return _sci_err

    field = body.get("field", "").strip()
    value = body.get("value", "")
    # ENC-FTR-111 / ENC-TSK-H83: holds a latch-context dict when a human-initiated non-forward
    # transition of an issue/feature/plan must auto-latch auto_walk_opt_out (applied at the
    # generic write below). Task human reverts are latched in _apply_user_initiated_advance.
    _optout_latch: Optional[Dict[str, str]] = None
    if not field:
        return _tracker_field_validation_error(
            "Field 'field' is required (or use 'action' for PWA mutations).",
            field="field",
            record_id=record_id,
            record_type=record_type,
            expected_type="string",
            expected_format="single field name",
        )

    # ENC-TSK-F41 / DOC-546B896390EA §5: Counter fields closed_count and
    # checkout_count are server-side only. Reject any direct PATCH attempt from
    # agent / io / coordination callers with HTTP 400 RESERVED_FIELD. These
    # fields are incremented atomically by the same UpdateExpression that
    # performs the triggering state transition (checkout / close) below — they
    # are never writable by clients and must never be accepted via tracker.set.
    if field in _F41_RESERVED_COUNTER_FIELDS:
        return _error(
            400,
            (
                f"Field '{field}' is server-side only. It is incremented by the "
                f"tracker lifecycle handler on the triggering transition and is "
                f"not writable via tracker.set / tracker.create."
            ),
            code="RESERVED_FIELD",
            field=field,
            reason="server_side_only",
            rule_citation="ENC-TSK-F41 / DOC-546B896390EA §5",
        )

    # ENC-FTR-052: Lesson append-only mutation enforcement
    if record_type == "lesson":
        if not ENABLE_LESSON_PRIMITIVE:
            return _error(400, "Lesson records are disabled. Set ENABLE_LESSON_PRIMITIVE=true to enable.")
        _LESSON_IMMUTABLE_FIELDS = {"observation", "provenance", "evidence_chain", "extensions"}
        if field == "observation":
            return _tracker_field_validation_error(
                "The 'observation' field is immutable after creation. Extend understanding via the extend endpoint.",
                field=field, record_id=record_id, record_type=record_type,
                expected_type="immutable",
                governed_rules=["observation is immutable after create (ENC-FTR-052). Use extensions to add context."],
            )
        if field == "extensions":
            return _tracker_field_validation_error(
                "The 'extensions' field is append-only. Use POST /{project}/lesson/{id}/extend to add extensions.",
                field=field, record_id=record_id, record_type=record_type,
                expected_type="append_only",
                governed_rules=["extensions is append-only via the extend sub-resource (ENC-FTR-052)."],
            )
        if field == "evidence_chain":
            return _tracker_field_validation_error(
                "The 'evidence_chain' field is append-only. Use POST /{project}/lesson/{id}/extend with evidence_ids.",
                field=field, record_id=record_id, record_type=record_type,
                expected_type="append_only",
                governed_rules=["evidence_chain is append-only via extensions (ENC-FTR-052)."],
            )

    # ENC-ISS-140: subtask_ids immutability enforcement.
    # Once a task has subtask_ids set and is past 'open' status (or has been checked out),
    # entries cannot be removed — only appended. This prevents agents from clearing
    # subtask_ids to bypass the ENC-ISS-106 subtask completion gate.
    if record_type == "task" and field == "subtask_ids":
        try:
            current_status = (item_data.get("status", "") or "").strip().lower()
            has_been_checked_out = bool(item_data.get("checked_out_at"))
            # ENC-ISS-242: item_data is deserialized (Python list), not raw DynamoDB format.
            # Previous code used .get("L", [])/.get("S", "") which raised AttributeError on lists.
            existing_subtask_ids = set()
            raw_subtask_ids = item_data.get("subtask_ids") or []
            if isinstance(raw_subtask_ids, list):
                for st in raw_subtask_ids:
                    existing_subtask_ids.add(str(st).strip())
            existing_subtask_ids.discard("")
            if existing_subtask_ids and (current_status != "open" or has_been_checked_out):
                new_subtask_ids = set()
                if isinstance(value, list):
                    new_subtask_ids = {str(v).strip() for v in value if str(v).strip()}
                removed = existing_subtask_ids - new_subtask_ids
                if removed:
                    return _tracker_field_validation_error(
                        f"Cannot remove entries from subtask_ids on a task that is past 'open' "
                        f"status or has been checked out (current status: '{current_status}'). "
                        f"subtask_ids is append-only to preserve the ENC-ISS-106 subtask "
                        f"completion gate. Attempted to remove: {', '.join(sorted(removed))}",
                        field=field, record_id=record_id, record_type=record_type,
                        expected_type="append_only",
                        governed_rules=[
                            "subtask_ids is append-only once task leaves 'open' or has been checked out (ENC-ISS-140).",
                            "Use PWA user_initiated path to override if needed.",
                        ],
                    )
        except Exception as e:
            logger.warning("subtask_ids immutability check failed (non-blocking): %s", e)

    # ENC-FTR-058 / ENC-TSK-C09: Plan objectives_set immutability enforcement
    # Objectives are append-only unless: plan is 'incomplete', or a governed removal/replacement
    # signal is present from the MCP server's plan.remove_objective / plan.replace_objectives actions.
    if record_type == "plan" and field == "objectives_set":
        is_governed_removal = body.get("remove_objective") is True
        is_governed_replacement = body.get("replace_objectives") is True
        try:
            key = {"project_id": {"S": project_id}, "record_id": {"S": f"plan#{record_id}"}}
            resp = _get_ddb().get_item(TableName=DYNAMODB_TABLE, Key=key, ConsistentRead=True)
            plan_item = resp.get("Item", {})
            plan_status = (plan_item.get("status", {}).get("S", "") or "").strip().lower()

            # Governed replacement is only allowed in 'drafted' status
            if is_governed_replacement and plan_status != "drafted":
                return _tracker_field_validation_error(
                    f"Bulk replacement of objectives is only permitted in drafted status. "
                    f"Use plan.add_objective or plan.remove_objective to modify an active plan. "
                    f"Current plan status: {plan_status}.",
                    field=field, record_id=record_id, record_type=record_type,
                    expected_type="drafted_only",
                    governed_rules=["plan.replace_objectives requires plan status 'drafted' (ENC-TSK-C09)."],
                )

            # Skip append-only enforcement for governed removals, replacements, or incomplete status
            if not is_governed_removal and not is_governed_replacement and plan_status != "incomplete":
                # Semantic set-difference on task IDs (ENC-TSK-C09: fix superset false-positive)
                existing_objectives = {
                    obj.get("S", "").strip()
                    for obj in plan_item.get("objectives_set", {}).get("L", [])
                    if obj.get("S", "").strip()
                }
                new_objectives = set()
                if isinstance(value, list):
                    new_objectives = {str(v).strip() for v in value if str(v).strip()}
                removed = existing_objectives - new_objectives
                if removed:
                    return _tracker_field_validation_error(
                        f"Cannot remove objectives from plan when status is '{plan_status}'. "
                        f"Objectives are append-only unless plan transitions to 'incomplete'. "
                        f"Attempted to remove: {', '.join(sorted(removed))}",
                        field=field, record_id=record_id, record_type=record_type,
                        expected_type="append_only",
                        governed_rules=["Plan objectives_set is append-only unless status is 'incomplete' (ENC-FTR-058)."],
                    )
        except Exception as exc:
            logger.warning("Failed to validate objectives_set immutability: %s", exc)

    if field == "acceptance_criteria":
        normalized_criteria, normalize_error = _normalize_acceptance_criteria_value(record_type, value)
        if normalize_error:
            return _tracker_field_validation_error(
                normalize_error,
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="array",
                expected_format="non-empty array of criteria",
            )
        value = normalized_criteria

    # ENC-TSK-783 / ENC-ISS-099: Coerce evidence JSON strings to proper List type so the
    # value is stored as DynamoDB {"L": [...]} instead of {"S": "[{...}]"}.
    if field == "evidence":
        normalized_evidence, evidence_error = _normalize_evidence_value(value)
        if evidence_error:
            return _tracker_field_validation_error(
                evidence_error,
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="array",
                expected_format="array of evidence objects with description + steps_to_duplicate",
            )
        value = normalized_evidence

    # ENC-ISS-059: Coerce related_*_ids JSON strings to proper List type so the
    # value is stored as DynamoDB {"L": [...]} instead of {"S": "[\"ENC-TSK-...\"]"}.
    if field in _RELATION_ID_FIELDS:
        normalized_ids, ids_error = _normalize_related_ids_value(value)
        if ids_error:
            return _tracker_field_validation_error(
                ids_error,
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="array",
                expected_format="array of tracker record IDs",
            )
        value = normalized_ids

    # ENC-FTR-111 / ENC-TSK-H83: auto_walk_opt_out is a real boolean (coerce string inputs), and
    # the Universal Arc-Walker can NEVER clear the circuit breaker. A clear (set false) originating
    # from the reserved arc-walker write_source is rejected; humans/agents may set or clear freely.
    if field == "auto_walk_opt_out":
        value = _coerce_bool(value)
        if value is False:
            _ws_guard = _normalize_write_source(body)
            _actor = str(_ws_guard.get("provider", "")).strip().lower()
            _chan = str(_ws_guard.get("channel", "")).strip().lower()
            if ARC_WALKER_ACTOR in (_actor, _chan):
                return _error(
                    403,
                    "The Universal Arc-Walker (system:arc-walker) cannot clear auto_walk_opt_out. "
                    "The circuit breaker is cleared only by an explicit human or agent "
                    "tracker.set(field='auto_walk_opt_out', value=false). (ENC-FTR-111 AC-2 / ENC-TSK-H83)",
                    code="ARC_WALKER_OPT_OUT_IMMUTABLE",
                    field=field,
                )

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Fetch existing record
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    item_data = _deser_item(raw_item)
    warnings: List[str] = []

    # --- ENC-TSK-L47: If-Match / HTTP 409 per-record revision contract ---
    # Own lightweight counter (sync_version), decoupled from ENC-TSK-L27's version_seq.
    # Absent header preserves today's unconditional-write behavior (backward compatible).
    try:
        _current_rev = int(item_data.get("sync_version", 0) or 0)
    except (TypeError, ValueError):
        _current_rev = 0
    _if_match = _extract_if_match(event)
    if _if_match is not None and _if_match != str(_current_rev):
        return _error(
            409,
            f"If-Match revision mismatch: client expected revision '{_if_match}', "
            f"server is at revision {_current_rev}.",
            code="REVISION_CONFLICT",
            field=field,
            record_id=record_id,
            record_type=record_type,
            expected_revision=_if_match,
            current_revision=_current_rev,
            current=item_data,
        )

    # --- ENC-ISS-092: user-initiated transitions (Cognito-only, bypass checkout gate) ---
    # Must be checked BEFORE session-ownership enforcement and the ENC-FTR-037 gate so
    # human operators can transition tasks that are checked out by another agent.
    if field == "status" and record_type == "task":
        te_pre = body.get("transition_evidence") or {}
        if te_pre.get("user_initiated"):
            return _apply_user_initiated_advance(
                project_id, record_type, record_id, body, item_data, claims
            )

    # --- Session ownership enforcement ---
    if field != "active_agent_session":
        ws = _normalize_write_source(body)
        current_session = item_data.get("active_agent_session", False)
        current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
        provider = str(ws.get("provider", "")).strip()
        if current_session and current_session_id:
            if not provider:
                return _error(
                    400,
                    f"Record is checked out by '{current_session_id}'. "
                    "write_source.provider is required for modifications.",
                )
            if current_session_id != provider:
                return _error(409, f"Record is checked out by '{current_session_id}'. Cannot modify.")

    # --- Validation for specific fields ---
    if field == "priority":
        normalized_priority = str(value or "").strip()
        if normalized_priority and normalized_priority not in _VALID_PRIORITIES:
            return _tracker_field_validation_error(
                f"Invalid priority '{normalized_priority}'. Allowed: {list(_VALID_PRIORITIES)}",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="enum",
                allowed_values=list(_VALID_PRIORITIES),
            )

    if field == "category":
        normalized_category = str(value or "").strip()
        allowed_categories = sorted(_VALID_CATEGORIES.get(record_type, set()))
        if normalized_category and normalized_category not in _VALID_CATEGORIES.get(record_type, set()):
            return _tracker_field_validation_error(
                f"Invalid category '{normalized_category}' for {record_type}. Allowed: {allowed_categories}",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="enum",
                allowed_values=allowed_categories,
            )

    if field == "transition_type":
        normalized_transition_type = str(value or "").strip().lower()
        if normalized_transition_type not in _VALID_TRANSITION_TYPES:
            return _tracker_field_validation_error(
                f"Invalid transition_type '{value}'. Allowed: {list(_VALID_TRANSITION_TYPES)}",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="enum",
                allowed_values=list(_VALID_TRANSITION_TYPES),
                governed_rules=[
                    "transition_type selects the lifecycle arc and should be set before checkout.",
                ],
            )
        # ENC-TSK-B07: Immutability enforcement for no_code and code_only.
        # Once set, these types cannot be changed. Other types can be tightened.
        current_tt = (item_data.get("transition_type") or "").strip().lower()
        if current_tt:
            if is_immutable_type(current_tt) and normalized_transition_type != current_tt:
                logger.warning(
                    "IMMUTABILITY VIOLATION: %s transition_type change blocked: "
                    "'%s' -> '%s' (current is immutable)",
                    record_id, current_tt, normalized_transition_type,
                )
                return _error(
                    422,
                    f"transition_type '{current_tt}' is immutable once set and cannot be "
                    f"changed to '{normalized_transition_type}'. Release the task and create "
                    "a new one with the desired transition_type.",
                    field=field,
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="enum",
                    violations=[{
                        "field": "transition_type",
                        "current_value": current_tt,
                        "rejected_value": normalized_transition_type,
                        "rule": "no_code and code_only transition_types are immutable once set",
                    }],
                )
            if is_immutable_type(normalized_transition_type) and current_tt != normalized_transition_type:
                logger.warning(
                    "IMMUTABILITY VIOLATION: %s transition_type change blocked: "
                    "'%s' -> '%s' (target is immutable and differs from current)",
                    record_id, current_tt, normalized_transition_type,
                )
                return _error(
                    422,
                    f"Cannot set transition_type to immutable value '{normalized_transition_type}' "
                    f"when current value is '{current_tt}'. The task must be created with "
                    f"'{normalized_transition_type}' from the start.",
                    field=field,
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="enum",
                    violations=[{
                        "field": "transition_type",
                        "current_value": current_tt,
                        "rejected_value": normalized_transition_type,
                        "rule": "no_code and code_only can only be set as the initial transition_type",
                    }],
                )

    if field == "status":
        # ENC-FTR-037: Task status transitions must go through checkout_service.
        # Direct calls (MCP tracker_set, PWA) are rejected with a clear redirect message.
        # Gate is permissive if CHECKOUT_SERVICE_KEY is not yet configured (graceful rollout).
        if record_type == "task" and not _is_checkout_service_request(event):
            return _error(
                403,
                "Task status transitions must be made via the checkout service. "
                "Use the advance_task_status MCP tool or POST "
                "/api/v1/checkout/{project}/task/{task_id}/advance.",
                field="status",
                record_id=record_id,
                record_type=record_type,
                expected_type="enum",
                expected_format="task lifecycle transition via checkout service",
                example_fix={
                    "tool": "advance_task_status",
                    "arguments": {
                        "record_id": record_id,
                        "target_status": str(value).strip().lower(),
                        "provider": "<provider>",
                        "governance_hash": "<governance_hash>",
                    },
                },
            )

        current_status = item_data.get("status", "").strip().lower()
        new_lower = value.strip().lower()
        closing = new_lower in ("closed", "completed", "complete")
        transition_evidence = body.get("transition_evidence", {})
        if not isinstance(transition_evidence, dict):
            transition_evidence = {}

        if record_type == "task" and current_status != new_lower:
            ws = _normalize_write_source(body)
            provider = str(ws.get("provider", "")).strip()
            current_session = bool(item_data.get("active_agent_session"))
            current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
            if not provider:
                return _tracker_field_validation_error(
                    "Task status transitions require write_source.provider (agent identity).",
                    field=field,
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="string",
                    expected_format="checked-out agent identity",
                )
            if not current_session or not current_session_id:
                return _error(
                    409,
                    "Task status transitions require an active checkout. "
                    "Check out the task before changing status.",
                )
            if provider != current_session_id:
                return _error(
                    409,
                    f"Task is checked out by '{current_session_id}'. "
                    f"Cannot transition status as '{provider}'.",
                )

        # Enforce valid transitions — forward + revert (ENC-FTR-022)
        is_revert = False
        _lifecycle_owned = False
        # ENC-TSK-H46 / B63 Phase 2A: when the flag is ON, the Lifecycle Service is the SOLE
        # authority for transition_type_matrix validation, STRICTNESS_RANK, and subtask gates on
        # task status transitions. FAIL-CLOSED — an invoke failure rejects the transition; the
        # inline validators below run only as the flag-OFF rollback path (zero inline fallback).
        if record_type == "task" and current_status != new_lower and _lifecycle_service_enabled():
            _lc_verdict = _invoke_lifecycle_service({
                "action": "validate_transition",
                "project_id": project_id,
                "record_type": record_type,
                "record_id": record_id,
                "current_status": current_status,
                "target_status": new_lower,
                "transition_type": (item_data.get("transition_type") or "github_pr_deploy").strip().lower(),
                "transition_evidence": transition_evidence,
                "components": item_data.get("components") or [],
                "subtask_ids": item_data.get("subtask_ids") or [],
                "is_checkout_service_request": _is_checkout_service_request(event),
            })
            if _lc_verdict is None:
                return _error(
                    503,
                    "Lifecycle Service unavailable; transition rejected (fail-closed, ENC-TSK-H46). "
                    "Retry shortly, or disable the enable_lifecycle_service_extraction flag to fall "
                    "back to inline validation.",
                    code="LIFECYCLE_SERVICE_UNAVAILABLE",
                    retryable=True,
                )
            if not _lc_verdict.get("allow"):
                _lc_err = _lc_verdict.get("error") or {}
                return _error(
                    int(_lc_err.get("status", 400) or 400),
                    _lc_err.get("message", "Lifecycle Service rejected the transition."),
                    code=_lc_err.get("code", "INVALID_INPUT"),
                    **(_lc_err.get("details") or {}),
                )
            is_revert = bool(_lc_verdict.get("is_revert"))
            _lifecycle_owned = True

        if not _lifecycle_owned and current_status != new_lower:
            type_transitions = _VALID_TRANSITIONS.get(record_type, {})
            valid_next = type_transitions.get(current_status, set())
            revert_targets = _REVERT_TRANSITIONS.get(record_type, {}).get(current_status, set())

            # ENC-ISS-092: For checkout-service-authenticated requests, expand valid_next
            # to include transition_type-specific shortcuts that bypass standard arc stages.
            # The checkout service already validated the transition against
            # ALLOWED_TRANSITIONS_BY_TYPE; here we just allow the write to succeed.
            if record_type == "task" and _is_checkout_service_request(event):
                task_tt = (item_data.get("transition_type") or "github_pr_deploy").strip().lower()
                if task_tt == "no_code" and current_status == "coding-complete":
                    # no_code arc: coding-complete → closed (skips committed/pr/merged-main/deploy)
                    valid_next = valid_next | {"closed"}
                elif task_tt == "code_only" and current_status == "merged-main":
                    # code_only arc: merged-main → closed (skips deploy-init/deploy-success)
                    valid_next = valid_next | {"closed"}

            if new_lower in valid_next:
                pass  # valid forward transition
            elif new_lower in revert_targets:
                revert_reason = transition_evidence.get("revert_reason", "").strip()
                if not revert_reason:
                    return _error(400,
                        f"Reverting {record_type} from '{current_status}' to '{new_lower}' "
                        f"requires transition_evidence.revert_reason")
                is_revert = True
            elif valid_next or revert_targets:
                transition_governed_rules = [
                    f"valid revert targets require transition_evidence.revert_reason: {sorted(revert_targets)}",
                ]
                # ENC-TSK-D77: Enrich lesson transition errors with gate requirements
                if record_type == "lesson":
                    target = new_lower
                    gate = _LESSON_TRANSITION_GATES.get(target)
                    if gate:
                        transition_governed_rules.append(
                            f"Gate requirements for '{target}': {json.dumps(gate, indent=None)}"
                        )
                return _tracker_field_validation_error(
                    (
                        f"Invalid status transition for {record_type}: "
                        f"'{current_status}' -> '{value}'. "
                        f"Valid forward: {sorted(valid_next)}. "
                        f"Valid revert (with revert_reason): {sorted(revert_targets)}"
                    ),
                    field=field,
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="enum",
                    allowed_values=sorted(valid_next),
                    governed_rules=transition_governed_rules,
                )

        # --- ENC-FTR-111 / ENC-TSK-H83: auto_walk_opt_out latch on human non-forward transition ---
        # Issue/feature/plan human-initiated reverts latch the circuit breaker here (the generic
        # write below applies it + emits the Artifact-Genesis record). Task human reverts go through
        # _apply_user_initiated_advance; agent/MCP transitions (internal-key) never latch.
        if record_type in ("issue", "feature", "plan") and is_revert and _is_human_request(claims):
            _optout_latch = {
                "from": current_status, "to": new_lower,
                "reason": "regression", "by": _human_actor(claims),
            }

        # --- ENC-ISS-155: Plan completion gate ---
        # When setting a plan to 'complete', validate all objectives_set entries
        # are in a terminal status (closed/completed/complete/archived).
        if record_type == "plan" and new_lower == "complete" and not is_revert:
            # item_data is already deserialized — objectives_set is a plain list of strings
            raw_objectives = item_data.get("objectives_set", [])
            if isinstance(raw_objectives, dict):
                # DynamoDB format fallback (raw get_item response)
                objective_ids = [o.get("S", "") for o in raw_objectives.get("L", []) if o.get("S", "")]
            else:
                objective_ids = [str(o).strip() for o in (raw_objectives or []) if str(o).strip()]
            if not objective_ids:
                return _tracker_field_validation_error(
                    "Cannot complete plan with empty objectives_set. "
                    "Add at least one objective before completing.",
                    field=field, record_id=record_id, record_type=record_type,
                    expected_type="gate",
                    governed_rules=["Plan completion requires all objectives in terminal status (ENC-ISS-155)."],
                )
            terminal_statuses = {"closed", "completed", "complete", "archived"}
            lagging = []
            for obj_id in objective_ids:
                try:
                    obj_prefix = obj_id.split("-")[1].upper() if "-" in obj_id else "TSK"
                    type_prefix_map = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan"}
                    obj_type = type_prefix_map.get(obj_prefix, "task")
                    obj_sk = f"{obj_type}#{obj_id}"
                    obj_key = {"project_id": {"S": project_id}, "record_id": {"S": obj_sk}}
                    obj_resp = _get_ddb().get_item(TableName=DYNAMODB_TABLE, Key=obj_key, ConsistentRead=True)
                    obj_item = obj_resp.get("Item")
                    if not obj_item:
                        lagging.append({"id": obj_id, "status": "NOT_FOUND"})
                        continue
                    obj_status = (obj_item.get("status", {}).get("S", "") or "").strip().lower()
                    if obj_status not in terminal_statuses:
                        lagging.append({"id": obj_id, "status": obj_status})
                except Exception as exc:
                    logger.warning("Failed to check objective %s status: %s", obj_id, exc)
                    lagging.append({"id": obj_id, "status": "CHECK_FAILED"})
            if lagging:
                lagging_summary = ", ".join(f"{l['id']} ({l['status']})" for l in lagging)
                return _tracker_field_validation_error(
                    f"Cannot complete plan: {len(lagging)} objective(s) not in terminal status. "
                    f"Lagging: {lagging_summary}. "
                    "All objectives must reach closed/completed/archived before plan completion.",
                    field=field, record_id=record_id, record_type=record_type,
                    expected_type="gate",
                    governed_rules=["Plan completion requires all objectives in terminal status (ENC-ISS-155)."],
                )

        # --- Evidence-gated forward transitions (ENC-FTR-022 / ENC-FTR-035) ---
        # Evidence gates apply to forward transitions only; reverts use revert_reason instead.
        # ENC-FTR-037: commit_sha gate moved from "pushed" → "committed" (pushed renamed to pr).
        # When checkout_service (Step 3) is deployed, this gate moves there; tracker_mutation
        # will only accept "committed" transitions from checkout_service via X-Checkout-Service-Key.
        if not is_revert and record_type == "task" and new_lower == "committed":
            commit_sha = transition_evidence.get("commit_sha", "").strip()
            if not commit_sha:
                return _tracker_field_validation_error(
                    "Cannot transition to 'committed': transition_evidence.commit_sha required",
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.commit_sha (40-char hex SHA)",
                )
            if not re.match(r'^[0-9a-f]{40}$', commit_sha.lower()):
                return _tracker_field_validation_error(
                    f"Invalid commit_sha: expected 40-char hex. Got: '{commit_sha}'",
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.commit_sha (40-char hex SHA)",
                )
            owner = transition_evidence.get("owner")
            repo = transition_evidence.get("repo")
            if not owner or not repo:
                resolved_owner, resolved_repo = _resolve_github_repo(project_id)
                owner = owner or resolved_owner
                repo = repo or resolved_repo
            if not owner or not repo:
                return _tracker_field_validation_error(
                    (
                        f"Cannot resolve GitHub repo for project '{project_id}'. "
                        "Provide owner and repo in transition_evidence, or set the "
                        "project's repo field in the projects table."
                    ),
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.owner + transition_evidence.repo",
                )
            valid, reason = _validate_commit_via_github(owner, repo, commit_sha)
            if not valid:
                return _tracker_field_validation_error(
                    f"GitHub commit validation failed for {commit_sha}: {reason}",
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.commit_sha validated against GitHub",
                )

        if not _lifecycle_owned and not is_revert and record_type == "task" and new_lower == "merged-main" \
                and not _is_checkout_service_request(event):
            # ENC-ISS-095: Skip merge_evidence requirement for checkout-service requests.
            # The checkout service validates pr_id + merged_at via GitHub API before writing;
            # requiring a free-text merge_evidence string here adds no governance value and
            # blocks the standard checkout lifecycle. Non-checkout-service PATCH requests
            # (e.g., direct PWA mutations) still require merge_evidence for backward compat.
            merge_evidence = transition_evidence.get("merge_evidence", "").strip()
            if not merge_evidence:
                return _tracker_field_validation_error(
                    "Cannot transition to 'merged-main': transition_evidence.merge_evidence required",
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.merge_evidence (non-empty string)",
                )

        if not _lifecycle_owned and not is_revert and record_type == "task" and new_lower == "deploy-success":
            # ENC-FTR-059: Matrix-driven deploy evidence validation (v{MATRIX_VERSION}).
            # Replaces hardcoded if/else branching with registry lookup.
            task_transition_type = (item_data.get("transition_type") or "github_pr_deploy").strip().lower()
            validator_entry = _DEPLOY_SUCCESS_VALIDATORS.get(task_transition_type)
            if validator_entry:
                ev_key, validator_fn, format_desc = validator_entry
                ev_err = validator_fn(transition_evidence.get(ev_key))
                if ev_err:
                    return _tracker_field_validation_error(
                        ev_err,
                        field="status",
                        record_id=record_id,
                        record_type=record_type,
                        expected_type="object",
                        expected_format=format_desc,
                    )
            else:
                # Unknown transition_type at deploy-success — fall back to deploy_evidence
                de_err = _validate_deploy_evidence(transition_evidence.get("deploy_evidence"))
                if de_err:
                    return _tracker_field_validation_error(
                        de_err,
                        field="status",
                        record_id=record_id,
                        record_type=record_type,
                        expected_type="object",
                        expected_format=(
                            "transition_evidence.deploy_evidence with id, name, run_id, "
                            "head_sha, status, conclusion, started_at, completed_at"
                        ),
                    )

        if not _lifecycle_owned and not is_revert and record_type == "task" and new_lower == "closed" and current_status == "deploy-success":
            live_validation_evidence = transition_evidence.get("live_validation_evidence", "").strip()
            if not live_validation_evidence:
                return _tracker_field_validation_error(
                    (
                        "Cannot transition to 'closed': transition_evidence.live_validation_evidence required. "
                        "Use ENC-FTR-032 (Cognito PWA diagnostics) to capture evidence autonomously, "
                        "or provide a manual confirmation string."
                    ),
                    field="status",
                    record_id=record_id,
                    record_type=record_type,
                    expected_type="object",
                    expected_format="transition_evidence.live_validation_evidence (non-empty string)",
                )

        if record_type == "feature" and new_lower == "production":
            prod_err = _validate_feature_production_gate(project_id, item_data)
            if prod_err:
                return prod_err

        # Hard enforcement of governed fields on close
        if record_type == "feature" and closing:
            if not item_data.get("user_story"):
                return _error(400, "Cannot complete feature: user_story is required.")
            ac_list = item_data.get("acceptance_criteria", [])
            if not ac_list:
                return _error(400, "Cannot complete feature: acceptance_criteria is required (min 1).")
            unvalidated = []
            for i, ac in enumerate(ac_list):
                if isinstance(ac, dict):
                    desc = ac.get("description", f"criterion[{i}]")
                    if not ac.get("evidence_acceptance", False):
                        unvalidated.append(f"[{i}] {desc}")
                elif isinstance(ac, str):
                    unvalidated.append(f"[{i}] {ac}")
            if unvalidated:
                return _error(400,
                    "Cannot complete feature: not all acceptance criteria validated. "
                    "Unvalidated:\n" + "\n".join(unvalidated))
        elif record_type == "feature" and not closing:
            if not item_data.get("user_story"):
                warnings.append("Feature missing governed field: user_story")
            if not item_data.get("acceptance_criteria"):
                warnings.append("Feature missing governed field: acceptance_criteria")

        if record_type == "issue" and closing:
            if not item_data.get("evidence"):
                return _error(400, "Cannot close issue: evidence is required (min 1).")

    if field == "parent" and value.strip():
        parent_type = None
        if "-TSK-" in value:
            parent_type = "task"
        elif "-ISS-" in value:
            parent_type = "issue"
        elif "-FTR-" in value:
            parent_type = "feature"
        elif "-PLN-" in value:
            parent_type = "plan"
        if parent_type and parent_type != record_type:
            return _tracker_field_validation_error(
                (
                    f"Parent must be the same record type. This is a {record_type} "
                    f"but parent '{value}' is a {parent_type}."
                ),
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="string",
                expected_format=f"{record_type.upper()} ID",
            )

    if field == "primary_task":
        if record_type not in ("feature", "issue"):
            return _tracker_field_validation_error(
                "primary_task is only valid on feature/issue records.",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="string",
                expected_format="feature or issue task ID",
            )
        if value.strip() and "-TSK-" not in value:
            return _tracker_field_validation_error(
                f"primary_task must reference a task ID. Got: '{value}'.",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_type="string",
                expected_format="task ID containing -TSK-",
            )

    now = _now_z()
    note_suffix = _write_source_note_suffix(body)

    # --- Session checkout/release ---
    if field == "active_agent_session":
        checking_out = value if isinstance(value, bool) else str(value).strip().lower() in ("true", "1", "yes")
        ws = _normalize_write_source(body)
        agent_id = str(ws.get("provider", "")).strip()

        if checking_out:
            if not agent_id:
                return _error(400, "Checkout requires write_source.provider as agent identity.")
            checkout_note = f"Agent session checkout by {agent_id}{note_suffix}"
            history_entry = {"M": {
                "timestamp": _ser_s(now), "status": _ser_s("worklog"),
                "description": _ser_s(checkout_note),
            }}
            # ENC-TSK-F41 / DOC-546B896390EA §5: atomically increment checkout_count
            # on every successful checkout transaction for task records. The ADD
            # action on a non-existent attribute treats it as 0, which preserves
            # pre-FTR-076-v2 records and survives the fail-closed IMPLEMENTS gate
            # semantic. Invocation path is checkout.task → checkout_service._handle_checkout
            # → tracker_mutation PATCH (field=active_agent_session value=True) →
            # this UpdateExpression. Atomic with the state transition itself.
            checkout_update_expr = (
                "SET active_agent_session = :t, active_agent_session_id = :aid, "
                "checkout_state = :checked_out, checked_out_by = :aid, checked_out_at = :now, "
                "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            )
            if record_type == "task":
                checkout_update_expr += " ADD checkout_count :one"
            try:
                ddb.update_item(
                    TableName=DYNAMODB_TABLE, Key=key,
                    UpdateExpression=checkout_update_expr,
                    ConditionExpression="active_agent_session <> :t OR attribute_not_exists(active_agent_session)",
                    ExpressionAttributeValues={
                        ":t": {"BOOL": True}, ":aid": _ser_s(agent_id),
                        ":checked_out": _ser_s("checked_out"),
                        ":now": _ser_s(now), ":note": _ser_s(checkout_note),
                        ":wsrc": _build_write_source(body),
                        ":zero": {"N": "0"}, ":one": {"N": "1"},
                        ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
                    },
                )
            except ClientError as exc:
                if _is_conditional_check_failed(exc):
                    current_agent = item_data.get("active_agent_session_id", "unknown")
                    return _error(409, f"Task already checked out by '{current_agent}'.")
                raise
            return _response(200, {
                "success": True, "record_id": record_id,
                "checkout": True, "checkout_state": "checked_out",
                "active_agent_session_id": agent_id, "updated_at": now,
            })
        else:
            release_note = f"Agent session released{note_suffix}"
            release_agent = str(ws.get("provider", "")).strip() or str(
                item_data.get("active_agent_session_id", "")
            ).strip()
            history_entry = {"M": {
                "timestamp": _ser_s(now), "status": _ser_s("worklog"),
                "description": _ser_s(release_note),
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET active_agent_session = :f, active_agent_session_id = :empty_s, "
                    "checkout_state = :checked_in, checked_in_by = :checkin_by, checked_in_at = :now, "
                    "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                    "sync_version = if_not_exists(sync_version, :zero) + :one, "
                    "history = list_append(if_not_exists(history, :empty_l), :hentry)"
                ),
                ExpressionAttributeValues={
                    ":f": {"BOOL": False}, ":empty_s": _ser_s(""),
                    ":checked_in": _ser_s("checked_in"), ":checkin_by": _ser_s(release_agent),
                    ":now": _ser_s(now), ":note": _ser_s(release_note),
                    ":wsrc": _build_write_source(body),
                    ":zero": {"N": "0"}, ":one": {"N": "1"},
                    ":hentry": {"L": [history_entry]}, ":empty_l": {"L": []},
                },
            )
            return _response(200, {
                "success": True, "record_id": record_id,
                "checkout": False, "checkout_state": "checked_in", "updated_at": now,
            })

    # --- Generic field update ---
    note_val = value if len(str(value)) <= 100 else str(value)[:100] + "..."
    note_text = f"Field '{field}' set to '{note_val}'{note_suffix}"

    # Enrich worklog with evidence details (ENC-FTR-022)
    transition_evidence = body.get("transition_evidence", {})
    if field == "status" and transition_evidence:
        evidence_parts = []
        if transition_evidence.get("commit_sha"):
            evidence_parts.append(f"commit: {transition_evidence['commit_sha'][:12]}")
        if transition_evidence.get("deployment_ref"):
            evidence_parts.append(f"deploy_ref: {transition_evidence['deployment_ref']}")
        if transition_evidence.get("deploy_evidence"):
            de = transition_evidence["deploy_evidence"]
            if isinstance(de, dict):
                # ENC-TSK-726: structured GH Actions Jobs API payload — summarise key fields
                de_summary = (
                    f"job_id={de.get('id')}, run_id={de.get('run_id')}, "
                    f"sha={str(de.get('head_sha', ''))[:12]}, conclusion={de.get('conclusion')}"
                )
            else:
                de_summary = str(de)[:80]
            evidence_parts.append(f"deploy_evidence: {de_summary}")
        if transition_evidence.get("live_validation_evidence"):
            evidence_parts.append(f"live_validation: {transition_evidence['live_validation_evidence'][:80]}")
        if transition_evidence.get("merge_evidence"):
            me = transition_evidence["merge_evidence"]
            me_str = json.dumps(me, separators=(",", ":")) if isinstance(me, dict) else str(me)
            evidence_parts.append(f"merge: {me_str[:80]}")
        if transition_evidence.get("revert_reason"):
            evidence_parts.append(f"revert: {transition_evidence['revert_reason'][:80]}")
        if evidence_parts:
            note_text += f" [evidence: {', '.join(evidence_parts)}]"

    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(note_text),
    }}

    # ENC-TSK-H86 (T5): an EXPLICIT human/agent tracker.set of auto_walk_opt_out records a governed
    # [ARC-WALKER][OPT-OUT-SET|OPT-OUT-CLEAR] history marker (parallel to the H83 auto-latch entry)
    # so the read-only arc_walk_metrics probe can count latch/clear events from record history.
    _optout_explicit: Optional[bool] = None
    if field == "auto_walk_opt_out":
        _optout_explicit = _coerce_bool(value)
        _optout_actor = str(_normalize_write_source(body, claims).get("provider", "")).strip()
        history_entry = _opt_out_state_history_entry(now, _optout_explicit, _optout_actor)

    # Build extra SET clauses for evidence fields (ENC-FTR-022)
    extra_sets = []
    extra_vals = {}
    if field == "status" and transition_evidence:
        if transition_evidence.get("commit_sha"):
            extra_sets.append("commit_sha = :commit_sha")
            extra_vals[":commit_sha"] = {"S": transition_evidence["commit_sha"].strip().lower()}
        if transition_evidence.get("deployment_ref"):
            extra_sets.append("deployment_ref = :deploy_ref")
            extra_vals[":deploy_ref"] = {"S": transition_evidence["deployment_ref"].strip()}
        if transition_evidence.get("deploy_evidence"):
            extra_sets.append("deploy_evidence = :deploy_ev")
            de = transition_evidence["deploy_evidence"]
            # ENC-TSK-726: store as JSON string for DynamoDB S compatibility (dict payload)
            de_val = json.dumps(de, separators=(",", ":")) if isinstance(de, dict) else str(de).strip()
            extra_vals[":deploy_ev"] = {"S": de_val}
        if transition_evidence.get("live_validation_evidence"):
            extra_sets.append("live_validation_evidence = :live_val_ev")
            extra_vals[":live_val_ev"] = {"S": transition_evidence["live_validation_evidence"].strip()}
        if transition_evidence.get("merge_evidence"):
            extra_sets.append("merge_evidence = :merge_ev")
            me = transition_evidence["merge_evidence"]
            # ENC-ISS-097: merge_evidence may be a dict (checkout service) or a string (direct PATCH)
            extra_vals[":merge_ev"] = {"S": json.dumps(me, separators=(",", ":")) if isinstance(me, dict) else str(me).strip()}
        if transition_evidence.get("external_deploy_evidence"):
            extra_sets.append("external_deploy_evidence = :external_deploy_ev")
            ede = transition_evidence["external_deploy_evidence"]
            extra_vals[":external_deploy_ev"] = {
                "S": json.dumps(ede, separators=(",", ":")) if isinstance(ede, dict) else str(ede).strip()
            }
        if transition_evidence.get("documentation_evidence"):
            extra_sets.append("documentation_evidence = :documentation_ev")
            docs = transition_evidence["documentation_evidence"]
            extra_vals[":documentation_ev"] = {
                "S": json.dumps(docs, separators=(",", ":")) if isinstance(docs, list) else str(docs).strip()
            }

    update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
        "history = list_append(if_not_exists(history, :empty), :hentry)"
    )
    if extra_sets:
        update_expr += ", " + ", ".join(extra_sets)

    # ENC-FTR-111 / ENC-TSK-H83: apply the auto_walk_opt_out latch (set true + Artifact-Genesis
    # history entry) atomically with the human non-forward transition of an issue/feature/plan.
    _hentry_list = [history_entry]
    if _optout_latch is not None:
        update_expr += ", auto_walk_opt_out = :optout"
        _hentry_list.append(_opt_out_latch_history_entry(
            now, _optout_latch["by"], _optout_latch["from"],
            _optout_latch["to"], _optout_latch["reason"],
        ))

    # ENC-TSK-F41 / DOC-546B896390EA §5: atomically increment closed_count on
    # every task->closed transition. The ADD action is appended to the same
    # UpdateExpression as the status SET, so the counter and the state transition
    # commit as a single atomic DynamoDB operation. ADD treats a missing
    # attribute as 0, which preserves pre-FTR-076-v2 records and keeps the
    # fail-closed DESIGNS gate semantic (closed_count>=1 required).
    if field == "status" and record_type == "task" and str(value).strip().lower() == "closed":
        update_expr += " ADD closed_count :one"

    attr_values = {
        ":val": _ser_value(value), ":now": _ser_s(now),
        ":note": _ser_s(note_text), ":wsrc": _build_write_source(body),
        ":zero": {"N": "0"}, ":one": {"N": "1"},
        ":hentry": {"L": _hentry_list}, ":empty": {"L": []},
    }
    if _optout_latch is not None:
        attr_values[":optout"] = {"BOOL": True}
    attr_values.update(extra_vals)

    vseq_expr, vseq_vals = _version_seq_update_parts()
    update_expr += vseq_expr
    attr_values.update(vseq_vals)

    # ENC-TSK-L47: when the caller presented If-Match, guard the commit itself
    # (not just the pre-check above) against a write that landed in between —
    # mirrors the existing sync_version CAS pattern used by _handle_pwa_action.
    update_kwargs: Dict[str, Any] = {
        "TableName": DYNAMODB_TABLE, "Key": key,
        "UpdateExpression": update_expr,
        "ExpressionAttributeNames": {"#fld": field},
        "ExpressionAttributeValues": attr_values,
    }
    if _if_match is not None:
        update_kwargs["ConditionExpression"] = "sync_version = :if_match_expected"
        attr_values[":if_match_expected"] = {"N": str(_current_rev)}

    try:
        ddb.update_item(**update_kwargs)
    except ClientError as exc:
        if _is_conditional_check_failed(exc):
            try:
                _refreshed_raw = _get_record_raw(project_id, record_type, record_id)
                _refreshed = _deser_item(_refreshed_raw) if _refreshed_raw else item_data
            except Exception:  # noqa: BLE001
                _refreshed = item_data
            return _error(
                409,
                "Record was modified concurrently: If-Match revision is no longer current.",
                code="REVISION_CONFLICT",
                field=field,
                record_id=record_id,
                record_type=record_type,
                expected_revision=_if_match,
                current_revision=_refreshed.get("sync_version"),
                current=_refreshed,
            )
        logger.error("update_item failed: %s", exc)
        return _error(500, "Database write failed.")
    except Exception as exc:
        logger.error("update_item failed: %s", exc)
        return _error(500, "Database write failed.")

    # ENC-TSK-L07 (B63 AC-7 / B65 AC-5/AC-7): mirror newly-added related_*_ids onto
    # each target's reverse field so the primary write's relation is bidirectional.
    if field in _RELATION_ID_FIELDS:
        try:
            _apply_reverse_relation_edges(
                project_id, record_type, record_id, field,
                item_data.get(field) or [], value,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[ENC-TSK-L07] reverse edge propagation failed (non-fatal): %s", exc)

    # ENC-FTR-111 / ENC-TSK-H83: emit the Artifact-Genesis telemetry event after the latch commits.
    if _optout_latch is not None:
        _emit_opt_out_latch_event(
            project_id, record_type, record_id,
            _optout_latch["from"], _optout_latch["to"], _optout_latch["reason"], _optout_latch["by"],
        )

    # ENC-TSK-H86 (T5) / ENC-FTR-111 AC-6: emit the opt_out latch-or-clear telemetry event after an
    # EXPLICIT tracker.set of auto_walk_opt_out commits, so both states reach the ENC-TSK-B66 dashboard.
    if _optout_explicit is not None:
        _emit_opt_out_state_event(
            project_id, record_type, record_id, _optout_explicit,
            str(_normalize_write_source(body, claims).get("provider", "")).strip(),
        )

    result: Dict[str, Any] = {
        "success": True, "record_id": record_id,
        "field": field, "value": value, "updated_at": now,
        "sync_version": _current_rev + 1,
    }
    if warnings:
        result["warnings"] = warnings

    # ENC-ISS-441 / ENC-TSK-J96: record reached its final lifecycle state — nudge the
    # acting session toward retirement (additive-only envelope field).
    if field == "status" and _is_terminal_transition(record_type, value):
        result["retirement_prompt"] = RETIREMENT_PROMPT

    # ENC-TSK-H85 / ENC-FTR-111 Phase 1: after a successful FORWARD task status advance, hand off to
    # the Universal Arc-Walker to walk forward across the mechanical gates in the same invocation
    # (DOC-078C57FC1BE6 §6.1). Behind its own independent flag; wrapped so a walk failure NEVER
    # affects the agent's already-committed advance (the walk is a pure optimization on top of it).
    if (record_type == "task" and field == "status" and not is_revert
            and _arc_walker_enabled()):
        try:
            arc_walk = _arc_walk_after_advance(project_id, record_id, item_data, new_lower)
            if arc_walk and arc_walk.get("walked"):
                result["arc_walk"] = arc_walk
            elif arc_walk:
                # Surface the halt reason too (observability) without implying any advance happened.
                result["arc_walk"] = arc_walk
        except Exception as exc:  # noqa: BLE001
            logger.error("[H85] arc-walk post-advance hook failed (non-fatal): %s", exc)

    return _response(200, result)


def _handle_pwa_action(project_id: str, record_type: str, record_id: str, body: Dict, action: str) -> Dict:
    """Handle legacy PWA mutations: close, note, reopen."""
    if action not in ("close", "note", "reopen", "worklog"):
        return _error(400, "Field 'action' must be 'close', 'note', 'reopen', or 'worklog'.")

    note_text = body.get("note", "")
    if action in ("note", "worklog"):
        if not note_text or not str(note_text).strip():
            return _error(400, "Field 'note' is required and must not be empty.")
        note_text = str(note_text).strip()
        if len(note_text) > MAX_NOTE_LENGTH:
            return _error(400, f"Note exceeds maximum length of {MAX_NOTE_LENGTH} characters.")

    try:
        existing = _get_record_full(project_id, record_type, record_id)
    except Exception:
        return _error(500, "Database read failed. Please try again.")

    if existing is None:
        return _error(404, f"Record not found: {record_id}")

    current_version = existing.get("sync_version", 0)
    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    try:
        if action == "close":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            if current_status == closed_status:
                return _response(200, {
                    "success": True, "action": "close", "record_id": record_id,
                    "updated_status": closed_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            now = _now_z()
            description = "Closed via Enceladus PWA"
            history_entry = {"M": {
                "timestamp": {"S": now}, "status": {"S": "close_audit"},
                "description": {"S": description},
                "agent_details": {"S": "Enceladus PWA (human user)"},
                "closed_time": {"S": now},
            }}
            # ENC-TSK-F41 / DOC-546B896390EA §5: when this legacy PWA close path
            # lands a task record at closed_status, increment closed_count atomically
            # with the status SET. Non-task record types (features/issues) do not
            # carry a closed_count field; restrict the ADD to tasks.
            pwa_close_update_expr = (
                "SET #status = :status, updated_at = :ts, last_update_note = :note, "
                "sync_version = sync_version + :one, "
                "#history = list_append(#history, :entry)"
            )
            if record_type == "task" and closed_status == "closed":
                pwa_close_update_expr += " ADD closed_count :one"
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=pwa_close_update_expr,
                ConditionExpression="sync_version = :expected",
                ExpressionAttributeNames={"#status": "status", "#history": "history"},
                ExpressionAttributeValues={
                    ":status": {"S": closed_status}, ":ts": {"S": now},
                    ":note": {"S": description}, ":one": {"N": "1"},
                    ":entry": {"L": [history_entry]},
                    ":expected": {"N": str(current_version)},
                },
            )
            return _response(200, {
                "success": True, "action": "close", "record_id": record_id,
                "updated_status": closed_status, "updated_at": now,
            })

        elif action == "reopen":
            current_status = existing.get("status", "")
            closed_status = _CLOSED_STATUS[record_type]
            default_status = _DEFAULT_STATUS[record_type]
            if current_status == default_status:
                return _response(200, {
                    "success": True, "action": "reopen", "record_id": record_id,
                    "updated_status": default_status,
                    "updated_at": existing.get("updated_at") or _now_z(),
                })
            if current_status != closed_status:
                return _error(400, f"Cannot reopen: record status is '{current_status}', not '{closed_status}'.")
            now = _now_z()
            description = "Reopened via Enceladus PWA"
            history_entry = {"M": {
                "timestamp": {"S": now}, "status": {"S": "reopened"},
                "description": {"S": description},
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #status = :new_status, updated_at = :ts, last_update_note = :note, "
                    "sync_version = sync_version + :one, "
                    "#history = list_append(#history, :entry)"
                ),
                ConditionExpression="sync_version = :expected AND #status = :closed_val",
                ExpressionAttributeNames={"#status": "status", "#history": "history"},
                ExpressionAttributeValues={
                    ":new_status": {"S": default_status}, ":ts": {"S": now},
                    ":note": {"S": description}, ":one": {"N": "1"},
                    ":entry": {"L": [history_entry]},
                    ":expected": {"N": str(current_version)},
                    ":closed_val": {"S": closed_status},
                },
            )
            _emit_reopen_event(project_id, record_type, record_id, closed_status, default_status, now)
            return _response(200, {
                "success": True, "action": "reopen", "record_id": record_id,
                "updated_status": default_status, "updated_at": now,
            })

        elif action == "worklog":
            # ENC-TSK-841: Post note directly as a worklog history entry
            # (used by PWA "Submit + Close") instead of storing as pending update.
            now = _now_z()
            history_entry = {"M": {
                "timestamp": {"S": now}, "status": {"S": "worklog"},
                "description": {"S": f"[USER] {note_text}"},
            }}
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET updated_at = :ts, last_update_note = :note, "
                    "sync_version = sync_version + :one, "
                    "#history = list_append(#history, :entry)"
                ),
                ConditionExpression="sync_version = :expected",
                ExpressionAttributeNames={"#history": "history"},
                ExpressionAttributeValues={
                    ":note": {"S": note_text}, ":ts": {"S": now},
                    ":one": {"N": "1"}, ":entry": {"L": [history_entry]},
                    ":expected": {"N": str(current_version)},
                },
            )
            return _response(200, {
                "success": True, "action": "worklog", "record_id": record_id,
                "updated_at": now,
            })

        else:  # note
            now = _now_z()
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #update = :note, updated_at = :ts, "
                    "sync_version = sync_version + :one"
                ),
                ConditionExpression="sync_version = :expected",
                ExpressionAttributeNames={"#update": "update"},
                ExpressionAttributeValues={
                    ":note": {"S": note_text}, ":ts": {"S": now},
                    ":one": {"N": "1"}, ":expected": {"N": str(current_version)},
                },
            )
            return _response(200, {
                "success": True, "action": "note", "record_id": record_id,
                "updated_at": now,
            })

    except ValueError as exc:
        return _error(409, str(exc))
    except ClientError as exc:
        if _is_conditional_check_failed(exc):
            return _error(409, "Record was modified concurrently. Please refresh and try again.")
        logger.error("mutation failed: %s", exc)
        return _error(500, "Database write failed. Please try again.")
    except Exception as exc:
        logger.error("mutation failed: %s", exc)
        return _error(500, "Database write failed. Please try again.")


def _mirror_worklog_to_session(
    session_id: str,
    record_type: str,
    record_id: str,
    description: str,
    timestamp: str,
) -> None:
    """Mirror a worklog entry onto the acting session's own SES record
    (ENC-TSK-L35: session detail + worklog mirroring, B67 PWA2.0).

    Whenever a session (write_source.provider is a minted ENC-SES id) appends
    a worklog entry to ANY record via ``_handle_log`` — the single shared
    ``/{project}/{type}/{id}/log`` endpoint for every record type (task,
    issue, feature, lesson, plan, generation) — a copy of that same entry is
    also appended onto the session's own ``history`` list in
    AGENT_SESSIONS_TABLE, keyed by ``session_id``. The mirrored description is
    prefixed with the source record so the SES worklog reads as a session
    activity feed across every record it touched.

    Best-effort and NON-blocking by contract, matching ``_touch_session_activity``:
    a missing/retired session, or any DynamoDB error, is logged and swallowed —
    mirroring must never fail the primary worklog append it rides on. Does NOT
    depend on the SCI gate outcome (mirroring is opportunistic bookkeeping, not
    an authorization decision) and applies equally to grandfathered sessions
    and checkout-service-forwarded requests.
    """
    session_id = str(session_id or "").strip()
    if not _AGENT_SESSION_ID_RE.match(session_id):
        return
    mirrored_entry = {"M": {
        "timestamp": _ser_s(timestamp),
        "status": _ser_s("worklog"),
        "description": _ser_s(f"[{record_type}:{record_id}] {description}"),
        "source_record_type": _ser_s(record_type),
        "source_record_id": _ser_s(record_id),
    }}
    try:
        _get_ddb().update_item(
            TableName=AGENT_SESSIONS_TABLE,
            Key={"session_id": {"S": session_id}},
            UpdateExpression=(
                "SET history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ConditionExpression="attribute_exists(session_id)",
            ExpressionAttributeValues={
                ":hentry": {"L": [mirrored_entry]},
                ":empty": {"L": []},
            },
        )
    except Exception as exc:  # noqa: BLE001 — mirroring is best-effort by contract
        if _is_conditional_check_failed(exc):
            logger.info(
                "[INFO] Worklog mirror skipped for %s (session not found)", session_id,
            )
        else:
            logger.warning(
                "[ERROR] Worklog mirror to session %s failed (continuing): %s",
                session_id, exc,
            )


def _handle_log(
    project_id: str,
    record_type: str,
    record_id: str,
    body: Dict,
    event: Optional[Dict] = None,
) -> Dict:
    """POST /{project}/{type}/{id}/log — append worklog entry to history."""
    description = body.get("description", "").strip()
    if not description:
        return _error(400, "Field 'description' is required.")
    _normalize_write_source(body)

    # ENC-ISS-441 / ENC-TSK-J93: SCI enforcement gate — agent-origin worklog
    # appends (write_source.provider is a minted ENC-SES id) require a valid
    # Session Claim ID. Checkout-service /log forwarding is exempt (gate runs
    # at that edge); non-agent providers pass through unchanged.
    _sci_err = _sci_gate_for_request(body, event)
    if _sci_err:
        return _sci_err

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Verify record exists
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    # Session ownership enforcement
    # ENC-FTR-037: worklog appends on tasks ALWAYS require an active checkout.
    item_data = _deser_item(raw_item)
    ws = _normalize_write_source(body)
    current_session = item_data.get("active_agent_session", False)
    current_session_id = str(item_data.get("active_agent_session_id", "")).strip()
    provider = str(ws.get("provider", "")).strip()
    if record_type == "task":
        if not current_session or not current_session_id:
            return _error(
                409,
                "Task must be checked out to append worklog. "
                "Use the append_worklog MCP tool (via checkout service) or "
                "POST /api/v1/checkout/{project}/task/{task_id}/log.",
            )
        if not provider:
            return _error(
                400,
                f"Task is checked out by '{current_session_id}'. "
                "write_source.provider is required.",
            )
        if current_session_id != provider:
            return _error(409, f"Task is checked out by '{current_session_id}'. Cannot modify as '{provider}'.")
    elif current_session and current_session_id:
        # Non-task records: preserve existing ownership check
        if not provider:
            return _error(
                400,
                f"Record is checked out by '{current_session_id}'. "
                "write_source.provider is required for modifications.",
            )
        if current_session_id != provider:
            return _error(409, f"Record is checked out by '{current_session_id}'. Cannot modify.")

    now = _now_z()
    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(description),
    }}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                "SET updated_at = :now, last_update_note = :note, "
                "write_source = :wsrc, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ExpressionAttributeValues={
                ":now": _ser_s(now), ":note": _ser_s(description),
                ":wsrc": _build_write_source(body),
                ":zero": {"N": "0"}, ":one": {"N": "1"},
                ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
            },
        )
    except Exception as exc:
        logger.error("update_item (log) failed: %s", exc)
        return _error(500, "Database write failed.")

    # ENC-TSK-L35: mirror this worklog entry onto the acting session's own
    # SES record (best-effort; never fails the primary append above).
    _mirror_worklog_to_session(provider, record_type, record_id, description, now)

    return _response(200, {"success": True, "record_id": record_id, "updated_at": now})


def _handle_lesson_extend(project_id: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/lesson/{id}/extend — append-only extension to a lesson (ENC-FTR-052).

    Adds a contextualization entry to the extensions array without modifying
    the original observation. Optionally appends new evidence IDs to evidence_chain.
    Increments lesson_version.
    """
    if not ENABLE_LESSON_PRIMITIVE:
        return _error(400, "Lesson records are disabled. Set ENABLE_LESSON_PRIMITIVE=true to enable.")

    content = str(body.get("content") or "").strip()
    if not content:
        return _error(400, "Field 'content' is required for lesson extension.")

    author = str(body.get("author") or body.get("write_source", {}).get("provider", "")).strip()
    if not author:
        return _error(400, "Field 'author' (or write_source.provider) is required.")

    new_evidence_ids = body.get("evidence_ids") or []
    if new_evidence_ids and not isinstance(new_evidence_ids, list):
        return _error(400, "evidence_ids must be an array of tracker record IDs.")

    # ENC-FTR-054: Optional pillar_scores update triggers score recomputation
    updated_pillar_scores = None
    raw_ps = body.get("pillar_scores")
    if raw_ps:
        updated_pillar_scores, ps_err = _validate_pillar_scores(raw_ps, "lesson")
        if ps_err:
            return ps_err

    _normalize_write_source(body)
    ddb = _get_ddb()
    key = _build_key(project_id, "lesson", record_id)

    # Verify record exists and is a lesson
    try:
        raw_item = _get_record_raw(project_id, "lesson", record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")
    if raw_item is None:
        return _error(404, f"Lesson not found: {record_id}")

    now = _now_z()
    extension_entry = {"M": {
        "timestamp": _ser_s(now),
        "author": _ser_s(author),
        "content": _ser_s(content),
    }}
    if new_evidence_ids:
        extension_entry["M"]["evidence_ids"] = {"L": [_ser_s(eid.strip()) for eid in new_evidence_ids if eid.strip()]}

    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(f"Extension added by {author}: {content[:100]}{'...' if len(content) > 100 else ''}"),
    }}

    # Build update expression: always append extension + history, optionally append evidence
    update_parts = [
        "SET updated_at = :now",
        "last_update_note = :note",
        "write_source = :wsrc",
        "sync_version = if_not_exists(sync_version, :zero) + :one",
        "lesson_version = if_not_exists(lesson_version, :zero) + :one",
        "extensions = list_append(if_not_exists(extensions, :empty), :ext)",
        "history = list_append(if_not_exists(history, :empty), :hentry)",
    ]
    expr_values = {
        ":now": _ser_s(now),
        ":note": _ser_s(f"Extension by {author}"),
        ":wsrc": _build_write_source(body),
        ":zero": {"N": "0"}, ":one": {"N": "1"},
        ":ext": {"L": [extension_entry]},
        ":hentry": {"L": [history_entry]},
        ":empty": {"L": []},
    }

    if new_evidence_ids:
        update_parts.append("evidence_chain = list_append(if_not_exists(evidence_chain, :empty), :new_ev)")
        expr_values[":new_ev"] = {"L": [_ser_s(eid.strip()) for eid in new_evidence_ids if eid.strip()]}

    # ENC-FTR-054: Recompute scores if pillar_scores updated. ENC-TSK-H47 / B63 Phase 2B: when the
    # Scoring Service is ON, defer the recomputation to the async service — store the new
    # pillar_scores and reset scoring_status='pending'; the SNS publish below (after the write
    # succeeds) re-scores. When OFF (rollback), recompute inline exactly as before.
    _scoring_deferred = False
    if updated_pillar_scores:
        update_parts.append("pillar_scores = :ps")
        expr_values[":ps"] = {"M": {k: {"N": str(v)} for k, v in updated_pillar_scores.items()}}
        if _scoring_service_enabled():
            update_parts.append("scoring_status = :pending")
            expr_values[":pending"] = {"S": "pending"}
            _scoring_deferred = True
        else:
            new_composite = _compute_lesson_pillar_composite(updated_pillar_scores)
            new_resonance = _compute_resonance_score(updated_pillar_scores)
            update_parts.append("resonance_score = :rs")
            update_parts.append("pillar_composite = :pc")
            update_parts.append("scoring_status = :scored")
            expr_values[":rs"] = {"N": str(new_resonance)}
            expr_values[":pc"] = {"N": str(new_composite)}
            expr_values[":scored"] = {"S": "scored"}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=", ".join(update_parts),
            ExpressionAttributeValues=expr_values,
        )
    except Exception as exc:
        logger.error("update_item (lesson extend) failed: %s", exc)
        return _error(500, "Database write failed.")

    # ENC-TSK-H47 / B63 Phase 2B: if scoring was deferred (flag ON + pillar_scores changed), the
    # lesson is now scoring_status='pending'; kick off the async Scoring Service. Best-effort —
    # the write already succeeded and is the source of truth.
    if _scoring_deferred and updated_pillar_scores:
        _publish_lesson_scoring_request(
            project_id, key["record_id"]["S"], record_id.upper(), updated_pillar_scores
        )

    return _response(200, {
        "success": True, "record_id": record_id, "updated_at": now,
        "evidence_ids_appended": len(new_evidence_ids) if new_evidence_ids else 0,
    })


def _handle_checkout(
    project_id: str,
    record_type: str,
    record_id: str,
    body: Dict,
    event: Optional[Dict] = None,
) -> Dict:
    """POST /{project}/{type}/{id}/checkout — session checkout."""
    body["field"] = "active_agent_session"
    body["value"] = True
    # ENC-TSK-J93: pass event through so the SCI gate can honor the
    # X-Checkout-Service-Key exemption on the ENC-FTR-037 checkout chain.
    return _handle_update_field(project_id, record_type, record_id, body, event=event)


def _handle_release(
    project_id: str,
    record_type: str,
    record_id: str,
    body: Dict,
    event: Optional[Dict] = None,
) -> Dict:
    """DELETE /{project}/{type}/{id}/checkout — session release."""
    body["field"] = "active_agent_session"
    body["value"] = False
    return _handle_update_field(project_id, record_type, record_id, body, event=event)


def _handle_acceptance_evidence(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/acceptance-evidence — set evidence on acceptance criterion."""
    criterion_index = body.get("criterion_index")
    evidence_text = body.get("evidence", "").strip()
    evidence_acceptance = body.get("evidence_acceptance", False)

    if criterion_index is None:
        return _error(400, "Field 'criterion_index' is required.")
    try:
        criterion_index = int(criterion_index)
    except (ValueError, TypeError):
        return _error(400, "Field 'criterion_index' must be an integer.")

    if evidence_acceptance and not evidence_text:
        return _error(400, "Cannot set evidence_acceptance=true without providing evidence text.")

    ddb = _get_ddb()
    key = _build_key(project_id, record_type, record_id)

    # Fetch the record
    try:
        raw_item = _get_record_raw(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if raw_item is None:
        return _error(404, f"Record not found: {record_id}")

    item_data = _deser_item(raw_item)

    if item_data.get("record_type") not in ("feature", "task"):
        return _error(400, f"acceptance-evidence only applies to features and tasks. This is a {item_data.get('record_type')}.")

    # ENC-TSK-I07 (Dedup P3): evidence freeze. A superseded record's accepted
    # acceptance-evidence is preserved-on-B and immutable (DOC-DF651F07D5C2 §7).
    # This also enforces the evidence-orphan invariant: B cannot gain evidence
    # after being collapsed into the canonical. Un-supersede first to edit again.
    if item_data.get("status") == "superseded":
        return _error(409,
            f"Record '{record_id}' is superseded (evidence frozen). "
            "Acceptance evidence is immutable on a superseded record; un-supersede first.")

    ac_list = item_data.get("acceptance_criteria", [])
    if not ac_list:
        return _error(400, f"Record '{record_id}' has no acceptance_criteria.")

    if criterion_index < 0 or criterion_index >= len(ac_list):
        return _error(400,
            f"criterion_index {criterion_index} out of range. "
            f"Record has {len(ac_list)} criteria (indices 0-{len(ac_list) - 1}).")

    # Get description from existing criterion
    raw_ac = raw_item.get("acceptance_criteria", {}).get("L", [])
    ac_item = raw_ac[criterion_index]
    if "S" in ac_item:
        description = ac_item["S"]
    elif "M" in ac_item:
        description = ac_item["M"].get("description", {}).get("S", "")
    else:
        description = str(ac_list[criterion_index])

    now = _now_z()
    note_suffix = _write_source_note_suffix(body)
    ac_updated = {"M": {
        "description": _ser_s(description),
        "evidence": _ser_s(evidence_text),
        "evidence_acceptance": {"BOOL": evidence_acceptance},
    }}
    status_word = "accepted" if evidence_acceptance else "updated"
    note_text = (
        f"Acceptance criterion [{criterion_index}] evidence {status_word}"
        f"{note_suffix}: {description[:80]}"
    )
    history_entry = {"M": {
        "timestamp": _ser_s(now), "status": _ser_s("worklog"),
        "description": _ser_s(note_text),
    }}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                f"SET acceptance_criteria[{criterion_index}] = :ac_item, "
                "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ExpressionAttributeValues={
                ":ac_item": ac_updated, ":now": _ser_s(now),
                ":note": _ser_s(note_text), ":wsrc": _build_write_source(body),
                ":zero": {"N": "0"}, ":one": {"N": "1"},
                ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
            },
        )
    except Exception as exc:
        logger.error("update_item (evidence) failed: %s", exc)
        return _error(500, "Database write failed.")

    # Build criteria summary
    criteria_summary = []
    for i, ac in enumerate(ac_list):
        if isinstance(ac, dict):
            desc = ac.get("description", str(ac))
            ev_acc = ac.get("evidence_acceptance", False)
        elif isinstance(ac, str):
            desc = ac
            ev_acc = False
        else:
            desc = str(ac)
            ev_acc = False
        if i == criterion_index:
            desc = description
            ev_acc = evidence_acceptance
        criteria_summary.append({"index": i, "description": desc[:100], "evidence_acceptance": ev_acc})

    all_accepted = all(c["evidence_acceptance"] for c in criteria_summary)

    return _response(200, {
        "success": True, "record_id": record_id,
        "criterion_index": criterion_index,
        "evidence_acceptance": evidence_acceptance,
        "updated_at": now, "criteria_summary": criteria_summary,
        "all_criteria_accepted": all_accepted, "completion_eligible": all_accepted,
    })


# ---------------------------------------------------------------------------
# Typed Relationship Edge Primitive (ENC-FTR-049)
# ---------------------------------------------------------------------------

_RELATIONSHIP_TYPES = frozenset({
    "blocks", "blocked-by",
    "duplicates", "duplicated-by",
    "relates-to",
    "parent-of", "child-of",
    "depends-on", "depended-on-by",
    "clones", "cloned-by",
    "affects", "affected-by",
    "tests", "tested-by",
    "consumes-from", "produces-for",
    # ENC-FTR-058: Plan primitive relationship types
    "plan-contains", "contained-by-plan",
    "plan-attached-doc", "doc-attached-to-plan",
    "plan-implements", "implemented-by-plan",
    # ENC-FTR-052 / ENC-TSK-C36: Lesson typed relationships
    "learned-from", "teaches",
    "supersedes", "superseded-by",
    # ENC-FTR-061 / ENC-TSK-C36: Handoff typed relationships
    "hands-off", "handed-off-by",
    # ENC-TSK-960 / ENC-TSK-C36: Coordination dispatch typed relationships
    "dispatches", "dispatched-by",
    # ENC-FTR-076 / ENC-TSK-E08: Component proposal provenance
    "component-proposed-by", "proposes-component",
    # ENC-FTR-077: Docstore subtype edges
    "investigates", "investigated-by",
    "tracks-wave-of", "has-wave-doc",
    # ENC-FTR-076 v2 / ENC-TSK-F45: Component-task lifecycle edges
    "designs", "designed-by",
    "implements", "implemented-by",
    "deploys", "deployed-by",
    # ENC-FTR-082 Phase A / AC-6: Pathway-telemetry traversal relationship.
    "pathway-traversed", "traversed-by",
    # ENC-TSK-C08 / ENC-FTR-064: Handoff Consolidation Engine provenance edges.
    "consolidated-from", "consolidates",
    "proposed-by", "proposes",
})

_INVERSE_PAIRS: Dict[str, str] = {
    "blocks": "blocked-by", "blocked-by": "blocks",
    "duplicates": "duplicated-by", "duplicated-by": "duplicates",
    "relates-to": "relates-to",
    "parent-of": "child-of", "child-of": "parent-of",
    "depends-on": "depended-on-by", "depended-on-by": "depends-on",
    "clones": "cloned-by", "cloned-by": "clones",
    "affects": "affected-by", "affected-by": "affects",
    "tests": "tested-by", "tested-by": "tests",
    "consumes-from": "produces-for", "produces-for": "consumes-from",
    # ENC-FTR-058: Plan primitive
    "plan-contains": "contained-by-plan", "contained-by-plan": "plan-contains",
    "plan-attached-doc": "doc-attached-to-plan", "doc-attached-to-plan": "plan-attached-doc",
    "plan-implements": "implemented-by-plan", "implemented-by-plan": "plan-implements",
    # ENC-FTR-052 / ENC-TSK-C36: Lesson typed relationships
    "learned-from": "teaches", "teaches": "learned-from",
    "supersedes": "superseded-by", "superseded-by": "supersedes",
    # ENC-FTR-061 / ENC-TSK-C36: Handoff typed relationships
    "hands-off": "handed-off-by", "handed-off-by": "hands-off",
    # ENC-TSK-960 / ENC-TSK-C36: Coordination dispatch typed relationships
    "dispatches": "dispatched-by", "dispatched-by": "dispatches",
    # ENC-FTR-076 / ENC-TSK-E08: Component proposal provenance
    "component-proposed-by": "proposes-component",
    "proposes-component": "component-proposed-by",
    # ENC-FTR-077: Docstore subtype edges
    "investigates": "investigated-by", "investigated-by": "investigates",
    "tracks-wave-of": "has-wave-doc", "has-wave-doc": "tracks-wave-of",
    # ENC-FTR-076 v2 / ENC-TSK-F45: Component-task lifecycle edges
    "designs": "designed-by", "designed-by": "designs",
    "implements": "implemented-by", "implemented-by": "implements",
    "deploys": "deployed-by", "deployed-by": "deploys",
    # ENC-FTR-082 Phase A / AC-6: Pathway-telemetry traversal relationship.
    "pathway-traversed": "traversed-by", "traversed-by": "pathway-traversed",
    # ENC-TSK-C08 / ENC-FTR-064: Handoff Consolidation Engine provenance edges.
    "consolidated-from": "consolidates", "consolidates": "consolidated-from",
    "proposed-by": "proposes", "proposes": "proposed-by",
}

_OWL_CHARACTERISTICS: Dict[str, Dict[str, bool]] = {
    "blocks":        {"asymmetric": True, "irreflexive": True, "transitive": False},
    "blocked-by":    {"asymmetric": True, "irreflexive": True, "transitive": False},
    "duplicates":    {"asymmetric": True, "irreflexive": True, "transitive": False},
    "duplicated-by": {"asymmetric": True, "irreflexive": True, "transitive": False},
    "relates-to":    {"symmetric": True, "irreflexive": True, "transitive": False},
    "parent-of":     {"asymmetric": True, "irreflexive": True, "transitive": True},
    "child-of":      {"asymmetric": True, "irreflexive": True, "transitive": True},
    "depends-on":    {"asymmetric": True, "irreflexive": True, "transitive": True},
    "depended-on-by": {"asymmetric": True, "irreflexive": True, "transitive": True},
    "clones":        {"asymmetric": True, "irreflexive": True, "transitive": False},
    "cloned-by":     {"asymmetric": True, "irreflexive": True, "transitive": False},
    "affects":       {"asymmetric": True, "irreflexive": True, "transitive": False},
    "affected-by":   {"asymmetric": True, "irreflexive": True, "transitive": False},
    "tests":         {"asymmetric": True, "irreflexive": True, "transitive": False},
    "tested-by":     {"asymmetric": True, "irreflexive": True, "transitive": False},
    "consumes-from": {"asymmetric": True, "irreflexive": True, "transitive": False},
    "produces-for":  {"asymmetric": True, "irreflexive": True, "transitive": False},
    # ENC-FTR-058: Plan primitive
    "plan-contains":      {"asymmetric": True, "irreflexive": True, "transitive": False},
    "contained-by-plan":  {"asymmetric": True, "irreflexive": True, "transitive": False},
    "plan-attached-doc":  {"asymmetric": True, "irreflexive": True, "transitive": False},
    "doc-attached-to-plan": {"asymmetric": True, "irreflexive": True, "transitive": False},
    "plan-implements":    {"asymmetric": True, "irreflexive": True, "transitive": False},
    "implemented-by-plan": {"asymmetric": True, "irreflexive": True, "transitive": False},
    # ENC-FTR-052 / ENC-TSK-C36: Lesson typed relationships
    "learned-from":       {"asymmetric": True, "irreflexive": True, "transitive": False},
    "teaches":            {"asymmetric": True, "irreflexive": True, "transitive": False},
    "supersedes":         {"asymmetric": True, "irreflexive": True, "transitive": True},
    "superseded-by":      {"asymmetric": True, "irreflexive": True, "transitive": True},
    # ENC-FTR-061 / ENC-TSK-C36: Handoff typed relationships
    "hands-off":          {"asymmetric": True, "irreflexive": True, "transitive": False},
    "handed-off-by":      {"asymmetric": True, "irreflexive": True, "transitive": False},
    # ENC-TSK-960 / ENC-TSK-C36: Coordination dispatch typed relationships
    "dispatches":         {"asymmetric": True, "irreflexive": True, "transitive": False},
    "dispatched-by":      {"asymmetric": True, "irreflexive": True, "transitive": False},
    # ENC-FTR-082 Phase A / AC-6: Pathway-telemetry traversal relationship.
    "pathway-traversed":  {"asymmetric": True, "irreflexive": True, "transitive": False},
    "traversed-by":       {"asymmetric": True, "irreflexive": True, "transitive": False},
    # ENC-TSK-C08 / ENC-FTR-064: Handoff Consolidation Engine provenance edges.
    "consolidated-from":  {"asymmetric": True, "irreflexive": True, "transitive": False},
    "consolidates":       {"asymmetric": True, "irreflexive": True, "transitive": False},
    "proposed-by":        {"asymmetric": True, "irreflexive": True, "transitive": False},
    "proposes":           {"asymmetric": True, "irreflexive": True, "transitive": False},
}

# Domain/range constraints: {relationship_type: {source_types, target_types}}
# None means any record type is allowed.
_DOMAIN_RANGE_CONSTRAINTS: Dict[str, Dict[str, Optional[frozenset]]] = {
    "blocks":        {"source": frozenset({"task", "issue"}), "target": frozenset({"task", "issue"})},
    "blocked-by":    {"source": frozenset({"task", "issue"}), "target": frozenset({"task", "issue"})},
    "duplicates":    {"source": None, "target": None},
    "duplicated-by": {"source": None, "target": None},
    "relates-to":    {"source": None, "target": None},
    "parent-of":     {"source": None, "target": None},
    "child-of":      {"source": None, "target": None},
    "depends-on":    {"source": frozenset({"task", "issue"}), "target": frozenset({"task", "issue", "feature"})},
    "depended-on-by": {"source": frozenset({"task", "issue", "feature"}), "target": frozenset({"task", "issue"})},
    "clones":        {"source": None, "target": None},
    "cloned-by":     {"source": None, "target": None},
    "affects":       {"source": frozenset({"issue"}), "target": frozenset({"task", "feature"})},
    "affected-by":   {"source": frozenset({"task", "feature"}), "target": frozenset({"issue"})},
    "tests":         {"source": frozenset({"task"}), "target": frozenset({"feature", "issue"})},
    "tested-by":     {"source": frozenset({"feature", "issue"}), "target": frozenset({"task"})},
    "consumes-from": {"source": None, "target": None},
    "produces-for":  {"source": None, "target": None},
    # ENC-FTR-058: Plan primitive
    "plan-contains":      {"source": frozenset({"plan"}), "target": frozenset({"task", "issue", "feature"})},
    "contained-by-plan":  {"source": frozenset({"task", "issue", "feature"}), "target": frozenset({"plan"})},
    "plan-attached-doc":  {"source": frozenset({"plan"}), "target": None},  # target can be any (documents are not a record type)
    "doc-attached-to-plan": {"source": None, "target": frozenset({"plan"})},
    "plan-implements":    {"source": frozenset({"plan"}), "target": frozenset({"feature"})},
    "implemented-by-plan": {"source": frozenset({"feature"}), "target": frozenset({"plan"})},
    # ENC-FTR-052 / ENC-TSK-C36: Lesson typed relationships.
    # learned-from: lesson -> any record type (cross-project allowed; target unconstrained).
    # teaches: any record type -> lesson (inverse).
    "learned-from":       {"source": frozenset({"lesson"}), "target": None},
    "teaches":            {"source": None, "target": frozenset({"lesson"})},
    # ENC-TSK-I07 (Dedup P3): generalized from lesson-only to {lesson, issue, task}
    # so the supersession primitive (DOC-DF651F07D5C2 §7) covers duplicate
    # issue/issue and task/task collapse. Same-type + same-project is enforced by
    # the supersede operation guard (_supersede_precheck), not the domain/range
    # layer, because the OWL constraint only bounds endpoint record types.
    "supersedes":         {"source": frozenset({"lesson", "issue", "task"}), "target": frozenset({"lesson", "issue", "task"})},
    "superseded-by":      {"source": frozenset({"lesson", "issue", "task"}), "target": frozenset({"lesson", "issue", "task"})},
    # ENC-FTR-061 / ENC-TSK-C36: Handoff typed relationships. Targets are document IDs
    # in practice; documents are not a tracker record type so target is unconstrained.
    "hands-off":          {"source": None, "target": None},
    "handed-off-by":      {"source": None, "target": None},
    # ENC-TSK-960 / ENC-TSK-C36: Coordination dispatch typed relationships.
    "dispatches":         {"source": None, "target": frozenset({"task"})},
    "dispatched-by":      {"source": frozenset({"task"}), "target": None},
    # ENC-FTR-082 Phase A / AC-6: Pathway-telemetry traversal relationship. Endpoints
    # can be any governed record type (intent/anchor -> result node), so unconstrained.
    "pathway-traversed":  {"source": None, "target": None},
    "traversed-by":       {"source": None, "target": None},
    # ENC-TSK-C08 / ENC-FTR-064: HCE provenance edges. Endpoints are document IDs
    # (candidate / handoff) and the proposer record; documents are not a tracker
    # record type, so source/target are unconstrained (mirrors hands-off).
    "consolidated-from":  {"source": None, "target": None},
    "consolidates":       {"source": None, "target": None},
    "proposed-by":        {"source": None, "target": None},
    "proposes":           {"source": None, "target": None},
}

_TRANSITIVE_TYPES = frozenset(
    t for t, chars in _OWL_CHARACTERISTICS.items() if chars.get("transitive")
)


def _record_type_from_id(record_id: str) -> Optional[str]:
    """Extract record type from a human-readable ID like ENC-TSK-001."""
    parts = record_id.strip().upper().split("-")
    if len(parts) < 2:
        return None
    return _ID_SEGMENT_TO_TYPE.get(parts[1])


def _validate_rel_irreflexive(source_id: str, target_id: str) -> Optional[str]:
    if source_id.upper() == target_id.upper():
        return "Self-referencing relationships are not allowed (irreflexive constraint)."
    return None


def _validate_rel_domain_range(
    relationship_type: str, source_type: Optional[str], target_type: Optional[str]
) -> Optional[str]:
    constraints = _DOMAIN_RANGE_CONSTRAINTS.get(relationship_type)
    if not constraints:
        return f"Unknown relationship type: {relationship_type}"
    allowed_source = constraints["source"]
    allowed_target = constraints["target"]
    if allowed_source is not None and source_type not in allowed_source:
        return (
            f"Domain constraint violation: '{relationship_type}' requires source type "
            f"in {sorted(allowed_source)}, got '{source_type}'."
        )
    if allowed_target is not None and target_type not in allowed_target:
        return (
            f"Range constraint violation: '{relationship_type}' requires target type "
            f"in {sorted(allowed_target)}, got '{target_type}'."
        )
    return None


def _validate_rel_no_circular(
    project_id: str, source_id: str, target_id: str, relationship_type: str
) -> Optional[str]:
    """BFS from target following same-type edges to detect if source is reachable (cycle)."""
    if relationship_type not in _TRANSITIVE_TYPES:
        return None
    ddb = _get_ddb()
    visited: set = set()
    queue = [target_id.upper()]
    while queue and len(visited) < 100:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current == source_id.upper():
            return (
                f"Circular reference detected: creating '{relationship_type}' from "
                f"{source_id} to {target_id} would create a cycle."
            )
        prefix = f"rel#{current}#{relationship_type}#"
        resp = ddb.query(
            TableName=DYNAMODB_TABLE,
            KeyConditionExpression="project_id = :pid AND begins_with(record_id, :prefix)",
            ExpressionAttributeValues={
                ":pid": _ser_s(project_id),
                ":prefix": _ser_s(prefix),
            },
            ProjectionExpression="record_id",
        )
        for item in resp.get("Items", []):
            sk = item.get("record_id", {}).get("S", "")
            parts = sk.split("#")
            if len(parts) >= 4:
                neighbor = parts[3]
                if neighbor not in visited:
                    queue.append(neighbor)
    return None


def _validate_rel_endpoints_exist(
    project_id: str, source_id: str, target_id: str
) -> Optional[str]:
    ddb = _get_ddb()
    for rid in (source_id, target_id):
        rtype = _record_type_from_id(rid)
        if not rtype:
            return f"Cannot determine record type from ID '{rid}'."
        key = _build_key(project_id, rtype, rid)
        resp = ddb.get_item(TableName=DYNAMODB_TABLE, Key=key, ProjectionExpression="project_id")
        if not resp.get("Item"):
            return f"Record '{rid}' does not exist in project '{project_id}'."
    return None


def _handle_create_relationship(project_id: str, body: Dict) -> Dict:
    """Create a typed relationship edge with auto-maintained inverse."""
    source_id = str(body.get("source_id", "")).strip().upper()
    target_id = str(body.get("target_id", "")).strip().upper()
    relationship_type = str(body.get("relationship_type", "")).strip().lower()
    reason = str(body.get("reason", "")).strip()
    weight = body.get("weight", 1.0)
    confidence = body.get("confidence", 1.0)
    provenance = str(body.get("provenance", "agent")).strip().lower()

    if not source_id or not target_id or not relationship_type:
        return _error(400, "source_id, target_id, and relationship_type are required.")
    if relationship_type not in _RELATIONSHIP_TYPES:
        return _error(400, f"Invalid relationship_type '{relationship_type}'. "
                      f"Valid types: {sorted(_RELATIONSHIP_TYPES)}")
    if not reason:
        return _error(400, "reason is required for relationship creation.")
    if provenance not in ("agent", "human", "system", "migration"):
        return _error(400, f"Invalid provenance '{provenance}'. "
                      "Valid: agent, human, system, migration.")
    try:
        weight = float(weight)
        confidence = float(confidence)
    except (ValueError, TypeError):
        return _error(400, "weight and confidence must be numeric.")
    if not (0.0 <= weight <= 1.0):
        return _error(400, "weight must be between 0.0 and 1.0.")
    if not (0.0 <= confidence <= 1.0):
        return _error(400, "confidence must be between 0.0 and 1.0.")

    source_type = _record_type_from_id(source_id)
    target_type = _record_type_from_id(target_id)

    err = _validate_rel_irreflexive(source_id, target_id)
    if err:
        return _error(400, err)
    err = _validate_rel_domain_range(relationship_type, source_type, target_type)
    if err:
        return _error(400, err)
    err = _validate_rel_endpoints_exist(project_id, source_id, target_id)
    if err:
        return _error(404, err)
    err = _validate_rel_no_circular(project_id, source_id, target_id, relationship_type)
    if err:
        return _error(409, err)

    # ENC-TSK-I07 (Dedup P3): supersession rides on the `superseded-by` edge.
    # Guard BEFORE creating the tombstone so we never leave a half-applied state
    # (idempotent re-supersede into the same canonical short-circuits to 200).
    _supersede_ctx = None
    if (relationship_type == "superseded-by"
            and source_type in _SUPERSEDABLE_TYPES
            and target_type in _SUPERSEDABLE_TYPES):
        _pre = _supersede_precheck(project_id, source_id, target_id)
        if "error" in _pre:
            return _error(_pre["status"], _pre["error"])
        if _pre.get("idempotent"):
            return _response(200, _pre["result"])
        _supersede_ctx = _pre

    inverse_type = _INVERSE_PAIRS[relationship_type]
    now = dt.datetime.now(dt.timezone.utc).isoformat()

    forward_sk = f"rel#{source_id}#{relationship_type}#{target_id}"
    inverse_sk = f"rel#{target_id}#{inverse_type}#{source_id}"

    ws = body.get("write_source", {})

    def _rel_item(sk: str, rel_type: str, src: str, tgt: str, is_inv: bool, canon_sk: str) -> Dict:
        return {
            "project_id": _ser_s(project_id),
            "record_id": _ser_s(sk),
            "record_type": _ser_s("relationship"),
            "relationship_type": _ser_s(rel_type),
            "source_id": _ser_s(src),
            "target_id": _ser_s(tgt),
            "weight": {"N": str(weight)},
            "confidence": {"N": str(confidence)},
            "reason": _ser_s(reason),
            "provenance": _ser_s(provenance),
            "is_inverse": {"BOOL": is_inv},
            "canonical_edge_id": _ser_s(canon_sk),
            "created_at": _ser_s(now),
            "updated_at": _ser_s(now),
            "write_source": _ser_value(ws) if ws else _ser_value({}),
        }

    forward_item = _rel_item(forward_sk, relationship_type, source_id, target_id, False, forward_sk)
    inverse_item = _rel_item(inverse_sk, inverse_type, target_id, source_id, True, forward_sk)

    ddb = _get_ddb()
    try:
        from enceladus_shared.relationship_store import build_create_transact_puts

        ddb.transact_write_items(
            TransactItems=build_create_transact_puts(
                DYNAMODB_TABLE, forward_item, inverse_item
            )
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons", [])
            for r in reasons:
                if r.get("Code") == "ConditionalCheckFailed":
                    return _error(409, f"Relationship already exists: {relationship_type} "
                                  f"from {source_id} to {target_id}.")
            return _error(500, f"Transaction failed: {exc}")
        raise

    _resp_body = {
        "success": True,
        "forward_edge": forward_sk,
        "inverse_edge": inverse_sk,
        "relationship_type": relationship_type,
        "source_id": source_id,
        "target_id": target_id,
        "weight": weight,
        "confidence": confidence,
        "reason": reason,
        "provenance": provenance,
        "created_at": now,
    }
    # ENC-TSK-I07: the `superseded-by` tombstone now exists — apply side-effects
    # (idempotent edge migration onto the canonical + transition B to `superseded`).
    if _supersede_ctx is not None:
        _resp_body["supersession"] = _apply_supersession(
            project_id, source_id, target_id, _supersede_ctx, body)
    return _response(201, _resp_body)


def _handle_archive_relationship(project_id: str, params: Dict) -> Dict:
    """Soft-delete a typed relationship edge by setting status=archived.

    No DynamoDB DeleteItem — data is preserved for audit. Graph sync
    removes the Neo4j edge when it sees status=archived.

    Reads source_id, target_id, relationship_type from query params (not body)
    because APIGW HTTP API does not reliably forward request body for DELETE.
    """
    source_id = str(params.get("source_id", "")).strip().upper()
    target_id = str(params.get("target_id", "")).strip().upper()
    relationship_type = str(params.get("relationship_type", "")).strip().lower()

    if not source_id or not target_id or not relationship_type:
        return _error(400, "source_id, target_id, and relationship_type are required.")
    if relationship_type not in _RELATIONSHIP_TYPES:
        return _error(400, f"Invalid relationship_type '{relationship_type}'.")

    inverse_type = _INVERSE_PAIRS[relationship_type]
    forward_sk = f"rel#{source_id}#{relationship_type}#{target_id}"
    inverse_sk = f"rel#{target_id}#{inverse_type}#{source_id}"
    now = dt.datetime.now(dt.timezone.utc).isoformat()

    ddb = _get_ddb()
    try:
        from enceladus_shared.relationship_store import build_archive_transact_updates

        ddb.transact_write_items(
            TransactItems=build_archive_transact_updates(
                DYNAMODB_TABLE,
                project_id_attr=_ser_s(project_id),
                forward_sk=forward_sk,
                inverse_sk=inverse_sk,
                archived_at_attr=_ser_s(now),
            )
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            return _error(404, f"Relationship not found: {relationship_type} "
                          f"from {source_id} to {target_id}.")
        raise

    _arch_body = {
        "success": True,
        "archived_forward": forward_sk,
        "archived_inverse": inverse_sk,
        "archived_at": now,
    }
    # ENC-TSK-I07: archiving a `superseded-by` edge un-supersedes the source —
    # restores its pre-supersession status, retrieval/triage eligibility, and
    # migrated edges (§7 reversibility).
    if (relationship_type == "superseded-by"
            and _record_type_from_id(source_id) in _SUPERSEDABLE_TYPES):
        _rev = _revert_supersession(project_id, source_id, {})
        if _rev:
            _arch_body["unsupersession"] = _rev
    return _response(200, _arch_body)


def _handle_list_relationships(project_id: str, query_params: Dict) -> Dict:
    """List relationship edges with optional filters."""
    source_id = str(query_params.get("source_id", "")).strip().upper()
    target_id = str(query_params.get("target_id", "")).strip().upper()
    relationship_type = str(query_params.get("relationship_type", "")).strip().lower()
    min_weight = query_params.get("min_weight", "")
    provenance_filter = str(query_params.get("provenance", "")).strip().lower()
    page_size = min(int(query_params.get("page_size", "50")), 200)

    ddb = _get_ddb()

    if source_id and relationship_type:
        sk_prefix = f"rel#{source_id}#{relationship_type}#"
    elif source_id:
        sk_prefix = f"rel#{source_id}#"
    elif target_id and relationship_type:
        inverse_type = _INVERSE_PAIRS.get(relationship_type, "")
        if not inverse_type:
            return _error(400, f"Invalid relationship_type '{relationship_type}'.")
        sk_prefix = f"rel#{target_id}#{inverse_type}#"
    elif target_id:
        sk_prefix = f"rel#{target_id}#"
    else:
        sk_prefix = "rel#"

    kwargs: Dict[str, Any] = {
        "Limit": page_size,
    }

    cursor = query_params.get("cursor", "")
    exclusive_start_key = None
    if cursor:
        try:
            import base64
            exclusive_start_key = json.loads(base64.b64decode(cursor))
        except Exception:
            pass

    from enceladus_shared.relationship_store import query_relationship_raw_items

    items, last_key = query_relationship_raw_items(
        ddb,
        DYNAMODB_TABLE,
        project_id,
        sk_prefix,
        ser_s=_ser_s,
        limit=page_size,
        exclusive_start_key=exclusive_start_key,
    )

    results = []
    for item in items:
        rec = _deser_item(item)
        if rec.get("record_type") != "relationship":
            continue
        if rec.get("is_inverse", False):
            continue
        if rec.get("status") == "archived":
            continue
        if min_weight:
            try:
                if float(rec.get("weight", 1.0)) < float(min_weight):
                    continue
            except (ValueError, TypeError):
                pass
        if provenance_filter and rec.get("provenance", "") != provenance_filter:
            continue
        if target_id and not source_id:
            pass
        results.append({
            "source_id": rec.get("source_id", ""),
            "target_id": rec.get("target_id", ""),
            "relationship_type": rec.get("relationship_type", ""),
            "weight": rec.get("weight", 1.0),
            "confidence": rec.get("confidence", 1.0),
            "reason": rec.get("reason", ""),
            "provenance": rec.get("provenance", ""),
            "created_at": rec.get("created_at", ""),
            "canonical_edge_id": rec.get("canonical_edge_id", ""),
        })

    response_body: Dict[str, Any] = {
        "success": True,
        "relationships": results,
        "count": len(results),
    }

    if last_key:
        import base64
        response_body["next_cursor"] = base64.b64encode(
            json.dumps(last_key, default=str).encode()
        ).decode()

    return _response(200, response_body)


# ---------------------------------------------------------------------------
# ENC-TSK-I07 (Dedup P3): Supersession primitive — DOC-DF651F07D5C2 §7
# ---------------------------------------------------------------------------
# Soft, reversible, non-destructive collapse of a duplicate record B into a
# canonical A. The operation rides on the typed `superseded-by` edge: creating
# B-[superseded-by]->A between two same-type, same-project issue/task records
# triggers supersession; archiving that edge reverts it. `superseded` is reached
# ONLY through this operation (never the generic status-PATCH path), which
# guarantees the tombstone edge + idempotent edge migration + evidence freeze
# happen atomically with the status transition. Records are preserved for audit
# (closed-not-deleted semantics); only B's active participation is retired.

_SUPERSEDABLE_TYPES = frozenset({"issue", "task"})


def _accepted_evidence_count(item_data: Dict) -> int:
    """Number of acceptance_criteria entries with evidence_acceptance=true."""
    n = 0
    for ac in item_data.get("acceptance_criteria", []) or []:
        if isinstance(ac, dict) and ac.get("evidence_acceptance"):
            n += 1
    return n


def _supersede_precheck(project_id: str, b_id: str, a_id: str) -> Dict:
    """Guard supersession before any write (DOC-DF651F07D5C2 §4.0/§4.3/§7).

    Returns a context dict on success ({_b_data,_a_data,_type,_prev_status}),
    {"error": msg, "status": code} to reject, or {"idempotent": True, "result": ...}
    when B is already superseded into the same canonical (no-op success).
    """
    b_type = _record_type_from_id(b_id)
    a_type = _record_type_from_id(a_id)
    if b_type not in _SUPERSEDABLE_TYPES or a_type not in _SUPERSEDABLE_TYPES:
        return {"error": f"Supersession applies to issue/task records only (got {b_type} -> {a_type}).", "status": 400}
    if b_type != a_type:
        return {"error": f"Supersession requires same record_type (got {b_type} superseded-by {a_type}); cross-type is a category error (§4.0).", "status": 400}
    b_raw = _get_record_raw(project_id, b_type, b_id)
    if b_raw is None:
        return {"error": f"Superseded record not found: {b_id}", "status": 404}
    a_raw = _get_record_raw(project_id, a_type, a_id)
    if a_raw is None:
        return {"error": f"Canonical record not found: {a_id}", "status": 404}
    b_data = _deser_item(b_raw)
    a_data = _deser_item(a_raw)
    if (a_data.get("project_id") or project_id) != (b_data.get("project_id") or project_id):
        return {"error": "Supersession requires same project (cross-project is a category error, §4.0).", "status": 400}
    if a_data.get("status") == "superseded":
        return {"error": f"Canonical {a_id} is itself superseded (into {a_data.get('superseded_by')}); choose the surviving canonical.", "status": 409}
    cur = b_data.get("status")
    if cur == "superseded":
        existing = str(b_data.get("superseded_by") or "").upper()
        if existing == a_id:
            return {"idempotent": True, "result": {
                "success": True, "idempotent": True,
                "superseded_id": b_id, "canonical_id": a_id,
                "note": "already superseded into canonical",
            }}
        return {"error": f"{b_id} is already superseded into {existing}; un-supersede before re-targeting.", "status": 409}
    # Evidence-orphan guard (§4.3/§7): B must hold no accepted acceptance-evidence
    # the canonical lacks. Conservative count proxy; issues carry no
    # acceptance_criteria so this is a no-op for issue/issue collapse.
    if _accepted_evidence_count(b_data) > _accepted_evidence_count(a_data):
        return {"error": (f"Evidence-orphan conflict: {b_id} holds more accepted acceptance-evidence than "
                          f"canonical {a_id}. Route to human adjudication (T-MID) rather than mechanical "
                          f"supersession (§4.3)."), "status": 409}
    return {"_b_data": b_data, "_a_data": a_data, "_type": b_type, "_prev_status": cur or "open"}


def _put_relationship_pair_idempotent(project_id: str, source_id: str, target_id: str,
                                      rel_type: str, reason: str, body: Dict) -> bool:
    """MERGE-create a forward+inverse typed edge. Returns True if newly created,
    False if it already existed (idempotent). Skips re-validation: callers pass
    endpoints already proven valid (same record_type as the migrated-from node)."""
    inverse_type = _INVERSE_PAIRS.get(rel_type)
    if not inverse_type:
        return False
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    forward_sk = f"rel#{source_id}#{rel_type}#{target_id}"
    inverse_sk = f"rel#{target_id}#{inverse_type}#{source_id}"
    ws = body.get("write_source", {}) if body else {}

    def _item(sk: str, rtype: str, src: str, tgt: str, is_inv: bool) -> Dict:
        return {
            "project_id": _ser_s(project_id), "record_id": _ser_s(sk),
            "record_type": _ser_s("relationship"), "relationship_type": _ser_s(rtype),
            "source_id": _ser_s(src), "target_id": _ser_s(tgt),
            "weight": {"N": "1.0"}, "confidence": {"N": "1.0"},
            "reason": _ser_s(reason), "provenance": _ser_s("migration"),
            "is_inverse": {"BOOL": is_inv}, "canonical_edge_id": _ser_s(forward_sk),
            "created_at": _ser_s(now), "updated_at": _ser_s(now),
            "write_source": _ser_value(ws) if ws else _ser_value({}),
        }

    try:
        _get_ddb().transact_write_items(TransactItems=[
            {"Put": {"TableName": DYNAMODB_TABLE, "Item": _item(forward_sk, rel_type, source_id, target_id, False),
                     "ConditionExpression": "attribute_not_exists(record_id)"}},
            {"Put": {"TableName": DYNAMODB_TABLE, "Item": _item(inverse_sk, inverse_type, target_id, source_id, True),
                     "ConditionExpression": "attribute_not_exists(record_id)"}},
        ])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            return False  # already exists -> idempotent no-op
        raise


def _unarchive_relationship_edge(project_id: str, source_id: str, target_id: str, rel_type: str) -> bool:
    """Reverse _handle_archive_relationship: clear status=archived on forward+inverse
    so graph_sync re-projects the edge (rel_status != 'archived' -> upsert)."""
    inverse_type = _INVERSE_PAIRS.get(rel_type)
    if not inverse_type:
        return False
    forward_sk = f"rel#{source_id}#{rel_type}#{target_id}"
    inverse_sk = f"rel#{target_id}#{inverse_type}#{source_id}"
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        _get_ddb().transact_write_items(TransactItems=[
            {"Update": {"TableName": DYNAMODB_TABLE,
                        "Key": {"project_id": _ser_s(project_id), "record_id": _ser_s(forward_sk)},
                        "UpdateExpression": "REMOVE #st SET unarchived_at = :now",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {":now": _ser_s(now)},
                        "ConditionExpression": "attribute_exists(record_id)"}},
            {"Update": {"TableName": DYNAMODB_TABLE,
                        "Key": {"project_id": _ser_s(project_id), "record_id": _ser_s(inverse_sk)},
                        "UpdateExpression": "REMOVE #st SET unarchived_at = :now",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {":now": _ser_s(now)},
                        "ConditionExpression": "attribute_exists(record_id)"}},
        ])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            return False
        raise


def _migrate_typed_edges(project_id: str, b_id: str, a_id: str, body: Dict) -> List[Dict]:
    """Re-point B's typed relationship edges onto canonical A, idempotently (§7).

    Every active typed edge incident to B is stored as an item with SK prefix
    `rel#{B}#` (B is the source endpoint of that stored item — both the forward
    edges B originates and the inverse legs of edges that target B). For each,
    create the A-equivalent (A as source, same rel_type, same other endpoint) if
    absent, then soft-archive the B edge. Idempotent and order-free. The
    superseded-by/supersedes tombstone is never migrated; edges whose other
    endpoint is the canonical are skipped (no self-loop). Returns descriptors for
    reversibility bookkeeping (stored on B.superseded_migrated_edges)."""
    ddb = _get_ddb()
    migrated: List[Dict] = []
    resp = ddb.query(
        TableName=DYNAMODB_TABLE,
        KeyConditionExpression="project_id = :pid AND begins_with(record_id, :pfx)",
        ExpressionAttributeValues={":pid": _ser_s(project_id), ":pfx": _ser_s(f"rel#{b_id}#")},
    )
    for raw in resp.get("Items", []):
        rec = _deser_item(raw)
        if rec.get("record_type") != "relationship":
            continue
        if rec.get("status") == "archived":
            continue
        rtype = rec.get("relationship_type", "")
        if rtype in ("superseded-by", "supersedes"):
            continue  # never migrate the tombstone itself
        other = str(rec.get("target_id", "")).upper()
        if not other or other == a_id or other == b_id:
            continue
        created = _put_relationship_pair_idempotent(
            project_id, a_id, other, rtype, f"edge migrated from superseded {b_id} (ENC-TSK-I07)", body)
        _handle_archive_relationship(project_id, {
            "source_id": b_id, "target_id": other, "relationship_type": rtype})
        migrated.append({"rel_type": rtype, "other_id": other, "created_on_canonical": created})
    return migrated


def _apply_supersession(project_id: str, b_id: str, a_id: str, ctx: Dict, body: Dict) -> Dict:
    """Execute supersession side-effects after the `superseded-by` tombstone exists.
    Migrates B's other typed edges onto A, then transitions B to the terminal
    `superseded` state with provenance fields for reversibility. Evidence freeze is
    implicit: _handle_acceptance_evidence rejects writes while status==superseded."""
    b_type = ctx["_type"]
    prev_status = ctx["_prev_status"]
    now = _now_z()
    migrated = _migrate_typed_edges(project_id, b_id, a_id, body)
    note = f"Superseded into {a_id}{_write_source_note_suffix(body)}"
    hist = {"M": {"timestamp": _ser_s(now), "status": _ser_s("superseded"), "description": _ser_s(note)}}
    _get_ddb().update_item(
        TableName=DYNAMODB_TABLE, Key=_build_key(project_id, b_type, b_id),
        UpdateExpression=(
            "SET #st = :superseded, superseded_by = :canon, superseded_at = :now, "
            "pre_supersession_status = if_not_exists(pre_supersession_status, :prev), "
            "superseded_migrated_edges = :migrated, "
            "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
            "sync_version = if_not_exists(sync_version, :zero) + :one, "
            "history = list_append(if_not_exists(history, :empty), :h)"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":superseded": _ser_s("superseded"), ":canon": _ser_s(a_id), ":now": _ser_s(now),
            ":prev": _ser_s(prev_status), ":migrated": _ser_value(migrated),
            ":note": _ser_s(note), ":wsrc": _build_write_source(body),
            ":zero": {"N": "0"}, ":one": {"N": "1"}, ":empty": {"L": []}, ":h": {"L": [hist]},
        },
    )
    return {
        "superseded_id": b_id, "canonical_id": a_id, "record_type": b_type,
        "migrated_edges": migrated, "migrated_edge_count": len(migrated),
        "superseded_at": now, "pre_supersession_status": prev_status, "reversible": True,
    }


def _revert_supersession(project_id: str, b_id: str, body: Dict) -> Optional[Dict]:
    """Reverse supersession: restore B's eligibility/status (§7 reversibility).
    Un-archives B's migrated edges (restoring B's neighborhood) and restores B's
    pre-supersession status. The canonical's gained edges are intentionally left
    in place (a coherence gain costly to safely un-merge — documented asymmetry,
    tracked as an I07 follow-on). Returns a summary, or None if B is not superseded."""
    b_type = _record_type_from_id(b_id)
    if b_type not in _SUPERSEDABLE_TYPES:
        return None
    b_raw = _get_record_raw(project_id, b_type, b_id)
    if b_raw is None:
        return None
    b_data = _deser_item(b_raw)
    if b_data.get("status") != "superseded":
        return None
    prev = b_data.get("pre_supersession_status") or "open"
    now = _now_z()
    restored: List[Dict] = []
    for m in b_data.get("superseded_migrated_edges", []) or []:
        rtype = m.get("rel_type") if isinstance(m, dict) else None
        other = m.get("other_id") if isinstance(m, dict) else None
        if rtype and other and _unarchive_relationship_edge(project_id, b_id, str(other), str(rtype)):
            restored.append({"rel_type": rtype, "other_id": other})

    # ENC-TSK-I09 (Dedup P5): if THIS supersession was performed by the MECHANICAL
    # arc-walker (write_source actor == system:arc-walker), an io walk-back of it
    # is corrective will exercised against an auto-merge. Per DOC-DF651F07D5C2 §6/§8
    # that PERMANENTLY demotes the record to ATTESTATION: latch auto_walk_opt_out=true
    # on the restored record (rides the same atomic write) and emit the Artifact-Genesis
    # latch telemetry. The arc-walker can never clear the latch (ENC-FTR-111 AC-2), so
    # the record is never auto-merged again. Human-approved (ENC-TSK-I08) supersessions
    # carry provenance=human / a non-walker provider and are intentionally NOT latched.
    prior_ws = b_data.get("write_source") or {}
    auto_merged = ARC_WALKER_ACTOR in (
        str(prior_ws.get("provider", "")).strip().lower(),
        str(prior_ws.get("channel", "")).strip().lower(),
    )

    note = f"Un-superseded (restored to {prev}){_write_source_note_suffix(body)}"
    hist_entries = [{"M": {"timestamp": _ser_s(now), "status": _ser_s(prev), "description": _ser_s(note)}}]
    set_clause = (
        "SET #st = :prev, updated_at = :now, last_update_note = :note, write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
    )
    eav: Dict[str, Any] = {
        ":prev": _ser_s(prev), ":now": _ser_s(now), ":note": _ser_s(note),
        ":wsrc": _build_write_source(body),
        ":zero": {"N": "0"}, ":one": {"N": "1"}, ":empty": {"L": []},
    }
    latched_by = ""
    if auto_merged:
        latched_by = str(_normalize_write_source(body).get("provider", "")).strip() or "io"
        set_clause += "auto_walk_opt_out = :optout, "
        eav[":optout"] = {"BOOL": True}
        hist_entries.append(_opt_out_latch_history_entry(now, latched_by, "superseded", prev, "auto-merge walk-back"))
    set_clause += "history = list_append(if_not_exists(history, :empty), :h) "
    set_clause += "REMOVE superseded_by, superseded_at, pre_supersession_status, superseded_migrated_edges"
    eav[":h"] = {"L": hist_entries}

    _get_ddb().update_item(
        TableName=DYNAMODB_TABLE, Key=_build_key(project_id, b_type, b_id),
        UpdateExpression=set_clause,
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=eav,
    )
    if auto_merged:
        _emit_opt_out_latch_event(project_id, b_type, b_id, "superseded", prev,
                                  "auto-merge walk-back", latched_by)
    return {"unsuperseded_id": b_id, "restored_status": prev, "restored_edges": restored,
            "unsuperseded_at": now, "auto_walk_opt_out_latched": auto_merged}


# ---------------------------------------------------------------------------
# ENC-TSK-I08 (Dedup P4): io-approval-gated tier-review surface.
#
# Promotes the offline I05 detector (clusters) + I06 certainty model (per-pair
# verdicts) into a LIVE governed approval surface. It PROPOSES; io APPROVES.
# Two ops on POST /{project}/dedup-review:
#   op=propose  — pure, mutation-free tier derivation (any authenticated caller).
#   op=approve  — io-Cognito-only; executes soft supersession by reusing the I07
#                 `superseded-by` primitive. The agent/internal-key path is
#                 rejected (never self-authorizes). See DOC-DF651F07D5C2 §5/§7/§8.
#
# NO auto-merge here: T-HIGH (certificate-certified) is deferred to ENC-TSK-I09's
# flag-gated arc-walker and is never actioned by this surface.
# ---------------------------------------------------------------------------

# Tier ladder boundaries (DOC-DF651F07D5C2 §5). T-MID floor and the review/distinct
# boundary are parameters; defaults match the design doc and I06's review_prob.
_DEDUP_TAU_MID = 0.95          # calibrated_prob >= tau_mid (cert not passed) -> T-MID
_DEDUP_REVIEW_FLOOR = 0.50     # calibrated_prob >= review_floor -> at least T-LOW; below -> distinct
_DEDUP_TIER_RANK = {"T-LOW": 1, "T-MID": 2, "T-HIGH": 3}
_DEDUP_ACTIONABLE_TIERS = ("T-HIGH", "T-MID", "T-LOW")

# ENC-TSK-I09 (Dedup P5): the earned-precision floor that licenses MECHANICAL
# auto-merge (DOC-DF651F07D5C2 §4.3). A T-HIGH pair's certificate is honored by
# the arc-walker ONLY when its 95% lower confidence bound on precision clears this
# value. Structural guarantee (per-pair), independent of the operational flag.
# Callers may RAISE the floor but never lower it below this constant.
_DEDUP_CERT_PRECISION_LCB_FLOOR = 0.999


def _dedup_auto_merge_enabled() -> bool:
    """ENC-TSK-I09: the operational gate. Auto-merge stays DARK (shadow / propose-only)
    until io enables this flag — which the design says is turned on ONLY after the
    certificate precision floor has been empirically certified (DOC-DF651F07D5C2 §4.3/§13)."""
    return _appconfig_flag("enable_dedup_auto_merge", env_fallback="ENABLE_DEDUP_AUTO_MERGE")


def _dedup_auto_merge_kill_switch() -> bool:
    """ENC-TSK-I09: the global kill switch (DOC-DF651F07D5C2 §8). When truthy the
    arc-walker auto-merge halts instantly regardless of the enable flag — checked
    FIRST, before any eligibility evaluation or write."""
    return _appconfig_flag("dedup_auto_merge_kill_switch", env_fallback="DEDUP_AUTO_MERGE_KILL_SWITCH")


def _dedup_auto_merge_cert_holds(verdict: Optional[Dict], lcb_floor: float) -> Tuple[bool, str]:
    """ENC-TSK-I09: does this verdict carry a passing P2 certificate that licenses a
    MECHANICAL merge (DOC-DF651F07D5C2 §4.3)? Requires the conjunctive certificate to
    have PASSED and its 95% precision lower confidence bound to clear the floor. The
    verdict must be the DIRECT (canonical, member) pair — the caller looks it up by the
    canonical-anchored pair key, so a (member, neighbor) verdict can never satisfy this
    (no transitive chain-drag, §4.4). Returns (holds, reason_when_not)."""
    if not verdict:
        return False, "no direct certificate against the chosen canonical (no chain-drag, §4.4)"
    cert = verdict.get("certificate") or {}
    if cert.get("passed") is not True:
        return False, "certificate not passed (P2 CERT does not hold)"
    lcb = cert.get("precision_lcb")
    try:
        lcb = float(lcb)
    except (TypeError, ValueError):
        return False, "certificate precision_lcb missing or non-numeric"
    if lcb < lcb_floor:
        return False, f"certificate precision LCB {lcb} < required floor {lcb_floor}"
    return True, ""


def _dedup_member_opt_out_latched(project_id: str, member_id: str) -> Tuple[bool, Optional[str]]:
    """ENC-TSK-I09: is the auto_walk_opt_out circuit breaker latched on this member?
    A latched record is demoted to ATTESTATION and the arc-walker MUST NOT auto-merge
    it (DOC-DF651F07D5C2 §6; ENC-FTR-111 AC-2). Note: the latch blocks ONLY the
    mechanical walker — the io-Cognito approval path (ENC-TSK-I08) is unaffected.
    Returns (latched, error_when_not_readable)."""
    mtype = _record_type_from_id(member_id)
    raw = _get_record_raw(project_id, mtype, member_id)
    if raw is None:
        return False, f"member record not found: {member_id}"
    data = _deser_item(raw)
    return bool(data.get("auto_walk_opt_out")), None


def _dedup_pair_key(a: str, b: str) -> Tuple[str, str]:
    """Orientation-stable pair key (uppercased, a <= b) — matches I05 edges and
    I06 verdict pair keys so a verdict joins to a cluster's (canonical, member) pair."""
    a2, b2 = str(a).strip().upper(), str(b).strip().upper()
    return (a2, b2) if a2 <= b2 else (b2, a2)


def _dedup_pair_tier(verdict: Optional[Dict], tau_mid: float, review_floor: float) -> str:
    """Map one I06 verdict to the design-doc tier ladder (DOC-DF651F07D5C2 §5).

    certificate passed (or I06 tier 'auto-merge')      -> T-HIGH  (I09's domain)
    calibrated_prob >= tau_mid                          -> T-MID
    calibrated_prob >= review_floor                     -> T-LOW
    else / no verdict (I06 is the tiering authority)    -> distinct  (not surfaced)
    """
    if not verdict:
        return "distinct"
    cert = verdict.get("certificate") or {}
    if cert.get("passed") is True or verdict.get("tier") == "auto-merge":
        return "T-HIGH"
    prob = verdict.get("calibrated_prob")
    if prob is None:
        return "distinct"
    try:
        prob = float(prob)
    except (TypeError, ValueError):
        return "distinct"
    if prob >= tau_mid:
        return "T-MID"
    if prob >= review_floor:
        return "T-LOW"
    return "distinct"


def _dedup_cluster_tier(duplicate_tiers: Sequence[str]) -> Optional[str]:
    """Conservative (least-confident) tier across a cluster's surfaced duplicates.
    Any T-LOW member pulls the whole cluster to T-LOW; all-T-MID-or-better with at
    least one T-MID -> T-MID; all T-HIGH -> T-HIGH. Returns None if none surfaced."""
    ranks = [_DEDUP_TIER_RANK[t] for t in duplicate_tiers if t in _DEDUP_TIER_RANK]
    if not ranks:
        return None
    return {1: "T-LOW", 2: "T-MID", 3: "T-HIGH"}[min(ranks)]


def _dedup_homogeneous(record_ids: Sequence[str]) -> Tuple[bool, Optional[str]]:
    """Hard-floor type check (§4.0): all ids must resolve to a single record_type
    from their ENC-<TYPE>- prefix. Returns (is_homogeneous, the_type_or_None).
    Same-project is enforced per-pair downstream by _supersede_precheck (needs DDB)."""
    types = {_record_type_from_id(str(r)) for r in record_ids if str(r).strip()}
    if len(types) == 1:
        return True, next(iter(types))
    return False, None


def _dedup_build_proposal(cluster: Dict, verdict_index: Dict[Tuple[str, str], Dict],
                          tau_mid: float, review_floor: float) -> Dict:
    """Build one tiered proposal from an I05 cluster + the I06 verdict index.

    Cross-type clusters are never surfaced (hard floor). Per-duplicate tiers are
    derived from each (canonical, duplicate) verdict; 'distinct' duplicates are
    dropped. The cluster tier determines the approval granularity offered to io:
      T-MID  -> 'plan'       (io approves the whole-cluster plan)
      T-LOW  -> 'per-record' (io approves the whole cluster OR a selected subset)
      T-HIGH -> 'deferred'   (ENC-TSK-I09 auto-merge; NOT actionable here)
    """
    cluster_id = cluster.get("cluster_id")
    rtype = cluster.get("record_type")
    project_id = cluster.get("project_id")
    canonical = str(cluster.get("canonical", "")).strip().upper()
    members = [str(m).strip().upper() for m in (cluster.get("members") or []) if str(m).strip()]

    if not canonical or canonical not in members:
        return {"cluster_id": cluster_id, "record_type": rtype, "project_id": project_id,
                "excluded": True, "reason": "cluster missing a canonical member"}

    homo, htype = _dedup_homogeneous(members)
    if not homo or htype not in _SUPERSEDABLE_TYPES:
        # Cross-type, or a type supersession does not apply to: never surfaced (§4.0).
        return {"cluster_id": cluster_id, "record_type": rtype, "project_id": project_id,
                "excluded": True,
                "reason": f"hard-floor excluded (record_type={htype or 'mixed'} not a same-type "
                          f"supersedable cluster; §4.0)"}

    dup_entries: List[Dict] = []
    for d in members:
        if d == canonical:
            continue
        v = verdict_index.get(_dedup_pair_key(canonical, d))
        tier = _dedup_pair_tier(v, tau_mid, review_floor)
        dup_entries.append({
            "record_id": d,
            "tier": tier,
            "calibrated_prob": (v or {}).get("calibrated_prob"),
            "cosine": ((v or {}).get("signals") or {}).get("cosine"),
            "certificate_passed": bool(((v or {}).get("certificate") or {}).get("passed")),
        })

    surfaced = [e for e in dup_entries if e["tier"] in _DEDUP_ACTIONABLE_TIERS]
    dropped = [e["record_id"] for e in dup_entries if e["tier"] == "distinct"]
    cluster_tier = _dedup_cluster_tier([e["tier"] for e in surfaced])

    if cluster_tier == "T-MID":
        actionable, granularity, defer_to = True, "plan", None
    elif cluster_tier == "T-LOW":
        actionable, granularity, defer_to = True, "per-record", None
    elif cluster_tier == "T-HIGH":
        actionable, granularity, defer_to = False, "deferred", "ENC-TSK-I09"
    else:
        actionable, granularity, defer_to = False, "none", None

    return {
        "cluster_id": cluster_id,
        "record_type": rtype,
        "project_id": project_id,
        "canonical": canonical,
        "cluster_tier": cluster_tier,
        "actionable": actionable,
        "granularity": granularity,
        "defer_to": defer_to,
        "duplicates": surfaced,
        "dropped_distinct": dropped,
        "excluded": False,
    }


def _handle_dedup_propose(project_id: str, body: Dict) -> Dict:
    """op=propose: pure, mutation-free tier derivation over I05 clusters + I06 verdicts."""
    clusters = body.get("clusters")
    if not isinstance(clusters, list):
        return _error(400, "Field 'clusters' (list of I05 cluster objects) is required.")
    verdicts = body.get("verdicts") or []
    if not isinstance(verdicts, list):
        return _error(400, "Field 'verdicts' must be a list of I06 verdict objects.")
    try:
        tau_mid = float(body.get("tau_mid", _DEDUP_TAU_MID))
        review_floor = float(body.get("review_floor", _DEDUP_REVIEW_FLOOR))
    except (TypeError, ValueError):
        return _error(400, "tau_mid and review_floor must be numeric.")
    if not (0.0 <= review_floor <= tau_mid <= 1.0):
        return _error(400, "Require 0 <= review_floor <= tau_mid <= 1.")

    vindex: Dict[Tuple[str, str], Dict] = {}
    for v in verdicts:
        a, b = v.get("a"), v.get("b")
        if a and b:
            vindex[_dedup_pair_key(a, b)] = v

    proposals = [_dedup_build_proposal(c, vindex, tau_mid, review_floor) for c in clusters]
    counts = {"T-MID": 0, "T-LOW": 0, "T-HIGH_deferred": 0, "excluded": 0, "not_actionable": 0}
    for p in proposals:
        if p.get("excluded"):
            counts["excluded"] += 1
        elif p.get("cluster_tier") == "T-MID":
            counts["T-MID"] += 1
        elif p.get("cluster_tier") == "T-LOW":
            counts["T-LOW"] += 1
        elif p.get("cluster_tier") == "T-HIGH":
            counts["T-HIGH_deferred"] += 1
        else:
            counts["not_actionable"] += 1

    return _response(200, {
        "success": True,
        "project_id": project_id,
        "tau_mid": tau_mid,
        "review_floor": review_floor,
        "proposal_count": len(proposals),
        "counts": counts,
        "proposals": proposals,
        "note": ("Propose-only (mutation-free). Cross-type/cross-project clusters are never "
                 "surfaced. T-HIGH is deferred to ENC-TSK-I09 auto-merge and not actionable here. "
                 "Approve T-MID (whole-cluster plan) or T-LOW (whole-or-per-record) via op=approve "
                 "(io Cognito session only)."),
    })


def _handle_dedup_approve(project_id: str, body: Dict, claims: Optional[Dict]) -> Dict:
    """op=approve: io-Cognito-gated execution of soft supersession (§7/§8).

    The agent/internal-key path is rejected — this surface records io's approval
    signal and only then writes. Each approved duplicate is superseded into the
    canonical by reusing the I07 `superseded-by` primitive (precheck + idempotent
    edge migration + evidence freeze + reversibility). Per-record failures (e.g.
    an evidence-orphan 409) are surfaced for human adjudication, never auto-forced.
    """
    # io-approval gate — never let the agent/internal-key self-authorize a merge.
    if not _is_human_request(claims):
        return _error(403, "Dedup supersession approval requires io Cognito authority (PWA session). "
                           "The internal-key/agent path cannot self-authorize a merge "
                           "(ENC-TSK-I08 io-gate; DOC-DF651F07D5C2 §8).")

    canonical_id = str(body.get("canonical_id", "")).strip().upper()
    superseded_ids = body.get("superseded_ids")
    tier = str(body.get("tier", "")).strip().upper()
    cluster_id = str(body.get("cluster_id", "")).strip()

    if not canonical_id:
        return _error(400, "Field 'canonical_id' is required.")
    if not isinstance(superseded_ids, list) or not superseded_ids:
        return _error(400, "Field 'superseded_ids' (non-empty list) is required.")
    superseded_ids = [str(s).strip().upper() for s in superseded_ids if str(s).strip()]
    if not superseded_ids:
        return _error(400, "superseded_ids contained no usable record ids.")
    if canonical_id in superseded_ids:
        return _error(400, "canonical_id must not appear in superseded_ids.")
    if len(set(superseded_ids)) != len(superseded_ids):
        return _error(400, "superseded_ids must be unique.")
    # I08 actions only T-MID / T-LOW. T-HIGH auto-merge is ENC-TSK-I09 (flag-gated).
    if tier not in ("T-MID", "T-LOW"):
        return _error(400, "Field 'tier' must be 'T-MID' or 'T-LOW'. T-HIGH auto-merge is "
                           "ENC-TSK-I09's flag-gated arc-walker, not actionable via this surface.")
    # Hard floor: never act on a cross-type set (§4.0). Same-project is enforced
    # per-pair by _supersede_precheck (which reads the records).
    homo, htype = _dedup_homogeneous([canonical_id] + superseded_ids)
    if not homo:
        return _error(400, "Cross-type supersession is a category error (§4.0): canonical and every "
                           "superseded_id must share record_type. Nothing actioned.")
    if htype not in _SUPERSEDABLE_TYPES:
        return _error(400, f"Supersession applies to {sorted(_SUPERSEDABLE_TYPES)} records only "
                           f"(got {htype}).")

    approver = _human_actor(claims)
    reason_extra = str(body.get("reason", "")).strip()
    write_source = body.get("write_source", {})

    results: List[Dict] = []
    superseded_count = 0
    for b_id in superseded_ids:
        reason = (f"io-approved dedup supersession (ENC-TSK-I08; tier={tier}"
                  + (f"; cluster={cluster_id}" if cluster_id else "")
                  + f"; approver={approver})")
        if reason_extra:
            reason = f"{reason}. {reason_extra}"
        resp = _handle_create_relationship(project_id, {
            "source_id": b_id,
            "target_id": canonical_id,
            "relationship_type": "superseded-by",
            "reason": reason,
            "provenance": "human",
            "write_source": write_source,
        })
        status_code = resp.get("statusCode")
        try:
            payload = json.loads(resp.get("body") or "{}")
        except (ValueError, TypeError):
            payload = {}
        ok = status_code in (200, 201)
        if ok:
            superseded_count += 1
        results.append({
            "superseded_id": b_id,
            "status_code": status_code,
            "ok": ok,
            "idempotent": bool(payload.get("idempotent") or (payload.get("supersession") or {}).get("idempotent")),
            "supersession": payload.get("supersession"),
            "detail": payload.get("error"),
        })

    return _response(200, {
        "success": True,
        "project_id": project_id,
        "canonical_id": canonical_id,
        "cluster_id": cluster_id or None,
        "tier": tier,
        "approved_by": approver,
        "requested_count": len(superseded_ids),
        "superseded_count": superseded_count,
        "rejected_count": len(superseded_ids) - superseded_count,
        "results": results,
        "note": ("Soft, reversible supersession via the ENC-TSK-I07 superseded-by op "
                 "(idempotent edge migration + evidence freeze). Per-record failures "
                 "(e.g. evidence-orphan 409) are surfaced for human adjudication, not forced."),
    })


# ---------------------------------------------------------------------------
# ENC-TSK-I09 (Dedup P5): MECHANICAL arc-walker auto-merge for T-HIGH.
#
# The universal arc-walker auto-supersedes certificate-certified T-HIGH duplicate
# pairs WITHOUT a per-merge io gate — judgment has been proved away by the P2
# certainty model (DOC-DF651F07D5C2 §4/§8). io sovereignty is preserved in
# substance by four rails, all wired here:
#   1. Feature flag   — auto-merge stays DARK (shadow / propose-only) until io
#                       enables enable_dedup_auto_merge after the precision floor
#                       is certified. Disabled => evaluate + report, never write.
#   2. Kill switch    — dedup_auto_merge_kill_switch halts auto-walk INSTANTLY,
#                       checked before any eligibility evaluation or write.
#   3. Certificate    — every member must individually hold a passing certificate
#                       with precision LCB >= 0.999 against the CHOSEN canonical
#                       (direct pair only — no transitive chain-drag, §4.4).
#   4. Opt-out latch  — auto_walk_opt_out (ENC-FTR-111/H83) demotes a record to
#                       ATTESTATION; the walker skips it. An io walk-back of any
#                       auto-merge latches it (see _revert_supersession).
# Every executed merge streams to the io-reviewable audit feed (EventBridge
# record.dedup.auto_merged). Supersession itself is the soft, reversible ENC-TSK-I07
# primitive — no auto-merge is ever destructive.
#
# Invoked via POST /{project}/dedup-review op=auto-merge (tracker:write). The merge
# is mechanical, NOT io-approved, so — unlike op=approve — it does NOT require an io
# Cognito session; it is gated by flag + kill switch + per-pair certificate instead.
# ---------------------------------------------------------------------------

def _dedup_auto_merge_cluster(project_id: str, cluster: Dict,
                              verdict_index: Dict[Tuple[str, str], Dict],
                              lcb_floor: float, shadow: bool, body: Dict) -> Dict:
    """Evaluate (and, unless shadow, execute) the MECHANICAL auto-merge for one
    I05 cluster. Each duplicate is auto-superseded into the cluster's canonical iff
    it holds a direct passing certificate (LCB >= floor) AND is not opt-out latched."""
    cluster_id = cluster.get("cluster_id")
    canonical = str(cluster.get("canonical", "")).strip().upper()
    members = [str(m).strip().upper() for m in (cluster.get("members") or []) if str(m).strip()]
    base = {"cluster_id": cluster_id, "canonical": canonical,
            "merged_count": 0, "skipped_count": 0, "results": []}

    if not canonical or canonical not in members:
        return {**base, "excluded": True, "reason": "cluster missing a canonical member"}

    homo, htype = _dedup_homogeneous(members)
    if not homo or htype not in _SUPERSEDABLE_TYPES:
        return {**base, "excluded": True,
                "reason": (f"hard-floor excluded (record_type={htype or 'mixed'} not a same-type "
                           f"supersedable cluster; §4.0)")}

    results: List[Dict] = []
    merged = 0
    skipped = 0
    for d in members:
        if d == canonical:
            continue
        # Rail 3 — direct certificate against the CHOSEN canonical (no chain-drag, §4.4).
        v = verdict_index.get(_dedup_pair_key(canonical, d))
        ok, why = _dedup_auto_merge_cert_holds(v, lcb_floor)
        if not ok:
            skipped += 1
            results.append({"member": d, "action": "skipped", "reason": why})
            continue
        # Rail 4 — opt-out circuit breaker: latched => ATTESTATION, walker must skip (§6).
        latched, latch_err = _dedup_member_opt_out_latched(project_id, d)
        if latch_err:
            skipped += 1
            results.append({"member": d, "action": "skipped", "reason": latch_err})
            continue
        if latched:
            skipped += 1
            results.append({"member": d, "action": "skipped",
                            "reason": "auto_walk_opt_out latched — demoted to ATTESTATION (§6)"})
            continue
        cosine = ((v or {}).get("signals") or {}).get("cosine")
        prob = (v or {}).get("calibrated_prob")
        lcb = ((v or {}).get("certificate") or {}).get("precision_lcb")
        if shadow:
            # Rail 1 — flag disabled: report the proposed merge, write nothing.
            results.append({"member": d, "action": "would-merge",
                            "cosine": cosine, "calibrated_prob": prob, "precision_lcb": lcb,
                            "reason": "shadow mode (enable_dedup_auto_merge off): certificate holds; no write"})
            continue
        # MECHANICAL merge: soft, reversible supersession via the ENC-TSK-I07 primitive,
        # stamped with the arc-walker write_source so the audit feed + walk-back latch
        # detection (in _revert_supersession) are unambiguous.
        reason = (f"MECHANICAL arc-walker auto-merge (ENC-TSK-I09; T-HIGH certificate-certified, "
                  f"precision LCB >= {lcb_floor}"
                  + (f"; cluster={cluster_id}" if cluster_id else "") + ").")
        resp = _handle_create_relationship(project_id, {
            "source_id": d,
            "target_id": canonical,
            "relationship_type": "superseded-by",
            "reason": reason,
            "provenance": "system",
            "write_source": body.get("write_source", {}),
        })
        status_code = resp.get("statusCode")
        try:
            payload = json.loads(resp.get("body") or "{}")
        except (ValueError, TypeError):
            payload = {}
        if status_code in (200, 201):
            merged += 1
            _emit_auto_merge_event(project_id, htype, d, canonical, cluster_id, cosine, prob, lcb)
            results.append({
                "member": d, "action": "auto-merged", "status_code": status_code,
                "idempotent": bool(payload.get("idempotent")
                                   or (payload.get("supersession") or {}).get("idempotent")),
                "supersession": payload.get("supersession"),
                "cosine": cosine, "calibrated_prob": prob, "precision_lcb": lcb,
            })
        else:
            # An evidence-orphan 409 (or any per-member failure) is surfaced, never forced.
            skipped += 1
            results.append({"member": d, "action": "failed", "status_code": status_code,
                            "detail": payload.get("error")})

    return {"cluster_id": cluster_id, "canonical": canonical, "record_type": htype,
            "excluded": False, "merged_count": merged, "skipped_count": skipped, "results": results}


def _handle_dedup_auto_merge(project_id: str, body: Dict, claims: Optional[Dict]) -> Dict:
    """op=auto-merge: the MECHANICAL T-HIGH arc-walker (DOC-DF651F07D5C2 §P5).

    Gated by kill switch (instant halt) + feature flag (dark-until-certified shadow)
    + per-pair certificate (precision LCB >= 0.999, direct against canonical) +
    opt-out latch. Soft, reversible supersession; every executed merge streams to the
    io audit feed. Not io-approved (mechanical), so no Cognito gate — the rails are the
    governance, not a per-merge keystroke."""
    # Rail 2 — global kill switch, checked FIRST: halt instantly, evaluate nothing.
    if _dedup_auto_merge_kill_switch():
        return _response(200, {
            "success": True, "project_id": project_id, "halted": True, "kill_switch": True,
            "enabled": _dedup_auto_merge_enabled(), "merged_count": 0, "skipped_count": 0,
            "clusters": [],
            "note": ("Global kill switch (dedup_auto_merge_kill_switch) engaged — arc-walker "
                     "auto-merge halted instantly (DOC-DF651F07D5C2 §8). No records superseded."),
        })

    # Earned-precision discipline: the floor may be RAISED but never lowered below 0.999.
    try:
        lcb_floor = float(body.get("precision_lcb_floor", _DEDUP_CERT_PRECISION_LCB_FLOOR))
    except (TypeError, ValueError):
        return _error(400, "precision_lcb_floor must be numeric.")
    if lcb_floor < _DEDUP_CERT_PRECISION_LCB_FLOOR:
        return _error(400, (f"precision_lcb_floor may not be lowered below the earned-precision floor "
                            f"{_DEDUP_CERT_PRECISION_LCB_FLOOR} (DOC-DF651F07D5C2 §4.3). "
                            f"Auto-walk is earned by measured precision, not asserted."))

    clusters = body.get("clusters")
    if not isinstance(clusters, list):
        return _error(400, "Field 'clusters' (list of I05 cluster objects) is required.")
    verdicts = body.get("verdicts") or []
    if not isinstance(verdicts, list):
        return _error(400, "Field 'verdicts' must be a list of I06 verdict objects (carrying certificates).")

    vindex: Dict[Tuple[str, str], Dict] = {}
    for v in verdicts:
        a, b = v.get("a"), v.get("b")
        if a and b:
            vindex[_dedup_pair_key(a, b)] = v

    enabled = _dedup_auto_merge_enabled()
    shadow = not enabled  # Rail 1 — dark until the flag is enabled post-certification.

    # Force arc-walker attribution: the audit feed and the walk-back opt-out latch
    # (_revert_supersession) key off write_source == system:arc-walker. A caller cannot
    # spoof a different actor onto a mechanical merge.
    body["write_source"] = {"channel": ARC_WALKER_ACTOR, "provider": ARC_WALKER_ACTOR}

    cluster_results: List[Dict] = []
    merged_count = 0
    skipped_count = 0
    for cluster in clusters:
        cres = _dedup_auto_merge_cluster(project_id, cluster, vindex, lcb_floor, shadow, body)
        cluster_results.append(cres)
        merged_count += cres.get("merged_count", 0)
        skipped_count += cres.get("skipped_count", 0)

    return _response(200, {
        "success": True,
        "project_id": project_id,
        "enabled": enabled,
        "shadow": shadow,
        "kill_switch": False,
        "advanced_by": ARC_WALKER_ACTOR,
        "precision_lcb_floor": lcb_floor,
        "cluster_count": len(clusters),
        "merged_count": merged_count,
        "skipped_count": skipped_count,
        "clusters": cluster_results,
        "note": ((("SHADOW (enable_dedup_auto_merge off): proposed merges reported, nothing written. "
                   if shadow else
                   "Executed MECHANICAL auto-merges via the soft, reversible ENC-TSK-I07 superseded-by op; "
                   "each streamed to the io audit feed. "))
                 + "Every member individually held a passing certificate (precision LCB >= "
                   f"{lcb_floor}) against the chosen canonical — no transitive chain-drag. "
                   "Opt-out-latched records were skipped (ATTESTATION). A global kill switch can halt instantly."),
    })


# ---------------------------------------------------------------------------
# ENC-FTR-121 Ph1 / ENC-TSK-J68 — escalation request/read handlers
# ---------------------------------------------------------------------------

def _parse_escalation_target(target_record_id: str):
    """Resolve (record_type, sort_key, error) for an escalation target ID.

    Target IDs look like PREFIX-SEG-SEQ (e.g. ENC-TSK-J68); SEG resolves the
    record type via _ID_SEGMENT_TO_TYPE and must be an escalatable type.
    """
    parts = str(target_record_id or "").strip().split("-")
    if len(parts) < 3:
        return None, None, (
            "Field 'target_record_id' must look like PREFIX-SEG-SEQ "
            "(e.g. ENC-TSK-123)."
        )
    segment = parts[1].upper()
    record_type = _ID_SEGMENT_TO_TYPE.get(segment)
    if record_type is None or record_type not in _ESCALATION_TARGET_TYPES:
        return None, None, (
            f"target_record_id type '{segment}' is not escalatable. "
            "Allowed: task (TSK), issue (ISS), feature (FTR)."
        )
    return record_type, f"{record_type}#{target_record_id}", ""


def _escalation_event(event_type: str, actor: str, detail: Optional[Dict] = None,
                      guidance_note: str = "") -> Dict:
    """Build one §11.2 event object in DynamoDB attribute shape (append-only)."""
    event_attrs = {
        "event_type": _ser_s(event_type),
        "at": _ser_s(_now_z()),
        "actor": _ser_s(actor or "system"),
    }
    if detail:
        event_attrs["detail"] = _ser_s(json.dumps(detail, default=str))
    if guidance_note:
        event_attrs["guidance_note"] = _ser_s(guidance_note)
    return {"M": event_attrs}


def _escalation_public(item: Dict) -> Dict:
    """Deserialize an escalation item for API responses (payload back to JSON)."""
    record = _deser_item(item)
    raw_payload = record.get("payload")
    if isinstance(raw_payload, str):
        try:
            record["payload"] = json.loads(raw_payload)
        except (ValueError, TypeError):
            pass
    for event in record.get("events") or []:
        raw_detail = event.get("detail") if isinstance(event, dict) else None
        if isinstance(raw_detail, str):
            try:
                event["detail"] = json.loads(raw_detail)
            except (ValueError, TypeError):
                pass
    return record


def _handle_escalation_request(project_id: str, body: Dict) -> Dict:
    """POST /{project}/escalation — governed escalation.request (§5.4).

    Validates the §11.1 envelope via the mutation-handler registry, mints an
    ENC-ESC id server-side, writes the item with status=requested, and appends
    the `requested` event. Malformed requests fail fast and write NOTHING —
    they never reach io's queue.
    """
    if not ENABLE_ESCALATION_PRIMITIVE:
        return _error(503, "Escalation primitive is disabled (enable_escalation_primitive).")

    target_record_id = str(body.get("target_record_id") or "").strip()
    mutation_type = str(body.get("mutation_type") or "").strip()
    payload = body.get("payload")
    justification = str(body.get("justification") or "").strip()
    expected_version = str(body.get("expected_version") or "").strip()

    if not target_record_id:
        return _error(400, "Field 'target_record_id' is required.")
    handler = _ESCALATION_MUTATION_HANDLERS.get(mutation_type)
    if handler is None:
        return _error(
            400,
            f"Unknown mutation_type '{mutation_type}'. "
            f"Allowed: {sorted(_ESCALATION_MUTATION_HANDLERS)}.",
        )
    if not isinstance(payload, dict) or not payload:
        return _error(400, "Field 'payload' is required and must be a non-empty object.")
    if not justification:
        return _error(400, "Field 'justification' is required (free-text rationale for io).")

    target_type, target_sk, target_err = _parse_escalation_target(target_record_id)
    if target_err:
        return _error(400, target_err)

    requested_by_raw = body.get("requested_by")
    requested_by = requested_by_raw if isinstance(requested_by_raw, dict) else {}
    session_id = str(
        requested_by.get("session_id")
        or (body.get("write_source") or {}).get("provider")
        or ""
    ).strip()
    if not session_id:
        return _error(
            400,
            "Field 'requested_by.session_id' is required "
            "(server-minted ENC-SES session id).",
        )
    agent_type_id = str(requested_by.get("agent_type_id") or "").strip()
    sci_present = bool(requested_by.get("sci_present", False))

    validation_error = handler["validate_payload"](payload, target_type)
    if validation_error:
        return _error(400, validation_error)

    # Target must exist — read fresh, never trust the caller's snapshot.
    ddb = _get_ddb()
    try:
        target_item = ddb.get_item(
            TableName=DYNAMODB_TABLE,
            Key={"project_id": _ser_s(project_id), "record_id": _ser_s(target_sk)},
            ConsistentRead=True,
        ).get("Item")
    except Exception as exc:
        logger.error("escalation target read failed: %s", exc)
        return _error(500, "Database read failed while validating target record.")
    if not target_item:
        return _error(404, f"Target record not found: {target_record_id}")

    prefix = _get_project_prefix(project_id)
    if not prefix:
        return _error(404, f"Project '{project_id}' not found or has no prefix.")

    escalation_id = _next_record_id(project_id, prefix, "escalation")
    now = _now_z()
    item = {
        "project_id": _ser_s(project_id),
        "record_id": _ser_s(f"escalation#{escalation_id}"),
        "item_id": _ser_s(escalation_id),
        "record_type": _ser_s("escalation"),
        "target_record_id": _ser_s(target_record_id),
        "target_record_type": _ser_s(target_type),
        "mutation_type": _ser_s(mutation_type),
        "payload": _ser_s(json.dumps(payload, default=str)),
        "justification": _ser_s(justification),
        "requested_by": {"M": {
            "session_id": _ser_s(session_id),
            "agent_type_id": _ser_s(agent_type_id),
            "sci_present": {"BOOL": sci_present},
        }},
        "status": _ser_s("requested"),
        "events": {"L": [_escalation_event(
            "requested",
            session_id,
            detail={"mutation_type": mutation_type, "target_record_id": target_record_id},
        )]},
        "created_at": _ser_s(now),
        "updated_at": _ser_s(now),
        "write_source": _build_write_source(body),
    }
    if expected_version:
        item["expected_version"] = _ser_s(expected_version)

    try:
        ddb.put_item(
            TableName=DYNAMODB_TABLE,
            Item=item,
            ConditionExpression="attribute_not_exists(record_id)",
        )
    except Exception as exc:
        logger.error("escalation put_item failed: %s", exc)
        return _error(500, "Database write failed while creating escalation.")

    # ENC-TSK-J72 (§5.8): push io's email AFTER the durable write; never fails it.
    _notify_escalation_event(
        "requested", escalation_id, target_record_id, mutation_type,
        session_id, note=justification,
    )

    return _response(201, {
        "success": True,
        "escalation_id": escalation_id,
        "status": "requested",
        "target_record_id": target_record_id,
        "target_record_type": target_type,
        "mutation_type": mutation_type,
        "created_at": now,
    })


def _handle_escalation_get(project_id: str, escalation_id: str) -> Dict:
    """GET /{project}/escalation/{id} — full escalation item (§5.4)."""
    if not ENABLE_ESCALATION_PRIMITIVE:
        return _error(503, "Escalation primitive is disabled (enable_escalation_primitive).")
    ddb = _get_ddb()
    try:
        item = ddb.get_item(
            TableName=DYNAMODB_TABLE,
            Key={
                "project_id": _ser_s(project_id),
                "record_id": _ser_s(f"escalation#{escalation_id}"),
            },
            ConsistentRead=True,
        ).get("Item")
    except Exception as exc:
        logger.error("escalation get_item failed: %s", exc)
        return _error(500, "Database read failed.")
    if not item:
        return _error(404, f"Escalation not found: {escalation_id}")
    return _response(200, {"success": True, "escalation": _escalation_public(item)})


def _handle_escalation_list(project_id: str, query_params: Dict) -> Dict:
    """GET /{project}/escalation — list with status/target/session filters (§5.4)."""
    if not ENABLE_ESCALATION_PRIMITIVE:
        return _error(503, "Escalation primitive is disabled (enable_escalation_primitive).")

    status_filter = str(query_params.get("status") or "").strip()
    target_filter = str(query_params.get("target_record_id") or "").strip()
    session_filter = str(query_params.get("session_id") or "").strip()
    if status_filter and status_filter not in _ESCALATION_STATUSES:
        return _error(
            400,
            f"Invalid status filter '{status_filter}'. "
            f"Allowed: {sorted(_ESCALATION_STATUSES)}",
        )
    try:
        page_size = max(1, min(int(query_params.get("page_size", "50")), 200))
    except (TypeError, ValueError):
        page_size = 50

    ddb = _get_ddb()
    key_values = {
        ":pid": _ser_s(project_id),
        ":esc_prefix": _ser_s("escalation#"),
    }
    filter_clauses = []
    expression_names = {}
    if status_filter:
        filter_clauses.append("#st = :status_filter")
        expression_names["#st"] = "status"
        key_values[":status_filter"] = _ser_s(status_filter)
    if target_filter:
        filter_clauses.append("target_record_id = :target_filter")
        key_values[":target_filter"] = _ser_s(target_filter)
    if session_filter:
        filter_clauses.append("requested_by.session_id = :session_filter")
        key_values[":session_filter"] = _ser_s(session_filter)

    kwargs = {
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": (
            "project_id = :pid AND begins_with(record_id, :esc_prefix)"
        ),
        "ExpressionAttributeValues": key_values,
    }
    if filter_clauses:
        kwargs["FilterExpression"] = " AND ".join(filter_clauses)
    if expression_names:
        kwargs["ExpressionAttributeNames"] = expression_names

    escalations = []
    try:
        while True:
            resp = ddb.query(**kwargs)
            escalations.extend(
                _escalation_public(raw) for raw in resp.get("Items", [])
            )
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(escalations) >= page_size:
                break
            kwargs["ExclusiveStartKey"] = last_key
    except Exception as exc:
        logger.error("escalation list query failed: %s", exc)
        return _error(500, "Database query failed.")

    escalations.sort(key=lambda esc: esc.get("created_at", ""), reverse=True)
    escalations = escalations[:page_size]
    return _response(200, {
        "success": True,
        "escalations": escalations,
        "count": len(escalations),
    })


# ---------------------------------------------------------------------------
# ENC-FTR-121 Ph2 / ENC-TSK-J69 — applyEscalatedMutation
#
# The SINGLE privileged code path that may write transitions the normal FSM
# forbids (DOC-5B888FCA43B8 §5.5, Tenet 2). Reachable only through the
# io-approval flow: the apply route no-ops unless the escalation is in
# status=approved with applied_at unset, and status=approved is writable
# ONLY by the Cognito-human approval route (Ph3/ENC-TSK-J70) — no MCP
# action, SCI token, or internal key can approve. Validators in
# _handle_update_field remain untouched and carry no bypass flags.
# ---------------------------------------------------------------------------

EVENT_DETAIL_TYPE_ESCALATION_APPLIED = "record.escalation.applied"


def _escalation_fsm_transition(project_id: str, escalation_id: str,
                               from_status: str, to_status: str, actor: str,
                               detail: Optional[Dict] = None,
                               extra_names: Optional[Dict] = None,
                               extra_values: Optional[Dict] = None,
                               extra_sets: Optional[list] = None,
                               require_not_applied: bool = False) -> bool:
    """Conditionally walk the escalation FSM one edge, appending the §11.2 event.

    Returns False (without raising) when the ConditionExpression loses — the
    concurrent-applier no-op path of the §5.5 idempotency contract.
    """
    if to_status not in _ESCALATION_FSM.get(from_status, set()):
        raise ValueError(f"escalation FSM forbids {from_status}→{to_status}")
    now = _now_z()
    update_parts = [
        "#st = :to_status",
        "updated_at = :now",
        "#ev = list_append(if_not_exists(#ev, :empty), :event)",
    ] + (extra_sets or [])
    names = {"#st": "status", "#ev": "events"}
    names.update(extra_names or {})
    values = {
        ":to_status": _ser_s(to_status),
        ":from_status": _ser_s(from_status),
        ":now": _ser_s(now),
        ":empty": {"L": []},
        ":event": {"L": [_escalation_event(to_status, actor, detail=detail)]},
    }
    values.update(extra_values or {})
    condition = "#st = :from_status"
    if require_not_applied:
        condition += " AND attribute_not_exists(applied_at)"
    try:
        _get_ddb().update_item(
            TableName=DYNAMODB_TABLE,
            Key={
                "project_id": _ser_s(project_id),
                "record_id": _ser_s(f"escalation#{escalation_id}"),
            },
            UpdateExpression="SET " + ", ".join(update_parts),
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _emit_escalation_applied_event(project_id: str, escalation: Dict,
                                   result_detail: Dict) -> None:
    """Best-effort audit-feed emission after a successful application."""
    detail = {
        "project_id": project_id,
        "event": "escalation_applied",
        "escalation_id": escalation.get("item_id"),
        "target_record_id": escalation.get("target_record_id"),
        "mutation_type": escalation.get("mutation_type"),
        "requested_by": (escalation.get("requested_by") or {}).get("session_id"),
        "approved_by": (escalation.get("approved_by") or {}).get("email")
        or (escalation.get("approved_by") or {}).get("sub"),
        "waived_fields": result_detail.get("waived_fields", []),
        "applied_at": _now_z(),
    }
    try:
        _get_events().put_events(Entries=[{
            "Source": EVENT_SOURCE,
            "DetailType": EVENT_DETAIL_TYPE_ESCALATION_APPLIED,
            "Detail": json.dumps(detail, default=str),
            "EventBusName": EVENT_BUS,
        }])
    except Exception as exc:
        logger.error("escalation applied audit event emit failed: %s", exc)


def _handle_escalation_apply(project_id: str, escalation_id: str, body: Dict) -> Dict:
    """POST /{project}/escalation/{id}/apply — applyEscalatedMutation (§5.5).

    Sequence: (1) approved + applied_at-null guard; (2) conditional
    approved→applying transition (the concurrency gate — a losing racer
    no-ops); (3) fresh target read; (4) expected_version drift was surfaced
    at approval time, proceed on io's informed approval; (5) registry handler
    apply — one atomic UpdateItem on the target; (6) provenance is stamped
    inside that same write; (7) applying→applied with applied_at + result.
    On handler exception: applying→failed with the error in result and no
    partial target write.
    """
    if not ENABLE_ESCALATION_PRIMITIVE:
        return _error(503, "Escalation primitive is disabled (enable_escalation_primitive).")

    actor = str((body.get("write_source") or {}).get("provider") or "system")
    ddb = _get_ddb()
    try:
        raw = ddb.get_item(
            TableName=DYNAMODB_TABLE,
            Key={
                "project_id": _ser_s(project_id),
                "record_id": _ser_s(f"escalation#{escalation_id}"),
            },
            ConsistentRead=True,
        ).get("Item")
    except Exception as exc:
        logger.error("escalation apply read failed: %s", exc)
        return _error(500, "Database read failed.")
    if not raw:
        return _error(404, f"Escalation not found: {escalation_id}")

    escalation = _escalation_public(raw)
    status = escalation.get("status")
    if escalation.get("applied_at") or status == "applied":
        return _response(200, {
            "success": True, "no_op": True, "escalation_id": escalation_id,
            "status": "applied",
            "reason": "applied_at already set — exactly-once guard (§5.5 step 1)",
        })
    if status != "approved":
        return _error(409, (
            f"Escalation {escalation_id} is '{status}', not 'approved'. "
            "Only the Cognito-human approval flow can authorize application."
        ))

    handler = _ESCALATION_MUTATION_HANDLERS.get(str(escalation.get("mutation_type")))
    if handler is None or "apply" not in handler:
        return _error(500, f"No apply handler for mutation_type '{escalation.get('mutation_type')}'.")

    # Concurrency gate: exactly one applier wins approved→applying.
    if not _escalation_fsm_transition(
        project_id, escalation_id, "approved", "applying", actor,
        detail={"target_record_id": escalation.get("target_record_id")},
        require_not_applied=True,
    ):
        return _response(200, {
            "success": True, "no_op": True, "escalation_id": escalation_id,
            "reason": "concurrent applier holds the applying transition",
        })

    now = _now_z()
    target_type, target_sk, target_err = _parse_escalation_target(
        str(escalation.get("target_record_id") or ""))
    result_detail = None
    failure = ""
    if target_err:
        failure = target_err
    else:
        try:
            target_raw = ddb.get_item(
                TableName=DYNAMODB_TABLE,
                Key={"project_id": _ser_s(project_id), "record_id": _ser_s(target_sk)},
                ConsistentRead=True,
            ).get("Item")
            if not target_raw:
                failure = f"Target record not found: {escalation.get('target_record_id')}"
            else:
                result_detail = handler["apply"](project_id, escalation, _deser_item(target_raw))
        except Exception as exc:
            logger.error("escalation apply handler failed: %s", exc)
            failure = f"{type(exc).__name__}: {exc}"

    if failure:
        _escalation_fsm_transition(
            project_id, escalation_id, "applying", "failed", "system",
            detail={"error": failure},
            extra_sets=["#res = :result"],
            extra_names={"#res": "result"},
            extra_values={":result": _ser_value({"success": False, "error": failure})},
        )
        # ENC-TSK-J72 (§5.8 optional terminal notification): closure telemetry
        # for io without opening the PWA; same failure-isolation contract.
        _notify_escalation_event(
            "failed", escalation_id,
            str(escalation.get("target_record_id") or ""),
            str(escalation.get("mutation_type") or ""),
            str((escalation.get("requested_by") or {}).get("session_id") or ""),
            note=failure,
        )
        return _error(409, f"Escalation application failed (no partial write): {failure}")

    _escalation_fsm_transition(
        project_id, escalation_id, "applying", "applied", "system",
        detail=result_detail,
        extra_sets=["applied_at = :applied_at", "#res = :result"],
        extra_names={"#res": "result"},
        extra_values={
            ":applied_at": _ser_s(now),
            ":result": _ser_value({"success": True, **(result_detail or {})}),
        },
    )
    _emit_escalation_applied_event(project_id, escalation, result_detail or {})
    # ENC-TSK-J72 (§5.8 optional terminal notification): applied closure telemetry.
    _notify_escalation_event(
        "applied", escalation_id,
        str(escalation.get("target_record_id") or ""),
        str(escalation.get("mutation_type") or ""),
        str((escalation.get("requested_by") or {}).get("session_id") or ""),
        note=json.dumps(result_detail or {}, default=str)[:300],
    )
    return _response(200, {
        "success": True,
        "escalation_id": escalation_id,
        "status": "applied",
        "applied_at": now,
        "result": result_detail,
    })


# ---------------------------------------------------------------------------
# Path parsing & routing
# ---------------------------------------------------------------------------

# Route patterns — order matters (most specific first)
_RE_PENDING_UPDATES = re.compile(r"^(?:/api/v1/tracker)?/pending-updates$")
_RE_DEDUP_REVIEW = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/dedup-review$"
)
_RE_ESCALATION = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)/escalation"
    r"(?:/(?P<id>[A-Za-z0-9_-]+)(?:/(?P<sub>apply))?)?$"
)
_RE_RELATIONSHIP = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)/relationship$"
)
_RE_RECORD_SUB = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan|generation)/(?P<id>[A-Za-z0-9_-]+)/(?P<sub>log|checkout|acceptance-evidence|extend)$"
)
_RE_RECORD = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan|generation)/(?P<id>[A-Za-z0-9_-]+)$"
)
_RE_TYPE_COLLECTION = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan|generation)$"
)
_RE_PROJECT = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-zA-Z0-9_-]+)$"
)


def lambda_handler(event: Dict, context: Any) -> Dict:
    method = (
        (event.get("requestContext") or {}).get("http", {}).get("method")
        or event.get("httpMethod", "")
    )
    path = event.get("rawPath") or event.get("path", "")
    query_params = event.get("queryStringParameters") or {}

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    # --- Route: GET /pending-updates ---
    if method == "GET" and _RE_PENDING_UPDATES.match(path):
        claims, auth_err = _authenticate(event, ["tracker:read"])
        if auth_err:
            return auth_err
        return _handle_pending_updates(query_params)

    # --- Route: dedup tier-review surface (ENC-TSK-I08) ---
    m_dedup = _RE_DEDUP_REVIEW.match(path)
    if m_dedup:
        project_id = m_dedup.group("project")
        if method != "POST":
            return _error(405, "Method not allowed on /dedup-review. Use POST with op=propose|approve.")
        try:
            body = json.loads(event.get("body") or "{}")
        except (ValueError, TypeError):
            return _error(400, "Invalid JSON body.")
        op = str(body.get("op", "")).strip().lower()
        # propose is mutation-free (read scope); approve and auto-merge write (write
        # scope). approve is additionally io-Cognito-gated inside _handle_dedup_approve;
        # auto-merge (ENC-TSK-I09) is MECHANICAL — gated by flag + kill switch + per-pair
        # certificate, not by an io session.
        scopes = ["tracker:write"] if op in ("approve", "auto-merge") else ["tracker:read"]
        claims, auth_err = _authenticate(event, scopes)
        if auth_err:
            return auth_err
        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)
        _normalize_write_source(body, claims)
        if op == "propose":
            return _handle_dedup_propose(project_id, body)
        elif op == "approve":
            return _handle_dedup_approve(project_id, body, claims)
        elif op == "auto-merge":
            return _handle_dedup_auto_merge(project_id, body, claims)
        else:
            return _error(400, "Field 'op' must be 'propose', 'approve', or 'auto-merge'.")

    # --- Route: escalations (ENC-FTR-121 Ph1+Ph2 / ENC-TSK-J68, ENC-TSK-J69) ---
    m_escalation = _RE_ESCALATION.match(path)
    if m_escalation:
        project_id = m_escalation.group("project")
        escalation_id = m_escalation.group("id")
        escalation_sub = m_escalation.group("sub")
        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err
        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)
        if method == "POST" and escalation_sub == "apply":
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_escalation_apply(project_id, escalation_id, body)
        elif method == "POST" and not escalation_id:
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_escalation_request(project_id, body)
        elif method == "GET" and escalation_id == "list":
            # Pseudo-id alias: gamma APIGW registers {recordType}/{recordId}
            # but not the bare {recordType} collection path, so the list
            # surface rides GET /{project}/escalation/list (ENC-TSK-J69;
            # found during ENC-TSK-J68 gamma validation). "list" can never
            # collide with a server-minted ENC-ESC-* id.
            return _handle_escalation_list(project_id, query_params)
        elif method == "GET" and escalation_id:
            return _handle_escalation_get(project_id, escalation_id)
        elif method == "GET":
            return _handle_escalation_list(project_id, query_params)
        return _error(405, f"Method {method} not allowed on /escalation.")

    # --- Route: typed relationship edges (ENC-FTR-049) ---
    m_rel = _RE_RELATIONSHIP.match(path)
    if m_rel:
        project_id = m_rel.group("project")
        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err
        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)
        try:
            body = json.loads(event.get("body") or "{}")
        except (ValueError, TypeError):
            body = {}
        _normalize_write_source(body, claims)
        if method == "POST":
            return _handle_create_relationship(project_id, body)
        elif method == "DELETE":
            return _handle_archive_relationship(project_id, query_params)
        elif method == "GET":
            return _handle_list_relationships(project_id, query_params)
        else:
            return _error(405, f"Method {method} not allowed on /relationship.")

    # --- Route: sub-resource operations (log, checkout, acceptance-evidence) ---
    m_sub = _RE_RECORD_SUB.match(path)
    if m_sub:
        project_id = m_sub.group("project")
        record_type = m_sub.group("type")
        record_id = m_sub.group("id")
        sub = m_sub.group("sub")

        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        try:
            body = json.loads(event.get("body") or "{}")
        except (ValueError, TypeError):
            body = {}
        _normalize_write_source(body, claims)

        if sub == "log" and method == "POST":
            return _handle_log(project_id, record_type, record_id, body, event=event)
        elif sub == "extend" and method == "POST" and record_type == "lesson":
            return _handle_lesson_extend(project_id, record_id, body)
        elif sub == "checkout" and method == "POST":
            return _handle_checkout(project_id, record_type, record_id, body, event=event)
        elif sub == "checkout" and method == "DELETE":
            return _handle_release(project_id, record_type, record_id, body, event=event)
        elif sub == "acceptance-evidence" and method == "POST":
            return _handle_acceptance_evidence(project_id, record_type, record_id, body)
        else:
            return _error(405, f"Method {method} not allowed on /{sub}.")

    # --- Route: single record (GET, PATCH) ---
    m_record = _RE_RECORD.match(path)
    if m_record:
        project_id = m_record.group("project")
        record_type = m_record.group("type")
        record_id = m_record.group("id")

        claims, auth_err = _authenticate(
            event,
            ["tracker:read"] if method == "GET" else ["tracker:write"],
        )
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        if method == "GET":
            return _handle_get_record(project_id, record_type, record_id)
        elif method == "PATCH":
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_update_field(project_id, record_type, record_id, body, event=event, claims=claims)
        else:
            return _error(405, f"Method {method} not allowed. Use GET or PATCH.")

    # --- Route: type collection (POST = create) ---
    m_type = _RE_TYPE_COLLECTION.match(path)
    if m_type:
        project_id = m_type.group("project")
        record_type = m_type.group("type")

        claims, auth_err = _authenticate(event, ["tracker:write"])
        if auth_err:
            return auth_err

        project_err = _validate_project_exists(project_id)
        if project_err:
            return _error(404, project_err)

        if method == "POST":
            try:
                body = json.loads(event.get("body") or "{}")
            except (ValueError, TypeError):
                return _error(400, "Invalid JSON body.")
            _normalize_write_source(body, claims)
            return _handle_create_record(project_id, record_type, body, event=event)
        else:
            return _error(405, f"Method {method} not allowed. Use POST to create.")

    # --- Route: project listing (GET) ---
    m_project = _RE_PROJECT.match(path)
    if m_project:
        project_id = m_project.group("project")

        # Don't require auth for listing? Actually yes, require it.
        claims, auth_err = _authenticate(event, ["tracker:read"])
        if auth_err:
            return auth_err

        if method == "GET":
            return _handle_list_records(project_id, query_params)
        else:
            return _error(405, f"Method {method} not allowed. Use GET to list.")

    return _error(404, f"No route matched: {method} {path}")
