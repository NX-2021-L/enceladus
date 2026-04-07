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
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request
from urllib.parse import unquote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from transition_type_matrix import (
    MATRIX_VERSION,
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
except ImportError:
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
MAX_NOTE_LENGTH = 2000
# ENC-FTR-052: Governed Lesson Primitive — feature flag
ENABLE_LESSON_PRIMITIVE = os.environ.get("ENABLE_LESSON_PRIMITIVE", "false").lower() == "true"

# Valid record types and their closed/default statuses
_RECORD_TYPES = {"task", "issue", "feature", "lesson", "plan"}
_CLOSED_STATUS = {"task": "closed", "issue": "closed", "feature": "completed", "lesson": "archived", "plan": "complete"}
_DEFAULT_STATUS = {"task": "open", "issue": "open", "feature": "planned", "lesson": "draft", "plan": "drafted"}
_TRACKER_TYPE_SUFFIX = {"task": "TSK", "issue": "ISS", "feature": "FTR", "lesson": "LSN", "plan": "PLN"}
_ID_SEGMENT_TO_TYPE = {"TSK": "task", "ISS": "issue", "FTR": "feature", "LSN": "lesson", "PLN": "plan"}

# Category validation per record type
_VALID_CATEGORIES = {
    "feature": {"epic", "capability", "enhancement", "infrastructure"},
    "task": {"implementation", "investigation", "documentation", "maintenance", "validation"},
    "issue": {"bug", "debt", "risk", "security", "performance"},
    "lesson": {"pattern", "failure_mode", "resolution_pathway", "opportunity", "principle", "intention"},
    "plan": {"strategic", "tactical", "operational", "remediation"},
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
            governed_rules=["pillar_scores is required on lesson creation (ENC-FTR-054)."],
        )
    missing = _REQUIRED_PILLARS - set(raw_pillar_scores.keys())
    if missing:
        return None, _tracker_create_validation_error(
            f"pillar_scores missing required keys: {sorted(missing)}. All four pillars are required.",
            record_type=record_type,
            governed_rules=["pillar_scores must include: efficiency, human_protection, intention, alignment."],
        )
    parsed = {}
    for pillar in _REQUIRED_PILLARS:
        try:
            val = float(raw_pillar_scores[pillar])
        except (TypeError, ValueError):
            return None, _tracker_create_validation_error(
                f"pillar_scores.{pillar} must be a number in [0.0, 1.0]. Got: {raw_pillar_scores[pillar]!r}",
                record_type=record_type,
                governed_rules=[f"pillar_scores.{pillar} must be numeric in [0.0, 1.0]."],
            )
        if val < 0.0 or val > 1.0:
            return None, _tracker_create_validation_error(
                f"pillar_scores.{pillar} = {val} is out of range [0.0, 1.0].",
                record_type=record_type,
                governed_rules=[f"pillar_scores.{pillar} must be in [0.0, 1.0]."],
            )
        parsed[pillar] = val
    if all(v == 0.0 for v in parsed.values()):
        return None, _tracker_create_validation_error(
            "All pillar_scores are zero. At least one pillar must be > 0 for constitutional evaluation.",
            record_type=record_type,
            governed_rules=["At least one pillar score must be > 0 (ENC-FTR-054 AC1)."],
        )
    return parsed, None


# EventBridge event config for reopen notifications
EVENT_BUS = os.environ.get("EVENT_BUS", "default")
EVENT_SOURCE = "enceladus.tracker"
EVENT_DETAIL_TYPE_REOPENED = "record.status.reopened"

# Type segment mapping for SK construction
_TYPE_SEG_TO_SK_PREFIX = {"task": "task", "issue": "issue", "feature": "feature", "lesson": "lesson", "plan": "plan"}

# Counter management
_TRACKER_COUNTER_PREFIX = "counter#"
_TRACKER_CREATE_MAX_ATTEMPTS = 32

# Relation fields
_RELATION_ID_FIELDS = {"related_task_ids", "related_issue_ids", "related_feature_ids"}

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


def _get_events():
    global _events_client
    if _events_client is None:
        _events_client = boto3.client("events")
    return _events_client


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
# Route handlers
# ---------------------------------------------------------------------------

def _handle_get_record(project_id: str, record_type: str, record_id: str) -> Dict:
    """GET /{project}/{type}/{id} — return full deserialized record."""
    try:
        item = _get_record_full(project_id, record_type, record_id)
    except Exception as exc:
        logger.error("get_item failed: %s", exc)
        return _error(500, "Database read failed.")

    if item is None:
        return _error(404, f"Record not found: {record_id}")

    return _response(200, {"success": True, "record": item})


def _handle_list_records(project_id: str, query_params: Dict) -> Dict:
    """GET /{project} — list records with optional type/status filters."""
    ddb = _get_ddb()
    record_type = query_params.get("type", "")
    status_filter = query_params.get("status", "")

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
            }
            if status_filter:
                kwargs["FilterExpression"] = "#st = :st"
                kwargs["ExpressionAttributeNames"] = {"#st": "status"}
                kwargs["ExpressionAttributeValues"][":st"] = _ser_s(status_filter)

            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                last_key = resp.get("LastEvaluatedKey")
                if not last_key:
                    break
                kwargs["ExclusiveStartKey"] = last_key
        else:
            # Query all records for project
            kwargs = {
                "TableName": DYNAMODB_TABLE,
                "KeyConditionExpression": "project_id = :pid",
                "ExpressionAttributeValues": {":pid": _ser_s(project_id)},
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

            items = []
            while True:
                resp = ddb.query(**kwargs)
                items.extend(resp.get("Items", []))
                last_key = resp.get("LastEvaluatedKey")
                if not last_key:
                    break
                kwargs["ExclusiveStartKey"] = last_key

        # Deserialize and filter out counter records
        records = []
        for raw in items:
            item = _deser_item(raw)
            if item.get("record_type") == "counter":
                continue
            records.append(item)

        return _response(200, {"success": True, "records": records, "count": len(records)})

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


def _handle_create_record(project_id: str, record_type: str, body: Dict) -> Dict:
    """POST /{project}/{type} — create a new tracker record."""
    title = body.get("title", "").strip()
    if not title:
        return _tracker_create_validation_error(
            "Field 'title' is required.",
            record_type=record_type,
            missing_required_fields=["title"],
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

    # Acceptance criteria normalization
    raw_ac = body.get("acceptance_criteria")
    acceptance_criteria: List[str] = []
    if isinstance(raw_ac, str):
        stripped = raw_ac.strip()
        if stripped:
            acceptance_criteria = [stripped]
    elif isinstance(raw_ac, list):
        acceptance_criteria = [str(x).strip() for x in raw_ac if str(x).strip()]

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
                governed_rules=["evidence_chain must contain at least one tracker record ID."],
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
            # ENC-FTR-048: features and tasks both use structured AC with evidence tracking
            ac_items = [{"M": {
                "description": _ser_s(ac), "evidence": _ser_s(""),
                "evidence_acceptance": {"BOOL": False},
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
    # ENC-FTR-052: Lesson-specific fields
    if record_type == "lesson":
        item["observation"] = _ser_s(observation)
        item["insight"] = _ser_s(insight)
        item["evidence_chain"] = {"L": [_ser_s(eid.strip()) for eid in evidence_chain]}
        item["provenance"] = _ser_s(provenance)
        item["confidence"] = {"N": str(body.get("confidence", 0.5))}
        # ENC-FTR-054: Compute constitutional scores server-side
        pillar_composite = _compute_lesson_pillar_composite(parsed_pillar_scores)
        resonance_score = _compute_resonance_score(parsed_pillar_scores)
        item["pillar_scores"] = {"M": {k: {"N": str(v)} for k, v in parsed_pillar_scores.items()}}
        item["resonance_score"] = {"N": str(resonance_score)}
        item["pillar_composite"] = {"N": str(pillar_composite)}
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

    # ENC-ISS-132: Reject externally-provided record IDs — IDs are server-generated only
    for forbidden_field in ("item_id", "record_id"):
        if body.get(forbidden_field):
            return _error(400, f"Field '{forbidden_field}' must not be provided — record IDs are generated server-side.")

    # Create with counter-based ID allocation (or hierarchical sub-task ID)
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

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=(
                "SET #fld = :val, updated_at = :now, last_update_note = :note, "
                "transition_evidence = :te, "
                "sync_version = if_not_exists(sync_version, :zero) + :one, "
                "history = list_append(if_not_exists(history, :empty), :hentry)"
            ),
            ExpressionAttributeNames={"#fld": "status"},
            ExpressionAttributeValues={
                ":val": _ser_value(new_lower), ":now": _ser_s(now),
                ":note": _ser_s(note_text), ":te": _ser_s(evidence_json),
                ":zero": {"N": "0"}, ":one": {"N": "1"},
                ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
            },
        )
    except Exception as exc:
        logger.error("user_initiated status update failed: %s", exc)
        return _error(500, "Database write failed.")

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

    field = body.get("field", "").strip()
    value = body.get("value", "")
    if not field:
        return _tracker_field_validation_error(
            "Field 'field' is required (or use 'action' for PWA mutations).",
            field="field",
            record_id=record_id,
            record_type=record_type,
            expected_type="string",
            expected_format="single field name",
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
        current_status = (item_data.get("status", "") or "").strip().lower()
        has_been_checked_out = bool(item_data.get("checked_out_at"))
        existing_subtask_ids = set()
        for st in item_data.get("subtask_ids", {}).get("L", []):
            existing_subtask_ids.add(st.get("S", ""))
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
        if current_status != new_lower:
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
                    governed_rules=[
                        f"valid revert targets require transition_evidence.revert_reason: {sorted(revert_targets)}",
                    ],
                )

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

        if not is_revert and record_type == "task" and new_lower == "merged-main" \
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

        if not is_revert and record_type == "task" and new_lower == "deploy-success":
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

        if not is_revert and record_type == "task" and new_lower == "closed" and current_status == "deploy-success":
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
            try:
                ddb.update_item(
                    TableName=DYNAMODB_TABLE, Key=key,
                    UpdateExpression=(
                        "SET active_agent_session = :t, active_agent_session_id = :aid, "
                        "checkout_state = :checked_out, checked_out_by = :aid, checked_out_at = :now, "
                        "updated_at = :now, last_update_note = :note, write_source = :wsrc, "
                        "sync_version = if_not_exists(sync_version, :zero) + :one, "
                        "history = list_append(if_not_exists(history, :empty), :hentry)"
                    ),
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

    update_expr = (
        "SET #fld = :val, updated_at = :now, last_update_note = :note, "
        "write_source = :wsrc, "
        "sync_version = if_not_exists(sync_version, :zero) + :one, "
        "history = list_append(if_not_exists(history, :empty), :hentry)"
    )
    if extra_sets:
        update_expr += ", " + ", ".join(extra_sets)

    attr_values = {
        ":val": _ser_value(value), ":now": _ser_s(now),
        ":note": _ser_s(note_text), ":wsrc": _build_write_source(body),
        ":zero": {"N": "0"}, ":one": {"N": "1"},
        ":hentry": {"L": [history_entry]}, ":empty": {"L": []},
    }
    attr_values.update(extra_vals)

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#fld": field},
            ExpressionAttributeValues=attr_values,
        )
    except Exception as exc:
        logger.error("update_item failed: %s", exc)
        return _error(500, "Database write failed.")

    result: Dict[str, Any] = {
        "success": True, "record_id": record_id,
        "field": field, "value": value, "updated_at": now,
    }
    if warnings:
        result["warnings"] = warnings
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
            ddb.update_item(
                TableName=DYNAMODB_TABLE, Key=key,
                UpdateExpression=(
                    "SET #status = :status, updated_at = :ts, last_update_note = :note, "
                    "sync_version = sync_version + :one, "
                    "#history = list_append(#history, :entry)"
                ),
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


def _handle_log(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/log — append worklog entry to history."""
    description = body.get("description", "").strip()
    if not description:
        return _error(400, "Field 'description' is required.")
    _normalize_write_source(body)

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

    # ENC-FTR-054: Recompute scores if pillar_scores updated
    if updated_pillar_scores:
        new_composite = _compute_lesson_pillar_composite(updated_pillar_scores)
        new_resonance = _compute_resonance_score(updated_pillar_scores)
        update_parts.append("pillar_scores = :ps")
        update_parts.append("resonance_score = :rs")
        update_parts.append("pillar_composite = :pc")
        expr_values[":ps"] = {"M": {k: {"N": str(v)} for k, v in updated_pillar_scores.items()}}
        expr_values[":rs"] = {"N": str(new_resonance)}
        expr_values[":pc"] = {"N": str(new_composite)}

    try:
        ddb.update_item(
            TableName=DYNAMODB_TABLE, Key=key,
            UpdateExpression=", ".join(update_parts),
            ExpressionAttributeValues=expr_values,
        )
    except Exception as exc:
        logger.error("update_item (lesson extend) failed: %s", exc)
        return _error(500, "Database write failed.")

    return _response(200, {
        "success": True, "record_id": record_id, "updated_at": now,
        "evidence_ids_appended": len(new_evidence_ids) if new_evidence_ids else 0,
    })


def _handle_checkout(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """POST /{project}/{type}/{id}/checkout — session checkout."""
    body["field"] = "active_agent_session"
    body["value"] = True
    return _handle_update_field(project_id, record_type, record_id, body)


def _handle_release(project_id: str, record_type: str, record_id: str, body: Dict) -> Dict:
    """DELETE /{project}/{type}/{id}/checkout — session release."""
    body["field"] = "active_agent_session"
    body["value"] = False
    return _handle_update_field(project_id, record_type, record_id, body)


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
        ddb.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": DYNAMODB_TABLE,
                        "Item": forward_item,
                        "ConditionExpression": "attribute_not_exists(record_id)",
                    }
                },
                {
                    "Put": {
                        "TableName": DYNAMODB_TABLE,
                        "Item": inverse_item,
                        "ConditionExpression": "attribute_not_exists(record_id)",
                    }
                },
            ]
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

    return _response(201, {
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
    })


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
        ddb.transact_write_items(
            TransactItems=[
                {
                    "Update": {
                        "TableName": DYNAMODB_TABLE,
                        "Key": {"project_id": _ser_s(project_id), "record_id": _ser_s(forward_sk)},
                        "UpdateExpression": "SET #st = :archived, archived_at = :now",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {
                            ":archived": _ser_s("archived"),
                            ":now": _ser_s(now),
                        },
                        "ConditionExpression": "attribute_exists(record_id)",
                    }
                },
                {
                    "Update": {
                        "TableName": DYNAMODB_TABLE,
                        "Key": {"project_id": _ser_s(project_id), "record_id": _ser_s(inverse_sk)},
                        "UpdateExpression": "SET #st = :archived, archived_at = :now",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {
                            ":archived": _ser_s("archived"),
                            ":now": _ser_s(now),
                        },
                        "ConditionExpression": "attribute_exists(record_id)",
                    }
                },
            ]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "TransactionCanceledException":
            return _error(404, f"Relationship not found: {relationship_type} "
                          f"from {source_id} to {target_id}.")
        raise

    return _response(200, {
        "success": True,
        "archived_forward": forward_sk,
        "archived_inverse": inverse_sk,
        "archived_at": now,
    })


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
        "TableName": DYNAMODB_TABLE,
        "KeyConditionExpression": "project_id = :pid AND begins_with(record_id, :prefix)",
        "ExpressionAttributeValues": {
            ":pid": _ser_s(project_id),
            ":prefix": _ser_s(sk_prefix),
        },
        "Limit": page_size,
    }

    cursor = query_params.get("cursor", "")
    if cursor:
        try:
            import base64
            decoded = json.loads(base64.b64decode(cursor))
            kwargs["ExclusiveStartKey"] = decoded
        except Exception:
            pass

    resp = ddb.query(**kwargs)
    items = resp.get("Items", [])

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

    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        import base64
        response_body["next_cursor"] = base64.b64encode(
            json.dumps(last_key, default=str).encode()
        ).decode()

    return _response(200, response_body)


# ---------------------------------------------------------------------------
# Path parsing & routing
# ---------------------------------------------------------------------------

# Route patterns — order matters (most specific first)
_RE_PENDING_UPDATES = re.compile(r"^(?:/api/v1/tracker)?/pending-updates$")
_RE_RELATIONSHIP = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/relationship$"
)
_RE_RECORD_SUB = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan)/(?P<id>[A-Za-z0-9_-]+)/(?P<sub>log|checkout|acceptance-evidence|extend)$"
)
_RE_RECORD = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan)/(?P<id>[A-Za-z0-9_-]+)$"
)
_RE_TYPE_COLLECTION = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)/(?P<type>task|issue|feature|lesson|plan)$"
)
_RE_PROJECT = re.compile(
    r"^(?:/api/v1/tracker)?/(?P<project>[a-z0-9_-]+)$"
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
            return _handle_log(project_id, record_type, record_id, body)
        elif sub == "extend" and method == "POST" and record_type == "lesson":
            return _handle_lesson_extend(project_id, record_id, body)
        elif sub == "checkout" and method == "POST":
            return _handle_checkout(project_id, record_type, record_id, body)
        elif sub == "checkout" and method == "DELETE":
            return _handle_release(project_id, record_type, record_id, body)
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
            return _handle_create_record(project_id, record_type, body)
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
