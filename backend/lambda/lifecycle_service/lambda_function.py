"""lifecycle_service/lambda_function.py — Enceladus Lifecycle Service (B63 Phase 2A / ENC-TSK-H46)

Extracts status-transition lifecycle VALIDATION out of the tracker_mutation monolith into a
standalone, synchronously-invoked Lambda. The service is the authoritative owner of:

  1. transition_type_matrix validation — allowed target statuses per transition_type, forward +
     revert transition validity, and per-gate evidence PRESENCE / SHAPE checks (pure functions).
  2. STRICTNESS_RANK enforcement      — the most-restrictive required_transition_type across a
     task's components (read from the component-registry), ENC-FTR-041 / ENC-TSK-F50.
  3. subtask gates                    — ENC-ISS-106: a parent task may not advance to
     coding-complete+ until every child has reached at least that stage.
  4. gate_class taxonomy              — ENC-FTR-111 scaffold (born-inside, consumed by the
     Universal Arc-Walker; this service does NOT implement the walker).
  5. deploy-init auto-walk gating     — ENC-TSK-H84 / ENC-FTR-111 AC-5: the `evaluate_auto_walk`
     action reads the project's deploy_policy (projects table) and applies ruling O-2 — deploy-init
     is auto-walkable only on ci_triggered projects. The walker (FTR-111) consumes this verdict;
     this service owns the read + the policy decision, not the walk loop itself.

Scope boundary (ENC-TSK-H46, io-confirmed tracker_mutation-only):
  - EXTERNAL verifications that hit third-party APIs (the `committed` GitHub commit-exists check
    and the `code_only|closed` GitHub ancestor-of-main compare) are EXTERNAL-FACT verifications,
    not part of the three responsibilities above. They remain in tracker_mutation, so this service
    stays a pure DynamoDB-only validator with no GitHub credentials.
  - checkout_service still owns its own copy of these gates; wiring checkout_service to call this
    service is a tracked follow-on. This service is BUILT as the complete owner so that follow-on
    is a pure call-site change.

Invocation: direct Lambda invoke (RequestResponse) from tracker_mutation. The event IS the request
dict (no API Gateway envelope). Returns a verdict dict: {allow, error, gate_class, matrix_version}.

Environment variables:
  DYNAMODB_TABLE     default: devops-project-tracker  (tracker records — children for subtask gate)
  COMPONENTS_TABLE   default: component-registry       (required_transition_type + lifecycle_status)
  DYNAMODB_REGION    default: us-west-2
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config

# ENC-TSK-H28 / ENC-LSN-053 resilience: import the AppConfig flag helper defensively so a function
# still on an older shared layer degrades to env-var fallback instead of ImportError-bricking at load.
try:
    from enceladus_shared.appconfig_flags import flag as _appconfig_flag
except ImportError:
    def _appconfig_flag(name, *, env_fallback=None, default=False):
        raw = os.environ.get(env_fallback, "") if env_fallback else ""
        return raw.strip().lower() == "true" if raw != "" else bool(default)

from transition_type_matrix import (
    MATRIX_VERSION,
    STRICTNESS_RANK,
    VALID_TRANSITION_TYPES,
    get_gate_class,
    is_auto_walkable_class,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

LIFECYCLE_SERVICE_VERSION = "1.0.0"  # ENC-TSK-H46

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DYNAMODB_TABLE = os.environ.get("DYNAMODB_TABLE", "devops-project-tracker")
DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
COMPONENTS_TABLE = os.environ.get("COMPONENTS_TABLE", "component-registry")
# ENC-TSK-H84 / ENC-FTR-111: the projects table carries the per-project deploy_policy the
# Universal Arc-Walker reads to gate deploy-init auto-walk (ruling O-2).
PROJECTS_TABLE = os.environ.get("PROJECTS_TABLE", "projects")

# ENC-TSK-H84 / ENC-FTR-111 AC-5 — project deploy_policy enum (mirrors the project_service +
# governance-dictionary contract). ci_triggered: deploys are kicked off by CI on merge, so the
# system can mechanically auto-walk deploy-init. manual: a human/external actor triggers the
# deploy, so the walker must NOT auto-advance deploy-init. Existing/absent values read as the
# ci_triggered default (the seeded baseline — see project_service + tools/seed_deploy_policy.py).
DEPLOY_POLICY_CI_TRIGGERED = "ci_triggered"
DEPLOY_POLICY_MANUAL = "manual"
VALID_DEPLOY_POLICIES = frozenset({DEPLOY_POLICY_CI_TRIGGERED, DEPLOY_POLICY_MANUAL})
DEFAULT_DEPLOY_POLICY = DEPLOY_POLICY_CI_TRIGGERED

_ddb_client = None


def _ddb():
    global _ddb_client
    if _ddb_client is None:
        _ddb_client = boto3.client(
            "dynamodb",
            region_name=DYNAMODB_REGION,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )
    return _ddb_client


# ---------------------------------------------------------------------------
# Transition maps — mirror of tracker_mutation (ENC-FTR-022 / ENC-FTR-035).
# Kept in sync with tracker_mutation/lambda_function.py:_VALID_TRANSITIONS.
# ---------------------------------------------------------------------------
_VALID_TRANSITIONS: Dict[str, Dict[str, set]] = {
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
        "merged-main": {"deploy-init"},
        "deploy-init": {"deploy-success"},
        "deploy-success": {"closed", "coding-updates"},
        "coding-updates": {"coding-complete"},
        "deployed": {"deploy-success"},  # ENC-TSK-704 legacy migration arc
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

_REVERT_TRANSITIONS: Dict[str, Dict[str, set]] = {
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

# ENC-ISS-106 subtask gate — mirror of checkout_service STATUS_RANK / _SUBTASK_GATE_MIN_RANK.
STATUS_RANK: Dict[str, int] = {
    "open": 0,
    "in-progress": 1,
    "coding-complete": 2,
    "committed": 3,
    "pr": 4,
    "merged-main": 5,
    "deploy-init": 6,
    "deploy-success": 7,
    "closed": 8,
    # ENC-TSK-I07 (Dedup P3): `superseded` alternate terminal (mirror of
    # checkout_service STATUS_RANK). Same rank as `closed`.
    "superseded": 8,
}
_SUBTASK_GATE_MIN_RANK: int = STATUS_RANK["coding-complete"]  # 2

_DEPLOY_EVIDENCE_REQUIRED_FIELDS = (
    "id", "name", "run_id", "head_sha", "status", "conclusion", "started_at", "completed_at",
)

# F42 / ENC-FTR-076 §7 opacity model — mirror of checkout_service.
_OPAQUE_LIFECYCLE_STATUSES = frozenset({"archived"})
_BLOCKED_LIFECYCLE_STATUSES = frozenset({"proposed", "deprecated"})


# ---------------------------------------------------------------------------
# Evidence validators — verbatim parity with tracker_mutation (ENC-FTR-059).
# Pure functions: shape/presence only, no external calls.
# ---------------------------------------------------------------------------
def _is_valid_iso8601(value: str) -> bool:
    """ISO 8601 datetime with a 'T' separator (date-only strings rejected)."""
    if not value or "T" not in value:
        return False
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except (ValueError, AttributeError):
        return False


def _validate_deploy_evidence(deploy_evidence) -> Optional[str]:
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
    # ENC-ISS-162: auto-detect simplified (lowercase) vs full AWS (PascalCase).
    if lambda_deploy_evidence.get("function_name") or not lambda_deploy_evidence.get("FunctionArn"):
        return _validate_lambda_deploy_evidence_simplified(lambda_deploy_evidence)
    return _validate_lambda_deploy_evidence_full(lambda_deploy_evidence)


def _validate_lambda_deploy_evidence_simplified(evidence: dict) -> Optional[str]:
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


# ---------------------------------------------------------------------------
# STRICTNESS_RANK component enforcement — parity with checkout_service
# (_get_required_transition_type / _get_components_lifecycle, ENC-FTR-041 / F50).
# ---------------------------------------------------------------------------
class ComponentMisconfiguredError(Exception):
    """Component record missing/invalid required_transition_type (F50/AC-3, no silent default)."""

    def __init__(self, component_id: str, *, reason: str = "missing", bad_value: Optional[str] = None) -> None:
        self.component_id = component_id
        self.reason = reason
        self.bad_value = bad_value
        if reason == "invalid_value":
            message = (
                f"Component '{component_id}' has invalid required_transition_type="
                f"'{bad_value}'; this is an invariant violation. Contact platform admin."
            )
        else:
            message = (
                f"Component '{component_id}' is missing required_transition_type; "
                "this is an invariant violation. Contact platform admin."
            )
        super().__init__(message)


def _get_required_transition_type(component_ids: list) -> Optional[str]:
    """Most-restrictive required_transition_type across components, or None if empty.
    Fail-loud (ComponentMisconfiguredError) on missing/invalid; fail-open WARN on unknown id."""
    if not component_ids:
        return None
    min_rank = 99
    required: Optional[str] = None
    for cid in component_ids:
        try:
            resp = _ddb().get_item(
                TableName=COMPONENTS_TABLE,
                Key={"component_id": {"S": str(cid)}},
            )
            item = resp.get("Item")
            if not item:
                logger.warning("[FTR-041] Component '%s' not found in registry; skipping enforcement", cid)
                continue
            comp_type = (item.get("required_transition_type", {}).get("S") or "").strip()
            if not comp_type:
                logger.error("[F50/AC-3] Component '%s' missing required_transition_type", cid)
                raise ComponentMisconfiguredError(cid, reason="missing")
            if comp_type not in STRICTNESS_RANK:
                logger.error("[F50/AC-3] Component '%s' invalid required_transition_type='%s'", cid, comp_type)
                raise ComponentMisconfiguredError(cid, reason="invalid_value", bad_value=comp_type)
            rank = STRICTNESS_RANK[comp_type]
            if rank < min_rank:
                min_rank = rank
                required = comp_type
        except ComponentMisconfiguredError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("[FTR-041] Failed to fetch component '%s': %s", cid, exc)
    return required


def _get_components_lifecycle(component_ids: list) -> Dict[str, Dict[str, str]]:
    """Per-component lifecycle metadata for the FTR-076/E10 gate. Missing components omitted;
    components without lifecycle_status default to 'active'."""
    out: Dict[str, Dict[str, str]] = {}
    if not component_ids:
        return out
    for cid in component_ids:
        try:
            resp = _ddb().get_item(
                TableName=COMPONENTS_TABLE,
                Key={"component_id": {"S": str(cid)}},
            )
            item = resp.get("Item")
            if not item:
                logger.warning("[FTR-076] Component '%s' not found; skipping lifecycle gate", cid)
                continue
            ls = item.get("lifecycle_status", {}).get("S", "active")
            entry: Dict[str, str] = {"lifecycle_status": ls}
            rr = item.get("rejection_reason", {}).get("S", "")
            if rr:
                entry["rejection_reason"] = rr
            out[str(cid)] = entry
        except Exception as exc:  # noqa: BLE001
            logger.error("[FTR-076] Failed to fetch component '%s' lifecycle: %s", cid, exc)
    return out


# ---------------------------------------------------------------------------
# Subtask completion gate (ENC-ISS-106) — parity with checkout_service.
# ---------------------------------------------------------------------------
def _get_task_status(project_id: str, task_id: str) -> Tuple[int, str]:
    """Return (http_status, child_status_lower). 404 -> ('', 'not_found' handled by caller)."""
    try:
        resp = _ddb().get_item(
            TableName=DYNAMODB_TABLE,
            Key={"project_id": {"S": project_id}, "record_id": {"S": f"task#{task_id}"}},
            ConsistentRead=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("[ISS-106] Failed to read child task '%s': %s", task_id, exc)
        return 500, ""
    item = resp.get("Item")
    if not item:
        return 404, ""
    return 200, (item.get("status", {}).get("S", "") or "").strip().lower()


def _validate_subtask_gate(
    project_id: str,
    task_id: str,
    subtask_ids: list,
    current_status: str,
    target_status: str,
    transition_type: str,
) -> Optional[dict]:
    """ENC-ISS-106: a parent task may not advance to coding-complete+ unless every direct child
    has reached at least that stage. Returns None if the gate passes or does not apply, else a
    reject verdict (built via _reject)."""
    if not subtask_ids:
        return None
    target_rank = STATUS_RANK.get(target_status)
    if target_rank is None or target_rank < _SUBTASK_GATE_MIN_RANK:
        return None

    lagging: list = []
    for child_id in subtask_ids:
        child_id = str(child_id).strip()
        if not child_id:
            continue
        code, child_current = _get_task_status(project_id, child_id)
        if code != 200:
            lagging.append((child_id, "not_found"))
            continue
        child_rank = STATUS_RANK.get(child_current, -1)
        if child_rank < target_rank:
            lagging.append((child_id, child_current or "unknown"))

    if not lagging:
        return None

    detail_lines = [f"  - {cid} ({cstatus})" for cid, cstatus in lagging[:20]]
    if len(lagging) > 20:
        detail_lines.append(f"  ... and {len(lagging) - 20} more")
    return _reject(
        400,
        (
            f"Cannot advance {task_id} to '{target_status}': "
            f"{len(lagging)} child task(s) have not reached this stage (ENC-ISS-106):\n"
            + "\n".join(detail_lines)
            + f"\nAdvance all child tasks to '{target_status}' or beyond before advancing the parent."
        ),
        code="SUBTASK_GATE",
        gate_class=get_gate_class(transition_type, target_status),
        lagging_subtasks=[{"task_id": cid, "status": cstatus} for cid, cstatus in lagging],
    )


# ---------------------------------------------------------------------------
# Verdict builders
# ---------------------------------------------------------------------------
def _allow(gate_class: Optional[str] = None, is_revert: bool = False, **extra) -> dict:
    out = {
        "allow": True,
        "error": None,
        "is_revert": is_revert,
        "gate_class": gate_class,
        "matrix_version": MATRIX_VERSION,
        "lifecycle_service_version": LIFECYCLE_SERVICE_VERSION,
    }
    out.update(extra)
    return out


def _reject(status: int, message: str, *, code: str = "INVALID_INPUT", gate_class: Optional[str] = None, **details) -> dict:
    retryable = bool(details.pop("retryable", status >= 500))
    return {
        "allow": False,
        "error": {
            "code": code,
            "message": message,
            "status": status,
            "retryable": retryable,
            "details": details,
        },
        "gate_class": gate_class,
        "matrix_version": MATRIX_VERSION,
        "lifecycle_service_version": LIFECYCLE_SERVICE_VERSION,
    }


# ---------------------------------------------------------------------------
# Core: validate a status transition (the action tracker_mutation invokes).
# ---------------------------------------------------------------------------
def validate_transition(req: dict) -> dict:
    """Validate a single status transition against the matrix + evidence + subtask gate.

    Required: record_type, current_status, target_status. Optional: transition_type (default
    github_pr_deploy), transition_evidence, project_id, record_id, subtask_ids,
    is_checkout_service_request. Pure DynamoDB-only (no GitHub).
    """
    record_type = (req.get("record_type") or "").strip().lower()
    current_status = (req.get("current_status") or "").strip().lower()
    target_status = (req.get("target_status") or "").strip().lower()
    transition_type = (req.get("transition_type") or "github_pr_deploy").strip().lower()
    transition_evidence = req.get("transition_evidence") or {}
    if not isinstance(transition_evidence, dict):
        transition_evidence = {}
    project_id = (req.get("project_id") or "").strip()
    record_id = (req.get("record_id") or "").strip()
    subtask_ids = req.get("subtask_ids") or []
    is_checkout_service_request = bool(req.get("is_checkout_service_request"))

    if record_type not in _VALID_TRANSITIONS:
        return _reject(400, f"Unknown record_type '{record_type}'.", code="INVALID_INPUT")

    gate_class = get_gate_class(transition_type, target_status) if record_type == "task" else None

    # No-op: same status is not a transition.
    if current_status == target_status:
        return _allow(gate_class=gate_class)

    # --- Transition validity (forward + revert) — ENC-FTR-022 ---
    type_transitions = _VALID_TRANSITIONS.get(record_type, {})
    valid_next = set(type_transitions.get(current_status, set()))
    revert_targets = set(_REVERT_TRANSITIONS.get(record_type, {}).get(current_status, set()))

    # ENC-ISS-092: checkout-service-authenticated requests expand valid_next with the
    # transition_type-specific arc shortcuts the checkout service already validated.
    if record_type == "task" and is_checkout_service_request:
        if transition_type == "no_code" and current_status == "coding-complete":
            valid_next = valid_next | {"closed"}
        elif transition_type == "code_only" and current_status == "merged-main":
            valid_next = valid_next | {"closed"}

    is_revert = False
    if target_status in valid_next:
        pass
    elif target_status in revert_targets:
        revert_reason = str(transition_evidence.get("revert_reason", "")).strip()
        if not revert_reason:
            return _reject(
                400,
                f"Reverting {record_type} from '{current_status}' to '{target_status}' "
                f"requires transition_evidence.revert_reason",
                code="REVERT_REASON_REQUIRED",
                gate_class=gate_class,
            )
        is_revert = True
    else:
        return _reject(
            400,
            f"Invalid status transition for {record_type}: '{current_status}' -> '{target_status}'. "
            f"Valid forward: {sorted(valid_next)}. "
            f"Valid revert (with revert_reason): {sorted(revert_targets)}",
            code="INVALID_TRANSITION",
            gate_class=gate_class,
            allowed_forward=sorted(valid_next),
            allowed_revert=sorted(revert_targets),
        )

    # Evidence gates apply to FORWARD task transitions only.
    if record_type == "task" and not is_revert:
        # committed — commit_sha PRESENCE + 40-hex FORMAT (GitHub existence check stays in tracker_mutation).
        if target_status == "committed":
            commit_sha = str(transition_evidence.get("commit_sha", "")).strip()
            if not commit_sha:
                return _reject(
                    400, "Cannot transition to 'committed': transition_evidence.commit_sha required",
                    code="EVIDENCE_REQUIRED", gate_class=gate_class,
                    expected_format="transition_evidence.commit_sha (40-char hex SHA)",
                )
            if not re.match(r"^[0-9a-f]{40}$", commit_sha.lower()):
                return _reject(
                    400, f"Invalid commit_sha: expected 40-char hex. Got: '{commit_sha}'",
                    code="EVIDENCE_INVALID", gate_class=gate_class,
                    expected_format="transition_evidence.commit_sha (40-char hex SHA)",
                )

        # merged-main — merge_evidence presence (skipped for checkout-service requests, ENC-ISS-095).
        elif target_status == "merged-main" and not is_checkout_service_request:
            merge_evidence = str(transition_evidence.get("merge_evidence", "")).strip()
            if not merge_evidence:
                return _reject(
                    400, "Cannot transition to 'merged-main': transition_evidence.merge_evidence required",
                    code="EVIDENCE_REQUIRED", gate_class=gate_class,
                    expected_format="transition_evidence.merge_evidence (non-empty string)",
                )

        # deploy-success — matrix-driven evidence shape (ENC-FTR-059).
        elif target_status == "deploy-success":
            validator_entry = _DEPLOY_SUCCESS_VALIDATORS.get(transition_type)
            if validator_entry:
                ev_key, validator_fn, format_desc = validator_entry
                ev_err = validator_fn(transition_evidence.get(ev_key))
                if ev_err:
                    return _reject(400, ev_err, code="EVIDENCE_INVALID", gate_class=gate_class,
                                   expected_format=format_desc)
            else:
                de_err = _validate_deploy_evidence(transition_evidence.get("deploy_evidence"))
                if de_err:
                    return _reject(400, de_err, code="EVIDENCE_INVALID", gate_class=gate_class)

        # closed — per transition_type: deploy arcs need live_validation_evidence;
        # no_code needs no_code_evidence; code_only needs code_on_main_evidence.commit_sha
        # (the GitHub ancestor-of-main compare itself stays in tracker_mutation).
        elif target_status == "closed":
            if transition_type == "no_code":
                if not str(transition_evidence.get("no_code_evidence", "")).strip():
                    return _reject(
                        400, "Cannot transition to 'closed': transition_evidence.no_code_evidence required (non-empty string)",
                        code="EVIDENCE_REQUIRED", gate_class=gate_class,
                    )
            elif transition_type == "code_only":
                code_ev = transition_evidence.get("code_on_main_evidence") or {}
                sha = str((code_ev.get("commit_sha") if isinstance(code_ev, dict) else "") or "").strip()
                if not re.match(r"^[0-9a-f]{40}$", sha.lower()):
                    return _reject(
                        400, "Cannot transition to 'closed': transition_evidence.code_on_main_evidence.commit_sha (40-char hex) required",
                        code="EVIDENCE_REQUIRED", gate_class=gate_class,
                    )
            elif current_status == "deploy-success":
                if not str(transition_evidence.get("live_validation_evidence", "")).strip():
                    return _reject(
                        400, "Cannot transition to 'closed': transition_evidence.live_validation_evidence required (non-empty string)",
                        code="EVIDENCE_REQUIRED", gate_class=gate_class,
                    )

        # Subtask completion gate (ENC-ISS-106).
        subtask_reject = _validate_subtask_gate(
            project_id, record_id, subtask_ids, current_status, target_status, transition_type
        )
        if subtask_reject is not None:
            return subtask_reject

    return _allow(gate_class=gate_class, is_revert=is_revert)


# ---------------------------------------------------------------------------
# STRICTNESS_RANK check (exposed for the checkout_service follow-on; ENC-TSK-C15).
# ---------------------------------------------------------------------------
def validate_components_transition_type(req: dict) -> dict:
    """Validate a task's transition_type is at least as strict as its components require, and that
    no component is in a blocked/opaque lifecycle state. Owned by the Lifecycle Service; called at
    checkout time. (checkout_service wiring is a tracked follow-on; tracker_mutation does not use this.)"""
    components = req.get("components") or []
    transition_type = (req.get("transition_type") or "github_pr_deploy").strip().lower()
    try:
        lifecycles = _get_components_lifecycle(components)
        for cid, meta in lifecycles.items():
            ls = (meta.get("lifecycle_status") or "active").strip().lower()
            if ls in _OPAQUE_LIFECYCLE_STATUSES:
                return _reject(404, f"Component '{cid}' not found.", code="NOT_FOUND")
            if ls in _BLOCKED_LIFECYCLE_STATUSES:
                return _reject(
                    400, f"Component '{cid}' is '{ls}' and cannot be used for checkout.",
                    code="COMPONENT_BLOCKED", component_id=cid,
                    rejection_reason=meta.get("rejection_reason", ""),
                )
        required = _get_required_transition_type(components)
    except ComponentMisconfiguredError as exc:
        return _reject(500, str(exc), code="COMPONENT_MISCONFIGURED", retryable=False,
                       component_id=exc.component_id, reason=exc.reason)
    if required is None:
        return _allow()
    if transition_type not in STRICTNESS_RANK:
        return _reject(400, f"Unknown transition_type '{transition_type}'.", code="INVALID_INPUT")
    if STRICTNESS_RANK[transition_type] > STRICTNESS_RANK[required]:
        return _reject(
            400,
            f"transition_type '{transition_type}' is less strict than required '{required}' "
            f"(component minimum). Set transition_type to '{required}' or stricter.",
            code="STRICTNESS_VIOLATION", required_transition_type=required,
        )
    return _allow(required_transition_type=required)


# ---------------------------------------------------------------------------
# ENC-TSK-H84 / ENC-FTR-111 AC-5 — deploy_policy-gated deploy-init auto-walk (ruling O-2).
#
# The gate_class taxonomy (transition_type_matrix) classifies deploy-init as MECHANICAL, which
# is the only Phase-1 auto-walkable class. Ruling O-2 (DOC-078C57FC1BE6 §3) adds a runtime
# qualifier: deploy-init is mechanical ONLY on ci_triggered projects — on manual projects a
# human/external actor owns the deploy trigger, so the Universal Arc-Walker must not synthesize
# the advance. This service is the authoritative reader of that project field for the walker.
# ---------------------------------------------------------------------------
def _get_project_deploy_policy(project_id: str) -> str:
    """Return the project's deploy_policy enum, defaulting to ci_triggered.

    Mirrors deploy_orchestrator._get_project_deploy_mode (ENC-ISS-102 precedent): a missing
    record, missing field, or unrecognized value all degrade to the ci_triggered seeded default
    so an unseeded/legacy project never blocks the mechanical deploy-init walk. Fail-open WARN on
    a DynamoDB read error for the same reason."""
    pid = (project_id or "").strip()
    if not pid:
        return DEFAULT_DEPLOY_POLICY
    try:
        resp = _ddb().get_item(
            TableName=PROJECTS_TABLE,
            Key={"project_id": {"S": pid}},
            ProjectionExpression="deploy_policy",
        )
        item = resp.get("Item") or {}
        val = (item.get("deploy_policy", {}).get("S") or "").strip().lower()
        if val in VALID_DEPLOY_POLICIES:
            return val
        return DEFAULT_DEPLOY_POLICY
    except Exception:  # noqa: BLE001
        logger.warning(
            "[FTR-111] Failed to read deploy_policy for project '%s'; defaulting to '%s'",
            pid, DEFAULT_DEPLOY_POLICY, exc_info=True,
        )
        return DEFAULT_DEPLOY_POLICY


def evaluate_auto_walk(req: dict) -> dict:
    """ENC-FTR-111 AC-5 — decide whether the Universal Arc-Walker may auto-advance a task across
    a (transition_type, target_status) gate.

    Eligibility derives SOLELY from the gate_class taxonomy (DOC-078C57FC1BE6 §7.2 — never from
    whether the gate's evidence contract happens to be empty). The `mechanical` class is the only
    Phase-1 auto-walkable class.

    Ruling O-2 runtime qualifier: the `deploy-init` gate is mechanical, but auto-walkable only on
    ci_triggered projects. On manual projects the deploy is human/externally triggered, so the
    walker MUST NOT auto-advance — even though the static class is mechanical.

    Required: target_status. Optional: transition_type (default github_pr_deploy), project_id
    (required for a meaningful deploy-init decision). Returns a verdict dict the walker consumes.
    """
    transition_type = (req.get("transition_type") or "github_pr_deploy").strip().lower()
    target_status = (req.get("target_status") or "").strip().lower()
    project_id = (req.get("project_id") or "").strip()

    gate_class = get_gate_class(transition_type, target_status)
    auto_walkable = is_auto_walkable_class(gate_class)
    reason: Optional[str] = None
    deploy_policy: Optional[str] = None

    if target_status == "deploy-init":
        deploy_policy = _get_project_deploy_policy(project_id)
        if auto_walkable and deploy_policy != DEPLOY_POLICY_CI_TRIGGERED:
            # Ruling O-2: manual projects gate out of the mechanical auto-walk.
            auto_walkable = False
            reason = (
                f"deploy-init auto-walk blocked (ruling O-2): project '{project_id or '<unknown>'}' "
                f"deploy_policy='{deploy_policy}'. Only ci_triggered projects auto-walk deploy-init; "
                "manual projects require a human/external deploy trigger."
            )
        elif auto_walkable:
            reason = (
                f"deploy-init auto-walk permitted (ruling O-2): project "
                f"'{project_id or '<unknown>'}' deploy_policy='{deploy_policy}'."
            )

    out = {
        "auto_walkable": auto_walkable,
        "gate_class": gate_class,
        "transition_type": transition_type,
        "target_status": target_status,
        "matrix_version": MATRIX_VERSION,
        "lifecycle_service_version": LIFECYCLE_SERVICE_VERSION,
    }
    if deploy_policy is not None:
        out["deploy_policy"] = deploy_policy
    if reason is not None:
        out["reason"] = reason
    return out


_ACTIONS = {
    "validate_transition": validate_transition,
    "validate_components_transition_type": validate_components_transition_type,
    "evaluate_auto_walk": evaluate_auto_walk,
    "health": lambda req: {"ok": True, "service": "lifecycle_service",
                           "version": LIFECYCLE_SERVICE_VERSION, "matrix_version": MATRIX_VERSION},
}


def lambda_handler(event, context):  # noqa: ANN001
    """Direct-invoke dispatch. event = {"action": ..., ...request fields}. Returns a verdict dict.

    Defensive: any unexpected exception returns a retryable 500 verdict so the synchronous caller
    (tracker_mutation) can apply its FAIL-CLOSED policy deterministically rather than seeing an
    opaque Lambda error.
    """
    try:
        if isinstance(event, str):
            event = json.loads(event)
        action = (event.get("action") or "validate_transition").strip()
        handler = _ACTIONS.get(action)
        if handler is None:
            return _reject(400, f"Unknown action '{action}'. "
                                f"Valid: {sorted(_ACTIONS)}", code="UNKNOWN_ACTION")
        return handler(event)
    except Exception as exc:  # noqa: BLE001
        logger.exception("lifecycle_service unhandled error")
        return _reject(500, f"Lifecycle Service internal error: {exc}", code="INTERNAL_ERROR", retryable=True)
