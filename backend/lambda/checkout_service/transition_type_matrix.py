"""
Canonical Transition Type Matrix v1 — ENC-FTR-059

Single source of truth for all gate evidence contracts in the Enceladus task lifecycle.
Embedded as Python constant for 0ms cold-start latency.

Reference document: DOC-B5B807D7C2CE
Related feature: ENC-FTR-059
Tasks: ENC-TSK-B05, ENC-TSK-B06, ENC-TSK-B07, ENC-TSK-B08
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

MATRIX_VERSION: int = 1
MATRIX_DOCUMENT_ID: str = "DOC-B5B807D7C2CE"

# ---------------------------------------------------------------------------
# Strictness ranking — lower rank = stricter enforcement
# ---------------------------------------------------------------------------
STRICTNESS_RANK: Dict[str, int] = {
    "github_pr_deploy": 0,
    "lambda_deploy": 1,
    "web_deploy": 1,
    "code_only": 2,
    "no_code": 3,
}

VALID_TRANSITION_TYPES: Set[str] = set(STRICTNESS_RANK.keys())

# ---------------------------------------------------------------------------
# Deploy-success gate contracts — keyed by transition_type
# Each entry: (evidence_key, error_label)
# evidence_key is the field name in transition_evidence to extract and validate.
# Validator functions are registered separately by the consuming Lambda.
# ---------------------------------------------------------------------------
DEPLOY_SUCCESS_EVIDENCE: Dict[str, Dict[str, str]] = {
    "github_pr_deploy": {
        "evidence_key": "deploy_evidence",
        "label": "transition_evidence.deploy_evidence",
        "description": "GitHub Actions Jobs API response object",
    },
    "lambda_deploy": {
        "evidence_key": "lambda_deploy_evidence",
        "label": "transition_evidence.lambda_deploy_evidence",
        "description": "AWS Lambda GetFunctionConfiguration response",
    },
    "web_deploy": {
        "evidence_key": "web_deploy_evidence",
        "label": "transition_evidence.web_deploy_evidence",
        "description": "HTTP verification with url, http_status, checked_at",
    },
    # code_only and no_code do not have a deploy-success gate (not_applicable)
}

# ---------------------------------------------------------------------------
# Closed gate contracts — keyed by transition_type
# Each entry: (evidence_key, evidence_type, error_label)
# evidence_type: "object" requires isinstance(dict) check; "string" requires non-empty str
# ---------------------------------------------------------------------------
CLOSED_EVIDENCE: Dict[str, Dict[str, str]] = {
    "github_pr_deploy": {
        "evidence_key": "live_validation_evidence",
        "evidence_type": "string",
        "label": "transition_evidence.live_validation_evidence",
    },
    "lambda_deploy": {
        "evidence_key": "live_validation_evidence",
        "evidence_type": "string",
        "label": "transition_evidence.live_validation_evidence",
    },
    "web_deploy": {
        "evidence_key": "live_validation_evidence",
        "evidence_type": "string",
        "label": "transition_evidence.live_validation_evidence",
    },
    "code_only": {
        "evidence_key": "code_on_main_evidence",
        "evidence_type": "object",
        "label": "transition_evidence.code_on_main_evidence",
        "validator_id": "code_on_main",
    },
    "no_code": {
        "evidence_key": "no_code_evidence",
        "evidence_type": "string",
        "label": "transition_evidence.no_code_evidence",
    },
}

# ---------------------------------------------------------------------------
# Per-type allowed target statuses (derived from the 40-cell matrix)
# A status is "allowed" if its cell applicability is "required".
# ---------------------------------------------------------------------------
ALLOWED_TRANSITIONS_BY_TYPE: Dict[str, List[str]] = {
    "github_pr_deploy": [
        "in-progress", "coding-complete", "committed", "pr",
        "merged-main", "deploy-init", "deploy-success", "closed",
    ],
    "lambda_deploy": [
        "in-progress", "coding-complete", "committed", "pr",
        "merged-main", "deploy-init", "deploy-success", "closed",
    ],
    "web_deploy": [
        "in-progress", "coding-complete", "committed", "pr",
        "merged-main", "deploy-init", "deploy-success", "closed",
    ],
    "code_only": [
        "in-progress", "coding-complete", "committed", "pr",
        "merged-main", "closed",
    ],
    "no_code": [
        "in-progress", "coding-complete", "closed",
    ],
}

# ---------------------------------------------------------------------------
# Transition types that participate in the GitHub PR flow (CAI/CCI tokens)
# ---------------------------------------------------------------------------
GITHUB_PR_TYPES: Set[str] = {"github_pr_deploy", "web_deploy", "code_only", "lambda_deploy"}

# ---------------------------------------------------------------------------
# Immutable transition types (ENC-TSK-B07)
# Once set, these types cannot be changed via PATCH.
# ---------------------------------------------------------------------------
IMMUTABLE_TRANSITION_TYPES: Set[str] = {"no_code", "code_only"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_deploy_success_gate(transition_type: str) -> Optional[Dict[str, str]]:
    """Return the deploy-success evidence contract for a transition_type, or None if N/A."""
    return DEPLOY_SUCCESS_EVIDENCE.get(transition_type)


def get_closed_gate(transition_type: str) -> Optional[Dict[str, str]]:
    """Return the closed evidence contract for a transition_type."""
    return CLOSED_EVIDENCE.get(transition_type)


def get_allowed_statuses(transition_type: str) -> List[str]:
    """Return the list of allowed target statuses for a transition_type."""
    return ALLOWED_TRANSITIONS_BY_TYPE.get(transition_type, [])


def uses_github_pr(transition_type: str) -> bool:
    """Return True if the transition_type participates in the GitHub PR/token flow."""
    return transition_type in GITHUB_PR_TYPES


def is_immutable_type(transition_type: str) -> bool:
    """Return True if the transition_type cannot be changed once set (ENC-TSK-B07)."""
    return transition_type in IMMUTABLE_TRANSITION_TYPES
