"""
Canonical Transition Type Matrix v1 — ENC-FTR-059 (Lifecycle Service copy)

Single source of truth for all gate evidence contracts in the Enceladus task lifecycle.
Embedded as a Python constant for 0ms cold-start latency.

This is the Lifecycle Service's authoritative copy (ENC-TSK-H46 / B63 Phase 2A). It is
byte-compatible with checkout_service/transition_type_matrix.py and
tracker_mutation/transition_type_matrix.py for the canonical sections, and additionally
carries the per-cell gate_class taxonomy scaffold (ENC-FTR-111 / DOC-078C57FC1BE6 §3).

Reference document: DOC-B5B807D7C2CE
Related feature:    ENC-FTR-059 (matrix), ENC-FTR-111 (Universal Arc-Walker)
Tasks:              ENC-TSK-B05, ENC-TSK-B06, ENC-TSK-B07, ENC-TSK-B08, ENC-TSK-H46
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
# ENC-FTR-111 / DOC-078C57FC1BE6 §3 — per-cell gate_class taxonomy SCAFFOLD.
#
# Classifies every (transition_type, target_status) gate so the Universal Arc-Walker
# (ENC-FTR-111) can derive auto-walk eligibility SOLELY from the class — NEVER from
# evidence-field emptiness (DOC §7.2, "the coding-complete trap": an empty evidence
# contract is not a license to auto-cross).
#
# H46 (this task) scaffolds the DATA. The walker logic that consumes it — the
# auto_walk_opt_out latch and the synchronous walk loop — is FTR-111's deliverable.
#
#   "mechanical"    — system already holds / can trivially+safely derive all evidence;
#                     crossing introduces no new external claim. Auto-walkable (Phase 1).
#   "external-fact" — evidence is a verifiable fact about an external system; auto-walkable
#                     ONLY via independently verified event-sourcing (Phase 2), never synthesis.
#   "attestation"   — evidence is an irreducible human/agent claim about reality.
#                     NEVER auto-walkable in any phase (the hard safety floor).
#
# Rulings baked in: O-1 (`pr` is EXTERNAL-FACT, not mechanical); O-2 (`deploy-init` is
# mechanical only on ci_triggered projects — the walker additionally gates on the project's
# deploy_policy at runtime); coding-complete / LiveValidation closed / no_code closed are the
# attestation floor.
# ---------------------------------------------------------------------------
GATE_CLASS_MECHANICAL: str = "mechanical"
GATE_CLASS_EXTERNAL_FACT: str = "external-fact"
GATE_CLASS_ATTESTATION: str = "attestation"

VALID_GATE_CLASSES: Set[str] = {
    GATE_CLASS_MECHANICAL,
    GATE_CLASS_EXTERNAL_FACT,
    GATE_CLASS_ATTESTATION,
}

_DEPLOY_ARC_GATE_CLASS: Dict[str, str] = {
    "in-progress": GATE_CLASS_ATTESTATION,      # checkout act — always agent-driven
    "coding-complete": GATE_CLASS_ATTESTATION,  # "the code is written" — irreducible agent claim
    "committed": GATE_CLASS_EXTERNAL_FACT,      # commit_sha pointer (irreducible input) + GitHub verify
    "pr": GATE_CLASS_EXTERNAL_FACT,             # ruling O-1: a PR was actually issued
    "merged-main": GATE_CLASS_EXTERNAL_FACT,    # merge webhook observable (Phase 2)
    "deploy-init": GATE_CLASS_MECHANICAL,       # ruling O-2: CI-triggered projects only
    "deploy-success": GATE_CLASS_EXTERNAL_FACT,  # deploy_finalize / changelog telemetry (Phase 2)
    "closed": GATE_CLASS_ATTESTATION,           # LiveValidationGate — someone verified the live system
}

GATE_CLASS: Dict[str, Dict[str, str]] = {
    "github_pr_deploy": dict(_DEPLOY_ARC_GATE_CLASS),
    "lambda_deploy": dict(_DEPLOY_ARC_GATE_CLASS),
    "web_deploy": dict(_DEPLOY_ARC_GATE_CLASS),
    "code_only": {
        "in-progress": GATE_CLASS_ATTESTATION,
        "coding-complete": GATE_CLASS_ATTESTATION,
        "committed": GATE_CLASS_EXTERNAL_FACT,
        "pr": GATE_CLASS_EXTERNAL_FACT,
        "merged-main": GATE_CLASS_EXTERNAL_FACT,
        # reuses the commit_sha already supplied at `committed`; the only action is a
        # system-run GitHub compare confirming ancestry of main — mechanical, not attestation.
        "closed": GATE_CLASS_MECHANICAL,
    },
    "no_code": {
        "in-progress": GATE_CLASS_ATTESTATION,
        # no_code_evidence is a free-text human attestation — the ontological terminus.
        "closed": GATE_CLASS_ATTESTATION,
    },
}

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


def get_gate_class(transition_type: str, target_status: str) -> Optional[str]:
    """Return the gate_class for a (transition_type, target_status) cell, or None if the
    cell is not a defined gate for that transition_type.

    ENC-FTR-111 scaffold (DOC-078C57FC1BE6 §3/§7.2): the Universal Arc-Walker MUST derive
    auto-walk eligibility solely from this classification — never from whether the gate's
    evidence contract happens to be empty.
    """
    return GATE_CLASS.get(transition_type, {}).get(target_status)


def is_auto_walkable_class(gate_class: Optional[str]) -> bool:
    """True only for the synchronously auto-walkable class (mechanical). external-fact requires
    verified event-sourcing (Phase 2); attestation is never auto-walkable. ENC-FTR-111 Phase 1
    consumes this; provided here so the eligibility rule lives with the matrix data."""
    return gate_class == GATE_CLASS_MECHANICAL
