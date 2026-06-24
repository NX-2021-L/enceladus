"""Unit tests for the Enceladus Lifecycle Service (ENC-TSK-H46 / B63 Phase 2A).

Pure-function tests — no AWS. The subtask-gate test monkeypatches the DynamoDB read.
Runs under pytest (test_* discovery) and standalone (`python test_lambda_function.py`).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402
import transition_type_matrix as ttm  # noqa: E402

SHA = "a" * 40
GOOD_DEPLOY_EVIDENCE = {
    "id": 123, "name": "Deploy Lambda Artifacts (Gen2)", "run_id": 456,
    "head_sha": SHA, "status": "completed", "conclusion": "success",
    "started_at": "2026-06-24T00:00:00Z", "completed_at": "2026-06-24T00:01:00Z",
}


# --- transition validity -----------------------------------------------------
def test_forward_transition_allowed():
    v = lf.validate_transition({"record_type": "task", "current_status": "open", "target_status": "in-progress"})
    assert v["allow"] is True, v


def test_invalid_transition_rejected():
    v = lf.validate_transition({"record_type": "task", "current_status": "open", "target_status": "merged-main"})
    assert v["allow"] is False and v["error"]["code"] == "INVALID_TRANSITION", v


def test_revert_requires_reason():
    v = lf.validate_transition({"record_type": "task", "current_status": "in-progress", "target_status": "open"})
    assert v["allow"] is False and v["error"]["code"] == "REVERT_REASON_REQUIRED", v
    v2 = lf.validate_transition({"record_type": "task", "current_status": "in-progress",
                                 "target_status": "open", "transition_evidence": {"revert_reason": "rollback"}})
    assert v2["allow"] is True and v2["is_revert"] is True, v2


def test_unknown_record_type_rejected():
    v = lf.validate_transition({"record_type": "widget", "current_status": "open", "target_status": "in-progress"})
    assert v["allow"] is False and v["error"]["code"] == "INVALID_INPUT", v


def test_no_code_shortcut_only_for_checkout_service():
    base = {"record_type": "task", "transition_type": "no_code",
            "current_status": "coding-complete", "target_status": "closed",
            "transition_evidence": {"no_code_evidence": "verified via SSH"}}
    # Without checkout-service context, coding-complete -> closed is not a standard task arc.
    assert lf.validate_transition(dict(base))["allow"] is False
    # With checkout-service context, the shortcut is permitted and evidence validates.
    assert lf.validate_transition({**base, "is_checkout_service_request": True})["allow"] is True


# --- evidence gates ----------------------------------------------------------
def test_committed_requires_commit_sha():
    v = lf.validate_transition({"record_type": "task", "current_status": "coding-complete", "target_status": "committed"})
    assert v["allow"] is False and v["error"]["code"] == "EVIDENCE_REQUIRED", v
    v2 = lf.validate_transition({"record_type": "task", "current_status": "coding-complete",
                                 "target_status": "committed", "transition_evidence": {"commit_sha": SHA}})
    assert v2["allow"] is True, v2


def test_committed_bad_sha_rejected():
    v = lf.validate_transition({"record_type": "task", "current_status": "coding-complete",
                                "target_status": "committed", "transition_evidence": {"commit_sha": "xyz"}})
    assert v["allow"] is False and v["error"]["code"] == "EVIDENCE_INVALID", v


def test_deploy_success_evidence_shape():
    ok = lf.validate_transition({"record_type": "task", "transition_type": "github_pr_deploy",
                                 "current_status": "deploy-init", "target_status": "deploy-success",
                                 "transition_evidence": {"deploy_evidence": GOOD_DEPLOY_EVIDENCE}})
    assert ok["allow"] is True, ok
    bad = lf.validate_transition({"record_type": "task", "transition_type": "github_pr_deploy",
                                  "current_status": "deploy-init", "target_status": "deploy-success",
                                  "transition_evidence": {"deploy_evidence": {"id": 1}}})
    assert bad["allow"] is False and bad["error"]["code"] == "EVIDENCE_INVALID", bad


def test_closed_requires_live_validation():
    v = lf.validate_transition({"record_type": "task", "transition_type": "github_pr_deploy",
                                "current_status": "deploy-success", "target_status": "closed"})
    assert v["allow"] is False and v["error"]["code"] == "EVIDENCE_REQUIRED", v
    v2 = lf.validate_transition({"record_type": "task", "transition_type": "github_pr_deploy",
                                 "current_status": "deploy-success", "target_status": "closed",
                                 "transition_evidence": {"live_validation_evidence": "PWA shows record"}})
    assert v2["allow"] is True, v2


# --- subtask gate (ENC-ISS-106) ---------------------------------------------
def test_subtask_gate_blocks_until_children_advance(monkeypatch=None):
    statuses = {"ENC-TSK-C1": "in-progress", "ENC-TSK-C2": "coding-complete"}
    lf._get_task_status = lambda pid, tid: (200, statuses.get(tid, ""))  # type: ignore
    blocked = lf.validate_transition({
        "record_type": "task", "project_id": "enceladus", "record_id": "ENC-TSK-P",
        "current_status": "in-progress", "target_status": "coding-complete",
        "subtask_ids": ["ENC-TSK-C1", "ENC-TSK-C2"],
    })
    assert blocked["allow"] is False and blocked["error"]["code"] == "SUBTASK_GATE", blocked
    statuses["ENC-TSK-C1"] = "coding-complete"
    passed = lf.validate_transition({
        "record_type": "task", "project_id": "enceladus", "record_id": "ENC-TSK-P",
        "current_status": "in-progress", "target_status": "coding-complete",
        "subtask_ids": ["ENC-TSK-C1", "ENC-TSK-C2"],
    })
    assert passed["allow"] is True, passed


# --- gate_class taxonomy (ENC-FTR-111 scaffold; DOC §3/§7.2) -----------------
def test_gate_class_attestation_never_auto():
    # The coding-complete trap: empty evidence contract, but MUST be attestation (never auto-walk).
    assert ttm.get_gate_class("github_pr_deploy", "coding-complete") == "attestation"
    assert ttm.is_auto_walkable_class("attestation") is False
    # LiveValidation closed and no_code closed are the attestation floor.
    assert ttm.get_gate_class("github_pr_deploy", "closed") == "attestation"
    assert ttm.get_gate_class("no_code", "closed") == "attestation"


def test_gate_class_mechanical_and_external_fact():
    assert ttm.get_gate_class("github_pr_deploy", "deploy-init") == "mechanical"
    assert ttm.is_auto_walkable_class("mechanical") is True
    assert ttm.get_gate_class("code_only", "closed") == "mechanical"
    # Ruling O-1: pr is external-fact, not mechanical; never auto-synthesized.
    assert ttm.get_gate_class("github_pr_deploy", "pr") == "external-fact"
    assert ttm.is_auto_walkable_class("external-fact") is False
    assert ttm.get_gate_class("github_pr_deploy", "deploy-success") == "external-fact"


def test_gate_class_carried_in_verdict():
    v = lf.validate_transition({"record_type": "task", "transition_type": "github_pr_deploy",
                                "current_status": "merged-main", "target_status": "deploy-init"})
    assert v["allow"] is True and v["gate_class"] == "mechanical", v


# --- dispatch ----------------------------------------------------------------
def test_handler_unknown_action():
    v = lf.lambda_handler({"action": "frobnicate"}, None)
    assert v["allow"] is False and v["error"]["code"] == "UNKNOWN_ACTION", v


def test_handler_health():
    v = lf.lambda_handler({"action": "health"}, None)
    assert v["ok"] is True and v["matrix_version"] == ttm.MATRIX_VERSION, v


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
