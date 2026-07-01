#!/usr/bin/env python3
"""Tests for env_parity_core + AC2 (env_drift_auditor uses the shared core).

ENC-TSK-H19 (ENC-PLN-048 Objective 2). Run:
    python3 backend/lambda/env_drift_auditor/test_env_parity_core.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import env_parity_core as core  # noqa: E402


def test_build_placeholders_merges_policy_and_defaults():
    ph = core.build_placeholders({"placeholder_values_that_count_as_drift": ["XX"]})
    assert "XX" in ph
    assert "" in ph and "CHANGE_ME" in ph and "None" in ph


def test_build_placeholders_handles_none_policy():
    ph = core.build_placeholders(None)
    assert "TODO" in ph


def test_is_placeholder():
    ph = core.build_placeholders(None)
    assert core.is_placeholder("", ph) is True
    assert core.is_placeholder("REPLACE_ME", ph) is True  # REPLACE_ prefix
    assert core.is_placeholder("real-value", ph) is False
    assert core.is_placeholder(None, ph) is False  # None is 'missing', not placeholder


def test_classify_required_missing_and_placeholder_and_ok():
    ph = core.build_placeholders(None)
    env = {"A": "ok", "B": "", "C": "REPLACE_X"}
    drift = core.classify_required(["A", "B", "C", "D"], env, ph)
    by_var = {d["var"]: d["reason"] for d in drift}
    assert "A" not in by_var  # present and real
    assert by_var["B"].startswith("placeholder")
    assert by_var["C"].startswith("placeholder")
    assert by_var["D"] == "missing"


def test_live_only_vars():
    assert core.live_only_vars({"A": "1", "B": "2"}, {"A": "1"}) == ["B"]
    assert core.live_only_vars({"A": "1"}, {"A": "1", "B": "2"}) == []  # live subset
    assert core.live_only_vars({}, {"A": "1"}) == []


# --- ENC-TSK-H16: registry entry shape + classification --------------------
def test_required_vars_dict_and_list_and_none():
    assert core.required_vars({"A": "deploy-critical", "B": "advisory"}) == ["A", "B"]
    assert core.required_vars(["A", "B"]) == ["A", "B"]  # legacy flat list
    assert core.required_vars(None) == []


def test_required_vars_rejects_bad_type():
    try:
        core.required_vars(42)
    except TypeError:
        return
    raise AssertionError("expected TypeError for non-dict/list entry")


def test_classification_of_dict_list_and_default():
    entry = {"A": "deploy-critical", "B": "advisory"}
    assert core.classification_of(entry, "A") == core.DEPLOY_CRITICAL
    assert core.classification_of(entry, "B") == core.ADVISORY
    # var absent from a dict entry -> fail-closed default (deploy-critical)
    assert core.classification_of(entry, "Z") == core.DEPLOY_CRITICAL
    # unknown classification string -> fail-closed default
    assert core.classification_of({"A": "wat"}, "A") == core.DEPLOY_CRITICAL
    # legacy list entry -> every var deploy-critical
    assert core.classification_of(["A"], "A") == core.DEPLOY_CRITICAL


def test_is_deploy_critical():
    entry = {"A": "deploy-critical", "B": "advisory"}
    assert core.is_deploy_critical(entry, "A") is True
    assert core.is_deploy_critical(entry, "B") is False
    assert core.is_deploy_critical(["A"], "A") is True  # legacy = critical


def test_critical_and_advisory_partition():
    entry = {"A": "deploy-critical", "B": "advisory", "C": "deploy-critical"}
    assert core.critical_vars(entry) == ["A", "C"]
    assert core.advisory_vars(entry) == ["B"]
    # legacy list: all critical, none advisory
    assert core.critical_vars(["A", "B"]) == ["A", "B"]
    assert core.advisory_vars(["A", "B"]) == []


def test_classification_map():
    entry = {"A": "deploy-critical", "B": "advisory"}
    assert core.classification_map(entry) == {"A": "deploy-critical", "B": "advisory"}
    assert core.classification_map(["A"]) == {"A": "deploy-critical"}
    assert core.classification_map(None) == {}


# --- AC2: env_drift_auditor delegates to the shared core --------------------
class _StubExceptions:
    class ResourceNotFoundException(Exception):
        pass


class _StubLambdaClient:
    def __init__(self, variables):
        self._variables = variables
        self.exceptions = _StubExceptions

    def get_function_configuration(self, FunctionName):  # noqa: N803 (boto3 casing)
        return {"Environment": {"Variables": self._variables}}


def test_env_drift_auditor_uses_shared_core():
    os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test-key")
    try:
        import lambda_function as lf  # noqa: E402
    except Exception as exc:  # boto3 missing etc. — don't fail the whole suite
        print(f"  SKIP test_env_drift_auditor_uses_shared_core ({exc})")
        return
    # The auditor must import the very same functions from the core (no copy).
    assert lf.classify_required is core.classify_required
    assert lf.build_placeholders is core.build_placeholders
    # Behavior: a missing required var surfaces as drift via the shared core.
    client = _StubLambdaClient({"PRESENT": "ok"})
    status, drift = lf._audit_lambda(client, "fn", ["PRESENT", "MISSING_ONE"])
    assert status == "drift"
    assert {d["var"] for d in drift} == {"MISSING_ONE"}


# --- ENC-TSK-H10: drift-issue dedup signature -------------------------------
def test_drift_signature_stable_and_order_independent():
    # Same (lambda, missing-var SET) -> same signature regardless of var order
    # or duplicates (the frozenset(missing_vars) dedup key).
    a = core.drift_signature("devops-fn", ["B", "A"])
    b = core.drift_signature("devops-fn", ["A", "B"])
    c = core.drift_signature("devops-fn", ["A", "B", "B", "A"])
    assert a == b == c
    # Different missing-var set -> different signature.
    assert core.drift_signature("devops-fn", ["A"]) != a
    # Different lambda -> different signature.
    assert core.drift_signature("devops-other", ["A", "B"]) != a
    # 12 hex chars.
    assert len(a) == 12 and all(ch in "0123456789abcdef" for ch in a)


def test_sig_token_format():
    assert core.sig_token("abc123") == "[sig:abc123]"


def test_find_signature_match_by_title_token():
    sig = core.drift_signature("devops-fn", ["A", "B"])
    issues = [
        {"item_id": "ENC-ISS-001", "title": "[auto-drift] other thing [sig:deadbeef0000]"},
        {"item_id": "ENC-ISS-002", "title": f"[auto-drift] devops-fn missing X {core.sig_token(sig)}"},
    ]
    assert core.find_signature_match(issues, sig) == "ENC-ISS-002"
    # No carrier -> no match.
    assert core.find_signature_match([{"item_id": "ENC-ISS-003", "title": "unrelated"}], sig) is None
    # record_id fallback when item_id is absent.
    rid_only = [{"record_id": "issue#ENC-ISS-004", "title": f"x {core.sig_token(sig)}"}]
    assert core.find_signature_match(rid_only, sig) == "ENC-ISS-004"


def test_find_signature_match_idempotency_core():
    """Pure AC-2 core (no boto3/network): once an issue carrying the signature is
    open, a repeat finding matches it, so the auditor bumps instead of filing."""
    sig = core.drift_signature("devops-fn", ["A", "B"])
    open_issues: list = []
    # First run: nothing open yet -> no match -> auditor would FILE.
    assert core.find_signature_match(open_issues, sig) is None
    # Simulate the filed issue now being open (title carries the token).
    open_issues.append({
        "item_id": "ENC-ISS-T1",
        "title": f"[auto-drift] devops-fn missing required env vars: A, B {core.sig_token(sig)}",
        "status": "open",
    })
    # Second run, same finding (even with vars discovered in a different order) ->
    # matches the open issue -> auditor BUMPS, files nothing new.
    assert core.find_signature_match(open_issues, core.drift_signature("devops-fn", ["B", "A"])) == "ENC-ISS-T1"


def test_auditor_idempotent_dedup_bumps_not_refiles():
    """AC-2 (ENC-TSK-H10) at the orchestrator level: a repeat run against unresolved
    drift creates ZERO new issues — it bumps the existing one. Only the network I/O
    is stubbed; the real _handle_drift_finding + drift_signature + find_signature_match
    make the decision."""
    os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test-key")
    try:
        import lambda_function as lf  # noqa: E402
    except Exception as exc:  # boto3 missing locally etc. — pure test above still proves AC-2
        print(f"  SKIP test_auditor_idempotent_dedup_bumps_not_refiles ({exc})")
        return

    open_issues: list = []  # simulated tracker OPEN-issue store
    counters = {"filed": 0, "bumped": 0}

    def fake_fetch_open_issues():
        return list(open_issues)

    def fake_file(fn_name, drift, run_id, signature):
        counters["filed"] += 1
        open_issues.append({
            "item_id": f"ENC-ISS-T{counters['filed']}",
            "title": f"[auto-drift] {fn_name} missing required env vars: X {core.sig_token(signature)}",
            "status": "open",
        })
        return {"status": 201, "filed": True, "signature": signature}

    def fake_bump(issue_id, fn_name, run_id, now):
        counters["bumped"] += 1
        return {"status": 200, "deduped": True, "issue_id": issue_id}

    saved = (lf._fetch_open_issues, lf._file_drift_issue, lf._bump_drift_issue, lf.DRY_RUN)
    lf._fetch_open_issues = fake_fetch_open_issues
    lf._file_drift_issue = fake_file
    lf._bump_drift_issue = fake_bump
    lf.DRY_RUN = False
    try:
        drift = [{"var": "COORDINATION_INTERNAL_API_KEY", "reason": "missing"}]
        lf._handle_drift_finding("devops-some-fn", drift, "run-1")
        r2 = lf._handle_drift_finding("devops-some-fn", drift, "run-2")
    finally:
        (lf._fetch_open_issues, lf._file_drift_issue, lf._bump_drift_issue, lf.DRY_RUN) = saved

    assert counters["filed"] == 1, f"expected exactly 1 file, got {counters['filed']}"
    assert counters["bumped"] == 1, f"expected exactly 1 bump, got {counters['bumped']}"
    assert len(open_issues) == 1, "repeat run must not create a new issue record"
    assert r2.get("deduped") is True


def test_find_matching_drift_issue_consolidates_legacy_tokenless():
    """ENC-TSK-J30: the matcher consolidates pre-signature (tokenless) auto-drift
    issues for the same (fn, missing-var set), so a new run bumps the 2026-06 storm
    issue instead of filing yet another duplicate on top of it."""
    sig = core.drift_signature("devops-deploy-intake", ["SQS_QUEUE_URL"])
    legacy = [{
        "item_id": "ENC-ISS-319",
        "title": "[auto-drift] devops-deploy-intake missing required env vars: SQS_QUEUE_URL",
        "status": "open",
    }]
    # find_signature_match alone can't see a tokenless legacy issue...
    assert core.find_signature_match(legacy, sig) is None
    # ...but find_matching_drift_issue consolidates it by fn + var-set.
    assert core.find_matching_drift_issue(legacy, sig, "devops-deploy-intake", ["SQS_QUEUE_URL"]) == "ENC-ISS-319"
    # A different fn or a different missing-var set must NOT match.
    assert core.find_matching_drift_issue(legacy, sig, "devops-other", ["SQS_QUEUE_URL"]) is None
    assert core.find_matching_drift_issue(legacy, sig, "devops-deploy-intake", ["DEPLOY_TABLE"]) is None
    # Signature-token issues still take precedence when both are present.
    legacy.append({
        "item_id": "ENC-ISS-T9",
        "title": f"[auto-drift] devops-deploy-intake missing required env vars: SQS_QUEUE_URL {core.sig_token(sig)}",
    })
    assert core.find_matching_drift_issue(legacy, sig, "devops-deploy-intake", ["SQS_QUEUE_URL"]) == "ENC-ISS-T9"


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  FAIL {t.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
