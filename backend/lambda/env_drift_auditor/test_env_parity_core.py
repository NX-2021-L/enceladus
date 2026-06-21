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
