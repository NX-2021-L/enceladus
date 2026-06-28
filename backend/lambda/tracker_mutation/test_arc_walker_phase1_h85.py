"""Tests for ENC-TSK-H85 / ENC-FTR-111 Phase 1 — synchronous inline mechanical arc-walk.

Covers FTR-111 AC-1/AC-2 (this task's two acceptance criteria):
  - Behind an independent flag, after a successful advance the walker advances the two Phase-1
    mechanical legs via idempotent conditional writes:
      * <deploy-arc>|merged-main -> deploy-init  (auto-walkable only on ci_triggered projects)
      * code_only|merged-main    -> closed       (reuses stored commit_sha + GitHub compare)
  - The walk honors opt_out, pinned matrix_version, transition_type integrity (409 halt), halts at
    the first attestation / opt-out / gate-fail boundary, and emits Artifact-Genesis records.

Pure-logic units plus integration over _arc_walk_after_advance, mocking the Lifecycle Service
invoke, DynamoDB, EventBridge, and the GitHub compare. Runs standalone or under pytest.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class _FakeDDB:
    def __init__(self, raise_conditional=False):
        self.updates = []
        self.raise_conditional = raise_conditional

    def update_item(self, **kw):
        self.updates.append(kw)
        if self.raise_conditional:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}},
                "UpdateItem",
            )
        return {}


class _FakeEvents:
    def __init__(self):
        self.events = []

    def put_events(self, **kw):
        self.events.append(kw)
        return {"FailedEntryCount": 0}


def _install(ddb=None, events=None, verdicts=None, compare=(True, "ahead"), repo=("NX-2021-L", "enceladus")):
    """Wire the module-level seams. `verdicts` is a callable(payload)->dict driving the Lifecycle
    Service responses; defaults to the happy-path (auto_walkable + allow) for whatever is asked."""
    ddb = ddb or _FakeDDB()
    events = events or _FakeEvents()
    lf._get_ddb = lambda: ddb                                   # type: ignore
    lf._get_events = lambda: events                             # type: ignore
    lf._build_key = lambda p, t, r: {"project_id": {"S": p}, "record_id": {"S": f"{t}#{r}"}}  # type: ignore
    lf._resolve_github_repo = lambda p: repo                    # type: ignore
    lf._arc_walk_compare_commit_to_main = lambda o, r, s: compare  # type: ignore

    def _default_verdicts(payload):
        action = payload.get("action")
        if action == "evaluate_auto_walk":
            return {"auto_walkable": True, "gate_class": "mechanical",
                    "matrix_version": lf.MATRIX_VERSION, "target_status": payload.get("target_status")}
        if action == "validate_transition":
            return {"allow": True, "gate_class": "mechanical", "matrix_version": lf.MATRIX_VERSION}
        return None

    lf._invoke_lifecycle_action = verdicts or _default_verdicts  # type: ignore
    return ddb, events


_SHA = "a" * 40


def _writes(ddb):
    return [u for u in ddb.updates if ":next" in u.get("ExpressionAttributeValues", {})]


# ---------------------------------------------------------------------------
# Pure logic — candidate proposal + flag
# ---------------------------------------------------------------------------
def test_next_candidate_legs():
    assert lf._arc_walk_next_candidate("github_pr_deploy", "merged-main") == "deploy-init"
    assert lf._arc_walk_next_candidate("lambda_deploy", "merged-main") == "deploy-init"
    assert lf._arc_walk_next_candidate("web_deploy", "merged-main") == "deploy-init"
    assert lf._arc_walk_next_candidate("code_only", "merged-main") == "closed"
    # No mechanical leg out of these statuses / types.
    assert lf._arc_walk_next_candidate("github_pr_deploy", "deploy-init") is None
    assert lf._arc_walk_next_candidate("github_pr_deploy", "coding-complete") is None
    assert lf._arc_walk_next_candidate("no_code", "merged-main") is None
    assert lf._arc_walk_next_candidate("github_pr_deploy", "deploy-success") is None


def test_flag_default_off():
    for v in ("ENABLE_ARC_WALKER",):
        os.environ.pop(v, None)
    assert lf._arc_walker_enabled() is False
    os.environ["ENABLE_ARC_WALKER"] = "true"
    try:
        assert lf._arc_walker_enabled() is True
    finally:
        os.environ.pop("ENABLE_ARC_WALKER", None)


# ---------------------------------------------------------------------------
# Happy path — deploy arc: merged-main -> deploy-init (ci_triggered)
# ---------------------------------------------------------------------------
def test_deploy_arc_walks_to_deploy_init():
    ddb, events = _install()
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")

    assert summary["final_status"] == "deploy-init", summary
    assert summary["halted_reason"] == "no_mechanical_gate", summary
    assert len(summary["walked"]) == 1
    step = summary["walked"][0]
    assert (step["from"], step["to"], step["gate_class"]) == ("merged-main", "deploy-init", "mechanical")

    w = _writes(ddb)
    assert len(w) == 1, ddb.updates
    upd = w[0]
    # Idempotent conditional write: advance iff status == expected_prior.
    assert upd["ConditionExpression"] == "#s = :expected"
    assert upd["ExpressionAttributeValues"][":expected"] == {"S": "merged-main"}
    assert upd["ExpressionAttributeValues"][":next"] == {"S": "deploy-init"}
    # write_source attribution = system:arc-walker.
    assert upd["ExpressionAttributeValues"][":wsrc"]["M"]["provider"]["S"] == lf.ARC_WALKER_ACTOR
    # Artifact-Genesis history entry rode the write.
    hist = upd["ExpressionAttributeValues"][":hentry"]["L"]
    assert any("[ARC-WALKER][AUTO-ADVANCE]" in h["M"]["description"]["S"] for h in hist), hist
    # deploy-init must NOT touch closed_count.
    assert "ADD closed_count" not in upd["UpdateExpression"]
    # ARC_WALK telemetry event fired.
    assert len(events.events) == 1
    detail = json.loads(events.events[0]["Entries"][0]["Detail"])
    assert detail["event"] == "arc_walk_advanced"
    assert detail["to_status"] == "deploy-init"
    assert detail["trigger"] == "sync"


# ---------------------------------------------------------------------------
# Happy path — code_only: merged-main -> closed (compare passes)
# ---------------------------------------------------------------------------
def test_code_only_walks_to_closed():
    ddb, events = _install(compare=(True, "identical"))
    item = {"transition_type": "code_only", "checkout_transition_type": "code_only",
            "commit_sha": _SHA}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-Y", item, "merged-main")

    assert summary["final_status"] == "closed", summary
    assert len(summary["walked"]) == 1
    w = _writes(ddb)
    assert len(w) == 1
    upd = w[0]
    assert upd["ExpressionAttributeValues"][":next"] == {"S": "closed"}
    # code_only|closed persists code_on_main_evidence + increments closed_count atomically.
    assert "ADD closed_count :one" in upd["UpdateExpression"]
    coe = upd["ExpressionAttributeValues"][":coe"]["M"]
    assert coe["commit_sha"]["S"] == _SHA
    assert coe["github_verified"]["BOOL"] is True
    assert len(events.events) == 1


def test_code_only_halts_when_not_ancestor():
    ddb, events = _install(compare=(False, "diverged"))
    item = {"transition_type": "code_only", "checkout_transition_type": "code_only",
            "commit_sha": _SHA}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-Y", item, "merged-main")
    assert summary["walked"] == []
    assert summary["halted_reason"].startswith("gate_fail:compare"), summary
    assert _writes(ddb) == []
    assert events.events == []


def test_code_only_halts_when_commit_sha_missing():
    ddb, _ = _install()
    item = {"transition_type": "code_only", "checkout_transition_type": "code_only", "commit_sha": ""}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-Y", item, "merged-main")
    # validate_transition (default happy stub) allows, but the walker's own 40-hex guard halts.
    assert summary["halted_reason"] in ("gate_fail:missing_commit_sha", "gate_fail:INVALID"), summary
    assert _writes(ddb) == []


# ---------------------------------------------------------------------------
# Safety boundaries
# ---------------------------------------------------------------------------
def test_opt_out_latched_halts_before_any_eval_or_write():
    ddb, events = _install()
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy",
            "auto_walk_opt_out": True}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "opt_out_latched"
    assert summary["walked"] == []
    assert ddb.updates == []
    assert events.events == []


def test_opt_out_string_true_coerced():
    ddb, _ = _install()
    item = {"transition_type": "github_pr_deploy", "auto_walk_opt_out": "true"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "opt_out_latched"
    assert ddb.updates == []


def test_transition_type_integrity_409():
    ddb, _ = _install()
    # checkout stamped code_only but the live type is now github_pr_deploy — integrity violation.
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "code_only"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "transition_type_integrity_409"
    assert summary["halt_status"] == 409
    assert ddb.updates == []


def test_manual_deploy_policy_halts(deploy_arc=True):
    # evaluate_auto_walk returns auto_walkable False with the O-2 reason (manual project).
    def _verdicts(payload):
        if payload.get("action") == "evaluate_auto_walk":
            return {"auto_walkable": False, "gate_class": "mechanical",
                    "matrix_version": lf.MATRIX_VERSION,
                    "reason": "deploy-init auto-walk blocked (ruling O-2): deploy_policy='manual'."}
        return {"allow": True}
    ddb, _ = _install(verdicts=_verdicts)
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert "O-2" in summary["halted_reason"], summary
    assert _writes(ddb) == []


def test_matrix_version_mismatch_halts():
    def _verdicts(payload):
        if payload.get("action") == "evaluate_auto_walk":
            return {"auto_walkable": True, "gate_class": "mechanical", "matrix_version": 999}
        return {"allow": True}
    ddb, _ = _install(verdicts=_verdicts)
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "matrix_version_mismatch", summary
    assert summary["service_matrix_version"] == 999
    assert _writes(ddb) == []


def test_subtask_gate_fail_halts():
    def _verdicts(payload):
        if payload.get("action") == "evaluate_auto_walk":
            return {"auto_walkable": True, "gate_class": "mechanical", "matrix_version": lf.MATRIX_VERSION}
        # validate_transition rejects on the subtask gate.
        return {"allow": False, "error": {"code": "SUBTASK_GATE", "status": 400}}
    ddb, _ = _install(verdicts=_verdicts)
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "gate_fail:SUBTASK_GATE", summary
    assert _writes(ddb) == []


def test_no_mechanical_gate_is_noop():
    ddb, events = _install()
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "coding-complete")
    assert summary["halted_reason"] == "no_mechanical_gate"
    assert summary["walked"] == []
    assert ddb.updates == []
    assert events.events == []


def test_lifecycle_service_unavailable_halts():
    ddb, _ = _install(verdicts=lambda payload: None)
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "lifecycle_service_unavailable"
    assert _writes(ddb) == []


def test_concurrent_advance_halts_idempotently():
    ddb = _FakeDDB(raise_conditional=True)
    _install(ddb=ddb)
    item = {"transition_type": "github_pr_deploy", "checkout_transition_type": "github_pr_deploy"}
    summary = lf._arc_walk_after_advance("enceladus", "ENC-TSK-X", item, "merged-main")
    assert summary["halted_reason"] == "concurrent_advance", summary
    assert summary["walked"] == []  # the write was attempted but the conditional guard rejected it.


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
