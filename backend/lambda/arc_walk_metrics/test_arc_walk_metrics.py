"""Tests for ENC-TSK-H86 / ENC-FTR-111 Phase 1 (T5) — arc_walk_metrics convergence probe + telemetry.

Pure-function coverage (no AWS): the Phase-1 mechanical-leg model, the convergence-distance probe
(including the opt_out parking exclusion and the ruling O-2 deploy_policy gate), the governed
history-marker parser, the aggregate, and the CloudWatch MetricData builder.

Runs standalone (python3 test_arc_walk_metrics.py) or under pytest.
"""

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as m  # noqa: E402


# ---------------------------------------------------------------------------
# Mechanical-leg model + convergence distance
# ---------------------------------------------------------------------------
def test_mechanical_next_legs():
    assert m._mechanical_next("github_pr_deploy", "merged-main", "ci_triggered") == "deploy-init"
    assert m._mechanical_next("lambda_deploy", "merged-main", "ci_triggered") == "deploy-init"
    assert m._mechanical_next("web_deploy", "merged-main", "ci_triggered") == "deploy-init"
    assert m._mechanical_next("code_only", "merged-main", "manual") == "closed"  # code_only ignores policy
    # ruling O-2: manual deploy policy blocks deploy-init.
    assert m._mechanical_next("github_pr_deploy", "merged-main", "manual") is None
    # No mechanical leg out of these.
    assert m._mechanical_next("github_pr_deploy", "deploy-init", "ci_triggered") is None
    assert m._mechanical_next("github_pr_deploy", "coding-complete", "ci_triggered") is None
    assert m._mechanical_next("no_code", "merged-main", "ci_triggered") is None
    assert m._mechanical_next("github_pr_deploy", "deploy-success", "ci_triggered") is None


def test_convergence_distance():
    # Deploy arc at merged-main on a ci_triggered project is exactly one mechanical gate short.
    assert m.convergence_distance("github_pr_deploy", "merged-main", "ci_triggered", False) == 1
    assert m.convergence_distance("code_only", "merged-main", "ci_triggered", False) == 1
    # Manual project: deploy-init is not mechanical -> 0.
    assert m.convergence_distance("github_pr_deploy", "merged-main", "manual", False) == 0
    # Opt-out parks the record -> excluded from backlog regardless of available leg.
    assert m.convergence_distance("github_pr_deploy", "merged-main", "ci_triggered", True) == 0
    # No mechanical leg available.
    assert m.convergence_distance("github_pr_deploy", "deploy-success", "ci_triggered", False) == 0
    assert m.convergence_distance("no_code", "merged-main", "ci_triggered", False) == 0


# ---------------------------------------------------------------------------
# History marker parsing
# ---------------------------------------------------------------------------
def test_extract_gate_class():
    desc = "[ARC-WALKER][AUTO-ADVANCE] merged-main -> deploy-init (gate_class=mechanical, trigger=sync, matrix_version=1). ..."
    assert m._extract_gate_class(desc) == "mechanical"
    assert m._extract_gate_class("no marker here") is None


def test_parse_history_counts():
    history = [
        {"description": "[ARC-WALKER][AUTO-ADVANCE] merged-main -> deploy-init (gate_class=mechanical, trigger=sync, matrix_version=1)."},
        {"description": "[ARC-WALKER][AUTO-ADVANCE] merged-main -> closed (gate_class=mechanical, trigger=sync)."},
        {"description": "[ARC-WALKER][OPT-OUT-LATCH] auto_walk_opt_out latched true: human io ..."},
        {"description": "[ARC-WALKER][OPT-OUT-SET] auto_walk_opt_out latched true by io."},
        {"description": "[ARC-WALKER][OPT-OUT-CLEAR] auto_walk_opt_out cleared (set false) by io."},
        {"description": "Field 'priority' set to 'P2'"},
    ]
    counts = m.parse_history_arc_walk_counts(history)
    assert counts["auto_advances_by_gate_class"] == {"mechanical": 2}
    assert counts["opt_out_latch"] == 2  # LATCH + SET
    assert counts["opt_out_clear"] == 1


def test_parse_history_empty():
    counts = m.parse_history_arc_walk_counts([])
    assert counts == {"auto_advances_by_gate_class": {}, "opt_out_latch": 0, "opt_out_clear": 0}


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
def _policy_ci(_pid):
    return "ci_triggered"


def test_aggregate_full():
    records = [
        # backlog: deploy arc at merged-main, ci project, not opted out -> 1 gate short.
        {"record_type": "task", "status": "merged-main", "transition_type": "github_pr_deploy",
         "checkout_transition_type": "github_pr_deploy", "auto_walk_opt_out": False,
         "project_id": "enceladus", "history": [
             {"description": "[ARC-WALKER][AUTO-ADVANCE] x -> y (gate_class=mechanical, trigger=sync)."}]},
        # code_only at merged-main -> backlog + 1.
        {"record_type": "task", "status": "merged-main", "transition_type": "code_only",
         "checkout_transition_type": "code_only", "auto_walk_opt_out": False,
         "project_id": "enceladus", "history": []},
        # opted-out at merged-main -> NOT backlog, but counts as latched record.
        {"record_type": "task", "status": "merged-main", "transition_type": "github_pr_deploy",
         "checkout_transition_type": "github_pr_deploy", "auto_walk_opt_out": True,
         "project_id": "enceladus", "history": [
             {"description": "[ARC-WALKER][OPT-OUT-LATCH] latched"},
             {"description": "[ARC-WALKER][OPT-OUT-CLEAR] cleared"}]},
        # not a task -> history still counted, but no convergence contribution.
        {"record_type": "feature", "status": "in-progress", "transition_type": "github_pr_deploy",
         "checkout_transition_type": "", "auto_walk_opt_out": False,
         "project_id": "enceladus", "history": []},
        # task already at deploy-init -> no mechanical leg, no backlog.
        {"record_type": "task", "status": "deploy-init", "transition_type": "github_pr_deploy",
         "checkout_transition_type": "github_pr_deploy", "auto_walk_opt_out": False,
         "project_id": "enceladus", "history": []},
    ]
    agg = m.aggregate(records, _policy_ci)
    assert agg["convergence_backlog_records"] == 2
    assert agg["convergence_gates_short"] == 2
    assert agg["opt_out_latched_records"] == 1
    assert agg["auto_advances_by_gate_class"] == {"mechanical": 1}
    assert agg["opt_out_latch_events"] == 1
    assert agg["opt_out_clear_events"] == 1
    assert agg["tasks_scanned"] == 4
    assert agg["records_scanned"] == 5


def test_aggregate_respects_manual_policy():
    records = [
        {"record_type": "task", "status": "merged-main", "transition_type": "github_pr_deploy",
         "checkout_transition_type": "github_pr_deploy", "auto_walk_opt_out": False,
         "project_id": "manualproj", "history": []},
    ]
    agg = m.aggregate(records, lambda _pid: "manual")
    assert agg["convergence_backlog_records"] == 0
    assert agg["convergence_gates_short"] == 0


# ---------------------------------------------------------------------------
# MetricData builder
# ---------------------------------------------------------------------------
def test_build_metric_data():
    agg = {
        "convergence_backlog_records": 2, "convergence_gates_short": 3,
        "opt_out_latched_records": 1, "opt_out_latch_events": 4, "opt_out_clear_events": 1,
        "auto_advances_by_gate_class": {"mechanical": 5},
    }
    now = datetime(2026, 6, 30, tzinfo=timezone.utc)
    data = m.build_metric_data(agg, "enceladus", now)
    names = {d["MetricName"] for d in data}
    assert {"ConvergenceBacklog", "ConvergenceGatesShort", "OptOutLatchedRecords",
            "OptOutLatchEvents", "OptOutClearEvents", "ArcWalkAutoAdvances"} == names
    backlog = next(d for d in data if d["MetricName"] == "ConvergenceBacklog")
    assert backlog["Value"] == 2.0
    assert backlog["Dimensions"] == [{"Name": "ProjectId", "Value": "enceladus"}]
    adv = next(d for d in data if d["MetricName"] == "ArcWalkAutoAdvances")
    assert {"Name": "GateClass", "Value": "mechanical"} in adv["Dimensions"]
    assert adv["Value"] == 5.0


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
