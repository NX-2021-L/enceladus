"""DVP-TSK-976: the recipes parity test, replay of a recorded governance-arc run (no network, no agent)."""
import copy
import json
from pathlib import Path

import pytest

import recipe_replay as rr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "recipes"
FIXTURE = FIXTURES / "governance-arc.run.json"


@pytest.fixture()
def fx():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_replay_passes_on_the_fixture_with_zero_agent_calls(fx):
    res = rr.replay(fx)
    assert res["ok"], res["failures"]
    assert res["summary"] == "recipes parity: governance-arc replay PASS (3 segments, 3 gates, agent_calls=0)"
    assert res["status"] == "completed" and res["agent_calls"] == 0 and res["run_id"] == "DVP-RUN-001"


def test_sensitive_gates_refuse_the_starter_before_the_human_decision(fx):
    res = rr.replay(fx)
    assert res["starter_refused"] == ["acceptance_gate", "deploy_gate"]


def test_a_tampered_result_order_fails(fx):
    bad = copy.deepcopy(fx)
    results = bad["segments"][0]["results"]
    results[0], results[1] = results[1], results[0]
    res = rr.replay(bad)
    assert not res["ok"] and "replay FAIL" in res["summary"]
    assert any(f.startswith("step_results:") or "recorded result" in f for f in res["failures"])


def test_a_tampered_call_order_fails(fx):
    bad = copy.deepcopy(fx)
    bad["segments"][0]["calls"].reverse()
    res = rr.replay(bad)
    assert not res["ok"] and any("planned calls differ" in f for f in res["failures"])


def test_a_tampered_definition_fails_the_content_hash_pin(fx):
    bad = copy.deepcopy(fx)
    bad["recipe"]["definition"]["steps"][-1]["arguments"]["target_status"] = "open"
    res = rr.replay(bad)
    assert not res["ok"] and any("PIN_MISMATCH" in f for f in res["failures"])


def test_a_missing_gate_decision_leaves_the_run_awaiting_gate(fx):
    bad = copy.deepcopy(fx)
    bad["gates"] = bad["gates"][:-1]                       # no decision recorded for deploy_gate
    res = rr.replay(bad)
    assert res["status"] == "awaiting_gate" and not res["ok"]
    assert res["gates"] == 2 and res["segments"] == 2 and "replay FAIL" in res["summary"]
    assert any(f.startswith("final_state:") for f in res["failures"])


def test_a_denied_sensitive_gate_fails_the_run_instead_of_completing(fx):
    bad = copy.deepcopy(fx)
    bad["gates"][-1]["decision"] = "deny"
    res = rr.replay(bad)
    assert res["status"] == "failed" and not res["ok"]


def test_cli_replays_every_fixture_and_fails_on_a_tampered_one(fx, tmp_path, capsys):
    assert rr.main([str(FIXTURES), "--md", str(tmp_path / "summary.md")]) == 0
    assert "recipes parity: governance-arc replay PASS" in capsys.readouterr().out
    assert "governance-arc replay PASS" in (tmp_path / "summary.md").read_text(encoding="utf-8")
    bad = copy.deepcopy(fx)
    bad["segments"][1]["results"][0]["result"]["commit_complete_id"] = "CCI-TAMPERED"
    (tmp_path / "tampered.run.json").write_text(json.dumps(bad), encoding="utf-8")
    assert rr.main([str(tmp_path / "tampered.run.json")]) == 1
    assert "replay FAIL" in capsys.readouterr().out
    assert rr.main([str(tmp_path / "empty-dir-that-does-not-exist")]) == 1
