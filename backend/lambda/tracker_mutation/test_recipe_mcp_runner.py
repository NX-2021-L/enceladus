"""DVP-TSK-968 part C: the run service driving the EnceladusMcpExecutor (mock HTTP, in-memory store)."""
import copy
import json

import recipe_mcp_executor as mx
import recipe_run_service as rrs
from test_recipe_mcp_executor import FakeMcp


class Loose(dict):
    def __missing__(self, key):
        return None


def build(fake):
    exe = mx.EnceladusMcpExecutor(url="https://mcp.test/mcp", api_key="KEY", transport=fake, agent_type_id="ENC-AGT-007")
    store, holder = {}, {}

    def put(project, item, if_absent=False, expect=None):
        store[(project, item.get("record_id") or item.get("run_id"))] = copy.deepcopy(item)
        return True

    def execute(batch):
        run = holder["run"]
        sess = {"session_id": run["runner_session_id"], "sci": run["runner_sci"]} if run.get("runner_session_id") else None
        return mx.execute_batch(batch, exe, sess, lambda c, d: {"ok": False, "error": {"code": "ACTION_NOT_ROUTABLE", "message": "x"}})
    ctx = rrs.RunContext(
        get=lambda p, k: copy.deepcopy(store.get((p, k))), put=put, query=lambda p, prefix: list(holder.get("items", [])),
        mint=lambda p: "DVP-RUN-002", now=lambda: "2026-10-11T00:00:00+00:00", escalate=lambda p, b: (201, {}),
        escalation=lambda p, e: None, execute=execute, governance_hash=exe.governance_hash, server_hash=True,
        session_start=lambda p, r: exe.register_session(p, r["run_id"], r.get("governance_hash_last")),
        session_heartbeat=lambda p, r: exe.heartbeat(p, r["runner_session_id"]),
        session_end=lambda p, r: exe.retire(p, r["runner_session_id"]))
    return ctx, holder


def new_run():
    definition = {"steps": [{"id": "s1", "action": "tracker.create", "arguments": {"title": "t"}},
                            {"id": "s2", "action": "tracker.update", "arguments": {"record_id": "X"}}]}
    run = Loose(run_id="DVP-RUN-001", project_id="devops", status="queued", cursor=0, rev=0, inputs={}, meta={}, outputs=None,
                governance_hash_start="h1", governance_hash_last="h1", telemetry={"writes": 0},
                steps=[{"id": "s1", "status": "pending"}, {"id": "s2", "status": "pending"}])
    return run, definition


def retires(fake):
    return [a for t, a in fake.calls if t == "coordination" and a["action"] == "agent.retire"]


def test_segment_is_health_then_session_then_one_execute_and_session_is_hidden():
    fake = FakeMcp()
    ctx, holder = build(fake)
    run, definition = new_run()
    holder["run"] = run
    assert rrs._segment(ctx, "devops", run, definition, 0, 2, {}) is None
    assert [t for t, _ in fake.calls] == ["search", "coordination", "coordination", "execute"]
    steps = fake.calls[-1][1]["steps"]
    assert [s["action"] for s in steps] == ["tracker.create", "tracker.update"]
    assert all(s["arguments"]["governance_hash"] == "h1" for s in steps)
    assert steps[0]["arguments"]["active_agent_session_id"] == "ENC-SES-RUN1" and steps[0]["arguments"]["sci"] == "SCI-9"
    assert run["cursor"] == 2 and run["steps"][0]["status"] == "ok" and run["steps"][0]["receipt"] == {"record_id": "DVP-TSK-900"}
    assert run["runner_session_id"] == "ENC-SES-RUN1" and run["runner_sci"] == "SCI-9"      # stored on the run item
    shown = json.dumps(rrs.view(run))
    assert "runner_session_id" not in shown and "ENC-SES-RUN1" not in shown and "SCI-9" not in shown


def test_drift_is_computed_server_side_and_blocks_before_any_write():
    fake = FakeMcp(hash="h2")
    ctx, holder = build(fake)
    run, definition = new_run()
    holder["run"] = run
    res = rrs._segment(ctx, "devops", run, definition, 0, 2, {"governance_hash": "h1"})     # caller claims h1: ignored
    assert res[0] == 409 and "GOVERNANCE_DRIFT" in json.dumps(res[1])
    assert [t for t, _ in fake.calls] == ["search"]


def test_unreadable_governance_hash_fails_closed():
    fake = FakeMcp(health_fail=True)
    ctx, holder = build(fake)
    run, definition = new_run()
    holder["run"] = run
    res = rrs._segment(ctx, "devops", run, definition, 0, 2, {"governance_hash": "h1"})
    assert res[0] == 503 and "GOVERNANCE_UNAVAILABLE" in json.dumps(res[1])
    assert [t for t, _ in fake.calls] == ["search"]


def test_partial_failure_takes_the_on_error_abort_path_and_retires_the_session():
    fake = FakeMcp(fail_actions={"tracker.update"})
    ctx, holder = build(fake)
    run, definition = new_run()
    holder["run"] = run
    res = rrs._segment(ctx, "devops", run, definition, 0, 2, {})
    assert run["status"] == "failed"
    assert run["steps"][0]["status"] == "ok" and run["steps"][1]["status"] == "error"
    assert len([1 for t, _ in fake.calls if t == "execute"]) == 1
    assert len(retires(fake)) == 1 and retires(fake)[0]["arguments"]["session_id"] == "ENC-SES-RUN1"


def test_heartbeat_on_awaiting_gate_and_retire_once_at_terminal():
    fake = FakeMcp()
    ctx, holder = build(fake)
    run = Loose(run_id="DVP-RUN-001", project_id="devops", status="awaiting_gate", rev=0, steps=[], telemetry={},
                runner_session_id="ENC-SES-RUN1", runner_sci="SCI-9")
    assert rrs._save(ctx, "devops", run)
    assert fake.calls[-1] == ("coordination", {"action": "escalation.watch", "arguments": {"session_id": "ENC-SES-RUN1", "project_id": "devops"}})
    run["status"] = "completed"
    rrs._save(ctx, "devops", run)
    rrs._save(ctx, "devops", run)
    assert len(retires(fake)) == 1


def test_sweeper_heartbeats_every_awaiting_gate_run():
    fake = FakeMcp()
    ctx, holder = build(fake)
    holder["items"] = [{"run_id": "A", "status": "awaiting_gate", "runner_session_id": "ENC-SES-A"},
                       {"run_id": "B", "status": "running", "runner_session_id": "ENC-SES-B"},
                       {"run_id": "C", "status": "awaiting_gate"}]
    assert rrs._heartbeat_awaiting(ctx, "devops") == 1
    assert fake.calls == [("coordination", {"action": "escalation.watch", "arguments": {"session_id": "ENC-SES-A", "project_id": "devops"}})]
