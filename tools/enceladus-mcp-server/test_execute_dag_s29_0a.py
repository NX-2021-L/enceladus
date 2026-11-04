"""ENC-TSK-S29-0A: execute pre-validation, DAG scheduling (pool of eight), per-step timing and
fail-closed governance rotation (BRD DOC-E32D0ED08473 ruling D4)."""
import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

from mcp_server.runtime import RUNTIME

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
GOV = "a" * 64
ROTATED = "b" * 64
SLEEP = 0.03


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server():
    name = f"enceladus_server_dag_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "ENCELADUS_MCP_INTERFACE_MODE": "code"}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _call(server, arguments):
    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_set,tracker_log"}, clear=False):
        return json.loads(_run(server.call_tool("execute", arguments))[0].text)


def _step(n, **extra):
    return {"action": "tracker.set", "arguments": {
        "record_id": f"DVP-TSK-{n}", "field": "priority", "value": "P1", "governance_hash": GOV}, **extra}


class _Handler:
    """tracker_set stand-in: records order, concurrency and (optionally) sleeps."""

    def __init__(self, server, sleep=SLEEP, fail_on=None):
        self.server, self.sleep, self.fail_on = server, sleep, fail_on
        self.calls, self.active, self.max_active = [], 0, 0
        server._TOOL_HANDLERS["tracker_set"] = self

    async def __call__(self, args):
        self.calls.append(args["record_id"])
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(self.sleep)
        finally:
            self.active -= 1
        if self.fail_on and args["record_id"] == self.fail_on:
            return self.server._result_text({"success": False, "error": {"code": "boom", "message": "boom"}})
        return self.server._result_text({"success": True})


def test_prevalidation_422_writes_nothing():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    steps = [_step(1), _step(2), {"action": "tracker.set", "arguments": {"record_id": "X"}}, {"action": "nope.nothing"}]
    payload = _call(server, {"steps": steps})
    assert payload["success"] is False and handler.calls == []
    assert payload["problem"]["status"] == 422
    assert {(e["step"], e["pointer"]) for e in payload["problem"]["errors"]} >= {(3, "/governance_hash"), (4, "/action")}
    assert [r["status"] for r in payload["step_results"]][:2] == ["skipped", "skipped"]
    assert payload["committed_prefix"] == []


def test_prevalidation_checks_argument_shape_for_real_steps():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    bad = {"action": "tracker.set", "arguments": {"record_id": 7, "governance_hash": GOV}}
    payload = _call(server, {"steps": [_step(1), bad]})
    assert payload["success"] is False and handler.calls == []
    assert any(e["step"] == 2 and e["pointer"] for e in payload["problem"]["errors"])


def test_graph_errors_unknown_id_index_and_cycle_are_422_and_write_nothing():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    unknown = _call(server, {"steps": [_step(1, id="a"), _step(2, depends_on=["zzz", 9])]})
    pointers = {(e["step"], e["pointer"], e["code"]) for e in unknown["problem"]["errors"]}
    assert pointers == {(2, "/depends_on/0", "unknown_dependency"), (2, "/depends_on/1", "unknown_dependency")}
    cycle = _call(server, {"steps": [_step(1, id="a", depends_on=["b"]), _step(2, id="b", depends_on=["a"]), _step(3)]})
    assert cycle["problem"]["status"] == 422
    assert {e["step"] for e in cycle["problem"]["errors"] if e["code"] == "dependency_cycle"} == {1, 2}
    selfdep = _call(server, {"steps": [_step(1, id="a", depends_on=["a"])]})
    assert selfdep["success"] is False
    assert handler.calls == []


def test_governance_rotation_between_step_5_and_6_commits_five_aborts_five():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    probes = {"n": 0}

    def probe(_max_age):
        probes["n"] += 1
        return GOV if len(handler.calls) < 5 else ROTATED

    RUNTIME.current_governance_hash = probe
    payload = _call(server, {"steps": [_step(n) for n in range(1, 11)]})
    assert payload["success"] is False
    assert payload["committed_prefix"] == [1, 2, 3, 4, 5]
    assert handler.calls == [f"DVP-TSK-{n}" for n in range(1, 6)]  # zero stale acceptances
    statuses = [r["status"] for r in payload["step_results"]]
    assert statuses == ["success"] * 5 + ["aborted"] * 5
    assert payload["step_results"][5]["error_code"] == "governance_hash_stale"
    assert payload["error"]["code"] == "governance_hash_stale"
    assert payload["problem"]["status"] == 409
    assert probes["n"] == 6  # one cheap probe per step until the rotation is seen


def test_governance_rotation_in_dag_mode_aborts_unstarted_steps():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    RUNTIME.current_governance_hash = lambda _a: GOV if len(handler.calls) < 3 else ROTATED
    steps = [_step(1, id="s1", depends_on=[])] + [_step(n, depends_on=[n - 2]) for n in range(2, 8)]
    payload = _call(server, {"steps": steps})
    assert payload["committed_prefix"] == [1, 2, 3]
    assert [r["status"] for r in payload["step_results"]] == ["success"] * 3 + ["aborted"] * 4
    assert len(handler.calls) == 3


def test_matching_hash_probe_passes_and_receives_batch_age():
    server = _load_server()
    _Handler(server, sleep=0)
    ages = []
    RUNTIME.current_governance_hash = lambda age: (ages.append(age), GOV)[1]
    payload = _call(server, {"steps": [_step(1), _step(2)]})
    assert payload["success"] is True and payload["committed_prefix"] == [1, 2]
    assert len(ages) == 2 and ages[1] >= ages[0] >= 0


def test_unreadable_governance_hash_fails_closed():
    server = _load_server()
    handler = _Handler(server, sleep=0)

    def probe(_a):
        raise RuntimeError("governance api down")

    RUNTIME.current_governance_hash = probe
    payload = _call(server, {"steps": [_step(1), _step(2)]})
    assert handler.calls == [] and payload["success"] is False
    assert payload["error"]["code"] == "governance_hash_unverifiable"


def test_twenty_independent_steps_use_the_pool_of_eight():
    server = _load_server()
    handler = _Handler(server)
    payload = _call(server, {"steps": [_step(n, depends_on=[]) for n in range(1, 21)]})
    assert payload["success"] is True and payload["execution_mode"] == "dag"
    assert 2 <= handler.max_active <= 8
    assert handler.max_active == 8
    serial_sum_ms = 20 * SLEEP * 1000
    assert payload["execute_total_ms"] < serial_sum_ms * 0.6
    assert sorted(payload["committed_prefix"]) == list(range(1, 21))
    assert payload["critical_path_ms"] < serial_sum_ms * 0.3
    for r in payload["step_results"]:
        assert r["status"] == "success" and r["error"] is None
        assert r["duration_ms"] >= SLEEP * 1000 * 0.8 and r["started_ms"] >= 0


def test_twenty_chained_steps_keep_order_and_critical_path_is_the_serial_sum():
    server = _load_server()
    handler = _Handler(server)
    steps = [_step(1, id="s1", depends_on=[])] + [_step(n, id=f"s{n}", depends_on=[f"s{n - 1}"]) for n in range(2, 21)]
    payload = _call(server, {"steps": steps})
    assert payload["success"] is True
    assert handler.calls == [f"DVP-TSK-{n}" for n in range(1, 21)] and handler.max_active == 1
    assert payload["committed_prefix"] == list(range(1, 21))
    serial_sum = sum(r["duration_ms"] for r in payload["step_results"])
    assert abs(payload["critical_path_ms"] - serial_sum) <= 2
    assert payload["execute_total_ms"] >= payload["critical_path_ms"]


def test_diamond_graph_runs_branches_concurrently_and_join_waits():
    server = _load_server()
    handler = _Handler(server)
    steps = [_step(1, id="a"), _step(2, id="b", depends_on=["a"]), _step(3, id="c", depends_on=[0]), _step(4, id="d", depends_on=["b", "c"])]
    payload = _call(server, {"steps": steps})
    assert payload["success"] is True and handler.max_active == 2
    res = {r["step"]: r for r in payload["step_results"]}
    assert res[4]["started_ms"] >= max(res[2]["started_ms"] + res[2]["duration_ms"], res[3]["started_ms"] + res[3]["duration_ms"]) - 2
    assert payload["critical_path_ms"] < sum(r["duration_ms"] for r in res.values()) * 0.85


def test_abort_cancels_unstarted_steps_and_continue_lets_independents_proceed():
    server = _load_server()
    handler = _Handler(server, sleep=0, fail_on="DVP-TSK-2")
    steps = [_step(1, id="a"), _step(2, id="b", depends_on=["a"]), _step(3, id="c", depends_on=["b"]), _step(4, id="d", depends_on=["a"])]
    payload = _call(server, {"steps": steps})
    statuses = {r["step"]: r["status"] for r in payload["step_results"]}
    assert statuses[1] == "success" and statuses[2] == "error" and statuses[3] == "aborted"
    assert payload["committed_prefix"][0] == 1

    handler.calls.clear()
    steps[1]["on_error"] = "continue"
    payload = _call(server, {"steps": steps})
    statuses = {r["step"]: r["status"] for r in payload["step_results"]}
    assert statuses == {1: "success", 2: "error", 3: "skipped", 4: "success"}
    assert sorted(payload["committed_prefix"]) == [1, 4]


def test_legacy_batch_without_depends_on_is_strictly_serial_and_unchanged():
    server = _load_server()
    handler = _Handler(server)
    payload = _call(server, {"steps": [_step(n) for n in range(1, 6)]})
    assert payload["success"] is True and payload["execution_mode"] == "serial"
    assert handler.calls == [f"DVP-TSK-{n}" for n in range(1, 6)] and handler.max_active == 1
    assert payload["metadata"]["step_count"] == 5
    assert abs(payload["critical_path_ms"] - sum(r["duration_ms"] for r in payload["step_results"])) <= 1
    assert [r["step"] for r in payload["step_results"]] == [1, 2, 3, 4, 5]


def test_legacy_abort_stops_and_continue_proceeds():
    server = _load_server()
    handler = _Handler(server, sleep=0, fail_on="DVP-TSK-2")
    payload = _call(server, {"steps": [_step(n) for n in range(1, 5)]})
    assert handler.calls == ["DVP-TSK-1", "DVP-TSK-2"]
    assert [r["status"] for r in payload["step_results"]] == ["success", "error", "aborted", "aborted"]
    handler.calls.clear()
    payload = _call(server, {"steps": [_step(1), _step(2, on_error="continue"), _step(3)]})
    assert handler.calls == ["DVP-TSK-1", "DVP-TSK-2", "DVP-TSK-3"]
    assert payload["committed_prefix"] == [1, 3]


def test_dry_run_steps_never_invoke_and_report_dry_run_status():
    server = _load_server()
    handler = _Handler(server, sleep=0)
    RUNTIME.current_governance_hash = lambda _a: ROTATED  # must not even be consulted
    payload = _call(server, {"dry_run": True, "steps": [_step(n, depends_on=[]) for n in range(1, 4)]})
    assert handler.calls == [] and payload["success"] is True
    assert [r["status"] for r in payload["step_results"]] == ["dry_run"] * 3
    assert payload["committed_prefix"] == []
    mixed = _call(server, {"steps": [_step(1), _step(2, dry_run=True), {**_step(3), "arguments": {**_step(3)["arguments"], "dry_run": "true"}}]})
    assert mixed["success"] is False  # step 1 aborts on the rotated hash; dry steps still never invoke
    assert handler.calls == []
