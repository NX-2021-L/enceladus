"""DVP-TSK-968 part C: EnceladusMcpExecutor against a mock MCP endpoint (no network)."""
import json

import recipe_mcp_executor as mx


class FakeMcp:
    """Mock streamable-HTTP MCP endpoint; records (url, headers, rpc message) and (tool, arguments)."""

    def __init__(self, hash="h1", fail_actions=(), health_fail=False, http_status=200):
        self.hash, self.fail_actions, self.health_fail, self.http_status = hash, set(fail_actions), health_fail, http_status
        self.requests, self.calls = [], []

    def __call__(self, url, headers, body, timeout=60):
        msg = json.loads(body)
        self.requests.append((url, headers, msg))
        tool, args = msg["params"]["name"], msg["params"]["arguments"]
        self.calls.append((tool, args))
        if self.http_status != 200 or (tool == "search" and self.health_fail):
            return (self.http_status if self.http_status != 200 else 500), b"boom"
        res = {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": json.dumps(self.handle(tool, args))}]}}
        return 200, json.dumps(res).encode()

    def handle(self, tool, args):
        if tool == "search":
            return {"success": True, "connection_health": {"governance_hash": self.hash}}
        if tool == "coordination":
            return {"success": True, "session_id": "ENC-SES-RUN1"} if args["action"] == "agent.register" else \
                {"success": True, "sci": "SCI-9"} if args["action"] == "agent.claim" else {"success": True}
        out = []
        for i, st in enumerate(args["steps"]):
            if st["action"] in self.fail_actions:
                out.append({"step": i, "action": st["action"], "status": "error", "error": "Underlying tool returned an error",
                            "result": {"success": False, "error": {"code": "nope", "message": "refused"}}})
                if st.get("on_error") != "continue":
                    break
                continue
            out.append({"step": i, "action": st["action"], "status": "success", "result": {"success": True, "record_id": f"DVP-TSK-{900 + i}"}})
        return {"success": all(o["status"] == "success" for o in out), "step_results": out}


def make(fake=None, **kw):
    fake = fake or FakeMcp(**kw)
    return mx.EnceladusMcpExecutor(url="https://mcp.test/mcp", api_key="KEY-123", transport=fake, agent_type_id="ENC-AGT-007"), fake


def never_local(call, dry):
    raise AssertionError("governed steps must not run in-process: " + str(call.get("action")))


def call(step_id, action, args=None, **kw):
    return dict({"step_id": step_id, "surface": "enceladus", "action": action, "arguments": args or {}, "dry_run": False, "on_error": "abort"}, **kw)


def test_bearer_stateless_transport_and_governance_hash():
    exe, fake = make()
    assert exe.governance_hash() == "h1"
    url, headers, msg = fake.requests[0]
    assert url == "https://mcp.test/mcp" and headers["Authorization"] == "Bearer KEY-123"
    assert msg["method"] == "tools/call" and msg["params"]["name"] == "search"
    assert msg["params"]["arguments"] == {"action": "system.connection_health"}
    assert "Mcp-Session-Id" not in headers and len(fake.requests) == 1          # stateless: no initialize
    fake.hash = "h2"
    assert exe.governance_hash() == "h2"                                          # re-read every call, never cached
    assert make(health_fail=True)[0].governance_hash() is None


def test_segment_is_one_execute_with_hash_and_session_injected():
    exe, fake = make()
    batch = {"run_id": "DVP-RUN-001", "governance_hash": "h1", "calls": [
        call("s1", "tracker.create", {"title": "t"}), call("s2", "tracker.get", {"record_id": "X"})]}
    out = mx.execute_batch(batch, exe, {"session_id": "ENC-SES-RUN1", "sci": "SCI-9"}, never_local)["results"]
    assert [t for t, _ in fake.calls] == ["execute"]
    steps = fake.calls[0][1]["steps"]
    assert steps[0]["arguments"]["governance_hash"] == "h1" and steps[1]["arguments"]["governance_hash"] == "h1"
    assert steps[0]["arguments"]["active_agent_session_id"] == "ENC-SES-RUN1"
    assert steps[0]["arguments"]["sci"] == "SCI-9" and steps[0]["arguments"]["provider"] == "recipe_runner"
    assert "active_agent_session_id" not in steps[1]["arguments"]                 # reads carry no session args
    assert [r["ok"] for r in out] == [True, True] and out[0]["receipt"] == {"record_id": "DVP-TSK-900"}
    assert [r["step_id"] for r in out] == ["s1", "s2"]


def test_partial_failure_stops_the_batch_and_maps_the_error():
    exe, fake = make(fail_actions={"tracker.update"})
    batch = {"run_id": "DVP-RUN-001", "governance_hash": "h1", "calls": [
        call("s1", "tracker.create"), call("s2", "tracker.update"), call("s3", "tracker.create")]}
    out = mx.execute_batch(batch, exe, None, never_local)["results"]
    assert [r["ok"] for r in out] == [True, False] and out[1]["error"]["code"] == "nope"
    assert "refused" in out[1]["error"]["message"]
    assert len(fake.calls) == 1


def test_on_error_continue_keeps_going():
    exe, fake = make(fail_actions={"tracker.update"})
    batch = {"run_id": "R", "governance_hash": "h1", "calls": [
        call("s1", "tracker.update", on_error="continue"), call("s2", "tracker.create")]}
    out = mx.execute_batch(batch, exe, None, never_local)["results"]
    assert [r["ok"] for r in out] == [False, True]


def test_recipe_actions_and_surfaces_stay_in_process():
    exe, fake = make()
    seen = []

    def local(c, dry):
        seen.append(c["action"])
        return {"ok": True, "result": {"recipe_id": "DVP-REC-001"}, "receipt": {"recipe_id": "DVP-REC-001"}}
    batch = {"run_id": "R", "governance_hash": "h1", "calls": [
        call("s1", "recipe.get", {"recipe_id": "DVP-REC-001"}), call("s2", "tracker.create"),
        call("s3", "x.y", surface="io-finance")]}
    out = mx.execute_batch(batch, exe, None, local)["results"]
    assert seen == ["recipe.get", "x.y"] and [r["step_id"] for r in out] == ["s1", "s2", "s3"]
    assert [t for t, _ in fake.calls] == ["execute"] and len(fake.calls[0][1]["steps"]) == 1


def test_mcp_failure_becomes_a_step_error():
    exe, _ = make(http_status=502)
    out = mx.execute_batch({"run_id": "R", "governance_hash": "h1", "calls": [call("s1", "tracker.create")]}, exe, None, never_local)["results"]
    assert out[0]["ok"] is False and out[0]["error"]["code"] == "MCP_HTTP_502" and out[0]["step_id"] == "s1"


def test_session_register_claim_heartbeat_retire():
    exe, fake = make()
    assert exe.register_session("devops", "DVP-RUN-001") == {"session_id": "ENC-SES-RUN1", "sci": "SCI-9"}
    assert fake.calls[0] == ("coordination", {"action": "agent.register", "arguments": {
        "agent_type_id": "ENC-AGT-007", "runtime": "recipe_runner", "project_id": "devops", "purpose": "recipe run DVP-RUN-001"}})
    assert fake.calls[1][0] == "search"  # governance_hash fetched for agent.claim
    assert fake.calls[2] == ("coordination", {"action": "agent.claim", "arguments": {"session_id": "ENC-SES-RUN1", "governance_hash": fake.hash}})
    exe.heartbeat("devops", "ENC-SES-RUN1")
    exe.retire("devops", "ENC-SES-RUN1")
    assert fake.calls[3] == ("coordination", {"action": "escalation.watch", "arguments": {"session_id": "ENC-SES-RUN1", "project_id": "devops"}})
    assert fake.calls[3][1]["action"] == "agent.retire"
