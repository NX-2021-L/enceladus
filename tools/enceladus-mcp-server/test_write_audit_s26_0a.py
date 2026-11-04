"""ENC-TSK-S26-0A (part 1): [WRITE-AUDIT] lines, correlation_id propagation, EMF envelope."""
import asyncio
import importlib.util
import io
import json
import os
import pathlib
import sys
import uuid
import pytest
from contextlib import redirect_stdout
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
GOV = "a" * 64
REQUIRED_KEYS = {
    "correlation_id", "request_id", "session_id", "tool", "project_id", "record_id", "idempotency_key",
    "execute_step_index", "surface", "server_total_ms", "cold_start", "init_ms", "hops", "t_route_ms",
    "t_governance_ms", "governance_cache_hit", "governance_hash_in", "governance_hash_verified",
    "t_invoke_ms", "memory_mb", "runtime", "arch", "function_version",
    "attempt_outcome", "success", "dry_run",
}


@pytest.fixture(autouse=True)
def _audit_to_stdout(monkeypatch):
    monkeypatch.setenv("ENCELADUS_WRITE_AUDIT_STDOUT", "1")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server(mode="code"):
    name = f"enceladus_server_write_audit_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "ENCELADUS_MCP_INTERFACE_MODE": mode,
           "ENCELADUS_WRITE_AUDIT_STDOUT": "1"}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _audit_lines(text):
    return [json.loads(l.split(" ", 1)[1]) for l in text.splitlines() if l.startswith("[WRITE-AUDIT] ")]


def _emf_lines(text):
    return [json.loads(l) for l in text.splitlines() if l.startswith("{") and '"_aws"' in l]


class _FakeResp:
    def __init__(self):
        self.status = 200

    def read(self):
        return b'{"success": true}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_direct_write_tool_emits_audit_line_and_emf():
    server = _load_server("raw")
    server._begin_request_context(type("Ctx", (), {"aws_request_id": "req-123"})())
    server._absorb_request_headers({
        "X-Correlation-Id": "corr-abc", "X-Enc-T-Client-Start": "1730000000000",
        "X-Enc-Client-Session-Reused": "1", "X-Enc-Client-Session-Init-Ms": "12",
        "X-Enc-Client-Tls-New": "0", "X-Enc-Client-Serialize-Ms": "3", "X-Enc-Surface": "claude-code",
    })

    async def stub(args):
        server._require_governance_hash(args)
        server._note_invoke(5)
        return server._result_text({"success": True})

    buf = io.StringIO()
    with patch.dict(server._TOOL_HANDLERS, {"tracker_set": stub}), \
            patch.object(server, "_current_governance_hash_for_validation", return_value=GOV), \
            redirect_stdout(buf):
        _run(server.call_tool("tracker_set", {
            "project_id": "enceladus", "record_id": "ENC-TSK-1", "governance_hash": GOV,
            "active_agent_session_id": "ENC-SES-X", "idempotency_key": "idem-1"}))
    out = buf.getvalue()
    lines = _audit_lines(out)
    assert len(lines) == 1
    line = lines[0]
    assert REQUIRED_KEYS <= set(line)
    assert line["correlation_id"] == "corr-abc" and line["request_id"] == "req-123"
    assert line["tool"] == "tracker_set" and line["record_id"] == "ENC-TSK-1"
    assert line["session_id"] == "ENC-SES-X" and line["idempotency_key"] == "idem-1"
    assert line["execute_step_index"] is None and line["hops"] == 1
    assert line["governance_hash_in"] == GOV[:16] and line["governance_hash_verified"] is True
    assert line["cold_start"] is True and isinstance(line["init_ms"], int)
    assert line["t_invoke_ms"] == 5
    assert line["attempt_outcome"] == "success" and line["success"] is True and line["dry_run"] is False
    # client passthrough (surface header overrides the "mcp_server" default)
    assert line["t_client_start"] == "1730000000000" and line["client_session_reused"] == "1"
    assert line["client_session_init_ms"] == "12" and line["client_tls_new"] == "0"
    assert line["client_serialize_ms"] == "3" and line["surface"] == "claude-code"

    emf = _emf_lines(out)
    assert len(emf) == 1
    directive = emf[0]["_aws"]["CloudWatchMetrics"][0]
    assert directive["Namespace"] == "Enceladus/WritePath"
    assert directive["Dimensions"] == [["tool"]]
    assert {m["Name"]: m["Unit"] for m in directive["Metrics"]} == {"server_total_ms": "Milliseconds", "cold_start": "Count"}
    assert emf[0]["tool"] == "tracker_set" and emf[0]["cold_start"] == 1
    assert isinstance(emf[0]["server_total_ms"], int) and isinstance(emf[0]["_aws"]["Timestamp"], int)


def test_every_execute_step_is_audited_with_step_index():
    server = _load_server()
    server._begin_request_context(None)
    server._absorb_request_headers({})

    async def stub(args):
        return server._result_text({"success": True})

    buf = io.StringIO()
    steps = [
        {"action": "tracker.set", "arguments": {"record_id": "DVP-TSK-1", "field": "priority", "value": "P1", "governance_hash": GOV}},
        {"action": "tracker.log", "arguments": {"record_id": "DVP-TSK-1", "description": "n", "governance_hash": GOV}},
    ]
    with patch.dict(os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "tracker_set,tracker_log"}), \
            patch.dict(server._TOOL_HANDLERS, {"tracker_set": stub, "tracker_log": stub}), \
            redirect_stdout(buf):
        _run(server.call_tool("execute", {"steps": steps}))
    lines = _audit_lines(buf.getvalue())
    assert [(l["tool"], l["execute_step_index"]) for l in lines] == [("tracker_set", 1), ("tracker_log", 2)]


def test_correlation_id_propagates_to_all_three_tool_lambda_helpers():
    server = _load_server()
    server._begin_request_context(None)
    server._absorb_request_headers({"x-correlation-id": "corr-xyz"})
    seen = []

    def fake_urlopen(req, timeout=None, context=None):
        seen.append(req)
        return _FakeResp()

    with patch.object(server.urllib.request, "urlopen", fake_urlopen):
        server._tracker_api_request("POST", "/enceladus/task", {"title": "t"})
        server._document_api_request("PATCH", "/DOC-1", {"x": 1})
        server._checkout_api_request("POST", "/checkout", {"task_id": "ENC-TSK-1"})
        server._tracker_api_request("GET", "/enceladus/task/ENC-TSK-1")
    assert len(seen) == 4
    for req in seen:
        assert req.get_header("X-correlation-id") == "corr-xyz"
    for req in seen[:3]:
        assert json.loads(req.data)["correlation_id"] == "corr-xyz"
    assert seen[3].data is None


def test_correlation_id_minted_when_header_absent():
    server = _load_server()
    server._begin_request_context(None)
    server._absorb_request_headers({})
    cid = server._current_correlation_id()
    assert cid and server._current_correlation_id() == cid
    uuid.UUID(cid)
