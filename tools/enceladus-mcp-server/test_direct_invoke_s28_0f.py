"""ENC-TSK-S28-0F: direct qualified (:live) invoke of the write tool Lambdas from the MCP server."""
import asyncio
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

import pytest

HERE = pathlib.Path(__file__).parent
BACKEND = HERE.parent.parent / "backend" / "lambda"
MODULE_PATH = HERE / "server.py"
GOV = "a" * 64
KEY = "test-internal-key"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ENCELADUS_WRITE_AUDIT_STDOUT", "1")
    for name in ("WRITE_TOOL_INVOKE_MODE", "ENVIRONMENT_SUFFIX", "ENV_SUFFIX", "AWS_LAMBDA_FUNCTION_NAME",
                 "TRACKER_TOOL_FUNCTION", "DOCUMENT_TOOL_FUNCTION", "CHECKOUT_TOOL_FUNCTION"):
        monkeypatch.delenv(name, raising=False)


def _load_server():
    name = f"enceladus_server_s28_0f_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", "ENCELADUS_MCP_INTERFACE_MODE": "raw",
           "ENCELADUS_WRITE_AUDIT_STDOUT": "1"}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    module.TRACKER_API_INTERNAL_API_KEY = KEY
    module.TRACKER_API_INTERNAL_API_KEYS = ()
    module.COMMON_INTERNAL_API_KEYS = ()
    module.DOCUMENT_API_INTERNAL_API_KEY = KEY
    return module


def _load_backend(module_dir, unique):
    """Load a backend lambda_function.py (sibling imports resolved from its own dir)."""
    path = BACKEND / module_dir
    for sibling in ("transition_type_matrix", "outline", "sections", "version_seq_util"):
        sys.modules.pop(sibling, None)
    sys.path.insert(0, str(path))
    try:
        with patch.dict(os.environ, {"AWS_DEFAULT_REGION": "us-west-2", "AWS_ACCESS_KEY_ID": "t",
                                     "AWS_SECRET_ACCESS_KEY": "t"}):
            spec = importlib.util.spec_from_file_location(f"{unique}_{uuid.uuid4().hex}", path / "lambda_function.py")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)
            return mod
    finally:
        sys.path.remove(str(path))
        for sibling in ("transition_type_matrix", "outline", "sections", "version_seq_util"):
            sys.modules.pop(sibling, None)


class _Payload:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class FakeLambda:
    """Records invoke() kwargs; replies with the queued {statusCode, body} (or raises)."""

    def __init__(self, replies=None, error=None, function_error=None):
        self.calls = []
        self.replies = list(replies or [])
        self.error = error
        self.function_error = function_error

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        out = {"Payload": _Payload(json.dumps(self.replies.pop(0) if self.replies else
                                              {"statusCode": 200, "body": json.dumps({"success": True})}).encode())}
        if self.function_error:
            out["FunctionError"] = self.function_error
        return out


class _FakeHttp:
    def __init__(self, body=b'{"success": true, "via": "http"}'):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _client_error(code):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "Invoke")


# ---------------------------------------------------------------- mode + names
def test_mode_defaults_gamma_direct_prod_http(monkeypatch):
    s = _load_server()
    assert s._write_tool_invoke_mode() == "http"  # local / prod default
    monkeypatch.setenv("ENVIRONMENT_SUFFIX", "-gamma")
    assert s._write_tool_invoke_mode() == "direct"
    monkeypatch.delenv("ENVIRONMENT_SUFFIX")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "enceladus-mcp-code-gamma")
    assert s._write_tool_invoke_mode() == "direct"
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "enceladus-mcp-code")
    assert s._write_tool_invoke_mode() == "http"
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")  # explicit env wins in prod
    assert s._write_tool_invoke_mode() == "direct"
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "enceladus-mcp-code-gamma")
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "http")  # ...and in gamma
    assert s._write_tool_invoke_mode() == "http"


def test_function_name_defaults_and_overrides(monkeypatch):
    s = _load_server()
    assert [s._tool_function_name(k) for k in ("tracker", "document", "checkout")] == [
        "devops-tracker-mutation-api", "devops-document-api", "enceladus-checkout-service"]
    monkeypatch.setenv("ENVIRONMENT_SUFFIX", "-gamma")
    assert [s._tool_function_name(k) for k in ("tracker", "document", "checkout")] == [
        "devops-tracker-mutation-api-gamma", "devops-document-api-gamma", "enceladus-checkout-service-gamma"]
    monkeypatch.setenv("TRACKER_TOOL_FUNCTION", "custom-tracker")
    assert s._tool_function_name("tracker") == "custom-tracker"


# ---------------------------------------------------------------- event shape
def test_synthesized_event_shape_and_route_parity():
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({"X-Correlation-Id": "corr-1", "X-Enc-Surface": "claude-code",
                               "X-Enc-Client-Tls-New": "0"})
    ev = s._build_tool_event(
        "PATCH", "/api/v1/documents/DOC-ABC", {"title": "t", "correlation_id": "corr-1"},
        {"Accept": "application/json", "X-Coordination-Internal-Key": KEY, "X-Correlation-Id": "corr-1",
         "If-Match": "3"},
        {"include": "content", "skip": None})
    assert ev["version"] == "2.0" and ev["routeKey"] == "$default" and ev["isBase64Encoded"] is False
    assert ev["rawPath"] == "/api/v1/documents/DOC-ABC" and ev["rawQueryString"] == "include=content"
    assert ev["queryStringParameters"] == {"include": "content"}
    assert ev["requestContext"]["http"]["method"] == "PATCH"
    assert ev["requestContext"]["http"]["path"] == "/api/v1/documents/DOC-ABC"
    assert ev["headers"]["x-coordination-internal-key"] == KEY and ev["headers"]["x-correlation-id"] == "corr-1"
    assert ev["headers"]["if-match"] == "3"
    assert ev["headers"]["x-enc-surface"] == "claude-code" and ev["headers"]["x-enc-client-tls-new"] == "0"
    assert isinstance(ev["body"], str) and json.loads(ev["body"]) == {"title": "t", "correlation_id": "corr-1"}
    assert "body" not in s._build_tool_event("GET", "/x", None, {}, None)


def test_event_is_parsed_by_the_real_tool_lambdas():
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({})
    # document_api: method + document_id from rawPath tail, internal key auth
    da = _load_backend("document_api", "da_s28")
    da.DOCUMENT_API_INTERNAL_API_KEYS = (KEY,)
    ev = s._build_tool_event("PATCH", "/api/v1/documents/DOC-ABC123", {"title": "t"},
                             {"X-Coordination-Internal-Key": KEY}, None)
    method, document_id, qs, *_ = da._parse_request(ev)
    assert (method, document_id) == ("PATCH", "DOC-ABC123")
    claims, err = da._authenticate(ev, ["documents:write"])
    assert err is None and claims["auth_mode"] == "internal-key"
    sec = s._build_tool_event("PATCH", "/api/v1/documents/DOC-ABC123/sections", {}, {}, None)
    assert da._parse_request(sec)[1] == "DOC-ABC123" and da._parse_request(sec)[4] is True  # is_sections
    # tracker_mutation: method, routed tool name, internal key auth
    tm = _load_backend("tracker_mutation", "tm_s28")
    tm.COORDINATION_INTERNAL_API_KEYS = (KEY,)
    tev = s._build_tool_event("PATCH", "/api/v1/tracker/enceladus/task/ENC-TSK-1", {"field": "title"},
                              {"X-Coordination-Internal-Key": KEY}, {"q": "1"})
    assert tev["requestContext"]["http"]["method"] == "PATCH"
    assert tm._wa_tool_for("PATCH", tev["rawPath"]) == ("tracker.set", "enceladus", "ENC-TSK-1")
    assert tm._RE_RECORD.match(tev["rawPath"]) and tev["queryStringParameters"] == {"q": "1"}
    claims, err = tm._authenticate(tev, ["tracker:write"])
    assert err is None and claims["auth_mode"] == "internal-key"
    # checkout_service: reads requestContext.http.path
    cs = _load_backend("checkout_service", "cs_s28")
    cs._INTERNAL_API_KEYS = (KEY,)
    cev = s._build_tool_event("POST", "/api/v1/checkout/enceladus/task/ENC-TSK-1/advance", {"x": 1},
                              {"X-Coordination-Internal-Key": KEY}, None)
    parsed = cs._parse_path(cev["requestContext"]["http"]["path"])
    assert parsed["route"] == "task_action" and parsed["action"] == "advance" and parsed["task_id"] == "ENC-TSK-1"
    assert cs._is_authenticated(cev) is True


# ---------------------------------------------------------------- direct invoke
def test_direct_mode_invokes_live_alias_and_never_http(monkeypatch):
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({"X-Correlation-Id": "corr-d"})
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    monkeypatch.setenv("ENVIRONMENT_SUFFIX", "-gamma")
    fake = FakeLambda([{"statusCode": 201, "headers": {}, "body": json.dumps({"success": True, "record_id": "ENC-TSK-9"})}])
    s._lambda_client = fake
    with patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("HTTP must not be used")):
        out = s._tracker_api_request("POST", "/enceladus/task", payload={"title": "x"})
    assert out == {"success": True, "record_id": "ENC-TSK-9"}
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["FunctionName"] == "devops-tracker-mutation-api-gamma:live"
    assert call["InvocationType"] == "RequestResponse"
    event = json.loads(call["Payload"])
    assert event["rawPath"] == "/api/v1/tracker/enceladus/task"
    assert event["requestContext"]["http"]["method"] == "POST"
    assert event["headers"]["x-coordination-internal-key"] == KEY and event["headers"]["x-correlation-id"] == "corr-d"
    assert json.loads(event["body"]) == {"title": "x", "correlation_id": "corr-d"}


def test_document_and_checkout_use_their_own_functions(monkeypatch):
    s = _load_server()
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    fake = FakeLambda()
    s._lambda_client = fake
    with patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("HTTP must not be used")):
        s._document_api_request("PUT", payload={"title": "d"})
        s._document_api_request("PATCH", path="/DOC-1", payload={"x": 1}, extra_headers={"If-Match": "2"})
        s._checkout_api_request("POST", "/enceladus/task/ENC-TSK-1/checkout", payload={"a": 1})
    names = [c["FunctionName"] for c in fake.calls]
    assert names == ["devops-document-api:live", "devops-document-api:live", "enceladus-checkout-service:live"]
    assert all(":live" in n and "$LATEST" not in n for n in names)
    events = [json.loads(c["Payload"]) for c in fake.calls]
    assert events[1]["rawPath"] == "/api/v1/documents/DOC-1" and events[1]["headers"]["if-match"] == "2"
    assert events[2]["requestContext"]["http"]["path"] == "/api/v1/checkout/enceladus/task/ENC-TSK-1/checkout"


def test_error_status_translated_like_http_helper(monkeypatch):
    s = _load_server()
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    body = {"success": False, "error": "GOVERNANCE_STALE: nope",
            "error_envelope": {"code": "GOVERNANCE_STALE", "message": "GOVERNANCE_STALE: nope", "retryable": True,
                               "details": {"current": "b"}}, "current": "b"}
    s._lambda_client = FakeLambda([{"statusCode": 409, "body": json.dumps(body)}])
    direct = s._tracker_api_request("POST", "/enceladus/task", payload={"t": 1})
    assert direct == s._normalize_legacy_error_payload(body, 409)
    assert direct["error_envelope"]["code"] == "GOVERNANCE_STALE"


def test_reads_and_http_mode_stay_on_http(monkeypatch):
    s = _load_server()
    fake = FakeLambda()
    s._lambda_client = fake
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    with patch.object(s.urllib.request, "urlopen", return_value=_FakeHttp()) as uo:
        assert s._tracker_api_request("GET", "/enceladus/task/ENC-TSK-1")["via"] == "http"
    assert uo.call_count == 1 and fake.calls == []
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "http")
    with patch.object(s.urllib.request, "urlopen", return_value=_FakeHttp()) as uo:
        assert s._tracker_api_request("POST", "/enceladus/task", payload={})["via"] == "http"
    assert uo.call_count == 1 and fake.calls == []


# ---------------------------------------------------------------- fallback
@pytest.mark.parametrize("fake_factory,reason", [
    (lambda: FakeLambda(error=_client_error("ResourceNotFoundException")), "ResourceNotFoundException"),
    (lambda: FakeLambda(error=_client_error("TooManyRequestsException")), "TooManyRequestsException"),
    (lambda: FakeLambda(error=_client_error("AccessDeniedException")), "AccessDeniedException"),
    (lambda: FakeLambda(error=_client_error("EC2ThrottledException")), "EC2ThrottledException"),
])
def test_invoke_error_falls_back_to_http_once_and_logs(monkeypatch, fake_factory, reason):
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({"X-Correlation-Id": "corr-f"})
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    fake = fake_factory()
    s._lambda_client = fake
    buf = io.StringIO()
    with patch.object(s.urllib.request, "urlopen", return_value=_FakeHttp()) as uo, contextlib.redirect_stdout(buf):
        out = s._tracker_api_request("POST", "/enceladus/task", payload={"t": 1})
    assert out["via"] == "http"
    assert len(fake.calls) == 1 and uo.call_count == 1  # one direct attempt, one HTTP fallback
    notes = [json.loads(l.split(" ", 1)[1]) for l in buf.getvalue().splitlines() if l.startswith("[WRITE-AUDIT] ")]
    assert len(notes) == 1
    assert notes[0]["invoke_mode"] == "direct_fallback" and notes[0]["fallback_reason"] == reason
    assert notes[0]["attempt_outcome"] == "error" and notes[0]["success"] is False
    assert notes[0]["audit_kind"] == "invoke_fallback"
    assert notes[0]["correlation_id"] == "corr-f" and notes[0]["tool_function"] == "devops-tracker-mutation-api:live"


def test_function_error_never_falls_back_and_returns_tool_envelope(monkeypatch):
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({})
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    tool_env = {"success": False, "error": "boom", "error_envelope": {
        "code": "UPSTREAM_ERROR", "message": "boom", "retryable": True, "details": {}}}
    for reply in (tool_env, {"errorType": "KeyError", "errorMessage": "'x'"}):
        fake = FakeLambda([reply], function_error="Unhandled")
        s._lambda_client = fake
        buf = io.StringIO()

        async def stub(args):
            return s._result_text(s._tracker_api_request("POST", "/enceladus/task", payload={"t": 1}))

        with patch.dict(s._TOOL_HANDLERS, {"tracker_create": stub}), \
                patch.object(s, "_current_governance_hash_for_validation", return_value=GOV), \
                patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("a write must not run twice")), \
                contextlib.redirect_stdout(buf):
            _run(s.call_tool("tracker_create", {"project_id": "enceladus", "governance_hash": GOV}))
        assert len(fake.calls) == 1
        lines = [json.loads(l.split(" ", 1)[1]) for l in buf.getvalue().splitlines() if l.startswith("[WRITE-AUDIT] ")]
        assert len(lines) == 1 and "audit_kind" not in lines[0]  # no fallback note
        assert lines[0]["invoke_mode"] == "direct" and lines[0]["attempt_outcome"] == "error"
        assert lines[0]["success"] is False
    s._lambda_client = FakeLambda([tool_env], function_error="Unhandled")
    with patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("no HTTP")):
        got = s._tracker_api_request("POST", "/enceladus/task", payload={})
    assert got["error_envelope"]["code"] == "UPSTREAM_ERROR" and got["error_envelope"]["retryable"] is True
    s._lambda_client = FakeLambda([{"errorType": "KeyError", "errorMessage": "'x'"}], function_error="Unhandled")
    with patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("no HTTP")):
        got = s._tracker_api_request("POST", "/enceladus/task", payload={})
    assert got["error_envelope"]["code"] == "INTERNAL_ERROR" and got["error_envelope"]["retryable"] is False


def test_read_timeout_is_not_retried_over_http(monkeypatch):
    from botocore.exceptions import ReadTimeoutError
    s = _load_server()
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    s._lambda_client = FakeLambda(error=ReadTimeoutError(endpoint_url="https://lambda"))
    with patch.object(s.urllib.request, "urlopen", side_effect=AssertionError("must not double-write")):
        out = s._tracker_api_request("POST", "/enceladus/task", payload={"t": 1})
    assert out["success"] is False and out["error"]["code"] == "UPSTREAM_ERROR" and out["error"]["retryable"] is True


def test_auth_key_retry_walks_candidates(monkeypatch):
    s = _load_server()
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", "direct")
    s.TRACKER_API_INTERNAL_API_KEYS = ("second-key",)
    fake = FakeLambda([{"statusCode": 403, "body": "{}"}, {"statusCode": 200, "body": '{"success": true}'}])
    s._lambda_client = fake
    assert s._tracker_api_request("POST", "/enceladus/task", payload={})["success"] is True
    keys = [json.loads(c["Payload"])["headers"]["x-coordination-internal-key"] for c in fake.calls]
    assert keys == [KEY, "second-key"]


# ---------------------------------------------------------------- audit line
def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.mark.parametrize("mode,fake_factory,expect_mode,expect_hops", [
    ("direct", lambda: FakeLambda(), "direct", 1),
    ("direct", lambda: FakeLambda(error=_client_error("ResourceNotFoundException")), "direct_fallback", 2),
    ("http", lambda: FakeLambda(), "http", 2),
])
def test_audit_line_records_invoke_mode_and_hops(monkeypatch, mode, fake_factory, expect_mode, expect_hops):
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({})
    monkeypatch.setenv("WRITE_TOOL_INVOKE_MODE", mode)
    s._lambda_client = fake_factory()

    async def stub(args):
        return s._result_text(s._tracker_api_request("POST", "/enceladus/task", payload={"title": "x"}))

    buf = io.StringIO()
    with patch.dict(s._TOOL_HANDLERS, {"tracker_create": stub}), \
            patch.object(s, "_current_governance_hash_for_validation", return_value=GOV), \
            patch.object(s.urllib.request, "urlopen", return_value=_FakeHttp()), \
            contextlib.redirect_stdout(buf):
        _run(s.call_tool("tracker_create", {"project_id": "enceladus", "governance_hash": GOV}))
    lines = [json.loads(l.split(" ", 1)[1]) for l in buf.getvalue().splitlines()
             if l.startswith("[WRITE-AUDIT] ") and "audit_kind" not in l]
    assert len(lines) == 1
    assert lines[0]["invoke_mode"] == expect_mode and lines[0]["hops"] == expect_hops
    assert isinstance(lines[0]["t_invoke_ms"], int)


def test_audit_line_invoke_mode_none_when_no_tool_request():
    s = _load_server()
    s._begin_request_context(None)
    s._absorb_request_headers({})
    fields = s._build_write_audit_fields("tracker_set", {}, None, server_total_ms=1, t_route_ms=0, state={})
    assert fields["invoke_mode"] == "none" and fields["hops"] == 1
