"""ENC-TSK-S28-0B: long-lived transport -- keep-alive reuse, reconnect-once,
one MCP handshake per process, and truthful tls/session timing. Offline: a fake
http.client connection stands in for HTTPSConnection."""

import http.client
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from elr_lib import client_timing as ct
from elr_lib import config as elr_config
from elr_lib import keepalive as ka
from elr_lib import transport as elr_transport


class _FakeResp:
    def __init__(self, status, body, headers=None, will_close=False):
        self.status = status
        self._body = body
        self._headers = headers or {"Content-Type": "application/json"}
        self.will_close = will_close

    def read(self):
        return self._body

    def getheaders(self):
        return list(self._headers.items())


class _Script:
    """Shared script for all fake connections: a list of outcomes (a
    _FakeResp, or an exception instance to raise from getresponse)."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []  # (conn_id, method, target, headers)
        self.created = 0


class _FakeConn:
    def __init__(self, script):
        script.created += 1
        self.id = script.created
        self.script = script
        self.sock = None
        self.timeout = None
        self.closed = False

    def request(self, method, target, body=None, headers=None):
        self.sock = object()  # connected after first request
        self.script.requests.append((self.id, method, target, dict(headers or {}), body))

    def getresponse(self):
        out = self.script.outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return out

    def close(self):
        self.closed = True
        self.sock = None


def _factory(script):
    return lambda scheme, host, port, timeout, ctx: _FakeConn(script)


def _pool(script):
    pool = ka.KeepAlivePool(None, connection_factory=_factory(script))
    # fake sockets are plain objects: never report them as stale
    return pool


def _json_resp(obj, **kw):
    return _FakeResp(200, json.dumps(obj).encode(), **kw)


class _Base(unittest.TestCase):
    def setUp(self):
        ct.reset_process_context()
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self._tmp.name, "ledger.jsonl")
        env = patch.dict(os.environ, {"ELR_LONG_LIVED": "1", "ELR_LEDGER": "1", "ELR_LEDGER_PATH": self.ledger})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self._tmp.cleanup)
        stale = patch.object(ka, "_looks_stale", return_value=False)
        stale.start()
        self.addCleanup(stale.stop)

    def rows(self):
        with open(self.ledger, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


class PoolTests(_Base):
    def test_sequential_requests_share_one_connection(self):
        script = _Script([_json_resp({"n": 1}), _json_resp({"n": 2}), _json_resp({"n": 3})])
        pool = _pool(script)
        flags = []
        for _ in range(3):
            r = pool.request("GET", "https://h.example/a?x=1", {}, None, timeout=5, idempotent=True,
                             on_connection=flags.append)
            self.assertEqual(r.status, 200)
        self.assertEqual(script.created, 1)
        self.assertEqual(flags, [True, False, False])
        self.assertEqual({rq[0] for rq in script.requests}, {1})
        self.assertEqual(script.requests[0][2], "/a?x=1")

    def test_reconnect_once_and_retry_idempotent(self):
        script = _Script([_json_resp({"n": 1}), http.client.RemoteDisconnected("gone"), _json_resp({"n": 2})])
        pool = _pool(script)
        pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)
        flags = []
        r = pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True,
                         on_connection=flags.append)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.reconnected)
        self.assertTrue(r.opened_new)
        self.assertEqual(script.created, 2)
        self.assertEqual(flags, [False, True])  # reused attempt dropped, replay on a new connection

    def test_non_idempotent_is_not_replayed(self):
        script = _Script([_json_resp({"n": 1}), ConnectionResetError("reset"), _json_resp({"n": 2})])
        pool = _pool(script)
        pool.request("POST", "https://h.example/w", {}, b"{}", timeout=5, idempotent=False)
        with self.assertRaises(ConnectionResetError):
            pool.request("POST", "https://h.example/w", {}, b"{}", timeout=5, idempotent=False)
        self.assertEqual(len(script.requests), 2)  # the dropped write was sent once, never replayed

    def test_only_one_retry(self):
        script = _Script([_json_resp({}), http.client.BadStatusLine("x"), http.client.BadStatusLine("y")])
        pool = _pool(script)
        pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)
        with self.assertRaises(http.client.BadStatusLine):
            pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)

    def test_fresh_connection_failure_is_not_retried(self):
        script = _Script([ConnectionResetError("boom"), _json_resp({})])
        pool = _pool(script)
        with self.assertRaises(ConnectionResetError):
            pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)
        self.assertEqual(script.created, 1)

    def test_will_close_response_is_not_pooled(self):
        script = _Script([_json_resp({}, will_close=True), _json_resp({})])
        pool = _pool(script)
        pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)
        pool.request("GET", "https://h.example/a", {}, None, timeout=5, idempotent=True)
        self.assertEqual(script.created, 2)


class InternalClientKeepAliveTests(_Base):
    def _client(self, script):
        client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)
        client._pool = _pool(script)
        return client

    def test_tls_new_only_on_first_call_and_status_contract(self):
        script = _Script([_json_resp({"a": 1}), _json_resp({"b": 2}), _FakeResp(404, b'{"error":"nf"}')])
        client = self._client(script)
        self.assertEqual(client.request("GET", "tracker", "/x"), (200, {"a": 1}))
        self.assertEqual(client.request("GET", "tracker", "/y"), (200, {"b": 2}))
        self.assertEqual(client.request("GET", "tracker", "/z"), (404, {"error": "nf"}))
        self.assertEqual(script.created, 1)
        tls = [rq[3][ct.H_TLS_NEW] for rq in script.requests]
        self.assertEqual(tls, ["1", "0", "0"])
        self.assertEqual([r["client_tls_new"] for r in self.rows()], [True, False, False])
        self.assertEqual([r["client_session_reused"] for r in self.rows()], [False, True, True])

    def test_get_5xx_retry_once_over_pool(self):
        script = _Script([_FakeResp(502, b'{"error":"bg"}'), _json_resp({"ok": True})])
        client = self._client(script)
        self.assertEqual(client.request("GET", "tracker", "/x"), (200, {"ok": True}))
        self.assertEqual(script.created, 1)

    def test_write_not_replayed_after_drop(self):
        script = _Script([_json_resp({"ok": 1}), http.client.RemoteDisconnected("gone"), _json_resp({"ok": 2})])
        client = self._client(script)
        client.request("GET", "tracker", "/x")
        status, body = client.request("POST", "tracker", "/w", payload={"k": "v"})
        self.assertEqual(status, 0)
        self.assertIn("unreachable", body["error"])
        self.assertEqual(len(script.requests), 2)

    def test_long_lived_off_uses_urllib(self):
        client = elr_transport.InternalClient(elr_config.InternalProfileConfig(), timeout=5)
        with patch.dict(os.environ, {"ELR_LONG_LIVED": "0"}):
            self.assertIsNone(client._get_pool())


class McpKeepAliveTests(_Base):
    def _tool_body(self, obj):
        env = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(obj)}],
                                                       "isError": False}}
        return json.dumps(env).encode()

    def test_one_handshake_per_process_and_session_reuse(self):
        sid = {"Content-Type": "application/json", "Mcp-Session-Id": "sess-1"}
        script = _Script([
            _FakeResp(200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode(), sid),  # initialize
            _FakeResp(202, b"", {}),  # notifications/initialized
            _FakeResp(200, self._tool_body({"n": 1})),
            _FakeResp(200, self._tool_body({"n": 2})),
            _FakeResp(200, self._tool_body({"n": 3})),
        ])
        with patch.dict(os.environ, {"ENCELADUS_MCP_BEARER_TOKEN": "tok-not-real"}):
            client = elr_transport.McpHttpClient(elr_config.McpHttpProfileConfig(), timeout=5)
            client._pool = _pool(script)
            results = [client.call_tool("search", {"i": i}) for i in range(3)]
        self.assertEqual([r.result for r in results], [{"n": 1}, {"n": 2}, {"n": 3}])
        methods = [json.loads(rq[4])["method"] for rq in script.requests]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/call", "tools/call", "tools/call"])
        self.assertEqual(client.handshakes_run, 1)
        self.assertEqual(script.created, 1)
        # session id minted by initialize is sent on every later call
        for rq in script.requests[1:]:
            self.assertEqual(rq[3]["Mcp-Session-Id"], "sess-1")
        calls = [r for r in self.rows() if r["verb"] == "tools/call"]
        self.assertEqual([r["client_session_reused"] for r in calls], [False, True, True])
        self.assertEqual([r["client_tls_new"] for r in self.rows()], [True, False, False, False, False])
        self.assertGreaterEqual(calls[0]["client_session_init_ms"], 0)
        self.assertEqual(calls[1]["client_session_init_ms"], 0)
        self.assertEqual(calls[2]["client_session_init_ms"], 0)

    def test_manual_handshake_is_not_repeated(self):
        script = _Script([
            _json_resp({"jsonrpc": "2.0", "id": 1, "result": {}}),
            _FakeResp(202, b"", {}),
            _FakeResp(200, self._tool_body({"ok": 1})),
        ])
        client = elr_transport.McpHttpClient(elr_config.McpHttpProfileConfig(), timeout=5)
        client._pool = _pool(script)
        client.initialize()
        client.notify_initialized()
        client.call_tool("search", {})
        self.assertEqual(len(script.requests), 3)

    def test_tools_call_replayed_after_drop_only_with_idempotency_key(self):
        def mk():
            return _Script([
                _json_resp({"jsonrpc": "2.0", "id": 1, "result": {}}),
                _FakeResp(202, b"", {}),
                http.client.RemoteDisconnected("gone"),
                _FakeResp(200, self._tool_body({"ok": 1})),
            ])

        # reuse the connection for the tools/call (it follows the handshake on conn 1)
        script = mk()
        client = elr_transport.McpHttpClient(elr_config.McpHttpProfileConfig(), timeout=5)
        client._pool = _pool(script)
        res = client.call_tool("search", {}, idempotency_key="idem-1")
        self.assertEqual(res.result, {"ok": 1})
        self.assertEqual(script.requests[-1][3]["Idempotency-Key"], "idem-1")

        script = mk()
        client = elr_transport.McpHttpClient(elr_config.McpHttpProfileConfig(), timeout=5)
        client._pool = _pool(script)
        res = client.call_tool("search", {})
        self.assertEqual(res.status, 0)  # not replayed without a key
        self.assertEqual(len(script.requests), 3)


if __name__ == "__main__":
    unittest.main()
