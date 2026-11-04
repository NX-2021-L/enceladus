"""Offline tests for elr_lib.client_timing and its transport wiring
(ENC-TSK-S26-0B). urllib.request.urlopen is mocked; no network.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from elr_lib import client_timing as ct
from elr_lib import config as elr_config
from elr_lib import transport as elr_transport

SECRET_KEY = "super-secret-internal-key-value"
SECRET_BEARER = "super-secret-bearer-value"


class _Resp:
    def __init__(self, status, body, headers=None):
        self._status, self._body = status, body
        self.headers = _H(headers or {})

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _H:
    def __init__(self, d):
        self._d = d

    def items(self):
        return self._d.items()


def _mcp_body(payload):
    env = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
    return json.dumps(env).encode("utf-8")


class _LedgerCase(unittest.TestCase):
    def setUp(self):
        ct.reset_process_context()
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = os.path.join(self.tmp.name, "sub", "client_timing.jsonl")
        env = {"ELR_LEDGER": "1", "ELR_LEDGER_PATH": self.ledger}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        os.environ.pop("ELR_CORRELATION_ID", None)
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def rows(self):
        with open(self.ledger, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


class HeaderTests(_LedgerCase):
    def test_header_set_is_exact_and_formatted(self):
        t = ct.begin_call("internal")
        ct.serialize_body(t, {"a": 1})
        h = ct.headers_for(t)
        self.assertEqual(set(h), set(ct.TIMING_HEADER_NAMES))
        self.assertEqual(len(h), 7)
        self.assertRegex(h["X-Correlation-Id"], r"^[0-9a-f-]{36}$")
        self.assertRegex(h["X-Enc-T-Client-Start"], r"^\d{13}$")
        self.assertEqual(h["X-Enc-Client-Session-Reused"], "0")
        self.assertRegex(h["X-Enc-Client-Session-Init-Ms"], r"^\d+$")
        self.assertEqual(h["X-Enc-Client-Tls-New"], "1")
        self.assertRegex(h["X-Enc-Client-Serialize-Ms"], r"^\d+$")
        self.assertEqual(h["X-Enc-Surface"], "elr")

    def test_correlation_id_precedence(self):
        self.assertEqual(ct.resolve_correlation_id("kw-id"), "kw-id")
        with patch.dict(os.environ, {"ELR_CORRELATION_ID": "env-id"}):
            self.assertEqual(ct.resolve_correlation_id(), "env-id")
            self.assertEqual(ct.resolve_correlation_id("kw-id"), "kw-id")
        self.assertNotEqual(ct.new_correlation_id(), ct.new_correlation_id())


class InternalClientTests(_LedgerCase):
    def _client(self):
        with patch.dict(os.environ, {"ENCELADUS_INTERNAL_API_KEY": SECRET_KEY}):
            cfg = elr_config.InternalProfileConfig()
            return elr_transport.InternalClient(cfg, timeout=5)

    def test_headers_sent_every_call_and_ledger_written(self):
        client = self._client()
        seen = []

        def fake_urlopen(req, timeout=None, context=None):
            seen.append({k.lower(): v for k, v in req.header_items()})
            return _Resp(200, b'{"ok": true}')

        with patch("elr_lib.transport.urllib.request.urlopen", side_effect=fake_urlopen):
            client.request("GET", "tracker", "/x", correlation_id="cid-1")
            client.request("POST", "tracker", "/y", payload={"k": "v"})
        for hdrs in seen:
            for name in ct.TIMING_HEADER_NAMES:
                self.assertIn(name.lower(), hdrs)
        self.assertEqual(seen[0]["x-correlation-id"], "cid-1")
        self.assertNotEqual(seen[1]["x-correlation-id"], "cid-1")
        self.assertEqual(seen[0]["x-enc-client-session-reused"], "0")
        self.assertEqual(seen[1]["x-enc-client-session-reused"], "1")
        self.assertEqual(seen[0]["x-enc-client-session-init-ms"], "0")

        rows = self.rows()
        self.assertEqual(len(rows), 2)
        for row in rows:
            for key in ct.LEDGER_KEYS:
                self.assertIn(key, row)
        self.assertEqual(rows[0]["correlation_id"], "cid-1")
        self.assertEqual(rows[0]["response_bytes"], len(b'{"ok": true}'))
        self.assertEqual(rows[0]["status"], 200)
        self.assertEqual(rows[1]["method"], "POST")
        self.assertTrue(rows[0]["client_tls_new"])
        self.assertEqual(rows[0]["surface"], "elr")

    def test_no_secret_in_ledger(self):
        client = self._client()
        with patch("elr_lib.transport.urllib.request.urlopen", return_value=_Resp(200, b"{}")):
            client.request("GET", "tracker", "/x")
        with open(self.ledger, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn(SECRET_KEY, raw)
        self.assertNotIn("authorization", raw.lower())
        self.assertNotIn(elr_config.INTERNAL_AUTH_HEADER.lower(), raw.lower())

    def test_ledger_disabled(self):
        client = self._client()
        with patch.dict(os.environ, {"ELR_LEDGER": "0"}):
            with patch("elr_lib.transport.urllib.request.urlopen", return_value=_Resp(200, b"{}")):
                client.request("GET", "tracker", "/x")
        self.assertFalse(os.path.exists(self.ledger))


class McpClientTests(_LedgerCase):
    def test_session_reused_flips_and_init_ms_reported(self):
        with patch.dict(os.environ, {"ENCELADUS_MCP_BEARER_TOKEN": SECRET_BEARER}):
            cfg = elr_config.McpHttpProfileConfig()
            client = elr_transport.McpHttpClient(cfg, timeout=5)
            seen = []

            def fake_urlopen(req, timeout=None, context=None):
                seen.append({k.lower(): v for k, v in req.header_items()})
                if json.loads(req.data)["method"] == "notifications/initialized":
                    return _Resp(202, b"")
                return _Resp(200, _mcp_body({"ok": True}), {"content-type": "application/json"})

            with patch("elr_lib.transport.urllib.request.urlopen", side_effect=fake_urlopen):
                client.initialize()
                client.notify_initialized()
                client.call_tool("search", {"action": "x"}, correlation_id="mcp-cid")
                client.call_tool("search", {"action": "y"})
        self.assertEqual(len(seen), 4)
        for hdrs in seen:
            for name in ct.TIMING_HEADER_NAMES:
                self.assertIn(name.lower(), hdrs)
        reused = [h["x-enc-client-session-reused"] for h in seen]
        self.assertEqual(reused, ["0", "0", "0", "1"])
        self.assertEqual(seen[2]["x-correlation-id"], "mcp-cid")
        self.assertEqual(seen[3]["x-enc-client-session-init-ms"], "0")

        rows = self.rows()
        self.assertEqual([r["verb"] for r in rows], ["initialize", "notifications/initialized", "tools/call", "tools/call"])
        self.assertTrue(all(r["method"] == "POST" for r in rows))
        self.assertEqual([r["client_session_reused"] for r in rows], [False, False, False, True])
        self.assertGreater(rows[0]["response_bytes"], 0)
        with open(self.ledger, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn(SECRET_BEARER, raw)


if __name__ == "__main__":
    unittest.main()
