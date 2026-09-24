"""Offline tests for elr_lib.transport's McpHttpClient / SSE double-parse
contract. No network access -- urllib.request.urlopen is mocked.
"""

import json
import unittest
from unittest.mock import patch

from elr_lib import config as elr_config
from elr_lib import transport as elr_transport


def _sse_body(*envelopes):
    """Build a multi-event SSE body from a list of envelope dicts."""
    chunks = []
    for env in envelopes:
        chunks.append(f"event: message\ndata: {json.dumps(env)}\n\n")
    return "".join(chunks).encode("utf-8")


class ParseMcpHttpResponseTests(unittest.TestCase):
    def test_sse_takes_last_data_line_not_first(self):
        first_event = {"jsonrpc": "2.0", "id": 1, "result": {"marker": "FIRST-must-be-ignored"}}
        last_event = {"jsonrpc": "2.0", "id": 1, "result": {"marker": "LAST-must-win"}}
        body = _sse_body(first_event, last_event)
        envelope = elr_transport.parse_mcp_http_response({"content-type": "text/event-stream"}, body)
        self.assertEqual(envelope["result"]["marker"], "LAST-must-win")

    def test_sse_content_type_case_and_charset_tolerant(self):
        env = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        body = _sse_body(env)
        envelope = elr_transport.parse_mcp_http_response(
            {"Content-Type": "TEXT/EVENT-STREAM; charset=utf-8"}, body
        )
        self.assertEqual(envelope["result"]["ok"], True)

    def test_sse_with_no_data_lines_raises(self):
        body = b"event: message\n\n"
        with self.assertRaises(ValueError):
            elr_transport.parse_mcp_http_response({"content-type": "text/event-stream"}, body)

    def test_plain_json_response_parsed_directly(self):
        env = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        body = json.dumps(env).encode("utf-8")
        envelope = elr_transport.parse_mcp_http_response({"content-type": "application/json"}, body)
        self.assertEqual(envelope, env)

    def test_missing_content_type_falls_back_to_plain_json(self):
        env = {"jsonrpc": "2.0", "id": 1, "result": {}}
        body = json.dumps(env).encode("utf-8")
        envelope = elr_transport.parse_mcp_http_response({}, body)
        self.assertEqual(envelope, env)

    def test_empty_body_returns_empty_dict(self):
        envelope = elr_transport.parse_mcp_http_response({"content-type": "application/json"}, b"")
        self.assertEqual(envelope, {})


class UnwrapToolResultDoubleParseTests(unittest.TestCase):
    """The core SSE double-parse contract: result.content[0].text is a
    JSON-ENCODED STRING (server.py's _result_text does json.dumps(payload)).
    A single parse of the HTTP body only recovers the outer envelope; the
    inner text still needs its own json.loads. This is the "single-parse
    trap" the ELR contract calls out explicitly.
    """

    def _make_envelope(self, inner_payload):
        inner_text = json.dumps(inner_payload)
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": inner_text}],
                "isError": False,
            },
        }

    def test_double_parse_recovers_dict(self):
        envelope = self._make_envelope({"tools_count": 3, "ok": True})
        result = elr_transport.unwrap_tool_result(envelope)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {"tools_count": 3, "ok": True})

    def test_single_parse_trap_yields_a_string_not_a_dict(self):
        """Demonstrates the trap: naively reading content[0]["text"]
        WITHOUT a second json.loads gives a plain string, not the parsed
        payload. unwrap_tool_result() must never make this mistake.
        """
        envelope = self._make_envelope({"tools_count": 3, "ok": True})
        naive_single_parse = envelope["result"]["content"][0]["text"]
        self.assertIsInstance(naive_single_parse, str)  # the trap

        guarded_result = elr_transport.unwrap_tool_result(envelope)
        self.assertIsInstance(guarded_result, dict)  # the guard avoids it
        self.assertNotEqual(type(naive_single_parse), type(guarded_result))

    def test_end_to_end_sse_then_double_parse(self):
        inner_payload = {"dynamodb": "ok", "s3": "ok"}
        envelope = self._make_envelope(inner_payload)
        body = _sse_body(envelope)
        parsed_envelope = elr_transport.parse_mcp_http_response({"content-type": "text/event-stream"}, body)
        result = elr_transport.unwrap_tool_result(parsed_envelope)
        self.assertEqual(result, inner_payload)

    def test_non_json_text_falls_back_to_raw_string(self):
        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "not json at all"}], "isError": False},
        }
        result = elr_transport.unwrap_tool_result(envelope)
        self.assertEqual(result, "not json at all")

    def test_result_without_content_returns_result_as_is(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        result = elr_transport.unwrap_tool_result(envelope)
        self.assertEqual(result, {"protocolVersion": "2024-11-05"})

    def test_missing_result_returns_none(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "not found"}}
        result = elr_transport.unwrap_tool_result(envelope)
        self.assertIsNone(result)


class PostureClassificationTests(unittest.TestCase):
    def test_mcp_posture_bearer_on_success(self):
        posture, anomalies = elr_transport.classify_mcp_posture(bearer_sent=True, tool_status_code=200, is_error=False)
        self.assertEqual(posture, "bearer")
        self.assertEqual(anomalies, [])

    def test_mcp_posture_server_held_keys_when_no_bearer(self):
        posture, anomalies = elr_transport.classify_mcp_posture(bearer_sent=False, tool_status_code=200, is_error=False)
        self.assertEqual(posture, "server-held-keys")

    def test_mcp_posture_unknown_on_401(self):
        posture, anomalies = elr_transport.classify_mcp_posture(bearer_sent=True, tool_status_code=401, is_error=False)
        self.assertEqual(posture, "unknown")
        self.assertTrue(any("401" in a for a in anomalies))

    def test_mcp_posture_unknown_on_tool_error(self):
        posture, anomalies = elr_transport.classify_mcp_posture(bearer_sent=True, tool_status_code=200, is_error=True)
        self.assertEqual(posture, "unknown")
        self.assertIn("tool_call_reported_error", anomalies)

    def test_internal_posture_key_sent(self):
        posture, _ = elr_transport.classify_internal_posture(key_sent=True, status_code=200)
        self.assertEqual(posture, "internal-key")

    def test_internal_posture_no_key_sent(self):
        posture, _ = elr_transport.classify_internal_posture(key_sent=False, status_code=200)
        self.assertEqual(posture, "server-held-keys")

    def test_internal_posture_unreachable(self):
        posture, anomalies = elr_transport.classify_internal_posture(key_sent=True, status_code=0)
        self.assertEqual(posture, "unknown")
        self.assertIn("unreachable", anomalies)


class _FakeHeaders:
    """Mimics http.client.HTTPMessage's .items() surface used by our
    _get_header() helper, without importing http.client for the test.
    """

    def __init__(self, items):
        self._items = items

    def items(self):
        return self._items


class _FakeHttpResponse:
    def __init__(self, status, headers, body):
        self._status = status
        self.headers = _FakeHeaders(headers)
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class McpHttpClientEmptySessionIdTests(unittest.TestCase):
    def test_empty_mcp_session_id_header_does_not_fail(self):
        result_envelope = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        fake_resp = _FakeHttpResponse(
            200,
            [("Content-Type", "application/json"), ("Mcp-Session-Id", "")],
            json.dumps(result_envelope).encode("utf-8"),
        )
        cfg = elr_config.McpHttpProfileConfig()
        client = elr_transport.McpHttpClient(cfg, timeout=5)

        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            resp = client.initialize()

        self.assertEqual(resp.status, 200)
        self.assertEqual(client.session_id, "")  # tolerated, not an error
        self.assertEqual(resp.session_id, "")

    def test_missing_mcp_session_id_header_does_not_fail(self):
        result_envelope = {"jsonrpc": "2.0", "id": 1, "result": {}}
        fake_resp = _FakeHttpResponse(
            200,
            [("Content-Type", "application/json")],  # no Mcp-Session-Id at all
            json.dumps(result_envelope).encode("utf-8"),
        )
        cfg = elr_config.McpHttpProfileConfig()
        client = elr_transport.McpHttpClient(cfg, timeout=5)

        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            resp = client.initialize()

        self.assertEqual(resp.status, 200)
        self.assertEqual(client.session_id, "")

    def test_non_empty_session_id_is_captured_and_reused(self):
        result_envelope = {"jsonrpc": "2.0", "id": 1, "result": {}}
        fake_resp = _FakeHttpResponse(
            200,
            [("Content-Type", "application/json"), ("Mcp-Session-Id", "sess-abc123")],
            json.dumps(result_envelope).encode("utf-8"),
        )
        cfg = elr_config.McpHttpProfileConfig()
        client = elr_transport.McpHttpClient(cfg, timeout=5)

        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
            client.initialize()
            self.assertEqual(client.session_id, "sess-abc123")

            client.notify_initialized()
            # second call should now carry the session header
            sent_request = mock_urlopen.call_args[0][0]
            self.assertEqual(sent_request.get_header("Mcp-session-id"), "sess-abc123")


class McpHttpClientCallToolTests(unittest.TestCase):
    def test_call_tool_double_parses_and_classifies_posture(self):
        inner_payload = {"success": True, "dynamodb": "ok"}
        envelope = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": json.dumps(inner_payload)}], "isError": False},
        }
        fake_resp = _FakeHttpResponse(
            200,
            [("Content-Type", "application/json")],
            json.dumps(envelope).encode("utf-8"),
        )
        with patch.dict("os.environ", {"ENCELADUS_MCP_BEARER_TOKEN": "test-bearer"}, clear=False):
            cfg = elr_config.McpHttpProfileConfig()
        client = elr_transport.McpHttpClient(cfg, timeout=5)

        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            outcome = client.call_tool("connection_health", {})

        self.assertEqual(outcome.result, inner_payload)
        self.assertFalse(outcome.is_error)
        self.assertEqual(outcome.identity_posture, "bearer")

    def test_initialize_200_never_sets_posture(self):
        """Regression guard for the ELR contract: initialize() must not
        expose/derive an identity_posture field at all -- only call_tool()
        does, and only from the tool result.
        """
        envelope = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        fake_resp = _FakeHttpResponse(200, [], json.dumps(envelope).encode("utf-8"))
        cfg = elr_config.McpHttpProfileConfig()
        client = elr_transport.McpHttpClient(cfg, timeout=5)

        with patch("elr_lib.transport.urllib.request.urlopen", return_value=fake_resp):
            resp = client.initialize()

        self.assertFalse(hasattr(resp, "identity_posture"))


if __name__ == "__main__":
    unittest.main()
