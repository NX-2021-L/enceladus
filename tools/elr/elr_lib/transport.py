"""ELR transport: two client shapes over stdlib urllib only.

InternalClient  -- direct HTTPS calls to the governed Enceladus APIs,
                   using the same ``X-Coordination-Internal-Key`` header
                   convention as tools/enceladus-mcp-server/server.py.

McpHttpClient   -- JSON-RPC 2.0 client for the streaming MCP-over-HTTP
                   gateway (initialize -> notifications/initialized ->
                   tools/call), including the SSE double-parse contract
                   that gateway's tool results require.

Nothing here imports server.py -- ELR must run standalone on any
workstation with only the Python 3.11 standard library.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import config as elr_config

DEFAULT_TIMEOUT_SECONDS = 20


def _build_ssl_context() -> ssl.SSLContext:
    """Mirror server.py's CA-bundle fallback, minus the optional certifi
    dependency (ELR is stdlib-only, so no soft pip fallback here).
    """
    if os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context()
    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return ssl.create_default_context()
    return ssl.create_default_context()


def _get_header(headers: Dict[str, str], name: str) -> str:
    """Case-insensitive header lookup; never raises on a missing header."""
    lowered = name.lower()
    for key, value in (headers or {}).items():
        if key.lower() == lowered:
            return value or ""
    return ""


def _join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path:
        return base
    route = path if path.startswith("/") else f"/{path}"
    return f"{base}{route}"


# ---------------------------------------------------------------------------
# Identity-posture classification. These are pure functions so they are
# trivially unit-testable offline; the transport layer calls them at the
# point where the network truth (was a credential attached, what did the
# call return) is known.
# ---------------------------------------------------------------------------


def classify_internal_posture(*, key_sent: bool, status_code: int) -> Tuple[str, List[str]]:
    anomalies: List[str] = []
    if status_code in (401, 403):
        anomalies.append(f"auth_rejected_http_{status_code}")
        return "unknown", anomalies
    if status_code == 0:
        anomalies.append("unreachable")
        return "unknown", anomalies
    if status_code >= 500:
        anomalies.append(f"upstream_error_http_{status_code}")
        return "unknown", anomalies
    if 200 <= status_code < 300:
        return ("internal-key" if key_sent else "server-held-keys"), anomalies
    anomalies.append(f"unexpected_http_{status_code}")
    return "unknown", anomalies


def classify_mcp_posture(*, bearer_sent: bool, tool_status_code: int, is_error: bool) -> Tuple[str, List[str]]:
    """Derive identity posture from a tools/call OUTCOME only.

    Per the ELR contract: never infer auth posture from a 200 on
    initialize -- the gateway's initialize handshake does not gate on
    identity, so only a tools/call result is evidence of who the caller
    was authenticated as.
    """
    anomalies: List[str] = []
    if tool_status_code in (401, 403):
        anomalies.append(f"auth_rejected_http_{tool_status_code}")
        return "unknown", anomalies
    if tool_status_code == 0:
        anomalies.append("unreachable")
        return "unknown", anomalies
    if is_error:
        anomalies.append("tool_call_reported_error")
        return "unknown", anomalies
    if 200 <= tool_status_code < 300:
        return ("bearer" if bearer_sent else "server-held-keys"), anomalies
    anomalies.append(f"unexpected_http_{tool_status_code}")
    return "unknown", anomalies


# ---------------------------------------------------------------------------
# InternalClient
# ---------------------------------------------------------------------------


class InternalClient:
    """Direct HTTPS client for the governed Enceladus internal-key APIs."""

    def __init__(self, config: "elr_config.InternalProfileConfig", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.config = config
        self.timeout = timeout
        self._ssl_ctx = _build_ssl_context()

    def request(
        self,
        method: str,
        api: str,
        path: str = "",
        *,
        payload: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, Any]:
        """Issue one governed-API call.

        Returns (status_code, parsed_body). status_code is 0 for a
        transport-level failure (DNS/connect/timeout) that never reached
        the server, in which case parsed_body carries an "error" string.

        A single retry is attempted on a 5xx response, but ONLY for
        idempotent GET requests -- a write (POST/PUT/PATCH/DELETE) is
        never auto-retried on 5xx, because a 5xx after the request body
        was sent is an ambiguous echo (the write may have already landed
        server-side); retrying blind could double-apply it. Ambiguous
        write failures are surfaced as-is for the caller to investigate.
        """
        base = self.config.base_url(api)
        key = self.config.key_for(api)
        url = _join_url(base, path)
        if query:
            encoded_qs = urllib.parse.urlencode({k: v for k, v in query.items() if v is not None})
            if encoded_qs:
                url = f"{url}?{encoded_qs}"

        headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        body: Optional[bytes] = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        if key:
            headers[elr_config.INTERNAL_AUTH_HEADER] = key

        method_upper = method.upper()
        allow_retry = method_upper == "GET"
        return self._do(method_upper, url, headers, body, allow_retry)

    def _do(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        allow_retry: bool,
    ) -> Tuple[int, Any]:
        attempted_retry = False
        while True:
            req = urllib.request.Request(url=url, method=method, headers=headers, data=body)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                    status = resp.getcode()
                    text = resp.read().decode("utf-8")
                    parsed = json.loads(text) if text else {}
                    return status, parsed
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
                try:
                    parsed = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    parsed = {"error": raw or str(exc)}
                if exc.code >= 500 and allow_retry and not attempted_retry:
                    attempted_retry = True
                    continue
                return exc.code, parsed
            except urllib.error.URLError as exc:
                return 0, {"error": f"unreachable: {exc.reason if hasattr(exc, 'reason') else exc}"}
            except TimeoutError as exc:
                return 0, {"error": f"timeout: {exc}"}
            except Exception as exc:  # noqa: BLE001 -- surface, never swallow
                return 0, {"error": f"request_failed: {exc}"}

    def health(self) -> Tuple[int, Any]:
        """Cheap governed READ: GET the same health endpoint the MCP
        connection_health tool uses (server.py:_health_api_request).
        No internal key is sent for this endpoint, matching server.py.
        """
        return self.request("GET", "health")


# ---------------------------------------------------------------------------
# McpHttpClient
# ---------------------------------------------------------------------------


def parse_mcp_http_response(headers: Dict[str, str], body_bytes: bytes) -> Dict[str, Any]:
    """First-level parse of a gateway HTTP response into the outer
    JSON-RPC envelope.

    If the response is SSE-framed (Content-Type: text/event-stream),
    the body is a sequence of "event:"/"data:" lines (possibly several
    events); per the ELR contract, take the LAST line starting with
    "data: " and parse that. Otherwise treat the whole body as a plain
    JSON document.
    """
    content_type = _get_header(headers, "content-type")
    text = body_bytes.decode("utf-8", errors="replace")

    if "text/event-stream" in content_type.lower():
        data_lines = [line[len("data: ") :] for line in text.splitlines() if line.startswith("data: ")]
        if not data_lines:
            raise ValueError("SSE response contained no 'data: ' lines")
        return json.loads(data_lines[-1])

    if not text.strip():
        return {}
    return json.loads(text)


def unwrap_tool_result(envelope: Dict[str, Any]) -> Any:
    """Second-level parse: a tools/call result wraps its actual payload
    as a JSON-encoded string in result.content[0].text (server.py's
    _result_text() does `TextContent(text=json.dumps(payload))`).

    A single parse of the HTTP body only recovers the OUTER envelope --
    result.content[0]["text"] is still a string at that point. This
    function always performs the second json.loads so callers never
    silently receive a string where they expect the parsed payload. If
    the text truly isn't JSON, the raw string is returned as a fallback
    (still better than raising for a non-tools/call envelope).
    """
    result = envelope.get("result")
    if not isinstance(result, dict):
        return result

    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict) and "text" in first:
            text_value = first["text"]
            if isinstance(text_value, str):
                try:
                    return json.loads(text_value)
                except json.JSONDecodeError:
                    return text_value
            return text_value

    return result


@dataclass
class McpResponse:
    status: int
    envelope: Dict[str, Any] = field(default_factory=dict)
    session_id: str = ""


@dataclass
class ToolCallResult:
    status: int
    result: Any
    is_error: bool
    identity_posture: str
    anomalies: List[str]
    session_id: str = ""


class McpHttpClient:
    """JSON-RPC 2.0 client for the streaming MCP-over-HTTP gateway.

    Lifecycle: initialize() -> notify_initialized() -> call_tool(...).
    """

    def __init__(self, config: "elr_config.McpHttpProfileConfig", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.config = config
        self.timeout = timeout
        self.session_id = ""
        self._ssl_ctx = _build_ssl_context()
        self._next_id = 1

    def _post(self, method_name: str, params: Optional[Dict[str, Any]] = None, *, is_notification: bool = False) -> McpResponse:
        req_id: Optional[int] = None
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method_name, "params": params or {}}
        if not is_notification:
            req_id = self._next_id
            self._next_id += 1
            payload["id"] = req_id

        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": self.config.user_agent,
        }
        if self.config.bearer_configured:
            headers["Authorization"] = f"Bearer {self.config.bearer_token()}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        req = urllib.request.Request(url=self.config.gateway_url, method="POST", headers=headers, data=body)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                status = resp.getcode()
                resp_headers = dict(resp.headers.items())
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = dict(exc.headers.items()) if getattr(exc, "headers", None) else {}
            raw = exc.read() if hasattr(exc, "read") else b""
        except urllib.error.URLError as exc:
            return McpResponse(status=0, envelope={"error": f"unreachable: {exc}"}, session_id=self.session_id)
        except TimeoutError as exc:
            return McpResponse(status=0, envelope={"error": f"timeout: {exc}"}, session_id=self.session_id)

        # Tolerate an EMPTY (or entirely absent) mcp-session-id header --
        # the gateway is not required to mint one, and a blank value must
        # never fail the call.
        sid = _get_header(resp_headers, "mcp-session-id")
        if sid:
            self.session_id = sid

        if is_notification and not raw:
            return McpResponse(status=status, envelope={}, session_id=self.session_id)

        try:
            envelope = parse_mcp_http_response(resp_headers, raw)
        except (json.JSONDecodeError, ValueError) as exc:
            envelope = {"error": f"parse_failed: {exc}"}

        return McpResponse(status=status, envelope=envelope, session_id=self.session_id)

    def initialize(self) -> McpResponse:
        """Send the initialize handshake.

        Per the ELR contract, the result of this call is NEVER used to
        infer identity_posture -- only tools/call outcomes are.
        """
        return self._post(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "elr-core", "version": "1.0"},
            },
        )

    def notify_initialized(self) -> McpResponse:
        return self._post("notifications/initialized", {}, is_notification=True)

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> ToolCallResult:
        resp = self._post("tools/call", {"name": name, "arguments": arguments or {}})
        result = unwrap_tool_result(resp.envelope)

        is_error = False
        raw_result = resp.envelope.get("result")
        if isinstance(raw_result, dict):
            is_error = bool(raw_result.get("isError"))
        elif "error" in resp.envelope:
            is_error = True

        posture, anomalies = classify_mcp_posture(
            bearer_sent=self.config.bearer_configured,
            tool_status_code=resp.status,
            is_error=is_error,
        )
        return ToolCallResult(
            status=resp.status,
            result=result,
            is_error=is_error,
            identity_posture=posture,
            anomalies=anomalies,
            session_id=resp.session_id,
        )
