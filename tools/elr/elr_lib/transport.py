"""ELR transport: two client shapes over stdlib urllib only.

InternalClient  -- direct HTTPS calls to the governed Enceladus APIs,
                   using the same ``X-Coordination-Internal-Key`` header
                   convention as tools/enceladus-mcp-server/server.py.

McpHttpClient   -- JSON-RPC 2.0 client for the streaming MCP-over-HTTP
                   gateway (initialize -> notifications/initialized ->
                   tools/call), including the SSE double-parse contract
                   that gateway's tool results require.

Long-lived mode (ENC-TSK-S28-0B, default on; ``ELR_LONG_LIVED=0`` restores
one urllib connection per call): both clients keep an http.client connection
alive per host for the life of the process (elr_lib.keepalive), and
McpHttpClient runs initialize + notifications/initialized once per process
and reuses the Mcp-Session-Id for every later tools/call.

Nothing here imports server.py -- ELR must run standalone on any
workstation with only the Python 3.11 standard library.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import client_timing as elr_timing
from . import config as elr_config
from . import keepalive as elr_keepalive
from . import tls as elr_tls

DEFAULT_TIMEOUT_SECONDS = 20


def _build_ssl_context() -> ssl.SSLContext:
    """Deprecated shim kept for any external caller that imported this
    name directly -- resolution now lives in elr_lib.tls (ENC-TSK-P76,
    T-B3, FR-B4-8..9). Prefer elr_tls.resolve_ca_bundle() +
    elr_tls.build_ssl_context() directly when the CA bundle source/path
    needs to be reported (e.g. in a digest).
    """
    return elr_tls.build_ssl_context()


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



REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 3


def _tls_header_callback(timing: Optional["elr_timing.CallTiming"], headers: Dict[str, str]):
    """Return an on_connection hook that keeps client_tls_new (ledger row and
    X-Enc-Client-Tls-New header) truthful for each send attempt, including a
    replay after a dropped connection."""

    def _hook(opened_new: bool) -> None:
        if timing is not None:
            timing.tls_new = bool(opened_new)
        headers[elr_timing.H_TLS_NEW] = "1" if opened_new else "0"

    return _hook


# ---------------------------------------------------------------------------
# InternalClient
# ---------------------------------------------------------------------------


class InternalClient:
    """Direct HTTPS client for the governed Enceladus internal-key APIs."""

    def __init__(self, config: "elr_config.InternalProfileConfig", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.config = config
        self.timeout = timeout
        self._ca_bundle = elr_tls.resolve_ca_bundle()
        self.ca_bundle = self._ca_bundle.as_digest_field()
        self._ssl_ctx = elr_tls.build_ssl_context(self._ca_bundle)
        self._pool: Optional[elr_keepalive.KeepAlivePool] = None

    def _get_pool(self) -> Optional[elr_keepalive.KeepAlivePool]:
        """The keep-alive pool, or None when ELR_LONG_LIVED=0 (per-call urllib)."""
        if not elr_keepalive.long_lived_enabled():
            return None
        if self._pool is None:
            self._pool = elr_keepalive.KeepAlivePool(self._ssl_ctx)
        return self._pool

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()

    def request(
        self,
        method: str,
        api: str,
        path: str = "",
        *,
        payload: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
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
        timing = elr_timing.begin_call("internal", correlation_id)
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
            body = elr_timing.serialize_body(timing, payload)
        if key:
            headers[elr_config.INTERNAL_AUTH_HEADER] = key
        headers.update(elr_timing.headers_for(timing))

        method_upper = method.upper()
        allow_retry = method_upper == "GET"
        status, parsed = self._do(method_upper, url, headers, body, allow_retry, timing)
        elr_timing.finish_call(timing, method=method_upper, url=url, status=status)
        return status, parsed

    def _do(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        allow_retry: bool,
        timing: Optional["elr_timing.CallTiming"] = None,
    ) -> Tuple[int, Any]:
        # AC-2 (ENC-TSK-P76): fail fast, BEFORE urlopen ever runs, when the
        # CA bundle resolution chain came up empty -- never let urllib
        # surface a raw ssl.SSLCertVerificationError / CERTIFICATE_VERIFY_
        # FAILED traceback for this, and never attempt the handshake at
        # all (the constructed context has no CA certs loaded anyway).
        if self._ca_bundle.unresolved:
            return elr_tls.TLS_UNRESOLVED_STATUS, {"error": elr_tls.REMEDIATION_MESSAGE}

        pool = self._get_pool()
        if pool is not None:
            return self._do_pooled(pool, method, url, headers, body, allow_retry, timing)

        attempted_retry = False
        while True:
            req = urllib.request.Request(url=url, method=method, headers=headers, data=body)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                    status = resp.getcode()
                    raw_bytes = resp.read()
                    if timing is not None:
                        timing.response_bytes = len(raw_bytes)
                    text = raw_bytes.decode("utf-8")
                    parsed = json.loads(text) if text else {}
                    return status, parsed
            except urllib.error.HTTPError as exc:
                raw_bytes = exc.read() if hasattr(exc, "read") else b""
                if timing is not None:
                    timing.response_bytes = len(raw_bytes)
                raw = raw_bytes.decode("utf-8")
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

    def _do_pooled(
        self,
        pool: "elr_keepalive.KeepAlivePool",
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        allow_retry: bool,
        timing: Optional["elr_timing.CallTiming"],
    ) -> Tuple[int, Any]:
        """Same status/body contract as the urllib path, over a kept-alive
        connection. 4xx/5xx come back as (code, parsed) exactly as the
        HTTPError branch does; a single GET-only retry on 5xx is preserved."""
        attempted_retry = False
        redirects = 0
        hook = _tls_header_callback(timing, headers)
        while True:
            try:
                resp = pool.request(
                    method, url, headers, body, timeout=self.timeout, idempotent=allow_retry, on_connection=hook
                )
            except TimeoutError as exc:
                return 0, {"error": f"timeout: {exc}"}
            except (OSError, http.client.HTTPException) as exc:
                return 0, {"error": f"unreachable: {exc}"}
            except Exception as exc:  # noqa: BLE001 -- surface, never swallow
                return 0, {"error": f"request_failed: {exc}"}

            if timing is not None:
                timing.response_bytes = len(resp.body)
            if resp.status in REDIRECT_STATUSES and allow_retry and redirects < MAX_REDIRECTS:
                location = _get_header(resp.headers, "location")
                if location:
                    redirects += 1
                    url = urllib.parse.urljoin(url, location)
                    continue
            try:
                text = resp.body.decode("utf-8")
            except UnicodeDecodeError as exc:
                return 0, {"error": f"request_failed: {exc}"}
            if resp.status >= 400:
                try:
                    parsed = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    parsed = {"error": text or f"HTTP Error {resp.status}"}
                if resp.status >= 500 and allow_retry and not attempted_retry:
                    attempted_retry = True
                    continue
                return resp.status, parsed
            try:
                parsed = json.loads(text) if text else {}
            except json.JSONDecodeError as exc:
                return 0, {"error": f"request_failed: {exc}"}
            return resp.status, parsed

    def health(self) -> Tuple[int, Any]:
        """Cheap governed READ: GET the same health endpoint the MCP
        connection_health tool uses (server.py:_health_api_request).
        No internal key is sent for this endpoint, matching server.py.
        """
        return self.request("GET", "health")

    def ca_bundle_digest_fields(self) -> Dict[str, Any]:
        """AC-1/AC-2 (ENC-TSK-P76): the {"ca_bundle": ..., "remediation":
        ...} kwargs every digest should merge in so ca_bundle:{source,path}
        (and, when unresolved, the remediation string) is reported on
        every digest a caller builds from this client, not only on a
        failed network call.
        """
        fields: Dict[str, Any] = {"ca_bundle": self.ca_bundle}
        if self._ca_bundle.unresolved:
            fields["remediation"] = elr_tls.REMEDIATION_MESSAGE
        return fields


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


def handshake_method(method_name: str) -> bool:
    return method_name in ("initialize", "notifications/initialized")


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

    Long-lived mode (default; ELR_LONG_LIVED=0 disables): call_tool() runs
    the handshake lazily, ONCE per client, then reuses the Mcp-Session-Id and
    a kept-alive connection for every later call. The server rebuilds its
    ASGI state per Lambda invocation, so the session id is not durable
    server-side across invocations; reuse here saves the per-process
    handshake round trips and the TLS setup, not server state.
    """

    def __init__(self, config: "elr_config.McpHttpProfileConfig", timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self.config = config
        self.timeout = timeout
        self.session_id = ""
        self._ca_bundle = elr_tls.resolve_ca_bundle()
        self.ca_bundle = self._ca_bundle.as_digest_field()
        self._ssl_ctx = elr_tls.build_ssl_context(self._ca_bundle)
        self._next_id = 1
        self._pool: Optional[elr_keepalive.KeepAlivePool] = None
        self._session_ready = False
        self.handshakes_run = 0

    def _get_pool(self) -> Optional[elr_keepalive.KeepAlivePool]:
        if not elr_keepalive.long_lived_enabled():
            return None
        if self._pool is None:
            self._pool = elr_keepalive.KeepAlivePool(self._ssl_ctx)
        return self._pool

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()

    def ensure_session(self) -> bool:
        """Run initialize + notifications/initialized once per client.
        Returns True when the session is ready (idempotent afterwards)."""
        if self._session_ready:
            return True
        init = self.initialize()
        if not (200 <= init.status < 300):
            return False
        self.notify_initialized()
        self._session_ready = True
        self.handshakes_run += 1
        return True

    def ca_bundle_digest_fields(self) -> Dict[str, Any]:
        """See InternalClient.ca_bundle_digest_fields (ENC-TSK-P76 AC-1)."""
        fields: Dict[str, Any] = {"ca_bundle": self.ca_bundle}
        if self._ca_bundle.unresolved:
            fields["remediation"] = elr_tls.REMEDIATION_MESSAGE
        return fields

    def _post(
        self,
        method_name: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        is_notification: bool = False,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> McpResponse:
        handshake = method_name in ("initialize", "notifications/initialized")
        timing = elr_timing.begin_call("mcp", correlation_id, handshake=handshake)
        resp = self._post_timed(method_name, params, is_notification, timing, idempotency_key)
        row = elr_timing.finish_call(
            timing,
            method="POST",
            url=self.config.gateway_url,
            status=resp.status,
            verb=method_name,
        )
        if handshake:
            # Time spent in initialize + notifications/initialized is
            # reported as client_session_init_ms on the next tools/call.
            elr_timing.add_session_init_ms(row["client_total_ms"])
        return resp

    def _post_timed(
        self,
        method_name: str,
        params: Optional[Dict[str, Any]],
        is_notification: bool,
        timing: "elr_timing.CallTiming",
        idempotency_key: Optional[str] = None,
    ) -> McpResponse:
        # AC-2 (ENC-TSK-P76): same fail-fast contract as InternalClient._do
        # -- never attempt the handshake when the CA bundle is unresolved.
        if self._ca_bundle.unresolved:
            return McpResponse(
                status=elr_tls.TLS_UNRESOLVED_STATUS,
                envelope={"error": elr_tls.REMEDIATION_MESSAGE},
                session_id=self.session_id,
            )

        req_id: Optional[int] = None
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method_name, "params": params or {}}
        if not is_notification:
            req_id = self._next_id
            self._next_id += 1
            payload["id"] = req_id

        body = elr_timing.serialize_body(timing, payload)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": self.config.user_agent,
        }
        if self.config.bearer_configured:
            headers["Authorization"] = f"Bearer {self.config.bearer_token()}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        headers.update(elr_timing.headers_for(timing))

        pool = self._get_pool()
        if pool is not None:
            # Handshake messages are safe to replay; a tools/call is replayed
            # only when the caller supplied an Idempotency-Key.
            idempotent = handshake_method(method_name) or bool(idempotency_key)
            try:
                presp = pool.request(
                    "POST",
                    self.config.gateway_url,
                    headers,
                    body,
                    timeout=self.timeout,
                    idempotent=idempotent,
                    on_connection=_tls_header_callback(timing, headers),
                )
            except TimeoutError as exc:
                return McpResponse(status=0, envelope={"error": f"timeout: {exc}"}, session_id=self.session_id)
            except (OSError, http.client.HTTPException) as exc:
                return McpResponse(status=0, envelope={"error": f"unreachable: {exc}"}, session_id=self.session_id)
            status, resp_headers, raw = presp.status, presp.headers, presp.body
        else:
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
                timing.response_bytes = len(raw)
            except urllib.error.URLError as exc:
                return McpResponse(status=0, envelope={"error": f"unreachable: {exc}"}, session_id=self.session_id)
            except TimeoutError as exc:
                return McpResponse(status=0, envelope={"error": f"timeout: {exc}"}, session_id=self.session_id)

        timing.response_bytes = len(raw)

        timing.response_bytes = len(raw)

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
        resp = self._post("notifications/initialized", {}, is_notification=True)
        if 200 <= resp.status < 300:
            # A caller driving the handshake by hand must not trigger a second
            # one from call_tool().
            self._session_ready = True
        return resp

    def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ToolCallResult:
        if elr_keepalive.long_lived_enabled():
            self.ensure_session()
        resp = self._post(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        if resp.status == 404 and idempotency_key and self._session_ready and self.session_id:
            # Unknown/expired session (MCP spec: 404). Re-handshake once and
            # replay -- only safe because the call is idempotent.
            self._session_ready = False
            self.session_id = ""
            if elr_keepalive.long_lived_enabled() and self.ensure_session():
                resp = self._post(
                    "tools/call",
                    {"name": name, "arguments": arguments or {}},
                    correlation_id=correlation_id,
                    idempotency_key=idempotency_key,
                )
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
