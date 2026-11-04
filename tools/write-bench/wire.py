"""Wire layer for the Enceladus write-bench (ENC-TSK-S26-0C).

Stdlib only. Speaks MCP streamable HTTP (JSON-RPC 2.0) to the GAMMA gateway:
initialize -> notifications/initialized -> tools/call. The wire shape mirrors
tools/elr/elr_lib/transport.py McpHttpClient (headers, SSE last-"data:" parse,
result.content[0].text double-parse) but does NOT import ELR.

Also runnable as a one-shot child (`python3 wire.py oneshot`) for the
elr_per_process arm: reads a JSON spec on stdin, opens a NEW session, makes one
tools/call, prints a JSON timing record on stdout, exits.
"""
from __future__ import annotations

import http.client
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

ALLOWED_HOST = "mcp-gamma.jreese.net"
DEFAULT_PATH = "/mcp"
PROTOCOL_VERSION = "2024-11-05"
USER_AGENT = "enceladus-write-bench/1.0"
SURFACE = "write-bench"
DEFAULT_TIMEOUT = 60


class RefusedTarget(Exception):
    """Raised when the target is anything but the gamma MCP gateway."""


def assert_gamma_target(env: str, url: str) -> str:
    """Hard allowlist. Returns the validated URL or raises RefusedTarget."""
    if env != "gamma":
        raise RefusedTarget(f"refused: --env must be 'gamma' (got {env!r}); the write-bench never targets prod")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise RefusedTarget(f"refused: MCP URL must be https (got scheme {parsed.scheme!r})")
    if parsed.username or parsed.password:
        raise RefusedTarget("refused: MCP URL must not carry userinfo")
    host = (parsed.hostname or "").lower()
    if host != ALLOWED_HOST:
        raise RefusedTarget(f"refused: MCP URL host {host!r} is not the allowlisted {ALLOWED_HOST!r}")
    if parsed.port not in (None, 443):
        raise RefusedTarget(f"refused: MCP URL port {parsed.port} is not 443")
    return url


# --------------------------------------------------------------------------
# JSON-RPC payload builders (pure, no network)
# --------------------------------------------------------------------------

def build_rpc(method: str, params: Optional[Dict[str, Any]] = None, req_id: Optional[int] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if req_id is not None:
        payload["id"] = req_id
    return payload


def build_initialize(req_id: int = 1) -> Dict[str, Any]:
    return build_rpc(
        "initialize",
        {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "write-bench", "version": "1.0"}},
        req_id,
    )


def build_initialized() -> Dict[str, Any]:
    return build_rpc("notifications/initialized", {})


def build_tool_call(name: str, arguments: Dict[str, Any], req_id: int) -> Dict[str, Any]:
    return build_rpc("tools/call", {"name": name, "arguments": arguments}, req_id)


def build_headers(token: str, session_id: str = "", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": USER_AGENT,
        "Authorization": f"Bearer {token}",
    }
    if session_id:
        h["Mcp-Session-Id"] = session_id
    if extra:
        h.update(extra)
    return h


def client_headers(correlation_id: str, t_client_start: float, session_reused: bool,
                   session_init_ms: float, tls_new: bool, serialize_ms: float) -> Dict[str, str]:
    """The X-Enc-* client attribution headers (BRD 7.3)."""
    return {
        "X-Correlation-Id": correlation_id,
        "X-Enc-T-Client-Start": f"{t_client_start:.6f}",
        "X-Enc-Client-Session-Reused": "true" if session_reused else "false",
        "X-Enc-Client-Session-Init-Ms": f"{session_init_ms:.3f}",
        "X-Enc-Client-Tls-New": "true" if tls_new else "false",
        "X-Enc-Client-Serialize-Ms": f"{serialize_ms:.3f}",
        "X-Enc-Surface": SURFACE,
    }


def execute_args(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"steps": steps}


def step(action: str, arguments: Dict[str, Any], governance_hash: str) -> Dict[str, Any]:
    a = dict(arguments)
    a["governance_hash"] = governance_hash
    return {"action": action, "arguments": a}


# --------------------------------------------------------------------------
# Operations (BRD 7.3). Each returns (tool_name, arguments).
# --------------------------------------------------------------------------

OPERATIONS = [
    "tracker_create",
    "tracker_set",
    "documents_put_2kb",
    "documents_put_60kb",
    "execute_10_independent",
    "execute_10_chained",
    "execute_20_independent",
]

IDEMPOTENT_VALUE = "write-bench idempotent description (no semantic content)"


def _body(nbytes: int, tag: str) -> str:
    head = f"# [BENCH] write-bench payload\n\n# {tag}\n\n"
    line = "write-bench filler line. lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
    out = head
    while len(out.encode("utf-8")) < nbytes:
        out += line
    return out[:nbytes]


def build_operation(op: str, project: str, pool: List[str], governance_hash: str,
                    nonce: str = "") -> Tuple[str, Dict[str, Any]]:
    nonce = nonce or uuid.uuid4().hex[:12]
    if op == "tracker_create":
        s = step("tracker.create", {
            "project_id": project, "record_type": "task",
            "title": f"[BENCH] write-bench task {nonce}",
            "description": "write-bench scratch record; never deleted",
            "category": "implementation", "priority": "P3",
            "acceptance_criteria": ["write-bench scratch record exists"],
            "transition_type": "no_code",
        }, governance_hash)
        return "execute", execute_args([s])
    if op == "tracker_set":
        s = step("tracker.set", {"record_id": pool[0], "field": "description", "value": IDEMPOTENT_VALUE}, governance_hash)
        return "execute", execute_args([s])
    if op in ("documents_put_2kb", "documents_put_60kb"):
        size = 2 * 1024 if op.endswith("2kb") else 60 * 1024
        s = step("documents.put", {
            "project_id": project, "title": f"[BENCH] write-bench doc {op} {nonce}",
            "content": _body(size, f"{op} {nonce}"), "description": "write-bench scratch document",
            "file_name": f"bench-{op}-{nonce}.md", "document_subtype": "doc",
        }, governance_hash)
        return "execute", execute_args([s])
    if op == "execute_10_independent":
        return "execute", execute_args(_set_steps(pool, 10, governance_hash, chained=False))
    if op == "execute_10_chained":
        return "execute", execute_args(_set_steps(pool, 10, governance_hash, chained=True))
    if op == "execute_20_independent":
        return "execute", execute_args(_set_steps(pool, 20, governance_hash, chained=False))
    raise ValueError(f"unknown operation {op!r}")


def _set_steps(pool: List[str], count: int, governance_hash: str, chained: bool) -> List[Dict[str, Any]]:
    steps = []
    for i in range(count):
        # independent: round-robin over the pool (wraps when count > pool size), value fixed.
        # chained: ALL steps hit pool[0]; step i's value is derived from step i-1's index.
        rid = pool[0] if chained else pool[i % len(pool)]
        value = f"write-bench chain index {i} after {i - 1}" if chained else IDEMPOTENT_VALUE
        steps.append(step("tracker.set", {"record_id": rid, "field": "description", "value": value}, governance_hash))
    return steps


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------

def parse_response(content_type: str, raw: bytes) -> Dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    if "text/event-stream" in (content_type or "").lower():
        lines = [ln[len("data: "):] for ln in text.splitlines() if ln.startswith("data: ")]
        if not lines:
            raise ValueError("SSE response contained no 'data: ' lines")
        return json.loads(lines[-1])
    if not text.strip():
        return {}
    return json.loads(text)


def unwrap_tool_result(envelope: Dict[str, Any]) -> Any:
    result = envelope.get("result")
    if not isinstance(result, dict):
        return result
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict) and "text" in content[0]:
        t = content[0]["text"]
        if isinstance(t, str):
            try:
                return json.loads(t)
            except json.JSONDecodeError:
                return t
        return t
    return result


def find_key(obj: Any, key: str) -> Optional[Any]:
    """Depth-first search for the first value stored under `key`."""
    if isinstance(obj, dict):
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def call_ok(envelope: Dict[str, Any], payload: Any) -> bool:
    if "error" in envelope:
        return False
    res = envelope.get("result")
    if isinstance(res, dict) and res.get("isError"):
        return False
    if isinstance(payload, dict) and payload.get("success") is False:
        return False
    return True


# --------------------------------------------------------------------------
# Long-lived session (http.client, keep-alive)
# --------------------------------------------------------------------------

class LongLivedSession:
    def __init__(self, url: str, token: str, timeout: int = DEFAULT_TIMEOUT):
        p = urlparse(url)
        self.host, self.path = p.hostname or "", (p.path or DEFAULT_PATH)
        self.token, self.timeout = token, timeout
        self.conn: Optional[http.client.HTTPSConnection] = None
        self.session_id = ""
        self._rid = 0
        self._ctx = ssl.create_default_context()
        self.initialized = False
        self.fresh_conn = False  # a connection was (re)created since the last completed call

    def _connect(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass
        self.conn = http.client.HTTPSConnection(self.host, timeout=self.timeout, context=self._ctx)
        self.fresh_conn = True

    def _post(self, payload: Dict[str, Any], extra: Optional[Dict[str, str]] = None, notification: bool = False
              ) -> Tuple[int, Dict[str, Any], int]:
        body = json.dumps(payload).encode("utf-8")
        headers = build_headers(self.token, self.session_id, extra)
        for attempt in (0, 1):
            if self.conn is None:
                self._connect()
            try:
                self.conn.request("POST", self.path, body=body, headers=headers)
                resp = self.conn.getresponse()
                raw = resp.read()
                break
            except (http.client.HTTPException, OSError):
                self._connect()
                if attempt == 1:
                    raise
        sid = resp.getheader("mcp-session-id")
        if sid:
            self.session_id = sid
        if resp.getheader("connection", "").lower() == "close":
            self.conn = None
        if notification and not raw:
            return resp.status, {}, 0
        try:
            env = parse_response(resp.getheader("content-type", ""), raw)
        except (ValueError, json.JSONDecodeError) as exc:
            env = {"error": f"parse_failed: {exc}"}
        return resp.status, env, len(raw)

    def ensure_initialized(self) -> float:
        """Returns session-init ms (0.0 when already initialized)."""
        if self.initialized:
            return 0.0
        t0 = time.perf_counter()
        self._rid += 1
        self._post(build_initialize(self._rid))
        self._post(build_initialized(), notification=True)
        self.initialized = True
        return (time.perf_counter() - t0) * 1000.0

    def call(self, tool: str, arguments: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """One timed tools/call; returns a per-call record (no op/arm fields)."""
        t_start_wall = time.time()
        t0 = time.perf_counter()
        reused = self.initialized
        init_ms = self.ensure_initialized()
        s0 = time.perf_counter()
        self._rid += 1
        payload = build_tool_call(tool, arguments, self._rid)
        serialize_ms = (time.perf_counter() - s0) * 1000.0
        tls_new = self.fresh_conn or self.conn is None  # header value is a pre-send prediction
        hdrs = client_headers(correlation_id, t_start_wall, reused, init_ms, tls_new, serialize_ms)
        status, env, nbytes = self._post(payload, hdrs)
        t1 = time.perf_counter()
        tls_new = self.fresh_conn  # actual value for the record
        self.fresh_conn = False
        parsed = unwrap_tool_result(env)
        return {
            "t_client_start": t_start_wall, "t_client_end": t_start_wall + (t1 - t0),
            "client_total_ms": (t1 - t0) * 1000.0, "client_session_reused": reused,
            "client_session_init_ms": init_ms, "client_tls_new": tls_new,
            "client_serialize_ms": serialize_ms, "response_bytes": nbytes,
            "correlation_id": correlation_id, "http_status": status,
            "ok": status == 200 and call_ok(env, parsed), "payload": parsed,
        }

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------
# One-shot (fresh session, fresh TLS per HTTP request, like the ELR runner)
# --------------------------------------------------------------------------

def _urllib_post(url: str, token: str, payload: Dict[str, Any], session_id: str,
                 extra: Optional[Dict[str, str]], timeout: int, ctx: ssl.SSLContext,
                 notification: bool = False) -> Tuple[int, Dict[str, Any], int, str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, method="POST", data=body, headers=build_headers(token, session_id, extra))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status, hdrs, raw = resp.getcode(), dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        status, hdrs, raw = exc.code, dict(exc.headers.items()), exc.read()
    low = {k.lower(): v for k, v in hdrs.items()}
    sid = low.get("mcp-session-id", "") or session_id
    if notification and not raw:
        return status, {}, 0, sid
    try:
        env = parse_response(low.get("content-type", ""), raw)
    except (ValueError, json.JSONDecodeError) as exc:
        env = {"error": f"parse_failed: {exc}"}
    return status, env, len(raw), sid


def run_oneshot(spec: Dict[str, Any]) -> Dict[str, Any]:
    """spec: url, token, tool, arguments, correlation_id, t_client_start (parent's wall start)."""
    assert_gamma_target("gamma", spec["url"])
    ctx = ssl.create_default_context()
    t0 = time.perf_counter()
    sid = ""
    _, _, _, sid = _urllib_post(spec["url"], spec["token"], build_initialize(1), sid, None, DEFAULT_TIMEOUT, ctx)
    _, _, _, sid = _urllib_post(spec["url"], spec["token"], build_initialized(), sid, None, DEFAULT_TIMEOUT, ctx, True)
    init_ms = (time.perf_counter() - t0) * 1000.0
    s0 = time.perf_counter()
    payload = build_tool_call(spec["tool"], spec["arguments"], 2)
    serialize_ms = (time.perf_counter() - s0) * 1000.0
    hdrs = client_headers(spec["correlation_id"], spec["t_client_start"], False, init_ms, True, serialize_ms)
    status, env, nbytes, _ = _urllib_post(spec["url"], spec["token"], payload, sid, hdrs, DEFAULT_TIMEOUT, ctx)
    parsed = unwrap_tool_result(env)
    return {
        "client_session_init_ms": init_ms, "client_serialize_ms": serialize_ms, "response_bytes": nbytes,
        "http_status": status, "ok": status == 200 and call_ok(env, parsed), "payload": parsed,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "oneshot":
        try:
            out = run_oneshot(json.loads(sys.stdin.read()))
        except RefusedTarget as exc:
            print(json.dumps({"fatal": str(exc)}))
            sys.exit(2)
        except Exception as exc:  # noqa: BLE001
            out = {"ok": False, "http_status": 0, "error": f"{type(exc).__name__}: {exc}", "payload": None,
                   "client_session_init_ms": 0.0, "client_serialize_ms": 0.0, "response_bytes": 0}
        print(json.dumps(out))
    else:
        print("wire.py is a library; use bench.py", file=sys.stderr)
        sys.exit(2)
