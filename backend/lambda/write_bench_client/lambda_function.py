"""devops-write-bench-client-gamma (ENC-TSK-S26-0C): in-region client arm of the write-bench.

GAMMA ONLY, on-demand, no idle cost. Performs one MCP tools/call against
https://mcp-gamma.jreese.net from inside the region and returns its own measured
timings, which separates internet + TLS from server time (BRD DOC-E32D0ED08473 7.3).
Stdlib only. The bearer token arrives in the invoke payload and is never logged or returned.

Event: {mcp_url, token, tool, arguments, correlation_id, reuse_session=true}
Warm containers keep one initialized MCP session + keep-alive connection (reuse_session)
so repeated invokes measure the steady-state path; reuse_session=false forces a fresh
session and TLS handshake per invoke.
"""
from __future__ import annotations

import http.client
import json
import ssl
import time
from urllib.parse import urlparse

ALLOWED_HOST = "mcp-gamma.jreese.net"
SURFACE = "write-bench"
_CTX = ssl.create_default_context()
_STATE = {"conn": None, "sid": "", "rid": 0, "init": False}
_CONTAINER = {"invocations": 0}


def _check(url):
    p = urlparse(url)
    if p.scheme != "https" or (p.hostname or "").lower() != ALLOWED_HOST or p.username or p.password or p.port not in (None, 443):
        raise ValueError(f"refused: host must be {ALLOWED_HOST}")
    return p


def _parse(content_type, raw):
    text = raw.decode("utf-8", errors="replace")
    if "text/event-stream" in (content_type or "").lower():
        lines = [ln[6:] for ln in text.splitlines() if ln.startswith("data: ")]
        return json.loads(lines[-1]) if lines else {}
    return json.loads(text) if text.strip() else {}


def _post(host, path, token, payload, extra=None, notification=False):
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "User-Agent": "enceladus-write-bench-lambda/1.0", "Authorization": f"Bearer {token}"}
    if _STATE["sid"]:
        headers["Mcp-Session-Id"] = _STATE["sid"]
    headers.update(extra or {})
    new_conn = False
    for attempt in (0, 1):
        if _STATE["conn"] is None:
            _STATE["conn"] = http.client.HTTPSConnection(host, timeout=55, context=_CTX)
            new_conn = True
        try:
            _STATE["conn"].request("POST", path, body=body, headers=headers)
            resp = _STATE["conn"].getresponse()
            raw = resp.read()
            break
        except (http.client.HTTPException, OSError):
            _STATE["conn"] = None
            if attempt == 1:
                raise
    sid = resp.getheader("mcp-session-id")
    if sid:
        _STATE["sid"] = sid
    if (resp.getheader("connection") or "").lower() == "close":
        _STATE["conn"] = None
    if notification and not raw:
        return resp.status, {}, 0, new_conn
    try:
        env = _parse(resp.getheader("content-type", ""), raw)
    except (ValueError, json.JSONDecodeError) as exc:
        env = {"error": f"parse_failed: {exc}"}
    return resp.status, env, len(raw), new_conn


def _unwrap(env):
    res = env.get("result")
    if isinstance(res, dict) and isinstance(res.get("content"), list) and res["content"]:
        first = res["content"][0]
        t = first.get("text") if isinstance(first, dict) else None
        if isinstance(t, str):
            try:
                return json.loads(t)
            except json.JSONDecodeError:
                return t
    return res


def lambda_handler(event, context):
    p = _check(event["mcp_url"])
    host, path, token = p.hostname, p.path or "/mcp", event["token"]
    _CONTAINER["invocations"] += 1
    if not event.get("reuse_session", True):
        _STATE.update({"conn": None, "sid": "", "rid": 0, "init": False})
    t_wall, t0 = time.time(), time.perf_counter()
    reused, init_ms, tls_new = _STATE["init"], 0.0, False
    if not _STATE["init"]:
        i0 = time.perf_counter()
        _STATE["rid"] += 1
        _, _, _, n1 = _post(host, path, token, {"jsonrpc": "2.0", "id": _STATE["rid"], "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "write-bench-lambda", "version": "1.0"}}})
        _, _, _, n2 = _post(host, path, token, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                            notification=True)
        _STATE["init"] = True
        init_ms, tls_new = (time.perf_counter() - i0) * 1000.0, n1 or n2
    s0 = time.perf_counter()
    _STATE["rid"] += 1
    payload = {"jsonrpc": "2.0", "id": _STATE["rid"], "method": "tools/call",
               "params": {"name": event["tool"], "arguments": event["arguments"]}}
    serialize_ms = (time.perf_counter() - s0) * 1000.0
    conn_missing = _STATE["conn"] is None
    hdrs = {"X-Correlation-Id": event["correlation_id"], "X-Enc-T-Client-Start": f"{t_wall:.6f}",
            "X-Enc-Client-Session-Reused": "true" if reused else "false",
            "X-Enc-Client-Session-Init-Ms": f"{init_ms:.3f}",
            "X-Enc-Client-Tls-New": "true" if (tls_new or conn_missing) else "false",
            "X-Enc-Client-Serialize-Ms": f"{serialize_ms:.3f}", "X-Enc-Surface": SURFACE}
    status, env, nbytes, n3 = _post(host, path, token, payload, hdrs)
    t1 = time.perf_counter()
    parsed = _unwrap(env)
    res = env.get("result")
    ok = (status == 200 and "error" not in env and not (isinstance(res, dict) and res.get("isError"))
          and not (isinstance(parsed, dict) and parsed.get("success") is False))
    return {"t_client_start": t_wall, "t_client_end": t_wall + (t1 - t0), "client_total_ms": (t1 - t0) * 1000.0,
            "client_session_reused": reused, "client_session_init_ms": init_ms,
            "client_tls_new": bool(tls_new or conn_missing or n3), "client_serialize_ms": serialize_ms,
            "response_bytes": nbytes, "http_status": status, "ok": ok,
            "lambda_container_invocations": _CONTAINER["invocations"]}
