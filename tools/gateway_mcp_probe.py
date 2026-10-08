#!/usr/bin/env python3
"""Coordination MCP gateway probe (ENC-TSK-Q42 AC-3 / ENC-ISS-835).

POSTs JSON-RPC ``initialize`` then ``tools/list`` to <base>/api/v1/coordination/mcp
with the internal key and exits non-zero unless the result tools array contains
``get_compact_context``. Handles plain JSON and SSE (``data:``) responses.
The key is read from $COORDINATION_INTERNAL_API_KEY (never printed).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

REQUIRED_TOOL = "get_compact_context"


def parse_body(body: str) -> Dict[str, Any]:
    body = body.strip()
    if body.startswith("{"):
        return json.loads(body)
    last: Optional[Dict[str, Any]] = None
    for line in body.splitlines():
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload.startswith("{"):
                last = json.loads(payload)
    if last is None:
        raise ValueError(f"no JSON-RPC payload in response: {body[:200]!r}")
    return last


def tools_ok(msg: Dict[str, Any]) -> Tuple[bool, str]:
    if "error" in msg:
        return False, f"JSON-RPC error: {json.dumps(msg['error'])[:300]}"
    tools = (msg.get("result") or {}).get("tools")
    if not isinstance(tools, list):
        return False, "result.tools is not an array"
    names = {t.get("name") for t in tools if isinstance(t, dict)}
    if REQUIRED_TOOL not in names:
        return False, f"{REQUIRED_TOOL} missing from {len(names)} tools"
    return True, f"{len(names)} tools incl. {REQUIRED_TOOL}"


def _post(url: str, key: str, payload: Dict[str, Any], session: Optional[str]) -> Tuple[Dict[str, Any], Optional[str]]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-Coordination-Internal-Key": key,
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return parse_body(resp.read().decode("utf-8", "replace")), resp.headers.get("Mcp-Session-Id")


def probe(base: str, key: str) -> Tuple[bool, str]:
    url = base.rstrip("/") + "/api/v1/coordination/mcp"
    try:
        init, session = _post(url, key, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "gateway-probe", "version": "1"}}}, None)
        if "error" in init:
            return False, f"initialize failed: {json.dumps(init['error'])[:300]}"
        listing, _ = _post(url, key, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session)
        return tools_ok(listing)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read()[:200]!r}"
    except Exception as e:  # noqa: BLE001 - probe must fail closed on anything
        return False, f"{type(e).__name__}: {e}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base-url", required=True)
    args = ap.parse_args(argv)
    key = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    if not key:
        print("[ERROR] COORDINATION_INTERNAL_API_KEY is not set")
        return 2
    ok, detail = probe(args.base_url, key)
    print(f"[{'SUCCESS' if ok else 'ERROR'}] gateway probe {args.base_url}: {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
