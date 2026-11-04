"""ENC-TSK-S28-0B: tools/list is cached per warm container."""

import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")


def _load_server():
    name = f"enceladus_server_tools_list_cache_{uuid.uuid4().hex}"
    with patch.dict(os.environ, {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off"}, clear=False):
        spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


def _event(body, accept="application/json, text/event-stream"):
    return {
        "headers": {"accept": accept, "content-type": "application/json"},
        "requestContext": {"http": {"method": "POST", "path": "/mcp"}},
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }


def _call(server, body, **kw):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(server._handle_mcp_request(_event(body, **kw)))
    finally:
        loop.close()


def _list(req_id):
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}}


def test_second_tools_list_is_served_from_cache_without_rebuilding():
    server = _load_server()
    real = server._raw_tool_definitions
    builds = []

    def counting():
        builds.append(1)
        return real()

    with patch.object(server, "_raw_tool_definitions", side_effect=counting):
        first = _call(server, _list(1))
        built_after_first = len(builds)
        second = _call(server, _list(2))
        third = _call(server, _list("abc"))

    assert first["statusCode"] == 200 and built_after_first >= 1
    assert len(builds) == built_after_first  # no rebuild on the cached calls
    assert server._TOOLS_LIST_CACHE["stores"] == 1
    assert server._TOOLS_LIST_CACHE["hits"] == 2
    # byte-identical result payload; only the JSON-RPC id differs
    first_body, second_body, third_body = (json.loads(r["body"]) for r in (first, second, third))
    assert second_body["id"] == 2 and third_body["id"] == "abc"
    assert first_body["result"] == second_body["result"] == third_body["result"]
    assert first["body"].split('"result":', 1)[1] == second["body"].split('"result":', 1)[1]
    assert second["headers"]["content-type"] == "application/json"
    assert int(second["headers"]["content-length"]) == len(second["body"].encode("utf-8"))


def test_cache_key_change_invalidates_and_non_list_requests_bypass():
    server = _load_server()
    _call(server, _list(1))
    assert server._TOOLS_LIST_CACHE["stores"] == 1
    with patch.object(server, "SERVER_VERSION", "9.9.9"):
        assert server._tools_list_cached_response(json.dumps(_list(5)).encode(), {}) is None
    # cursor pagination and unsupported Accept never use the cache
    paged = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"cursor": "x"}}
    assert server._tools_list_cached_response(json.dumps(paged).encode(), {}) is None
    assert server._tools_list_cached_response(json.dumps(_list(4)).encode(), {"accept": "text/html"}) is None
    other = {"jsonrpc": "2.0", "id": 6, "method": "ping"}
    assert server._tools_list_cached_response(json.dumps(other).encode(), {}) is None
    assert server._tools_list_cached_response(json.dumps(_list(7)).encode(), {}) is not None
