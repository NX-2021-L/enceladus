"""ENC-TSK-J89: escalation.watch must call the coordination API with a path
RELATIVE to COORDINATION_API_BASE.

The base already ends in /api/v1/coordination; the original handler passed the
absolute route and double-prefixed the URL, 404ing on both gamma and prod while
every unit test mocked the helper. These tests pin the composed URL itself so a
prefix regression can never be mock-blind again.
"""
import asyncio
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server(**env):
    module_name = f"enceladus_server_watch_path_{uuid.uuid4().hex}"
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


def test_watch_path_is_base_relative_and_never_double_prefixed():
    server = _load_server(
        ENCELADUS_COORDINATION_API_BASE="https://example.test/api/v1/coordination")
    captured = {}

    def fake_request(method, path="", payload=None, query=None):
        base = server.COORDINATION_API_BASE.rstrip("/")
        route = path if path.startswith("/") else (f"/{path}" if path else "")
        captured["url"] = f"{base}{route}"
        captured["path"] = path
        return {"success": True, "events": [], "next_cursor": "e30"}

    with patch.object(server, "_coordination_api_request", side_effect=fake_request):
        result = _run(server._escalation_watch(
            {"session_id": "ENC-SES-02F", "project_id": "enceladus"}))

    assert captured["path"] == "/escalations/watch"
    assert captured["url"] == (
        "https://example.test/api/v1/coordination/escalations/watch")
    assert "/api/v1/coordination/api/v1/coordination" not in captured["url"]
    payload = json.loads(result[0].text)
    assert payload["success"] is True


def test_watch_requires_session_id():
    server = _load_server()
    result = _run(server._escalation_watch({"project_id": "enceladus"}))
    payload = json.loads(result[0].text)
    assert "session_id" in payload.get("error", "")
