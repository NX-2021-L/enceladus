import asyncio
import importlib.util
import json
import pathlib
import sys
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("enceladus_server_coord_auth", MODULE_PATH)
server = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_tool_handler_is_registered():
    assert "coordination_cognito_session" in server._TOOL_HANDLERS


def test_coordination_cognito_session_forwards_payload():
    with patch.object(server, "_coordination_api_request") as mock_request:
        mock_request.return_value = {"success": True, "session": {"target_origin": "https://jreese.net"}}
        content = _run(
            server._coordination_cognito_session(
                {
                    "target_origin": "https://jreese.net",
                    "include_set_cookie_headers": True,
                    "include_tokens": False,
                }
            )
        )

    mock_request.assert_called_once_with(
        "POST",
        "/auth/cognito/session",
        payload={
            "target_origin": "https://jreese.net",
            "include_set_cookie_headers": True,
            "include_tokens": False,
        },
    )
    body = json.loads(content[0].text)
    assert body["success"] is True
