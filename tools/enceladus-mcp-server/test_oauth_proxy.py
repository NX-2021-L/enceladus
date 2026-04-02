"""Unit tests for Cognito OAuth proxy handlers (ENC-TSK-930 AC1).

Covers _handle_cognito_authorize, _handle_cognito_callback, _handle_cognito_token
with happy-path + error-branch coverage.
"""
import base64
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from io import BytesIO

MODULE_PATH = pathlib.Path(__file__).with_name("server.py")


def _load_server(**env):
    import uuid
    module_name = f"enceladus_server_oauth_test_{uuid.uuid4().hex}"
    defaults = {
        "ENCELADUS_COGNITO_USER_POOL_ID": "us-east-1_TestPool",
        "ENCELADUS_COGNITO_CLIENT_ID": "test-client-id",
        "ENCELADUS_COGNITO_CLIENT_SECRET": "test-client-secret",
        "ENCELADUS_COGNITO_DOMAIN": "https://auth.example.com",
        "ENCELADUS_COGNITO_REGION": "us-east-1",
        "ENCELADUS_MCP_INTERFACE_MODE": "code",
        "ENCELADUS_MCP_API_KEY": "",
    }
    defaults.update(env)
    with patch.dict(os.environ, defaults, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


def _make_event(qs=None, body="", method="GET", path="/", headers=None, base64_encoded=False):
    return {
        "queryStringParameters": qs or {},
        "body": body,
        "isBase64Encoded": base64_encoded,
        "headers": headers or {"host": "mcp.example.com", "x-forwarded-proto": "https"},
        "requestContext": {"http": {"method": method, "path": path, "sourceIp": "1.2.3.4"}},
    }


class TestHandleCognitoAuthorize(unittest.TestCase):
    """Tests for _handle_cognito_authorize (server.py /authorize proxy)."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def test_happy_path_redirects_to_cognito(self):
        event = _make_event(qs={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:9999/callback",
            "state": "client-state-abc",
            "scope": "openid email",
        }, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 302)
        location = result["headers"]["location"]
        self.assertIn("auth.example.com/oauth2/authorize", location)
        self.assertIn("redirect_uri=https%3A%2F%2Fmcp.example.com%2Fcallback", location)
        # Original redirect_uri should NOT be in the Cognito URL
        self.assertNotIn("localhost%3A9999", location)
        # Client state should be encoded inside Cognito state, not passed directly
        self.assertNotIn("state=client-state-abc", location)

    def test_strips_resource_param(self):
        """RFC 8707 resource param must not reach Cognito (ENC-ISS-124)."""
        event = _make_event(qs={
            "response_type": "code",
            "client_id": "test-client-id",
            "resource": "https://mcp.example.com",
        }, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 302)
        self.assertNotIn("resource=", result["headers"]["location"])

    def test_missing_response_type_returns_400(self):
        event = _make_event(qs={"client_id": "test-client-id"}, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 400)
        body = json.loads(result["body"])
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn("response_type", body["error_description"])

    def test_missing_client_id_returns_400(self):
        event = _make_event(qs={"response_type": "code"}, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 400)
        body = json.loads(result["body"])
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn("client_id", body["error_description"])

    def test_missing_both_required_params_returns_400(self):
        event = _make_event(qs={}, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 400)
        body = json.loads(result["body"])
        self.assertIn("response_type", body["error_description"])
        self.assertIn("client_id", body["error_description"])

    def test_default_scope_added_when_missing(self):
        event = _make_event(qs={
            "response_type": "code",
            "client_id": "test-client-id",
        }, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        self.assertEqual(result["statusCode"], 302)
        self.assertIn("scope=openid+email+profile", result["headers"]["location"])

    def test_encodes_client_redirect_uri_in_state(self):
        event = _make_event(qs={
            "response_type": "code",
            "client_id": "test-client-id",
            "redirect_uri": "http://localhost:8080/cb",
            "state": "mystate",
        }, path="/authorize")
        result = self.server._handle_cognito_authorize(event)
        location = result["headers"]["location"]
        # Extract state from URL
        import urllib.parse
        parsed = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed.query)
        state = params["state"][0]
        # Decode and verify relay payload
        padded = state + "=" * (-len(state) % 4)
        relay = json.loads(base64.urlsafe_b64decode(padded).decode())
        self.assertEqual(relay["ru"], "http://localhost:8080/cb")
        self.assertEqual(relay["st"], "mystate")


class TestHandleCognitoCallback(unittest.TestCase):
    """Tests for _handle_cognito_callback (server.py /callback relay)."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def _encode_state(self, redirect_uri, state=""):
        relay = json.dumps({"ru": redirect_uri, "st": state}, separators=(",", ":"))
        return base64.urlsafe_b64encode(relay.encode()).decode().rstrip("=")

    def test_happy_path_relays_code_to_client(self):
        state = self._encode_state("http://localhost:9999/callback", "abc")
        event = _make_event(qs={"code": "auth-code-123", "state": state}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 302)
        location = result["headers"]["location"]
        self.assertIn("localhost:9999/callback", location)
        self.assertIn("code=auth-code-123", location)
        self.assertIn("state=abc", location)

    def test_error_from_cognito_redirects_to_client(self):
        state = self._encode_state("http://localhost:9999/callback", "abc")
        event = _make_event(qs={"error": "access_denied", "state": state}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 302)
        self.assertIn("error=access_denied", result["headers"]["location"])

    def test_error_without_redirect_returns_html_error_page(self):
        event = _make_event(qs={"error": "access_denied"}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("text/html", result["headers"]["content-type"])
        self.assertIn("Authentication Failed", result["body"])
        self.assertIn("access_denied", result["body"])

    def test_invalid_state_returns_html_error_page(self):
        event = _make_event(qs={"code": "some-code", "state": "not-valid-base64!!!"}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("text/html", result["headers"]["content-type"])
        self.assertIn("Invalid Request", result["body"])

    def test_missing_state_returns_html_error_page(self):
        event = _make_event(qs={"code": "some-code"}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("text/html", result["headers"]["content-type"])

    def test_missing_code_returns_html_error_page(self):
        state = self._encode_state("http://localhost:9999/callback")
        event = _make_event(qs={"state": state}, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("text/html", result["headers"]["content-type"])
        self.assertIn("Authorization Failed", result["body"])

    def test_error_with_description_shows_in_html(self):
        event = _make_event(qs={
            "error": "server_error",
            "error_description": "Something went wrong",
        }, path="/callback")
        result = self.server._handle_cognito_callback(event)
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("Something went wrong", result["body"])


class TestHandleCognitoToken(unittest.TestCase):
    """Tests for _handle_cognito_token (server.py /oauth/token proxy)."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def test_missing_grant_type_returns_400(self):
        event = _make_event(
            body="code=abc&redirect_uri=http://localhost:9999/cb",
            method="POST",
            path="/oauth/token",
        )
        result = self.server._handle_cognito_token(event)
        self.assertEqual(result["statusCode"], 400)
        body = json.loads(result["body"])
        self.assertEqual(body["error"], "invalid_request")
        self.assertIn("grant_type", body["error_description"])

    @patch("urllib.request.urlopen")
    def test_happy_path_swaps_redirect_uri(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"access_token":"tok","token_type":"Bearer"}'
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        event = _make_event(
            body="grant_type=authorization_code&code=abc&redirect_uri=http://localhost:9999/cb",
            method="POST",
            path="/oauth/token",
        )
        result = self.server._handle_cognito_token(event)
        self.assertEqual(result["statusCode"], 200)
        # Verify redirect_uri was swapped to server-side callback
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertIn(b"redirect_uri=https%3A%2F%2Fmcp.example.com%2Fcallback", req.data)

    @patch("urllib.request.urlopen")
    def test_cognito_http_error_returns_rfc6749_error(self, mock_urlopen):
        err_body = json.dumps({"error": "invalid_grant", "error_description": "Code expired"}).encode()
        mock_urlopen.side_effect = HTTPError(
            url="https://auth.example.com/oauth2/token",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=BytesIO(err_body),
        )
        event = _make_event(
            body="grant_type=authorization_code&code=expired-code",
            method="POST",
            path="/oauth/token",
        )
        result = self.server._handle_cognito_token(event)
        self.assertEqual(result["statusCode"], 400)
        body = json.loads(result["body"])
        self.assertEqual(body["error"], "invalid_grant")

    @patch("urllib.request.urlopen")
    def test_network_error_returns_502(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionError("Network unreachable")
        event = _make_event(
            body="grant_type=authorization_code&code=abc",
            method="POST",
            path="/oauth/token",
        )
        result = self.server._handle_cognito_token(event)
        self.assertEqual(result["statusCode"], 502)
        body = json.loads(result["body"])
        self.assertEqual(body["error"], "server_error")

    @patch("urllib.request.urlopen")
    def test_base64_encoded_body_decoded(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"access_token":"tok"}'
        mock_resp.status = 200
        mock_urlopen.return_value = mock_resp

        raw_body = "grant_type=refresh_token&refresh_token=rt-123"
        event = _make_event(
            body=base64.b64encode(raw_body.encode()).decode(),
            method="POST",
            path="/oauth/token",
            base64_encoded=True,
        )
        event["isBase64Encoded"] = True
        result = self.server._handle_cognito_token(event)
        self.assertEqual(result["statusCode"], 200)


class TestAuthFailureLogging(unittest.TestCase):
    """Tests for _log_auth_failure and _get_client_ip helpers."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def test_get_client_ip_from_source_ip(self):
        event = {"requestContext": {"http": {"sourceIp": "10.0.0.1"}}, "headers": {}}
        self.assertEqual(self.server._get_client_ip(event), "10.0.0.1")

    def test_get_client_ip_from_forwarded_for(self):
        event = {"requestContext": {}, "headers": {"x-forwarded-for": "192.168.1.1, 10.0.0.1"}}
        self.assertEqual(self.server._get_client_ip(event), "192.168.1.1")

    def test_get_client_ip_unknown_fallback(self):
        event = {"requestContext": {}, "headers": {}}
        self.assertEqual(self.server._get_client_ip(event), "unknown")

    @patch("logging.Logger.warning")
    def test_log_auth_failure_emits_structured_log(self, mock_warn):
        event = _make_event()
        self.server._log_auth_failure("/authorize", "missing_params", event, missing_params=["client_id"])
        mock_warn.assert_called_once()
        log_msg = mock_warn.call_args[0][1]
        parsed = json.loads(log_msg)
        self.assertEqual(parsed["endpoint"], "/authorize")
        self.assertEqual(parsed["error_type"], "missing_params")
        self.assertEqual(parsed["client_ip"], "1.2.3.4")
        self.assertIn("timestamp", parsed)
        # Must not contain token or secret data
        self.assertNotIn("token", log_msg.lower().replace("missing_params", ""))

    @patch("logging.Logger.warning")
    def test_authorize_missing_params_logs_failure(self, mock_warn):
        event = _make_event(qs={}, path="/authorize")
        self.server._handle_cognito_authorize(event)
        mock_warn.assert_called_once()
        log_msg = mock_warn.call_args[0][1]
        parsed = json.loads(log_msg)
        self.assertEqual(parsed["endpoint"], "/authorize")
        self.assertEqual(parsed["error_type"], "missing_params")


class TestCallbackErrorHtml(unittest.TestCase):
    """Tests for _callback_error_html helper."""

    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def test_returns_400_with_html_content_type(self):
        result = self.server._callback_error_html("Test Title", "Test detail message")
        self.assertEqual(result["statusCode"], 400)
        self.assertIn("text/html", result["headers"]["content-type"])

    def test_html_contains_title_and_detail(self):
        result = self.server._callback_error_html("Auth Error", "Session expired")
        self.assertIn("Auth Error", result["body"])
        self.assertIn("Session expired", result["body"])
        self.assertIn("close this window", result["body"])


if __name__ == "__main__":
    unittest.main()
