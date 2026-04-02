"""Unit tests for coordination API authentication (ENC-TSK-930 AC2).

Covers _extract_token, _verify_token, _authenticate with Bearer token,
cookie, expired, malformed, and fallback paths.
"""
import importlib.util
import json
import pathlib
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")
SPEC = importlib.util.spec_from_file_location("coordination_auth_test", MODULE_PATH)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class TestExtractToken(unittest.TestCase):
    """Tests for _extract_token — Bearer header and cookie extraction."""

    def test_bearer_header_extracted(self):
        event = {
            "headers": {"authorization": "Bearer my-access-token"},
            "cookies": [],
        }
        self.assertEqual(mod._extract_token(event), "my-access-token")

    def test_bearer_header_case_insensitive(self):
        event = {
            "headers": {"Authorization": "bearer MY-TOKEN"},
            "cookies": [],
        }
        self.assertEqual(mod._extract_token(event), "MY-TOKEN")

    def test_bearer_header_with_extra_whitespace(self):
        event = {
            "headers": {"authorization": "Bearer   spaced-token  "},
            "cookies": [],
        }
        self.assertEqual(mod._extract_token(event), "spaced-token")

    def test_malformed_bearer_header_no_token(self):
        event = {
            "headers": {"authorization": "Bearer "},
            "cookies": [],
        }
        # Empty token part after "Bearer " — should fall through to cookie
        result = mod._extract_token(event)
        self.assertIsNone(result)

    def test_malformed_auth_header_wrong_scheme(self):
        event = {
            "headers": {"authorization": "Basic dXNlcjpwYXNz"},
            "cookies": [],
        }
        result = mod._extract_token(event)
        self.assertIsNone(result)

    def test_cookie_fallback(self):
        event = {
            "headers": {"cookie": "other=val; enceladus_id_token=cookie-token-123; foo=bar"},
            "cookies": [],
        }
        self.assertEqual(mod._extract_token(event), "cookie-token-123")

    def test_event_cookies_array(self):
        event = {
            "headers": {},
            "cookies": ["enceladus_id_token=from-cookies-array"],
        }
        self.assertEqual(mod._extract_token(event), "from-cookies-array")

    def test_no_auth_returns_none(self):
        event = {"headers": {}, "cookies": []}
        self.assertIsNone(mod._extract_token(event))

    def test_bearer_takes_priority_over_cookie(self):
        event = {
            "headers": {
                "authorization": "Bearer bearer-token",
                "cookie": "enceladus_id_token=cookie-token",
            },
            "cookies": [],
        }
        self.assertEqual(mod._extract_token(event), "bearer-token")


class TestVerifyToken(unittest.TestCase):
    """Tests for _verify_token — JWT validation branches."""

    def _make_valid_claims(self, token_use="access"):
        claims = {
            "sub": "user-123",
            "iss": f"https://cognito-idp.us-east-1.amazonaws.com/{mod.COGNITO_USER_POOL_ID}",
            "token_use": token_use,
            "exp": int(time.time()) + 3600,
        }
        if token_use == "access":
            claims["client_id"] = str(mod.COGNITO_CLIENT_ID or "test-client")
        elif token_use == "id":
            claims["aud"] = str(mod.COGNITO_CLIENT_ID or "test-client")
        return claims

    @patch.object(mod, "_get_jwks")
    def test_valid_access_token_accepted(self, mock_jwks):
        """Valid access token with correct client_id passes validation."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        claims = self._make_valid_claims("access")
        mock_key = MagicMock()
        mock_jwks.return_value = {"test-kid": mock_key}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "test-kid", "alg": "RS256"}):
            with patch.object(mod.jwt, "decode", return_value=claims):
                result = mod._verify_token("fake-token")
                self.assertEqual(result["sub"], "user-123")
                self.assertEqual(result["token_use"], "access")

    @patch.object(mod, "_get_jwks")
    def test_valid_id_token_accepted(self, mock_jwks):
        """Valid ID token with correct aud passes validation."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        claims = self._make_valid_claims("id")
        mock_key = MagicMock()
        mock_jwks.return_value = {"test-kid": mock_key}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "test-kid", "alg": "RS256"}):
            with patch.object(mod.jwt, "decode", return_value=claims):
                result = mod._verify_token("fake-token")
                self.assertEqual(result["token_use"], "id")

    @patch.object(mod, "_get_jwks")
    def test_expired_token_rejected(self, mock_jwks):
        """Expired token raises ValueError."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        mock_key = MagicMock()
        mock_jwks.return_value = {"test-kid": mock_key}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "test-kid", "alg": "RS256"}):
            with patch.object(mod.jwt, "decode", side_effect=mod.jwt.ExpiredSignatureError("expired")):
                with self.assertRaises(ValueError) as ctx:
                    mod._verify_token("expired-token")
                self.assertIn("expired", str(ctx.exception).lower())

    @patch.object(mod, "_get_jwks")
    def test_wrong_client_id_rejected(self, mock_jwks):
        """Access token with wrong client_id raises ValueError."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        claims = self._make_valid_claims("access")
        claims["client_id"] = "wrong-client-id"
        mock_key = MagicMock()
        mock_jwks.return_value = {"test-kid": mock_key}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "test-kid", "alg": "RS256"}):
            with patch.object(mod.jwt, "decode", return_value=claims):
                if mod.COGNITO_CLIENT_ID:
                    with self.assertRaises(ValueError) as ctx:
                        mod._verify_token("wrong-client-token")
                    self.assertIn("mismatch", str(ctx.exception).lower())

    def test_invalid_header_raises(self):
        """Completely malformed token raises ValueError."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        with self.assertRaises(ValueError) as ctx:
            mod._verify_token("not-a-jwt-at-all")
        self.assertIn("invalid", str(ctx.exception).lower())

    @patch.object(mod, "_get_jwks")
    def test_unknown_kid_rejected(self, mock_jwks):
        """Token with unknown key ID raises ValueError."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        mock_jwks.return_value = {"known-kid": MagicMock()}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "unknown-kid", "alg": "RS256"}):
            with self.assertRaises(ValueError) as ctx:
                mod._verify_token("unknown-kid-token")
            self.assertIn("key ID", str(ctx.exception))

    @patch.object(mod, "_get_jwks")
    def test_wrong_algorithm_rejected(self, mock_jwks):
        """Token with non-RS256 algorithm is rejected."""
        if not mod._JWT_AVAILABLE:
            self.skipTest("PyJWT not available")
        mock_jwks.return_value = {"test-kid": MagicMock()}

        with patch.object(mod.jwt, "get_unverified_header", return_value={"kid": "test-kid", "alg": "HS256"}):
            with self.assertRaises(ValueError) as ctx:
                mod._verify_token("hs256-token")
            self.assertIn("algorithm", str(ctx.exception).lower())


class TestAuthenticate(unittest.TestCase):
    """Tests for _authenticate — full auth flow including logging."""

    def _make_event(self, auth_header=None, cookie=None, internal_key=None):
        headers = {}
        if auth_header:
            headers["authorization"] = auth_header
        if cookie:
            headers["cookie"] = cookie
        if internal_key:
            headers["x-coordination-internal-key"] = internal_key
        return {
            "headers": headers,
            "cookies": [],
            "requestContext": {"http": {"sourceIp": "10.0.0.5"}},
        }

    def test_no_token_returns_401(self):
        event = self._make_event()
        claims, err = mod._authenticate(event)
        self.assertIsNone(claims)
        self.assertEqual(err["statusCode"], 401)

    @patch.object(mod, "_verify_token")
    def test_valid_bearer_token_returns_claims(self, mock_verify):
        mock_verify.return_value = {"sub": "user-1", "token_use": "access"}
        event = self._make_event(auth_header="Bearer valid-token")
        claims, err = mod._authenticate(event)
        self.assertIsNone(err)
        self.assertEqual(claims["sub"], "user-1")

    @patch.object(mod, "_verify_token")
    def test_valid_cookie_token_returns_claims(self, mock_verify):
        mock_verify.return_value = {"sub": "user-2", "token_use": "id"}
        event = self._make_event(cookie="enceladus_id_token=cookie-jwt")
        claims, err = mod._authenticate(event)
        self.assertIsNone(err)
        self.assertEqual(claims["sub"], "user-2")

    @patch.object(mod, "_verify_token", side_effect=ValueError("Token has expired"))
    def test_expired_token_returns_401(self, mock_verify):
        event = self._make_event(auth_header="Bearer expired-token")
        claims, err = mod._authenticate(event)
        self.assertIsNone(claims)
        self.assertEqual(err["statusCode"], 401)

    @patch("logging.Logger.warning")
    def test_no_token_logs_auth_failure(self, mock_warn):
        event = self._make_event()
        mod._authenticate(event)
        mock_warn.assert_called()
        log_msg = mock_warn.call_args[0][1]
        parsed = json.loads(log_msg)
        self.assertEqual(parsed["error_type"], "no_token")
        self.assertEqual(parsed["client_ip"], "10.0.0.5")

    @patch("logging.Logger.warning")
    @patch.object(mod, "_verify_token", side_effect=ValueError("Token client_id mismatch."))
    def test_invalid_token_logs_auth_failure(self, mock_verify, mock_warn):
        event = self._make_event(auth_header="Bearer bad-client-token")
        mod._authenticate(event)
        mock_warn.assert_called()
        log_msg = mock_warn.call_args[0][1]
        parsed = json.loads(log_msg)
        self.assertEqual(parsed["error_type"], "token_validation_failed")
        self.assertIn("mismatch", parsed["error_detail"])
        # Must not contain the actual token value
        self.assertNotIn("bad-client-token", log_msg)

    def test_internal_key_bypasses_jwt(self):
        if not mod.COORDINATION_INTERNAL_API_KEYS:
            self.skipTest("No internal API keys configured")
        key = next(iter(mod.COORDINATION_INTERNAL_API_KEYS))
        event = self._make_event(internal_key=key)
        claims, err = mod._authenticate(event)
        self.assertIsNone(err)
        self.assertEqual(claims["auth_mode"], "internal-key")

    def test_missing_auth_header_falls_through_to_cookie(self):
        """Missing Authorization header doesn't block cookie auth path."""
        with patch.object(mod, "_verify_token") as mock_verify:
            mock_verify.return_value = {"sub": "cookie-user"}
            event = self._make_event(cookie="enceladus_id_token=jwt-from-cookie")
            claims, err = mod._authenticate(event)
            self.assertIsNone(err)
            self.assertEqual(claims["sub"], "cookie-user")


class TestGetClientIp(unittest.TestCase):
    """Tests for coordination API _get_client_ip helper."""

    def test_from_source_ip(self):
        event = {"requestContext": {"http": {"sourceIp": "203.0.113.1"}}, "headers": {}}
        self.assertEqual(mod._get_client_ip(event), "203.0.113.1")

    def test_from_x_forwarded_for(self):
        event = {"requestContext": {}, "headers": {"x-forwarded-for": "198.51.100.1, 10.0.0.1"}}
        self.assertEqual(mod._get_client_ip(event), "198.51.100.1")

    def test_unknown_fallback(self):
        event = {"requestContext": {}, "headers": {}}
        self.assertEqual(mod._get_client_ip(event), "unknown")


if __name__ == "__main__":
    unittest.main()
