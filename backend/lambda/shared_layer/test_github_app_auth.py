"""test_github_app_auth.py — Unit tests for enceladus_shared.github_app_auth.

ENC-TSK-O07 (ENC-ISS-621 C4): covers the hardened semantics extracted from
the four lambdas' duplicated GitHub App JWT / installation-token minting —
the 401/403 re-mint-and-retry with a 60s token-age floor, the expires_at
-driven cache expiry (with now+3600 fallback), and the structured
github_validation_fail / mint logging.

Run:
    python3 -m unittest discover -s backend/lambda/shared_layer -p 'test_github_app_auth.py' -v
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "python"))

from enceladus_shared import github_app_auth as gha  # noqa: E402


def _config(**overrides) -> "gha.GitHubAppConfig":
    defaults = dict(
        app_id="12345",
        installation_id="67890",
        private_key_secret="devops/github-app/test-key",
        region="us-west-2",
        api_base="https://api.github.com",
    )
    defaults.update(overrides)
    return gha.GitHubAppConfig(**defaults)


class ParseExpiresAtTests(unittest.TestCase):
    def test_valid_iso8601_z_suffix_parses(self):
        epoch = gha._parse_expires_at("2020-01-22T19:33:11Z")
        self.assertAlmostEqual(epoch, 1579721591.0, delta=1)

    def test_missing_falls_back_to_now_plus_3600(self):
        before = time.time()
        epoch = gha._parse_expires_at(None)
        after = time.time()
        self.assertGreaterEqual(epoch, before + gha._FALLBACK_TOKEN_TTL_S)
        self.assertLessEqual(epoch, after + gha._FALLBACK_TOKEN_TTL_S)

    def test_unparseable_falls_back_to_now_plus_3600(self):
        before = time.time()
        epoch = gha._parse_expires_at("not-a-timestamp")
        after = time.time()
        self.assertGreaterEqual(epoch, before + gha._FALLBACK_TOKEN_TTL_S)
        self.assertLessEqual(epoch, after + gha._FALLBACK_TOKEN_TTL_S)


class GenerateAppJwtTests(unittest.TestCase):
    def test_raises_when_jwt_unavailable(self):
        with patch.object(gha, "_JWT_AVAILABLE", False):
            with self.assertRaises(ValueError):
                gha.generate_app_jwt(_config())

    def test_raises_when_app_id_missing(self):
        with self.assertRaises(ValueError):
            gha.generate_app_jwt(_config(app_id=""))

    @patch.object(gha, "_get_private_key", return_value="fake-pem")
    def test_encodes_iss_as_string_with_expected_claims(self, _mock_key):
        with patch.object(gha, "jwt") as mock_jwt:
            mock_jwt.encode.return_value = "signed.jwt.token"
            token = gha.generate_app_jwt(_config(app_id="999"))
        self.assertEqual(token, "signed.jwt.token")
        payload = mock_jwt.encode.call_args[0][0]
        self.assertEqual(payload["iss"], "999")
        self.assertLess(payload["iat"], int(time.time()))
        self.assertGreater(payload["exp"], int(time.time()))


class MintInstallationTokenTests(unittest.TestCase):
    def test_raises_when_installation_id_missing(self):
        with self.assertRaises(ValueError):
            gha._mint_installation_token(_config(installation_id=""))

    @patch.object(gha, "generate_app_jwt", return_value="app-jwt")
    def test_logs_expires_at_and_permission_keys_only(self, _mock_jwt):
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        resp.read.return_value = (
            b'{"token": "ghs_abc", "expires_at": "2020-01-22T19:33:11Z", '
            b'"permissions": {"contents": "read", "issues": "write"}}'
        )
        with patch.object(gha.urllib.request, "urlopen", return_value=resp), \
             patch.object(gha, "logger") as mock_logger:
            entry = gha._mint_installation_token(_config())

        self.assertEqual(entry["token"], "ghs_abc")
        self.assertAlmostEqual(entry["expires_at_epoch"], 1579721591.0, delta=1)

        info_call = mock_logger.info.call_args
        self.assertIn("github_app_token_minted", info_call[0][0])
        logged_expires_at, logged_perm_keys = info_call[0][1], info_call[0][2]
        self.assertEqual(logged_expires_at, "2020-01-22T19:33:11Z")
        # Keys only, sorted — values ("read"/"write") must never appear.
        self.assertEqual(logged_perm_keys, ["contents", "issues"])
        for call in mock_logger.info.call_args_list:
            self.assertNotIn("read", call[0])
            self.assertNotIn("write", call[0])

    @patch.object(gha, "generate_app_jwt", return_value="app-jwt")
    def test_fallback_expiry_when_expires_at_absent(self, _mock_jwt):
        resp = MagicMock()
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        resp.read.return_value = b'{"token": "ghs_abc"}'
        before = time.time()
        with patch.object(gha.urllib.request, "urlopen", return_value=resp):
            entry = gha._mint_installation_token(_config())
        self.assertGreaterEqual(entry["expires_at_epoch"], before + gha._FALLBACK_TOKEN_TTL_S)


class TokenCacheTests(unittest.TestCase):
    def _entry(self, token="tok", age_s=0.0, ttl_s=3600.0):
        now = time.time()
        return {"token": token, "minted_at": now - age_s, "expires_at_epoch": now - age_s + ttl_s}

    def setUp(self):
        gha._token_cache.clear()

    def tearDown(self):
        gha._token_cache.clear()

    @patch.object(gha, "_mint_installation_token")
    def test_mints_once_and_serves_cache_within_buffer(self, mock_mint):
        mock_mint.return_value = self._entry()
        config = _config()
        first = gha.get_installation_token(config)
        second = gha.get_installation_token(config)
        self.assertEqual(first, "tok")
        self.assertEqual(second, "tok")
        mock_mint.assert_called_once()

    @patch.object(gha, "_mint_installation_token")
    def test_remints_once_past_refresh_buffer(self, mock_mint):
        # expires_at_epoch within the 300s refresh buffer of "now" -> stale.
        stale_entry = self._entry(age_s=3400.0, ttl_s=3600.0)  # 200s of life left
        fresh_entry = self._entry(token="tok2")
        mock_mint.side_effect = [stale_entry, fresh_entry]
        config = _config()
        first = gha.get_installation_token(config)
        second = gha.get_installation_token(config)
        self.assertEqual(first, "tok")
        self.assertEqual(second, "tok2")
        self.assertEqual(mock_mint.call_count, 2)

    @patch.object(gha, "_mint_installation_token")
    def test_force_refresh_always_remints(self, mock_mint):
        mock_mint.return_value = self._entry()
        config = _config()
        gha.get_installation_token(config)
        gha.get_installation_token(config, force_refresh=True)
        self.assertEqual(mock_mint.call_count, 2)


class GithubRequestRetryTests(unittest.TestCase):
    def setUp(self):
        gha._token_cache.clear()

    def tearDown(self):
        gha._token_cache.clear()

    def _old_entry(self, token="tok-old"):
        now = time.time()
        return {"token": token, "minted_at": now - 120, "expires_at_epoch": now + 3000}

    def _fresh_entry(self, token="tok-new"):
        now = time.time()
        return {"token": token, "minted_at": now, "expires_at_epoch": now + 3600}

    @patch.object(gha, "_do_request")
    @patch.object(gha, "_mint_installation_token")
    def test_200_makes_a_single_call_no_retry(self, mock_mint, mock_do_request):
        mock_mint.return_value = self._old_entry()
        mock_do_request.return_value = (200, {"sha": "a" * 40})
        status, body = gha.github_request(_config(), "GET", "/repos/o/r/commits/x")
        self.assertEqual(status, 200)
        self.assertEqual(mock_do_request.call_count, 1)
        mock_mint.assert_called_once()  # one mint, no re-mint

    @patch.object(gha, "_do_request")
    @patch.object(gha, "_mint_installation_token")
    @patch.object(gha, "_log_validation_fail")
    def test_401_past_age_floor_remints_and_retries_once(
        self, mock_log, mock_mint, mock_do_request
    ):
        mock_mint.side_effect = [self._old_entry(), self._fresh_entry()]
        mock_do_request.side_effect = [(401, {"message": "Bad credentials"}), (200, {"ok": True})]

        status, body = gha.github_request(
            _config(), "GET", "/repos/o/r/commits/x", repo="o/r", sha="x" * 40
        )

        self.assertEqual(status, 200)
        self.assertEqual(mock_do_request.call_count, 2)  # original + single retry
        self.assertEqual(mock_mint.call_count, 2)  # one mint + exactly one re-mint
        mock_log.assert_called_once()
        args = mock_log.call_args[0]
        self.assertEqual(args[0], "/repos/o/r/commits/x")  # endpoint
        self.assertEqual(args[1], 401)  # status
        self.assertGreaterEqual(args[3], gha._REMINT_AGE_FLOOR_S)  # token_age_s
        self.assertEqual(args[4], "o/r")  # repo
        self.assertEqual(args[5], "x" * 40)  # sha

    @patch.object(gha, "_do_request")
    @patch.object(gha, "_mint_installation_token")
    @patch.object(gha, "_log_validation_fail")
    def test_401_under_age_floor_does_not_remint_or_loop(
        self, mock_log, mock_mint, mock_do_request
    ):
        mock_mint.return_value = self._fresh_entry()  # token minted "now" — under the floor
        mock_do_request.return_value = (401, {"message": "Bad credentials"})

        status, body = gha.github_request(_config(), "GET", "/repos/o/r/commits/x")

        self.assertEqual(status, 401)
        self.assertEqual(mock_do_request.call_count, 1)  # no retry
        mock_mint.assert_called_once()  # no re-mint
        mock_log.assert_called_once()

    @patch.object(gha, "_do_request")
    @patch.object(gha, "_mint_installation_token")
    @patch.object(gha, "_log_validation_fail")
    def test_persistent_401_after_retry_never_loops(self, mock_log, mock_mint, mock_do_request):
        """Both the original and the retried call fail — at most one re-mint,
        exactly two calls total, and the function returns rather than looping."""
        mock_mint.side_effect = [self._old_entry(), self._fresh_entry()]
        mock_do_request.side_effect = [
            (403, {"message": "first"}),
            (403, {"message": "second"}),
        ]

        status, body = gha.github_request(_config(), "GET", "/repos/o/r/commits/x")

        self.assertEqual(status, 403)
        self.assertEqual(mock_do_request.call_count, 2)
        self.assertEqual(mock_mint.call_count, 2)
        self.assertEqual(mock_log.call_count, 2)  # one log per failed attempt


if __name__ == "__main__":
    unittest.main()
