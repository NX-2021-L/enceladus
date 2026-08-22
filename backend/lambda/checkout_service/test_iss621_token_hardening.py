"""Unit tests for ENC-TSK-O03 / ENC-ISS-621 GitHub App token path hardening.

Covers three changes to backend/lambda/checkout_service/lambda_function.py:

  B1 — _github_request re-mints and retries EXACTLY ONCE on a 401/403, but
       only when the cached token is older than 60s (age floor prevents a
       mint storm when GitHub is 403-ing even brand-new tokens).
  B2 — _get_installation_token honors the mint response's `expires_at`
       (ISO-8601) instead of always assuming a 1-hour lifetime, falling back
       to now+3600 when the field is absent or unparseable.
  B3 — structured `[ISS-621] github_validation_fail` logging on validation
       failure, and mint-time logging of expires_at + permission KEYS (never
       values).

Per house style (see test_validate_commit_installation_scope.py), the module
is loaded directly from file and patched via unittest.mock.patch.object.
Retry-path tests stub beneath _github_request (_do_github_get / the urllib
layer, and _get_installation_token) since existing tests already patch
_github_request itself for the commit/PR validation call sites.
"""

import importlib.util
import json
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "checkout_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(checkout_service)


class _FakeUrlopenResponse:
    """Minimal context-manager stand-in for urllib.request.urlopen()'s
    return value, used to exercise the real _get_installation_token mint
    path without hitting the network."""

    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _reset_token_globals():
    checkout_service._installation_token_cache = None
    checkout_service._installation_token_expires_at = 0.0
    checkout_service._installation_token_minted_at = 0.0


class GithubRequestRemintRetryTests(unittest.TestCase):
    """B1: re-mint + single retry on 401/403, gated by a 60s token-age floor."""

    def setUp(self):
        _reset_token_globals()

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token")
    @patch.object(checkout_service, "_do_github_get")
    def test_403_with_old_token_remints_and_retries_once(self, mock_get, mock_mint):
        checkout_service._installation_token_cache = "stale-token"
        checkout_service._installation_token_expires_at = time.time() + 1000
        checkout_service._installation_token_minted_at = time.time() - 120  # age=120s > 60s

        mock_mint.return_value = "fresh-token"
        mock_get.side_effect = [
            (403, {"message": "Bad credentials"}),
            (200, {"sha": "a" * 40}),
        ]

        status, body = checkout_service._github_request(
            "/repos/NX-2021-L/enceladus/commits/" + "a" * 40
        )

        self.assertEqual(status, 200)
        self.assertEqual(mock_get.call_count, 2)  # exactly one retry
        self.assertEqual(mock_mint.call_count, 2)  # initial fetch + one re-mint

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token")
    @patch.object(checkout_service, "_do_github_get")
    def test_403_with_fresh_token_does_not_remint(self, mock_get, mock_mint):
        checkout_service._installation_token_cache = "fresh-token"
        checkout_service._installation_token_expires_at = time.time() + 1000
        checkout_service._installation_token_minted_at = time.time() - 10  # age=10s <= 60s

        mock_mint.return_value = "fresh-token"
        mock_get.return_value = (403, {"message": "Bad credentials"})

        status, body = checkout_service._github_request(
            "/repos/NX-2021-L/enceladus/commits/" + "a" * 40
        )

        self.assertEqual(status, 403)
        self.assertEqual(mock_get.call_count, 1)  # no retry
        self.assertEqual(mock_mint.call_count, 1)  # only the initial fetch, no re-mint

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token")
    @patch.object(checkout_service, "_do_github_get")
    def test_persistent_403_does_not_loop(self, mock_get, mock_mint):
        """A persistently-403ing endpoint must still stop after exactly one
        retry — never an infinite re-mint loop."""
        checkout_service._installation_token_cache = "stale-token"
        checkout_service._installation_token_expires_at = time.time() + 1000
        checkout_service._installation_token_minted_at = time.time() - 300

        mock_mint.return_value = "still-bad-token"
        mock_get.return_value = (403, {"message": "Bad credentials"})  # always 403

        status, body = checkout_service._github_request(
            "/repos/NX-2021-L/enceladus/commits/" + "a" * 40
        )

        self.assertEqual(status, 403)
        self.assertEqual(mock_get.call_count, 2)  # initial + exactly one retry, then stop
        self.assertEqual(mock_mint.call_count, 2)

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token")
    @patch.object(checkout_service, "_do_github_get")
    def test_retry_result_returned_even_when_retry_also_fails(self, mock_get, mock_mint):
        checkout_service._installation_token_cache = "stale-token"
        checkout_service._installation_token_expires_at = time.time() + 1000
        checkout_service._installation_token_minted_at = time.time() - 300

        mock_mint.return_value = "fresh-but-still-bad"
        mock_get.side_effect = [
            (401, {"message": "Bad credentials"}),
            (403, {"message": "Forbidden"}),
        ]

        status, body = checkout_service._github_request(
            "/repos/NX-2021-L/enceladus/commits/" + "a" * 40
        )

        # The retry's own result is returned, not the original.
        self.assertEqual(status, 403)
        self.assertEqual(body, {"message": "Forbidden"})


class GetInstallationTokenExpiryTests(unittest.TestCase):
    """B2: honor server-provided expires_at; fall back to now+3600."""

    def setUp(self):
        _reset_token_globals()

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_generate_app_jwt", return_value="fake.jwt.token")
    @patch("urllib.request.urlopen")
    def test_expires_at_from_response_is_honored(self, mock_urlopen, _mock_jwt):
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        expires_at_str = future.strftime("%Y-%m-%dT%H:%M:%SZ")
        mock_urlopen.return_value = _FakeUrlopenResponse(
            {"token": "minted-token", "expires_at": expires_at_str, "permissions": {}}
        )

        token = checkout_service._get_installation_token()

        self.assertEqual(token, "minted-token")
        expected_epoch = datetime.fromisoformat(
            expires_at_str.replace("Z", "+00:00")
        ).timestamp()
        self.assertAlmostEqual(
            checkout_service._installation_token_expires_at, expected_epoch, delta=2
        )

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_generate_app_jwt", return_value="fake.jwt.token")
    @patch("urllib.request.urlopen")
    def test_missing_expires_at_falls_back_to_now_plus_3600(self, mock_urlopen, _mock_jwt):
        mock_urlopen.return_value = _FakeUrlopenResponse({"token": "minted-token"})

        before = time.time()
        checkout_service._get_installation_token()
        after = time.time()

        self.assertGreaterEqual(
            checkout_service._installation_token_expires_at, before + 3600 - 2
        )
        self.assertLessEqual(
            checkout_service._installation_token_expires_at, after + 3600 + 2
        )

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_generate_app_jwt", return_value="fake.jwt.token")
    @patch("urllib.request.urlopen")
    def test_malformed_expires_at_falls_back_to_now_plus_3600(self, mock_urlopen, _mock_jwt):
        mock_urlopen.return_value = _FakeUrlopenResponse(
            {"token": "minted-token", "expires_at": "not-a-real-timestamp"}
        )

        before = time.time()
        checkout_service._get_installation_token()
        after = time.time()

        self.assertGreaterEqual(
            checkout_service._installation_token_expires_at, before + 3600 - 2
        )
        self.assertLessEqual(
            checkout_service._installation_token_expires_at, after + 3600 + 2
        )


class StructuredLoggingTests(unittest.TestCase):
    """B3: validation-failure logging and mint-time diagnostic logging."""

    def setUp(self):
        _reset_token_globals()

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token", return_value="tok")
    @patch.object(checkout_service, "_do_github_get", return_value=(404, {"message": "Not Found"}))
    def test_validation_fail_log_line_for_commits(self, _mock_get, _mock_mint):
        checkout_service._installation_token_cache = "tok"
        checkout_service._installation_token_minted_at = time.time() - 5
        checkout_service._installation_token_expires_at = time.time() + 1000

        sha = "b" * 40
        with self.assertLogs(checkout_service.logger, level="WARNING") as cm:
            status, _body = checkout_service._github_request(
                f"/repos/NX-2021-L/enceladus/commits/{sha}"
            )

        self.assertEqual(status, 404)
        line = next(l for l in cm.output if "github_validation_fail" in l)
        self.assertIn("[ISS-621] github_validation_fail", line)
        self.assertIn("endpoint=commits", line)
        self.assertIn("status=404", line)
        self.assertIn("msg=Not Found", line)
        self.assertIn("repo=NX-2021-L/enceladus", line)
        self.assertIn(f"sha={sha}", line)
        self.assertRegex(line, r"token_age_s=\d+")

    @patch.object(checkout_service, "GITHUB_APP_ID", "999")
    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_get_installation_token", return_value="tok")
    @patch.object(checkout_service, "_do_github_get", return_value=(404, {"message": "Not Found"}))
    def test_validation_fail_log_line_for_pulls_has_no_sha(self, _mock_get, _mock_mint):
        checkout_service._installation_token_cache = "tok"
        checkout_service._installation_token_minted_at = time.time() - 5
        checkout_service._installation_token_expires_at = time.time() + 1000

        with self.assertLogs(checkout_service.logger, level="WARNING") as cm:
            checkout_service._github_request("/repos/NX-2021-L/enceladus/pulls/42")

        line = next(l for l in cm.output if "github_validation_fail" in l)
        self.assertIn("endpoint=pulls", line)
        self.assertIn("sha=-", line)
        self.assertIn("repo=NX-2021-L/enceladus", line)

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(checkout_service, "_generate_app_jwt", return_value="fake.jwt.token")
    @patch("urllib.request.urlopen")
    def test_mint_logs_expires_at_and_permission_keys_only(self, mock_urlopen, _mock_jwt):
        mock_urlopen.return_value = _FakeUrlopenResponse(
            {
                "token": "minted-token",
                "expires_at": "2026-08-17T18:00:00Z",
                # Distinct values (not "read") so a values-leak would be
                # detectable in the assertions below.
                "permissions": {"metadata": "admin", "contents": "write"},
            }
        )

        with self.assertLogs(checkout_service.logger, level="INFO") as cm:
            checkout_service._get_installation_token()

        line = next(l for l in cm.output if "github_token_minted" in l)
        self.assertIn("expires_at=2026-08-17T18:00:00Z", line)
        # Keys only, sorted, never the permission values.
        self.assertIn("permissions=contents,metadata", line)
        self.assertNotIn("admin", line)
        self.assertNotIn("write", line)


if __name__ == "__main__":
    unittest.main()
