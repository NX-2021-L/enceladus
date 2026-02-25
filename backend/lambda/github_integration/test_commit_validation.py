"""test_commit_validation.py — Tests for ENC-TSK-596: GitHub commit validation endpoint.

Tests the GET /api/v1/github/commits/validate route added for ENC-FTR-022.

Run: python3 -m pytest test_commit_validation.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

# Set required env vars before import
os.environ.setdefault("GITHUB_APP_ID", "12345")
os.environ.setdefault("GITHUB_INSTALLATION_ID", "67890")
os.environ.setdefault("ALLOWED_REPOS", "NX-2021-L/enceladus")

_spec = importlib.util.spec_from_file_location(
    "github_integration",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
github_integration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(github_integration)


def _make_event(method="GET", path="/api/v1/github/commits/validate",
                query_params=None, internal_key="valid-key"):
    """Build a mock API Gateway event."""
    headers = {}
    if internal_key:
        headers["x-coordination-internal-key"] = internal_key
    return {
        "requestContext": {"http": {"method": method, "path": path}},
        "headers": headers,
        "queryStringParameters": query_params or {},
        "rawPath": path,
        "body": None,
    }


class TestCommitValidationRoute(unittest.TestCase):
    """Route matching for /github/commits/validate."""

    @patch.object(github_integration, "_authenticate")
    @patch.object(github_integration, "_handle_validate_commit")
    def test_get_routes_to_handler(self, mock_handler, mock_auth):
        mock_auth.return_value = ({"sub": "user"}, None)
        mock_handler.return_value = {"statusCode": 200, "body": "{}"}
        event = _make_event(query_params={"owner": "NX-2021-L", "repo": "enceladus", "sha": "a" * 40})
        github_integration.lambda_handler(event, None)
        mock_handler.assert_called_once()


class TestCommitValidationParams(unittest.TestCase):
    """Parameter validation for _handle_validate_commit."""

    def _call(self, query_params):
        event = _make_event(query_params=query_params)
        claims = {"sub": "user"}
        return github_integration._handle_validate_commit(event, claims)

    def test_missing_owner_returns_400(self):
        resp = self._call({"repo": "enceladus", "sha": "a" * 40})
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_repo_returns_400(self):
        resp = self._call({"owner": "NX-2021-L", "sha": "a" * 40})
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_sha_returns_400(self):
        resp = self._call({"owner": "NX-2021-L", "repo": "enceladus"})
        self.assertEqual(resp["statusCode"], 400)

    def test_empty_params_returns_400(self):
        resp = self._call({})
        self.assertEqual(resp["statusCode"], 400)


class TestCommitValidationRepoAllowlist(unittest.TestCase):
    """Disallowed repos return 403."""

    def test_disallowed_repo_returns_403(self):
        event = _make_event(query_params={
            "owner": "evil-org", "repo": "malware", "sha": "a" * 40
        })
        claims = {"sub": "user"}
        resp = github_integration._handle_validate_commit(event, claims)
        self.assertEqual(resp["statusCode"], 403)
        body = json.loads(resp["body"])
        self.assertIn("not allowed", body.get("error", ""))


class TestCommitValidationGitHubAPI(unittest.TestCase):
    """GitHub API responses for valid/invalid commits."""

    @patch.object(github_integration, "_get_installation_token", return_value="mock-token")
    @patch("urllib.request.urlopen")
    def test_valid_sha_returns_commit_data(self, mock_urlopen, mock_token):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "sha": "a" * 40,
            "commit": {
                "message": "Fix bug in parser",
                "author": {"name": "Test User", "date": "2026-02-25T15:00:00Z"},
            },
        }).encode()
        mock_urlopen.return_value = mock_resp

        event = _make_event(query_params={
            "owner": "NX-2021-L", "repo": "enceladus", "sha": "a" * 40
        })
        resp = github_integration._handle_validate_commit(event, {"sub": "user"})
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertTrue(body["valid"])
        self.assertEqual(body["sha"], "a" * 40)
        self.assertEqual(body["author"], "Test User")
        self.assertIn("Fix bug", body["message"])

    @patch.object(github_integration, "_get_installation_token", return_value="mock-token")
    @patch("urllib.request.urlopen")
    def test_invalid_sha_returns_not_found(self, mock_urlopen, mock_token):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.github.com/repos/NX-2021-L/enceladus/commits/bad",
            404, "Not Found", {}, None
        )
        event = _make_event(query_params={
            "owner": "NX-2021-L", "repo": "enceladus", "sha": "b" * 40
        })
        resp = github_integration._handle_validate_commit(event, {"sub": "user"})
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertFalse(body["valid"])
        self.assertEqual(body["reason"], "commit_not_found")

    @patch.object(github_integration, "_get_installation_token", return_value="mock-token")
    @patch("urllib.request.urlopen")
    def test_github_500_returns_502(self, mock_urlopen, mock_token):
        import urllib.error
        error = urllib.error.HTTPError(
            "https://api.github.com/repos/NX-2021-L/enceladus/commits/x",
            500, "Internal Server Error", {},
            MagicMock(read=MagicMock(return_value=b"server error"))
        )
        error.read = MagicMock(return_value=b"server error")
        mock_urlopen.side_effect = error
        event = _make_event(query_params={
            "owner": "NX-2021-L", "repo": "enceladus", "sha": "c" * 40
        })
        resp = github_integration._handle_validate_commit(event, {"sub": "user"})
        self.assertEqual(resp["statusCode"], 502)


if __name__ == "__main__":
    unittest.main()
