"""Unit tests for _validate_commit installation-scope self-diagnosis.

ENC-TSK-C68 / ENC-ISS-183: on a GitHub 404 during commit validation, the
checkout service should probe the installation's accessible-repositories list
and, when the target repo is not in scope, return a descriptive error
pointing at the installation management URL instead of the ambiguous
"Commit <sha> not found" message.

Root cause these tests are guarding against: the enceladus-integration App
installation on NX-2021-L was scoped `repository_selection=selected` and did
not list NX-2021-L/devops, so every devops-project task stalled at
coding-complete for weeks. The error surfaced by _validate_commit looked like
a commit resolution bug, but the actual fix was an Organization Owner click
in the GitHub UI. The new error path makes that root cause immediately
discoverable from the advance-task-status response body.
"""

import importlib.util
import os
import unittest
from unittest.mock import patch


_SPEC = importlib.util.spec_from_file_location(
    "checkout_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(checkout_service)


class ValidateCommitInstallationScopeTests(unittest.TestCase):
    def setUp(self):
        # Clear the installation-repos cache between tests so each case sees a
        # fresh lookup path.
        checkout_service._installation_repos_cache = None
        checkout_service._installation_repos_expires_at = 0.0

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(
        checkout_service,
        "_list_installation_repos",
        return_value={"NX-2021-L/enceladus", "NX-2021-L/mod"},
    )
    @patch.object(
        checkout_service,
        "_github_request",
        return_value=(404, {"message": "Not Found"}),
    )
    def test_installation_scope_404_returns_descriptive_error(
        self, _mock_gh, _mock_list
    ):
        ok, reason = checkout_service._validate_commit(
            "NX-2021-L", "devops", "bb92ce0459259d7c3ae21a4189e227cf8c5fa19f"
        )
        self.assertFalse(ok)
        self.assertIn("enceladus-integration", reason)
        self.assertIn("does not have access to NX-2021-L/devops", reason)
        self.assertIn("112392089", reason)
        self.assertIn(
            "https://github.com/organizations/NX-2021-L/settings/installations/112392089",
            reason,
        )
        self.assertIn("Organization Owner required", reason)
        # Currently accessible list is included to help the operator confirm
        # which repos the installation can see.
        self.assertIn("NX-2021-L/enceladus", reason)

    @patch.object(checkout_service, "GITHUB_INSTALLATION_ID", "112392089")
    @patch.object(
        checkout_service,
        "_list_installation_repos",
        return_value={"NX-2021-L/devops", "NX-2021-L/enceladus"},
    )
    @patch.object(
        checkout_service,
        "_github_request",
        return_value=(404, {"message": "Not Found"}),
    )
    def test_in_scope_404_returns_generic_commit_not_found(
        self, _mock_gh, _mock_list
    ):
        """If the repo IS in the installation scope, the 404 really means the
        commit does not exist. Preserve the original error for that case so
        we do not mislead operators into chasing a non-existent access bug.
        """
        missing_sha = "0" * 40
        ok, reason = checkout_service._validate_commit(
            "NX-2021-L", "devops", missing_sha
        )
        self.assertFalse(ok)
        self.assertEqual(reason, f"Commit {missing_sha} not found in NX-2021-L/devops")
        self.assertNotIn("enceladus-integration", reason)

    @patch.object(
        checkout_service,
        "_list_installation_repos",
        return_value=set(),
    )
    @patch.object(
        checkout_service,
        "_github_request",
        return_value=(404, {"message": "Not Found"}),
    )
    def test_probe_failure_falls_back_to_generic_error(
        self, _mock_gh, _mock_list
    ):
        """If the installation-repos probe returns an empty set (probe failed
        or installation is legitimately empty), fall back to the generic
        'commit not found' error rather than inventing a misleading
        installation-scope message.
        """
        ok, reason = checkout_service._validate_commit(
            "NX-2021-L", "devops", "a" * 40
        )
        self.assertFalse(ok)
        self.assertIn("not found in NX-2021-L/devops", reason)
        self.assertNotIn("enceladus-integration", reason)

    @patch.object(
        checkout_service,
        "_github_request",
        return_value=(200, {"sha": "a" * 40}),
    )
    def test_commit_found_returns_success_without_probing(self, _mock_gh):
        """Happy path: a 200 response bypasses the installation probe entirely
        and returns success. Guards against accidentally introducing a probe
        call on the fast path."""
        with patch.object(
            checkout_service, "_list_installation_repos"
        ) as probe_mock:
            ok, reason = checkout_service._validate_commit(
                "NX-2021-L", "devops", "a" * 40
            )
            self.assertTrue(ok)
            self.assertEqual(reason, "")
            probe_mock.assert_not_called()

    @patch.object(
        checkout_service,
        "_github_request",
        return_value=(500, {"message": "Internal Server Error"}),
    )
    def test_non_404_error_returns_api_error_without_probing(self, _mock_gh):
        """Non-404 errors (500, 502, timeouts surfaced as 503) should not
        trigger the installation-scope probe — the repo access check is only
        meaningful on 404."""
        with patch.object(
            checkout_service, "_list_installation_repos"
        ) as probe_mock:
            ok, reason = checkout_service._validate_commit(
                "NX-2021-L", "devops", "a" * 40
            )
            self.assertFalse(ok)
            self.assertIn("GitHub API returned 500", reason)
            probe_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
