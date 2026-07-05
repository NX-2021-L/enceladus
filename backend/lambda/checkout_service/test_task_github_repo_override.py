"""Unit tests for _resolve_task_github_repo (per-task GitHub repo override).

ENC-FTR-119: satellite repos (e.g. enceladus-support) host code for tasks
that still live under the primary project's project_id, so the
project-level ``repo`` field alone (_resolve_github_repo) cannot express
"this one task's code is in a different repo than its siblings." Before this
fix, the only way to correct that was for the caller to remember to pass
transition_evidence.owner/repo at every single advance (committed, pr,
merged-main, closed) -- forgetting any one of them silently fell back to the
project default and produced a confusing GitHub 404/422 far from the real
cause (this is what happened to ENC-TSK-J49: code lived in
NX-2021-L/enceladus-support but committed/pr validation silently resolved to
NX-2021-L/enceladus).

These tests guard the new task-level ``github_repo`` override field, which
once set on a task durably applies to every subsequent advance without
per-call evidence.
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


class ResolveTaskGithubRepoTests(unittest.TestCase):
    def test_task_override_owner_slash_repo_wins_over_project_default(self):
        task = {"github_repo": "NX-2021-L/enceladus-support"}
        with patch.object(
            checkout_service, "_resolve_github_repo"
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus-support"))
        project_mock.assert_not_called()

    def test_task_override_full_url_is_parsed(self):
        task = {"github_repo": "https://github.com/NX-2021-L/enceladus-support"}
        with patch.object(
            checkout_service, "_resolve_github_repo"
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus-support"))
        project_mock.assert_not_called()

    def test_no_override_falls_back_to_project_resolution(self):
        task = {}
        with patch.object(
            checkout_service, "_resolve_github_repo",
            return_value=("NX-2021-L", "enceladus"),
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        project_mock.assert_called_once_with("enceladus")

    def test_blank_override_falls_back_to_project_resolution(self):
        task = {"github_repo": "   "}
        with patch.object(
            checkout_service, "_resolve_github_repo",
            return_value=("NX-2021-L", "enceladus"),
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        project_mock.assert_called_once_with("enceladus")

    def test_unparseable_override_falls_back_to_project_resolution(self):
        """A malformed override (no slash, not a URL) should not silently
        resolve to a broken (owner, None) pair -- fall back to the project
        default and log a warning instead."""
        task = {"github_repo": "not-a-valid-repo-string"}
        with patch.object(
            checkout_service, "_resolve_github_repo",
            return_value=("NX-2021-L", "enceladus"),
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        project_mock.assert_called_once_with("enceladus")

    def test_override_with_trailing_slash_segments_takes_first_two(self):
        task = {"github_repo": "NX-2021-L/enceladus-support/extra"}
        with patch.object(
            checkout_service, "_resolve_github_repo"
        ) as project_mock:
            owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        # partition() on the first "/" -- repo captures everything after it.
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus-support/extra"))
        project_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
