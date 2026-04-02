"""Unit tests for Bedrock agent GitHub action handlers (ENC-TSK-954/955/956/962).

Covers _handle_github_create_branch, _handle_github_create_commit,
_handle_github_create_pr, _handle_github_status, _handle_schema_version,
_build_write_source, _validate_repo, _validate_branch_name, _rollback_github_state.
"""
import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

MODULE_PATH = pathlib.Path(__file__).with_name("lambda_function.py")


def _load_module(**env):
    import uuid
    module_name = f"bedrock_actions_test_{uuid.uuid4().hex}"
    defaults = {
        "TRACKER_TABLE": "test-tracker",
        "PROJECTS_TABLE": "test-projects",
        "DOCUMENTS_TABLE": "test-documents",
        "DEPLOY_TABLE": "test-deploy",
        "GITHUB_TOKEN": "ghp_test_token_1234567890",
        "GITHUB_API_BASE": "https://api.github.com",
        "ALLOWED_REPOS": "NX-2021-L/enceladus,test-org/test-repo",
    }
    defaults.update(env)
    with patch.dict(os.environ, defaults, clear=False):
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


mod = _load_module()


class TestValidateRepo(unittest.TestCase):
    def test_allowed_repo_passes(self):
        self.assertIsNone(mod._validate_repo("NX-2021-L", "enceladus"))

    def test_disallowed_repo_fails(self):
        err = mod._validate_repo("evil-org", "evil-repo")
        self.assertIsNotNone(err)
        self.assertIn("not in allowed list", err)

    def test_case_insensitive(self):
        self.assertIsNone(mod._validate_repo("nx-2021-l", "Enceladus"))


class TestValidateBranchName(unittest.TestCase):
    def test_valid_agent_branch(self):
        self.assertIsNone(mod._validate_branch_name("agent/bedrock-1/ENC-TSK-954-github"))

    def test_invalid_branch_no_agent_prefix(self):
        err = mod._validate_branch_name("feature/my-branch")
        self.assertIsNotNone(err)
        self.assertIn("does not match", err)

    def test_invalid_branch_missing_tracker_id(self):
        err = mod._validate_branch_name("agent/bedrock-1/no-tracker")
        self.assertIsNotNone(err)


class TestBuildWriteSource(unittest.TestCase):
    def test_with_session_attributes(self):
        ws = mod._build_write_source({"agentId": "agent-123", "dispatchId": "disp-456"})
        self.assertEqual(ws["channel"], "bedrock_agent_action")
        self.assertEqual(ws["agent_id"], "agent-123")
        self.assertEqual(ws["dispatch_id"], "disp-456")
        self.assertIn("timestamp", ws)

    def test_without_session_attributes(self):
        ws = mod._build_write_source()
        self.assertEqual(ws["channel"], "bedrock_agent_action")
        self.assertEqual(ws["agent_id"], "")

    def test_with_none(self):
        ws = mod._build_write_source(None)
        self.assertEqual(ws["channel"], "bedrock_agent_action")


class TestHandleGithubCreateBranch(unittest.TestCase):
    @patch.object(mod, "_github_request")
    def test_happy_path(self, mock_req):
        mock_req.side_effect = [
            (200, {"object": {"sha": "abc123def456"}}),  # GET ref
            (201, {"ref": "refs/heads/agent/bedrock/ENC-TSK-954-test"}),  # POST ref
        ]
        result = mod._handle_github_create_branch([], {
            "owner": "NX-2021-L", "repo": "enceladus",
            "branch_name": "agent/bedrock/ENC-TSK-954-test",
        })
        self.assertTrue(result["success"])
        self.assertEqual(result["branch"], "agent/bedrock/ENC-TSK-954-test")
        self.assertEqual(result["base_sha"], "abc123def456")

    def test_missing_params(self):
        result = mod._handle_github_create_branch([], {"owner": "NX-2021-L"})
        self.assertIn("error", result)

    def test_disallowed_repo(self):
        result = mod._handle_github_create_branch([], {
            "owner": "evil", "repo": "repo",
            "branch_name": "agent/test/ENC-TSK-1-x",
        })
        self.assertIn("error", result)
        self.assertIn("not in allowed", result["error"])

    def test_invalid_branch_name(self):
        result = mod._handle_github_create_branch([], {
            "owner": "NX-2021-L", "repo": "enceladus",
            "branch_name": "bad-name",
        })
        self.assertIn("error", result)
        self.assertIn("does not match", result["error"])


class TestHandleGithubCreateCommit(unittest.TestCase):
    @patch.object(mod, "_github_request")
    def test_happy_path_multi_file(self, mock_req):
        mock_req.side_effect = [
            (200, {"object": {"sha": "parent123"}}),  # GET ref
            (200, {"tree": {"sha": "tree123"}}),  # GET commit
            (201, {"sha": "blob1"}),  # POST blob 1
            (201, {"sha": "blob2"}),  # POST blob 2
            (201, {"sha": "newtree123"}),  # POST tree
            (201, {"sha": "commit123", "html_url": "https://github.com/..."}),  # POST commit
            (200, {}),  # PATCH ref
        ]
        result = mod._handle_github_create_commit([], {
            "owner": "NX-2021-L", "repo": "enceladus",
            "branch": "agent/test/ENC-TSK-1-x",
            "message": "[ENC-TSK-1] test commit",
            "files": [
                {"path": "file1.py", "content": "print('hello')"},
                {"path": "file2.py", "content": "print('world')"},
            ],
        })
        self.assertTrue(result["success"])
        self.assertEqual(result["commit_sha"], "commit123")
        self.assertEqual(result["files_committed"], 2)

    def test_missing_files(self):
        result = mod._handle_github_create_commit([], {
            "owner": "NX-2021-L", "repo": "enceladus",
            "branch": "test", "message": "test",
        })
        self.assertIn("error", result)


class TestHandleGithubCreatePR(unittest.TestCase):
    @patch.object(mod, "_github_request")
    def test_happy_path(self, mock_req):
        mock_req.return_value = (201, {
            "number": 42, "html_url": "https://github.com/NX-2021-L/enceladus/pull/42",
            "state": "open",
        })
        result = mod._handle_github_create_pr([], {
            "owner": "NX-2021-L", "repo": "enceladus",
            "title": "Test PR", "head": "agent/test/ENC-TSK-1-x",
        })
        self.assertTrue(result["success"])
        self.assertEqual(result["pr_number"], 42)

    def test_missing_head(self):
        result = mod._handle_github_create_pr([], {
            "owner": "NX-2021-L", "repo": "enceladus", "title": "Test",
        })
        self.assertIn("error", result)


class TestHandleGithubStatus(unittest.TestCase):
    @patch.object(mod, "_github_request")
    def test_pr_status(self, mock_req):
        mock_req.return_value = (200, {
            "number": 42, "state": "open", "merged": False, "mergeable": True, "title": "Test",
        })
        result = mod._handle_github_status([
            {"name": "owner", "value": "NX-2021-L"},
            {"name": "repo", "value": "enceladus"},
            {"name": "prNumber", "value": "42"},
        ])
        self.assertEqual(result["pr"]["number"], 42)
        self.assertEqual(result["pr"]["state"], "open")


class TestHandleSchemaVersion(unittest.TestCase):
    def test_returns_version(self):
        result = mod._handle_schema_version()
        self.assertEqual(result["version"], "1.1.0")
        self.assertEqual(result["action_count"], 18)
        self.assertIn("POST /github/branch", result["actions"])
        self.assertIn("POST /github/commit", result["actions"])
        self.assertIn("POST /github/pr", result["actions"])
        self.assertIn("GET /github/status", result["actions"])


class TestRollbackGithubState(unittest.TestCase):
    @patch.object(mod, "_github_request")
    def test_rollback_orphan_branch(self, mock_req):
        mock_req.return_value = (204, {})
        result = mod._rollback_github_state({
            "github_owner": "NX-2021-L",
            "github_repo": "enceladus",
            "github_branch_created": "agent/test/ENC-TSK-1-x",
        })
        self.assertEqual(result["rollback"], "completed")
        self.assertIn("delete", result["actions"][0])

    @patch.object(mod, "_github_request")
    def test_rollback_open_pr(self, mock_req):
        mock_req.return_value = (200, {})
        result = mod._rollback_github_state({
            "github_owner": "NX-2021-L",
            "github_repo": "enceladus",
            "github_branch_created": "agent/test/ENC-TSK-1-x",
            "github_pr_number": "42",
        })
        self.assertEqual(result["rollback"], "completed")
        self.assertIn("close", result["actions"][0])

    def test_no_github_context(self):
        result = mod._rollback_github_state({})
        self.assertEqual(result["rollback"], "skipped")


class TestWriteSourceOnMutations(unittest.TestCase):
    """Verify write_source is included in DynamoDB mutations."""

    @patch.object(mod, "_get_ddb")
    def test_tracker_create_includes_write_source(self, mock_ddb):
        mock_client = MagicMock()
        mock_ddb.return_value = mock_client
        # Mock projects table
        mock_client.get_item.return_value = {
            "Item": {"project_id": {"S": "enceladus"}, "prefix": {"S": "ENC"}}
        }

        mod._handle_tracker_create({
            "project_id": "enceladus",
            "record_type": "task",
            "title": "Test task",
            "acceptance_criteria": ["AC1"],
        })

        put_call = mock_client.put_item.call_args
        item = put_call[1]["Item"] if "Item" in (put_call[1] or {}) else put_call[0][0] if put_call[0] else {}
        if not item and put_call[1]:
            item = put_call[1].get("Item", {})
        self.assertIn("write_source", item)
        ws = item["write_source"]
        self.assertEqual(ws["M"]["channel"]["S"], "bedrock_agent_action")


if __name__ == "__main__":
    unittest.main()
