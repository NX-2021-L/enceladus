import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

_SPEC = importlib.util.spec_from_file_location(
    "checkout_service",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
checkout_service = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(checkout_service)


class CheckoutServiceErrorContextTests(unittest.TestCase):
    def test_checkout_missing_session_id_includes_self_correcting_context(self):
        response = checkout_service._handle_checkout("enceladus", "ENC-TSK-840", {})
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "active_agent_session_id is required in request body")
        details = body["error_envelope"]["details"]
        self.assertEqual(details["required_fields"], ["active_agent_session_id"])
        self.assertIn("github_pr_deploy", details["allowed_transition_types"])
        rank_table = {entry["transition_type"]: entry["rank"] for entry in details["strictness_rank"]}
        self.assertEqual(rank_table["github_pr_deploy"], 0)
        self.assertEqual(details["example_fix"][0]["tool"], "tracker_set")
        self.assertEqual(details["example_fix"][-1]["tool"], "checkout_task")

    @patch.object(checkout_service, "_get_required_transition_type", return_value="code")
    @patch.object(checkout_service, "_get_task")
    def test_advance_missing_deploy_evidence_includes_full_schema(self, mock_get_task, _mock_required_type):
        mock_get_task.return_value = (
            200,
            {
                "status": "deploy-init",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "codex-agent",
                "components": ["comp-checkout-service"],
            },
        )

        response = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-840",
            {
                "target_status": "deploy-success",
                "provider": "codex-agent",
                "governance_hash": "hash",
            },
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["current_status"], "deploy-init")
        self.assertEqual(details["target_status"], "deploy-success")
        self.assertEqual(
            details["valid_next_statuses"],
            checkout_service.ALLOWED_TRANSITIONS_BY_TYPE["github_pr_deploy"],
        )
        schema = details["required_evidence_schema"]
        self.assertIn("name", schema["required_fields"])
        self.assertIn("head_sha", schema["required_fields"])
        self.assertEqual(
            schema["required_fields"]["status"]["allowed_values"],
            ["completed"],
        )


    def test_plan_checkout_missing_session_id_includes_plan_context(self):
        """Plan checkout with missing active_agent_session_id returns plan context."""
        response = checkout_service._handle_plan_checkout(
            "enceladus", "ENC-PLN-TEST", {},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "active_agent_session_id is required in request body")
        details = body["error_envelope"]["details"]
        self.assertEqual(details["required_fields"], ["active_agent_session_id"])
        self.assertEqual(details["plan_id"], "ENC-PLN-TEST")
        self.assertIn("allowed_plan_transitions", details)
        self.assertEqual(
            details["allowed_plan_transitions"],
            dict(checkout_service.PLAN_ALLOWED_TRANSITIONS),
        )
        self.assertIn("plan_terminal_statuses", details)
        fix = details["example_fix"]
        self.assertEqual(fix["tool"], "plan.checkout")
        self.assertEqual(fix["arguments"]["record_id"], "ENC-PLN-TEST")

    def test_plan_advance_missing_target_status_includes_allowed_transitions(self):
        """Plan advance with missing target_status returns allowed_plan_transitions."""
        response = checkout_service._handle_plan_advance(
            "enceladus", "ENC-PLN-TEST", {},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "target_status is required")
        details = body["error_envelope"]["details"]
        self.assertIn("allowed_plan_transitions", details)
        self.assertEqual(
            details["allowed_plan_transitions"],
            dict(checkout_service.PLAN_ALLOWED_TRANSITIONS),
        )
        self.assertEqual(details["required_fields"], ["target_status"])
        fix = details["example_fix"]
        self.assertEqual(fix["tool"], "plan.advance")
        self.assertEqual(fix["arguments"]["record_id"], "ENC-PLN-TEST")

    @patch.object(checkout_service, "_get_plan")
    def test_plan_log_missing_description_includes_example_fix(self, mock_get_plan):
        """Plan log with missing description returns example plan.log call."""
        mock_get_plan.return_value = (
            200,
            {"status": "started", "active_agent_session": True},
        )
        response = checkout_service._handle_plan_log(
            "enceladus", "ENC-PLN-TEST", {},
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "description is required")
        details = body["error_envelope"]["details"]
        self.assertEqual(details["required_fields"], ["description"])
        self.assertEqual(details["plan_id"], "ENC-PLN-TEST")
        fix = details["example_fix"]
        self.assertEqual(fix["tool"], "plan.log")
        self.assertEqual(fix["arguments"]["record_id"], "ENC-PLN-TEST")


    @patch.object(checkout_service, "_validate_commit", return_value=(True, ""))
    @patch.object(checkout_service, "_resolve_github_repo", return_value=("NX-2021-L", "enceladus"))
    @patch.object(checkout_service, "_get_required_transition_type", return_value="code")
    @patch.object(checkout_service, "_get_task")
    def test_cai_missing_includes_token_semantics(
        self, mock_get_task, _mock_required_type, _mock_resolve, _mock_validate,
    ):
        """CAI gate error includes token_type, token_purpose, prerequisite_call."""
        mock_get_task.return_value = (
            200,
            {
                "status": "coding-complete",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "codex-agent",
                "components": ["comp-checkout-service"],
                # No commit_approval_id — triggers CAI gate
            },
        )

        response = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-840",
            {
                "target_status": "committed",
                "provider": "codex-agent",
                "governance_hash": "hash",
                "transition_evidence": {
                    "commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac",
                },
            },
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 409)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["token_type"], "CAI (Commit Approval ID)")
        self.assertIn("coding-complete", details["token_purpose"])
        self.assertEqual(details["prerequisite_status"], "coding-complete")
        prereq = details["prerequisite_call"]
        self.assertEqual(prereq["tool"], "checkout.advance")
        self.assertEqual(prereq["arguments"]["record_id"], "ENC-TSK-840")
        self.assertEqual(prereq["arguments"]["target_status"], "coding-complete")

    @patch.object(checkout_service, "_get_required_transition_type", return_value="code")
    @patch.object(checkout_service, "_get_task")
    def test_cci_missing_includes_token_semantics(self, mock_get_task, _mock_required_type):
        """CCI gate error includes token_type, token_purpose, prerequisite_call."""
        mock_get_task.return_value = (
            200,
            {
                "status": "committed",
                "transition_type": "github_pr_deploy",
                "active_agent_session": True,
                "active_agent_session_id": "codex-agent",
                "components": ["comp-checkout-service"],
                # No commit_complete_id — triggers CCI gate
            },
        )

        response = checkout_service._handle_advance(
            "enceladus",
            "ENC-TSK-840",
            {
                "target_status": "pr",
                "provider": "codex-agent",
                "governance_hash": "hash",
            },
        )
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 409)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["token_type"], "CCI (Commit Complete ID)")
        self.assertIn("committed", details["token_purpose"])
        self.assertEqual(details["prerequisite_status"], "committed")
        prereq = details["prerequisite_call"]
        self.assertEqual(prereq["tool"], "checkout.advance")
        self.assertEqual(prereq["arguments"]["record_id"], "ENC-TSK-840")
        self.assertEqual(prereq["arguments"]["target_status"], "committed")
        self.assertIn("commit_sha", prereq["arguments"]["transition_evidence"])

    def test_cci_invalid_format_includes_pattern(self):
        """CCI format validation error includes expected_format and pattern."""
        response = checkout_service._handle_validate_cci("CCI-INVALID")
        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 400)
        details = body["error_envelope"]["details"]
        self.assertEqual(details["expected_format"], "CCI-{32 hex chars}")
        self.assertEqual(details["pattern"], "^CCI-[0-9a-f]{32}$")
        self.assertEqual(details["provided_value"], "CCI-INVALID")


class TestCodeOnMainEvidenceValidator(unittest.TestCase):
    """ENC-ISS-161: code_only close gate must accept any valid main ancestor SHA."""

    @patch.object(checkout_service, "_github_request")
    def test_ancestor_sha_accepted_ahead_status(self, mock_gh):
        """When sha is ancestor of main, compare returns 'ahead' (main ahead of sha)."""
        mock_gh.return_value = (200, {"status": "ahead", "ahead_by": 5})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"}
        )
        self.assertTrue(valid, reason)

    @patch.object(checkout_service, "_github_request")
    def test_identical_sha_accepted(self, mock_gh):
        """When sha IS main HEAD, compare returns 'identical'."""
        mock_gh.return_value = (200, {"status": "identical"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"}
        )
        self.assertTrue(valid, reason)

    @patch.object(checkout_service, "_github_request")
    def test_behind_status_rejected(self, mock_gh):
        """'behind' means main is behind sha — sha is NOT an ancestor, reject."""
        mock_gh.return_value = (200, {"status": "behind"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"}
        )
        self.assertFalse(valid)
        self.assertIn("not on main", reason)

    @patch.object(checkout_service, "_github_request")
    def test_diverged_status_rejected(self, mock_gh):
        """'diverged' means sha and main have diverged — reject."""
        mock_gh.return_value = (200, {"status": "diverged"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"}
        )
        self.assertFalse(valid)
        self.assertIn("not on main", reason)

    def test_missing_commit_sha_rejected(self):
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus", {}
        )
        self.assertFalse(valid)
        self.assertIn("commit_sha is required", reason)

    def test_invalid_sha_format_rejected(self):
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus", {"commit_sha": "not-a-sha"}
        )
        self.assertFalse(valid)
        self.assertIn("40-char hex", reason)


class FailureClassificationTests(unittest.TestCase):
    """ENC-TSK-H49 / ENC-ISS-142: every blocked-transition envelope carries a
    machine-readable failure_classification + a recommended_next_actions array."""

    def _envelope(self, status, **kw):
        resp = checkout_service._error(status, "boom", **kw)
        return json.loads(resp["body"])["error_envelope"]

    def test_invalid_input_is_deterministic_governance(self):
        env = self._envelope(400)
        self.assertEqual(env["failure_classification"], "deterministic-governance")
        self.assertTrue(env["recommended_next_actions"])
        self.assertIn("validation_rules", " ".join(env["recommended_next_actions"]))

    def test_conflict_is_deterministic_governance(self):
        self.assertEqual(
            self._envelope(409)["failure_classification"], "deterministic-governance"
        )

    def test_permission_denied_is_human_override(self):
        env = self._envelope(403)
        self.assertEqual(env["failure_classification"], "human-override-required")
        self.assertTrue(env["recommended_next_actions"])

    def test_internal_error_is_transient(self):
        self.assertEqual(self._envelope(500)["failure_classification"], "transient")

    def test_explicit_override_wins(self):
        env = self._envelope(400, failure_classification="external-dependency")
        self.assertEqual(env["failure_classification"], "external-dependency")
        self.assertTrue(env["recommended_next_actions"])

    def test_unknown_override_is_ignored(self):
        # An override outside the canonical set falls back to code/status mapping.
        env = self._envelope(400, failure_classification="bogus")
        self.assertEqual(env["failure_classification"], "deterministic-governance")

    def test_domain_code_classified(self):
        env = self._envelope(400, code="COMPONENT_MISCONFIGURED")
        self.assertEqual(env["failure_classification"], "human-override-required")

    def test_classification_always_in_canonical_set(self):
        for status in (400, 401, 403, 404, 409, 500):
            self.assertIn(
                self._envelope(status)["failure_classification"],
                checkout_service.FAILURE_CLASSIFICATIONS,
            )

    def test_backward_compatible_details_preserved(self):
        # New fields coexist with existing details (AC#3 backward-compat).
        env = self._envelope(
            400, details={"required_fields": ["x"], "valid_next_statuses": ["y"]}
        )
        self.assertEqual(env["details"]["required_fields"], ["x"])
        self.assertEqual(env["details"]["valid_next_statuses"], ["y"])
        self.assertIn("failure_classification", env)
        self.assertIn("recommended_next_actions", env)

    def test_real_checkout_block_carries_classification(self):
        # Integration: a real blocked checkout (missing session id) is classified.
        resp = checkout_service._handle_checkout("enceladus", "ENC-TSK-840", {})
        env = json.loads(resp["body"])["error_envelope"]
        self.assertEqual(env["failure_classification"], "deterministic-governance")
        self.assertTrue(env["recommended_next_actions"])




class TestIssue603OwnerDoubling(unittest.TestCase):
    """ENC-TSK-O34 / ENC-ISS-603: task-level github_repo override and the
    project-config fallback must never double the owner in the resolved
    (owner, repo) pair, regardless of whether the override is given as a
    plain 'owner/repo' string or a full https://github.com/owner/repo URL."""

    def test_normalize_strips_redundant_owner_prefix(self):
        owner, repo = checkout_service._normalize_owner_repo(
            "NX-2021-L", "NX-2021-L/enceladus"
        )
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))

    def test_normalize_is_noop_for_bare_repo(self):
        owner, repo = checkout_service._normalize_owner_repo("NX-2021-L", "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))

    def test_split_owner_repo_plain_form(self):
        owner, repo = checkout_service._split_owner_repo("NX-2021-L/enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))

    def test_split_owner_repo_url_form(self):
        owner, repo = checkout_service._split_owner_repo(
            "https://github.com/NX-2021-L/enceladus"
        )
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))

    def test_split_owner_repo_never_doubles_on_qualified_plain_value(self):
        """A pathological already-doubled input never produces a doubled
        full_name -- the redundant leading owner segment is stripped."""
        owner, repo = checkout_service._split_owner_repo(
            "NX-2021-L/NX-2021-L/enceladus"
        )
        self.assertEqual(owner, "NX-2021-L")
        self.assertNotIn("/", repo)

    @patch.object(checkout_service, "_resolve_github_repo")
    def test_resolve_task_github_repo_plain_form_override_no_doubling(self, mock_resolve):
        """ISS-603 deterministic repro: plain-form override must resolve to
        the bare repo name, not the owner-qualified string (previously only
        the full-URL override form worked)."""
        task = {"github_repo": "NX-2021-L/enceladus"}
        owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        mock_resolve.assert_not_called()

    @patch.object(checkout_service, "_resolve_github_repo")
    def test_resolve_task_github_repo_url_form_override(self, mock_resolve):
        task = {"github_repo": "https://github.com/NX-2021-L/enceladus"}
        owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        mock_resolve.assert_not_called()

    @patch.object(checkout_service, "_resolve_github_repo")
    def test_resolve_task_github_repo_no_override_falls_back_to_project(self, mock_resolve):
        """ISS-603 default/no-override path: falls through to the
        project-config resolver, which itself never doubles the owner."""
        mock_resolve.return_value = ("NX-2021-L", "enceladus")
        task = {}
        owner, repo = checkout_service._resolve_task_github_repo(task, "enceladus")
        self.assertEqual((owner, repo), ("NX-2021-L", "enceladus"))
        mock_resolve.assert_called_once_with("enceladus")

    def test_resolve_github_repo_project_fallback_accepts_plain_form(self):
        """ISS-603 project-level fallback: a project 'repo' field stored as a
        bare 'owner/repo' string (not a URL, e.g. the 'mod' project) resolves
        cleanly instead of doubling or failing outright."""
        fake_ddb = MagicMock()
        fake_ddb.get_item.return_value = {"Item": {"repo": {"S": "NX-2021-L/mod"}}}
        with patch.object(checkout_service, "_ddb", fake_ddb):
            owner, repo = checkout_service._resolve_github_repo("mod")
        self.assertEqual((owner, repo), ("NX-2021-L", "mod"))


class TestIssue630BaseBranchOverride(unittest.TestCase):
    """ENC-TSK-O34 / ENC-ISS-630: the code_only close gate must honor a
    task-declared base branch instead of the hardcoded 'main'."""

    @patch.object(checkout_service, "_github_request")
    def test_default_base_branch_is_main(self, mock_gh):
        mock_gh.return_value = (200, {"status": "identical"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
        )
        self.assertTrue(valid, reason)
        called_path = mock_gh.call_args[0][0]
        self.assertTrue(called_path.endswith("...main"))

    @patch.object(checkout_service, "_github_request")
    def test_v4_main_base_branch_override_compares_against_v4_main(self, mock_gh):
        """A v4/main-only commit (never landed on 'main' pre-cutover) closes a
        code_only task when the task declares github_base_branch=v4/main."""
        mock_gh.return_value = (200, {"status": "ahead", "ahead_by": 2})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
            base_branch="v4/main",
        )
        self.assertTrue(valid, reason)
        called_path = mock_gh.call_args[0][0]
        self.assertTrue(called_path.endswith("...v4/main"))

    @patch.object(checkout_service, "_github_request")
    def test_base_branch_rejection_message_names_the_branch(self, mock_gh):
        mock_gh.return_value = (200, {"status": "behind"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
            base_branch="v4/main",
        )
        self.assertFalse(valid)
        self.assertIn("not on v4/main", reason)

    @patch.object(checkout_service, "_github_request")
    def test_blank_base_branch_defaults_to_main(self, mock_gh):
        mock_gh.return_value = (200, {"status": "identical"})
        valid, reason = checkout_service._validate_code_on_main_evidence(
            "NX-2021-L", "enceladus",
            {"commit_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac"},
            base_branch="   ",
        )
        self.assertTrue(valid, reason)
        called_path = mock_gh.call_args[0][0]
        self.assertTrue(called_path.endswith("...main"))


if __name__ == "__main__":
    unittest.main()
