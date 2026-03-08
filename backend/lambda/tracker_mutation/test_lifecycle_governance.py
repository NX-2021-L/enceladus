"""test_lifecycle_governance.py — Tests for ENC-FTR-022 / ENC-FTR-035 lifecycle governance.

Tests cover:
- ENC-TSK-594: Transition table enforcement and revert-with-evidence
- ENC-TSK-595: Evidence gates (committed, merged-main, deploy-success, production)
- ENC-TSK-698: New deploy-init/deploy-success/coding-updates state machine
  + deploy_evidence gate (deploy-init → deploy-success)
  + live_validation_evidence gate (deploy-success → closed)
  + coding-updates re-entry arc (deploy-success → coding-updates → coding-complete)
- ENC-TSK-726: deploy_evidence must be a structured GitHub Actions Jobs API payload
  + required fields: id, run_id, head_sha, status, conclusion, started_at, completed_at
  + status must equal "completed", conclusion must equal "success"
  + started_at / completed_at must be valid ISO 8601 datetimes

Run: python3 -m pytest test_lifecycle_governance.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location(
    "tracker_mutation",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
tracker_mutation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tracker_mutation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_patch_event(project_id, record_type, record_id, body_dict, internal_key="valid-key"):
    """Build a PATCH event for _handle_update_field."""
    path = f"/api/v1/tracker/{project_id}/{record_type}/{record_id}"
    headers = {}
    if internal_key:
        headers["x-coordination-internal-key"] = internal_key
    return {
        "requestContext": {"http": {"method": "PATCH", "path": path}},
        "headers": headers,
        "body": json.dumps(body_dict),
        "rawPath": path,
    }


def _mock_ddb_item(status="open", record_type="task", item_id="ENC-TSK-001",
                    extra=None):
    """Return a DynamoDB-style raw item dict."""
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": f"{record_type}#{item_id}"},
        "item_id": {"S": item_id},
        "status": {"S": status},
        "record_type": {"S": record_type},
        "sync_version": {"N": "1"},
        "history": {"L": []},
    }
    if extra:
        item.update(extra)
    return item


def _mock_checked_out_task(status="open", item_id="ENC-TSK-001", agent_id="codex", extra=None):
    """Return a task item already checked out by a specific agent."""
    task_extra = {
        "active_agent_session": {"BOOL": True},
        "active_agent_session_id": {"S": agent_id},
        "checkout_state": {"S": "checked_out"},
        "checked_out_by": {"S": agent_id},
        "checked_out_at": {"S": "2026-02-26T00:00:00Z"},
    }
    if extra:
        task_extra.update(extra)
    return _mock_ddb_item(status=status, record_type="task", item_id=item_id, extra=task_extra)


def _call_update_field(project_id, record_type, record_id, body):
    """Directly invoke _handle_update_field."""
    return tracker_mutation._handle_update_field(project_id, record_type, record_id, body)


def _valid_deploy_evidence(**overrides):
    """Return a minimal valid GitHub Actions Jobs API payload for deploy_evidence.

    Source: GET /repos/{owner}/{repo}/actions/jobs/{job_id}
    All required fields (ENC-TSK-726) are present with valid values by default.
    Pass keyword overrides to test invalid variations.
    """
    payload = {
        "id": 12345678,
        "name": "Deploy tracker mutation",
        "run_id": 22549608910,
        "head_sha": "0e608c0d4079570dd970e9696e2b7b3fdfaa79ac",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-03-01T18:20:00Z",
        "completed_at": "2026-03-01T18:21:57Z",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# ENC-TSK-594 / ENC-TSK-698: Transition table enforcement
# ---------------------------------------------------------------------------

class TestTaskForwardTransitions(unittest.TestCase):
    """Task lifecycle: open → in-progress → coding-complete → committed →
    pr → merged-main → deploy-init → deploy-success → closed.
    Re-entry arc: deploy-success → coding-updates → coding-complete."""

    def _patch_and_call(self, current_status, new_status, body_extra=None):
        body = {"field": "status", "value": new_status, "provider": "codex"}
        if body_extra:
            body.update(body_extra)
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status=current_status, agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")):
                result = _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", body
                )
        return json.loads(result.get("body", "{}"))

    def test_open_to_in_progress(self):
        result = self._patch_and_call("open", "in-progress")
        self.assertTrue(result.get("success"))

    def test_in_progress_to_coding_complete(self):
        result = self._patch_and_call("in-progress", "coding-complete")
        self.assertTrue(result.get("success"))

    def test_coding_complete_to_committed(self):
        result = self._patch_and_call("coding-complete", "committed", {
            "transition_evidence": {
                "commit_sha": "a" * 40,
                "owner": "NX-2021-L",
                "repo": "enceladus",
            }
        })
        self.assertTrue(result.get("success"))

    def test_committed_to_pr(self):
        result = self._patch_and_call("committed", "pr")
        self.assertTrue(result.get("success"))

    def test_pr_to_merged_main_with_evidence(self):
        result = self._patch_and_call("pr", "merged-main", {
            "transition_evidence": {
                "merge_evidence": "PR #42 merged to main, commit abc123 on main"
            }
        })
        self.assertTrue(result.get("success"))

    def test_merged_main_to_deploy_init(self):
        """merged-main → deploy-init requires no additional evidence."""
        result = self._patch_and_call("merged-main", "deploy-init")
        self.assertTrue(result.get("success"))

    def test_deploy_init_to_deploy_success_with_evidence(self):
        """deploy-init → deploy-success requires transition_evidence.deploy_evidence (GH API payload)."""
        result = self._patch_and_call("deploy-init", "deploy-success", {
            "transition_evidence": {
                "deploy_evidence": _valid_deploy_evidence()
            }
        })
        self.assertTrue(result.get("success"))

    def test_deploy_success_to_closed_with_evidence(self):
        """deploy-success → closed requires transition_evidence.live_validation_evidence."""
        result = self._patch_and_call("deploy-success", "closed", {
            "transition_evidence": {
                "live_validation_evidence": "PWA smoke test passed, feature verified live at jreese.net"
            }
        })
        self.assertTrue(result.get("success"))

    def test_deploy_success_to_coding_updates(self):
        """deploy-success → coding-updates re-entry arc (deployment failed checks)."""
        result = self._patch_and_call("deploy-success", "coding-updates")
        self.assertTrue(result.get("success"))

    def test_coding_updates_to_coding_complete(self):
        """coding-updates → coding-complete re-enters the standard coding path."""
        result = self._patch_and_call("coding-updates", "coding-complete")
        self.assertTrue(result.get("success"))


class TestTaskSkipStagesBlocked(unittest.TestCase):
    """Skipping stages must be rejected."""

    def _patch_and_call(self, current_status, new_status):
        body = {"field": "status", "value": new_status}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_item(status=current_status)
        }
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body
            )
        return json.loads(result.get("body", "{}"))

    def test_open_to_committed_blocked(self):
        result = self._patch_and_call("open", "committed")
        self.assertIn("error", result)

    def test_open_to_closed_blocked(self):
        result = self._patch_and_call("open", "closed")
        self.assertIn("error", result)

    def test_in_progress_to_pr_blocked(self):
        result = self._patch_and_call("in-progress", "pr")
        self.assertIn("error", result)

    def test_coding_complete_to_deploy_success_blocked(self):
        """Can't skip straight to deploy-success from coding-complete."""
        result = self._patch_and_call("coding-complete", "deploy-success")
        self.assertIn("error", result)

    def test_open_to_deploy_success_blocked(self):
        result = self._patch_and_call("open", "deploy-success")
        self.assertIn("error", result)

    def test_merged_main_cannot_skip_to_closed(self):
        """merged-main must go through deploy-init and deploy-success before closing."""
        result = self._patch_and_call("merged-main", "closed")
        self.assertIn("error", result)

    def test_deploy_init_cannot_skip_to_closed(self):
        """deploy-init cannot jump directly to closed; must go via deploy-success."""
        result = self._patch_and_call("deploy-init", "closed")
        self.assertIn("error", result)

    def test_deploy_success_cannot_go_to_in_progress(self):
        """deploy-success cannot revert to in-progress directly (must use coding-updates)."""
        result = self._patch_and_call("deploy-success", "in-progress")
        self.assertIn("error", result)

    def test_coding_updates_cannot_go_to_pr(self):
        """coding-updates must re-enter at coding-complete, not skip ahead to pr."""
        result = self._patch_and_call("coding-updates", "pr")
        self.assertIn("error", result)

    def test_deployed_is_no_longer_a_valid_target(self):
        """'deployed' is a retired status; it must not be reachable from any state."""
        result = self._patch_and_call("merged-main", "deployed")
        self.assertIn("error", result)


class TestTaskCheckoutEnforcement(unittest.TestCase):
    """Task status transitions require active checkout and owning provider identity."""

    def test_status_transition_without_checkout_rejected(self):
        body = {"field": "status", "value": "in-progress", "provider": "codex"}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_ddb_item(status="open")}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("active checkout", parsed["error"])

    def test_status_transition_without_provider_rejected(self):
        body = {"field": "status", "value": "in-progress"}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_checked_out_task(status="open", agent_id="codex")}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("write_source.provider", parsed["error"])

    def test_status_transition_owner_mismatch_rejected(self):
        body = {"field": "status", "value": "in-progress", "provider": "claude"}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": _mock_checked_out_task(status="open", agent_id="codex")}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("checked out by 'codex'", parsed["error"])


class TestFeatureForwardTransitions(unittest.TestCase):
    """Feature lifecycle: planned -> in-progress -> completed -> production -> deprecated."""

    def _patch_and_call(self, current_status, new_status, extra_item=None, body_extra=None):
        body = {"field": "status", "value": new_status}
        if body_extra:
            body.update(body_extra)
        item = _mock_ddb_item(status=current_status, record_type="feature",
                               item_id="ENC-FTR-001")
        if extra_item:
            item.update(extra_item)
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": item}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_feature_production_gate",
                              return_value=None):
                result = _call_update_field(
                    "enceladus", "feature", "ENC-FTR-001", body
                )
        return json.loads(result.get("body", "{}"))

    def test_planned_to_in_progress(self):
        result = self._patch_and_call("planned", "in-progress")
        self.assertTrue(result.get("success"))

    def test_in_progress_to_completed(self):
        # completed requires user_story + acceptance_criteria
        result = self._patch_and_call("in-progress", "completed", extra_item={
            "user_story": {"S": "As a user I need X so that Y"},
            "acceptance_criteria": {"L": [
                {"M": {
                    "description": {"S": "criterion 1"},
                    "evidence": {"S": "test passed"},
                    "evidence_acceptance": {"BOOL": True},
                }}
            ]},
        })
        self.assertTrue(result.get("success"))

    def test_completed_to_production(self):
        result = self._patch_and_call("completed", "production")
        self.assertTrue(result.get("success"))

    def test_production_to_deprecated(self):
        result = self._patch_and_call("production", "deprecated")
        self.assertTrue(result.get("success"))


class TestIssueTransitionsUnchanged(unittest.TestCase):
    """Issues keep the existing open -> in-progress -> closed lifecycle."""

    def _patch_and_call(self, current_status, new_status):
        body = {"field": "status", "value": new_status}
        item = _mock_ddb_item(status=current_status, record_type="issue",
                               item_id="ENC-ISS-001")
        if new_status == "closed":
            item["evidence"] = {"L": [
                {"M": {"description": {"S": "bug found"}, "steps_to_duplicate": {"L": [{"S": "step 1"}]}}}
            ]}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {"Item": item}
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "issue", "ENC-ISS-001", body
            )
        return json.loads(result.get("body", "{}"))

    def test_open_to_in_progress(self):
        result = self._patch_and_call("open", "in-progress")
        self.assertTrue(result.get("success"))

    def test_open_to_closed(self):
        result = self._patch_and_call("open", "closed")
        self.assertTrue(result.get("success"))

    def test_in_progress_to_closed(self):
        result = self._patch_and_call("in-progress", "closed")
        self.assertTrue(result.get("success"))


class TestRevertWithEvidence(unittest.TestCase):
    """Backward transitions require transition_evidence.revert_reason."""

    def _patch_and_call(self, current_status, new_status, revert_reason=None):
        body = {"field": "status", "value": new_status, "provider": "codex"}
        if revert_reason is not None:
            body["transition_evidence"] = {"revert_reason": revert_reason}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status=current_status, agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body
            )
        return json.loads(result.get("body", "{}"))

    def test_revert_without_reason_blocked(self):
        result = self._patch_and_call("in-progress", "open")
        self.assertIn("error", result)
        self.assertIn("revert_reason", result["error"])

    def test_revert_with_empty_reason_blocked(self):
        result = self._patch_and_call("in-progress", "open", revert_reason="")
        self.assertIn("error", result)

    def test_revert_with_reason_succeeds(self):
        result = self._patch_and_call("in-progress", "open",
                                       revert_reason="Task requirements changed")
        self.assertTrue(result.get("success"))

    def test_revert_coding_complete_to_in_progress(self):
        result = self._patch_and_call("coding-complete", "in-progress",
                                       revert_reason="Found additional bugs")
        self.assertTrue(result.get("success"))

    def test_revert_committed_to_coding_complete(self):
        result = self._patch_and_call("committed", "coding-complete",
                                       revert_reason="Commit was incorrect")
        self.assertTrue(result.get("success"))

    def test_revert_pr_to_committed(self):
        result = self._patch_and_call("pr", "committed",
                                       revert_reason="Push was to wrong branch")
        self.assertTrue(result.get("success"))

    def test_revert_deploy_init_to_merged_main(self):
        """deploy-init can be reverted to merged-main with a reason (deployment aborted)."""
        result = self._patch_and_call("deploy-init", "merged-main",
                                       revert_reason="Deployment aborted due to config error")
        self.assertTrue(result.get("success"))

    def test_revert_coding_updates_to_deploy_success(self):
        """coding-updates can be reverted to deploy-success with a reason."""
        result = self._patch_and_call("coding-updates", "deploy-success",
                                       revert_reason="Additional changes not needed after review")
        self.assertTrue(result.get("success"))


# ---------------------------------------------------------------------------
# ENC-TSK-595 / ENC-TSK-698: Evidence gates
# ---------------------------------------------------------------------------

class TestCommittedGate(unittest.TestCase):
    """task -> committed requires valid commit_sha."""

    def _patch_and_call(self, transition_evidence=None):
        body = {"field": "status", "value": "committed", "provider": "codex"}
        if transition_evidence:
            evidence = dict(transition_evidence)
            evidence.setdefault("owner", "NX-2021-L")
            evidence.setdefault("repo", "enceladus")
            body["transition_evidence"] = evidence
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="coding-complete", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(True, "ok")) as mock_validate:
                result = _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", body
                )
        return json.loads(result.get("body", "{}")), mock_validate

    def test_missing_commit_sha_returns_400(self):
        result, _ = self._patch_and_call()
        self.assertIn("error", result)
        self.assertIn("commit_sha", result["error"])

    def test_empty_commit_sha_returns_400(self):
        result, _ = self._patch_and_call({"commit_sha": ""})
        self.assertIn("error", result)

    def test_invalid_sha_format_returns_400(self):
        result, _ = self._patch_and_call({"commit_sha": "not-a-sha"})
        self.assertIn("error", result)
        self.assertIn("40-char hex", result["error"])

    def test_short_sha_returns_400(self):
        result, _ = self._patch_and_call({"commit_sha": "abc123"})
        self.assertIn("error", result)

    def test_valid_sha_calls_github_validation(self):
        sha = "a" * 40
        result, mock_validate = self._patch_and_call({"commit_sha": sha})
        self.assertTrue(result.get("success"))
        mock_validate.assert_called_once_with("NX-2021-L", "enceladus", sha)

    def test_github_validation_failure_returns_400(self):
        body = {"field": "status", "value": "committed", "provider": "codex",
                "transition_evidence": {"commit_sha": "b" * 40, "owner": "NX-2021-L", "repo": "enceladus"}}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="coding-complete", agent_id="codex")
        }
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_validate_commit_via_github",
                              return_value=(False, "commit_not_found")):
                result = _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", body
                )
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("commit_not_found", parsed["error"])


class TestMergedMainGate(unittest.TestCase):
    """Direct task -> merged-main calls are rejected in favor of checkout_service."""

    def _patch_and_call(self, transition_evidence=None):
        body = {"field": "status", "value": "merged-main", "provider": "codex"}
        if transition_evidence:
            body["transition_evidence"] = transition_evidence
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="pr", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            with patch.object(tracker_mutation, "_is_checkout_service_request", return_value=False):
                result = _call_update_field(
                    "enceladus", "task", "ENC-TSK-001", body
                )
        return json.loads(result.get("body", "{}"))

    def test_missing_merge_evidence_returns_checkout_service_redirect(self):
        result = self._patch_and_call()
        self.assertIn("error", result)
        self.assertIn("advance_task_status", result["error"])

    def test_empty_merge_evidence_returns_checkout_service_redirect(self):
        result = self._patch_and_call({"merge_evidence": "  "})
        self.assertIn("error", result)
        self.assertIn("advance_task_status", result["error"])

    def test_valid_merge_evidence_still_requires_checkout_service(self):
        result = self._patch_and_call({
            "merge_evidence": "PR #42 merged, commit abc123 verified on main"
        })
        self.assertIn("error", result)
        self.assertIn("advance_task_status", result["error"])


class TestDeploySuccessGate(unittest.TestCase):
    """task -> deploy-success requires a structured GitHub Actions Jobs API payload (ENC-TSK-726).

    Source: GET /repos/{owner}/{repo}/actions/jobs/{job_id}
    Required fields: id, name, run_id, head_sha, status, conclusion, started_at, completed_at
    Assertions: status == "completed", conclusion == "success"
    Datetime validation: started_at / completed_at must be ISO 8601.
    """

    def _patch_and_call(self, transition_evidence=None):
        body = {"field": "status", "value": "deploy-success", "provider": "codex"}
        if transition_evidence:
            body["transition_evidence"] = transition_evidence
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="deploy-init", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body
            )
        return json.loads(result.get("body", "{}"))

    # --- valid payload ---

    def test_valid_gh_actions_payload_succeeds(self):
        """Full valid GitHub Actions Jobs API payload passes all gates."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence()})
        self.assertTrue(result.get("success"), result)

    # --- missing / wrong type ---

    def test_missing_deploy_evidence_returns_400(self):
        """No deploy_evidence key → 400."""
        result = self._patch_and_call()
        self.assertIn("error", result)
        self.assertIn("deploy_evidence", result["error"])

    def test_none_deploy_evidence_returns_400(self):
        """deploy_evidence=None → 400."""
        result = self._patch_and_call({"deploy_evidence": None})
        self.assertIn("error", result)

    def test_plain_string_deploy_evidence_rejected(self):
        """Plain string (old format) is rejected; must be a structured object."""
        result = self._patch_and_call({"deploy_evidence": "SPEC-20260301T143000"})
        self.assertIn("error", result)
        self.assertIn("structured object", result["error"])

    def test_empty_string_deploy_evidence_rejected(self):
        """Empty string → 400."""
        result = self._patch_and_call({"deploy_evidence": "  "})
        self.assertIn("error", result)

    # --- missing required fields ---

    def test_missing_id_field_rejected(self):
        de = _valid_deploy_evidence()
        del de["id"]
        result = self._patch_and_call({"deploy_evidence": de})
        self.assertIn("error", result)
        self.assertIn("id", result["error"])

    def test_missing_run_id_field_rejected(self):
        de = _valid_deploy_evidence()
        del de["run_id"]
        result = self._patch_and_call({"deploy_evidence": de})
        self.assertIn("error", result)
        self.assertIn("run_id", result["error"])

    def test_missing_head_sha_field_rejected(self):
        de = _valid_deploy_evidence()
        del de["head_sha"]
        result = self._patch_and_call({"deploy_evidence": de})
        self.assertIn("error", result)
        self.assertIn("head_sha", result["error"])

    def test_missing_started_at_field_rejected(self):
        de = _valid_deploy_evidence()
        del de["started_at"]
        result = self._patch_and_call({"deploy_evidence": de})
        self.assertIn("error", result)
        self.assertIn("started_at", result["error"])

    def test_missing_completed_at_field_rejected(self):
        de = _valid_deploy_evidence()
        del de["completed_at"]
        result = self._patch_and_call({"deploy_evidence": de})
        self.assertIn("error", result)
        self.assertIn("completed_at", result["error"])

    # --- wrong status / conclusion values ---

    def test_status_in_progress_rejected(self):
        """status='in_progress' (job still running) → rejected."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(status="in_progress")})
        self.assertIn("error", result)
        self.assertIn("completed", result["error"])

    def test_status_queued_rejected(self):
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(status="queued")})
        self.assertIn("error", result)

    def test_conclusion_failure_rejected(self):
        """conclusion='failure' → rejected; only success qualifies."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(conclusion="failure")})
        self.assertIn("error", result)
        self.assertIn("success", result["error"])

    def test_conclusion_cancelled_rejected(self):
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(conclusion="cancelled")})
        self.assertIn("error", result)

    def test_conclusion_skipped_rejected(self):
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(conclusion="skipped")})
        self.assertIn("error", result)

    # --- invalid datetime formats ---

    def test_invalid_started_at_epoch_int_rejected(self):
        """Integer epoch timestamp for started_at → rejected; must be ISO 8601 string."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(started_at=1740845200)})
        self.assertIn("error", result)
        self.assertIn("started_at", result["error"])

    def test_invalid_started_at_garbage_string_rejected(self):
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(started_at="not-a-date")})
        self.assertIn("error", result)
        self.assertIn("started_at", result["error"])

    def test_invalid_completed_at_date_only_rejected(self):
        """Date-only string (no time component) → rejected."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(completed_at="2026-03-01")})
        self.assertIn("error", result)
        self.assertIn("completed_at", result["error"])

    def test_valid_iso8601_with_offset_accepted(self):
        """ISO 8601 with numeric offset (+00:00) is also valid."""
        result = self._patch_and_call({"deploy_evidence": _valid_deploy_evidence(
            started_at="2026-03-01T18:20:00+00:00",
            completed_at="2026-03-01T18:21:57+00:00",
        )})
        self.assertTrue(result.get("success"), result)


class TestDeploySuccessToClosedGate(unittest.TestCase):
    """task -> closed (from deploy-success) requires live_validation_evidence."""

    def _patch_and_call(self, transition_evidence=None):
        body = {"field": "status", "value": "closed", "provider": "codex"}
        if transition_evidence:
            body["transition_evidence"] = transition_evidence
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="deploy-success", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body
            )
        return json.loads(result.get("body", "{}"))

    def test_missing_live_validation_evidence_returns_400(self):
        result = self._patch_and_call()
        self.assertIn("error", result)
        self.assertIn("live_validation_evidence", result["error"])

    def test_empty_live_validation_evidence_returns_400(self):
        result = self._patch_and_call({"live_validation_evidence": "  "})
        self.assertIn("error", result)

    def test_valid_live_validation_evidence_succeeds(self):
        result = self._patch_and_call({
            "live_validation_evidence": "PWA smoke test passed at jreese.net; status chip shows deploy-success"
        })
        self.assertTrue(result.get("success"))

    def test_ftr032_style_evidence_succeeds(self):
        """Evidence captured via ENC-FTR-032 Cognito session diagnostics."""
        result = self._patch_and_call({
            "live_validation_evidence": (
                "ENC-FTR-032 diagnostic: GET /enceladus/projects/enceladus 200 OK; "
                "feature ENC-FTR-035 visible with status=production at 2026-03-01T15:00:00Z"
            )
        })
        self.assertTrue(result.get("success"))


class TestFeatureProductionGate(unittest.TestCase):
    """feature -> production requires all child tasks deploy-success/closed (ENC-FTR-035)."""

    def _make_task_items(self, tasks):
        """tasks: list of (item_id, status, parent_or_None)"""
        items = []
        for item_id, status, parent in tasks:
            raw = {
                "record_id": {"S": f"task#{item_id}"},
                "item_id": {"S": item_id},
                "status": {"S": status},
            }
            if parent:
                raw["parent"] = {"S": parent}
            items.append(raw)
        return items

    def test_no_child_tasks_returns_400(self):
        feature_data = {"status": "completed", "primary_task": "", "related_task_ids": []}
        result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("no child tasks", parsed["error"])

    def test_all_children_deploy_success_succeeds(self):
        """All tasks at deploy-success → production gate should pass."""
        feature_data = {
            "primary_task": "ENC-TSK-001",
            "related_task_ids": ["ENC-TSK-002"],
        }
        task_items = self._make_task_items([
            ("ENC-TSK-001", "deploy-success", None),
            ("ENC-TSK-002", "closed", None),
        ])
        mock_ddb = MagicMock()
        mock_ddb.query.return_value = {"Items": task_items}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        self.assertIsNone(result)

    def test_task_at_deployed_legacy_status_blocks_production(self):
        """Old 'deployed' status is no longer accepted; tasks must be at deploy-success."""
        feature_data = {
            "primary_task": "ENC-TSK-001",
            "related_task_ids": [],
        }
        task_items = self._make_task_items([
            ("ENC-TSK-001", "deployed", None),
        ])
        mock_ddb = MagicMock()
        mock_ddb.query.return_value = {"Items": task_items}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("ENC-TSK-001", parsed["error"])

    def test_some_children_not_ready_returns_400(self):
        feature_data = {
            "primary_task": "ENC-TSK-001",
            "related_task_ids": ["ENC-TSK-002"],
        }
        task_items = self._make_task_items([
            ("ENC-TSK-001", "deploy-success", None),
            ("ENC-TSK-002", "in-progress", None),
        ])
        mock_ddb = MagicMock()
        mock_ddb.query.return_value = {"Items": task_items}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("ENC-TSK-002", parsed["error"])

    def test_recursive_children_checked(self):
        """Feature -> TSK-001 -> child TSK-002 -> grandchild TSK-003.
        TSK-003 is in-progress -> should block."""
        feature_data = {"primary_task": "ENC-TSK-001", "related_task_ids": []}
        task_items = self._make_task_items([
            ("ENC-TSK-001", "deploy-success", None),
            ("ENC-TSK-002", "deploy-success", "ENC-TSK-001"),
            ("ENC-TSK-003", "in-progress", "ENC-TSK-002"),
        ])
        mock_ddb = MagicMock()
        mock_ddb.query.return_value = {"Items": task_items}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("ENC-TSK-003", parsed["error"])

    def test_recursive_children_all_deploy_success_succeeds(self):
        """Feature -> TSK-001 -> child TSK-002 -> grandchild TSK-003.
        All deploy-success or closed -> should pass."""
        feature_data = {"primary_task": "ENC-TSK-001", "related_task_ids": []}
        task_items = self._make_task_items([
            ("ENC-TSK-001", "deploy-success", None),
            ("ENC-TSK-002", "closed", "ENC-TSK-001"),
            ("ENC-TSK-003", "deploy-success", "ENC-TSK-002"),
        ])
        mock_ddb = MagicMock()
        mock_ddb.query.return_value = {"Items": task_items}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = tracker_mutation._validate_feature_production_gate("enceladus", feature_data)
        self.assertIsNone(result)


class TestAcceptanceCriteriaPatchNormalization(unittest.TestCase):
    """PATCH acceptance_criteria normalization and validation safeguards."""

    def test_feature_acceptance_criteria_json_string_normalized_to_structured_items(self):
        body = {
            "field": "acceptance_criteria",
            "value": json.dumps(["Criterion A", " Criterion B "]),
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_item(
                status="in-progress",
                record_type="feature",
                item_id="ENC-FTR-001",
            )
        }
        mock_ddb.update_item.return_value = {}

        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "feature", "ENC-FTR-001", body)

        parsed = json.loads(result.get("body", "{}"))
        self.assertTrue(parsed.get("success"))
        self.assertEqual(len(parsed.get("value", [])), 2)
        self.assertEqual(parsed["value"][0]["description"], "Criterion A")
        self.assertEqual(parsed["value"][1]["description"], "Criterion B")

        update_kwargs = mock_ddb.update_item.call_args.kwargs
        self.assertEqual(
            update_kwargs["ExpressionAttributeValues"][":val"],
            {
                "L": [
                    {
                        "M": {
                            "description": {"S": "Criterion A"},
                            "evidence": {"S": ""},
                            "evidence_acceptance": {"BOOL": False},
                        }
                    },
                    {
                        "M": {
                            "description": {"S": "Criterion B"},
                            "evidence": {"S": ""},
                            "evidence_acceptance": {"BOOL": False},
                        }
                    },
                ]
            },
        )

    def test_task_acceptance_criteria_json_string_normalized_to_string_list(self):
        body = {
            "field": "acceptance_criteria",
            "value": json.dumps([" first criterion ", "", "second criterion"]),
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_item(
                status="in-progress",
                record_type="task",
                item_id="ENC-TSK-001",
            )
        }
        mock_ddb.update_item.return_value = {}

        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)

        parsed = json.loads(result.get("body", "{}"))
        self.assertTrue(parsed.get("success"))
        self.assertEqual(parsed.get("value"), ["first criterion", "second criterion"])

        update_kwargs = mock_ddb.update_item.call_args.kwargs
        self.assertEqual(
            update_kwargs["ExpressionAttributeValues"][":val"],
            {
                "L": [
                    {"S": "first criterion"},
                    {"S": "second criterion"},
                ]
            },
        )

    def test_feature_acceptance_criteria_rejects_empty_description_object(self):
        body = {
            "field": "acceptance_criteria",
            "value": json.dumps([{"description": "   "}]),
        }
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_ddb_item(
                status="in-progress",
                record_type="feature",
                item_id="ENC-FTR-001",
            )
        }

        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "feature", "ENC-FTR-001", body)

        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)
        self.assertIn("description", parsed["error"])
        mock_ddb.update_item.assert_not_called()


class TestDeployedMigrationArc(unittest.TestCase):
    """ENC-TSK-704: deployed → deploy-success migration arc.

    Legacy tasks at 'deployed' status must be able to transition to 'deploy-success'
    after the ENC-FTR-035 Lambda deploy. The migration arc is temporary and should
    be removed once all deployed tasks have been migrated.
    """

    def _patch_and_call(self, transition_evidence=None):
        body = {"field": "status", "value": "deploy-success", "provider": "codex"}
        if transition_evidence:
            body["transition_evidence"] = transition_evidence
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="deployed", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field(
                "enceladus", "task", "ENC-TSK-001", body
            )
        return json.loads(result.get("body", "{}"))

    def test_deployed_to_deploy_success_with_evidence_succeeds(self):
        """Migration arc: deployed → deploy-success with valid GH Actions payload passes."""
        result = self._patch_and_call({
            "deploy_evidence": _valid_deploy_evidence()
        })
        self.assertTrue(result.get("success"), result)

    def test_deployed_to_deploy_success_without_evidence_returns_400(self):
        """deploy_evidence is still required even for the migration arc."""
        result = self._patch_and_call()
        self.assertIn("error", result)
        self.assertIn("deploy_evidence", result["error"])

    def test_deployed_cannot_skip_to_closed(self):
        """Migration arc only goes to deploy-success; deployed → closed is no longer valid."""
        body = {"field": "status", "value": "closed", "provider": "codex"}
        mock_ddb = MagicMock()
        mock_ddb.get_item.return_value = {
            "Item": _mock_checked_out_task(status="deployed", agent_id="codex")
        }
        mock_ddb.update_item.return_value = {}
        with patch.object(tracker_mutation, "_get_ddb", return_value=mock_ddb):
            result = _call_update_field("enceladus", "task", "ENC-TSK-001", body)
        parsed = json.loads(result.get("body", "{}"))
        self.assertIn("error", parsed)


if __name__ == "__main__":
    unittest.main()
