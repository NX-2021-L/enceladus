"""Regression tests for the ENC-TSK-E70 deploy capability guard workflow.

Validates the YAML structure and the intent of each guard step. Full
end-to-end enforcement relies on the env-secrets manifest + audit tool
from ENC-TSK-E66 already being present on main; these tests just lock
in the guard's shape so future refactors don't silently skip checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD_PATH = REPO_ROOT / ".github" / "workflows" / "deploy-capability-guard.yml"


@pytest.fixture(scope="module")
def guard_text() -> str:
    return GUARD_PATH.read_text()


def test_workflow_file_exists(guard_text: str):
    assert GUARD_PATH.exists(), "deploy-capability-guard.yml missing"


def test_triggers_on_pull_request_to_main(guard_text: str):
    assert "pull_request:" in guard_text
    assert "main" in guard_text


def test_watches_workflows_and_cfn_and_manifest(guard_text: str):
    assert ".github/workflows/**" in guard_text
    assert "infrastructure/cloudformation/**" in guard_text
    assert "tools/deploy-capability/**" in guard_text


def test_runs_env_secrets_audit_check_declaration(guard_text: str):
    assert "tools/audit_gha_env_secrets.py" in guard_text
    assert "--check-declaration" in guard_text


def test_detects_new_env_production_jobs(guard_text: str):
    assert "environment:\\s+production" in guard_text or "environment: production" in guard_text


def test_detects_new_apigw_routes(guard_text: str):
    assert "RouteKey:" in guard_text


def test_fails_on_audit_nonzero_exit(guard_text: str):
    assert "steps.env_audit.outputs.exit_code" in guard_text
    assert "exit 1" in guard_text


def test_self_correcting_error_messages_present(guard_text: str):
    assert "gh secret set --env production" in guard_text
    assert "required_apigw_routes" in guard_text
    assert "ENC-LSN-032" in guard_text
