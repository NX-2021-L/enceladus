"""Regression tests for tools/audit_cfn_drift.py.

ENC-TSK-E67 / ENC-TSK-J08 / ENC-TSK-J12. Covers the CFN parsing path (no AWS
calls), Condition-aware (IsProduction/IsGamma) declared-side scoping, and the
delta computation shape.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "audit_cfn_drift.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("audit_cfn_drift", MODULE_PATH)
    m = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


def _write_cfn_template(tmp_path: Path, routes=(), rules=()) -> Path:
    """routes/rules: iterable of (key_or_name,) or (key_or_name, condition)."""
    body = ["AWSTemplateFormatVersion: '2010-09-09'", "Resources:"]
    for i, entry in enumerate(routes):
        rk, condition = (entry, None) if isinstance(entry, str) else entry
        body.append(f"  Route{i}:")
        body.append("    Type: AWS::ApiGatewayV2::Route")
        if condition:
            body.append(f"    Condition: {condition}")
        body.append("    Properties:")
        body.append("      ApiId: !Ref HttpApi")
        body.append(f"      RouteKey: {rk}")
        body.append("      Target: !Sub integrations/${X}")
    for i, entry in enumerate(rules):
        name, condition = (entry, None) if isinstance(entry, str) else entry
        body.append(f"  Rule{i}:")
        body.append("    Type: AWS::Events::Rule")
        if condition:
            body.append(f"    Condition: {condition}")
        body.append("    Properties:")
        body.append(f"      Name: {name}")
        body.append("      ScheduleExpression: rate(24 hours)")
    path = tmp_path / f"{tmp_path.name}.yaml"
    path.write_text("\n".join(body))
    return path


def test_declared_routes_extracts_all_route_keys(tmp_path, mod):
    _write_cfn_template(
        tmp_path,
        routes=[
            "GET /api/v1/foo",
            "POST /api/v1/bar/{id}",
            "PATCH /api/v1/baz",
        ],
    )
    found = mod.declared_routes(str(tmp_path / "*.yaml"))
    assert found == {
        "GET /api/v1/foo",
        "POST /api/v1/bar/{id}",
        "PATCH /api/v1/baz",
    }


def test_declared_eventbridge_rules_parses_name(tmp_path, mod):
    _write_cfn_template(
        tmp_path,
        rules=[
            "enceladus-auditor-schedule",
            "enceladus-health-probe",
        ],
    )
    found = mod.declared_eventbridge_rules(str(tmp_path / "*.yaml"), "enceladus-")
    assert found == {"enceladus-auditor-schedule", "enceladus-health-probe"}


def test_declared_routes_isgamma_scoped_to_gamma_environment(tmp_path, mod):
    """ENC-TSK-J12 / ENC-ISS-455: a Condition: IsGamma route only materializes
    in the gamma stack; it must not count as declared on a prod audit (else it
    reads as cfn_only drift the moment the route is added — the 16-route
    false-positive class)."""
    _write_cfn_template(
        tmp_path,
        routes=[
            "GET /api/v1/always",
            ("POST /api/v1/gamma-only", "IsGamma"),
        ],
    )
    glob_pattern = str(tmp_path / "*.yaml")
    prod = mod.declared_routes(glob_pattern, "prod")
    gamma = mod.declared_routes(glob_pattern, "gamma")
    assert prod == {"GET /api/v1/always"}
    assert gamma == {"GET /api/v1/always", "POST /api/v1/gamma-only"}


def test_declared_eventbridge_rules_isproduction_scoped_to_prod_environment(tmp_path, mod):
    """ENC-TSK-J12 / ENC-ISS-455: a Condition: IsProduction rule (e.g.
    enceladus-standing-projection-refresh) only exists in the prod stack; it
    must not count as declared on a gamma audit."""
    _write_cfn_template(
        tmp_path,
        rules=[
            "enceladus-always-rule",
            ("enceladus-prod-only-rule", "IsProduction"),
        ],
    )
    glob_pattern = str(tmp_path / "*.yaml")
    prod = mod.declared_eventbridge_rules(glob_pattern, "enceladus-", "prod")
    gamma = mod.declared_eventbridge_rules(glob_pattern, "enceladus-", "gamma")
    assert prod == {"enceladus-always-rule", "enceladus-prod-only-rule"}
    assert gamma == {"enceladus-always-rule"}


def test_unconditioned_and_unknown_condition_always_declared(tmp_path, mod):
    """A resource with no Condition, or one gated by a condition name this
    tool doesn't understand, keeps the pre-J12 always-declared behavior rather
    than being silently dropped."""
    _write_cfn_template(
        tmp_path,
        routes=[("GET /api/v1/weird", "SomeOtherCondition")],
    )
    glob_pattern = str(tmp_path / "*.yaml")
    assert mod.declared_routes(glob_pattern, "prod") == {"GET /api/v1/weird"}
    assert mod.declared_routes(glob_pattern, "gamma") == {"GET /api/v1/weird"}


def test_audit_report_has_expected_shape(tmp_path, monkeypatch, mod):
    _write_cfn_template(
        tmp_path,
        routes=["GET /api/v1/foo", "POST /api/v1/bar"],
        rules=["enceladus-auditor-schedule"],
    )

    def fake_live_routes(api_id):
        return {"GET /api/v1/foo", "DELETE /api/v1/extra"}

    def fake_live_rules(prefix, environment="prod"):
        return {"enceladus-auditor-schedule", "enceladus-extra-rule"}

    monkeypatch.setattr(mod, "live_apigw_routes", fake_live_routes)
    monkeypatch.setattr(mod, "live_eventbridge_rules", fake_live_rules)

    report = mod.audit(
        api_id="abc123",
        cfn_glob=str(tmp_path / "*.yaml"),
        event_rule_prefix="enceladus-",
    )

    assert report["apigw_routes"]["live_only"] == ["DELETE /api/v1/extra"]
    assert report["apigw_routes"]["cfn_only"] == ["POST /api/v1/bar"]
    assert report["eventbridge_rules"]["live_only"] == ["enceladus-extra-rule"]
    assert report["eventbridge_rules"]["cfn_only"] == []


def test_audit_isgamma_route_is_not_prod_drift(tmp_path, monkeypatch, mod):
    """End-to-end: an IsGamma route that is live in gamma but declared with a
    Condition must not appear as cfn_only drift on a prod-environment audit
    (it was never supposed to exist in prod)."""
    _write_cfn_template(
        tmp_path,
        routes=[
            "GET /api/v1/always",
            ("POST /api/v1/gamma-only", "IsGamma"),
        ],
    )
    monkeypatch.setattr(mod, "live_apigw_routes", lambda api_id: {"GET /api/v1/always"})
    monkeypatch.setattr(mod, "live_eventbridge_rules", lambda p, environment="prod": set())

    report = mod.audit(
        api_id="abc123",
        cfn_glob=str(tmp_path / "*.yaml"),
        event_rule_prefix="enceladus-",
        environment="prod",
    )
    assert report["apigw_routes"]["cfn_only"] == []
    assert report["apigw_routes"]["live_only"] == []


def test_resolve_api_id_drops_gamma_sibling(monkeypatch, mod):
    """prod + gamma siblings both match the prefix filter; resolver must
    deterministically return the production ApiId (ENC-TSK-H36)."""
    apis = {
        "Items": [
            {"Name": "devops-tracker-api", "ApiId": "prod123"},
            {"Name": "devops-tracker-api-gamma", "ApiId": "gamma456"},
        ]
    }
    monkeypatch.setattr(mod, "_aws_json", lambda cmd: apis)
    assert mod.resolve_api_id("enceladus-") == "prod123"


def test_resolve_api_id_still_raises_on_genuine_ambiguity(monkeypatch, mod):
    """Two genuine (non-env-suffixed) prod candidates remain ambiguous and
    must still raise so the operator passes --api-id explicitly."""
    apis = {
        "Items": [
            {"Name": "devops-tracker-api", "ApiId": "a1"},
            {"Name": "devops-checkout-api", "ApiId": "a2"},
        ]
    }
    monkeypatch.setattr(mod, "_aws_json", lambda cmd: apis)
    with pytest.raises(RuntimeError, match="Multiple API Gateway v2 APIs match"):
        mod.resolve_api_id("enceladus-")


def test_resolve_api_id_single_match(monkeypatch, mod):
    apis = {"Items": [{"Name": "devops-tracker-api", "ApiId": "only1"}]}
    monkeypatch.setattr(mod, "_aws_json", lambda cmd: apis)
    assert mod.resolve_api_id("enceladus-") == "only1"


def test_audit_no_drift(tmp_path, monkeypatch, mod):
    _write_cfn_template(
        tmp_path,
        routes=["GET /api/v1/foo"],
        rules=["enceladus-auditor-schedule"],
    )
    monkeypatch.setattr(mod, "live_apigw_routes", lambda api_id: {"GET /api/v1/foo"})
    monkeypatch.setattr(
        mod, "live_eventbridge_rules", lambda p, environment="prod": {"enceladus-auditor-schedule"}
    )

    report = mod.audit(
        api_id="abc123",
        cfn_glob=str(tmp_path / "*.yaml"),
        event_rule_prefix="enceladus-",
    )

    for section in ("apigw_routes", "eventbridge_rules"):
        assert report[section]["live_only"] == []
        assert report[section]["cfn_only"] == []


def test_self_check_passes(mod):
    """The tool's own offline self-check (ENC-TSK-J12) must pass; this pins
    it as a real regression signal rather than a script that always exits 0."""
    assert mod._self_check() is True
