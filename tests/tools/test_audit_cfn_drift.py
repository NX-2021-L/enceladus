"""Regression tests for tools/audit_cfn_drift.py.

ENC-TSK-E67. Covers the CFN parsing path (no AWS calls) and the delta
computation shape.
"""

from __future__ import annotations

import importlib.util
import json
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


def _write_cfn_template(tmp_path: Path, routes: list[str], rules: list[str]) -> Path:
    body = ["AWSTemplateFormatVersion: '2010-09-09'", "Resources:"]
    for i, rk in enumerate(routes):
        body.append(f"  Route{i}:")
        body.append("    Type: AWS::ApiGatewayV2::Route")
        body.append("    Properties:")
        body.append("      ApiId: !Ref HttpApi")
        body.append(f"      RouteKey: {rk}")
        body.append("      Target: !Sub integrations/${X}")
    for i, name in enumerate(rules):
        body.append(f"  Rule{i}:")
        body.append("    Type: AWS::Events::Rule")
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
        rules=[],
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
        routes=[],
        rules=[
            "enceladus-auditor-schedule",
            "enceladus-health-probe",
        ],
    )
    found = mod.declared_eventbridge_rules(str(tmp_path / "*.yaml"))
    assert found == {"enceladus-auditor-schedule", "enceladus-health-probe"}


def test_audit_report_has_expected_shape(tmp_path, monkeypatch, mod):
    _write_cfn_template(
        tmp_path,
        routes=["GET /api/v1/foo", "POST /api/v1/bar"],
        rules=["enceladus-auditor-schedule"],
    )

    def fake_live_routes(api_id):
        return {"GET /api/v1/foo", "DELETE /api/v1/extra"}

    def fake_live_rules(prefix):
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


def test_audit_no_drift(tmp_path, monkeypatch, mod):
    _write_cfn_template(
        tmp_path,
        routes=["GET /api/v1/foo"],
        rules=["enceladus-auditor-schedule"],
    )
    monkeypatch.setattr(mod, "live_apigw_routes", lambda api_id: {"GET /api/v1/foo"})
    monkeypatch.setattr(mod, "live_eventbridge_rules", lambda p: {"enceladus-auditor-schedule"})

    report = mod.audit(
        api_id="abc123",
        cfn_glob=str(tmp_path / "*.yaml"),
        event_rule_prefix="enceladus-",
    )

    for section in ("apigw_routes", "eventbridge_rules"):
        assert report[section]["live_only"] == []
        assert report[section]["cfn_only"] == []
