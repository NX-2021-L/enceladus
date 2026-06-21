#!/usr/bin/env python3
"""Tests for tools/cfn_env_resolver.py — ENC-TSK-H17 (ENC-PLN-048 Objective 2).

Covers the intrinsic-function evaluation that the PLN-048 prototype got wrong
(!If / AWS::NoValue), plus !Ref/--parameter-overrides, !Sub, gamma suffixing,
and the required-env diff. Runs under pytest OR directly:

    python3 tools/test_cfn_env_resolver.py
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cfn_env_resolver as r  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml"
REGISTRY = REPO_ROOT / "backend" / "lambda" / "env_drift_auditor" / "env_drift_registry.json"


# --- Synthetic template exercising every intrinsic deterministically --------
SYNTHETIC = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  EnvironmentSuffix:
    Type: String
    Default: ""
  LayerArn:
    Type: String
    Default: "arn:aws:lambda:us-west-2:1:layer:x:1"
  SuppliedKey:
    Type: String
    Default: ""
Conditions:
  IsGamma: !Not [!Equals [!Ref EnvironmentSuffix, ""]]
  HasLayer: !Not [!Equals [!Ref LayerArn, ""]]
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "widget${EnvironmentSuffix}"
      Environment:
        Variables:
          PLAIN: hello
          TABLE: !Sub "tbl${EnvironmentSuffix}"
          REGION_VAR: !Ref AWS::Region
          SUPPLIED: !Ref SuppliedKey
          APPCONFIG: !If [HasLayer, !Ref SuppliedKey, !Ref "AWS::NoValue"]
          ROLE_ATTR: !GetAtt SomeRole.Arn
          JOINED: !Join ["-", ["a", !Ref EnvironmentSuffix, "b"]]
  NotALambda:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ignored
"""


def _resolve_synthetic(overrides=None, region="us-west-2"):
    template = r.yaml.load(io.StringIO(SYNTHETIC), Loader=r._CfnLoader)
    ctx = r.ResolveContext(r.build_params(template, overrides or {}), region=region)
    return r.resolve_function_envs(template, ctx)


def test_plain_and_sub_and_region():
    env = _resolve_synthetic()["widget"]["resolved_env"]
    assert env["PLAIN"] == "hello"
    assert env["TABLE"] == "tbl"  # suffix "" -> no suffix
    assert env["REGION_VAR"] == "us-west-2"  # AWS::Region pseudo-param
    assert env["JOINED"] == "a--b"  # empty suffix joins to a--b


def test_novalue_dropped_when_condition_false():
    # LayerArn="" -> HasLayer False -> APPCONFIG = !Ref AWS::NoValue -> ABSENT.
    env = _resolve_synthetic({"LayerArn": ""})["widget"]["resolved_env"]
    assert "APPCONFIG" not in env, "AWS::NoValue var must be dropped, not present-empty"


def test_novalue_present_when_condition_true():
    # Default LayerArn non-empty -> HasLayer True -> APPCONFIG present (== SuppliedKey).
    env = _resolve_synthetic()["widget"]["resolved_env"]
    assert "APPCONFIG" in env
    assert env["APPCONFIG"] == ""  # SuppliedKey default ""


def test_param_override_resolves():
    env = _resolve_synthetic({"SuppliedKey": "s3cr3t"})["widget"]["resolved_env"]
    assert env["SUPPLIED"] == "s3cr3t"
    assert env["APPCONFIG"] == "s3cr3t"  # HasLayer True branch picks SuppliedKey


def test_gamma_suffix_applies_to_name_and_vars():
    funcs = _resolve_synthetic({"EnvironmentSuffix": "-gamma"})
    assert "widget-gamma" in funcs
    env = funcs["widget-gamma"]["resolved_env"]
    assert env["TABLE"] == "tbl-gamma"
    assert env["JOINED"] == "a--gamma-b"


def test_getatt_present_but_opaque():
    env = _resolve_synthetic()["widget"]["resolved_env"]
    assert env["ROLE_ATTR"].startswith("<GetAtt:SomeRole.Arn")


def test_only_lambda_resources_returned():
    funcs = _resolve_synthetic()
    assert set(funcs) == {"widget"}  # S3 bucket excluded


# --- Real-template smoke tests (the documented prototype failure) -----------
def test_real_template_appconfig_present_under_defaults():
    template = r.load_template(TEMPLATE)
    ctx = r.ResolveContext(r.build_params(template, {}))
    funcs = r.resolve_function_envs(template, ctx)
    env = funcs["devops-coordination-api"]["resolved_env"]
    # HasAppConfigLayer True under defaults -> these are SET (the prototype's bug
    # was reporting them as "would be stripped").
    assert "APPCONFIG_APPLICATION" in env
    assert "APPCONFIG_ENVIRONMENT" in env


def test_real_template_appconfig_dropped_when_layer_absent():
    template = r.load_template(TEMPLATE)
    ctx = r.ResolveContext(r.build_params(template, {"AppConfigExtensionLayerArnX86": ""}))
    funcs = r.resolve_function_envs(template, ctx)
    env = funcs["devops-coordination-api"]["resolved_env"]
    assert "APPCONFIG_APPLICATION" not in env
    assert "APPCONFIG_ENVIRONMENT" not in env


def test_real_template_gamma_names():
    template = r.load_template(TEMPLATE)
    ctx = r.ResolveContext(r.build_params(template, {"EnvironmentSuffix": "-gamma"}))
    funcs = r.resolve_function_envs(template, ctx)
    assert "devops-coordination-api-gamma" in funcs


def test_diff_required_surfaces_missing_keys():
    # Deterministic: the diff must surface a required var absent from the resolved
    # env. (Previously asserted a specific real-template gap, but the live template
    # is remediated over time — ENC-TSK-H05 codified COORDINATION_INTERNAL_API_KEY
    # on main — so this is synthetic to stay stable across template changes.)
    resolved = {"fn-x": {"logical_id": "X", "resolved_env": {"A": "1"}}}
    diff = r.diff_required(resolved, {"fn-x": ["A", "B"]})
    assert diff["fn-x"]["missing"] == ["B"]
    assert diff["fn-x"]["has_registry_entry"] is True
    # ENC-TSK-H16: legacy flat-list entry -> every var classified deploy-critical.
    assert diff["fn-x"]["classification"] == {"A": "deploy-critical", "B": "deploy-critical"}


def test_diff_required_surfaces_classification_dict_form():
    # ENC-TSK-H16: a dict-form registry entry surfaces per-var classification in
    # the diff so the H18 gate can split FAIL (deploy-critical) vs WARN (advisory)
    # without re-deriving it.
    resolved = {"fn-x": {"logical_id": "X", "resolved_env": {"A": "1"}}}
    diff = r.diff_required(
        resolved, {"fn-x": {"A": "deploy-critical", "B": "advisory", "C": "deploy-critical"}}
    )
    assert diff["fn-x"]["missing"] == ["B", "C"]
    assert diff["fn-x"]["classification"] == {
        "A": "deploy-critical",
        "B": "advisory",
        "C": "deploy-critical",
    }
    assert diff["fn-x"]["has_registry_entry"] is True


def test_diff_required_no_entry_has_empty_classification():
    resolved = {"fn-y": {"logical_id": "Y", "resolved_env": {"A": "1"}}}
    diff = r.diff_required(resolved, {})  # fn-y not in registry
    assert diff["fn-y"]["has_registry_entry"] is False
    assert diff["fn-y"]["missing"] == []
    assert diff["fn-y"]["classification"] == {}


def test_secret_params_redacted_in_report():
    report = r.resolve_and_diff(TEMPLATE, {"CoordinationInternalApiKey": "abc"}, REGISTRY)
    assert report["parameters"]["CoordinationInternalApiKey"] == "<redacted>"


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  FAIL {t.__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
