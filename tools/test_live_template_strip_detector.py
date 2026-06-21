#!/usr/bin/env python3
"""Tests for tools/live_template_strip_detector.py — ENC-TSK-H19.

Covers the live-vs-template comparison + classification, the baseline
(live subset of template -> zero strip risk), the end-to-end proof that
template vars correctly resolved by H17 (incl. AppConfig !If vars) are NOT
false-flagged as live-only, and (ENC-TSK-H33) the CLI process-exit parity:
main() returns rc=2 on a live-only deploy-critical var and rc=0 on a subset.

    python3 tools/test_live_template_strip_detector.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cfn_env_resolver as resolver  # noqa: E402
import live_template_strip_detector as det  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml"
REGISTRY = REPO_ROOT / "backend" / "lambda" / "env_drift_auditor" / "env_drift_registry.json"


def test_baseline_live_subset_no_findings():
    template = {"fn": {"resolved_env": {"A": "1", "B": "2"}}}
    live = {"fn": {"A": "1"}}  # subset
    result = det.detect(template, live, {"fn": ["A", "B"]})
    assert result["failed"] is False
    assert result["findings"] == []


def test_live_only_required_is_critical():
    template = {"fn": {"resolved_env": {"A": "1"}}}
    live = {"fn": {"A": "1", "COORDINATION_INTERNAL_API_KEY": "live-secret"}}
    result = det.detect(template, live, {"fn": ["A", "COORDINATION_INTERNAL_API_KEY"]})
    assert result["failed"] is True
    crit = [f for f in result["findings"] if f["classification"] == det.CRITICAL]
    assert len(crit) == 1
    assert crit[0]["var"] == "COORDINATION_INTERNAL_API_KEY"
    assert crit[0]["message"] == "deploy would strip COORDINATION_INTERNAL_API_KEY from fn"


def test_live_only_nonrequired_is_warning():
    template = {"fn": {"resolved_env": {"A": "1"}}}
    live = {"fn": {"A": "1", "MANUAL_DEBUG_FLAG": "on"}}
    result = det.detect(template, live, {"fn": ["A"]})  # MANUAL_DEBUG_FLAG not required
    assert result["failed"] is False
    warn = [f for f in result["findings"] if f["classification"] == det.WARNING]
    assert len(warn) == 1 and warn[0]["var"] == "MANUAL_DEBUG_FLAG"


def test_advisory_required_live_only_is_warning():
    # ENC-TSK-H16: a live-only var that is REQUIRED but classified advisory WARNs
    # (not FAIL) — the same split the H18 gate applies. A deploy-critical live-only
    # var still FAILs, so the detector fails overall.
    template = {"fn": {"resolved_env": {"A": "1"}}}
    live = {"fn": {"A": "1", "OPT": "x", "KEY": "y"}}
    required_map = {"fn": {"A": "deploy-critical", "OPT": "advisory", "KEY": "deploy-critical"}}
    result = det.detect(template, live, required_map)
    assert result["failed"] is True  # KEY (deploy-critical) is live-only
    by_var = {f["var"]: f["classification"] for f in result["findings"]}
    assert by_var["OPT"] == det.WARNING
    assert by_var["KEY"] == det.CRITICAL


def test_function_not_live_is_skipped():
    template = {"fn-a": {"resolved_env": {"A": "1"}}, "fn-b": {"resolved_env": {"B": "1"}}}
    live = {"fn-a": {"A": "1"}}  # fn-b not deployed
    result = det.detect(template, live, {})
    assert "fn-b" in result["skipped_not_live"]


def test_accepts_flat_env_shape():
    # detect() should also accept {fn: {var: val}} without the resolved_env wrapper.
    result = det.detect({"fn": {"A": "1"}}, {"fn": {"A": "1", "X": "2"}}, {"fn": ["A"]})
    assert result["counts"][det.WARNING] == 1


def test_end_to_end_appconfig_not_false_flagged():
    """The prototype flagged APPCONFIG_* as 'would strip'. With H17 resolving !If
    correctly, APPCONFIG_APPLICATION is present in the template-resolved env, so a
    live env that also has it is NOT flagged — only the genuine out-of-band var is.
    """
    template = resolver.load_template(TEMPLATE)
    ctx = resolver.ResolveContext(resolver.build_params(template, {}))
    template_envs = resolver.resolve_function_envs(template, ctx)
    fn = "devops-coordination-api"
    resolved = template_envs[fn]["resolved_env"]
    assert "APPCONFIG_APPLICATION" in resolved  # H17 resolved the !If branch

    # Live = exactly the template-resolved env PLUS one genuine out-of-band var.
    live = {fn: dict(resolved, OUT_OF_BAND_ONLY="x")}
    result = det.detect(template_envs, live, resolver.load_required_env(REGISTRY))
    flagged_vars = {f["var"] for f in result["findings"]}
    assert flagged_vars == {"OUT_OF_BAND_ONLY"}  # APPCONFIG_* NOT flagged
    assert "APPCONFIG_APPLICATION" not in flagged_vars


def test_run_with_injected_provider():
    # Full run() path with a synthetic live provider (no AWS).
    def provider(names, region):
        return {"devops-coordination-api": {"BOGUS_LIVE_ONLY": "1"}}

    result = det.run(TEMPLATE, {}, REGISTRY, live_env_provider=provider)
    msgs = [f["message"] for f in result["findings"]]
    assert "deploy would strip BOGUS_LIVE_ONLY from devops-coordination-api" in msgs


# ---------------------------------------------------------------------------
# ENC-TSK-H33 — CLI process-exit parity with the env-parity gate.
#
# The detect()/run() tests above assert on result dicts; they never exercise the
# CLI's process exit code. These two drive the entrypoint main() end-to-end via
# the OFFLINE --live-env-file path and assert the returned exit code, mirroring
# tools/test_env_parity_gate.py::test_main_exit_code_nonzero_on_critical
# (fail-closed CLI contract). No boto3 / no AWS — --live-env-file only, against a
# synthetic template + registry so the cases stay stable regardless of the real
# 02-compute.yaml / env_drift_registry.json.
# ---------------------------------------------------------------------------

_SYNTH_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  A:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: fn-a
      Environment:
        Variables:
          PRESENT: ok
  B:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: fn-b
      Environment:
        Variables:
          PRESENT: ok
          ALSO: ok
"""


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(content)
    return p


def test_main_exit_code_nonzero_on_critical():
    # A live-only DEPLOY-CRITICAL required var (fn-a.NEEDED — present live, absent
    # from the template-resolved env) must make the CLI exit rc=2 — the same
    # fail-closed contract test_env_parity_gate asserts for the gate.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", _SYNTH_TEMPLATE)
        reg = _write(tmp, "registry.json", json.dumps({"lambdas": {"fn-a": ["PRESENT", "NEEDED"]}}))
        live = _write(tmp, "live.json", json.dumps({"fn-a": {"PRESENT": "ok", "NEEDED": "live-secret"}}))
        rc = det.main(
            ["--template", str(tpl), "--registry", str(reg),
             "--live-env-file", str(live), "--format", "json"]
        )
        assert rc == 2


def test_main_exit_code_zero_on_live_subset():
    # When the live env is a SUBSET of the template-resolved env there are no
    # live-only vars (zero strip risk) -> the CLI exits rc=0.
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", _SYNTH_TEMPLATE)
        reg = _write(tmp, "registry.json", json.dumps({"lambdas": {"fn-a": ["PRESENT", "NEEDED"]}}))
        live = _write(tmp, "live.json", json.dumps({"fn-a": {"PRESENT": "ok"}}))
        rc = det.main(
            ["--template", str(tpl), "--registry", str(reg),
             "--live-env-file", str(live), "--format", "json"]
        )
        assert rc == 0


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
