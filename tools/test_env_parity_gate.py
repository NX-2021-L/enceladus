#!/usr/bin/env python3
"""Tests for tools/env_parity_gate.py — ENC-TSK-H18 (ENC-PLN-048 Objective 2).

Proves fail-closed exit, the documented-waiver suppression (recorded, not
silent), and advisory warn-without-fail. Uses synthetic templates so the tests
stay stable when the real 02-compute.yaml is later remediated.

    python3 tools/test_env_parity_gate.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import env_parity_gate as gate  # noqa: E402

SYNTH_TEMPLATE = """
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


def _registry(tmp: Path, mapping: dict) -> Path:
    return _write(tmp, "registry.json", json.dumps({"lambdas": mapping}))


def test_critical_missing_fails():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT", "NEEDED"], "fn-b": ["PRESENT"]})
        result = gate.run_gate(tpl, {}, reg, {"waivers": {}, "advisory": {}})
        assert result["failed"] is True
        crit = [f for f in result["findings"] if f["classification"] == gate.CRITICAL]
        assert len(crit) == 1
        assert crit[0]["function"] == "fn-a" and crit[0]["var"] == "NEEDED"
        assert "02-compute.yaml" in crit[0]["remediation"]


def test_waiver_suppresses_but_records():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT", "NEEDED"]})
        cfg = {
            "waivers": {("fn-a", "NEEDED"): {"reason": "intentional", "owner": "io", "review_by": "2026-12-31"}},
            "advisory": {},
        }
        result = gate.run_gate(tpl, {}, reg, cfg)
        assert result["failed"] is False  # waived -> no critical
        waived = [f for f in result["findings"] if f["classification"] == gate.WAIVED]
        assert len(waived) == 1  # still RECORDED (not silent)
        assert waived[0]["waiver"]["reason"] == "intentional"


def test_advisory_warns_without_failing():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT", "OPTIONAL"]})
        cfg = {"waivers": {}, "advisory": {"fn-a": {"OPTIONAL"}}}
        result = gate.run_gate(tpl, {}, reg, cfg)
        assert result["failed"] is False
        adv = [f for f in result["findings"] if f["classification"] == gate.ADVISORY]
        assert len(adv) == 1 and adv[0]["var"] == "OPTIONAL"


def test_advisory_wildcard():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT", "OPTIONAL"]})
        cfg = {"waivers": {}, "advisory": {"*": {"OPTIONAL"}}}
        result = gate.run_gate(tpl, {}, reg, cfg)
        assert result["failed"] is False
        assert result["counts"][gate.ADVISORY] == 1


def test_all_present_passes():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT"], "fn-b": ["PRESENT", "ALSO"]})
        result = gate.run_gate(tpl, {}, reg, {"waivers": {}, "advisory": {}})
        assert result["failed"] is False
        assert result["findings"] == []


def test_untracked_function_not_gated():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        # fn-b not in registry -> not gated even though it has extra var.
        reg = _registry(tmp, {"fn-a": ["PRESENT"]})
        result = gate.run_gate(tpl, {}, reg, {"waivers": {}, "advisory": {}})
        assert all(f["function"] != "fn-b" for f in result["findings"])


def test_load_waivers_filters_example_entries():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        wf = _write(
            tmp,
            "w.json",
            json.dumps(
                {
                    "waivers": [
                        {"function": "EXAMPLE-x", "var": "Y", "reason": "doc"},
                        {"function": "fn-a", "var": "NEEDED", "reason": "real", "owner": "io"},
                    ],
                    "advisory_vars": {"_comment": "x", "fn-a": ["OPT"]},
                }
            ),
        )
        cfg = gate.load_waivers(wf)
        assert ("fn-a", "NEEDED") in cfg["waivers"]
        assert ("EXAMPLE-x", "Y") not in cfg["waivers"]
        assert cfg["advisory"]["fn-a"] == {"OPT"}


def test_main_exit_code_nonzero_on_critical():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        tpl = _write(tmp, "t.yaml", SYNTH_TEMPLATE)
        reg = _registry(tmp, {"fn-a": ["PRESENT", "NEEDED"]})
        wf = _write(tmp, "w.json", json.dumps({"waivers": [], "advisory_vars": {}}))
        rc = gate.main(["--template", str(tpl), "--registry", str(reg), "--waivers", str(wf), "--format", "json"])
        assert rc == 2


def test_shipped_waiver_file_has_no_active_waivers():
    """The committed waiver file must not pre-waive real findings (stays honest)."""
    cfg = gate.load_waivers(gate._DEFAULT_WAIVERS)
    assert cfg["waivers"] == {}, "shipped waivers file should have zero active waivers"


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
