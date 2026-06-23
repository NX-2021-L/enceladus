#!/usr/bin/env python3
"""Synthetic-strip proof for the pre-deploy env-parity gate — ENC-TSK-H22.

ENC-PLN-048 Objective 4.1 (parent ENC-TSK-H14, feature ENC-FTR-102). This is
the recorded "prove, not assert" evidence that ENC-TSK-H05 AC-8 lacked
(correctness was previously asserted only by code inspection): that
tools/env_parity_gate.py actually FAILS (non-zero exit) when a deploy-critical
required var is stripped from the real CloudFormation template, and PASSES
(exit 0) against the current good 02-compute.yaml.

It supersedes the single-var synthetic strip that ENC-TSK-H05 baked into a
standalone hard-coded coverage guard (retired in ENC-TSK-H21 once this
gate-driven proof subsumed it) — a registry-driven proof over the two
deploy-critical vars from the 2026-06-18 Sev-1 (ENC-LSN-053):
COORDINATION_INTERNAL_API_KEY and SQS_QUEUE_URL.

The strip is applied to the REAL infrastructure/cloudformation/02-compute.yaml
rather than a hand-written synthetic template, so the proof tracks the live
template as it evolves. The historical pre-#493 template (commit a258b40, with
SQS_QUEUE_URL absent on devops-deploy-intake) is the real-world instance of this
exact strip; here we reproduce it deterministically by removing the var — incl.
its multi-line `!ImportValue` value — from a temp copy and running the gate.

No AWS calls; pure template-side resolution (the gate consumes
cfn_env_resolver). Run standalone or in CI:

    python3 tools/test_synthetic_strip_proof.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import env_parity_gate as gate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml"
REGISTRY = REPO_ROOT / "backend" / "lambda" / "env_drift_auditor" / "env_drift_registry.json"
WAIVERS = REPO_ROOT / "tools" / "env_parity_waivers.json"

# The two deploy-critical vars from the ENC-LSN-053 Sev-1 the gate must catch.
TARGET_VARS = ["COORDINATION_INTERNAL_API_KEY", "SQS_QUEUE_URL"]

# Canonical deploy parameter-override sets (prod uses the "" default; gamma uses
# -gamma). The gate must pass under each, proving the good template is correct
# for every sanctioned deploy target. ENC-TSK-H54: the gamma set now also pins
# Environment=gamma so IsProduction=false — the real gamma deploy's parameters
# (the prior ["EnvironmentSuffix=-gamma"]-only set left Environment at its
# "production" default, masking the IsProduction-gated GDS_STANDING_PROJECTION_PREFIX).
GAMMA_OVERRIDES = ["Environment=gamma", "EnvironmentSuffix=-gamma"]
OVERRIDE_SETS = [[], ["EnvironmentSuffix="], ["EnvironmentSuffix=-gamma"], GAMMA_OVERRIDES]

# ENC-TSK-H54 (ENC-PLN-050 P0): gamma parity coverage. Before H54 the registry
# was keyed only by prod function names, so a -gamma-rendered deploy matched no
# entry and the gate skipped every gamma function. These prove the gate now
# catches a strip on a gamma function. ENCELADUS_COGNITO_CLIENT_SECRET is a
# genuinely gamma-only deploy-critical var (only enceladus-mcp-code-gamma
# requires it; no prod twin does). devops-coordination-api-gamma is one of the
# H54-added twins that had NO registry entry before this task.
GAMMA_ONLY_VAR = "ENCELADUS_COGNITO_CLIENT_SECRET"
GAMMA_TWIN_FN = "devops-coordination-api-gamma"
GAMMA_TWIN_VAR = "COORDINATION_INTERNAL_API_KEY"


def _strip_var(text: str, var: str):
    """Remove every ``<var>:`` mapping (including multi-line intrinsic values)
    from a CFN template's text. Returns ``(new_text, removed_count)``.

    Indent-aware so it correctly drops a multi-line value such as
    ``SQS_QUEUE_URL: !ImportValue`` followed by an indented ``Fn::Sub:`` line
    without orphaning the continuation, and the trailing ``:`` boundary keeps it
    from matching longer keys that share the prefix (e.g.
    ``COORDINATION_INTERNAL_API_KEY_PREVIOUS``).
    """
    lines = text.split("\n")
    key_re = re.compile(rf"^(\s*){re.escape(var)}:(?:\s|$)")
    out = []
    removed = 0
    i = 0
    while i < len(lines):
        m = key_re.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        indent = len(m.group(1))
        removed += 1
        i += 1
        # Drop the (optional) more-indented continuation lines of a block value.
        while i < len(lines):
            nxt = lines[i]
            if nxt.strip() and (len(nxt) - len(nxt.lstrip(" "))) <= indent:
                break
            i += 1
    return "\n".join(out), removed


def _write(tmpdir: Path, name: str, text: str) -> Path:
    p = tmpdir / name
    p.write_text(text)
    return p


def _empty_waivers(tmpdir: Path) -> Path:
    # Hermetic: a known-empty waiver file so the strip proof is unaffected by any
    # waiver later added to the shipped tools/env_parity_waivers.json.
    return _write(tmpdir, "waivers.json", json.dumps({"waivers": [], "advisory_vars": {}}))


def _run_main(template: Path, waivers: Path, overrides=None) -> int:
    argv = ["--template", str(template), "--registry", str(REGISTRY),
            "--waivers", str(waivers), "--format", "json"]
    for kv in overrides or []:
        argv += ["--parameter", kv]
    return gate.main(argv)


def test_good_template_passes():
    """AC2: the gate exits 0 against the current good 02-compute.yaml under the
    default and each canonical deploy parameter-override set."""
    for overrides in OVERRIDE_SETS:
        rc = _run_main(TEMPLATE, WAIVERS, overrides)
        assert rc == 0, f"gate failed on the good template with overrides={overrides} (rc={rc})"
    result = gate.run_gate(TEMPLATE, {}, REGISTRY, gate.load_waivers(WAIVERS))
    assert result["failed"] is False
    assert result["counts"][gate.CRITICAL] == 0


def test_strip_each_required_var_fails():
    """AC1: stripping COORDINATION_INTERNAL_API_KEY, and separately
    SQS_QUEUE_URL, from the real template makes the gate fail closed (rc=2), and
    the stripped var is reported as a deploy-critical finding."""
    real = TEMPLATE.read_text()
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        waivers = _empty_waivers(tmp)
        for var in TARGET_VARS:
            stripped, removed = _strip_var(real, var)
            assert removed > 0, f"strip of {var} was a no-op — has the template format changed?"
            tpl = _write(tmp, f"stripped_{var}.yaml", stripped)

            rc = _run_main(tpl, waivers, overrides=[])
            assert rc != 0, f"gate did NOT fail when {var} was stripped (rc={rc})"
            assert rc == 2, f"expected fail-closed rc=2 for stripped {var}, got rc={rc}"

            result = gate.run_gate(tpl, {}, REGISTRY, gate.load_waivers(None))
            crit_vars = {f["var"] for f in result["findings"] if f["classification"] == gate.CRITICAL}
            assert var in crit_vars, f"{var} not flagged critical after strip; got {sorted(crit_vars)}"


def test_sqs_strip_attributes_the_right_function():
    """The SQS_QUEUE_URL strip is attributed to devops-deploy-intake (its sole
    registry consumer) — proving per-function attribution, not just a global
    fail. This is the deterministic reproduction of the pre-#493 / ENC-TSK-H09
    real-world strip."""
    real = TEMPLATE.read_text()
    stripped, removed = _strip_var(real, "SQS_QUEUE_URL")
    assert removed == 1, f"expected exactly one SQS_QUEUE_URL occurrence; removed {removed}"
    with tempfile.TemporaryDirectory() as d:
        tpl = _write(Path(d), "stripped_sqs.yaml", stripped)
        result = gate.run_gate(tpl, {}, REGISTRY, gate.load_waivers(None))
        hits = [f for f in result["findings"]
                if f["classification"] == gate.CRITICAL and f["var"] == "SQS_QUEUE_URL"]
        assert len(hits) == 1, f"expected one SQS_QUEUE_URL critical finding; got {hits}"
        assert hits[0]["function"] == "devops-deploy-intake", hits[0]["function"]


def test_gamma_only_var_strip_fails():
    """ENC-TSK-H54 AC0.2 (gamma-only var coverage): stripping
    ENCELADUS_COGNITO_CLIENT_SECRET — a deploy-critical var that ONLY a -gamma
    registry entry (enceladus-mcp-code-gamma) requires — makes the gate fail
    closed (rc=2) under the gamma parameter-override set, attributed to the gamma
    function. The good template passes under the same overrides."""
    real = TEMPLATE.read_text()
    # good template passes under the real gamma params (sanity).
    assert _run_main(TEMPLATE, WAIVERS, GAMMA_OVERRIDES) == 0
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        waivers = _empty_waivers(tmp)
        stripped, removed = _strip_var(real, GAMMA_ONLY_VAR)
        assert removed > 0, f"strip of {GAMMA_ONLY_VAR} was a no-op — template format changed?"
        tpl = _write(tmp, "stripped_gamma_only.yaml", stripped)
        rc = _run_main(tpl, waivers, overrides=GAMMA_OVERRIDES)
        assert rc == 2, f"gate did NOT fail closed when gamma-only {GAMMA_ONLY_VAR} stripped (rc={rc})"
        result = gate.run_gate(tpl, {"Environment": "gamma", "EnvironmentSuffix": "-gamma"},
                               REGISTRY, gate.load_waivers(None))
        hits = [f for f in result["findings"]
                if f["classification"] == gate.CRITICAL and f["var"] == GAMMA_ONLY_VAR]
        assert any(f["function"] == "enceladus-mcp-code-gamma" for f in hits), \
            f"{GAMMA_ONLY_VAR} strip not attributed to enceladus-mcp-code-gamma; got {hits}"


def test_gamma_twin_governance_catches_strip():
    """ENC-TSK-H54 AC0.2: a deploy-critical strip on a gamma twin that had NO
    registry entry before H54 is now caught under the gamma override set. Proves
    the registry expansion closed the 'gamma silently rots' gap (DOC-A07B553431FD):
    the same strip on devops-coordination-api-gamma produced ZERO findings before
    this task because the function was unregistered."""
    real = TEMPLATE.read_text()
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        stripped, _ = _strip_var(real, GAMMA_TWIN_VAR)
        tpl = _write(tmp, "stripped_twin.yaml", stripped)
        result = gate.run_gate(tpl, {"Environment": "gamma", "EnvironmentSuffix": "-gamma"},
                               REGISTRY, gate.load_waivers(None))
        crit = [f for f in result["findings"]
                if f["classification"] == gate.CRITICAL and f["function"] == GAMMA_TWIN_FN
                and f["var"] == GAMMA_TWIN_VAR]
        assert len(crit) == 1, f"expected {GAMMA_TWIN_FN}::{GAMMA_TWIN_VAR} critical finding; got {result['findings']}"
        # And at least one finding must be on a -gamma function (gamma governance).
        assert any(f["function"].endswith("-gamma") for f in result["findings"])


def test_gds_prefix_is_advisory_on_gamma_not_failing():
    """ENC-TSK-H54 AC0.3 reconciliation: GDS_STANDING_PROJECTION_PREFIX is
    IsProduction-gated (02-compute.yaml L1047 -> AWS::NoValue on gamma) and is
    registered ADVISORY on devops-graph-query-api-gamma. On the GOOD template
    under the gamma params it must surface as an advisory WARN (visible gap) but
    NOT fail the gate — it becomes deploy-critical only after ENC-TSK-H56 sets it
    on gamma."""
    result = gate.run_gate(TEMPLATE, {"Environment": "gamma", "EnvironmentSuffix": "-gamma"},
                           REGISTRY, gate.load_waivers(WAIVERS))
    assert result["failed"] is False, "good gamma template must pass"
    adv = [f for f in result["findings"]
           if f["classification"] == gate.ADVISORY
           and f["function"] == "devops-graph-query-api-gamma"
           and f["var"] == "GDS_STANDING_PROJECTION_PREFIX"]
    assert len(adv) == 1, f"expected GDS_STANDING_PROJECTION_PREFIX advisory on gamma; got {result['findings']}"


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
