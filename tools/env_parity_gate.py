#!/usr/bin/env python3
"""Pre-deploy environment-parity gate — ENC-TSK-H18.

ENC-PLN-048 Objective 2 (parent ENC-TSK-H12, feature ENC-FTR-102). Wraps the
H17 resolver/diff engine (tools/cfn_env_resolver.py) with fail-closed behavior:

  * Exits NON-ZERO if any deploy-critical required var would be unset by the
    template-resolved env (the H05/H09 "deploy would strip <var>" class).
  * Prints function + var + remediation for every finding.
  * Advisory vars WARN without failing (configurable per-function or via "*").
  * A documented, auditable waiver suppresses a specific (function, var) FAILURE
    — but the waiver is still RECORDED in the report. Waivers are never silent,
    so the gate cannot be quietly bypassed.

Single diff implementation: this gate does NOT re-diff. It consumes
cfn_env_resolver.diff_required so pre-deploy and the resolver stay consistent
(ENC-TSK-H17/H19 AC2 — no divergent second implementation).

Usage:
  python3 tools/env_parity_gate.py \
      --template infrastructure/cloudformation/02-compute.yaml \
      --parameter EnvironmentSuffix=-gamma \
      --waivers tools/env_parity_waivers.json
Exit codes: 0 = pass (no un-waived critical gaps), 2 = fail.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cfn_env_resolver as resolver  # noqa: E402

CRITICAL = "critical"
ADVISORY = "advisory"
WAIVED = "waived"

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_WAIVERS = _REPO_ROOT / "tools" / "env_parity_waivers.json"


def load_waivers(path: Optional[Path]) -> Dict[str, Any]:
    """Load the waiver/advisory config. Missing file -> empty (fail-closed)."""
    if path is None or not Path(path).exists():
        return {"waivers": {}, "advisory": {}}
    data = json.loads(Path(path).read_text())
    waivers: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for entry in data.get("waivers", []) or []:
        fn = entry.get("function")
        var = entry.get("var")
        if fn and var and not str(fn).startswith("EXAMPLE"):
            waivers[(fn, var)] = entry
    advisory: Dict[str, set] = {}
    for fn, vars_ in (data.get("advisory_vars", {}) or {}).items():
        if fn.startswith("_"):
            continue
        advisory[fn] = set(vars_ or [])
    return {"waivers": waivers, "advisory": advisory}


def _is_advisory(fn: str, var: str, advisory: Dict[str, set]) -> bool:
    return var in advisory.get(fn, set()) or var in advisory.get("*", set())


def _remediation(fn: str, var: str) -> str:
    return (
        f"add '{var}' to {fn}'s Environment.Variables in "
        f"infrastructure/cloudformation/02-compute.yaml (reference the deploy "
        f"parameter that supplies it so the next deploy does not strip the live "
        f"value), or add a documented waiver to tools/env_parity_waivers.json"
    )


def run_gate(
    template_path: Path,
    overrides: Dict[str, str],
    registry_path: Path,
    waivers_cfg: Dict[str, Any],
    region: str = resolver.DEFAULT_REGION,
) -> Dict[str, Any]:
    """Resolve template env, diff vs required-env, classify each missing var."""
    report = resolver.resolve_and_diff(template_path, overrides, registry_path, region=region)
    waivers = waivers_cfg["waivers"]
    advisory = waivers_cfg["advisory"]

    findings: List[Dict[str, Any]] = []
    counts = {CRITICAL: 0, ADVISORY: 0, WAIVED: 0}
    for fn_name in sorted(report["diff"]):
        d = report["diff"][fn_name]
        if not d["has_registry_entry"]:
            continue  # only registry-governed functions are gated
        for var in d["missing"]:
            if (fn_name, var) in waivers:
                klass = WAIVED
                detail = waivers[(fn_name, var)]
            elif _is_advisory(fn_name, var, advisory):
                klass = ADVISORY
                detail = None
            else:
                klass = CRITICAL
                detail = None
            counts[klass] += 1
            findings.append(
                {
                    "function": fn_name,
                    "var": var,
                    "classification": klass,
                    "waiver": detail,
                    "remediation": _remediation(fn_name, var),
                }
            )

    return {
        "template": str(template_path),
        "region": region,
        "findings": findings,
        "counts": counts,
        "failed": counts[CRITICAL] > 0,
    }


def format_report(result: Dict[str, Any]) -> str:
    lines = [
        "============================================================",
        "  PRE-DEPLOY ENV PARITY GATE (ENC-PLN-048 / ENC-FTR-102)",
        "============================================================",
        f"  Template: {result['template']}  Region: {result['region']}",
        f"  critical={result['counts'][CRITICAL]} "
        f"advisory={result['counts'][ADVISORY]} waived={result['counts'][WAIVED]}",
        "",
    ]
    if not result["findings"]:
        lines.append("  All registry-required vars are present in the template-resolved env.")
    for f in result["findings"]:
        tag = {CRITICAL: "[FAIL]", ADVISORY: "[WARN]", WAIVED: "[WAIVED]"}[f["classification"]]
        lines.append(f"  {tag} {f['function']} :: {f['var']}")
        if f["classification"] == WAIVED and f["waiver"]:
            w = f["waiver"]
            lines.append(f"          waiver: {w.get('reason', '')} (owner={w.get('owner', '?')}, review_by={w.get('review_by', '?')})")
        elif f["classification"] == CRITICAL:
            lines.append(f"          fix: {f['remediation']}")
    lines.append("")
    if result["failed"]:
        lines.append(f"  GATE: FAILED — {result['counts'][CRITICAL]} deploy-critical var(s) would be stripped.")
    else:
        lines.append("  GATE: PASSED")
    lines.append("============================================================")
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail-closed pre-deploy env parity gate (ENC-TSK-H18).")
    parser.add_argument("--template", default=str(resolver._DEFAULT_TEMPLATE))
    parser.add_argument("--registry", default=str(resolver._DEFAULT_REGISTRY))
    parser.add_argument("--waivers", default=str(_DEFAULT_WAIVERS))
    parser.add_argument("--region", default=resolver.DEFAULT_REGION)
    parser.add_argument("--parameter", action="append", default=[], metavar="Key=Value")
    parser.add_argument("--parameters-file")
    parser.add_argument("--format", choices=["json", "text"], default="text")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    overrides = resolver._parse_overrides(args.parameter, args.parameters_file)
    waivers_cfg = load_waivers(Path(args.waivers))
    result = run_gate(
        Path(args.template), overrides, Path(args.registry), waivers_cfg, region=args.region
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(format_report(result))
    return 2 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
