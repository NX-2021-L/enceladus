#!/usr/bin/env python3
"""Live-vs-template env strip detector — ENC-TSK-H19.

ENC-PLN-048 Objective 2 (child 2.3), parent ENC-TSK-H12, feature ENC-FTR-102.

For each in-scope function, dump the LIVE Environment.Variables
(aws lambda get-function-configuration) and diff them against the H17
template-resolved env. Any variable present LIVE but NOT set by the
template-resolved env is flagged:

    deploy would strip <var> from <function>

— the exact H05/H09 failure signature — BEFORE merge/deploy.

Classification:
  * critical : the live-only var is a REQUIRED var (env_drift_registry.json).
    A deploy that strips it reproduces the incident class -> gate FAILS.
  * warning  : the live-only var is not in the registry (extra / out-of-band but
    not declared deploy-critical) -> reported, does not fail the gate.

AC2 (no divergent second implementation): the live-vs-template comparison uses
backend/lambda/env_drift_auditor/env_parity_core.live_only_vars — the same module
the env_drift_auditor Lambda uses for its post-deploy scan. The template side is
tools/cfn_env_resolver.py (H17), which correctly evaluates !If/AWS::NoValue/!Sub
so a conditionally-unset template var is NOT mistaken for a live-only var (the
prototype's AppConfig false-positive).

Live env is pluggable: --live-env-file <json> ({fn: {var: val}}) for offline/CI
or unit tests; otherwise boto3 lambda.get_function_configuration is used. No AWS
writes — read-only get-function-configuration only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "tools"))
sys.path.insert(0, str(_REPO_ROOT / "backend" / "lambda" / "env_drift_auditor"))

import cfn_env_resolver as resolver  # noqa: E402
import env_parity_core  # noqa: E402  (shared comparison core — AC2)

CRITICAL = "critical"
WARNING = "warning"


def detect(
    template_envs: Dict[str, Dict[str, Any]],
    live_envs: Dict[str, Dict[str, str]],
    required_map: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Pure comparison: for each function present in BOTH the template and live,
    flag vars that are live-only (the deploy would strip them).

    template_envs: {fn: {"resolved_env": {...}}} (H17 output) or {fn: {...env...}}.
    live_envs:     {fn: {var: value}} live Environment.Variables.
    required_map:  {fn: [required vars]} from env_drift_registry.json.
    """
    findings: List[Dict[str, Any]] = []
    counts = {CRITICAL: 0, WARNING: 0}
    skipped: List[str] = []

    for fn_name in sorted(template_envs):
        template_env = _extract_env(template_envs[fn_name])
        if fn_name not in live_envs:
            skipped.append(fn_name)  # not deployed live (nothing to strip)
            continue
        required = set(required_map.get(fn_name, []))
        for var in env_parity_core.live_only_vars(live_envs[fn_name], template_env):
            klass = CRITICAL if var in required else WARNING
            counts[klass] += 1
            findings.append(
                {
                    "function": fn_name,
                    "var": var,
                    "classification": klass,
                    "required": var in required,
                    "message": f"deploy would strip {var} from {fn_name}",
                }
            )

    return {
        "findings": findings,
        "counts": counts,
        "skipped_not_live": sorted(skipped),
        "failed": counts[CRITICAL] > 0,
    }


def _extract_env(value: Any) -> Dict[str, str]:
    if isinstance(value, dict) and "resolved_env" in value:
        return value["resolved_env"]
    return value if isinstance(value, dict) else {}


def fetch_live_envs_boto3(function_names: List[str], region: str) -> Dict[str, Dict[str, str]]:
    """Read-only live env fetch via boto3 (get-function-configuration)."""
    import boto3  # local import so offline/file mode needs no boto3

    client = boto3.client("lambda", region_name=region)
    out: Dict[str, Dict[str, str]] = {}
    for fn in function_names:
        try:
            cfg = client.get_function_configuration(FunctionName=fn)
        except client.exceptions.ResourceNotFoundException:
            continue  # not deployed -> nothing to strip
        out[fn] = (cfg.get("Environment") or {}).get("Variables", {}) or {}
    return out


def run(
    template_path: Path,
    overrides: Dict[str, str],
    registry_path: Path,
    region: str = resolver.DEFAULT_REGION,
    live_env_provider: Optional[Callable[[List[str], str], Dict[str, Dict[str, str]]]] = None,
) -> Dict[str, Any]:
    template = resolver.load_template(template_path)
    ctx = resolver.ResolveContext(resolver.build_params(template, overrides), region=region)
    template_envs = resolver.resolve_function_envs(template, ctx)
    required_map = resolver.load_required_env(registry_path)

    provider = live_env_provider or fetch_live_envs_boto3
    live_envs = provider(sorted(template_envs), region)

    result = detect(template_envs, live_envs, required_map)
    result["template"] = str(template_path)
    result["region"] = region
    return result


def format_report(result: Dict[str, Any]) -> str:
    lines = [
        "============================================================",
        "  LIVE-vs-TEMPLATE STRIP DETECTOR (ENC-TSK-H19 / ENC-FTR-102)",
        "============================================================",
        f"  Template: {result.get('template')}  Region: {result.get('region')}",
        f"  critical={result['counts'][CRITICAL]} warning={result['counts'][WARNING]} "
        f"not-live={len(result['skipped_not_live'])}",
        "",
    ]
    if not result["findings"]:
        lines.append("  No live-only vars — live env is a SUBSET of the template-resolved env.")
        lines.append("  (Zero pre-deploy strip risk.)")
    for f in result["findings"]:
        tag = "[FAIL]" if f["classification"] == CRITICAL else "[WARN]"
        lines.append(f"  {tag} {f['message']}" + (" (required)" if f["required"] else " (not in registry)"))
    lines.append("")
    if result["failed"]:
        lines.append(
            f"  DETECTOR: FAILED — {result['counts'][CRITICAL]} required var(s) are live-only "
            f"and would be stripped by the deploy. Add them to the template or remove them live."
        )
    else:
        lines.append("  DETECTOR: PASSED")
    lines.append("============================================================")
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live-vs-template env strip detector (ENC-TSK-H19).")
    parser.add_argument("--template", default=str(resolver._DEFAULT_TEMPLATE))
    parser.add_argument("--registry", default=str(resolver._DEFAULT_REGISTRY))
    parser.add_argument("--region", default=resolver.DEFAULT_REGION)
    parser.add_argument("--parameter", action="append", default=[], metavar="Key=Value")
    parser.add_argument("--parameters-file")
    parser.add_argument(
        "--live-env-file",
        help="JSON {function: {var: value}} of live env (offline/CI/test). "
        "Omit to read live via boto3 get-function-configuration.",
    )
    parser.add_argument("--format", choices=["json", "text"], default="text")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    overrides = resolver._parse_overrides(args.parameter, args.parameters_file)

    provider: Optional[Callable[[List[str], str], Dict[str, Dict[str, str]]]] = None
    if args.live_env_file:
        live_data = json.loads(Path(args.live_env_file).read_text())
        provider = lambda names, region: {k: v for k, v in live_data.items() if k in set(names)}  # noqa: E731

    result = run(
        Path(args.template),
        overrides,
        Path(args.registry),
        region=args.region,
        live_env_provider=provider,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_report(result))
    return 2 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
