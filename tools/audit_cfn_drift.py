#!/usr/bin/env python3
"""Audit live AWS resources against CloudFormation-declared resources.

ENC-TSK-E67 / ENC-PLN-031 Phase 2.

Primary focus: API Gateway v2 routes. The ENC-TSK-E57 incident created
route zmra44n via `aws apigatewayv2 create-route` because the endpoint
was needed urgently. Without this audit, a future CFN deploy (or any
refactor of 03-api.yaml) would have silently deleted the route.

Additional categories (lightweight coverage):
- EventBridge rules (prefix filtered to project-scoped names)

For each category the script computes the set delta:

    live_only: resources in AWS that are NOT declared in any CFN template
    cfn_only:  resources declared in CFN that do NOT exist in AWS

Both directions of drift are surfaced. The GitHub Actions wrapper
(cfn-drift-audit.yml) posts new drift to an idempotent GitHub issue.

Modes:
  --api-id <id>                Explicit API Gateway v2 API ID (skips lookup)
  --stack-prefix <prefix>      Only match CFN resources whose stack name
                               starts with this prefix (default: enceladus-)
  --cfn-glob <pattern>         Glob of CFN template files to parse
                               (default: infrastructure/cloudformation/*.yaml)
  --environment <prod|gamma>   Which environment's live resources to audit
                               against the checked-out branch's templates.
                               Also scopes which Condition-gated (IsProduction/
                               IsGamma) resources count as declared (ENC-TSK-J12).
  --output-json <path>         Write JSON drift report for CI consumption
  --fail-on-drift              Exit 1 if any drift is detected
  --self-check                 Run an offline sanity check of the
                               Condition-aware parser (no AWS calls) and exit

The YAML parser handles CFN intrinsic tags (!Ref, !Sub, etc.) without
requiring cfn-lint. Only the fields we care about (route keys, rule names,
Condition) are extracted, so the parser is deliberately minimal.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


def _aws_json(cmd: List[str]) -> object:
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out) if out.strip() else None


def live_apigw_routes(api_id: str) -> Set[str]:
    data = _aws_json([
        "aws", "apigatewayv2", "get-routes",
        "--api-id", api_id,
        "--max-results", "500",
    ])
    return {item["RouteKey"] for item in (data or {}).get("Items", [])}


# Non-production environment siblings (e.g. devops-tracker-api-gamma) share
# the production name prefix but are NOT the audit target. The audit compares
# live routes against the CFN templates that declare the *production* stack, so
# these env-suffixed APIs are dropped when disambiguating. Without this, the
# creation of a gamma sibling makes resolve_api_id ambiguous and the daily
# CFN Drift Audit workflow fails (ENC-TSK-H36).
_ENV_SUFFIXES = ("-gamma", "-beta", "-staging", "-dev", "-test")


def _is_env_sibling(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in _ENV_SUFFIXES)


def resolve_api_id(stack_prefix: str, environment: str = "prod") -> str:
    """Resolve the ApiGatewayV2 API to audit, matching ``environment``.

    ENC-TSK-J12: previously this always dropped every env-suffixed sibling
    and returned the production ApiId, regardless of ``environment`` — a
    gamma audit would silently compare gamma-declared routes against PROD's
    live routes. Now prefers the -gamma sibling when environment == "gamma"
    (still dropping every OTHER env-suffixed sibling, e.g. -beta/-staging),
    and keeps the original prod-preferring behavior otherwise (ENC-TSK-H36).
    """
    data = _aws_json([
        "aws", "apigatewayv2", "get-apis",
        "--max-results", "500",
    ])
    candidates = [
        item for item in (data or {}).get("Items", [])
        if item.get("Name", "").startswith(stack_prefix)
        or item.get("Name", "").startswith("devops-")
        or item.get("Name", "").lower().startswith("enceladus")
    ]
    if not candidates:
        raise RuntimeError(
            f"No API Gateway v2 API matched stack_prefix={stack_prefix}; "
            f"pass --api-id explicitly."
        )
    if len(candidates) > 1:
        if environment == "gamma":
            gamma = [c for c in candidates if c.get("Name", "").endswith("-gamma")]
            if len(gamma) == 1:
                return gamma[0]["ApiId"]
            names = [c["Name"] for c in (gamma or candidates)]
            raise RuntimeError(
                f"Multiple API Gateway v2 APIs match environment=gamma: {names}. "
                f"Pass --api-id explicitly."
            )
        # Prefer production APIs by dropping env-suffixed siblings. If exactly
        # one production candidate remains the ambiguity is resolved.
        prod = [c for c in candidates if not _is_env_sibling(c.get("Name", ""))]
        if len(prod) == 1:
            return prod[0]["ApiId"]
        names = [c["Name"] for c in (prod or candidates)]
        raise RuntimeError(
            f"Multiple API Gateway v2 APIs match: {names}. "
            f"Pass --api-id explicitly."
        )
    return candidates[0]["ApiId"]


_ROUTEKEY_RE = re.compile(
    r"RouteKey:\s*['\"]?(?P<key>[^'\"\n]+?)['\"]?\s*$",
    re.MULTILINE,
)

# ENC-TSK-J12 / ENC-ISS-455: every top-level CFN resource is a `  <Name>:`
# line (2-space indent) followed by its body until the next such line. This
# generic block splitter lets us read each resource's own `Type:` and
# `Condition:` fields instead of scanning RouteKey/Name lines flat across the
# whole file with no idea which resource (or Condition) they belong to.
_RESOURCE_BLOCK_RE = re.compile(r"^  (?P<name>\w+):\n(?P<body>(?:(?!^  \w+:).*\n)*)", re.MULTILINE)
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>[\w:]+)\s*$", re.MULTILINE)
_CONDITION_RE = re.compile(r"^\s*Condition:\s*(?P<cond>\w+)\s*$", re.MULTILINE)


def _iter_resources(text: str):
    """Yield (name, type, condition, body) for every top-level CFN resource."""
    for m in _RESOURCE_BLOCK_RE.finditer(text):
        body = m.group("body")
        type_m = _TYPE_RE.search(body)
        if not type_m:
            continue
        cond_m = _CONDITION_RE.search(body)
        yield m.group("name"), type_m.group("type"), (cond_m.group("cond") if cond_m else None), body


def _condition_declared_for_environment(condition: str | None, environment: str) -> bool:
    """Does a Condition-gated resource actually materialize for ``environment``?

    ENC-TSK-J12 / ENC-ISS-455: a CFN Condition decides, at deploy time, whether
    a resource is created at all. `Condition: IsGamma` resources exist ONLY in
    the gamma stack (EnvironmentSuffix != ""); `Condition: IsProduction`
    resources exist ONLY in the production stack (Environment == "production").
    Treating every declared resource as always-declared (the pre-J12 behavior)
    makes every such resource look like drift in the OTHER environment — the
    16 IsGamma routes / enceladus-standing-projection-refresh false positives.
    Any other (or absent) condition is treated as always-declared, matching
    prior behavior, since we don't know its semantics.
    """
    if condition == "IsGamma":
        return environment == "gamma"
    if condition == "IsProduction":
        return environment == "prod"
    return True


def declared_routes(cfn_glob: str, environment: str = "prod") -> Set[str]:
    """Extract RouteKey values from every AWS::ApiGatewayV2::Route resource
    in the matched CFN templates that is actually declared for ``environment``
    (see _condition_declared_for_environment).
    """
    keys: Set[str] = set()
    for path in sorted(glob.glob(cfn_glob)):
        text = Path(path).read_text()
        for _name, rtype, condition, body in _iter_resources(text):
            if rtype != "AWS::ApiGatewayV2::Route":
                continue
            if not _condition_declared_for_environment(condition, environment):
                continue
            m = _ROUTEKEY_RE.search(body)
            if not m:
                continue
            key = m.group("key").strip()
            if key:
                keys.add(key)
    return keys


def _in_environment(name: str, environment: str) -> bool:
    """Does a live rule name belong to the environment being audited?

    ENC-TSK-J08 / ENC-ISS-455: `aws events list-rules --name-prefix enceladus-`
    returns BOTH prod (`<base>`) and gamma (`<base>-gamma`) rules, but the CFN
    templates on a given branch declare only that branch's environment (main =>
    prod, v4/main => gamma). Auditing conflated live rules against one branch's
    templates makes every gamma rule look like drift on the (main-scheduled)
    audit even though it is properly CFN-managed on v4/main. Scoping the live
    set to the audited environment fixes the gh#635 inflation at its root.
    """
    is_gamma = name.endswith("-gamma")
    if environment == "gamma":
        return is_gamma
    # prod: exclude every non-prod environment sibling (-gamma/-beta/-staging/...)
    return not _is_env_sibling(name)


def live_eventbridge_rules(name_prefix: str, environment: str = "prod") -> Set[str]:
    data = _aws_json([
        "aws", "events", "list-rules",
        "--name-prefix", name_prefix,
    ])
    return {
        item["Name"]
        for item in (data or {}).get("Rules", [])
        if _in_environment(item["Name"], environment)
    }


# ENC-TSK-J08 / ENC-ISS-455: the name class must include the characters used by
# `!Sub "<base>${EnvironmentSuffix}"` (the form EVERY rule in 02-compute.yaml /
# 05-monitoring.yaml uses). The previous class `[A-Za-z0-9_.-]+` could not match
# a value beginning with `!`/`$`/`{`, so EVERY !Sub-named rule extracted no name
# and declared_count collapsed to 0 — the gh#635 false positive. We now capture
# the optional `!Sub`, optional quotes, and the `${...}` substitution markers.
_RULE_NAME_RE = re.compile(
    r"(?:Name|RuleName):\s*(?:!Sub\s+)?['\"]?(?P<name>[A-Za-z0-9_.${}-]+)['\"]?"
)

# CLI-only EventBridge rules: live and serving a real feature, but declared in
# NEITHER branch's CFN templates (genuine out-of-band orphans, confirmed via
# ENC-TSK-J07 grep of main + v4/main). Environment scoping (_in_environment)
# already keeps gamma-managed rules from showing as prod drift, so the ONLY rule
# that still needs an explicit exception is enceladus-checkout-auto — the
# ENC-FTR-037 auto-checkout companion, created out-of-band alongside
# enceladus-checkout-service-auto and never codified.
#
# Durable fix is a CloudFormation change-set IMPORT (the rule already exists, so
# a plain stack update plans it as an Add and AWS::EarlyValidation::ResourceExistenceCheck
# rejects the whole change set — the ENC-ISS-386 / ENC-TSK-H29 wedge). Import is a
# privileged manual op tracked under ENC-ISS-455; until then this documented
# exception keeps the daily audit from re-raising gh#635 noise. Stored as an
# env-suffix-stripped BASE name (see _strip_env_suffix). Verified live + ENABLED
# via `aws events describe-rule` on 2026-06-30.
_EVENTBRIDGE_CLI_EXCEPTION_BASES = {
    "enceladus-checkout-auto",  # ENC-FTR-037 auto-checkout companion, rate(5 minutes)
}


def _strip_env_suffix(name: str) -> str:
    """Collapse an environment-suffixed rule name to its base.

    CFN declares rules once via `!Sub "<base>${EnvironmentSuffix}"`; that single
    declaration materializes as `<base>` in prod and `<base>-gamma` in gamma.
    `aws events list-rules --name-prefix enceladus-` returns BOTH live variants.
    Comparing on the stripped base makes one declaration cover both environments.
    """
    for suffix in _ENV_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _resolve_declared_name(raw: str) -> str | None:
    """Resolve a declared rule name to its base, or None if unresolvable.

    `${EnvironmentSuffix}` resolves to '' (the prod/base name). Any rule whose
    name carries a different, non-resolvable `${...}` substitution is skipped
    rather than guessed at.
    """
    base = re.sub(r"\$\{EnvironmentSuffix\}", "", raw).strip().strip("'\"")
    if "${" in base:
        return None
    return _strip_env_suffix(base)


def declared_eventbridge_rules(cfn_glob: str, name_prefix: str, environment: str = "prod") -> Set[str]:
    """CFN-declared EventBridge rule BASE names, scoped to ``name_prefix`` and
    filtered to whatever is actually declared for ``environment`` (ENC-TSK-J12;
    see _condition_declared_for_environment — e.g. StandingProjectionRefreshSchedule
    is Condition: IsProduction and must not appear as cfn_only drift on gamma).

    Scoping to the same prefix the live query uses keeps the comparison
    apples-to-apples: without it, fixing the !Sub bug would surface every
    out-of-prefix declared rule (devops-*, on-project-json-sync) as phantom
    ``cfn_only`` drift.
    """
    bases: Set[str] = set()
    for path in sorted(glob.glob(cfn_glob)):
        text = Path(path).read_text()
        for _name, rtype, condition, body in _iter_resources(text):
            if rtype != "AWS::Events::Rule":
                continue
            if not _condition_declared_for_environment(condition, environment):
                continue
            m = _RULE_NAME_RE.search(body)
            if not m:
                continue
            base = _resolve_declared_name(m.group("name"))
            if base and base.startswith(name_prefix):
                bases.add(base)
    return bases


def audit(
    api_id: str,
    cfn_glob: str,
    event_rule_prefix: str,
    environment: str = "prod",
) -> Dict[str, Dict[str, List[str]]]:
    declared_rt = declared_routes(cfn_glob, environment)
    live_rt = live_apigw_routes(api_id)

    # ENC-TSK-J08: EventBridge comparison is done on environment-suffix-stripped
    # base names (see _strip_env_suffix), with the live set scoped to the audited
    # environment (see _in_environment) so gamma rules are not compared against
    # prod (main) templates. declared_ev_bases is prefix-scoped to match the live
    # query; the documented CLI-only exception is removed from the live side so
    # the daily audit does not re-raise gh#635. ENC-TSK-J12: both declared_rt and
    # declared_ev_bases are also Condition-scoped to `environment` so IsGamma/
    # IsProduction-gated resources only count as declared where they actually
    # deploy.
    declared_ev_bases = declared_eventbridge_rules(cfn_glob, event_rule_prefix, environment)
    live_ev = live_eventbridge_rules(event_rule_prefix, environment)
    live_ev_bases = {_strip_env_suffix(n) for n in live_ev}
    exceptions = sorted(
        n for n in live_ev
        if _strip_env_suffix(n) in _EVENTBRIDGE_CLI_EXCEPTION_BASES
    )
    live_only = sorted(
        n for n in live_ev
        if _strip_env_suffix(n) not in declared_ev_bases
        and _strip_env_suffix(n) not in _EVENTBRIDGE_CLI_EXCEPTION_BASES
    )
    cfn_only = sorted(b for b in declared_ev_bases if b not in live_ev_bases)
    return {
        "apigw_routes": {
            "live_count": len(live_rt),
            "declared_count": len(declared_rt),
            "live_only": sorted(live_rt - declared_rt),
            "cfn_only": sorted(declared_rt - live_rt),
        },
        "eventbridge_rules": {
            "live_count": len(live_ev),
            "declared_count": len(declared_ev_bases),
            "live_only": live_only,
            "cfn_only": cfn_only,
            "documented_exceptions": exceptions,
        },
    }


def _self_check() -> bool:
    """Offline sanity check of the Condition-aware parsing logic.

    ENC-TSK-J12: no AWS calls, no real CFN templates — writes synthetic
    templates to a temp dir and asserts declared_routes/declared_eventbridge_rules
    scope IsGamma/IsProduction resources to the right --environment. Intended
    as a fast pre-flight (e.g. inside tools/pre-deploy-health-gate.sh) that
    catches a broken parser before spending an AWS round-trip on the live
    --fail-on-drift check.
    """
    import tempfile

    failures: List[str] = []

    def check(label: str, condition: bool) -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {label}")
        if not condition:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        template = Path(tmp) / "self-check.yaml"
        template.write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\n"
            "Resources:\n"
            "  RouteAlways:\n"
            "    Type: AWS::ApiGatewayV2::Route\n"
            "    Properties:\n"
            "      RouteKey: GET /always\n"
            "  RouteGammaOnly:\n"
            "    Type: AWS::ApiGatewayV2::Route\n"
            "    Condition: IsGamma\n"
            "    Properties:\n"
            "      RouteKey: GET /gamma-only\n"
            "  RuleProdOnly:\n"
            "    Type: AWS::Events::Rule\n"
            "    Condition: IsProduction\n"
            "    Properties:\n"
            "      Name: !Sub \"enceladus-prod-only${EnvironmentSuffix}\"\n"
        )
        glob_pattern = str(Path(tmp) / "*.yaml")

        prod_routes = declared_routes(glob_pattern, "prod")
        gamma_routes = declared_routes(glob_pattern, "gamma")
        check(
            "IsGamma route excluded from prod-declared set",
            "GET /gamma-only" not in prod_routes and "GET /always" in prod_routes,
        )
        check(
            "IsGamma route included in gamma-declared set",
            "GET /gamma-only" in gamma_routes and "GET /always" in gamma_routes,
        )

        prod_rules = declared_eventbridge_rules(glob_pattern, "enceladus-", "prod")
        gamma_rules = declared_eventbridge_rules(glob_pattern, "enceladus-", "gamma")
        check(
            "IsProduction rule included in prod-declared set",
            "enceladus-prod-only" in prod_rules,
        )
        check(
            "IsProduction rule excluded from gamma-declared set",
            "enceladus-prod-only" not in gamma_rules,
        )

    print(f"[{'PASS' if not failures else 'FAIL'}] self-check: {len(failures)} failure(s)")
    return not failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--self-check",
        action="store_true",
        help="Run an offline sanity check of the Condition-aware parser (no AWS calls) and exit.",
    )
    ap.add_argument("--api-id", default=None)
    ap.add_argument("--stack-prefix", default="enceladus-")
    ap.add_argument(
        "--cfn-glob",
        default="infrastructure/cloudformation/*.yaml",
    )
    ap.add_argument(
        "--event-rule-prefix",
        default="enceladus-",
    )
    ap.add_argument(
        "--environment",
        default="prod",
        choices=("prod", "gamma"),
        help=(
            "Which environment's live EventBridge rules to audit against the "
            "checked-out branch's templates. Default 'prod' (main). Use 'gamma' "
            "when auditing on v4/main. See _in_environment (ENC-TSK-J08)."
        ),
    )
    ap.add_argument("--output-json", default=None)
    ap.add_argument("--fail-on-drift", action="store_true")
    args = ap.parse_args()

    if args.self_check:
        return 0 if _self_check() else 1

    api_id = args.api_id or resolve_api_id(args.stack_prefix, args.environment)

    report = audit(api_id, args.cfn_glob, args.event_rule_prefix, args.environment)
    report["_api_id"] = api_id
    report["_cfn_glob"] = args.cfn_glob
    report["_environment"] = args.environment

    payload = json.dumps(report, indent=2, sort_keys=True)
    print(payload)

    if args.output_json:
        Path(args.output_json).write_text(payload)

    any_drift = any(
        report[section]["live_only"] or report[section]["cfn_only"]
        for section in ("apigw_routes", "eventbridge_rules")
    )
    if args.fail_on_drift and any_drift:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
