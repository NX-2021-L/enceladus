#!/usr/bin/env python3
"""ENC-TSK-R31 (C2.7 / BRD FR-34): persistent-cost CI guard.

Diffs the CloudFormation templates under infrastructure/ between a PR's merge
base and its head, and FAILS when the PR ADDS a resource that bills while idle
(a "persistent cost" resource) -- unless the PR carries the `cost-approved`
label (workflow passes --cost-approved). Cost class C1 guard; see agents.md
cost rule-block v1.

A resource counts as ADDED when its logical id is present in the head template
but absent from the SAME file at the merge base (a brand-new template file
adds every resource in it). Moving a resource between template files therefore
reads as an add and needs the label; adopting already-billed live resources via
the import lane is the same cost decision and is cheap to label.

Flagged additions (one finding line each):

  AWS::SecretsManager::Secret          AWS::KMS::Key
  AWS::EC2::NatGateway                 AWS::EC2::Instance
  AWS::EC2::EIP                        AWS::CloudWatch::Alarm
  AWS::DynamoDB::Table
  AWS::EC2::VPCEndpoint                VpcEndpointType: Interface
  AWS::Events::Rule / Scheduler::Schedule   ScheduleExpression faster than daily
  AWS::S3::Bucket                      versioning Enabled, no NoncurrentVersionExpiration
  AWS::Logs::LogGroup                  no RetentionInDays
  AWS::ECR::Repository                 no LifecyclePolicy
  AWS::Lambda::Function                TracingConfig Mode Active when evaluated for
                                       gamma (literal Active, or Fn::If whose gamma
                                       branch is Active)

Usage:
  cost_resource_guard.py --base <sha> --head <sha> [--cost-approved]
  cost_resource_guard.py --base-file old.yaml --head-file new.yaml
Environment: COST_APPROVED=true is equivalent to --cost-approved.

Exit 0 = no unapproved findings. Exit 1 = findings and no approval.
Exit 2 = the guard could not run (bad usage, git failure, missing PyYAML).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

try:
    import yaml  # noqa: F401
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required (pip install pyyaml)")
    sys.exit(2)

try:  # reuse the CFN short-form-tag loader (!Ref / !If / !Sub / !GetAtt -> Fn:: dicts)
    from cfn_deploy_role_reach_guard import CfnLoader  # type: ignore
except ImportError:  # imported as tools.cost_resource_guard
    from tools.cfn_deploy_role_reach_guard import CfnLoader  # type: ignore

APPROVAL_LABEL = "cost-approved"
TEMPLATE_ROOT = "infrastructure"
TEMPLATE_SUFFIXES = (".yaml", ".yml", ".json", ".template")

# Condition names whose truth value under a gamma deploy is known.
GAMMA_CONDITIONS = {"IsGamma": True, "IsNotGamma": False}

Finding = Tuple[str, str, str, str]  # (file, logical_id, resource_type, reason)


# --------------------------------------------------------------------------
# Template loading
# --------------------------------------------------------------------------
def load_template_text(text: str) -> dict:
    """Parse CFN YAML (with short-form tags) or JSON; {} when not a template."""
    doc = yaml.load(text, Loader=CfnLoader)  # JSON is a YAML subset
    if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
        return {}
    return doc


def _resources(template: dict) -> dict:
    res = template.get("Resources") if isinstance(template, dict) else None
    return res if isinstance(res, dict) else {}


# --------------------------------------------------------------------------
# Intrinsic helpers
# --------------------------------------------------------------------------
def _props(resource: Any) -> dict:
    p = resource.get("Properties") if isinstance(resource, dict) else None
    return p if isinstance(p, dict) else {}


def _candidates(value: Any, template: dict, gamma: bool = False) -> List[Any]:
    """Possible concrete values of a property. Ref -> parameter Default;
    Fn::If -> both branches (or the gamma branch when gamma=True and the
    condition is a known gamma switch). Unresolvable -> []."""
    if isinstance(value, dict) and len(value) == 1:
        (key, arg), = value.items()
        if key == "Ref":
            params = template.get("Parameters")
            p = params.get(arg) if isinstance(params, dict) else None
            if isinstance(p, dict) and "Default" in p:
                return [p["Default"]]
            return []
        if key == "Fn::If" and isinstance(arg, list) and len(arg) == 3:
            cond, a, b = arg
            if gamma and cond in GAMMA_CONDITIONS:
                return _candidates(a if GAMMA_CONDITIONS[cond] else b, template, gamma)
            return _candidates(a, template, gamma) + _candidates(b, template, gamma)
        if key == "Fn::Sub" and isinstance(arg, str) and "${" not in arg:
            return [arg]
        return []  # other intrinsics (GetAtt, Join, ...) are not statically resolvable
    if isinstance(value, dict) and value.get("Ref") == "AWS::NoValue":
        return []
    return [value]


def _contains_key(node: Any, names: Iterable[str]) -> bool:
    names = tuple(names)
    if isinstance(node, dict):
        return any(k in names or _contains_key(v, names) for k, v in node.items())
    if isinstance(node, list):
        return any(_contains_key(v, names) for v in node)
    return False


def _truthy_present(value: Any) -> bool:
    """A property counts as set when present and not AWS::NoValue/None."""
    if value is None:
        return False
    if isinstance(value, dict) and value.get("Ref") == "AWS::NoValue":
        return False
    return True


# --------------------------------------------------------------------------
# Schedule parsing
# --------------------------------------------------------------------------
_RATE = re.compile(r"^rate\(\s*(\d+)\s+(minutes?|hours?|days?)\s*\)$", re.I)
_CRON = re.compile(r"^cron\((.*)\)$", re.I)


def _expand(field: str, lo: int, hi: int) -> Optional[set]:
    out: set = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            if not step_s.isdigit() or int(step_s) < 1:
                return None
            step = int(step_s)
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return None
            start, end = int(a), int(b)
        elif part.isdigit():
            start = int(part)
            end = hi if step != 1 else start
        else:
            return None
        out.update(range(start, end + 1, step))
    return out


def schedule_faster_than_daily(expr: Any) -> Optional[bool]:
    """True/False for a rate()/cron()/at() expression; None when unparseable."""
    if not isinstance(expr, str):
        return None
    expr = expr.strip()
    if expr.lower().startswith("at("):
        return False
    m = _RATE.match(expr)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        if unit.startswith("minute"):
            return n < 1440
        if unit.startswith("hour"):
            return n < 24
        return False
    m = _CRON.match(expr)
    if m:
        fields = m.group(1).split()
        if len(fields) != 6:
            return None
        mins = _expand(fields[0], 0, 59)
        hours = _expand(fields[1], 0, 23)
        if not mins or not hours:
            return None
        return len(mins) * len(hours) > 1
    return None


# --------------------------------------------------------------------------
# Rules: each returns a reason string (flag) or None
# --------------------------------------------------------------------------
def _rule_always(reason: str):
    return lambda res, tpl: reason


def _rule_vpc_endpoint(res: dict, tpl: dict) -> Optional[str]:
    kinds = _candidates(_props(res).get("VpcEndpointType"), tpl)
    if any(str(k).lower() == "interface" for k in kinds):
        return "Interface VPC endpoint bills hourly per AZ"
    return None


def _rule_schedule(res: dict, tpl: dict) -> Optional[str]:
    expr = _props(res).get("ScheduleExpression")
    if expr is None:
        return None
    verdicts = [schedule_faster_than_daily(c) for c in _candidates(expr, tpl)]
    if any(v for v in verdicts):
        return "ScheduleExpression fires faster than daily"
    return None


def _rule_s3(res: dict, tpl: dict) -> Optional[str]:
    props = _props(res)
    versioning = props.get("VersioningConfiguration")
    statuses = []
    if isinstance(versioning, dict):
        if "Fn::If" in versioning:
            statuses = [c for c in _flatten_if(versioning, "Status")]
        else:
            statuses = _candidates(versioning.get("Status"), tpl)
    if not any(str(s).lower() == "enabled" for s in statuses):
        return None
    lifecycle = props.get("LifecycleConfiguration")
    if _contains_key(lifecycle, ("NoncurrentVersionExpiration", "NoncurrentVersionExpirationInDays")):
        return None
    return "versioned bucket has no NoncurrentVersionExpiration lifecycle rule"


def _flatten_if(node: Any, key: str) -> List[Any]:
    """Collect `key` values across the branches of an Fn::If-wrapped mapping."""
    if isinstance(node, dict):
        if "Fn::If" in node and isinstance(node["Fn::If"], list) and len(node["Fn::If"]) == 3:
            return _flatten_if(node["Fn::If"][1], key) + _flatten_if(node["Fn::If"][2], key)
        v = node.get(key)
        return [v] if v is not None else []
    return []


def _rule_log_group(res: dict, tpl: dict) -> Optional[str]:
    if _truthy_present(_props(res).get("RetentionInDays")):
        return None
    return "log group has no RetentionInDays (retains forever)"


def _rule_ecr(res: dict, tpl: dict) -> Optional[str]:
    if _truthy_present(_props(res).get("LifecyclePolicy")):
        return None
    return "ECR repository has no LifecyclePolicy (images accumulate)"


def _rule_tracing(res: dict, tpl: dict) -> Optional[str]:
    props = _props(res)
    tracing = props.get("TracingConfig")
    modes: List[Any] = []
    if isinstance(tracing, dict):
        modes = _gamma_modes_from_if(tracing, tpl)
    # AWS::Serverless::Function uses Tracing: Active
    modes += _candidates(props.get("Tracing"), tpl, gamma=True)
    if any(str(m).lower() == "active" for m in modes):
        return "TracingConfig Mode Active on a gamma function (use PassThrough on gamma)"
    return None


def _gamma_modes_from_if(node: Any, tpl: dict) -> List[Any]:
    """TracingConfig Mode values as seen by a gamma deploy (known switch -> one
    branch; unknown condition -> either branch, conservatively)."""
    if isinstance(node, dict) and "Fn::If" in node:
        cond, a, b = node["Fn::If"]
        if cond in GAMMA_CONDITIONS:
            return _gamma_modes_from_if(a if GAMMA_CONDITIONS[cond] else b, tpl)
        return _gamma_modes_from_if(a, tpl) + _gamma_modes_from_if(b, tpl)
    if isinstance(node, dict):
        return _candidates(node.get("Mode"), tpl, gamma=True)
    return []


RULES = {
    "AWS::SecretsManager::Secret": _rule_always("Secrets Manager secret bills monthly per secret"),
    "AWS::KMS::Key": _rule_always("KMS key bills monthly per key"),
    "AWS::EC2::NatGateway": _rule_always("NAT gateway bills hourly plus per GB"),
    "AWS::EC2::VPCEndpoint": _rule_vpc_endpoint,
    "AWS::EC2::Instance": _rule_always("EC2 instance bills while running"),
    "AWS::EC2::EIP": _rule_always("Elastic IP bills hourly"),
    "AWS::CloudWatch::Alarm": _rule_always("CloudWatch alarm bills monthly per alarm"),
    "AWS::Events::Rule": _rule_schedule,
    "AWS::Scheduler::Schedule": _rule_schedule,
    "AWS::DynamoDB::Table": _rule_always("DynamoDB table (storage/capacity/PITR bill while idle)"),
    "AWS::S3::Bucket": _rule_s3,
    "AWS::Logs::LogGroup": _rule_log_group,
    "AWS::ECR::Repository": _rule_ecr,
    "AWS::Lambda::Function": _rule_tracing,
    "AWS::Serverless::Function": _rule_tracing,
}


# --------------------------------------------------------------------------
# Diff + evaluation
# --------------------------------------------------------------------------
def evaluate_resource(logical_id: str, resource: Any, template: dict) -> Optional[str]:
    if not isinstance(resource, dict):
        return None
    rule = RULES.get(resource.get("Type"))
    return rule(resource, template) if rule else None


def find_findings(base_tpl: dict, head_tpl: dict, file: str = "<template>") -> List[Finding]:
    """Findings for resources ADDED in head_tpl relative to base_tpl."""
    base_ids = set(_resources(base_tpl))
    out: List[Finding] = []
    for logical_id, resource in _resources(head_tpl).items():
        if logical_id in base_ids:
            continue
        reason = evaluate_resource(logical_id, resource, head_tpl)
        if reason:
            out.append((file, logical_id, str(resource.get("Type")), reason))
    return out


def _git(args: List[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def _git_show(rev: str, path: str, cwd: str) -> Optional[str]:
    proc = _git(["show", f"{rev}:{path}"], cwd)
    return proc.stdout if proc.returncode == 0 else None


def diff_git(base: str, head: str, repo_root: str = ".") -> Tuple[List[Finding], List[str]]:
    """Findings + warnings for templates changed between base and head."""
    mb = _git(["merge-base", base, head], repo_root)
    merge_base = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else base
    names = _git(["diff", "--name-only", "--diff-filter=ACMR", merge_base, head, "--", TEMPLATE_ROOT], repo_root)
    if names.returncode != 0:
        raise RuntimeError(f"git diff failed: {names.stderr.strip()}")
    findings: List[Finding] = []
    warnings: List[str] = []
    for path in sorted(p for p in names.stdout.splitlines() if p.endswith(TEMPLATE_SUFFIXES)):
        head_text = _git_show(head, path, repo_root)
        if head_text is None:
            continue
        try:
            head_tpl = load_template_text(head_text)
        except yaml.YAMLError as exc:
            warnings.append(f"{path}: head template unparseable ({type(exc).__name__}); skipped")
            continue
        if not head_tpl:
            continue  # not a CloudFormation template (import map, manifest, ...)
        base_text = _git_show(merge_base, path, repo_root)
        try:
            base_tpl = load_template_text(base_text) if base_text else {}
        except yaml.YAMLError:
            base_tpl = {}
        findings.extend(find_findings(base_tpl, head_tpl, path))
    return findings, warnings


def format_finding(f: Finding, annotate: bool = False, approved: bool = False) -> str:
    """One line per finding; GitHub annotation form when annotate=True."""
    file, logical_id, rtype, reason = f
    tag = "APPROVED" if approved else "FAIL"
    body = f"{logical_id} ({rtype}): {reason}"
    if annotate:
        level = "notice" if approved else "error"
        return f"::{level} file={file},title=cost-resource-guard::{tag} {body}"
    return f"{tag} {file}: {body}"


def run(findings: List[Finding], approved: bool, annotate: bool = False, out=None) -> int:
    out = out or sys.stdout
    for f in findings:
        print(format_finding(f, annotate, approved), file=out)
    if not findings:
        print("cost-resource-guard: no persistent-cost resources added", file=out)
        return 0
    if approved:
        print(f"cost-resource-guard: {len(findings)} finding(s) accepted via '{APPROVAL_LABEL}' label", file=out)
        return 0
    print(f"cost-resource-guard: {len(findings)} unapproved persistent-cost addition(s); "
          f"add the '{APPROVAL_LABEL}' label to accept", file=out)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", help="PR base commit (merge base is computed)")
    ap.add_argument("--head", help="PR head commit")
    ap.add_argument("--base-file", help="old template file (single-pair mode)")
    ap.add_argument("--head-file", help="new template file (single-pair mode)")
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--cost-approved", action="store_true",
                    help=f"PR carries the '{APPROVAL_LABEL}' label (also env COST_APPROVED=true)")
    args = ap.parse_args(argv)
    approved = args.cost_approved or os.environ.get("COST_APPROVED", "").strip().lower() == "true"
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    try:
        if args.head_file:
            base_tpl = load_template_text(Path(args.base_file).read_text()) if args.base_file else {}
            head_tpl = load_template_text(Path(args.head_file).read_text())
            findings, warnings = find_findings(base_tpl, head_tpl, args.head_file), []
        elif args.base and args.head:
            findings, warnings = diff_git(args.base, args.head, args.repo_root)
        else:
            ap.error("provide --base and --head, or --head-file")
            return 2
    except (OSError, RuntimeError, yaml.YAMLError) as exc:
        print(f"::error::cost-resource-guard could not run: {exc}")
        return 2
    for w in warnings:
        print(f"WARN {w}")
    return run(findings, approved, annotate)


if __name__ == "__main__":
    sys.exit(main())
