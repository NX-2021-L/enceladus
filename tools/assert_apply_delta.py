#!/usr/bin/env python3
"""Assert what a CloudFormation apply would ADD and REMOVE, before it runs.

ENC-TSK-O61 / ENC-ISS-652.

WHY THIS EXISTS
---------------
Nothing in the pre-deploy gate compared the INCOMING TEMPLATE against the TARGET
STACK's current resource set. ``audit_cfn_drift.py`` answers a different question
-- live AWS service state versus repo template files -- and passed cleanly on the
exact ref whose apply would have removed nine live prod-stack resources
(ENC-ISS-648) and attempted 52 CREATEs including three live-name collisions
(ENC-ISS-651). Both were found by hand.

This tool asks the missing question directly:

    would_remove = stack_logical_ids  -  template_logical_ids(conditions evaluated)
    would_create = template_logical_ids(conditions evaluated)  -  stack_logical_ids

and then, for every would_create, checks whether its resolved PHYSICAL name already
exists live -- because CloudFormation fails a CREATE whose name is taken, and a
single CREATE_FAILED rolls back the entire change-set.

TWO DEFECTS IN audit_cfn_drift.py THAT ARE DELIBERATELY NOT INHERITED
--------------------------------------------------------------------
1. SCOPE. Its ``audit()`` returns only ``apigw_routes`` and ``eventbridge_rules``.
   This tool considers every top-level resource in the template.
2. DIRECTIONALITY. Its ``any_drift`` is computed from ``live_only`` alone, so
   ``cfn_only`` can never fail ``--fail-on-drift``. This tool fails in BOTH
   directions, because a REMOVE and a CREATE-collision are the two directions that
   matter for an in-place update.

A DENIED READ IS NOT A CLEAN RESULT
-----------------------------------
The collision census that produced ENC-ISS-651 first returned "clear" for all 29
candidate names -- because the lookup lists were empty and every comparison was
vacuous. Only a positive control exposed three real collisions. So this tool:

  * runs a POSITIVE CONTROL per AWS API it uses, against a name taken from the
    target stack's own live resources, and
  * reports INDETERMINATE (exit 2) rather than PASS when a control fails or a
    lookup is denied.

Exit codes, matching audit_cfn_drift.py's convention:
  0  no destructive removes, no create collisions
  1  FAIL -- a resource would be destroyed, or a CREATE would collide
  2  INDETERMINATE -- a live read was denied or a control failed; NOT a pass
  3  usage / parse error
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation's ``!Ref`` / ``!Sub`` short tags."""


def _multi_constructor(loader: yaml.Loader, suffix: str, node: yaml.Node) -> Dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{suffix}": loader.construct_sequence(node, deep=True)}
    return {f"Fn::{suffix}": loader.construct_mapping(node, deep=True)}


_CfnLoader.add_multi_constructor("!", _multi_constructor)

# Resource types whose physical name we can resolve AND look up live.
# Anything absent here is reported as name-unresolvable rather than assumed clear.
_NAME_PROPERTY = {
    "AWS::Lambda::Function": "FunctionName",
    "AWS::IAM::Role": "RoleName",
    "AWS::Events::Rule": "Name",
    "AWS::Pipes::Pipe": "Name",
    "AWS::CloudWatch::Alarm": "AlarmName",
    "AWS::SecretsManager::Secret": "Name",
    "AWS::SQS::Queue": "QueueName",
    "AWS::DynamoDB::Table": "TableName",
    "AWS::SNS::Topic": "TopicName",
}


def _aws(args: List[str], region: str) -> Tuple[int, str, str]:
    proc = subprocess.run(
        ["aws", "--region", region, *args],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _is_denied(stderr: str) -> bool:
    low = stderr.lower()
    return (
        "accessdenied" in low
        or "not authorized" in low
        or "explicit deny" in low
        or "unrecognizedclient" in low
    )


# --- condition evaluation --------------------------------------------------


def _resolve_params(template: Dict[str, Any], overrides: Dict[str, str]) -> Dict[str, str]:
    params: Dict[str, str] = {}
    for name, spec in (template.get("Parameters") or {}).items():
        if isinstance(spec, dict) and "Default" in spec:
            params[name] = str(spec["Default"])
    params.update(overrides)
    return params


def _eval_expr(expr: Any, params: Dict[str, str], conditions: Dict[str, Any],
               seen: Set[str]) -> Optional[bool]:
    """Evaluate a CFN condition expression. None means indeterminate."""
    if isinstance(expr, bool):
        return expr
    if not isinstance(expr, dict):
        return None

    if "Fn::Equals" in expr:
        operands = expr["Fn::Equals"]
        if not isinstance(operands, list) or len(operands) != 2:
            return None
        left = _eval_value(operands[0], params)
        right = _eval_value(operands[1], params)
        if left is None or right is None:
            return None
        return left == right

    if "Fn::Not" in expr:
        operands = expr["Fn::Not"]
        if not isinstance(operands, list) or len(operands) != 1:
            return None
        inner = _eval_expr(operands[0], params, conditions, seen)
        return None if inner is None else (not inner)

    if "Fn::And" in expr:
        results = [_eval_expr(o, params, conditions, seen) for o in expr["Fn::And"]]
        if any(r is False for r in results):
            return False
        return None if any(r is None for r in results) else True

    if "Fn::Or" in expr:
        results = [_eval_expr(o, params, conditions, seen) for o in expr["Fn::Or"]]
        if any(r is True for r in results):
            return True
        return None if any(r is None for r in results) else False

    if "Condition" in expr and isinstance(expr["Condition"], str):
        return _eval_condition(expr["Condition"], params, conditions, seen)

    return None


def _eval_value(value: Any, params: Dict[str, str]) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict) and "Fn::Ref" in value:
        ref = value["Fn::Ref"]
        return params.get(ref) if isinstance(ref, str) else None
    if isinstance(value, dict) and "Ref" in value:
        ref = value["Ref"]
        return params.get(ref) if isinstance(ref, str) else None
    return None


def _eval_condition(name: str, params: Dict[str, str], conditions: Dict[str, Any],
                    seen: Optional[Set[str]] = None) -> Optional[bool]:
    seen = seen or set()
    if name in seen:            # cyclic definition -- refuse rather than loop
        return None
    seen = seen | {name}
    if name not in conditions:
        return None
    return _eval_expr(conditions[name], params, conditions, seen)


# --- template parsing ------------------------------------------------------


def _sub_physical_name(raw: Any, params: Dict[str, str]) -> Optional[str]:
    """Resolve a name property to a literal, or None if it cannot be resolved."""
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, dict):
        return None
    if "Fn::Sub" in raw:
        tmpl = raw["Fn::Sub"]
        if not isinstance(tmpl, str):
            return None
        out = tmpl
        for key, val in params.items():
            out = out.replace("${" + key + "}", val)
        if "${" in out:         # an unresolved placeholder remains
            return None
        return out
    return None


def parse_template(path: str, overrides: Dict[str, str]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as handle:
        doc = yaml.load(handle, Loader=_CfnLoader)
    if not isinstance(doc, dict) or "Resources" not in doc:
        raise ValueError(f"{path} has no Resources block")
    params = _resolve_params(doc, overrides)
    conditions = doc.get("Conditions") or {}

    resources: Dict[str, Any] = {}
    for logical_id, body in doc["Resources"].items():
        if not isinstance(body, dict):
            continue
        cond_name = body.get("Condition")
        included: Optional[bool] = True
        if isinstance(cond_name, str):
            included = _eval_condition(cond_name, params, conditions)
        rtype = body.get("Type")
        props = body.get("Properties") or {}
        name_prop = _NAME_PROPERTY.get(rtype) if isinstance(rtype, str) else None
        physical = _sub_physical_name(props.get(name_prop), params) if name_prop else None
        resources[logical_id] = {
            "type": rtype,
            "condition": cond_name,
            "included": included,
            "deletion_policy": body.get("DeletionPolicy"),
            "physical_name": physical,
        }
    return resources, params


# --- live lookups ----------------------------------------------------------


def stack_resources(stack: str, region: str) -> Tuple[Optional[Dict[str, str]], str]:
    code, out, err = _aws(
        ["cloudformation", "list-stack-resources", "--stack-name", stack, "--output", "json"],
        region,
    )
    if code != 0:
        return None, err.strip()
    payload = json.loads(out)
    return (
        {
            r["LogicalResourceId"]: r.get("PhysicalResourceId", "")
            for r in payload.get("StackResourceSummaries", [])
        },
        "",
    )


def _exists(rtype: str, name: str, region: str) -> Tuple[Optional[bool], str]:
    """True/False if determinable; None if the read was denied or unsupported."""
    probes = {
        "AWS::Lambda::Function": ["lambda", "get-function", "--function-name", name],
        "AWS::IAM::Role": ["iam", "get-role", "--role-name", name],
        "AWS::Events::Rule": ["events", "describe-rule", "--name", name],
        "AWS::Pipes::Pipe": ["pipes", "describe-pipe", "--name", name],
        "AWS::SecretsManager::Secret": ["secretsmanager", "describe-secret", "--secret-id", name],
        "AWS::SQS::Queue": ["sqs", "get-queue-url", "--queue-name", name],
        "AWS::DynamoDB::Table": ["dynamodb", "describe-table", "--table-name", name],
    }
    if rtype == "AWS::CloudWatch::Alarm":
        code, out, err = _aws(
            ["cloudwatch", "describe-alarms", "--alarm-names", name, "--output", "json"], region
        )
        if code != 0:
            return (None, err.strip()) if _is_denied(err) else (None, err.strip())
        payload = json.loads(out)
        return bool(payload.get("MetricAlarms") or payload.get("CompositeAlarms")), ""
    if rtype not in probes:
        return None, "unsupported-type"
    code, _out, err = _aws([*probes[rtype], "--output", "json"], region)
    if code == 0:
        return True, ""
    if _is_denied(err):
        return None, "denied"
    low = err.lower()
    if "notfound" in low or "nosuchentity" in low or "does not exist" in low \
            or "resourcenotfound" in low or "cannot be found" in low:
        return False, ""
    return None, err.strip()[:200]


def run_controls(live_stack: Dict[str, str], resources: Dict[str, Any],
                 region: str) -> Tuple[Dict[str, str], List[str]]:
    """Positive control per API actually used: a name known to exist must be found.

    Without this a denied or malformed lookup returns 'absent' for every candidate
    and the whole census reads as a clean pass. That exact false negative is what
    ENC-ISS-651 records.
    """
    needed: Set[str] = set()
    for meta in resources.values():
        if meta.get("_probe_needed"):
            needed.add(meta["type"])

    results: Dict[str, str] = {}
    failures: List[str] = []
    for rtype in sorted(needed):
        # Find a live, stack-managed resource of this type to use as the control.
        control_name = None
        for logical_id, physical in live_stack.items():
            meta = resources.get(logical_id)
            if meta and meta.get("type") == rtype and physical and "/" not in physical:
                control_name = physical
                break
        if control_name is None:
            results[rtype] = "no-control-available"
            continue
        found, detail = _exists(rtype, control_name, region)
        if found is True:
            results[rtype] = f"ok ({control_name})"
        elif found is None:
            results[rtype] = f"INDETERMINATE ({control_name}: {detail})"
            failures.append(rtype)
        else:
            results[rtype] = f"FAILED ({control_name} reported absent but is stack-managed)"
            failures.append(rtype)
    return results, failures


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Assert what a CloudFormation apply would ADD and REMOVE."
    )
    ap.add_argument("--stack", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("--region", default="us-west-2")
    # NOTE: singular --parameter, repeatable. cfn_env_resolver.py uses the same
    # convention; a plural --parameters abbreviation-binds to --parameters-file
    # and dies (ENC-TSK-O43).
    ap.add_argument("--parameter", action="append", default=[], metavar="Key=Value")
    ap.add_argument("--output-json")
    ap.add_argument("--fail-on-delta", action="store_true")
    args = ap.parse_args(argv)

    overrides: Dict[str, str] = {}
    for item in args.parameter:
        if "=" not in item:
            print(f"[ERROR] --parameter expects Key=Value, got: {item}", file=sys.stderr)
            return 3
        key, _, value = item.partition("=")
        overrides[key] = value

    try:
        resources, params = parse_template(args.template, overrides)
    except Exception as exc:                       # noqa: BLE001 - surface any parse failure
        print(f"[ERROR] template parse failed: {exc}", file=sys.stderr)
        return 3

    live_stack, err = stack_resources(args.stack, args.region)
    if live_stack is None:
        print(f"[INDETERMINATE] could not read stack {args.stack}: {err}", file=sys.stderr)
        return 2

    included = {k for k, v in resources.items() if v["included"] is True}
    indeterminate_cond = sorted(k for k, v in resources.items() if v["included"] is None)

    would_remove = sorted(set(live_stack) - included)
    would_create = sorted(included - set(live_stack))

    # Mark which would_create entries need a live probe, so controls cover exactly
    # the APIs actually used.
    for logical_id in would_create:
        meta = resources[logical_id]
        if meta["physical_name"] and meta["type"] in _NAME_PROPERTY:
            meta["_probe_needed"] = True

    controls, control_failures = run_controls(live_stack, resources, args.region)

    destructive: List[Dict[str, Any]] = []
    orphaning: List[Dict[str, Any]] = []
    for logical_id in would_remove:
        meta = resources.get(logical_id, {})
        policy = meta.get("deletion_policy")
        row = {
            "logical_id": logical_id,
            "physical_id": live_stack.get(logical_id, ""),
            "deletion_policy": policy,
        }
        # A resource absent from the incoming template is removed. With
        # DeletionPolicy: Retain CloudFormation stops managing it but does NOT
        # delete it -- bad (permutation 2, DOC-AB51FA4D9232) but not destructive.
        (orphaning if policy == "Retain" else destructive).append(row)

    collisions: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    for logical_id in would_create:
        meta = resources[logical_id]
        name = meta["physical_name"]
        if not name or meta["type"] not in _NAME_PROPERTY:
            unresolved.append({"logical_id": logical_id, "type": meta["type"],
                               "reason": "physical name not resolvable from template"})
            continue
        exists, detail = _exists(meta["type"], name, args.region)
        if exists is True:
            collisions.append({"logical_id": logical_id, "type": meta["type"], "name": name})
        elif exists is None:
            unresolved.append({"logical_id": logical_id, "type": meta["type"],
                               "name": name, "reason": detail or "indeterminate"})

    report = {
        "stack": args.stack,
        "template": args.template,
        "parameters_applied": {k: params.get(k) for k in
                               ("Environment", "EnvironmentSuffix") if k in params},
        "counts": {
            "declared_total": len(resources),
            "applicable": len(included),
            "in_stack": len(live_stack),
            "would_modify": len(included & set(live_stack)),
            "would_remove": len(would_remove),
            "would_create": len(would_create),
        },
        "controls": controls,
        "would_remove_destructive": destructive,
        "would_remove_orphaning": orphaning,
        "create_collisions": collisions,
        "indeterminate_conditions": indeterminate_cond,
        "indeterminate_creates": unresolved,
    }
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    counts = report["counts"]
    print(f"  stack {args.stack}: MODIFY {counts['would_modify']} / "
          f"REMOVE {counts['would_remove']} / CREATE {counts['would_create']}")
    for rtype, status in sorted(controls.items()):
        print(f"  control {rtype}: {status}")
    for row in destructive:
        print(f"  [FAIL] would DESTROY {row['logical_id']} "
              f"({row['physical_id']}) - no DeletionPolicy")
    for row in orphaning:
        print(f"  [WARN] would ORPHAN {row['logical_id']} "
              f"({row['physical_id']}) - DeletionPolicy: Retain, becomes unmanaged")
    for row in collisions:
        print(f"  [FAIL] CREATE collision {row['logical_id']} -> {row['name']} already exists live")
    for row in unresolved:
        print(f"  [WARN] indeterminate CREATE {row['logical_id']}: {row['reason']}")
    for name in indeterminate_cond:
        print(f"  [WARN] indeterminate Condition on {name} - excluded from both sets")

    # PRECEDENCE MATTERS. A CONFIRMED destructive removal or CREATE collision is
    # strictly more actionable than an inconclusive control, so it must win. The
    # first version of this function returned 2 first, which let an unrelated
    # denied IAM control MASK a proven "would DESTROY" -- surfaced by running the
    # negative control rather than by reading the code.
    if args.fail_on_delta and (destructive or collisions):
        if control_failures:
            print(f"[NOTE] controls were inconclusive for: {', '.join(control_failures)} -- "
                  "reported below, but the confirmed findings above already fail this gate.")
        return 1

    if control_failures:
        print(f"[INDETERMINATE] positive control failed for: {', '.join(control_failures)}. "
              "Treat this run as inconclusive, NOT as a pass.")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
