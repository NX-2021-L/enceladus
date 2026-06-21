#!/usr/bin/env python3
"""CFN template environment resolver + required-env diff — ENC-TSK-H17.

ENC-PLN-048 Objective 2 (parity gate core), parent ENC-TSK-H12, feature ENC-FTR-102.

Parses infrastructure/cloudformation/02-compute.yaml, resolves each
``AWS::Lambda::Function``'s ``Environment.Variables`` to their fully-evaluated
values for a given parameter set, and diffs the resolved key set against the
canonical required-env registry
(backend/lambda/env_drift_auditor/env_drift_registry.json — codified as the
single source by ENC-TSK-H16).

Why a real intrinsic-function evaluator instead of naive ``!Ref`` substitution
(PLN-048 refinement, CRITICAL): the prototype's ``!Ref``-only resolver
FALSE-FLAGGED the AppConfig vars as "would be stripped" purely because it did
not evaluate ``!If``. A variable whose value resolves to ``AWS::NoValue`` is NOT
SET (absent) — not present-empty. To match what CloudFormation will actually
apply, this module evaluates ``Ref``, ``Fn::Sub``, ``Fn::If``, ``Fn::Equals``,
``Fn::Not``, ``Fn::And``, ``Fn::Or``, ``Fn::Join``, ``Fn::Select``,
``Fn::GetAtt``, ``Fn::ImportValue`` and the template ``Conditions`` block, and
drops any property/variable that resolves to ``AWS::NoValue``.

Consumed by:
  - tools/env_parity_gate.py            (ENC-TSK-H18 fail-closed gate + waivers)
  - tools/live_template_strip_detector.py (ENC-TSK-H19 live-vs-template detector)
  - tools/pre-deploy-health-gate.sh     (direct-deploy safety gate)

Pure template-side resolution — performs no AWS calls. ``--parameters`` /
``--parameters-file`` supply the deploy's actual ``--parameter-overrides`` so
``!Ref`` resolution matches the real deploy (no false "missing" for params).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# --- AWS::NoValue sentinel -------------------------------------------------
# A node that resolves to this is treated as "not set" and dropped from its
# containing mapping/list, exactly as CloudFormation removes a property set to
# AWS::NoValue.
class _NoValue:
    _instance: Optional["_NoValue"] = None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "<AWS::NoValue>"


NOVALUE = _NoValue()

# Pseudo-parameter defaults. AWS::Region is the one that actually appears in
# 02-compute.yaml env vars (DYNAMODB_REGION, SSM_REGION, SECRETS_REGION, and the
# H09 SQS_QUEUE_URL !Sub). The rest are provided for completeness.
DEFAULT_REGION = "us-west-2"
DEFAULT_ACCOUNT_ID = "356364570033"  # enceladus prod/gamma account


def _pseudo_params(region: str, account_id: str, stack_name: str) -> Dict[str, Any]:
    return {
        "AWS::Region": region,
        "AWS::AccountId": account_id,
        "AWS::StackName": stack_name,
        "AWS::Partition": "aws",
        "AWS::URLSuffix": "amazonaws.com",
        "AWS::NoValue": NOVALUE,
        "AWS::NotificationARNs": [],
    }


# --- CFN-aware YAML loader -------------------------------------------------
# Normalizes short-form tags (!Ref, !Sub, !If, ...) to the long JSON form
# ({"Ref": ...}, {"Fn::Sub": ...}, {"Fn::If": ...}) so resolution logic can be
# written against a single representation.
class _CfnLoader(yaml.SafeLoader):
    pass


def _cfn_multi_constructor(loader: "_CfnLoader", tag_suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)

    if tag_suffix == "Ref":
        return {"Ref": value}
    key = f"Fn::{tag_suffix}"
    if key == "Fn::GetAtt" and isinstance(value, str):
        # "Resource.Attr.Sub" -> ["Resource", "Attr.Sub"]
        head, _, tail = value.partition(".")
        value = [head, tail]
    return {key: value}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def load_template(template_path: Path) -> Dict[str, Any]:
    """Load a CloudFormation YAML template with intrinsic tags normalized."""
    with open(template_path) as fh:
        return yaml.load(fh, Loader=_CfnLoader) or {}


# --- Resolution context ----------------------------------------------------
class ResolveContext:
    def __init__(
        self,
        params: Dict[str, Any],
        region: str = DEFAULT_REGION,
        account_id: str = DEFAULT_ACCOUNT_ID,
        stack_name: str = "enceladus-compute",
        imports: Optional[Dict[str, str]] = None,
    ) -> None:
        self.params = dict(params)
        self.region = region
        self.account_id = account_id
        self.stack_name = stack_name
        self.imports = imports or {}
        self.pseudo = _pseudo_params(region, account_id, stack_name)
        self.conditions: Dict[str, bool] = {}
        self._raw_conditions: Dict[str, Any] = {}

    def ref(self, name: str) -> Any:
        if name in self.pseudo:
            return self.pseudo[name]
        if name in self.params:
            return self.params[name]
        # Ref to a resource logical id (rare in env vars) — opaque but present.
        return f"<Ref:{name}>"


def build_params(template: Dict[str, Any], overrides: Dict[str, str]) -> Dict[str, Any]:
    """Merge template Parameter defaults with explicit overrides.

    Overrides win. A parameter with no default and no override is left absent so
    that a Ref to it surfaces as unresolved rather than silently empty.
    """
    params: Dict[str, Any] = {}
    for name, spec in (template.get("Parameters") or {}).items():
        if isinstance(spec, dict) and "Default" in spec:
            params[name] = spec["Default"]
    for name, value in overrides.items():
        params[name] = value
    return params


# --- Condition evaluation --------------------------------------------------
def evaluate_conditions(template: Dict[str, Any], ctx: ResolveContext) -> Dict[str, bool]:
    ctx._raw_conditions = dict(template.get("Conditions") or {})
    ctx.conditions = {}
    for name in ctx._raw_conditions:
        _eval_named_condition(name, ctx, set())
    return ctx.conditions


def _eval_named_condition(name: str, ctx: ResolveContext, seen: set) -> bool:
    if name in ctx.conditions:
        return ctx.conditions[name]
    if name in seen:
        raise ValueError(f"circular condition reference: {name}")
    seen.add(name)
    result = _eval_condition_expr(ctx._raw_conditions[name], ctx, seen)
    ctx.conditions[name] = result
    return result


def _eval_condition_expr(expr: Any, ctx: ResolveContext, seen: set) -> bool:
    if isinstance(expr, dict) and len(expr) == 1:
        key, val = next(iter(expr.items()))
        if key == "Fn::Equals":
            return _as_scalar(resolve(val[0], ctx)) == _as_scalar(resolve(val[1], ctx))
        if key == "Fn::Not":
            return not _eval_condition_expr(val[0], ctx, seen)
        if key == "Fn::And":
            return all(_eval_condition_expr(v, ctx, seen) for v in val)
        if key == "Fn::Or":
            return any(_eval_condition_expr(v, ctx, seen) for v in val)
        if key == "Condition":
            return _eval_named_condition(val, ctx, seen)
    raise ValueError(f"unsupported condition expression: {expr!r}")


# --- Value resolution ------------------------------------------------------
_SUB_VAR = re.compile(r"\$\{([^}]+)\}")


def resolve(node: Any, ctx: ResolveContext) -> Any:
    """Recursively resolve an intrinsic node to a concrete value.

    Mappings and lists drop entries that resolve to AWS::NoValue (matching CFN).
    """
    if isinstance(node, dict):
        if len(node) == 1:
            key = next(iter(node))
            if key in _INTRINSIC_HANDLERS:
                return _INTRINSIC_HANDLERS[key](node[key], ctx)
        out: Dict[str, Any] = {}
        for k, v in node.items():
            rv = resolve(v, ctx)
            if rv is NOVALUE:
                continue
            out[k] = rv
        return out
    if isinstance(node, list):
        resolved = [resolve(x, ctx) for x in node]
        return [x for x in resolved if x is not NOVALUE]
    return node


def _r_ref(value: Any, ctx: ResolveContext) -> Any:
    return ctx.ref(value)


def _r_sub(value: Any, ctx: ResolveContext) -> Any:
    if isinstance(value, list):
        template_str, var_map = value[0], (value[1] if len(value) > 1 else {})
        local = {k: _as_scalar(resolve(v, ctx)) for k, v in (var_map or {}).items()}
    else:
        template_str, local = value, {}

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name in local:
            return local[name]
        if "." in name:  # ${Resource.Attr} GetAtt-style — opaque but present
            return f"<{name}>"
        resolved = ctx.ref(name)
        if resolved is NOVALUE:
            return ""
        return _as_scalar(resolved)

    return _SUB_VAR.sub(_replace, str(template_str))


def _r_if(value: Any, ctx: ResolveContext) -> Any:
    cond_name, true_val, false_val = value[0], value[1], value[2]
    chosen = true_val if _eval_named_condition(cond_name, ctx, set()) else false_val
    return resolve(chosen, ctx)


def _r_join(value: Any, ctx: ResolveContext) -> Any:
    delim, items = value[0], value[1]
    resolved = resolve(items, ctx)  # list resolution drops NoValue
    return str(delim).join(_as_scalar(x) for x in resolved)


def _r_select(value: Any, ctx: ResolveContext) -> Any:
    index, items = int(value[0]), resolve(value[1], ctx)
    return items[index]


def _r_getatt(value: Any, ctx: ResolveContext) -> Any:
    parts = value if isinstance(value, list) else [value]
    return f"<GetAtt:{'.'.join(str(p) for p in parts)}>"


def _r_importvalue(value: Any, ctx: ResolveContext) -> Any:
    name = _as_scalar(resolve(value, ctx))
    if name in ctx.imports:
        return ctx.imports[name]
    return f"<ImportValue:{name}>"


def _r_findinmap(value: Any, ctx: ResolveContext) -> Any:
    return f"<FindInMap:{'.'.join(_as_scalar(resolve(v, ctx)) for v in value)}>"


_INTRINSIC_HANDLERS = {
    "Ref": _r_ref,
    "Fn::Sub": _r_sub,
    "Fn::If": _r_if,
    "Fn::Join": _r_join,
    "Fn::Select": _r_select,
    "Fn::GetAtt": _r_getatt,
    "Fn::ImportValue": _r_importvalue,
    "Fn::FindInMap": _r_findinmap,
}


def _as_scalar(value: Any) -> str:
    """Coerce a resolved value to the string form CFN would apply to an env var."""
    if value is NOVALUE or value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


# --- Per-function resolution + diff ---------------------------------------
def resolve_function_envs(template: Dict[str, Any], ctx: ResolveContext) -> Dict[str, Dict[str, Any]]:
    """Return {resolved_function_name: {"logical_id", "resolved_env"}} for every
    AWS::Lambda::Function in the template.

    A variable whose value resolves to AWS::NoValue is omitted from resolved_env
    (it is NOT set on the deployed function).
    """
    evaluate_conditions(template, ctx)
    result: Dict[str, Dict[str, Any]] = {}
    for logical_id, resource in (template.get("Resources") or {}).items():
        if not isinstance(resource, dict) or resource.get("Type") != "AWS::Lambda::Function":
            continue
        props = resource.get("Properties") or {}
        fn_name = _as_scalar(resolve(props.get("FunctionName"), ctx))
        environment = resolve(props.get("Environment"), ctx)
        variables = {}
        if isinstance(environment, dict):
            for k, v in (environment.get("Variables") or {}).items():
                variables[k] = _as_scalar(v)
        result[fn_name] = {"logical_id": logical_id, "resolved_env": variables}
    return result


def load_required_env(registry_path: Path) -> Dict[str, List[str]]:
    with open(registry_path) as fh:
        registry = json.load(fh)
    return registry.get("lambdas", {})


def diff_required(
    resolved: Dict[str, Dict[str, Any]],
    required_map: Dict[str, List[str]],
) -> Dict[str, Dict[str, Any]]:
    """Per-function diff of resolved template env keys vs the required-env registry.

    missing  = required vars not present in the template-resolved env (would fail
               the parity gate — the deploy would not set a var the handler needs).
    """
    report: Dict[str, Dict[str, Any]] = {}
    for fn_name, info in resolved.items():
        keys = set(info["resolved_env"])
        required = required_map.get(fn_name, [])
        report[fn_name] = {
            "logical_id": info["logical_id"],
            "has_registry_entry": fn_name in required_map,
            "required": sorted(required),
            "resolved_keys": sorted(keys),
            "missing": sorted(set(required) - keys),
        }
    return report


def resolve_and_diff(
    template_path: Path,
    overrides: Dict[str, str],
    registry_path: Path,
    region: str = DEFAULT_REGION,
    imports: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Top-level helper used by the H18 gate and H19 detector."""
    template = load_template(template_path)
    ctx = ResolveContext(build_params(template, overrides), region=region, imports=imports)
    resolved = resolve_function_envs(template, ctx)
    required_map = load_required_env(registry_path)
    return {
        "template": str(template_path),
        "region": region,
        "parameters": {k: ("<redacted>" if _is_secret(k) else v) for k, v in ctx.params.items()},
        "functions": resolved,
        "diff": diff_required(resolved, required_map),
    }


def _is_secret(param_name: str) -> bool:
    lowered = param_name.lower()
    return any(tok in lowered for tok in ("secret", "apikey", "api_key", "password", "token"))


# --- CLI -------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_TEMPLATE = _REPO_ROOT / "infrastructure" / "cloudformation" / "02-compute.yaml"
_DEFAULT_REGISTRY = _REPO_ROOT / "backend" / "lambda" / "env_drift_auditor" / "env_drift_registry.json"


def _parse_overrides(pairs: List[str], file_path: Optional[str]) -> Dict[str, str]:
    overrides: Dict[str, str] = {}
    if file_path:
        data = json.loads(Path(file_path).read_text())
        # Accept either {"Key": "Value"} or CFN [{"ParameterKey","ParameterValue"}]
        if isinstance(data, list):
            for item in data:
                overrides[item["ParameterKey"]] = item["ParameterValue"]
        else:
            overrides.update({str(k): str(v) for k, v in data.items()})
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"[ERROR] --parameter expects Key=Value, got: {pair!r}")
        key, _, value = pair.partition("=")
        overrides[key.strip()] = value
    return overrides


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve CFN Lambda env vars and diff vs required-env registry.")
    parser.add_argument("--template", default=str(_DEFAULT_TEMPLATE))
    parser.add_argument("--registry", default=str(_DEFAULT_REGISTRY))
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument(
        "--parameter",
        action="append",
        default=[],
        metavar="Key=Value",
        help="Parameter override (repeatable). Mirrors --parameter-overrides.",
    )
    parser.add_argument("--parameters-file", help="JSON file of parameter overrides.")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    overrides = _parse_overrides(args.parameter, args.parameters_file)
    report = resolve_and_diff(
        Path(args.template),
        overrides,
        Path(args.registry),
        region=args.region,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"# CFN env resolution: {report['template']} (region={report['region']})")
    for fn_name in sorted(report["diff"]):
        d = report["diff"][fn_name]
        flag = "registry" if d["has_registry_entry"] else "no-registry-entry"
        print(f"\n{fn_name} [{d['logical_id']}] ({flag})")
        print(f"  resolved keys ({len(d['resolved_keys'])}): {', '.join(d['resolved_keys'])}")
        if d["missing"]:
            print(f"  MISSING required: {', '.join(d['missing'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
