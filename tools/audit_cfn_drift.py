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
  --output-json <path>         Write JSON drift report for CI consumption
  --fail-on-drift              Exit 1 if any drift is detected

The YAML parser handles CFN intrinsic tags (!Ref, !Sub, etc.) without
requiring cfn-lint. Only the fields we care about (route keys) are
extracted, so the parser is deliberately minimal.
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


def resolve_api_id(stack_prefix: str) -> str:
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
        names = [c["Name"] for c in candidates]
        raise RuntimeError(
            f"Multiple API Gateway v2 APIs match: {names}. "
            f"Pass --api-id explicitly."
        )
    return candidates[0]["ApiId"]


_ROUTEKEY_RE = re.compile(
    r"RouteKey:\s*['\"]?(?P<key>[^'\"\n]+?)['\"]?\s*$",
    re.MULTILINE,
)


def declared_routes(cfn_glob: str) -> Set[str]:
    """Extract RouteKey values from every AWS::ApiGatewayV2::Route resource
    in the matched CFN templates. Uses a regex scoped to RouteKey lines so
    we don't need to handle full CFN intrinsic parsing.
    """
    keys: Set[str] = set()
    for path in sorted(glob.glob(cfn_glob)):
        text = Path(path).read_text()
        for m in _ROUTEKEY_RE.finditer(text):
            key = m.group("key").strip()
            if key:
                keys.add(key)
    return keys


def live_eventbridge_rules(name_prefix: str) -> Set[str]:
    data = _aws_json([
        "aws", "events", "list-rules",
        "--name-prefix", name_prefix,
    ])
    return {item["Name"] for item in (data or {}).get("Rules", [])}


_EVENTBRIDGE_RULE_RE = re.compile(
    r"Type:\s*AWS::Events::Rule[\s\S]*?(?=Type:\s*AWS::|\Z)"
)
_RULE_NAME_RE = re.compile(
    r"(?:Name|RuleName):\s*['\"]?(?P<name>[A-Za-z0-9_.-]+)['\"]?"
)


def declared_eventbridge_rules(cfn_glob: str) -> Set[str]:
    names: Set[str] = set()
    for path in sorted(glob.glob(cfn_glob)):
        text = Path(path).read_text()
        for block in _EVENTBRIDGE_RULE_RE.findall(text):
            m = _RULE_NAME_RE.search(block)
            if m:
                names.add(m.group("name"))
    return names


def audit(
    api_id: str,
    cfn_glob: str,
    event_rule_prefix: str,
) -> Dict[str, Dict[str, List[str]]]:
    declared_rt = declared_routes(cfn_glob)
    live_rt = live_apigw_routes(api_id)
    declared_ev = declared_eventbridge_rules(cfn_glob)
    live_ev = live_eventbridge_rules(event_rule_prefix)
    return {
        "apigw_routes": {
            "live_count": len(live_rt),
            "declared_count": len(declared_rt),
            "live_only": sorted(live_rt - declared_rt),
            "cfn_only": sorted(declared_rt - live_rt),
        },
        "eventbridge_rules": {
            "live_count": len(live_ev),
            "declared_count": len(declared_ev),
            "live_only": sorted(live_ev - declared_ev),
            "cfn_only": sorted(declared_ev - live_ev),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
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
    ap.add_argument("--output-json", default=None)
    ap.add_argument("--fail-on-drift", action="store_true")
    args = ap.parse_args()

    api_id = args.api_id or resolve_api_id(args.stack_prefix)

    report = audit(api_id, args.cfn_glob, args.event_rule_prefix)
    report["_api_id"] = api_id
    report["_cfn_glob"] = args.cfn_glob

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
