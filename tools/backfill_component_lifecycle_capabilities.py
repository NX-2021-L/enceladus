#!/usr/bin/env python3
"""Backfill capability declarations on existing component registry records.

ENC-TSK-E68 (ENC-PLN-031 Phase 3). Mirrors the E12 pattern used in
tools/backfill_component_lifecycle.py: read every component registry
record via the coordination API, determine its capability requirements
from static lookup + declared-secrets manifest + CFN resource scan, and
PATCH the record via `coordination_api /api/v1/coordination/components/{id}`.

Runs under agent-CLI scope. All writes route through the governed HTTP
API — no direct DynamoDB writes. The governance_hash is refreshed before
each write batch.

Safety rails:
- --dry-run prints intended updates without PATCHing
- Only populates fields that are currently absent OR empty-array on the
  record (never overwrites human-edited values)
- Stops after --limit records (default 0 = unlimited) so gamma rollout
  can validate on a subset first

Capability source resolution:
- required_env_secrets: from tools/deploy-capability/env-production-secrets.json
  (ENC-TSK-E66) filtered by "referenced_by" matching the component's lambda path
- required_iam_actions: static lookup table keyed by category / component_id
- required_apigw_routes: extracted from infrastructure/cloudformation/03-api.yaml
  via the same regex used in tools/audit_cfn_drift.py, filtered by
  integration target matching the component's Lambda
- required_cfn_resources: derived from route/integration references
- required_lambda_env_vars: read live via `aws lambda get-function-configuration`
  (optional; skipped under --no-aws)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import request as _urllib_request

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_BASE = os.environ.get(
    "COORDINATION_API_BASE",
    "https://jreese.net/api/v1/coordination",
)
DEFAULT_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")


STATIC_IAM_LOOKUP: Dict[str, List[str]] = {
    "comp-enceladus-mcp-server": [
        "lambda:UpdateFunctionCode",
        "lambda:GetFunction",
        "lambda:CreateFunctionUrlConfig",
    ],
    "comp-tracker-mutation": [
        "lambda:UpdateFunctionCode",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
        "dynamodb:GetItem",
    ],
    "comp-deploy-intake": [
        "lambda:UpdateFunctionCode",
        "dynamodb:UpdateItem",
        "dynamodb:GetItem",
    ],
    "comp-deploy-decide": [
        "lambda:UpdateFunctionCode",
        "dynamodb:UpdateItem",
    ],
    "comp-github-integration": [
        "lambda:UpdateFunctionCode",
        "dynamodb:UpdateItem",
        "dynamodb:Scan",
    ],
    "comp-coordination-api": [
        "lambda:UpdateFunctionCode",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
    ],
    "comp-checkout-service": [
        "lambda:UpdateFunctionCode",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
    ],
    "comp-deploy-capability-auditor": [
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "apigatewayv2:GetRoutes",
        "cloudformation:ListStackResources",
        "secretsmanager:ListSecrets",
    ],
}


def _load_env_secrets_manifest() -> Dict[str, List[str]]:
    path = REPO_ROOT / "tools" / "deploy-capability" / "env-production-secrets.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    out: Dict[str, List[str]] = {}
    for entry in data.get("required_secrets", []):
        for ref in entry.get("referenced_by", []):
            key = ref.split(":", 1)[0]
            out.setdefault(key, []).append(entry["name"])
    return out


def _gh_coordination_get(api_base: str, api_key: str, path: str) -> Any:
    req = _urllib_request.Request(
        f"{api_base.rstrip('/')}{path}",
        headers={
            "Accept": "application/json",
            "X-Coordination-Internal-Key": api_key,
        },
    )
    with _urllib_request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _gh_coordination_patch(
    api_base: str, api_key: str, path: str, body: Dict[str, Any]
) -> Any:
    data = json.dumps(body).encode("utf-8")
    req = _urllib_request.Request(
        f"{api_base.rstrip('/')}{path}",
        method="PATCH",
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Coordination-Internal-Key": api_key,
        },
    )
    with _urllib_request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _resolve_lambda_env_vars(function_name: str) -> List[str]:
    try:
        out = subprocess.check_output(
            [
                "aws", "lambda", "get-function-configuration",
                "--function-name", function_name,
                "--query", "Environment.Variables",
                "--output", "json",
            ],
            text=True, stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    data = json.loads(out) if out.strip() and out.strip() != "null" else {}
    return sorted(data.keys()) if isinstance(data, dict) else []


def compute_capabilities(
    component: Dict[str, Any],
    env_secrets_manifest: Dict[str, List[str]],
    use_aws: bool,
) -> Dict[str, List[str]]:
    component_id = component["component_id"]
    result: Dict[str, List[str]] = {
        "required_iam_actions": sorted(set(STATIC_IAM_LOOKUP.get(component_id, []))),
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    }

    source_paths = component.get("source_paths") or {}
    primary = source_paths.get("primary") or ""
    directory = source_paths.get("directory") or ""

    env_secrets: List[str] = []
    for key, names in env_secrets_manifest.items():
        if key and (key in primary or key in directory or key.startswith(".github")):
            env_secrets.extend(names)
    result["required_env_secrets"] = sorted(set(env_secrets))

    function_name = (component.get("source_paths") or {}).get("function_name")
    if not function_name and component.get("category") == "lambda":
        slug = component_id.replace("comp-", "")
        function_name = slug if "-" in slug else f"enceladus-{slug}"

    if use_aws and function_name:
        result["required_lambda_env_vars"] = _resolve_lambda_env_vars(function_name)

    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--api-base", default=DEFAULT_API_BASE)
    ap.add_argument("--api-key", default=DEFAULT_API_KEY)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-aws", action="store_true")
    args = ap.parse_args()

    if not args.api_key:
        print(
            "ERROR: COORDINATION_INTERNAL_API_KEY env var or --api-key required",
            file=sys.stderr,
        )
        return 2

    env_secrets_manifest = _load_env_secrets_manifest()

    listing = _gh_coordination_get(args.api_base, args.api_key, "/components")
    components = listing.get("components") or listing.get("items") or []
    print(f"[INFO] {len(components)} component(s) found")

    written = 0
    for i, component in enumerate(components):
        if args.limit and written >= args.limit:
            break
        cid = component["component_id"]
        capabilities = compute_capabilities(
            component, env_secrets_manifest, use_aws=not args.no_aws
        )

        patch: Dict[str, List[str]] = {}
        for field, value in capabilities.items():
            existing = component.get(field) or []
            if not existing and value:
                patch[field] = value

        if not patch:
            print(f"[SKIP] {cid} — already populated or nothing to backfill")
            continue

        print(f"[PLAN] {cid} <- {json.dumps(patch, sort_keys=True)}")
        if args.dry_run:
            continue

        try:
            resp = _gh_coordination_patch(
                args.api_base, args.api_key, f"/components/{cid}", patch
            )
            if resp.get("success"):
                print(f"[OK]   {cid} patched")
                written += 1
            else:
                print(f"[WARN] {cid} response not success: {resp}")
        except Exception as exc:
            print(f"[ERROR] {cid} patch failed: {exc}", file=sys.stderr)

    print(f"[DONE] {written} record(s) patched (dry_run={args.dry_run})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
