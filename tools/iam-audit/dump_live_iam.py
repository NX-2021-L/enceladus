#!/usr/bin/env python3
"""ENC-TSK-G95 / ENC-ISS-313 — live IAM dump for 02-compute.yaml Lambda execution roles.

Dumps live inline + attached managed policies for every role defined in
infrastructure/cloudformation/02-compute.yaml so the template can be made the
authoritative source of truth (the April audit DOC-FBD770A9483B is invalidated:
it predates the deploy.sh tombstoning in ENC-TSK-G43).

Read-only: iam:GetRole / ListRolePolicies / GetRolePolicy / ListAttachedRolePolicies.
Requires the product-lead (io-dev-admin) AWS CLI profile; product-lead-inspect is
denied iam:ListRolePolicies/GetRolePolicy.

Usage: python3 tools/iam-audit/dump_live_iam.py [profile] > live-iam-dump.json
"""
import json
import subprocess
import sys

PROFILE = sys.argv[1] if len(sys.argv) > 1 else "product-lead"

# prod role names (EnvironmentSuffix='') as declared in 02-compute.yaml, in template order
ROLES = [
    "devops-coordination-api-lambda-role",
    "devops-tracker-mutation-lambda-role",
    "devops-document-api-lambda-role",
    "devops-project-service-lambda-role",
    "devops-feed-query-lambda-role",
    "devops-coordination-monitor-lambda-role",
    "devops-deploy-intake-lambda-role",
    "devops-deploy-orchestrator-lambda-role",
    "devops-deploy-finalize-lambda-role",
    "devops-deploy-decide-lambda-role",
    "devops-deploy-parity-validator-role",
    "devops-reference-search-lambda-role",
    "devops-feed-publisher-lambda-role",
    "enceladus-governance-audit-role",
    "devops-doc-prep-lambda-role",
    "enceladus-bedrock-actions-lambda-role",
    "devops-changelog-api-lambda-role",
    "auth-refresh-lambda-role",
    "devops-feed-pipe-role",
    "devops-graph-sync-lambda-role",
    "devops-graph-query-api-lambda-role",
    "enceladus-neo4j-backup-lambda-role",
    "enceladus-graph-health-metrics-role",
    "devops-graph-pipe-role",
    "devops-env-drift-auditor-role",
]


def aws(*args):
    cp = subprocess.run(
        ["aws", "iam", *args, "--profile", PROFILE, "--output", "json"],
        capture_output=True, text=True,
    )
    if cp.returncode != 0:
        return None, cp.stderr.strip()
    return json.loads(cp.stdout), None


def main():
    out = {
        "_meta": {
            "generated": "2026-06-17",
            "task": "ENC-TSK-G95",
            "issue": "ENC-ISS-313",
            "profile": PROFILE,
            "account": "356364570033",
            "env": "prod (EnvironmentSuffix='')",
            "supersedes": "DOC-FBD770A9483B (April 2026 audit, invalidated by ENC-TSK-G43 deploy.sh tombstoning)",
        },
        "roles": {},
    }
    for r in ROLES:
        role_meta, err = aws("get-role", "--role-name", r)
        if role_meta is None:
            out["roles"][r] = {"exists": False, "error": err}
            print(f"MISSING/ERROR: {r} :: {err}", file=sys.stderr)
            continue
        names, err = aws("list-role-policies", "--role-name", r)
        attached, _ = aws("list-attached-role-policies", "--role-name", r)
        inline = {}
        for p in (names or {}).get("PolicyNames", []):
            doc, derr = aws("get-role-policy", "--role-name", r, "--policy-name", p)
            inline[p] = doc.get("PolicyDocument") if doc else {"error": derr}
        out["roles"][r] = {
            "exists": True,
            "arn": role_meta["Role"]["Arn"],
            "inline_policy_names": (names or {}).get("PolicyNames", []),
            "attached_policy_arns": [a["PolicyArn"] for a in (attached or {}).get("AttachedPolicies", [])],
            "inline_policies": inline,
        }
        print(f"DUMPED: {r}  inline={(names or {}).get('PolicyNames', [])}", file=sys.stderr)
    json.dump(out, sys.stdout, indent=2, sort_keys=False)


if __name__ == "__main__":
    main()
