#!/usr/bin/env python3
"""ENC-TSK-G95 / ENC-ISS-313 — diff live IAM (dump) against CFN-declared inline policies.

Compares, per role, the union of IAM actions declared in
infrastructure/cloudformation/02-compute.yaml inline Policies against the live
inline policies captured by dump_live_iam.py. Surfaces:
  - actions present LIVE but absent in CFN  (CFN deploy would FAIL to grant -> drift / Sev1)
  - actions present in CFN but absent LIVE  (CFN deploy would ADD -> benign per AC-5)
  - roles declared in CFN but missing LIVE  (deploy would CREATE -> ISS-252 / iam:CreateRole)
  - out-of-band attached managed policies live (not represented as CFN inline)

Resource-level fidelity (intrinsic !Sub/!ImportValue vs resolved live ARNs) is NOT
string-comparable here; this diff is action-level. Exact resource strings for codified
statements are taken verbatim from the live dump in the AC-4 codification step.
"""
import json
import re
import sys

import yaml

CFN = "infrastructure/cloudformation/02-compute.yaml"
DUMP = "tools/iam-audit/live-iam-dump-20260617.json"

# logical-id -> live role name (prod, EnvironmentSuffix='')
ROLE_MAP = {
    "CoordinationApiRole": "devops-coordination-api-lambda-role",
    "TrackerMutationRole": "devops-tracker-mutation-lambda-role",
    "DocumentApiRole": "devops-document-api-lambda-role",
    "ProjectServiceRole": "devops-project-service-lambda-role",
    "FeedQueryRole": "devops-feed-query-lambda-role",
    "CoordinationMonitorRole": "devops-coordination-monitor-lambda-role",
    "DeployIntakeRole": "devops-deploy-intake-lambda-role",
    "DeployOrchestratorRole": "devops-deploy-orchestrator-lambda-role",
    "DeployFinalizeRole": "devops-deploy-finalize-lambda-role",
    "DeployDecideRole": "devops-deploy-decide-lambda-role",
    "DeployParityValidatorRole": "devops-deploy-parity-validator-role",
    "ReferenceSearchRole": "devops-reference-search-lambda-role",
    "FeedPublisherRole": "devops-feed-publisher-lambda-role",
    "GovernanceAuditRole": "enceladus-governance-audit-role",
    "DocPrepRole": "devops-doc-prep-lambda-role",
    "BedrockActionsRole": "enceladus-bedrock-actions-lambda-role",
    "ChangelogApiRole": "devops-changelog-api-lambda-role",
    "AuthRefreshRole": "auth-refresh-lambda-role",
    "FeedPipeRole": "devops-feed-pipe-role",
    "GraphSyncRole": "devops-graph-sync-lambda-role",
    "GraphQueryApiRole": "devops-graph-query-api-lambda-role",
    "Neo4jBackupRole": "enceladus-neo4j-backup-lambda-role",
    "GraphHealthMetricsRole": "enceladus-graph-health-metrics-role",
    "GraphPipeRole": "devops-graph-pipe-role",
    "EnvDriftAuditorRole": "devops-env-drift-auditor-role",
}


def cfn_loader():
    """SafeLoader that keeps CFN short-form intrinsics as plain strings/lists."""
    loader = yaml.SafeLoader
    tags = ["!Sub", "!Ref", "!GetAtt", "!ImportValue", "!Join", "!Select",
            "!Split", "!FindInMap", "!Base64", "!Sub", "!If", "!Equals", "!And",
            "!Or", "!Not", "!Cidr", "!GetAZs"]

    def construct(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    for t in set(tags):
        loader.add_constructor(t, lambda l, n, _t=t: _scalar_or_seq(l, n))
    return loader


def _scalar_or_seq(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


# register a generic multi-constructor for any ! tag
yaml.SafeLoader.add_multi_constructor("!", lambda l, suffix, node: _scalar_or_seq(l, node))


def as_list(x):
    return x if isinstance(x, list) else [x]


def collect_actions(policies):
    """policies: CFN Properties.Policies list -> set of actions (lowercased)."""
    actions = set()
    sids = set()
    for pol in policies or []:
        doc = pol.get("PolicyDocument", {})
        for st in as_list(doc.get("Statement", [])):
            if not isinstance(st, dict):
                continue
            if st.get("Sid"):
                sids.add(st["Sid"])
            for a in as_list(st.get("Action", [])):
                if isinstance(a, str):
                    actions.add(a.lower())
    return actions, sids


def collect_live_actions(inline_policies):
    actions, sids = set(), set()
    for pname, doc in (inline_policies or {}).items():
        if not isinstance(doc, dict):
            continue
        for st in as_list(doc.get("Statement", [])):
            if not isinstance(st, dict):
                continue
            if st.get("Sid"):
                sids.add(st["Sid"])
            for a in as_list(st.get("Action", [])):
                if isinstance(a, str):
                    actions.add(a.lower())
    return actions, sids


def main():
    with open(CFN) as f:
        tpl = yaml.load(f, Loader=cfn_loader())
    resources = tpl["Resources"]
    dump = json.load(open(DUMP))["roles"]

    findings = []
    for logical, rolename in ROLE_MAP.items():
        res = resources.get(logical, {})
        cfn_policies = res.get("Properties", {}).get("Policies", [])
        cfn_actions, cfn_sids = collect_actions(cfn_policies)
        live = dump.get(rolename, {})
        if not live.get("exists"):
            findings.append({
                "role": rolename, "logical_id": logical,
                "status": "CFN_ONLY_NOT_LIVE",
                "note": "Declared in CFN but does not exist live -> deploy CREATES role (ISS-252: iam:CreateRole).",
                "cfn_actions": sorted(cfn_actions),
            })
            continue
        live_actions, live_sids = collect_live_actions(live.get("inline_policies"))
        missing_in_cfn = sorted(live_actions - cfn_actions)   # live has, CFN lacks -> DRIFT
        extra_in_cfn = sorted(cfn_actions - live_actions)      # CFN has, live lacks -> benign add
        findings.append({
            "role": rolename, "logical_id": logical,
            "status": "PLACEHOLDER_NO_CFN_POLICIES" if not cfn_policies else "HAS_CFN_POLICIES",
            "cfn_policy_count": len(cfn_policies),
            "live_inline_policy_names": live.get("inline_policy_names"),
            "live_attached_managed": live.get("attached_policy_arns"),
            "actions_missing_in_cfn": missing_in_cfn,
            "actions_extra_in_cfn": extra_in_cfn,
        })

    json.dump({"task": "ENC-TSK-G95", "generated": "2026-06-17", "findings": findings},
              open("tools/iam-audit/cfn-vs-live-diff-20260617.json", "w"), indent=2)

    # markdown summary to stdout
    print("# ENC-TSK-G95 — CFN vs Live IAM action-level diff (2026-06-17)\n")
    print("Supersedes DOC-FBD770A9483B. Source: live dump under product-lead (io-dev-admin).\n")
    drift = [f for f in findings if f.get("actions_missing_in_cfn")]
    placeholders = [f for f in findings if f.get("status") == "PLACEHOLDER_NO_CFN_POLICIES"]
    cfn_only = [f for f in findings if f.get("status") == "CFN_ONLY_NOT_LIVE"]
    print(f"- roles compared: {len(findings)}")
    print(f"- roles with live actions MISSING from CFN (drift): {len(drift)}")
    print(f"- roles that are CFN placeholders (no inline Policies): {len(placeholders)}")
    print(f"- roles in CFN but not live (deploy would create): {[f['role'] for f in cfn_only]}\n")
    for f in findings:
        print(f"## {f['logical_id']}  ({f['role']}) — {f['status']}")
        if f["status"] == "CFN_ONLY_NOT_LIVE":
            print(f"  - {f['note']}\n")
            continue
        if f.get("live_attached_managed"):
            print(f"  - live attached managed policies: {f['live_attached_managed']}")
        if f["actions_missing_in_cfn"]:
            print(f"  - **ACTIONS MISSING IN CFN (live-only):** {f['actions_missing_in_cfn']}")
        if f["actions_extra_in_cfn"]:
            print(f"  - actions in CFN but not live (benign add on deploy): {f['actions_extra_in_cfn']}")
        if not f["actions_missing_in_cfn"] and not f["actions_extra_in_cfn"]:
            print("  - action sets MATCH")
        print()


if __name__ == "__main__":
    main()
