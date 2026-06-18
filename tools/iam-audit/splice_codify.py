#!/usr/bin/env python3
"""ENC-TSK-G95 — splice dual-env-PROVEN inline-policy statements into 02-compute.yaml.

Reads tools/iam-audit/codify-snippets-20260617.json (produced by codify_roles.py) and,
for each role with proven statements, inserts a single inline policy
'G95RestoredGrants' before that role's `Tags:` block. Only statements proven faithful
to BOTH prod-live (suffix='') and gamma-live (suffix='-gamma') are emitted; NEEDS_REVIEW
statements are intentionally left for human codification (see codify-report).

Idempotent: refuses to insert if G95RestoredGrants already present for a role.
"""
import json
import re

TPL = "infrastructure/cloudformation/02-compute.yaml"

# prod role name -> CFN logical id
LOGICAL = {
    "devops-coordination-api-lambda-role": "CoordinationApiRole",
    "devops-tracker-mutation-lambda-role": "TrackerMutationRole",
    "devops-document-api-lambda-role": "DocumentApiRole",
    "devops-project-service-lambda-role": "ProjectServiceRole",
    "devops-feed-query-lambda-role": "FeedQueryRole",
    "devops-coordination-monitor-lambda-role": "CoordinationMonitorRole",
    "devops-deploy-intake-lambda-role": "DeployIntakeRole",
    "devops-deploy-orchestrator-lambda-role": "DeployOrchestratorRole",
    "devops-deploy-finalize-lambda-role": "DeployFinalizeRole",
    "devops-reference-search-lambda-role": "ReferenceSearchRole",
    "devops-feed-publisher-lambda-role": "FeedPublisherRole",
    "enceladus-governance-audit-role": "GovernanceAuditRole",
    "devops-doc-prep-lambda-role": "DocPrepRole",
    "enceladus-bedrock-actions-lambda-role": "BedrockActionsRole",
    "devops-changelog-api-lambda-role": "ChangelogApiRole",
    "devops-coordination-monitor-lambda-role": "CoordinationMonitorRole",
}


def yaml_resource(r):
    if "${" in r:
        return f'!Sub "{r}"'
    return f'"{r}"'


def render_statement(st, indent):
    pad = " " * indent
    lines = []
    if st.get("Sid"):
        lines.append(f"{pad}- Sid: {st['Sid']}")
        first = f"{pad}  Effect: Allow"
    else:
        lines.append(f"{pad}- Effect: Allow")
        first = None
    if first:
        lines.append(first)
    else:
        pass
    lines.append(f"{pad}  Action:")
    for a in st["Action"]:
        lines.append(f"{pad}    - {a}")
    res = st["Resource"]
    if len(res) == 1:
        lines.append(f"{pad}  Resource: {yaml_resource(res[0])}")
    else:
        lines.append(f"{pad}  Resource:")
        for r in res:
            lines.append(f"{pad}    - {yaml_resource(r)}")
    return lines


def build_policy_block(role, statements):
    lines = [
        "        # ENC-ISS-313 / ENC-TSK-G95: grants applied out-of-band by the tombstoned",
        "        # per-Lambda deploy.sh ensure_role() (dropped by matrix-build migration",
        "        # ENC-TSK-G43), codified here from the live IAM dump. Each statement is",
        "        # proven to resolve identically to prod-live (EnvironmentSuffix='') and",
        "        # gamma-live (EnvironmentSuffix='-gamma'). See tools/iam-audit/.",
        "        - PolicyName: G95RestoredGrants",
        "          PolicyDocument:",
        "            Version: '2012-10-17'",
        "            Statement:",
    ]
    for st in statements:
        lines += render_statement(st, 14)
    return "\n".join(lines)


def main():
    data = json.load(open("tools/iam-audit/codify-snippets-20260617.json"))
    snippets = data["snippets"]
    text = open(TPL).read()
    lines = text.split("\n")

    # find each role's `  Logical:` header line and the next `      Tags:` line
    header_idx = {}
    for i, ln in enumerate(lines):
        m = re.match(r"^  ([A-Za-z0-9]+):\s*$", ln)
        if m:
            header_idx[m.group(1)] = i

    inserts = []  # (line_index_to_insert_before, block_text)
    spliced = []
    for role, statements in snippets.items():
        logical = LOGICAL.get(role)
        if not logical or logical not in header_idx:
            print(f"SKIP (no logical/header): {role}")
            continue
        start = header_idx[logical]
        # find next role header to bound search
        ends = [v for v in header_idx.values() if v > start]
        bound = min(ends) if ends else len(lines)
        if "G95RestoredGrants" in "\n".join(lines[start:bound]):
            print(f"SKIP (already present): {role}")
            continue
        pol_i = None
        for j in range(start, bound):
            if lines[j] == "      Policies:":
                pol_i = j
                break
        if pol_i is None:
            print(f"SKIP (no Policies anchor): {role}")
            continue
        # insert as the first item right after the `Policies:` line
        inserts.append((pol_i + 1, build_policy_block(role, statements)))
        spliced.append(f"{logical}({role}): {len(statements)} stmts")

    # apply inserts bottom-up so indices stay valid
    for idx, block in sorted(inserts, key=lambda x: -x[0]):
        lines[idx:idx] = block.split("\n")

    open(TPL, "w").write("\n".join(lines))
    print("SPLICED:")
    for s in spliced:
        print("  ", s)


if __name__ == "__main__":
    main()
