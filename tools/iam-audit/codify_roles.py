#!/usr/bin/env python3
"""ENC-TSK-G95 / ENC-ISS-313 — generate parameterized CFN inline-policy additions
for the drifted roles, PROVEN faithful against both prod-live and gamma-live.

For each role, for each live statement that introduces an IAM action absent from the
current CFN declaration, emit a CFN statement whose resources are parameterized as:
  356364570033 -> ${AWS::AccountId},  us-west-2 -> ${AWS::Region},  -gamma -> ${EnvironmentSuffix}
A statement is ACCEPTED only if the parameterized resource template resolves EXACTLY to
prod-live (suffix='') and to gamma-live (suffix='-gamma'). Statements that cannot be
proven (prod-only, no gamma counterpart, or non-suffix divergence) are flagged
NEEDS_REVIEW and NOT emitted automatically.

Output: tools/iam-audit/codify-report-20260617.md  + per-role YAML snippets dict (json).
"""
import json
import re

import yaml

PROD = json.load(open("tools/iam-audit/live-iam-dump-20260617.json"))["roles"]
GAMMA = json.load(open("tools/iam-audit/live-iam-dump-gamma-20260617.json"))["roles"]
DIFF = {f["role"]: f for f in json.load(open("tools/iam-audit/cfn-vs-live-diff-20260617.json"))["findings"]}

ACCT = "356364570033"
REGION = "us-west-2"

# prod role -> gamma role
GMAP = lambda r: r + "-gamma"

# roles already codified by hand (graph regression) + CFN-only role -> skip auto
SKIP = {"devops-graph-sync-lambda-role", "devops-graph-query-api-lambda-role",
        "devops-deploy-parity-validator-role"}


def stmt_list(doc):
    if not isinstance(doc, dict):
        return []
    s = doc.get("Statement", [])
    return s if isinstance(s, list) else [s]


def all_live_statements(inline_policies):
    out = []
    for pname, doc in (inline_policies or {}).items():
        for st in stmt_list(doc):
            if isinstance(st, dict):
                out.append((pname, st))
    return out


def actions_of(st):
    a = st.get("Action", [])
    a = a if isinstance(a, list) else [a]
    return [x.lower() for x in a if isinstance(x, str)]


def norm_acct_region(s):
    return s.replace(ACCT, "${AWS::AccountId}").replace(REGION, "${AWS::Region}")


def resources_of(st):
    r = st.get("Resource", [])
    return r if isinstance(r, list) else [r]


def resolve(tmpl, suffix):
    return (tmpl.replace("${AWS::AccountId}", ACCT)
                .replace("${AWS::Region}", REGION)
                .replace("${EnvironmentSuffix}", suffix))


def parameterize_resource(p_res, g_res):
    """Return (param_template, proven_bool). param_template uses ${...} tokens."""
    p = norm_acct_region(p_res)
    if g_res is None:
        # prod-only: tokenize acct/region; cannot prove suffix -> not proven
        proven = (resolve(p, "") == p_res)  # at least prod-faithful with acct/region only
        return p, False if "${EnvironmentSuffix}" not in p else False
    g = norm_acct_region(g_res)
    if p == g:
        return p, (resolve(p, "") == p_res and resolve(p, "-gamma") == g_res)
    # differ -> assume the difference is the -gamma token in gamma string
    t = g.replace("-gamma", "${EnvironmentSuffix}")
    proven = (resolve(t, "") == p_res and resolve(t, "-gamma") == g_res)
    return t, proven


def match_gamma_stmt(p_st, gamma_stmts):
    psid = p_st.get("Sid")
    if psid:
        for _, g in gamma_stmts:
            if g.get("Sid") == psid:
                return g
    pa = set(actions_of(p_st))
    for _, g in gamma_stmts:
        if set(actions_of(g)) == pa:
            return g
    return None


def main():
    report = ["# ENC-TSK-G95 — bulk-role codification report (2026-06-17)\n",
              "Parameterization proven against prod-live (suffix='') AND gamma-live (suffix='-gamma').\n"]
    snippets = {}
    needs_review = {}
    for role, f in DIFF.items():
        if role in SKIP:
            continue
        missing = set(f.get("actions_missing_in_cfn", []))
        if not missing:
            continue
        p_inline = PROD[role]["inline_policies"]
        g_inline = GAMMA.get(GMAP(role), {}).get("inline_policies", {})
        gamma_stmts = all_live_statements(g_inline)
        emit_stmts = []
        review_stmts = []
        seen = set()
        for pname, st in all_live_statements(p_inline):
            sacts = actions_of(st)
            if not (missing & set(sacts)):
                continue  # statement adds nothing new
            sig = (st.get("Sid"), tuple(sorted(sacts)))
            if sig in seen:
                continue
            seen.add(sig)
            g_st = match_gamma_stmt(st, gamma_stmts)
            param_resources = []
            proven_all = True
            for pr in resources_of(st):
                gr = None
                if g_st is not None:
                    g_resources = resources_of(g_st)
                    # pair by index when counts match, else by acct/region-normalized stem
                    gr = g_resources[0] if len(g_resources) == 1 else None
                    if gr is None:
                        for cand in g_resources:
                            if norm_acct_region(cand).replace("-gamma", "") == norm_acct_region(pr):
                                gr = cand
                                break
                tmpl, proven = parameterize_resource(pr, gr)
                param_resources.append(tmpl)
                proven_all = proven_all and proven
            entry = {
                "Sid": st.get("Sid", ""),
                "Action": sacts_original(st),
                "Resource": param_resources,
                "src_policy": pname,
                "proven_dual_env": proven_all,
            }
            (emit_stmts if proven_all else review_stmts).append(entry)
        if emit_stmts:
            snippets[role] = emit_stmts
        if review_stmts:
            needs_review[role] = review_stmts
        report.append(f"## {role}")
        report.append(f"  - missing actions: {sorted(missing)}")
        report.append(f"  - PROVEN statements (auto-codify): {[e['Sid'] or e['Action'] for e in emit_stmts]}")
        if review_stmts:
            report.append(f"  - NEEDS REVIEW (not auto-emitted): {[(e['Sid'], e['Resource']) for e in review_stmts]}")
        report.append("")
    json.dump({"snippets": snippets, "needs_review": needs_review},
              open("tools/iam-audit/codify-snippets-20260617.json", "w"), indent=2)
    open("tools/iam-audit/codify-report-20260617.md", "w").write("\n".join(report))
    print("\n".join(report))
    print(f"\nPROVEN roles: {len(snippets)}; roles with NEEDS_REVIEW statements: {len(needs_review)}")


def sacts_original(st):
    a = st.get("Action", [])
    return a if isinstance(a, list) else [a]


if __name__ == "__main__":
    main()
