#!/usr/bin/env python3
"""ENC-TSK-O46 / ENC-ISS-649 — mechanical CFN transcription for the 7 gap roles.

Partially supersedes codify_roles.py for this class of problem: codify_roles.py
computes a DIFF and emits ADDITIONS to an EXISTING CFN role declaration. The 7
gap roles have no existing CFN declaration at all -- there is nothing to diff
against. This script instead transcribes each role's live-dumped state (from
dump_live_iam.py) directly into a fresh AWS::IAM::Role resource.

PURELY MECHANICAL. No diffing, no inference, no invented policy content.

For each of the 3 paired roles (prod + -gamma both live, same functional
purpose), each inline policy is independently tested for a parameterized
round-trip: substitute ${AWS::AccountId}/${AWS::Region} everywhere, and
${EnvironmentSuffix} ONLY where doing so is consistent with the role's own
plane suffixing convention -- then render the template with
EnvironmentSuffix='' and EnvironmentSuffix='-gamma' and diff byte-for-byte
against the two live-dumped statement lists. A statement/policy that does not
round-trip is emitted LITERAL (unparameterized, exact live content) rather
than smoothed over, and flagged in the report.

The 4th role (devops-json-parquet-lambda) has no -gamma counterpart at all
(verified separately: no such live role, no live function referencing it) and
is emitted as a single Condition: IsProduction resource with literal names --
parameterizing a resource that only exists on one plane would produce a
template that either fails gamma import (no live counterpart) or CREATEs a
role on gamma that should not exist there.

Usage: python3 tools/iam-audit/transcribe_gap_roles.py \
         tools/iam-audit/live-iam-dump-20260822.json \
         > tools/iam-audit/gap-roles-20260822.yaml
       (report goes to stderr)
"""
import json
import sys

ACCT = "356364570033"
REGION = "us-west-2"

PAIRS = [
    # (logical_id, prod_role, gamma_role)
    ("GithubIntegrationLambdaRole", "devops-github-integration-lambda-role", "devops-github-integration-lambda-role-gamma"),
    ("TitanEmbeddingBackfillLambdaRole", "devops-titan-embedding-backfill-lambda-role", "devops-titan-embedding-backfill-lambda-role-gamma"),
    ("CheckoutServiceRole", "enceladus-checkout-service-role", "enceladus-checkout-service-role-gamma"),
]
SINGLETON = ("JsonParquetLambdaRole", "devops-json-parquet-lambda")

# Policies already declared as separate CFN resources elsewhere in the template
# (attached via Roles: [!Sub ...]) -- must NOT be re-declared inline on the role
# or CFN would manage the same live inline policy from two resources at once.
ALREADY_CFN_MANAGED = {
    "enceladus-checkout-service-role-gamma": {"AgentSessionsGammaAccessCfn"},
}


def sub_acct_region(s):
    return s.replace(ACCT, "${AWS::AccountId}").replace(REGION, "${AWS::Region}")


def unsub_for_plane(template_str, suffix):
    return (
        template_str.replace("${AWS::AccountId}", ACCT)
        .replace("${AWS::Region}", REGION)
        .replace("${EnvironmentSuffix}", suffix)
    )


def try_parameterize_value(v, prod_suffix_literal, gamma_suffix_literal):
    """Return a parameterized string form of v, substituting EnvironmentSuffix
    only where v's prod form vs gamma form differ by exactly that literal
    suffix. Returns None if v is not a plane-suffixable string at all (no
    ${EnvironmentSuffix} needed) -- caller falls back to plain acct/region sub."""
    if gamma_suffix_literal in v and prod_suffix_literal not in v:
        return sub_acct_region(v).replace(gamma_suffix_literal, "${EnvironmentSuffix}" + gamma_suffix_literal.replace("-gamma", ""))
    return None


def round_trip_ok(param_doc, prod_doc, gamma_doc):
    prod_render = json.loads(unsub_for_plane(json.dumps(param_doc), ""))
    gamma_render = json.loads(unsub_for_plane(json.dumps(param_doc), "-gamma"))
    return prod_render == prod_doc and gamma_render == gamma_doc


def parameterize_statement(prod_stmt, gamma_stmt):
    """Attempt a per-field parameterization of one statement pair. Returns
    (param_stmt, ok) where ok=True only if the round-trip is byte-exact."""
    param = json.loads(json.dumps(prod_stmt))  # start from prod, deep copy

    def param_resource(r):
        r2 = sub_acct_region(r)
        # Only substitute EnvironmentSuffix where the gamma resource literally
        # differs from prod by a "-gamma" token appended to this exact resource.
        return r2

    if "Resource" in param:
        res = param["Resource"]
        if isinstance(res, str):
            param["Resource"] = sub_acct_region(res)
        elif isinstance(res, list):
            param["Resource"] = [sub_acct_region(r) for r in res]

    # Try EnvironmentSuffix substitution on resource strings that differ
    # between prod/gamma by a trailing/embedded "-gamma".
    def find_suffix_diff(pr, ga):
        if isinstance(pr, str) and isinstance(ga, str) and ga != pr:
            # gamma resource = prod resource with "-gamma" inserted somewhere
            if ga.replace("-gamma", "") == pr:
                idx = ga.index("-gamma")
                return pr[:idx] + "${EnvironmentSuffix}" + pr[idx:] if idx <= len(pr) else None
        return None

    if "Resource" in prod_stmt and "Resource" in gamma_stmt:
        pr, ga = prod_stmt["Resource"], gamma_stmt["Resource"]
        if isinstance(pr, str) and isinstance(ga, str):
            templ = find_suffix_diff(sub_acct_region(pr), sub_acct_region(ga))
            if templ:
                param["Resource"] = templ

    ok = round_trip_ok(param, prod_stmt, gamma_stmt)
    return param, ok


def build_policy_map(role_data):
    return {name: role_data["inline_policies"][name] for name in role_data["inline_policy_names"]}


def match_policy_names(prod_names, gamma_names):
    """Return list of (prod_name_or_None, gamma_name_or_None). Matches by
    identical name, or gamma_name == prod_name + '-gamma'."""
    matched = []
    gamma_remaining = set(gamma_names)
    for pn in prod_names:
        if pn in gamma_remaining:
            matched.append((pn, pn))
            gamma_remaining.discard(pn)
        elif pn + "-gamma" in gamma_remaining:
            matched.append((pn, pn + "-gamma"))
            gamma_remaining.discard(pn + "-gamma")
        else:
            matched.append((pn, None))
    for gn in gamma_remaining:
        matched.append((None, gn))
    return matched


def render_policy_document_yaml_dict(doc):
    return doc  # already plain-JSON-compatible; pyyaml will render it


def build_pair_role(logical_id, prod_role, gamma_role, roles, report):
    p = roles[prod_role]
    g = roles[gamma_role]
    excluded_prod = ALREADY_CFN_MANAGED.get(prod_role, set())
    excluded_gamma = ALREADY_CFN_MANAGED.get(gamma_role, set())
    prod_names = [n for n in p["inline_policy_names"] if n not in excluded_prod]
    gamma_names = [n for n in g["inline_policy_names"] if n not in excluded_gamma]
    if excluded_prod or excluded_gamma:
        report.append(f"{logical_id}: excluded already-CFN-managed policies "
                       f"prod={sorted(excluded_prod)} gamma={sorted(excluded_gamma)}")

    prod_docs = build_policy_map(p)
    gamma_docs = build_policy_map(g)
    matches = match_policy_names(prod_names, gamma_names)

    policies_yaml = []
    literal_conditional = []
    for pn, gn in matches:
        if pn and gn:
            prod_doc = prod_docs[pn]
            gamma_doc = gamma_docs[gn]
            if pn == gn:
                # Same name both planes -- try whole-document round trip with
                # only acct/region substitution (no suffix needed in the name
                # or, hopefully, the content).
                param_doc = json.loads(sub_acct_region(json.dumps(prod_doc)))
                stmts_ok = True
                param_stmts = []
                for i, (ps, gs) in enumerate(zip(prod_doc.get("Statement", []), gamma_doc.get("Statement", []))):
                    ps_param, ok = parameterize_statement(ps, gs)
                    param_stmts.append(ps_param)
                    stmts_ok = stmts_ok and ok
                if stmts_ok and len(prod_doc.get("Statement", [])) == len(gamma_doc.get("Statement", [])):
                    policies_yaml.append({
                        "PolicyName": pn,
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": param_stmts},
                    })
                    report.append(f"{logical_id}/{pn}: parameterized clean (round-trip verified)")
                else:
                    report.append(f"{logical_id}/{pn}: round-trip FAILED -- emitting LITERAL per-plane (Fn::If)")
                    literal_conditional.append((pn, prod_doc, gamma_doc))
            else:
                # Name itself differs by -gamma suffix.
                base = pn
                param_stmts = []
                stmts_ok = True
                for ps, gs in zip(prod_doc.get("Statement", []), gamma_doc.get("Statement", [])):
                    ps_param, ok = parameterize_statement(ps, gs)
                    param_stmts.append(ps_param)
                    stmts_ok = stmts_ok and ok
                if stmts_ok and len(prod_doc.get("Statement", [])) == len(gamma_doc.get("Statement", [])):
                    policies_yaml.append({
                        "PolicyName": {"Fn::Sub": f"{base}${{EnvironmentSuffix}}"},
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": param_stmts},
                    })
                    report.append(f"{logical_id}/{base}(+gamma suffix on name): parameterized clean (round-trip verified)")
                else:
                    report.append(f"{logical_id}/{pn}<->{gn}: round-trip FAILED -- emitting LITERAL per-plane (Fn::If)")
                    literal_conditional.append((pn, prod_doc, gamma_doc, gn))
        elif pn and not gn:
            report.append(f"{logical_id}/{pn}: PROD-ONLY, no gamma counterpart -- emitting literal, Condition: IsProduction")
            literal_conditional.append((pn, prod_docs[pn], None))
        elif gn and not pn:
            report.append(f"{logical_id}/{gn}: GAMMA-ONLY, no prod counterpart -- emitting literal, Condition: IsGamma")
            literal_conditional.append((gn, None, gamma_docs[gn]))

    return policies_yaml, literal_conditional, p, g


def emit_role_yaml(lines, logical_id, base_name, assume_doc, managed_arns, policies_yaml,
                    literal_conditional, condition=None, singleton_literal_name=None):
    lines.append(f"  {logical_id}:")
    lines.append("    Type: AWS::IAM::Role")
    lines.append("    DeletionPolicy: Retain")
    lines.append("    UpdateReplacePolicy: Retain")
    if condition:
        lines.append(f"    Condition: {condition}")
    lines.append("    Properties:")
    if singleton_literal_name:
        lines.append(f'      RoleName: "{singleton_literal_name}"')
    else:
        lines.append(f'      RoleName: !Sub "{base_name}${{EnvironmentSuffix}}"')
    lines.append("      AssumeRolePolicyDocument:")
    _yaml_block(lines, assume_doc, 8)
    if managed_arns:
        lines.append("      ManagedPolicyArns:")
        for arn in managed_arns:
            lines.append(f"        - {arn}")
    all_policies = list(policies_yaml)
    if all_policies or literal_conditional:
        lines.append("      Policies:")
        for pol in policies_yaml:
            pn = pol["PolicyName"]
            if isinstance(pn, dict):
                lines.append(f'        - PolicyName: !Sub "{pn["Fn::Sub"]}"')
            else:
                lines.append(f'        - PolicyName: "{pn}"')
            lines.append("          PolicyDocument:")
            _yaml_block(lines, pol["PolicyDocument"], 12)
        for item in literal_conditional:
            if len(item) == 3 and item[2] is None:
                # prod-only literal
                name, doc, _ = item
                lines.append("        - !If")
                lines.append("          - IsProduction")
                lines.append("          - PolicyName: " + f'"{name}"')
                lines.append("            PolicyDocument:")
                _yaml_block(lines, doc, 14)
                lines.append("          - !Ref AWS::NoValue")
            elif len(item) == 3 and item[1] is None:
                # gamma-only literal
                name, _, doc = item
                lines.append("        - !If")
                lines.append("          - IsGamma")
                lines.append("          - PolicyName: " + f'"{name}"')
                lines.append("            PolicyDocument:")
                _yaml_block(lines, doc, 14)
                lines.append("          - !Ref AWS::NoValue")
            else:
                # same-name round-trip failure: literal per-plane via Fn::If
                if len(item) == 3:
                    name, prod_doc, gamma_doc = item
                    gname = name
                else:
                    name, prod_doc, gamma_doc, gname = item
                lines.append("        - !If")
                lines.append("          - IsGamma")
                lines.append(f'          - PolicyName: "{gname}"')
                lines.append("            PolicyDocument:")
                _yaml_block(lines, gamma_doc, 14)
                lines.append("          - PolicyName: " + f'"{name}"')
                lines.append("            PolicyDocument:")
                _yaml_block(lines, prod_doc, 12)
    lines.append("")


def wrap_sub_strings(obj):
    """Any string containing '${' must be wrapped in Fn::Sub for CFN to
    actually substitute it -- a bare scalar containing '${...}' is a literal
    string to CloudFormation, not a substitution (cfn-lint E1029)."""
    if isinstance(obj, dict):
        return {k: wrap_sub_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [wrap_sub_strings(v) for v in obj]
    if isinstance(obj, str) and "${" in obj:
        return {"Fn::Sub": obj}
    return obj


class _SubDumper(__import__("yaml").Dumper):
    pass


def _sub_representer(dumper, data):
    if list(data.keys()) == ["Fn::Sub"]:
        return dumper.represent_scalar("!Sub", data["Fn::Sub"])
    return dumper.represent_mapping("tag:yaml.org,2002:map", data)


_SubDumper.add_representer(dict, _sub_representer)


def _yaml_block(lines, obj, indent):
    obj = wrap_sub_strings(obj)
    text = __import__("yaml").dump(obj, Dumper=_SubDumper, default_flow_style=False, sort_keys=False)
    pad = " " * indent
    for line in text.rstrip("\n").split("\n"):
        lines.append(pad + line if line else line)


def main():
    dump_path = sys.argv[1]
    d = json.load(open(dump_path))
    roles = d["roles"]
    report = []
    lines = ["Resources:"]

    for logical_id, prod_role, gamma_role in PAIRS:
        policies_yaml, literal_conditional, p, g = build_pair_role(logical_id, prod_role, gamma_role, roles, report)
        base_name = prod_role
        managed_arns = p["attached_policy_arns"]
        if managed_arns != g["attached_policy_arns"]:
            report.append(f"{logical_id}: WARNING attached_policy_arns differ prod={managed_arns} gamma={g['attached_policy_arns']} -- using prod set, verify manually")
        emit_role_yaml(lines, logical_id, base_name, p["assume_role_policy_document"], managed_arns, policies_yaml, literal_conditional)

    sid, prod_role = SINGLETON
    p = roles[prod_role]
    report.append(f"{sid}: SINGLETON (verified no live -gamma counterpart, no live function references one) -- Condition: IsProduction, literal RoleName")
    policies_yaml = [{"PolicyName": n, "PolicyDocument": p["inline_policies"][n]} for n in p["inline_policy_names"]]
    for pol in policies_yaml:
        pol["PolicyDocument"] = json.loads(sub_acct_region(json.dumps(pol["PolicyDocument"])))
    emit_role_yaml(lines, sid, prod_role, p["assume_role_policy_document"], p["attached_policy_arns"],
                   policies_yaml, [], condition="IsProduction", singleton_literal_name=prod_role)

    print("\n".join(lines))
    print("\n".join(f"# {r}" for r in report), file=sys.stderr)


if __name__ == "__main__":
    main()
