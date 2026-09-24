#!/usr/bin/env python3
"""ENC-TSK-O99 / ENC-ISS-660: CloudFormation deploy-role reach guard.

THE GAP THIS CLOSES. Nothing in CI had any notion of IAM REACH. A PR could
introduce a brand-new AWS resource TYPE, pass the arch-parity guard, the
governance dictionary guard, the PR commit gate and the pre-deploy health gate
-- all green -- merge, and then fail at apply. CloudFormation's response to a
failed create is a ROLLBACK, and a rollback reverts unrelated in-flight
parameter changes along with it.

That is not hypothetical. On 2026-08-23 ENC-TSK-O80 declared an
AWS::Glue::Database; the deploy role holds no Glue permissions. The create
failed, the stack rolled back, and the rollback restored SharedLayerArn to the
stack's stored :10 -- performing exactly the fleet downgrade the health gate
had just refused (ENC-ISS-656). A correct fix was undone by an unrelated IAM
gap in a resource that landed minutes earlier.

A DRY-RUN CHANGE-SET DOES NOT SUBSTITUTE. Change-set CREATION succeeds
regardless of execution-time permissions -- which is exactly why run
32617957788's Plan job was green and its Apply job was not.

WHY A COMMITTED MAP AND NOT LIVE INTROSPECTION. ENC-ISS-660 offers both. Live
introspection is not available: enceladus-agent-cli is explicitly denied
iam:ListRolePolicies / iam:GetRolePolicy, and giving CI a privileged reader
would mean handing the pre-merge lane an IAM-read credential to answer a
question the repo can already answer about itself. So the guard reads the
GRANTS from the committed sources that define them -- 04-github-roles.yaml plus
the checked-in iam-cfn-deploy-role-*.yml patch workflows -- and only the
per-TYPE facts (which IAM action creates it, what its ARN looks like) come from
a hand-maintained map. Consequence that matters: widening the deploy role in a
PR updates what this guard permits automatically, in the same diff. There is no
second ledger to drift.

TWO TIERS, AND THE SECOND ONE IS WHY THIS ISN'T JUST A TYPE LIST.

  Tier 1 (every resource, fail-closed): the resource's TYPE must appear in
  tools/cfn_deploy_role_reach_map.json. A template introducing an unclassified
  type fails the PR. This is the Glue case.

  Tier 2 (types the map gives an `arn` shape): the resource's rendered ARN must
  match a resource pattern the role is actually granted the create action on.
  This tier is not optional decoration -- ENC-TSK-O98's audit found that
  ENC-TSK-O80's AWS::Scheduler::Schedule was of an ALREADY-ALLOWED type and
  still unreachable, because it sets no GroupName and so lands at
  schedule/default/... while every grant was scoped to schedule/rhythm-*/* and
  schedule/enceladus-*/*. A type-only guard passes that and the stack rolls
  back a second time.

CONDITION AWARENESS. A resource's Condition decides which planes it can be
created on, so it decides which ARNs must be reachable. An IsGamma resource is
checked only against its -gamma rendering; an IsProduction resource only
against its production rendering. This is what lets a deliberately gamma-only
grant (ENC-TSK-O98) be judged correct rather than incomplete -- and it means a
resource that quietly loses its IsGamma condition starts requiring production
reach, and says so.

COVERAGE IS REPORTED, NEVER SILENT. ENC-ISS-660's own words: a check that does
not enumerate cannot report what it failed to consider. The summary always
states how many resources got tier-2 and how many got tier-1 only, so the
limits of this guard are visible in the log rather than mistaken for a clean
bill of health.

Exit 0 = every resource classified and every tier-2 resource reachable.
Exit 1 = at least one violation (each named with file, logical id, type, ARN).
Exit 2 = the guard could not run (missing dependency or malformed input).
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required (pip install pyyaml)")
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
CFN_DIR = REPO_ROOT / "infrastructure" / "cloudformation"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
MAP_PATH = REPO_ROOT / "tools" / "cfn_deploy_role_reach_map.json"

ACCOUNT_ID = "356364570033"
REGION = "us-west-2"
DEPLOY_ROLE_LOGICAL_ID = "CloudFormationDeployRole"
DEPLOY_ROLE_NAME = "enceladus-cloudformation-deploy-github-role"

# The templates this role deploys, per the cloudformation-*-stack-deploy.yml
# workflows. Deliberately explicit rather than a glob: 04-github-roles.yaml
# defines the role itself and is not deployed by it, and the *-import-stage-*
# copies are frozen point-in-time artifacts for resource imports.
GOVERNED_TEMPLATES = [
    "01-data.yaml",
    "02-compute.yaml",
    "03-api.yaml",
    "05-monitoring.yaml",
    "06-appsync-events.yaml",
    "06-feature-flags.yaml",
    "07-codedeploy.yaml",
    "07-ui-cdn.yaml",
    "08-agent-auth.yaml",
    # 08-lambda-artifacts-staging.yaml is deliberately absent: no workflow
    # deploys it, so it is not part of this role's reach surface. Re-add it
    # here the moment a deploy lane picks it up.
    "09-appconfig-governance.yaml",
    "10-opensearch-node.yaml",
    "11-appconfig-rhythm-tenants.yaml",
]

# EnvironmentSuffix renderings per plane. A resource's Condition selects which
# of these it must be reachable under.
PLANES = {"production": "", "gamma": "-gamma"}

CONDITION_PLANES = {
    "IsProduction": ["production"],
    "IsGamma": ["gamma"],
}


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that keeps CloudFormation short-form tags addressable.

    !Sub / !Ref / !GetAtt are preserved as {"Fn::Sub": ...} style dicts so the
    name renderer can recognise them, instead of being flattened to opaque
    strings the way a bare multi_constructor would.
    """


def _cfn_multi_constructor(loader, tag_suffix, node):
    name = "Fn::" + tag_suffix if tag_suffix != "Ref" else "Ref"
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if tag_suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".")
    return {name: value}


CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def load_template(path: Path) -> dict:
    with path.open() as handle:
        return yaml.load(handle, Loader=CfnLoader) or {}


# --------------------------------------------------------------------------
# 1. Derive what the deploy role is actually granted, from committed sources.
# --------------------------------------------------------------------------

def _normalise(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _resolve_pseudo(text: str) -> str:
    return (
        text.replace("${AWS::AccountId}", ACCOUNT_ID)
        .replace("${AWS::Region}", REGION)
        .replace("${AWS::Partition}", "aws")
        # The patch workflows interpolate the account with bash, not CFN.
        .replace("${ACCOUNT_ID}", ACCOUNT_ID)
    )


def _flatten_resource(value) -> list[str]:
    """Render a statement Resource entry to plain ARN pattern strings."""
    out = []
    for entry in _normalise(value):
        if isinstance(entry, str):
            out.append(_resolve_pseudo(entry))
        elif isinstance(entry, dict):
            sub = entry.get("Fn::Sub")
            if isinstance(sub, str):
                out.append(_resolve_pseudo(sub))
            elif isinstance(sub, list) and sub and isinstance(sub[0], str):
                out.append(_resolve_pseudo(sub[0]))
            # Anything else (Ref/GetAtt to a stack resource) cannot be rendered
            # statically. Treated as no-reach rather than as a wildcard: this
            # guard must never invent permission it cannot prove.
    return out


def collect_granted_statements() -> tuple[list[dict], list[str]]:
    """Every Allow statement attached to the CFN deploy role, from committed sources.

    Sources, both required: 04-github-roles.yaml (the role's inline policies
    plus any ManagedPolicy naming it in Roles) and the iam-*patch*.yml dispatch
    workflows, which apply grants live ahead of a github-roles stack deploy and
    are therefore part of the role's real reach.
    """
    statements: list[dict] = []
    sources: list[str] = []

    roles_path = CFN_DIR / "04-github-roles.yaml"
    template = load_template(roles_path)
    resources = template.get("Resources") or {}

    role = resources.get(DEPLOY_ROLE_LOGICAL_ID) or {}
    for policy in _normalise((role.get("Properties") or {}).get("Policies")):
        doc = (policy or {}).get("PolicyDocument") or {}
        statements.extend(_normalise(doc.get("Statement")))
    sources.append(f"{roles_path.name}:{DEPLOY_ROLE_LOGICAL_ID} inline policies")

    for logical_id, resource in resources.items():
        if resource.get("Type") != "AWS::IAM::ManagedPolicy":
            continue
        props = resource.get("Properties") or {}
        attached = [
            r.get("Ref") if isinstance(r, dict) else r
            for r in _normalise(props.get("Roles"))
        ]
        if DEPLOY_ROLE_LOGICAL_ID not in attached:
            continue
        doc = props.get("PolicyDocument") or {}
        statements.extend(_normalise(doc.get("Statement")))
        sources.append(f"{roles_path.name}:{logical_id} (managed)")

    for workflow in sorted(WORKFLOWS_DIR.glob("iam-*.yml")):
        text = workflow.read_text()
        if DEPLOY_ROLE_NAME not in text:
            continue
        found = False
        for block in re.findall(r"<<\s*'?JSON'?\n(.*?)\n\s*JSON\b", text, re.S):
            dedented = re.sub(r"^\s{0,20}", "", block, flags=re.M)
            try:
                doc = json.loads(dedented)
            except json.JSONDecodeError:
                continue
            statements.extend(_normalise(doc.get("Statement")))
            found = True
        if found:
            sources.append(workflow.name)

    allows = [
        s for s in statements
        if isinstance(s, dict) and s.get("Effect", "Allow") == "Allow"
    ]
    return allows, sources


def action_allowed_on(statements: list[dict], action: str, arn: str) -> bool:
    """True when some Allow statement grants `action` on `arn`.

    Deliberately ignores explicit Deny: the deploy role's committed policies
    carry none, and silently modelling a Deny we have not seen would make this
    guard claim precision it does not have. If a Deny is ever added to these
    sources, this function must learn about it -- the accompanying test asserts
    the sources are Deny-free so that day cannot pass unnoticed.
    """
    for statement in statements:
        actions = [a.lower() for a in _normalise(statement.get("Action"))]
        if not any(
            fnmatch.fnmatchcase(action.lower(), pattern) for pattern in actions
        ):
            continue
        for resource in _flatten_resource(statement.get("Resource")):
            if resource == "*" or fnmatch.fnmatchcase(arn, resource):
                return True
    return False


# --------------------------------------------------------------------------
# 2. Render each template resource's physical name and ARN.
# --------------------------------------------------------------------------

def render_name(value, suffix: str) -> str | None:
    """Render a name property to a literal string for one plane, or None.

    None means "not statically derivable" -- a Ref/GetAtt to another resource,
    or a Sub over parameters this guard does not model. Those resources fall
    back to tier 1 and are counted in the coverage summary rather than guessed
    at.
    """
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict) and isinstance(value.get("Fn::Sub"), str):
        text = value["Fn::Sub"]
    else:
        return None
    text = text.replace("${EnvironmentSuffix}", suffix)
    text = _resolve_pseudo(text)
    if "${" in text:
        return None
    return text


def _dig(props: dict, path: str):
    """Look up a possibly-dotted property path (e.g. DatabaseInput.Name)."""
    if not path:
        return None
    current = props
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _resolve_reference(value, suffix: str, resources: dict, types_map: dict) -> str | None:
    """Render a value that may be a literal, a Sub, or a Ref to a sibling resource.

    A Ref to another resource in the same template resolves to that resource's
    own physical name, using the name_property the map records for its type.
    That is how `GroupName: !Ref RhythmSenseGroup` becomes `rhythm-sense-gamma`
    rather than being mistaken for the default schedule group.
    """
    direct = render_name(value, suffix)
    if direct is not None:
        return direct
    if isinstance(value, dict) and isinstance(value.get("Ref"), str):
        target = resources.get(value["Ref"])
        if isinstance(target, dict):
            spec = types_map.get(target.get("Type")) or {}
            target_props = target.get("Properties") or {}
            for prop in _normalise(spec.get("name_property")):
                found = _dig(target_props, prop)
                if found is not None:
                    return render_name(found, suffix)
    return None


def planes_for(condition: str | None) -> list[str]:
    if condition is None:
        return list(PLANES)
    return CONDITION_PLANES.get(condition, list(PLANES))


def main() -> int:
    if not MAP_PATH.exists():
        print(f"::error::missing reach map: {MAP_PATH}")
        return 2
    reach_map = json.loads(MAP_PATH.read_text())
    types_map = reach_map.get("types") or {}

    statements, sources = collect_granted_statements()
    if not statements:
        print("::error::derived zero Allow statements for the CFN deploy role -- "
              "the policy sources moved or changed shape; refusing to pass.")
        return 2

    raw_exceptions = reach_map.get("exceptions") or []
    exceptions = {
        (e["template"], e["logical_id"], e["action"], e["arn"]): e
        for e in raw_exceptions
    }
    matched_exceptions: set[tuple] = set()

    violations: list[str] = []
    tier2_checked = 0
    tier1_only = 0
    total = 0

    for filename in GOVERNED_TEMPLATES:
        path = CFN_DIR / filename
        if not path.exists():
            # Branch-specific templates (main vs v4/main) legitimately differ.
            continue
        template = load_template(path)
        for logical_id, resource in (template.get("Resources") or {}).items():
            if not isinstance(resource, dict):
                continue
            rtype = resource.get("Type")
            if not isinstance(rtype, str) or not rtype.startswith("AWS::"):
                continue
            total += 1

            spec = types_map.get(rtype)
            if spec is None:
                violations.append(
                    f"{filename}:{logical_id} declares {rtype}, which is NOT in "
                    f"{MAP_PATH.name}. Classify it -- confirm the CFN deploy role can "
                    f"create, update and delete this type, add the grant if it cannot, "
                    f"then add the type to the map. An unclassified type is how "
                    f"ENC-ISS-660's rollback happened."
                )
                continue

            arn_shape = spec.get("arn")
            if not arn_shape:
                tier1_only += 1
                continue

            props = resource.get("Properties") or {}
            name = None
            for prop in _normalise(spec.get("name_property")):
                found = _dig(props, prop)
                if found is not None:
                    name = found
                    break
            if name is None:
                tier1_only += 1
                continue

            checked_any = False
            for plane in planes_for(resource.get("Condition")):
                suffix = PLANES[plane]
                rendered = render_name(name, suffix)
                if rendered is None:
                    continue
                fields = {
                    "account": ACCOUNT_ID,
                    "region": REGION,
                    "name": rendered,
                }
                unresolved = False
                for extra, default in (spec.get("extra_fields") or {}).items():
                    prop_value = _dig(props, spec.get("extra_properties", {}).get(extra, ""))
                    if prop_value is None:
                        fields[extra] = default
                        continue
                    resolved = _resolve_reference(
                        prop_value, suffix, template.get("Resources") or {}, types_map
                    )
                    if resolved is None:
                        # Present but not statically derivable. Falling back to
                        # the default here would invent an ARN and report a
                        # violation that does not exist -- the rhythm schedules
                        # all carry GroupName: !Ref, and defaulting them to the
                        # `default` group manufactured ten false positives on
                        # the first run of this guard. Drop to tier 1 instead.
                        unresolved = True
                        break
                    fields[extra] = resolved
                if unresolved:
                    continue
                arn = arn_shape.format(**fields)
                checked_any = True
                for action in spec.get("create_actions") or []:
                    if action_allowed_on(statements, action, arn):
                        continue
                    key = (filename, logical_id, action, arn)
                    if key in exceptions:
                        matched_exceptions.add(key)
                        continue
                    violations.append(
                        f"{filename}:{logical_id} ({rtype}) needs {action} on "
                        f"{arn} [{plane} plane] and the CFN deploy role is not "
                        f"granted it by any committed policy source. This apply "
                        f"would fail and roll the stack back. Either grant the "
                        f"reach, or record a dated exception in "
                        f"{MAP_PATH.name} explaining why this resource is never "
                        f"created by this role."
                    )
            if checked_any:
                tier2_checked += 1
            else:
                tier1_only += 1

    print("CFN deploy-role reach guard (ENC-TSK-O99 / ENC-ISS-660)")
    print(f"  grant sources ({len(sources)}): " + ", ".join(sources))
    print(f"  Allow statements derived: {len(statements)}")
    print(f"  resources scanned: {total}")
    print(f"  tier 2 (type + ARN reach verified): {tier2_checked}")
    print(f"  tier 1 only (type classified; ARN not statically derivable "
          f"or no ARN shape mapped): {tier1_only}")

    # A recorded exception that no longer fires is a lie in the ledger. Fail on
    # it so the list cannot rot the way an unreviewed allowlist always does --
    # the same rule prod_gate_coverage_guard.py applies to its grace entries.
    stale = set(exceptions) - matched_exceptions
    for key in sorted(stale):
        filename, logical_id, action, arn = key
        violations.append(
            f"STALE EXCEPTION in {MAP_PATH.name}: {filename}:{logical_id} "
            f"{action} on {arn} is now reachable (or the resource is gone). "
            f"Delete the exception -- a resolved exception left in place hides "
            f"the next real gap."
        )

    print(f"  recorded exceptions still in force: {len(matched_exceptions)}"
          f" of {len(exceptions)}")

    if violations:
        for violation in violations:
            print(f"::error::{violation}")
        print(f"[FAIL] CFN deploy-role reach guard: {len(violations)} violation(s).")
        return 1

    print("[SUCCESS] CFN deploy-role reach guard: every declared resource type is "
          "classified, and every resource with a derivable ARN is reachable by the "
          "CloudFormation deploy role.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
