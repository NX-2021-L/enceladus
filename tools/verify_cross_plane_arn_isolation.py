#!/usr/bin/env python3
"""ENC-TSK-P15 / ENC-ISS-669: cross-plane ARN isolation sweep.

THE HAZARD THIS CLOSES. infrastructure/cloudformation/02-compute.yaml's
ProjectJsonSyncRule carries `Name: !Sub "on-project-json-sync${EnvironmentSuffix}"`
-- a plane-generic identity, the same shape every other EventBridge rule in
this template uses so it CAN render on either plane -- while its Target Arn
hardcodes the PRODUCTION devops-json-to-parquet-transformer Lambda with no
suffix at all. Today `Condition: IsProduction` keeps the rule from ever
materialising on gamma. That Condition is the ENTIRE isolation mechanism, it
is not visible from the Name, and nothing enforced it before this guard --
it is exactly the kind of line a future template cleanup deletes because it
looks redundant next to a Name that already "does the suffix thing".

THE RULING THIS ENFORCES. Directional isolation: gamma READS devops prod;
gamma NEVER WRITES into it, and an invoke is a write. A gamma rendering of
ProjectJsonSyncRule would invoke the production devops Lambda from the gamma
plane -- a direct violation, and unlike a bad IAM grant (ENC-ISS-660's class)
this would not even need gamma to hold any special permission: EventBridge
already runs same-account, and nothing but the Condition stands in the way.

WHY THIS IS A SEPARATE CHECK FROM THE DEPLOY-ROLE REACH GUARD
(cfn_deploy_role_reach_guard.py, ENC-TSK-O99). That guard asks "can the CFN
deploy role actually CREATE this resource" -- IAM reach. This guard asks a
structurally different question: "if this resource's identity says it can
render on more than one plane, does everything it points AT track the same
plane, or did the author hardcode a fixed cross-plane pointer instead". A
resource can pass every IAM-reach check (its own creation is fully granted)
and still be this hazard, because the hazard is in what it INVOKES once
created, not in whether creating it succeeds.

THE DETECTION RULE. For each resource of a small set of invoke-target-bearing
types (the ones whose Properties cause AWS to actually CALL something --
Events::Rule, Scheduler::Schedule, Pipes::Pipe, Lambda::Permission,
Lambda::EventSourceMapping, Lambda::Url, SNS::Subscription; see
TARGET_BEARING_TYPES), walk its target field(s) -- the WRITE direction only
(Targets[].Arn, FunctionName, TargetFunctionArn, Endpoint, Target -- never a
SourceArn/EventSourceArn, which name who is ALLOWED to invoke, not what gets
invoked):

  * A Ref / GetAtt / ImportValue target is never flagged. CloudFormation
    resolves all three within the SAME stack evaluation, so whatever plane
    this resource renders on, the thing it points at renders on that same
    plane too -- it cannot structurally cross planes. This is also why
    IAM::Role policy Resource lists are OUT OF SCOPE for this guard entirely:
    a policy grant is read-direction capability, not a write, and mixing it
    in would just reproduce the reach guard's job worse.

  * A literal / !Sub target string that itself contains ${EnvironmentSuffix}
    is self-consistent by construction: it renders per-plane exactly like
    the resource carrying it, so there is nothing to check further.

  * A literal / !Sub target with NO ${EnvironmentSuffix} at all is a
    candidate -- but only treated as this hazard's shape when the resource
    is itself in a plane-generic context: SOME property of the SAME resource
    (anywhere in its Properties, not just the target field) contains the
    literal token ${EnvironmentSuffix}. That is the ProjectJsonSyncRule
    signature exactly: its Name says "I can be any plane" while its Target
    says "I always point here". A resource none of whose properties ever
    mention ${EnvironmentSuffix} -- e.g. CheckoutAutoScheduleRule's
    `Name: enceladus-checkout-auto`, or any of the Lambda::Url resources
    here, which have no Name property to begin with and nothing else
    plane-templated either -- never claimed to be plane-generic anywhere, so
    a fixed target next to it is not a contradiction. It is reported as
    SKIP_NOT_PLANE_CONTEXT, not silently ignored, but also not treated as
    this hazard.
    (verified 2026-08-23: every such resource in this repo's Lambda::Url /
    literal-Name family is already independently documented in-template as a
    deliberate single-plane adoption -- EnceladusMcpCodeLiveFunctionUrl,
    EnceladusMcpCodeGammaLiveFunctionUrl, EnceladusMcpStreamableLiveFunctionUrl,
    CheckoutAutoScheduleRule.)

  * Every plane-suffixed-context candidate is then checked against
    cross_plane_arn_isolation_exceptions.json. A match classifies as
    NOT_APPLICABLE_ON_PLANE and is printed with its owning repo and ruling --
    it still FIRES, it is never a silent skip, and a skip and an exception
    are reported as distinct states for exactly that reason. No match is a
    VIOLATION.

COVERAGE IS REPORTED, NEVER SILENT (same principle as ENC-TSK-O99): the
summary states counts for every classification, and a stale exception (one
that no longer fires) is itself a violation, so the exceptions file cannot
rot into a lie about what is actually deliberate.

Exit 0 = every plane-suffixed-context target is either self-consistent or a
          live, matched exception.
Exit 1 = at least one violation, or a stale exception.
Exit 2 = the guard could not run (missing dependency, missing/malformed
          exceptions file, or zero resources scanned).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required (pip install pyyaml)")
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ENC-TSK-P15: reuse the CFN-tag-preserving YAML loader already established in
# verify_lambda_arch_parity.py (ENC-TSK-O83) rather than defining a second one.
# !Sub / !Ref / !GetAtt / !ImportValue round-trip into inspectable
# {"!TagName": <value>} dicts instead of raising on PyYAML's SafeLoader.
from verify_lambda_arch_parity import _CfnTagPreservingLoader as CfnLoader  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CFN_DIR = REPO_ROOT / "infrastructure" / "cloudformation"
EXCEPTIONS_PATH = REPO_ROOT / "tools" / "cross_plane_arn_isolation_exceptions.json"

ACCOUNT_ID = "356364570033"
REGION = "us-west-2"

# Every resource type in these templates whose Properties cause AWS to
# actually INVOKE something (the write direction of the isolation ruling).
# `target_paths` names the field(s) that are the invoke destination -- never
# a SourceArn/EventSourceArn (who is allowed to call in), only what gets
# called.
TARGET_BEARING_TYPES: dict[str, list[str]] = {
    "AWS::Events::Rule": ["Targets[].Arn"],
    "AWS::Scheduler::Schedule": ["Target.Arn"],
    "AWS::Pipes::Pipe": ["Target"],
    "AWS::Lambda::Permission": ["FunctionName"],
    "AWS::Lambda::EventSourceMapping": ["FunctionName"],
    "AWS::Lambda::Url": ["TargetFunctionArn"],
    "AWS::SNS::Subscription": ["Endpoint"],
}

DYNAMIC_TAGS = ("!Ref", "!GetAtt", "!ImportValue")


def load_template(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=CfnLoader) or {}


def _resolve_pseudo(text: str) -> str:
    return (
        text.replace("${AWS::AccountId}", ACCOUNT_ID)
        .replace("${AWS::Region}", REGION)
        .replace("${AWS::Partition}", "aws")
    )


def _sub_text(value: Any) -> str | None:
    """The raw template text of a literal string or an Fn::Sub, else None."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "!Sub" in value:
        sub = value["!Sub"]
        if isinstance(sub, str):
            return sub
        if isinstance(sub, list) and sub and isinstance(sub[0], str):
            return sub[0]
    return None


def _is_dynamic_ref(value: Any) -> bool:
    """True for a value that CloudFormation resolves within the same stack.

    Ref / GetAtt / ImportValue all point at something CFN evaluates as part
    of THIS stack's own deploy, so whatever plane this stack is, that is the
    plane the reference resolves to -- it cannot structurally cross planes.
    """
    return isinstance(value, dict) and any(tag in value for tag in DYNAMIC_TAGS)


def _contains_env_suffix_token(value: Any) -> bool:
    """True if ${EnvironmentSuffix} appears literally anywhere under `value`.

    Used against a resource's WHOLE Properties block (not just the target
    field) to decide whether the resource is in a plane-generic context at
    all. A resource that never mentions ${EnvironmentSuffix} anywhere never
    claimed to render per-plane, so a fixed target next to it is not this
    hazard's shape -- see SKIP_NOT_PLANE_CONTEXT in scan() below.
    """
    if isinstance(value, str):
        return "${EnvironmentSuffix}" in value
    if isinstance(value, dict):
        return any(_contains_env_suffix_token(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_env_suffix_token(v) for v in value)
    return False


def _resolve_property_paths(props: dict, path: str) -> list[tuple[str, Any]]:
    """Walk a dotted/indexed property path; `Foo[].Bar` iterates a list.

    Returns [(display_path, value), ...]. A path segment that is absent
    yields no results (property not set on this resource) rather than an
    error -- most target fields are optional (e.g. not every Events::Rule
    Target carries every sub-key).
    """

    def walk(node: Any, parts: list[str], prefix: str) -> list[tuple[str, Any]]:
        if not parts:
            return [(prefix.rstrip("."), node)]
        part, rest = parts[0], parts[1:]
        if part.endswith("[]"):
            key = part[:-2]
            items = node.get(key) if isinstance(node, dict) else None
            if items is None:
                return []
            items = items if isinstance(items, list) else [items]
            out: list[tuple[str, Any]] = []
            for i, item in enumerate(items):
                out.extend(walk(item, rest, f"{prefix}{key}[{i}]."))
            return out
        if not isinstance(node, dict) or part not in node:
            return []
        return walk(node[part], rest, f"{prefix}{part}.")

    return walk(props, path.split("."), "")


def _load_exceptions() -> dict[tuple[str, str, str], dict]:
    if not EXCEPTIONS_PATH.exists():
        print(f"::error::missing exceptions file: {EXCEPTIONS_PATH}")
        sys.exit(2)
    try:
        raw = json.loads(EXCEPTIONS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"::error::{EXCEPTIONS_PATH} is not valid JSON: {exc}")
        sys.exit(2)
    exceptions = {}
    for entry in raw.get("exceptions") or []:
        key = (entry["template"], entry["logical_id"], entry["field"])
        exceptions[key] = entry
    return exceptions


class Finding:
    __slots__ = ("state", "template", "logical_id", "rtype", "field", "arn", "detail")

    def __init__(self, state, template, logical_id, rtype, field, arn, detail=""):
        self.state = state
        self.template = template
        self.logical_id = logical_id
        self.rtype = rtype
        self.field = field
        self.arn = arn
        self.detail = detail

    def line(self) -> str:
        return f"{self.template}:{self.logical_id} ({self.rtype}) [{self.field}] -> {self.arn}"


def scan(
    cfn_dir: Path = CFN_DIR,
    templates: Iterable[str] | None = None,
    exceptions: dict[tuple[str, str, str], dict] | None = None,
) -> tuple[list[Finding], dict[str, int], set[tuple[str, str, str]]]:
    """Scan governed templates for the cross-plane ARN isolation hazard shape.

    Returns (findings, tally, matched_exception_keys). `findings` holds only
    the non-trivial classifications (VIOLATION and NOT_APPLICABLE_ON_PLANE)
    -- DYNAMIC_REF / SUFFIX_MATCH / SKIP_NOT_PLANE_CONTEXT are tallied but
    not individually printed, the same coverage-without-noise convention
    cfn_deploy_role_reach_guard.py uses for tier-1-only resources.
    """
    if exceptions is None:
        exceptions = {}
    if templates is None:
        templates = sorted(p.name for p in cfn_dir.glob("*.yaml"))

    findings: list[Finding] = []
    matched_exceptions: set[tuple[str, str, str]] = set()
    tally = {
        "resources_scanned": 0,
        "targets_examined": 0,
        "dynamic_ref": 0,
        "suffix_match": 0,
        "skip_not_plane_context": 0,
        "unresolved": 0,
        "not_applicable_on_plane": 0,
        "violation": 0,
    }

    for filename in templates:
        path = cfn_dir / filename
        if not path.exists():
            continue
        template = load_template(path)
        for logical_id, resource in (template.get("Resources") or {}).items():
            if not isinstance(resource, dict):
                continue
            rtype = resource.get("Type")
            target_paths = TARGET_BEARING_TYPES.get(rtype)
            if target_paths is None:
                continue
            tally["resources_scanned"] += 1
            props = resource.get("Properties") or {}

            # Whole-resource gate: does ANY property of this resource mention
            # ${EnvironmentSuffix}? If nothing about it is plane-templated,
            # a fixed target elsewhere in it is not a contradiction -- see
            # the module docstring's CheckoutAutoScheduleRule / Lambda::Url
            # examples.
            resource_is_plane_generic = _contains_env_suffix_token(props)

            for target_path in target_paths:
                for field_path, value in _resolve_property_paths(props, target_path):
                    if value is None:
                        continue
                    tally["targets_examined"] += 1

                    if _is_dynamic_ref(value):
                        tally["dynamic_ref"] += 1
                        continue

                    text = _sub_text(value)
                    if text is None:
                        tally["unresolved"] += 1
                        continue

                    if "${EnvironmentSuffix}" in text:
                        tally["suffix_match"] += 1
                        continue

                    # Hardcoded literal, no plane suffix at all.
                    if not resource_is_plane_generic:
                        tally["skip_not_plane_context"] += 1
                        continue

                    arn = _resolve_pseudo(text)
                    key = (filename, logical_id, field_path)
                    exc = exceptions.get(key)
                    if exc is not None and exc.get("arn") == arn:
                        matched_exceptions.add(key)
                        tally["not_applicable_on_plane"] += 1
                        findings.append(
                            Finding(
                                "NOT_APPLICABLE_ON_PLANE", filename, logical_id, rtype,
                                field_path, arn,
                                detail=(
                                    f"owning repo: {exc.get('owning_repo')}; "
                                    f"ruling: {exc.get('ruling')}; "
                                    f"owner record: {exc.get('owner_record')}"
                                ),
                            )
                        )
                    else:
                        tally["violation"] += 1
                        findings.append(
                            Finding(
                                "VIOLATION", filename, logical_id, rtype, field_path, arn,
                                detail=(
                                    f"hardcodes a literal target ARN with no "
                                    f"${{EnvironmentSuffix}} while some OTHER property of "
                                    f"this same resource IS plane-suffixed -- this resource "
                                    f"can render per-plane and would invoke {arn} from "
                                    f"every plane it renders on. Either make the target "
                                    f"plane-aware, or record a dated exception in "
                                    f"{EXCEPTIONS_PATH.name} naming the owning repo and the "
                                    f"ruling that makes this deliberate."
                                ),
                            )
                        )

    return findings, tally, matched_exceptions


def main() -> int:
    exceptions = _load_exceptions()
    findings, tally, matched = scan(exceptions=exceptions)

    if tally["resources_scanned"] == 0:
        print("::error::zero invoke-target-bearing resources scanned -- "
              "the governed templates moved or the resource-type map is stale; "
              "refusing to pass.")
        return 2

    print("Cross-plane ARN isolation sweep (ENC-TSK-P15 / ENC-ISS-669)")
    print(f"  templates dir: {CFN_DIR}")
    print(f"  resources scanned (invoke-target-bearing types): {tally['resources_scanned']}")
    print(f"  target fields examined: {tally['targets_examined']}")
    print(f"    dynamic ref (Ref/GetAtt/ImportValue, same-stack, trusted): {tally['dynamic_ref']}")
    print(f"    plane-suffix present (self-consistent): {tally['suffix_match']}")
    print(f"    skipped -- not a plane-suffixed context: {tally['skip_not_plane_context']}")
    print(f"    unresolved (unrecognised shape): {tally['unresolved']}")
    print(f"    NOT_APPLICABLE_ON_PLANE (declared exception, fired): {tally['not_applicable_on_plane']}")
    print(f"    VIOLATION: {tally['violation']}")

    violations = [f for f in findings if f.state == "VIOLATION"]
    excepted = [f for f in findings if f.state == "NOT_APPLICABLE_ON_PLANE"]

    for f in excepted:
        print(f"::notice::NOT_APPLICABLE_ON_PLANE {f.line()} -- {f.detail}")

    stale = set(exceptions) - matched
    stale_violations = []
    for key in sorted(stale):
        filename, logical_id, field_path = key
        entry = exceptions[key]
        stale_violations.append(
            f"STALE EXCEPTION in {EXCEPTIONS_PATH.name}: {filename}:{logical_id} "
            f"[{field_path}] (expected arn {entry.get('arn')}) did not fire on this "
            f"run -- either the target changed, the resource is gone, or the ARN in "
            f"the exception no longer matches what the template renders. Delete or "
            f"correct the exception; a stale entry left in place hides the next real "
            f"gap."
        )

    print(f"  recorded exceptions still in force: {len(matched)} of {len(exceptions)}")

    if violations or stale_violations:
        for f in violations:
            print(f"::error::VIOLATION {f.line()} -- {f.detail}")
        for msg in stale_violations:
            print(f"::error::{msg}")
        print(
            f"[FAIL] Cross-plane ARN isolation sweep: {len(violations)} violation(s), "
            f"{len(stale_violations)} stale exception(s)."
        )
        return 1

    print(
        "[SUCCESS] Cross-plane ARN isolation sweep: every plane-suffixed-context "
        "target either tracks its own plane or is a live, matched, named exception."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
