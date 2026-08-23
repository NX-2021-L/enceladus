#!/usr/bin/env python3
"""ENC-TSK-P11 / ENC-ISS-666: Component Dependency Closure primitive.

THE GAP THIS CLOSES
-----------------------------------------------------------------------------
DOC-6EFD5DB32CD8 Revision 19 Addendum landed a three-state model for "does a
component's dependency exist on a given plane": PROVISIONED_ON_PLANE (exists,
verified live), NOT_YET_PROVISIONED (absent and SHOULD exist -- an ordinary
gap that blocks enablement), and STRUCTURALLY_ABSENT (absent BY DECISION,
will never exist on this plane -- not a gap, not a backlog item). Nothing in
this repo could express the third state before this file. A two-state
present/absent model has nowhere to put the Trino/Superset estate (one EC2
host, no gamma twin, and none is intended), so a check meeting that edge
invents an answer -- which is ENC-ISS-665's fabricated-verdict failure mode
arriving by a different route.

THE FOUR VERDICTS, AND WHY THEY MUST NOT COLLAPSE
-----------------------------------------------------------------------------
  PASS                  -- checked, and confirmed present.
  VIOLATION             -- checked (or checkable-but-declared-absent-while-
                            required), and confirmed a problem.
  NOT_APPLICABLE_ON_PLANE -- the dependency is STRUCTURALLY_ABSENT by
                            declaration. Sourced from the declaration, never
                            inferred at runtime, and structurally incapable
                            of ever becoming PASS.
  UNKNOWN               -- could not run the check (no boto3, no
                            credentials, no cheap mechanism exists for this
                            dependency kind). A permission ceiling, not a
                            defect. NEVER printed or counted as a pass.
A fifth label, GAP, is this tool's own addition for a declared, tracked,
NOT_YET_PROVISIONED finding -- distinct from VIOLATION so "this is a known,
open, tracked absence" is never confused with "this is unclassifiable drift."
A skipped check and an excepted check are different states in this output,
by construction: NOT_APPLICABLE_ON_PLANE only ever comes from a declaration,
UNKNOWN only ever comes from an inability to check, and neither is a PASS.

AC-7 -- PROVISIONING COMPLETENESS, AND WHY A DECLARATION IS NOT EVIDENCE
-----------------------------------------------------------------------------
Today's proof this is not hypothetical, ENC-ISS-672: glue:CreateDatabase IS
declared for the CFN deploy role at 04-github-roles.yaml:619 (ENC-TSK-O98),
and the live role does not have it -- 04-github-roles.yaml has no push-deploy
lane, and the one-off patch workflow failed closed at its own preflight.
tools/cfn_deploy_role_reach_guard.py reads the committed allowlist and
reports GREEN because it is declared-vs-DECLARED; the gap is declared-vs-
ACTUAL. This tool's PROVISIONED_ON_PLANE branch is the general form of that
distinction: where an existence check is cheap and local (a bundled_module's
source file must actually exist on disk, and actually be listed in the
consuming function's .build_extras manifest -- no AWS needed, always runs),
it runs for real, every invocation. Where existence can only be confirmed by
an AWS read (a lambda_layer, an s3_bucket, an external_layer's published
ARN), it runs only under --live (mirrors tools/verify_lambda_arch_parity.py
's --check-live-reconciliation and tools/verify_liveness_contract.py's
--live: this job has no AWS credentials configured anywhere, so attempting
those checks by default would either silently no-op or need per-step
credential wiring nothing else in this file's CI job carries) and prints
UNKNOWN, never a fabricated pass, when it cannot run.

AC-9 -- A RATCHET STAGED BY DEPENDENCY CLASS
-----------------------------------------------------------------------------
This tool SEES every declared dependency of every declared plane, always --
every finding (VIOLATION, GAP, NOT_APPLICABLE_ON_PLANE, UNKNOWN) is computed
and printed regardless of kind. It only BLOCKS (affects the exit code) for
a dependency whose kind appears in component_dependency_closure.json's
enforced_dependency_kinds[]: today, the shared-layer supply chain
(bundled_module, lambda_layer) and data-plane storage (s3_bucket) -- see
that file's _schema block for the full rationale. That list may only GROW:
--base-ref diffs it against the same file's own git history (the same
technique tools/verify_lambda_arch_parity.py's
_validate_architecture_exceptions_ratchet uses for architecture_exceptions,
ENC-TSK-O84) and fails a PR that shrinks it.

AC-8 -- THE REVERT-ORPHAN RULE
-----------------------------------------------------------------------------
ENC-TSK-O95 removed GovernanceMartBucketGamma from 02-compute.yaml while
devops-governance-mart-gamma stayed deployed and enabled with its bucket
gone, silently -- that is ENC-ISS-666, and ENC-TSK-P10 re-landed the
resources afterward. --base-ref also diffs each component's dependency list
against its own git history: a dependency present at the base ref and
missing now is a VIOLATION unless the affected plane(s) were also dropped
from the component's own planes[], or a matching entry exists in this file's
degradation_markers[] naming what was removed and why the dependent is not
left orphaned.

WHY A COMMITTED FILE AND NOT A SECOND DISCOVERY MECHANISM
-----------------------------------------------------------------------------
The dependency graph a component actually has is a set of DECISIONS (is this
class of absence a decision or a gap?) that nothing in AWS can answer by
itself -- the same reason tools/devops_lambda_ownership_snapshot.json is a
committed, hand-refreshed pin rather than a live fetch (NX-2021-L/devops is
private; enceladus CI carries no token for it). This file is that pin's
sibling for dependency closures. For the one predicate this file must NOT
reinvent -- "is this component owned by NX-2021-L/devops" -- it reuses
tools/verify_lambda_arch_parity.py's _load_devops_ownership_snapshot /
_devops_owned_function_names exactly as committed, never a second ownership
mechanism (ENC-TSK-P15 AC-6's own instruction, restated here).

Exit 0 = every check that ran found no violation (UNKNOWN and non-enforced
         findings never fail the run on their own).
Exit 1 = at least one enforced VIOLATION, un-waived enforced GAP, stale
         known_open_gaps/degradation_markers entry, or ratchet regression.
Exit 2 = the guard could not run (missing/malformed input file).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
CLOSURE_PATH = REPO_ROOT / "infrastructure" / "component_dependency_closure.json"

# Reuse verify_lambda_arch_parity.py's ownership predicate for
# NX-2021-L/devops-owned components -- ENC-TSK-P15's own instruction is not
# to build a second ownership mechanism, and this file's devops-io-devops-mcp
# design-test entry needs exactly that predicate.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_lambda_arch_parity as _arch_parity  # noqa: E402

PLANE_STATE_ENUM = {"PROVISIONED_ON_PLANE", "NOT_YET_PROVISIONED", "STRUCTURALLY_ABSENT"}
DEPENDENCY_KIND_ENUM = {
    "bundled_module",
    "lambda_layer",
    "s3_bucket",
    "external_estate",
    "external_layer",
    "iam_role_out_of_band",
}
MIN_ABSENCE_RATIONALE_LEN = 40


def log(message: str) -> None:
    print(f"[component-closure] {message}")


def load_closure(path: Path = CLOSURE_PATH) -> dict:
    if not path.is_file():
        print(f"::error::missing component dependency closure: {path}")
        sys.exit(2)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"::error::{path} is not valid JSON: {exc}")
        sys.exit(2)


# ---------------------------------------------------------------------------
# Structural validation -- always runs, no AWS, no network.
# ---------------------------------------------------------------------------

def validate_structure(closure: dict) -> list[str]:
    errors: list[str] = []

    for key in ("enforced_dependency_kinds", "known_open_gaps", "degradation_markers", "components"):
        if key not in closure:
            errors.append(f"missing required top-level key: {key!r}")
    if errors:
        return errors

    enforced = closure["enforced_dependency_kinds"]
    if not isinstance(enforced, list) or not enforced:
        errors.append("enforced_dependency_kinds must be a non-empty array")
    else:
        for kind in enforced:
            if kind not in DEPENDENCY_KIND_ENUM:
                errors.append(
                    f"enforced_dependency_kinds contains {kind!r}, which is not "
                    f"in the declared dependency_kind_enum {sorted(DEPENDENCY_KIND_ENUM)}"
                )

    components = closure["components"]
    if not isinstance(components, list) or not components:
        errors.append("components must be a non-empty array")
        return errors

    seen_component_names: set[str] = set()
    for component in components:
        name = component.get("name")
        if not name:
            errors.append(f"component entry missing required 'name': {component!r}")
            continue
        if name in seen_component_names:
            errors.append(f"duplicate component name: {name!r}")
        seen_component_names.add(name)

        for field in ("owning_repository", "deployed_by", "planes", "dependencies"):
            if field not in component:
                errors.append(f"component {name!r} missing required field {field!r}")

        planes = component.get("planes")
        if not isinstance(planes, list) or not planes:
            errors.append(f"component {name!r}: planes must be a non-empty array")
            planes = []

        dependencies = component.get("dependencies")
        if not isinstance(dependencies, list):
            errors.append(f"component {name!r}: dependencies must be an array")
            dependencies = []

        seen_dep_ids: set[str] = set()
        for dep in dependencies:
            dep_id = dep.get("id")
            if not dep_id:
                errors.append(f"component {name!r}: dependency entry missing 'id': {dep!r}")
                continue
            if dep_id in seen_dep_ids:
                errors.append(f"component {name!r}: duplicate dependency id {dep_id!r}")
            seen_dep_ids.add(dep_id)

            prefix = f"component {name!r} dependency {dep_id!r}"

            kind = dep.get("kind")
            if kind not in DEPENDENCY_KIND_ENUM:
                errors.append(
                    f"{prefix}: kind {kind!r} is not one of {sorted(DEPENDENCY_KIND_ENUM)}"
                )

            if not dep.get("owning_repository"):
                errors.append(f"{prefix}: missing required 'owning_repository'")

            plane_state = dep.get("plane_state")
            if not isinstance(plane_state, dict):
                errors.append(f"{prefix}: plane_state must be an object")
                plane_state = {}

            # Every plane the OWNING component declares must have a stated
            # plane_state for this dependency -- an absent entry is not a
            # silent PASS, it is a structural hole (ENC-TSK-O83 vacuous-pass
            # lesson: "nothing to check" must be visible, never quiet).
            for plane in planes:
                if plane not in plane_state:
                    errors.append(
                        f"{prefix}: no plane_state declared for plane {plane!r}, "
                        f"which component {name!r} declares in its own planes[]"
                    )

            structurally_absent_planes = []
            for plane, state in plane_state.items():
                if state not in PLANE_STATE_ENUM:
                    errors.append(
                        f"{prefix}: plane_state[{plane!r}] = {state!r} is not one "
                        f"of {sorted(PLANE_STATE_ENUM)}. If this is meant to be "
                        f"'PROVISIONED', the full spelling is PROVISIONED_ON_PLANE "
                        f"-- the abbreviation is not accepted (fail-closed on an "
                        f"ambiguous enum value, not a silent alias)."
                    )
                elif state == "STRUCTURALLY_ABSENT":
                    structurally_absent_planes.append(plane)

            if structurally_absent_planes:
                rationale = dep.get("absence_rationale", "")
                if len(rationale) < MIN_ABSENCE_RATIONALE_LEN:
                    errors.append(
                        f"{prefix}: STRUCTURALLY_ABSENT on plane(s) "
                        f"{structurally_absent_planes} but absence_rationale is "
                        f"missing or shorter than {MIN_ABSENCE_RATIONALE_LEN} "
                        f"chars -- a structural-absence declaration with no "
                        f"stated ruling is indistinguishable from an unexamined gap."
                    )

    # known_open_gaps / degradation_markers shape checks.
    for i, gap in enumerate(closure.get("known_open_gaps") or []):
        for field in ("component", "dependency_id", "plane", "reason", "tracker", "recorded"):
            if not gap.get(field):
                errors.append(f"known_open_gaps[{i}] missing required field {field!r}")

    for i, marker in enumerate(closure.get("degradation_markers") or []):
        for field in ("component", "plane", "removed_dependency_id", "reason", "tracker", "recorded"):
            if not marker.get(field):
                errors.append(f"degradation_markers[{i}] missing required field {field!r}")

    return errors


# ---------------------------------------------------------------------------
# Ownership predicate reuse (ENC-TSK-P15) -- for devops-io-devops-mcp's
# design test: a component can be owning_repository=NX-2021-L/devops and
# absent from that repo's own canonical manifest. This does not re-derive
# ownership; it reads the same pinned snapshot verify_lambda_arch_parity.py
# already reads.
# ---------------------------------------------------------------------------

def validate_devops_ownership(closure: dict) -> list[str]:
    errors: list[str] = []
    devops_components = [
        c for c in closure.get("components", [])
        if c.get("owning_repository") == "NX-2021-L/devops"
    ]
    if not devops_components:
        return errors

    snapshot, snapshot_errors = _arch_parity._load_devops_ownership_snapshot()
    if snapshot_errors:
        errors.append(
            "cannot validate NX-2021-L/devops-owned component(s) against the "
            "devops ownership snapshot: " + "; ".join(snapshot_errors)
        )
        return errors

    devops_names = _arch_parity._devops_owned_function_names(snapshot)
    for component in devops_components:
        name = component["name"]
        if name not in devops_names:
            errors.append(
                f"component {name!r} declares owning_repository=NX-2021-L/devops "
                f"but is not present in "
                f"infrastructure/devops_lambda_ownership_snapshot.json's "
                f"functions[] -- ownership here must be backed by that pinned, "
                f"hash-verified snapshot, never asserted by prose alone "
                f"(ENC-TSK-P15's ownership predicate, reused not reinvented)."
            )
        else:
            log(
                f"ownership confirmed via devops_lambda_ownership_snapshot.json: "
                f"{name!r} is a real, pinned devops-owned function"
            )
    return errors


# ---------------------------------------------------------------------------
# Cheap, local, always-on existence check: bundled_module.
# ---------------------------------------------------------------------------

def _check_bundled_module(dep: dict) -> tuple[str, str]:
    """Returns (verdict, detail). Never UNKNOWN -- this check needs no AWS
    and no network, so it always actually runs (AC-7: "where you can check
    existence live and cheaply, do")."""
    source_path = dep.get("source_path")
    if not source_path:
        return "UNKNOWN", "no source_path declared -- cannot check bundled_module existence"

    full_path = REPO_ROOT / source_path
    if not full_path.is_file():
        return "VIOLATION", f"declared source_path {source_path!r} does not exist on disk"

    manifest_path = dep.get("build_extras_manifest")
    if manifest_path:
        full_manifest = REPO_ROOT / manifest_path
        if not full_manifest.is_file():
            return "VIOLATION", (
                f"declared build_extras_manifest {manifest_path!r} does not exist -- "
                f"the bundling mechanism this dependency claims to use is itself absent"
            )
        manifest_lines = [
            ln.strip() for ln in full_manifest.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if source_path not in manifest_lines:
            return "VIOLATION", (
                f"{source_path!r} exists on disk but is NOT listed in "
                f"{manifest_path!r} -- a template declaration is not evidence of "
                f"existence; this dependency is declared but never actually bundled"
            )

    return "PASS", f"source file exists on disk at {source_path!r}" + (
        f" and is listed in {manifest_path!r}" if manifest_path else ""
    )


# ---------------------------------------------------------------------------
# AWS-derived existence checks -- opt-in via --live only (this job has no
# AWS credentials configured anywhere; mirrors verify_lambda_arch_parity.py
# --check-live-reconciliation and verify_liveness_contract.py --live).
# ---------------------------------------------------------------------------

def _boto3_client(service: str, region: str):
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        return None, None, "boto3 not available"
    try:
        return boto3.client(service, region_name=region), (BotoCoreError, ClientError, NoCredentialsError), ""
    except Exception as exc:  # pragma: no cover - defensive
        return None, None, f"could not construct boto3 {service} client: {exc}"


def _check_lambda_layer(dep: dict, region: str) -> tuple[str, str]:
    layer_name = dep.get("layer_name")
    if not layer_name:
        return "UNKNOWN", "no layer_name declared -- cannot resolve a live layer to check"
    client, exc_types, reason = _boto3_client("lambda", region)
    if client is None:
        return "UNKNOWN", f"live check unavailable: {reason}"
    try:
        client.list_layer_versions(LayerName=layer_name, MaxItems=1)
        return "PASS", f"lambda:ListLayerVersions succeeded for layer {layer_name!r}"
    except exc_types as exc:
        code = getattr(getattr(exc, "response", {}), "get", lambda *_: {})("Error", {}).get("Code", "") \
            if hasattr(exc, "response") else ""
        if code == "ResourceNotFoundException":
            return "VIOLATION", f"layer {layer_name!r} does not exist live -- declared PROVISIONED_ON_PLANE, actually absent"
        return "UNKNOWN", f"live check for layer {layer_name!r} failed: {exc}"


def _check_s3_bucket(dep: dict, region: str) -> tuple[str, str]:
    bucket_name = dep.get("bucket_name")
    if not bucket_name:
        return "UNKNOWN", "no bucket_name declared -- cannot resolve a live bucket to check"
    client, exc_types, reason = _boto3_client("s3", region)
    if client is None:
        return "UNKNOWN", f"live check unavailable: {reason}"
    try:
        client.head_bucket(Bucket=bucket_name)
        return "PASS", f"s3:HeadBucket succeeded for {bucket_name!r}"
    except exc_types as exc:
        response = getattr(exc, "response", {}) or {}
        status = str(response.get("ResponseMetadata", {}).get("HTTPStatusCode", ""))
        if status == "404":
            return "VIOLATION", f"bucket {bucket_name!r} does not exist live -- declared PROVISIONED_ON_PLANE, actually absent"
        return "UNKNOWN", f"live check for bucket {bucket_name!r} failed: {exc}"


def _check_external_layer(dep: dict, region: str) -> tuple[str, str]:
    layer_arn = dep.get("layer_arn")
    if not layer_arn:
        return "UNKNOWN", "no layer_arn declared -- cannot resolve a live layer to check"
    client, exc_types, reason = _boto3_client("lambda", region)
    if client is None:
        return "UNKNOWN", f"live check unavailable: {reason}"
    try:
        client.get_layer_version_by_arn(Arn=layer_arn)
        return "PASS", f"lambda:GetLayerVersionByArn succeeded for {layer_arn!r}"
    except exc_types as exc:
        return "UNKNOWN", f"live check for external layer {layer_arn!r} failed: {exc}"


_LIVE_CHECKS = {
    "lambda_layer": _check_lambda_layer,
    "s3_bucket": _check_s3_bucket,
    "external_layer": _check_external_layer,
}


# ---------------------------------------------------------------------------
# Per-dependency-per-plane verdict computation.
# ---------------------------------------------------------------------------

def evaluate_closure(closure: dict, live: bool, region: str) -> tuple[list[str], list[str]]:
    """Returns (violations, findings). findings is every printed line
    (informational or otherwise); violations is the subset that must fail
    the run."""
    enforced = set(closure.get("enforced_dependency_kinds", []))
    known_open_gaps = {
        (g["component"], g["dependency_id"], g["plane"]): g
        for g in closure.get("known_open_gaps", [])
    }
    matched_gaps: set[tuple[str, str, str]] = set()

    violations: list[str] = []
    findings: list[str] = []

    for component in closure["components"]:
        cname = component["name"]
        planes = component.get("planes", [])
        for dep in component.get("dependencies", []):
            did = dep["id"]
            kind = dep.get("kind")
            plane_state = dep.get("plane_state", {})
            is_enforced = kind in enforced

            for plane in planes:
                state = plane_state.get(plane)
                where = f"{cname} / {did} [{plane}]"

                if state == "STRUCTURALLY_ABSENT":
                    findings.append(
                        f"[NOT_APPLICABLE_ON_PLANE] {where}: structurally absent by "
                        f"decision -- {dep.get('absence_rationale', '(no rationale)')}"
                    )
                    continue

                if state == "NOT_YET_PROVISIONED":
                    gap_key = (cname, did, plane)
                    ledger_entry = known_open_gaps.get(gap_key)
                    if ledger_entry:
                        matched_gaps.add(gap_key)
                        findings.append(
                            f"[GAP] {where}: not yet provisioned -- KNOWN, tracked "
                            f"({ledger_entry['tracker']}): {ledger_entry['reason']}"
                        )
                    else:
                        findings.append(
                            f"[GAP] {where}: not yet provisioned -- UNTRACKED "
                            f"(no known_open_gaps entry)"
                        )
                        if is_enforced:
                            violations.append(
                                f"{where}: kind {kind!r} is enforced and this gap is "
                                f"UNTRACKED -- component {cname!r} declares itself "
                                f"live on plane {plane!r} while this dependency is "
                                f"declared NOT_YET_PROVISIONED there. Either add a "
                                f"dated entry to known_open_gaps naming the tracker, "
                                f"or the enablement itself is premature (AC-7)."
                            )
                    continue

                if state == "PROVISIONED_ON_PLANE":
                    if kind == "bundled_module":
                        verdict, detail = _check_bundled_module(dep)
                    elif kind in _LIVE_CHECKS:
                        if live:
                            verdict, detail = _LIVE_CHECKS[kind](dep, region)
                        else:
                            verdict, detail = "UNKNOWN", (
                                "declared PROVISIONED_ON_PLANE; live verification not "
                                "attempted in this invocation (pass --live). A "
                                "template declaration is not evidence of existence "
                                "(AC-7 / ENC-ISS-672) -- this is reported as UNKNOWN, "
                                "never PASS."
                            )
                    else:
                        verdict, detail = "UNKNOWN", (
                            f"no existence-check mechanism implemented for kind "
                            f"{kind!r} -- reported as UNKNOWN, never PASS"
                        )

                    findings.append(f"[{verdict}] {where}: {detail}")
                    if verdict == "VIOLATION" and is_enforced:
                        violations.append(f"{where}: {detail}")
                    continue

                # state is None or otherwise invalid -- already caught by
                # validate_structure as a structural error, but guard anyway.
                findings.append(f"[UNKNOWN] {where}: no valid plane_state to evaluate")

    # Stale known_open_gaps: a ledger entry whose dependency has stopped
    # being NOT_YET_PROVISIONED is a lie in the ledger -- same rule
    # tools/cfn_deploy_role_reach_guard.py applies to its own exceptions.
    stale_gaps = set(known_open_gaps) - matched_gaps
    for key in sorted(stale_gaps):
        cname, did, plane = key
        violations.append(
            f"STALE known_open_gaps ENTRY: {cname} / {did} [{plane}] is no longer "
            f"NOT_YET_PROVISIONED (resolved, reclassified, or the dependency/"
            f"component/plane no longer exists) -- delete the entry. A resolved "
            f"gap left in the ledger hides the next real one."
        )

    return violations, findings


# ---------------------------------------------------------------------------
# --base-ref ratchets: enforced_dependency_kinds may only grow (AC-9), and
# no dependency may vanish from a still-declared plane without a marker
# (AC-8, the revert-orphan rule).
# ---------------------------------------------------------------------------

_EMPTY_BASELINE = {"enforced_dependency_kinds": [], "components": [], "degradation_markers": []}

# Substrings git prints on stderr when the REF resolves but the PATH simply
# did not exist there yet -- as opposed to the ref itself being bogus. Both
# phrasings are observed across git versions.
_PATH_NOT_AT_REF_MARKERS = ("does not exist in", "exists on disk, but not in")


def _git_show_closure_at_ref(ref: str) -> Optional[dict]:
    """Returns the closure dict as committed at `ref`, an _EMPTY_BASELINE
    sentinel if `ref` is a real commit but this file did not exist there yet
    (bootstrapping: this file's own introducing PR must not fail its own
    ratchet against a pre-history base), or None if `ref` itself could not
    be resolved at all (a genuine could-not-run)."""
    try:
        rel_path = CLOSURE_PATH.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel_path = "infrastructure/component_dependency_closure.json"
    proc = subprocess.run(
        ["git", "show", f"{ref}:{rel_path}"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        if any(marker in proc.stderr for marker in _PATH_NOT_AT_REF_MARKERS):
            return dict(_EMPTY_BASELINE)
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def validate_ratchets(closure: dict, base_ref: str) -> list[str]:
    errors: list[str] = []
    baseline = _git_show_closure_at_ref(base_ref)
    if baseline is None:
        return [
            f"could not read {CLOSURE_PATH.name} at base ref {base_ref!r} via "
            f"`git show` -- cannot evaluate the enforced_dependency_kinds or "
            f"revert-orphan ratchets. Treating an unresolvable baseline as a "
            f"hard failure, not a silent skip (ENC-TSK-O83 vacuous-pass lesson). "
            f"Check that the checkout has enough history (fetch-depth: 0) and "
            f"that {base_ref!r} is a valid ref."
        ]

    if baseline is _EMPTY_BASELINE or baseline == _EMPTY_BASELINE:
        print(
            f"[INFO] {CLOSURE_PATH.name} did not exist at base ref {base_ref!r} -- "
            f"bootstrapping against an empty baseline (nothing enforced, no "
            f"components declared). This is this file's own introducing change; "
            f"neither ratchet can regress against nothing."
        )

    # AC-9: enforced_dependency_kinds may only grow.
    baseline_enforced = set(baseline.get("enforced_dependency_kinds", []))
    current_enforced = set(closure.get("enforced_dependency_kinds", []))
    dropped = baseline_enforced - current_enforced
    if dropped:
        errors.append(
            f"enforced_dependency_kinds SHRANK: {sorted(dropped)} were enforced "
            f"at {base_ref} and are not enforced now. AC-9's ratchet is "
            f"monotonic -- narrow the BLOCK surface only by removing a kind's "
            f"last enforced dependency, never by widening what escapes "
            f"enforcement."
        )

    # AC-8: revert-orphan rule.
    baseline_components = {c["name"]: c for c in baseline.get("components", []) if c.get("name")}
    current_components = {c["name"]: c for c in closure.get("components", []) if c.get("name")}
    degradation_markers = {
        (m["component"], m["plane"], m["removed_dependency_id"])
        for m in closure.get("degradation_markers", [])
    }

    for name, base_component in baseline_components.items():
        current_component = current_components.get(name)
        if current_component is None:
            continue  # component removed entirely -- nothing left to orphan
        current_planes = set(current_component.get("planes", []))
        base_deps = {d["id"]: d for d in base_component.get("dependencies", []) if d.get("id")}
        current_dep_ids = {d["id"] for d in current_component.get("dependencies", []) if d.get("id")}

        for dep_id, base_dep in base_deps.items():
            if dep_id in current_dep_ids:
                continue
            # Dependency vanished. OK if every plane it covered is no longer
            # in the component's own planes[], or a degradation marker
            # explicitly accounts for the removal.
            base_dep_planes = set((base_dep.get("plane_state") or {}).keys())
            still_relevant_planes = base_dep_planes & current_planes
            for plane in still_relevant_planes:
                if (name, plane, dep_id) not in degradation_markers:
                    errors.append(
                        f"REVERT-ORPHAN (AC-8 / ENC-ISS-666): component {name!r} "
                        f"still declares plane {plane!r} but its dependency "
                        f"{dep_id!r} (present at {base_ref}) is gone, with no "
                        f"degradation_markers entry. ENC-TSK-O95 did exactly this "
                        f"to GovernanceMartBucketGamma / devops-governance-mart-"
                        f"gamma -- a change that removes a dependency must remove "
                        f"its dependent (drop the plane) or mark it explicitly "
                        f"degraded (add a degradation_markers entry naming why)."
                    )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ENC-TSK-P11: verify the Component Dependency Closure declaration."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Attempt AWS-derived existence checks (lambda:ListLayerVersions, "
            "s3:HeadBucket, lambda:GetLayerVersionByArn -- all read-only) for "
            "PROVISIONED_ON_PLANE dependencies whose kind supports one. "
            "Requires boto3 + AWS credentials; prints UNKNOWN and never fails "
            "the run on that basis alone when unavailable. Not part of the "
            "default invocation -- this CI job has no AWS credentials "
            "configured anywhere, same convention as "
            "verify_lambda_arch_parity.py --check-live-reconciliation."
        ),
    )
    parser.add_argument(
        "--live-region", default="us-west-2",
        help="AWS region for --live's read-only calls (default: us-west-2).",
    )
    parser.add_argument(
        "--base-ref", metavar="REF",
        help=(
            "Git ref/sha to diff this file's own history against: fails when "
            "enforced_dependency_kinds shrinks (AC-9) or when a dependency "
            "vanishes from a component that still declares the affected plane "
            "with no degradation_markers entry (AC-8, the revert-orphan rule). "
            "Omit to skip both ratchets (e.g. a plain local structural check)."
        ),
    )
    parser.add_argument(
        "--check-component-coverage", action="store_true",
        help=(
            "AC-6: enumerate LIVE Lambda functions via lambda:ListFunctions "
            "(reusing verify_lambda_arch_parity.py's own "
            "_enumerate_live_lambda_functions -- never a second enumeration "
            "mechanism) and report how many declared components in this file "
            "correspond to a live function, by name (+ -gamma variant). "
            "Informational only -- prints [UNKNOWN] and does not fail the run "
            "when live access is unavailable. Requires boto3 + AWS credentials."
        ),
    )
    args = parser.parse_args()

    closure = load_closure()

    structural_errors = validate_structure(closure)
    if structural_errors:
        print("[ERROR] Component dependency closure structural validation FAILED:")
        for err in structural_errors:
            print(f"  {err}")
        return 1
    print(
        f"[INFO] Structural validation passed: {len(closure['components'])} "
        f"component(s) declared, enforced_dependency_kinds="
        f"{sorted(closure['enforced_dependency_kinds'])}"
    )

    ownership_errors = validate_devops_ownership(closure)

    violations, findings = evaluate_closure(closure, live=args.live, region=args.live_region)
    for line in findings:
        print(line)
    if not args.live:
        print(
            "[INFO] --live not passed: PROVISIONED_ON_PLANE dependencies of kind "
            "lambda_layer / s3_bucket / external_layer were reported UNKNOWN, "
            "not checked against AWS. This is NOT a pass -- see the [UNKNOWN] "
            "lines above."
        )

    ratchet_errors: list[str] = []
    if args.base_ref:
        ratchet_errors = validate_ratchets(closure, args.base_ref)
        if not ratchet_errors:
            print(
                f"[INFO] Ratchets clear against {args.base_ref}: "
                f"enforced_dependency_kinds did not shrink, no un-marked "
                f"revert-orphans."
            )
    else:
        print(
            "[INFO] --base-ref not passed: enforced_dependency_kinds ratchet "
            "(AC-9) and revert-orphan rule (AC-8) were skipped, not vacuously "
            "passed -- nothing to diff against for a plain local structural check."
        )

    coverage_status = None
    if args.check_component_coverage:
        coverage_errors, coverage_status = _validate_component_coverage(closure, region=args.live_region)
        ownership_errors.extend(coverage_errors)

    all_errors = ownership_errors + violations + ratchet_errors
    if all_errors:
        print("[ERROR] Component dependency closure check FAILED:")
        for err in all_errors:
            print(f"  ::error:: {err}")
        print(f"[FAIL] {len(all_errors)} violation(s).")
        return 1

    print(
        "[SUCCESS] Component dependency closure: structurally valid, every "
        "enforced finding accounted for (PASS, tracked GAP, or "
        "NOT_APPLICABLE_ON_PLANE), no stale ledger entries, ratchets clear."
    )
    return 0


def _validate_component_coverage(closure: dict, region: str) -> tuple[list[str], str]:
    """AC-6: live-derived, never manifest-derived. Reuses
    verify_lambda_arch_parity.py's _enumerate_live_lambda_functions -- the
    exact function tools/verify_lambda_arch_parity.py's own AC-6 cross-source
    reconciliation uses -- rather than writing a third enumeration path."""
    declared = {c["name"] for c in closure.get("components", []) if c.get("name")}
    declared_all = declared | {f"{n}-gamma" for n in declared}

    live, reason = _arch_parity._enumerate_live_lambda_functions(region=region)
    if live is None:
        print(
            f"[UNKNOWN] Component coverage (ENC-TSK-P11 AC-6): live Lambda "
            f"enumeration unavailable ({reason}). This is NOT a pass -- "
            f"declared-vs-live component coverage did not run this invocation. "
            f"{len(declared)} component(s) known from "
            f"{CLOSURE_PATH.relative_to(REPO_ROOT)}; none were checked against "
            f"the live account."
        )
        return [], "UNKNOWN_NO_LIVE_ACCESS"

    covered = sorted(n for n in declared if n in live or f"{n}-gamma" in live)
    uncovered = sorted(declared - set(covered))
    print(
        f"[INFO] Component coverage (ENC-TSK-P11 AC-6): {len(live)} live "
        f"Lambda function(s) enumerated; {len(covered)} of {len(declared)} "
        f"declared component(s) matched to a live function "
        f"({', '.join(covered) or 'none'})."
    )
    if uncovered:
        print(
            f"[INFO] {len(uncovered)} declared component(s) not currently live "
            f"(not yet deployed, prod-only/gamma-only by design, or a stale "
            f"declaration) -- reported for visibility only, not failed: "
            f"{', '.join(uncovered)}"
        )
    return [], "RECONCILED"


if __name__ == "__main__":
    sys.exit(main())
