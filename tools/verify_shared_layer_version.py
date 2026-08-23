#!/usr/bin/env python3
"""Pre-deploy guard: the enceladus-shared layer in 02-compute.yaml must be pinned to
the canonical version, the sanctioned compute-deploy workflow must PASS that version as
a --parameter-override, and a compute deploy must never leave a live function on a
non-canonical layer.

WHY (ENC-TSK-H24, child of ENC-FTR-103) -- the :7-vs-:10 fix
-----------------------------------------------------------------------------
The enceladus-shared:10 layer is the appconfig_flags-bearing SUPERSET of :7
(:10 == :7 + enceladus_shared.appconfig_flags). The F65 hotfix (2026-04-21) moved
prod functions to :10 out-of-band but left the CFN default at :7; the 2026-06-18
full-env CFN deploy then reset functions to :7 -> Runtime.ImportModuleError
'No module named enceladus_shared.appconfig_flags' (AXIS 2 of the Sev-1, ENC-LSN-053).
ENC-TSK-H05 codified the template default to :10. This guard makes that pin
ENFORCED so :7 (or any non-canonical version) can never silently return via the
template default or a per-function hardcode.

WHY (ENC-TSK-H28 / ENC-ISS-385) -- closing the template-Default-only blind spot
-----------------------------------------------------------------------------
H24 enforced template Default == :10, yet two successful compute deploys still left
21/23 fns on :7. ROOT CAUSE: `aws cloudformation deploy` REUSES the stack's stored
parameter value for any param NOT in --parameter-overrides (the template Default
applies only when the stack has no stored value). The deployed enceladus-compute
stack stored SharedLayerArn=:7 and the workflow never passed it, so every deploy
reused :7 and the :10 Default was inert ("No changes to deploy" for layers). A gate
that checks only the TEMPLATE stays green while the DEPLOYED param -- and live --
stay :7. A template Default is NOT a deployed value. This guard now also asserts the
workflow passes the canonical override, and (--live) reconciles the deployed stack
param + live function layers against canonical.

CANONICAL VERSION (AC-4 pin -- single source of truth)
-----------------------------------------------------------------------------
CANONICAL_SHARED_LAYER_ARN below is the pin. Build provenance (ENC-LSN-020,
three-flag ABI): the layer is built for the consumers' full ABI -- it carries the
enceladus_shared package INCLUDING the appconfig_flags submodule that :7 lacked.
:10 is proven-working on coordination-api in prod. Raising the canonical version
(e.g. after a vetted rebuild) is a ONE-LINE edit here + the template Default + the
workflow override; this guard then enforces template == workflow == canonical
fleet-wide. Supersedes the ENC-TSK-D22 layer-ABI parity-gate intent for the V3 lock.

CHECKS
-----------------------------------------------------------------------------
Static mode (default; no AWS creds -- safe for CI, fail-closed):
  1. The SharedLayerArn parameter Default == CANONICAL_SHARED_LAYER_ARN.
  2. No resource hardcodes a DIFFERENT enceladus-shared:N ARN literal (every
     consumer must inherit via !Ref SharedLayerArn, or pin the canonical version).
  3. (ENC-TSK-H28 / ENC-ISS-385) The sanctioned compute-deploy workflow PASSES
     SharedLayerArn=CANONICAL in `aws cloudformation deploy --parameter-overrides`.
     Without it the deploy reuses the stale stored param (:7) and the :10 template
     Default is inert -- the H24 gate stayed green while live stayed :7 on 21/23 fns.

Live mode (--live; requires aws creds -- reconciliation / defense-in-depth per
ENC-FTR-102 AC-4. Run to PROVE the heal post-deploy or to detect drift; NOT the
pre-deploy blocker -- pre-deploy the live state legitimately sits at :7 until the
deploy runs, which is exactly why checks 1-3 are the pre-deploy gate):
  4. The DEPLOYED stack's SharedLayerArn parameter (describe-stacks) == canonical.
  5. Every managed function in lambda_workflow_manifest.json has its live attached
     enceladus-shared version == canonical -- FIRING on a STALE version (live <
     canonical, the :7-stuck state) as well as a REGRESS (live > canonical).
     --regress-only narrows checks 4-5 to fire ONLY on a REGRESS (live > canonical),
     TOLERATING a stale live -- the pre-deploy regression guard used by
     tools/pre-deploy-health-gate.sh, where a stale :7 is the state THIS deploy heals
     (firing on it pre-deploy would deadlock the heal). Post-deploy, use bare --live.
  5b. (ENC-ISS-656) Same as 5, for each function's "-gamma" twin, gated on a
      gamma-targeted --stack-name so a prod-targeted run is unaffected by gamma drift.
  6. (ENC-TSK-P13 AC-5) LIVE-DERIVED consumer census -- NOT manifest-driven, unlike
     5/5b. Enumerates every function the ACCOUNT reports as carrying enceladus-shared
     (`aws lambda list-functions`, no manifest consulted) and diffs it against the
     manifest-derived set from 5/5b. Anything live the manifest never named is an
     UNKNOWN CONSUMER -- a coverage gap distinct from the version-drift STALE/REGRESS
     classes above (an unknown consumer could even be on the canonical version and 5/5b
     would never notice, because they never look at a function the manifest didn't
     name). This is the check that would have caught
     enceladus-checkout-service-auto-gamma -- live in the account, enceladus-shared
     attached, absent from lambda_workflow_manifest.json for BOTH planes. Scoped to the
     SAME plane as --stack-name, for the same ENC-ISS-624 reason 5b is gamma-scoped.

Exit 0 = all checks pass. Exit 1 = a violation that would (re)introduce the
:7-class incident. Exit 2 = usage error.

WIRING (coordinate with ENC-FTR-102 / ENC-TSK-H13)
-----------------------------------------------------------------------------
Pre-deploy (static, no creds) -- run in the sanctioned compute deploy path
(.github/workflows/cloudformation-compute-stack-deploy.yml) and/or from
tools/pre-deploy-health-gate.sh. The workflow path is auto-derived from the
template's repo root; override with --workflow:

    python3 tools/verify_shared_layer_version.py infrastructure/cloudformation/02-compute.yaml

Post-deploy reconciliation (proves the :7->:10 heal moved live; ENC-ISS-385 AC):

    python3 tools/verify_shared_layer_version.py infrastructure/cloudformation/02-compute.yaml \
        --live --stack-name enceladus-compute   # or enceladus-compute-gamma

Self-test (ENC-TSK-H24 AC-3 + ENC-TSK-H28 AC-2: fires on a synthetic version
mismatch, a missing/non-canonical workflow override, and a stale :7 live param):

    python3 tools/verify_shared_layer_version.py --selftest
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# AC-4 canonical pin. ENC-TSK-O94 (ENC-ISS-656) moved this :10 -> :12.
# History: :10 was the appconfig_flags-bearing superset of :7 (ENC-TSK-H24 / ENC-FTR-103).
# :12 is in turn a pure-Python superset of :10 adding github_app_auth, record_extensions,
# relationship_store and version_seq. ENC-TSK-O07 moved three functions onto :12 without
# bumping this constant, which check 5b (gamma-aware since ENC-TSK-O78) then caught as a
# would-be downgrade. Moving a function to a new layer version and bumping this pin are
# ONE change, not two.
CANONICAL_SHARED_LAYER_ARN = (
    "arn:aws:lambda:us-west-2:356364570033:layer:enceladus-shared:12"
)

# ENC-TSK-H28 / ENC-ISS-385: the sanctioned compute-deploy workflow that MUST pass
# SharedLayerArn in --parameter-overrides (path relative to repo root; auto-derived from
# the template's location, overridable with --workflow), and the default stack whose
# deployed SharedLayerArn parameter --live reconciles against.
DEFAULT_WORKFLOW_PATH = ".github/workflows/cloudformation-compute-stack-deploy.yml"
DEFAULT_STACK_NAME = "enceladus-compute"

LAYER_NAME = "enceladus-shared"
# arn:aws:lambda:<region>:<acct>:layer:enceladus-shared:<version>
_ARN_RE = re.compile(
    r"arn:aws:lambda:[a-z0-9-]+:\d+:layer:" + re.escape(LAYER_NAME) + r":(\d+)"
)

# ENC-ISS-459: a template with none of these has no enceladus-shared subject at all
# (e.g. 03-api.yaml -- ApiGatewayV2 + Lambda::Permission entries that reference
# functions by ARN/name, but define no Lambda resource of their own). The gate
# fail-closed on that absence (no resolvable SharedLayerArn Default == violation),
# blocking every non-compute stack unconditionally. Detect the subject instead.
_SHARED_LAYER_PARAM_HEADER_RE = re.compile(r"^  SharedLayerArn:\s*$")
_LAMBDA_SUBJECT_RESOURCE_RE = re.compile(
    r"^\s*Type:\s*AWS::Lambda::(?:Function|LayerVersion)\s*$"
)


def _canonical_version():
    m = _ARN_RE.search(CANONICAL_SHARED_LAYER_ARN)
    return int(m.group(1)) if m else None


def template_has_shared_layer_subject(path):
    """True if `path` has anything for this gate to validate: a SharedLayerArn
    parameter (declared, whether or not its Default resolves), or a
    Lambda::Function / Lambda::LayerVersion resource. False for a template with
    none of these -- the gate does not apply (ENC-ISS-459)."""
    for line in open(path).read().split("\n"):
        if _SHARED_LAYER_PARAM_HEADER_RE.match(line):
            return True
        if _LAMBDA_SUBJECT_RESOURCE_RE.match(line):
            return True
    return False


def shared_layer_default(path):
    """Return the ARN string set as `Default:` of the SharedLayerArn parameter.

    Lightweight line scan (no YAML dep) so the guard runs anywhere in CI: find the
    `  SharedLayerArn:` parameter header, then the first `    Default:` before the
    next top-level (2-space-indented) key.
    """
    lines = open(path).read().split("\n")
    in_param = False
    for line in lines:
        if re.match(r"^  SharedLayerArn:\s*$", line):
            in_param = True
            continue
        if in_param:
            # next top-level key (exactly 2-space indent, not blank/comment) ends the block
            if re.match(r"^  [A-Za-z]", line):
                break
            m = re.match(r"^\s+Default:\s*(\S+)\s*$", line)
            if m:
                return m.group(1).strip().strip("'\"")
    return None


def stray_layer_arns(path):
    """Return list of (line_no, version, text) for any enceladus-shared:N ARN literal
    whose version != canonical. The SharedLayerArn Default itself is excluded (checked
    separately) so a single canonical default does not self-report."""
    canonical = _canonical_version()
    out = []
    in_param = False
    for i, line in enumerate(open(path).read().split("\n"), start=1):
        if re.match(r"^  SharedLayerArn:\s*$", line):
            in_param = True
        elif in_param and re.match(r"^  [A-Za-z]", line):
            in_param = False
        m = _ARN_RE.search(line)
        if not m:
            continue
        if in_param and re.match(r"^\s+Default:", line):
            continue  # the canonical default, validated by check 1
        if int(m.group(1)) != canonical:
            out.append((i, int(m.group(1)), line.strip()))
    return out


def check_template(path):
    """Checks 1-2. Returns list of human-readable failure strings (empty == pass)."""
    failures = []
    canonical = _canonical_version()
    default = shared_layer_default(path)
    if default is None:
        failures.append(
            "SharedLayerArn parameter has no resolvable Default in " + path
        )
    elif default != CANONICAL_SHARED_LAYER_ARN:
        dv = _ARN_RE.search(default)
        dv = dv.group(1) if dv else "?"
        failures.append(
            f"SharedLayerArn Default is :{dv} but canonical is :{canonical} "
            f"({CANONICAL_SHARED_LAYER_ARN}). A deploy would attach the wrong "
            f"enceladus-shared layer fleet-wide (the :7-class incident, ENC-LSN-053)."
        )
    for ln, ver, text in stray_layer_arns(path):
        failures.append(
            f"L{ln}: hardcoded enceladus-shared:{ver} != canonical :{canonical} "
            f"-> {text}. Use !Ref SharedLayerArn or the canonical ARN."
        )
    return failures


def shared_layer_override(path):
    """Return the enceladus-shared ARN passed as the SharedLayerArn override in the
    compute-deploy workflow's `aws cloudformation deploy --parameter-overrides`, or None
    if the workflow does not pass SharedLayerArn. Line scan (no YAML dep): each override is
    its own line `SharedLayerArn="<arn>"` (the file's convention, mirroring the AppConfig*/
    EnceladusCognitoClientSecret overrides). COMMENT lines are skipped so a prose mention of
    `SharedLayerArn=:7` (e.g. the H05/H28 rationale comments) cannot masquerade as the real
    override. A value that is not a recognizable enceladus-shared ARN is returned verbatim
    so check_workflow can report it."""
    if not os.path.isfile(path):
        return None
    for raw_line in open(path).read().split("\n"):
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            continue  # rationale comments may mention SharedLayerArn=:N in prose
        candidate = stripped.rstrip("\\").strip()
        if candidate.startswith("SharedLayerArn="):
            val = candidate[len("SharedLayerArn="):].strip().strip("'\"")
            m = _ARN_RE.search(val)
            return m.group(0) if m else val
    return None


def check_workflow(path):
    """Check 3 (ENC-TSK-H28 / ENC-ISS-385): the compute-deploy workflow must pass
    SharedLayerArn=CANONICAL in --parameter-overrides. Closes the template-Default-only
    blind spot -- `aws cloudformation deploy` reuses the stack's stored param value for
    un-passed params, so the :10 template Default is inert while the deployed param sits
    at :7. Returns failure strings (empty == pass)."""
    canonical = _canonical_version()
    if not os.path.isfile(path):
        return [
            f"compute-deploy workflow not found: {path} -- cannot confirm the deploy "
            f"passes SharedLayerArn=:{canonical}. Without the override the deployed stack "
            f"param (:7) is retained and the template Default is inert (ENC-ISS-385). "
            f"Pass --workflow <path> if the workflow lives elsewhere."
        ]
    override = shared_layer_override(path)
    if override is None:
        return [
            f"{path} does not pass SharedLayerArn in --parameter-overrides. "
            f"`aws cloudformation deploy` retains the stale deployed param (:7) and the "
            f"template :10 Default stays inert -> fns stuck on :7 (ENC-ISS-385). Add "
            f'SharedLayerArn="{CANONICAL_SHARED_LAYER_ARN}" to the override block.'
        ]
    if override != CANONICAL_SHARED_LAYER_ARN:
        ov = _ARN_RE.search(override)
        ov = ov.group(1) if ov else "?"
        return [
            f"{path} passes SharedLayerArn={override} but canonical is "
            f"{CANONICAL_SHARED_LAYER_ARN} (:{ov} != :{canonical}). The deploy would "
            f"force the wrong enceladus-shared version fleet-wide."
        ]
    return []


def _live_layer_version(function_name, region):
    """Return the live attached enceladus-shared layer version for a function, or None."""
    try:
        out = subprocess.check_output(
            [
                "aws", "lambda", "get-function-configuration",
                "--function-name", function_name,
                "--region", region,
                "--query", "Layers[].Arn",
                "--output", "json",
            ],
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    arns = json.loads(out.decode() if isinstance(out, bytes) else out or "null")
    for arn in arns or []:
        m = _ARN_RE.search(arn)
        if m:
            return int(m.group(1))
    return None


def _live_stack_param(stack_name, region):
    """Return the deployed stack's SharedLayerArn parameter version (int), or None if the
    stack / param / creds are unavailable. This is the value `aws cloudformation deploy`
    reuses for an un-passed param -- the exact quantity ENC-ISS-385 turned on."""
    try:
        out = subprocess.check_output(
            [
                "aws", "cloudformation", "describe-stacks",
                "--stack-name", stack_name,
                "--region", region,
                "--query",
                "Stacks[0].Parameters[?ParameterKey=='SharedLayerArn'].ParameterValue",
                "--output", "json",
            ],
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    vals = json.loads(out.decode() if isinstance(out, bytes) else out or "null")
    for val in vals or []:
        m = _ARN_RE.search(val or "")
        if m:
            return int(m.group(1))
    return None


def _live_functions_with_layer(region):
    """Return {function_name: version_int} for EVERY live Lambda function in the
    account/region that has ANY version of enceladus-shared attached (LAYER_NAME,
    via the same _ARN_RE every other check in this file uses) -- discovered by
    enumerating the account (aws lambda list-functions, auto-paginated by the
    CLI), never by consulting a manifest. This is the ENC-TSK-P13 AC-5 primitive:
    check 5/5b above (unchanged) start from lambda_workflow_manifest.json's
    function list and ask "is THIS known function's layer version canonical" --
    manifest-driven by construction, and therefore structurally blind to a live
    function the manifest never named (ENC-ISS-656's fix, PR #1134, was correct
    but exactly this shape of blind -- it could not see
    enceladus-checkout-service-auto-gamma, live in the account and attached to
    enceladus-shared, because that name is absent from
    lambda_workflow_manifest.json for BOTH planes; confirmed live via
    `aws lambda get-function --function-name enceladus-checkout-service-auto-gamma`
    during ENC-TSK-P13). This function instead asks the account itself "which
    live functions have this layer attached at all" and returns ALL of them;
    check_live's new check 6 (below) is what then diffs that live-derived set
    against the manifest-derived set from checks 5/5b to name the unknowns,
    rather than silently iterating past them.

    Returns {} (not None) on any failure (no creds / cli missing / account
    unreadable) so callers can distinguish "queried, found nothing" from
    "could not query" via the accompanying INFO log in check_live, matching the
    existing _live_layer_version / _live_stack_param fail-quiet convention."""
    functions = {}
    try:
        out = subprocess.check_output(
            [
                "aws", "lambda", "list-functions",
                "--region", region,
                "--query", "Functions[].{n:FunctionName,l:Layers[].Arn}",
                "--output", "json",
            ],
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None  # could not query at all -- distinct from "queried, found none"
    rows = json.loads(out.decode() if isinstance(out, bytes) else out or "null") or []
    for row in rows:
        name = row.get("n")
        for arn in row.get("l") or []:
            m = _ARN_RE.search(arn or "")
            if m and name:
                functions[name] = int(m.group(1))
                break
    return functions


def _classify_live_version(label, live_version, canonical, regress_only=False):
    """Pure comparator (no AWS) for checks 4-5. Returns a failure string when the live
    version != canonical (STALE if below, REGRESS if above), else None. Factored out so
    the FIRE-on-:7 / PASS-on-:10 behavior (ENC-TSK-H28 AC-2) is unit-testable offline.
    regress_only=True tolerates a STALE live (live < canonical) and fires only on a
    REGRESS -- the pre-deploy regression guard (a stale :7 is the state THIS deploy heals,
    so firing on it pre-deploy would deadlock the heal)."""
    if live_version is None:
        return None  # not found / no creds -> skip silently (caller counts checks)
    if live_version == canonical:
        return None
    if live_version < canonical:
        if regress_only:
            return None  # stale tolerated pre-deploy; the deploy heals it
        return (
            f"{label}: live enceladus-shared:{live_version} < canonical :{canonical} "
            f"-> STALE; the :{canonical} heal has NOT moved live here (ENC-ISS-385: the "
            f"stale deployed SharedLayerArn was retained / the override is not deployed yet)."
        )
    return (
        f"{label}: live enceladus-shared:{live_version} > canonical :{canonical} "
        f"-> REGRESS; a deploy would move this function/stack DOWN."
    )


def check_live(repo_root, region, stack_name=DEFAULT_STACK_NAME, regress_only=False):
    """Checks 4-5 (reconciliation / defense-in-depth): the DEPLOYED stack's SharedLayerArn
    parameter and every managed function's live attached enceladus-shared version must
    EQUAL canonical -- firing on a stale :7 (heal not applied) as well as a regress.
    Returns failure strings. Run post-deploy to prove the heal. With regress_only=True it
    becomes the PRE-deploy regression guard (tolerates stale :7 -- the deploy heals it --
    and fires only on a function/stack ABOVE canonical), so it can run before the heal
    without deadlocking it."""
    canonical = _canonical_version()
    failures = []
    mode = " (regress-only)" if regress_only else ""

    # Check 4: the deployed stack parameter -- the value the deploy actually reuses.
    stack_ver = _live_stack_param(stack_name, region)
    if stack_ver is None:
        print(
            f"[INFO] --live{mode}: stack '{stack_name}' SharedLayerArn param not readable "
            f"(missing stack / param / creds) -- skipped check 4."
        )
    else:
        fail = _classify_live_version(
            f"stack '{stack_name}' SharedLayerArn param", stack_ver, canonical, regress_only
        )
        if fail:
            failures.append(fail)
        else:
            print(
                f"[INFO] --live{mode}: stack '{stack_name}' SharedLayerArn param = :{stack_ver} "
                f"(canonical :{canonical})."
            )

    # Check 5: every managed function's live attached layer version (PROD plane).
    # Unchanged from before ENC-ISS-656 -- prod-named functions only, same classifier,
    # same failure list. This loop's behavior must not change.
    manifest = os.path.join(repo_root, "infrastructure", "lambda_workflow_manifest.json")
    if not os.path.isfile(manifest):
        failures.append(f"--live: manifest not found: {manifest}")
        return failures
    fns = [f["function_name"] for f in json.load(open(manifest)).get("functions", [])]
    checked = 0
    for fn in fns:
        live = _live_layer_version(fn, region)
        if live is None:
            continue  # function not found / no shared layer / no creds -> skip silently
        checked += 1
        fail = _classify_live_version(fn, live, canonical, regress_only)
        if fail:
            failures.append(fail)
    print(f"[INFO] --live{mode}: compared {checked} function(s) against canonical :{canonical}.")

    # Check 5b (ENC-ISS-656): the SAME manifest's live attached layer version, but for
    # each function's "-gamma" twin. Before this, the gamma plane was structurally
    # invisible here -- ENC-TSK-O78's manual census found 4 gamma functions (out of 46
    # attaching enceladus-shared) live on :12 while this gate reported OK, because this
    # loop simply never queried a "-gamma" name regardless of --stack-name. That is a
    # blindness, not a tolerance: nothing upstream decided gamma drift was acceptable,
    # the gate just never looked. This loop closes that gap.
    #
    # Deliberately reuses _classify_live_version unchanged (same canonical, same
    # STALE/REGRESS math, same regress_only semantics) rather than inventing a
    # gamma-specific canonical -- ENC-ISS-656 explicitly rejected bumping the pin to
    # :12 for this plan (that is fleet-wide, production-affecting, BRD Phase 5 /
    # ENC-PLN-082 territory), so the gate must go RED against the live :12 drift, not
    # quietly grow a second accepted version. The label makes the plane explicit so a
    # human reading FAIL output does not mistake this for the prod ABI-regression class
    # checks 1-4 exist to prevent -- ENC-ISS-624 already showed that conflation costs a
    # P1 investigation. A gamma mismatch is appended to the SAME `failures` list (same
    # nonzero exit code as every other check here) rather than a separate warn tier:
    # per ENC-ISS-656, the four drifted functions are confirmed pure-Python and
    # architecture-neutral at every inspected version (zero .so files), so this is not
    # the breakage class -- but "not a breakage" must still mean RED, never silently
    # green, or the next real gamma regression ships behind the same shrug ENC-ISS-385
    # already taught this platform to fear.
    #
    # SCOPED TO A GAMMA-TARGETED INVOCATION ONLY (stack_name ends with "-gamma"). This
    # is the one condition that must hold for "keep the prod path behaving exactly as
    # it does now": tools/pre-deploy-health-gate.sh invokes this script once per plane
    # with --stack-name set to that plane's stack (enceladus-compute or
    # enceladus-compute-gamma). Without this guard, a PROD-targeted invocation would
    # start failing on gamma-only drift it has no power to fix and no business gating
    # on -- exactly the "mandatory guard is red for a reason unrelated to the change
    # under review" failure mode ENC-ISS-624 already diagnosed as teaching operators to
    # wave the gate through. check 5 (prod names, above) is intentionally left
    # unconditional -- that was already its behavior before this change and is
    # unrelated to stack_name -- only this new gamma loop is gated on the target plane.
    is_gamma_target = stack_name.endswith("-gamma")
    if is_gamma_target:
        checked_gamma = 0
        for fn in fns:
            gamma_fn = f"{fn}-gamma"
            live = _live_layer_version(gamma_fn, region)
            if live is None:
                continue  # no gamma twin / no shared layer / no creds -> skip silently
            checked_gamma += 1
            fail = _classify_live_version(f"{gamma_fn} (gamma-plane; see ENC-ISS-656)", live, canonical, regress_only)
            if fail:
                failures.append(fail)
        print(
            f"[INFO] --live{mode}: compared {checked_gamma} gamma-plane function(s) "
            f"against canonical :{canonical} (ENC-ISS-656)."
        )
    else:
        print(
            f"[INFO] --live{mode}: stack '{stack_name}' is not gamma-suffixed -- "
            f"skipping check 5b (gamma-plane drift, ENC-ISS-656); prod-targeted "
            f"invocations are unaffected by gamma-plane state."
        )

    # Check 6 (ENC-TSK-P13 AC-5): LIVE-DERIVED consumer census -- not manifest-driven.
    # Checks 5/5b above start from lambda_workflow_manifest.json's function list and
    # ask "is THIS KNOWN function's live layer version canonical" -- by construction
    # they can only ever be as complete as the manifest. ENC-ISS-656's fix (PR #1134)
    # was correct on its own terms but exactly this shape of blind: it cannot see a
    # live function the manifest never named. ENC-TSK-P13 found one --
    # enceladus-checkout-service-auto-gamma is live in the account, carries
    # enceladus-shared, and is absent from the manifest for BOTH planes (confirmed via
    # `aws lambda get-function --function-name enceladus-checkout-service-auto-gamma`).
    # This check instead asks the ACCOUNT ITSELF which live functions carry the layer
    # (_live_functions_with_layer, one list-functions scan, no manifest involved) and
    # diffs that against the manifest-derived set from checks 5/5b -- anything live
    # that the manifest never named is an UNKNOWN CONSUMER, a distinct failure class
    # from the STALE/REGRESS version-drift checks above (this is a *coverage* gap, not
    # a *version* gap -- an unknown consumer could even be sitting on the canonical
    # version, and checks 5/5b would stay silent forever because they never look at it).
    #
    # Scoped to the SAME plane as stack_name, for the SAME ENC-ISS-624 reason check 5b
    # is gamma-scoped immediately above: a prod-targeted invocation must not go red
    # because of an unknown GAMMA function it has no power to fix and no business
    # gating on, and a gamma-targeted invocation must not go red over unknown PROD
    # surface it isn't running against. "Plane" is decided the same way as every other
    # plane test in this file: a "-gamma" name suffix.
    live_map = _live_functions_with_layer(region)
    if live_map is None:
        print(
            f"[INFO] --live{mode}: could not enumerate live functions via "
            f"`aws lambda list-functions` (no creds / denied / cli missing) -- "
            f"skipped check 6 (live-derived consumer census, ENC-TSK-P13 AC-5)."
        )
    else:
        known = set(fns)
        if is_gamma_target:
            known |= {f"{fn}-gamma" for fn in fns}
            live_plane = {n: v for n, v in live_map.items() if n.endswith("-gamma")}
            plane_label = "gamma-plane"
        else:
            live_plane = {n: v for n, v in live_map.items() if not n.endswith("-gamma")}
            plane_label = "prod-plane"
        unknown = sorted(set(live_plane) - known)
        for fn in unknown:
            failures.append(
                f"UNKNOWN CONSUMER (live-derived, ENC-TSK-P13 AC-5): {fn} is LIVE on "
                f"enceladus-shared:{live_plane[fn]} but is absent from "
                f"lambda_workflow_manifest.json ({plane_label}). A manifest-driven "
                f"check (checks 5/5b) cannot see a consumer the manifest never named "
                f"-- this one can, because it starts from the account, not the "
                f"manifest. Add it to the manifest (if it should exist) or delete the "
                f"function (if it should not) -- either way this cannot stay silent."
            )
        print(
            f"[INFO] --live{mode}: check 6 (ENC-TSK-P13 AC-5, live-derived): "
            f"{len(live_plane)} live {plane_label} function(s) carry enceladus-shared; "
            f"{len(unknown)} absent from the manifest."
        )
    return failures


# --------------------------------------------------------------------------- selftest
_SELFTEST_TEMPLATE = """\
Parameters:
  CorsOrigin:
    Type: String
    Default: https://jreese.net
  SharedLayerArn:
    Type: String
    Default: {arn}
  NextParam:
    Type: String
Resources:
  SomeFunction:
    Properties:
      Layers:
        - !Ref SharedLayerArn
"""

# ENC-ISS-459: an API-Gateway-only stack (like 03-api.yaml) -- integrations reference
# Lambda functions by ARN/name, but the template defines no Lambda resource of its own
# and takes no SharedLayerArn parameter. Nothing here for the gate to validate.
_SELFTEST_TEMPLATE_NO_SUBJECT = """\
Parameters:
  EnvironmentSuffix:
    Type: String
    Default: ""
Resources:
  SomeRoute:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref SomeApi
  SomePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Sub "some-function${EnvironmentSuffix}"
"""

# Regression guard: a template with a bare Lambda::Function resource but no
# SharedLayerArn parameter still has a subject -- the gate must still apply (and
# check_template still fires: no resolvable Default at all).
_SELFTEST_TEMPLATE_LAMBDA_NO_PARAM = """\
Resources:
  SomeFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
"""

# Minimal compute-deploy workflow fragment. check_workflow line-scans for the override,
# so this need not be valid YAML -- only the --parameter-overrides shape matters.
_SELFTEST_WORKFLOW = """\
      - name: Deploy Compute stack (02-compute)
        run: |
          aws cloudformation deploy \\
            --stack-name enceladus-compute \\
            --parameter-overrides \\
              DataStackName="enceladus-data" \\
              CoordinationInternalApiKey="$KEY"{override}
"""


def _selftest():
    canonical = _canonical_version()
    bad_arn = CANONICAL_SHARED_LAYER_ARN.rsplit(":", 1)[0] + ":7"
    canonical_override_line = ' \\\n              SharedLayerArn="%s"' % CANONICAL_SHARED_LAYER_ARN
    bad_override_line = ' \\\n              SharedLayerArn="%s"' % bad_arn
    cases = []
    tmp_paths = []

    def _tmp(suffix, body):
        f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
        f.write(body)
        f.close()
        tmp_paths.append(f.name)
        return f.name

    # template checks (1-2)
    good_path = _tmp(".yaml", _SELFTEST_TEMPLATE.format(arn=CANONICAL_SHARED_LAYER_ARN))
    bad_path = _tmp(".yaml", _SELFTEST_TEMPLATE.format(arn=bad_arn))
    stray_path = _tmp(
        ".yaml",
        _SELFTEST_TEMPLATE.format(arn=CANONICAL_SHARED_LAYER_ARN)
        + "        - " + bad_arn + "\n",
    )
    # workflow check (3)
    wf_ok = _tmp(".yml", _SELFTEST_WORKFLOW.format(override=canonical_override_line))
    wf_missing = _tmp(".yml", _SELFTEST_WORKFLOW.format(override=""))
    wf_bad = _tmp(".yml", _SELFTEST_WORKFLOW.format(override=bad_override_line))
    # ENC-ISS-459 applicability gate
    no_subject_path = _tmp(".yaml", _SELFTEST_TEMPLATE_NO_SUBJECT)
    lambda_no_param_path = _tmp(".yaml", _SELFTEST_TEMPLATE_LAMBDA_NO_PARAM)

    bad = []
    try:
        bad = check_template(bad_path)
        cases.append(("canonical template default passes", check_template(good_path) == []))
        cases.append(
            (f"synthetic :7 template default fires (canonical :{canonical})", bad != [])
        )
        cases.append(("synthetic stray hardcoded :7 fires", check_template(stray_path) != []))
        # check 3: workflow override
        cases.append(
            ("workflow with canonical SharedLayerArn override passes", check_workflow(wf_ok) == [])
        )
        cases.append(
            (
                "workflow MISSING SharedLayerArn override fires (ENC-ISS-385 blind spot)",
                check_workflow(wf_missing) != [],
            )
        )
        cases.append(
            ("workflow with stale :7 SharedLayerArn override fires", check_workflow(wf_bad) != [])
        )
        # checks 4-5: live comparator (synthetic; no AWS)
        cases.append(
            (
                "--live stale :7 stack param FIRES (ENC-TSK-H28 AC-2)",
                _classify_live_version("stack 'enceladus-compute' param", 7, canonical) is not None,
            )
        )
        cases.append(
            (
                f"--live reconciled :{canonical} PASSES",
                _classify_live_version("stack 'enceladus-compute' param", canonical, canonical) is None,
            )
        )
        cases.append(
            (
                "--live regress (> canonical) fires",
                _classify_live_version("fn", canonical + 1, canonical) is not None,
            )
        )
        cases.append(
            (
                "--live --regress-only TOLERATES stale :7 (no pre-deploy deadlock)",
                _classify_live_version("stack param", 7, canonical, regress_only=True) is None,
            )
        )
        cases.append(
            (
                "--live --regress-only still fires on a regress",
                _classify_live_version("fn", canonical + 1, canonical, regress_only=True) is not None,
            )
        )

        # ENC-ISS-656: prove check_live's NEW gamma loop (check 5b) is actually wired
        # and reachable, not just that the underlying _classify_live_version primitive
        # works in isolation (checks above already cover that). This monkeypatches the
        # two AWS-calling seams (_live_layer_version, _live_stack_param) so check_live
        # itself -- the real function, unmodified -- runs end-to-end against synthetic
        # data with no AWS creds required. Without this, a future edit could silently
        # turn check 5b into a no-op (e.g. an early continue, a wrong suffix, a typo in
        # "-gamma") and every case above would keep passing.
        global _live_layer_version, _live_stack_param, _live_functions_with_layer
        _real_live_layer_version = _live_layer_version
        _real_live_stack_param = _live_stack_param
        _real_live_functions_with_layer = _live_functions_with_layer
        # Check 6 (ENC-TSK-P13 AC-5) is unconditional in check_live, so every case
        # below must also stub this seam -- otherwise the "offline, no AWS creds
        # required" selftest would shell out to the real `aws lambda list-functions`
        # on every check_live() call in this block. Default: no live-derived
        # consumers at all, so cases that are not specifically testing check 6 see
        # zero contribution from it (an empty dict, not None -- None means
        # "could not query" and would just print an INFO skip, which is also
        # exercised explicitly below).
        _live_functions_with_layer = lambda region: {}
        gamma_test_tmpdir = tempfile.mkdtemp(prefix="iss656-gamma-selftest-")
        try:
            infra_dir = os.path.join(gamma_test_tmpdir, "infrastructure")
            os.makedirs(infra_dir, exist_ok=True)
            with open(os.path.join(infra_dir, "lambda_workflow_manifest.json"), "w") as mf:
                json.dump({"functions": [{"function_name": "iss656-synthetic-fn"}]}, mf)

            def _fake_stack_param(stack_name, region):
                return canonical  # keep check 4 quiet; this test is only about check 5b

            def _make_fake_live(gamma_version):
                def _fake(function_name, region):
                    if function_name == "iss656-synthetic-fn":
                        return canonical  # prod twin stays clean/canonical
                    if function_name == "iss656-synthetic-fn-gamma":
                        return gamma_version
                    return None
                return _fake

            _live_stack_param = _fake_stack_param

            _live_layer_version = _make_fake_live(canonical + 1)
            drifted_failures = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack-gamma")
            cases.append(
                (
                    "ENC-ISS-656: synthetic gamma fn on non-canonical version FAILS "
                    "check_live against a gamma-targeted stack (gamma path is "
                    "reachable, not skipped)",
                    any("iss656-synthetic-fn-gamma" in f for f in drifted_failures),
                )
            )

            _live_layer_version = _make_fake_live(canonical)
            clean_failures = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack-gamma")
            cases.append(
                (
                    "ENC-ISS-656: synthetic gamma fn on canonical version PASSES "
                    "check_live against a gamma-targeted stack (no false positive "
                    "once reconciled)",
                    not any("iss656-synthetic-fn" in f for f in clean_failures),
                )
            )

            # The scope guard itself: a PROD-targeted stack name (no "-gamma" suffix)
            # must NOT see gamma drift at all, even with the exact same drifted
            # synthetic function live underneath it -- this is what "keep the prod
            # path behaving exactly as it does now" means operationally, and it is
            # the one thing that stops this fix from turning into a new way for
            # unrelated gamma drift to block a prod deploy (the ENC-ISS-624 failure
            # shape, recurred).
            _live_layer_version = _make_fake_live(canonical + 1)
            prod_targeted_failures = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack")
            cases.append(
                (
                    "ENC-ISS-656: a PROD-targeted stack name (no '-gamma' suffix) "
                    "sees NO gamma-plane check at all, even with live gamma drift "
                    "present -- prod invocations stay unaffected by gamma state",
                    not any("gamma" in f for f in prod_targeted_failures),
                )
            )

            # ---- Check 6 (ENC-TSK-P13 AC-5): live-derived consumer census ----
            # Reset 5/5b's seams to canonical/clean so every failure asserted below
            # can only have come from check 6, never from version drift.
            _live_layer_version = _make_fake_live(canonical)
            _live_stack_param = _fake_stack_param

            # Case A: an UNKNOWN gamma consumer -- live, layer attached, canonical
            # version, absent from the manifest entirely (this is the
            # enceladus-checkout-service-auto-gamma shape: checks 5/5b would stay
            # silent forever on it because they never look at a name the manifest
            # didn't provide).
            _live_functions_with_layer = lambda region: {
                "iss656-synthetic-fn-gamma": canonical,       # known (manifest twin)
                "totally-unknown-fn-gamma": canonical,        # NOT in the manifest
            }
            unknown_gamma_failures = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack-gamma")
            cases.append(
                (
                    "ENC-TSK-P13 AC-5: an unnamed live gamma consumer is caught by "
                    "check 6 even though its layer version is canonical (checks "
                    "5/5b would never see it)",
                    any(
                        "UNKNOWN CONSUMER" in f and "totally-unknown-fn-gamma" in f
                        for f in unknown_gamma_failures
                    ),
                )
            )
            cases.append(
                (
                    "ENC-TSK-P13 AC-5: the manifest-known gamma twin is NOT flagged "
                    "as an unknown consumer",
                    not any(
                        "UNKNOWN CONSUMER" in f and "iss656-synthetic-fn-gamma" in f
                        for f in unknown_gamma_failures
                    ),
                )
            )

            # Case B: plane scoping -- an unknown PROD-named consumer must not leak
            # into a gamma-targeted run, and an unknown GAMMA consumer must not leak
            # into a prod-targeted run. Same ENC-ISS-624 discipline as check 5b.
            _live_functions_with_layer = lambda region: {
                "iss656-synthetic-fn-gamma": canonical,
                "totally-unknown-fn-gamma": canonical,   # gamma-plane unknown
                "totally-unknown-fn": canonical,         # prod-plane unknown
            }
            gamma_targeted = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack-gamma")
            cases.append(
                (
                    "ENC-TSK-P13 AC-5: a gamma-targeted run flags the unknown GAMMA "
                    "consumer but not the unknown PROD one",
                    any("totally-unknown-fn-gamma" in f for f in gamma_targeted)
                    and not any(
                        ("totally-unknown-fn" in f and "gamma" not in f) for f in gamma_targeted
                    ),
                )
            )
            prod_targeted = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack")
            cases.append(
                (
                    "ENC-TSK-P13 AC-5: a prod-targeted run flags the unknown PROD "
                    "consumer but not the unknown GAMMA one",
                    any(
                        ("totally-unknown-fn" in f and "gamma" not in f) for f in prod_targeted
                    )
                    and not any("totally-unknown-fn-gamma" in f for f in prod_targeted),
                )
            )

            # Case C: _live_functions_with_layer returning None (no creds / denied /
            # cli missing) must skip check 6 quietly -- never a crash, never a
            # spurious failure.
            _live_functions_with_layer = lambda region: None
            no_creds_failures = check_live(gamma_test_tmpdir, "us-west-2", "synthetic-stack-gamma")
            cases.append(
                (
                    "ENC-TSK-P13 AC-5: check 6 with no queryable live data (None) "
                    "contributes zero failures rather than crashing or false-firing",
                    not any("UNKNOWN CONSUMER" in f for f in no_creds_failures),
                )
            )
        finally:
            _live_layer_version = _real_live_layer_version
            _live_stack_param = _real_live_stack_param
            _live_functions_with_layer = _real_live_functions_with_layer
            shutil.rmtree(gamma_test_tmpdir, ignore_errors=True)

        # ENC-ISS-459: applicability gate
        cases.append(
            (
                "no-subject (API-only) template is N/A, not a violation",
                template_has_shared_layer_subject(no_subject_path) is False,
            )
        )
        cases.append(
            (
                "template with Lambda::Function but no SharedLayerArn param still has a subject",
                template_has_shared_layer_subject(lambda_no_param_path) is True,
            )
        )
        cases.append(
            (
                "template with SharedLayerArn param still has a subject (regression guard)",
                template_has_shared_layer_subject(good_path) is True,
            )
        )
        cases.append(
            (
                "no-subject template still has a subject-less check_template (would "
                "otherwise fail-close were the gate not skipped)",
                check_template(no_subject_path) != [],
            )
        )
    finally:
        for p in tmp_paths:
            os.unlink(p)

    ok = True
    for name, passed in cases:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    if bad:
        print("  sample template failure ->", bad[0])
    missing_msg = check_workflow_message_sample()
    if missing_msg:
        print("  sample workflow failure ->", missing_msg)
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def check_workflow_message_sample():
    """Return a representative 'missing override' failure message for selftest display."""
    f = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    try:
        f.write(_SELFTEST_WORKFLOW.format(override=""))
        f.close()
        msgs = check_workflow(f.name)
        return msgs[0] if msgs else ""
    finally:
        os.unlink(f.name)


def main(argv):
    if "--selftest" in argv:
        return _selftest()

    region = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
    do_live = False
    regress_only = False
    workflow_opt = None
    stack_name = DEFAULT_STACK_NAME
    positional = []

    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--live":
            do_live = True
        elif a == "--regress-only":
            regress_only = True
        elif a == "--workflow":
            i += 1
            workflow_opt = argv[i] if i < len(argv) else None
        elif a == "--stack-name":
            i += 1
            stack_name = argv[i] if i < len(argv) else stack_name
        elif a.startswith("--workflow="):
            workflow_opt = a.split("=", 1)[1]
        elif a.startswith("--stack-name="):
            stack_name = a.split("=", 1)[1]
        elif a.startswith("-"):
            pass  # unknown flag -- ignore
        else:
            positional.append(a)
        i += 1

    if len(positional) != 1:
        print(
            f"usage: {argv[0]} <path-to-02-compute.yaml> "
            f"[--workflow <deploy-workflow.yml>] "
            f"[--live [--stack-name <name>] [--regress-only]] | --selftest",
            file=sys.stderr,
        )
        return 2
    template = positional[0]
    if not os.path.isfile(template):
        print(f"FAIL: template not found: {template}", file=sys.stderr)
        return 2

    if not template_has_shared_layer_subject(template):
        print(
            f"N/A: {template} declares no SharedLayerArn parameter and no "
            f"Lambda::Function/LayerVersion resource -- the enceladus-shared "
            f"layer-version gate does not apply to this template (ENC-ISS-459)."
        )
        return 0

    # template lives at infrastructure/cloudformation/ -> repo root is two up
    repo_root = os.path.abspath(os.path.join(os.path.dirname(template), "..", ".."))
    workflow = workflow_opt or os.path.join(repo_root, DEFAULT_WORKFLOW_PATH)

    failures = check_template(template)
    failures += check_workflow(workflow)
    if do_live:
        failures += check_live(repo_root, region, stack_name, regress_only)

    if failures:
        print(
            "FAIL: enceladus-shared layer-version parity gate "
            f"(canonical {CANONICAL_SHARED_LAYER_ARN}):",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        f"OK: enceladus-shared pinned to canonical :{_canonical_version()} "
        f"(template + workflow{' + live' if do_live else ''} parity verified)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
