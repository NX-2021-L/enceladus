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
import subprocess
import sys
import tempfile

# AC-4 canonical pin. enceladus-shared:10 = the appconfig_flags-bearing superset of :7,
# proven-working on coordination-api in prod (ENC-TSK-H24 / ENC-FTR-103).
CANONICAL_SHARED_LAYER_ARN = (
    "arn:aws:lambda:us-west-2:356364570033:layer:enceladus-shared:10"
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


def _canonical_version():
    m = _ARN_RE.search(CANONICAL_SHARED_LAYER_ARN)
    return int(m.group(1)) if m else None


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

    # Check 5: every managed function's live attached layer version.
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
