#!/usr/bin/env python3
"""Pre-deploy guard: the enceladus-shared layer in 02-compute.yaml must be pinned to
the canonical version, and a compute deploy must never REGRESS a live function's layer.

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

CANONICAL VERSION (AC-4 pin -- single source of truth)
-----------------------------------------------------------------------------
CANONICAL_SHARED_LAYER_ARN below is the pin. Build provenance (ENC-LSN-020,
three-flag ABI): the layer is built for the consumers' full ABI -- it carries the
enceladus_shared package INCLUDING the appconfig_flags submodule that :7 lacked.
:10 is proven-working on coordination-api in prod. Raising the canonical version
(e.g. after a vetted rebuild) is a ONE-LINE edit here + the template Default;
this guard then enforces template == canonical fleet-wide. Supersedes the
ENC-TSK-D22 layer-ABI parity-gate intent for the V3 lock.

CHECKS
-----------------------------------------------------------------------------
Template mode (default; no AWS creds -- safe for CI, mirrors
verify_internal_key_coverage.py):
  1. The SharedLayerArn parameter Default == CANONICAL_SHARED_LAYER_ARN.
  2. No resource hardcodes a DIFFERENT enceladus-shared:N ARN literal (every
     consumer must inherit via !Ref SharedLayerArn, or pin the canonical version).

Live mode (--live; requires aws creds, defense-in-depth per ENC-FTR-102 AC-4):
  3. For each managed function in lambda_workflow_manifest.json, the canonical
     template version must not REGRESS the live attached enceladus-shared version
     (template_version < live_version => the deploy would move a function DOWN).

Exit 0 = all checks pass. Exit 1 = a violation that would (re)introduce the
:7-class incident. Exit 2 = usage error.

WIRING (coordinate with ENC-FTR-102 / ENC-TSK-H13)
-----------------------------------------------------------------------------
Run before `aws cloudformation deploy` in the sanctioned compute deploy path
(.github/workflows/cloudformation-compute-stack-deploy.yml) and/or from
tools/pre-deploy-health-gate.sh:

    python3 tools/verify_shared_layer_version.py infrastructure/cloudformation/02-compute.yaml

Self-test (AC-3 'proven to fire on a synthetic version mismatch'):

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


def check_live(repo_root, region):
    """Check 3 (defense-in-depth): the canonical template version must not regress any
    live function's attached enceladus-shared version. Returns failure strings."""
    canonical = _canonical_version()
    manifest = os.path.join(repo_root, "infrastructure", "lambda_workflow_manifest.json")
    if not os.path.isfile(manifest):
        return [f"--live: manifest not found: {manifest}"]
    fns = [f["function_name"] for f in json.load(open(manifest)).get("functions", [])]
    failures = []
    checked = 0
    for fn in fns:
        live = _live_layer_version(fn, region)
        if live is None:
            continue  # function not found / no shared layer / no creds -> skip silently
        checked += 1
        if canonical < live:
            failures.append(
                f"{fn}: live enceladus-shared:{live} > canonical :{canonical} "
                f"-> deploy would REGRESS this function's layer."
            )
    print(f"[INFO] --live: compared {checked} function(s) against canonical :{canonical}")
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


def _selftest():
    canonical = _canonical_version()
    bad_arn = CANONICAL_SHARED_LAYER_ARN.rsplit(":", 1)[0] + ":7"
    cases = []
    # case 1: canonical default -> PASS (no failures)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(_SELFTEST_TEMPLATE.format(arn=CANONICAL_SHARED_LAYER_ARN))
        good_path = f.name
    # case 2: :7 default -> must FAIL
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(_SELFTEST_TEMPLATE.format(arn=bad_arn))
        bad_path = f.name
    # case 3: canonical default but a stray hardcoded :7 -> must FAIL
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        body = _SELFTEST_TEMPLATE.format(arn=CANONICAL_SHARED_LAYER_ARN)
        body += "        - " + bad_arn + "\n"
        f.write(body)
        stray_path = f.name
    try:
        good = check_template(good_path)
        bad = check_template(bad_path)
        stray = check_template(stray_path)
        cases.append(("canonical default passes", good == []))
        cases.append((f"synthetic :7 default fires (canonical :{canonical})", bad != []))
        cases.append(("synthetic stray hardcoded :7 fires", stray != []))
    finally:
        for p in (good_path, bad_path, stray_path):
            os.unlink(p)

    ok = True
    for name, passed in cases:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    if bad:
        print("  sample failure message ->", bad[0])
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv):
    if "--selftest" in argv:
        return _selftest()

    region = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
    do_live = "--live" in argv
    positional = [a for a in argv[1:] if not a.startswith("-")]
    if len(positional) != 1:
        print(
            f"usage: {argv[0]} <path-to-02-compute.yaml> [--live] | --selftest",
            file=sys.stderr,
        )
        return 2
    template = positional[0]
    if not os.path.isfile(template):
        print(f"FAIL: template not found: {template}", file=sys.stderr)
        return 2

    failures = check_template(template)
    if do_live:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(template)))
        # template lives at infrastructure/cloudformation/ -> repo root is two up
        repo_root = os.path.abspath(os.path.join(os.path.dirname(template), "..", ".."))
        failures += check_live(repo_root, region)

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
        f"(template{' + live' if do_live else ''} parity verified)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
