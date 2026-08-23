#!/usr/bin/env python3
"""Consumer census for the enceladus-shared supply chain, spanning BOTH repos
that depend on it (ENC-TSK-P13 AC-2).

WHY BOTH REPOS
-----------------------------------------------------------------------------
enceladus-shared has exactly one real consumer graph but two structurally
different attachment mechanisms, because enceladus OWNS the content and
NX-2021-L/devops only ever CONSUMES it:

  1. NX-2021-L/enceladus (this repo): Lambda functions attach the published
     LAYER by ARN (`Layers: [!Ref SharedLayerArn]` in
     infrastructure/cloudformation/02-compute.yaml). This is the "72 of 92
     functions" population ENC-TSK-O78 measured and ENC-ISS-656 (PR #1134)
     already has drift tooling for (tools/verify_shared_layer_version.py).

  2. NX-2021-L/devops: does NOT attach the layer at all. It fetches ONE
     module (warehouse_registration.py) at BUILD time, pinned by commit +
     sha256 (scripts/fetch_shared_library.py, pin recorded in
     infrastructure/analytics-stack.yaml `shared_library`), and vendors it
     into its own function packages. This is deliberate -- see that script's
     docstring -- not an oversight, but it is a second, structurally
     invisible-from-this-repo consumer relationship. A census that only
     walks 02-compute.yaml never sees it.

A supply-chain census that only covers (1) undercounts the blast radius of an
enceladus_shared change by exactly the two devops functions in (2)
(devops-adhoc-promotion, devops-platform-health per the current pin) -- small
today, but structurally the same class of blind spot ENC-ISS-656 closed for
the gamma plane within this repo. This script closes it across the repo
boundary.

OUTPUT
-----------------------------------------------------------------------------
JSON to stdout: {"enceladus": [...], "devops": [...], "totals": {...}}.
Each enceladus entry is a Lambda::Function resource in 02-compute.yaml with
Layers containing `!Ref SharedLayerArn`, its FunctionName (as a raw !Sub/
literal string -- ${EnvironmentSuffix} etc are left as template text, not
resolved, since resolution depends on the IsGamma condition per-stack).

Each devops entry is a consumer directory declared in that repo's
infrastructure/analytics-stack.yaml `shared_library.consumers` list, fetched
live via `gh api` when reachable (needs `gh` auth with read access to the
PRIVATE NX-2021-L/devops repo) and falling back to a dated, committed
snapshot (DEVOPS_CONSUMERS_SNAPSHOT below) when it is not -- mirroring
fetch_shared_library.py's own SHARED_LIBRARY_LOCAL_SOURCE fallback: a
best-effort live read, never a silent zero, and the fallback is honest about
being a snapshot rather than pretending to be live.

USAGE
-----------------------------------------------------------------------------
    python3 tools/census_shared_layer_consumers.py [--refresh-devops]
        # default: scans every infrastructure/cloudformation/*.yaml template
        # that declares a SharedLayerArn parameter (currently 02-compute.yaml
        # AND 06-appsync-events.yaml -- a single-template scan undercounts).
    python3 tools/census_shared_layer_consumers.py --template <path.yaml>
        # scan exactly one template instead of the auto-discovered set.
    python3 tools/census_shared_layer_consumers.py --selftest
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CFN_DIR = os.path.join(REPO_ROOT, "infrastructure", "cloudformation")

# A SharedLayerArn PARAMETER header -- a template that declares this is a subject
# for this census even if 02-compute.yaml is not the only place a consumer lives.
# ENC-TSK-P13: 06-appsync-events.yaml also declares the parameter and attaches it
# to one function; a single-template scan silently undercounts. Mirrors
# template_has_shared_layer_subject() in tools/verify_shared_layer_version.py.
_SHARED_LAYER_PARAM_HEADER_RE = re.compile(r"^  SharedLayerArn:\s*$")


def discover_templates(cfn_dir: str = CFN_DIR) -> list:
    """Every *.yaml template under infrastructure/cloudformation/ that declares a
    SharedLayerArn parameter -- i.e. every template this census must walk, not
    just 02-compute.yaml (ENC-TSK-P13: 06-appsync-events.yaml is a second one)."""
    if not os.path.isdir(cfn_dir):
        return []
    out = []
    for name in sorted(os.listdir(cfn_dir)):
        if not name.endswith(".yaml"):
            continue
        path = os.path.join(cfn_dir, name)
        try:
            content = open(path).read()
        except OSError:
            continue
        if any(_SHARED_LAYER_PARAM_HEADER_RE.match(ln) for ln in content.split("\n")):
            out.append(path)
    return out

# Dated fallback snapshot of NX-2021-L/devops's infrastructure/analytics-stack.yaml
# `shared_library` block, captured 2026-08-23 (ENC-TSK-P13) via
#   gh api repos/NX-2021-L/devops/contents/infrastructure/analytics-stack.yaml
# Refresh with --refresh-devops when `gh` has read access to that (private) repo;
# this snapshot is the honest fallback when it does not (e.g. most CI contexts,
# where the default GITHUB_TOKEN is scoped to THIS repo only).
DEVOPS_CONSUMERS_SNAPSHOT = {
    "captured_at": "2026-08-23T00:00:00Z",
    "source_repo": "NX-2021-L/devops",
    "source_file": "infrastructure/analytics-stack.yaml",
    "pinned_commit": "d7277132506b68acd98645fe6342f6fa3d70105e",
    "package": "enceladus_shared",
    "modules": ["warehouse_registration.py"],
    "consumers": [
        "services/lambda/adhoc_promotion",
        "services/lambda/platform_health",
    ],
    "mechanism": (
        "build-time fetch + pinned sha256 verification (scripts/"
        "fetch_shared_library.py) -- NOT a Lambda layer attachment. Deliberate "
        "per that script's docstring: a vendored copy would fork silently."
    ),
}

_LAMBDA_FN_RESOURCE_RE = re.compile(r"^  ([A-Za-z0-9]+):\s*$")
_TYPE_RE = re.compile(r"^\s+Type:\s*AWS::Lambda::Function\s*$")
_FUNCTION_NAME_RE = re.compile(r"^\s+FunctionName:\s*(.+?)\s*$")
_SHARED_LAYER_REF_RE = re.compile(r"!Ref\s+SharedLayerArn\b")


def census_enceladus(template_path: str) -> list:
    """Walk ONE template and return every AWS::Lambda::Function resource whose
    Layers list references !Ref SharedLayerArn."""
    if not os.path.isfile(template_path):
        raise SystemExit(f"template not found: {template_path}")

    entries = []
    current_id = None
    current_type_is_function = False
    current_function_name = None
    current_has_shared_layer = False

    def _flush():
        if current_id and current_type_is_function and current_has_shared_layer:
            entries.append(
                {
                    "logical_id": current_id,
                    "function_name": current_function_name,
                }
            )

    for line in open(template_path).read().split("\n"):
        m = _LAMBDA_FN_RESOURCE_RE.match(line)
        if m:
            _flush()
            current_id = m.group(1)
            current_type_is_function = False
            current_function_name = None
            current_has_shared_layer = False
            continue
        if current_id is None:
            continue
        if _TYPE_RE.match(line):
            current_type_is_function = True
            continue
        fn_m = _FUNCTION_NAME_RE.match(line)
        if fn_m and current_function_name is None:
            current_function_name = fn_m.group(1)
        if _SHARED_LAYER_REF_RE.search(line):
            current_has_shared_layer = True
    _flush()
    return entries


def census_enceladus_all(cfn_dir: str = CFN_DIR) -> list:
    """Walk EVERY template under cfn_dir that has a SharedLayerArn subject
    (discover_templates), not just 02-compute.yaml. Each entry is tagged with
    its source template so a 06-appsync-events.yaml consumer isn't confused
    for a 02-compute.yaml one."""
    entries = []
    for template_path in discover_templates(cfn_dir):
        rel = os.path.relpath(template_path, REPO_ROOT)
        for e in census_enceladus(template_path):
            e = dict(e)
            e["template"] = rel
            entries.append(e)
    return entries


def census_devops(refresh: bool = False) -> dict:
    """Return the devops-side consumer block: live via `gh api` if --refresh-devops
    is requested and reachable, else the dated fallback snapshot."""
    if not refresh:
        out = dict(DEVOPS_CONSUMERS_SNAPSHOT)
        out["source"] = "fallback_snapshot"
        return out

    try:
        raw = subprocess.check_output(
            [
                "gh", "api",
                "repos/NX-2021-L/devops/contents/infrastructure/analytics-stack.yaml",
                "--jq", ".content",
            ],
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        import base64
        text = base64.b64decode(raw.strip()).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - best-effort live fetch
        out = dict(DEVOPS_CONSUMERS_SNAPSHOT)
        out["source"] = "fallback_snapshot"
        out["refresh_error"] = f"{type(exc).__name__}: {exc}"
        return out

    commit_m = re.search(r"^\s*commit:\s*(\S+)\s*$", text, re.MULTILINE)
    consumers_m = re.search(r"consumers:\s*\n((?:\s*-\s*\S+\s*\n?)+)", text)
    modules_m = re.search(r"modules:\s*\n((?:\s+\S+\.py:\s*\S+\s*\n?)+)", text)

    consumers = []
    if consumers_m:
        consumers = [
            ln.strip().lstrip("-").strip()
            for ln in consumers_m.group(1).splitlines()
            if ln.strip()
        ]
    modules = []
    if modules_m:
        modules = [
            ln.strip().split(":")[0].strip()
            for ln in modules_m.group(1).splitlines()
            if ln.strip()
        ]

    return {
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_repo": "NX-2021-L/devops",
        "source_file": "infrastructure/analytics-stack.yaml",
        "pinned_commit": commit_m.group(1) if commit_m else None,
        "package": "enceladus_shared",
        "modules": modules or DEVOPS_CONSUMERS_SNAPSHOT["modules"],
        "consumers": consumers or DEVOPS_CONSUMERS_SNAPSHOT["consumers"],
        "mechanism": DEVOPS_CONSUMERS_SNAPSHOT["mechanism"],
        "source": "live",
    }


def build_census(template_path: str = None, refresh_devops: bool = False) -> dict:
    """template_path=None (default) scans every SharedLayerArn-bearing template
    under infrastructure/cloudformation/ (census_enceladus_all); pass an explicit
    path to scan just one template (used by the selftest)."""
    if template_path is None:
        enceladus_consumers = census_enceladus_all()
    else:
        enceladus_consumers = census_enceladus(template_path)
    devops_block = census_devops(refresh=refresh_devops)
    return {
        "_purpose": (
            "Cross-repo consumer census for enceladus-shared (ENC-TSK-P13 AC-2). "
            "Regenerate with `python3 tools/census_shared_layer_consumers.py "
            "[--refresh-devops] > backend/lambda/shared_layer/consumers_census.json`."
        ),
        "_generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "enceladus": enceladus_consumers,
        "devops": devops_block,
        "totals": {
            "enceladus_layer_attachments": len(enceladus_consumers),
            "devops_pinned_fetch_consumers": len(devops_block.get("consumers", [])),
            "cross_repo_total": (
                len(enceladus_consumers) + len(devops_block.get("consumers", []))
            ),
        },
    }


# --------------------------------------------------------------------------- selftest
_SELFTEST_TEMPLATE = """\
Parameters:
  SharedLayerArn:
    Type: String
Resources:
  PlainFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "plain-fn${EnvironmentSuffix}"
      Layers: []
  SharedLayerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "shared-fn${EnvironmentSuffix}"
      Layers:
        - !Ref SharedLayerArn
      Environment:
        Variables:
          X: "1"
  NotAFunction:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: something
  SecondSharedLayerFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: literal-name
      Layers:
        - !Ref SomeOtherLayerArn
        - !Ref SharedLayerArn
"""


def _selftest() -> int:
    import tempfile

    cases = []
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(_SELFTEST_TEMPLATE)
        path = f.name
    try:
        entries = census_enceladus(path)
        ids = {e["logical_id"] for e in entries}
        cases.append(("plain function (no shared layer) excluded", "PlainFunction" not in ids))
        cases.append(("non-Lambda resource excluded", "NotAFunction" not in ids))
        cases.append(("function with SharedLayerArn ref included", "SharedLayerFunction" in ids))
        cases.append(
            (
                "function with SharedLayerArn among multiple layers included",
                "SecondSharedLayerFunction" in ids,
            )
        )
        cases.append(("exactly 2 consumers found", len(entries) == 2))
        name_by_id = {e["logical_id"]: e["function_name"] for e in entries}
        cases.append(
            (
                "FunctionName captured as raw template text",
                name_by_id.get("SharedLayerFunction") == '!Sub "shared-fn${EnvironmentSuffix}"',
            )
        )

        devops_fallback = census_devops(refresh=False)
        cases.append(("devops fallback has >=1 consumer", len(devops_fallback["consumers"]) >= 1))
        cases.append(("devops fallback marked as such", devops_fallback["source"] == "fallback_snapshot"))

        census = build_census(path, refresh_devops=False)
        cases.append(
            (
                "cross_repo_total == enceladus + devops",
                census["totals"]["cross_repo_total"]
                == census["totals"]["enceladus_layer_attachments"]
                + census["totals"]["devops_pinned_fetch_consumers"],
            )
        )

        # discover_templates / census_enceladus_all: ENC-TSK-P13 multi-template
        # scan (06-appsync-events.yaml also declares SharedLayerArn and this
        # single-template selftest fixture must not be the only thing exercised).
        import tempfile as _tf
        cfn_dir = _tf.mkdtemp()
        with open(os.path.join(cfn_dir, "02-compute.yaml"), "w") as f2:
            f2.write(_SELFTEST_TEMPLATE)
        no_subject_tpl = "Resources:\n  BucketOnly:\n    Type: AWS::S3::Bucket\n"
        with open(os.path.join(cfn_dir, "03-api.yaml"), "w") as f3:
            f3.write(no_subject_tpl)
        second_subject_tpl = (
            "Parameters:\n  SharedLayerArn:\n    Type: String\n"
            "Resources:\n  AnotherSharedFn:\n"
            "    Type: AWS::Lambda::Function\n"
            "    Properties:\n"
            "      FunctionName: another-fn\n"
            "      Layers:\n        - !Ref SharedLayerArn\n"
        )
        with open(os.path.join(cfn_dir, "06-appsync-events.yaml"), "w") as f6:
            f6.write(second_subject_tpl)
        discovered = discover_templates(cfn_dir)
        cases.append(
            (
                "discover_templates finds both SharedLayerArn-subject templates, not the S3-only one",
                len(discovered) == 2
                and any("02-compute" in p for p in discovered)
                and any("06-appsync-events" in p for p in discovered)
                and not any("03-api" in p for p in discovered),
            )
        )
        all_entries = census_enceladus_all(cfn_dir)
        all_ids = {e["logical_id"] for e in all_entries}
        cases.append(
            (
                "census_enceladus_all aggregates consumers across BOTH templates",
                "SharedLayerFunction" in all_ids
                and "SecondSharedLayerFunction" in all_ids
                and "AnotherSharedFn" in all_ids
                and len(all_entries) == 3,
            )
        )
        for f2 in os.listdir(cfn_dir):
            os.unlink(os.path.join(cfn_dir, f2))
        os.rmdir(cfn_dir)
    finally:
        os.unlink(path)

    ok = True
    for name, passed in cases:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv: list) -> int:
    if "--selftest" in argv:
        return _selftest()

    template_path = None  # default: scan every SharedLayerArn-subject template
    refresh_devops = "--refresh-devops" in argv
    for i, a in enumerate(argv):
        if a == "--template" and i + 1 < len(argv):
            template_path = argv[i + 1]

    census = build_census(template_path, refresh_devops=refresh_devops)
    print(json.dumps(census, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
