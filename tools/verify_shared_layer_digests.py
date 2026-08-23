#!/usr/bin/env python3
"""Pre-build guard: every module in the enceladus_shared package must match its
recorded sha256 digest in backend/lambda/shared_layer/MODULE_DIGESTS.json, or the
build is a hard failure.

WHY (ENC-TSK-P13, Gate F -- the enceladus-shared supply chain)
-----------------------------------------------------------------------------
NX-2021-L/devops already applies exactly this discipline in the OTHER direction:
scripts/fetch_shared_library.py pulls warehouse_registration.py from this repo at
a pinned commit and refuses (DIGEST MISMATCH, a hard SystemExit) if the fetched
content's sha256 does not match the digest recorded in its
infrastructure/analytics-stack.yaml `shared_library.modules` block. That refusal
protects devops's consumers from a silent, unreviewed change to code they did not
author. This script is the enceladus-side half of the same contract: it protects
enceladus-shared's own 72-function consumer fleet (see
backend/lambda/shared_layer/consumers.json, ENC-TSK-P13 AC-2) from exactly the
same failure mode -- a module edited without anyone noticing that the *published
layer artifact* now silently disagrees with what was reviewed.

Until this task there was no enforcement of this kind at all: shared_layer/deploy.sh
was tombstoned (see git history: b826fd3 restored it, 5140e46/c96d8a8 re-tombstoned
it, and nothing ever replaced it), no workflow ever ran `aws lambda
publish-layer-version` for enceladus-shared (git grep across .github/workflows/
returns zero hits), and the two published versions this task could trace
(:11, :12) were both hand-run by a human operator via the CLI, not CI -- see
backend/lambda/shared_layer/PROVENANCE.json. A digest gate cannot fix an
out-of-band humans-with-CLI-access channel by itself (see PROVENANCE.json's
"channel" field and the ENC-TSK-P13 worklog for what CAN close that gap -- it is
an IAM/process question, not a CI question). What this DOES fix is the in-repo
half: from here forward, any content change to python/enceladus_shared/*.py that
goes through THIS build lane is a loud, blocking, reviewed event, exactly like the
governance-dictionary gate elsewhere in this repo (AGENTS.md 3.11) -- never a
silent drift between "what the PR diff shows" and "what actually got zipped."

WHAT COUNTS AS A VIOLATION (all three are hard failures, none are warnings)
-----------------------------------------------------------------------------
  1. DIGEST MISMATCH  -- a declared module's sha256 no longer matches its content.
  2. UNDECLARED MODULE -- a .py file exists in the package dir but MODULE_DIGESTS.json
     has no entry for it (a new module landed without the manifest being updated).
  3. STALE ENTRY       -- MODULE_DIGESTS.json declares a module that no longer
     exists in the package dir (a deleted module the manifest still pins).

USAGE
-----------------------------------------------------------------------------
    python3 tools/verify_shared_layer_digests.py              # verify (CI mode)
    python3 tools/verify_shared_layer_digests.py --write       # regenerate the
                                                                 manifest from
                                                                 current content
    python3 tools/verify_shared_layer_digests.py --selftest    # offline self-test

Exit 0 = every module's digest matches. Exit 1 = a violation (build must fail).
Exit 2 = usage error.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_MANIFEST = os.path.join(
    REPO_ROOT, "backend", "lambda", "shared_layer", "MODULE_DIGESTS.json"
)
DEFAULT_PACKAGE_DIR = os.path.join(
    REPO_ROOT, "backend", "lambda", "shared_layer", "python", "enceladus_shared"
)


def _sha256_file(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def compute_digests(package_dir: str) -> dict:
    """Return {filename: sha256hex} for every *.py file directly in package_dir
    (non-recursive -- enceladus_shared is a flat package, matching
    scripts/fetch_shared_library.py's per-module model in devops)."""
    if not os.path.isdir(package_dir):
        raise SystemExit(f"package dir not found: {package_dir}")
    out = {}
    for name in sorted(os.listdir(package_dir)):
        if name.endswith(".py"):
            out[name] = _sha256_file(os.path.join(package_dir, name))
    return out


def load_manifest(manifest_path: str) -> dict:
    if not os.path.isfile(manifest_path):
        raise SystemExit(
            f"MODULE_DIGESTS.json not found at {manifest_path}. Run with --write "
            f"to generate it, then commit it alongside the module content."
        )
    with open(manifest_path) as fh:
        data = json.load(fh)
    if "modules" not in data or not isinstance(data["modules"], dict):
        raise SystemExit(f"{manifest_path}: missing or malformed `modules` object")
    return data


def verify(package_dir: str, manifest_path: str) -> list:
    """Returns a list of human-readable failure strings (empty == pass)."""
    actual = compute_digests(package_dir)
    manifest = load_manifest(manifest_path)
    declared = manifest["modules"]

    failures = []

    for name, actual_digest in sorted(actual.items()):
        if name not in declared:
            failures.append(
                f"UNDECLARED MODULE: {name} exists in {package_dir} but has no "
                f"entry in {manifest_path}. Add it (run --write) and commit the "
                f"manifest change in the SAME PR as the new module -- an "
                f"undeclared module is invisible provenance, exactly what this "
                f"gate exists to prevent."
            )
            continue
        expected_digest = declared[name]
        if actual_digest != expected_digest:
            failures.append(
                f"DIGEST MISMATCH: {name}\n"
                f"    expected {expected_digest}\n"
                f"    actual   {actual_digest}\n"
                f"    {name}'s content changed without {manifest_path} being "
                f"regenerated. Run `python3 tools/verify_shared_layer_digests.py "
                f"--write` and commit the manifest diff alongside the module "
                f"change. This is a refusal, not a warning (same contract as "
                f"NX-2021-L/devops's fetch_shared_library.py DIGEST MISMATCH)."
            )

    for name in sorted(set(declared) - set(actual)):
        failures.append(
            f"STALE ENTRY: {manifest_path} declares {name} but "
            f"{package_dir}/{name} no longer exists. Remove the stale entry "
            f"(run --write) and commit it -- a manifest that pins deleted "
            f"content cannot be honored by a real build."
        )

    return failures


def write_manifest(package_dir: str, manifest_path: str, package_dir_rel: str) -> None:
    actual = compute_digests(package_dir)
    manifest = {
        "_generated_by": (
            "tools/verify_shared_layer_digests.py --write (ENC-TSK-P13)"
        ),
        "_purpose": (
            "Per-module sha256 provenance pin for the enceladus_shared package "
            "shipped in the enceladus-shared Lambda layer. See this script's "
            "module docstring for the full rationale. To change a module: edit "
            "it, run this script with --write, and commit both the module "
            "change and this file's diff in the SAME PR."
        ),
        "package_dir": package_dir_rel,
        "modules": actual,
    }
    with open(manifest_path, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"wrote {manifest_path} ({len(actual)} module(s))")


# --------------------------------------------------------------------------- selftest
def _selftest() -> int:
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        pkg_dir = os.path.join(tmp, "pkg")
        os.makedirs(pkg_dir)
        with open(os.path.join(pkg_dir, "a.py"), "w") as fh:
            fh.write("VALUE = 1\n")
        with open(os.path.join(pkg_dir, "b.py"), "w") as fh:
            fh.write("VALUE = 2\n")

        manifest_path = os.path.join(tmp, "MODULE_DIGESTS.json")
        write_manifest(pkg_dir, manifest_path, "pkg")

        # 1. Freshly-written manifest verifies clean.
        cases.append(("freshly written manifest verifies clean", verify(pkg_dir, manifest_path) == []))

        # 2. Content drift -> DIGEST MISMATCH.
        with open(os.path.join(pkg_dir, "a.py"), "w") as fh:
            fh.write("VALUE = 999  # changed, manifest not regenerated\n")
        failures = verify(pkg_dir, manifest_path)
        cases.append(
            ("edited module without --write fires DIGEST MISMATCH", any("DIGEST MISMATCH" in f and "a.py" in f for f in failures))
        )
        # restore
        with open(os.path.join(pkg_dir, "a.py"), "w") as fh:
            fh.write("VALUE = 1\n")
        cases.append(("restoring content clears the mismatch", verify(pkg_dir, manifest_path) == []))

        # 3. New undeclared module -> UNDECLARED MODULE.
        with open(os.path.join(pkg_dir, "c.py"), "w") as fh:
            fh.write("VALUE = 3\n")
        failures = verify(pkg_dir, manifest_path)
        cases.append(
            ("new module without --write fires UNDECLARED MODULE", any("UNDECLARED MODULE" in f and "c.py" in f for f in failures))
        )
        os.unlink(os.path.join(pkg_dir, "c.py"))
        cases.append(("removing the undeclared module clears the finding", verify(pkg_dir, manifest_path) == []))

        # 4. Manifest pins a module that no longer exists -> STALE ENTRY.
        os.unlink(os.path.join(pkg_dir, "b.py"))
        failures = verify(pkg_dir, manifest_path)
        cases.append(
            ("deleted module still pinned fires STALE ENTRY", any("STALE ENTRY" in f and "b.py" in f for f in failures))
        )

        # 5. --write after legitimate changes re-syncs and clears everything.
        write_manifest(pkg_dir, manifest_path, "pkg")
        cases.append(("--write after a legitimate change verifies clean again", verify(pkg_dir, manifest_path) == []))

        # 6. Missing manifest is a hard usage error, not a silent pass.
        os.unlink(manifest_path)
        try:
            load_manifest(manifest_path)
            missing_manifest_raises = False
        except SystemExit:
            missing_manifest_raises = True
        cases.append(("missing manifest raises rather than silently passing", missing_manifest_raises))

    ok = True
    for name, passed in cases:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv: list) -> int:
    if "--selftest" in argv:
        return _selftest()

    do_write = "--write" in argv
    package_dir = DEFAULT_PACKAGE_DIR
    manifest_path = DEFAULT_MANIFEST
    package_dir_rel = os.path.relpath(package_dir, REPO_ROOT)

    if do_write:
        write_manifest(package_dir, manifest_path, package_dir_rel)
        return 0

    failures = verify(package_dir, manifest_path)
    if failures:
        print(
            "FAIL: enceladus-shared module digest gate "
            f"({os.path.relpath(manifest_path, REPO_ROOT)}):",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        f"OK: all {len(load_manifest(manifest_path)['modules'])} module(s) in "
        f"{package_dir_rel} match {os.path.relpath(manifest_path, REPO_ROOT)}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
