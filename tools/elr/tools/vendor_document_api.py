#!/usr/bin/env python3
"""vendor_document_api.py -- re-vendor outline.py/sections.py from
backend/lambda/document_api (ENC-TSK-P78, T-B5, FR-B4-12).

tools/elr lives ONLY on origin/main; backend/lambda/document_api lives
ONLY on origin/v4/main (deploys v4-gamma on merge). ELR's conformance
engine (elr_lib/sections.py) needs the EXACT same outline/section-patch
logic the server runs, so this dev-only utility pulls verbatim copies of
outline.py and sections.py out of a given git ref (default
origin/v4/main) via `git show`/`git rev-parse` -- it NEVER checks that
ref out -- and writes them into elr_lib/vendor/ with:

  1. A provenance header comment (source path, ref, resolved commit sha,
     sha256 of the UNMODIFIED upstream source bytes) prepended ABOVE the
     module's own docstring (a comment, not a statement, so the original
     module docstring stays the first real statement -- import machinery
     and humans alike still see it as "the" docstring).
  2. ONE deliberate transformation: sections.py's `import outline as
     outline_mod` becomes a relative import of the vendored sibling
     module (`from . import document_api_outline as outline_mod`), since
     the vendored copies live in a package (elr_lib.vendor), not as
     top-level modules the way they do in backend/lambda/document_api/.
     No other line is touched -- this is the ONE intentional deviation
     from byte-identical vendoring, and it is what elr_lib/sections.py's
     conformance test exists to prove doesn't change behavior.

After writing both files, this script recomputes sha256 over the FINAL
on-disk vendored bytes (post-transformation) and refreshes PINS.json --
a pin file a test (tests/test_sections_vendor.py) checks on every run so
a hand-edit to a vendored file is caught immediately, without needing to
re-run this script or reach the network.

Usage:
    python3 tools/elr/tools/vendor_document_api.py
    python3 tools/elr/tools/vendor_document_api.py --ref origin/v4/main
    python3 tools/elr/tools/vendor_document_api.py --repo-root /path/to/enceladus/repo

This script is a DEV TOOL, not part of the ELR runtime -- unlike every
elr_*.py CLI and elr_lib module, it is allowed to shell out to `git` and
is never imported by anything under elr_lib/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Tuple

SOURCE_DIR = "backend/lambda/document_api"
MODULES = ("outline.py", "sections.py")
VENDORED_NAME = {
    "outline.py": "document_api_outline.py",
    "sections.py": "document_api_sections.py",
}
DEFAULT_REF = "origin/v4/main"

# The one deliberate, documented import fix (see module docstring).
_IMPORT_FIXUPS: Dict[str, Tuple[str, str]] = {
    "sections.py": ("import outline as outline_mod", "from . import document_api_outline as outline_mod"),
}

THIS_FILE = Path(__file__).resolve()
VENDOR_DIR = THIS_FILE.parents[1] / "elr_lib" / "vendor"
DEFAULT_REPO_ROOT = THIS_FILE.parents[3]
PINS_PATH = VENDOR_DIR / "PINS.json"


def _run_git(args: list, *, cwd: Path) -> str:
    result = subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout.decode("utf-8")


def _run_git_bytes(args: list, *, cwd: Path) -> bytes:
    result = subprocess.run(
        ["git"] + args, cwd=str(cwd), capture_output=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def resolve_commit(ref: str, *, repo_root: Path) -> str:
    return _run_git(["rev-parse", ref], cwd=repo_root).strip()


def fetch_source(ref: str, module: str, *, repo_root: Path) -> bytes:
    path = f"{SOURCE_DIR}/{module}"
    return _run_git_bytes(["show", f"{ref}:{path}"], cwd=repo_root)


def build_provenance_header(*, module: str, ref: str, commit: str, source_sha256: str) -> str:
    source_path = f"{SOURCE_DIR}/{module}"
    lines = [
        "# " + ("-" * 76),
        f"# VENDORED FILE -- DO NOT HAND-EDIT (ENC-TSK-P78, T-B5, FR-B4-12).",
        f"# Source:  {source_path}",
        f"# Ref:     {ref}",
        f"# Commit:  {commit}",
        f"# SHA-256 of the unmodified upstream source bytes: {source_sha256}",
        "#",
        "# Re-vendor with: python3 tools/elr/tools/vendor_document_api.py --ref <ref>",
        "# This file is byte-identical to the upstream source EXCEPT for one",
        "# documented import fixup (see vendor_document_api.py's module",
        "# docstring) needed because this copy lives in the elr_lib.vendor",
        "# package rather than as a top-level module.",
        "# " + ("-" * 76),
        "",
    ]
    return "\n".join(lines)


def transform(module: str, source_text: str) -> str:
    fixup = _IMPORT_FIXUPS.get(module)
    if not fixup:
        return source_text
    old, new = fixup
    if old not in source_text:
        raise RuntimeError(
            f"expected import fixup source line {old!r} not found in {module} -- "
            "upstream import shape may have changed; update _IMPORT_FIXUPS."
        )
    return source_text.replace(old, new, 1)


def vendor_one(module: str, *, ref: str, commit: str, repo_root: Path) -> Tuple[Path, str]:
    raw_bytes = fetch_source(ref, module, repo_root=repo_root)
    source_text = raw_bytes.decode("utf-8")
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    header = build_provenance_header(module=module, ref=ref, commit=commit, source_sha256=source_sha256)
    transformed = transform(module, source_text)
    final_text = header + transformed

    out_path = VENDOR_DIR / VENDORED_NAME[module]
    out_path.write_text(final_text, encoding="utf-8")
    final_sha256 = hashlib.sha256(final_text.encode("utf-8")).hexdigest()
    return out_path, final_sha256


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vendor_document_api",
        description="Re-vendor outline.py/sections.py from backend/lambda/document_api into elr_lib/vendor/.",
        allow_abbrev=False,
    )
    parser.add_argument("--ref", default=DEFAULT_REF, help=f"git ref to vendor from (default: {DEFAULT_REF}).")
    parser.add_argument(
        "--repo-root",
        default=str(DEFAULT_REPO_ROOT),
        help="Path to the enceladus repo/worktree (default: this worktree's root).",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root)

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    commit = resolve_commit(args.ref, repo_root=repo_root)

    pins: Dict[str, str] = {}
    for module in MODULES:
        out_path, final_sha256 = vendor_one(module, ref=args.ref, commit=commit, repo_root=repo_root)
        rel = out_path.relative_to(VENDOR_DIR).as_posix()
        pins[rel] = final_sha256
        print(f"vendored {module} -> {out_path} (sha256={final_sha256})", file=sys.stderr)

    init_path = VENDOR_DIR / "__init__.py"
    if not init_path.exists():
        init_path.write_text(
            '"""elr_lib.vendor -- verbatim (see PINS.json) copies of '
            "backend/lambda/document_api's outline.py/sections.py, "
            're-vendored by tools/elr/tools/vendor_document_api.py."""\n',
            encoding="utf-8",
        )

    pins_payload = {
        "ref": args.ref,
        "commit": commit,
        "files": pins,
    }
    PINS_PATH.write_text(json.dumps(pins_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {PINS_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
