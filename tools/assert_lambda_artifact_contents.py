#!/usr/bin/env python3
"""ENC-TSK-Q07 (ENC-ISS-778 P0 true root cause): fail closed when a built
Lambda artifact zip is missing entries its handler needs at import time.

Concrete incident this guards against: main's build-mcp-code job packages
enceladus-mcp-code by copying an explicit, hand-maintained list of files out
of tools/enceladus-mcp-server/ into the build dir before zipping. That list
can silently drift out of sync with what tools/enceladus-mcp-server/server.py
actually imports (a new local module added there, or -- as on v4/main, which
has decomposed server.py into a tools/enceladus-mcp-server/mcp_server/
package, ENC-TSK-L09 -- an entire local package the zip needs on its
sys.path root). A zip missing the handler module, or a package it imports,
uploads successfully and deploys successfully; the failure only surfaces at
invoke time as a 502 from server.lambda_handler failing to import. This
script makes that failure happen at build time instead, against the zip
itself, so it cannot ship.

Usage:
    tools/assert_lambda_artifact_contents.py <zip_path> <function_name> \\
        [--require ENTRY [ENTRY ...]]

<function_name> selects a built-in required-entries list (see
REQUIRED_ENTRIES below). Pass --require to override that default with an
explicit list -- required when the repo's actual packaging for a function
does not (yet) match the built-in list, e.g. main's mcp_code build, which
does not include mcp_server/__init__.py because main has not adopted the
v4/main mcp_server/ package decomposition. The built-in default is left set
to the general-case requirement (server.py AND mcp_server/__init__.py) so
this script starts enforcing the package the moment main's build actually
produces it, with no code change needed here.

Exits 0 and prints a confirmation when every required entry is present.
Exits 1 and prints exactly which entries are missing otherwise. Exits 2 on
usage errors (bad zip path, unknown function with no --require override).
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence

# Function name -> required zip entries (paths relative to the zip root,
# matching what `zip -qrX out.zip .` run from inside the build dir produces).
# Extend this table as new functions adopt this guard.
REQUIRED_ENTRIES: Dict[str, List[str]] = {
    "mcp_code": ["server.py", "mcp_server/__init__.py"],
}


def _normalize(entry: str) -> str:
    # Tolerate an accidental "./" prefix so the comparison is robust to which
    # exact `zip` invocation produced the archive.
    return entry[2:] if entry.startswith("./") else entry


def resolve_required_entries(
    function_name: str, override: Optional[Sequence[str]]
) -> List[str]:
    if override:
        return list(override)
    try:
        return list(REQUIRED_ENTRIES[function_name])
    except KeyError as exc:
        known = ", ".join(sorted(REQUIRED_ENTRIES)) or "(none)"
        raise SystemExit(
            f"ERROR: no built-in required-entries list for function "
            f"'{function_name}' (known: {known}). Pass --require to specify "
            f"one explicitly."
        ) from exc


def missing_entries(zip_path: Path, required: Sequence[str]) -> List[str]:
    with zipfile.ZipFile(zip_path) as zf:
        present = {_normalize(name) for name in zf.namelist()}
    return [entry for entry in required if _normalize(entry) not in present]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("zip_path", type=Path, help="Path to the built Lambda artifact zip.")
    parser.add_argument("function_name", help="Lambda function/directory name, e.g. mcp_code.")
    parser.add_argument(
        "--require",
        nargs="+",
        metavar="ENTRY",
        default=None,
        help="Explicit list of required zip entries, overriding the built-in default for function_name.",
    )
    args = parser.parse_args(argv)

    if not args.zip_path.is_file():
        print(f"ERROR: zip not found: {args.zip_path}", file=sys.stderr)
        return 2

    try:
        required = resolve_required_entries(args.function_name, args.require)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2

    if not zipfile.is_zipfile(args.zip_path):
        print(f"ERROR: not a valid zip file: {args.zip_path}", file=sys.stderr)
        return 2

    missing = missing_entries(args.zip_path, required)
    if missing:
        print(
            f"ERROR: {args.zip_path} is missing required entries for "
            f"function '{args.function_name}':",
            file=sys.stderr,
        )
        for entry in missing:
            print(f"  - {entry}", file=sys.stderr)
        print(
            f"({len(missing)} of {len(required)} required entries missing -- "
            "this artifact will fail to import at invoke time.)",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {args.zip_path} contains all {len(required)} required entries "
        f"for function '{args.function_name}'."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
