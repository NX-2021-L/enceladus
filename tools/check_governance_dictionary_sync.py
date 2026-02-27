#!/usr/bin/env python3
"""Fail closed when schema-affecting changes omit governance dictionary updates."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

SCHEMA_AFFECTING_PATTERNS = (
    "backend/lambda/*/lambda_function.py",
    "backend/lambda/*/tracker_ops.py",
    "backend/lambda/*/handlers.py",
    "tools/enceladus-mcp-server/server.py",
    "backend/lambda/coordination_api/config.py",
)

DICTIONARY_FILES = (
    "backend/lambda/coordination_api/governance_data_dictionary.json",
)


def _git_changed_files(base: str, head: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git diff failed")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _matches_any(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()

    changed = _git_changed_files(args.base, args.head)
    if not changed:
        print("[OK] No changed files.")
        return 0

    schema_changes = [p for p in changed if _matches_any(p, SCHEMA_AFFECTING_PATTERNS)]
    dictionary_changes = [p for p in changed if _matches_any(p, DICTIONARY_FILES)]

    if not schema_changes:
        print("[OK] No schema-affecting files changed.")
        return 0

    print("[INFO] Schema-affecting changes detected:")
    for path in schema_changes:
        print(f"  - {path}")

    if dictionary_changes:
        print("[OK] Dictionary update detected:")
        for path in dictionary_changes:
            print(f"  - {path}")
        return 0

    print(
        "[ERROR] Schema-affecting changes require governance dictionary updates.\n"
        "Update backend/lambda/coordination_api/governance_data_dictionary.json "
        "in the same change set."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
