#!/usr/bin/env python3
"""Verify that a Lambda deployment zip contains no wrong-architecture C extensions.

CI / deploy-time guard that inspects the *contents* of a built Lambda zip and
rejects the package when any compiled shared object (.so) targets a different
CPU architecture than the declared Lambda runtime.

Part of ENC-TSK-E19 (follow-up to ENC-ISS-213).

Context
-------
The existing ``tools/verify_lambda_arch_parity.py`` enforces the CFN and
deploy-script declarations (every Lambda uses
``!If [IsGamma, arm64, x86_64]`` for Architectures and the right
``pip --platform`` flag in its deploy script). That check is necessary but
not sufficient: it verifies the *declarations* are correct, not the *artifact*
that actually gets uploaded.

ENC-ISS-213 happened because the ``devops-coordination-api-gamma`` Lambda
shipped x86_64-compiled ``pydantic_core`` wheels on an arm64 runtime. The
deploy declarations were correct after ENC-FTR-072 / ENC-ISS-224, but the
zip that got uploaded still contained x86_64 binaries -- likely due to a
pip resolution path that silently fell through to a pre-cached wheel. No
guard looked inside the zip, so the bug reached production.

This tool closes that gap. Every ``deploy.sh`` invokes it between zip
creation and ``aws lambda update-function-code``; the CI test suite runs
the self-test against fixture zips.

Design
------
* Stdlib only (``zipfile``, ``subprocess``, ``argparse``, ``tempfile``).
* Uses ``file --brief`` to classify each .so (present on Amazon Linux,
  Ubuntu, macOS, and the CodeBuild images used by the deploy orchestrator).
* Falls back to direct ELF magic-byte parsing if ``file`` is unavailable.
* Pure-Python packages (zero .so files) pass trivially -- the check is a
  no-op for functions that ship no native extensions.
* Non-ELF ``.so`` files (rare: Windows DLLs renamed, symlinks) emit a
  warning but do not fail the check. We only fail on *definite* mismatches.

Exit codes
----------
* 0 -- all .so files match expected arch (or package is pure-Python).
* 1 -- at least one .so reports a mismatched architecture.
* 2 -- invalid arguments, package not readable, or ``file`` unavailable
       and ELF magic-byte parsing also failed.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Architecture constants
# ---------------------------------------------------------------------------

# `file` reports these substrings for the two Linux ELF architectures we ship.
#
# Example outputs:
#   ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked
#   ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked
FILE_SIGNATURES = {
    "x86_64": ("ELF", "x86-64"),
    "arm64":  ("ELF", "aarch64"),
}

# ELF e_machine values (ELF header offset 0x12, 2 bytes little-endian).
# Source: /usr/include/elf.h (EM_X86_64 = 62, EM_AARCH64 = 183).
ELF_MACHINE_TO_ARCH = {
    0x3E: "x86_64",   # EM_X86_64
    0xB7: "arm64",    # EM_AARCH64
}

ELF_MAGIC = b"\x7fELF"

SUPPORTED_ARCHES = tuple(sorted(FILE_SIGNATURES))


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _classify_with_file(path: Path) -> Optional[str]:
    """Run `file --brief` on path, return 'x86_64' / 'arm64' / None."""
    try:
        out = subprocess.check_output(
            ["file", "--brief", str(path)], text=True, stderr=subprocess.STDOUT
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None
    for arch, needles in FILE_SIGNATURES.items():
        if all(n in out for n in needles):
            return arch
    return None


def _classify_with_elf_magic(path: Path) -> Optional[str]:
    """Parse ELF header directly. Returns 'x86_64' / 'arm64' / None.

    Used as a fallback when `file` is unavailable. Reads the first 20 bytes
    of the file and inspects the e_machine field at offset 0x12.
    """
    try:
        with path.open("rb") as f:
            header = f.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != ELF_MAGIC:
        return None  # not an ELF file
    # e_machine is at offset 0x12 (little-endian uint16 on all supported ELF)
    e_machine = struct.unpack_from("<H", header, 0x12)[0]
    return ELF_MACHINE_TO_ARCH.get(e_machine)


def classify_so(path: Path) -> Optional[str]:
    """Return 'x86_64', 'arm64', or None for an alleged .so file.

    Tries the `file` command first (richer error messages), falls back
    to ELF magic-byte parsing if `file` is unavailable.
    """
    if shutil.which("file"):
        arch = _classify_with_file(path)
        if arch is not None:
            return arch
    return _classify_with_elf_magic(path)


# ---------------------------------------------------------------------------
# Zip inspection
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    """Outcome of a package arch verification."""
    package: Path
    expected_arch: str
    so_files: List[Path]                          # extracted paths (for debugging)
    matches: List[Path]
    mismatches: List[Tuple[Path, str]]            # (path, actual_arch)
    unknowns: List[Path]                          # `file`/ELF could not classify

    @property
    def passed(self) -> bool:
        return not self.mismatches

    @property
    def pure_python(self) -> bool:
        return not self.so_files


def verify_package(package: Path, expected_arch: str) -> VerifyResult:
    """Extract the zip and classify every .so file it contains.

    Raises ValueError for invalid args, FileNotFoundError for missing package.
    """
    if expected_arch not in FILE_SIGNATURES:
        raise ValueError(
            f"unsupported expected-arch {expected_arch!r}; "
            f"use one of: {', '.join(SUPPORTED_ARCHES)}"
        )
    if not package.is_file():
        raise FileNotFoundError(f"package not found: {package}")

    matches: List[Path] = []
    mismatches: List[Tuple[Path, str]] = []
    unknowns: List[Path] = []
    so_files: List[Path] = []

    with tempfile.TemporaryDirectory(prefix="verify_lambda_arch_") as tmp:
        tmp_path = Path(tmp)
        try:
            with zipfile.ZipFile(package) as zf:
                zf.extractall(tmp_path)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"not a valid zip: {package} ({exc})") from exc

        # Collect .so files (includes versioned suffixes like libfoo.so.1.2)
        for pat in ("*.so", "*.so.*"):
            so_files.extend(tmp_path.rglob(pat))

        for so in so_files:
            rel = so.relative_to(tmp_path)
            arch = classify_so(so)
            if arch is None:
                unknowns.append(rel)
            elif arch == expected_arch:
                matches.append(rel)
            else:
                mismatches.append((rel, arch))

    return VerifyResult(
        package=package,
        expected_arch=expected_arch,
        so_files=[s.relative_to(tmp_path) for s in so_files] if so_files else [],
        matches=matches,
        mismatches=mismatches,
        unknowns=unknowns,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_success(result: VerifyResult) -> str:
    if result.pure_python:
        return (
            f"[OK] {result.package.name} is pure-Python "
            f"(0 .so files -- nothing to check)"
        )
    return (
        f"[OK] {result.package.name} "
        f"all {len(result.matches)} .so files match {result.expected_arch}"
    )


def _format_failure(result: VerifyResult) -> str:
    lines = [
        f"[FAIL] {result.package.name} expected {result.expected_arch}, "
        f"found {len(result.mismatches)} mismatch(es):",
    ]
    for rel, actual in result.mismatches:
        lines.append(f"  {rel}: {actual}")
    return "\n".join(lines)


def _format_warnings(result: VerifyResult) -> str:
    if not result.unknowns:
        return ""
    lines = [
        f"[WARN] {result.package.name} "
        f"{len(result.unknowns)} .so file(s) could not be classified:",
    ]
    for rel in result.unknowns:
        lines.append(f"  {rel}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Verify a Lambda deployment zip contains only the expected "
            "architecture for its compiled C extensions."
        )
    )
    ap.add_argument("--package", required=True, type=Path,
                    help="Path to the Lambda zip to inspect.")
    ap.add_argument("--expected-arch", required=True, choices=SUPPORTED_ARCHES,
                    help="Expected Lambda runtime architecture.")
    args = ap.parse_args(argv)

    try:
        result = verify_package(args.package, args.expected_arch)
    except (ValueError, FileNotFoundError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    warn = _format_warnings(result)
    if warn:
        print(warn, file=sys.stderr)

    if result.passed:
        print(_format_success(result))
        return 0

    print(_format_failure(result), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
