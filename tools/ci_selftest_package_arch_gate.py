#!/usr/bin/env python3
"""CI self-test for the Gen2 package-arch gate (ENC-TSK-Q19 FR-4).

Proves tools/verify_lambda_package_arch.py -- the gate _build.yml now runs
on every zip right before S3 upload -- actually gates, on a live subprocess
invocation of the real CLI (not just its unit tests). Builds two tiny zips
in-memory: one with an arm64 .so, one with an x86_64 .so. Neither is
committed to disk (ENC-TSK-Q19 explicitly avoids checking in binary
fixtures) -- the ELF headers are the same 64-byte synthetic buffer
tools/test_verify_lambda_package_arch.py's own ClassifySoTests fixture
builds (reused here via import, not duplicated), which is all `file
--brief`/the tool's fallback parser need to classify an ELF's machine type.

Usage: python3 tools/ci_selftest_package_arch_gate.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from test_verify_lambda_package_arch import _build_elf_so  # noqa: E402

GATE = REPO_ROOT / "tools" / "verify_lambda_package_arch.py"


def _make_zip(path: Path, arch: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("lambda_function.py", b"def handler(e, c): return {}\n")
        zf.writestr("_native.so", _build_elf_so(arch))


def _run_gate(zip_path: Path, expected_arch: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, str(GATE),
            "--package", str(zip_path),
            "--expected-arch", expected_arch,
        ],
        capture_output=True, text=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        arm_zip = tmp / "arm64_ok.zip"
        _make_zip(arm_zip, "arm64")
        ok_result = _run_gate(arm_zip, "arm64")
        if ok_result.returncode != 0:
            print(
                "[ERROR] package-arch gate self-test FAILED: an arm64 zip "
                "against --expected-arch arm64 must pass (exit 0), got "
                f"{ok_result.returncode}:\n{ok_result.stdout}{ok_result.stderr}"
            )
            return 1

        x86_zip = tmp / "x86_64_mismatch.zip"
        _make_zip(x86_zip, "x86_64")
        fail_result = _run_gate(x86_zip, "arm64")
        if fail_result.returncode == 0:
            print(
                "[ERROR] package-arch gate self-test FAILED: an x86_64 zip "
                "against --expected-arch arm64 must fail (nonzero exit), got 0 "
                "-- the gate would silently wave through a wrong-ABI artifact"
            )
            return 1

    print("package-arch gate self-test: OK (arm64 zip passes, x86_64 mismatch fails)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
