#!/usr/bin/env python3
"""Tests for tools/verify_lambda_package_arch.py.

ENC-TSK-E19 AC-5: construct test Lambda zips with known-good and known-bad
contents and confirm the verifier accepts/rejects each as expected.

The tests synthesize minimal ELF 64-bit headers for both x86_64 and aarch64
so they run anywhere Python runs -- no dependency on pre-built wheels or on
the ``file`` command being present. Both classification paths are exercised:
``file``-based (when present) and ELF-magic fallback (forced via
``shutil.which`` patch).

Run from repo root:
    python3 -m unittest tools.test_verify_lambda_package_arch -v
"""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_lambda_package_arch as vlpa  # noqa: E402


# ---------------------------------------------------------------------------
# ELF fixture builder
# ---------------------------------------------------------------------------

# Minimal ELF64 header. We only care that the file starts with the magic
# bytes and has a valid e_machine at offset 0x12. `file --brief` also only
# needs e_ident + e_machine to classify; the rest can be zeros.
#
# Layout (20 bytes, matches what classify_so reads):
#   0x00: \x7fELF        (magic)
#   0x04: class=64       (0x02)
#   0x05: data=LE        (0x01)
#   0x06: version=1      (0x01)
#   0x07..0x0F: padding  (zeros)
#   0x10: e_type=ET_DYN  (0x03, 0x00 LE)
#   0x12: e_machine      (2 bytes LE -- this is what we vary)
#   0x14+: zeros
def _build_elf_so(arch: str) -> bytes:
    """Return a minimal 64-byte buffer that `file` and our fallback parser
    both classify as an ELF shared object for the given arch."""
    if arch == "x86_64":
        e_machine = 0x3E
    elif arch == "arm64":
        e_machine = 0xB7
    else:
        raise ValueError(f"unsupported arch {arch!r}")
    buf = bytearray(64)
    buf[0:4] = b"\x7fELF"
    buf[4] = 0x02      # EI_CLASS = ELFCLASS64
    buf[5] = 0x01      # EI_DATA = ELFDATA2LSB
    buf[6] = 0x01      # EI_VERSION = EV_CURRENT
    struct.pack_into("<H", buf, 0x10, 0x03)          # e_type = ET_DYN
    struct.pack_into("<H", buf, 0x12, e_machine)     # e_machine
    struct.pack_into("<H", buf, 0x14, 0x01)          # e_version = EV_CURRENT
    return bytes(buf)


def _make_zip(path: Path, members: dict) -> None:
    """Write a zip with the given {arcname: bytes} entries."""
    with zipfile.ZipFile(path, "w") as zf:
        for arcname, data in members.items():
            zf.writestr(arcname, data)


# ---------------------------------------------------------------------------
# Classification (unit) tests
# ---------------------------------------------------------------------------

class ClassifySoTests(unittest.TestCase):
    """Low-level ELF magic-byte parsing, independent of `file`."""

    def test_elf_magic_recognizes_x86_64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "libx.so"
            p.write_bytes(_build_elf_so("x86_64"))
            self.assertEqual(vlpa._classify_with_elf_magic(p), "x86_64")

    def test_elf_magic_recognizes_arm64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "liba.so"
            p.write_bytes(_build_elf_so("arm64"))
            self.assertEqual(vlpa._classify_with_elf_magic(p), "arm64")

    def test_elf_magic_rejects_non_elf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fake.so"
            p.write_bytes(b"this is not an ELF header at all" * 3)
            self.assertIsNone(vlpa._classify_with_elf_magic(p))

    def test_classify_so_falls_back_when_file_missing(self) -> None:
        """When `file` is not on PATH, ELF-magic fallback still works."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "lib.so"
            p.write_bytes(_build_elf_so("arm64"))
            with mock.patch.object(vlpa.shutil, "which", return_value=None):
                self.assertEqual(vlpa.classify_so(p), "arm64")


# ---------------------------------------------------------------------------
# End-to-end verify_package tests
# ---------------------------------------------------------------------------

class VerifyPackageTests(unittest.TestCase):
    """Round-trip tests against synthesized Lambda zips."""

    def _tmp_zip(self, members: dict) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        zp = Path(self._tmp.name) / "function.zip"
        _make_zip(zp, members)
        return zp

    # --- AC-2: pure-Python -------------------------------------------------

    def test_pure_python_package_passes(self) -> None:
        """Zip with zero .so files is a trivial pass regardless of expected arch."""
        zp = self._tmp_zip({
            "lambda_function.py": b"def handler(e, c): return {}\n",
            "package/__init__.py": b"",
            "package/utils.py": b"x = 1\n",
        })
        for arch in ("x86_64", "arm64"):
            with self.subTest(arch=arch):
                r = vlpa.verify_package(zp, arch)
                self.assertTrue(r.passed)
                self.assertTrue(r.pure_python)
                self.assertEqual(r.mismatches, [])

    # --- AC-1 / AC-5: happy path + mismatch detection ----------------------

    def test_matching_arch_passes(self) -> None:
        """Zip whose .so files all match the expected arch passes."""
        zp = self._tmp_zip({
            "lambda_function.py": b"def handler(e, c): return {}\n",
            "pydantic_core/_pydantic_core.cpython-311-x86_64-linux-gnu.so":
                _build_elf_so("x86_64"),
            "pydantic_core/__init__.py": b"",
        })
        r = vlpa.verify_package(zp, "x86_64")
        self.assertTrue(r.passed, msg=f"mismatches={r.mismatches}")
        self.assertEqual(len(r.matches), 1)

    def test_wrong_arch_fails(self) -> None:
        """The ENC-ISS-213 scenario: x86_64 .so files in an arm64 package."""
        zp = self._tmp_zip({
            "lambda_function.py": b"",
            "pydantic_core/_pydantic_core.cpython-311-x86_64-linux-gnu.so":
                _build_elf_so("x86_64"),
        })
        r = vlpa.verify_package(zp, "arm64")
        self.assertFalse(r.passed)
        self.assertEqual(len(r.mismatches), 1)
        rel, actual = r.mismatches[0]
        self.assertEqual(actual, "x86_64")
        self.assertIn("pydantic_core", str(rel))

    def test_mixed_arch_fails(self) -> None:
        """A zip with one correct and one wrong .so still fails."""
        zp = self._tmp_zip({
            "ok/lib.so":   _build_elf_so("arm64"),
            "bad/lib.so":  _build_elf_so("x86_64"),
        })
        r = vlpa.verify_package(zp, "arm64")
        self.assertFalse(r.passed)
        self.assertEqual(len(r.mismatches), 1)
        self.assertEqual(len(r.matches), 1)

    def test_versioned_so_extension_detected(self) -> None:
        """libfoo.so.1.2 is still a shared object and must be inspected."""
        zp = self._tmp_zip({
            "lib/libfoo.so.1.2.3": _build_elf_so("x86_64"),
        })
        r = vlpa.verify_package(zp, "arm64")
        self.assertFalse(r.passed)
        self.assertEqual(len(r.mismatches), 1)

    # --- AC-1: error paths -------------------------------------------------

    def test_unsupported_arch_raises(self) -> None:
        zp = self._tmp_zip({"lambda_function.py": b""})
        with self.assertRaises(ValueError):
            vlpa.verify_package(zp, "sparc64")

    def test_missing_package_raises(self) -> None:
        missing = Path(tempfile.gettempdir()) / "does-not-exist.zip"
        if missing.exists():
            missing.unlink()
        with self.assertRaises(FileNotFoundError):
            vlpa.verify_package(missing, "x86_64")

    def test_bad_zip_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "notazip.zip"
            fake.write_bytes(b"garbage that is not a zip")
            with self.assertRaises(ValueError):
                vlpa.verify_package(fake, "x86_64")


# ---------------------------------------------------------------------------
# CLI (argparse + exit code) tests
# ---------------------------------------------------------------------------

class CLITests(unittest.TestCase):

    def test_cli_exit_zero_on_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            zp = Path(tmp) / "fn.zip"
            _make_zip(zp, {"lib/x.so": _build_elf_so("x86_64")})
            rc = vlpa.main(["--package", str(zp), "--expected-arch", "x86_64"])
            self.assertEqual(rc, 0)

    def test_cli_exit_one_on_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            zp = Path(tmp) / "fn.zip"
            _make_zip(zp, {"lib/x.so": _build_elf_so("x86_64")})
            rc = vlpa.main(["--package", str(zp), "--expected-arch", "arm64"])
            self.assertEqual(rc, 1)

    def test_cli_exit_two_on_missing_package(self) -> None:
        rc = vlpa.main([
            "--package", "/nonexistent/path/to/fn.zip",
            "--expected-arch", "x86_64",
        ])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
