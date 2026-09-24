#!/usr/bin/env python3
"""Tests for tools/arch_declaration.py (ENC-TSK-Q19 FR-1 / DOC-5368FE6515ED).

Run from repo root:
    python3 -m unittest tools.test_arch_declaration -v
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import arch_declaration as ad  # noqa: E402

GOOD = """\
# comment line, ignored
schema_version: 1
planes:
  prod: {arch: arm64, runtime: python3.12, runner: ubuntu-24.04-arm}
  gamma: {arch: arm64, runtime: python3.12, runner: ubuntu-24.04-arm}
env_plane:
  v3-prod: prod
  v4-prod: prod
  v4-gamma: gamma
"""


def _write(tmp_dir: Path, content: str) -> Path:
    p = tmp_dir / "architecture.yaml"
    p.write_text(content, encoding="utf-8")
    return p


class TestLoadDeclaration(unittest.TestCase):
    def test_repo_declaration_loads_and_matches_facts(self):
        decl = ad.load_declaration()
        self.assertEqual(decl.schema_version, 1)
        self.assertEqual(decl.planes["prod"], {"arch": "arm64", "runtime": "python3.12", "runner": "ubuntu-24.04-arm"})
        self.assertEqual(decl.planes["gamma"], {"arch": "arm64", "runtime": "python3.12", "runner": "ubuntu-24.04-arm"})
        self.assertEqual(decl.env_plane["v3-prod"], "prod")
        self.assertEqual(decl.env_plane["v4-prod"], "prod")
        self.assertEqual(decl.env_plane["v4-gamma"], "gamma")

    def test_good_fixture_parses(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), GOOD)
            decl = ad.load_declaration(path)
        self.assertEqual(decl.field_for_env("v3-prod", "arch"), "arm64")
        self.assertEqual(decl.field_for_plane("gamma", "runtime"), "python3.12")

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ad.ArchDeclarationError):
                ad.load_declaration(Path(td) / "nope.yaml")

    def test_unknown_env_raises(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), GOOD)
            decl = ad.load_declaration(path)
        with self.assertRaises(ad.ArchDeclarationError):
            decl.plane_for_env("v9-nowhere")

    def test_unknown_field_raises(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), GOOD)
            decl = ad.load_declaration(path)
        with self.assertRaises(ad.ArchDeclarationError):
            decl.field_for_plane("prod", "os")

    def test_bad_schema_version_raises(self):
        bad = GOOD.replace("schema_version: 1", "schema_version: 2")
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), bad)
            with self.assertRaises(ad.ArchDeclarationError):
                ad.load_declaration(path)

    def test_env_plane_referencing_undeclared_plane_raises(self):
        bad = GOOD + "  v9-nowhere: nonexistent-plane\n"
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), bad)
            with self.assertRaises(ad.ArchDeclarationError):
                ad.load_declaration(path)

    def test_malformed_plane_line_raises(self):
        bad = GOOD.replace(
            "  prod: {arch: arm64, runtime: python3.12, runner: ubuntu-24.04-arm}",
            "  prod: not-a-flow-mapping",
        )
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), bad)
            with self.assertRaises(ad.ArchDeclarationError):
                ad.load_declaration(path)

    def test_general_yaml_that_isnt_this_schema_raises(self):
        # Valid YAML, but block-style planes -- not the flow-style shape this
        # loader deliberately restricts itself to.
        not_this_schema = "schema_version: 1\nplanes:\n  prod:\n    arch: arm64\n"
        with tempfile.TemporaryDirectory() as td:
            path = _write(Path(td), not_this_schema)
            with self.assertRaises(ad.ArchDeclarationError):
                ad.load_declaration(path)


class TestCli(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "arch_declaration.py"), *args],
            capture_output=True, text=True,
        )

    def test_env_arch(self):
        result = self._run("--env", "v3-prod", "--field", "arch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "arm64")

    def test_plane_runtime(self):
        result = self._run("--plane", "gamma", "--field", "runtime")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "python3.12")

    def test_plane_runner(self):
        result = self._run("--plane", "prod", "--field", "runner")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ubuntu-24.04-arm")

    def test_unknown_env_exits_nonzero_with_error_marker(self):
        result = self._run("--env", "v9-nowhere", "--field", "arch")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("::error::", result.stderr)

    def test_env_and_plane_mutually_exclusive(self):
        result = self._run("--env", "v3-prod", "--plane", "prod", "--field", "arch")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
