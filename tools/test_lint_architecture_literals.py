#!/usr/bin/env python3
"""Tests for tools/lint_architecture_literals.py (ENC-TSK-Q19 FR-1 / DOC-5368FE6515ED).

Run from repo root:
    python3 -m unittest tools.test_lint_architecture_literals -v
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import lint_architecture_literals as lal  # noqa: E402


class TestStripComment(unittest.TestCase):
    def test_pure_comment_line_stripped_to_empty(self):
        self.assertEqual(lal._strip_comment("# x86_64 note").strip(), "")

    def test_inline_comment_stripped(self):
        self.assertEqual(lal._strip_comment('ARCH="arm64"  # was x86_64').strip(), 'ARCH="arm64"')

    def test_hash_inside_quotes_preserved(self):
        self.assertIn("x86_64", lal._strip_comment('echo "tag#x86_64"'))


class TestJsonWalk(unittest.TestCase):
    def _walk(self, data):
        findings: list = []
        lal._walk_json(data, "$", "fake.json", findings)
        return findings

    def test_exact_x86_64_value_flagged(self):
        self.assertEqual(len(self._walk({"arch": "x86_64"})), 1)

    def test_exact_python311_value_flagged(self):
        self.assertEqual(len(self._walk({"runtime": "python3.11"})), 1)

    def test_arch_tag_value_flagged(self):
        self.assertEqual(len(self._walk({"tag": "x86_64-py311"})), 1)

    def test_prose_string_with_spaces_ignored(self):
        self.assertEqual(self._walk({"note": "retire x86_64 support in Q20"}), [])

    def test_x86_64_key_empty_list_not_flagged(self):
        self.assertEqual(self._walk({"architecture_exceptions": {"x86_64": []}}), [])

    def test_x86_64_key_nonempty_list_flagged(self):
        self.assertEqual(len(self._walk({"architecture_exceptions": {"x86_64": ["some-fn"]}})), 1)

    def test_unrelated_string_ignored(self):
        self.assertEqual(self._walk({"env_name": "v3-prod"}), [])


class TestTextScan(unittest.TestCase):
    def _scan(self, text: str, suffix=".yaml"):
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as fh:
            fh.write(text)
            path = Path(fh.name)
        try:
            return lal._scan_text_file(path, "fake" + suffix)
        finally:
            path.unlink(missing_ok=True)

    def test_bare_x86_64_flagged(self):
        self.assertEqual(len(self._scan("pip_platform: manylinux2014_x86_64\n")), 1)

    def test_python311_flagged(self):
        self.assertEqual(len(self._scan("runtime: python3.11\n")), 1)

    def test_comment_only_line_not_flagged(self):
        self.assertEqual(self._scan("# manylinux2014_x86_64 was the old target\n"), [])

    def test_arch_runtime_conditional_any_condition_name_flagged(self):
        findings = self._scan("Runtime: !If [IsGamma, python3.12, python3.11]\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("arch-runtime-!If", findings[0].text)

    def test_clean_line_not_flagged(self):
        self.assertEqual(self._scan("architecture_plane: prod\n"), [])


class TestExclusions(unittest.TestCase):
    def test_docs_excluded(self):
        self.assertTrue(lal._is_excluded("docs/how-to/thing.md"))

    def test_markdown_excluded_anywhere(self):
        self.assertTrue(lal._is_excluded("backend/README.md"))

    def test_test_file_excluded(self):
        self.assertTrue(lal._is_excluded("tools/test_verify_lambda_arch_parity.py"))
        self.assertTrue(lal._is_excluded("tools/some_module_test.py"))
        self.assertTrue(lal._is_excluded("backend/lambda/foo/tests/test_x.py"))

    def test_cfn_guard_excluded(self):
        self.assertTrue(lal._is_excluded("tools/cfn-guard/manifest-shape.guard"))

    def test_verify_tools_excluded(self):
        self.assertTrue(lal._is_excluded("tools/verify_lambda_arch_parity.py"))
        self.assertTrue(lal._is_excluded("tools/verify_shared_layer_version.py"))

    def test_lint_and_declaration_tool_excluded(self):
        self.assertTrue(lal._is_excluded("tools/lint_architecture_literals.py"))
        self.assertTrue(lal._is_excluded("tools/arch_declaration.py"))

    def test_frontend_excluded(self):
        self.assertTrue(lal._is_excluded("frontend/src/App.tsx"))

    def test_ordinary_source_not_excluded(self):
        self.assertFalse(lal._is_excluded("backend/lambda/deploy_decide/lambda_function.py"))


class TestRunLintIntegration(unittest.TestCase):
    """Exercises run_lint() end-to-end against a synthetic tracked-file set
    under a synthetic REPO_ROOT, isolated from the real repo tree."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self._repo_root_patch = mock.patch.object(lal, "REPO_ROOT", self.root)
        self._repo_root_patch.start()

    def tearDown(self):
        self._repo_root_patch.stop()
        self._tmpdir.cleanup()

    def _write(self, rel_path: str, content: str) -> None:
        path = self.root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _allowlist_path(self, entries: list) -> Path:
        path = self.root / "tools" / "architecture_literal_allowlist.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entries), encoding="utf-8")
        return path

    def test_clean_tree_passes(self):
        allowlist_path = self._allowlist_path([])
        self._write("envs/architecture.yaml", "schema_version: 1\n")
        with mock.patch.object(lal, "ALLOWLIST_PATH", allowlist_path):
            errors, scanned, allowlisted = lal.run_lint(tracked_files=["envs/architecture.yaml"])
        self.assertEqual(errors, [])
        self.assertEqual(scanned, 1)
        self.assertEqual(allowlisted, 0)

    def test_finding_outside_allowlist_fails(self):
        allowlist_path = self._allowlist_path([])
        self._write("envs/bad.yaml", "architecture: x86_64\n")
        with mock.patch.object(lal, "ALLOWLIST_PATH", allowlist_path):
            errors, _, _ = lal.run_lint(tracked_files=["envs/bad.yaml"])
        self.assertTrue(errors)
        self.assertTrue(any("envs/bad.yaml" in e for e in errors))

    def test_allowlisted_finding_suppressed(self):
        allowlist_path = self._allowlist_path(
            [{"path": "legacy/thing.yaml", "retired_by": "ENC-TSK-FAKE", "reason": "test"}]
        )
        self._write("legacy/thing.yaml", "architecture: x86_64\n")
        with mock.patch.object(lal, "ALLOWLIST_PATH", allowlist_path):
            errors, _, _ = lal.run_lint(tracked_files=["legacy/thing.yaml"])
        self.assertEqual(errors, [])

    def test_stale_allowlist_entry_with_zero_findings_fails(self):
        allowlist_path = self._allowlist_path(
            [{"path": "legacy/clean.yaml", "retired_by": "ENC-TSK-FAKE", "reason": "test"}]
        )
        self._write("legacy/clean.yaml", "architecture_plane: prod\n")
        with mock.patch.object(lal, "ALLOWLIST_PATH", allowlist_path):
            errors, _, _ = lal.run_lint(tracked_files=["legacy/clean.yaml"])
        self.assertTrue(errors)
        self.assertTrue(any("stale" in e for e in errors))

    def test_vacuous_allowlist_entry_with_zero_findings_passes(self):
        allowlist_path = self._allowlist_path(
            [{
                "path": "legacy/clean.yaml", "retired_by": "ENC-TSK-FAKE",
                "reason": "test", "vacuous": True,
            }]
        )
        self._write("legacy/clean.yaml", "architecture_plane: prod\n")
        with mock.patch.object(lal, "ALLOWLIST_PATH", allowlist_path):
            errors, _, _ = lal.run_lint(tracked_files=["legacy/clean.yaml"])
        self.assertEqual(errors, [])


class TestRealAllowlist(unittest.TestCase):
    """Every entry names the ENC-PLN-094 task that retires it (ENC-TSK-Q19 AC-3).
    The list must only shrink: ENC-TSK-Q20 and ENC-TSK-Q22 remove their entries
    and the plan closes with it empty."""

    RETIRING_TASKS = {"ENC-TSK-Q20", "ENC-TSK-Q22"}

    def test_every_entry_is_tagged_with_a_retiring_task_and_reason(self):
        entries = lal.load_allowlist()
        for entry in entries:
            self.assertIn(entry["retired_by"], self.RETIRING_TASKS, entry["path"])
            self.assertTrue(entry.get("reason", "").strip(), entry["path"])

    def test_paths_are_unique_and_tracked(self):
        paths = [e["path"] for e in lal.load_allowlist()]
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            self.assertTrue((REPO_ROOT / path).is_file(), path)

    def test_allowlist_is_now_empty(self):
        """ENC-TSK-Q22 (DOC-5368FE6515ED FR-12, Phase D) is the retiring task
        this class's own docstring predicted would close the plan out: with
        02-compute.yaml, 03-api.yaml, and 06-appsync-events.yaml literalized
        and component_dependency_closure.json's appconfig-extension-x86
        entry retired, nothing legitimately carries an IsArm64-conditional
        finding anymore, so the allowlist -- 03-api.yaml's former vacuous
        entry included -- is empty and must stay that way."""
        self.assertEqual(lal.load_allowlist(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
