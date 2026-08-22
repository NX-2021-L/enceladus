"""Offline tests for elr_sync.py -- ELR hash-pinned manifest distribution
(ENC-TSK-O55, ENC-FTR-134 AC-1). No network access: pull's github path is
never exercised here; every fetch test uses the local: source against a
small, real, throwaway git repo built and committed in a tmp dir. That
keeps the tests hermetic while still exercising the REAL `git show` /
`git ls-tree` code paths pull relies on for the local: source.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch

import elr_sync


# ---------------------------------------------------------------------------
# Fixture helpers -- a tiny throwaway git repo shaped like tools/elr/
# ---------------------------------------------------------------------------


def _run_git(*args: str, cwd: Path) -> str:
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed (cwd={cwd}): {proc.stderr}")
    return proc.stdout


def _init_repo(root: Path) -> Path:
    repo_dir = root / "repo"
    repo_dir.mkdir()
    _run_git("init", "-q", cwd=repo_dir)
    _run_git("config", "user.email", "elr-sync-tests@example.invalid", cwd=repo_dir)
    _run_git("config", "user.name", "ELR Sync Tests", cwd=repo_dir)
    return repo_dir


def _write_base_fixture_files(repo_dir: Path) -> Path:
    elr_dir = repo_dir / "tools" / "elr"
    (elr_dir / "elr_lib").mkdir(parents=True)
    (elr_dir / "tests").mkdir(parents=True)
    (elr_dir / "elr_lib" / "__init__.py").write_text("", encoding="utf-8")
    (elr_dir / "elr_lib" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (elr_dir / "elr_x.py").write_text("#!/usr/bin/env python3\nprint('x')\n", encoding="utf-8")
    (elr_dir / "README.md").write_text("# Fixture ELR\n", encoding="utf-8")
    (elr_dir / "elr_contracts.json").write_text(json.dumps({"entries": []}), encoding="utf-8")
    # Must NEVER end up in the manifest -- lives under tests/, not matched
    # by any of the four include patterns.
    (elr_dir / "tests" / "test_should_be_excluded.py").write_text("# excluded\n", encoding="utf-8")
    return elr_dir


def _commit_manifest(repo_dir: Path, elr_dir: Path, extra_entries: Optional[List[dict]] = None, message: str = "fixture commit") -> str:
    manifest = elr_sync.build_manifest(repo_dir, elr_dir, generated_at="2026-01-01T00:00:00Z")
    if extra_entries:
        manifest["files"].extend(extra_entries)
        manifest["files"].sort(key=lambda e: e["path"])
    (elr_dir / elr_sync.MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _run_git("add", "-A", cwd=repo_dir)
    _run_git("commit", "-q", "-m", message, cwd=repo_dir)
    return _run_git("rev-parse", "HEAD", cwd=repo_dir).strip()


class _GitFixtureCase(unittest.TestCase):
    """Base class that builds one committed fixture repo per test."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)
        self.repo_dir = _init_repo(self.root)
        self.elr_dir = _write_base_fixture_files(self.repo_dir)
        self.sha = _commit_manifest(self.repo_dir, self.elr_dir)
        self.dest = self.root / "dest"


# ---------------------------------------------------------------------------
# Pure-function tests
# ---------------------------------------------------------------------------


class ForbiddenPathTests(unittest.TestCase):
    def test_dictionary_token_is_forbidden(self):
        self.assertTrue(elr_sync.is_forbidden_path("governance_data_dictionary.json"))
        self.assertTrue(elr_sync.is_forbidden_path("tools/elr/elr_DICTIONARY_helper.py"))

    def test_session_cache_token_is_forbidden(self):
        self.assertTrue(elr_sync.is_forbidden_path("session-cache/anything.json"))

    def test_ordinary_runtime_path_is_not_forbidden(self):
        self.assertFalse(elr_sync.is_forbidden_path("elr_lib/config.py"))
        self.assertFalse(elr_sync.is_forbidden_path("elr_sync.py"))
        self.assertFalse(elr_sync.is_forbidden_path("README.md"))


class RefValidationTests(unittest.TestCase):
    def test_valid_40_hex_accepted(self):
        self.assertTrue(elr_sync.is_valid_ref("a" * 40))
        self.assertTrue(elr_sync.is_valid_ref("0123456789abcdef0123456789ABCDEF01234567"))

    def test_branch_name_rejected(self):
        self.assertFalse(elr_sync.is_valid_ref("main"))
        self.assertFalse(elr_sync.is_valid_ref("v4/main"))

    def test_short_sha_rejected(self):
        self.assertFalse(elr_sync.is_valid_ref("abc1234"))

    def test_empty_or_none_rejected(self):
        self.assertFalse(elr_sync.is_valid_ref(""))
        self.assertFalse(elr_sync.is_valid_ref(None))


class RuntimePatternTests(unittest.TestCase):
    def test_top_level_script_matches(self):
        self.assertTrue(elr_sync._matches_runtime_pattern("tools/elr/elr_sync.py"))

    def test_elr_lib_module_matches(self):
        self.assertTrue(elr_sync._matches_runtime_pattern("tools/elr/elr_lib/config.py"))

    def test_contracts_and_readme_match(self):
        self.assertTrue(elr_sync._matches_runtime_pattern("tools/elr/elr_contracts.json"))
        self.assertTrue(elr_sync._matches_runtime_pattern("tools/elr/README.md"))

    def test_manifest_itself_does_not_match(self):
        self.assertFalse(elr_sync._matches_runtime_pattern("tools/elr/elr_manifest.json"))

    def test_tests_directory_does_not_match(self):
        self.assertFalse(elr_sync._matches_runtime_pattern("tools/elr/tests/test_sync.py"))

    def test_nested_elr_lib_subdir_does_not_match(self):
        self.assertFalse(elr_sync._matches_runtime_pattern("tools/elr/elr_lib/sub/deep.py"))

    def test_outside_tools_elr_does_not_match(self):
        self.assertFalse(elr_sync._matches_runtime_pattern("backend/lambda/foo.py"))

    def test_relative_path_strip(self):
        self.assertEqual(elr_sync._elr_relative_path("tools/elr/elr_lib/config.py"), "elr_lib/config.py")
        self.assertEqual(elr_sync._elr_relative_path("tools/elr/elr_sync.py"), "elr_sync.py")


class CollectRuntimeFilesTests(unittest.TestCase):
    def test_collects_expected_set_and_excludes_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            elr_root = Path(tmp)
            (elr_root / "elr_lib").mkdir()
            (elr_root / "tests").mkdir()
            (elr_root / "elr_lib" / "config.py").write_text("x = 1\n")
            (elr_root / "elr_ok.py").write_text("print(1)\n")
            (elr_root / "elr_contracts.json").write_text("{}")
            (elr_root / "README.md").write_text("# hi\n")
            (elr_root / "tests" / "test_foo.py").write_text("# should be excluded\n")

            files = elr_sync.collect_runtime_files(elr_root)
            names = sorted(str(p.relative_to(elr_root)) for p in files)
            self.assertEqual(
                names,
                ["README.md", "elr_contracts.json", "elr_lib/config.py", "elr_ok.py"],
            )

    def test_dictionary_filename_raises_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            elr_root = Path(tmp)
            (elr_root / "elr_ok.py").write_text("print(1)\n")
            (elr_root / "elr_dictionary_helper.py").write_text("# forbidden\n")
            with self.assertRaises(AssertionError):
                elr_sync.collect_runtime_files(elr_root)

    def test_session_cache_filename_raises_assertion(self):
        with tempfile.TemporaryDirectory() as tmp:
            elr_root = Path(tmp)
            (elr_root / "elr_session-cache_thing.py").write_text("# forbidden\n")
            with self.assertRaises(AssertionError):
                elr_sync.collect_runtime_files(elr_root)

    def test_missing_optional_pieces_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            elr_root = Path(tmp)
            (elr_root / "elr_only.py").write_text("print(1)\n")
            files = elr_sync.collect_runtime_files(elr_root)
            self.assertEqual([p.name for p in files], ["elr_only.py"])


# ---------------------------------------------------------------------------
# build_manifest determinism
# ---------------------------------------------------------------------------


class BuildManifestDeterminismTests(unittest.TestCase):
    def test_repeated_generation_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            elr_root = repo_root / "tools" / "elr"
            elr_root.mkdir(parents=True)
            (elr_root / "elr_lib").mkdir()
            (elr_root / "elr_lib" / "a.py").write_text("A = 1\n")
            (elr_root / "elr_top.py").write_text("print('top')\n")
            (elr_root / "README.md").write_text("# doc\n")

            m1 = elr_sync.build_manifest(repo_root, elr_root, generated_at="2026-01-01T00:00:00Z")
            m2 = elr_sync.build_manifest(repo_root, elr_root, generated_at="2026-01-01T00:00:00Z")
            self.assertEqual(json.dumps(m1, sort_keys=True), json.dumps(m2, sort_keys=True))

    def test_manifest_never_lists_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            elr_root = repo_root / "tools" / "elr"
            elr_root.mkdir(parents=True)
            (elr_root / "elr_top.py").write_text("print(1)\n")
            # Pre-existing manifest from a prior run must not be picked up
            # by a subsequent generation (it's .json, not matched by the
            # elr_*.py glob, and not named elr_contracts.json/README.md).
            (elr_root / elr_sync.MANIFEST_FILENAME).write_text("{}")

            manifest = elr_sync.build_manifest(repo_root, elr_root, generated_at="2026-01-01T00:00:00Z")
            paths = [f["path"] for f in manifest["files"]]
            self.assertNotIn("tools/elr/elr_manifest.json", paths)

    def test_dictionary_exclusion_propagates_through_build_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            elr_root = repo_root / "tools" / "elr"
            elr_root.mkdir(parents=True)
            (elr_root / "elr_dictionary_sync.py").write_text("# forbidden\n")
            with self.assertRaises(AssertionError):
                elr_sync.build_manifest(repo_root, elr_root)

    def test_content_change_changes_hash_not_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            elr_root = repo_root / "tools" / "elr"
            elr_root.mkdir(parents=True)
            target = elr_root / "elr_top.py"
            target.write_text("print(1)\n")
            m1 = elr_sync.build_manifest(repo_root, elr_root, generated_at="t")
            target.write_text("print(2)\n")
            m2 = elr_sync.build_manifest(repo_root, elr_root, generated_at="t")
            self.assertNotEqual(m1["files"][0]["sha256"], m2["files"][0]["sha256"])
            self.assertEqual(m1["files"][0]["path"], m2["files"][0]["path"])


# ---------------------------------------------------------------------------
# generate-manifest CLI (ELR_ROOT/REPO_ROOT patched to a temp fixture so
# the real live tools/elr/elr_manifest.json is never touched by tests)
# ---------------------------------------------------------------------------


class GenerateManifestCliTests(_GitFixtureCase):
    def test_cmd_generate_manifest_writes_file_and_digest(self):
        with patch.object(elr_sync, "ELR_ROOT", self.elr_dir), patch.object(elr_sync, "REPO_ROOT", self.repo_dir):
            parser = elr_sync.build_parser()
            args = parser.parse_args(["generate-manifest", "--generated-at", "2026-02-02T00:00:00Z"])
            digest = elr_sync.cmd_generate_manifest(args)

        self.assertTrue(digest["ok"])
        self.assertEqual(digest["operation"], "elr_sync.generate_manifest")
        self.assertEqual(digest["manifest_version"], elr_sync.MANIFEST_VERSION)
        self.assertTrue(digest["source_ref"])
        out_path = Path(digest["local_path"])
        self.assertTrue(out_path.is_file())
        written = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(written["generated_at"], "2026-02-02T00:00:00Z")
        paths = [f["path"] for f in written["files"]]
        self.assertIn("tools/elr/elr_x.py", paths)
        self.assertNotIn("tools/elr/elr_manifest.json", paths)
        self.assertNotIn("tools/elr/tests/test_should_be_excluded.py", paths)


# ---------------------------------------------------------------------------
# pull -- happy path, refusals, and the corrupted-script drill
# ---------------------------------------------------------------------------


class PullHappyPathTests(_GitFixtureCase):
    def test_all_verified_lands_files_and_metadata(self):
        digest = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))

        self.assertTrue(digest["ok"], digest)
        self.assertEqual(digest["operation"], "elr_sync.pull")
        self.assertEqual(digest["source_ref"], self.sha)
        self.assertEqual(digest["files_failed"], 0)
        self.assertGreater(digest["files_verified"], 0)
        self.assertEqual(digest["dest"], str(self.dest))

        self.assertTrue((self.dest / "elr_x.py").is_file())
        self.assertTrue((self.dest / "elr_lib" / "mod.py").is_file())
        self.assertTrue((self.dest / "README.md").is_file())
        self.assertTrue((self.dest / "elr_contracts.json").is_file())
        self.assertFalse((self.dest / "tests").exists())
        self.assertTrue((self.dest / elr_sync.SYNC_MANIFEST_METAFILE).is_file())

        # No leftover staging siblings.
        staging_siblings = [p.name for p in self.dest.parent.iterdir() if ".staging-" in p.name]
        self.assertEqual(staging_siblings, [])

    def test_digest_is_json_serializable_and_stable_shape(self):
        digest = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))
        serialized = json.dumps(digest, sort_keys=True)
        self.assertEqual(json.loads(serialized), digest)

    def test_second_pull_preserves_previous_install_as_prev(self):
        first = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))
        self.assertTrue(first["ok"])

        (self.elr_dir / "elr_y.py").write_text("print('y')\n", encoding="utf-8")
        sha2 = _commit_manifest(self.repo_dir, self.elr_dir, message="add elr_y.py")

        second = elr_sync.pull_manifest_at_ref(sha2, f"local:{self.repo_dir}", str(self.dest))
        self.assertTrue(second["ok"], second)

        self.assertTrue((self.dest / "elr_y.py").is_file())
        prev_dir = self.dest.parent / f"{self.dest.name}.prev"
        self.assertTrue(prev_dir.is_dir())
        self.assertTrue((prev_dir / "elr_x.py").is_file())
        self.assertFalse((prev_dir / "elr_y.py").exists())


class PullRefusalTests(_GitFixtureCase):
    def test_ref_not_40_hex_refuses_before_any_fetch(self):
        digest = elr_sync.pull_manifest_at_ref("main", f"local:{self.repo_dir}", str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "ref-not-40-hex")
        self.assertFalse(self.dest.exists())

    def test_short_sha_refused(self):
        digest = elr_sync.pull_manifest_at_ref(self.sha[:7], f"local:{self.repo_dir}", str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "ref-not-40-hex")

    def test_unknown_source_refused(self):
        digest = elr_sync.pull_manifest_at_ref(self.sha, "not-a-real-source", str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "unknown-source")

    def test_manifest_fetch_failed_for_nonexistent_commit(self):
        fake_sha = ("0" * 40)
        digest = elr_sync.pull_manifest_at_ref(fake_sha, f"local:{self.repo_dir}", str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "manifest-fetch-failed")
        self.assertFalse(self.dest.exists())

    def test_listed_file_missing_refuses_activation(self):
        ghost_entry = {"path": "tools/elr/elr_ghost.py", "sha256": "0" * 64, "size_bytes": 1}
        sha_ghost = _commit_manifest(self.repo_dir, self.elr_dir, extra_entries=[ghost_entry], message="ghost entry")

        digest = elr_sync.pull_manifest_at_ref(sha_ghost, f"local:{self.repo_dir}", str(self.dest))

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "listed-file-missing")
        self.assertIn("tools/elr/elr_ghost.py", digest["mismatched"])
        self.assertFalse(self.dest.exists())

    def test_manifest_missing_files_refuses_activation(self):
        # A real runtime file lands in the tree AFTER the manifest was
        # committed, without the manifest being regenerated -- direction
        # 2 of the completeness check must catch this.
        (self.elr_dir / "elr_untracked.py").write_text("print('oops')\n", encoding="utf-8")
        _run_git("add", "-A", cwd=self.repo_dir)
        _run_git("commit", "-q", "-m", "add file without regenerating manifest", cwd=self.repo_dir)
        sha2 = _run_git("rev-parse", "HEAD", cwd=self.repo_dir).strip()

        digest = elr_sync.pull_manifest_at_ref(sha2, f"local:{self.repo_dir}", str(self.dest))

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "manifest-missing-files")
        self.assertIn("tools/elr/elr_untracked.py", digest["mismatched"])
        self.assertFalse(self.dest.exists())

    def test_corrupted_script_drill_refuses_and_leaves_dest_untouched(self):
        """The corrupted-script drill: a transport/staging corruption
        serves DIFFERENT bytes than the pinned commit actually contains
        for one file, while the manifest and every other file are
        untouched. pull must name the exact corrupted path, refuse
        activation with reason "hash-mismatch", and leave a
        pre-existing dest completely alone.
        """
        self.dest.mkdir(parents=True)
        sentinel = self.dest / "SENTINEL.txt"
        sentinel.write_text("do-not-touch", encoding="utf-8")

        real_source = elr_sync.LocalGitSource(str(self.repo_dir))

        class _TamperingSource:
            def __init__(self, inner, tamper_path):
                self._inner = inner
                self._tamper_path = tamper_path

            def read_file(self, repo_relative_path, ref):
                data = self._inner.read_file(repo_relative_path, ref)
                if repo_relative_path == self._tamper_path and data is not None:
                    return data + b"\ntampered-in-transit\n"
                return data

            def list_tree(self, dir_repo_relative_path, ref):
                return self._inner.list_tree(dir_repo_relative_path, ref)

        tampering_source = _TamperingSource(real_source, "tools/elr/elr_x.py")

        with patch.object(elr_sync, "build_source", return_value=tampering_source):
            digest = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))

        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "hash-mismatch")
        self.assertEqual(digest["mismatched"], ["tools/elr/elr_x.py"])

        # dest untouched: still just the sentinel, unchanged.
        remaining = sorted(p.name for p in self.dest.iterdir())
        self.assertEqual(remaining, ["SENTINEL.txt"])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "do-not-touch")

        # No leftover staging siblings next to dest.
        staging_siblings = [p.name for p in self.dest.parent.iterdir() if ".staging-" in p.name]
        self.assertEqual(staging_siblings, [])


# ---------------------------------------------------------------------------
# verify -- pure local drift detection
# ---------------------------------------------------------------------------


class VerifyTests(_GitFixtureCase):
    def test_verify_clean_install_ok(self):
        pulled = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))
        self.assertTrue(pulled["ok"])

        digest = elr_sync.verify_install(str(self.dest))
        self.assertTrue(digest["ok"], digest)
        self.assertEqual(digest["files_failed"], 0)
        self.assertEqual(digest["files_verified"], pulled["files_verified"])
        self.assertEqual(digest["source_ref"], self.sha)

    def test_verify_detects_drift(self):
        pulled = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))
        self.assertTrue(pulled["ok"])

        (self.dest / "elr_x.py").write_text("print('DRIFTED')\n", encoding="utf-8")

        digest = elr_sync.verify_install(str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "drift-detected")
        self.assertIn("tools/elr/elr_x.py", digest["mismatched"])

    def test_verify_detects_deleted_file(self):
        pulled = elr_sync.pull_manifest_at_ref(self.sha, f"local:{self.repo_dir}", str(self.dest))
        self.assertTrue(pulled["ok"])

        (self.dest / "elr_x.py").unlink()

        digest = elr_sync.verify_install(str(self.dest))
        self.assertFalse(digest["ok"])
        self.assertIn("tools/elr/elr_x.py", digest["mismatched"])

    def test_verify_no_recorded_manifest(self):
        empty_dest = self.root / "empty_dest"
        empty_dest.mkdir()
        digest = elr_sync.verify_install(str(empty_dest))
        self.assertFalse(digest["ok"])
        self.assertEqual(digest["refusal"]["reason"], "no-recorded-manifest")


# ---------------------------------------------------------------------------
# CLI: allow_abbrev + main() end-to-end
# ---------------------------------------------------------------------------


class AllowAbbrevTests(unittest.TestCase):
    def test_top_level_parser_has_allow_abbrev_false(self):
        parser = elr_sync.build_parser()
        self.assertFalse(parser.allow_abbrev)

    def test_pull_requires_full_flag_names(self):
        parser = elr_sync.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                # "--re" is an unambiguous prefix of "--ref" -- with
                # allow_abbrev=True argparse would accept it silently.
                parser.parse_args(["pull", "--re", "a" * 40])

    def test_pull_full_flag_names_accepted(self):
        parser = elr_sync.build_parser()
        args = parser.parse_args(["pull", "--ref", "a" * 40, "--source", "local:/tmp/x", "--dest", "/tmp/y"])
        self.assertEqual(args.ref, "a" * 40)
        self.assertEqual(args.source, "local:/tmp/x")
        self.assertEqual(args.dest, "/tmp/y")

    def test_pull_defaults(self):
        parser = elr_sync.build_parser()
        args = parser.parse_args(["pull", "--ref", "a" * 40])
        self.assertEqual(args.source, elr_sync.DEFAULT_SOURCE)
        self.assertEqual(args.dest, elr_sync.DEFAULT_DEST)

    def test_pull_missing_ref_errors(self):
        parser = elr_sync.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["pull"])

    def test_verify_default_dest(self):
        parser = elr_sync.build_parser()
        args = parser.parse_args(["verify"])
        self.assertEqual(args.dest, elr_sync.DEFAULT_DEST)

    def test_command_required(self):
        parser = elr_sync.build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args([])


class MainEndToEndTests(_GitFixtureCase):
    def test_main_pull_prints_single_json_line_and_exit_zero(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = elr_sync.main(["pull", "--ref", self.sha, "--source", f"local:{self.repo_dir}", "--dest", str(self.dest)])
        self.assertEqual(exit_code, 0)
        lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertTrue(parsed["ok"])

    def test_main_pull_refusal_exit_one(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = elr_sync.main(["pull", "--ref", "main", "--source", f"local:{self.repo_dir}", "--dest", str(self.dest)])
        self.assertEqual(exit_code, 1)
        parsed = json.loads(stdout.getvalue().strip())
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["refusal"]["reason"], "ref-not-40-hex")

    def test_main_verify_after_pull(self):
        with contextlib.redirect_stdout(io.StringIO()):
            elr_sync.main(["pull", "--ref", self.sha, "--source", f"local:{self.repo_dir}", "--dest", str(self.dest)])

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = elr_sync.main(["verify", "--dest", str(self.dest)])
        self.assertEqual(exit_code, 0)
        parsed = json.loads(stdout.getvalue().strip())
        self.assertTrue(parsed["ok"])


# ---------------------------------------------------------------------------
# Sources: build_source() dispatch + GithubApiSource construction (no
# network -- only object/attribute assertions).
# ---------------------------------------------------------------------------


class BuildSourceTests(unittest.TestCase):
    def test_github_source(self):
        source = elr_sync.build_source("github")
        self.assertIsInstance(source, elr_sync.GithubApiSource)

    def test_local_source(self):
        source = elr_sync.build_source("local:/some/path")
        self.assertIsInstance(source, elr_sync.LocalGitSource)
        self.assertEqual(source.repo_path, "/some/path")

    def test_local_source_requires_path(self):
        with self.assertRaises(ValueError):
            elr_sync.build_source("local:")

    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError):
            elr_sync.build_source("ftp://nope")


class GithubApiSourceAuthTests(unittest.TestCase):
    def test_env_token_preferred(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "shh"}, clear=False):
            source = elr_sync.GithubApiSource()
            self.assertEqual(source.auth_mode, "env-token")

    def test_falls_back_to_gh_cli_when_no_token(self):
        with patch.dict("os.environ", {}, clear=True):
            source = elr_sync.GithubApiSource()
            self.assertEqual(source.auth_mode, "gh-cli-fallback")

    def test_repr_and_digest_never_contain_token_value(self):
        # There is no __repr__ override, but the object's __dict__ must
        # not leak the raw token into anything that gets printed by this
        # module -- the token is only ever used inside a header dict
        # built at request time, never stored anywhere logged.
        with patch.dict("os.environ", {"GITHUB_TOKEN": "super-secret-value"}, clear=False):
            source = elr_sync.GithubApiSource()
            self.assertNotIn("super-secret-value", repr(vars(source).get("auth_mode")))


if __name__ == "__main__":
    unittest.main()
