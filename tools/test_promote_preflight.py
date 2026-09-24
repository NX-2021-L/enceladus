"""Unit tests for tools/promote_preflight.py (ENC-TSK-Q21 FR-8).

Builds throwaway git repos in a temp dir per test -- no dependency on this
repo's own history, no network, no real origin/main.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import promote_preflight as pf  # noqa: E402


def _git(*args: str, cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def _commit(repo: Path, rel_path: str, content: str, message: str) -> str:
    full = repo / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    _git("add", rel_path, cwd=repo)
    _git("commit", "-q", "-m", message, cwd=repo)
    return _git("rev-parse", "HEAD", cwd=repo)


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git("init", "-q", cwd=repo)
    # Pin the initial branch name explicitly rather than relying on the
    # ambient git version's default-branch config.
    _git("symbolic-ref", "HEAD", "refs/heads/main", cwd=repo)
    _git("config", "user.email", "test@example.com", cwd=repo)
    _git("config", "user.name", "Test", cwd=repo)


def _run_main(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = pf.main(argv)
    return code, buf.getvalue()


class PromotePreflightTests(unittest.TestCase):
    def setUp(self):
        self._orig_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        _init_repo(self.repo)
        self.base = _commit(self.repo, "README.md", "base\n", "base")
        os.chdir(self.repo)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        self._tmp.cleanup()

    def test_ancestor_ok(self):
        c1 = _commit(self.repo, "docs/notes.md", "hello\n", "docs change")
        _git("update-ref", "refs/remotes/origin/main", c1, cwd=self.repo)
        code, out = _run_main(["--commit-sha", c1, "--main-ref", "refs/remotes/origin/main"])
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)

    def test_non_ancestor_fails(self):
        _git("update-ref", "refs/remotes/origin/main", self.base, cwd=self.repo)
        _git("checkout", "-q", "-b", "side", cwd=self.repo)
        side = _commit(self.repo, "docs/side.md", "side\n", "side change")
        code, out = _run_main(["--commit-sha", side, "--main-ref", "refs/remotes/origin/main"])
        self.assertEqual(code, 1)
        self.assertIn("::error::", out)
        self.assertIn("FR-8", out)

    def test_gamma_equal_commit_ok(self):
        c1 = _commit(self.repo, "docs/notes2.md", "x\n", "docs change 2")
        _git("update-ref", "refs/remotes/origin/main", c1, cwd=self.repo)
        code, out = _run_main([
            "--commit-sha", c1,
            "--gamma-sha", c1,
            "--main-ref", "refs/remotes/origin/main",
        ])
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)

    def test_gamma_ancestor_nondeployable_delta_ok(self):
        gamma = _commit(self.repo, "docs/gamma.md", "g\n", "gamma commit")
        merge_commit = _commit(self.repo, "governance/note.md", "n\n", "promote merge (docs only)")
        _git("update-ref", "refs/remotes/origin/main", merge_commit, cwd=self.repo)
        code, out = _run_main([
            "--commit-sha", merge_commit,
            "--gamma-sha", gamma,
            "--main-ref", "refs/remotes/origin/main",
        ])
        self.assertEqual(code, 0, out)
        self.assertIn("PASS", out)

    def test_gamma_ancestor_deployable_delta_fails(self):
        gamma = _commit(
            self.repo, "backend/lambda/x/lambda_function.py", "print(1)\n", "gamma runtime change"
        )
        merge_commit = _commit(
            self.repo, "backend/lambda/x/lambda_function.py", "print(2)\n", "smuggled runtime change"
        )
        _git("update-ref", "refs/remotes/origin/main", merge_commit, cwd=self.repo)
        code, out = _run_main([
            "--commit-sha", merge_commit,
            "--gamma-sha", gamma,
            "--main-ref", "refs/remotes/origin/main",
        ])
        self.assertEqual(code, 1)
        self.assertIn("::error::", out)
        self.assertIn("backend/lambda/x/lambda_function.py", out)

    def test_gamma_not_ancestor_fails(self):
        c1 = _commit(self.repo, "docs/a.md", "a\n", "a")
        _git("update-ref", "refs/remotes/origin/main", c1, cwd=self.repo)
        _git("checkout", "-q", "-b", "gamma-side", self.base, cwd=self.repo)
        stray_gamma = _commit(self.repo, "docs/b.md", "b\n", "unrelated gamma commit")
        code, out = _run_main([
            "--commit-sha", c1,
            "--gamma-sha", stray_gamma,
            "--main-ref", "refs/remotes/origin/main",
        ])
        self.assertEqual(code, 1)
        self.assertIn("::error::", out)


if __name__ == "__main__":
    unittest.main()
