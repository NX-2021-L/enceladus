#!/usr/bin/env python3
"""ENC-TSK-P15 / ENC-ISS-669: tests for the devops ownership snapshot guard.

Mirrors the positive-control discipline established by
test_verify_cross_plane_arn_isolation.py: a clean result on the real
snapshot proves the file is well-formed, but the point of this suite is the
synthetic negative controls -- a snapshot missing devops-io-devops-mcp (the
exact ENC-ISS-669 gap), a snapshot with a bad digest shape, a snapshot with
an un-provenanced function name, and a digest that no longer matches a
local checkout -- must all be refused, not waved through.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import verify_devops_ownership_snapshot as guard  # noqa: E402


def _valid_snapshot() -> dict:
    """A minimal, fully valid synthetic snapshot -- independent of the real
    committed file, so these tests exercise the SHAPE contract, not today's
    specific devops estate."""
    return {
        "owning_repo": "NX-2021-L/devops",
        "pinned_commit": "a" * 40,
        "pinned_at": "2026-08-23",
        "sources": {
            "infrastructure/aws/lambda/functions.yaml": {
                "sha256": "b" * 64,
                "declares_functions": ["devops-widget-one"],
                "reason": "the manifest",
            },
            "scripts/deploy_io_devops_mcp.py": {
                "sha256": "c" * 64,
                "declares_functions": ["devops-io-devops-mcp"],
                "reason": "self-contained deploy script, not in functions.yaml",
            },
        },
        "functions": [
            {
                "function_name": "devops-widget-one",
                "declared_in": "infrastructure/aws/lambda/functions.yaml",
                "runtime": "python3.11",
                "architecture": "x86_64",
                "deploy_channel": "Deploy Analytics Stack",
            },
            {
                "function_name": "devops-io-devops-mcp",
                "declared_in": "scripts/deploy_io_devops_mcp.py",
                "runtime": "python3.12",
                "architecture": "arm64",
                "deploy_channel": "Deploy io-devops MCP",
            },
        ],
        "ownership_predicate": "exact name match against functions[]",
    }


class TestRealSnapshotFile(unittest.TestCase):
    """Positive control: the actual committed snapshot must be valid."""

    def test_real_snapshot_loads_and_validates(self):
        snapshot = guard.load_snapshot()
        errors = guard.validate_structure(snapshot)
        self.assertEqual(errors, [])

    def test_real_snapshot_carries_devops_io_devops_mcp(self):
        """ENC-ISS-669's own acceptance test: the function functions.yaml misses."""
        snapshot = guard.load_snapshot()
        names = {f["function_name"] for f in snapshot["functions"]}
        self.assertIn("devops-io-devops-mcp", names)
        # And it must NOT be attributed to functions.yaml -- that would be
        # exactly the false provenance this file exists to prevent.
        entry = next(f for f in snapshot["functions"] if f["function_name"] == "devops-io-devops-mcp")
        self.assertNotIn("functions.yaml", entry["declared_in"])

    def test_real_snapshot_has_exactly_five_functions(self):
        snapshot = guard.load_snapshot()
        self.assertEqual(len(snapshot["functions"]), 5)

    def test_cli_passes_on_real_tree(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_devops_ownership_snapshot.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[SUCCESS]", result.stdout)
        self.assertIn("[SKIPPED]", result.stdout)  # no local source in a plain run

    def test_cli_verifies_against_the_real_local_devops_checkout_when_present(self):
        """If a local devops-repo checkout happens to be available (as it was
        during ENC-TSK-P15's authoring), the digest re-verification path must
        actually run and actually pass -- proving the pin is not fabricated.
        Skips cleanly when no such checkout exists (the normal CI case)."""
        import os
        import subprocess
        local_source = os.environ.get(
            "DEVOPS_OWNERSHIP_LOCAL_SOURCE_TEST_PATH", "/Users/jreese/devops-repo"
        )
        if not Path(local_source).is_dir():
            self.skipTest(f"no local devops checkout at {local_source}")
        env = dict(os.environ, DEVOPS_OWNERSHIP_LOCAL_SOURCE=local_source)
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "verify_devops_ownership_snapshot.py")],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("digest-verified", result.stdout)
        self.assertNotIn("[SKIPPED]", result.stdout)
        self.assertNotIn("DIGEST MISMATCH", result.stdout)


class TestStructuralValidation(unittest.TestCase):
    def test_valid_synthetic_snapshot_passes(self):
        self.assertEqual(guard.validate_structure(_valid_snapshot()), [])

    def test_missing_devops_io_devops_mcp_is_refused(self):
        """The central negative control: a snapshot that reproduces the exact
        functions.yaml-only gap ENC-ISS-669 found must be refused, not pass."""
        snapshot = _valid_snapshot()
        snapshot["functions"] = [
            f for f in snapshot["functions"] if f["function_name"] != "devops-io-devops-mcp"
        ]
        # also drop its source entry so the fixture stays internally consistent
        del snapshot["sources"]["scripts/deploy_io_devops_mcp.py"]
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("devops-io-devops-mcp" in e for e in errors), errors)

    def test_duplicate_function_name_is_refused(self):
        snapshot = _valid_snapshot()
        snapshot["functions"].append(copy.deepcopy(snapshot["functions"][0]))
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("more than once" in e for e in errors), errors)

    def test_bad_digest_shape_is_refused(self):
        snapshot = _valid_snapshot()
        snapshot["sources"]["infrastructure/aws/lambda/functions.yaml"]["sha256"] = "not-a-hash"
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("sha256" in e for e in errors), errors)

    def test_short_commit_is_refused(self):
        snapshot = _valid_snapshot()
        snapshot["pinned_commit"] = "abc123"
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("pinned_commit" in e for e in errors), errors)

    def test_wrong_owning_repo_is_refused(self):
        snapshot = _valid_snapshot()
        snapshot["owning_repo"] = "NX-2021-L/enceladus"
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("owning_repo" in e for e in errors), errors)

    def test_function_with_no_provenance_is_refused(self):
        """AC-3's explicit prohibition: a function listed in functions[] with
        no matching declares_functions entry anywhere is a hand-copied name
        with no provenance -- exactly what this file must never allow."""
        snapshot = _valid_snapshot()
        snapshot["functions"].append({
            "function_name": "devops-hand-copied-no-provenance",
            "declared_in": "someone's memory",
            "runtime": "python3.11",
            "architecture": "x86_64",
            "deploy_channel": "unknown",
        })
        errors = guard.validate_structure(snapshot)
        self.assertTrue(
            any("devops-hand-copied-no-provenance" in e and "no entry" in e for e in errors),
            errors,
        )

    def test_missing_required_top_key_is_refused(self):
        snapshot = _valid_snapshot()
        del snapshot["ownership_predicate"]
        errors = guard.validate_structure(snapshot)
        self.assertTrue(any("ownership_predicate" in e for e in errors), errors)

    def test_empty_functions_list_is_refused(self):
        snapshot = _valid_snapshot()
        snapshot["functions"] = []
        errors = guard.validate_structure(snapshot)
        # An empty functions[] is falsy, so it's caught by the required-key
        # sweep before the deeper functions[]-specific check ever runs --
        # either way, it must be refused, not pass.
        self.assertTrue(any("functions" in e for e in errors), errors)


class TestLocalSourceVerification(unittest.TestCase):
    def test_matching_local_source_passes(self):
        snapshot = _valid_snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel_path, entry in snapshot["sources"].items():
                payload = f"content for {rel_path}".encode()
                entry["sha256"] = guard._sha256(payload)
                target = root / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            errors, verified = guard.verify_local_source(snapshot, tmp)
            self.assertEqual(errors, [])
            self.assertEqual(len(verified), len(snapshot["sources"]))

    def test_digest_mismatch_is_refused_not_warned(self):
        snapshot = _valid_snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel_path in snapshot["sources"]:
                target = root / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"this does not match the pinned digest")
            errors, verified = guard.verify_local_source(snapshot, tmp)
            self.assertTrue(errors)
            self.assertIn("DIGEST MISMATCH", errors[0])
            self.assertEqual(verified, [])

    def test_missing_local_file_is_refused(self):
        snapshot = _valid_snapshot()
        with tempfile.TemporaryDirectory() as tmp:
            errors, verified = guard.verify_local_source(snapshot, tmp)
            self.assertTrue(errors)
            self.assertTrue(any("does not exist" in e for e in errors))


class TestCliExitCodes(unittest.TestCase):
    def test_malformed_snapshot_exits_2(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "devops_lambda_ownership_snapshot.json"
            bad_path.write_text("{not valid json", encoding="utf-8")
            script = (REPO_ROOT / "tools" / "verify_devops_ownership_snapshot.py").read_text()
            runner = Path(tmp) / "run_against_bad.py"
            runner.write_text(
                script.replace(
                    'SNAPSHOT_PATH = REPO_ROOT / "infrastructure" / "devops_lambda_ownership_snapshot.json"',
                    f'SNAPSHOT_PATH = Path({str(bad_path)!r})',
                ),
                encoding="utf-8",
            )
            result = subprocess.run([sys.executable, str(runner)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
