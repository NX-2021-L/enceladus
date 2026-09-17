#!/usr/bin/env python3
"""ENC-TSK-Q07: unit tests for tools/assert_lambda_artifact_contents.py.

Builds two fixture zips in a tempdir -- one "complete" mcp_code artifact
(contains server.py and mcp_server/__init__.py) and one "broken" artifact
missing server.py (the exact incident shape: the handler module absent, so
server.lambda_handler cannot be imported at invoke time) -- and asserts the
guard passes the former and fails the latter with server.py named in its
missing-entries output.

Run: python3 -m pytest tools/test_assert_lambda_artifact_contents.py -q
"""
from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent / "assert_lambda_artifact_contents.py"
_spec = importlib.util.spec_from_file_location("assert_lambda_artifact_contents", MODULE_PATH)
alac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(alac)  # type: ignore[union-attr]


def _make_zip(path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for arcname, content in entries.items():
            zf.writestr(arcname, content)
    return path


@pytest.fixture
def complete_mcp_code_zip(tmp_path: Path) -> Path:
    return _make_zip(
        tmp_path / "mcp_code-complete.zip",
        {
            "server.py": "def lambda_handler(event, context):\n    return {}\n",
            "manifest_projection.py": "# helper\n",
            "dispatch_plan_generator.py": "# helper\n",
            "mcp_server/__init__.py": "# package init\n",
            "mcp_server/runtime.py": "# runtime\n",
        },
    )


@pytest.fixture
def missing_server_zip(tmp_path: Path) -> Path:
    # The exact incident shape: mcp_server/ present, server.py (the handler
    # module itself) absent from the zip root.
    return _make_zip(
        tmp_path / "mcp_code-broken.zip",
        {
            "manifest_projection.py": "# helper\n",
            "mcp_server/__init__.py": "# package init\n",
        },
    )


class TestResolveRequiredEntries:
    def test_known_function_uses_builtin_defaults(self):
        assert alac.resolve_required_entries("mcp_code", None) == [
            "server.py",
            "mcp_server/__init__.py",
        ]

    def test_override_replaces_builtin_defaults(self):
        assert alac.resolve_required_entries("mcp_code", ["server.py"]) == ["server.py"]

    def test_unknown_function_without_override_raises(self):
        with pytest.raises(SystemExit):
            alac.resolve_required_entries("some_unregistered_fn", None)

    def test_unknown_function_with_override_is_allowed(self):
        assert alac.resolve_required_entries("some_unregistered_fn", ["a.py"]) == ["a.py"]


class TestMissingEntries:
    def test_complete_zip_has_no_missing_entries(self, complete_mcp_code_zip):
        required = alac.REQUIRED_ENTRIES["mcp_code"]
        assert alac.missing_entries(complete_mcp_code_zip, required) == []

    def test_broken_zip_reports_server_py_missing(self, missing_server_zip):
        required = alac.REQUIRED_ENTRIES["mcp_code"]
        missing = alac.missing_entries(missing_server_zip, required)
        assert "server.py" in missing

    def test_dotslash_prefixed_entries_are_normalized(self, tmp_path):
        zip_path = _make_zip(
            tmp_path / "dotslash.zip",
            {
                "./server.py": "x\n",
                "./mcp_server/__init__.py": "x\n",
            },
        )
        assert alac.missing_entries(zip_path, ["server.py", "mcp_server/__init__.py"]) == []


class TestMainCli:
    def test_complete_zip_exits_zero(self, complete_mcp_code_zip, capsys):
        rc = alac.main([str(complete_mcp_code_zip), "mcp_code"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out

    def test_broken_zip_exits_one_and_names_server_py(self, missing_server_zip, capsys):
        rc = alac.main([str(missing_server_zip), "mcp_code"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "server.py" in err

    def test_missing_zip_path_exits_two(self, tmp_path, capsys):
        rc = alac.main([str(tmp_path / "does-not-exist.zip"), "mcp_code"])
        assert rc == 2

    def test_unknown_function_no_override_exits_two(self, complete_mcp_code_zip, capsys):
        rc = alac.main([str(complete_mcp_code_zip), "some_unregistered_fn"])
        assert rc == 2

    def test_explicit_require_overrides_default_for_broken_zip(self, missing_server_zip):
        # missing_server_zip lacks server.py but does have mcp_server/__init__.py;
        # an override that only requires the latter must pass even though the
        # built-in mcp_code default would fail it.
        rc = alac.main([str(missing_server_zip), "mcp_code", "--require", "mcp_server/__init__.py"])
        assert rc == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
