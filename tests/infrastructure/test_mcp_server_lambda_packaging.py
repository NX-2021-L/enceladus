"""ENC-TSK-L63 / ENC-ISS-492: MCP Lambda artifacts must include mcp_server package."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_ROOT = REPO_ROOT / "tools" / "enceladus-mcp-server"


def _simulate_mcp_lambda_packaging(workdir: Path) -> None:
    """Mirror .github/workflows/_build.yml MCP runtime packaging block."""
    for py in sorted(MCP_ROOT.glob("*.py")):
        if py.name.startswith("test_"):
            continue
        shutil.copy2(py, workdir / py.name)

    mcp_pkg_src = MCP_ROOT / "mcp_server"
    assert mcp_pkg_src.is_dir(), "mcp_server package must exist in repo"
    shutil.copytree(
        mcp_pkg_src,
        workdir / "mcp_server",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def test_mcp_server_package_importable_after_simulated_lambda_packaging():
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        _simulate_mcp_lambda_packaging(workdir)
        assert (workdir / "server.py").is_file()
        assert (workdir / "mcp_server" / "actions.py").is_file()

        env = {**os.environ, "PYTHONPATH": str(workdir)}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import mcp_server.actions; import mcp_server.runtime; print('ok')",
            ],
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout


def test_build_yml_declares_mcp_server_rsync():
    build_yml = (REPO_ROOT / ".github" / "workflows" / "_build.yml").read_text()
    assert "mcp_server/" in build_yml
    assert "ENC-TSK-L63" in build_yml or "ENC-ISS-492" in build_yml
