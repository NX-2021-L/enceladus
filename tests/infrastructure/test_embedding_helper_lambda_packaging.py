"""ENC-TSK-O35 / ENC-ISS-566: Lambdas that import the canonical
backend/lambda/graph_sync/embedding.py helper must declare it in their
.build_extras manifest, or the matrix build (.github/workflows/_build.yml)
never copies the file into the deployment package and the function
crash-loops at import: Runtime.ImportModuleError: No module named
'embedding'.

This is a repeat of ENC-ISS-304 / ENC-TSK-G94 (graph_query_api hit the same
regression when the per-Lambda deploy.sh scripts were tombstoned in favor of
the .build_extras mechanism, ENC-TSK-F60 / PLN-041 Stage 2). This test
mirrors tests/infrastructure/test_mcp_server_lambda_packaging.py so the class
of bug is guarded generically, not just for the one function that happened
to be reported.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LAMBDA_ROOT = REPO_ROOT / "backend" / "lambda"
EMBEDDING_HELPER = LAMBDA_ROOT / "graph_sync" / "embedding.py"

# Matches `import embedding`, `from embedding import ...`, `import embedding as x`
# as a bare top-level module reference (not `graph_sync.embedding` or similar).
_EMBEDDING_IMPORT_RE = re.compile(r"^\s*(?:from embedding import|import embedding\b)", re.MULTILINE)


def _lambdas_importing_embedding_helper() -> list[Path]:
    """Every backend/lambda/<fn>/ (excluding graph_sync itself, which owns the
    helper and needs no .build_extras entry) whose lambda_function.py imports
    the bare `embedding` module."""
    hits = []
    for lambda_function in sorted(LAMBDA_ROOT.glob("*/lambda_function.py")):
        fn_dir = lambda_function.parent
        if fn_dir.name == "graph_sync":
            continue
        text = lambda_function.read_text()
        if _EMBEDDING_IMPORT_RE.search(text):
            hits.append(fn_dir)
    return hits


def test_every_embedding_importer_declares_build_extras():
    importers = _lambdas_importing_embedding_helper()
    assert importers, "expected at least titan_embedding_backfill to import the embedding helper"

    missing = []
    for fn_dir in importers:
        extras_file = fn_dir / ".build_extras"
        if not extras_file.is_file():
            missing.append(f"{fn_dir.name}: no .build_extras file")
            continue
        extras_text = extras_file.read_text()
        if "backend/lambda/graph_sync/embedding.py" not in extras_text:
            missing.append(f"{fn_dir.name}: .build_extras does not declare graph_sync/embedding.py")

    assert not missing, (
        "Lambda(s) import the bare `embedding` module but do not declare "
        "backend/lambda/graph_sync/embedding.py in .build_extras, so the matrix "
        "build will not package it (see ENC-ISS-304/G94, ENC-ISS-566/O35):\n"
        + "\n".join(missing)
    )


def _simulate_build_extras_packaging(fn_dir: Path, workdir: Path) -> None:
    """Mirror the .build_extras copy block in .github/workflows/_build.yml."""
    for item in fn_dir.iterdir():
        if item.name in {".build_extras", "__pycache__"} or item.name.startswith("test_"):
            continue
        if item.is_file():
            shutil.copy2(item, workdir / item.name)

    extras_file = fn_dir / ".build_extras"
    for line in extras_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        src = REPO_ROOT / line
        assert src.is_file(), f".build_extras references missing file: {line}"
        shutil.copy2(src, workdir / src.name)


def test_titan_embedding_backfill_importable_after_simulated_lambda_packaging():
    fn_dir = LAMBDA_ROOT / "titan_embedding_backfill"
    assert (fn_dir / ".build_extras").is_file(), (
        "titan_embedding_backfill/.build_extras is missing -- the matrix build "
        "will not package graph_sync/embedding.py and the Lambda will crash-loop "
        "at import (ENC-ISS-566)"
    )

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        _simulate_build_extras_packaging(fn_dir, workdir)
        assert (workdir / "embedding.py").is_file()
        assert (workdir / "lambda_function.py").is_file()

        env = {**os.environ, "PYTHONPATH": str(workdir)}
        proc = subprocess.run(
            [sys.executable, "-c", "import embedding; print('ok')"],
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
