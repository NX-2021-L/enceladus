#!/usr/bin/env python3
"""check_lambda_pyjwt_requirements.py

Guard tool (ENC-LSN-020): ensure every Lambda function that imports jwt has
PyJWT declared in its own requirements.txt.

Failure modes caught:
  MODE A — Function relies solely on a shared layer for PyJWT. If the layer
            was compiled for the wrong Python ABI the import silently fails,
            causing downstream 401/502 errors with no clear diagnostic.
  MODE B — Function has no requirements.txt; pip never installs anything.

Exit 0 = all clear. Exit 1 = one or more violations found.

Usage:
    python tools/check_lambda_pyjwt_requirements.py [--lambda-dir backend/lambda]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PYJWT_PATTERN = re.compile(r"^\s*pyjwt\b", re.IGNORECASE | re.MULTILINE)
JWT_IMPORT_PATTERN = re.compile(r"^\s*import jwt\b|^\s*from jwt\b", re.MULTILINE)


def _has_jwt_import(py_file: Path) -> bool:
    try:
        return bool(JWT_IMPORT_PATTERN.search(py_file.read_text(errors="replace")))
    except OSError:
        return False


def _has_pyjwt_in_requirements(req_file: Path) -> bool:
    try:
        return bool(PYJWT_PATTERN.search(req_file.read_text(errors="replace")))
    except OSError:
        return False


def scan(lambda_dir: Path) -> list[dict]:
    violations: list[dict] = []
    for fn_dir in sorted(lambda_dir.iterdir()):
        if not fn_dir.is_dir():
            continue
        lf = fn_dir / "lambda_function.py"
        if not lf.exists():
            continue
        if not _has_jwt_import(lf):
            continue
        req = fn_dir / "requirements.txt"
        if not req.exists():
            violations.append({
                "function": fn_dir.name,
                "mode": "B",
                "detail": "no requirements.txt — pip installs nothing",
            })
        elif not _has_pyjwt_in_requirements(req):
            violations.append({
                "function": fn_dir.name,
                "mode": "A",
                "detail": "requirements.txt exists but does not declare PyJWT",
            })
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lambda-dir",
        default="backend/lambda",
        help="Path to the Lambda functions root (default: backend/lambda)",
    )
    args = parser.parse_args()
    lambda_dir = Path(args.lambda_dir)
    if not lambda_dir.is_dir():
        print(f"ERROR: {lambda_dir} is not a directory", file=sys.stderr)
        return 1

    violations = scan(lambda_dir)
    if not violations:
        print(f"OK — all jwt-importing Lambda functions declare PyJWT in requirements.txt")
        return 0

    print(f"FAIL — {len(violations)} PyJWT requirement violation(s) found (ENC-LSN-020):\n")
    for v in violations:
        print(f"  [{v['mode']}] {v['function']}: {v['detail']}")
    print(
        "\nEvery Lambda that imports jwt must have PyJWT in its own requirements.txt.\n"
        "Shared-layer PyJWT is not reliable (ABI mismatch risk on layer updates).\n"
        "See ENC-LSN-020 for the full failure mode taxonomy."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
