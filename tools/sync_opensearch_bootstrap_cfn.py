#!/usr/bin/env python3
"""Keep 10-opensearch-node.yaml UserData bootstrap base64 in sync with bootstrap-node.sh."""

from __future__ import annotations

import argparse
import base64
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "infrastructure/opensearch/bootstrap-node.sh"
TEMPLATE = REPO_ROOT / "infrastructure/cloudformation/10-opensearch-node.yaml"
B64_KEY = "BootstrapScriptB64"


def _read_b64(script: Path) -> str:
    return base64.b64encode(script.read_bytes()).decode("ascii")


def _replace_b64(template_text: str, b64: str) -> str:
    pattern = rf'({B64_KEY}: ")([A-Za-z0-9+/=]+)(")'
    if not re.search(pattern, template_text):
        raise RuntimeError(f"Could not find {B64_KEY} string in {TEMPLATE}")
    return re.sub(pattern, rf"\1{b64}\3", template_text, count=1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when template embed is stale vs bootstrap-node.sh",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite 10-opensearch-node.yaml embedded base64",
    )
    args = parser.parse_args()

    if not SCRIPT.is_file() or not TEMPLATE.is_file():
        print("Missing bootstrap script or CFN template", file=sys.stderr)
        return 2

    expected = _read_b64(SCRIPT)
    current_match = re.search(rf'{B64_KEY}: "([A-Za-z0-9+/=]+)"', TEMPLATE.read_text())
    current = current_match.group(1) if current_match else ""

    if expected == current:
        print("[OK] bootstrap-node.sh is synced into 10-opensearch-node.yaml")
        return 0

    if args.check:
        print(
            "[ERROR] bootstrap-node.sh changed but 10-opensearch-node.yaml UserData base64 is stale. "
            "Run: python3 tools/sync_opensearch_bootstrap_cfn.py --write",
            file=sys.stderr,
        )
        return 1

    if args.write:
        updated = _replace_b64(TEMPLATE.read_text(), expected)
        TEMPLATE.write_text(updated)
        print(f"[OK] Updated embedded base64 in {TEMPLATE}")
        return 0

    print("[WARN] bootstrap embed is stale (pass --check or --write)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
