#!/usr/bin/env python3
"""Vendor or verify enceladus_shared/content_store.py in migrating Lambda folders (isolation W4, DVP-TSK-A78).

A function moving off s3://jreese-net vendors an identical copy of the canonical helper next to its handler, so
the move ships with that function's own Gen2 build and needs no shared-layer republish or fleet-wide layer pin.

  python3 tools/isolation/sync_content_store.py --add document_api   # vendor into backend/lambda/document_api/
  python3 tools/isolation/sync_content_store.py --check              # CI: every vendored copy == canonical
  (tools/enceladus-mcp-server/content_store.py is a vendored copy too: refresh it with
   cp backend/lambda/shared_layer/python/enceladus_shared/content_store.py tools/enceladus-mcp-server/)
"""

from __future__ import annotations

import argparse
import filecmp
import glob
import os
import shutil
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CANONICAL = os.path.join(ROOT, "backend/lambda/shared_layer/python/enceladus_shared/content_store.py")
LAMBDA_DIR = os.path.join(ROOT, "backend/lambda")


# DVP-TSK-B40: the MCP server vendors a copy next to server.py (it ships to every MCP Lambda root and runs as a local
# stdio server, where neither .build_extras nor the shared layer applies).
MCP_SERVER_COPY = os.path.join(ROOT, "tools", "enceladus-mcp-server", "content_store.py")


def vendored_copies():
    copies = [p for p in glob.glob(os.path.join(LAMBDA_DIR, "*", "content_store.py"))
              if os.sep + "shared_layer" + os.sep not in p]
    if os.path.isfile(MCP_SERVER_COPY):
        copies.append(MCP_SERVER_COPY)
    return sorted(copies)


def check() -> int:
    bad = [p for p in vendored_copies() if not filecmp.cmp(p, CANONICAL, shallow=False)]
    for p in bad:
        print(f"DRIFT: {os.path.relpath(p, ROOT)} differs from the canonical content_store.py; re-run --add")
    print(f"content_store copies: {len(vendored_copies())}, drifted: {len(bad)}")
    return 1 if bad else 0


def add(function_dir: str) -> int:
    dest_dir = os.path.join(LAMBDA_DIR, function_dir)
    if not os.path.isfile(os.path.join(dest_dir, "lambda_function.py")):
        print(f"no lambda_function.py in backend/lambda/{function_dir}")
        return 1
    shutil.copyfile(CANONICAL, os.path.join(dest_dir, "content_store.py"))
    print(f"vendored content_store.py into backend/lambda/{function_dir}/")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--add", metavar="FUNCTION_DIR")
    g.add_argument("--check", action="store_true")
    a = ap.parse_args()
    sys.exit(add(a.add) if a.add else check())
