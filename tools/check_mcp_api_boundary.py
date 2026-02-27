#!/usr/bin/env python3
"""Hard governance gate: MCP tool handlers must not bypass service APIs for DynamoDB.

This guard enforces that async MCP tool handlers in tools/enceladus-mcp-server/server.py
do not directly call DynamoDB clients/helpers. Tool handlers must route through
service APIs so auth/governance behavior is consistent across transports.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from typing import List


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_PATH = REPO_ROOT / "tools" / "enceladus-mcp-server" / "server.py"


def _call_name(node: ast.Call) -> str:
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def main() -> int:
    src = SERVER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(SERVER_PATH))
    lines = src.splitlines()

    violations: List[str] = []
    for node in tree.body:
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = _call_name(child)
            # Direct DynamoDB access inside async tool handlers is disallowed.
            if call_name in {"_get_ddb", "scan", "query", "get_item", "put_item", "update_item", "delete_item"}:
                lineno = getattr(child, "lineno", node.lineno)
                code_line = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                violations.append(
                    f"{SERVER_PATH}:{lineno} async {node.name} uses DynamoDB call '{call_name}': {code_line}"
                )

    if violations:
        print("[ERROR] MCP API boundary violation(s) detected:")
        for v in violations:
            print(f"  - {v}")
        print(
            "[ERROR] Async MCP tool handlers must call service APIs instead of accessing DynamoDB directly."
        )
        return 1

    print("[OK] MCP API boundary guard passed (no async tool DynamoDB bypass found).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
