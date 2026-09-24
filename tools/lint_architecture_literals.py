#!/usr/bin/env python3
"""Lint for stray architecture literals (ENC-TSK-Q19 FR-1 / DOC-5368FE6515ED).

envs/architecture.yaml (loaded by tools/arch_declaration.py) is now the ONE
declaration of arch/runtime/runner per plane. This lint catches a
DECLARATION of the retired x86_64/python3.11 pairing -- or an arch/runtime-
selecting `!If [Is<Anything>, arm64|python3.12, ...]` conditional of any
condition name (IsArm64, IsGamma, or a future one) -- reappearing anywhere
else in the tracked tree, so a hand-edit or copy-paste can't quietly
reintroduce the pre-cutover contract outside the files that are still
allowed to carry it until their own retirement task lands (see
tools/architecture_literal_allowlist.json).

Excluded classes (path pattern -> one-line reason), applied before scanning:
  docs/**, **/*.md               -- prose, not an enforced declaration
  test_*.py, *_test.py, **/tests/**
                                  -- fixtures deliberately construct both the
                                     good and the bad literal forms
  tools/cfn-guard/**              -- cfn-guard rule files must name every
                                     allowed/forbidden literal in their enums
  tools/verify_*.py, tools/ci_selftest_*.py, tools/lint_architecture_literals.py,
  tools/arch_declaration.py       -- validator tools must name the forbidden
                                     value in order to detect it
  infrastructure/lambda-live-inventory-*.json,
  infrastructure/devops_lambda_ownership_snapshot.json,
  backend/lambda/shared_layer/PROVENANCE.json,
  infrastructure/lambda-manifests/*.json
                                  -- generated snapshots of a past live state
                                     (each carries its own generated_at +
                                     parity_status), not read by any deploy
                                     path -- confirmed by grep: only two
                                     lambda_function.py docstrings point at
                                     specific files here by filename in a
                                     comment; nothing json.loads()s the
                                     directory
  backend/lambda/coordination_api/governance_data_dictionary.json
                                  -- documents x86_64/python3.11 as valid
                                     historical enum values, not a live
                                     declaration
  frontend/**, node_modules/**    -- UI code, out of scope for Lambda arch

Files listed in tools/architecture_literal_allowlist.json are SCANNED like
any other file, but a finding there is suppressed (not silenced project-
wide) until the entry's `retired_by` task lands. An entry may set
"vacuous": true (currently only 03-api.yaml) to permit that one file to have
ZERO findings without being treated as stale; every OTHER allowlist entry
must currently have at least one finding, or the allowlist itself has
drifted from reality and the lint fails loudly on that drift rather than
silently trusting a stale exemption.

A finding on any OTHER in-scope, non-allowlisted file is a hard failure --
see this task's own worklog for the two known, deliberately-unresolved
findings on this branch (infrastructure/component_dependency_closure.json's
external AWS-owned layer ARN, and tools/enceladus-mcp-server/server.py's
arch_tag docstring, both of which accurately describe real external/current
state rather than a fixable stray literal).

Usage: python3 tools/lint_architecture_literals.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = REPO_ROOT / "tools" / "architecture_literal_allowlist.json"

FORBIDDEN_SUBSTRINGS = ("x86_64", "python3.11")
# `!If [IsArm64, arm64, x86_64]` / `!If [IsGamma, python3.12, python3.11]` --
# any condition name, arm64/python3.12 as the (previously ABI-selecting) branch.
ARCH_RUNTIME_CONDITIONAL_RE = re.compile(
    r"!If\s*\[\s*Is[A-Za-z0-9]+\s*,\s*(arm64|python3\.12)\b"
)
JSON_ARCH_TAG_RE = re.compile(r"^x86_64(-py\d+)?$")

SCANNED_EXTENSIONS = (
    ".py", ".sh", ".yaml", ".yml", ".json", ".guard", ".txt",
    ".js", ".ts", ".tsx", ".jsx", ".mjs", ".sql", ".cypher",
)

EXCLUDED_DIR_PREFIXES = (
    "docs/",
    "tools/cfn-guard/",
    "frontend/",
    "node_modules/",
)
EXCLUDED_EXACT_FILES = (
    "infrastructure/devops_lambda_ownership_snapshot.json",
    "backend/lambda/shared_layer/PROVENANCE.json",
    "backend/lambda/coordination_api/governance_data_dictionary.json",
)
EXCLUDED_GLOBS = (
    "infrastructure/lambda-live-inventory-*.json",
    "infrastructure/lambda-manifests/*.json",
    "tools/verify_*.py",
    "tools/ci_selftest_*.py",
)
EXCLUDED_TOOL_FILES = (
    "tools/lint_architecture_literals.py",
    "tools/arch_declaration.py",
)


@dataclass
class Finding:
    path: str
    line: Optional[int]
    text: str


def _is_test_file(rel_path: str) -> bool:
    name = Path(rel_path).name
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith("_test.py"):
        return True
    if f"/{rel_path}".find("/tests/") != -1:
        return True
    return False


def _is_excluded(rel_path: str) -> bool:
    if rel_path.endswith(".md"):
        return True
    if any(rel_path.startswith(prefix) for prefix in EXCLUDED_DIR_PREFIXES):
        return True
    if rel_path in EXCLUDED_EXACT_FILES or rel_path in EXCLUDED_TOOL_FILES:
        return True
    if _is_test_file(rel_path):
        return True
    for pattern in EXCLUDED_GLOBS:
        if Path(rel_path).match(pattern):
            return True
    return False


def _tracked_files() -> List[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [line for line in result.stdout.splitlines() if line]


def _strip_comment(line: str) -> str:
    """Strip a trailing `#` comment, quote-aware. Covers YAML/workflow/
    shell/python `#` comments; a `#` inside a quoted string is left alone.
    Languages that don't use `#` for comments (JS/TS/SQL/...) are unaffected
    unless they happen to contain a literal unquoted `#`, which is rare and
    conservative (fewer false positives, not silent false negatives -- the
    forbidden substrings this lint looks for never legitimately follow a
    `#` in those files either)."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def _scan_text_file(path: Path, rel_path: str) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    findings: List[Finding] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(raw_line)
        if not stripped.strip():
            continue
        hits = [s for s in FORBIDDEN_SUBSTRINGS if s in stripped]
        if ARCH_RUNTIME_CONDITIONAL_RE.search(stripped):
            hits.append("arch-runtime-!If")
        if hits:
            findings.append(
                Finding(rel_path, lineno, f"{stripped.strip()!r} ({', '.join(hits)})")
            )
    return findings


def _walk_json(node, path_str: str, rel_path: str, findings: List[Finding]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "x86_64" and isinstance(value, list) and len(value) > 0:
                findings.append(
                    Finding(
                        rel_path, None,
                        f"key 'x86_64' at {path_str}.{key} is a non-empty list "
                        f"({len(value)} entries)",
                    )
                )
            _walk_json(value, f"{path_str}.{key}", rel_path, findings)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_json(item, f"{path_str}[{i}]", rel_path, findings)
    elif isinstance(node, str):
        if " " in node:
            return  # prose, not a declaration
        if node in ("x86_64", "python3.11") or JSON_ARCH_TAG_RE.match(node):
            findings.append(Finding(rel_path, None, f"string value {node!r} at {path_str}"))


def _scan_json_file(path: Path, rel_path: str) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    findings: List[Finding] = []
    _walk_json(data, "$", rel_path, findings)
    return findings


def scan_file(rel_path: str) -> List[Finding]:
    path = REPO_ROOT / rel_path
    if not path.is_file():
        return []
    if rel_path.endswith(".json"):
        return _scan_json_file(path, rel_path)
    return _scan_text_file(path, rel_path)


def load_allowlist() -> list:
    return json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))


def run_lint(tracked_files: Optional[List[str]] = None) -> tuple[List[str], int, int]:
    """Returns (errors, scanned_count, allowlisted_count)."""
    allowlist = load_allowlist()
    allowlist_by_path: Dict[str, dict] = {entry["path"]: entry for entry in allowlist}

    tracked = tracked_files if tracked_files is not None else _tracked_files()
    scanned = 0
    findings_by_path: Dict[str, List[Finding]] = {}

    for rel_path in tracked:
        is_allowlisted = rel_path in allowlist_by_path
        if not is_allowlisted:
            if _is_excluded(rel_path):
                continue
            if not rel_path.endswith(SCANNED_EXTENSIONS):
                continue
        scanned += 1
        findings = scan_file(rel_path)
        if findings:
            findings_by_path[rel_path] = findings

    errors: List[str] = []

    for entry in allowlist:
        path = entry["path"]
        if entry.get("vacuous"):
            continue
        if path not in findings_by_path:
            errors.append(
                f"allowlist entry {path!r} (retired_by {entry.get('retired_by')}) has "
                f"ZERO findings -- it is stale (already retired, or never had a "
                f"finding) and must be removed, or marked \"vacuous\": true if a "
                f"file legitimately references the condition without a literal"
            )

    for rel_path, findings in findings_by_path.items():
        if rel_path in allowlist_by_path:
            continue
        errors.append(f"{rel_path}: {len(findings)} architecture-literal finding(s):")
        for finding in findings[:5]:
            loc = f"line {finding.line}" if finding.line else "(json)"
            errors.append(f"    {loc}: {finding.text}")

    return errors, scanned, len(allowlist)


def main() -> int:
    errors, scanned, allowlisted = run_lint()

    if errors:
        print("[ERROR] architecture-literal lint FAILED:")
        for err in errors:
            print(f"  {err}")
        return 1

    print(f"architecture-literal lint: OK ({scanned} files scanned, {allowlisted} allowlisted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
