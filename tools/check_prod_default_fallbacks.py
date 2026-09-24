#!/usr/bin/env python3
"""Static linter for prod-defaulting env fallbacks (ENC-ISS-640 / ENC-TSK-O42).

Scans backend/lambda and tools/enceladus-mcp-server for the idiom that caused
the ISS-640 SEV2: routing/table/URL configuration read via

    os.environ.get("SOME_TABLE", "prod-resource-name")
    os.getenv("SOME_API_URL", "https://prod-host/...")

where the fallback literal names a PROD resource. On a gamma-deployed Lambda a
single missing env var then silently routes traffic to production (observed
live 2026-08-22: the gamma MCP gateway checkout path executed a governed arc
against PROD devops-project-tracker). A gamma function missing its config
should fail loudly, not degrade to prod.

Flags any environ.get/getenv call where BOTH:
  - the env var NAME looks like plane-scoped wiring
    (TABLE / URL / API / ENDPOINT / BUCKET / QUEUE / SESSIONS / TOKENS /
     REGISTRY / LAYER), and
  - the DEFAULT is a non-empty string literal that is not plane-templated
    (contains no 'gamma', no '{'-style formatting, no env-suffix interpolation).

Exit codes: 0 clean (or --report-only), 1 findings present, 2 usage error.
Usage:
    python3 tools/check_prod_default_fallbacks.py [--root REPO_ROOT] [--report-only]
"""

import argparse
import os
import re
import sys

SCAN_DIRS = ("backend/lambda", "tools/enceladus-mcp-server")

NAME_HINT = re.compile(
    r"(TABLE|_URL|URL_|API|ENDPOINT|BUCKET|QUEUE|SESSIONS|TOKENS|REGISTRY|LAYER)"
)

CALL_RE = re.compile(
    r"os\.(?:environ\.get|getenv)\(\s*"
    r"(?P<q1>['\"])(?P<name>[A-Z][A-Z0-9_]+)(?P=q1)\s*,\s*"
    r"(?P<q2>['\"])(?P<default>[^'\"]*)(?P=q2)",
    re.DOTALL,
)

SKIP_FILE = re.compile(r"(^|/)(test_[^/]+|[^/]+_test)\.py$")


def default_is_plane_safe(default: str) -> bool:
    """True when the fallback cannot silently select the prod plane."""
    if default == "":
        return True  # empty default -> downstream code must handle absence
    if "gamma" in default.lower():
        return True  # explicitly gamma-scoped literal
    if "{" in default or "%s" in default:
        return True  # templated with a suffix at runtime
    return False


def scan_file(path: str, rel: str):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    findings = []
    for m in CALL_RE.finditer(text):
        name, default = m.group("name"), m.group("default")
        if not NAME_HINT.search(name):
            continue
        if default_is_plane_safe(default):
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append((rel, line, name, default))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="repo root (default: cwd)")
    ap.add_argument(
        "--report-only",
        action="store_true",
        help="always exit 0; report findings without failing",
    )
    args = ap.parse_args()

    findings = []
    for scan_dir in SCAN_DIRS:
        base = os.path.join(args.root, scan_dir)
        if not os.path.isdir(base):
            print(f"[warn] missing scan dir: {scan_dir}", file=sys.stderr)
            continue
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in sorted(filenames):
                if not fn.endswith(".py"):
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, args.root)
                if SKIP_FILE.search(rel.replace(os.sep, "/")):
                    continue
                findings.extend(scan_file(full, rel))

    if findings:
        print(f"PROD-DEFAULTING ENV FALLBACKS: {len(findings)}")
        for rel, line, name, default in findings:
            print(f"  {rel}:{line}  {name}  default={default!r}")
        print(
            "\nEach of these silently selects a PROD resource when the env var is"
            " unset on a gamma deployment (ENC-ISS-640 class). Fix by requiring"
            " the var (os.environ[...]) or templating the default with the"
            " environment suffix."
        )
    else:
        print("clean: no prod-defaulting env fallbacks found")

    if args.report_only:
        return 0
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
