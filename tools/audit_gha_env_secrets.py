#!/usr/bin/env python3
"""Audit GitHub Actions environment-scoped secrets.

ENC-TSK-E66 / ENC-ISS-244 / ENC-LSN-032.

Validates that every ${{ secrets.X }} reference inside a job with
`environment: production` is declared in tools/deploy-capability/env-production-secrets.json
AND that it is actually scoped to the 'production' environment in GitHub
(per `gh secret list --env production`).

Exits non-zero on drift so CI can block PRs that introduce undeclared or
unscoped secret references (Phase 5 pre-merge guard uses this directly).

Modes:
  --check-declaration   Only compares workflow diff against the manifest.
                        Does not call gh. Safe to run offline.
  --check-scope         Additionally compares the manifest against live
                        `gh secret list --env production` output. Requires
                        gh CLI with repo admin / environment read scope.

Exit codes:
  0  no drift
  1  undeclared secret reference (must append to manifest)
  2  declared secret not actually scoped in GitHub (must `gh secret set
     --env production`)
  3  orphan manifest entry (declared but no workflow references it)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}")


def load_manifest(manifest_path: Path) -> Dict:
    with manifest_path.open() as f:
        return json.load(f)


def scan_workflows(workflows_dir: Path) -> Dict[str, Set[Tuple[str, int]]]:
    """Return {secret_name: {(workflow_path, line_number), ...}} for every
    secret referenced inside a job declaring `environment: production`.
    """
    result: Dict[str, Set[Tuple[str, int]]] = {}
    for yml in sorted(workflows_dir.glob("*.yml")):
        text = yml.read_text()
        lines = text.splitlines()
        env_prod_job_blocks = _find_env_prod_blocks(lines)
        for (start, end) in env_prod_job_blocks:
            for i in range(start, min(end, len(lines))):
                for m in SECRET_REF_RE.finditer(lines[i]):
                    name = m.group(1)
                    result.setdefault(name, set()).add(
                        (str(yml.relative_to(workflows_dir.parents[1])), i + 1)
                    )
    return result


def _find_env_prod_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    """Find (start_index, end_index) of each job declaring environment:
    production. end is exclusive. Uses indentation to scope the block.
    """
    blocks: List[Tuple[int, int]] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped != "environment: production":
            continue
        env_indent = len(line) - len(line.lstrip())
        job_indent = env_indent
        start = idx
        for back in range(idx - 1, -1, -1):
            bl = lines[back]
            if not bl.strip():
                continue
            bi = len(bl) - len(bl.lstrip())
            if bi < env_indent and bl.rstrip().endswith(":"):
                job_indent = bi
                start = back
                break
        end = len(lines)
        for fwd in range(idx + 1, len(lines)):
            fl = lines[fwd]
            if not fl.strip():
                continue
            fi = len(fl) - len(fl.lstrip())
            if fi <= job_indent:
                end = fwd
                break
        blocks.append((start, end))
    return blocks


def gh_env_secrets(env_name: str) -> Set[str]:
    try:
        out = subprocess.check_output(
            ["gh", "secret", "list", "--env", env_name, "--json", "name"],
            text=True,
        )
    except FileNotFoundError:
        print("ERROR: gh CLI not found on PATH", file=sys.stderr)
        raise
    except subprocess.CalledProcessError as exc:
        print(
            f"ERROR: gh secret list --env {env_name} failed: {exc}",
            file=sys.stderr,
        )
        raise
    return {item["name"] for item in json.loads(out)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--manifest",
        default="tools/deploy-capability/env-production-secrets.json",
        help="Path to declared-secrets manifest JSON.",
    )
    ap.add_argument(
        "--workflows",
        default=".github/workflows",
        help="Path to GitHub Actions workflows directory.",
    )
    ap.add_argument(
        "--check-declaration",
        action="store_true",
        default=True,
        help="Compare workflow references against manifest (default).",
    )
    ap.add_argument(
        "--check-scope",
        action="store_true",
        default=False,
        help="Also verify `gh secret list --env production` covers every declared secret.",
    )
    ap.add_argument(
        "--env-name",
        default="production",
        help="GitHub environment name to audit (default: production).",
    )
    args = ap.parse_args()

    manifest = load_manifest(Path(args.manifest))
    declared = {entry["name"] for entry in manifest.get("required_secrets", [])}
    workflow_refs = scan_workflows(Path(args.workflows))

    referenced = set(workflow_refs.keys())

    undeclared = referenced - declared
    orphans = declared - referenced

    print(f"[INFO] {len(referenced)} secret(s) referenced by `environment: {args.env_name}` jobs")
    print(f"[INFO] {len(declared)} secret(s) declared in manifest")

    rc = 0

    if undeclared:
        print(
            f"::error::Undeclared secret(s) in `environment: {args.env_name}` jobs: "
            f"{sorted(undeclared)}. Append to {args.manifest} required_secrets[] "
            f"and scope via `gh secret set --env {args.env_name} <NAME> --body <value>`.",
            file=sys.stderr,
        )
        for name in sorted(undeclared):
            for src in sorted(workflow_refs[name]):
                print(f"  - {name}: referenced at {src[0]}:{src[1]}", file=sys.stderr)
        rc = 1

    if orphans:
        print(
            f"::warning::Orphan manifest entries (declared but unreferenced in workflows): "
            f"{sorted(orphans)}. If no longer needed, remove from {args.manifest}.",
            file=sys.stderr,
        )
        if rc == 0:
            rc = 3

    if args.check_scope:
        gh_scoped = gh_env_secrets(args.env_name)
        missing_scope = declared - gh_scoped
        if missing_scope:
            print(
                f"::error::Declared secret(s) missing from `gh secret list --env "
                f"{args.env_name}`: {sorted(missing_scope)}. Scope via "
                f"`gh secret set --env {args.env_name} <NAME> --body <value>` "
                f"(see ENC-LSN-032).",
                file=sys.stderr,
            )
            rc = 2 if rc == 0 else rc

    if rc == 0:
        print("[OK] All environment-scoped secret references declared and scoped.")

    return rc


if __name__ == "__main__":
    sys.exit(main())
