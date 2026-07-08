#!/usr/bin/env python3
"""ENC-ISS-519 assertion: prove the deploy actually shipped.

resolve_last_deployed_sha() / compute_affected_targets.py (candidates 2+3)
harden the *decision* of what to diff and deploy. This tool is the backstop
that catches ANY other way a "0 Lambda updates" false-green could happen
(a future regression, a different discriminator bypass, a bad function_name_map
entry, etc.): after _deploy.yml's "Deploy Lambda functions" step reports
success, assert that every function this run claims to have touched actually
has a CONFIGURATION LastModified timestamp at or after the merge commit's
timestamp. If a claimed-deployed function's code is actually still stale,
fail the run loudly instead of leaving a silent, undetected no-op behind a
green check (the exact ENC-ISS-519 failure mode, reproduced live in run
28919007760 / PR #958).

Two pure, unit-testable pieces (no live AWS/git calls):
  - resolve_target_functions(): affected_functions_json + function_name_map_json
    -> the flat list of actual Lambda function names this run should have touched.
  - is_fresh(): compare a function's LastModified string to the merge commit
    timestamp string.

main() wires those to `git show` (merge commit timestamp) and
`aws lambda get-function-configuration` (LastModified) and fails loudly
(exit 1, ::error::) on any stale or unreadable function.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]


def resolve_target_functions(
    full_scope: bool,
    affected_functions: List[str],
    function_name_map: Dict[str, str],
    all_lambda_dirs: Optional[List[str]] = None,
) -> List[str]:
    """Flatten (dir -> mapped Lambda name(s), comma-separated per ENC-ISS-398)
    into the list of real Lambda function names this deploy should have
    touched. Dirs absent from the map are skipped -- _deploy.yml's own deploy
    step silently skips them too (see 'not in function_name_map' logs), so
    asserting freshness on them would be asserting something the deploy step
    never claimed to do."""
    dirs = list(all_lambda_dirs or []) if full_scope else list(affected_functions)
    targets: List[str] = []
    for d in dirs:
        mapped = (function_name_map.get(d) or "").strip()
        if not mapped:
            continue
        targets.extend(name.strip() for name in mapped.split(",") if name.strip())
    return sorted(set(targets))


def _parse_ts(value: str) -> datetime:
    v = value.strip()
    # AWS Lambda LastModified: "2026-07-08T06:10:00.000+0000" (no colon in tz offset).
    if len(v) >= 5 and v[-5] in "+-" and v[-3] != ":":
        v = f"{v[:-2]}:{v[-2:]}"
    return datetime.fromisoformat(v)


def is_fresh(last_modified: str, merge_commit_ts: str) -> bool:
    """True iff the function's LastModified is at/after the merge commit's
    timestamp -- proof this function's code was actually touched by (or
    after) the commit being deployed, not left stale by a silent skip."""
    lm = _parse_ts(last_modified)
    merge = _parse_ts(merge_commit_ts)
    if lm.tzinfo is None:
        lm = lm.replace(tzinfo=timezone.utc)
    if merge.tzinfo is None:
        merge = merge.replace(tzinfo=timezone.utc)
    return lm >= merge


def _run(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def merge_commit_timestamp(sha: str) -> Optional[str]:
    out = _run(["git", "show", "-s", "--format=%cI", sha])
    if out is None:
        return None
    return out.strip()


def function_last_modified(function_name: str, region: str) -> Optional[str]:
    out = _run([
        "aws", "lambda", "get-function-configuration",
        "--function-name", function_name,
        "--region", region,
        "--query", "LastModified",
        "--output", "text",
    ])
    if out is None:
        return None
    out = out.strip()
    return out or None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--full-scope", required=True, choices=["true", "false"])
    parser.add_argument("--affected-functions-json", default="[]")
    parser.add_argument("--function-name-map-json", default="{}")
    parser.add_argument("--region", default="us-west-2")
    args = parser.parse_args()

    merge_ts = merge_commit_timestamp(args.commit_sha)
    if not merge_ts:
        print(f"::error::could not resolve commit timestamp for {args.commit_sha} -- "
              f"cannot verify post-deploy freshness", file=sys.stderr)
        return 1

    try:
        affected = json.loads(args.affected_functions_json)
        fn_map = json.loads(args.function_name_map_json)
    except json.JSONDecodeError as exc:
        print(f"::error::could not parse affected-functions/function-name-map JSON: {exc}", file=sys.stderr)
        return 1

    all_dirs = None
    if args.full_scope == "true":
        all_dirs = sorted(
            p.parent.name for p in (REPO_ROOT / "backend" / "lambda").glob("*/lambda_function.py")
        )

    targets = resolve_target_functions(args.full_scope == "true", affected, fn_map, all_dirs)
    if not targets:
        print("No mapped target functions to verify (nothing claimed to deploy) -- skipping.")
        return 0

    print(f"Verifying {len(targets)} function(s) have LastModified >= {merge_ts} (commit {args.commit_sha[:7]})")
    stale = []
    unreadable = []
    for name in targets:
        lm = function_last_modified(name, args.region)
        if lm is None:
            unreadable.append(name)
            print(f"::error::{name}: could not read LastModified via get-function-configuration", file=sys.stderr)
            continue
        if is_fresh(lm, merge_ts):
            print(f"  OK {name}: LastModified={lm}")
        else:
            stale.append((name, lm))
            print(f"::error::{name}: LastModified={lm} is BEFORE merge commit timestamp {merge_ts} "
                  f"-- this function was NOT actually updated by this deploy (ENC-ISS-519 silent-skip class)", file=sys.stderr)

    if stale or unreadable:
        print(f"::error::Post-deploy freshness assertion FAILED: {len(stale)} stale, {len(unreadable)} unreadable "
              f"out of {len(targets)} target function(s). This run must not be treated as a successful deploy.", file=sys.stderr)
        return 1

    print(f"Post-deploy freshness assertion passed for all {len(targets)} function(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
