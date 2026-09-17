#!/usr/bin/env python3
"""ENC-TSK-Q05 AC-2 (ENC-ISS-778 P0): deploy-time architecture guard.

ENC-ISS-778's root cause chain shipped an x86_64-py3.11 mcp_code artifact
onto the arm64-only enceladus-mcp-code Lambda. Every prior defect in that
chain (stale key prefix, dual producers, affected-set scoping) was about
*deciding what to ship*. Nothing in the deploy path ever compared what was
about to be shipped against what the target function actually IS. This
script is that comparison, run as its own step in _deploy.yml's deploy job,
immediately before "Deploy Lambda functions" -- so a mismatch fails the run
BEFORE any `update-function-code` call, not after.

Two inputs, both already resolved by the time the deploy job runs:
  - The artifact's arch/python version, encoded in its resolved S3 key
    prefix as "<arch>-py<pyver>" (see resolve job's KEY_PREFIX /
    MCP_CODE_KEY_PREFIX construction in _deploy.yml).
  - The function's actual arch/runtime, read live via
    `aws lambda get-function-configuration` (Architectures, Runtime).

Design is deliberately FAIL CLOSED. See parse_key_prefix() / evaluate_match()
docstrings for the exact semantics of each failure mode:
  - unparseable prefix                         -> mismatch (fail)
  - Architectures absent or has != 1 entries    -> mismatch (fail)
  - Runtime absent or not a "python..." runtime -> mismatch (fail)
  - get-function-configuration errors           -> mismatch (fail), UNLESS
  - the function does not exist in this environment yet (ResourceNotFound /
    "Function not found") -> SKIP, not a failure. Bootstrapping a new
    environment must not be blocked by a guard for functions that are not
    provisioned there yet -- _deploy.yml's own deploy_one() already treats
    this exact condition as a legitimate skip, not an error.

Two testable layers:
  - Pure core: parse_key_prefix(), evaluate_match() -- no I/O.
  - Thin CLI: main() -- resolves which (short function name, deployed Lambda
    name) pairs this run is actually about to deploy from
    --function-name-map-json + --key-prefixes-json (both already-resolved
    _deploy.yml resolve-job outputs), calls AWS for each, and exits non-zero
    with a report naming every mismatch.

Usage:
    assert_artifact_arch_matches_functions.py \\
        --function-name-map-json '{"mcp_code": "enceladus-mcp-code", ...}' \\
        --key-prefixes-json '{"mcp_code": "lambda-artifacts/arm64-py3.12", ...}' \\
        --region us-west-2

Exit codes: 0 = every deployed function's live config matches its artifact's
arch/runtime (or the function isn't provisioned yet, which is not a
failure). 1 = at least one mismatch or unreadable configuration. 2 = usage
error (bad JSON input).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

# Markers _deploy.yml's own deploy_one() treats as "not provisioned in this
# environment yet" (a legitimate skip, not an error) for
# update-function-code. get-function-configuration raises the same
# ResourceNotFoundException shape for a function that does not exist, so the
# same markers apply here.
_NOT_PROVISIONED_MARKERS = ("ResourceNotFoundException", "Function not found")

_PREFIX_RE = re.compile(r"^(?P<arch>[A-Za-z0-9_]+)-py(?P<py>\d+\.\d+)$")


# ---------------------------------------------------------------------------
# Pure core
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArchCheckResult:
    ok: bool
    reason: str


def parse_key_prefix(prefix: str) -> Tuple[str, str]:
    """Extract (arch, py_version) from the trailing "<arch>-py<pyver>" path
    segment of an S3 key prefix, e.g. "lambda-artifacts/arm64-py3.12" ->
    ("arm64", "3.12"). Raises ValueError if the trailing segment does not
    match that shape -- callers MUST treat that as a fail-closed mismatch,
    never as "no opinion" / pass-through."""
    segment = prefix.rstrip("/").rsplit("/", 1)[-1]
    m = _PREFIX_RE.match(segment)
    if not m:
        raise ValueError(
            f"cannot parse '<arch>-py<pyver>' from key prefix segment {segment!r} "
            f"(full prefix: {prefix!r})"
        )
    return m.group("arch"), m.group("py")


def evaluate_match(
    prefix: str,
    architectures: Optional[Sequence[str]],
    runtime: Optional[str],
) -> ArchCheckResult:
    """Fail-closed comparison of an artifact's resolved S3 key prefix against
    a live function's get-function-configuration Architectures/Runtime.

    Every branch below that is not an exact single-architecture,
    exact-python-version match returns ok=False. In particular: an
    unparseable prefix, a missing/absent Architectures list, a
    multi-architecture Architectures list (Lambda supports at most one in
    practice, but nothing here should assume that silently), and a missing
    or non-python Runtime all fail closed rather than being treated as
    "cannot determine, so pass"."""
    try:
        arch, py = parse_key_prefix(prefix)
    except ValueError as exc:
        return ArchCheckResult(False, f"unparseable artifact key prefix: {exc}")

    if not architectures:
        return ArchCheckResult(
            False, "function configuration is missing Architectures"
        )
    if len(architectures) != 1:
        return ArchCheckResult(
            False,
            f"function configuration has ambiguous Architectures {list(architectures)!r} "
            "(expected exactly 1)",
        )
    fn_arch = architectures[0]

    if not runtime:
        return ArchCheckResult(False, "function configuration is missing Runtime")
    if not runtime.startswith("python"):
        return ArchCheckResult(
            False, f"function configuration Runtime {runtime!r} is not a python runtime"
        )
    fn_py = runtime[len("python"):]

    if fn_arch.lower() != arch.lower():
        return ArchCheckResult(
            False,
            f"artifact arch {arch!r} (from prefix {prefix!r}) != function "
            f"Architectures {fn_arch!r}",
        )
    if fn_py != py:
        return ArchCheckResult(
            False,
            f"artifact python {py!r} (from prefix {prefix!r}) != function "
            f"Runtime python {fn_py!r} ({runtime!r})",
        )

    return ArchCheckResult(True, f"matches ({fn_arch}, python{fn_py})")


def resolve_deploy_targets(
    function_name_map: Dict[str, str], key_prefixes: Dict[str, str]
) -> List[Tuple[str, str, str]]:
    """(short_fn_name, deployed Lambda name, key prefix) for every function
    this run is actually about to deploy -- i.e. every short name present in
    key_prefixes (the set the resolve job actually probed/resolved
    artifacts for this run, narrowed or full-scope) that also has a mapped
    Lambda name. A short name with no mapping is skipped here exactly as
    _deploy.yml's own deploy step skips it (logged there as
    "not in function_name_map")."""
    targets: List[Tuple[str, str, str]] = []
    for fn, prefix in sorted(key_prefixes.items()):
        mapped = (function_name_map.get(fn) or "").strip()
        if not mapped:
            continue
        for mapped_name in (n.strip() for n in mapped.split(",")):
            if mapped_name:
                targets.append((fn, mapped_name, prefix))
    return targets


# ---------------------------------------------------------------------------
# Thin CLI (AWS I/O)
# ---------------------------------------------------------------------------

def _run(cmd: List[str]) -> Tuple[Optional[str], Optional[str]]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001 -- fail closed, report the exception
        return None, f"exception invoking {' '.join(cmd)}: {exc}"
    if result.returncode != 0:
        return None, (result.stderr or "").strip() or f"exit {result.returncode}"
    return result.stdout, None


def get_function_configuration(
    function_name: str, region: str
) -> Tuple[Optional[dict], Optional[str]]:
    out, err = _run(
        [
            "aws", "lambda", "get-function-configuration",
            "--function-name", function_name,
            "--region", region,
            "--output", "json",
        ]
    )
    if out is None:
        return None, err
    try:
        return json.loads(out), None
    except json.JSONDecodeError as exc:
        return None, f"could not parse get-function-configuration JSON: {exc}"


def _is_not_provisioned(err: Optional[str]) -> bool:
    return bool(err) and any(marker in err for marker in _NOT_PROVISIONED_MARKERS)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--function-name-map-json", required=True,
        help="short function name -> deployed Lambda name(s), comma-separated "
        "(same shape as _deploy.yml's FUNCTION_NAME_MAP_JSON).",
    )
    parser.add_argument(
        "--key-prefixes-json", required=True,
        help="short function name -> resolved S3 key prefix for THIS run "
        "(resolve job's key_prefixes_json output).",
    )
    parser.add_argument("--region", default="us-west-2")
    args = parser.parse_args(argv)

    try:
        fn_map = json.loads(args.function_name_map_json)
        key_prefixes = json.loads(args.key_prefixes_json)
    except json.JSONDecodeError as exc:
        print(f"::error::could not parse function-name-map/key-prefixes JSON: {exc}", file=sys.stderr)
        return 2

    targets = resolve_deploy_targets(fn_map, key_prefixes)
    if not targets:
        print("No deploy targets to check (nothing resolved for this run) -- skipping.")
        return 0

    print(f"Checking {len(targets)} deploy target(s) for artifact/function arch+runtime match...")
    mismatches: List[Tuple[str, str, str]] = []
    skipped: List[Tuple[str, str]] = []
    for fn, mapped_name, prefix in targets:
        config, err = get_function_configuration(mapped_name, args.region)
        if config is None:
            if _is_not_provisioned(err):
                print(f"  [skip] {fn} -> {mapped_name}: not provisioned in this environment yet")
                skipped.append((fn, mapped_name))
                continue
            reason = f"could not read function configuration: {err}"
            print(f"::error::{fn} -> {mapped_name}: {reason}", file=sys.stderr)
            mismatches.append((fn, mapped_name, reason))
            continue

        result = evaluate_match(prefix, config.get("Architectures"), config.get("Runtime"))
        if result.ok:
            print(f"  OK {fn} -> {mapped_name}: {result.reason}")
        else:
            print(f"::error::{fn} -> {mapped_name}: {result.reason}", file=sys.stderr)
            mismatches.append((fn, mapped_name, result.reason))

    if mismatches:
        print(
            f"::error::Deploy-time architecture guard FAILED: {len(mismatches)} of "
            f"{len(targets)} deploy target(s) mismatched (ENC-ISS-778 P0 class -- "
            "the exact defect that shipped an x86_64 artifact onto the arm64-only "
            "enceladus-mcp-code Lambda). Mismatches:",
            file=sys.stderr,
        )
        for fn, mapped_name, reason in mismatches:
            print(f"  - {fn} -> {mapped_name}: {reason}", file=sys.stderr)
        return 1

    print(
        f"Deploy-time architecture guard passed: {len(targets) - len(skipped)} checked, "
        f"{len(skipped)} not-yet-provisioned (skipped)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
