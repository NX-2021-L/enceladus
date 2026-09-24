#!/usr/bin/env python3
"""Every manifest Lambda must be mapped for the environment, or declared excluded.

WHY (ENC-ISS-663 / ENC-TSK-P03, diagnosis DOC-F3585A1827EF)
-----------------------------------------------------------------------------
`envs/<env>.yaml` carries a `function_name_map` from source directory to the
deployed function name. `_deploy.yml` SILENTLY SKIPS any function absent from
it:

    [skip] governance_mart  (not in function_name_map)

Meanwhile `02-compute.yaml` still creates the function, carrying the
placeholder body that only deploy.sh replaces. The result is a function that
exists, reports arm64/python3.12/UPDATE_COMPLETE, and returns
Runtime.ImportModuleError on every invocation -- with a GREEN deploy.

THIS HAS ALREADY HAPPENED TWICE.
  - ENC-TSK-K56: the AppSync FeedPublisher was missing from the map, was
    silently skipped, and kept its CFN placeholder code.
  - 2026-08-23: convergence_telemetry, escalation_decision_authorizer and
    governance_mart, all three dead for 90 minutes.

After the first occurrence the remedy was a COMMENT in envs/v4-gamma.yaml
asking a human to "keep this map in lockstep with lambda_workflow_manifest."
The knowledge existed and was enforced nowhere, so it recurred. This script is
that comment, executed.

THE DISTINCTION IT ENFORCES: an OMISSION must not be able to masquerade as a
DECISION. A function may legitimately not exist in an environment -- but then
it belongs in `function_name_map_exclusions` with a reason, where it is a
declaration someone made rather than a line nobody wrote.

SCOPE: v4-gamma only, deliberately. v3-prod currently has 23 unmapped
functions; whether that reflects a smaller prod fleet or the same silent-skip
defect is UNKNOWN and needs its own investigation. Enforcing prod blind would
either fail 23 times on day one or be waived into uselessness -- and a guard
that cries wolf gets switched off, which is how the real finding gets lost.
Widen this only after that question is answered on evidence.

USAGE
-----------------------------------------------------------------------------
    python3 tools/assert_function_name_map_lockstep.py            # v4-gamma
    python3 tools/assert_function_name_map_lockstep.py --env v4-gamma
    python3 tools/assert_function_name_map_lockstep.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "infrastructure" / "lambda_workflow_manifest.json"

ENFORCED_ENVS = ("v4-gamma",)


def manifest_dirs(manifest_path: Path = MANIFEST) -> Set[str]:
    data = json.loads(manifest_path.read_text())
    return {f["lambda_dir"].rstrip("/").split("/")[-1] for f in data["functions"]}


def evaluate(dirs: Set[str], mapped: Set[str], excluded: Set[str]) -> Tuple[List[str], List[str]]:
    """Returns (missing, stale_exclusions).

    missing            -- in the manifest, neither mapped nor excluded. FAILS.
    stale_exclusions   -- excluded but no longer in the manifest, or excluded
                          AND mapped. Reported so the declaration cannot rot
                          into a lie; treated as a failure too, because a
                          contradictory declaration is worse than none.
    """
    missing = sorted(dirs - mapped - excluded)
    stale = sorted((excluded - dirs) | (excluded & mapped))
    return missing, stale


def load_env(env: str) -> Tuple[Set[str], Set[str]]:
    import yaml  # noqa: PLC0415 - only needed for the live path

    data = yaml.safe_load((REPO_ROOT / "envs" / f"{env}.yaml").read_text())
    return (set((data.get("function_name_map") or {}).keys()),
            set((data.get("function_name_map_exclusions") or {}).keys()))


def _self_test() -> int:
    cases = [
        ("fully mapped passes", ({"a", "b"}, {"a", "b"}, set()), ([], [])),
        ("declared exclusion passes", ({"a", "b"}, {"a"}, {"b"}), ([], [])),
        ("silent omission FAILS -- the ENC-ISS-663 case",
         ({"a", "governance_mart"}, {"a"}, set()), (["governance_mart"], [])),
        ("exclusion for a function no longer in the manifest is stale",
         ({"a"}, {"a"}, {"gone"}), ([], ["gone"])),
        ("excluded AND mapped is contradictory, reported",
         ({"a"}, {"a"}, {"a"}), ([], ["a"])),
    ]
    failed = 0
    for label, (dirs, mapped, excl), expected in cases:
        got = evaluate(dirs, mapped, excl)
        ok = got == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            print(f"        expected {expected}, got {got}")
            failed += 1
    print(f"\n{len(cases) - failed}/{len(cases)} self-tests passed")
    return 1 if failed else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", action="append", default=[],
                   help=f"Environment to check. Default: {', '.join(ENFORCED_ENVS)}")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    if args.self_test:
        return _self_test()

    envs = args.env or list(ENFORCED_ENVS)
    dirs = manifest_dirs()
    rc = 0
    for env in envs:
        mapped, excluded = load_env(env)
        missing, stale = evaluate(dirs, mapped, excluded)
        print(f"{env}: manifest={len(dirs)} mapped={len(mapped)} excluded={len(excluded)} "
              f"missing={len(missing)} stale={len(stale)}")
        for m in missing:
            print(f"::error title=Unmapped Lambda::{env}: '{m}' is in "
                  f"lambda_workflow_manifest.json but has no function_name_map entry. "
                  f"_deploy.yml will SILENTLY SKIP it while CloudFormation still creates "
                  f"it, leaving it on the placeholder body (ENC-ISS-663). Add a mapping, "
                  f"or declare it in function_name_map_exclusions with a reason.",
                  file=sys.stderr)
            rc = 1
        for s in stale:
            print(f"::error title=Stale exclusion::{env}: '{s}' is declared in "
                  f"function_name_map_exclusions but is either absent from the manifest "
                  f"or also mapped. A declaration that contradicts reality is worse than "
                  f"none -- remove it or fix the mapping.", file=sys.stderr)
            rc = 1
        if not missing and not stale:
            print(f"  OK: every manifest function is mapped or explicitly excluded.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
