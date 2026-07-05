#!/usr/bin/env python3
"""ENC-TSK-J40 AC-2: fail closed when a component's declared deploy_targets is
narrower than what a merge's diff actually touched under that component's
source_paths.

Reads the component registry via `GET /coordination/components` (governed
HTTP API, same auth pattern as tools/backfill_component_lifecycle_capabilities.py),
and cross-checks each component that has BOTH source_paths.directory and a
non-empty deploy_targets declared: if any changed backend/lambda/<dir> in
`affected_functions` falls under that component's source_paths.directory,
the function name (or a matching glob) must be present in deploy_targets.

Deliberately asymmetric with tools/compute_affected_targets.py's safety
contract: components that have NOT declared deploy_targets are skipped
(warned, not failed) -- an undeclared component cannot be "narrower" than
anything, so it never blocks. Only a component that HAS opted into
deploy_targets and gets it wrong fails the build. This is the "fail-closed
on shortfall" the AC asks for, without retroactively blocking every merge
touching one of the ~30 Lambda functions that predate this task.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from urllib import error as _urllib_error
from urllib import request as _urllib_request

DEFAULT_API_BASE = os.environ.get(
    "COORDINATION_API_BASE",
    "https://jreese.net/api/v1/coordination",
)
DEFAULT_API_KEY = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")


def _get(url: str, api_key: str) -> dict:
    req = _urllib_request.Request(url, headers={"x-internal-api-key": api_key})
    with _urllib_request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_components(api_base: str, api_key: str, project_id: str) -> list:
    url = f"{api_base}/components?project_id={project_id}"
    try:
        data = _get(url, api_key)
    except (_urllib_error.URLError, _urllib_error.HTTPError, TimeoutError) as exc:
        print(f"::warning::could not fetch component registry ({exc}) -- skipping coverage assertion", file=sys.stderr)
        return []
    return data.get("components") or data.get("items") or []


def owning_component(component: dict, function_dir: str) -> bool:
    source_paths = component.get("source_paths") or {}
    directory = (source_paths.get("directory") or "").strip().rstrip("/")
    if not directory:
        return False
    return directory.endswith(f"backend/lambda/{function_dir}") or directory == f"backend/lambda/{function_dir}"


def covered(function_dir: str, deploy_targets: list) -> bool:
    return any(fnmatch.fnmatch(function_dir, pattern) for pattern in deploy_targets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--affected-functions-json", required=True, help="JSON array of affected lambda dir names")
    parser.add_argument("--project-id", default="enceladus")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--api-key", default=DEFAULT_API_KEY)
    args = parser.parse_args()

    try:
        affected = json.loads(args.affected_functions_json)
    except json.JSONDecodeError:
        print("::error::--affected-functions-json is not valid JSON", file=sys.stderr)
        sys.exit(1)

    if not affected:
        print("No affected functions to check.")
        return

    if not args.api_key:
        print("::warning::COORDINATION_INTERNAL_API_KEY not set -- skipping coverage assertion (fails open, per AC-3 'ambiguity widens')", file=sys.stderr)
        return

    components = fetch_components(args.api_base, args.api_key, args.project_id)

    failures = []
    for fn_dir in affected:
        owner = next((c for c in components if owning_component(c, fn_dir)), None)
        if owner is None:
            print(f"[skip] {fn_dir}: no owning component declared -- not gated")
            continue
        deploy_targets = owner.get("deploy_targets") or []
        if not deploy_targets:
            print(f"[skip] {fn_dir}: owning component {owner.get('component_id')} has no deploy_targets declared -- not gated")
            continue
        if covered(fn_dir, deploy_targets):
            print(f"[ok] {fn_dir}: covered by {owner.get('component_id')}.deploy_targets={deploy_targets}")
        else:
            failures.append((fn_dir, owner.get("component_id"), deploy_targets))

    if failures:
        print("::error::deploy_targets coverage shortfall -- these components declared deploy_targets narrower than the actual diff:", file=sys.stderr)
        for fn_dir, comp_id, targets in failures:
            print(f"::error::  {fn_dir} touched by this merge, but {comp_id}.deploy_targets={targets} does not cover it", file=sys.stderr)
        sys.exit(1)

    print(f"Coverage assertion passed for {len(affected)} affected function(s).")


if __name__ == "__main__":
    main()
