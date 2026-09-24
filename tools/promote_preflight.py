#!/usr/bin/env python3
"""ENC-TSK-Q21 FR-8: v3-prod promote preflight (DOC-5368FE6515ED).

"Promote is a merge": a v3-prod deploy dispatch must target a commit that is
an ancestor-or-equal of origin/main (the promote PR actually merged), and if
a gamma_sha is supplied (the v4/main head the promote PR was cut from), that
gamma commit must be an ancestor-or-equal of commit_sha AND the diff between
gamma_sha and commit_sha must not touch any deployable path. A promote merge
is expected to ship exactly the code gamma already validated (plus
non-runtime housekeeping like the merge commit itself, docs, or governance
files) -- never a vehicle for smuggling unvalidated runtime changes past the
gamma validation gate and the reviewer-approved dispatch.

Invoked from _deploy.yml's promote_preflight job for every workflow_dispatch
/ workflow_call whose target_environment == v3-prod. Stdlib only; shells out
to `git`. Exits non-zero with a `::error::`-prefixed message (parseable by
both a human and the Actions UI) on any violation; exits 0 on success.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import List, Optional

# ENC-TSK-Q21 FR-8: mirrors the deployable-path set _deploy.yml/resolve
# treats as ship-affecting (backend Lambdas, the UI, env manifests,
# CloudFormation, and the MCP server tool). Any change under one of these
# prefixes between gamma_sha and commit_sha means the promote is carrying
# more than gamma already validated.
DEPLOYABLE_PATH_PREFIXES = (
    "backend/",
    "frontend/",
    "envs/",
    "infrastructure/",
    "tools/enceladus-mcp-server/",
)


def run_git(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def is_ancestor(ancestor: str, descendant: str) -> bool:
    """True if `ancestor` is an ancestor of, or equal to, `descendant`."""
    if ancestor == descendant:
        return True
    result = run_git(["merge-base", "--is-ancestor", ancestor, descendant])
    if result.returncode in (0, 1):
        return result.returncode == 0
    raise RuntimeError(
        f"git merge-base --is-ancestor {ancestor} {descendant} errored "
        f"(exit {result.returncode}): {result.stderr.strip()}"
    )


def changed_deployable_paths(a: str, b: str) -> List[str]:
    result = run_git(["diff", "--name-only", a, b])
    if result.returncode != 0:
        raise RuntimeError(
            f"git diff --name-only {a} {b} failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    paths = [p for p in result.stdout.splitlines() if p]
    return [p for p in paths if p.startswith(DEPLOYABLE_PATH_PREFIXES)]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit-sha", required=True, help="the SHA being deployed to v3-prod")
    parser.add_argument(
        "--gamma-sha", default="",
        help="the v4/main head_sha the promote PR was cut from (optional)",
    )
    parser.add_argument(
        "--main-ref", default="origin/main",
        help="ref the commit_sha must be an ancestor-or-equal of (default: origin/main)",
    )
    args = parser.parse_args(argv)

    commit_sha = (args.commit_sha or "").strip()
    gamma_sha = (args.gamma_sha or "").strip()
    main_ref = args.main_ref

    if not commit_sha:
        print("::error::ENC-TSK-Q21 FR-8 ancestry: --commit-sha is required and was empty.")
        return 1

    try:
        commit_is_ancestor = is_ancestor(commit_sha, main_ref)
    except RuntimeError as exc:
        print(f"::error::ENC-TSK-Q21 FR-8 ancestry: {exc}")
        return 1

    if not commit_is_ancestor:
        print(
            f"::error::ENC-TSK-Q21 FR-8 ancestry: commit_sha {commit_sha} is not an "
            f"ancestor-or-equal of {main_ref} -- a v3-prod deploy must target a commit "
            f"that has actually landed on main via the promote PR merge, not an "
            f"arbitrary/hand-crafted dispatch."
        )
        return 1
    print(f"OK: commit_sha {commit_sha} is an ancestor-or-equal of {main_ref}.")

    if gamma_sha:
        try:
            gamma_is_ancestor = is_ancestor(gamma_sha, commit_sha)
        except RuntimeError as exc:
            print(f"::error::ENC-TSK-Q21 FR-8 ancestry: {exc}")
            return 1

        if not gamma_is_ancestor:
            print(
                f"::error::ENC-TSK-Q21 FR-8 ancestry: gamma_sha {gamma_sha} is not an "
                f"ancestor-or-equal of commit_sha {commit_sha} -- the promote PR's base "
                f"must be the gamma commit it claims to promote."
            )
            return 1
        print(f"OK: gamma_sha {gamma_sha} is an ancestor-or-equal of commit_sha {commit_sha}.")

        try:
            offending = changed_deployable_paths(gamma_sha, commit_sha)
        except RuntimeError as exc:
            print(f"::error::ENC-TSK-Q21 FR-8 ancestry: {exc}")
            return 1

        if offending:
            offending_list = "\n  ".join(offending)
            print(
                "::error::ENC-TSK-Q21 FR-8 ancestry: the promote merge from gamma_sha "
                f"{gamma_sha} to commit_sha {commit_sha} touches deployable path(s) -- a "
                "promote must ship exactly the code gamma already validated, not new "
                "runtime changes. Offending paths:\n  " + offending_list
            )
            return 1
        print(
            f"OK: no deployable-path changes between gamma_sha {gamma_sha} and "
            f"commit_sha {commit_sha}."
        )
    else:
        print("gamma_sha not supplied -- skipping gamma-ancestry and deployable-delta checks.")

    print("PASS: v3-prod promote preflight.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
