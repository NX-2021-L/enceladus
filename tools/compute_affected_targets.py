#!/usr/bin/env python3
"""ENC-TSK-J40: compute the affected-set of Lambda functions for a deploy.

Diffs the merge being deployed against the last successfully-deployed SHA for
the target environment (via the GitHub Deployments API, the existing deploy-
state store per _deploy.yml's AC-2), and maps changed files to affected
Lambda function directories under backend/lambda/.

Safety contract (AC-3, "ambiguity widens, never narrows"):
  - Any failure to resolve a base SHA, run git diff, or parse output ->
    full_scope=true (deploy everything, current behavior).
  - Any changed path matching a cross-cutting pattern (shared layer source,
    04-github-roles.yaml IAM, envs/*.yaml CFN parameter files, the deploy
    workflow files themselves, or the build manifest) -> full_scope=true.
  - Otherwise: affected_functions = the set of backend/lambda/<dir> whose
    directory appears in the diff. Empty diff-under-backend/lambda with no
    cross-cutting hit -> affected_functions=[] (a real no-op deploy, e.g. a
    docs-only merge) -- callers must treat this as "skip", not "deploy none
    of everything" (distinct from full_scope).

Output: a single JSON object on stdout, and (if GITHUB_OUTPUT is set) the
same fields written as step outputs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]

# AC-3: any changed path matching one of these forces full_scope=True.
CROSS_CUTTING_PATTERNS = [
    re.compile(r"^backend/lambda/shared_layer/"),
    re.compile(r"^infrastructure/cloudformation/04-github-roles\.yaml$"),
    re.compile(r"^envs/.*\.yaml$"),
    re.compile(r"^\.github/workflows/_build\.yml$"),
    re.compile(r"^\.github/workflows/_deploy\.yml$"),
    re.compile(r"^infrastructure/lambda_workflow_manifest\.json$"),
]

LAMBDA_DIR_RE = re.compile(r"^backend/lambda/([^/]+)/")

# ENC-ISS-519: discriminator for GitHub Deployment records that actually came
# from THIS workflow's own Lambda code-deploy (see the "Create GitHub
# Deployment" step in _deploy.yml). The CFN stack-deploy workflows
# (cloudformation-api-stack-deploy.yml, cloudformation-compute-stack-deploy.yml)
# declare `environment: v4-gamma` on their `apply` job, which makes GitHub
# Actions itself auto-create a Deployment + success status for that same
# environment/sha -- racing ahead of _deploy.yml's own deployment record for
# the identical commit. Those GitHub-managed deployments default `task` to
# "deploy" and carry no marker. Treating ANY success status on ANY deployment
# for the environment as "already deployed" let the CFN race masquerade as a
# real Lambda deploy: base_sha == head_sha, 0 Lambda updates, green run,
# nothing shipped (reproduced live, run 28919007760 / PR #958). A deployment
# record is only trustworthy evidence of a real Lambda deploy if it carries
# this exact task.
LAMBDA_CODE_DEPLOY_TASK = "lambda-artifacts"


def _run(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def resolve_last_deployed_sha(environment: str, repo: str) -> Optional[str]:
    """Last successful GitHub Deployment SHA for `environment`, via `gh api`.
    Returns None on any failure -- caller must treat that as "can't diff,
    go full_scope", never as "nothing changed"."""
    out = _run([
        "gh", "api",
        f"/repos/{repo}/deployments?environment={environment}&per_page=30",
    ])
    if out is None:
        return None
    try:
        deployments = json.loads(out)
    except json.JSONDecodeError:
        return None
    for dep in deployments:
        dep_id = dep.get("id")
        if dep_id is None:
            continue
        # ENC-ISS-519 (candidates 2+3): a deployment record is only usable as
        # "last deployed sha" evidence if it is THIS workflow's own Lambda
        # code-deploy. Any other deployment for the same environment/sha
        # (e.g. a CFN stack-apply's auto-created Deployment) is skipped
        # entirely -- it is never used to short-circuit base_sha == head_sha,
        # and never returned as a base sha. This both discriminates the
        # record (candidate 2) and hardens the same-sha short-circuit
        # (candidate 3): fail-open by falling through to the next matching
        # deployment, or to full_scope=True if none match.
        if dep.get("task") != LAMBDA_CODE_DEPLOY_TASK:
            continue
        statuses_out = _run([
            "gh", "api", f"/repos/{repo}/deployments/{dep_id}/statuses?per_page=10",
        ])
        if statuses_out is None:
            continue
        try:
            statuses = json.loads(statuses_out)
        except json.JSONDecodeError:
            continue
        if any(s.get("state") == "success" for s in statuses):
            sha = dep.get("sha")
            if sha:
                return sha
    return None


def diff_changed_files(base_sha: str, head_sha: str) -> Optional[List[str]]:
    out = _run(["git", "diff", "--name-only", f"{base_sha}..{head_sha}"])
    if out is None:
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def compute(environment: str, repo: str, head_sha: str, base_sha_override: Optional[str] = None) -> dict:
    base_sha = base_sha_override or resolve_last_deployed_sha(environment, repo)
    if not base_sha:
        return {
            "full_scope": True,
            "reason": "no prior successful deployment found for this environment (or GH API call failed) -- deploying everything",
            "base_sha": None,
            "head_sha": head_sha,
            "affected_functions": [],
        }

    if base_sha == head_sha:
        return {
            "full_scope": False,
            "reason": "base_sha == head_sha, nothing to diff",
            "base_sha": base_sha,
            "head_sha": head_sha,
            "affected_functions": [],
        }

    changed = diff_changed_files(base_sha, head_sha)
    if changed is None:
        return {
            "full_scope": True,
            "reason": f"git diff {base_sha}..{head_sha} failed -- deploying everything",
            "base_sha": base_sha,
            "head_sha": head_sha,
            "affected_functions": [],
        }

    for path in changed:
        for pattern in CROSS_CUTTING_PATTERNS:
            if pattern.match(path):
                return {
                    "full_scope": True,
                    "reason": f"cross-cutting path changed: {path}",
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                    "affected_functions": [],
                }

    affected = set()
    for path in changed:
        m = LAMBDA_DIR_RE.match(path)
        if m:
            affected.add(m.group(1))

    return {
        "full_scope": False,
        "reason": f"{len(changed)} file(s) changed, {len(affected)} lambda dir(s) affected",
        "base_sha": base_sha,
        "head_sha": head_sha,
        "affected_functions": sorted(affected),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True, help="GitHub Deployments environment name, e.g. v4-gamma, v3-prod")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "NX-2021-L/enceladus"))
    parser.add_argument("--head-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--base-sha", default="", help="Override auto-resolved base SHA (mainly for testing)")
    args = parser.parse_args()

    if not args.head_sha:
        print("::error::--head-sha (or $GITHUB_SHA) is required", file=sys.stderr)
        sys.exit(1)

    result = compute(args.environment, args.repo, args.head_sha, args.base_sha or None)
    print(json.dumps(result, indent=2))

    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"full_scope={'true' if result['full_scope'] else 'false'}\n")
            f.write(f"affected_functions_json={json.dumps(result['affected_functions'])}\n")
            f.write(f"reason={result['reason']}\n")


if __name__ == "__main__":
    main()
