#!/usr/bin/env python3
"""IAM inline-policy character-budget checker — ENC-TSK-P99 / ENC-ISS-775.

Run 35169979296 of iam-cfn-deploy-role-cloudwatch-dashboard-prod-patch.yml
failed with `aws iam put-role-policy` -> LimitExceeded: the role
enceladus-cloudformation-deploy-github-role already carries ~11 inline patch
policies (see the sibling iam-cfn-deploy-role-*-patch.yml workflows) plus its
stack-defined ones, and the IAM aggregate inline-policy cap per role is
10,240 characters (whitespace excluded, per AWS's own accounting).

This script never writes anything. It only reads (`aws iam list-role-policies`
/ `aws iam get-role-policy`) and computes: it prints a per-policy size table,
the aggregate total, the headroom against `--limit` (default 10240), and —
when `--merge-policy` / `--merge-document` are given — the size delta of
replacing (or creating) that one policy in place with the given document, so
a workflow step can fail BEFORE attempting the mutating `put-role-policy`
call that would otherwise hit LimitExceeded.

Size rule (matches AWS's own aggregate-policy-size accounting): each policy
document is minified to compact JSON (`json.dumps(doc, separators=(",", ":"))`)
and then ALL whitespace is stripped with `re.sub(r"\\s", "", ...)`; the
resulting string length is that policy's byte/char count.

The `--json` flag additionally emits a machine-readable JSON blob of the same
data. Either way a one-line `BUDGET total=.. headroom=.. delta=.. fits=..`
summary is always printed last, so a workflow log grep can find it without
parsing the table.

Exit codes:
  0  no --merge-policy given, or the merge fits within headroom; also
     --on-list-denied warn whenever the listing itself was denied (the
     aggregate budget is then unknown but that must not block the grant)
  1  --merge-policy given and the merge does NOT fit within headroom, or any
     other unrecoverable fetch error (e.g. get-role-policy denied on the
     merge target)

--on-list-denied {fail,warn} (default fail): controls what happens when
`list-role-policies` itself fails (observed in run 35172068267: the OIDC
role has put/get-role-policy on this one role but not list-role-policies,
so the aggregate listing 403s with AccessDenied). `fail` (default) preserves
today's behaviour of propagating the error as a non-zero exit — but stderr
from the failing aws CLI invocation is now always printed first. `warn`
degrades gracefully: it prints a WARNING line, and if --merge-policy was
given it measures ONLY that one policy (via get-role-policy; NoSuchEntity
means the policy does not exist yet, treated as existing size 0), prints a
one-row table plus a BUDGET line with total/headroom reported as "unknown"
and delta computed just from that single policy, and exits 0 — a denied
LIST must never block the atomic, self-guarding put-role-policy call.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Tuple

DEFAULT_LIMIT = 10240


class ListDenied(Exception):
    """Raised by a fetcher when list-role-policies itself failed.

    Carries the offending command and stripped stderr so callers (main())
    can decide, per --on-list-denied, whether to fail closed or degrade to
    measuring only the merge target. ``printed`` is True when the stderr was
    already written to sys.stderr by the raiser (the real aws-CLI-backed
    fetchers do this via _run_aws_json), so main() knows not to print it a
    second time; a directly-raised ListDenied (as tests do) leaves it False
    so main() prints the stderr itself.
    """

    def __init__(
        self,
        message: str,
        *,
        cmd: Optional[List[str]] = None,
        stderr: str = "",
        printed: bool = False,
    ):
        super().__init__(message)
        self.cmd = cmd
        self.stderr = stderr
        self.printed = printed


class GetPolicyDenied(Exception):
    """Raised when get-role-policy for a specific policy failed (not NoSuchEntity).

    See ListDenied for the meaning of ``printed``.
    """

    def __init__(
        self,
        message: str,
        *,
        cmd: Optional[List[str]] = None,
        stderr: str = "",
        printed: bool = False,
    ):
        super().__init__(message)
        self.cmd = cmd
        self.stderr = stderr
        self.printed = printed


# Type alias for the injectable fetcher used by tests: given a role name,
# returns {policy_name: policy_document_dict}.
Fetcher = Callable[[str], Dict[str, dict]]

# Type alias for the injectable single-policy fetcher used in degraded
# (list-denied) mode: given (role, policy_name), returns the policy document
# dict, or None if the policy does not exist (NoSuchEntity).
SinglePolicyFetcher = Callable[[str, str], Optional[dict]]


def _run_aws_json(args: List[str]) -> dict:
    """Run an `aws ... --output json` subprocess call and parse stdout.

    On failure, the failing command and its stripped stderr are always
    printed to stderr before the error is raised/converted, so a workflow
    log always says *why* the aws CLI call failed instead of just showing a
    bare CalledProcessError traceback.
    """
    proc = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        print(f"aws CLI command failed (exit {proc.returncode}): {' '.join(args)}", file=sys.stderr)
        if stderr:
            print(stderr, file=sys.stderr)
        raise subprocess.CalledProcessError(
            proc.returncode, args, output=proc.stdout, stderr=proc.stderr
        )
    return json.loads(proc.stdout)


def make_aws_fetcher(region: Optional[str] = None) -> Fetcher:
    """Build a Fetcher backed by real `aws iam` subprocess calls."""

    def _fetch(role: str) -> Dict[str, dict]:
        base = ["aws", "iam"]
        if region:
            base += ["--region", region]

        list_args = base + [
            "list-role-policies",
            "--role-name",
            role,
            "--output",
            "json",
        ]
        try:
            listed = _run_aws_json(list_args)
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            raise ListDenied(
                f"list-role-policies failed (exit {exc.returncode})",
                cmd=list_args,
                stderr=stderr,
                printed=True,
            ) from exc
        names = listed.get("PolicyNames", [])

        docs: Dict[str, dict] = {}
        for name in names:
            get_args = base + [
                "get-role-policy",
                "--role-name",
                role,
                "--policy-name",
                name,
                "--output",
                "json",
            ]
            got = _run_aws_json(get_args)
            docs[name] = got["PolicyDocument"]
        return docs

    return _fetch


def make_aws_single_policy_fetcher(region: Optional[str] = None) -> SinglePolicyFetcher:
    """Build a SinglePolicyFetcher backed by a real `aws iam get-role-policy` call.

    Used in degraded (list-denied, warn mode) operation: fetches just the
    --merge-policy target. Returns None (treated as "does not exist yet")
    when the aws CLI reports NoSuchEntity; raises GetPolicyDenied for any
    other failure (e.g. the merge target itself is also denied).
    """

    def _fetch_one(role: str, policy_name: str) -> Optional[dict]:
        base = ["aws", "iam"]
        if region:
            base += ["--region", region]
        get_args = base + [
            "get-role-policy",
            "--role-name",
            role,
            "--policy-name",
            policy_name,
            "--output",
            "json",
        ]
        try:
            got = _run_aws_json(get_args)
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            if "nosuchentity" in stderr.lower():
                return None
            raise GetPolicyDenied(
                f"get-role-policy failed (exit {exc.returncode}) for {policy_name}",
                cmd=get_args,
                stderr=stderr,
                printed=True,
            ) from exc
        return got["PolicyDocument"]

    return _fetch_one


def policy_size(document: dict) -> int:
    """Whitespace-excluded character size of a policy document.

    Matches AWS's own aggregate inline-policy size accounting: compact JSON
    serialization, then strip every remaining whitespace character.
    """
    compact = json.dumps(document, separators=(",", ":"))
    stripped = re.sub(r"\s", "", compact)
    return len(stripped)


def load_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def compute_budget(
    policies: Dict[str, dict],
    limit: int,
    merge_policy: Optional[str] = None,
    merge_document: Optional[dict] = None,
) -> dict:
    """Pure computation over an already-fetched policy map.

    Returns a dict with: sizes (list of (name, size) sorted desc), total,
    headroom, and — if merge_policy is given — existing_size, merged_size,
    delta, fits.
    """
    sizes: List[Tuple[str, int]] = [
        (name, policy_size(doc)) for name, doc in policies.items()
    ]
    sizes.sort(key=lambda kv: (-kv[1], kv[0]))
    total = sum(size for _, size in sizes)
    headroom = limit - total

    result: dict = {
        "sizes": sizes,
        "total": total,
        "limit": limit,
        "headroom": headroom,
    }

    if merge_policy is not None:
        existing_size = policies.get(merge_policy)
        existing_size = policy_size(existing_size) if existing_size is not None else 0
        merged_size = policy_size(merge_document) if merge_document is not None else 0
        delta = merged_size - existing_size
        fits = delta <= headroom
        result.update(
            {
                "merge_policy": merge_policy,
                "existing_size": existing_size,
                "merged_size": merged_size,
                "delta": delta,
                "fits": fits,
            }
        )

    return result


def print_table(result: dict) -> None:
    print(f"{'POLICY':<60} {'BYTES':>8}")
    for name, size in result["sizes"]:
        print(f"{name:<60} {size:>8}")
    print("-" * 69)
    print(f"{'TOTAL':<60} {result['total']:>8}")
    print(f"{'LIMIT':<60} {result['limit']:>8}")
    print(f"{'HEADROOM':<60} {result['headroom']:>8}")

    if "merge_policy" in result:
        print()
        print(f"Merge target policy : {result['merge_policy']}")
        print(f"  existing size      : {result['existing_size']}")
        print(f"  merged size        : {result['merged_size']}")
        print(f"  delta              : {result['delta']}")
        print(f"  fits within headroom: {result['fits']}")


def print_summary(result: dict) -> None:
    delta = result.get("delta")
    fits = result.get("fits")
    delta_str = str(delta) if delta is not None else "n/a"
    fits_str = "true" if fits else ("false" if fits is not None else "n/a")
    print(
        f"BUDGET total={result['total']} headroom={result['headroom']} "
        f"delta={delta_str} fits={fits_str}"
    )


def print_degraded_merge_table(merge_policy: str, existing_size: int, merged_size: int, delta: int) -> None:
    """One-row table for --on-list-denied warn when the aggregate listing failed.

    Only the merge target's own size is known, so there is no aggregate
    total/headroom to render — just the single policy row and the merge
    delta.
    """
    print(f"{'POLICY':<60} {'BYTES':>8}")
    print(f"{merge_policy:<60} {merged_size:>8}")
    print("-" * 69)
    print(f"{'TOTAL':<60} {'unknown':>8}")
    print()
    print(f"Merge target policy : {merge_policy}")
    print(f"  existing size      : {existing_size}")
    print(f"  merged size        : {merged_size}")
    print(f"  delta              : {delta}")
    print("  fits within headroom: unknown (list-role-policies denied; aggregate total not available)")


def main(
    argv: Optional[List[str]] = None,
    fetcher: Optional[Fetcher] = None,
    single_fetcher: Optional[SinglePolicyFetcher] = None,
) -> int:
    parser = argparse.ArgumentParser(
        description="Check an IAM role's aggregate inline-policy size budget.",
    )
    parser.add_argument("--role", required=True, help="IAM role name")
    parser.add_argument(
        "--merge-policy",
        default=None,
        help="Policy name to merge/replace in place (existing size subtracted, "
        "merged document's size added; missing policy = delta is full size)",
    )
    parser.add_argument(
        "--merge-document",
        default=None,
        help="Path to a JSON file containing the merged policy document "
        "(required if --merge-policy is given)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Aggregate inline-policy character limit (default {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Also emit a JSON blob of the computed data",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region to pass to the aws CLI (optional)",
    )
    parser.add_argument(
        "--on-list-denied",
        choices=["fail", "warn"],
        default="fail",
        help="What to do when `aws iam list-role-policies` itself fails "
        "(e.g. AccessDenied): 'fail' (default) exits non-zero, matching "
        "today's behaviour but with stderr now printed; 'warn' degrades to "
        "measuring only --merge-policy (if given) via get-role-policy and "
        "exits 0, since a denied listing must not block the atomic, "
        "self-guarding put-role-policy call",
    )
    args = parser.parse_args(argv)

    if args.merge_policy is not None and args.merge_document is None:
        parser.error("--merge-policy requires --merge-document")

    fetch = fetcher if fetcher is not None else make_aws_fetcher(args.region)

    merge_document = None
    if args.merge_document is not None:
        merge_document = load_json_file(args.merge_document)

    try:
        policies = fetch(args.role)
    except ListDenied as exc:
        # The real aws-CLI-backed fetcher already printed this stderr once
        # (via _run_aws_json) before wrapping it into ListDenied; only print
        # here for a fetcher that raised ListDenied directly (e.g. a test).
        if exc.stderr and not exc.printed:
            print(exc.stderr, file=sys.stderr)

        if args.on_list_denied == "fail":
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        print(
            "WARNING: list-role-policies denied; aggregate budget unknown, "
            "measuring merge target only",
            file=sys.stderr,
        )

        if args.merge_policy is None:
            print("BUDGET total=unknown headroom=unknown delta=n/a fits=n/a")
            return 0

        single_fetch = (
            single_fetcher
            if single_fetcher is not None
            else make_aws_single_policy_fetcher(args.region)
        )
        try:
            existing_doc = single_fetch(args.role, args.merge_policy)
        except GetPolicyDenied as get_exc:
            if get_exc.stderr and not get_exc.printed:
                print(get_exc.stderr, file=sys.stderr)
            print(f"ERROR: {get_exc}", file=sys.stderr)
            return 1

        existing_size = policy_size(existing_doc) if existing_doc is not None else 0
        merged_size = policy_size(merge_document) if merge_document is not None else 0
        delta = merged_size - existing_size

        print_degraded_merge_table(args.merge_policy, existing_size, merged_size, delta)
        print(f"BUDGET total=unknown headroom=unknown delta={delta} fits=unknown")
        return 0

    result = compute_budget(
        policies,
        limit=args.limit,
        merge_policy=args.merge_policy,
        merge_document=merge_document,
    )

    print_table(result)
    if args.as_json:
        print(json.dumps(result, default=list))
    print_summary(result)

    if args.merge_policy is not None and not result["fits"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
