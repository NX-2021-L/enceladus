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
  0  no --merge-policy given, or the merge fits within headroom
  1  --merge-policy given and the merge does NOT fit within headroom
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Tuple

DEFAULT_LIMIT = 10240

# Type alias for the injectable fetcher used by tests: given a role name,
# returns {policy_name: policy_document_dict}.
Fetcher = Callable[[str], Dict[str, dict]]


def _run_aws_json(args: List[str]) -> dict:
    """Run an `aws ... --output json` subprocess call and parse stdout."""
    proc = subprocess.run(
        args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
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
        listed = _run_aws_json(list_args)
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


def main(argv: Optional[List[str]] = None, fetcher: Optional[Fetcher] = None) -> int:
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
    args = parser.parse_args(argv)

    if args.merge_policy is not None and args.merge_document is None:
        parser.error("--merge-policy requires --merge-document")

    fetch = fetcher if fetcher is not None else make_aws_fetcher(args.region)
    policies = fetch(args.role)

    merge_document = None
    if args.merge_document is not None:
        merge_document = load_json_file(args.merge_document)

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
