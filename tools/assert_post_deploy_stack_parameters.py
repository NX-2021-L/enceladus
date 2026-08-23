#!/usr/bin/env python3
"""ENC-TSK-O99 / ENC-ISS-660 (secondary): post-rollback stack-parameter assertion.

THE HOLE THIS FILLS. CloudFormation's response to a failed create is a rollback,
and a rollback restores the stack's PREVIOUSLY STORED parameter values --
including parameters the failed update was deliberately changing, and which have
nothing to do with the resource that failed.

On 2026-08-23 that is exactly what happened. ENC-TSK-O94 correctly bumped
SharedLayerArn :10 -> :12 and the pre-deploy health gate passed. ENC-TSK-O80 had
merged minutes earlier declaring an AWS::Glue::Database the deploy role cannot
create. The Glue create failed, the stack rolled back, and the rollback restored
SharedLayerArn to the stored :10 -- performing precisely the fleet downgrade the
health gate had just refused, across a layer 75 of 233 account functions attach.

Nothing asserted otherwise. The deploy lane checked the stack STATUS, which is a
different question: a rollback that completes cleanly can leave the stack in a
terminal state while silently having undone a correct fix. This closes that by
asserting the VALUES after the fact.

Runs with `if: always()` so it reports on the failure path -- the only path where
it matters. It is a detector, not a gate: by the time it speaks the revert has
already happened. Its job is to make sure the revert is never again something
someone has to notice.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_shared_layer_version import CANONICAL_SHARED_LAYER_ARN  # noqa: E402

ROLLBACK_STATES = {
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_IN_PROGRESS",
}


def describe(stack_name: str, region: str) -> dict:
    result = subprocess.run(
        ["aws", "cloudformation", "describe-stacks",
         "--region", region, "--stack-name", stack_name,
         "--query", "Stacks[0].{Status:StackStatus,Parameters:Parameters}",
         "--output", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"::error::describe-stacks failed for {stack_name}: {result.stderr.strip()}")
        sys.exit(2)
    return json.loads(result.stdout or "{}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument(
        "--expect", action="append", default=[], metavar="Key=Value",
        help="Additional parameter the update intended to set. Repeatable.")
    parser.add_argument(
        "--skip-shared-layer", action="store_true",
        help="For stacks that do not take a SharedLayerArn parameter.")
    args = parser.parse_args()

    detail = describe(args.stack_name, args.region)
    status = detail.get("Status") or "(unknown)"
    live = {
        p["ParameterKey"]: p.get("ParameterValue", "")
        for p in (detail.get("Parameters") or [])
    }

    expected: dict[str, str] = {}
    if not args.skip_shared_layer and "SharedLayerArn" in live:
        expected["SharedLayerArn"] = CANONICAL_SHARED_LAYER_ARN
    for item in args.expect:
        key, _, value = item.partition("=")
        expected[key] = value

    print(f"Post-deploy parameter assertion — {args.stack_name}")
    print(f"  stack status: {status}")
    if status in ROLLBACK_STATES:
        print("::warning::This stack ROLLED BACK. A rollback restores previously "
              "stored parameter values, including ones this update intended to "
              "change. That is the ENC-ISS-656 regression path; the assertions "
              "below are the check that was missing when it happened.")

    drift = []
    for key, want in expected.items():
        got = live.get(key)
        if got is None:
            print(f"  {key}: NOT PRESENT on the stack (expected {want})")
            drift.append(f"{key} is absent from the stack; expected {want!r}")
        elif got != want:
            print(f"  {key}: {got}  != expected {want}")
            drift.append(
                f"{key} is {got!r} but the canonical value is {want!r}. If this "
                f"stack just rolled back, the rollback reverted it -- the fix that "
                f"set it is undone and must be re-applied, not assumed landed.")
        else:
            print(f"  {key}: {got}  (matches canonical)")

    if not expected:
        print("  (no asserted parameters for this stack)")

    if drift:
        for item in drift:
            print(f"::error::post-deploy parameter drift: {item}")
        print(f"[FAIL] post-deploy parameter assertion: {len(drift)} parameter(s) "
              f"do not match their canonical values.")
        return 1

    print("[SUCCESS] post-deploy parameter assertion: every asserted parameter "
          "still holds its canonical value.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
