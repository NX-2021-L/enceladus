#!/usr/bin/env python3
"""assert_changeset_safe.py — the fail-closed change-set safety assertion.

ENC-TSK-J13 / DOC-AA5C7A37A103. This is the compensating control that REPLACES
human review for the ENC-TSK-J10 CFN-drift close-out wave. The privileged import
workflow (.github/workflows/cfn-resource-import.yml) calls this on the output of
`aws cloudformation describe-change-set` BEFORE `execute-change-set`. If this
script exits non-zero, the workflow aborts and NEVER executes the change-set.

It answers one question: "Is this change-set safe to execute autonomously (no
human in the loop)?" — where SAFE means it cannot delete, replace, or wedge a
live resource on the frozen prod stacks (PLN-047 / ENC-TSK-1292 Sev1 class).

Modes (matched to the wave's operations):

  import   Adopt out-of-band live resources into a stack via change-set-type
           IMPORT. The change-set MUST contain ONLY Action=Import. ANY Add,
           Modify, Remove, Replace, or Dynamic aborts. (J14 route/rule imports.)

  recover  Repair a degraded stack (UPDATE_ROLLBACK_COMPLETE) or roll a stack
  create   forward. Adds of GENUINELY-NEW resources are allowed (CFN's own
           EarlyValidation::ResourceExistenceCheck fails closed, non-destructively,
           on an Add-of-EXISTING resource, so it cannot wedge/destroy); in-place
           Modifies are allowed. Remove, Replace, and Conditional-replacement are
           ALWAYS forbidden. (J15 monitoring recovery/create.)

  preview  Same classification as recover/create but purely advisory — used by
           the workflow's no-execute preview mode. Still exits non-zero on a
           destructive change so a preview surfaces danger loudly.

Destructive actions forbidden in EVERY mode: Remove; Replacement in {True,
Conditional}; Action=Dynamic (cannot be proven safe offline).

Usage:
  assert_changeset_safe.py --changeset-json describe.json --mode import
  assert_changeset_safe.py --self-check
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Tuple

# Actions that CloudFormation reports on a ResourceChange.
DESTRUCTIVE_ACTIONS = {"Remove"}
UNSAFE_ACTIONS = {"Dynamic"}  # effect unknown at plan time -> never auto-execute


def _classify_change(rc: dict, mode: str) -> Tuple[bool, str]:
    """Return (ok, reason) for a single ResourceChange under ``mode``."""
    action = rc.get("Action", "?")
    logical = rc.get("LogicalResourceId", "?")
    rtype = rc.get("ResourceType", "?")
    replacement = rc.get("Replacement")  # "True" | "False" | "Conditional" | None
    tag = f"{action} {rtype} {logical}"

    # --- Universal fail-closed rules (all modes) ---
    if action in DESTRUCTIVE_ACTIONS:
        return False, f"FORBIDDEN delete of a live resource: {tag}"
    if action in UNSAFE_ACTIONS:
        return False, f"FORBIDDEN unprovable (Dynamic) change: {tag}"
    if replacement in ("True", "Conditional"):
        return False, f"FORBIDDEN replacement (Replacement={replacement}): {tag}"

    # --- Mode-specific rules ---
    if mode == "import":
        if action != "Import":
            return False, (
                f"IMPORT change-set must contain ONLY Action=Import; found {tag}"
            )
        return True, f"OK import: {tag}"

    # recover / create / preview
    if action == "Import":
        return True, f"OK import: {tag}"
    if action == "Add":
        # Add-of-EXISTING is blocked non-destructively by CFN EarlyValidation;
        # Add-of-NEW is the intended create. Either way it cannot delete/replace.
        return True, f"OK add (new-resource create; Add-of-existing self-blocks): {tag}"
    if action == "Modify":
        # Replacement already asserted False above -> in-place update, non-destructive.
        return True, f"OK in-place modify (Replacement=False): {tag}"
    return False, f"UNRECOGNIZED action, refusing: {tag}"


def assert_safe(changeset: dict, mode: str) -> Tuple[bool, List[str]]:
    changes = changeset.get("Changes", []) or []
    lines: List[str] = []
    ok_all = True

    status = changeset.get("Status")
    status_reason = changeset.get("StatusReason", "")
    # A change-set that FAILED to create is not executable. The classic benign
    # case is "no changes / no updates" -> for import that means nothing to
    # import (suspicious -> fail); for create/recover an empty no-op is fine.
    if status == "FAILED":
        benign = "didn't contain changes" in status_reason or "No updates" in status_reason
        if benign and mode != "import":
            lines.append(f"[PASS] empty no-op change-set ({status_reason!r}); nothing to execute")
            return True, lines
        return False, [f"[FAIL] change-set Status=FAILED: {status_reason!r}"]

    if not changes:
        if mode == "import":
            return False, ["[FAIL] import mode but change-set has ZERO Import actions"]
        lines.append("[PASS] change-set has zero changes (no-op)")
        return True, lines

    for c in changes:
        rc = c.get("ResourceChange", {})
        ok, reason = _classify_change(rc, mode)
        lines.append(("[ok] " if ok else "[FAIL] ") + reason)
        ok_all = ok_all and ok

    # Summary counts
    from collections import Counter
    counts = Counter(c.get("ResourceChange", {}).get("Action", "?") for c in changes)
    lines.append(f"--- {len(changes)} change(s): {dict(counts)} | mode={mode} ---")
    return ok_all, lines


def _self_check() -> bool:
    cases = [
        # (name, changeset, mode, expect_ok)
        ("pure import ok",
         {"Changes": [{"ResourceChange": {"Action": "Import", "ResourceType": "AWS::ApiGatewayV2::Route", "LogicalResourceId": "R1"}}]},
         "import", True),
        ("import mode rejects Add",
         {"Changes": [{"ResourceChange": {"Action": "Add", "ResourceType": "AWS::ApiGatewayV2::Route", "LogicalResourceId": "R2"}}]},
         "import", False),
        ("import mode rejects Modify",
         {"Changes": [{"ResourceChange": {"Action": "Modify", "Replacement": "False", "LogicalResourceId": "R3"}}]},
         "import", False),
        ("any mode rejects Remove",
         {"Changes": [{"ResourceChange": {"Action": "Remove", "LogicalResourceId": "R4"}}]},
         "import", False),
        ("recover rejects Remove",
         {"Changes": [{"ResourceChange": {"Action": "Remove", "LogicalResourceId": "R5"}}]},
         "recover", False),
        ("recover rejects Replace(True)",
         {"Changes": [{"ResourceChange": {"Action": "Modify", "Replacement": "True", "LogicalResourceId": "R6"}}]},
         "recover", False),
        ("recover rejects Conditional replacement",
         {"Changes": [{"ResourceChange": {"Action": "Modify", "Replacement": "Conditional", "LogicalResourceId": "R7"}}]},
         "recover", False),
        ("recover allows Add(new)",
         {"Changes": [{"ResourceChange": {"Action": "Add", "ResourceType": "AWS::Events::Rule", "LogicalResourceId": "R8"}}]},
         "recover", True),
        ("recover allows in-place Modify",
         {"Changes": [{"ResourceChange": {"Action": "Modify", "Replacement": "False", "LogicalResourceId": "R9"}}]},
         "recover", True),
        ("recover allows Import",
         {"Changes": [{"ResourceChange": {"Action": "Import", "LogicalResourceId": "R10"}}]},
         "recover", True),
        ("any mode rejects Dynamic",
         {"Changes": [{"ResourceChange": {"Action": "Dynamic", "LogicalResourceId": "R11"}}]},
         "recover", False),
        ("import empty is fail",
         {"Changes": []}, "import", False),
        ("create empty is pass",
         {"Changes": []}, "create", True),
        ("failed benign no-op create pass",
         {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes.", "Changes": []},
         "create", True),
        ("failed benign no-op import fail",
         {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes.", "Changes": []},
         "import", False),
        ("mixed import+add in create passes",
         {"Changes": [
             {"ResourceChange": {"Action": "Import", "LogicalResourceId": "I1"}},
             {"ResourceChange": {"Action": "Add", "LogicalResourceId": "A1"}},
         ]}, "create", True),
        ("mixed import+remove fails",
         {"Changes": [
             {"ResourceChange": {"Action": "Import", "LogicalResourceId": "I2"}},
             {"ResourceChange": {"Action": "Remove", "LogicalResourceId": "D1"}},
         ]}, "create", False),
    ]
    failures = 0
    for name, cs, mode, expect in cases:
        ok, _ = assert_safe(cs, mode)
        status = "PASS" if ok == expect else "FAIL"
        if ok != expect:
            failures += 1
        print(f"[{status}] {name}: got ok={ok} expect={expect}")
    print(f"[self-check] {failures} failure(s)")
    return failures == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Fail-closed CFN change-set safety assertion (ENC-TSK-J13).")
    ap.add_argument("--changeset-json", help="Path to `aws cloudformation describe-change-set` JSON output.")
    ap.add_argument("--mode", choices=["import", "recover", "create", "preview"], default="import")
    ap.add_argument("--self-check", action="store_true", help="Run offline classifier self-check and exit.")
    args = ap.parse_args()

    if args.self_check:
        return 0 if _self_check() else 1

    if not args.changeset_json:
        print("[ERROR] --changeset-json is required (or use --self-check)", file=sys.stderr)
        return 2
    with open(args.changeset_json) as fh:
        changeset = json.load(fh)

    ok, lines = assert_safe(changeset, args.mode)
    for ln in lines:
        print(ln)
    if ok:
        print(f"[PASS] change-set is SAFE to execute autonomously (mode={args.mode}).")
        return 0
    print(f"[FAIL] change-set is UNSAFE — aborting fail-closed (mode={args.mode}). NOT executing.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
