#!/usr/bin/env python3
"""ENC-TSK-P02 / ENC-ISS-659: transform enceladus-agent-cli-policy's S3 boundary.

Reads the live policy document, applies three narrow rules, writes the new one.
A TRANSFORM rather than a hand-authored replacement because removing one
statement means rewriting the whole document, and no agent session can read this
policy (iam:GetPolicyVersion is denied to enceladus-agent-cli) -- so a
hand-authored version would be guessing at the statements it is not changing.

THE RULES, each asserted before it is applied:

  R1  Drop every Allow whose Resource mentions harrisonfamily-frontend.
      This is the cross-project privilege: s3:* -- Put, Delete, overwrite -- on
      an unrelated project's PRODUCTION frontend bucket.

  R2  Drop the Deny of s3:* on NotResource harrisonfamily-frontend.
      Explicit Deny beats Allow, so a NotResource Deny naming only that bucket
      denies s3 on every other bucket, which is what makes the AllowMinimalReads
      s3:GetObject/ListBucket on Resource '*' a dead letter.

  R3  Put back a containment Deny of the SAME SHAPE, scoped to what enceladus
      actually needs -- or to nothing, if read_scope=none.
        read_scope=none        NotResource: []  -> s3 denied everywhere.
                               Preserves today's EFFECTIVE posture exactly while
                               still removing the harrisonfamily write privilege.
                               The CLAUDE.md claim must then be withdrawn.
        read_scope=jreese-net  NotResource: the jreese-net bucket and its objects
                               -> AllowMinimalReads applies there and nowhere
                               else, making the documented capability true.

R3 keeps the original author's containment shape rather than deleting it,
because deleting it would let AllowMinimalReads' Resource '*' become live across
every bucket in the account -- a far larger widening than this record asks for,
arrived at by removing a statement rather than adding one. That is precisely the
kind of silent consequence ENC-ISS-659 exists to stop.

FAIL-CLOSED. If the document does not contain the statements described above,
this exits non-zero and writes nothing. A policy that has already been corrected,
or has drifted into a different shape, must be looked at by a human rather than
transformed by a script working from stale assumptions.
"""

from __future__ import annotations

import argparse
import json
import sys

HARRISON = "harrisonfamily-frontend"
JREESE_NET = ["arn:aws:s3:::jreese-net", "arn:aws:s3:::jreese-net/*"]
CONTAINMENT_SID = "DenyS3OutsideEnceladusScope"


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _mentions_harrison(value) -> bool:
    return any(HARRISON in entry for entry in _as_list(value) if isinstance(entry, str))


def transform(document: dict, read_scope: str) -> tuple[dict, list[str]]:
    statements = _as_list(document.get("Statement"))
    if not statements:
        raise SystemExit("::error::policy document has no Statement array")

    notes: list[str] = []
    kept: list[dict] = []
    removed_allow = 0
    removed_deny = 0

    for statement in statements:
        effect = statement.get("Effect")
        sid = statement.get("Sid", "(no sid)")

        if effect == "Allow" and _mentions_harrison(statement.get("Resource")):
            actions = ", ".join(_as_list(statement.get("Action")))
            notes.append(f"R1 REMOVED Allow [{sid}] {actions} on {HARRISON}")
            removed_allow += 1
            continue

        if effect == "Deny" and _mentions_harrison(statement.get("NotResource")):
            notes.append(
                f"R2 REMOVED Deny [{sid}] on NotResource {HARRISON} "
                f"-- the statement that shadowed every other S3 grant")
            removed_deny += 1
            continue

        kept.append(statement)

    if removed_allow == 0:
        raise SystemExit(
            "::error::no Allow statement referencing harrisonfamily-frontend was "
            "found. Either this policy has already been corrected or it has "
            "drifted; refusing to write. Re-inspect before re-running.")
    if removed_deny == 0:
        raise SystemExit(
            "::error::no Deny on NotResource harrisonfamily-frontend was found. "
            "The document does not have the shape ENC-ISS-659 describes; "
            "refusing to write.")

    not_resource = [] if read_scope == "none" else list(JREESE_NET)
    kept.append({
        "Sid": CONTAINMENT_SID,
        "Effect": "Deny",
        "Action": "s3:*",
        "NotResource": not_resource,
    })
    if read_scope == "none":
        notes.append(
            f"R3 ADDED Deny [{CONTAINMENT_SID}] s3:* on NotResource [] -- s3 denied "
            f"everywhere. Effective posture is unchanged from today; only the "
            f"harrisonfamily write privilege is gone. CLAUDE.md must stop claiming "
            f"baseline S3 reads.")
    else:
        notes.append(
            f"R3 ADDED Deny [{CONTAINMENT_SID}] s3:* on NotResource {JREESE_NET} -- "
            f"AllowMinimalReads now applies to jreese-net and nowhere else, making "
            f"the documented read capability true.")

    return {"Version": document.get("Version", "2012-10-17"), "Statement": kept}, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="src", required=True)
    parser.add_argument("--out", dest="dst", required=True)
    parser.add_argument("--read-scope", choices=["none", "jreese-net"], default="none")
    args = parser.parse_args()

    document = json.loads(open(args.src).read())
    if isinstance(document, str):  # aws cli can hand back a JSON string
        document = json.loads(document)

    before = len(_as_list(document.get("Statement")))
    new_document, notes = transform(document, args.read_scope)
    after = len(_as_list(new_document.get("Statement")))

    print(f"enceladus-agent-cli-policy: {before} statements -> {after}")
    for note in notes:
        print(f"  {note}")

    # Everything untouched is listed too, so a reviewer can see the blast radius
    # of this edit is exactly the three statements named above.
    print("  UNTOUCHED:")
    for statement in _as_list(new_document.get("Statement")):
        if statement.get("Sid") == CONTAINMENT_SID:
            continue
        print(f"    [{statement.get('Sid', '(no sid)')}] {statement.get('Effect')}")

    with open(args.dst, "w") as handle:
        json.dump(new_document, handle, indent=2)
        handle.write("\n")
    print(f"wrote {args.dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
