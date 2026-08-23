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
        read_scope=none        Resource: "*"  -> s3 denied everywhere.
                               Preserves today's EFFECTIVE posture exactly while
                               still removing the harrisonfamily write privilege.
                               The CLAUDE.md claim must then be withdrawn.
                               (This was NotResource: [] until ENC-TSK-P05, which
                               Access Analyzer reports as a NO-OP -- see the R3
                               comment in transform().)
        read_scope=artifacts   NotResource: the bucket + lambda-artifacts/* only
                               -> DEFAULT. BRD section 8 point 1 becomes
                               satisfiable; agent-documents/ objects stay denied,
                               so the raw-S3 path around governed documents.get
                               stays closed (ENC-ISS-640 class).
        read_scope=jreese-net  NotResource: the jreese-net bucket and ALL objects
                               -> makes the documented capability true, but also
                               re-opens raw-S3 reads of agent-documents/.

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

# ENC-TSK-P05: object reads confined to the build-artifact prefix, plus the bare
# bucket ARN. Both entries are load-bearing and for different reasons.
#
#   the bucket ARN            -- s3:ListBucket acts on the BUCKET, not on an
#                                object. Without it S3 answers a missing key with
#                                403 AccessDenied instead of 404 NoSuchKey, and
#                                the arm64 harness's point 1 routes a real
#                                artifact_missing FAIL into the permission_denied
#                                UNKNOWN branch -- silently destroying the most
#                                important verdict its tri-state exists to carry.
#   the lambda-artifacts/*    -- object reads reach the build artifacts and
#                                NOTHING else. agent-documents/ objects stay
#                                denied, so the raw-S3 path around governed
#                                documents.get stays closed (ENC-ISS-640 class).
ARTIFACTS_SCOPE = [
    "arn:aws:s3:::jreese-net",
    "arn:aws:s3:::jreese-net/lambda-artifacts/*",
]

READ_SCOPES = ("none", "artifacts", "jreese-net")
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

    # ENC-TSK-P05 -- read_scope=none previously emitted "NotResource": [].
    # AWS Access Analyzer's verdict on that document, run live 2026-08-23:
    #
    #   SUGGESTION  EMPTY_ARRAY_RESOURCE
    #   "This statement includes no resources and does not affect the policy."
    #
    # So the containment Deny was a NO-OP. Applying it would have removed the
    # shadowing Deny and replaced it with nothing, promoting AllowMinimalReads'
    # Resource "*" from dead letter to LIVE ACROSS EVERY BUCKET -- the exact
    # widening R3's docstring says it exists to prevent, defeated by an empty
    # array. "Deny everywhere" is Resource "*", never NotResource [].
    if read_scope == "none":
        containment = {
            "Sid": CONTAINMENT_SID,
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
        }
        notes.append(
            f"R3 ADDED Deny [{CONTAINMENT_SID}] s3:* on Resource '*' -- s3 denied "
            f"everywhere. Effective posture is unchanged from today; only the "
            f"harrisonfamily write privilege is gone. CLAUDE.md must stop claiming "
            f"baseline S3 reads.")
    else:
        not_resource = list(ARTIFACTS_SCOPE if read_scope == "artifacts" else JREESE_NET)
        containment = {
            "Sid": CONTAINMENT_SID,
            "Effect": "Deny",
            "Action": "s3:*",
            "NotResource": not_resource,
        }
        if read_scope == "artifacts":
            notes.append(
                f"R3 ADDED Deny [{CONTAINMENT_SID}] s3:* on NotResource "
                f"{ARTIFACTS_SCOPE} -- object reads reach the build-artifact prefix "
                f"and nothing else, so BRD DOC-56CFA21523C1 section 8 point 1 becomes "
                f"satisfiable while agent-documents/ objects stay denied and the "
                f"raw-S3 path around governed documents.get stays closed. The bare "
                f"bucket ARN is deliberate: without ListBucket, a missing artifact "
                f"returns 403 instead of 404 and the harness reports UNKNOWN where it "
                f"should report a FAIL.")
        else:
            notes.append(
                f"R3 ADDED Deny [{CONTAINMENT_SID}] s3:* on NotResource {JREESE_NET} -- "
                f"AllowMinimalReads now applies to the whole jreese-net bucket. NOTE "
                f"this includes agent-documents/, which re-opens a raw-S3 read path "
                f"around governed documents.get (ENC-ISS-640 class). Prefer "
                f"read_scope=artifacts unless whole-bucket read is genuinely intended.")
    kept.append(containment)

    return {"Version": document.get("Version", "2012-10-17"), "Statement": kept}, notes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="src", required=True)
    parser.add_argument("--out", dest="dst", required=True)
    parser.add_argument("--read-scope", choices=list(READ_SCOPES), default="artifacts",
                        help="none = deny s3 everywhere (Resource '*'); the CLAUDE.md claim "
                             "must then be withdrawn. artifacts = read the build-artifact "
                             "prefix only, which makes BRD section 8 point 1 satisfiable "
                             "without opening a raw-S3 path to agent-documents (DEFAULT). "
                             "jreese-net = whole-bucket read, which DOES open that path.")
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
