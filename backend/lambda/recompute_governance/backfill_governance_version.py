#!/usr/bin/env python3
"""Backfill the canonical governance-version DDB record from current live S3 state.

ENC-TSK-I32 / ENC-FTR-116 — DOC-6F7A14667E7D §8 (backfill and migration).

The canonical ``governance-version-current`` record is normally written only by
the storage-event recompute Lambda (``lambda_function.handler``). Before that
Lambda has fired for the first time the record does not exist, so the §13
version-agreement gate and ``connection_health`` have nothing to read. This
script performs the one-time seed: it reads the current live S3 state of the
canonical governance file set, computes the §4.3 bundle hash, captures each
file's ``versionId`` + ``checksum_sha256_hex`` and the embedded
``governance_revision``, and writes generation 1 under a first-write CAS guard
(``attribute_not_exists(version_id)``) — exactly the shape the recompute Lambda
would have produced.

Safety model (DOC-6F7A14667E7D §8 + the ENC-TSK-I32 row split):
  * DRY-RUN BY DEFAULT. The actual mutation is deferred to the privileged run.
    Without ``--commit`` the script only reads, builds the planned record, and
    emits before/after evidence — it never writes.
  * IDEMPOTENT SEED. The backfill is a first-write only. If the record already
    exists (the recompute Lambda already fired, or a prior backfill ran) the
    script reports ``already_seeded`` and makes no write, even with ``--commit``.
  * COMPLETE-MEDIATION SAFE. ``--commit`` must run under the sole-writer
    recompute role (I28 IAM). Every other principal is denied write to the
    record; a ``--commit`` from an unprivileged principal fails closed at DDB.

Evidence: the script always prints a JSON ``backfill_evidence`` block (and writes
it to ``--evidence-out`` when given) carrying ``before`` (the record state prior
to the seed, or null), ``seed`` (the planned/written record), ``after`` (the
record state after, or the would-be record in dry-run), and ``committed``. This
is the before/after evidence the ENC-TSK-I32 acceptance criterion requires.

Usage:
  # Dry-run (default) — read live S3, print the planned record + evidence:
  python backfill_governance_version.py

  # Privileged seed — actually write generation 1 (sole-writer role required):
  python backfill_governance_version.py --commit --evidence-out backfill.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

# Import the recompute Lambda module so the backfill reuses the *identical*
# §4.3 hashing / checksum / canonical-file-set contract. Co-located in this
# directory; add it to the path so the script runs from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lambda_function as recompute  # noqa: E402


def _utcnow_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _read_full_record() -> dict[str, Any] | None:
    """Read the full canonical item (all attributes) for before/after evidence.

    Returns a plain-Python projection of the DDB item, or None if absent.
    """
    resp = recompute._get_ddb().get_item(
        TableName=recompute.TABLE_NAME,
        Key={"version_id": {"S": recompute.CANONICAL_ITEM_KEY}},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return None
    out: dict[str, Any] = {}
    for key, attr in item.items():
        if "S" in attr:
            out[key] = attr["S"]
        elif "N" in attr:
            out[key] = int(attr["N"])
        else:
            out[key] = attr
    # files / source_event are stored as JSON strings; decode for readability.
    for json_field in ("files", "source_event"):
        raw = out.get(json_field)
        if isinstance(raw, str):
            try:
                out[json_field] = json.loads(raw)
            except (ValueError, TypeError):
                pass
    return out


def build_seed_state() -> dict[str, Any]:
    """Recompute the canonical seed record from current live S3 state.

    Mirrors ``recompute.handler`` for a first-write: generation 1, per-file
    versionId + checksum captured, bundle hash + embedded governance_revision.
    """
    canonical = recompute._list_canonical_files()
    if not canonical:
        raise RuntimeError(
            "Canonical governance file set is empty in live S3; refusing to "
            "seed an empty governance-version record."
        )

    agents_md_key = f"{recompute.S3_GOVERNANCE_PREFIX}/agents.md"
    governance_revision = recompute._read_governance_revision(agents_md_key)

    file_entries: list[dict[str, str]] = []
    for uri, s3_key in canonical:
        checksum_hex, version_id = recompute._get_file_checksum(s3_key)
        file_entries.append(
            {
                "uri": uri,
                "s3_key": s3_key,
                "s3_version_id": version_id,
                "checksum_sha256_hex": checksum_hex,
            }
        )

    governance_hash = recompute._compute_bundle_hash(file_entries)

    return {
        "version_id": recompute.CANONICAL_ITEM_KEY,
        "governance_revision": governance_revision,
        "governance_hash": governance_hash,
        "generation": 1,
        "cas_version": 1,
        "files": file_entries,
        # Marks the record's provenance as a backfill seed (no triggering S3
        # event). An empty s3_sequencer means the first real recompute event
        # will not dedup against it and will advance to generation 2.
        "source_event": {
            "s3_sequencer": "",
            "trigger_s3_key": "",
            "backfill": True,
            "backfilled_at": _utcnow_iso(),
        },
    }


def perform_backfill(commit: bool) -> dict[str, Any]:
    """Run the backfill (dry-run unless commit=True). Returns the evidence dict."""
    before = _read_full_record()
    seed = build_seed_state()

    already_seeded = before is not None
    wrote = False
    note = ""

    if already_seeded:
        note = (
            "Record already exists (generation={}); backfill is a first-write "
            "seed only and makes no change.".format(before.get("generation"))
        )
    elif commit:
        wrote = recompute._cas_write(
            governance_revision=seed["governance_revision"],
            governance_hash=seed["governance_hash"],
            generation=seed["generation"],
            file_entries=seed["files"],
            source_event=seed["source_event"],
            expected_cas=None,  # first-write guard: attribute_not_exists
        )
        note = (
            "Seed committed (generation=1)."
            if wrote
            else "First-write CAS lost a race; another writer seeded the record "
            "concurrently. No change by this run."
        )
    else:
        note = (
            "DRY-RUN: no write performed. Re-run with --commit under the "
            "sole-writer recompute role to seed the record."
        )

    after = _read_full_record()

    return {
        "backfill_evidence": {
            "table": recompute.TABLE_NAME,
            "version_id": recompute.CANONICAL_ITEM_KEY,
            "captured_at": _utcnow_iso(),
            "committed": wrote,
            "dry_run": not commit,
            "already_seeded": already_seeded,
            "note": note,
            "before": before,
            "seed": seed,
            "after": after,
        }
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Backfill the canonical governance-version record from live S3 "
            "state (ENC-TSK-I32 / DOC-6F7A14667E7D §8). Dry-run by default."
        )
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help=(
            "Actually write the seed record (requires the sole-writer recompute "
            "role). Without this flag the script is read-only."
        ),
    )
    parser.add_argument(
        "--evidence-out",
        metavar="PATH",
        default=None,
        help="Write the before/after evidence JSON to this path.",
    )
    args = parser.parse_args(argv)

    evidence = perform_backfill(commit=args.commit)
    rendered = json.dumps(evidence, indent=2, default=str)
    print(rendered)

    if args.evidence_out:
        with open(args.evidence_out, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")

    ev = evidence["backfill_evidence"]
    # Non-zero exit only on a genuine failure to leave the record seeded after a
    # commit. Dry-runs and idempotent already-seeded runs are success (0).
    if args.commit and not ev["already_seeded"] and not ev["committed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
