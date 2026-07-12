#!/usr/bin/env python3
"""ENC-TSK-M98 / ENC-ISS-538 — canonical → gamma tracker mirror (overwrite sync).

Gamma's tracker is a DISPOSABLE MIRROR of canonical (io direction 2026-07-12):
every sync fully overwrites gamma; gamma-native records are destroyed. This tool
is the sole codified sync path. Phases (execute mode):

  1. MIRROR      — scan canonical devops-project-tracker, BatchWriteItem overwrite
                   every item into devops-project-tracker-gamma.
  2. DELETE      — delete gamma keys absent from the canonical snapshot (the
                   gamma-native / collision records), AFTER dumping each doomed
                   item to a local snapshot dir (optionally uploaded to S3).
  3. COUNTERS    — delete ALL rows in enceladus-id-counters-gamma and wipe
                   enceladus-id-idempotency-gamma. The ID service (ENC-TSK-L06)
                   cold-seeds its next-mint from a decode-max scan of the tracker
                   table, so post-mirror the freshly copied canonical high-water
                   IS the seed — the collision mechanism becomes self-healing.
  4. VERIFY      — item counts match, aux tables empty. Non-zero exit on mismatch.

Fail-closed guardrails (non-negotiable, ENC-TSK-M98 AC):
  * DIRECTION LOCK — source is hard-coded to the canonical table; every write
    target must end in "-gamma". Any tampering aborts before any AWS call.
  * DRY-RUN DEFAULT — without --execute the tool only scans and writes a local
    diff manifest (adds / changed / unchanged / deletes, gamma-native deletes
    flagged). Zero mutations.
  * --execute is a separate explicit flag; the GitHub workflow additionally
    gates it behind a typed confirm phrase and the gamma-mirror Environment.

Never run --execute from an agent terminal: execution is ENC-TSK-N01,
io-supervised, via .github/workflows/gamma-tracker-mirror.yml only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

CANONICAL_TABLE = "devops-project-tracker"          # hard-coded source of truth
GAMMA_TABLE = "devops-project-tracker-gamma"
GAMMA_COUNTERS_TABLE = "enceladus-id-counters-gamma"
GAMMA_IDEMPOTENCY_TABLE = "enceladus-id-idempotency-gamma"
DEFAULT_REGION = "us-west-2"

BATCH_MAX = 25  # DynamoDB BatchWriteItem hard limit

Key = Tuple[str, str]


class DirectionLockError(RuntimeError):
    """Raised when the source/dest table wiring violates the mirror direction."""


def assert_direction_lock(source: str, dest: str, aux_tables: List[str]) -> None:
    """Abort unless data flows canonical → gamma. Source must be the canonical
    table verbatim; every mutated table must end in -gamma; source and dest may
    never be the same table."""
    if source != CANONICAL_TABLE:
        raise DirectionLockError(
            f"source table must be {CANONICAL_TABLE!r} verbatim, got {source!r}"
        )
    for t in [dest, *aux_tables]:
        if not t.endswith("-gamma"):
            raise DirectionLockError(
                f"write target {t!r} does not end in '-gamma' — refusing to mutate"
            )
    if dest == source:
        raise DirectionLockError("source and dest are the same table")


def item_key(item: Dict[str, Any]) -> Key:
    return (item["project_id"]["S"], item["record_id"]["S"])


def scan_table(client, table: str) -> Dict[Key, Dict[str, Any]]:
    items: Dict[Key, Dict[str, Any]] = {}
    kwargs: Dict[str, Any] = {"TableName": table, "ConsistentRead": True}
    while True:
        resp = client.scan(**kwargs)
        for it in resp.get("Items", []):
            items[item_key(it)] = it
        last = resp.get("LastEvaluatedKey")
        if not last:
            return items
        kwargs["ExclusiveStartKey"] = last


def compute_diff(
    canonical: Dict[Key, Dict[str, Any]], gamma: Dict[Key, Dict[str, Any]]
) -> Dict[str, List[Key]]:
    """Classify keys: adds (canonical-only), changed / unchanged (both), and
    deletes (gamma-only — the gamma-native records the mirror will destroy)."""
    adds, changed, unchanged, deletes = [], [], [], []
    for k, item in canonical.items():
        if k not in gamma:
            adds.append(k)
        elif gamma[k] == item:
            unchanged.append(k)
        else:
            changed.append(k)
    deletes = [k for k in gamma if k not in canonical]
    return {
        "adds": sorted(adds),
        "changed": sorted(changed),
        "unchanged": sorted(unchanged),
        "deletes": sorted(deletes),
    }


def _s(item: Dict[str, Any], attr: str) -> str:
    return item.get(attr, {}).get("S", "")


def build_manifest(
    diff: Dict[str, List[Key]],
    canonical: Dict[Key, Dict[str, Any]],
    gamma: Dict[Key, Dict[str, Any]],
    mode: str,
) -> Dict[str, Any]:
    delete_detail = []
    for k in diff["deletes"]:
        it = gamma[k]
        delete_detail.append(
            {
                "project_id": k[0],
                "record_id": k[1],
                "item_id": _s(it, "item_id"),
                "record_type": _s(it, "record_type"),
                "title": _s(it, "title")[:120],
                "created_at": _s(it, "created_at"),
                # a gamma-only key with a tracker item_id is a gamma-native mint —
                # exactly the ENC-ISS-538 collision class
                "gamma_native_record": bool(_s(it, "item_id")),
            }
        )
    changed_detail = [
        {"project_id": k[0], "record_id": k[1], "canonical_title": _s(canonical[k], "title")[:80]}
        for k in diff["changed"]
    ]
    return {
        "tool": "gamma-tracker-mirror",
        "task": "ENC-TSK-M98",
        "issue": "ENC-ISS-538",
        "mode": mode,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_table": CANONICAL_TABLE,
        "dest_table": GAMMA_TABLE,
        "counts": {
            "canonical_items": len(canonical),
            "gamma_items_before": len(gamma),
            "adds": len(diff["adds"]),
            "changed": len(diff["changed"]),
            "unchanged": len(diff["unchanged"]),
            "deletes": len(diff["deletes"]),
            "gamma_native_deletes": sum(1 for d in delete_detail if d["gamma_native_record"]),
        },
        "deletes": delete_detail,
        "changed": changed_detail,
    }


def snapshot_deletes(
    gamma: Dict[Key, Dict[str, Any]], deletes: List[Key], snapshot_dir: str
) -> Path:
    """Dump every to-be-deleted gamma item (full DynamoDB JSON) before deletion."""
    out_dir = Path(snapshot_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"gamma-mirror-predelete-{stamp}.jsonl"
    with open(path, "w") as fh:
        for k in deletes:
            fh.write(json.dumps(gamma[k], separators=(",", ":")) + "\n")
    return path


def upload_snapshot(s3_client, path: Path, s3_uri: str) -> str:
    if not s3_uri.startswith("s3://"):
        raise ValueError(f"--snapshot-s3-uri must start with s3://, got {s3_uri!r}")
    bucket, _, prefix = s3_uri[5:].partition("/")
    key = f"{prefix.rstrip('/')}/{path.name}" if prefix else path.name
    s3_client.upload_file(str(path), bucket, key)
    return f"s3://{bucket}/{key}"


def _batch_write(client, table: str, requests: List[Dict[str, Any]], throttle_ms: int) -> None:
    """BatchWriteItem in chunks of 25 with unprocessed-item retry + backoff."""
    for i in range(0, len(requests), BATCH_MAX):
        chunk = requests[i : i + BATCH_MAX]
        pending = {table: chunk}
        attempt = 0
        while pending:
            resp = client.batch_write_item(RequestItems=pending)
            pending = resp.get("UnprocessedItems") or {}
            if pending:
                attempt += 1
                if attempt > 8:
                    raise RuntimeError(f"batch_write_item to {table}: unprocessed items after 8 retries")
                time.sleep(min(2**attempt * 0.05, 2.0))
        if throttle_ms:
            time.sleep(throttle_ms / 1000.0)


def mirror_puts(client, canonical: Dict[Key, Dict[str, Any]], throttle_ms: int) -> None:
    reqs = [{"PutRequest": {"Item": it}} for it in canonical.values()]
    _batch_write(client, GAMMA_TABLE, reqs, throttle_ms)


def delete_extras(client, deletes: List[Key], throttle_ms: int) -> None:
    reqs = [
        {"DeleteRequest": {"Key": {"project_id": {"S": p}, "record_id": {"S": r}}}}
        for (p, r) in deletes
    ]
    _batch_write(client, GAMMA_TABLE, reqs, throttle_ms)


def wipe_table(client, table: str, throttle_ms: int = 0) -> int:
    """Delete every item in `table` (key schema discovered via describe_table).
    Used for the counter + idempotency reset (phase 3). Direction lock applies."""
    if not table.endswith("-gamma"):
        raise DirectionLockError(f"wipe_table refused: {table!r} does not end in '-gamma'")
    key_attrs = [k["AttributeName"] for k in client.describe_table(TableName=table)["Table"]["KeySchema"]]
    deleted = 0
    kwargs: Dict[str, Any] = {"TableName": table, "ConsistentRead": True}
    while True:
        resp = client.scan(**kwargs)
        items = resp.get("Items", [])
        if items:
            reqs = [
                {"DeleteRequest": {"Key": {a: it[a] for a in key_attrs}}} for it in items
            ]
            _batch_write(client, table, reqs, throttle_ms)
            deleted += len(items)
        last = resp.get("LastEvaluatedKey")
        if not last:
            return deleted
        kwargs["ExclusiveStartKey"] = last


def count_items(client, table: str) -> int:
    n = 0
    kwargs: Dict[str, Any] = {"TableName": table, "Select": "COUNT", "ConsistentRead": True}
    while True:
        resp = client.scan(**kwargs)
        n += resp["Count"]
        last = resp.get("LastEvaluatedKey")
        if not last:
            return n
        kwargs["ExclusiveStartKey"] = last


def verify(client) -> List[str]:
    problems = []
    canonical_n = count_items(client, CANONICAL_TABLE)
    gamma_n = count_items(client, GAMMA_TABLE)
    # canonical is live-minting; allow gamma <= canonical but never extras
    if gamma_n > canonical_n:
        problems.append(f"gamma has {gamma_n} items > canonical {canonical_n} — extras survived")
    if gamma_n < canonical_n:
        print(f"[INFO] canonical grew during mirror ({canonical_n} vs {gamma_n} mirrored) — expected drift, next sync picks it up")
    for t in (GAMMA_COUNTERS_TABLE, GAMMA_IDEMPOTENCY_TABLE):
        n = count_items(client, t)
        if n:
            problems.append(f"{t} still holds {n} items after wipe")
    return problems


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--execute", action="store_true",
                    help="Perform the mirror. WITHOUT this flag the tool is a dry run: scan + manifest only, zero writes.")
    ap.add_argument("--manifest-out", default="gamma-mirror-manifest.json")
    ap.add_argument("--snapshot-dir", default="mirror-snapshot",
                    help="Local dir receiving the pre-delete dump of doomed gamma items (execute mode).")
    ap.add_argument("--snapshot-s3-uri", default="",
                    help="Optional s3://bucket/prefix also receiving the pre-delete dump.")
    ap.add_argument("--region", default=DEFAULT_REGION)
    ap.add_argument("--throttle-ms", type=int, default=0,
                    help="Sleep between write batches (stream/CDC burst control, ENC-TSK-M99).")
    args = ap.parse_args(argv)

    try:
        assert_direction_lock(
            CANONICAL_TABLE, GAMMA_TABLE, [GAMMA_COUNTERS_TABLE, GAMMA_IDEMPOTENCY_TABLE]
        )
    except DirectionLockError as e:
        print(f"[ERROR] direction lock: {e}")
        return 2

    import boto3  # deferred so unit tests import this module without boto3 installed

    client = boto3.client("dynamodb", region_name=args.region)

    print(f"[START] scanning {CANONICAL_TABLE} + {GAMMA_TABLE}")
    canonical = scan_table(client, CANONICAL_TABLE)
    gamma = scan_table(client, GAMMA_TABLE)
    diff = compute_diff(canonical, gamma)
    mode = "execute" if args.execute else "dry-run"
    manifest = build_manifest(diff, canonical, gamma, mode)
    Path(args.manifest_out).write_text(json.dumps(manifest, indent=1))
    c = manifest["counts"]
    print(f"[INFO] canonical={c['canonical_items']} gamma={c['gamma_items_before']} "
          f"adds={c['adds']} changed={c['changed']} unchanged={c['unchanged']} "
          f"deletes={c['deletes']} (gamma-native {c['gamma_native_deletes']})")
    print(f"[INFO] manifest -> {args.manifest_out}")

    if not args.execute:
        print("[SUCCESS] dry run complete — no writes performed. Re-run with --execute via the io-gated workflow.")
        return 0

    if diff["deletes"]:
        snap = snapshot_deletes(gamma, diff["deletes"], args.snapshot_dir)
        print(f"[INFO] pre-delete snapshot -> {snap} ({len(diff['deletes'])} items)")
        if args.snapshot_s3_uri:
            import boto3 as _b3
            uri = upload_snapshot(_b3.client("s3", region_name=args.region), snap, args.snapshot_s3_uri)
            print(f"[INFO] snapshot uploaded -> {uri}")

    print(f"[INFO] phase 1: overwriting {len(canonical)} items into {GAMMA_TABLE}")
    mirror_puts(client, canonical, args.throttle_ms)
    print(f"[INFO] phase 2: deleting {len(diff['deletes'])} gamma-only items")
    delete_extras(client, diff["deletes"], args.throttle_ms)
    print(f"[INFO] phase 3: wiping {GAMMA_COUNTERS_TABLE} + {GAMMA_IDEMPOTENCY_TABLE}")
    n1 = wipe_table(client, GAMMA_COUNTERS_TABLE, args.throttle_ms)
    n2 = wipe_table(client, GAMMA_IDEMPOTENCY_TABLE, args.throttle_ms)
    print(f"[INFO] wiped counters={n1} idempotency={n2}")

    problems = verify(client)
    if problems:
        for p in problems:
            print(f"[ERROR] verify: {p}")
        return 3
    print("[SUCCESS] mirror complete: gamma == canonical snapshot; counters reset for cold-seed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
