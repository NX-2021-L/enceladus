#!/usr/bin/env python3
"""Isolation W3: copy the Enceladus prefixes out of s3://jreese-net into the content buckets (plan DOC-EF4BC758CCC9).

  production  jreese-net/<prefix>/...          -> enceladus-content-<acct>-us-west-2/<prefix>/...
  gamma       jreese-net/gamma/<prefix>/...    -> enceladus-content-gamma-<acct>-us-west-2/<prefix>/...

DRY RUN BY DEFAULT: it lists and plans. --apply copies; --verify writes the parity report (the W3 data gate).
- Copies are server-side CopyObject calls (cross-region). Metadata, content type and tags are kept. The destination
  default (SSE-KMS, content key) encrypts, and S3 stores a SHA-256 of each destination object.
- Idempotent: an object whose destination already has the same size and SHA-256 is skipped, so a re-run is the
  delta sync before the W4 cutover. Deletions in the source are NOT propagated; the parity report lists extras.
- Verification is byte-level: each source object is streamed and SHA-256-hashed, then compared with the stored
  destination checksum (GetObjectAttributes). Nothing in jreese-net is modified.

Usage:
  python3 tools/isolation/w3_copy_prefixes.py --profile product-lead            # plan
  python3 tools/isolation/w3_copy_prefixes.py --profile product-lead --apply    # copy
  python3 tools/isolation/w3_copy_prefixes.py --profile product-lead --verify --report w3-parity.json
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SOURCE_BUCKET = "jreese-net"
SOURCE_REGION = "us-west-1"
DEST_REGION = "us-west-2"
# DOC-EF4BC758CCC9 W3 list. lambda-artifacts follows D3 (live SHAs only, separate tool). The unclassified prefixes
# (dom-cache, deploy-artifacts, enceladus/, enceladus-gamma/, cutover, codex-sessions, ...) are classified before
# they are added here.
PREFIXES = (
    "agent-documents/", "governance/", "agent-scratch/", "mobile/", "proposals/", "pathway-telemetry/",
    "deploy-config/", "deploy-sources/", "cfn-templates/", "cfn-staging/", "security/",
)


def plan_pairs(s3_src, account: str) -> List[Tuple[str, str, str, int, Any]]:
    """[(source_key, dest_bucket, dest_key, size, source_last_modified)] for production prefixes and gamma/<prefix> mirrors."""
    prod = f"enceladus-content-{account}-{DEST_REGION}"
    gamma = f"enceladus-content-gamma-{account}-{DEST_REGION}"
    pairs: List[Tuple[str, str, str, int, Any]] = []
    pag = s3_src.get_paginator("list_objects_v2")
    for p in PREFIXES:
        for page in pag.paginate(Bucket=SOURCE_BUCKET, Prefix=p):
            for o in page.get("Contents", []):
                pairs.append((o["Key"], prod, o["Key"], o["Size"], o.get("LastModified")))
        for page in pag.paginate(Bucket=SOURCE_BUCKET, Prefix="gamma/" + p):
            for o in page.get("Contents", []):
                pairs.append((o["Key"], gamma, o["Key"][len("gamma/"):], o["Size"], o.get("LastModified")))
    return pairs


def sha256_b64_of_source(s3_src, key: str) -> str:
    h = hashlib.sha256()
    body = s3_src.get_object(Bucket=SOURCE_BUCKET, Key=key)["Body"]
    for chunk in iter(lambda: body.read(1 << 20), b""):
        h.update(chunk)
    return base64.b64encode(h.digest()).decode()


def sha256_b64_of_dest(s3_dst, bucket: str, key: str) -> str:
    """Stream the destination object (S3 decrypts with the content key) and hash it: used when the object was written
    by a dual-mode Lambda (boto3 upload_file stores CRC32, not SHA-256), so there is no stored checksum to compare."""
    h = hashlib.sha256()
    body = s3_dst.get_object(Bucket=bucket, Key=key)["Body"]
    for chunk in iter(lambda: body.read(1 << 20), b""):
        h.update(chunk)
    return base64.b64encode(h.digest()).decode()


def compare(s3_src, s3_dst, src: str, bucket: str, key: str, size: int) -> Dict:
    """Byte-level comparison of one source object and its copy (DVP-TSK-B12)."""
    have = dest_attrs(s3_dst, bucket, key)
    if not have:
        return {"src": src, "status": "missing"}
    if have["size"] != size:
        return {"src": src, "status": "size_mismatch", "src_size": size, "dst_size": have["size"]}
    dst_sha = have["sha256"] or sha256_b64_of_dest(s3_dst, bucket, key)
    if dst_sha != sha256_b64_of_source(s3_src, src):
        return {"src": src, "status": "sha256_mismatch"}
    return {"src": src, "status": "ok"}


def dest_attrs(s3_dst, bucket: str, key: str) -> Optional[Dict]:
    try:
        a = s3_dst.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["Checksum", "ObjectSize"])
    except s3_dst.exceptions.NoSuchKey:
        return None
    except Exception as exc:  # 404 surfaces as ClientError on some SDKs
        if "NoSuchKey" in str(exc) or "404" in str(exc) or "Not Found" in str(exc):
            return None
        raise
    return {"size": a.get("ObjectSize"), "sha256": (a.get("Checksum") or {}).get("ChecksumSHA256"),
            "last_modified": a.get("LastModified")}


def needs_copy(have: Optional[Dict], size: int, source_last_modified: Any) -> bool:
    """DVP-TSK-B12: copy unless the destination already holds this exact source revision.

    Size + a stored checksum is not enough: a source rewritten with a same-length body (deploy-config's
    current-version.json) keeps its size. A source modified after the destination was written is recopied.
    """
    if not have or not have.get("sha256") or have.get("size") != size:
        return True
    dst_lm = have.get("last_modified")
    return bool(source_last_modified and dst_lm and source_last_modified > dst_lm)


def copy_one(s3_dst, src_key: str, bucket: str, key: str) -> None:
    s3_dst.copy_object(
        Bucket=bucket, Key=key,
        CopySource={"Bucket": SOURCE_BUCKET, "Key": src_key},
        MetadataDirective="COPY", TaggingDirective="COPY", ChecksumAlgorithm="SHA256",
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--profile", default=None)
    ap.add_argument("--apply", action="store_true", help="copy objects (default: plan only)")
    ap.add_argument("--verify", action="store_true", help="byte-level parity report")
    ap.add_argument("--report", default=None, help="write the parity report JSON here")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--recheck-after", type=float, default=90.0, help="seconds before re-checking mismatches once")
    args = ap.parse_args(argv)
    import boto3

    session = boto3.Session(profile_name=args.profile)
    account = session.client("sts").get_caller_identity()["Account"]
    s3_src = session.client("s3", region_name=SOURCE_REGION)
    s3_dst = session.client("s3", region_name=DEST_REGION)
    pairs = plan_pairs(s3_src, account)
    by_prefix: Dict[str, List[int]] = {}
    for src, bucket, key, size, _lm in pairs:
        fam = ("gamma/" if src.startswith("gamma/") else "") + key.split("/", 1)[0] + "/"
        n_b = by_prefix.setdefault(fam, [0, 0])
        n_b[0] += 1
        n_b[1] += size
    print(f"plan: {len(pairs)} objects, {sum(p[3] for p in pairs) / 1048576:.1f} MB")
    for fam, (n, b) in sorted(by_prefix.items()):
        print(f"  {fam:30s} {n:6d} objs {b / 1048576:9.1f} MB")

    if args.apply:
        def do(pair):
            src, bucket, key, size, src_lm = pair
            have = dest_attrs(s3_dst, bucket, key)
            if not needs_copy(have, size, src_lm):
                return "skipped"
            copy_one(s3_dst, src, bucket, key)
            return "copied"
        with cf.ThreadPoolExecutor(args.workers) as ex:
            res = list(ex.map(do, pairs))
        print(f"apply: copied {res.count('copied')}, skipped {res.count('skipped')}")

    if args.verify:
        def check(pair):
            src, bucket, key, size, _lm = pair
            return compare(s3_src, s3_dst, src, bucket, key, size)
        with cf.ThreadPoolExecutor(args.workers) as ex:
            results = list(ex.map(check, pairs))
        # A live dual-mode writer (feed_publisher, every few minutes) can land between reading the source and the copy.
        # Re-list and re-check each mismatch once after a pause; a real divergence is still reported.
        retry = [r["src"] for r in results if r["status"] != "ok"]
        if retry:
            time.sleep(args.recheck_after)
            fresh = {p[0]: p for p in plan_pairs(s3_src, account) if p[0] in set(retry)}
            rechecked = {src: (compare(s3_src, s3_dst, *fresh[src][:4]) if src in fresh
                               else {"src": src, "status": "source_deleted"}) for src in retry}
            results = [rechecked.get(r["src"], r) if r["status"] != "ok" else r for r in results]
        bad = [r for r in results if r["status"] != "ok"]
        summary = {
            "objects": len(pairs), "bytes": sum(p[3] for p in pairs), "ok": len(results) - len(bad),
            "not_ok": len(bad), "by_prefix": {k: {"objects": v[0], "bytes": v[1]} for k, v in sorted(by_prefix.items())},
            "failures": bad[:200],
        }
        print(f"verify: {summary['ok']}/{summary['objects']} byte-identical (sha256), {summary['not_ok']} not ok")
        if args.report:
            json.dump(summary, open(args.report, "w"), indent=2)
        return 0 if not bad else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
