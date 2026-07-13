#!/usr/bin/env python3
"""Apply equalized S3 lifecycle rules for rhythm-cycle beat artifacts (ENC-TSK-N49).

The jreese-net bucket is not owned by CloudFormation; lifecycle is applied via this
idempotent merge script during the gamma compute-stack deploy (CloudFormationDeployRole
has s3:Get/PutLifecycleConfiguration). Sense/decide tiers were aging out ~1 day while
light/heavy/coherence retained ~7 days — this equalizes all rhythm-cycle timestamped
artifacts to 7 days so ENC-ISS-553 / N44 harvesters retain sense+decide history.

Rules managed here use Id prefix ``RhythmArtifact-`` so re-runs replace prior
rhythm rules without clobbering unrelated bucket lifecycle rules.

Usage:
  python3 tools/apply_rhythm_artifact_lifecycle.py --dry-run
  python3 tools/apply_rhythm_artifact_lifecycle.py --bucket jreese-net --env-prefix gamma
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

import boto3

DEFAULT_BUCKET = "jreese-net"
DEFAULT_ENV_PREFIX = "gamma"
DEFAULT_PREFIX = "rhythm-cycle"
DEFAULT_RETENTION_DAYS = 7
TIERS = ("sense", "light_integrate", "decide", "heavy_integrate", "coherence")
RULE_ID_PREFIX = "RhythmArtifact-"


def _artifact_prefix(env_prefix: str, prefix: str) -> str:
    return "/".join(p.strip("/") for p in (env_prefix, prefix) if p.strip("/"))


def build_rhythm_rules(env_prefix: str, prefix: str, retention_days: int) -> List[Dict[str, Any]]:
    base = _artifact_prefix(env_prefix, prefix)
    rules = []
    for tier in TIERS:
        rules.append({
            "ID": f"{RULE_ID_PREFIX}{tier}",
            "Status": "Enabled",
            "Filter": {"Prefix": f"{base}/{tier}/"},
            "Expiration": {"Days": retention_days},
        })
    # Tenant completion stanzas under heavy_integrate/tenant-results/
    rules.append({
        "ID": f"{RULE_ID_PREFIX}tenant-results",
        "Status": "Enabled",
        "Filter": {"Prefix": f"{base}/heavy_integrate/tenant-results/"},
        "Expiration": {"Days": retention_days},
    })
    return rules


def merge_lifecycle(existing: Dict[str, Any], rhythm_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    kept = [
        r for r in (existing.get("Rules") or [])
        if not str(r.get("ID", "")).startswith(RULE_ID_PREFIX)
    ]
    return {"Rules": kept + rhythm_rules}


def apply(bucket: str, env_prefix: str, prefix: str, retention_days: int, *, dry_run: bool) -> Dict[str, Any]:
    s3 = boto3.client("s3")
    rhythm_rules = build_rhythm_rules(env_prefix, prefix, retention_days)
    try:
        existing = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
    except s3.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchLifecycleConfiguration", "NoSuchBucket"):
            existing = {}
        else:
            raise
    merged = merge_lifecycle(existing, rhythm_rules)
    summary = {
        "bucket": bucket,
        "artifact_prefix": _artifact_prefix(env_prefix, prefix),
        "retention_days": retention_days,
        "rhythm_rule_ids": [r["ID"] for r in rhythm_rules],
        "total_rules_after": len(merged["Rules"]),
        "dry_run": dry_run,
    }
    if dry_run:
        summary["would_apply"] = merged
        return summary
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=merged)
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Equalize rhythm-cycle S3 artifact retention.")
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    parser.add_argument("--env-prefix", default=DEFAULT_ENV_PREFIX)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = apply(
            args.bucket,
            args.env_prefix,
            args.prefix,
            args.retention_days,
            dry_run=args.dry_run,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
