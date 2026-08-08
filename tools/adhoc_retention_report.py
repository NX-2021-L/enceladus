#!/usr/bin/env python3
"""Ad-hoc namespace quota, retention and disk-safety report.

DVP-TSK-663. BRD B5-R5, and the R-5 detector.

Ad-hoc is the platform's only write surface, on a host with a chronic memory
ceiling. Disk is ample today, but catalog and prefix sprawl grow silently, and
the specific thing that must stay visible is **R-5: adhoc growth without
corresponding promotions** -- a quarantine namespace quietly becoming the
production warehouse (DOC-325D4FB98208).

Two design decisions here are deliberate and load-bearing.

**Removal is never blind, so it is never an S3 lifecycle Expiration rule.**
The bucket lifecycle configuration on devops-agentcli-compute carries exactly one
rule for this prefix -- AbortIncompleteMultipartUpload after 7 days, which is
pure garbage collection and can never destroy a committed object. It carries no
Expiration action, on purpose. An Expiration rule cannot know whether a table
backs a live Superset dataset, so enabling one would delete a table io is
actively charting from, which is precisely what the B5-R5 exemption clause
exists to prevent. Retention is therefore enforced as FLAG-then-remove through
this report, where reference state is knowable, rather than as a blind timer in
S3 where it is not.

**A referenced table is exempt from removal but is NEVER exempt from the
report.** It appears under ``promotion_candidates`` instead. That inversion is
the whole point: durable ad-hoc content should become a visible prompt to take
the B4-R4 promotion path, not an invisible permanent fixture. A table that is
both old and actively used is the strongest promotion signal the platform has,
so hiding it would suppress exactly the signal worth acting on.

Reference state is fail-safe. When the set of Superset-referenced tables cannot
be determined, every table is treated as REFERENCED -- nothing is ever proposed
for removal on missing information.

Usage::

    python3 tools/adhoc_retention_report.py [--json] [--referenced t1,t2]

Read-only. This script proposes; it does not delete.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Set

ADHOC_DATABASE = os.environ.get("ADHOC_DATABASE", "adhoc")
ADHOC_BUCKET = os.environ.get("ADHOC_BUCKET", "devops-agentcli-compute")
ADHOC_PREFIX = os.environ.get("ADHOC_PREFIX", "adhoc")

# ---------------------------------------------------------------------------
# Adopted defaults -- AWAITING IO RATIFICATION (DOC-325D4FB98208).
#
# These were chosen by an agent under io's standing instruction to make a
# reasonable call rather than block, and they are NOT yet io-authored. The
# report prints that status on every run rather than letting the provenance of
# these numbers quietly fade into looking like policy.
# ---------------------------------------------------------------------------
RETENTION_DAYS = int(os.environ.get("ADHOC_RETENTION_DAYS", "90"))
QUOTA_BYTES = int(os.environ.get("ADHOC_QUOTA_GB", "50")) * 1024**3
QUOTA_OBJECTS = int(os.environ.get("ADHOC_QUOTA_OBJECTS", "5000"))
MAX_FILE_BYTES = int(os.environ.get("ADHOC_MAX_FILE_MB", "512")) * 1024**2
DEFAULTS_RATIFIED_BY_IO = False

#: Where the time series lands, so successive observations are comparable and
#: R-5 is detectable from two runs rather than from memory. Sibling of the
#: namespace, never a child of it -- a JSON sidecar under adhoc/ would be read
#: as a corrupt table object, the same reasoning as the library's
#: registration_prefix.
SERIES_PREFIX = "adhoc-retention-reports"


def _client(service: str):
    import boto3
    from botocore.config import Config

    return boto3.client(
        service,
        region_name=os.environ.get("AWS_REGION", "us-west-2"),
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def list_objects(s3, bucket: str, prefix: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix.rstrip("/") + "/"}
        if token:
            kwargs["ContinuationToken"] = token
        response = s3.list_objects_v2(**kwargs)
        out.extend(response.get("Contents", []) or [])
        if not response.get("IsTruncated"):
            return out
        token = response.get("NextContinuationToken")


def _table_of(key: str, prefix: str) -> str:
    remainder = key[len(prefix.rstrip("/")) + 1 :]
    return remainder.split("/", 1)[0] if "/" in remainder else remainder


def build_report(
    s3,
    glue,
    referenced: Optional[Set[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = now or _now()
    objects = list_objects(s3, ADHOC_BUCKET, ADHOC_PREFIX)

    tables: Dict[str, Dict[str, Any]] = {}
    oversized: List[Dict[str, Any]] = []
    total_bytes = 0

    for entry in objects:
        key = entry["Key"]
        size = int(entry.get("Size") or 0)
        modified = entry.get("LastModified")
        if hasattr(modified, "tzinfo") and modified.tzinfo is None:
            modified = modified.replace(tzinfo=timezone.utc)
        total_bytes += size
        name = _table_of(key, ADHOC_PREFIX)
        bucket_entry = tables.setdefault(
            name, {"table": name, "bytes": 0, "objects": 0, "last_modified": None}
        )
        bucket_entry["bytes"] += size
        bucket_entry["objects"] += 1
        if bucket_entry["last_modified"] is None or modified > bucket_entry["last_modified"]:
            bucket_entry["last_modified"] = modified

        # Criterion: per-file size limit. Reported per object, because the limit
        # is about a single upload rather than about the namespace.
        if size > MAX_FILE_BYTES:
            oversized.append({"key": key, "bytes": size, "limit_bytes": MAX_FILE_BYTES})

    # Reference state is FAIL-SAFE: unknown means referenced, so nothing is ever
    # proposed for removal on missing information.
    reference_known = referenced is not None
    referenced = referenced or set()

    cutoff = now - timedelta(days=RETENTION_DAYS)
    flagged_for_removal: List[Dict[str, Any]] = []
    promotion_candidates: List[Dict[str, Any]] = []
    rows: List[Dict[str, Any]] = []

    for name, data in sorted(tables.items()):
        modified = data["last_modified"]
        age_days = (now - modified).days if modified else 0
        is_referenced = (not reference_known) or (name in referenced)
        stale = bool(modified and modified < cutoff)
        row = {
            "table": name,
            "bytes": data["bytes"],
            "objects": data["objects"],
            "age_days": age_days,
            "last_modified": modified.isoformat().replace("+00:00", "Z") if modified else "",
            "referenced_by_superset": is_referenced,
            "reference_state_known": reference_known,
            "past_retention_window": stale,
        }
        rows.append(row)

        if stale and is_referenced:
            # Exempt from removal, and for that exact reason it belongs on the
            # report: old AND in use is the strongest promotion signal there is.
            promotion_candidates.append(
                dict(
                    row,
                    reason=(
                        "past the %d-day retention window and still referenced by a live "
                        "Superset dataset. Exempt from automatic removal -- and that is "
                        "precisely why it should be promoted (B4-R4) rather than left as a "
                        "permanent fixture in quarantine."
                        % RETENTION_DAYS
                        if reference_known
                        else "past the %d-day retention window; reference state could not be "
                        "determined, so it is treated as referenced and exempted."
                        % RETENTION_DAYS
                    ),
                )
            )
        elif stale:
            flagged_for_removal.append(
                dict(
                    row,
                    reason=(
                        "past the %d-day retention window and referenced by no live Superset "
                        "dataset. FLAGGED -- removal is a separate, deliberate step."
                        % RETENTION_DAYS
                    ),
                )
            )

    object_count = len(objects)
    return {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "namespace": {
            "glue_database": ADHOC_DATABASE,
            "s3_uri": "s3://%s/%s/" % (ADHOC_BUCKET, ADHOC_PREFIX),
        },
        "policy": {
            "retention_days": RETENTION_DAYS,
            "quota_bytes": QUOTA_BYTES,
            "quota_objects": QUOTA_OBJECTS,
            "max_file_bytes": MAX_FILE_BYTES,
            "ratified_by_io": DEFAULTS_RATIFIED_BY_IO,
            "status": (
                "AGENT-ADOPTED, AWAITING IO RATIFICATION (DOC-325D4FB98208). These numbers "
                "were not handed down from a spec."
            ),
            "automatic_expiry_enabled": False,
            "automatic_expiry_note": (
                "No S3 lifecycle Expiration rule exists for this prefix, deliberately: a "
                "blind timer cannot know whether a table backs a live Superset dataset and "
                "would delete exactly the tables B5-R5 exempts. The only lifecycle rule is "
                "AbortIncompleteMultipartUpload after 7 days."
            ),
        },
        # R-5 detection surface. Growth is only meaningful against promotions,
        # so both are counted and reported side by side.
        "usage": {
            "total_bytes": total_bytes,
            "total_objects": object_count,
            "table_count": len(tables),
            "quota_bytes_used_pct": round(100.0 * total_bytes / QUOTA_BYTES, 3)
            if QUOTA_BYTES
            else 0.0,
            "quota_objects_used_pct": round(100.0 * object_count / QUOTA_OBJECTS, 3)
            if QUOTA_OBJECTS
            else 0.0,
            "over_byte_quota": total_bytes > QUOTA_BYTES,
            "over_object_quota": object_count > QUOTA_OBJECTS,
        },
        "per_file_limit_violations": oversized,
        "tables": rows,
        "flagged_for_removal": flagged_for_removal,
        "promotion_candidates": promotion_candidates,
    }


def emit_series_record(s3, report: Dict[str, Any]) -> str:
    """Persist one observation so R-5 is detectable across runs, not from memory."""
    key = "%s/%s.json" % (SERIES_PREFIX, report["generated_at"].replace(":", ""))
    s3.put_object(
        Bucket=ADHOC_BUCKET,
        Key=key,
        Body=json.dumps(
            {
                "generated_at": report["generated_at"],
                "usage": report["usage"],
                "flagged_count": len(report["flagged_for_removal"]),
                "promotion_candidate_count": len(report["promotion_candidates"]),
            },
            sort_keys=True,
        ).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    return key


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return str(n)


def render(report: Dict[str, Any]) -> str:
    usage = report["usage"]
    lines = [
        "Ad-hoc namespace retention & quota report  (%s)" % report["generated_at"],
        "  namespace : %s  /  glue db `%s`"
        % (report["namespace"]["s3_uri"], report["namespace"]["glue_database"]),
        "  policy    : retention %dd, quota %s / %d objects, per-file max %s"
        % (
            report["policy"]["retention_days"],
            _human(report["policy"]["quota_bytes"]),
            report["policy"]["quota_objects"],
            _human(report["policy"]["max_file_bytes"]),
        ),
        "  RATIFIED BY IO: %s  <-- %s"
        % (report["policy"]["ratified_by_io"], report["policy"]["status"]),
        "",
        "  usage     : %s (%.3f%% of quota), %d objects (%.3f%%), %d tables"
        % (
            _human(usage["total_bytes"]),
            usage["quota_bytes_used_pct"],
            usage["total_objects"],
            usage["quota_objects_used_pct"],
            usage["table_count"],
        ),
        "  over quota: bytes=%s objects=%s"
        % (usage["over_byte_quota"], usage["over_object_quota"]),
        "  per-file limit violations: %d" % len(report["per_file_limit_violations"]),
        "",
        "  flagged for removal (stale AND unreferenced): %d"
        % len(report["flagged_for_removal"]),
    ]
    for row in report["flagged_for_removal"]:
        lines.append("     - %s (%d days, %s)" % (row["table"], row["age_days"], _human(row["bytes"])))
    lines.append(
        "  PROMOTION CANDIDATES (stale but referenced -- exempt from removal, still shown): %d"
        % len(report["promotion_candidates"])
    )
    for row in report["promotion_candidates"]:
        lines.append("     - %s (%d days, %s)" % (row["table"], row["age_days"], _human(row["bytes"])))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the raw report")
    parser.add_argument(
        "--referenced",
        default=None,
        help="comma-separated tables backing a live Superset dataset. Omit and every "
        "table is treated as referenced (fail-safe: nothing is proposed for removal).",
    )
    parser.add_argument(
        "--emit-series",
        action="store_true",
        help="persist this observation to the time series so R-5 is detectable across runs",
    )
    args = parser.parse_args(argv)

    referenced = (
        {t.strip() for t in args.referenced.split(",") if t.strip()}
        if args.referenced is not None
        else None
    )
    s3, glue = _client("s3"), _client("glue")
    report = build_report(s3, glue, referenced=referenced)
    if args.emit_series:
        report["series_key"] = emit_series_record(s3, report)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
