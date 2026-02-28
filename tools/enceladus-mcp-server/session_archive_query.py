#!/usr/bin/env python3
"""Query and replay coordination session archive objects from S3.

Supports:
- fetch by --session-id
- list by --date / --start-date --end-date
- output modes: raw, replay, summary
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
from typing import Dict, Iterable, List

import boto3


def _parse_date(value: str) -> dt.date:
    return dt.datetime.strptime(value, "%Y-%m-%d").date()


def _iter_dates(start: dt.date, end: dt.date) -> Iterable[dt.date]:
    current = start
    while current <= end:
        yield current
        current += dt.timedelta(days=1)


def _load_records(s3, *, bucket: str, key: str) -> List[Dict]:
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj["Body"].read()
    if key.endswith(".gz"):
        data = gzip.decompress(data)
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    payload = json.loads(text)
    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _list_keys_for_session(s3, *, bucket: str, prefix: str, session_id: str) -> List[str]:
    keys: List[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix.rstrip("/") + "/"):
        for item in page.get("Contents", []):
            key = str(item.get("Key") or "")
            if f"/{session_id}/" in key and key.endswith((".json", ".json.gz", ".jsonl", ".jsonl.gz")):
                keys.append(key)
    return sorted(keys)


def _list_keys_for_date_range(
    s3,
    *,
    bucket: str,
    prefix: str,
    start_date: dt.date,
    end_date: dt.date,
) -> List[str]:
    keys: List[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for day in _iter_dates(start_date, end_date):
        day_prefix = f"{prefix.rstrip('/')}/{day.year:04d}/{day.month:02d}/{day.day:02d}/"
        for page in paginator.paginate(Bucket=bucket, Prefix=day_prefix):
            for item in page.get("Contents", []):
                key = str(item.get("Key") or "")
                if key.endswith((".json", ".json.gz", ".jsonl", ".jsonl.gz")):
                    keys.append(key)
    return sorted(keys)


def _render_raw(records: List[Dict]) -> None:
    for record in records:
        print(json.dumps(record, ensure_ascii=False))


def _render_replay(records: List[Dict]) -> None:
    for record in records:
        role = str(record.get("role") or "unknown").upper()
        ts = str(record.get("timestamp_utc") or "")
        content = str(record.get("content") or "")
        print(f"[{ts}] {role}: {content}")


def _render_summary(records: List[Dict]) -> None:
    if not records:
        print(json.dumps({"turn_count": 0}))
        return
    session_id = str(records[0].get("session_id") or "")
    timestamps = [str(r.get("timestamp_utc") or "") for r in records if r.get("timestamp_utc")]
    payload = {
        "session_id": session_id,
        "turn_count": len(records),
        "start_timestamp_utc": min(timestamps) if timestamps else "",
        "end_timestamp_utc": max(timestamps) if timestamps else "",
    }
    print(json.dumps(payload, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description="Query/replay coordination session archives from S3")
    parser.add_argument("--bucket", default="jreese-net")
    parser.add_argument("--prefix", default="codex-sessions")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--session-id", help="Fetch and replay a single session id")
    parser.add_argument("--date", help="Single date (YYYY-MM-DD)")
    parser.add_argument("--start-date", help="Range start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="Range end date (YYYY-MM-DD)")
    parser.add_argument("--output", choices=("raw", "replay", "summary"), default="replay")
    args = parser.parse_args()

    if not args.session_id and not args.date and not (args.start_date and args.end_date):
        parser.error("Provide --session-id OR --date OR both --start-date and --end-date")

    s3 = boto3.client("s3", region_name=args.region)

    keys: List[str] = []
    if args.session_id:
        keys = _list_keys_for_session(s3, bucket=args.bucket, prefix=args.prefix, session_id=args.session_id)
    elif args.date:
        day = _parse_date(args.date)
        keys = _list_keys_for_date_range(s3, bucket=args.bucket, prefix=args.prefix, start_date=day, end_date=day)
    else:
        start = _parse_date(args.start_date)
        end = _parse_date(args.end_date)
        keys = _list_keys_for_date_range(s3, bucket=args.bucket, prefix=args.prefix, start_date=start, end_date=end)

    records: List[Dict] = []
    for key in keys:
        records.extend(_load_records(s3, bucket=args.bucket, key=key))
    records.sort(key=lambda item: (str(item.get("session_id") or ""), int(item.get("turn_index") or 0)))

    if args.output == "raw":
        _render_raw(records)
    elif args.output == "summary":
        _render_summary(records)
    else:
        _render_replay(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

