#!/usr/bin/env python3
"""Isolation W1 traffic report (DVP-TSK-A96, plan DOC-EF4BC758CCC9).

Reads the Enceladus-owned observation bucket and reports who still reaches Enceladus through jreese.net:

  cf/jreese.net/   CloudFront standard logs for E2BOQXCW1TA6Y4 (jreese.net, www, cast)
  s3/jreese-net/   S3 server access logs for s3://jreese-net

Sections:
  1. jreese.net requests on Enceladus paths (/api/v1/*, /mobile/v1/*, /.well-known/oauth-*, /enceladus*),
     grouped by path family, status, user agent and referer;
  2. jreese-net object access on the Enceladus prefixes, grouped by prefix, operation and requester
     (IAM principal; anonymous requests show as "-").

The W7 gate (strip jreese.net) needs 7 consecutive days with zero Enceladus traffic in section 1.
Read-only. Client IPs are counted, never printed.

Usage:
  python3 tools/isolation/w1_traffic_report.py --profile product-lead [--days 7] [--out report.md]
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import io
import shlex
import sys
from typing import Dict, Iterable, List, Optional, Tuple

BUCKET_FMT = "enceladus-observe-logs-{account}-us-west-1"
CF_PREFIX = "cf/jreese.net/"
S3_PREFIX = "s3/jreese-net/"

ENCELADUS_PATHS = ("/api/v1/", "/mobile/v1/", "/.well-known/oauth-", "/enceladus")
ENCELADUS_PREFIXES = (
    "agent-documents/", "governance/", "agent-scratch/", "mobile/", "proposals/", "pathway-telemetry/",
    "deploy-config/", "deploy-sources/", "cfn-templates/", "security/", "lambda-artifacts/", "neo4j-backups/",
    "gamma/",
)


def path_family(uri: str) -> Optional[str]:
    for p in ENCELADUS_PATHS:
        if uri.startswith(p):
            if p == "/api/v1/":
                rest = uri[len(p):].split("/", 1)[0]
                return f"/api/v1/{rest}"
            return p.rstrip("/") + ("*" if p.endswith("-") else "/*")
    return None


def s3_family(key: str) -> Optional[str]:
    for p in ENCELADUS_PREFIXES:
        if key.startswith(p):
            if p == "gamma/":
                sub = key[len(p):].split("/", 1)[0]
                return f"gamma/{sub}/"
            return p
    return None


def parse_cloudfront(lines: Iterable[str]) -> Iterable[Dict[str, str]]:
    """CloudFront standard log: '#Fields:' header then tab-separated rows."""
    fields: List[str] = []
    for line in lines:
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            continue
        if not line.strip() or line.startswith("#") or not fields:
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) == len(fields):
            yield dict(zip(fields, cols))


def parse_s3_access(line: str) -> Optional[Dict[str, str]]:
    """S3 server access log line: space-delimited, [time] bracketed, quoted request/UA."""
    try:
        line = line.replace("[", '"').replace("]", '"', 1)
        parts = shlex.split(line)
    except ValueError:
        return None
    if len(parts) < 10:
        return None
    # owner bucket [time] remote_ip requester request_id operation key "request_uri" status error bytes size
    # total_ms turnaround_ms "referer" "user_agent" ...
    return {"time": parts[2], "requester": parts[4], "operation": parts[6], "key": parts[7], "status": parts[9],
            "ua": parts[16] if len(parts) > 16 else ""}


def iter_objects(s3, bucket: str, prefix: str, since: dt.datetime):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] >= since:
                yield obj["Key"]


def read_lines(s3, bucket: str, key: str) -> List[str]:
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    if key.endswith(".gz"):
        body = gzip.GzipFile(fileobj=io.BytesIO(body)).read()
    return body.decode("utf-8", errors="replace").splitlines()


def report(cf_rows: Iterable[Dict[str, str]], s3_rows: Iterable[Dict[str, str]], days: int) -> str:
    cf = collections.Counter()
    cf_ua = collections.defaultdict(collections.Counter)
    cf_ref = collections.defaultdict(collections.Counter)
    cf_ips = collections.defaultdict(set)
    cf_days = collections.defaultdict(int)
    cf_total = 0
    for r in cf_rows:
        cf_total += 1
        fam = path_family(r.get("cs-uri-stem", ""))
        if not fam:
            continue
        key = (fam, r.get("sc-status", ""))
        cf[key] += 1
        cf_ua[fam][r.get("cs(User-Agent)", "-")[:80]] += 1
        cf_ref[fam][r.get("cs(Referer)", "-")[:80]] += 1
        cf_ips[fam].add(r.get("c-ip", ""))
        cf_days[r.get("date", "")] += 1
    s3c = collections.Counter()
    s3_total = 0
    for r in s3_rows:
        s3_total += 1
        fam = s3_family(r.get("key", ""))
        if fam:
            s3c[(fam, r.get("operation", ""), r.get("requester", "-"))] += 1

    out = [f"# Isolation W1 traffic report (last {days} days)", ""]
    out.append(f"jreese.net CloudFront rows read: {cf_total}; Enceladus-path requests: {sum(cf.values())}")
    out.append("")
    out.append("## 1. jreese.net requests on Enceladus paths")
    if not cf:
        out.append("")
        out.append("None in the window.")
    for (fam, status), n in sorted(cf.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append(f"- `{fam}` status {status}: {n} requests")
    for fam in sorted(cf_ua):
        out.append(f"  - {fam}: {len(cf_ips[fam])} distinct client IPs; top user agents "
                   + "; ".join(f"{ua} ({n})" for ua, n in cf_ua[fam].most_common(3))
                   + "; top referers " + "; ".join(f"{rf} ({n})" for rf, n in cf_ref[fam].most_common(3)))
    if cf_days:
        out.append("- by day: " + ", ".join(f"{d} {n}" for d, n in sorted(cf_days.items())))
    out.append("")
    out.append(f"## 2. s3://jreese-net access on Enceladus prefixes (rows read: {s3_total})")
    if not s3c:
        out.append("")
        out.append("None in the window.")
    for (fam, op, who), n in sorted(s3c.items(), key=lambda kv: (-kv[1], kv[0]))[:80]:
        out.append(f"- `{fam}` {op} by {who}: {n}")
    out.append("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--profile", default=None)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    import boto3

    session = boto3.Session(profile_name=args.profile, region_name="us-west-1")
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = BUCKET_FMT.format(account=account)
    s3 = session.client("s3")
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.days)

    def cf_rows():
        for key in iter_objects(s3, bucket, CF_PREFIX, since):
            yield from parse_cloudfront(read_lines(s3, bucket, key))

    def s3_rows():
        for key in iter_objects(s3, bucket, S3_PREFIX, since):
            for line in read_lines(s3, bucket, key):
                row = parse_s3_access(line)
                if row:
                    yield row

    text = report(cf_rows(), s3_rows(), args.days)
    if args.out:
        open(args.out, "w").write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
