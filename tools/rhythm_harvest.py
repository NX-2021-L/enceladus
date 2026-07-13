#!/usr/bin/env python3
"""Rhythm-cycle MAXIMAL raw-data harvester (read-only).

Dumps the theoretical maximum of raw data about every rhythm cycle + tenant into
a structured local bundle, so downstream analysis (intelligence / tuning /
schedule questions) can be done against ground truth. Read-only: S3 Get/List,
CloudWatch GetMetricStatistics/ListMetrics, DynamoDB Scan, AppConfig read, IAM
get-role-policy. No mutations.

Output tree (under --out):
  s3/<tier|tenant-results>/...           every beat artifact + tenant stanza (verbatim)
  cloudwatch/<namespace>.json            every metric, every dimension set, full series
  cloudwatch/lambda.json                 AWS/Lambda Invocations/Errors/Duration/Throttles per fn
  ddb/percolation_telemetry.json         full table scan
  config/*.json                          live AppConfig manifest, feature-flags, IAM role snapshot
  aggregates/<...>.json                  flattened time-series per tier/metric for charting
  INDEX.json                             manifest of everything harvested + counts

Usage:
  python3 tools/rhythm_harvest.py
  python3 tools/rhythm_harvest.py --out /Users/jreese/rhythm-analysis
  python3 tools/rhythm_harvest.py --env-prefix gamma --days 60
  python3 tools/rhythm_harvest.py --region us-west-2 --bucket jreese-net --prefix rhythm-cycle

The full S3 key prefix is <env-prefix>/<prefix> (default gamma/rhythm-cycle). Each
harvest stage is isolated: a failure in one stage is recorded in INDEX.json and the
remaining stages still run.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import boto3

DEFAULT_REGION = "us-west-2"
DEFAULT_BUCKET = "jreese-net"
DEFAULT_PREFIX = "rhythm-cycle"
DEFAULT_ENV_PREFIX = "gamma"
DEFAULT_OUT = "/Users/jreese/rhythm-analysis"
DEFAULT_DAYS = 60

NAMESPACES = ["Enceladus/Rhythm", "Enceladus/GraphHealth", "Enceladus/CEE", "Enceladus/Percolation"]
TENANT_FNS = [
    "enceladus-memory-consolidation-gamma",
    "enceladus-handoff-consolidation-engine-gamma",
    "enceladus-graph-health-metrics-gamma",
    "enceladus-corpus-entropy-engine-gamma",
    "enceladus-percolation-monitor-gamma",
    "devops-titan-embedding-backfill-gamma",
    "enceladus-rhythm-cycle-gamma",
]
TIERS = ["sense", "light_integrate", "decide", "heavy_integrate", "coherence"]

# DynamoDB percolation-telemetry table (gamma).
DDB_TABLE = "enceladus-percolation-telemetry-gamma"

# AppConfig identifiers for the live rhythm config snapshot.
APPCONFIG_APPLICATION = "fhhcl7m"
APPCONFIG_ENVIRONMENT = "zecfu42"
APPCONFIG_PROFILE_RHYTHM_TENANTS = "xiijj0l"
APPCONFIG_PROFILE_FEATURE_FLAGS = "wj68k4k"

# IAM role/policy snapshot.
IAM_ROLE_NAME = "enceladus-rhythm-cycle-role-gamma"
IAM_POLICY_NAME = "RhythmCyclePolicy"


def _artifact_prefix(env_prefix: str, prefix: str) -> str:
    """Join env-prefix and prefix into the full S3 key prefix (e.g. gamma/rhythm-cycle)."""
    return "/".join(p.strip("/") for p in (env_prefix, prefix) if p.strip("/"))


class RhythmHarvest:
    def __init__(self, args: argparse.Namespace) -> None:
        self.region = args.region
        self.bucket = args.bucket
        self.prefix = _artifact_prefix(args.env_prefix, args.prefix)
        self.out = args.out
        self.days = args.days
        self.s3 = boto3.client("s3", region_name=self.region)
        self.cw = boto3.client("cloudwatch", region_name=self.region)
        self.ddb = boto3.client("dynamodb", region_name=self.region)
        self.now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------
    def ensure(self, *parts) -> str:
        p = os.path.join(self.out, *parts)
        os.makedirs(p, exist_ok=True)
        return p

    def dump(self, rel: str, obj) -> str:
        path = os.path.join(self.out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)
        return path

    # ------------------------------------------------------------------
    # 1. S3: sync every rhythm-cycle artifact verbatim
    # ------------------------------------------------------------------
    def harvest_s3(self) -> dict:
        dest = self.ensure("s3")
        # aws s3 sync grabs the whole tree in one shot (all tiers + tenant-results)
        subprocess.run(
            ["aws", "s3", "sync", f"s3://{self.bucket}/{self.prefix}/", dest,
             "--region", self.region,
             "--exclude", "*", "--include", "*.json", "--quiet"],
            check=False,
        )
        counts = {}
        for root, _dirs, files in os.walk(dest):
            js = [f for f in files if f.endswith(".json")]
            if js:
                rel = os.path.relpath(root, dest)
                counts[rel] = len(js)
        return {"objects": sum(counts.values()), "by_dir": counts}

    # ------------------------------------------------------------------
    # 2. CloudWatch custom namespaces: every metric, every dimension set, full series
    # ------------------------------------------------------------------
    def _series(self, namespace, metric, dims, start, end, period) -> list:
        out = []
        resp = self.cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=period,
            Statistics=["Sum", "Average", "Minimum", "Maximum", "SampleCount"],
        )
        for d in sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"]):
            out.append({
                "t": d["Timestamp"].astimezone(timezone.utc).isoformat(),
                "sum": d.get("Sum"), "avg": d.get("Average"),
                "min": d.get("Minimum"), "max": d.get("Maximum"), "n": d.get("SampleCount"),
            })
        return out

    def harvest_cw_namespaces(self) -> dict:
        # hourly over --days (60d => 1440 pts max, covers all history)
        start = self.now - timedelta(days=self.days)
        summary = {}
        for ns in NAMESPACES:
            metrics = self.cw.list_metrics(Namespace=ns).get("Metrics", [])
            ns_out = {"metrics": []}
            for m in metrics:
                dims = m.get("Dimensions", [])
                series = self._series(ns, m["MetricName"], dims, start, self.now, 3600)
                ns_out["metrics"].append({
                    "metric": m["MetricName"],
                    "dimensions": {d["Name"]: d["Value"] for d in dims},
                    "points": series,
                    "point_count": len(series),
                })
            self.dump(f"cloudwatch/{ns.replace('/', '_')}.json", ns_out)
            summary[ns] = {"metric_series": len(ns_out["metrics"]),
                           "datapoints": sum(x["point_count"] for x in ns_out["metrics"])}
        return summary

    # ------------------------------------------------------------------
    # 3. CloudWatch AWS/Lambda: per-function operational metrics
    # ------------------------------------------------------------------
    def harvest_cw_lambda(self) -> dict:
        start = self.now - timedelta(days=self.days)
        out = {}
        for fn in TENANT_FNS:
            out[fn] = {}
            for metric in ["Invocations", "Errors", "Duration", "Throttles"]:
                out[fn][metric] = self._series(
                    "AWS/Lambda", metric, [{"Name": "FunctionName", "Value": fn}],
                    start, self.now, 3600,
                )
        self.dump("cloudwatch/lambda.json", out)
        return {fn: {"invocations": sum(p["sum"] or 0 for p in out[fn]["Invocations"]),
                     "errors": sum(p["sum"] or 0 for p in out[fn]["Errors"])} for fn in out}

    # ------------------------------------------------------------------
    # 4. DynamoDB: full percolation-telemetry scan
    # ------------------------------------------------------------------
    def harvest_ddb(self) -> dict:
        items = []
        kwargs = {"TableName": DDB_TABLE}
        try:
            while True:
                resp = self.ddb.scan(**kwargs)
                items.extend(resp.get("Items", []))
                lek = resp.get("LastEvaluatedKey")
                if not lek:
                    break
                kwargs["ExclusiveStartKey"] = lek
        except Exception as exc:  # noqa: BLE001
            self.dump("ddb/percolation_telemetry.json", {"_error": str(exc)})
            return {"error": str(exc)}

        # Flatten DynamoDB typed values to plain JSON
        def unwrap(v):
            (t, val), = v.items()
            if t == "N":
                return float(val)
            if t == "M":
                return {k: unwrap(x) for k, x in val.items()}
            if t == "L":
                return [unwrap(x) for x in val]
            if t == "BOOL":
                return val
            return val

        rows = [{k: unwrap(v) for k, v in it.items()} for it in items]
        self.dump("ddb/percolation_telemetry.json", {"row_count": len(rows), "rows": rows})
        return {"rows": len(rows)}

    # ------------------------------------------------------------------
    # 5. Config snapshot: live AppConfig manifest + feature flags + IAM role
    # ------------------------------------------------------------------
    def _appconfig(self, profile_id: str):
        tok = subprocess.run(
            ["aws", "appconfigdata", "start-configuration-session",
             "--application-identifier", APPCONFIG_APPLICATION,
             "--environment-identifier", APPCONFIG_ENVIRONMENT,
             "--configuration-profile-identifier", profile_id, "--region", self.region,
             "--query", "InitialConfigurationToken", "--output", "text"],
            capture_output=True, text=True,
        ).stdout.strip()
        raw = subprocess.run(
            ["aws", "appconfigdata", "get-latest-configuration",
             "--configuration-token", tok, "--region", self.region, "/dev/stdout"],
            capture_output=True, text=True,
        ).stdout
        try:
            return json.loads(raw.split("\n{")[0]) if raw.strip().startswith("{") else json.loads(raw)
        except Exception:
            return {"_raw": raw[:4000]}

    def harvest_config(self) -> dict:
        self.dump("config/rhythm_tenants.json", self._appconfig(APPCONFIG_PROFILE_RHYTHM_TENANTS))
        self.dump("config/feature_flags.json", self._appconfig(APPCONFIG_PROFILE_FEATURE_FLAGS))
        role = subprocess.run(
            ["aws", "iam", "get-role-policy", "--role-name", IAM_ROLE_NAME,
             "--policy-name", IAM_POLICY_NAME, "--region", self.region, "--output", "json"],
            capture_output=True, text=True,
        ).stdout
        try:
            self.dump("config/rhythm_role_policy.json", json.loads(role))
        except Exception:
            self.dump("config/rhythm_role_policy.json", {"_raw": role[:4000]})
        return {"profiles": ["rhythm_tenants", "feature_flags"], "iam": "rhythm_role_policy"}

    # ------------------------------------------------------------------
    # 6. Aggregates: flatten per-tier beat artifacts into chartable series
    # ------------------------------------------------------------------
    def _load_all(self, tier: str) -> list:
        d = os.path.join(self.out, "s3", tier)
        out = []
        if not os.path.isdir(d):
            return out
        for root, _dirs, files in os.walk(d):
            for f in files:
                if f.endswith(".json") and f != "latest.json":
                    try:
                        with open(os.path.join(root, f)) as fh:
                            out.append(json.load(fh))
                    except Exception:
                        pass
        out.sort(key=lambda x: x.get("beat_at") or x.get("alignment_point_utc") or "")
        return out

    def harvest_aggregates(self) -> dict:
        agg = {}
        for tier in TIERS:
            beats = self._load_all(tier)
            agg[tier] = {"beat_count": len(beats), "beats": beats}
        self.dump("aggregates/tier_beats.json", agg)
        # tenant stanzas across every window
        tr = os.path.join(self.out, "s3", "heavy_integrate", "tenant-results")
        windows = {}
        if os.path.isdir(tr):
            for win in sorted(os.listdir(tr)):
                wdir = os.path.join(tr, win)
                if os.path.isdir(wdir):
                    windows[win] = {}
                    for f in os.listdir(wdir):
                        if f.endswith(".json"):
                            try:
                                with open(os.path.join(wdir, f)) as fh:
                                    windows[win][f[:-5]] = json.load(fh)
                            except Exception:
                                pass
        self.dump("aggregates/tenant_stanzas.json", {"window_count": len(windows), "windows": windows})
        return {"tiers": {t: agg[t]["beat_count"] for t in TIERS}, "tenant_windows": len(windows)}

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def run(self) -> dict:
        os.makedirs(self.out, exist_ok=True)
        index = {
            "harvested_at": self.now.isoformat(),
            "region": self.region,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "days": self.days,
        }
        stages = [
            ("s3", "S3 artifacts", self.harvest_s3),
            ("cloudwatch_namespaces", "CloudWatch custom namespaces", self.harvest_cw_namespaces),
            ("cloudwatch_lambda", "CloudWatch AWS/Lambda", self.harvest_cw_lambda),
            ("ddb", "DynamoDB percolation-telemetry", self.harvest_ddb),
            ("config", "Config snapshot", self.harvest_config),
            ("aggregates", "Aggregates", self.harvest_aggregates),
        ]
        total = len(stages)
        for i, (key, label, fn) in enumerate(stages, start=1):
            print(f"[{i}/{total}] {label} ...")
            try:
                index[key] = fn()
            except Exception as exc:  # noqa: BLE001
                index[key] = {"_error": str(exc)}
                print(f"    ! {label} failed: {exc}", file=sys.stderr)
        self.dump("INDEX.json", index)
        print(f"\nHARVEST COMPLETE -> {self.out}")
        print(json.dumps(index, indent=2, default=str))
        return index


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rhythm-cycle MAXIMAL raw-data harvester (read-only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Local output directory for the harvested bundle.")
    parser.add_argument("--region", default=DEFAULT_REGION, help="AWS region.")
    parser.add_argument("--bucket", default=DEFAULT_BUCKET, help="S3 bucket holding rhythm artifacts.")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX,
                        help="S3 sub-prefix under the env-prefix (full prefix is <env-prefix>/<prefix>).")
    parser.add_argument("--env-prefix", default=DEFAULT_ENV_PREFIX,
                        help="S3 environment prefix (e.g. gamma).")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help="Lookback window in days for CloudWatch metric series.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        RhythmHarvest(args).run()
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
