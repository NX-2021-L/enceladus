#!/usr/bin/env python3
"""Rhythm-cycle heavy-window diagnostic harness (read-only).

ENC-TSK-N42 (PLN-078 W3 tooling). Productizes the ad-hoc verification run for the
2026-07-13T00:45Z heavy_integrate window (see DOC-2ADECC07A4F2) into a repeatable,
read-only diagnostic. Given a rhythm environment it dumps a consolidated view of a
window:

  * All 5 tier beat artifacts (sense / light_integrate / decide / heavy_integrate /
    coherence) from s3://<bucket>/<env-prefix>/rhythm-cycle/<tier>/latest.json
  * The heavy_integrate tenant_orchestration block + every per-tenant completion
    stanza written under its result_prefix (executed vs. silent)
  * Per-tenant Lambda invocation counts + errors (CloudWatch AWS/Lambda metrics)
  * Enceladus/Rhythm custom metrics (beat_duration_ms, artifact_bytes,
    beat_cost_estimate, deferral_count, tenant_stall)
  * The Lyapunov series read from recent decide beats

It performs ONLY read operations: S3 GetObject/ListObjectsV2, CloudWatch
GetMetricStatistics. No mutations, no infra change.

Usage:
  python3 tools/rhythm_diag_harness.py --environment gamma
  python3 tools/rhythm_diag_harness.py --environment gamma --output-json /tmp/rpt.json
  python3 tools/rhythm_diag_harness.py --environment gamma --output-md /tmp/rpt.md
  python3 tools/rhythm_diag_harness.py --environment gamma --window 20260713-004529

Environment presets resolve the S3 env-prefix and tenant function suffix. Override
any of --bucket / --region / --s3-prefix / --env-prefix / --namespace as needed.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import boto3

TIERS = ("sense", "light_integrate", "decide", "heavy_integrate", "coherence")

# CloudWatch Enceladus/Rhythm custom metrics emitted by the beats/tenant_invoker.
RHYTHM_METRICS = (
    "beat_duration_ms",
    "artifact_bytes",
    "beat_cost_estimate",
    "deferral_count",
    "tenant_stall",
)

# Environment presets: env-prefix mirrors the rhythm-cycle Lambda's
# S3_ENV_PREFIX, and the function suffix matches the deployed tenant Lambdas.
ENV_PRESETS = {
    "gamma": {"env_prefix": "gamma", "suffix": "-gamma"},
    "production": {"env_prefix": "", "suffix": ""},
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _artifact_prefix(env_prefix: str, s3_prefix: str) -> str:
    return "/".join(p.strip("/") for p in (env_prefix, s3_prefix) if p.strip("/"))


class RhythmDiag:
    def __init__(self, args: argparse.Namespace) -> None:
        self.region = args.region
        self.bucket = args.bucket
        self.namespace = args.namespace
        preset = ENV_PRESETS.get(args.environment, ENV_PRESETS["gamma"])
        self.env_prefix = args.env_prefix if args.env_prefix is not None else preset["env_prefix"]
        self.suffix = preset["suffix"]
        self.prefix = _artifact_prefix(self.env_prefix, args.s3_prefix)
        self.window = args.window
        self.lyapunov_points = args.lyapunov_points
        self._s3 = boto3.client("s3", region_name=self.region)
        self._cw = boto3.client("cloudwatch", region_name=self.region)

    # -- S3 artifact helpers -------------------------------------------------
    def _get_json(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=key)
            return json.loads(obj["Body"].read())
        except self._s3.exceptions.NoSuchKey:
            return None
        except Exception as exc:  # noqa: BLE001 - diagnostic best-effort
            return {"_error": f"{type(exc).__name__}: {exc}", "_key": key}

    def _tier_latest(self, tier: str) -> Optional[Dict[str, Any]]:
        return self._get_json(f"{self.prefix}/{tier}/latest.json")

    def _list_stanzas(self, result_prefix: str) -> Dict[str, Any]:
        """List + read the completion stanzas under a heavy window result_prefix."""
        out: Dict[str, Any] = {}
        if not result_prefix:
            return out
        prefix = result_prefix.rstrip("/") + "/"
        token: Optional[str] = None
        while True:
            kw: Dict[str, Any] = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kw)
            for item in resp.get("Contents", []):
                key = item["Key"]
                name = key[len(prefix):]
                if name.endswith(".json"):
                    name = name[: -len(".json")]
                if name:
                    out[name] = self._get_json(key)
            token = resp.get("NextContinuationToken")
            if not token:
                break
        return out

    # -- CloudWatch helpers --------------------------------------------------
    def _lambda_stat(self, function_name: str, metric: str, start: datetime, end: datetime) -> float:
        try:
            resp = self._cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName=metric,
                Dimensions=[{"Name": "FunctionName", "Value": function_name}],
                StartTime=start,
                EndTime=end,
                Period=3600,
                Statistics=["Sum"],
            )
            return sum(dp.get("Sum", 0.0) for dp in resp.get("Datapoints", []))
        except Exception as exc:  # noqa: BLE001
            return float("nan")

    def _metric_dimension_sets(self, metric: str) -> List[List[Dict[str, str]]]:
        """Discover the dimension sets a rhythm metric is published under.

        Enceladus/Rhythm metrics carry dimensions (Tier, ProjectId, and sometimes
        Tenant/Grooming), so a dimensionless GetMetricStatistics returns nothing —
        we enumerate the published sets and query each. Returns [[]] as a fallback
        so a dimensionless query is still attempted.
        """
        try:
            sets: List[List[Dict[str, str]]] = []
            paginator = self._cw.get_paginator("list_metrics")
            for page in paginator.paginate(Namespace=self.namespace, MetricName=metric):
                for m in page.get("Metrics", []):
                    dims = m.get("Dimensions", [])
                    if dims not in sets:
                        sets.append(dims)
            return sets or [[]]
        except Exception:  # noqa: BLE001
            return [[]]

    def _rhythm_metric(self, metric: str, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for dims in self._metric_dimension_sets(metric):
            try:
                resp = self._cw.get_metric_statistics(
                    Namespace=self.namespace,
                    MetricName=metric,
                    Dimensions=dims,
                    StartTime=start,
                    EndTime=end,
                    Period=3600,
                    Statistics=["Sum", "Average", "Maximum"],
                )
            except Exception as exc:  # noqa: BLE001
                out.append({"_error": f"{type(exc).__name__}: {exc}", "dimensions": dims})
                continue
            dps = sorted(resp.get("Datapoints", []), key=lambda d: d["Timestamp"])
            if not dps:
                continue
            label = {d["Name"]: d["Value"] for d in dims}
            out.append(
                {
                    "dimensions": label,
                    "points": [
                        {
                            "t": _iso(d["Timestamp"]),
                            "sum": d.get("Sum"),
                            "avg": d.get("Average"),
                            "max": d.get("Maximum"),
                        }
                        for d in dps
                    ],
                }
            )
        return out

    # -- report assembly -----------------------------------------------------
    def collect(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=13)  # heavy cadence is ~12h; pad one hour

        report: Dict[str, Any] = {
            "generated_at": _iso(now),
            "environment": {
                "region": self.region,
                "bucket": self.bucket,
                "artifact_prefix": self.prefix,
                "namespace": self.namespace,
            },
            "tiers": {},
            "tenant_orchestration": {},
            "tenant_stanzas": {},
            "tenant_invocations": {},
            "rhythm_metrics": {},
            "lyapunov_series": [],
            "findings": [],
        }

        # 1. Tier beat artifacts
        heavy: Optional[Dict[str, Any]] = None
        for tier in TIERS:
            art = self._tier_latest(tier)
            report["tiers"][tier] = art
            if tier == "heavy_integrate":
                heavy = art

        # 2. Heavy tenant orchestration + stanzas
        if heavy and isinstance(heavy, dict):
            orch = heavy.get("tenant_orchestration") or {}
            report["tenant_orchestration"] = orch
            report["recompute_backlog"] = heavy.get("recompute_backlog")
            result_prefix = orch.get("result_prefix", "")
            if self.window:
                # Override to a specific window folder under the same tenant-results root.
                root = result_prefix.rsplit("/", 1)[0] if result_prefix else (
                    f"{self.prefix}/heavy_integrate/tenant-results"
                )
                result_prefix = f"{root}/{self.window}"
            stanzas = self._list_stanzas(result_prefix)
            report["tenant_stanzas"] = stanzas

            invoked = orch.get("invoked_tenants") or []
            manifest_size = orch.get("manifest_size")
            if manifest_size is not None and manifest_size != len(invoked):
                report["findings"].append(
                    f"manifest_size={manifest_size} but invoked_tenants={len(invoked)} "
                    f"— {manifest_size - len(invoked)} tenant(s) dropped at invocation "
                    f"(likely IAM invoke gap; check rhythm-cycle logs)"
                )
            for t in invoked:
                name = t.get("name")
                if name and name not in stanzas:
                    report["findings"].append(f"tenant '{name}' invoked but no completion stanza (silent)")

            # 3. Per-tenant Lambda invocation counts + errors
            for t in invoked:
                fn = t.get("function_name")
                if not fn:
                    continue
                report["tenant_invocations"][t.get("name", fn)] = {
                    "function_name": fn,
                    "invocations": self._lambda_stat(fn, "Invocations", window_start, now),
                    "errors": self._lambda_stat(fn, "Errors", window_start, now),
                }

        rb = report.get("recompute_backlog")
        if isinstance(rb, dict) and rb.get("error"):
            report["findings"].append(f"recompute_backlog errored: {rb['error']}")

        # 4. Enceladus/Rhythm custom metrics
        for metric in RHYTHM_METRICS:
            report["rhythm_metrics"][metric] = self._rhythm_metric(metric, window_start, now)

        # 5. Lyapunov series from recent decide beats
        report["lyapunov_series"] = self._lyapunov_series(now)

        return report

    def _lyapunov_series(self, now: datetime) -> List[Dict[str, Any]]:
        """Read recent decide-beat artifacts and extract the backlog Lyapunov series.

        The decide tier's canonical Lyapunov function (ENC-TSK-N20) is the open-leaf
        backlog: ``backlog_open_leaves`` is the candidate Lyapunov value V and
        ``backlog_open_leaves_delta`` its per-beat derivative dV (converging when
        consistently <= 0). We also carry ``backlog_cursor_terminus`` for the cursor
        read, and fall back to any literal ``lyapunov`` field for schema drift.
        Decide beats are archived under <prefix>/decide/<YYYY>/<MM>/<DD>/*.json.
        """
        series: List[Dict[str, Any]] = []
        base = f"{self.prefix}/decide/"
        try:
            keys = self._recent_keys(base, limit=self.lyapunov_points * 3)
        except Exception as exc:  # noqa: BLE001
            return [{"_error": f"{type(exc).__name__}: {exc}"}]
        for key in keys[: self.lyapunov_points]:
            beat = self._get_json(key)
            if not isinstance(beat, dict):
                continue
            literal = _dig(beat, ("lyapunov", "value")) or beat.get("lyapunov")
            series.append(
                {
                    "key": key,
                    "beat_at": beat.get("beat_at"),
                    "open_leaves": beat.get("backlog_open_leaves"),
                    "open_leaves_delta": beat.get("backlog_open_leaves_delta"),
                    "cursor_terminus": beat.get("backlog_cursor_terminus"),
                    "lyapunov": literal,
                }
            )
        # Newest-first from _recent_keys; present oldest-first so a reader sees the
        # trajectory in time order.
        series.reverse()
        return series

    def _recent_keys(self, base: str, limit: int) -> List[str]:
        """Return the newest object keys under base (by LastModified), excluding latest.json."""
        keys: List[Dict[str, Any]] = []
        token: Optional[str] = None
        while True:
            kw: Dict[str, Any] = {"Bucket": self.bucket, "Prefix": base}
            if token:
                kw["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kw)
            for item in resp.get("Contents", []):
                if item["Key"].endswith("/latest.json"):
                    continue
                if item["Key"].endswith(".json"):
                    keys.append(item)
            token = resp.get("NextContinuationToken")
            if not token:
                break
        keys.sort(key=lambda i: i["LastModified"], reverse=True)
        return [k["Key"] for k in keys[:limit]]


def _dig(obj: Any, path: tuple) -> Any:
    cur = obj
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    env = report["environment"]
    lines.append(f"# Rhythm diagnostic — {report['generated_at']}")
    lines.append("")
    lines.append(f"- region: `{env['region']}`  bucket: `{env['bucket']}`  prefix: `{env['artifact_prefix']}`")
    lines.append("")

    orch = report.get("tenant_orchestration") or {}
    invoked = orch.get("invoked_tenants") or []
    lines.append("## Heavy window tenant orchestration")
    lines.append("")
    lines.append(f"- beat_at: `{(report.get('tiers', {}).get('heavy_integrate') or {}).get('beat_at')}`")
    lines.append(f"- manifest_size: {orch.get('manifest_size')}  invoked: {len(invoked)}")
    rb = report.get("recompute_backlog")
    lines.append(f"- recompute_backlog: `{json.dumps(rb)[:200] if rb is not None else None}`")
    lines.append("")
    stanzas = report.get("tenant_stanzas") or {}
    for t in invoked:
        name = t.get("name")
        st = stanzas.get(name) or {}
        status = st.get("status", "NO STANZA (silent)") if isinstance(st, dict) else "NO STANZA (silent)"
        inv = (report.get("tenant_invocations") or {}).get(name, {})
        lines.append(
            f"- **{name}** — stanza: `{status}`  "
            f"invocations: {inv.get('invocations')}  errors: {inv.get('errors')}"
        )
    lines.append("")

    findings = report.get("findings") or []
    lines.append("## Findings")
    lines.append("")
    if findings:
        for f in findings:
            lines.append(f"- ⚠️ {f}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Lyapunov / backlog-convergence series (recent decide beats, oldest→newest)")
    lines.append("")
    for pt in report.get("lyapunov_series") or []:
        if pt.get("_error"):
            lines.append(f"- error: {pt['_error']}")
            continue
        lines.append(
            f"- `{pt.get('beat_at')}` V(open_leaves)={pt.get('open_leaves')} "
            f"dV={pt.get('open_leaves_delta')} cursor={pt.get('cursor_terminus')}"
            + (f" lyapunov={pt.get('lyapunov')}" if pt.get("lyapunov") is not None else "")
        )
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Read-only rhythm-cycle heavy-window diagnostic harness")
    p.add_argument("--environment", default="gamma", choices=sorted(ENV_PRESETS), help="rhythm environment preset")
    p.add_argument("--region", default="us-west-2", help="AWS region (default us-west-2)")
    p.add_argument("--bucket", default="jreese-net", help="artifact S3 bucket")
    p.add_argument("--s3-prefix", default="rhythm-cycle", help="base S3 prefix (default rhythm-cycle)")
    p.add_argument("--env-prefix", default=None, help="override env prefix (default from --environment preset)")
    p.add_argument("--namespace", default="Enceladus/Rhythm", help="CloudWatch namespace for rhythm metrics")
    p.add_argument("--window", default=None, help="specific tenant-results window folder (e.g. 20260713-004529)")
    p.add_argument("--lyapunov-points", type=int, default=8, help="how many recent decide beats to sample")
    p.add_argument("--output-json", default=None, help="write full JSON report to this path")
    p.add_argument("--output-md", default=None, help="write markdown summary to this path")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    diag = RhythmDiag(args)
    report = diag.collect()

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
    md = render_markdown(report)
    if args.output_md:
        with open(args.output_md, "w", encoding="utf-8") as fh:
            fh.write(md)

    print(md)
    # Non-zero exit if any invoked tenant went silent or a tenant was dropped.
    return 1 if report.get("findings") else 0


if __name__ == "__main__":
    sys.exit(main())
