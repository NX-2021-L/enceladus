#!/usr/bin/env python3
"""Write-path passive-reading and governance counter-metric runner (ENC-TSK-S26-0D).

Pulls raw [WRITE-AUDIT] lines and Lambda REPORT Init Durations with CloudWatch Logs Insights
(or reads a local JSONL fixture), merges them on request_id / correlation_id in Python
(Logs Insights has no join), and writes a JSON reading plus a markdown table shaped like
BRD DOC-E32D0ED08473 Appendix A (rows = stage, columns = p50/p95 by tool).

    python3 run_queries.py --env gamma --days 7 --out-dir ./readings
    python3 run_queries.py --fixture fixtures/synthetic_audit_lines.jsonl --out-dir ./readings

Cost rule (agents.md cost rule-block v1): Logs Insights scans are the only cost; the total
bytesScanned returned by the API is printed and recorded in the JSON as scanned_bytes.
"""
import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGES = ["t_edge_ms", "t_auth_ms", "t_route_ms", "t_invoke_ms", "t_governance_ms", "t_validate_ms",
          "t_idempotency_ms", "t_counter_ms", "t_ddb_ms", "t_s3_ms", "t_compliance_ms", "init_ms"]
GROUPS = ("identity", "client_side", "server_side", "async_side", "derived")
MARK = "[WRITE-AUDIT]"
LOG_GROUP_BASES = ["enceladus-mcp-code", "devops-tracker-mutation-api", "devops-document-api",
                   "enceladus-checkout-service", "devops-graph-sync", "devops-feed-publisher",
                   "devops-appsync-feed-publisher"]  # verified with describe-log-groups 2026-11-04
DLQ_QUEUES = {
    "prod": ["devops-graph-sync-dlq.fifo", "devops-appsync-feed-publisher-dlq"],
    "gamma": ["devops-graph-sync-dlq-gamma.fifo", "devops-appsync-feed-publisher-dlq-gamma",
              "devops-search-index-cdc-dlq-gamma"],
}
REPORT_RE = re.compile(r"^REPORT RequestId:\s*(\S+).*?Init Duration:\s*([0-9.]+)\s*ms", re.S)


# ----------------------------------------------------------------------------- helpers
def pct(values, q):
    """Linear-interpolation percentile (q in 0..100); None for an empty list."""
    v = sorted(x for x in values if x is not None)
    if not v:
        return None
    if len(v) == 1:
        return float(v[0])
    k = (len(v) - 1) * q / 100.0
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return float(v[lo] + (v[hi] - v[lo]) * (k - lo))


def num(x):
    try:
        return None if x in (None, "") else float(x)
    except (TypeError, ValueError):
        return None


def as_bool(x):
    if isinstance(x, bool):
        return x
    if isinstance(x, str):
        return {"true": True, "false": False}.get(x.strip().lower())
    return None


def parse_ts(s):
    s = str(s).strip().replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    t = datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def flatten(d):
    out = {}
    for k, v in d.items():
        if k in GROUPS and isinstance(v, dict):
            out.update(v)
        else:
            out[k] = v
    return out


def parse_audit(msg):
    if MARK not in msg:
        return None
    try:
        return flatten(json.loads(msg.split(MARK, 1)[1].strip()))
    except (ValueError, TypeError):
        return {"_malformed": True}


def parse_report(msg):
    m = REPORT_RE.match(msg)
    return (m.group(1), float(m.group(2))) if m else None


# ----------------------------------------------------------------------------- sources
def load_fixture(path):
    rows = []
    with open(path) as fh:
        for ln in fh:
            if ln.strip():
                rows.append(json.loads(ln))
    audit = [{"ts": r["ts"], "log_group": r.get("log_group"), "message": r["message"]} for r in rows]
    window_end = max(parse_ts(r["ts"]) for r in rows)
    window_start = min(parse_ts(r["ts"]) for r in rows)
    return audit, window_start, window_end


class Insights:
    def __init__(self, logs):
        self.logs = logs
        self.scanned_bytes = 0
        self.queries = 0

    def run(self, groups, query, start, end, limit=10000):
        """Run one query; returns list[dict]. Splits the window in half when the 10k cap is hit."""
        r = self.logs.start_query(logGroupNames=groups, startTime=int(start.timestamp()),
                                  endTime=int(end.timestamp()), queryString=query, limit=limit)
        qid = r["queryId"]
        self.queries += 1
        while True:
            res = self.logs.get_query_results(queryId=qid)
            if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
            time.sleep(1.5)
        if res["status"] != "Complete":
            raise RuntimeError(f"query {qid} ended {res['status']}")
        self.scanned_bytes += int(res.get("statistics", {}).get("bytesScanned", 0))
        rows = [{c["field"]: c["value"] for c in row} for row in res["results"]]
        if len(rows) >= limit and (end - start) > timedelta(seconds=2):
            mid = start + (end - start) / 2
            return (self.run(groups, query, start, mid - timedelta(seconds=1), limit)
                    + self.run(groups, query, mid, end, limit))
        return rows

    def run_days(self, groups, query, start, end):
        out, cur = [], start
        while cur < end:
            nxt = min(cur + timedelta(days=1), end)
            out += self.run(groups, query, cur, nxt - timedelta(seconds=1) if nxt < end else end)
            cur = nxt
        return out


def existing_groups(logs, names):
    found = set()
    for n in names:
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=n):
            found.update(g["logGroupName"] for g in page["logGroups"] if g["logGroupName"] == n)
    return [n for n in names if n in found]


def read_dlq_depth(sqs, names):
    depth, detail = 0, {}
    for name in names:
        try:
            url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
            a = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[
                "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed"])["Attributes"]
            n = sum(int(a.get(k, 0)) for k in a)
            detail[name] = n
            depth += n
        except Exception as exc:  # missing queue is reported, never fatal
            detail[name] = f"unreadable: {type(exc).__name__}"
    return depth, detail


def load_aws(args):
    import boto3
    sess = boto3.Session(profile_name=args.profile, region_name=args.region)
    logs, sqs = sess.client("logs"), sess.client("sqs")
    suffix = "-gamma" if args.env == "gamma" else ""
    wanted = ["/aws/lambda/" + b + suffix for b in LOG_GROUP_BASES] + list(args.log_group or [])
    groups = existing_groups(logs, wanted)
    missing = [g for g in wanted if g not in groups]
    for g in missing:
        print(f"[WARN] log group not found, skipped: {g}", file=sys.stderr)
    if not groups:
        sys.exit("no log groups found")
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=args.days)
    ins = Insights(logs)
    audit_q = (HERE / "05_extract_audit_lines.query").read_text()
    report_q = (HERE / "06_extract_report_init.query").read_text()
    audit = [{"ts": r["@timestamp"], "log_group": r.get("@log"), "message": r["@message"]}
             for r in ins.run_days(groups, audit_q, start, end)]
    reports = [{"request_id": r.get("request_id"), "init_duration_ms": r.get("init_duration_ms")}
               for r in ins.run_days(groups, report_q, start, end)]
    extra = {}
    if args.insights_queries:
        for p in sorted(HERE.glob("*.query")):
            if p.name[:2] in ("05", "06"):
                continue
            extra[p.stem] = ins.run(groups, p.read_text(), start, end)
    dlq_depth, dlq_detail = read_dlq_depth(sqs, args.dlq_queue or DLQ_QUEUES[args.env])
    meta = {"log_groups": groups, "skipped_log_groups": missing, "queries_run": ins.queries,
            "scanned_bytes": ins.scanned_bytes, "dlq_depth": dlq_depth, "dlq_detail": dlq_detail,
            "insights": extra}
    return audit, reports, start, end, meta


# ----------------------------------------------------------------------------- computation
def compute(lines, reports, window_start, window_end, grace_min=15, dlq_depth=0):
    """lines: [{ts, log_group, message}] (audit + optional REPORT messages); reports: [{request_id, init_duration_ms}]."""
    writes, consumers, init_by_req, malformed = [], [], {}, 0
    for ln in lines:
        msg = ln["message"]
        rep = parse_report(msg)
        if rep:
            init_by_req[rep[0]] = rep[1]
            continue
        a = parse_audit(msg)
        if a is None:
            continue
        if a.get("_malformed"):
            malformed += 1
            continue
        a["_ts"] = parse_ts(ln["ts"])
        (consumers if a.get("consumer") else writes).append(a)
    for r in reports or []:
        if r.get("request_id") and num(r.get("init_duration_ms")) is not None:
            init_by_req[r["request_id"]] = num(r["init_duration_ms"])

    # REPORT join on request_id (init_ms from the audit line wins when present)
    joined = 0
    for w in writes:
        if num(w.get("init_ms")) is None and w.get("request_id") in init_by_req:
            w["init_ms"] = init_by_req[w["request_id"]]
            w["_init_from_report"] = True
            joined += 1
        w["_cold"] = bool(as_bool(w.get("cold_start"))) or (num(w.get("init_ms")) or 0) > 0

    # --- latency by tool and surface; per-tool rollup for Appendix A
    def summarize(group):
        tot = [num(w.get("server_total_ms")) for w in group]
        cli = [num(w.get("client_total_ms")) for w in group]
        cold_n = sum(1 for w in group if w["_cold"])
        return {"n": len(group), "p50": pct(tot, 50), "p90": pct(tot, 90), "p95": pct(tot, 95),
                "max": max([x for x in tot if x is not None], default=None),
                "cold_n": cold_n, "cold_share": cold_n / len(group) if group else None,
                "client_n": sum(1 for x in cli if x is not None),
                "client_p50": pct(cli, 50), "client_p95": pct(cli, 95)}

    by_ts, by_tool = defaultdict(list), defaultdict(list)
    for w in writes:
        by_ts[(w.get("tool"), w.get("surface"))].append(w)
        by_tool[w.get("tool")].append(w)
    latency = [{"tool": t, "surface": s, **summarize(g)} for (t, s), g in sorted(by_ts.items(), key=str)]
    latency_by_tool = [{"tool": t, **summarize(g)} for t, g in sorted(by_tool.items(), key=str)]

    stage_table = {}
    for st in STAGES + ["server_total_ms", "client_total_ms"]:
        stage_table[st] = {t: {"p50": pct([num(w.get(st)) for w in g], 50),
                               "p95": pct([num(w.get(st)) for w in g], 95),
                               "n": sum(1 for w in g if num(w.get(st)) is not None)}
                           for t, g in sorted(by_tool.items(), key=str)}

    # --- governed lag (consumer lines; tool attached from the originating write by correlation_id)
    tool_of = {w.get("correlation_id"): w.get("tool") for w in writes}
    lag_by_tool = defaultdict(list)
    for c in consumers:
        lag = num(c.get("governed_lag_ms"))
        if lag is not None:
            lag_by_tool[c.get("tool") or tool_of.get(c.get("correlation_id")) or "unknown"].append(lag)
    governed_lag = [{"tool": t, "n": len(v), "p50": pct(v, 50), "p95": pct(v, 95)} for t, v in sorted(lag_by_tool.items())]

    # --- ENC-TSK-S46-0A: per-consumer stage clocks and derived lags (BRD 7.1). Derived values are
    # computed HERE, never in the Lambdas. governed_lag_ms stays as the compatibility alias.
    by_consumer = defaultdict(list)
    for c in consumers:
        by_consumer[c.get("consumer")].append(c)

    def _diff(c, later, earlier):
        a, b = num(c.get(later)), num(c.get(earlier))
        return None if a is None or b is None else max(0.0, a - b)

    def _col(rows, fn):
        return [fn(c) for c in rows]

    def _row(label, v):
        return {f"{label}_p50": pct(v, 50), f"{label}_p95": pct(v, 95), f"{label}_n": sum(1 for x in v if x is not None)}

    consumer_lag = []
    for name, rows in sorted(by_consumer.items(), key=str):
        ok = [c for c in rows if as_bool(c.get("success")) is not False]
        graph = [_diff(c, "t_record_done", "t_ack") for c in ok if c.get("projection_phase") == "projected"]
        feed = [_diff(c, "t_feed_published", "t_ack") for c in ok]
        entry = {"consumer": name, "n": len(rows),
                 **_row("governed_lag_ms", [num(c.get("governed_lag_ms")) for c in ok]),
                 **_row("graph_projection_lag_ms", graph), **_row("feed_projection_lag_ms", feed),
                 **_row("stream_delay_ms", _col(ok, lambda c: _diff(c, "t_batch_start", "t_ack"))),
                 **_row("queue_ms", _col(ok, lambda c: _diff(c, "t_record_start", "t_batch_start"))),
                 **_row("store_ms", [num(c.get("store_ms")) for c in ok]),
                 **_row("mark_ms", [num(c.get("mark_ms")) for c in ok]),
                 **_row("publish_ms", [num(c.get("publish_ms")) for c in ok]),
                 "marker_only_skipped_n": sum(1 for c in rows if as_bool(c.get("marker_only_skipped")) is True),
                 "cold_n": sum(1 for c in rows if as_bool(c.get("cold_start")) is True)}
        consumer_lag.append(entry)

    # --- per-session cold fraction distribution
    sess = defaultdict(lambda: [0, 0])
    for w in writes:
        if w.get("session_id"):
            sess[w["session_id"]][0] += 1
            sess[w["session_id"]][1] += 1 if w["_cold"] else 0
    fracs = [c / n for n, c in sess.values()]
    cold_fraction = {
        "sessions": len(fracs), "mean": sum(fracs) / len(fracs) if fracs else None,
        "p50": pct(fracs, 50), "p90": pct(fracs, 90), "max": max(fracs, default=None),
        "buckets": {"0": sum(1 for f in fracs if f == 0), "(0,0.25]": sum(1 for f in fracs if 0 < f <= .25),
                    "(0.25,0.5]": sum(1 for f in fracs if .25 < f <= .5), "(0.5,1]": sum(1 for f in fracs if f > .5)},
        "per_session": {k: {"n": v[0], "cold_n": v[1], "cold_fraction": v[1] / v[0]} for k, v in sorted(sess.items())},
    }

    # --- governance counter-metrics (each must be 0)
    cm = {}
    stale = [w for w in writes if as_bool(w.get("governance_hash_verified")) is False and as_bool(w.get("success")) is not False]
    cm["stale_hash_acceptances"] = {"count": len(stale), "ids": [w.get("correlation_id") for w in stale]}

    cutoff = window_end - timedelta(minutes=grace_min)
    seen = {c.get("correlation_id") for c in consumers}
    orphans = [w for w in writes
               if w["_ts"] <= cutoff and as_bool(w.get("success")) is not False
               and as_bool(w.get("dry_run")) is not True and as_bool(w.get("idempotency_hit")) is not True
               and (num(w.get("ddb_ops")) is None or num(w.get("ddb_ops")) > 0)
               and w.get("correlation_id") not in seen]
    cm["records_without_audit_item"] = {"count": len(orphans), "ids": [w.get("correlation_id") for w in orphans],
                                        "grace_min": grace_min}

    receipts = defaultdict(set)
    for w in writes:
        if w.get("idempotency_key") and w.get("receipt_hash"):
            receipts[w["idempotency_key"]].add(w["receipt_hash"])
    if receipts:
        bad = sorted(k for k, v in receipts.items() if len(v) > 1)
        cm["idempotent_replay_receipt_mismatch"] = {"count": len(bad), "ids": bad}
    else:
        cm["idempotent_replay_receipt_mismatch"] = {"count": None, "ids": [],
                                                    "note": "not computable until W2.4 emits receipt_hash"}

    dry = [w for w in writes if as_bool(w.get("dry_run")) is True and (num(w.get("ddb_ops")) or 0) > 0]
    cm["dry_run_writes"] = {"count": len(dry), "ids": [w.get("correlation_id") for w in dry]}

    done = {(c.get("correlation_id"), c.get("consumer")) for c in consumers if c.get("t_projection_done")}
    failing = [c for c in consumers if (num(c.get("attempt")) or 0) >= 3 and not c.get("t_projection_done")]
    unrecovered = [c for c in failing if (c.get("correlation_id"), c.get("consumer")) not in done]
    cm["unrecovered_consumer_failures"] = {
        "count": len(unrecovered) + dlq_depth, "unrecovered_lines": len(unrecovered),
        "literal_attempt_ge_3_without_done": len(failing), "dlq_depth": dlq_depth,
        "ids": [c.get("correlation_id") for c in unrecovered]}

    # ENC-TSK-S46-0D: edges a consumer could not create because the target node was absent
    # and could not be placed (graph_sync edge order guard). Summed over the window.
    skipped = [c for c in consumers if (num(c.get("edges_skipped_missing_target")) or 0) > 0]
    cm["edges_skipped_missing_target"] = {
        "count": int(sum(num(c.get("edges_skipped_missing_target")) for c in skipped)),
        "placeholder_targets": int(sum(num(c.get("edges_placeholder_targets")) or 0 for c in consumers)),
        "ids": [c.get("correlation_id") for c in skipped]}

    return {"window": {"start": window_start.isoformat(), "end": window_end.isoformat()},
            "counts": {"write_lines": len(writes), "consumer_lines": len(consumers), "report_init_rows": len(init_by_req),
                       "report_joined": joined, "malformed_lines": malformed},
            "latency_by_tool_surface": latency, "latency_by_tool": latency_by_tool, "stage_table": stage_table,
            "governed_lag": governed_lag, "consumer_lag": consumer_lag, "cold_fraction": cold_fraction, "counter_metrics": cm}


# ----------------------------------------------------------------------------- rendering
def f(x, nd=1):
    return "-" if x is None else f"{x:.{nd}f}"


def render_markdown(res, title):
    tools = sorted({t for st in res["stage_table"].values() for t in st}, key=str)
    out = [f"# {title}", "", f"Window: {res['window']['start']} to {res['window']['end']}  ",
           f"Write lines {res['counts']['write_lines']}, consumer lines {res['counts']['consumer_lines']}, "
           f"REPORT init joined {res['counts']['report_joined']}"
           + (f", scanned_bytes {res['scanned_bytes']}" if res.get("scanned_bytes") is not None else ""), "",
           "## Stage budget (ms, p50/p95 by tool; BRD Appendix A shape)", "",
           "| stage | " + " | ".join(str(t) for t in tools) + " |", "|---|" + "---|" * len(tools)]
    for st, per in res["stage_table"].items():
        cells = [f"{f(per[t]['p50'])}/{f(per[t]['p95'])}" if t in per and per[t]["n"] else "-" for t in tools]
        out.append(f"| {st} | " + " | ".join(cells) + " |")
    out += ["", "## Latency by tool and surface (server_total_ms)", "",
            "| tool | surface | n | p50 | p90 | p95 | max | cold n | cold share | client p50 | client p95 |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in res["latency_by_tool_surface"]:
        out.append(f"| {r['tool']} | {r['surface']} | {r['n']} | {f(r['p50'])} | {f(r['p90'])} | {f(r['p95'])} | {f(r['max'])} "
                   f"| {r['cold_n']} | {f(r['cold_share'], 3)} | {f(r['client_p50'])} | {f(r['client_p95'])} |")
    out += ["", "## Governed lag (ms)", "", "| tool | n | p50 | p95 |", "|---|---|---|---|"]
    out += [f"| {r['tool']} | {r['n']} | {f(r['p50'])} | {f(r['p95'])} |" for r in res["governed_lag"]]
    out += ["", "## Consumer projection lag (ms, p50/p95; governed_lag_ms = compatibility alias)", "",
            "| consumer | n | graph_projection_lag_ms | feed_projection_lag_ms | governed_lag_ms | stream_delay_ms | queue_ms | store_ms | publish_ms |",
            "|---|---|---|---|---|---|---|---|---|"]
    for r in res.get("consumer_lag", []):
        cells = [f"{f(r[k + '_p50'])}/{f(r[k + '_p95'])}" if r[k + "_n"] else "-" for k in (
            "graph_projection_lag_ms", "feed_projection_lag_ms", "governed_lag_ms", "stream_delay_ms", "queue_ms",
            "store_ms", "publish_ms")]
        out.append(f"| {r['consumer']} | {r['n']} | " + " | ".join(cells) + " |")
    c = res["cold_fraction"]
    out += ["", "## Per-session cold fraction", "",
            f"sessions {c['sessions']}, mean {f(c['mean'], 3)}, p50 {f(c['p50'], 3)}, p90 {f(c['p90'], 3)}, max {f(c['max'], 3)}  ",
            "buckets: " + ", ".join(f"{k}: {v}" for k, v in c["buckets"].items()), "",
            "## Governance counter-metrics (each must be 0)", "", "| metric | count | detail |", "|---|---|---|"]
    for k, v in res["counter_metrics"].items():
        detail = v.get("note") or ", ".join(map(str, v["ids"][:5])) or ""
        out.append(f"| {k} | {'n/a' if v['count'] is None else v['count']} | {detail} |")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", choices=["gamma", "prod"])
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--fixture", help="local JSONL of synthetic audit lines; no AWS calls")
    ap.add_argument("--out-dir", default="readings")
    ap.add_argument("--profile", default=None, help="AWS profile (default: the default credential chain)")
    ap.add_argument("--region", default="us-west-2")
    ap.add_argument("--grace-min", type=int, default=15, help="writes newer than this are not yet expected on a consumer line")
    ap.add_argument("--log-group", action="append", help="extra log group (full name); repeatable")
    ap.add_argument("--dlq-queue", action="append", help="override the on-failure SQS queue names; repeatable")
    ap.add_argument("--insights-queries", action="store_true", help="also run the aggregate .query files (extra scans) and attach rows")
    args = ap.parse_args(argv)
    if not args.fixture and not args.env:
        ap.error("one of --env or --fixture is required")

    if args.fixture:
        lines, ws, we = load_fixture(args.fixture)
        res = compute(lines, [], ws, we, args.grace_min, 0)
        res["scanned_bytes"], res["source"], label = 0, f"fixture:{args.fixture}", "fixture"
        res["counter_metrics"]["unrecovered_consumer_failures"]["dlq_note"] = "fixture mode: SQS not read"
    else:
        lines, reports, ws, we, meta = load_aws(args)
        res = compute(lines, reports, ws, we, args.grace_min, meta["dlq_depth"])
        res.update(meta)
        res["source"], label = f"aws:{args.env}", args.env
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = out / f"write-path-reading-{label}-{stamp}"
    base.with_suffix(".json").write_text(json.dumps(res, indent=2, default=str))
    base.with_suffix(".md").write_text(render_markdown(res, f"Write-path reading ({label}, {args.days}d)"))
    print(f"[INFO] wrote {base}.json and {base}.md")
    print(f"[INFO] scanned_bytes_total={res.get('scanned_bytes')} queries_run={res.get('queries_run', 0)}")
    for k, v in res["counter_metrics"].items():
        print(f"[INFO] counter {k} = {v['count']}")
    return res


if __name__ == "__main__":
    main()
