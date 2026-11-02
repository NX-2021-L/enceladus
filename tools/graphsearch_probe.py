#!/usr/bin/env python3
"""graphsearch_probe: shared reading tool for PLN-103 graph-search latency work (ENC-TSK-S02).

Runs `elr compact_context --mode record` over anchors, waits for CloudWatch ingestion,
then aggregates the hybrid `graphsearch_query` audit lines (per-signal timings,
pathway_status, candidates) from Logs Insights. Prints one JSON summary. stdlib + boto3.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from typing import Any, Dict, List, Optional

ELR = os.path.expanduser("~/.enceladus/elr/elr")
LOG_GROUPS = {"prod": "/aws/lambda/devops-graph-query-api", "v4-gamma": "/aws/lambda/devops-graph-query-api-gamma"}
TEN_FIELDS = ("vector_ms", "graph_ms", "keyword_ms", "facets_ms", "pathway_ms", "graph_candidates",
              "keyword_candidates", "graph_algorithm", "pathway_status", "query_hash")
TIMED = ("duration_ms", "vector_ms", "graph_ms", "keyword_ms", "facets_ms", "pathway_ms")


def percentile(values: List[float], p: float) -> Optional[float]:
    """Nearest-rank percentile (p in 0..100); None for an empty list."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    return vals[max(1, math.ceil(p / 100.0 * len(vals))) - 1]


def p50_p95(values: List[float]) -> Dict[str, Optional[float]]:
    return {"p50": percentile(values, 50), "p95": percentile(values, 95)}


def parse_audit(message: str) -> Optional[Dict[str, Any]]:
    """Extract the JSON object from a Lambda log line; None when not parseable."""
    i = message.find("{")
    if i < 0:
        return None
    try:
        obj = json.loads(message[i:])
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def aggregate(audits: List[Dict[str, Any]], top_n: int) -> Dict[str, Any]:
    n = len(audits)
    out: Dict[str, Any] = {"n_audit_lines": n}
    if not n:
        return out
    present = sum(1 for a in audits for f in TEN_FIELDS if f in a and a[f] is not None)
    out["fields_present_fraction"] = round(present / (n * len(TEN_FIELDS)), 4)
    all_present = sum(1 for a in audits if all(a.get(f) is not None for f in TEN_FIELDS))
    out["lines_with_all_fields"] = all_present
    for f in TIMED:
        out[f] = p50_p95([a[f] for a in audits if isinstance(a.get(f), (int, float))])
    out["pathway_status"] = dict(Counter(str(a.get("pathway_status")) for a in audits))
    out["graph_algorithm"] = dict(Counter(str(a.get("graph_algorithm")) for a in audits))
    kc = [a["keyword_candidates"] for a in audits if isinstance(a.get("keyword_candidates"), int)]
    out["frac_keyword_candidates_lt_top_n"] = round(sum(1 for k in kc if k < top_n) / len(kc), 4) if kc else None
    ec = [a["edge_count"] for a in audits if isinstance(a.get("edge_count"), int)]
    out["frac_edge_count_gt0"] = round(sum(1 for e in ec if e > 0) / len(ec), 4) if ec else None
    return out


def run_elr(args: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([ELR] + args, capture_output=True, text=True, timeout=timeout)


def sample_ids(profile: str, n: int) -> List[str]:
    with tempfile.TemporaryDirectory() as d:
        run_elr(["list", "--project", "enceladus", "--type", "task", "--status", "closed", "--page-size",
                 str(min(max(n, 1), 200)), "--page", "", "--lists-dir", d, "--profile", profile])
        ids: List[str] = []
        for fn in os.listdir(d):
            if fn.endswith(".ids"):
                with open(os.path.join(d, fn)) as fh:
                    ids += [ln.strip() for ln in fh if ln.strip()]
    return ids[:n]


def insights(logs, group: str, query: str, start: int, end: int) -> List[Dict[str, str]]:
    qid = logs.start_query(logGroupName=group, startTime=start, endTime=end, queryString=query, limit=10000)["queryId"]
    for _ in range(120):
        r = logs.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            return [{c["field"]: c["value"] for c in row} for row in r.get("results", [])]
        time.sleep(1)
    return []


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", choices=sorted(LOG_GROUPS), required=True)
    ap.add_argument("--anchors-file")
    ap.add_argument("--sample", type=int, default=30)
    ap.add_argument("--top-n", type=int, default=20)
    ap.add_argument("--settle-s", type=int, default=25)
    ap.add_argument("--json", action="store_true", help="(default output is JSON; accepted for symmetry)")
    a = ap.parse_args(argv)
    import boto3  # deferred so helpers are importable without boto3 for offline tests

    if a.anchors_file:
        with open(a.anchors_file) as fh:
            anchors = [ln.strip() for ln in fh if ln.strip()]
    else:
        anchors = sample_ids(a.profile, a.sample)
    start = int(time.time()) - 2
    walls: List[float] = []
    failures = 0
    for rid in anchors:
        t0 = time.perf_counter()
        try:
            cp = run_elr(["compact_context", "--mode", "record", "--record-id", rid, "--profile", a.profile,
                          "--top-n", str(a.top_n), "--json"])
            ok = cp.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        walls.append((time.perf_counter() - t0) * 1000)
        failures += 0 if ok else 1  # not-found anchors are tolerated, only counted
    time.sleep(a.settle_s)
    end = int(time.time()) + 1
    logs = boto3.Session(profile_name="enceladus-agent", region_name="us-west-2").client("logs")
    group = LOG_GROUPS[a.profile]
    rows = insights(logs, group, "fields @message | filter @message like /graphsearch_query/ and "
                    "@message like /hybrid/ | sort @timestamp asc", start, end)
    audits = [x for x in (parse_audit(r.get("@message", "")) for r in rows)
              if x and x.get("event") == "graphsearch_query" and x.get("search_type") == "hybrid"]
    warn = insights(logs, group, "fields @message | filter @message like /UnknownPropertyKeyWarning/ | stats count(*) as c",
                    start, end)
    cold = insights(logs, group, "fields @message | filter @message like /REPORT/ and @message like /Init Duration/ "
                    "| stats count(*) as c", start, end)
    summary = {"profile": a.profile, "log_group": group, "n_calls": len(anchors), "elr_failures": failures,
               **aggregate(audits, a.top_n),
               "unknown_property_warnings": int(warn[0]["c"]) if warn else 0,
               "cold_count": int(cold[0]["c"]) if cold else 0,
               "client_wall_ms": p50_p95(walls)}
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
