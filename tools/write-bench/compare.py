#!/usr/bin/env python3
"""Pre/post comparison for write-bench runs (BRD 7.5).

    python3 compare.py --pre run1.json [run2.json run3.json] --post runA.json [...] \
        [--out compare.json] [--md compare.md] [--metric client_total_ms] [--resamples 10000]

* Delta per cell (operation x arm x series), cells paired by key, samples NOT paired.
  Delta = post - pre; 95 percent bootstrap CI (independent resampling of each side).
  A change is an improvement only if the delta CI excludes zero (and is negative).
* Up to three runs per side are pooled WITHIN a cell, but only after the
  between-run consistency check; the result still carries `pool_consistent`.
* Consistency: run i is divergent in a cell if its p50 lies outside the p50 95 percent
  CI of EVERY other run (so a single outlier is isolated; see README).
* Warm and cold are separate cells and never pooled.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, List

import stats

MAX_RUNS = 3


def load_run(path: str) -> List[dict]:
    with open(path) as fh:
        doc = json.load(fh)
    return doc["calls"] if isinstance(doc, dict) else doc


def consistency(per_run: List[List[float]], key: str, resamples: int) -> dict:
    """per_run: samples of one cell for each run."""
    infos = []
    for i, data in enumerate(per_run):
        if not data:
            infos.append({"run": i, "n": 0})
            continue
        cis = stats.bootstrap_percentile_cis(data, (50,), resamples, stats.cell_seed(f"{key}:run{i}"))
        infos.append({"run": i, "n": len(data), "p50": stats.percentile(sorted(data), 50), "p50_ci95": list(cis[50])})
    usable = [x for x in infos if x["n"]]
    for x in usable:
        others = [o for o in usable if o is not x]
        if not others:
            x["divergent"] = False
            continue
        x["divergent"] = all(not (o["p50_ci95"][0] <= x["p50"] <= o["p50_ci95"][1]) for o in others)
    return {"runs": infos, "any_divergent": any(x.get("divergent") for x in usable), "checked": len(usable) >= 2}


def side_cells(paths: List[str], metric: str) -> Dict[str, List[List[float]]]:
    out: Dict[str, List[List[float]]] = {}
    for idx, p in enumerate(paths):
        for k, v in stats.group_samples(load_run(p), metric).items():
            runs = out.setdefault(k, [[] for _ in paths])
            runs[idx] = v
    return out


def _cell_stats(samples: List[float], key: str, resamples: int) -> dict:
    return stats.summarize(samples, key, resamples)


def compare(pre_paths: List[str], post_paths: List[str], metric: str = "client_total_ms",
            resamples: int = stats.RESAMPLES) -> dict:
    if len(pre_paths) > MAX_RUNS or len(post_paths) > MAX_RUNS:
        raise ValueError(f"at most {MAX_RUNS} runs per side")
    pre, post = side_cells(pre_paths, metric), side_cells(post_paths, metric)
    cells = {}
    for key in sorted(set(pre) & set(post)):
        pre_runs, post_runs = pre[key], post[key]
        pre_all = [x for r in pre_runs for x in r]
        post_all = [x for r in post_runs for x in r]
        c_pre, c_post = consistency(pre_runs, key + ":pre", resamples), consistency(post_runs, key + ":post", resamples)
        deltas = stats.bootstrap_delta_cis(pre_all, post_all, (50, 95), resamples, stats.cell_seed(key + ":delta"))
        s_pre, s_post = _cell_stats(pre_all, key + ":pre", resamples), _cell_stats(post_all, key + ":post", resamples)
        entry = {"pre": s_pre, "post": s_post,
                 "pool_consistent": not (c_pre["any_divergent"] or c_post["any_divergent"]),
                 "consistency": {"pre": c_pre, "post": c_post}}
        for p, name in ((50, "p50"), (95, "p95")):
            lo, hi = deltas[p]
            value = s_post[name] - s_pre[name]
            excludes = lo > 0 or hi < 0
            entry[f"delta_{name}"] = {
                "value_ms": value, "ci95": [lo, hi], "excludes_zero": excludes,
                "improved": excludes and hi < 0,
                "regressed": excludes and lo > 0,
                "gating_ok": True if name == "p50" else bool(s_pre["p95_gating_ok"] and s_post["p95_gating_ok"]),
            }
        cells[key] = entry
    return {"metric": metric, "resamples": resamples, "pre_runs": pre_paths, "post_runs": post_paths,
            "cells_only_pre": sorted(set(pre) - set(post)), "cells_only_post": sorted(set(post) - set(pre)),
            "cells": cells}


def to_markdown(result: dict) -> str:
    lines = [
        f"Metric: `{result['metric']}`, absolute milliseconds. Delta = post - pre; 95% bootstrap CI "
        f"({result['resamples']} resamples). p99 is information only and omitted here.", "",
        "| cell (operation / arm / series) | n pre | n post | p50 pre | p50 post | d p50 [CI] | p95 pre | p95 post | d p95 [CI] | verdict | pool |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]

    def verdict(d: dict) -> str:
        if not d["gating_ok"]:
            return "n<300 (not gating)"
        return "improved" if d["improved"] else ("regressed" if d["regressed"] else "no change")

    for key, c in result["cells"].items():
        op, arm, series = key.split("|")
        d50, d95 = c["delta_p50"], c["delta_p95"]
        lines.append(
            f"| {op} / {arm} / {series} | {c['pre']['n']} | {c['post']['n']} "
            f"| {c['pre']['p50']:.1f} | {c['post']['p50']:.1f} | {d50['value_ms']:+.1f} [{d50['ci95'][0]:+.1f}, {d50['ci95'][1]:+.1f}] "
            f"| {c['pre']['p95']:.1f} | {c['post']['p95']:.1f} | {d95['value_ms']:+.1f} [{d95['ci95'][0]:+.1f}, {d95['ci95'][1]:+.1f}] "
            f"| p50 {verdict(d50)}; p95 {verdict(d95)} | {'ok' if c['pool_consistent'] else 'DIVERGENT'} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pre", nargs="+", required=True)
    ap.add_argument("--post", nargs="+", required=True)
    ap.add_argument("--metric", default="client_total_ms")
    ap.add_argument("--resamples", type=int, default=stats.RESAMPLES)
    ap.add_argument("--out", help="write JSON here (default: stdout)")
    ap.add_argument("--md", help="write a markdown table here")
    a = ap.parse_args(argv)
    res = compare(a.pre, a.post, a.metric, a.resamples)
    text = json.dumps(res, indent=2)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    if a.md:
        with open(a.md, "w") as fh:
            fh.write(to_markdown(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
