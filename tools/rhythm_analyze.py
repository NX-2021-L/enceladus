#!/usr/bin/env python3
"""Distill the rhythm-cycle harvest bundle into dashboard_data.json.

Reads the local harvest bundle produced by rhythm_harvest.py (tier beats, tenant
stanzas, CloudWatch series, percolation DDB rows, Lambda operational metrics, and
the rhythm tenant manifest) and emits a single dashboard_data.json containing the
time series, signals, and notes the rhythm dashboard generator consumes.

This tool is read-only and performs no AWS calls; it operates entirely on the
files already written into the harvest output directory. Its output schema is a
stable contract with the dashboard generator — top-level keys are:
generated_at, tiers, tenants, cloudwatch, percolation, lambda, manifest.

Usage:
  # Distill the default harvest bundle
  python3 tools/rhythm_analyze.py

  # Point at a specific harvest output directory
  python3 tools/rhythm_analyze.py --out /Users/jreese/rhythm-analysis

The HARVEST_OUT environment variable, when set, provides the default output
directory (overridden by --out).

Part of the Enceladus rhythm-cycle observability tooling.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from datetime import datetime


DEFAULT_OUT = os.environ.get("HARVEST_OUT", "/Users/jreese/rhythm-analysis")


def _load(out_dir, rel):
    """Load a JSON file from the harvest bundle, relative to out_dir."""
    path = os.path.join(out_dir, rel)
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"[ERROR] Missing harvest artifact: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] Malformed JSON in {path}: {exc}")


def series_by_metric(cw, metric):
    """Merge all dimension sets for a metric into one time-sorted avg series."""
    pts = []
    for m in cw["metrics"]:
        if m["metric"] == metric:
            for p in m["points"]:
                pts.append((p["t"], p.get("avg")))
    pts.sort()
    return pts


def cee_series_by_category(cw_cee: dict) -> dict:
    """Per-category EntropyFindingCount series — do not collapse dimensions (N49)."""
    out: dict = {}
    for m in cw_cee.get("metrics", []):
        if m.get("metric") != "EntropyFindingCount":
            continue
        category = (m.get("dimensions") or {}).get("Category")
        if not category:
            continue
        pts = sorted((p["t"], p.get("avg")) for p in m.get("points", []))
        out[category] = pts
    return out


def cadence_minutes(bl):
    """Median inter-beat interval, in minutes, for a list of beats (or None)."""
    ts = sorted(b.get("beat_at") or b.get("alignment_point_utc") or "" for b in bl)
    ts = [t for t in ts if t]
    if len(ts) < 2:
        return None
    deltas = []
    for a, b in zip(ts, ts[1:]):
        try:
            da = datetime.fromisoformat(a.replace("Z", "+00:00"))
            db = datetime.fromisoformat(b.replace("Z", "+00:00"))
            deltas.append((db - da).total_seconds() / 60)
        except Exception:
            pass
    return round(statistics.median(deltas), 1) if deltas else None


def field_series(bl, field):
    """Extract [(beat_at, value), ...] pairs for a field present on the beats."""
    return [(b.get("beat_at"), b.get(field)) for b in bl if field in b]


def build_dashboard(out_dir):
    """Read the harvest bundle in out_dir and return the dashboard data dict."""
    beats = _load(out_dir, "aggregates/tier_beats.json")
    stanzas = _load(out_dir, "aggregates/tenant_stanzas.json")
    cw_gh = _load(out_dir, "cloudwatch/Enceladus_GraphHealth.json")
    cw_rh = _load(out_dir, "cloudwatch/Enceladus_Rhythm.json")
    cw_cee = _load(out_dir, "cloudwatch/Enceladus_CEE.json")
    cw_perc = _load(out_dir, "cloudwatch/Enceladus_Percolation.json")
    lam = _load(out_dir, "cloudwatch/lambda.json")
    perc = _load(out_dir, "ddb/percolation_telemetry.json")
    manifest = _load(out_dir, "config/rhythm_tenants.json")

    data = {"generated_at": datetime.utcnow().isoformat() + "Z", "tiers": {}, "tenants": {}, "cloudwatch": {}, "percolation": {}}

    # --- Tiers ---
    sense = beats["sense"]["beats"]
    data["tiers"]["sense"] = {
        "cadence_min": cadence_minutes(sense), "beat_count": len(sense),
        "series": {f: field_series(sense, f) for f in ["open_task_count", "queue_depth", "open_task_delta"]},
        "latest_session_census": (sense[-1].get("session_census") if sense else []),
    }
    light = beats["light_integrate"]["beats"]
    data["tiers"]["light_integrate"] = {
        "cadence_min": cadence_minutes(light), "beat_count": len(light),
        "series": {"delta_count": field_series(light, "delta_count")},
        "actions_latest": (light[-1].get("actions") if light else []),
    }
    decide = beats["decide"]["beats"]
    data["tiers"]["decide"] = {
        "cadence_min": cadence_minutes(decide), "beat_count": len(decide),
        "series": {f: field_series(decide, f) for f in ["backlog_open_leaves", "backlog_open_leaves_delta", "backlog_page_count"]},
        "dispatch_nonempty": sum(1 for b in decide if b.get("dispatch_plan")),
    }
    heavy = beats["heavy_integrate"]["beats"]
    data["tiers"]["heavy_integrate"] = {
        "cadence_min": cadence_minutes(heavy), "beat_count": len(heavy),
        "invoked_history": [(b.get("beat_at"), (b.get("tenant_orchestration") or {}).get("manifest_size"),
                             len((b.get("tenant_orchestration") or {}).get("invoked_tenants") or [])) for b in heavy],
        "recompute_errors": sum(1 for b in heavy if isinstance(b.get("recompute_backlog"), dict) and b["recompute_backlog"].get("error")),
    }
    coh = beats["coherence"]["beats"]
    data["tiers"]["coherence"] = {"cadence_min": cadence_minutes(coh), "beat_count": len(coh)}

    # --- Tenants (from the one tenant-invoking window's stanzas) ---
    win = list(stanzas["windows"].values())
    latest_win = win[-1] if win else {}
    for name, st in latest_win.items():
        data["tenants"][name] = {"status": st.get("status"), "detail": st.get("detail")}

    # --- CloudWatch series for charts ---
    data["cloudwatch"]["GraphHealth"] = {m: series_by_metric(cw_gh, m) for m in
        ["FiedlerAlgebraicConnectivity", "GraphEdgeDensity", "IsolatedNodeRatio", "GraphNodeCount"]}
    data["cloudwatch"]["Rhythm"] = {m: series_by_metric(cw_rh, m) for m in
        ["beat_duration_ms", "beat_cost_estimate", "backlog_open_leaves"]}
    data["cloudwatch"]["CEE"] = cee_series_by_category(cw_cee)
    data["cloudwatch"]["CEE_raw"] = {
        m["metric"] + "|" + json.dumps(m["dimensions"]): m["points"]
        for m in cw_cee["metrics"]
    }
    data["cloudwatch"]["Percolation"] = {m: series_by_metric(cw_perc, m) for m in ["analytical_pc", "empirical_pc", "mean_degree"]}

    # --- Percolation DDB rows (rich) ---
    prows = sorted(perc.get("rows", []), key=lambda r: r.get("computed_at", ""))
    data["percolation"]["rows"] = [{k: r.get(k) for k in
        ["computed_at", "analytical_pc", "empirical_pc", "mean_degree", "node_count", "edge_count",
         "flow_weight_entropy", "spurious_attractor_rate", "analytical_pc_in_range"]} for r in prows]

    # --- Lambda operational ---
    data["lambda"] = {fn: {"invocations": sum(p["sum"] or 0 for p in v["Invocations"]),
                            "errors": sum(p["sum"] or 0 for p in v["Errors"]),
                            "avg_duration_ms": round(statistics.mean([p["avg"] for p in v["Duration"] if p["avg"]]), 1) if any(p["avg"] for p in v["Duration"]) else None}
                      for fn, v in lam.items()}

    # --- manifest (cadence/enabled) ---
    data["manifest"] = {name: {"enabled": t.get("enabled"), "order": t.get("order"),
                                "window_hours": (t.get("expected_output_contract") or {}).get("window_hours")}
                         for name, t in (manifest.get("tenants") or {}).items()}

    return data


def print_key_signals(data):
    """Emit a quick console read of the key signals for eyeballing a run."""
    print("\n=== KEY SIGNALS ===")
    print("decide backlog_open_leaves:", [v for _, v in data['tiers']['decide']['series']['backlog_open_leaves']])
    print("GraphHealth Fiedler:", [round(v, 4) if v else v for _, v in data['cloudwatch']['GraphHealth']['FiedlerAlgebraicConnectivity']][-8:])
    print("GraphHealth IsolatedNodeRatio:", [round(v, 4) if v else v for _, v in data['cloudwatch']['GraphHealth']['IsolatedNodeRatio']][-8:])
    print("Percolation analytical_pc:", [r['analytical_pc'] for r in data['percolation']['rows']])
    print("Percolation empirical_pc:", [r['empirical_pc'] for r in data['percolation']['rows']])
    print("tenants:", {k: v['detail'] for k, v in data['tenants'].items()})
    print("lambda:", data['lambda'])


def main():
    parser = argparse.ArgumentParser(
        description="Distill the rhythm-cycle harvest bundle into dashboard_data.json.")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="Harvest output directory to read from and write dashboard_data.json into "
                             f"(default: {DEFAULT_OUT})")
    args = parser.parse_args()

    out_dir = args.out
    data = build_dashboard(out_dir)

    dest = os.path.join(out_dir, "dashboard_data.json")
    try:
        with open(dest, "w") as fh:
            json.dump(data, fh, indent=2, default=str)
    except OSError as exc:
        raise SystemExit(f"[ERROR] Could not write {dest}: {exc}")

    print("dashboard_data.json written")
    print_key_signals(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
