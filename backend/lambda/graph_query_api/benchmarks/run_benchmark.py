"""GHN-vs-RRF multi-hop recall@k benchmark runner (ENC-TSK-I99 / FTR-104 Ph2).

Runs BOTH scoring paths over the same per-query signals on synthetic proxies for
MuSiQue, 2WikiMultiHopQA, and HotpotQA (see synthetic_multihop.py for the
honest-limitations disclosure), reports:

  * recall@k         — fraction of gold supporting facts retrieved in top-k
                       (mean over questions).
  * answerable@k     — fraction of questions with ALL gold supporting facts in
                       top-k (the strict multi-hop metric: you cannot answer
                       until every hop's fact is present).
  * per-hop breakdown of recall@k.
  * fusion latency   — wall time of ONLY the fusion/ranking step (RRF fuse vs
                       GHN energy descent); upstream signal computation is shared
                       and excluded so the comparison is like-for-like.

Plus a lambda_graph/lambda_kw tuning sweep for GHN (RRF is lambda-agnostic — the
reciprocal-rank fusion does not consume the energy weights).

Usage (from backend/lambda/graph_query_api/):
    python3 -m benchmarks.run_benchmark [--seed N] [--out results/ghn_vs_rrf.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# Support both `python3 -m benchmarks.run_benchmark` and direct execution.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from benchmarks import ghn, signals, synthetic_multihop
    from benchmarks.synthetic_multihop import Dataset, Question
else:
    from . import ghn, signals, synthetic_multihop  # type: ignore
    from .synthetic_multihop import Dataset, Question  # type: ignore

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import energy_function as ef  # noqa: E402
import lambda_function as lf  # noqa: E402

DATASETS = ["HotpotQA", "2WikiMultiHopQA", "MuSiQue"]
K_LIST = [1, 2, 3, 5, 10, 20]
GRAPH_ALGO = ef.GDS_PAGERANK_SOURCE  # E_PPR provenance for the synthetic PPR


def _ghn_field(sig: "signals.QuerySignals", lambda_graph: float,
               lambda_kw: float) -> List[float]:
    """h_i = -E_Ph1(x)_i for each candidate, via energy_function (read-only)."""
    h: List[float] = []
    for rid in sig.candidate_ids:
        e = ef.compute_retrieval_energy(
            vector_score=sig.vector_by_rid.get(rid),
            graph_score=sig.graph_by_rid.get(rid),
            keyword_score=sig.keyword_by_rid.get(rid),
            max_graph_score=sig.max_graph,
            max_keyword_score=sig.max_keyword,
            graph_algorithm=GRAPH_ALGO,
            lambda_graph=lambda_graph,
            lambda_kw=lambda_kw,
        )
        h.append(-e["retrieval_energy"])
    return h


def _recall_and_answerable(ranked_ids: Sequence[str], gold: Sequence[str],
                           k_list: Sequence[int]) -> Tuple[Dict[int, float], Dict[int, int]]:
    gold_set = set(gold)
    n_gold = len(gold_set)
    recall: Dict[int, float] = {}
    answerable: Dict[int, int] = {}
    for k in k_list:
        topk = set(ranked_ids[:k])
        hit = len(gold_set & topk)
        recall[k] = hit / n_gold if n_gold else 0.0
        answerable[k] = 1 if hit == n_gold else 0
    return recall, answerable


def _rrf_rank(sig: "signals.QuerySignals") -> List[str]:
    fused = lf._rrf_fuse(signals.rrf_signal_dict(sig), k=lf.RRF_K)
    return [item["record_id"] for item in fused]


def _ghn_rank(sig: "signals.QuerySignals", lambda_graph: float, lambda_kw: float,
              beta: float) -> List[str]:
    h = _ghn_field(sig, lambda_graph, lambda_kw)
    w = signals.coupling_matrix(sig)
    ranked, _ = ghn.rank_candidates(
        sig.candidate_ids, h, w, beta=beta, lambda_graph=lambda_graph,
    )
    return [r["record_id"] for r in ranked]


def evaluate_dataset(ds: Dataset, *, lambda_graph: float, lambda_kw: float,
                     beta: float, precomputed_signals=None) -> Dict[str, object]:
    """Evaluate RRF and GHN over one dataset. Returns aggregated metrics.

    precomputed_signals: optional {qid: QuerySignals} to avoid recomputing the
    (shared, method-independent) signals during a lambda sweep.
    """
    methods = ("rrf", "ghn")
    recall_acc = {m: {k: [] for k in K_LIST} for m in methods}
    answerable_acc = {m: {k: [] for k in K_LIST} for m in methods}
    # Per-hop recall@10 breakdown.
    per_hop = {m: {} for m in methods}
    latency = {m: [] for m in methods}

    for q in ds.questions:
        if precomputed_signals is not None:
            sig = precomputed_signals[q.qid]
        else:
            sig = signals.compute_query_signals(ds, q)

        t0 = time.perf_counter()
        rrf_ids = _rrf_rank(sig)
        latency["rrf"].append((time.perf_counter() - t0) * 1000.0)

        t0 = time.perf_counter()
        ghn_ids = _ghn_rank(sig, lambda_graph, lambda_kw, beta)
        latency["ghn"].append((time.perf_counter() - t0) * 1000.0)

        for m, ids in (("rrf", rrf_ids), ("ghn", ghn_ids)):
            rec, ans = _recall_and_answerable(ids, q.supporting_doc_ids, K_LIST)
            for k in K_LIST:
                recall_acc[m][k].append(rec[k])
                answerable_acc[m][k].append(ans[k])
            per_hop[m].setdefault(q.hops, []).append(rec[10])

    def _mean(xs):
        return round(statistics.mean(xs), 4) if xs else 0.0

    def _p95(xs):
        if not xs:
            return 0.0
        s = sorted(xs)
        return round(s[min(len(s) - 1, int(0.95 * len(s)))], 4)

    result = {"dataset": ds.name, "stats": synthetic_multihop.dataset_stats(ds)}
    for m in methods:
        result[m] = {
            "recall_at_k": {str(k): _mean(recall_acc[m][k]) for k in K_LIST},
            "answerable_at_k": {str(k): _mean(answerable_acc[m][k]) for k in K_LIST},
            "recall_at_10_by_hops": {
                str(hops): _mean(vals) for hops, vals in sorted(per_hop[m].items())
            },
            "fusion_latency_ms": {
                "mean": round(statistics.mean(latency[m]), 4),
                "p95": _p95(latency[m]),
            },
        }
    # Deltas (GHN - RRF).
    result["delta_ghn_minus_rrf"] = {
        "recall_at_k": {
            str(k): round(result["ghn"]["recall_at_k"][str(k)]
                          - result["rrf"]["recall_at_k"][str(k)], 4)
            for k in K_LIST
        },
        "answerable_at_k": {
            str(k): round(result["ghn"]["answerable_at_k"][str(k)]
                          - result["rrf"]["answerable_at_k"][str(k)], 4)
            for k in K_LIST
        },
    }
    return result


def tuning_sweep(datasets: List[Dataset], precomputed, *, beta: float,
                 target_k: int = 10) -> Dict[str, object]:
    """Grid-search lambda_graph x lambda_kw for GHN, scoring by mean recall@target_k
    across all datasets. RRF is lambda-agnostic, so this tunes GHN only."""
    graph_grid = [0.25, 0.5, 0.75, 1.0]
    kw_grid = [0.1, 0.25, 0.5]
    grid_results = []
    best = None
    for lg in graph_grid:
        for lk in kw_grid:
            recalls = []
            answerables = []
            for ds in datasets:
                r = evaluate_dataset(
                    ds, lambda_graph=lg, lambda_kw=lk, beta=beta,
                    precomputed_signals=precomputed[ds.name],
                )
                recalls.append(r["ghn"]["recall_at_k"][str(target_k)])
                answerables.append(r["ghn"]["answerable_at_k"][str(target_k)])
            mean_recall = round(statistics.mean(recalls), 4)
            mean_answerable = round(statistics.mean(answerables), 4)
            entry = {
                "lambda_graph": lg, "lambda_kw": lk,
                f"mean_recall_at_{target_k}": mean_recall,
                f"mean_answerable_at_{target_k}": mean_answerable,
            }
            grid_results.append(entry)
            score = (mean_recall, mean_answerable)
            if best is None or score > best["_score"]:
                best = {**entry, "_score": score}
    if best:
        best.pop("_score", None)
    return {"target_k": target_k, "grid": grid_results, "recommended": best}


def main(argv=None):
    parser = argparse.ArgumentParser(description="GHN vs RRF multi-hop benchmark")
    parser.add_argument("--seed", type=int, default=1099)
    parser.add_argument("--beta", type=float, default=ghn.DEFAULT_BETA)
    parser.add_argument("--lambda-graph", type=float, default=ef.DEFAULT_LAMBDA_GRAPH)
    parser.add_argument("--lambda-kw", type=float, default=ef.DEFAULT_LAMBDA_KW)
    parser.add_argument("--out", type=str,
                        default=str(Path(__file__).resolve().parent / "results" / "ghn_vs_rrf.json"))
    parser.add_argument("--skip-sweep", action="store_true")
    args = parser.parse_args(argv)

    datasets = [synthetic_multihop.generate(name, seed=args.seed) for name in DATASETS]

    # Precompute the (method-independent) signals once per question so the
    # headline eval and the lambda sweep reuse them.
    precomputed = {}
    for ds in datasets:
        precomputed[ds.name] = {
            q.qid: signals.compute_query_signals(ds, q) for q in ds.questions
        }

    per_dataset = [
        evaluate_dataset(
            ds, lambda_graph=args.lambda_graph, lambda_kw=args.lambda_kw,
            beta=args.beta, precomputed_signals=precomputed[ds.name],
        )
        for ds in datasets
    ]

    report = {
        "task": "ENC-TSK-I99",
        "feature": "ENC-FTR-104 Ph2 (AC-3 GHN energy-descent, AC-4 recall@k eval)",
        "generated_at_epoch": int(time.time()),
        "dataset_source": "SYNTHETIC — real MuSiQue/2Wiki/HotpotQA splits "
                          "unfetchable (no network, datasets lib absent). See "
                          "synthetic_multihop.py module docstring.",
        "config": {
            "seed": args.seed, "beta": args.beta,
            "lambda_graph": args.lambda_graph, "lambda_kw": args.lambda_kw,
            "rrf_k": lf.RRF_K, "ppr_damping": lf.PPR_DAMPING_FACTOR,
            "k_list": K_LIST,
        },
        "methods": {
            "rrf": "lambda_function._rrf_fuse (production, imported read-only)",
            "ghn": "benchmarks.ghn graph-coupled Hopfield energy descent "
                   "(field h = -energy_function.compute_retrieval_energy)",
        },
        "per_dataset": per_dataset,
    }

    if not args.skip_sweep:
        report["tuning_sweep"] = tuning_sweep(datasets, precomputed, beta=args.beta)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))

    # Console summary.
    print(f"\n=== GHN vs RRF (synthetic multi-hop) — seed={args.seed} beta={args.beta} "
          f"lambda_graph={args.lambda_graph} lambda_kw={args.lambda_kw} ===")
    for r in per_dataset:
        print(f"\n{r['dataset']}  ({r['stats']['n_questions']} q, "
              f"{r['stats']['n_documents']} docs, {r['stats']['n_edges']} edges, "
              f"hops={r['stats']['hop_distribution']})")
        for m in ("rrf", "ghn"):
            rk = r[m]["recall_at_k"]
            ak = r[m]["answerable_at_k"]
            lat = r[m]["fusion_latency_ms"]
            print(f"  {m.upper():4s} recall@ "
                  + " ".join(f"{k}={rk[str(k)]:.3f}" for k in K_LIST)
                  + f"  | answerable@10={ak['10']:.3f}"
                  + f"  | fuse {lat['mean']:.3f}ms(mean)")
        d = r["delta_ghn_minus_rrf"]["recall_at_k"]
        da = r["delta_ghn_minus_rrf"]["answerable_at_k"]
        print("  DELTA recall  " + " ".join(f"{k}={d[str(k)]:+.3f}" for k in K_LIST))
        print("  DELTA answ@   " + " ".join(f"{k}={da[str(k)]:+.3f}" for k in K_LIST))

    if not args.skip_sweep:
        rec = report["tuning_sweep"]["recommended"]
        print(f"\n=== Tuning sweep (GHN, score=mean recall@{report['tuning_sweep']['target_k']}) ===")
        print(f"  RECOMMENDED: lambda_graph={rec['lambda_graph']} lambda_kw={rec['lambda_kw']} "
              f"-> mean_recall@10={rec['mean_recall_at_10']} "
              f"mean_answerable@10={rec['mean_answerable_at_10']}")

    print(f"\nWrote {out_path}")
    return report


if __name__ == "__main__":
    main()
