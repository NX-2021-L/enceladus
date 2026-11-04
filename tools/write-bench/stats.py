"""Statistics for the write-bench (BRD DOC-E32D0ED08473 section 7.5). Stdlib only.

* Percentiles use linear interpolation between order statistics (R type 7).
* Bootstrap CIs: percentile method, 95 percent, 10,000 resamples, seeded
  random.Random (deterministic; seed per cell derived from a stable hash).
* Warm and cold are NEVER pooled: a cell key always includes the series.
* p99 is reported but flagged information_only (a stable p99 needs ~1,000 samples).
* p95 is gating only when n >= MIN_N_P95 (300).
"""
from __future__ import annotations

import hashlib
import math
import random
from typing import Dict, Iterable, List, Sequence, Tuple

RESAMPLES = 10_000
MIN_N_P95 = 300
BASE_SEED = 20261104
CI_LEVEL = 0.95


def percentile(sorted_data: Sequence[float], p: float) -> float:
    """p in [0, 100]; `sorted_data` ascending. Linear interpolation (type 7)."""
    if not sorted_data:
        raise ValueError("percentile of empty data")
    if not 0 <= p <= 100:
        raise ValueError("p must be within [0, 100]")
    n = len(sorted_data)
    if n == 1:
        return float(sorted_data[0])
    h = (n - 1) * p / 100.0
    lo = math.floor(h)
    hi = min(lo + 1, n - 1)
    return float(sorted_data[lo] + (h - lo) * (sorted_data[hi] - sorted_data[lo]))


def cell_seed(key: str, base: int = BASE_SEED) -> int:
    return int.from_bytes(hashlib.sha256(f"{base}:{key}".encode()).digest()[:8], "big")


def _quantiles(vals: List[float], level: float = CI_LEVEL) -> Tuple[float, float]:
    vals.sort()
    a = (1 - level) / 2 * 100
    return percentile(vals, a), percentile(vals, 100 - a)


def bootstrap_percentile_cis(data: Sequence[float], ps: Sequence[float] = (50, 95),
                             resamples: int = RESAMPLES, seed: int = BASE_SEED
                             ) -> Dict[float, Tuple[float, float]]:
    """95 percent bootstrap CI for each percentile in `ps` (one shared set of resamples)."""
    if not data:
        raise ValueError("bootstrap of empty data")
    rng = random.Random(seed)
    n = len(data)
    pop = list(data)
    draws: Dict[float, List[float]] = {p: [] for p in ps}
    for _ in range(resamples):
        s = sorted(rng.choices(pop, k=n))
        for p in ps:
            draws[p].append(percentile(s, p))
    return {p: _quantiles(v) for p, v in draws.items()}


def bootstrap_delta_cis(pre: Sequence[float], post: Sequence[float], ps: Sequence[float] = (50, 95),
                        resamples: int = RESAMPLES, seed: int = BASE_SEED
                        ) -> Dict[float, Tuple[float, float]]:
    """95 percent CI of stat(post) - stat(pre); pre and post resampled independently."""
    if not pre or not post:
        raise ValueError("delta bootstrap needs both sides")
    rng = random.Random(seed)
    npre, npost = len(pre), len(post)
    a, b = list(pre), list(post)
    draws: Dict[float, List[float]] = {p: [] for p in ps}
    for _ in range(resamples):
        sa = sorted(rng.choices(a, k=npre))
        sb = sorted(rng.choices(b, k=npost))
        for p in ps:
            draws[p].append(percentile(sb, p) - percentile(sa, p))
    return {p: _quantiles(v) for p, v in draws.items()}


def summarize(data: Sequence[float], key: str = "", resamples: int = RESAMPLES,
              seed: int = BASE_SEED) -> Dict[str, object]:
    """Per-cell summary. All numbers are absolute milliseconds."""
    s = sorted(data)
    n = len(s)
    if n == 0:
        return {"n": 0}
    cis = bootstrap_percentile_cis(s, (50, 95), resamples, cell_seed(key, seed))
    return {
        "n": n,
        "p50": percentile(s, 50), "p90": percentile(s, 90), "p95": percentile(s, 95),
        "p99": percentile(s, 99), "p99_information_only": True,
        "p50_ci95": list(cis[50]), "p95_ci95": list(cis[95]),
        "p95_gating_ok": n >= MIN_N_P95,
        "min": s[0], "max": s[-1], "mean": sum(s) / n,
        "resamples": resamples,
    }


def cell_key(operation: str, arm: str, series: str) -> str:
    return f"{operation}|{arm}|{series}"


def group_samples(calls: Iterable[dict], metric: str = "client_total_ms") -> Dict[str, List[float]]:
    """Group measured (non-warmup, ok) calls by operation x arm x series."""
    cells: Dict[str, List[float]] = {}
    for c in calls:
        if c.get("warmup") or not c.get("ok", True):
            continue
        v = c.get(metric)
        if v is None:
            continue
        cells.setdefault(cell_key(c["operation"], c["arm"], c["series"]), []).append(float(v))
    return cells


def summarize_run(calls: Iterable[dict], metric: str = "client_total_ms",
                  resamples: int = RESAMPLES) -> Dict[str, Dict[str, object]]:
    return {k: summarize(v, k, resamples) for k, v in sorted(group_samples(calls, metric).items())}
