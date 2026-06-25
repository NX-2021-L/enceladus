#!/usr/bin/env python3
"""ENC-TSK-I06 — Duplicate-certainty model over the Enceladus near-duplicate
pair corpus (Dedup P2).

Phase 2 of the PLN-052 dedup track and the probabilistic successor to
ENC-TSK-I05. Where I05 turns the ENC-TSK-H91 cosine signal into hard
same-type >=0.95 *clusters* (a single threshold + union-find), I06 asks the
sharper question: **for a given candidate pair, how certain are we that it is a
true duplicate, and can we carve out an auto-merge region whose precision we can
*certify* with a statistical lower bound?**

It is a strictly **shadow-mode / propose-only** analysis tool: it reads the
governed pair corpus (+ optional per-record metadata), fits a model, and writes
local (+ optional S3) result artifacts. It performs **zero mutations** — no
tracker writes, no merges, nothing proposed to the governed store. A human (or a
later governed task) decides what to do with the per-pair tiers and the
certificate.

Pipeline (READ -> SIGNALS -> FUSE -> CALIBRATE -> CERTIFY -> SINK):

  READ      Candidate pairs come from an ENC-TSK-H91 ``pairs.jsonl``
            (``--source pairs``; each row ``{a, b, a_type, b_type, cosine}``) or
            are computed from the corpus via the ENC-TSK-H89 ``vector_read``
            path, reusing ``correlation_analysis_h91`` verbatim (single governed
            read path). Only **same-type** pairs are scored. An optional
            ``--records`` JSON map supplies the per-record text + graph +
            metadata fields the non-cosine signals need; without it those
            signals degrade to *unavailable* (surfaced as a coverage warning),
            exactly as I05's ``--metadata`` degrades gracefully.

  SIGNALS   Four signal families per pair, each a float in ``[0, 1]`` or
            ``None`` when its inputs are absent:
              * ``cosine``     — the embedding cosine (the H91 signal).
              * ``lexical``    — token-set Jaccard over title (+ intent/body).
              * ``structural`` — Jaccard of the two records' graph neighborhoods
                                 (related_*_ids / neighbor_ids / parent) plus a
                                 direct cross-reference bonus.
              * ``metadata``   — agreement of priority / category / status-family
                                 and created-time proximity.

  FUSE      ``logit(p_dup) = w0 + sum_k w_k * s_k`` — a **log-odds fusion**: the
            signals are combined linearly in log-odds space by an L2-regularized
            logistic regression fit on the labeled seed. Per-pair missing signals
            are mean-imputed (and flagged) so a partially-covered pair still
            scores. Pure-Python + deterministic (fixed init / iteration budget);
            numpy is not required for fusion.

  CALIBRATE The fused log-odds is mapped to a trustworthy probability by
            **Platt** scaling (default; ``p = sigmoid(A*f + B)`` with Platt's
            target smoothing) or **isotonic** regression (``--calibration
            isotonic``; pool-adjacent-violators monotone fit). To keep the
            certificate honest, fusion + calibration are fit with k-fold
            **out-of-fold** (OOF) cross-validation: the precision the certificate
            reports is measured on held-out predictions, never in-sample. A final
            model fit on all labels scores the unlabeled pairs.

  CERTIFY   A **conjunctive auto-merge certificate** = the AND of clauses
            (calibrated_p >= tau_p, cosine >= tau_cos, same_type, and lexical >=
            tau_lex when available). Over the **labeled OOF** pairs that fall in
            the certificate region, region precision is modeled as
            ``Beta(a0 + k, b0 + (n - k))`` (Jeffreys prior a0=b0=0.5 by default,
            k = true dups, n = labeled pairs in region). The reported certificate
            is the **Beta-posterior 95% lower-confidence bound**
            ``betaincinv(a0 + k, b0 + (n - k), 0.05)`` — i.e. "with 95% posterior
            confidence, auto-merge-region precision is at least this". Each pair
            is tiered ``auto-merge`` / ``review`` / ``distinct``.

  SINK      ``write_results`` mirrors the H91 / I05 sink: ALWAYS writes
            ``verdicts.jsonl`` + ``summary.json`` to ``--out`` and emits one
            structured ``DEDUP_CERTAINTY {json-summary}`` stdout line (the
            CloudWatch-degraded mirror); when ``DEDUP_CERTAINTY_BUCKET`` is set it
            ALSO best-effort PUTs both files to S3. An S3 failure never aborts the
            local write.

Labels. The certificate is only as trustworthy as its labels. ``--labels``
supplies a real labeled set ``{"<a>|<b>": 0|1}``. Without it the tool derives a
**weak seed** from the H91 corpus: near-identical pairs (cosine >= --pos-cosine)
are weak-positives; pairs that are highly cosine-similar yet *textually*
divergent (lexical < --neg-lexical) are weak-negatives — an independent negative
signal that breaks the cosine-vs-cosine circularity. When ``--records`` is absent
the only available negatives are a low-cosine band, which is **circular** (labels
and a model feature are both cosine); the tool loudly flags this so the reported
LCB is read as internal consistency, not external validity. Supplying
``--records`` (independent signals) and/or ``--labels`` (ground truth) is what
makes the certificate meaningful.

verdicts.jsonl schema (one JSON object per line, sorted by calibrated_prob desc):

    {"a": <record_id>, "b": <record_id>, "record_type": <type>,
     "signals": {"cosine": <float>, "lexical": <float|null>,
                 "structural": <float|null>, "metadata": <float|null>},
     "signals_available": [<name>, ...], "imputed_signals": [<name>, ...],
     "fused_logit": <float>, "calibrated_prob": <float>,
     "tier": "auto-merge"|"review"|"distinct",
     "certificate": {"passed": <bool>,
                     "clauses": {"prob": <bool>, "cosine": <bool>,
                                 "same_type": <bool>, "lexical": <bool|null>},
                     "failed_clauses": [<name>, ...]},
     "label": <0|1|null>, "label_source": "provided"|"weak-seed"|null,
     "oof_prob": <float|null>}
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Reuse the ENC-TSK-H91 corpus read + ENC-TSK-I05 helpers verbatim so there is a
# single governed vector_read path and one shared S3-sink idiom. tools/ is put
# on sys.path so the sibling imports resolve both as a script and from tests.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
import correlation_analysis_h91 as h91  # noqa: E402
import dedup_cluster_i05 as i05  # noqa: E402

# scipy is OPTIONAL: when present it accelerates the regularized incomplete-beta
# inverse; otherwise a pure-Python implementation (math only) is used. Tests
# cross-check the two. numpy is re-exported from h91 for the (inherited) corpus
# cosine path only; fusion/calibration are pure-Python.
try:  # pragma: no cover - exercised indirectly
    from scipy import special as _scipy_special  # type: ignore
except Exception:  # pragma: no cover - scipy absent is a supported config
    _scipy_special = None  # type: ignore

np = h91.np

DEFAULT_PROJECT_ID = h91.DEFAULT_PROJECT_ID
DEFAULT_THRESHOLD = h91.DEFAULT_THRESHOLD
DEFAULT_PAGE_LIMIT = h91.DEFAULT_PAGE_LIMIT
DEFAULT_GAMMA_FUNCTION = h91.DEFAULT_GAMMA_FUNCTION
DEFAULT_OUT_DIR = "./i06_results"

# Signal order is fixed so feature vectors, weights, and scalers line up.
SIGNAL_NAMES: Tuple[str, ...] = ("cosine", "lexical", "structural", "metadata")

# S3 sink env contract (mirrors H91 / I05).
RESULTS_BUCKET_ENV = "DEDUP_CERTAINTY_BUCKET"
RESULTS_PREFIX_ENV = "DEDUP_CERTAINTY_PREFIX"
DEFAULT_RESULTS_PREFIX = "dedup-certainty-i06"

VERDICTS_FILENAME = "verdicts.jsonl"
SUMMARY_FILENAME = "summary.json"

# ---- Defaults for the certificate + weak-label seed (all CLI-overridable) ----
DEFAULT_CALIBRATION = "platt"
DEFAULT_CV_FOLDS = 5
DEFAULT_BETA_PRIOR = (0.5, 0.5)          # Jeffreys
DEFAULT_LCB_QUANTILE = 0.05              # 95% one-sided lower bound
DEFAULT_CERT_PROB = 0.99                 # tau_p
DEFAULT_CERT_COSINE = 0.97               # tau_cos
DEFAULT_CERT_LEXICAL = 0.30              # tau_lex (clause active only if lexical present)
DEFAULT_REVIEW_PROB = 0.50              # tier boundary review/distinct
DEFAULT_POS_COSINE = 0.9999             # weak-positive: near-identical mass
DEFAULT_NEG_LEXICAL = 0.20              # weak-negative: cosine-high but text-divergent
DEFAULT_NEG_COSINE_BAND = 0.97          # cosine-only weak-negative ceiling (circular; flagged)

# Recency decay for the metadata signal (days).
_RECENCY_TAU_DAYS = 30.0
_SECONDS_PER_DAY = 86400.0

# Lightweight English stopword set for lexical tokenization (deterministic).
_STOPWORDS = frozenset("""
a an and are as at be but by for from has have in into is it its of on or that
the this to was were will with we you your not no fix add update via use using
""".split())

# Coarse status families for the metadata "same status family" agreement signal.
_STATUS_FAMILY: Dict[str, str] = {
    "open": "early", "drafted": "early", "started": "early", "in-progress": "early",
    "reopened": "early", "coding-updates": "early",
    "coding-complete": "mid", "committed": "mid", "pr": "mid", "pushed": "mid",
    "merged-main": "done", "deploy-init": "done", "deploy-success": "done",
    "deployed": "done", "closed": "done", "complete": "done", "accepted": "done",
    "production": "done", "active": "done", "incomplete": "done",
}


# ===========================================================================
# SIGNALS layer
# ===========================================================================
def _tokens(text: Any) -> set:
    """Normalize free text into a deterministic token set: lowercase, split on
    non-alphanumeric, drop stopwords and 1-char tokens."""
    if not text or not isinstance(text, str):
        return set()
    out = set()
    cur = []
    for ch in text.lower():
        if ch.isalnum():
            cur.append(ch)
        elif cur:
            tok = "".join(cur)
            cur = []
            if len(tok) > 1 and tok not in _STOPWORDS:
                out.add(tok)
    if cur:
        tok = "".join(cur)
        if len(tok) > 1 and tok not in _STOPWORDS:
            out.add(tok)
    return out


def _jaccard(a: set, b: set) -> float:
    """Jaccard similarity |a∩b| / |a∪b|. Two empty sets are dissimilar (0.0),
    not similar — absence of evidence is not evidence of duplication."""
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _record_text(rec: Dict[str, Any]) -> str:
    """Concatenate the human-text fields used for the lexical signal."""
    if not isinstance(rec, dict):
        return ""
    parts = [rec.get("title") or "", rec.get("intent") or rec.get("description") or ""]
    return " ".join(p for p in parts if p)


def _neighbor_set(rec: Dict[str, Any]) -> set:
    """Union of a record's graph-neighborhood id references for the structural
    signal: related_task_ids / related_issue_ids / related_feature_ids /
    neighbor_ids / subtask_ids and parent."""
    if not isinstance(rec, dict):
        return set()
    out = set()
    for key in ("related_task_ids", "related_issue_ids", "related_feature_ids",
                "neighbor_ids", "subtask_ids", "related_ids"):
        val = rec.get(key)
        if isinstance(val, (list, tuple)):
            out.update(str(v) for v in val if v)
        elif isinstance(val, str) and val:
            out.add(val)
    parent = rec.get("parent")
    if isinstance(parent, str) and parent:
        out.add(parent)
    return out


def lexical_signal(rec_a: Optional[Dict[str, Any]], rec_b: Optional[Dict[str, Any]]) -> Optional[float]:
    """Token-set Jaccard over (title + intent/body). ``None`` when either record
    is absent or carries no usable text."""
    if not isinstance(rec_a, dict) or not isinstance(rec_b, dict):
        return None
    ta, tb = _tokens(_record_text(rec_a)), _tokens(_record_text(rec_b))
    if not ta and not tb:
        return None
    return _jaccard(ta, tb)


def structural_signal(a_id: str, b_id: str,
                      rec_a: Optional[Dict[str, Any]], rec_b: Optional[Dict[str, Any]]) -> Optional[float]:
    """Graph-neighborhood Jaccard plus a direct cross-reference bonus. ``None``
    when either record is absent. A direct a<->b reference floors the signal at
    0.5 even when the wider neighborhoods are disjoint."""
    if not isinstance(rec_a, dict) or not isinstance(rec_b, dict):
        return None
    na, nb = _neighbor_set(rec_a), _neighbor_set(rec_b)
    jac = _jaccard(na, nb)
    direct = (b_id in na) or (a_id in nb)
    return max(jac, 0.5) if direct else jac


def _epoch_or_none(created_at: Any) -> Optional[float]:
    e = i05._age_epoch(created_at if isinstance(created_at, str) else None)
    return None if e == math.inf else e


def metadata_signal(rec_a: Optional[Dict[str, Any]], rec_b: Optional[Dict[str, Any]]) -> Optional[float]:
    """Mean agreement over priority, category, status-family, and created-time
    proximity. Each component contributes only when both records carry it; the
    signal is ``None`` if no component is computable."""
    if not isinstance(rec_a, dict) or not isinstance(rec_b, dict):
        return None
    components: List[float] = []

    for key in ("priority", "category"):
        va, vb = rec_a.get(key), rec_b.get(key)
        if va is not None and vb is not None:
            components.append(1.0 if str(va).strip().lower() == str(vb).strip().lower() else 0.0)

    sa, sb = rec_a.get("status"), rec_b.get("status")
    if sa and sb:
        fa = _STATUS_FAMILY.get(str(sa).strip().lower())
        fb = _STATUS_FAMILY.get(str(sb).strip().lower())
        if fa is not None and fb is not None:
            components.append(1.0 if fa == fb else 0.0)

    ea, eb = _epoch_or_none(rec_a.get("created_at")), _epoch_or_none(rec_b.get("created_at"))
    if ea is not None and eb is not None:
        delta_days = abs(ea - eb) / _SECONDS_PER_DAY
        components.append(math.exp(-delta_days / _RECENCY_TAU_DAYS))

    if not components:
        return None
    return sum(components) / len(components)


def pair_signals(pair: Dict[str, Any], records: Optional[Dict[str, Any]]) -> Dict[str, Optional[float]]:
    """Compute the four signal families for one candidate pair. ``cosine`` comes
    from the pair record; the others need ``records`` and are ``None`` without it."""
    a, b = str(pair.get("a")), str(pair.get("b"))
    try:
        cos = float(pair.get("cosine"))
    except (TypeError, ValueError):
        cos = None
    if cos is not None:
        cos = max(0.0, min(1.0, cos))  # clamp to [0,1]; embeddings can dip slightly <0

    rec_a = (records or {}).get(a)
    rec_b = (records or {}).get(b)
    return {
        "cosine": cos,
        "lexical": lexical_signal(rec_a, rec_b),
        "structural": structural_signal(a, b, rec_a, rec_b),
        "metadata": metadata_signal(rec_a, rec_b),
    }


# ===========================================================================
# Candidate assembly (same-type pairs + their signals)
# ===========================================================================
def _pair_key(a: str, b: str) -> str:
    """Orientation-stable ``"<lo>|<hi>"`` key for label lookup + folds."""
    return f"{a}|{b}" if str(a) <= str(b) else f"{b}|{a}"


def build_candidates(pairs: Sequence[Dict[str, Any]],
                     records: Optional[Dict[str, Any]],
                     threshold: float) -> List[Dict[str, Any]]:
    """Filter to same-type pairs with a numeric cosine >= ``threshold`` and
    attach signals. ``a`` is the lexicographically smaller id (orientation
    stable)."""
    out: List[Dict[str, Any]] = []
    for p in pairs:
        if not isinstance(p, dict):
            continue
        a, b = p.get("a"), p.get("b")
        if not a or not b:
            continue
        if p.get("a_type") != p.get("b_type"):
            continue
        try:
            cos = float(p.get("cosine"))
        except (TypeError, ValueError):
            continue
        if cos < threshold:
            continue
        a, b = str(a), str(b)
        if b < a:
            a, b = b, a
        rtype = p.get("a_type")
        cand = {
            "a": a, "b": b, "record_type": rtype,
            "pair_key": _pair_key(a, b),
            "signals": pair_signals({"a": a, "b": b, "cosine": cos}, records),
        }
        out.append(cand)
    # Deterministic order (stable across runs / fold assignment).
    out.sort(key=lambda c: c["pair_key"])
    return out


# ===========================================================================
# WEAK-LABEL seed (the H91-seeded labeled set)
# ===========================================================================
def derive_labels(candidates: Sequence[Dict[str, Any]],
                  provided: Optional[Dict[str, Any]],
                  pos_cosine: float, neg_lexical: float, neg_cosine_band: float
                  ) -> Tuple[Dict[str, Tuple[int, str]], Dict[str, Any]]:
    """Resolve a label for as many candidates as possible.

    Priority: an explicit ``provided`` label (source ``provided``) wins. Else the
    H91-seeded weak rule:
      * weak-POSITIVE  when cosine >= ``pos_cosine`` (near-identical mass).
      * weak-NEGATIVE  when lexical is present and < ``neg_lexical`` (cosine-high
                       but text-divergent — an *independent* negative signal), OR
                       when no lexical is available and cosine <= ``neg_cosine_band``
                       (a cosine-only band — CIRCULAR, flagged in meta).
      * otherwise UNLABELED.

    Returns ``(labels_by_pair_key, meta)`` where labels map pair_key ->
    ``(label, source)`` and meta carries counts + a circularity flag.
    """
    labels: Dict[str, Tuple[int, str]] = {}
    n_pos = n_neg = 0
    n_provided = 0
    n_weak_neg_lexical = n_weak_neg_cosine = 0
    used_cosine_only_negatives = False

    provided = provided or {}
    for cand in candidates:
        key = cand["pair_key"]
        sig = cand["signals"]
        cos = sig.get("cosine")
        lex = sig.get("lexical")

        if key in provided:
            try:
                lab = int(provided[key])
            except (TypeError, ValueError):
                continue
            if lab in (0, 1):
                labels[key] = (lab, "provided")
                n_provided += 1
                n_pos += lab
                n_neg += (1 - lab)
            continue

        # Weak seed.
        if cos is not None and cos >= pos_cosine:
            labels[key] = (1, "weak-seed")
            n_pos += 1
        elif lex is not None and lex < neg_lexical:
            labels[key] = (0, "weak-seed")
            n_neg += 1
            n_weak_neg_lexical += 1
        elif lex is None and cos is not None and cos <= neg_cosine_band:
            labels[key] = (0, "weak-seed")
            n_neg += 1
            n_weak_neg_cosine += 1
            used_cosine_only_negatives = True
        # else: unlabeled.

    meta = {
        "labeled_total": len(labels),
        "positives": n_pos,
        "negatives": n_neg,
        "provided": n_provided,
        "weak_negatives_from_lexical": n_weak_neg_lexical,
        "weak_negatives_from_cosine_band": n_weak_neg_cosine,
        "circular_cosine_only_negatives": used_cosine_only_negatives,
        "pos_cosine": pos_cosine,
        "neg_lexical": neg_lexical,
        "neg_cosine_band": neg_cosine_band,
    }
    return labels, meta


# ===========================================================================
# FUSE layer — L2-regularized logistic regression (log-odds fusion)
# ===========================================================================
def _sigmoid(z: float) -> float:
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


def feature_vector(signals: Dict[str, Optional[float]],
                   active: Sequence[str],
                   means: Dict[str, float]) -> Tuple[List[float], List[str]]:
    """Build the model feature vector over the ``active`` signals, mean-imputing
    any that are ``None``. Returns ``(x, imputed_signal_names)``."""
    x: List[float] = []
    imputed: List[str] = []
    for name in active:
        v = signals.get(name)
        if v is None:
            v = means.get(name, 0.0)
            imputed.append(name)
        x.append(float(v))
    return x, imputed


def _standardizer(rows: Sequence[Sequence[float]]) -> Tuple[List[float], List[float]]:
    """Per-column mean/std (population) for z-scoring; std floored to 1.0 for
    constant columns so they pass through unchanged."""
    if not rows:
        return [], []
    ncol = len(rows[0])
    means = [0.0] * ncol
    for r in rows:
        for j in range(ncol):
            means[j] += r[j]
    means = [m / len(rows) for m in means]
    var = [0.0] * ncol
    for r in rows:
        for j in range(ncol):
            d = r[j] - means[j]
            var[j] += d * d
    stds = [math.sqrt(v / len(rows)) or 1.0 for v in var]
    stds = [s if s > 1e-12 else 1.0 for s in stds]
    return means, stds


def fit_logistic(X: Sequence[Sequence[float]], y: Sequence[int],
                 l2: float = 1.0, iters: int = 500, lr: float = 0.5
                 ) -> Dict[str, Any]:
    """Deterministic L2-regularized logistic regression by full-batch gradient
    descent on z-scored features. Returns a model dict ``{w, b, means, stds}``
    where ``logit = b + sum_j w_j * (x_j - means_j)/stds_j``.

    Pure-Python (numpy not required); zero-initialized so the fit is fully
    reproducible. The bias is not regularized.
    """
    n = len(X)
    if n == 0:
        raise ValueError("fit_logistic requires at least one sample")
    ncol = len(X[0])
    means, stds = _standardizer(X)
    Z = [[(row[j] - means[j]) / stds[j] for j in range(ncol)] for row in X]

    w = [0.0] * ncol
    b = 0.0
    for _ in range(iters):
        gw = [0.0] * ncol
        gb = 0.0
        for i in range(n):
            z = b + sum(w[j] * Z[i][j] for j in range(ncol))
            err = _sigmoid(z) - y[i]
            gb += err
            for j in range(ncol):
                gw[j] += err * Z[i][j]
        gb /= n
        for j in range(ncol):
            gw[j] = gw[j] / n + l2 * w[j] / n
        b -= lr * gb
        for j in range(ncol):
            w[j] -= lr * gw[j]
    return {"w": w, "b": b, "means": means, "stds": stds}


def logistic_logit(model: Dict[str, Any], x: Sequence[float]) -> float:
    """Raw log-odds (the fused score) for a standardized-on-the-fly feature row."""
    w, b, means, stds = model["w"], model["b"], model["means"], model["stds"]
    return b + sum(w[j] * (x[j] - means[j]) / stds[j] for j in range(len(w)))


# ===========================================================================
# CALIBRATE layer — Platt + isotonic, with k-fold out-of-fold orchestration
# ===========================================================================
def fit_platt(scores: Sequence[float], labels: Sequence[int],
              iters: int = 200, lr: float = 0.1) -> Dict[str, float]:
    """Platt scaling: fit ``p = sigmoid(A*f + B)`` with Platt's target smoothing
    (Lin/Lin/Weng 2007 targets) by gradient descent. Returns ``{"A", "B"}``.

    Convention: prob = sigmoid(A*f + B), so for a "higher score => more likely
    duplicate" fit A is positive.
    """
    n = len(scores)
    if n == 0:
        return {"A": 1.0, "B": 0.0}
    n_pos = sum(1 for v in labels if v == 1)
    n_neg = n - n_pos
    hi = (n_pos + 1.0) / (n_pos + 2.0) if n_pos > 0 else 0.5
    lo = 1.0 / (n_neg + 2.0) if n_neg > 0 else 0.5
    t = [hi if labels[i] == 1 else lo for i in range(n)]

    A, B = 1.0, 0.0
    for _ in range(iters):
        gA = gB = 0.0
        for i in range(n):
            p = _sigmoid(A * scores[i] + B)
            err = p - t[i]
            gA += err * scores[i]
            gB += err
        A -= lr * gA / n
        B -= lr * gB / n
    return {"A": A, "B": B}


def platt_predict(params: Dict[str, float], f: float) -> float:
    return _sigmoid(params["A"] * f + params["B"])


def fit_isotonic(scores: Sequence[float], labels: Sequence[int]) -> Dict[str, List[float]]:
    """Isotonic regression via pool-adjacent-violators (PAV): the least-squares
    monotone non-decreasing fit of ``labels`` ordered by ``scores``. Returns
    block boundaries for piecewise-constant prediction: ``{"x": [...], "y": [...]}``
    where ``x`` are the right edges (max score) of each block and ``y`` the block
    value, both ascending.
    """
    n = len(scores)
    if n == 0:
        return {"x": [], "y": []}
    order = sorted(range(n), key=lambda i: scores[i])
    xs = [scores[i] for i in order]
    ys = [float(labels[i]) for i in order]

    # PAV: each block tracks (sum, count, value, right_edge_index).
    vals: List[float] = []
    cnts: List[float] = []
    edges: List[float] = []
    for k in range(n):
        v = ys[k]
        c = 1.0
        e = xs[k]
        while vals and vals[-1] >= v:  # >= keeps merge stable for ties
            pv, pc = vals.pop(), cnts.pop()
            edges.pop()
            v = (v * c + pv * pc) / (c + pc)
            c += pc
            e = max(e, xs[k])
        vals.append(v)
        cnts.append(c)
        edges.append(e)
    # Expand block right-edges to actual ascending score cut points.
    # Re-walk to assign each block its maximum score.
    out_x: List[float] = []
    out_y: List[float] = []
    idx = 0
    for bi in range(len(vals)):
        cnt = int(round(cnts[bi]))
        idx += cnt
        out_x.append(xs[idx - 1])
        out_y.append(vals[bi])
    return {"x": out_x, "y": out_y}


def isotonic_predict(model: Dict[str, List[float]], f: float) -> float:
    """Piecewise-constant isotonic prediction: the value of the first block whose
    right edge is >= ``f`` (clamped to the last block above the range)."""
    xs, ys = model["x"], model["y"]
    if not xs:
        return 0.5
    for i, edge in enumerate(xs):
        if f <= edge:
            return ys[i]
    return ys[-1]


class Calibrator:
    """Uniform Platt/isotonic calibration handle."""

    def __init__(self, method: str, params: Any):
        self.method = method
        self.params = params

    def predict(self, f: float) -> float:
        if self.method == "isotonic":
            return isotonic_predict(self.params, f)
        return platt_predict(self.params, f)


def fit_calibrator(method: str, scores: Sequence[float], labels: Sequence[int]) -> Calibrator:
    if method == "isotonic":
        return Calibrator("isotonic", fit_isotonic(scores, labels))
    return Calibrator("platt", fit_platt(scores, labels))


def _fold_of(pair_key: str, k: int) -> int:
    """Deterministic, content-derived fold assignment (no RNG, stable across
    runs): a simple rolling hash of the pair key mod k."""
    h = 0
    for ch in pair_key:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    return h % k


def fit_fusion_and_calibration(labeled: Sequence[Dict[str, Any]],
                               active: Sequence[str], method: str,
                               l2: float) -> Tuple[Dict[str, Any], Calibrator, Dict[str, float]]:
    """Fit the log-odds fusion + calibrator on a labeled candidate subset.
    Returns ``(fusion_model, calibrator, signal_means)`` where signal_means is
    the per-signal imputation table derived from the labeled rows.
    """
    means = _signal_means(labeled, active)
    X, y = [], []
    for cand in labeled:
        x, _ = feature_vector(cand["signals"], active, means)
        X.append(x)
        y.append(cand["_label"])
    fusion = fit_logistic(X, y, l2=l2)
    fused = [logistic_logit(fusion, X[i]) for i in range(len(X))]
    calib = fit_calibrator(method, fused, y)
    return fusion, calib, means


def _signal_means(candidates: Sequence[Dict[str, Any]], active: Sequence[str]) -> Dict[str, float]:
    """Per-signal mean over present values (the imputation table). Defaults to
    0.5 for a signal with no present value among the rows."""
    means: Dict[str, float] = {}
    for name in active:
        vals = [c["signals"][name] for c in candidates if c["signals"].get(name) is not None]
        means[name] = (sum(vals) / len(vals)) if vals else 0.5
    return means


# ===========================================================================
# CERTIFY layer — Beta-posterior LCB + conjunctive certificate + tiering
# ===========================================================================
def _betacf(a: float, b: float, x: float, itmax: int = 200, eps: float = 1e-14) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes
    ``betacf``), evaluated by the modified Lentz method."""
    tiny = 1e-30
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, itmax + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc_reg(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a,b) in [0,1]. Uses scipy when available,
    else a pure-Python continued-fraction (math only)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    if _scipy_special is not None:
        return float(_scipy_special.betainc(a, b, x))
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    bt = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def beta_ppf(q: float, a: float, b: float, iters: int = 200) -> float:
    """Inverse regularized incomplete beta (Beta quantile): the ``x`` with
    ``I_x(a,b) = q``. scipy.betaincinv when available, else monotone bisection
    on the pure-Python CDF.
    """
    if q <= 0.0:
        return 0.0
    if q >= 1.0:
        return 1.0
    if _scipy_special is not None:
        return float(_scipy_special.betaincinv(a, b, q))
    lo, hi = 0.0, 1.0
    for _ in range(iters):
        mid = 0.5 * (lo + hi)
        if betainc_reg(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def beta_lcb(k: int, n: int, prior: Tuple[float, float] = DEFAULT_BETA_PRIOR,
             quantile: float = DEFAULT_LCB_QUANTILE) -> Dict[str, Any]:
    """Beta-posterior lower-confidence bound on a precision (Bernoulli rate).

    ``k`` successes (true dups) out of ``n`` trials (labeled pairs in region),
    prior ``Beta(a0, b0)``. Posterior ``Beta(a0 + k, b0 + (n - k))``; the LCB is
    the ``quantile`` (default 0.05 => one-sided 95% lower bound).
    """
    a0, b0 = prior
    a_post = a0 + k
    b_post = b0 + (n - k)
    point = a_post / (a_post + b_post)
    lcb = beta_ppf(quantile, a_post, b_post)
    return {
        "k": k, "n": n,
        "prior": [a0, b0],
        "posterior": [a_post, b_post],
        "precision_point": point,
        "precision_lcb": lcb,
        "lcb_quantile": quantile,
        "confidence": round(1.0 - quantile, 4),
    }


def certificate_clauses(signals: Dict[str, Optional[float]], prob: float,
                        record_type: Any, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate the conjunctive auto-merge certificate clauses for one pair.

    Clauses (AND): prob >= tau_p, cosine >= tau_cos, same_type (always true for
    I06 same-type candidates — kept explicit so a mixed feed cannot certify), and
    lexical >= tau_lex *when lexical is available* (clause is null/skipped when
    the signal is absent — a missing clause neither passes nor fails the
    conjunction, but is recorded).
    """
    cos = signals.get("cosine")
    lex = signals.get("lexical")
    clauses: Dict[str, Optional[bool]] = {}
    clauses["prob"] = prob >= cfg["cert_prob"]
    clauses["cosine"] = (cos is not None and cos >= cfg["cert_cosine"])
    clauses["same_type"] = record_type is not None
    clauses["lexical"] = None if lex is None else (lex >= cfg["cert_lexical"])

    active = [v for v in clauses.values() if v is not None]
    passed = all(active) and len(active) > 0
    failed = [name for name, v in clauses.items() if v is False]
    return {"passed": passed, "clauses": clauses, "failed_clauses": failed}


def assign_tier(prob: float, cert_passed: bool, cfg: Dict[str, Any]) -> str:
    if cert_passed:
        return "auto-merge"
    if prob >= cfg["review_prob"]:
        return "review"
    return "distinct"


# ===========================================================================
# Assembly — verdicts + summary
# ===========================================================================
def build_verdicts(candidates: List[Dict[str, Any]],
                   labels: Dict[str, Tuple[int, str]],
                   cfg: Dict[str, Any],
                   generated_at: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """End-to-end COMPUTE: signals -> fusion -> calibration (OOF) -> certificate.

    ``candidates`` carry precomputed signals; ``labels`` maps pair_key ->
    (label, source). Never reads the clock — ``generated_at`` is threaded through.
    """
    method = cfg["calibration"]
    folds = cfg["cv_folds"]
    l2 = cfg["l2"]

    # Active signals: any present on at least one candidate. Cosine is always in.
    active = [name for name in SIGNAL_NAMES
              if any(c["signals"].get(name) is not None for c in candidates)]
    if "cosine" not in active:
        active = ["cosine"] + active

    # Attach labels.
    labeled: List[Dict[str, Any]] = []
    for cand in candidates:
        lab = labels.get(cand["pair_key"])
        if lab is not None:
            cand["_label"], cand["_label_source"] = lab[0], lab[1]
            labeled.append(cand)
        else:
            cand["_label"], cand["_label_source"] = None, None

    n_pos = sum(1 for c in labeled if c["_label"] == 1)
    n_neg = len(labeled) - n_pos
    trainable = len(labeled) >= 2 and n_pos >= 1 and n_neg >= 1

    model_meta: Dict[str, Any] = {
        "active_signals": active,
        "calibration": method,
        "cv_folds": folds,
        "trainable": trainable,
    }

    oof_prob: Dict[str, float] = {}
    if trainable:
        # Out-of-fold predictions for the labeled set (honest certificate input).
        use_cv = len(labeled) >= folds and n_pos >= 2 and n_neg >= 2
        if use_cv:
            for fold in range(folds):
                train = [c for c in labeled if _fold_of(c["pair_key"], folds) != fold]
                test = [c for c in labeled if _fold_of(c["pair_key"], folds) == fold]
                if not test:
                    continue
                tp = sum(1 for c in train if c["_label"] == 1)
                tn = len(train) - tp
                if tp < 1 or tn < 1:
                    # Degenerate fold: fall back to the full-data model below.
                    continue
                fusion_f, calib_f, means_f = fit_fusion_and_calibration(train, active, method, l2)
                for c in test:
                    x, _ = feature_vector(c["signals"], active, means_f)
                    oof_prob[c["pair_key"]] = calib_f.predict(logistic_logit(fusion_f, x))
            model_meta["oof"] = True
        else:
            model_meta["oof"] = False
            model_meta["oof_skipped_reason"] = "insufficient labeled samples for k-fold CV"

        # Final model on ALL labels — scores every (incl. unlabeled) pair.
        fusion, calib, means = fit_fusion_and_calibration(labeled, active, method, l2)
        model_meta["fusion_weights"] = {active[j]: fusion["w"][j] for j in range(len(active))}
        model_meta["fusion_bias"] = fusion["b"]
        model_meta["calibration_params"] = (
            calib.params if method == "platt" else {"blocks": len(calib.params["x"])}
        )
    else:
        fusion = calib = means = None
        model_meta["oof"] = False
        model_meta["degraded_reason"] = (
            "labeled seed not separable (need >=1 positive and >=1 negative); "
            "emitting signals + certificate clauses without a fitted probability"
        )

    # Score every candidate.
    verdicts: List[Dict[str, Any]] = []
    for cand in candidates:
        sig = cand["signals"]
        available = [n for n in active if sig.get(n) is not None]
        if fusion is not None:
            x, imputed = feature_vector(sig, active, means)
            f = logistic_logit(fusion, x)
            prob = calib.predict(f)
        else:
            # Degraded: a transparent cosine fallback so tiers still order pairs.
            x, imputed = feature_vector(sig, active, _signal_means(candidates, active))
            f = None
            prob = sig.get("cosine") if sig.get("cosine") is not None else 0.0

        cert = certificate_clauses(sig, prob, cand["record_type"], cfg)
        tier = assign_tier(prob, cert["passed"], cfg)
        verdicts.append({
            "a": cand["a"], "b": cand["b"], "record_type": cand["record_type"],
            "signals": sig,
            "signals_available": available,
            "imputed_signals": imputed,
            "fused_logit": f,
            "calibrated_prob": prob,
            "tier": tier,
            "certificate": cert,
            "label": cand["_label"],
            "label_source": cand["_label_source"],
            "oof_prob": oof_prob.get(cand["pair_key"]),
        })

    verdicts.sort(key=lambda v: (v["calibrated_prob"] if v["calibrated_prob"] is not None else -1.0),
                  reverse=True)

    stats = _summary_stats(verdicts, candidates, labeled, model_meta, cfg, oof_prob, generated_at)
    return verdicts, stats


def _certificate_region_lcb(verdicts: Sequence[Dict[str, Any]],
                            oof_prob: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Beta-posterior 95% LCB on certificate-region precision, measured on the
    labeled OOF pairs that satisfy the certificate (using the OOF probability for
    the prob clause so the estimate is out-of-sample). Reports the prior-only
    bound with a caveat when the labeled region is empty.
    """
    k = n = 0
    total_certified = 0
    for v in verdicts:
        if v["certificate"]["passed"]:
            total_certified += 1
        if v["label"] is None:
            continue
        key = _pair_key(v["a"], v["b"])
        prob_for_clause = oof_prob.get(key, v["calibrated_prob"])
        if prob_for_clause is None:
            continue
        cert = certificate_clauses(v["signals"], prob_for_clause, v["record_type"], cfg)
        if cert["passed"]:
            n += 1
            k += int(v["label"] == 1)

    prior = cfg["beta_prior"]
    bound = beta_lcb(k, n, prior=prior, quantile=cfg["lcb_quantile"])
    bound["total_certified_pairs"] = total_certified
    bound["labeled_pairs_in_region"] = n
    if n == 0:
        bound["caveat"] = ("no labeled pairs fell inside the certificate region; "
                           "precision_lcb is the prior-only bound, not data-backed")
    return bound


def _summary_stats(verdicts: Sequence[Dict[str, Any]], candidates: Sequence[Dict[str, Any]],
                   labeled: Sequence[Dict[str, Any]], model_meta: Dict[str, Any],
                   cfg: Dict[str, Any], oof_prob: Dict[str, Any],
                   generated_at: Optional[str]) -> Dict[str, Any]:
    tier_hist: Dict[str, int] = {"auto-merge": 0, "review": 0, "distinct": 0}
    by_type: Dict[str, int] = {}
    coverage = {name: 0 for name in SIGNAL_NAMES}
    for v in verdicts:
        tier_hist[v["tier"]] = tier_hist.get(v["tier"], 0) + 1
        by_type[str(v["record_type"])] = by_type.get(str(v["record_type"]), 0) + 1
        for name in SIGNAL_NAMES:
            if v["signals"].get(name) is not None:
                coverage[name] += 1

    certificate = _certificate_region_lcb(verdicts, oof_prob, cfg)

    caveats: List[str] = []
    if cfg["_label_meta"].get("circular_cosine_only_negatives"):
        caveats.append(
            "weak-label negatives were derived from a cosine band while cosine is "
            "also a fusion feature: the certificate reflects internal consistency, "
            "not external validity. Supply --records (independent lexical/structural "
            "signals) and/or --labels (ground truth) for a trustworthy certificate.")
    if coverage["lexical"] == 0 and coverage["structural"] == 0:
        caveats.append(
            "no --records supplied: lexical/structural/metadata signals are absent; "
            "fusion ran on cosine alone.")
    if not model_meta.get("trainable"):
        caveats.append(model_meta.get("degraded_reason", "model not trainable"))
    if model_meta.get("trainable") and not model_meta.get("oof"):
        caveats.append("certificate precision is in-sample (OOF cross-validation "
                       "skipped: too few labeled samples) — read it as optimistic.")

    return {
        "num_pairs": len(verdicts),
        "num_same_type_candidates": len(candidates),
        "record_type_distribution": by_type,
        "signal_coverage": coverage,
        "labels": cfg["_label_meta"],
        "model": model_meta,
        "tier_histogram": tier_hist,
        "certificate_definition": {
            "conjunction": ["calibrated_prob >= cert_prob", "cosine >= cert_cosine",
                            "same_type", "lexical >= cert_lexical (when available)"],
            "cert_prob": cfg["cert_prob"],
            "cert_cosine": cfg["cert_cosine"],
            "cert_lexical": cfg["cert_lexical"],
            "review_prob": cfg["review_prob"],
        },
        "certificate": certificate,
        "caveats": caveats,
        "mutation_free": True,
        "generated_at": generated_at,
    }


# ===========================================================================
# SINK layer — mirror H91 / I05 (local + best-effort S3 + stdout-degraded)
# ===========================================================================
def _verdicts_to_jsonl(verdicts: Sequence[Dict[str, Any]]) -> str:
    return "".join(json.dumps(v, default=str) + "\n" for v in verdicts)


def write_results(verdicts: Sequence[Dict[str, Any]], stats: Dict[str, Any],
                  args: argparse.Namespace) -> Dict[str, Any]:
    """SINK entrypoint. ALWAYS writes ``verdicts.jsonl`` + ``summary.json`` to
    ``--out`` and emits one ``DEDUP_CERTAINTY {json}`` stdout line. When
    ``DEDUP_CERTAINTY_BUCKET`` is set, ALSO best-effort PUTs both to S3; an S3
    failure never aborts the local write."""
    out_dir = getattr(args, "out", DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    verdicts_path = os.path.join(out_dir, VERDICTS_FILENAME)
    summary_path = os.path.join(out_dir, SUMMARY_FILENAME)

    verdicts_body = _verdicts_to_jsonl(verdicts)
    summary_obj = dict(stats)

    with open(verdicts_path, "w", encoding="utf-8") as fh:
        fh.write(verdicts_body)

    bucket = os.environ.get(RESULTS_BUCKET_ENV, "").strip()
    prefix = (os.environ.get(RESULTS_PREFIX_ENV, DEFAULT_RESULTS_PREFIX).strip()
              or DEFAULT_RESULTS_PREFIX).rstrip("/")
    s3_uris: Dict[str, str] = {}
    if bucket:
        try:
            client = h91._get_s3()
            verdicts_key = f"{prefix}/{VERDICTS_FILENAME}"
            summary_key = f"{prefix}/{SUMMARY_FILENAME}"
            client.put_object(Bucket=bucket, Key=verdicts_key,
                              Body=verdicts_body.encode("utf-8"),
                              ContentType="application/x-ndjson")
            s3_uris = {"verdicts": f"s3://{bucket}/{verdicts_key}",
                       "summary": f"s3://{bucket}/{summary_key}"}
        except Exception as exc:
            print(f"[WARNING] dedup-certainty S3 put failed ({exc}); local write retained",
                  file=sys.stderr)
            s3_uris = {}

    summary_obj["artifacts"] = {
        "verdicts_local": verdicts_path,
        "summary_local": summary_path,
        **({"verdicts_s3": s3_uris["verdicts"], "summary_s3": s3_uris["summary"]} if s3_uris else {}),
    }

    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary_obj, fh, indent=2, default=str)

    if bucket and s3_uris:
        try:
            client = h91._get_s3()
            client.put_object(Bucket=bucket, Key=f"{prefix}/{SUMMARY_FILENAME}",
                              Body=json.dumps(summary_obj, default=str).encode("utf-8"),
                              ContentType="application/json")
        except Exception as exc:
            print(f"[WARNING] dedup-certainty summary S3 put failed ({exc}); local summary retained",
                  file=sys.stderr)

    print("DEDUP_CERTAINTY " + json.dumps(summary_obj, default=str))
    return summary_obj


# ===========================================================================
# READ helpers
# ===========================================================================
def load_pairs_file(path: str) -> List[Dict[str, Any]]:
    """Load an H91 ``pairs.jsonl`` (one ``{a,b,a_type,b_type,cosine}`` per line)."""
    pairs: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                pairs.append(json.loads(line))
    return pairs


def load_records_file(path: str) -> Dict[str, Any]:
    """Load the optional per-record metadata map keyed by record_id."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("--records file must be a JSON object keyed by record_id")
    return data


def load_labels_file(path: str) -> Dict[str, Any]:
    """Load an optional label map. Accepts ``{"<a>|<b>": 0|1}`` directly, or a
    list of ``{"a","b","label"}`` objects (normalized to the pair-key form)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return {(_pair_key(*k.split("|", 1)) if "|" in k else k): v for k, v in data.items()}
    out: Dict[str, Any] = {}
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict) and row.get("a") and row.get("b") and "label" in row:
                out[_pair_key(str(row["a"]), str(row["b"]))] = row["label"]
    return out


def load_pairs(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Resolve candidate pairs from the chosen source. ``pairs`` ingests an H91
    pairs.jsonl; ``file``/``gamma``/``mcp`` read the corpus and compute cosine
    pairs via the reused H91 compute layer (single governed read path)."""
    if args.source == "pairs":
        if not args.input:
            raise ValueError("--input PATH (an H91 pairs.jsonl) is required for --source pairs")
        return load_pairs_file(args.input)
    nodes = h91.load_corpus(args)
    pairs, _ = h91.cosine_pairs(nodes, args.threshold)
    return pairs


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dedup_certainty_i06",
        description=(
            "ENC-TSK-I06 duplicate-certainty model (Dedup P2): log-odds fusion "
            "over cosine/lexical/structural/metadata signals, Platt/isotonic "
            "calibration on an H91-seeded labeled set, and a conjunctive "
            "auto-merge certificate with a Beta-posterior 95% lower-confidence "
            "bound on certificate-region precision. Shadow-mode / propose-only; "
            "zero mutations."),
    )
    p.add_argument("--source", choices=["pairs", "file", "gamma", "mcp"], default="pairs",
                   help="Candidate source: 'pairs' (H91 pairs.jsonl, default) or a corpus read.")
    p.add_argument("--input", default=None,
                   help="Path for --source pairs (pairs.jsonl) or --source file (corpus JSON).")
    p.add_argument("--records", default=None,
                   help="Optional JSON map {record_id: {title, intent?, status, created_at, "
                        "priority, category, related_*_ids?}} for lexical/structural/metadata signals.")
    p.add_argument("--labels", default=None,
                   help="Optional label map {'<a>|<b>': 0|1} (ground truth) overriding the weak seed.")
    p.add_argument("--project-id", dest="project_id", default=DEFAULT_PROJECT_ID,
                   help="Project id to read / default partition (default: enceladus).")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                   help="Candidate floor: keep pairs with cosine >= this (default: 0.95).")
    p.add_argument("--page-limit", dest="page_limit", type=int, default=DEFAULT_PAGE_LIMIT,
                   help="vector_read page size for corpus sources (default: 200).")
    p.add_argument("--gamma-function", dest="gamma_function", default=DEFAULT_GAMMA_FUNCTION,
                   help="Gamma graph-query Lambda name (corpus sources).")
    p.add_argument("--calibration", choices=["platt", "isotonic"], default=DEFAULT_CALIBRATION,
                   help="Probability calibration method (default: platt).")
    p.add_argument("--cv-folds", dest="cv_folds", type=int, default=DEFAULT_CV_FOLDS,
                   help="Out-of-fold CV folds for the honest certificate (default: 5).")
    p.add_argument("--l2", type=float, default=1.0, help="Logistic-regression L2 strength (default: 1.0).")
    p.add_argument("--cert-prob", dest="cert_prob", type=float, default=DEFAULT_CERT_PROB,
                   help="Certificate clause: calibrated_prob >= this (default: 0.99).")
    p.add_argument("--cert-cosine", dest="cert_cosine", type=float, default=DEFAULT_CERT_COSINE,
                   help="Certificate clause: cosine >= this (default: 0.97).")
    p.add_argument("--cert-lexical", dest="cert_lexical", type=float, default=DEFAULT_CERT_LEXICAL,
                   help="Certificate clause: lexical >= this when available (default: 0.30).")
    p.add_argument("--review-prob", dest="review_prob", type=float, default=DEFAULT_REVIEW_PROB,
                   help="Tier boundary: prob >= this is 'review', else 'distinct' (default: 0.50).")
    p.add_argument("--pos-cosine", dest="pos_cosine", type=float, default=DEFAULT_POS_COSINE,
                   help="Weak-positive seed: cosine >= this is a duplicate (default: 0.9999).")
    p.add_argument("--neg-lexical", dest="neg_lexical", type=float, default=DEFAULT_NEG_LEXICAL,
                   help="Weak-negative seed: lexical < this (with high cosine) is a non-dup (default: 0.20).")
    p.add_argument("--neg-cosine-band", dest="neg_cosine_band", type=float, default=DEFAULT_NEG_COSINE_BAND,
                   help="Cosine-only weak-negative ceiling when --records is absent (circular; flagged).")
    p.add_argument("--beta-prior", dest="beta_prior", default="0.5,0.5",
                   help="Beta prior 'a0,b0' for the precision posterior (default: 0.5,0.5 = Jeffreys).")
    p.add_argument("--lcb-quantile", dest="lcb_quantile", type=float, default=DEFAULT_LCB_QUANTILE,
                   help="Lower-bound quantile (default: 0.05 => 95%% one-sided LCB).")
    p.add_argument("--out", default=DEFAULT_OUT_DIR, help="Local output directory (default: ./i06_results).")
    p.add_argument("--generated-at", dest="generated_at", default=None,
                   help="Optional ISO timestamp stamped into stats.generated_at.")
    return p


def _parse_prior(text: str) -> Tuple[float, float]:
    try:
        a0, b0 = (float(x) for x in str(text).split(","))
        if a0 <= 0 or b0 <= 0:
            raise ValueError
        return a0, b0
    except Exception:
        raise ValueError(f"--beta-prior must be 'a0,b0' with a0,b0 > 0 (got {text!r})")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        pairs = load_pairs(args)
    except Exception as exc:
        print(f"[ERROR] pair/corpus read failed (source={args.source}): {exc}", file=sys.stderr)
        return 2

    records = None
    if args.records:
        try:
            records = load_records_file(args.records)
        except Exception as exc:
            print(f"[ERROR] --records read failed ({args.records}): {exc}", file=sys.stderr)
            return 2

    provided_labels = None
    if args.labels:
        try:
            provided_labels = load_labels_file(args.labels)
        except Exception as exc:
            print(f"[ERROR] --labels read failed ({args.labels}): {exc}", file=sys.stderr)
            return 2

    try:
        beta_prior = _parse_prior(args.beta_prior)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    candidates = build_candidates(pairs, records, args.threshold)
    labels, label_meta = derive_labels(
        candidates, provided_labels,
        pos_cosine=args.pos_cosine, neg_lexical=args.neg_lexical,
        neg_cosine_band=args.neg_cosine_band,
    )

    cfg = {
        "calibration": args.calibration,
        "cv_folds": max(2, args.cv_folds),
        "l2": args.l2,
        "cert_prob": args.cert_prob,
        "cert_cosine": args.cert_cosine,
        "cert_lexical": args.cert_lexical,
        "review_prob": args.review_prob,
        "beta_prior": beta_prior,
        "lcb_quantile": args.lcb_quantile,
        "_label_meta": label_meta,
    }

    print(f"[INFO] {len(candidates)} same-type candidates "
          f"(source={args.source}); labeled={label_meta['labeled_total']} "
          f"(+{label_meta['positives']}/-{label_meta['negatives']}); "
          f"records={'yes' if records else 'no'}; calibration={args.calibration}",
          file=sys.stderr)

    verdicts, stats = build_verdicts(candidates, labels, cfg, generated_at=args.generated_at)
    write_results(verdicts, stats, args)

    cert = stats["certificate"]
    print(f"[SUCCESS] tiers auto-merge={stats['tier_histogram']['auto-merge']} "
          f"review={stats['tier_histogram']['review']} distinct={stats['tier_histogram']['distinct']}; "
          f"certificate precision LCB{int((1-cfg['lcb_quantile'])*100)}="
          f"{cert['precision_lcb']:.4f} over n={cert['n']} labeled region pairs "
          f"(point={cert['precision_point']:.4f})", file=sys.stderr)
    for c in stats["caveats"]:
        print(f"[WARNING] {c}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
