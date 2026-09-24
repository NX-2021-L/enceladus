# GHN vs RRF multi-hop benchmark (ENC-TSK-I99 / ENC-FTR-104 Ph2)

Evaluation-only benchmark harness comparing a **Graph-Hopfield-Network (GHN)
energy-descent** scorer (FTR-104 AC-3) against the production **Reciprocal Rank
Fusion (RRF)** on multi-hop QA recall@k (AC-4).

> **This code is NOT wired into the live retrieval path.** GHN is a standalone
> reference/comparison, not a swap-in replacement for RRF. The one direction of
> dependency is read-only imports *into* this package (see below).

## What it compares

| | Production RRF | GHN (this package) |
|---|---|---|
| Source | `lambda_function._rrf_fuse` (imported unmodified) | `benchmarks/ghn.py` |
| Fusion input | per-signal **ranks** → `Σ 1/(k+rank)` | per-candidate **energy field** `h = -E_Ph1` + graph coupling |
| Graph use | PPR as one of three fused signals | PPR in the field **plus** candidate-candidate coupling via energy descent |

Both methods consume **identical upstream signals** (vector / graph-PPR /
keyword), computed once per query in `signals.py`. Only the fusion/ranking step
differs, so the comparison — including the reported fusion latency — is
like-for-like.

## The GHN energy-descent update rule (AC-3)

Built directly on the Ph1 (ENC-TSK-I98) static energy
`E(x) = E_vector + λ_graph·E_PPR + λ_kw·E_keyword` from `energy_function.py`
(imported read-only). Ph1's energy is per-candidate and uncoupled; Ph2 promotes
it to a coupled modern-Hopfield energy over an activation distribution `x` on the
candidate simplex:

```
E_GHN(x) = - Σ h_i x_i  - (λ_graph/2) xᵀ W_psd x  + (1/β) Σ x_i ln x_i
h_i      = - E_Ph1(x)_i                       # negated Ph1 energy = attractive field
W        = candidate-candidate weighted graph adjacency (GRAPH_EDGE_WEIGHTS)
W_psd    = W + τI,  τ = max row sum (Gershgorin PSD shift)
```

Energy-descent (CCCP) update, iterated to convergence:

```
x_i^{t+1} = softmax_i( β · ( h_i + λ_graph · (W_psd x^t)_i ) )
```

This is the exact concave–convex-procedure step (convex entropy+field part,
concave PSD coupling part), which **guarantees `E_GHN(x^{t+1}) ≤ E_GHN(x^t)`** —
monotone energy descent. `test_ghn.py` asserts this numerically over 40 random
instances. The graph coupling term `(W x)` is the multi-hop mechanism: a weak
bridge/2nd-hop fact adjacent to a strongly-matching 1st-hop fact accumulates
activation from its neighbour — something rank fusion cannot do.

See the `ghn.py` module docstring for the full derivation and the PSD-shift
rationale.

## Datasets — SYNTHETIC (honest limitation)

FTR-104 AC-4 names {MuSiQue, 2WikiMultiHopQA, HotpotQA}. **The real splits are
unfetchable in this sandbox:** outbound network is TLS-blocked (verified
2026-07-02 against huggingface.co), the `datasets` library is absent, and no raw
splits exist on the image. Rather than fabricate numbers "as if" from the real
corpora, `synthetic_multihop.py` **constructs documented synthetic proxies**
whose *structure* mirrors each dataset's published construction (hop count,
lexical-leakage decay of later hops, distractor count and graph-connectivity).
100 questions per dataset.

**Interpretation caveat:** the recall@k deltas measure a real *algorithmic*
property (does graph-coupled energy descent recover graph-reachable bridge facts
that rank fusion under-ranks?) on a controlled proxy. They are **not** a claim
about absolute recall on the public leaderboards. Any Lesson candidate derived
from these numbers must carry this caveat. To run on the real data, drop the
JSONL splits in and replace `synthetic_multihop.generate` with a loader that
emits the same `Dataset`/`Question` shape.

## Reproduce

```bash
cd backend/lambda/graph_query_api
python3 -m benchmarks.run_benchmark            # writes results/ghn_vs_rrf.json + prints summary
python3 -m benchmarks.run_benchmark --lambda-graph 1.0 --lambda-kw 0.1 --skip-sweep   # tuned config
python3 -m pytest benchmarks/test_ghn.py -q    # GHN unit tests
```

Deterministic (seeded); the committed `results/ghn_vs_rrf.json` regenerates
bit-for-bit at `--seed 1099`.

## Findings (see results/ghn_vs_rrf.json for full numbers)

1. **GHN wins early multi-hop recall.** On 2Wiki and MuSiQue, GHN improves
   recall@2 by **+0.15–0.18** and recall@3 by **+0.07–0.17** — it surfaces
   graph-reachable bridge/later-hop facts *sooner* than RRF. On the easy
   HotpotQA (RRF already saturates by k=3) it is at parity.
2. **GHN can regress deep recall (recall@10+) on the hardest set.** The additive
   energy field penalizes a fact for being *absent* on 2 of 3 signals (E=1 on
   each missing signal), whereas RRF's rank fusion is robust to single-strong-
   signal facts. MuSiQue later-hop facts are often graph-*only*, so under the
   FTR-104 default weights they can fall below k=10 in GHN.
3. **Tuning fixes most of the regression.** Raising `λ_graph` to parity with the
   vector signal and damping `λ_kw` boosts exactly those graph-only facts'
   field. See the recommendation below.
4. **Latency:** GHN fusion is ~1.5–3.5 ms/query vs RRF's ~0.05 ms — 30–70×
   slower in the *ranking step only* (the shared signal computation dominates
   real end-to-end latency and is identical). Still sub-5ms; not a blocker for a
   re-rank of a small candidate set.

**Conclusion:** GHN energy-descent is a **precision/early-recall instrument for
multi-hop bridge discovery**, best used as a **re-ranker over the RRF candidate
set** (or fused with RRF) — not a wholesale RRF replacement, consistent with the
FTR-104 "evaluation-only, not swap-in" framing.

## Recommended λ_graph / λ_kw

From the sweep (maximizing mean recall@10 across the three datasets):

- **`λ_graph = 1.0`, `λ_kw = 0.1`** (FTR-104 defaults are 0.5 / 0.25).

Rationale: multi-hop later-hop facts carry their signal almost entirely in
`E_PPR`; weighting the graph term at parity with the (fixed, implicit-1.0)
vector term lets those facts compete, recovering most of the deep-recall
regression while keeping the strong early-recall gains. Keyword is the noisiest
signal (per the `_hybrid_keyword_ranks` tokenization notes), so damping it to
0.1 removes distractor lexical confusers. Under this config, GHN reaches
near-parity-or-better than RRF on 2Wiki at every k and roughly halves the
MuSiQue deep-recall gap versus the defaults.

## Files

- `ghn.py` — GHN energy, PSD shift, energy-descent update, ranking. Pure-Python.
- `synthetic_multihop.py` — seeded synthetic multi-hop QA dataset generator.
- `signals.py` — offline vector/keyword/PPR stand-ins + candidate + W assembly.
- `run_benchmark.py` — harness: recall@k, answerable@k, latency, λ tuning sweep.
- `test_ghn.py` — GHN energy-descent unit tests.
- `results/ghn_vs_rrf.json` — committed benchmark output (seed 1099).
