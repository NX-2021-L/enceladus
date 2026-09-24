"""Unit tests for ENC-TSK-K43 (B66 Ph5) F_governance percentile normalization
in the Scoring Service.

Math gate: DOC-A3D0CDF91CE9 Q3.1 ("Explicit F_governance Functional",
ENRICHING -> CORRECTED).

  F_governance = percentile_rank(F_structural) + percentile_rank(F_temporal)
                 + percentile_rank(F_evidential)

bounded [0, 3], where 0 == perfect health (not achievable in practice per the
Q3.1 sub-question, since each term is strictly positive for an active
project). Covers:

  - percentile_rank: order-statistic semantics, degrades to neutral 0.5 for
    an empty/absent historical distribution.
  - compute_f_governance: sums three independent percentile ranks, bounded
    [0, 3].
  - governance_compliance_weight: linear inverse map onto [0, 1], 1.0 at
    F_governance==0 (perfect health), 0.0 at F_governance==F_GOVERNANCE_MAX.
  - _compute_resonance_score(..., f_governance=...): AC-3 hard requirement —
    a unit test asserting the percentile weighting SHIFTS RANKING in the
    expected direction: two records with identical pillar_scores but
    different F_governance must rank in compliance order (better governance
    health -> higher resonance_score -> higher retrieval/context-assembly
    rank), and the effect must vanish (score unchanged) when f_governance is
    omitted, preserving pre-K43 backward compatibility.
  - score_lesson: end-to-end wiring — an optional message-level f_governance
    field flows through to the resonance computation and is degraded (not
    erroring) when absent or malformed.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as sf  # noqa: E402


GOOD_PILLARS = {"efficiency": 0.8, "human_protection": 0.7, "intention": 0.6, "alignment": 0.75}


# ---------------------------------------------------------------------------
# percentile_rank
# ---------------------------------------------------------------------------
def test_percentile_rank_order_statistic():
    dist = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert sf.percentile_rank(3.0, dist) == 0.6  # 3 of 5 values <= 3.0
    assert sf.percentile_rank(0.0, dist) == 0.0
    assert sf.percentile_rank(5.0, dist) == 1.0
    assert sf.percentile_rank(100.0, dist) == 1.0  # clamped


def test_percentile_rank_empty_distribution_is_neutral():
    assert sf.percentile_rank(0.5, []) == 0.5
    assert sf.percentile_rank(0.5, None) == 0.5


# ---------------------------------------------------------------------------
# compute_f_governance
# ---------------------------------------------------------------------------
def test_compute_f_governance_sums_three_percentile_ranks():
    # percentile_rank is an order-statistic "fraction <= value": querying the
    # true median of a 3-point distribution captures 2 of 3 points (itself
    # plus everything below), i.e. 0.667 per term -> sum 2.0.
    dist = [0.0, 0.5, 1.0]
    fg = sf.compute_f_governance(
        0.5, 0.5, 0.5,
        structural_distribution=dist, temporal_distribution=dist, evidential_distribution=dist,
    )
    assert fg == round(3 * (2 / 3), 4)


def test_compute_f_governance_bounded_0_to_3():
    dist = [0.0, 1.0]
    worst = sf.compute_f_governance(
        999, 999, 999,
        structural_distribution=dist, temporal_distribution=dist, evidential_distribution=dist,
    )
    assert worst == 3.0
    best = sf.compute_f_governance(
        -999, -999, -999,
        structural_distribution=dist, temporal_distribution=dist, evidential_distribution=dist,
    )
    assert best == 0.0


def test_compute_f_governance_no_distributions_is_neutral_1_5():
    # Each term degrades to percentile_rank==0.5 with no history -> sum 1.5.
    assert sf.compute_f_governance(0.3, 10.0, -5.0) == 1.5


# ---------------------------------------------------------------------------
# governance_compliance_weight
# ---------------------------------------------------------------------------
def test_compliance_weight_perfect_health_is_1():
    assert sf.governance_compliance_weight(0.0) == 1.0


def test_compliance_weight_worst_health_is_0():
    assert sf.governance_compliance_weight(sf.F_GOVERNANCE_MAX) == 0.0


def test_compliance_weight_midpoint_is_neutral_0_5():
    assert sf.governance_compliance_weight(sf.F_GOVERNANCE_MAX / 2) == 0.5


def test_compliance_weight_clamps_out_of_range():
    assert sf.governance_compliance_weight(-5.0) == 1.0
    assert sf.governance_compliance_weight(999.0) == 0.0


# ---------------------------------------------------------------------------
# AC-3 (hard requirement): percentile weighting shifts ranking in the
# expected direction.
# ---------------------------------------------------------------------------
def test_f_governance_shifts_ranking_ac3():
    """Two records with IDENTICAL pillar_scores but different governance
    health must rank in compliance order: the better-governed record (lower
    F_governance, i.e. closer to the Q3.1 perfect-health floor) must score
    strictly higher than the worse-governed record (higher F_governance),
    and both must differ from the ungoverned (no f_governance) baseline —
    proving the weighting term actually moves the ranking signal rather than
    being a inert no-op."""
    baseline = sf._compute_resonance_score(GOOD_PILLARS)

    good_governance = sf._compute_resonance_score(GOOD_PILLARS, f_governance=0.0)  # perfect health
    poor_governance = sf._compute_resonance_score(GOOD_PILLARS, f_governance=sf.F_GOVERNANCE_MAX)  # worst

    # Directionality: better governance health outranks worse governance health.
    assert good_governance > poor_governance

    # Both diverge from the ungoverned baseline (the term has real effect).
    assert good_governance > baseline
    assert poor_governance < baseline

    # Neutral midpoint (weight==0.5, multiplier==1.0x) reproduces the baseline exactly.
    neutral = sf._compute_resonance_score(GOOD_PILLARS, f_governance=sf.F_GOVERNANCE_MAX / 2)
    assert neutral == baseline


def test_f_governance_omitted_preserves_pre_k43_score():
    # Backward compatibility: no f_governance kwarg -> byte-identical to the
    # pre-K43 call signature (verbatim-parity call sites in tracker_mutation /
    # coordination_api that never pass f_governance are unaffected).
    assert sf._compute_resonance_score(GOOD_PILLARS) == sf._compute_resonance_score(GOOD_PILLARS, f_governance=None)


def test_f_governance_still_bounded_unit_interval():
    r_good = sf._compute_resonance_score(GOOD_PILLARS, f_governance=0.0)
    r_bad = sf._compute_resonance_score(GOOD_PILLARS, f_governance=sf.F_GOVERNANCE_MAX)
    assert 0.0 <= r_good <= 1.0
    assert 0.0 <= r_bad <= 1.0


def test_f_governance_composes_with_anti_pattern_penalties():
    # A spiky (force/surrender anti-pattern) profile with perfect governance
    # health must still rank below a balanced profile with worst governance
    # health is NOT asserted (the anti-pattern penalty is intentionally
    # strong) — but perfect governance health must measurably lift the spiky
    # profile's own score relative to itself without governance weighting.
    spiky = {"efficiency": 1.0, "human_protection": 0.0, "intention": 0.0, "alignment": 0.0}
    spiky_baseline = sf._compute_resonance_score(spiky)
    spiky_good_gov = sf._compute_resonance_score(spiky, f_governance=0.0)
    assert spiky_good_gov > spiky_baseline


# ---------------------------------------------------------------------------
# End-to-end wiring through score_lesson
# ---------------------------------------------------------------------------
def _scoring_message(**over):
    msg = {
        "event_type": "lesson.scoring.requested",
        "schema_version": 1,
        "project_id": "enceladus",
        "record_id": "lesson#ENC-LSN-001",
        "item_id": "ENC-LSN-001",
        "pillar_scores": dict(GOOD_PILLARS),
    }
    msg.update(over)
    return msg


def test_score_lesson_wires_f_governance_through():
    outcome_good, detail_good = sf.score_lesson(_scoring_message(f_governance=0.0))
    outcome_poor, detail_poor = sf.score_lesson(_scoring_message(
        record_id="lesson#ENC-LSN-002", f_governance=sf.F_GOVERNANCE_MAX,
    ))
    assert outcome_good == "error" or outcome_good in ("scored", "noop")  # DDB unmocked here; just check detail math
    assert detail_good["f_governance"] == 0.0
    assert detail_poor["f_governance"] == sf.F_GOVERNANCE_MAX
    assert detail_good["resonance_score"] > detail_poor["resonance_score"]


def test_score_lesson_missing_f_governance_omits_detail_key():
    _outcome, detail = sf.score_lesson(_scoring_message())
    assert "f_governance" not in detail


def test_score_lesson_malformed_f_governance_degrades_gracefully():
    # A non-numeric f_governance must not raise or poison the score — it is
    # logged and treated as absent (same as the omitted case).
    outcome, detail = sf.score_lesson(_scoring_message(f_governance="not-a-number"))
    assert outcome in ("scored", "noop", "error")  # never 'skipped' due to f_governance parsing
    assert "f_governance" not in detail
    baseline = sf._compute_resonance_score(GOOD_PILLARS)
    assert detail["resonance_score"] == baseline


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
