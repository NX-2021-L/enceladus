"""ENC-TSK-G45 — gate test for the top-20 tool-description Diataxis rewrite.

Asserts the argument-hallucination distractor surface dropped >=10% pre/post
(AC-4), and that the rewrite did not silently shrink the audited action set.
"""
import g45_tooldesc_eval as e


def test_top20_present_in_baseline_and_post():
    baseline = e.load_baseline()
    post = e.load_post()
    for name in e.TOP20:
        assert name in baseline, f"{name} missing from pinned baseline"
        assert name in post, f"{name} missing from current server.py"
    assert len(e.TOP20) == 20


def test_argument_hallucination_surface_reduced_at_least_10pct():
    rep = e.corpus_report(e.load_baseline(), e.load_post())
    assert rep["pre_total"] > 0
    assert rep["reduction_pct"] >= 10.0, (
        f"reduction {rep['reduction_pct']:.1f}% < 10% gate "
        f"(pre={rep['pre_total']} post={rep['post_total']})"
    )


def test_no_top20_description_gained_distractors():
    baseline = e.load_baseline()
    post = e.load_post()
    for name in e.TOP20:
        pre = e.score(name, baseline)
        pos = e.score(name, post)
        assert pos <= pre, f"{name} distractor surface grew: {pre} -> {pos}"
