#!/usr/bin/env python3
"""Unit tests for ENC-TSK-I06 duplicate-certainty model (tools/dedup_certainty_i06.py).

stdlib unittest (NOT pytest), matching test_dedup_cluster_i05 / test_correlation_
analysis_h91. Synthetic in-memory data only — no network, no S3, no live corpus.
Exercises:
  * the four signal families (cosine clamp, lexical Jaccard, structural overlap +
    direct-ref floor, metadata agreement) incl. graceful None on missing records,
  * same-type candidate assembly + orientation stability,
  * the H91-seeded weak-label rule (provided > weak-positive > weak-negative) and
    the cosine-only circularity flag,
  * log-odds fusion (logistic regression separability + mean-imputation),
  * Platt + isotonic calibration (monotonicity, PAV correctness) and deterministic folds,
  * the Beta-posterior LCB (pure-Python incomplete-beta vs scipy, analytic Beta(1,1)),
  * the conjunctive certificate clauses + tiering,
  * end-to-end build_verdicts (schema, OOF, determinism, degraded single-class),
  * the verdicts.jsonl + summary.json sink shape,
  * mutation-freeness (no governed-write surface is importable/called).
"""

import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dedup_certainty_i06 as dq  # noqa: E402

try:
    from scipy import special as _scipy  # noqa: E402
except Exception:  # pragma: no cover
    _scipy = None


def _rec(title="", intent="", status=None, created_at=None, priority=None,
         category=None, related=None, parent=None):
    r = {"title": title, "intent": intent}
    if status is not None:
        r["status"] = status
    if created_at is not None:
        r["created_at"] = created_at
    if priority is not None:
        r["priority"] = priority
    if category is not None:
        r["category"] = category
    if related is not None:
        r["related_ids"] = list(related)
    if parent is not None:
        r["parent"] = parent
    return r


def _cand(a, b, rtype="issue", cosine=0.99, lexical=None, structural=None, metadata=None):
    if b < a:
        a, b = b, a
    return {
        "a": a, "b": b, "record_type": rtype,
        "pair_key": dq._pair_key(a, b),
        "signals": {"cosine": cosine, "lexical": lexical,
                    "structural": structural, "metadata": metadata},
    }


def _cfg(**over):
    cfg = {
        "calibration": "platt", "cv_folds": 5, "l2": 1.0,
        "cert_prob": 0.99, "cert_cosine": 0.97, "cert_lexical": 0.30,
        "review_prob": 0.50, "beta_prior": (0.5, 0.5), "lcb_quantile": 0.05,
        "_label_meta": {"circular_cosine_only_negatives": False},
    }
    cfg.update(over)
    return cfg


# ===========================================================================
# SIGNALS — tokenization, lexical, structural, metadata
# ===========================================================================
class SignalTest(unittest.TestCase):
    def test_tokens_drops_stopwords_and_short(self):
        toks = dq._tokens("Fix the Auth Session bug in PWA")
        self.assertIn("auth", toks)
        self.assertIn("session", toks)
        self.assertIn("pwa", toks)
        self.assertNotIn("the", toks)   # stopword
        self.assertNotIn("in", toks)    # stopword
        self.assertNotIn("fix", toks)   # stopword (verb noise)

    def test_jaccard_identity_and_disjoint(self):
        self.assertEqual(dq._jaccard({"a", "b"}, {"a", "b"}), 1.0)
        self.assertEqual(dq._jaccard({"a"}, {"b"}), 0.0)
        self.assertEqual(dq._jaccard(set(), set()), 0.0)   # empty != similar
        self.assertAlmostEqual(dq._jaccard({"a", "b"}, {"b", "c"}), 1 / 3)

    def test_lexical_signal_present_vs_missing(self):
        a = _rec(title="auth session expiry loop bug")
        b = _rec(title="auth session expiry infinite loop")
        val = dq.lexical_signal(a, b)
        self.assertIsNotNone(val)
        self.assertGreater(val, 0.0)
        # Missing record -> None.
        self.assertIsNone(dq.lexical_signal(a, None))
        # Both empty text -> None.
        self.assertIsNone(dq.lexical_signal(_rec(), _rec()))

    def test_structural_signal_jaccard_and_direct_ref(self):
        a = _rec(related=["ENC-FTR-1", "ENC-TSK-2"])
        b = _rec(related=["ENC-FTR-1", "ENC-TSK-9"])
        self.assertAlmostEqual(dq.structural_signal("A", "B", a, b), 1 / 3)
        # Direct cross-reference (a's neighborhood names b) floors at 0.5 even
        # when the wider neighborhoods are disjoint.
        self.assertEqual(dq.structural_signal("A", "B", _rec(related=["B"]), _rec()), 0.5)
        # None when a record is absent.
        self.assertIsNone(dq.structural_signal("A", "B", a, None))

    def test_metadata_signal_components(self):
        a = _rec(status="closed", created_at="2026-01-01T00:00:00Z", priority="P1", category="bug")
        b = _rec(status="closed", created_at="2026-01-02T00:00:00Z", priority="P1", category="bug")
        val = dq.metadata_signal(a, b)
        self.assertIsNotNone(val)
        self.assertGreater(val, 0.8)   # same priority+category+status-family, 1 day apart
        # Disagreement lowers it.
        c = _rec(status="open", created_at="2020-01-01T00:00:00Z", priority="P3", category="debt")
        self.assertLess(dq.metadata_signal(a, c), val)
        # No computable component -> None.
        self.assertIsNone(dq.metadata_signal(_rec(), _rec()))

    def test_pair_signals_clamps_cosine_and_uses_records(self):
        records = {
            "ENC-ISS-A": _rec(title="auth bug", priority="P1", status="open",
                              created_at="2026-01-01T00:00:00Z", category="bug"),
            "ENC-ISS-B": _rec(title="auth bug", priority="P1", status="open",
                              created_at="2026-01-01T00:00:00Z", category="bug"),
        }
        sig = dq.pair_signals({"a": "ENC-ISS-A", "b": "ENC-ISS-B", "cosine": 1.4}, records)
        self.assertEqual(sig["cosine"], 1.0)   # clamped to [0,1]
        self.assertEqual(sig["lexical"], 1.0)  # identical titles
        self.assertIsNotNone(sig["metadata"])
        # No records -> only cosine.
        sig2 = dq.pair_signals({"a": "X", "b": "Y", "cosine": 0.98}, None)
        self.assertEqual(sig2["cosine"], 0.98)
        self.assertIsNone(sig2["lexical"])


# ===========================================================================
# Candidate assembly
# ===========================================================================
class BuildCandidatesTest(unittest.TestCase):
    def _pairs(self):
        return [
            {"a": "ENC-ISS-B", "b": "ENC-ISS-A", "a_type": "issue", "b_type": "issue", "cosine": 0.99},
            {"a": "ENC-ISS-C", "b": "ENC-TSK-D", "a_type": "issue", "b_type": "task", "cosine": 0.999},
            {"a": "ENC-ISS-E", "b": "ENC-ISS-F", "a_type": "issue", "b_type": "issue", "cosine": 0.80},
        ]

    def test_same_type_kept_cross_type_and_below_threshold_dropped(self):
        cands = dq.build_candidates(self._pairs(), None, threshold=0.95)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["a"], "ENC-ISS-A")  # orientation: a < b
        self.assertEqual(cands[0]["b"], "ENC-ISS-B")
        self.assertEqual(cands[0]["record_type"], "issue")
        self.assertEqual(cands[0]["signals"]["cosine"], 0.99)

    def test_sorted_deterministically(self):
        pairs = [
            {"a": "ENC-ISS-Z", "b": "ENC-ISS-Y", "a_type": "issue", "b_type": "issue", "cosine": 0.99},
            {"a": "ENC-ISS-A", "b": "ENC-ISS-B", "a_type": "issue", "b_type": "issue", "cosine": 0.99},
        ]
        cands = dq.build_candidates(pairs, None, threshold=0.95)
        self.assertEqual([c["pair_key"] for c in cands], ["ENC-ISS-A|ENC-ISS-B", "ENC-ISS-Y|ENC-ISS-Z"])


# ===========================================================================
# Weak-label seed
# ===========================================================================
class DeriveLabelsTest(unittest.TestCase):
    def test_provided_label_wins(self):
        cands = [_cand("A", "B", cosine=1.0)]  # would be weak-positive
        labels, meta = dq.derive_labels(cands, {"A|B": 0}, pos_cosine=0.9999,
                                        neg_lexical=0.2, neg_cosine_band=0.97)
        self.assertEqual(labels["A|B"], (0, "provided"))
        self.assertEqual(meta["provided"], 1)
        self.assertEqual(meta["negatives"], 1)

    def test_weak_positive_from_high_cosine(self):
        cands = [_cand("A", "B", cosine=0.99995)]
        labels, meta = dq.derive_labels(cands, None, pos_cosine=0.9999,
                                        neg_lexical=0.2, neg_cosine_band=0.97)
        self.assertEqual(labels["A|B"], (1, "weak-seed"))
        self.assertEqual(meta["positives"], 1)

    def test_weak_negative_from_low_lexical(self):
        # High cosine but textually divergent -> independent negative.
        cands = [_cand("A", "B", cosine=0.991, lexical=0.05)]
        labels, meta = dq.derive_labels(cands, None, pos_cosine=0.9999,
                                        neg_lexical=0.2, neg_cosine_band=0.97)
        self.assertEqual(labels["A|B"], (0, "weak-seed"))
        self.assertEqual(meta["weak_negatives_from_lexical"], 1)
        self.assertFalse(meta["circular_cosine_only_negatives"])

    def test_cosine_only_negative_sets_circular_flag(self):
        cands = [_cand("A", "B", cosine=0.96, lexical=None)]
        labels, meta = dq.derive_labels(cands, None, pos_cosine=0.9999,
                                        neg_lexical=0.2, neg_cosine_band=0.97)
        self.assertEqual(labels["A|B"], (0, "weak-seed"))
        self.assertTrue(meta["circular_cosine_only_negatives"])
        self.assertEqual(meta["weak_negatives_from_cosine_band"], 1)


# ===========================================================================
# FUSE — logistic regression (log-odds fusion)
# ===========================================================================
class FusionTest(unittest.TestCase):
    def test_feature_vector_imputes_missing(self):
        x, imputed = dq.feature_vector({"cosine": 0.9, "lexical": None},
                                       ["cosine", "lexical"], {"cosine": 0.9, "lexical": 0.5})
        self.assertEqual(x, [0.9, 0.5])
        self.assertEqual(imputed, ["lexical"])

    def test_logistic_recovers_separable_boundary(self):
        # Feature 0 separates: low -> 0, high -> 1.
        X = [[0.1], [0.2], [0.15], [0.9], [0.95], [0.85]]
        y = [0, 0, 0, 1, 1, 1]
        model = dq.fit_logistic(X, y, l2=0.01, iters=800, lr=0.5)
        p_low = dq._sigmoid(dq.logistic_logit(model, [0.1]))
        p_high = dq._sigmoid(dq.logistic_logit(model, [0.9]))
        self.assertLess(p_low, 0.5)
        self.assertGreater(p_high, 0.5)
        self.assertGreater(p_high, p_low)

    def test_standardizer_handles_constant_column(self):
        means, stds = dq._standardizer([[1.0, 5.0], [3.0, 5.0]])
        self.assertEqual(means, [2.0, 5.0])
        self.assertEqual(stds[1], 1.0)   # constant column floored to 1.0

    def test_fit_logistic_is_deterministic(self):
        X = [[0.1], [0.9], [0.2], [0.8]]
        y = [0, 1, 0, 1]
        m1 = dq.fit_logistic(X, y)
        m2 = dq.fit_logistic(X, y)
        self.assertEqual(m1["w"], m2["w"])
        self.assertEqual(m1["b"], m2["b"])


# ===========================================================================
# CALIBRATE — Platt + isotonic + folds
# ===========================================================================
class CalibrationTest(unittest.TestCase):
    def test_platt_is_monotonic_and_bounded(self):
        scores = [-3.0, -2.0, -1.0, 1.0, 2.0, 3.0]
        labels = [0, 0, 0, 1, 1, 1]
        params = dq.fit_platt(scores, labels, iters=400, lr=0.2)
        p_lo = dq.platt_predict(params, -3.0)
        p_hi = dq.platt_predict(params, 3.0)
        self.assertTrue(0.0 < p_lo < p_hi < 1.0)
        self.assertGreater(p_hi, 0.5)
        self.assertLess(p_lo, 0.5)

    def test_isotonic_pav_is_monotone_nondecreasing(self):
        model = dq.fit_isotonic([1.0, 2.0, 3.0, 4.0], [0, 0, 1, 1])
        p1 = dq.isotonic_predict(model, 1.0)
        p4 = dq.isotonic_predict(model, 4.0)
        self.assertLessEqual(p1, p4)
        self.assertEqual(p1, 0.0)
        self.assertEqual(p4, 1.0)
        # Above the observed range -> last block value.
        self.assertEqual(dq.isotonic_predict(model, 99.0), 1.0)

    def test_isotonic_pools_violation(self):
        # Non-monotone labels get pooled into a monotone fit.
        model = dq.fit_isotonic([1.0, 2.0, 3.0, 4.0], [0, 1, 0, 1])
        ys = model["y"]
        self.assertEqual(ys, sorted(ys))   # non-decreasing

    def test_calibrator_dispatch(self):
        c_platt = dq.fit_calibrator("platt", [-1.0, 1.0], [0, 1])
        c_iso = dq.fit_calibrator("isotonic", [-1.0, 1.0], [0, 1])
        self.assertEqual(c_platt.method, "platt")
        self.assertEqual(c_iso.method, "isotonic")
        self.assertTrue(0.0 <= c_platt.predict(0.0) <= 1.0)

    def test_fold_assignment_is_deterministic_and_in_range(self):
        for key in ("ENC-ISS-A|ENC-ISS-B", "ENC-TSK-1|ENC-TSK-2", "x|y"):
            f1 = dq._fold_of(key, 5)
            f2 = dq._fold_of(key, 5)
            self.assertEqual(f1, f2)
            self.assertIn(f1, range(5))


# ===========================================================================
# CERTIFY — incomplete beta, Beta LCB, clauses, tiers
# ===========================================================================
class BetaTest(unittest.TestCase):
    def test_betainc_uniform_identity(self):
        # I_x(1,1) == x exactly.
        for x in (0.05, 0.3, 0.5, 0.9):
            self.assertAlmostEqual(dq.betainc_reg(1.0, 1.0, x), x, places=9)

    def test_beta_ppf_uniform_identity(self):
        for q in (0.05, 0.5, 0.95):
            self.assertAlmostEqual(dq.beta_ppf(q, 1.0, 1.0), q, places=6)

    def test_pure_python_betainc_matches_scipy(self):
        if _scipy is None:
            self.skipTest("scipy not installed")
        saved = dq._scipy_special
        dq._scipy_special = None  # force the pure-Python continued fraction
        try:
            for (a, b, x) in [(2, 3, 0.4), (0.5, 0.5, 0.7), (10.5, 0.5, 0.9), (3, 7, 0.25)]:
                self.assertAlmostEqual(dq.betainc_reg(a, b, x),
                                       float(_scipy.betainc(a, b, x)), places=8)
            for (a, b, q) in [(10.5, 0.5, 0.05), (0.5, 10.5, 0.05), (5, 5, 0.5)]:
                self.assertAlmostEqual(dq.beta_ppf(q, a, b),
                                       float(_scipy.betaincinv(a, b, q)), places=6)
        finally:
            dq._scipy_special = saved

    def test_beta_lcb_perfect_region_high_bound(self):
        b = dq.beta_lcb(k=20, n=20, prior=(0.5, 0.5), quantile=0.05)
        self.assertEqual(b["posterior"], [20.5, 0.5])
        self.assertAlmostEqual(b["precision_point"], 20.5 / 21.0, places=9)
        self.assertLess(b["precision_lcb"], b["precision_point"])
        self.assertGreater(b["precision_lcb"], 0.80)   # 20/20 is strong evidence
        self.assertEqual(b["confidence"], 0.95)

    def test_beta_lcb_with_one_false_positive(self):
        b = dq.beta_lcb(k=19, n=20, prior=(0.5, 0.5), quantile=0.05)
        self.assertEqual(b["posterior"], [19.5, 1.5])
        self.assertLess(b["precision_lcb"], b["precision_point"])
        # One FP lowers the bound vs a perfect region.
        self.assertLess(b["precision_lcb"], dq.beta_lcb(20, 20)["precision_lcb"])

    def test_beta_lcb_empty_region_is_prior_only(self):
        b = dq.beta_lcb(k=0, n=0, prior=(0.5, 0.5))
        self.assertEqual(b["posterior"], [0.5, 0.5])


class CertificateTest(unittest.TestCase):
    def test_conjunction_all_pass(self):
        sig = {"cosine": 0.99, "lexical": 0.5, "structural": 0.4, "metadata": 0.8}
        cert = dq.certificate_clauses(sig, prob=0.995, record_type="issue", cfg=_cfg())
        self.assertTrue(cert["passed"])
        self.assertEqual(cert["failed_clauses"], [])

    def test_conjunction_fails_on_low_prob(self):
        sig = {"cosine": 0.99, "lexical": 0.5, "structural": None, "metadata": None}
        cert = dq.certificate_clauses(sig, prob=0.80, record_type="issue", cfg=_cfg())
        self.assertFalse(cert["passed"])
        self.assertIn("prob", cert["failed_clauses"])

    def test_lexical_clause_null_when_absent(self):
        sig = {"cosine": 0.99, "lexical": None, "structural": None, "metadata": None}
        cert = dq.certificate_clauses(sig, prob=0.999, record_type="issue", cfg=_cfg())
        self.assertIsNone(cert["clauses"]["lexical"])   # skipped, not failed
        self.assertTrue(cert["passed"])                 # other active clauses hold

    def test_low_lexical_blocks_certificate(self):
        sig = {"cosine": 0.99, "lexical": 0.1, "structural": None, "metadata": None}
        cert = dq.certificate_clauses(sig, prob=0.999, record_type="issue", cfg=_cfg())
        self.assertFalse(cert["passed"])
        self.assertIn("lexical", cert["failed_clauses"])

    def test_assign_tier(self):
        cfg = _cfg()
        self.assertEqual(dq.assign_tier(0.999, True, cfg), "auto-merge")
        self.assertEqual(dq.assign_tier(0.7, False, cfg), "review")
        self.assertEqual(dq.assign_tier(0.2, False, cfg), "distinct")


# ===========================================================================
# Assembly — build_verdicts end to end
# ===========================================================================
class BuildVerdictsTest(unittest.TestCase):
    def _labeled_set(self):
        """8 candidates: 4 clear duplicates (high cosine+lexical) labeled 1,
        4 collisions (high cosine, low lexical) labeled 0."""
        cands, labels = [], {}
        for i in range(4):
            c = _cand(f"ENC-ISS-D{i}", f"ENC-ISS-E{i}", cosine=0.999,
                      lexical=0.9, structural=0.7, metadata=0.9)
            cands.append(c)
            labels[c["pair_key"]] = (1, "weak-seed")
        for i in range(4):
            c = _cand(f"ENC-ISS-F{i}", f"ENC-ISS-G{i}", cosine=0.98,
                      lexical=0.02, structural=0.0, metadata=0.1)
            cands.append(c)
            labels[c["pair_key"]] = (0, "weak-seed")
        return cands, labels

    def test_verdict_schema_and_sorting(self):
        cands, labels = self._labeled_set()
        verdicts, stats = dq.build_verdicts(cands, labels, _cfg(),
                                            generated_at="2026-06-25T00:00:00Z")
        self.assertEqual(len(verdicts), 8)
        keys = {"a", "b", "record_type", "signals", "signals_available",
                "imputed_signals", "fused_logit", "calibrated_prob", "tier",
                "certificate", "label", "label_source", "oof_prob"}
        self.assertEqual(set(verdicts[0].keys()), keys)
        # Sorted by calibrated_prob desc.
        probs = [v["calibrated_prob"] for v in verdicts]
        self.assertEqual(probs, sorted(probs, reverse=True))
        self.assertEqual(stats["generated_at"], "2026-06-25T00:00:00Z")

    def test_clear_duplicates_score_higher_than_collisions(self):
        cands, labels = self._labeled_set()
        verdicts, _ = dq.build_verdicts(cands, labels, _cfg())
        by_pair = {(v["a"], v["b"]): v for v in verdicts}
        dup = by_pair[("ENC-ISS-D0", "ENC-ISS-E0")]
        collision = by_pair[("ENC-ISS-F0", "ENC-ISS-G0")]
        self.assertGreater(dup["calibrated_prob"], collision["calibrated_prob"])

    def test_certificate_and_oof_present(self):
        cands, labels = self._labeled_set()
        _, stats = dq.build_verdicts(cands, labels, _cfg())
        self.assertTrue(stats["model"]["trainable"])
        self.assertTrue(stats["model"]["oof"])
        cert = stats["certificate"]
        for k in ("precision_point", "precision_lcb", "k", "n", "confidence"):
            self.assertIn(k, cert)
        self.assertLessEqual(cert["precision_lcb"], cert["precision_point"])

    def test_is_deterministic(self):
        c1, l1 = self._labeled_set()
        c2, l2 = self._labeled_set()
        v1, s1 = dq.build_verdicts(c1, l1, _cfg())
        v2, s2 = dq.build_verdicts(c2, l2, _cfg())
        self.assertEqual([v["calibrated_prob"] for v in v1],
                         [v["calibrated_prob"] for v in v2])
        self.assertEqual(s1["certificate"]["precision_lcb"], s2["certificate"]["precision_lcb"])

    def test_degraded_single_class(self):
        # All-positive labels -> not separable -> degraded (cosine fallback prob).
        cands = [_cand(f"A{i}", f"B{i}", cosine=0.99) for i in range(3)]
        labels = {c["pair_key"]: (1, "weak-seed") for c in cands}
        verdicts, stats = dq.build_verdicts(cands, labels, _cfg())
        self.assertFalse(stats["model"]["trainable"])
        self.assertEqual(len(verdicts), 3)
        self.assertTrue(any("not separable" in c or "not trainable" in c
                            for c in stats["caveats"]))

    def test_cosine_only_emits_circular_caveat(self):
        cands = [_cand("A", "B", cosine=0.99995),
                 _cand("C", "D", cosine=0.96)]  # cosine-only band -> negative
        cfg = _cfg(_label_meta={"circular_cosine_only_negatives": True})
        labels = {"A|B": (1, "weak-seed"), "C|D": (0, "weak-seed")}
        _, stats = dq.build_verdicts(cands, labels, cfg)
        self.assertTrue(any("internal consistency" in c for c in stats["caveats"]))


# ===========================================================================
# SINK shape
# ===========================================================================
class SinkTest(unittest.TestCase):
    def test_write_results_emits_local_files(self):
        verdicts = [{"a": "A", "b": "B", "tier": "auto-merge", "calibrated_prob": 0.99}]
        stats = {"num_pairs": 1, "generated_at": None}
        with tempfile.TemporaryDirectory() as tmp:
            args = dq.build_parser().parse_args(["--out", tmp])
            summary = dq.write_results(verdicts, stats, args)
            self.assertTrue((Path(tmp) / dq.VERDICTS_FILENAME).exists())
            self.assertTrue((Path(tmp) / dq.SUMMARY_FILENAME).exists())
            self.assertIn("artifacts", summary)
            body = (Path(tmp) / dq.VERDICTS_FILENAME).read_text().strip()
            self.assertEqual(json.loads(body), verdicts[0])

    def test_verdicts_to_jsonl_roundtrip(self):
        verdicts = [{"a": "A", "b": "B"}, {"a": "C", "b": "D"}]
        lines = [ln for ln in dq._verdicts_to_jsonl(verdicts).splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), verdicts[0])


# ===========================================================================
# Mutation-freeness — the tool must never carry a governed-write surface
# ===========================================================================
class MutationFreeTest(unittest.TestCase):
    def test_no_write_surface_symbols(self):
        # The module exposes no execute/checkout/tracker_set/put_item style writers.
        for forbidden in ("execute", "checkout_task", "tracker_set", "advance_task_status",
                          "put_item", "deploy_submit"):
            self.assertFalse(hasattr(dq, forbidden),
                             f"unexpected write-surface symbol: {forbidden}")

    def test_source_text_has_no_tracker_mutation_calls(self):
        src = Path(dq.__file__).read_text()
        for needle in ("dynamodb", "put_item", "tracker.set", "checkout.advance",
                       "advance_task_status", "execute("):
            self.assertNotIn(needle, src, f"mutation-suggesting token in source: {needle}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
