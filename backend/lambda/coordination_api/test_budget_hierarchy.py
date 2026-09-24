"""Unit tests for the Budget Hierarchy Controller (ENC-FTR-083 Ph1 / ENC-TSK-I86).

Covers the three core acceptance criteria:
  * AC-1: four-scale budget config is readable at runtime with canonical defaults.
  * AC-2: Banach-iteration solver converges in <= 1 pass (norm(s_new - s_old) < 1e-6).
  * AC-3: logarithmic beta-schedule with beta_0 = 8.0 hits ~8.0 at t=0 and ~3.33 at t=10.

Pure-stdlib unittest so it runs under both ``python -m unittest`` and pytest
without any AWS or third-party dependency.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import budget_hierarchy as bhc  # noqa: E402


class TestScaleBudgetConfig(unittest.TestCase):
    """AC-1: four canonical scale budgets, readable at runtime."""

    def test_default_budgets_present_for_all_scales(self):
        budgets = bhc.load_scale_budgets()
        self.assertEqual(set(budgets), set(bhc.SCALES))
        # Canonical ENC-TSK-I86 token budgets.
        self.assertEqual(budgets["session"], 200_000)
        self.assertEqual(budgets["wave"], 50_000)
        self.assertEqual(budgets["project"], 500_000)
        self.assertEqual(budgets["corpus"], 2_000_000)

    def test_env_override(self):
        os.environ["BUDGET_SESSION_TOKENS"] = "123456"
        try:
            budgets = bhc.load_scale_budgets()
            self.assertEqual(budgets["session"], 123_456)
        finally:
            del os.environ["BUDGET_SESSION_TOKENS"]

    def test_invalid_override_falls_back_to_default(self):
        os.environ["BUDGET_CORPUS_TOKENS"] = "not-a-number"
        try:
            budgets = bhc.load_scale_budgets()
            self.assertEqual(budgets["corpus"], 2_000_000)
        finally:
            del os.environ["BUDGET_CORPUS_TOKENS"]

    def test_appconfig_value_takes_precedence_over_env_and_default(self):
        """ENC-TSK-K33: the `budget-hierarchy` AppConfig profile ships
        `budget_<scale>_tokens` keys (see 09-appconfig-governance.yaml). Pins
        that exact key format against the reader so a schema/key mismatch
        between the CFN content and this resolver — the same silent-failure
        class ENC-TSK-K32 found for the dedup flags — would fail loudly here
        instead of being discovered live."""
        original = bhc._appconfig_budget_config
        bhc._appconfig_budget_config = lambda: {"budget_wave_tokens": 999}
        os.environ["BUDGET_WAVE_TOKENS"] = "111"  # lower precedence than AppConfig
        try:
            budgets = bhc.load_scale_budgets()
            self.assertEqual(budgets["wave"], 999)
        finally:
            bhc._appconfig_budget_config = original
            del os.environ["BUDGET_WAVE_TOKENS"]


class TestBanachSolver(unittest.TestCase):
    """AC-2: solver converges in <= 1 iteration on the interior 4-scale vector."""

    def setUp(self):
        cal = bhc.DEFAULT_SOLVER_CALIBRATION
        self.s = cal["s"]
        self.T = cal["T"]
        self.c = cal["c"]
        self.lam = cal["lam"]
        self.k_anchor = cal["k_anchor"]

    def test_converges_after_one_pass(self):
        # Seed every scale at the corpus anchor, then take two passes.
        seed = [self.k_anchor] * 4
        s_old = bhc.recurrence_step(seed, self.s, self.T, self.c, self.lam, self.k_anchor)
        s_new = bhc.recurrence_step(s_old, self.s, self.T, self.c, self.lam, self.k_anchor)
        delta = bhc.l2_norm_delta(s_new, s_old)
        # AC-2: ||s_new - s_old|| < 1e-6 after pass 1.
        self.assertLess(delta, 1e-6, f"solver not converged after one pass: delta={delta}")

    def test_find_fixed_point_one_effective_pass(self):
        k_star, iterations = bhc.find_fixed_point(
            self.s, self.T, self.c, self.lam, self.k_anchor
        )
        # Converges almost immediately (one solve pass + one confirmation pass).
        self.assertLessEqual(iterations, 2)
        # Corpus anchor is preserved by the recurrence.
        self.assertAlmostEqual(k_star[3], self.k_anchor, delta=1.0)
        # Interior modes are nested and strictly below their parents.
        self.assertLess(k_star[0], k_star[1])
        self.assertLess(k_star[1], k_star[2])
        self.assertLess(k_star[2], k_star[3])

    def test_fixed_point_is_stable_under_reapplication(self):
        k_star, _ = bhc.find_fixed_point(
            self.s, self.T, self.c, self.lam, self.k_anchor
        )
        k_again = bhc.recurrence_step(k_star, self.s, self.T, self.c, self.lam, self.k_anchor)
        self.assertLess(bhc.l2_norm_delta(k_again, k_star), 1e-6)


class TestLogarithmicBetaSchedule(unittest.TestCase):
    """AC-3: logarithmic beta-schedule, beta_0 = 8.0."""

    def test_beta_at_zero_is_anchor(self):
        self.assertAlmostEqual(bhc.beta_schedule(0), 8.0, delta=0.01)

    def test_beta_at_ten(self):
        self.assertAlmostEqual(bhc.beta_schedule(10), 3.33, delta=0.01)

    def test_beta_monotonically_decreasing(self):
        prev = bhc.beta_schedule(0)
        for t in range(1, 21):
            cur = bhc.beta_schedule(t)
            self.assertLess(cur, prev)
            prev = cur

    def test_negative_step_rejected(self):
        with self.assertRaises(ValueError):
            bhc.beta_schedule(-1)

    def test_budget_ratio_beta_session_anchor(self):
        # Canonical F15 budget-ratio schedule: session ratio == 1 -> beta_0.
        self.assertAlmostEqual(bhc.beta_for_budget(200_000, 200_000), 8.0, delta=1e-9)


class TestSessionBudgetLogging(unittest.TestCase):
    """AC-5: session-init allocation logging is best-effort and structured."""

    def test_log_session_budget_allocation_returns_allocation(self):
        class _CapturingLogger:
            def __init__(self):
                self.records = []

            def debug(self, *args, **kwargs):
                self.records.append((args, kwargs))

        logger = _CapturingLogger()
        result = bhc.log_session_budget_allocation(
            logger, request_id="REQ-1", project_id="enceladus"
        )
        self.assertEqual(set(result["scales_tokens"]), set(bhc.SCALES))
        self.assertAlmostEqual(result["beta_0"], 8.0)
        self.assertEqual(set(result["betas"]), set(bhc.SCALES))
        self.assertTrue(logger.records, "expected a DEBUG log record to be emitted")


if __name__ == "__main__":
    unittest.main()
