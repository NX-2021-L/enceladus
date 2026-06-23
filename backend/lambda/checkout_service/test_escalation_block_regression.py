"""ENC-TSK-H53 / ENC-ISS-142 gate #5 — regression coverage for the escalation/block
failure modes. Locks the escalation-signaling contract (ENC-TSK-H49) so the gate
semantics cannot silently regress: every deterministic-governance block must classify
correctly and carry operator-facing recommended_next_actions, and the no_code arc /
subtask gate / transition_type strictness blocks must route to that signal rather than
to a bypass. Covers DOC-476D273C6566 Phase-2 gate #5 cases (a)-(d):

  (a) invalid no_code direct close (B58/B72) — no_code arc still requires coding-complete
  (b) transition_type strictness mismatch before checkout — component_lifecycle_blocked
  (c) subtask gate block (ENC-ISS-106) — GATE_CONDITION_UNMET
  (d) stale-checkout detection (ENC-TSK-H51)
"""
import importlib.util
import json
import os
import unittest
from datetime import datetime, timezone

_HERE = os.path.dirname(__file__)


def _load(mod_name, rel_path):
    spec = importlib.util.spec_from_file_location(mod_name, os.path.join(_HERE, rel_path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


checkout_service = _load("checkout_service", "lambda_function.py")
stale_monitor = _load(
    "stale_checkout_monitor", "../stale_checkout_monitor/lambda_function.py"
)


class EscalationClassificationContractTests(unittest.TestCase):
    """The H49 classification system is the source of the escalation signal."""

    def test_canonical_classifications(self):
        self.assertEqual(
            checkout_service.FAILURE_CLASSIFICATIONS,
            ("transient", "deterministic-governance", "external-dependency", "human-override-required"),
        )

    def test_governance_block_codes_classify_deterministic(self):
        # (a) invalid no_code close + generic bad input, (b) strictness mismatch,
        # (c) subtask gate — all are deterministic-governance blocks the agent must
        # NOT bypass.
        for code in ("INVALID_INPUT", "CONFLICT", "component_lifecycle_blocked", "GATE_CONDITION_UNMET"):
            self.assertEqual(
                checkout_service._failure_classification(code, 400, None),
                "deterministic-governance",
                f"{code} must classify as deterministic-governance",
            )

    def test_authority_and_status_fallbacks(self):
        self.assertEqual(
            checkout_service._failure_classification("PERMISSION_DENIED", 403, None),
            "human-override-required",
        )
        self.assertEqual(checkout_service._failure_classification(None, 500, None), "transient")
        self.assertEqual(checkout_service._failure_classification(None, 400, None), "deterministic-governance")
        # explicit override wins; an invalid override is ignored
        self.assertEqual(
            checkout_service._failure_classification("CONFLICT", 409, "external-dependency"),
            "external-dependency",
        )
        self.assertEqual(
            checkout_service._failure_classification("CONFLICT", 409, "bogus"),
            "deterministic-governance",
        )

    def test_every_classification_has_actionable_guidance(self):
        for cls in checkout_service.FAILURE_CLASSIFICATIONS:
            actions = checkout_service._RECOMMENDED_NEXT_ACTIONS.get(cls, [])
            self.assertTrue(actions, f"{cls} must have recommended_next_actions")
            self.assertTrue(all(isinstance(a, str) and a for a in actions))
        # the governance guidance must point at escalation, not circumvention
        gov = " ".join(checkout_service._RECOMMENDED_NEXT_ACTIONS["deterministic-governance"]).lower()
        self.assertIn("escalat", gov)
        self.assertIn("subtask gate", gov)


class ErrorEnvelopeCarriesEscalationTests(unittest.TestCase):
    """_error() must inject failure_classification + recommended_next_actions on every
    blocked response (the signal H50 then preserves across the MCP boundary)."""

    @staticmethod
    def _envelope(result):
        if isinstance(result, dict) and "error_envelope" in result:
            return result["error_envelope"]
        return json.loads(result["body"])["error_envelope"]

    def test_subtask_gate_block_envelope(self):
        env = self._envelope(
            checkout_service._error(409, "subtask gate unmet", code="GATE_CONDITION_UNMET")
        )
        self.assertEqual(env["failure_classification"], "deterministic-governance")
        self.assertTrue(env["recommended_next_actions"])

    def test_strictness_block_envelope(self):
        env = self._envelope(
            checkout_service._error(400, "transition_type too weak", code="component_lifecycle_blocked")
        )
        self.assertEqual(env["failure_classification"], "deterministic-governance")
        self.assertTrue(env["recommended_next_actions"])

    def test_authority_block_envelope(self):
        env = self._envelope(
            checkout_service._error(403, "needs human override", code="PERMISSION_DENIED")
        )
        self.assertEqual(env["failure_classification"], "human-override-required")
        self.assertTrue(env["recommended_next_actions"])


class NoCodeArcRegressionTests(unittest.TestCase):
    """(a) B58/B72: a no_code task still flows open -> in-progress -> coding-complete ->
    closed. A direct close that skips coding-complete is an invalid transition, not a
    shortcut — the arc must not admit deploy stages."""

    def test_no_code_arc_requires_coding_complete_and_excludes_deploy(self):
        arc = checkout_service.ALLOWED_TRANSITIONS_BY_TYPE["no_code"]
        self.assertIn("coding-complete", arc)
        self.assertIn("closed", arc)
        for forbidden in ("committed", "pr", "deploy-init", "deploy-success"):
            self.assertNotIn(forbidden, arc, f"no_code arc must not include {forbidden}")


class StaleCheckoutDetectionRegressionTests(unittest.TestCase):
    """(d) ENC-TSK-H51: the monitor flags a long-held checkout and emits the signal shape."""

    def test_long_held_checkout_flagged(self):
        now = datetime(2026, 6, 23, 20, 0, 0, tzinfo=timezone.utc)
        items = [
            {
                "record_type": "task",
                "item_id": "ENC-TSK-STALE",
                "checkout_state": "checked_out",
                "checked_out_by": "abandoned-session",
                "checked_out_at": "2026-06-23T10:00:00Z",
            }
        ]
        signals = stale_monitor.detect_stale(items, now, 240)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["reason"], "long_held_checkout")
        for key in ("record_id", "checked_out_by", "checked_out_at", "age_minutes"):
            self.assertIn(key, signals[0])


if __name__ == "__main__":
    unittest.main()
