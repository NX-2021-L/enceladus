"""Tests for coordination_api lesson gate error enrichment (ENC-TSK-D80).

Validates that _validate_lesson_transition_gate returns structured dicts
with gate_requirements, current_values, deficit, example_fix, and
ogtm_compliance_template when a lesson fails a transition gate.
"""
import importlib.util
import json
import os
import sys
import unittest


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)


class LessonGateErrorContextTests(unittest.TestCase):
    """Tests for enriched _validate_lesson_transition_gate return shape."""

    def test_gate_failure_returns_structured_dict_for_active(self):
        """Gate failure for 'active' returns dict with all enriched fields."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="active",
            pillar_scores={
                "efficiency": 0.3,
                "human_protection": 0.3,
                "intention": 0.2,
                "alignment": 0.2,
            },
            resonance_score=0.2,
            confidence=0.4,
            evidence_chain_length=1,
            lesson_id="ENC-LSN-TEST",
        )
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)

        # Required top-level keys
        for key in ("message", "gate_status", "gate_requirements",
                     "current_values", "deficit", "example_fix",
                     "ogtm_compliance_template"):
            self.assertIn(key, result, f"Missing key: {key}")

        self.assertEqual(result["gate_status"], "blocked")
        self.assertIn("active", result["message"])

        # gate_requirements should match _LESSON_TRANSITION_GATES["active"]
        self.assertIn("min_pillar_composite", result["gate_requirements"])
        self.assertIn("min_resonance", result["gate_requirements"])
        self.assertIn("min_confidence", result["gate_requirements"])
        self.assertIn("min_evidence_chain", result["gate_requirements"])

        # current_values should reflect what we passed in
        cv = result["current_values"]
        self.assertEqual(cv["resonance_score"], 0.2)
        self.assertEqual(cv["confidence"], 0.4)
        self.assertEqual(cv["evidence_chain_length"], 1)
        self.assertIn("pillar_composite", cv)
        self.assertIn("pillar_scores", cv)

        # deficit should be non-empty list of dicts
        self.assertIsInstance(result["deficit"], list)
        self.assertGreater(len(result["deficit"]), 0)
        for d in result["deficit"]:
            self.assertIn("field", d)
            self.assertIn("requirement", d)
            self.assertIn("current", d)
            self.assertIn("threshold", d)

        # example_fix should have tool and arguments
        self.assertEqual(result["example_fix"]["tool"], "tracker.set")
        self.assertIn("record_id", result["example_fix"]["arguments"])
        self.assertEqual(result["example_fix"]["arguments"]["record_id"], "ENC-LSN-TEST")

    def test_gate_failure_returns_structured_dict_for_accepted(self):
        """Gate failure for 'accepted' returns dict with pillar deficits."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="accepted",
            pillar_scores={
                "efficiency": 0.0,
                "human_protection": 0.1,
                "intention": 0.0,
                "alignment": 0.0,
            },
            resonance_score=0.1,
            confidence=0.2,
            evidence_chain_length=1,
            lesson_id="ENC-LSN-002",
        )
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["gate_status"], "blocked")

        # Should have deficit entries for pillar_composite, resonance, and
        # individual pillars below min_all_pillars (0.01)
        deficit_fields = [d["field"] for d in result["deficit"]]
        self.assertIn("pillar_composite", deficit_fields)
        self.assertIn("resonance_score", deficit_fields)

    def test_gate_pass_returns_none_for_active(self):
        """Gate passes for 'active' when all thresholds are met."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="active",
            pillar_scores={
                "efficiency": 0.8,
                "human_protection": 0.8,
                "intention": 0.7,
                "alignment": 0.8,
            },
            resonance_score=0.7,
            confidence=0.8,
            evidence_chain_length=3,
            lesson_id="ENC-LSN-PASS",
        )
        self.assertIsNone(result)

    def test_gate_pass_returns_none_for_proposed(self):
        """Gate passes for 'proposed' when evidence chain >= 1."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="proposed",
            pillar_scores={
                "efficiency": 0.1,
                "human_protection": 0.1,
                "intention": 0.1,
                "alignment": 0.1,
            },
            resonance_score=0.1,
            confidence=0.1,
            evidence_chain_length=1,
        )
        self.assertIsNone(result)

    def test_gate_no_gate_for_unknown_status_returns_none(self):
        """Unknown target status has no gate and returns None."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="unknown_status",
            pillar_scores={"efficiency": 0.1, "human_protection": 0.1,
                           "intention": 0.1, "alignment": 0.1},
            resonance_score=0.1,
            confidence=0.1,
            evidence_chain_length=0,
        )
        self.assertIsNone(result)

    def test_proposed_gate_failure_evidence_chain(self):
        """'proposed' gate fails when evidence_chain_length < 1."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="proposed",
            pillar_scores={"efficiency": 0.5, "human_protection": 0.5,
                           "intention": 0.5, "alignment": 0.5},
            resonance_score=0.5,
            confidence=0.5,
            evidence_chain_length=0,
            lesson_id="ENC-LSN-003",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["gate_status"], "blocked")
        deficit_fields = [d["field"] for d in result["deficit"]]
        self.assertIn("evidence_chain", deficit_fields)
        # example_fix should reference evidence_chain
        self.assertEqual(result["example_fix"]["arguments"]["field"], "evidence_chain")

    def test_ogtm_compliance_template_present_on_failure(self):
        """OGTM compliance template is included in gate failure response."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="active",
            pillar_scores={"efficiency": 0.1, "human_protection": 0.1,
                           "intention": 0.1, "alignment": 0.1},
            resonance_score=0.1,
            confidence=0.1,
            evidence_chain_length=0,
            lesson_id="ENC-LSN-OGTM",
        )
        self.assertIsNotNone(result)
        ogtm = result["ogtm_compliance_template"]
        self.assertIn("ogtm_requirements", ogtm)
        self.assertIn("evidence_template", ogtm)
        self.assertEqual(len(ogtm["ogtm_requirements"]), 4)
        self.assertIn("_reconcile_edges", ogtm["ogtm_requirements"][0])
        self.assertIn("RELATIONSHIP_TYPE_TO_EDGE_LABEL", ogtm["ogtm_requirements"][1])
        self.assertIn("_ALLOWED_EDGE_TYPES", ogtm["ogtm_requirements"][2])
        self.assertIn("graphsearch", ogtm["ogtm_requirements"][3])

    def test_accepted_gate_human_protection_deficit(self):
        """'accepted' gate catches human_protection below min threshold."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="accepted",
            pillar_scores={
                "efficiency": 0.8,
                "human_protection": 0.1,  # Below 0.3 min_human_protection
                "intention": 0.8,
                "alignment": 0.8,
            },
            resonance_score=0.6,
            confidence=0.7,
            evidence_chain_length=3,
            lesson_id="ENC-LSN-HP",
        )
        self.assertIsNotNone(result)
        deficit_fields = [d["field"] for d in result["deficit"]]
        self.assertIn("pillar_scores.human_protection", deficit_fields)

    def test_deficit_descriptions_in_message(self):
        """Gate failure message includes human-readable deficit descriptions."""
        result = coordination_lambda._validate_lesson_transition_gate(
            target_status="active",
            pillar_scores={"efficiency": 0.3, "human_protection": 0.3,
                           "intention": 0.2, "alignment": 0.2},
            resonance_score=0.2,
            confidence=0.3,
            evidence_chain_length=1,
            lesson_id="ENC-LSN-MSG",
        )
        self.assertIsNotNone(result)
        # Message should contain deficit descriptions
        self.assertIn("active", result["message"])
        self.assertIn("<", result["message"])  # "field (current) < threshold"


if __name__ == "__main__":
    unittest.main()
