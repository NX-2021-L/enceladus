"""E4-R25: producer-created cards (source_principal, no mutation_type) resolve to the
producer_delegated applier, which records the verdict and executes nothing hub-side."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
import lambda_function as L  # noqa: E402


class ProducerDelegatedTests(unittest.TestCase):
    def test_tool_call_from_producer_resolves_to_delegated(self):
        esc = {"kind": "tool_call", "source_principal": "vagamod", "subject": {"record_id": "x"}}
        self.assertEqual(L._escalation_subject_type(esc), "producer_delegated")
        self.assertIn("producer_delegated", L._ESCALATION_APPLIERS)

    def test_reconciliation_from_think_resolves_to_delegated(self):
        esc = {"kind": "reconciliation", "sourcePrincipal": "think"}
        self.assertEqual(L._escalation_subject_type(esc), "producer_delegated")

    def test_legacy_mutation_escalation_unchanged(self):
        esc = {"kind": "escalation", "mutation_type": "deploy_arc_change", "source_principal": "x"}
        self.assertEqual(L._escalation_subject_type(esc), "deploy_arc_change")

    def test_explicit_subject_type_wins(self):
        esc = {"kind": "tool_call", "source_principal": "think", "subject": {"type": "recipe_run_step"}}
        self.assertEqual(L._escalation_subject_type(esc), "recipe_run_step")

    def test_no_source_principal_is_not_delegated(self):
        self.assertEqual(L._escalation_subject_type({"kind": "tool_call"}), "")

    def test_applier_executes_nothing(self):
        out = L._apply_producer_delegated_escalation("mod", "MOD-ESC-001", {"source_principal": "vagamod"}, "io", {})
        self.assertEqual(out["_status_code"], 200)
        self.assertEqual(out["result"], {"executed": False, "delegated_to": "vagamod", "idempotency_key": "MOD-ESC-001"})


if __name__ == "__main__":
    unittest.main()
