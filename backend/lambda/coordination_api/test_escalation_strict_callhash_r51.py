"""ENC-TSK-R51 (ENC-ISS-865): a strict mutation_type escalation is approved with the client callHash.

An explicit kind other than 'escalation' makes a card strict, and strict approve requires a client
callHash. The cockpit sent one only for candidates/proposedCalls, so every strict mutation_type card
was refused 428 (gamma ZRP-ESC-001, 2026-10-21). The clients now send the legacy-triple hash on every
approve. These tests pin the hub side of that contract; the hub code itself is unchanged.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import _escalation_item, coordination_lambda as coord  # noqa: E402
from test_escalation_decide_hardening_e4 import _decide, _strict_headers  # noqa: E402

# Shared with frontend/ui-v2/src/routes/EscalationsRoute.test.tsx (callHashFor of the same triple).
VECTOR = "ada322f0433f968cd545b270ff17e1760fdeb98c5a4f65dfa9350fc92b02aec4"


def _strict_mutation_item():
    item = _escalation_item(mutation_type="direct_state_override", payload={"target_status": "closed"})
    item["kind"] = "reconciliation"   # explicit non-legacy kind: strict, no proposedCalls
    return item


class TestLegacyTripleCallHash(unittest.TestCase):
    def test_hub_hash_of_the_shared_vector(self):
        item = {"mutation_type": "direct_state_override", "target_record_id": "ENC-TSK-X01",
                "payload": json.dumps({"target_status": "closed"})}
        basis, stored = coord._escalation_call_basis(item, None)
        self.assertEqual(VECTOR, coord._gate_call_hash(basis))
        self.assertEqual("", stored)

    def test_strict_mutation_card_is_strict(self):
        self.assertTrue(coord._escalation_is_strict(_strict_mutation_item()))


class TestStrictMutationApprove(unittest.TestCase):
    def _body(self, item, **extra):
        basis, _stored = coord._escalation_call_basis(item, None)
        body = {"subject_version": "4", "callHash": coord._gate_call_hash(basis)}
        body.update(extra)
        return body

    def test_client_legacy_triple_hash_approves_and_applies(self):
        item = _strict_mutation_item()
        resp, ddb, invoke = _decide(item, body=self._body(item), headers=_strict_headers(item))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()
        self.assertEqual("applied", json.loads(resp["body"])["status"])

    def test_without_call_hash_it_is_still_428(self):
        item = _strict_mutation_item()
        body = self._body(item)
        del body["callHash"]
        resp, ddb, invoke = _decide(item, body=body, headers=_strict_headers(item))
        self.assertEqual(428, resp["statusCode"])
        self.assertEqual("precondition_required", json.loads(resp["body"])["reason"])
        self.assertIn("callHash", json.loads(resp["body"])["error"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()

    def test_wrong_call_hash_is_409_call_changed(self):
        item = _strict_mutation_item()
        resp, ddb, invoke = _decide(item, body=self._body(item, callHash="0" * 64), headers=_strict_headers(item))
        self.assertEqual(409, resp["statusCode"])
        self.assertEqual("call_changed", json.loads(resp["body"])["reason"])
        invoke.assert_not_called()

    def test_non_strict_legacy_card_accepts_the_same_hash(self):
        item = _escalation_item(mutation_type="direct_state_override", payload={"target_status": "closed"})
        resp, _ddb, invoke = _decide(item, body=self._body(item))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()


if __name__ == "__main__":
    unittest.main()
