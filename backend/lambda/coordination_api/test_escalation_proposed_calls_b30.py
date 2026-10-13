"""DVP-TSK-B30: the escalations feed serves proposedCalls as a list, never as its stored JSON string."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402

# The recipe.publish call of DVP-ESC-011 as tracker_mutation stores it (a JSON string).
CALL = {
    "capability": "recipe.publish", "mcpTool": "recipe_publish_request", "method": "POST",
    "path": "/api/v1/tracker/devops/recipe/DVP-REC-001/apply",
    "args": {"version": "1.0.0", "target": "published", "content_hash": "sha256:9f15"},
    "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "ifMatch": "sha256:9f15", "callHash": "bbd05bc3",
}


def _record(**extra):
    item = {"item_id": "DVP-ESC-011", "project_id": "devops", "status": "requested", "kind": "acceptance",
            "source_principal": "recipe-runner", "updated_at": "2026-10-12T03:15:40Z",
            "created_at": "2026-10-12T03:15:40Z", "proposedCalls": json.dumps([CALL])}
    item.update(extra)
    return item


def _view(item):
    lf._escalation_gate_view(item)
    return item


class ProposedCallsViewTests(unittest.TestCase):
    def test_json_string_proposed_calls_are_served_as_a_list(self):
        card = _view(_record())
        self.assertIsInstance(card["proposedCalls"], list)
        self.assertEqual([CALL], card["proposedCalls"])

    def test_list_proposed_calls_are_untouched(self):
        card = _view(_record(proposedCalls=[dict(CALL)]))
        self.assertEqual([CALL], card["proposedCalls"])

    def test_etag_is_unchanged_by_the_parse(self):
        raw = _record()
        self.assertEqual(lf._escalation_etag(dict(raw)), _view(dict(raw))["etag"])

    def test_client_hash_over_the_served_list_matches_the_decide_recompute(self):
        # The kit hashes card.proposedCalls when it is an array; decide recomputes from the stored record.
        raw = _record()
        served = _view(dict(raw))["proposedCalls"]
        basis, _stored = lf._escalation_call_basis(dict(raw), None)
        self.assertEqual(lf._gate_call_hash(basis), lf._gate_call_hash(served))

    def test_unparseable_string_is_left_as_is(self):
        card = _view(_record(proposedCalls="not json"))
        self.assertEqual("not json", card["proposedCalls"])


if __name__ == "__main__":
    unittest.main()
