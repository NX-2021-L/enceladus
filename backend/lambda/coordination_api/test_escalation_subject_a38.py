"""DVP-TSK-A38: the escalations feed view gives every card a gates.schema subject."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambda_function as lf  # noqa: E402


def _view(item):
    lf._escalation_gate_view(item)
    return item


class SubjectBackfillTests(unittest.TestCase):
    def test_legacy_request_without_subject_gets_target_subject(self):
        card = _view({"item_id": "ENC-ESC-007", "project_id": "enceladus", "status": "requested",
                      "target_record_id": "ENC-TSK-Q01", "expected_version": "12"})
        self.assertEqual({"record_id": "ENC-TSK-Q01", "project": "enceladus", "version": "12"}, card["subject"])

    def test_subject_without_record_id_falls_back_to_item_id(self):
        card = _view({"item_id": "DVP-ESC-020", "project_id": "devops", "status": "requested",
                      "kind": "notice", "subject": {"type": "producer_delegated", "record_id": ""}})
        self.assertEqual("DVP-ESC-020", card["subject"]["record_id"])
        self.assertEqual("producer_delegated", card["subject"]["type"])
        self.assertEqual("", card["subject"]["version"])

    def test_json_string_subject_is_read_not_replaced(self):
        # recipe.publish gates (DVP-ESC-011..015) store subject as a JSON string; the card must name
        # the recipe, not fall back to its own escalation id.
        card = _view({"item_id": "DVP-ESC-011", "project_id": "devops", "status": "requested", "kind": "acceptance",
                      "subject": '{"type": "recipe_version", "record_id": "DVP-REC-001", "version": "1.0.0", "target": "published"}'})
        self.assertEqual("DVP-REC-001", card["subject"]["record_id"])
        self.assertEqual("1.0.0", card["subject"]["version"])
        self.assertEqual("devops", card["subject"]["project"])
        self.assertEqual("recipe_version", card["subject"]["type"])

    def test_unparseable_string_subject_still_backfills(self):
        card = _view({"item_id": "DVP-ESC-030", "project_id": "devops", "status": "requested", "subject": "not json"})
        self.assertEqual("DVP-ESC-030", card["subject"]["record_id"])

    def test_card_carries_id_equal_to_item_id_and_etag_unchanged(self):
        # DVP-TSK-B03: the cockpit only renders Approve/Deny (and decideCard only posts) when card.id is set.
        base = {"item_id": "DVP-ESC-016", "project_id": "devops", "status": "requested", "updated_at": "2026-10-12T14:34:34Z"}
        card = _view(dict(base))
        self.assertEqual("DVP-ESC-016", card["id"])
        self.assertEqual(lf._escalation_etag(dict(base)), card["etag"])

    def test_complete_subject_is_untouched(self):
        subject = {"record_id": "DVP-REC-001", "project": "devops", "version": "3", "type": "recipe"}
        card = _view({"item_id": "DVP-ESC-011", "project_id": "devops", "status": "requested",
                      "subject": dict(subject)})
        self.assertEqual(subject, card["subject"])

    def test_etag_does_not_depend_on_subject(self):
        a = _view({"item_id": "X", "status": "requested", "updated_at": "t"})
        b = {"item_id": "X", "status": "requested", "updated_at": "t", "subject": {"record_id": "Y", "version": "1"}}
        self.assertEqual(a["etag"], lf._escalation_etag(b))


class LegacyCardInvariantTests(unittest.TestCase):
    """Mirror of @io-kit/gates parseGateCard rules for a pre-gate escalation.request record."""

    TS = __import__("re").compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

    def test_legacy_record_satisfies_the_kit_card_rules(self):
        card = _view({"item_id": "ENC-ESC-007", "project_id": "enceladus", "status": "requested",
                      "target_record_id": "ENC-TSK-Q01", "created_at": "2026-10-11T10:00:00.123456+00:00",
                      "requiredAuth": "cognito_max_age"})
        self.assertRegex(card["createdAt"], self.TS)
        self.assertRegex(card["expiresAt"], self.TS)
        self.assertLess(card["createdAt"], card["expiresAt"])
        self.assertTrue(card["evidence"] and all(isinstance(e["label"], str) and isinstance(e["ref"], str) for e in card["evidence"]))
        self.assertEqual("ENC-TSK-Q01", card["evidence"][0]["ref"])
        self.assertIn(card["requiredAuth"], ("session", "interactive_human", "step_up"))
        self.assertTrue(card["subject"]["record_id"])
        self.assertIsInstance(card["subject"]["version"], str)

    def test_existing_evidence_is_kept(self):
        card = _view({"item_id": "X", "status": "requested", "evidence": [{"label": "run", "ref": "R1"}]})
        self.assertEqual([{"label": "run", "ref": "R1"}], card["evidence"])


if __name__ == "__main__":
    unittest.main()
