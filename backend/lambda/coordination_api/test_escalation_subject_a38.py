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

    def test_complete_subject_is_untouched(self):
        subject = {"record_id": "DVP-REC-001", "project": "devops", "version": "3", "type": "recipe"}
        card = _view({"item_id": "DVP-ESC-011", "project_id": "devops", "status": "requested",
                      "subject": dict(subject)})
        self.assertEqual(subject, card["subject"])

    def test_etag_does_not_depend_on_subject(self):
        a = _view({"item_id": "X", "status": "requested", "updated_at": "t"})
        b = {"item_id": "X", "status": "requested", "updated_at": "t", "subject": {"record_id": "Y", "version": "1"}}
        self.assertEqual(a["etag"], lf._escalation_etag(b))


if __name__ == "__main__":
    unittest.main()
