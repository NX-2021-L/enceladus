"""DVP-TSK-B18: an empty subjectVersion (the A38 view backfill echoed by the kit) is "not supplied"."""
import datetime as dt
import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import (  # noqa: E402
    COGNITO_CLAIMS, _decision_event, _escalation_item, _fake_ddb, _target_item,
)

_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda_b18", os.path.join(os.path.dirname(__file__), "lambda_function.py"))
coord = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = coord
_SPEC.loader.exec_module(coord)

NOW = dt.datetime(2026, 7, 2, 5, 0, 0, tzinfo=dt.timezone.utc)


def _decide(escalation, body):
    ddb = _fake_ddb(escalation=escalation, target=_target_item(sync_version=4))
    invoke = mock.MagicMock(return_value={"success": True, "status": "applied", "_status_code": 200})
    with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
         mock.patch.object(coord, "_gate_now", return_value=NOW), \
         mock.patch.object(coord, "_invoke_tracker_mutation_api", invoke), \
         mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value={"io@jreese.net"}):
        resp = coord._handle_escalation_decision(
            "enceladus", "ENC-ESC-001", "approve", _decision_event(body, COGNITO_CLAIMS), COGNITO_CLAIMS)
    return resp, invoke


class EmptySubjectVersionTests(unittest.TestCase):
    def test_legacy_card_with_backfilled_empty_version_can_be_approved(self):
        # The live failure: DVP-ESC-016's card carries subject.version "" and the kit posts it back.
        resp, invoke = _decide(_escalation_item(), {"subjectVersion": "", "guidance_note": "n"})
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()

    def test_whitespace_version_is_also_not_supplied(self):
        resp, invoke = _decide(_escalation_item(), {"subject_version": "  "})
        self.assertEqual(200, resp["statusCode"], resp["body"])

    def test_real_stale_version_is_still_412_subject_changed(self):
        resp, invoke = _decide(_escalation_item(), {"subjectVersion": "3"})
        self.assertEqual(412, resp["statusCode"])
        self.assertEqual("subject_changed", json.loads(resp["body"])["reason"])
        invoke.assert_not_called()

    def test_matching_version_still_passes(self):
        resp, invoke = _decide(_escalation_item(), {"subjectVersion": "4"})
        self.assertEqual(200, resp["statusCode"], resp["body"])

    def test_strict_record_with_empty_version_is_428_not_a_pass(self):
        item = dict(_escalation_item(), kind="tool_call")   # explicit non-legacy kind => strict
        ddb = _fake_ddb(escalation=item, target=_target_item(sync_version=4))
        with mock.patch.object(coord, "_get_ddb", return_value=ddb), \
             mock.patch.object(coord, "_gate_now", return_value=NOW), \
             mock.patch.object(coord, "_invoke_tracker_mutation_api", mock.MagicMock()), \
             mock.patch.object(coord, "_load_escalation_approver_allowlist", return_value={"io@jreese.net"}):
            event = _decision_event({"subjectVersion": ""}, COGNITO_CLAIMS)
            event["headers"] = {"If-Match": coord._escalation_etag(item), "Idempotency-Key": "k-b18"}
            resp = coord._handle_escalation_decision("enceladus", "ENC-ESC-001", "approve", event, COGNITO_CLAIMS)
        self.assertEqual(428, resp["statusCode"], resp["body"])
        self.assertEqual("precondition_required", json.loads(resp["body"])["reason"])


if __name__ == "__main__":
    unittest.main()
