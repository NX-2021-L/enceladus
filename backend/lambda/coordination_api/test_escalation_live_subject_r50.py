"""ENC-TSK-R50 (ENC-ISS-864): the decide subject token is the target's live sync_version.

DVP-ESC-024 was filed with expected_version = the target's version_seq (15715), the view copied
it into subject.version, the cockpit echoed it as subjectVersion and decide compared it with the
target's sync_version (18): every approve was a permanent, silent 412. These tests pin the fix:
the token is bound at render (AC1), a 412 means a write between render and click and its card
carries the fresh token (AC2), filing-time drift is informational (AC4), refusals carry matching
error codes (AC6) and are logged (AC7). Strict 428s, replay, deny, expiry and self-review stay
covered by the existing suites (test_escalation_decide_hardening_e4.py, test_escalation_gate_e4.py,
test_escalation_decision_j70.py), which run unchanged apart from the diff shape.
"""
import datetime as dt
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))

from test_escalation_decision_j70 import (  # noqa: E402
    COGNITO_CLAIMS, _escalation_item, _serialized, _target_item, coordination_lambda as coord,
)
from test_escalation_decide_hardening_e4 import (  # noqa: E402
    _decide, _strict_body, _strict_headers, _strict_item,
)

UTC = dt.timezone.utc
VERSION_SEQ = 15715   # what tracker.get showed the requesting agent


def _feed(escalation, target):
    """GET the single-project feed over a fake table holding one escalation and its target."""
    ddb = mock.MagicMock()
    ddb.query.return_value = {"Items": [_serialized(escalation)]}

    def _get_item(TableName=None, Key=None, **kwargs):
        if (Key or {}).get("record_id", {}).get("S", "").startswith("task#") and target is not None:
            return {"Item": _serialized(target)}
        return {}

    ddb.get_item.side_effect = _get_item
    with mock.patch.object(coord, "_get_ddb", return_value=ddb):
        resp = coord._handle_escalations_feed({"queryStringParameters": {"project_id": "enceladus"}},
                                              COGNITO_CLAIMS)
    return json.loads(resp["body"])


def _legacy_item(**extra):
    item = _escalation_item(mutation_type="direct_state_override", payload={"target_status": "closed"},
                            expected_version=str(VERSION_SEQ))
    item.update(extra)
    return item


def _seq_target(sync_version):
    target = _target_item(sync_version=sync_version)
    target["version_seq"] = VERSION_SEQ + 100   # the record moved on; version_seq is a global stamp
    return target


class TestLiveSubjectToken(unittest.TestCase):
    def test_feed_binds_the_live_sync_version_not_expected_version(self):
        card = _feed(_legacy_item(), _seq_target(18))["pending"][0]
        self.assertEqual({"record_id": "ENC-TSK-J10", "project": "enceladus", "version": "18"}, card["subject"])
        self.assertEqual(str(VERSION_SEQ), card["diff"]["filed_against"]["expected_version"])
        self.assertTrue(card["diff"]["filed_against"]["changed"])   # informational only
        self.assertIs(False, card["diff"]["drift"])                  # never blocks approve
        self.assertEqual("ENC-SES-02F", card["requestedBy"])          # AC5: Requested by is filled

    def test_version_seq_filed_escalation_approves_with_the_rendered_token(self):
        # AC10 (a): the DVP-ESC-024 shape. Render, echo the token, approve: applied on the first click.
        item = _legacy_item()
        token = _feed(item, _seq_target(4))["pending"][0]["subject"]["version"]
        self.assertEqual("4", token)
        resp, ddb, invoke = _decide(item, body={"subject_version": token}, target=_seq_target(4))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()
        self.assertEqual("applied", json.loads(resp["body"])["status"])

    def test_write_between_render_and_click_is_412_with_the_fresh_token_then_succeeds(self):
        # AC10 (b) / AC2: a real change since render is refused, and the 412 card re-renders it.
        item = _legacy_item()
        resp, ddb, invoke = _decide(item, body={"subject_version": "4"}, target=_seq_target(5))
        body = json.loads(resp["body"])
        self.assertEqual(412, resp["statusCode"])
        self.assertEqual("subject_changed", body["reason"])
        self.assertEqual("5", body["subject_version"])
        self.assertEqual("5", body["card"]["subject"]["version"])
        self.assertIs(False, body["card"]["diff"]["drift"])
        ddb.update_item.assert_not_called()
        invoke.assert_not_called()
        resp, ddb, invoke = _decide(item, body={"subject_version": body["card"]["subject"]["version"]},
                                    target=_seq_target(5))
        self.assertEqual(200, resp["statusCode"], resp["body"])
        invoke.assert_called_once()

    def test_card_changed_412_card_carries_the_live_token_and_diff(self):
        item = _strict_item()
        headers = dict(_strict_headers(item), **{"If-Match": '"deadbeef"'})
        resp, _ddb, invoke = _decide(item, body=_strict_body(item), headers=headers)
        body = json.loads(resp["body"])
        self.assertEqual(412, resp["statusCode"])
        self.assertEqual("card_changed", body["reason"])
        self.assertEqual("4", body["card"]["subject"]["version"])
        self.assertEqual("transition_type", body["card"]["diff"]["field"])
        invoke.assert_not_called()

    def test_producer_gate_semver_subject_is_untouched(self):
        # AC10 (c): recipe.publish style gate, no tracker target: the stored subject stands.
        producer = {"item_id": "DVP-ESC-011", "project_id": "devops", "status": "requested", "kind": "acceptance",
                    "created_at": "2026-07-02T04:00:00Z", "updated_at": "2026-07-02T04:00:00Z",
                    "subject": '{"type": "recipe_version", "record_id": "DVP-REC-001", "version": "1.0.0"}'}
        card = _feed(producer, None)["pending"][0]
        self.assertEqual("1.0.0", card["subject"]["version"])
        self.assertEqual("DVP-REC-001", card["subject"]["record_id"])
        view = dict(producer)
        coord._escalation_gate_view(view)
        coord._escalation_bind_live_subject(view, _target_item(sync_version=99))
        self.assertEqual("1.0.0", view["subject"]["version"])

    def test_missing_target_renders_an_empty_token(self):
        view = dict(_legacy_item())
        coord._escalation_gate_view(view)
        coord._escalation_bind_live_subject(view, None)
        self.assertEqual("", view["subject"]["version"])   # "" is "not supplied" at decide (DVP-TSK-B18)


class TestRefusalErrorCodes(unittest.TestCase):
    def test_error_helper_maps_each_status_to_a_matching_code(self):
        expected = {403: "PERMISSION_DENIED", 404: "NOT_FOUND", 409: "CONFLICT", 410: "GONE",
                    412: "PRECONDITION_FAILED", 422: "INVALID_INPUT", 428: "PRECONDITION_REQUIRED",
                    418: "REQUEST_REJECTED", 500: "INTERNAL_ERROR"}
        for status, code in expected.items():
            body = json.loads(coord._error(status, "x")["body"])
            self.assertEqual(code, body["error_envelope"]["code"], status)

    def _code(self, resp):
        return json.loads(resp["body"])["error_envelope"]["code"]

    def test_decide_refusals_never_report_internal_error(self):
        resp, _ddb, _invoke = _decide(_legacy_item(), body={"subject_version": "3"})
        self.assertEqual((412, "PRECONDITION_FAILED"), (resp["statusCode"], self._code(resp)))
        item = _strict_item()
        resp, _ddb, _invoke = _decide(item, body=_strict_body(item), headers={"Idempotency-Key": "k"})
        self.assertEqual((428, "PRECONDITION_REQUIRED"), (resp["statusCode"], self._code(resp)))
        resp, _ddb, _invoke = _decide(_legacy_item(status="approved"))
        self.assertEqual((409, "CONFLICT"), (resp["statusCode"], self._code(resp)))
        later = dt.datetime(2026, 7, 9, tzinfo=UTC)
        claims = dict(COGNITO_CLAIMS, auth_time=int(later.timestamp()) - 60)
        resp, _ddb, _invoke = _decide(_legacy_item(), claims=claims, now=later)
        self.assertEqual((410, "GONE"), (resp["statusCode"], self._code(resp)))


class TestRefusalLogging(unittest.TestCase):
    def _refusal_lines(self, logs):
        prefix = "escalation decision refused "
        return [json.loads(m.split(prefix, 1)[1]) for m in logs.output if prefix in m]

    def test_subject_changed_refusal_logs_one_structured_warning(self):
        with self.assertLogs(coord.logger, level="WARNING") as logs:
            resp, _ddb, _invoke = _decide(_legacy_item(), body={"subject_version": "4"}, target=_seq_target(5))
        self.assertEqual(412, resp["statusCode"])
        lines = self._refusal_lines(logs)
        self.assertEqual([{
            "escalation_id": "ENC-ESC-001", "project_id": "enceladus", "verdict": "approve",
            "status": 412, "reason": "subject_changed", "code": "PRECONDITION_FAILED",
            "client_subject_version": "4", "live_subject_version": "5",
        }], lines)
        joined = "\n".join(logs.output)
        for secret in ("io@jreese.net", COGNITO_CLAIMS["sub"], "auth_time"):
            self.assertNotIn(secret, joined)

    def test_every_refusal_status_is_logged(self):
        item = _strict_item()
        with self.assertLogs(coord.logger, level="WARNING") as logs:
            _decide(item, body=_strict_body(item), headers={"Idempotency-Key": "k"})   # 428
            _decide(_legacy_item(status="approved"))                                   # 409
        self.assertEqual([428, 409], [line["status"] for line in self._refusal_lines(logs)])

    def test_success_logs_no_refusal(self):
        with mock.patch.object(coord, "_log_escalation_refusal") as log_refusal:
            resp, _ddb, _invoke = _decide(_legacy_item(), body={"subject_version": "4"})
        self.assertEqual(200, resp["statusCode"], resp["body"])
        log_refusal.assert_not_called()


if __name__ == "__main__":
    unittest.main()
