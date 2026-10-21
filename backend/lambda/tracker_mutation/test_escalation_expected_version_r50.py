"""ENC-TSK-R50 (ENC-ISS-864): expected_version normalization and the live subject token.

AC3: escalation.request reads the target and pins its sync_version. The forms that name it
("N", "sync_version:N", updated_at) are stored as given; the version_seq tracker.get shows is
normalized to the sync_version (and the receipt says so); anything else is refused 409
expected_version_stale with nothing written; omitted, the current sync_version is pinned.
AC1: the get/list read views bind a pending card's subject.version to the live sync_version and
never copy expected_version; producer gates keep their stored subject.
"""
import json
import unittest
from unittest import mock

from test_escalation_j68 import _TARGET_TASK_ITEM, _fake_ddb, _request_body

_TARGET = dict(_TARGET_TASK_ITEM, sync_version={"N": "18"}, version_seq={"N": "15715"},
               updated_at={"S": "2026-10-14T22:12:23Z"})


class _Flagged(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._flag = mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()


class TestExpectedVersionNormalization(_Flagged):
    def _run(self, target=_TARGET, **body):
        ddb = _fake_ddb(target_item=target)
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"):
            resp = self.lf._handle_escalation_request("enceladus", _request_body(**body))
        return resp, json.loads(resp["body"]), ddb

    def _stored(self, ddb):
        return ddb.put_item.call_args.kwargs["Item"]["expected_version"]["S"]

    def test_current_sync_version_forms_are_stored_as_given(self):
        for given in ("18", "sync_version:18", "2026-10-14T22:12:23Z"):
            resp, body, ddb = self._run(expected_version=given)
            self.assertEqual(201, resp["statusCode"], body)
            self.assertEqual(given, self._stored(ddb))
            self.assertEqual(given, body["expected_version"])
            self.assertNotIn("expected_version_normalized_from", body)

    def test_version_seq_is_normalized_to_the_sync_version(self):
        resp, body, ddb = self._run(expected_version="15715")
        self.assertEqual(201, resp["statusCode"], body)
        self.assertEqual("18", self._stored(ddb))
        self.assertEqual("18", body["expected_version"])
        self.assertEqual("version_seq", body["expected_version_normalized_from"])

    def test_any_other_value_is_refused_stale_and_writes_nothing(self):
        resp, body, ddb = self._run(expected_version="17")
        self.assertEqual(409, resp["statusCode"])
        self.assertEqual("expected_version_stale", body["reason"])
        self.assertEqual("CONFLICT", body["error_envelope"]["code"])
        self.assertEqual("18", body["current_sync_version"])
        self.assertEqual("15715", body["current_version_seq"])
        ddb.put_item.assert_not_called()

    def test_omitted_expected_version_pins_the_current_sync_version(self):
        resp, body, ddb = self._run()
        self.assertEqual(201, resp["statusCode"], body)
        self.assertEqual("18", self._stored(ddb))
        self.assertNotIn("expected_version_normalized_from", body)

    def test_target_without_sync_version_keeps_the_legacy_behaviour(self):
        resp, body, ddb = self._run(target=_TARGET_TASK_ITEM, expected_version="anything")
        self.assertEqual(201, resp["statusCode"], body)
        self.assertEqual("anything", self._stored(ddb))
        resp, body, ddb = self._run(target=_TARGET_TASK_ITEM)
        self.assertNotIn("expected_version", ddb.put_item.call_args.kwargs["Item"])


def _escalation(status="requested", **extra):
    item = {
        "project_id": {"S": "enceladus"},
        "record_id": {"S": "escalation#ENC-ESC-024"},
        "item_id": {"S": "ENC-ESC-024"},
        "record_type": {"S": "escalation"},
        "status": {"S": status},
        "target_record_id": {"S": "ENC-TSK-J10"},
        "expected_version": {"S": "15715"},
        "payload": {"S": json.dumps({"target_status": "closed"})},
        "requested_by": {"M": {"session_id": {"S": "ENC-SES-0NN"}}},
        "created_at": {"S": "2026-10-21T01:39:40Z"},
    }
    item.update(extra)
    return item


def _routing_ddb(escalation, target=_TARGET):
    fake = mock.MagicMock()

    def _get_item(TableName=None, Key=None, **kwargs):
        record_id = (Key or {}).get("record_id", {}).get("S", "")
        if record_id.startswith("escalation#"):
            return {"Item": escalation}
        if record_id.startswith("task#") and target is not None:
            return {"Item": target}
        return {}

    fake.get_item.side_effect = _get_item
    fake.query.return_value = {"Items": [escalation]}
    return fake


class TestLiveSubjectReadViews(_Flagged):
    def _get(self, escalation, target=_TARGET):
        with mock.patch.object(self.lf, "_get_ddb", return_value=_routing_ddb(escalation, target)):
            resp = self.lf._handle_escalation_get("enceladus", "ENC-ESC-024")
        return json.loads(resp["body"])["escalation"]

    def test_pending_get_binds_the_live_sync_version(self):
        esc = self._get(_escalation())
        self.assertEqual({"record_id": "ENC-TSK-J10", "project": "enceladus", "version": "18"}, esc["subject"])
        self.assertEqual("ENC-SES-0NN", esc["requestedBy"])

    def test_pending_list_binds_the_live_sync_version(self):
        with mock.patch.object(self.lf, "_get_ddb", return_value=_routing_ddb(_escalation())):
            resp = self.lf._handle_escalation_list("enceladus", {})
        self.assertEqual("18", json.loads(resp["body"])["escalations"][0]["subject"]["version"])

    def test_terminal_record_never_shows_expected_version(self):
        self.assertEqual("", self._get(_escalation(status="approved"))["subject"]["version"])

    def test_missing_target_renders_an_empty_token(self):
        self.assertEqual("", self._get(_escalation(), target=None)["subject"]["version"])

    def test_producer_gate_keeps_its_stored_subject(self):
        producer = _escalation(subject={"S": json.dumps({"record_id": "DVP-REC-001", "version": "1.0.0"})})
        del producer["target_record_id"]
        self.assertEqual("1.0.0", self._get(producer)["subject"]["version"])


if __name__ == "__main__":
    unittest.main()
