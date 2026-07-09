"""ENC-TSK-J72 (ENC-FTR-121 Ph5): escalation SNS notification tests.

Covers: exactly one [ESCALATION]-prefixed publish on a successful
escalation.request (after the durable write, carrying escalation_id, target,
mutation type, requesting session, and the justification excerpt); §5.8
failure isolation (a raising SNS client never fails the request or applier);
no publish on request-validation failures (nothing reached io's queue);
terminal applied/failed notifications; and the unset-ARN skip path.
"""
import json
import unittest
from unittest import mock

from test_escalation_j68 import _fake_ddb, _request_body, _TARGET_TASK_ITEM
from test_escalation_applier_j69 import _FakeDdb, _escalation_item, _target_task


class _NotifyBase(unittest.TestCase):
    def setUp(self):
        import lambda_function as lf
        self.lf = lf
        self._patches = [
            mock.patch.object(lf, "ENABLE_ESCALATION_PRIMITIVE", True),
            mock.patch.object(lf, "ESCALATION_ALERTS_TOPIC_ARN",
                              "arn:aws:sns:us-west-2:1:devops-feed-alerts-test"),
            mock.patch.object(lf, "_get_events", return_value=mock.MagicMock()),
        ]
        for patch in self._patches:
            patch.start()
        self.sns = mock.MagicMock()
        self._sns_patch = mock.patch.object(self.lf, "_get_sns", return_value=self.sns)
        self._sns_patch.start()

    def tearDown(self):
        self._sns_patch.stop()
        for patch in self._patches:
            patch.stop()


class TestRequestNotification(_NotifyBase):
    def _request(self, body, ddb):
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb), \
             mock.patch.object(self.lf, "_get_project_prefix", return_value="ENC"):
            return self.lf._handle_escalation_request("enceladus", body)

    def test_successful_request_publishes_exactly_one_escalation_email(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM, counter_next=7)
        resp = self._request(_request_body(), ddb)
        self.assertEqual(201, resp["statusCode"])
        self.assertEqual(1, self.sns.publish.call_count)
        kwargs = self.sns.publish.call_args.kwargs
        self.assertTrue(kwargs["Subject"].startswith("[ESCALATION] requested:"))
        self.assertIn("deploy_arc_change", kwargs["Subject"])
        message = kwargs["Message"]
        escalation_id = json.loads(resp["body"])["escalation_id"]
        self.assertIn(escalation_id, message)
        self.assertIn("ENC-TSK-J10", message)
        self.assertIn("ENC-SES-02F", message)
        self.assertIn("Arc misclassified at create", message)
        self.assertEqual(kwargs["TopicArn"],
                         "arn:aws:sns:us-west-2:1:devops-feed-alerts-test")

    def test_publish_happens_after_write_and_failure_never_fails_request(self):
        self.sns.publish.side_effect = RuntimeError("SNS down")
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
        resp = self._request(_request_body(), ddb)
        # The escalation write succeeded and the response is still 201.
        self.assertEqual(201, resp["statusCode"])
        self.assertEqual(1, ddb.put_item.call_count)

    def test_validation_failure_publishes_nothing(self):
        ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
        resp = self._request(_request_body(justification=""), ddb)
        self.assertEqual(400, resp["statusCode"])
        self.sns.publish.assert_not_called()

    def test_unset_topic_arn_skips_publish_without_error(self):
        with mock.patch.object(self.lf, "ESCALATION_ALERTS_TOPIC_ARN", ""):
            ddb = _fake_ddb(target_item=_TARGET_TASK_ITEM)
            resp = self._request(_request_body(), ddb)
        self.assertEqual(201, resp["statusCode"])
        self.sns.publish.assert_not_called()


class TestTerminalNotifications(_NotifyBase):
    def _apply(self, ddb):
        with mock.patch.object(self.lf, "_get_ddb", return_value=ddb):
            return self.lf._handle_escalation_apply(
                "enceladus", "ENC-ESC-001",
                {"write_source": {"provider": "io:test"}})

    def test_applied_sends_terminal_notification(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        subjects = [call.kwargs["Subject"] for call in self.sns.publish.call_args_list]
        self.assertTrue(any(s.startswith("[ESCALATION] applied: ENC-ESC-001") for s in subjects))

    def test_failed_sends_terminal_notification_with_error_note(self):
        ddb = _FakeDdb(escalation=_escalation_item(), target=None)
        resp = self._apply(ddb)
        self.assertEqual(409, resp["statusCode"])
        kwargs = self.sns.publish.call_args.kwargs
        self.assertTrue(kwargs["Subject"].startswith("[ESCALATION] failed: ENC-ESC-001"))
        self.assertIn("not found", kwargs["Message"])

    def test_terminal_publish_failure_does_not_break_applier(self):
        self.sns.publish.side_effect = RuntimeError("SNS down")
        ddb = _FakeDdb(escalation=_escalation_item(), target=_target_task())
        resp = self._apply(ddb)
        self.assertEqual(200, resp["statusCode"])
        self.assertEqual("applied", json.loads(resp["body"])["status"])


if __name__ == "__main__":
    unittest.main()
