"""Tests for ENC-TSK-F43 alarm_arn persist + cloudwatch_event 501 stub.

Validates AC[1i]-a through AC[1i]-d:
- component.approve with alarm_arn → field persisted in DDB update
- component.approve without alarm_arn → alarm_arn absent from update expression
- POST /cloudwatch_event with valid JSON body → 501 with correct body shape
- POST /cloudwatch_event with malformed body → graceful 501 (no 500)
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.dirname(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)

_ARN = "arn:aws:cloudwatch:us-west-2:123456789012:alarm:MyAlarm"


def _cognito_claims():
    return {"sub": "io-lead-cognito-user", "cognito:username": "io-lead", "iss": "cognito"}


def _approve_event(body: dict) -> dict:
    return {
        "httpMethod": "POST",
        "path": "/api/v1/coordination/components/comp-test/approve",
        "body": json.dumps(body),
    }


def _cloudwatch_event(body_str: str) -> dict:
    return {
        "httpMethod": "POST",
        "path": "/api/v1/coordination/components/comp-test/cloudwatch_event",
        "body": body_str,
    }


class AlarmArnApproveTests(unittest.TestCase):

    def setUp(self):
        self._flag_patcher = mock.patch.object(
            coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True
        )
        self._flag_patcher.start()

    def tearDown(self):
        self._flag_patcher.stop()

    def test_approve_with_alarm_arn_persists_field(self):
        """AC[1i]-a: alarm_arn is written to DDB when provided at approve time."""
        fake_ddb = mock.MagicMock()
        fake_ddb.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-test"},
                "lifecycle_status": {"S": "approved"},
                "alarm_arn": {"S": _ARN},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb), \
             mock.patch.object(coordination_lambda, "_is_cognito_session", return_value=True), \
             mock.patch.object(coordination_lambda, "_publish_component_lifecycle_event"):
            resp = coordination_lambda._handle_components_approve(
                "comp-test",
                _approve_event({"alarm_arn": _ARN}),
                _cognito_claims(),
            )
        self.assertEqual(resp["statusCode"], 200)
        # The UpdateExpression must include alarm_arn
        call_kwargs = fake_ddb.update_item.call_args.kwargs
        update_expr = call_kwargs.get("UpdateExpression", "")
        attr_vals = call_kwargs.get("ExpressionAttributeValues", {})
        self.assertIn("alarm_arn", update_expr)
        self.assertEqual(attr_vals[":alarm"]["S"], _ARN)

    def test_approve_without_alarm_arn_omits_field(self):
        """AC[1i]-a: alarm_arn absent from DDB update when not provided."""
        fake_ddb = mock.MagicMock()
        fake_ddb.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-test"},
                "lifecycle_status": {"S": "approved"},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb), \
             mock.patch.object(coordination_lambda, "_is_cognito_session", return_value=True), \
             mock.patch.object(coordination_lambda, "_publish_component_lifecycle_event"):
            resp = coordination_lambda._handle_components_approve(
                "comp-test",
                _approve_event({}),
                _cognito_claims(),
            )
        self.assertEqual(resp["statusCode"], 200)
        call_kwargs = fake_ddb.update_item.call_args.kwargs
        update_expr = call_kwargs.get("UpdateExpression", "")
        attr_vals = call_kwargs.get("ExpressionAttributeValues", {})
        self.assertNotIn(":alarm", attr_vals)
        self.assertNotIn("alarm_arn", update_expr)


class CloudwatchEventStubTests(unittest.TestCase):

    def test_valid_json_body_returns_501(self):
        """AC[1i]-b: POST /cloudwatch_event with valid JSON returns 501 with v5-deferral."""
        body = {"AlarmName": "MyAlarm", "NewStateValue": "ALARM"}
        resp = coordination_lambda._handle_components_cloudwatch_event(
            "comp-test",
            _cloudwatch_event(json.dumps(body)),
        )
        self.assertEqual(resp["statusCode"], 501)
        resp_body = json.loads(resp["body"])
        self.assertIn("v5", resp_body.get("error", "").lower())
        self.assertEqual(resp_body.get("component_id"), "comp-test")

    def test_malformed_body_returns_graceful_501(self):
        """AC[1i]-b: malformed JSON body returns 501, not 500."""
        resp = coordination_lambda._handle_components_cloudwatch_event(
            "comp-test",
            _cloudwatch_event("not-valid-json{{"),
        )
        self.assertEqual(resp["statusCode"], 501)
        resp_body = json.loads(resp["body"])
        self.assertEqual(resp_body.get("component_id"), "comp-test")


if __name__ == "__main__":
    unittest.main()
