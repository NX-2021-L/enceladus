"""Tests for coordination_api _handle_components_approve / _handle_components_reject (ENC-TSK-E09).

Validates ENC-FTR-076 AC2 / AC3:
- Cognito-only enforcement (403 for internal-key sessions).
- ENABLE_COMPONENT_PROPOSAL feature flag gates both handlers.
- Rejection requires rejection_reason >= 10 chars.
- Atomic UpdateItem with ConditionExpression on lifecycle_status='proposed'.
- 404 for missing component, 409 for non-proposed lifecycle_status.
- Happy-path response includes lifecycle_status, decider identity, timestamp.
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


COGNITO_CLAIMS = {
    "auth_mode": "cognito",
    "sub": "user-sub-123",
    "email": "lead@example.com",
    "cognito:username": "lead",
}
INTERNAL_CLAIMS = {"auth_mode": "internal-key", "sub": "agent"}


def _event(body):
    return {"httpMethod": "POST", "body": json.dumps(body or {})}


class _TCE(Exception):
    """Stand-in for ddb.exceptions.ConditionalCheckFailedException."""


def _fake_ddb_for_existing(item):
    """Build a MagicMock ddb whose update_item raises CCFE and get_item returns `item`."""
    fake = mock.MagicMock()
    fake.exceptions.ConditionalCheckFailedException = _TCE
    fake.update_item.side_effect = _TCE()
    fake.get_item.return_value = {"Item": item} if item is not None else {}
    return fake


class ComponentApproveTests(unittest.TestCase):
    def setUp(self):
        self._flag = mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_feature_flag_off_returns_503(self):
        with mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", False):
            resp = coordination_lambda._handle_components_approve(
                "comp-x", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 503)

    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_components_approve(
            "comp-x", _event({}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_invalid_override_transition_type_returns_400(self):
        resp = coordination_lambda._handle_components_approve(
            "comp-x", _event({"transition_type": "bogus"}), COGNITO_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_component_returns_404(self):
        fake = _fake_ddb_for_existing(None)
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-missing", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_non_proposed_returns_409(self):
        existing = {
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "active"},
        }
        fake = _fake_ddb_for_existing(existing)
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-x", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 409)
        body = json.loads(resp["body"])
        self.assertEqual(body.get("current_lifecycle_status"), "active")

    def test_happy_path_200_sets_approved_and_decider(self):
        """ENC-FTR-076 v2: approve writes lifecycle_status='approved' (§3.1),
        not the legacy 'active'. Backfill (AC[5]) migrates v1 records."""
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "approved"},
                "approved_by": {"S": "lead@example.com"},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-x", _event({}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "approved")
        self.assertEqual(body["approved_by"], "lead@example.com")

        kwargs = fake.update_item.call_args.kwargs
        self.assertIn(":proposed", kwargs["ExpressionAttributeValues"])
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":proposed"]["S"], "proposed"
        )
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":approved"]["S"], "approved"
        )
        self.assertIn("#ls = :proposed", kwargs["ConditionExpression"])

    def test_override_transition_type_in_update(self):
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {"component_id": {"S": "comp-x"}, "lifecycle_status": {"S": "approved"}}
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-x", _event({"transition_type": "code_only"}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 200)
        kwargs = fake.update_item.call_args.kwargs
        self.assertEqual(kwargs["ExpressionAttributeValues"][":tt"]["S"], "code_only")
        self.assertIn("transition_type = :tt", kwargs["UpdateExpression"])

    # ENC-FTR-076 v2 / ENC-TSK-F40: approve accepts alarm_arn (optional,
    # v5 CloudWatch hook) alongside existing required_transition_type override.

    def test_alarm_arn_persisted_when_provided(self):
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "approved"},
                "alarm_arn": {"S": "arn:aws:cloudwatch:us-west-2:123456789012:alarm:MyAlarm"},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-x",
                _event({
                    "alarm_arn": "arn:aws:cloudwatch:us-west-2:123456789012:alarm:MyAlarm",
                }),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(
            body["alarm_arn"],
            "arn:aws:cloudwatch:us-west-2:123456789012:alarm:MyAlarm",
        )
        kwargs = fake.update_item.call_args.kwargs
        self.assertIn("alarm_arn = :alarm", kwargs["UpdateExpression"])
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":alarm"]["S"],
            "arn:aws:cloudwatch:us-west-2:123456789012:alarm:MyAlarm",
        )

    def test_invalid_alarm_arn_returns_400(self):
        """alarm_arn must start with 'arn:' when provided."""
        resp = coordination_lambda._handle_components_approve(
            "comp-x",
            _event({"alarm_arn": "not-an-arn"}),
            COGNITO_CLAIMS,
        )
        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        # _component_validation_error flattens `field` to top-level details.
        self.assertEqual(body["field"], "alarm_arn")

    def test_required_transition_type_override_persisted(self):
        """F50/AC-6 preserved: approve may tighten/loosen required_transition_type."""
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "approved"},
                "required_transition_type": {"S": "lambda_deploy"},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_approve(
                "comp-x",
                _event({"required_transition_type": "lambda_deploy"}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        kwargs = fake.update_item.call_args.kwargs
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":rtt"]["S"], "lambda_deploy"
        )
        self.assertIn("required_transition_type = :rtt", kwargs["UpdateExpression"])


class ComponentRejectTests(unittest.TestCase):
    def setUp(self):
        self._flag = mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True)
        self._flag.start()

    def tearDown(self):
        self._flag.stop()

    def test_feature_flag_off_returns_503(self):
        with mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", False):
            resp = coordination_lambda._handle_components_reject(
                "comp-x", _event({"rejection_reason": "long enough reason"}), COGNITO_CLAIMS
            )
        self.assertEqual(resp["statusCode"], 503)

    def test_internal_key_returns_403(self):
        resp = coordination_lambda._handle_components_reject(
            "comp-x", _event({"rejection_reason": "long enough reason"}), INTERNAL_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 403)

    def test_short_reason_returns_400(self):
        resp = coordination_lambda._handle_components_reject(
            "comp-x", _event({"rejection_reason": "short"}), COGNITO_CLAIMS
        )
        self.assertEqual(resp["statusCode"], 400)

    def test_missing_component_returns_404(self):
        fake = _fake_ddb_for_existing(None)
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_reject(
                "comp-missing",
                _event({"rejection_reason": "long enough reason here"}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 404)

    def test_non_proposed_returns_409(self):
        existing = {
            "component_id": {"S": "comp-x"},
            "lifecycle_status": {"S": "rejected"},
        }
        fake = _fake_ddb_for_existing(existing)
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_reject(
                "comp-x",
                _event({"rejection_reason": "already rejected earlier"}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 409)

    def test_happy_path_200_writes_reason_and_decider(self):
        fake = mock.MagicMock()
        fake.exceptions.ConditionalCheckFailedException = _TCE
        fake.update_item.return_value = {
            "Attributes": {
                "component_id": {"S": "comp-x"},
                "lifecycle_status": {"S": "rejected"},
                "rejection_reason": {"S": "out of scope for the registry"},
                "rejected_by": {"S": "lead@example.com"},
            }
        }
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake):
            resp = coordination_lambda._handle_components_reject(
                "comp-x",
                _event({"rejection_reason": "out of scope for the registry"}),
                COGNITO_CLAIMS,
            )
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "rejected")
        self.assertEqual(body["rejected_by"], "lead@example.com")
        self.assertEqual(body["rejection_reason"], "out of scope for the registry")

        kwargs = fake.update_item.call_args.kwargs
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":reason"]["S"],
            "out of scope for the registry",
        )
        self.assertIn("#ls = :proposed", kwargs["ConditionExpression"])


if __name__ == "__main__":
    unittest.main()
