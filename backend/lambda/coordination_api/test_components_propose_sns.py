"""Tests for SNS publish wiring in _handle_components_propose (ENC-TSK-E11).

Validates ENC-FTR-076 AC4-3 + AC4-5 surface contract:
- After a successful TransactWriteItems, _publish_component_proposed_event fires.
- Payload contains the agreed schema (event_type, component_id, project_id,
  proposing_agent_session_id, requested_minimum_transition_type, pwa_deep_link).
- When COMPONENT_EVENTS_TOPIC_ARN is empty the publish is skipped silently.
- SNS publish failures are logged but never raise, so the 201 response still
  reaches the caller (best-effort notification).
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


def _valid_body(**overrides):
    body = {
        "component_id": "comp-test-sns",
        "display_name": "Test SNS Proposal",
        "project_id": "enceladus",
        "source_paths": ["backend/lambda/foo/"],
        "description": "SNS publish wiring test",
        "requested_minimum_transition_type": "lambda_deploy",
        "proposing_agent_session_id": "agent-session-sns-1",
    }
    body.update(overrides)
    return body


def _event(body):
    return {
        "httpMethod": "POST",
        "path": "/api/v1/coordination/components/propose",
        "body": json.dumps(body),
    }


class _TCE(Exception):
    pass


class ComponentProposeSnsTests(unittest.TestCase):
    def setUp(self):
        self._flag = mock.patch.object(coordination_lambda, "ENABLE_COMPONENT_PROPOSAL", True)
        self._flag.start()
        self._topic = mock.patch.object(
            coordination_lambda,
            "COMPONENT_EVENTS_TOPIC_ARN",
            "arn:aws:sns:us-west-2:111122223333:enceladus-component-registry-events",
        )
        self._topic.start()

    def tearDown(self):
        self._topic.stop()
        self._flag.stop()

    def _ddb_ok(self):
        fake = mock.MagicMock()
        fake.exceptions.TransactionCanceledException = _TCE
        fake.transact_write_items.return_value = {}
        return fake

    def test_happy_path_publishes_with_expected_payload(self):
        fake_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=self._ddb_ok()), \
                mock.patch.object(coordination_lambda.boto3, "client", return_value=fake_sns) as mk_client:
            resp = coordination_lambda._handle_components_propose(_event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 201)
        mk_client.assert_called_once()
        self.assertEqual(mk_client.call_args.args[0], "sns")

        fake_sns.publish.assert_called_once()
        kwargs = fake_sns.publish.call_args.kwargs
        self.assertEqual(
            kwargs["TopicArn"],
            "arn:aws:sns:us-west-2:111122223333:enceladus-component-registry-events",
        )
        self.assertIn("comp-test-sns", kwargs["Subject"])
        payload = json.loads(kwargs["Message"])
        self.assertEqual(payload["event_type"], "component.proposed")
        self.assertEqual(payload["component_id"], "comp-test-sns")
        self.assertEqual(payload["project_id"], "enceladus")
        self.assertEqual(payload["proposing_agent_session_id"], "agent-session-sns-1")
        self.assertEqual(payload["requested_minimum_transition_type"], "lambda_deploy")
        self.assertIn("jreese.net/components", payload["pwa_deep_link"])

    def test_no_topic_arn_skips_publish_silently(self):
        with mock.patch.object(coordination_lambda, "COMPONENT_EVENTS_TOPIC_ARN", ""), \
                mock.patch.object(coordination_lambda, "_get_ddb", return_value=self._ddb_ok()), \
                mock.patch.object(coordination_lambda.boto3, "client") as mk_client:
            resp = coordination_lambda._handle_components_propose(_event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 201)
        mk_client.assert_not_called()

    def test_sns_failure_does_not_raise_or_change_response(self):
        fake_sns = mock.MagicMock()
        fake_sns.publish.side_effect = RuntimeError("SNS down")
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=self._ddb_ok()), \
                mock.patch.object(coordination_lambda.boto3, "client", return_value=fake_sns):
            resp = coordination_lambda._handle_components_propose(_event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 201)
        body = json.loads(resp["body"])
        self.assertEqual(body["lifecycle_status"], "proposed")
        fake_sns.publish.assert_called_once()

    def test_publish_skipped_when_ddb_transaction_fails(self):
        fake_ddb = mock.MagicMock()
        fake_ddb.exceptions.TransactionCanceledException = _TCE
        fake_ddb.transact_write_items.side_effect = _TCE()
        fake_ddb.transact_write_items.side_effect.response = {
            "CancellationReasons": [{"Code": "ConditionalCheckFailed"}, {"Code": "None"}, {"Code": "None"}]
        }
        fake_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake_ddb), \
                mock.patch.object(coordination_lambda.boto3, "client", return_value=fake_sns):
            resp = coordination_lambda._handle_components_propose(_event(_valid_body()), {})

        self.assertEqual(resp["statusCode"], 409)
        fake_sns.publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
