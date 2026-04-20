"""Tests for ENC-TSK-F45: SNS lifecycle events on component approve/revert/deprecate/restore."""
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


class TestPublishComponentLifecycleEvent(unittest.TestCase):
    """Unit tests for _publish_component_lifecycle_event."""

    def setUp(self):
        self._topic = mock.patch.object(
            coordination_lambda,
            "COMPONENT_EVENTS_TOPIC_ARN",
            "arn:aws:sns:us-west-2:123:topic",
        )
        self._topic.start()

    def tearDown(self):
        self._topic.stop()

    def test_approved_event_published(self):
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {
                    "event_type": "component.approved",
                    "component_id": "comp-test-alpha",
                    "project_id": "enceladus",
                    "approved_by_session_id": "session-abc",
                    "approved_at": "2026-04-20T19:00:00Z",
                },
            )

        mock_sns.publish.assert_called_once()
        call_kwargs = mock_sns.publish.call_args[1]
        self.assertEqual(call_kwargs["TopicArn"], "arn:aws:sns:us-west-2:123:topic")
        payload = json.loads(call_kwargs["Message"])
        self.assertEqual(payload["event_type"], "component.approved")
        self.assertEqual(payload["component_id"], "comp-test-alpha")
        self.assertEqual(payload["project_id"], "enceladus")
        self.assertEqual(payload["approved_by_session_id"], "session-abc")

    def test_reverted_event_published(self):
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.reverted",
                {
                    "event_type": "component.reverted",
                    "component_id": "comp-test-beta",
                    "reverted_reason": "design change required",
                    "reverted_at": "2026-04-20T19:01:00Z",
                    "archived_at": "2026-04-20T19:01:00Z",
                },
            )

        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.reverted")
        self.assertEqual(payload["reverted_reason"], "design change required")
        self.assertIn("archived_at", payload)

    def test_deprecated_event_published(self):
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.deprecated",
                {
                    "event_type": "component.deprecated",
                    "component_id": "comp-test-gamma",
                    "deprecated_at": "2026-04-20T19:02:00Z",
                },
            )

        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.deprecated")
        self.assertEqual(payload["component_id"], "comp-test-gamma")

    def test_restored_event_published(self):
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.restored",
                {
                    "event_type": "component.restored",
                    "component_id": "comp-test-delta",
                    "restored_at": "2026-04-20T19:03:00Z",
                },
            )

        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.restored")

    def test_skips_when_topic_arn_empty(self):
        self._topic.stop()
        with mock.patch.object(coordination_lambda, "COMPONENT_EVENTS_TOPIC_ARN", ""):
            with mock.patch.object(coordination_lambda.boto3, "client") as mock_boto:
                coordination_lambda._publish_component_lifecycle_event(
                    "component.approved",
                    {"event_type": "component.approved", "component_id": "comp-x"},
                )
                mock_boto.assert_not_called()
        self._topic.start()

    def test_sns_failure_does_not_raise(self):
        mock_sns = mock.MagicMock()
        mock_sns.publish.side_effect = Exception("SNS unreachable")
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            # Should not raise
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {"event_type": "component.approved", "component_id": "comp-x"},
            )


if __name__ == "__main__":
    unittest.main()
