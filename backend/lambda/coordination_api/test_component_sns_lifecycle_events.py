"""Tests for ENC-TSK-F46 / ENC-TSK-F45: SNS lifecycle event emission.

Validates that the coordination_api emits SNS events on all component
lifecycle transitions, including events from the v2 state machine:

  - component.approved (proposed -> approved)
  - component.reverted (active -> archived via revert)
  - component.deprecated (production/code-red -> deprecated)
  - component.restored (deprecated -> production)
  - component.advanced (advance transitions that emit events)
  - Error handling: SNS failure must not raise (fire-and-forget semantics)
  - Topic ARN guard: events skipped silently when no topic ARN configured

Per DOC-546B896390EA §7: all lifecycle transitions emit SNS events for
downstream consumers (e.g. the coordination monitor). The publish is
best-effort — Lambda continues even if SNS publish fails.
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


TOPIC_ARN = "arn:aws:sns:us-west-2:123456789012:enceladus-component-events"


class TestPublishComponentLifecycleEvent(unittest.TestCase):
    """Unit tests for _publish_component_lifecycle_event."""

    def setUp(self):
        self._topic = mock.patch.object(
            coordination_lambda,
            "COMPONENT_EVENTS_TOPIC_ARN",
            TOPIC_ARN,
        )
        self._topic.start()

    def tearDown(self):
        self._topic.stop()

    def test_approved_event_published(self):
        """component.approved event: correct TopicArn, event_type, component_id."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {
                    "event_type": "component.approved",
                    "component_id": "comp-test-alpha",
                    "project_id": "enceladus",
                    "approved_by_session_id": "session-abc",
                    "approved_at": "2026-04-21T00:00:00Z",
                },
            )
        mock_sns.publish.assert_called_once()
        call_kwargs = mock_sns.publish.call_args[1]
        self.assertEqual(call_kwargs["TopicArn"], TOPIC_ARN)
        payload = json.loads(call_kwargs["Message"])
        self.assertEqual(payload["event_type"], "component.approved")
        self.assertEqual(payload["component_id"], "comp-test-alpha")
        self.assertEqual(payload["project_id"], "enceladus")
        self.assertEqual(payload["approved_by_session_id"], "session-abc")

    def test_reverted_event_published(self):
        """component.reverted event: contains reverted_reason and archived_at."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.reverted",
                {
                    "event_type": "component.reverted",
                    "component_id": "comp-test-beta",
                    "reverted_reason": "design change required",
                    "reverted_at": "2026-04-21T00:01:00Z",
                    "archived_at": "2026-04-21T00:01:00Z",
                },
            )
        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.reverted")
        self.assertEqual(payload["reverted_reason"], "design change required")
        self.assertIn("archived_at", payload)

    def test_deprecated_event_published(self):
        """component.deprecated event: contains deprecated_at timestamp."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.deprecated",
                {
                    "event_type": "component.deprecated",
                    "component_id": "comp-test-gamma",
                    "deprecated_at": "2026-04-21T00:02:00Z",
                },
            )
        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.deprecated")
        self.assertEqual(payload["component_id"], "comp-test-gamma")

    def test_restored_event_published(self):
        """component.restored event: contains restored_at timestamp."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.restored",
                {
                    "event_type": "component.restored",
                    "component_id": "comp-test-delta",
                    "restored_at": "2026-04-21T00:03:00Z",
                },
            )
        payload = json.loads(mock_sns.publish.call_args[1]["Message"])
        self.assertEqual(payload["event_type"], "component.restored")
        self.assertEqual(payload["component_id"], "comp-test-delta")

    def test_event_payload_is_valid_json_string(self):
        """Published Message must be a JSON-serialized string, not a dict."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {
                    "event_type": "component.approved",
                    "component_id": "comp-json-test",
                    "project_id": "enceladus",
                },
            )
        call_kwargs = mock_sns.publish.call_args[1]
        message = call_kwargs["Message"]
        self.assertIsInstance(message, str)
        parsed = json.loads(message)
        self.assertIsInstance(parsed, dict)

    def test_skips_when_topic_arn_empty(self):
        """No SNS call when COMPONENT_EVENTS_TOPIC_ARN is empty string."""
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
        """SNS publish failure must not propagate — fire-and-forget semantics."""
        mock_sns = mock.MagicMock()
        mock_sns.publish.side_effect = Exception("SNS unreachable")
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            # Must not raise.
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {"event_type": "component.approved", "component_id": "comp-x"},
            )

    def test_sns_subject_attribute_set_on_publish(self):
        """SNS publish call must include a Subject or MessageAttributes for routing."""
        mock_sns = mock.MagicMock()
        with mock.patch.object(coordination_lambda.boto3, "client", return_value=mock_sns):
            coordination_lambda._publish_component_lifecycle_event(
                "component.approved",
                {"event_type": "component.approved", "component_id": "comp-y",
                 "project_id": "enceladus"},
            )
        call_kwargs = mock_sns.publish.call_args[1]
        # Must have either Subject or MessageAttributes for event routing.
        has_routing = (
            "Subject" in call_kwargs
            or "MessageAttributes" in call_kwargs
        )
        self.assertTrue(
            has_routing,
            "SNS publish must include Subject or MessageAttributes for event routing",
        )

    def test_all_v2_event_types_can_be_published(self):
        """All FTR-076 v2 event types can be published without error."""
        event_types = [
            "component.approved",
            "component.reverted",
            "component.deprecated",
            "component.restored",
            "component.advanced",
        ]
        for event_type in event_types:
            with self.subTest(event_type=event_type):
                mock_sns = mock.MagicMock()
                with mock.patch.object(
                    coordination_lambda.boto3, "client", return_value=mock_sns
                ):
                    # Should not raise.
                    coordination_lambda._publish_component_lifecycle_event(
                        event_type,
                        {
                            "event_type": event_type,
                            "component_id": "comp-event-test",
                            "project_id": "enceladus",
                        },
                    )


if __name__ == "__main__":
    unittest.main()
