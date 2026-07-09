"""ENC-TSK-J71 (ENC-FTR-121 Ph4): escalation.watch polling tests.

Covers the count-based opaque cursor (first poll full replay, incremental
polls return only unconsumed events, multi-escalation interleaving in a
merged at-sorted stream, stability on empty polls, malformed-cursor safe
replay), §11.2 event shape passthrough with guidance_note only on
denied_with_guidance, session scoping (the DDB filter targets
requested_by.session_id), the §5.9 last_activity_at heartbeat
(touch_session_activity conditional write + _idle_reference precedence), and
the agent-callable auth posture (no Cognito gate — internal-key claims work).
"""
import base64
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared_layer", "python"))
import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "coordination_lambda_j71",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
coordination_lambda = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = coordination_lambda
_SPEC.loader.exec_module(coordination_lambda)

import agent_id_alloc

INTERNAL_CLAIMS = {"auth_mode": "internal-key"}


def _event_entry(event_type, at, actor="ENC-SES-02F", guidance_note=None):
    entry = {"event_type": event_type, "at": at, "actor": actor}
    if guidance_note:
        entry["guidance_note"] = guidance_note
    return entry


def _escalation(escalation_id, status, events, session_id="ENC-SES-02F"):
    return {
        "project_id": "enceladus",
        "record_id": f"escalation#{escalation_id}",
        "item_id": escalation_id,
        "record_type": "escalation",
        "status": status,
        "mutation_type": "deploy_arc_change",
        "target_record_id": "ENC-TSK-J10",
        "requested_by": {"session_id": session_id},
        "events": events,
        "created_at": "2026-07-02T04:00:00Z",
        "updated_at": "2026-07-02T04:10:00Z",
    }


def _serialized(item):
    return {k: coordination_lambda._serialize(v) for k, v in item.items()}


def _cursor(counts):
    return base64.urlsafe_b64encode(json.dumps(counts).encode()).decode()


def _watch(escalations, params, touched=True):
    fake = mock.MagicMock()
    fake.query.return_value = {"Items": [_serialized(e) for e in escalations]}
    with mock.patch.object(coordination_lambda, "_get_ddb", return_value=fake), \
         mock.patch.object(coordination_lambda._agent_alloc, "touch_session_activity",
                           return_value=touched) as touch:
        resp = coordination_lambda._handle_escalation_watch(
            {"queryStringParameters": params}, INTERNAL_CLAIMS)
    return resp, fake, touch


class TestWatchCursor(unittest.TestCase):
    def test_first_poll_replays_all_events_and_returns_full_cursor(self):
        events = [
            _event_entry("requested", "2026-07-02T04:00:00Z"),
            _event_entry("approved", "2026-07-02T04:05:00Z", actor="cognito-sub"),
        ]
        resp, _, _ = _watch([_escalation("ENC-ESC-001", "approved", events)],
                            {"session_id": "ENC-SES-02F"})
        self.assertEqual(200, resp["statusCode"])
        body = json.loads(resp["body"])
        self.assertEqual(2, body["count"])
        self.assertEqual(["requested", "approved"],
                         [e["event_type"] for e in body["events"]])
        decoded = json.loads(base64.urlsafe_b64decode(body["next_cursor"]))
        self.assertEqual({"ENC-ESC-001": 2}, decoded)

    def test_incremental_poll_returns_only_unconsumed_events(self):
        events = [
            _event_entry("requested", "2026-07-02T04:00:00Z"),
            _event_entry("approved", "2026-07-02T04:05:00Z"),
            _event_entry("applying", "2026-07-02T04:05:30Z"),
            _event_entry("applied", "2026-07-02T04:05:30Z"),  # same second as applying
        ]
        resp, _, _ = _watch([_escalation("ENC-ESC-001", "applied", events)],
                            {"session_id": "ENC-SES-02F",
                             "since": _cursor({"ENC-ESC-001": 2})})
        body = json.loads(resp["body"])
        # Both same-second events delivered — the count cursor cannot drop them.
        self.assertEqual(["applying", "applied"],
                         [e["event_type"] for e in body["events"]])

    def test_empty_poll_returns_stable_cursor_and_no_events(self):
        events = [_event_entry("requested", "2026-07-02T04:00:00Z")]
        cursor = _cursor({"ENC-ESC-001": 1})
        resp, _, _ = _watch([_escalation("ENC-ESC-001", "requested", events)],
                            {"session_id": "ENC-SES-02F", "since": cursor})
        body = json.loads(resp["body"])
        self.assertEqual(0, body["count"])
        self.assertEqual(json.loads(base64.urlsafe_b64decode(cursor)),
                         json.loads(base64.urlsafe_b64decode(body["next_cursor"])))

    def test_multi_escalation_events_merge_sorted_by_time(self):
        first = _escalation("ENC-ESC-001", "applied", [
            _event_entry("requested", "2026-07-02T04:00:00Z"),
            _event_entry("applied", "2026-07-02T04:09:00Z"),
        ])
        second = _escalation("ENC-ESC-002", "denied_with_guidance", [
            _event_entry("requested", "2026-07-02T04:03:00Z"),
            _event_entry("denied_with_guidance", "2026-07-02T04:06:00Z",
                         guidance_note="Use a successor task."),
        ])
        resp, _, _ = _watch([first, second], {"session_id": "ENC-SES-02F"})
        body = json.loads(resp["body"])
        self.assertEqual(
            [("ENC-ESC-001", "requested"), ("ENC-ESC-002", "requested"),
             ("ENC-ESC-002", "denied_with_guidance"), ("ENC-ESC-001", "applied")],
            [(e["escalation_id"], e["event_type"]) for e in body["events"]])

    def test_malformed_cursor_replays_from_start(self):
        events = [_event_entry("requested", "2026-07-02T04:00:00Z")]
        resp, _, _ = _watch([_escalation("ENC-ESC-001", "requested", events)],
                            {"session_id": "ENC-SES-02F", "since": "!!!not-a-cursor!!!"})
        body = json.loads(resp["body"])
        self.assertEqual(1, body["count"])


class TestWatchSemantics(unittest.TestCase):
    def test_guidance_note_present_only_on_denied_with_guidance(self):
        events = [
            _event_entry("requested", "2026-07-02T04:00:00Z"),
            _event_entry("denied_with_guidance", "2026-07-02T04:06:00Z",
                         guidance_note="Fix the arc first."),
        ]
        resp, _, _ = _watch(
            [_escalation("ENC-ESC-001", "denied_with_guidance", events)],
            {"session_id": "ENC-SES-02F"})
        body = json.loads(resp["body"])
        requested, denied = body["events"]
        self.assertNotIn("guidance_note", requested)
        self.assertEqual("Fix the arc first.", denied["guidance_note"])

    def test_query_filters_to_the_calling_session(self):
        resp, fake, _ = _watch([], {"session_id": "ENC-SES-02F"})
        self.assertEqual(200, resp["statusCode"])
        kwargs = fake.query.call_args.kwargs
        self.assertEqual("requested_by.session_id = :sid", kwargs["FilterExpression"])
        self.assertEqual({"S": "ENC-SES-02F"},
                         kwargs["ExpressionAttributeValues"][":sid"])

    def test_missing_session_id_400(self):
        resp, fake, _ = _watch([], {})
        self.assertEqual(400, resp["statusCode"])
        fake.query.assert_not_called()

    def test_internal_key_claims_are_allowed(self):
        # The watch surface is the AGENT side of the loop — no Cognito gate.
        resp, _, _ = _watch([], {"session_id": "ENC-SES-02F"})
        self.assertEqual(200, resp["statusCode"])

    def test_poll_touches_session_and_reports_result(self):
        resp, _, touch = _watch([], {"session_id": "ENC-SES-02F"}, touched=True)
        touch.assert_called_once_with("ENC-SES-02F")
        self.assertTrue(json.loads(resp["body"])["session_touched"])

    def test_retired_session_reports_untouched_but_poll_succeeds(self):
        resp, _, _ = _watch([], {"session_id": "ENC-SES-0FF"}, touched=False)
        body = json.loads(resp["body"])
        self.assertEqual(200, resp["statusCode"])
        self.assertFalse(body["session_touched"])


class TestSessionActivity(unittest.TestCase):
    def test_touch_writes_last_activity_at_conditionally(self):
        fake = mock.MagicMock()
        with mock.patch.object(agent_id_alloc, "_get_ddb", return_value=fake):
            self.assertTrue(agent_id_alloc.touch_session_activity("ENC-SES-02F"))
        kwargs = fake.update_item.call_args.kwargs
        self.assertEqual("SET last_activity_at = :now", kwargs["UpdateExpression"])
        self.assertIn("#st = :allocated OR #st = :claimed",
                      kwargs["ConditionExpression"])

    def test_touch_returns_false_for_dead_session(self):
        from botocore.exceptions import ClientError
        fake = mock.MagicMock()
        fake.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        with mock.patch.object(agent_id_alloc, "_get_ddb", return_value=fake):
            self.assertFalse(agent_id_alloc.touch_session_activity("ENC-SES-0FF"))

    def test_touch_empty_session_id_is_noop_false(self):
        self.assertFalse(agent_id_alloc.touch_session_activity(""))

    def test_idle_reference_prefers_last_activity_at(self):
        item = {"created_at": "2026-07-01T00:00:00Z",
                "claimed_at": "2026-07-01T01:00:00Z",
                "last_activity_at": "2026-07-02T05:00:00Z"}
        self.assertEqual("2026-07-02T05:00:00Z", agent_id_alloc._idle_reference(item))

    def test_idle_reference_falls_back_to_lifecycle_timestamps(self):
        self.assertEqual(
            "2026-07-01T01:00:00Z",
            agent_id_alloc._idle_reference(
                {"created_at": "2026-07-01T00:00:00Z",
                 "claimed_at": "2026-07-01T01:00:00Z"}))
        self.assertEqual(
            "2026-07-01T00:00:00Z",
            agent_id_alloc._idle_reference({"created_at": "2026-07-01T00:00:00Z"}))


if __name__ == "__main__":
    unittest.main()
