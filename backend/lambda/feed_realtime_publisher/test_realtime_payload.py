#!/usr/bin/env python3
"""Unit tests for the real-time FeedPublisher payload contract (ENC-TSK-B67).

Covers AC-2 (source-agnostic actor attribution), AC-10 (event data model +
pre-rendered summary), AC-22 (absolute context-node scores), and AC-23
(payload ≤500 bytes, JSON-serializable). Stdlib-only — no AWS, no boto3.

Run: python3 -m pytest backend/lambda/feed_realtime_publisher/ -q
 or: python3 backend/lambda/feed_realtime_publisher/test_realtime_payload.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import realtime_payload as rp  # noqa: E402


class TestUuid7(unittest.TestCase):
    def test_format_and_version(self):
        u = rp.uuid7(1_700_000_000_000)
        self.assertRegex(u, r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    def test_timestamp_sortable(self):
        early = rp.uuid7(1_700_000_000_000)
        later = rp.uuid7(1_700_000_001_000)
        self.assertLess(early, later)

    def test_uniqueness(self):
        ids = {rp.uuid7(1_700_000_000_000) for _ in range(500)}
        self.assertEqual(len(ids), 500)


class TestCursor(unittest.TestCase):
    def test_monotonic_with_time(self):
        self.assertLess(rp.cursor_from_timestamp(1000), rp.cursor_from_timestamp(2000))

    def test_is_int(self):
        self.assertIsInstance(rp.cursor_from_timestamp(1234), int)


class TestActorAttribution(unittest.TestCase):
    def test_agent_via_session_id(self):
        actor_type, actor_id = rp.derive_actor({"active_agent_session_id": "ENC-SES-003"}, {})
        self.assertEqual(actor_type, "agent")
        self.assertEqual(actor_id, "ENC-SES-003")

    def test_human_via_user_initiated(self):
        actor_type, actor_id = rp.derive_actor(
            {"last_update_note": "[USER-INITIATED] closed", "initiated_by": "jreese"}, {}
        )
        self.assertEqual(actor_type, "human")
        self.assertEqual(actor_id, "jreese")

    def test_default_human(self):
        actor_type, actor_id = rp.derive_actor({"title": "x"}, {})
        self.assertEqual(actor_type, "human")
        self.assertEqual(actor_id, "io")

    def test_agent_via_write_source(self):
        actor_type, _ = rp.derive_actor({"write_source": {"provider": "ENC-SES-010"}}, {})
        self.assertEqual(actor_type, "agent")


class TestActionDerivation(unittest.TestCase):
    def test_insert_is_created(self):
        self.assertEqual(rp.derive_action("INSERT", {"status": "open"}, {}), "created")

    def test_remove_is_removed(self):
        self.assertEqual(rp.derive_action("REMOVE", {}, {"status": "open"}), "removed")

    def test_status_to_closed(self):
        self.assertEqual(
            rp.derive_action("MODIFY", {"status": "closed"}, {"status": "pr"}), "closed"
        )

    def test_status_changed(self):
        self.assertEqual(
            rp.derive_action("MODIFY", {"status": "in-progress"}, {"status": "open"}),
            "status_changed",
        )

    def test_worklog_appended(self):
        old = {"status": "open", "worklog": [1]}
        new = {"status": "open", "worklog": [1, 2]}
        self.assertEqual(rp.derive_action("MODIFY", new, old), "worklog_appended")

    def test_create_relationship(self):
        old = {"status": "open", "related_task_ids": []}
        new = {"status": "open", "related_task_ids": ["ENC-TSK-001"]}
        self.assertEqual(rp.derive_action("MODIFY", new, old), "create_relationship")

    def test_generic_update(self):
        self.assertEqual(
            rp.derive_action("MODIFY", {"status": "open", "title": "b"}, {"status": "open", "title": "a"}),
            "updated",
        )


class TestSummary(unittest.TestCase):
    def test_created_summary(self):
        s = rp.render_summary(
            "ENC-TSK-001", "task", "created", "agent", "ENC-SES-003",
            {"title": "Do the thing"}, {},
        )
        self.assertIn("created", s)
        self.assertIn("ENC-TSK-001", s)
        self.assertIn("Do the thing", s)

    def test_status_change_includes_both_states(self):
        s = rp.render_summary(
            "ENC-TSK-001", "task", "status_changed", "human", "io",
            {"title": "T", "status": "pr"}, {"status": "committed"},
        )
        self.assertIn("committed", s)
        self.assertIn("pr", s)


class TestContextNode(unittest.TestCase):
    def test_freshness_recent_is_high(self):
        now = 1_700_000_000_000
        self.assertGreater(rp.compute_freshness(now, now), 0.99)

    def test_freshness_decays(self):
        now = 1_700_000_000_000
        week_ago = now - 7 * 86_400_000
        self.assertAlmostEqual(rp.compute_freshness(week_ago, now), 0.5, places=2)

    def test_structural_importance_absolute_degree(self):
        none = rp.compute_structural_importance({"title": "x"})
        many = rp.compute_structural_importance(
            {"related_task_ids": ["a", "b"], "related_issue_ids": ["c"], "parent": "p", "components": ["x", "y"]}
        )
        self.assertEqual(none, 0.0)
        self.assertGreater(many, none)
        self.assertLessEqual(many, 1.0)

    def test_structural_importance_not_stub_half(self):
        # Must NOT be the v3 stubbed 0.5 seed-PPR value for an edge-less record.
        self.assertNotEqual(rp.compute_structural_importance({"title": "x"}), 0.5)

    def test_information_density_empty_is_zero(self):
        self.assertEqual(rp.compute_information_density({}), 0.0)

    def test_information_density_rich_text(self):
        rich = rp.compute_information_density(
            {"description": "The quick brown fox jumps over the lazy dog. " * 20}
        )
        self.assertGreater(rich, 0.0)
        self.assertLessEqual(rich, 1.0)

    def test_context_node_keys(self):
        cn = rp.compute_context_node({"title": "x", "access_frequency": 3}, 1_700_000_000_000, 1_700_000_000_000)
        self.assertEqual(
            set(cn.keys()),
            {"freshness_score", "structural_importance", "information_density", "access_frequency"},
        )
        self.assertEqual(cn["access_frequency"], 3)


class TestBuildPayload(unittest.TestCase):
    def _new_image(self):
        return {
            "record_id": "ENC-TSK-B67",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "PWA 2.0 Governance Cockpit",
            "status": "in-progress",
            "updated_at": "2026-06-28T10:00:00Z",
            "active_agent_session_id": "ENC-SES-003",
            "related_issue_ids": ["ENC-ISS-121", "ENC-ISS-138"],
        }

    def test_payload_has_exact_core_keys(self):
        p = rp.build_event_payload(
            event_name="MODIFY", new_image=self._new_image(), old_image={"status": "open"},
        )
        for key in ("eventId", "recordId", "record_type", "action", "actorType", "actorId", "summary", "cursor", "context_node"):
            self.assertIn(key, p)
        self.assertEqual(p["recordId"], "ENC-TSK-B67")
        self.assertEqual(p["actorType"], "agent")
        self.assertEqual(p["action"], "status_changed")

    def test_payload_json_serializable(self):
        import json

        p = rp.build_event_payload(event_name="INSERT", new_image=self._new_image(), old_image={})
        json.loads(json.dumps(p))

    def test_payload_under_500_bytes(self):
        p = rp.build_event_payload(event_name="INSERT", new_image=self._new_image(), old_image={})
        self.assertLessEqual(rp.payload_size_bytes(p), 500)

    def test_no_record_id_returns_none(self):
        self.assertIsNone(rp.build_event_payload(event_name="MODIFY", new_image={"title": "x"}, old_image={}))

    def test_channels_mapping(self):
        p = rp.build_event_payload(event_name="INSERT", new_image=self._new_image(), old_image={})
        chans = rp.channels_for_event(p)
        self.assertIn("/feed/updates", chans)
        self.assertIn("/records/ENC-TSK-B67", chans)
        self.assertIn("/projects/enceladus", chans)


class TestHandler(unittest.TestCase):
    def test_handler_dry_run_reports_no_failures(self):
        os.environ["DRY_RUN"] = "true"
        import importlib

        import lambda_function as lf

        importlib.reload(lf)
        event = {
            "Records": [
                {
                    "eventName": "INSERT",
                    "dynamodb": {
                        "SequenceNumber": "1",
                        "NewImage": {
                            "record_id": {"S": "ENC-TSK-B67"},
                            "record_type": {"S": "task"},
                            "project_id": {"S": "enceladus"},
                            "title": {"S": "Cockpit"},
                            "status": {"S": "open"},
                            "updated_at": {"S": "2026-06-28T10:00:00Z"},
                        },
                    },
                }
            ]
        }
        result = lf.handler(event, None)
        self.assertEqual(result, {"batchItemFailures": []})


if __name__ == "__main__":
    unittest.main(verbosity=2)
