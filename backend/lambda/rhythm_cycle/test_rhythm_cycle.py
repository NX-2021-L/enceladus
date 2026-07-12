"""Unit tests for rhythm_cycle (ENC-PLN-068)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import artifact_store  # noqa: E402
import config  # noqa: E402
import lambda_function  # noqa: E402
from legacy_schedules import LEGACY_SCHEDULE_INVENTORY  # noqa: E402


class ArtifactKeyTests(unittest.TestCase):
    def test_artifact_key_format(self):
        from datetime import datetime, timezone

        with mock.patch.object(config, "S3_ENV_PREFIX", "gamma"):
            with mock.patch.object(config, "S3_PREFIX", "rhythm-cycle"):
                key = artifact_store.artifact_key("sense", datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc))
        self.assertIn("gamma/rhythm-cycle/sense/2026/07/02/120000.json", key)

    def test_latest_key(self):
        with mock.patch.object(config, "S3_ENV_PREFIX", ""):
            with mock.patch.object(config, "S3_PREFIX", "rhythm-cycle"):
                self.assertEqual(artifact_store.latest_key("decide"), "rhythm-cycle/decide/latest.json")


class HandlerTests(unittest.TestCase):
    @mock.patch("lambda_function.run_beat")
    def test_handler_routes_tier(self, run_beat):
        run_beat.return_value = {"ok": True}
        resp = lambda_function.lambda_handler({"tier": "sense"}, None)
        self.assertEqual(resp["statusCode"], 200)
        run_beat.assert_called_once_with("sense")

    def test_legacy_inventory_action(self):
        resp = lambda_function.lambda_handler({"action": "legacy_inventory"}, None)
        self.assertIn("legacy_jobs", resp)
        self.assertGreaterEqual(len(resp["legacy_jobs"]), 3)


class LegacyInventoryTests(unittest.TestCase):
    def test_inventory_covers_embedding_jobs(self):
        tiers = {row["rhythm_tier"] for row in LEGACY_SCHEDULE_INVENTORY}
        self.assertIn("heavy_integrate", tiers)


class SenseConstraintTests(unittest.TestCase):
    @mock.patch("tiers.sense.write_artifact")
    @mock.patch("tiers.sense._open_task_count", return_value=5)
    @mock.patch("tiers.sense._checkout_census", return_value=[])
    @mock.patch("tiers.sense._session_census", return_value=[])
    @mock.patch("tiers.sense.read_latest", return_value={"open_task_count": 3})
    def test_sense_snapshot_shape(
        self, read_latest, _sess, _checkout, _open, write_artifact
    ):
        from tiers.sense import run_sense

        write_artifact.return_value = {"timestamped_key": "k", "latest_key": "l", "bytes": "10"}
        read_latest.return_value = {"open_task_count": 3}
        snap = run_sense()
        self.assertFalse(snap["constraints"]["embeddings"])
        self.assertEqual(snap["open_task_delta"], 2)


class TrackerUrlShapeTests(unittest.TestCase):
    """ENC-TSK-N28: tracker reads must use /records?project_id=, and the
    dispatch-plan URL must not double the /api/v1 prefix."""

    @mock.patch("tiers.sense.get_json", return_value={"total": 7})
    def test_sense_open_task_count_url_shape(self, get_json):
        import tiers.sense as sense

        with mock.patch.object(sense, "TRACKER_API_BASE", "https://x/api/v1/tracker"):
            count = sense._open_task_count()
        self.assertEqual(count, 7)
        url, params = get_json.call_args[0]
        self.assertEqual(url, "https://x/api/v1/tracker/records")
        self.assertEqual(params["project_id"], sense.PROJECT_ID)

    @mock.patch("tiers.decide.get_json", return_value={"records": []})
    def test_decide_open_leaf_tasks_url_shape(self, get_json):
        import tiers.decide as decide

        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"):
            backlog = decide._open_leaf_tasks()
        self.assertEqual(backlog["leaves"], [])
        self.assertEqual(backlog["page_count"], 1)
        self.assertIsNone(backlog["cursor_terminus"])
        self.assertFalse(backlog["truncated"])
        url, params = get_json.call_args[0]
        self.assertEqual(url, "https://x/api/v1/tracker/records")
        self.assertEqual(params["project_id"], decide.PROJECT_ID)

    @mock.patch("tiers.decide.post_json", return_value={"dispatches": []})
    def test_decide_dispatch_plan_no_double_prefix(self, post_json):
        import tiers.decide as decide

        with mock.patch.object(decide, "COORDINATION_API_BASE", "https://x/api/v1"):
            decide._dispatch_plan_dry_run({"beat_type": "sense"})
        url = post_json.call_args[0][0]
        self.assertEqual(url, "https://x/api/v1/coordination/dispatch-plan/dry-run")
        self.assertNotIn("/api/v1/api/v1", url)


class DecideCursorPaginationTests(unittest.TestCase):
    """ENC-TSK-N20 / BRD DOC-44230223DD1C §4.4 (C4): cursor-exhausted
    paginated backlog read replacing the single-page + orphan-flag heuristic
    (ENC-ISS-542)."""

    def test_pagination_exhaustion_accumulates_across_pages(self):
        import tiers.decide as decide

        responses = [
            {"records": [{"item_id": "ENC-TSK-A1"}, {"item_id": "ENC-TSK-A2"}], "next_cursor": "cur-1"},
            {"records": [{"item_id": "ENC-TSK-A3"}], "next_cursor": "cur-2"},
            {"records": [{"item_id": "ENC-TSK-A4"}]},  # no next_cursor -> natural exhaustion
        ]
        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", side_effect=responses
        ) as get_json:
            backlog = decide._open_leaf_tasks()

        self.assertEqual(len(backlog["leaves"]), 4)
        self.assertEqual(backlog["page_count"], 3)
        self.assertIsNone(backlog["cursor_terminus"])
        self.assertFalse(backlog["truncated"])
        # Second and third calls must forward the cursor from the prior response.
        self.assertEqual(get_json.call_args_list[1][0][1]["next_cursor"], "cur-1")
        self.assertEqual(get_json.call_args_list[2][0][1]["next_cursor"], "cur-2")
        # First call must not carry a next_cursor param at all.
        self.assertNotIn("next_cursor", get_json.call_args_list[0][0][1])

    def test_leaf_filter_is_explicit_parent_absence_not_orphan_flag(self):
        import tiers.decide as decide

        records = [
            {"item_id": "ENC-TSK-B1"},  # no parent key at all -> leaf
            {"item_id": "ENC-TSK-B2", "parent": ""},  # empty parent -> leaf
            {"item_id": "ENC-TSK-B3", "parent": "ENC-TSK-PARENT"},  # has parent -> not a leaf
            {"item_id": "ENC-TSK-B4", "orphan": False},  # orphan flag false but no parent -> leaf
            {"item_id": "ENC-TSK-B5", "orphan": True, "parent": "ENC-TSK-PARENT2"},  # orphan flag true but has parent -> not a leaf
        ]
        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", return_value={"records": records}
        ):
            backlog = decide._open_leaf_tasks()

        leaf_ids = {r["item_id"] for r in backlog["leaves"]}
        self.assertEqual(leaf_ids, {"ENC-TSK-B1", "ENC-TSK-B2", "ENC-TSK-B4"})

    def test_max_pages_guard_truncates_and_marks_artifact(self):
        import tiers.decide as decide

        def _always_more(url, params):
            # Every page reports a record and a next_cursor that never empties,
            # simulating a pathological/never-terminating tracker response.
            return {"records": [{"item_id": "ENC-TSK-C1"}], "next_cursor": "cur-forever"}

        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", side_effect=_always_more
        ) as get_json:
            backlog = decide._open_leaf_tasks()

        self.assertEqual(get_json.call_count, decide._MAX_PAGES)
        self.assertEqual(backlog["page_count"], decide._MAX_PAGES)
        self.assertTrue(backlog["truncated"])
        self.assertEqual(backlog["cursor_terminus"], "cur-forever")
        # Never loops unbounded — accumulates exactly one leaf per page.
        self.assertEqual(len(backlog["leaves"]), decide._MAX_PAGES)

    @mock.patch("tiers.decide._dispatch_plan_dry_run", return_value={"dispatches": []})
    @mock.patch("tiers.decide.write_artifact")
    @mock.patch("tiers.decide.read_latest", return_value={})
    @mock.patch("tiers.decide.publish_lyapunov")
    @mock.patch("tiers.decide._notify_beat")
    def test_run_decide_artifact_records_pagination_fields(
        self, _notify, _publish, read_latest, write_artifact, _dispatch
    ):
        import tiers.decide as decide

        write_artifact.return_value = {"timestamped_key": "k", "latest_key": "l", "bytes": "1"}
        read_latest.return_value = {}
        backlog = {
            "leaves": [{"item_id": "ENC-TSK-D1"}],
            "page_count": 2,
            "cursor_terminus": None,
            "truncated": False,
        }
        with mock.patch.object(decide, "_open_leaf_tasks", return_value=backlog):
            artifact = decide.run_decide()

        self.assertEqual(artifact["backlog_open_leaves"], 1)
        self.assertEqual(artifact["backlog_page_count"], 2)
        self.assertIsNone(artifact["backlog_cursor_terminus"])
        self.assertFalse(artifact["backlog_pagination_truncated"])


if __name__ == "__main__":
    unittest.main()
