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
            leaves = decide._open_leaf_tasks()
        self.assertEqual(leaves, [])
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


if __name__ == "__main__":
    unittest.main()
