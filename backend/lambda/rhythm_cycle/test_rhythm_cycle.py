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


class RunBeatIdentityResolutionTests(unittest.TestCase):
    """ENC-TSK-N21 / BRD §4.3: every beat attempts identity resolution (the
    live-validation signal for this task), regardless of tier or outcome."""

    @mock.patch("lambda_function.publish_beat_metrics")
    @mock.patch("lambda_function.read_latest", return_value={"ok": True})
    @mock.patch("lambda_function.TIER_HANDLERS", {"sense": lambda: {"bytes": 1}})
    @mock.patch("lambda_function.resolve_identity")
    def test_resolve_identity_called_and_logged_for_every_beat(
        self, resolve_identity, _read_latest, _publish
    ):
        resolve_identity.return_value = {"session_id": "ENC-SES-099", "degraded": False}
        with self.assertLogs(level="INFO") as logs:
            lambda_function.run_beat("sense")
        resolve_identity.assert_called_once()
        self.assertTrue(any("identity resolved" in line for line in logs.output))

    @mock.patch("lambda_function.publish_beat_metrics")
    @mock.patch("lambda_function.read_latest", return_value={"ok": True})
    @mock.patch("lambda_function.TIER_HANDLERS", {"sense": lambda: {"bytes": 1}})
    @mock.patch("lambda_function.resolve_identity")
    def test_degraded_identity_logs_warning_but_beat_still_runs(
        self, resolve_identity, _read_latest, _publish
    ):
        resolve_identity.return_value = {"degraded": True, "reason": "RHYTHM_AGENT_TYPE_ID unset"}
        with self.assertLogs(level="WARNING") as logs:
            result = lambda_function.run_beat("sense")
        self.assertTrue(any("degraded" in line for line in logs.output))
        self.assertEqual(result["bytes"], 1)


class LegacyInventoryTests(unittest.TestCase):
    def test_inventory_covers_embedding_jobs(self):
        tiers = {row["rhythm_tier"] for row in LEGACY_SCHEDULE_INVENTORY}
        self.assertIn("heavy_integrate", tiers)


class SenseConstraintTests(unittest.TestCase):
    @mock.patch("tiers.sense.write_artifact")
    @mock.patch(
        "tiers.sense._open_task_count",
        return_value={"count": 5, "truncated": False, "page_count": 1, "cursor_terminus": None},
    )
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
        self.assertEqual(snap["open_task_count"], 5)
        self.assertFalse(snap["open_task_count_truncated"])
        self.assertFalse(snap["open_count_truncated"])

    @mock.patch("tiers.sense.write_artifact")
    @mock.patch(
        "tiers.sense._open_task_count",
        return_value={"count": 10000, "truncated": True, "page_count": 50, "cursor_terminus": "c50"},
    )
    @mock.patch("tiers.sense._checkout_census", return_value=[])
    @mock.patch("tiers.sense._session_census", return_value=[])
    @mock.patch("tiers.sense.read_latest", return_value={"open_task_count": 0})
    def test_sense_snapshot_marks_truncated_count_as_floor(
        self, _read_latest, _sess, _checkout, _open, write_artifact
    ):
        from tiers.sense import run_sense

        write_artifact.return_value = {"timestamped_key": "k", "latest_key": "l", "bytes": "10"}
        snap = run_sense()
        self.assertTrue(snap["open_task_count_truncated"])
        self.assertTrue(snap["open_count_truncated"])


class TrackerUrlShapeTests(unittest.TestCase):
    """ENC-ISS-553 (supersedes ENC-TSK-N28): N28's /records?project_id=...
    shape (#1016) live-probed a 200 response but never checked the payload —
    tracker_mutation's _RE_PROJECT regex matches the literal "records"
    segment as {projectId}, so it silently queried a nonexistent project and
    always returned {"records": [], "count": 0}. The real route (confirmed
    live against gamma) is {TRACKER_API_BASE}/{PROJECT_ID} with query param
    "type" (the handler reads "type", not "record_type"). The dispatch-plan
    URL must not double the /api/v1 prefix."""

    @mock.patch("tiers.sense.get_json", return_value={"count": 7, "count_truncated": False})
    def test_sense_open_task_count_url_shape(self, get_json):
        import tiers.sense as sense

        with mock.patch.object(sense, "TRACKER_API_BASE", "https://x/api/v1/tracker"):
            result = sense._open_task_count()
        self.assertEqual(result["count"], 7)
        self.assertEqual(result["page_count"], 1)
        self.assertFalse(result["truncated"])
        self.assertIsNone(result["cursor_terminus"])
        url, params = get_json.call_args[0]
        self.assertEqual(url, f"https://x/api/v1/tracker/{sense.PROJECT_ID}")
        self.assertEqual(params["type"], "task")
        self.assertEqual(params["status"], "open")
        self.assertEqual(params["mode"], "census")
        self.assertEqual(params["page_size"], 100)
        self.assertNotIn("record_type", params)
        self.assertNotIn("project_id", params)

    def test_sense_open_task_count_follows_cursor_to_exhaustion(self):
        """ENC-ISS-557: sense's open task count now comes from a single
        `mode=census` call -- the tracker route performs its own
        server-side walk and hands back the true total in one round trip,
        rather than sense plateauing at one page's "count" or paginating
        itself via next_cursor."""
        import tiers.sense as sense

        census = {"count": 443, "count_truncated": False, "exhausted": True}
        with mock.patch.object(sense, "TRACKER_API_BASE", "https://x/api/v1/tracker"):
            with mock.patch.object(sense, "get_json", return_value=census) as get_json:
                result = sense._open_task_count()
        self.assertEqual(result["count"], 443)
        self.assertEqual(result["page_count"], 1)
        self.assertFalse(result["truncated"])
        self.assertIsNone(result["cursor_terminus"])
        self.assertEqual(get_json.call_count, 1)

    def test_sense_open_task_count_marks_truncated_at_max_pages(self):
        """A census response with count_truncated=True means the tracker's
        own server-side walk hit its budget -- count is a floor, not exact."""
        import tiers.sense as sense

        census = {"count": 200, "count_truncated": True}
        with mock.patch.object(sense, "TRACKER_API_BASE", "https://x/api/v1/tracker"):
            with mock.patch.object(sense, "get_json", return_value=census) as get_json:
                result = sense._open_task_count()
        self.assertEqual(result["count"], 200)
        self.assertEqual(result["page_count"], 1)
        self.assertTrue(result["truncated"])
        self.assertIsNone(result["cursor_terminus"])
        self.assertEqual(get_json.call_count, 1)

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
        self.assertEqual(url, f"https://x/api/v1/tracker/{decide.PROJECT_ID}")
        self.assertEqual(params["type"], "task")
        self.assertEqual(params["status"], "open")
        self.assertEqual(params["mode"], "census")
        self.assertNotIn("record_type", params)
        self.assertNotIn("project_id", params)

    @mock.patch("tiers.decide.post_json", return_value={"dispatches": []})
    def test_decide_dispatch_plan_no_double_prefix(self, post_json):
        import tiers.decide as decide

        with mock.patch.object(decide, "COORDINATION_API_BASE", "https://x/api/v1"):
            decide._dispatch_plan_dry_run({"beat_type": "sense"})
        url = post_json.call_args[0][0]
        self.assertEqual(url, "https://x/api/v1/coordination/dispatch-plan/dry-run")
        self.assertNotIn("/api/v1/api/v1", url)


class DecideEscalationIdentityTests(unittest.TestCase):
    """ENC-TSK-N21 / BRD §4.3: escalation writes must carry the rhythm's
    resolved governed identity (session_id + sci) instead of the old
    hardcoded requested_by_session="rhythm-decide-beat" pseudo-identity."""

    @mock.patch("tiers.decide.post_json", return_value={"escalation_id": "ENC-ESC-1"})
    @mock.patch("tiers.decide.resolve_identity")
    def test_escalation_carries_minted_identity_and_sci(self, resolve_identity, post_json):
        import tiers.decide as decide

        resolve_identity.return_value = {
            "session_id": "ENC-SES-099",
            "agent_type_id": "ENC-AGT-00C",
            "sci": "SCI-abc123",
            "degraded": False,
        }
        decide._create_escalation("ENC-TSK-X99", "some proposal")

        _, body = post_json.call_args[0]
        self.assertEqual(body["requested_by_session"], "ENC-SES-099")
        self.assertEqual(body["requested_by"]["session_id"], "ENC-SES-099")
        self.assertEqual(body["requested_by"]["agent_type_id"], "ENC-AGT-00C")
        self.assertTrue(body["requested_by"]["sci_present"])
        self.assertEqual(body["sci"], "SCI-abc123")
        self.assertNotEqual(body["requested_by_session"], "rhythm-decide-beat")

    @mock.patch("tiers.decide.post_json", return_value={"escalation_id": "ENC-ESC-2"})
    @mock.patch("tiers.decide.resolve_identity")
    def test_escalation_falls_back_to_pre_n21_identity_when_degraded(self, resolve_identity, post_json):
        import tiers.decide as decide

        resolve_identity.return_value = {
            "session_id": "",
            "agent_type_id": "",
            "sci": "",
            "degraded": True,
            "reason": "RHYTHM_AGENT_TYPE_ID unset",
        }
        decide._create_escalation("ENC-TSK-X99", "some proposal")

        _, body = post_json.call_args[0]
        self.assertEqual(body["requested_by_session"], "rhythm-decide-beat")
        self.assertEqual(body["requested_by"]["session_id"], "rhythm-decide-beat")
        self.assertFalse(body["requested_by"]["sci_present"])
        self.assertNotIn("sci", body)


class DecideEscalationSchemaTests(unittest.TestCase):
    """ENC-TSK-N29 / BRD §4.3: tracker_mutation._handle_escalation_request
    (the real POST /{project}/escalation handler) fails-closed 400 on any
    body that isn't {payload: dict, justification: str, target_record_id,
    mutation_type, requested_by...}. The prior body sent a bare 'summary'
    string and no 'payload' at all — every beat-originated escalation was
    rejected before reaching io's queue. These assertions mirror the
    handler's own validation order (tracker_mutation/lambda_function.py
    _handle_escalation_request + _validate_deploy_arc_change_payload) without
    importing that lambda directly.
    """

    # Mirrors backend/lambda/tracker_mutation/transition_type_matrix.py
    # STRICTNESS_RANK keys (VALID_TRANSITION_TYPES) as of ENC-TSK-N29.
    _VALID_TRANSITION_TYPES = {
        "github_pr_deploy",
        "lambda_deploy",
        "web_deploy",
        "code_only",
        "no_code",
    }

    @mock.patch("tiers.decide.post_json", return_value={"escalation_id": "ENC-ESC-3"})
    @mock.patch("tiers.decide.resolve_identity")
    def test_escalation_body_matches_handler_schema(self, resolve_identity, post_json):
        import tiers.decide as decide

        resolve_identity.return_value = {
            "session_id": "ENC-SES-099",
            "agent_type_id": "ENC-AGT-00C",
            "sci": "SCI-abc123",
            "degraded": False,
        }
        decide._create_escalation("ENC-TSK-X99", "proposal needs io review")

        _, body = post_json.call_args[0]

        # _handle_escalation_request: target_record_id + mutation_type required.
        self.assertEqual(body["target_record_id"], "ENC-TSK-X99")
        self.assertIn(body["mutation_type"], {"deploy_arc_change", "direct_state_override"})

        # payload must be a non-empty dict (bare 'summary' string is rejected).
        self.assertIsInstance(body.get("payload"), dict)
        self.assertTrue(body["payload"])

        # justification must be a non-empty string.
        self.assertIsInstance(body.get("justification"), str)
        self.assertTrue(body["justification"].strip())

        # mutation_type='deploy_arc_change' additionally requires
        # payload.new_deploy_arc_type in VALID_TRANSITION_TYPES.
        if body["mutation_type"] == "deploy_arc_change":
            new_arc = body["payload"].get("new_deploy_arc_type")
            self.assertIn(new_arc, self._VALID_TRANSITION_TYPES)

        # N21 identity/sci fields must survive the schema realignment.
        self.assertEqual(body["requested_by"]["session_id"], "ENC-SES-099")
        self.assertTrue(body["requested_by"]["sci_present"])
        self.assertEqual(body["sci"], "SCI-abc123")


class DecideCursorPaginationTests(unittest.TestCase):
    """ENC-TSK-N20 / BRD DOC-44230223DD1C §4.4 (C4): census-backed backlog
    read (ENC-PLN-093 O5.3) replacing the single-page + orphan-flag
    heuristic (ENC-ISS-542) and, later, the cursor-exhausted pagination
    walk."""

    def test_open_leaf_tasks_inline_census_returns_ids_in_one_call(self):
        """Small backlog: census inlines every id -- one call, no page walk."""
        import tiers.decide as decide

        ids = [f"ENC-TSK-L{i}" for i in range(500)]
        census = {"count": 500, "count_truncated": False, "ids_inline_cap": 500, "ids": ids}
        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", return_value=census
        ) as get_json:
            backlog = decide._open_leaf_tasks()

        self.assertEqual(backlog["leaves"], ids)
        self.assertEqual(backlog["page_count"], 1)
        self.assertIsNone(backlog["cursor_terminus"])
        self.assertFalse(backlog["truncated"])
        self.assertEqual(get_json.call_count, 1)

    def test_open_leaf_tasks_paged_census_walks_page_cursors(self):
        """Backlog over the inline cap: census has no inline ids, only a
        per-page cursor list -- each page's cursor is replayed against the
        plain (non-census) route to pull that page's records."""
        import tiers.decide as decide

        inline_ids = [f"ENC-TSK-L{i}" for i in range(500)]
        extra_id = "ENC-TSK-L500"
        census = {
            "count": 501,
            "count_truncated": False,
            "ids_inline_cap": 500,
            "pages": [{"cursor": None, "n": 300}, {"cursor": "c1", "n": 201}],
        }
        page_responses = [
            {"records": [{"item_id": i} for i in inline_ids[:300]]},
            {"records": [{"item_id": i} for i in inline_ids[300:]] + [{"item_id": extra_id}]},
        ]
        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", side_effect=[census, *page_responses]
        ) as get_json:
            backlog = decide._open_leaf_tasks()

        # The paged id set covers the same shared rows as the inline case,
        # plus the one extra record only reachable via the second page.
        self.assertEqual(set(backlog["leaves"]) & set(inline_ids), set(inline_ids))
        self.assertIn(extra_id, backlog["leaves"])
        self.assertEqual(backlog["page_count"], 2)
        self.assertIsNone(backlog["cursor_terminus"])
        self.assertFalse(backlog["truncated"])
        # census call + one call per page.
        self.assertEqual(get_json.call_count, 1 + 2)
        second_call_params = get_json.call_args_list[1][0][1]
        self.assertNotIn("next_cursor", second_call_params)
        third_call_params = get_json.call_args_list[2][0][1]
        self.assertEqual(third_call_params["next_cursor"], "c1")

    def test_open_leaf_tasks_truncated_census_marks_backlog_truncated(self):
        import tiers.decide as decide

        census = {"count": 300, "count_truncated": True, "ids_inline_cap": 500, "ids": []}
        with mock.patch.object(decide, "TRACKER_API_BASE", "https://x/api/v1/tracker"), mock.patch.object(
            decide, "get_json", return_value=census
        ):
            backlog = decide._open_leaf_tasks()

        self.assertTrue(backlog["truncated"])

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
