"""Unit tests for manifest_projection helpers (ENC-FTR-097, ENC-TSK-G41).

Target: ≥90% line coverage on the projection module. Run with:
    cd tools/enceladus-mcp-server && python3 -m pytest test_manifest_projection.py -v
or, without pytest:
    python3 -m unittest test_manifest_projection
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import manifest_projection as mp  # noqa: E402


# --- Fixtures ---------------------------------------------------------------


def _structured_ac(description: str, evidence: str = "", accepted: bool = False):
    return {
        "description": description,
        "evidence": evidence,
        "evidence_acceptance": accepted,
    }


def _record(**overrides):
    base = {
        "record_id": "task#ENC-TSK-G30",
        "item_id": "ENC-TSK-G30",
        "project_id": "enceladus",
        "record_type": "task",
        "title": "Sample task",
        "description": "Sample description.",
        "status": "in-progress",
        "priority": "P1",
        "transition_type": "github_pr_deploy",
        "components": ["comp-enceladus-mcp-server"],
        "acceptance_criteria": [
            _structured_ac("First criterion. Has a clause.", "DOC-XYZ", True),
            _structured_ac("Second criterion is much longer "
                           "and definitely exceeds the eighty character cap "
                           "applied by the projection helper module."),
            "Legacy plain-string AC",
        ],
        "history": [
            {"timestamp": "2026-04-25T05:00:00Z", "status": "created",
             "description": "Created via tracker API: Sample task"},
            {"timestamp": "2026-04-25T05:30:00Z", "status": "worklog",
             "description": "Field 'status' set to 'in-progress' [provider=agent-1]",
             "provider": "agent-1"},
            {"timestamp": "2026-04-25T06:00:00Z", "status": "worklog",
             "description": "Acceptance criterion [0] evidence accepted: First criterion",
             "provider": "agent-1"},
        ],
        "updated_at": "2026-04-25T06:00:00Z",
    }
    base.update(overrides)
    return base


# --- compute_content_hash --------------------------------------------------


class ContentHashTests(unittest.TestCase):

    def test_hash_is_deterministic(self):
        rec = _record()
        self.assertEqual(mp.compute_content_hash(rec), mp.compute_content_hash(rec))

    def test_hash_ignores_ephemeral_fields(self):
        a = _record()
        b = _record()
        b["sync_version"] = 999
        b["write_source"] = {"channel": "test"}
        b["history"] = []  # excluded from hash
        self.assertEqual(mp.compute_content_hash(a), mp.compute_content_hash(b))

    def test_hash_changes_on_status(self):
        a = _record()
        b = _record(status="closed")
        self.assertNotEqual(mp.compute_content_hash(a), mp.compute_content_hash(b))

    def test_hash_changes_on_ac_evidence(self):
        a = _record()
        b = _record()
        b["acceptance_criteria"][1]["evidence_acceptance"] = True
        self.assertNotEqual(mp.compute_content_hash(a), mp.compute_content_hash(b))

    def test_hash_handles_none_fields(self):
        rec = {"item_id": "ENC-TSK-1", "status": None, "title": "x"}
        # Should not raise and should be deterministic.
        h = mp.compute_content_hash(rec)
        self.assertEqual(len(h), 64)

    def test_hash_handles_empty_record(self):
        self.assertEqual(len(mp.compute_content_hash({})), 64)


# --- short_title -----------------------------------------------------------


class ShortTitleTests(unittest.TestCase):

    def test_first_sentence(self):
        self.assertEqual(mp.short_title("Hello world. Goodbye."), "Hello world")

    def test_semicolon_break(self):
        self.assertEqual(mp.short_title("Alpha; beta; gamma"), "Alpha")

    def test_newline_break(self):
        self.assertEqual(mp.short_title("Line one\nLine two"), "Line one")

    def test_truncation(self):
        text = "x" * 200
        self.assertTrue(mp.short_title(text).endswith("…"))
        self.assertLessEqual(len(mp.short_title(text)), 80)

    def test_short_text_returned_as_is(self):
        self.assertEqual(mp.short_title("short"), "short")

    def test_empty_inputs(self):
        self.assertEqual(mp.short_title(""), "")
        self.assertEqual(mp.short_title(None), "")
        self.assertEqual(mp.short_title("    "), "")

    def test_custom_max_len(self):
        self.assertEqual(mp.short_title("x" * 30, max_len=10), "x" * 9 + "…")


# --- AC projections ---------------------------------------------------------


class ACProjectionTests(unittest.TestCase):

    def test_project_ac_manifest_structured(self):
        rec = _record()
        out = mp.project_ac_manifest(
            rec["acceptance_criteria"][0], 0, rec["history"], rec["updated_at"]
        )
        self.assertEqual(out["ac_index"], 0)
        self.assertEqual(out["status"], "complete")
        self.assertEqual(out["evidence_ref"], "DOC-XYZ")
        self.assertTrue(out["short_title"])
        # AC 0 has a touch entry at 06:00:00 — that beats fallback updated_at
        self.assertEqual(out["last_touched"], "2026-04-25T06:00:00Z")

    def test_project_ac_manifest_legacy_string(self):
        rec = _record()
        out = mp.project_ac_manifest(
            rec["acceptance_criteria"][2], 2, rec["history"], rec["updated_at"]
        )
        self.assertEqual(out["status"], "incomplete")
        self.assertEqual(out["evidence_ref"], "")
        self.assertEqual(out["short_title"], "Legacy plain-string AC")
        # No touch entry → falls back to updated_at
        self.assertEqual(out["last_touched"], rec["updated_at"])

    def test_project_ac_manifest_no_history(self):
        out = mp.project_ac_manifest(
            _structured_ac("x"), 0, None, "2026-01-01T00:00:00Z"
        )
        self.assertEqual(out["last_touched"], "2026-01-01T00:00:00Z")

    def test_project_ac_body_includes_full_text(self):
        ac = _structured_ac("Body" * 100, "evidence" * 300, True)
        out = mp.project_ac_body(ac, 5)
        self.assertEqual(out["ac_index"], 5)
        self.assertEqual(out["body"], ac["description"])  # full body, untruncated
        self.assertEqual(out["status"], "complete")
        # evidence is 2400 chars > 2000-char max for body-mode evidence_ref
        self.assertTrue(out["evidence_ref"].endswith("…"))

    def test_project_ac_body_legacy_string(self):
        out = mp.project_ac_body("plain text AC", 0)
        self.assertEqual(out["body"], "plain text AC")
        self.assertEqual(out["status"], "incomplete")

    def test_project_ac_body_handles_none_evidence(self):
        out = mp.project_ac_body(_structured_ac("x", evidence=None), 0)
        self.assertEqual(out["evidence_ref"], "")


# --- record manifest --------------------------------------------------------


class RecordManifestTests(unittest.TestCase):

    def test_full_manifest_shape(self):
        rec = _record()
        m = mp.project_record_manifest(rec)
        self.assertEqual(m["record_id"], "ENC-TSK-G30")
        self.assertEqual(m["ac_count"], 3)
        self.assertEqual(len(m["acs"]), 3)
        self.assertEqual(len(m["content_hash"]), 64)
        for ac in m["acs"]:
            self.assertIn("ac_index", ac)
            self.assertIn("short_title", ac)
            self.assertIn("status", ac)

    def test_fields_narrowing(self):
        rec = _record()
        m = mp.project_record_manifest(rec, fields=["status"])
        # status retained, plus identity/freshness
        self.assertIn("status", m)
        self.assertIn("record_id", m)
        self.assertIn("content_hash", m)
        self.assertIn("updated_at", m)
        self.assertNotIn("acs", m)
        self.assertNotIn("title", m)

    def test_empty_fields_list_yields_full_manifest(self):
        rec = _record()
        m = mp.project_record_manifest(rec, fields=[])
        self.assertIn("acs", m)

    def test_handles_non_list_history(self):
        rec = _record()
        rec["history"] = "garbage"
        # Must not raise
        m = mp.project_record_manifest(rec)
        self.assertEqual(m["ac_count"], 3)


# --- worklog projections + filter ------------------------------------------


class WorklogProjectionTests(unittest.TestCase):

    def test_metadata_includes_size_bytes(self):
        rec = _record()
        out = mp.project_worklog_metadata(rec["history"][0], 0)
        self.assertEqual(out["worklog_id"], "wl-0000")
        self.assertGreater(out["size_bytes"], 0)
        self.assertEqual(out["author"], "system")
        self.assertNotIn("transition", out)

    def test_metadata_detects_transition(self):
        rec = _record()
        out = mp.project_worklog_metadata(rec["history"][1], 1)
        self.assertEqual(out["transition"], {"to": "in-progress"})

    def test_worklog_body_includes_status_and_body(self):
        rec = _record()
        out = mp.project_worklog_body(rec["history"][1], 1)
        self.assertEqual(out["status"], "worklog")
        self.assertIn("Field 'status'", out["body"])

    def test_filter_window(self):
        rec = _record()
        # since/until trim entries
        result = mp.filter_worklogs(
            rec["history"],
            since="2026-04-25T05:15:00Z",
            until="2026-04-25T05:45:00Z",
        )
        self.assertEqual([idx for idx, _ in result], [1])

    def test_filter_id_set(self):
        rec = _record()
        result = mp.filter_worklogs(rec["history"], ids={"wl-0002"})
        self.assertEqual([idx for idx, _ in result], [2])

    def test_filter_empty_history(self):
        self.assertEqual(mp.filter_worklogs([]), [])
        self.assertEqual(mp.filter_worklogs(None), [])

    def test_filter_window_combined_with_ids(self):
        rec = _record()
        # ids restricts to wl-0001 only; window also includes wl-0001
        result = mp.filter_worklogs(
            rec["history"], since="2026-04-25T05:15:00Z", ids={"wl-0001"}
        )
        self.assertEqual([idx for idx, _ in result], [1])

    def test_filter_orders_by_timestamp(self):
        history = [
            {"timestamp": "2026-04-25T03:00:00Z", "description": "later position, earlier time"},
            {"timestamp": "2026-04-25T01:00:00Z", "description": "earlier position, latest time"},
        ]
        # filter_worklogs sorts ascending — wl-0001 (idx 1, ts 01:00) comes first
        result = mp.filter_worklogs(history)
        self.assertEqual([idx for idx, _ in result], [1, 0])


# --- transition parser -----------------------------------------------------


class TransitionParserTests(unittest.TestCase):

    def test_parses_status_field_set(self):
        self.assertEqual(
            mp.parse_transition("Field 'status' set to 'closed'"),
            {"to": "closed"},
        )

    def test_returns_none_for_unrelated_lines(self):
        self.assertIsNone(mp.parse_transition("Created via tracker API"))
        self.assertIsNone(mp.parse_transition(""))
        self.assertIsNone(mp.parse_transition(None))

    def test_returns_none_for_field_other_than_status(self):
        self.assertIsNone(mp.parse_transition("Field 'priority' set to 'P0'"))


# --- coerce_indices --------------------------------------------------------


class CoerceIndicesTests(unittest.TestCase):

    def test_normalizes_dedup_sort(self):
        self.assertEqual(mp.coerce_indices([3, 1, 1, 2]), [1, 2, 3])

    def test_accepts_string_ints(self):
        self.assertEqual(mp.coerce_indices(["0", 1, "2"]), [0, 1, 2])

    def test_accepts_scalar(self):
        self.assertEqual(mp.coerce_indices(7), [7])

    def test_none_returns_empty(self):
        self.assertEqual(mp.coerce_indices(None), [])

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            mp.coerce_indices([-1])

    def test_rejects_non_integer(self):
        with self.assertRaises(ValueError):
            mp.coerce_indices(["abc"])

    def test_rejects_dict(self):
        with self.assertRaises(ValueError):
            mp.coerce_indices({"a": 1})


# --- staleness envelope + error codes --------------------------------------


class StalenessEnvelopeTests(unittest.TestCase):

    def test_envelope_shape(self):
        env = mp.staleness_envelope("ENC-TSK-1", "abc", "def")
        self.assertTrue(env["error"])
        self.assertEqual(env["error_code"], "STALE_CONTENT_HASH")
        self.assertEqual(env["current_content_hash"], "abc")
        self.assertEqual(env["supplied_content_hash"], "def")
        self.assertIn("retry_guidance", env)

    def test_error_codes_exposed(self):
        # Used by handlers and governance dictionary entries — must stay stable.
        self.assertEqual(mp.STALE_ERROR_CODE, "STALE_CONTENT_HASH")
        self.assertEqual(mp.BULK_LIMIT_ERROR_CODE, "BULK_SIZE_EXCEEDED")
        self.assertEqual(mp.INDEX_OUT_OF_RANGE_ERROR_CODE, "AC_INDEX_OUT_OF_RANGE")


# --- worklog_id ------------------------------------------------------------


class WorklogIdTests(unittest.TestCase):

    def test_zero_padded_4_digit(self):
        self.assertEqual(mp.worklog_id(0), "wl-0000")
        self.assertEqual(mp.worklog_id(7), "wl-0007")
        self.assertEqual(mp.worklog_id(12345), "wl-12345")


# --- Wave-handoff integration scenario -------------------------------------


class WaveHandoffIntegrationTest(unittest.TestCase):
    """ENC-FTR-097 AC4: handoff doc with 20 record IDs → manifest_bulk-shape
    response → resume-work on first incomplete AC via tracker.get_acs.

    This test exercises the projection helpers end-to-end against a synthetic
    20-record fixture; the handler-level integration test against the live
    Lambda lives in test_integration_server.py (network-gated).
    """

    def setUp(self):
        # 20 records, each with 5 ACs; mix of complete and incomplete.
        self.records = []
        for i in range(20):
            r = _record()
            r["item_id"] = f"ENC-TSK-W{i:02d}"
            r["record_id"] = f"task#{r['item_id']}"
            r["acceptance_criteria"] = [
                _structured_ac(f"AC{j} for record {i}", evidence=f"E{i}-{j}",
                               accepted=(j < (i % 5)))
                for j in range(5)
            ]
            self.records.append(r)

    def test_bulk_manifest_shape_and_resume_workflow(self):
        # Build the manifest_bulk shape from projection helpers.
        manifests = []
        for r in self.records:
            manifest = mp.project_record_manifest(r)
            manifests.append({
                "record_id": r["item_id"],
                "manifest": manifest,
                "content_hash": manifest["content_hash"],
            })
        self.assertEqual(len(manifests), 20)

        # Resume-work: pick the first record with at least one incomplete AC,
        # find its first incomplete AC, fetch via project_ac_body.
        target_record_id = None
        target_ac_index = None
        for entry in manifests:
            for ac in entry["manifest"]["acs"]:
                if ac["status"] == "incomplete":
                    target_record_id = entry["record_id"]
                    target_ac_index = ac["ac_index"]
                    break
            if target_record_id is not None:
                break
        self.assertIsNotNone(target_record_id)
        self.assertIsNotNone(target_ac_index)

        # Fetch the AC body for the resume target.
        target_record = next(r for r in self.records if r["item_id"] == target_record_id)
        body = mp.project_ac_body(
            target_record["acceptance_criteria"][target_ac_index], target_ac_index
        )
        self.assertEqual(body["ac_index"], target_ac_index)
        self.assertEqual(body["status"], "incomplete")
        self.assertTrue(body["body"])

    def test_freshness_contract_round_trip(self):
        # tracker.manifest returns content_hash → tracker.get_acs validates it.
        rec = self.records[0]
        manifest = mp.project_record_manifest(rec)
        token = manifest["content_hash"]

        # An unchanged record produces the same hash.
        same = mp.compute_content_hash(rec)
        self.assertEqual(token, same)

        # Mutate AC evidence — hash must change → caller would receive
        # STALE_CONTENT_HASH on the next selective fetch.
        rec["acceptance_criteria"][0]["evidence_acceptance"] = (
            not rec["acceptance_criteria"][0]["evidence_acceptance"]
        )
        post = mp.compute_content_hash(rec)
        self.assertNotEqual(token, post)
        env = mp.staleness_envelope(rec["item_id"], post, token)
        self.assertEqual(env["error_code"], "STALE_CONTENT_HASH")

    def test_payload_size_telemetry(self):
        """Phase A KPI: the manifest_bulk payload for 20 records should be
        well under the design ceiling of 10,000 tokens (~40KB). This test
        exists as a regression guardrail; the live evidence capture is
        recorded on ENC-TSK-G41 acceptance criteria."""
        manifests = [
            {
                "record_id": r["item_id"],
                "manifest": mp.project_record_manifest(r),
            }
            for r in self.records
        ]
        size_bytes = len(json.dumps(manifests, default=str).encode("utf-8"))
        self.assertLess(size_bytes, 40_000)


if __name__ == "__main__":
    unittest.main()
