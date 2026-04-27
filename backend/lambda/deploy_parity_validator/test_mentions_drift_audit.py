"""Unit tests for mentions_drift_audit (ENC-TSK-G43 / ENC-FTR-098 AC-7).

Run from backend/lambda/deploy_parity_validator/:
    python -m pytest test_mentions_drift_audit.py -v

The audit imports mentions_extraction.py at runtime, copied into the build
artifact via .build_extras. The tests place a sibling copy of that module
on sys.path before importing lambda_function so the local pytest run resolves
the same symbols the deployed Lambda would.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest


_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[2]
_GRAPH_SYNC = _REPO_ROOT / "backend" / "lambda" / "graph_sync"
sys.path.insert(0, str(_GRAPH_SYNC))
sys.path.insert(0, str(_HERE))

import lambda_function as lf  # noqa: E402  (sys.path set above)


# ---------------------------------------------------------------------------
# _load_mentions_helpers — proves .build_extras-style import resolves
# ---------------------------------------------------------------------------

class TestLoadMentionsHelpers:
    def test_returns_three_handles(self):
        prose, extract, strip = lf._load_mentions_helpers()
        assert isinstance(prose, dict)
        assert callable(extract)
        assert callable(strip)

    def test_prose_fields_match_live_path(self):
        # Sanity guard: the audit must read the exact same allowlist
        # graph_sync uses on the live reconciler path.
        prose, _, _ = lf._load_mentions_helpers()
        assert "task" in prose and "title" in prose["task"]
        assert "issue" in prose and "hypothesis" in prose["issue"]


# ---------------------------------------------------------------------------
# _expected_mentions_for — extractor parity
# ---------------------------------------------------------------------------

class TestExpectedMentionsFor:
    def setup_method(self):
        self.prose, self.extract, self.strip = lf._load_mentions_helpers()

    def test_extracts_governed_ids_from_description(self):
        record = {
            "title": "Fix ENC-TSK-G43 audit",
            "description": "Depends on ENC-FTR-098 and DOC-ABCDEF012345.",
            "intent": "",
        }
        out = lf._expected_mentions_for(
            "task", "ENC-TSK-G99", record, self.prose, self.extract, self.strip,
        )
        assert "ENC-TSK-G43" in out
        assert "ENC-FTR-098" in out
        assert "DOC-ABCDEF012345" in out

    def test_drops_self_mention(self):
        record = {"title": "ENC-TSK-G99 self", "description": ""}
        out = lf._expected_mentions_for(
            "task", "ENC-TSK-G99", record, self.prose, self.extract, self.strip,
        )
        assert "ENC-TSK-G99" not in out

    def test_skips_unknown_record_type(self):
        out = lf._expected_mentions_for(
            "alien_type", "ENC-TSK-G99", {"title": "ENC-TSK-G43"},
            self.prose, self.extract, self.strip,
        )
        assert out == set()

    def test_strips_code_fences_before_extraction(self):
        record = {
            "title": "x",
            "description": "real ENC-TSK-G43\n```\nfake ENC-TSK-XXX\n```\n",
            "intent": "",
        }
        out = lf._expected_mentions_for(
            "task", "ENC-TSK-G99", record, self.prose, self.extract, self.strip,
        )
        assert "ENC-TSK-G43" in out
        assert "ENC-TSK-XXX" not in out

    def test_non_string_field_skipped(self):
        record = {"title": "x", "description": ["not", "a", "string"], "intent": ""}
        out = lf._expected_mentions_for(
            "task", "ENC-TSK-G99", record, self.prose, self.extract, self.strip,
        )
        assert out == set()


# ---------------------------------------------------------------------------
# _current_mentions_for — graphsearch HTTP client
# ---------------------------------------------------------------------------

class TestCurrentMentionsFor:
    def test_returns_none_when_url_unset(self):
        with patch.object(lf, "GRAPHSEARCH_URL", ""), \
             patch.object(lf, "TRACKER_API_URL", ""):
            assert lf._current_mentions_for("ENC-TSK-G99") is None

    def test_extracts_target_from_edges(self):
        body = {
            "edges": [
                {"source": "ENC-TSK-G99", "target": "ENC-TSK-G43"},
                {"source": "ENC-TSK-G99", "target": "ENC-FTR-098"},
            ]
        }
        with patch.object(lf, "GRAPHSEARCH_URL", "https://api.example/gs"), \
             patch.object(lf, "_http", return_value=(200, body)):
            out = lf._current_mentions_for("ENC-TSK-G99")
        assert out == {"ENC-TSK-G43", "ENC-FTR-098"}

    def test_falls_back_to_nodes_when_edges_empty(self):
        body = {"edges": [], "nodes": [
            {"record_id": "ENC-TSK-G99"},  # source filtered out
            {"record_id": "ENC-TSK-G43"},
        ]}
        with patch.object(lf, "GRAPHSEARCH_URL", "https://api.example/gs"), \
             patch.object(lf, "_http", return_value=(200, body)):
            out = lf._current_mentions_for("ENC-TSK-G99")
        assert out == {"ENC-TSK-G43"}

    def test_returns_none_on_http_error(self):
        with patch.object(lf, "GRAPHSEARCH_URL", "https://api.example/gs"), \
             patch.object(lf, "_http", return_value=(503, {"error": "down"})):
            assert lf._current_mentions_for("ENC-TSK-G99") is None

    def test_falls_back_to_tracker_api_url(self):
        captured: Dict[str, Any] = {}

        def fake_http(method: str, url: str, **kw):
            captured["url"] = url
            return 200, {"edges": []}

        with patch.object(lf, "GRAPHSEARCH_URL", ""), \
             patch.object(lf, "TRACKER_API_URL", "https://tracker.example/api/v1/tracker"), \
             patch.object(lf, "_http", side_effect=fake_http):
            lf._current_mentions_for("ENC-TSK-G99")
        assert captured["url"].startswith("https://tracker.example/api/v1/tracker/graphsearch")


# ---------------------------------------------------------------------------
# _emit_drift_iss
# ---------------------------------------------------------------------------

class TestEmitDriftIss:
    def test_returns_none_when_tracker_url_unset(self):
        with patch.object(lf, "TRACKER_API_URL", ""):
            out = lf._emit_drift_iss("2026-04-27T00:00:00Z", 100, 5, [])
        assert out is None

    def test_posts_with_threshold_metadata(self):
        captured: Dict[str, Any] = {}

        def fake_http(method: str, url: str, body=None, **kw):
            captured["method"] = method
            captured["url"] = url
            captured["body"] = body
            return 201, {"item_id": "ENC-ISS-XXX"}

        divergent = [{"record_id": "ENC-TSK-A", "record_type": "task",
                      "missing": ["ENC-TSK-B01"], "extra": []}]
        with patch.object(lf, "TRACKER_API_URL", "https://api.example/v1/tracker"), \
             patch.object(lf, "_http", side_effect=fake_http):
            new_id = lf._emit_drift_iss("2026-04-27T00:00:00Z", 100, 5, divergent)
        assert new_id == "ENC-ISS-XXX"
        assert captured["method"] == "POST"
        assert captured["url"].endswith("/create")
        assert captured["body"]["record_type"] == "issue"
        assert captured["body"]["category"] == "bug"
        assert captured["body"]["source"] == "mentions_drift_audit"
        assert "5/100" in captured["body"]["title"]

    def test_returns_none_on_non_2xx(self):
        with patch.object(lf, "TRACKER_API_URL", "https://api.example/v1/tracker"), \
             patch.object(lf, "_http", return_value=(500, {"error": "boom"})):
            assert lf._emit_drift_iss("ts", 10, 1, []) is None


# ---------------------------------------------------------------------------
# _run_mentions_drift_audit — end-to-end with stubbed sample + graphsearch
# ---------------------------------------------------------------------------

def _make_sample(records: List[Tuple[str, str, Dict[str, Any]]]):
    def _stub(_per_type_limit: int):
        return list(records)
    return _stub


class TestRunMentionsDriftAudit:
    def test_zero_divergence_does_not_emit_iss(self):
        sample = [
            ("task", "ENC-TSK-A01", {"title": "see ENC-TSK-B01", "description": "", "intent": ""}),
        ]
        with patch.object(lf, "_sample_recent_records", _make_sample(sample)), \
             patch.object(lf, "_current_mentions_for", return_value={"ENC-TSK-B01"}), \
             patch.object(lf, "_emit_drift_iss") as emit:
            result = lf._run_mentions_drift_audit()
        emit.assert_not_called()
        assert result["mismatch_count"] == 0
        assert result["threshold_breached"] is False
        assert result["iss_emitted"] is None

    def test_under_threshold_does_not_emit(self):
        # 1% threshold, 100 records, 1 divergent => exactly at threshold (not >).
        sample = [
            ("task", f"ENC-TSK-S{i:03d}",
             {"title": "see ENC-TSK-B01", "description": "", "intent": ""})
            for i in range(100)
        ]

        # First record diverges, rest match.
        def fake_current(rid, *_a, **_kw):
            return set() if rid == "ENC-TSK-S000" else {"ENC-TSK-B01"}

        with patch.object(lf, "_sample_recent_records", _make_sample(sample)), \
             patch.object(lf, "_current_mentions_for", side_effect=fake_current), \
             patch.object(lf, "_emit_drift_iss") as emit:
            result = lf._run_mentions_drift_audit()
        emit.assert_not_called()
        assert result["mismatch_count"] == 1
        assert result["mismatch_ratio"] == 0.01
        assert result["threshold_breached"] is False

    def test_above_threshold_emits_iss(self):
        # 5 divergent of 100 => 5% ratio > 1% threshold.
        sample = [
            ("task", f"ENC-TSK-S{i:03d}",
             {"title": "see ENC-TSK-B01", "description": "", "intent": ""})
            for i in range(100)
        ]

        def fake_current(rid, *_a, **_kw):
            return set() if rid in {f"ENC-TSK-S{i:03d}" for i in range(5)} else {"ENC-TSK-B01"}

        with patch.object(lf, "_sample_recent_records", _make_sample(sample)), \
             patch.object(lf, "_current_mentions_for", side_effect=fake_current), \
             patch.object(lf, "_emit_drift_iss", return_value="ENC-ISS-EMITTED") as emit:
            result = lf._run_mentions_drift_audit()
        assert emit.called
        assert result["mismatch_count"] == 5
        assert result["threshold_breached"] is True
        assert result["iss_emitted"] == "ENC-ISS-EMITTED"

    def test_skipped_records_do_not_count_as_zero_divergence(self):
        # If graphsearch is down, we must NOT score the record as zero-divergence
        # (which would mask real audit gaps). Skips drop out of the denominator.
        sample = [
            ("task", "ENC-TSK-A01", {"title": "see ENC-TSK-B01", "description": "", "intent": ""}),
            ("task", "ENC-TSK-C01", {"title": "see ENC-TSK-D01", "description": "", "intent": ""}),
        ]

        def fake_current(rid, *_a, **_kw):
            return None if rid == "ENC-TSK-A01" else set()  # C01 diverges

        with patch.object(lf, "_sample_recent_records", _make_sample(sample)), \
             patch.object(lf, "_current_mentions_for", side_effect=fake_current), \
             patch.object(lf, "_emit_drift_iss") as emit:
            result = lf._run_mentions_drift_audit()
        assert result["sample_size"] == 2
        assert result["skipped_transport"] == 1
        assert result["effective_sample"] == 1
        assert result["mismatch_count"] == 1
        assert result["mismatch_ratio"] == 1.0
        assert result["threshold_breached"] is True

    def test_records_first_10_divergent_in_response(self):
        sample = [
            ("task", f"ENC-TSK-D01{i:02d}",
             {"title": "see ENC-TSK-B01", "description": "", "intent": ""})
            for i in range(15)
        ]
        with patch.object(lf, "_sample_recent_records", _make_sample(sample)), \
             patch.object(lf, "_current_mentions_for", return_value=set()), \
             patch.object(lf, "_emit_drift_iss", return_value="ENC-ISS-X"):
            result = lf._run_mentions_drift_audit()
        assert len(result["divergent_first_10"]) == 10
        assert all("missing" in d for d in result["divergent_first_10"])


# ---------------------------------------------------------------------------
# Dispatch — daily_drift_audit chains mentions_drift_audit
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_daily_drift_audit_chains_mentions(self):
        with patch.object(lf, "_run_daily_drift_audit",
                          return_value={"action": "daily_drift_audit", "total_anomalies": 0}), \
             patch.object(lf, "_run_mentions_drift_audit",
                          return_value={"action": "mentions_drift_audit", "mismatch_count": 0}):
            resp = lf.lambda_handler({"action": "daily_drift_audit"}, None)
        assert resp["statusCode"] == 200
        import json
        body = json.loads(resp["body"])
        assert body["action"] == "daily_drift_audit"
        assert body["mentions_audit"]["action"] == "mentions_drift_audit"

    def test_daily_drift_audit_continues_when_mentions_audit_raises(self):
        with patch.object(lf, "_run_daily_drift_audit",
                          return_value={"action": "daily_drift_audit", "total_anomalies": 0}), \
             patch.object(lf, "_run_mentions_drift_audit",
                          side_effect=RuntimeError("graphsearch down")):
            resp = lf.lambda_handler({"action": "daily_drift_audit"}, None)
        import json
        body = json.loads(resp["body"])
        assert body["mentions_audit"]["status"] == "error"
        assert "graphsearch down" in body["mentions_audit"]["error"]

    def test_mentions_drift_audit_direct_dispatch(self):
        with patch.object(lf, "_run_mentions_drift_audit",
                          return_value={"action": "mentions_drift_audit", "mismatch_count": 0}):
            resp = lf.lambda_handler({"action": "mentions_drift_audit"}, None)
        assert resp["statusCode"] == 200
        import json
        assert json.loads(resp["body"])["action"] == "mentions_drift_audit"
