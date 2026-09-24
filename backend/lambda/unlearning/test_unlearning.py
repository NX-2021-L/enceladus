"""Tests for FTR-106 unlearning core and handler."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import lambda_function as handler
import unlearning_core as core


def test_dry_run_default_on():
    assert core.is_dry_run() is True
    assert core.is_dry_run({"dry_run": False}) is False


def test_io_approval_ramp_blocks_mutation():
    assert core.io_approval_ramp_active(0) is True
    assert core.io_approval_ramp_active(2) is True
    assert core.io_approval_ramp_active(3) is False
    assert core.mutation_allowed(run_count=0, dry_run=False, mutation_enabled=True) is False
    assert core.mutation_allowed(run_count=3, dry_run=False, mutation_enabled=True) is True
    assert core.mutation_allowed(run_count=5, dry_run=True, mutation_enabled=True) is False


def test_identify_candidates_from_traces_miss_threshold():
    traces = []
    for i in range(5):
        traces.append(
            {
                "record_id_path": "DOC-AAA|DOC-BBB",
                "outcome_signal": json.dumps({"retrieval_outcome": "miss"}),
            }
        )
    cands = core.identify_candidates_from_traces(traces)
    ids = {c["record_id"] for c in cands}
    assert "DOC-AAA" in ids
    assert "DOC-BBB" in ids


def test_build_tombstone_recovery_window():
    now = datetime(2026, 7, 2, tzinfo=timezone.utc)
    tomb = core.build_tombstone("DOC-TEST", {"status": "active"}, now=now)
    assert tomb["schema"] == core.TOMBSTONE_SCHEMA
    recover = datetime.fromisoformat(tomb["recover_until"].replace("Z", "+00:00"))
    assert recover - now == timedelta(days=30)


def test_list_expired_tombstone_keys():
    now = datetime(2026, 7, 2, tzinfo=timezone.utc)
    past = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    future = (now + timedelta(days=1)).isoformat().replace("+00:00", "Z")

    def list_objects(_prefix):
        return ["old.json", "new.json"]

    def get_object(key):
        recover = past if key == "old.json" else future
        return json.dumps({"recover_until": recover})

    expired = core.list_expired_tombstone_keys(list_objects, "pfx", now=now, get_object=get_object)
    assert expired == ["old.json"]


@mock.patch.dict(
    "os.environ",
    {
        "UNLEARNING_DRY_RUN": "1",
        "UNLEARNING_MUTATION_ENABLED": "0",
        "DOCUMENTS_TABLE": "",
        "DRIFT_TELEMETRY_TABLE": "",
        "STIGMERGIC_TRACE_TABLE": "",
    },
    clear=False,
)
@mock.patch.object(handler, "_load_run_counter", return_value=0)
@mock.patch.object(handler, "_save_run_counter")
def test_handler_report_only_no_archive(mock_save, mock_counter):
    with mock.patch.object(handler, "_scan_recent_traces", return_value=[]):
        with mock.patch.object(handler, "fetch_high_spurious_waves", return_value=set()):
            result = handler.lambda_handler({"project_id": "enceladus"}, None)
    assert result["status"] == "ok"
    assert result["dry_run"] is True
    assert result["mutation_allowed"] is False
    assert result["archived_record_ids"] == []
    mock_save.assert_not_called()


@mock.patch.object(core, "UNLEARNING_MUTATION_ENABLED", True)
@mock.patch.object(handler, "UNLEARNING_MUTATION_ENABLED", True)
@mock.patch.dict(
    "os.environ",
    {
        "UNLEARNING_DRY_RUN": "0",
        "UNLEARNING_MUTATION_ENABLED": "1",
        "DOCUMENTS_TABLE": "docs",
        "TRACKER_TABLE": "tracker",
        "UNLEARNING_BUCKET": "bucket",
        "DRIFT_TELEMETRY_TABLE": "",
        "STIGMERGIC_TRACE_TABLE": "",
    },
    clear=False,
)
@mock.patch.object(handler, "_load_run_counter", return_value=3)
@mock.patch.object(handler, "_save_run_counter")
@mock.patch.object(handler, "_hard_delete_expired_tombstones", return_value=[])
@mock.patch.object(handler, "_archive_reference_record", return_value=True)
@mock.patch.object(handler, "_write_tombstone", return_value="tomb/key.json")
@mock.patch.object(handler, "_get_tracker_snapshot", return_value={"record_type": "reference"})
@mock.patch.object(handler, "_put_candidate_report", return_value="DOC-REPORT")
def test_handler_mutation_when_ramp_complete(
    mock_report,
    mock_snap,
    mock_tomb,
    mock_archive,
    mock_hard,
    mock_save,
    mock_counter,
):
    traces = [
        {
            "record_id_path": "DOC-PRUNE",
            "outcome_signal": json.dumps({"retrieval_outcome": "miss"}),
        }
    ] * 5
    with mock.patch.object(handler, "UNLEARNING_MUTATION_ENABLED", True):
        with mock.patch.object(handler, "_scan_recent_traces", return_value=traces):
            with mock.patch.object(handler, "fetch_high_spurious_waves", return_value={"w1"}):
                result = handler.lambda_handler(
                    {"project_id": "enceladus", "dry_run": False},
                    None,
                )
    assert result["mutation_allowed"] is True
    assert "DOC-PRUNE" in result["archived_record_ids"]
    mock_archive.assert_called()
    mock_tomb.assert_called()
    mock_save.assert_called_once_with(4)
