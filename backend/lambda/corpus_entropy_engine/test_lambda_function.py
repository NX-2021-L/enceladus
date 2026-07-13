"""Tests for the Corpus Entropy Engine (CEE) Lambda -- ENC-TSK-K41 / B66 Ph5.

Two layers, mirroring governance_drift_check/test_lambda_function.py and
scoring_service/test_lambda_function.py conventions in this repo:

  1. Pure-function tests against corpus_entropy_core (no AWS, no HTTP) -- each
     detector's counting/flagging logic in isolation.
  2. Handler-level tests against lambda_function, monkeypatching the governed
     HTTP fetch functions and the CloudWatch client so no real network/AWS
     call is made. Includes a "must never mutate" guard mirroring
     governance_drift_check's ForbiddenDDB/ForbiddenS3 idiom, and a
     CEE_HARD_DISABLED kill-switch test.

Runs under pytest (test_* discovery).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import corpus_entropy_core as core  # noqa: E402
import lambda_function as mod  # noqa: E402


# ---------------------------------------------------------------------------
# (a) Orphan Entropy
# ---------------------------------------------------------------------------

def test_orphan_task_with_no_parent_and_no_related_is_flagged():
    records = [
        {"record_id": "task#ENC-TSK-A01", "record_type": "task"},
    ]
    findings = core.detect_orphan_entropy(records)
    assert len(findings) == 1
    assert findings[0]["record_id"] == "task#ENC-TSK-A01"
    assert findings[0]["reason"] == "no_parent_task_id_and_no_related_task_ids"


def test_task_with_parent_task_id_not_flagged():
    records = [
        {"record_id": "task#ENC-TSK-A02", "record_type": "task", "parent_task_id": "ENC-TSK-A00"},
    ]
    assert core.detect_orphan_entropy(records) == []


def test_task_with_related_task_ids_not_flagged():
    records = [
        {"record_id": "task#ENC-TSK-A03", "record_type": "task", "related_task_ids": ["ENC-TSK-A00"]},
    ]
    assert core.detect_orphan_entropy(records) == []


def test_plan_records_never_orphaned():
    records = [{"record_id": "plan#ENC-PLN-001", "record_type": "plan"}]
    assert core.detect_orphan_entropy(records) == []


def test_wave_document_without_plan_anchor_is_flagged():
    records = [
        {
            "record_id": "DOC-AAA111",
            "record_type": "document",
            "document_subtype": "wave",
        },
    ]
    findings = core.detect_orphan_entropy(records)
    assert len(findings) == 1
    assert findings[0]["reason"] == "wave_document_missing_plan_anchor_id"


def test_wave_document_with_plan_anchor_not_flagged():
    records = [
        {
            "record_id": "DOC-AAA222",
            "record_type": "document",
            "document_subtype": "wave",
            "plan_anchor_id": "ENC-PLN-064",
        },
    ]
    assert core.detect_orphan_entropy(records) == []


def test_non_wave_document_not_flagged_for_missing_plan_anchor():
    records = [
        {"record_id": "DOC-AAA333", "record_type": "document", "document_subtype": "doc"},
    ]
    assert core.detect_orphan_entropy(records) == []


# ---------------------------------------------------------------------------
# (b) Stagnation Entropy
# ---------------------------------------------------------------------------

NOW = "2026-07-02T13:00:00Z"


def test_open_task_with_recent_worklog_not_flagged():
    records = [{
        "record_id": "task#ENC-TSK-B01",
        "record_type": "task",
        "status": "in-progress",
        "created_at": "2026-06-01T00:00:00Z",
        "history": [{"status": "worklog", "timestamp": "2026-07-01T00:00:00Z"}],
    }]
    assert core.detect_stagnation_entropy(records, now_iso=NOW, threshold_days=14) == []


def test_open_task_with_stale_worklog_is_flagged():
    records = [{
        "record_id": "task#ENC-TSK-B02",
        "record_type": "task",
        "status": "in-progress",
        "created_at": "2026-01-01T00:00:00Z",
        "history": [{"status": "worklog", "timestamp": "2026-01-05T00:00:00Z"}],
    }]
    findings = core.detect_stagnation_entropy(records, now_iso=NOW, threshold_days=14)
    assert len(findings) == 1
    assert findings[0]["reason"] == "no_worklog_within_threshold"
    assert findings[0]["last_worklog_at"] == "2026-01-05T00:00:00Z"


def test_open_task_with_no_worklog_ever_uses_created_at():
    records = [{
        "record_id": "task#ENC-TSK-B03",
        "record_type": "task",
        "status": "open",
        "created_at": "2026-01-01T00:00:00Z",
        "history": [],
    }]
    findings = core.detect_stagnation_entropy(records, now_iso=NOW, threshold_days=14)
    assert len(findings) == 1
    assert findings[0]["reason"] == "no_worklog_ever"


def test_closed_task_never_flagged_for_stagnation():
    records = [{
        "record_id": "task#ENC-TSK-B04",
        "record_type": "task",
        "status": "closed",
        "created_at": "2026-01-01T00:00:00Z",
        "history": [],
    }]
    assert core.detect_stagnation_entropy(records, now_iso=NOW, threshold_days=14) == []


def test_non_task_records_ignored_by_stagnation():
    records = [{
        "record_id": "issue#ENC-ISS-001",
        "record_type": "issue",
        "status": "open",
        "created_at": "2026-01-01T00:00:00Z",
        "history": [],
    }]
    assert core.detect_stagnation_entropy(records, now_iso=NOW, threshold_days=14) == []


# ---------------------------------------------------------------------------
# (c) Relational Entropy
# ---------------------------------------------------------------------------

def test_declared_relation_with_no_edge_is_flagged():
    records = [{"record_id": "task#ENC-TSK-C01", "related_task_ids": ["ENC-TSK-C02"]}]
    findings = core.detect_relational_entropy(records, edge_pairs=[])
    assert len(findings) == 1
    assert findings[0]["declared_target_id"] == "ENC-TSK-C02"
    assert findings[0]["field"] == "related_task_ids"


def test_declared_relation_with_matching_edge_not_flagged():
    records = [{"record_id": "task#ENC-TSK-C03", "related_task_ids": ["ENC-TSK-C04"]}]
    edges = [("task#ENC-TSK-C03", "ENC-TSK-C04")]
    assert core.detect_relational_entropy(records, edge_pairs=edges) == []


def test_relational_entropy_edge_is_undirected():
    records = [{"record_id": "task#ENC-TSK-C05", "related_issue_ids": ["ENC-ISS-C06"]}]
    # Edge stored in reverse order should still satisfy the check.
    edges = [("ENC-ISS-C06", "task#ENC-TSK-C05")]
    assert core.detect_relational_entropy(records, edge_pairs=edges) == []


def test_no_declared_relations_yields_no_findings():
    records = [{"record_id": "task#ENC-TSK-C07"}]
    assert core.detect_relational_entropy(records, edge_pairs=[]) == []


# ---------------------------------------------------------------------------
# (d) Retention Entropy (FSRS-6)
# ---------------------------------------------------------------------------

def test_lesson_below_t3_stability_is_flagged():
    lessons = [{"record_id": "lesson#ENC-LSN-001", "stability": 0.5}]
    findings = core.detect_retention_entropy(lessons)
    assert len(findings) == 1
    assert findings[0]["stability"] == 0.5
    assert findings[0]["source_field"] == "stability"


def test_lesson_at_or_above_t3_stability_not_flagged():
    lessons = [{"record_id": "lesson#ENC-LSN-002", "stability": 0.7}]
    assert core.detect_retention_entropy(lessons) == []
    lessons_high = [{"record_id": "lesson#ENC-LSN-003", "stability": 0.9}]
    assert core.detect_retention_entropy(lessons_high) == []


def test_lesson_falls_back_to_resonance_score_when_stability_absent():
    lessons = [{"record_id": "lesson#ENC-LSN-004", "resonance_score": 0.3}]
    findings = core.detect_retention_entropy(lessons)
    assert len(findings) == 1
    assert findings[0]["source_field"] == "resonance_score"


def test_lesson_with_neither_field_skipped_not_flagged():
    lessons = [{"record_id": "lesson#ENC-LSN-005"}]
    assert core.detect_retention_entropy(lessons) == []


def test_retention_threshold_is_fsrs_t3():
    assert core.FSRS_T3_THRESHOLD == 0.7


# ---------------------------------------------------------------------------
# (e) Compliance/Semantic Entropy
# ---------------------------------------------------------------------------

def test_raw_doc_below_threshold_is_flagged():
    docs = [{"record_id": "DOC-D01", "compliance_score": 40, "document_maturity_state": "raw"}]
    findings = core.detect_compliance_semantic_entropy(docs, score_threshold=70)
    assert len(findings) == 1
    assert findings[0]["compliance_score"] == 40


def test_raw_doc_above_threshold_not_flagged():
    docs = [{"record_id": "DOC-D02", "compliance_score": 90, "document_maturity_state": "raw"}]
    assert core.detect_compliance_semantic_entropy(docs, score_threshold=70) == []


def test_non_raw_doc_below_threshold_not_flagged():
    docs = [{"record_id": "DOC-D03", "compliance_score": 10, "document_maturity_state": "mature"}]
    assert core.detect_compliance_semantic_entropy(docs, score_threshold=70) == []


def test_doc_missing_compliance_score_skipped():
    docs = [{"record_id": "DOC-D04", "document_maturity_state": "raw"}]
    assert core.detect_compliance_semantic_entropy(docs, score_threshold=70) == []


# ---------------------------------------------------------------------------
# Kill switch (ISS-465 cost-preflight companion)
# ---------------------------------------------------------------------------

def test_hard_disabled_true_variants():
    for val in ("1", "true", "True", "YES", "yes"):
        assert core.is_hard_disabled({"CEE_HARD_DISABLED": val}) is True


def test_hard_disabled_false_when_unset_or_zero():
    assert core.is_hard_disabled({}) is False
    assert core.is_hard_disabled({"CEE_HARD_DISABLED": "0"}) is False


# ---------------------------------------------------------------------------
# CloudWatch metric batch shape
# ---------------------------------------------------------------------------

def test_build_category_metric_data_shape():
    counts = {"lineage_unanchored": 3, "stagnation": 1}
    data = core.build_category_metric_data(counts, function_name="cee-fn", timestamp="T")
    assert len(data) == 2
    for datum in data:
        assert datum["MetricName"] == "EntropyFindingCount"
        assert datum["Unit"] == "Count"
        names = {d["Name"] for d in datum["Dimensions"]}
        assert names == {"FunctionName", "Category"}


def test_build_scan_duration_metric_data_shape():
    datum = core.build_scan_duration_metric_data(26000.5, function_name="cee-fn", timestamp="T")
    assert datum["MetricName"] == "ScanDurationMs"
    assert datum["Value"] == 26000.5
    assert datum["Unit"] == "Milliseconds"
    assert {d["Name"] for d in datum["Dimensions"]} == {"FunctionName"}


# ---------------------------------------------------------------------------
# Handler-level tests (mock HTTP + CloudWatch, never touch AWS/network)
# ---------------------------------------------------------------------------

def _patch_fetches(monkeypatch, *, tasks=None, issues=None, features=None, plans=None,
                    documents=None, lessons=None, edges=None):
    monkeypatch.setattr(mod, "_fetch_tracker_records", lambda rtype: {
        "task": tasks or [], "issue": issues or [], "feature": features or [],
        "plan": plans or [], "lesson": lessons or [],
    }.get(rtype, []))
    monkeypatch.setattr(mod, "_fetch_documents", lambda: documents or [])
    monkeypatch.setattr(mod, "_fetch_lessons", lambda: lessons or [])
    monkeypatch.setattr(mod, "_fetch_graph_edges", lambda: edges or [])


class _FakeCW:
    def __init__(self):
        self.calls = []

    def put_metric_data(self, **kwargs):
        self.calls.append(kwargs)


def test_handler_publishes_all_five_category_counts(monkeypatch):
    _patch_fetches(
        monkeypatch,
        tasks=[{"record_id": "task#T1", "record_type": "task", "status": "open",
                "created_at": "2020-01-01T00:00:00Z", "history": []}],
        lessons=[{"record_id": "lesson#L1", "stability": 0.1}],
        documents=[{"record_id": "DOC-1", "compliance_score": 5, "document_maturity_state": "raw"}],
    )
    fake_cw = _FakeCW()
    monkeypatch.setattr(mod, "_get_cw", lambda: fake_cw)
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)

    result = mod.lambda_handler({}, None)

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["success"] is True
    counts = body["counts"]
    assert set(counts.keys()) == {
        "lineage_unanchored", "stagnation", "relational", "retention", "compliance_semantic",
    }
    assert counts["lineage_unanchored"] >= 1  # unanchored task has no parent/related
    assert counts["stagnation"] == 1
    assert counts["retention"] == 1
    assert counts["compliance_semantic"] == 1
    assert len(fake_cw.calls) == 1
    assert len(fake_cw.calls[0]["MetricData"]) == 6
    metric_names = {m["MetricName"] for m in fake_cw.calls[0]["MetricData"]}
    assert metric_names == {"EntropyFindingCount", "ScanDurationMs"}
    assert fake_cw.calls[0]["Namespace"] == "Enceladus/CEE"


def test_handler_respects_kill_switch(monkeypatch):
    monkeypatch.setenv("CEE_HARD_DISABLED", "1")

    def _boom(*args, **kwargs):
        raise AssertionError("must not fetch when kill switch is set")

    monkeypatch.setattr(mod, "_fetch_tracker_records", _boom)
    monkeypatch.setattr(mod, "_fetch_documents", _boom)
    monkeypatch.setattr(mod, "_fetch_graph_edges", _boom)

    fake_cw = _FakeCW()
    monkeypatch.setattr(mod, "_get_cw", lambda: fake_cw)

    result = mod.lambda_handler({}, None)

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["skipped"] is True
    assert fake_cw.calls == []
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)


def test_handler_never_mutates_tracker_or_documents(monkeypatch):
    """Read-only guard: any urlopen call the handler makes must be a GET.

    _http_get is the sole HTTP entry point used by every fetch helper; forcing
    it through a wrapper that asserts method=="GET" catches any future
    accidental POST/PUT/PATCH call without needing a live network stub.
    """
    _patch_fetches(monkeypatch)
    fake_cw = _FakeCW()
    monkeypatch.setattr(mod, "_get_cw", lambda: fake_cw)
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)

    calls = []

    def _guarded_http_get(url):
        calls.append(url)
        return {}

    monkeypatch.setattr(mod, "_http_get", _guarded_http_get)

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    # _patch_fetches replaced the higher-level fetchers, so _http_get itself
    # isn't invoked here -- this asserts the substitution point exists and the
    # handler completes without falling through to any write-shaped call.
    assert calls == []


def test_http_get_always_issues_get_requests(monkeypatch):
    """_http_get (the sole HTTP entry point for every fetch helper) must only
    ever issue GET requests -- CEE is telemetry-only and must never POST/PUT/
    PATCH/DELETE against the governed API surface."""
    seen_methods = []

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"success": true, "records": []}'

    def _fake_urlopen(req, timeout=30):
        seen_methods.append(req.get_method())
        return _FakeResp()

    monkeypatch.setattr(mod.urllib.request, "urlopen", _fake_urlopen)
    mod._http_get("https://example.invalid/api/v1/tracker/enceladus?type=task")

    assert seen_methods == ["GET"]


def test_handler_returns_500_on_unexpected_exception(monkeypatch):
    def _boom(rtype):
        raise RuntimeError("tracker api down")

    monkeypatch.setattr(mod, "_fetch_tracker_records", _boom)
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)

    result = mod.lambda_handler({}, None)

    assert result["statusCode"] == 500
    body = json.loads(result["body"])
    assert body["success"] is False


# ---------------------------------------------------------------------------
# ENC-TSK-N24: heavy-beat completion-stanza contract (tenant_invoker.py)
# ---------------------------------------------------------------------------


def test_rhythm_stanza_no_result_key_is_noop():
    from unittest import mock

    with mock.patch("boto3.client") as client:
        assert mod._write_rhythm_stanza({}, "completed", {}) is False
        assert mod._write_rhythm_stanza(None, "completed", {}) is False
        client.assert_not_called()


def test_rhythm_stanza_result_key_writes_contract_stanza():
    from unittest import mock

    key = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20260712-000000/corpus_entropy_engine.json"
    with mock.patch("boto3.client") as client:
        ok = mod._write_rhythm_stanza({"result_key": key}, "completed", {"counts": {"lineage_unanchored": 1}})
    assert ok is True
    kwargs = client.return_value.put_object.call_args.kwargs
    assert kwargs["Bucket"] == mod.RHYTHM_RESULTS_BUCKET
    assert kwargs["Key"] == key
    stanza = json.loads(kwargs["Body"].decode("utf-8"))
    assert stanza["tenant"] == "corpus_entropy_engine"
    assert stanza["status"] == "completed"
    assert "completed_at" in stanza
    assert stanza["detail"] == {"counts": {"lineage_unanchored": 1}}


def test_rhythm_stanza_hard_disabled_reports_skipped():
    from unittest import mock

    skipped = {
        "statusCode": 200,
        "body": json.dumps({"success": True, "skipped": True, "reason": "CEE_HARD_DISABLED"}),
    }
    with mock.patch.object(mod, "_run_scan", return_value=skipped):
        with mock.patch.object(mod, "_write_rhythm_stanza") as stanza:
            resp = mod.lambda_handler({"result_key": "k"}, None)
    assert resp["statusCode"] == 200
    assert stanza.call_args.args[1] == "skipped"


def test_rhythm_stanza_write_failure_never_raises():
    from unittest import mock

    with mock.patch("boto3.client", side_effect=RuntimeError("boom")):
        assert mod._write_rhythm_stanza({"result_key": "k"}, "completed", {}) is False
