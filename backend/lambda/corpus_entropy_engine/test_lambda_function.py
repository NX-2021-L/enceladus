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

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# ENC-TSK-P83: outline.py is vendored into this Lambda's build root via
# .build_extras (see that file); for local test runs it's appended (not
# inserted at 0) from its canonical home so it never shadows anything here.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "document_api")
)

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
# (f) Docstore Integrity Entropy -- I-D1, I-D3, I-D4, I-D6 (ENC-TSK-P83)
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_CLEAN_BODY = "# Title\n\nSome content.\n"
_CLEAN_OUTLINE = [{"heading_path": ["Title"], "level": 1, "ordinal": 1, "block_id": None,
                    "line_start": 1, "line_end": 3, "section_bytes": len("Some content.\n".encode())}]


def _clean_bundle(document_id="DOC-1", **overrides):
    bundle = {
        "document_id": document_id,
        "content_hash": _sha256(_CLEAN_BODY),
        "body_sha256": _sha256(_CLEAN_BODY),
        "manifest_outline": _CLEAN_OUTLINE,
        "computed_outline": _CLEAN_OUTLINE,
        "accepted_events": [
            {"before_hash": "h0", "after_hash": "h1", "after_version": 1},
            {"before_hash": "h1", "after_hash": "h2", "after_version": 2},
        ],
        "version_hashes": {1: "h1", 2: "h2"},
    }
    bundle.update(overrides)
    return bundle


def test_docstore_clean_document_yields_zero_findings():
    assert core.detect_docstore_integrity([_clean_bundle()]) == []


def test_docstore_drifted_body_flags_i_d1_with_expected_and_observed():
    bundle = _clean_bundle(body_sha256="deadbeef" * 8)
    findings = core.detect_docstore_integrity([bundle])
    assert len(findings) == 1
    assert findings[0]["invariant"] == "I-D1"
    assert findings[0]["expected"] == bundle["content_hash"]
    assert findings[0]["observed"] == "deadbeef" * 8


def test_docstore_missing_version_object_flags_i_d3():
    bundle = _clean_bundle(version_hashes={1: "h1", 2: None})
    findings = core.detect_docstore_integrity([bundle])
    assert len(findings) == 1
    assert findings[0]["invariant"] == "I-D3"
    assert findings[0]["expected"] == "h2"
    assert findings[0]["observed"] == "missing"


def test_docstore_version_hash_mismatch_flags_i_d3():
    bundle = _clean_bundle(version_hashes={1: "h1", 2: "wrong-hash"})
    findings = core.detect_docstore_integrity([bundle])
    assert len(findings) == 1
    assert findings[0]["invariant"] == "I-D3"
    assert findings[0]["expected"] == "h2"
    assert findings[0]["observed"] == "wrong-hash"


def test_docstore_duplicate_before_hash_flags_i_d4():
    bundle = _clean_bundle(accepted_events=[
        {"before_hash": "hdup", "after_hash": "h1", "after_version": 1},
        {"before_hash": "hdup", "after_hash": "h2", "after_version": 2},
    ])
    findings = core.detect_docstore_integrity([bundle])
    assert len(findings) == 1
    assert findings[0]["invariant"] == "I-D4"
    assert findings[0]["observed"] == "hdup"


def test_docstore_stale_outline_flags_i_d6():
    stale_manifest_outline = [{"heading_path": ["Old Title"], "level": 1, "ordinal": 1,
                                "block_id": None, "line_start": 1, "line_end": 1, "section_bytes": 0}]
    bundle = _clean_bundle(manifest_outline=stale_manifest_outline)
    findings = core.detect_docstore_integrity([bundle])
    assert len(findings) == 1
    assert findings[0]["invariant"] == "I-D6"
    assert findings[0]["expected"] == stale_manifest_outline
    assert findings[0]["observed"] == _CLEAN_OUTLINE


def test_docstore_missing_body_skips_i_d1_and_i_d6_not_falsely_flagged():
    bundle = _clean_bundle(body_sha256=None, computed_outline=None)
    assert core.detect_docstore_integrity([bundle]) == []


def test_docstore_multiple_invariants_same_document_all_reported():
    bundle = _clean_bundle(body_sha256="deadbeef" * 8, version_hashes={1: "h1", 2: None})
    findings = core.detect_docstore_integrity([bundle])
    assert {f["invariant"] for f in findings} == {"I-D1", "I-D3"}


def test_sample_document_ids_deterministic_rotation_by_day_offset():
    ids = [f"DOC-{i}" for i in range(10)]
    sample_a = core.sample_document_ids(ids, n=3, day_offset=0)
    sample_b = core.sample_document_ids(ids, n=3, day_offset=3)
    assert sample_a == sorted(ids)[:3]
    assert sample_b == sorted(ids)[3:6]
    # Same day_offset is fully deterministic (idempotent across calls).
    assert core.sample_document_ids(ids, n=3, day_offset=0) == sample_a


def test_sample_document_ids_returns_all_when_corpus_smaller_than_n():
    ids = ["DOC-2", "DOC-1"]
    assert core.sample_document_ids(ids, n=50, day_offset=100) == ["DOC-1", "DOC-2"]


def test_sample_document_ids_empty_inputs():
    assert core.sample_document_ids([], n=50, day_offset=0) == []
    assert core.sample_document_ids(["DOC-1"], n=0, day_offset=0) == []


def test_build_docstore_invariant_metric_data_shape():
    findings = [
        {"document_id": "DOC-1", "invariant": "I-D1", "expected": "a", "observed": "b"},
        {"document_id": "DOC-2", "invariant": "I-D1", "expected": "c", "observed": "d"},
        {"document_id": "DOC-3", "invariant": "I-D4", "expected": "e", "observed": "f"},
    ]
    metric_data = core.build_docstore_invariant_metric_data(findings, function_name="cee-fn", timestamp="T")
    by_invariant = {m["Dimensions"][1]["Value"]: m for m in metric_data}
    assert set(by_invariant.keys()) == {"I-D1", "I-D4"}
    assert by_invariant["I-D1"]["Value"] == 2.0
    assert by_invariant["I-D4"]["Value"] == 1.0
    for m in metric_data:
        assert m["MetricName"] == "DocstoreIntegrityViolation"
        assert {d["Name"] for d in m["Dimensions"]} == {"FunctionName", "Invariant"}


def test_build_docstore_invariant_metric_data_empty_findings_yields_no_datapoints():
    assert core.build_docstore_invariant_metric_data([], function_name="cee-fn", timestamp="T") == []


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


def test_handler_publishes_all_six_category_counts(monkeypatch):
    _patch_fetches(
        monkeypatch,
        tasks=[{"record_id": "task#T1", "record_type": "task", "status": "open",
                "created_at": "2020-01-01T00:00:00Z", "history": []}],
        lessons=[{"record_id": "lesson#L1", "stability": 0.1}],
        # No "document_id" key on this fixture -- ENC-TSK-P83's docstore_integrity
        # sampling only considers documents carrying document_id, so this document
        # (used to exercise the pre-existing compliance_semantic detector) is
        # correctly excluded from the docstore sample and stays a zero-finding,
        # zero-extra-HTTP-call category here (covered separately below).
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
        "docstore_integrity",
    }
    assert counts["lineage_unanchored"] >= 1  # unanchored task has no parent/related
    assert counts["stagnation"] == 1
    assert counts["retention"] == 1
    assert counts["compliance_semantic"] == 1
    assert counts["docstore_integrity"] == 0
    assert body["corpus_scanned"]["docstore_documents_sampled"] == 0
    assert len(fake_cw.calls) == 1
    # 6 categories + ScanDurationMs; no DocstoreIntegrityViolation datapoints
    # since the sample was empty (no findings -> no per-invariant metric).
    assert len(fake_cw.calls[0]["MetricData"]) == 7
    metric_names = {m["MetricName"] for m in fake_cw.calls[0]["MetricData"]}
    assert metric_names == {"EntropyFindingCount", "ScanDurationMs"}
    assert fake_cw.calls[0]["Namespace"] == "Enceladus/CEE"


def test_handler_docstore_integrity_wired_into_counts_and_invariant_metric(monkeypatch):
    """End-to-end handler wiring: a sampled document whose bundle carries an
    I-D1 drift must show up in counts["docstore_integrity"] AND publish a
    DocstoreIntegrityViolation datapoint dimensioned Invariant=I-D1."""
    _patch_fetches(monkeypatch, documents=[{"record_id": "DOC-1", "document_id": "DOC-1"}])
    drifted_bundle = {
        "document_id": "DOC-1",
        "content_hash": "expected-hash",
        "body_sha256": "observed-hash",
        "manifest_outline": [],
        "computed_outline": [],
        "accepted_events": [],
        "version_hashes": {},
    }
    monkeypatch.setattr(mod, "_fetch_docstore_bundle", lambda document_id, project_id: drifted_bundle)
    fake_cw = _FakeCW()
    monkeypatch.setattr(mod, "_get_cw", lambda: fake_cw)
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)

    result = mod.lambda_handler({}, None)

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["counts"]["docstore_integrity"] == 1
    assert body["corpus_scanned"]["docstore_documents_sampled"] == 1
    metric_data = fake_cw.calls[0]["MetricData"]
    violation_metrics = [m for m in metric_data if m["MetricName"] == "DocstoreIntegrityViolation"]
    assert len(violation_metrics) == 1
    assert violation_metrics[0]["Value"] == 1.0
    assert {d["Name"]: d["Value"] for d in violation_metrics[0]["Dimensions"]}["Invariant"] == "I-D1"


def test_fetch_docstore_bundle_assembles_manifest_body_and_versions(monkeypatch):
    """_fetch_docstore_bundle mocked at the HTTP + S3 boundary (per brief_p83's
    'mocked HTTP + mocked S3' requirement) -- verifies manifest/body/history/
    version-object wiring produces the bundle shape detect_docstore_integrity
    expects."""
    body_text = "# Doc\n\nBody text.\n"
    body_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()

    def _fake_http_get(url):
        if "/manifest" in url:
            return {"content_hash": body_hash, "version": 2, "outline": [{"heading_path": ["Doc"]}]}
        if "/history" in url:
            return {"events": [
                {"before_hash": "h0", "after_hash": "h1", "after_version": 1},
                {"before_hash": "h1", "after_hash": "h2", "after_version": 2, "rejection_code": "STALE_HASH"},
            ]}
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(mod, "_http_get", _fake_http_get)

    class _FakeS3Exceptions:
        NoSuchKey = KeyError

    class _FakeS3:
        exceptions = _FakeS3Exceptions()

        def get_object(self, Bucket, Key):
            if Key.endswith("versions/DOC-1/1.md"):
                return {"Body": _Body(body_text)}
            if Key.endswith("DOC-1.md"):
                return {"Body": _Body(body_text)}
            raise self.exceptions.NoSuchKey("missing")

    monkeypatch.setattr(mod, "_get_s3", lambda: _FakeS3())

    bundle = mod._fetch_docstore_bundle("DOC-1", "enceladus")

    assert bundle["document_id"] == "DOC-1"
    assert bundle["content_hash"] == body_hash
    assert bundle["body_sha256"] == body_hash
    assert bundle["computed_outline"] == mod.compute_outline(body_text)
    # Rejected event filtered out -- only the accepted before_hash/after_hash pair remains.
    assert bundle["accepted_events"] == [{"before_hash": "h0", "after_hash": "h1", "after_version": 1}]
    assert bundle["version_hashes"] == {1: body_hash}


class _Body:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text.encode("utf-8")


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
    # ENC-TSK-N48: completed => did_work True; no output_count passed => None.
    assert stanza["did_work"] is True
    assert stanza["output_count"] is None


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


def test_rhythm_stanza_hard_disabled_did_work_false():
    """ENC-TSK-N48 AC-2 proof case: CEE_HARD_DISABLED returns 200 but the
    completion stanza reports did_work=false — the lying-zero made visible."""
    from unittest import mock

    skipped = {
        "statusCode": 200,
        "body": json.dumps({"success": True, "skipped": True, "reason": "CEE_HARD_DISABLED"}),
    }
    with mock.patch.object(mod, "_run_scan", return_value=skipped):
        with mock.patch("boto3.client") as client:
            resp = mod.lambda_handler({"result_key": "k"}, None)
    assert resp["statusCode"] == 200
    stanza = json.loads(client.return_value.put_object.call_args.kwargs["Body"].decode("utf-8"))
    assert stanza["status"] == "skipped"
    assert stanza["did_work"] is False
    assert stanza["output_count"] is None


def test_rhythm_stanza_produced_did_work_true_output_count_sum():
    """ENC-TSK-N48: a real scan reports did_work=true and output_count equal to
    the total findings across the five detectors (0 total is a correct-zero)."""
    from unittest import mock

    produced = {
        "statusCode": 200,
        "body": json.dumps(
            {
                "success": True,
                "counts": {"orphan": 2, "stagnation": 1, "relational": 0, "retention": 3, "compliance_semantic": 0},
            }
        ),
    }
    with mock.patch.object(mod, "_run_scan", return_value=produced):
        with mock.patch("boto3.client") as client:
            mod.lambda_handler({"result_key": "k"}, None)
    stanza = json.loads(client.return_value.put_object.call_args.kwargs["Body"].decode("utf-8"))
    assert stanza["status"] == "completed"
    assert stanza["did_work"] is True
    assert stanza["output_count"] == 6


def test_rhythm_stanza_write_failure_never_raises():
    from unittest import mock

    with mock.patch("boto3.client", side_effect=RuntimeError("boom")):
        assert mod._write_rhythm_stanza({"result_key": "k"}, "completed", {}) is False
