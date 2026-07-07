"""Tests for GDMP Stage-1 auto-remediation -- ENC-TSK-K42 / B66 Ph5.

Two layers, mirroring corpus_entropy_engine/test_lambda_function.py and
unlearning/test_unlearning.py conventions in this repo:

  1. Pure-function tests against gdmp_remediation_core (no AWS, no HTTP) --
     warning classification, deterministic content fixers, remediation
     planning, idempotency guard, and the io-approval ramp gate.
  2. Handler-level tests against lambda_function, monkeypatching the governed
     HTTP fetch/patch functions and the S3 run-counter so no real network/AWS
     call is made. Includes a kill-switch test and a "never mutates when
     mutation not allowed" guard.

Runs under pytest (test_* discovery). corpus_entropy_core.py is provided at
collection time via sys.path (co-located at repo path during local test runs;
copied to the function root by _build.yml's .build_extras step at deploy time).
"""

import json
import os
import sys

# Own directory takes priority so `lambda_function` resolves to THIS Lambda's
# handler, not corpus_entropy_engine's. corpus_entropy_core.py is co-located
# at the function root in the deployed artifact (via .build_extras); for local
# test runs it's appended (not inserted at 0) so it never shadows this dir's
# own lambda_function.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.append(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "corpus_entropy_engine"
    )
)

import gdmp_remediation_core as core  # noqa: E402
import lambda_function as mod  # noqa: E402


# ---------------------------------------------------------------------------
# Warning classification (DATA-SAFETY whitelist)
# ---------------------------------------------------------------------------

def test_fence_missing_language_is_classified_deterministic():
    result = core.classify_warning("Code fence at line 12 should include a language identifier.")
    assert result == {"class": "fence_missing_language", "line": 12}


def test_metadata_field_missing_is_classified_deterministic():
    result = core.classify_warning("Metadata block missing '**Author**:' near top of document.")
    assert result == {"class": "metadata_field_missing", "field": "Author"}


def test_title_format_warning_is_ambiguous_not_classified():
    assert core.classify_warning("Title should follow '# {ITEM_ID} Title' (e.g., '# DVP-TSK-123 Name').") is None


def test_empty_document_warning_is_ambiguous_not_classified():
    assert core.classify_warning("Document is empty.") is None


def test_heading_hierarchy_warning_is_ambiguous_not_classified():
    assert core.classify_warning("Heading level jump detected at line 5 (h1 -> h3).") is None


def test_unclosed_fence_warning_is_ambiguous_not_classified():
    assert core.classify_warning("Unclosed code fence opened at line 3.") is None


def test_partition_warnings_splits_deterministic_and_ambiguous():
    warnings = [
        "Code fence at line 4 should include a language identifier.",
        "Document is empty.",
        "Metadata block missing '**Project**:' near top of document.",
    ]
    result = core.partition_warnings(warnings)
    assert len(result["deterministic"]) == 2
    assert result["ambiguous"] == ["Document is empty."]


# ---------------------------------------------------------------------------
# Deterministic fixers -- additive, idempotent
# ---------------------------------------------------------------------------

def test_fix_fence_missing_language_adds_default_language():
    content = "# Doc\n\n```\ncode here\n```\n"
    fixed = core._fix_fence_missing_language(content)
    assert "```text\ncode here\n```" in fixed


def test_fix_fence_missing_language_leaves_tagged_fence_untouched():
    content = "# Doc\n\n```python\ncode here\n```\n"
    assert core._fix_fence_missing_language(content) == content


def test_fix_fence_missing_language_is_idempotent():
    content = "# Doc\n\n```\ncode here\n```\n"
    once = core._fix_fence_missing_language(content)
    twice = core._fix_fence_missing_language(once)
    assert once == twice


def test_fix_metadata_field_missing_inserts_placeholder_after_title():
    content = "# ENC-TSK-K42 Title\n\nSome body text.\n"
    fixed = core._fix_metadata_field_missing(content, "Author")
    lines = fixed.splitlines()
    assert lines[0] == "# ENC-TSK-K42 Title"
    assert "**Author**: TBD" in fixed
    assert "Some body text." in fixed


def test_fix_metadata_field_missing_is_idempotent():
    content = "# ENC-TSK-K42 Title\n\nBody.\n"
    once = core._fix_metadata_field_missing(content, "Project")
    twice = core._fix_metadata_field_missing(once, "Project")
    assert once == twice


def test_fix_metadata_field_missing_noop_when_field_already_present():
    content = "# Title\n\n**Author**: io\n\nBody.\n"
    assert core._fix_metadata_field_missing(content, "Author") == content


def test_remediate_content_applies_both_fixer_classes():
    content = "# Doc\n\n```\ncode\n```\n"
    findings = [
        {"class": "fence_missing_language", "line": 3, "warning": "..."},
        {"class": "metadata_field_missing", "field": "Project", "warning": "..."},
    ]
    remediated = core.remediate_content(content, findings)
    assert "```text" in remediated
    assert "**Project**: TBD" in remediated


def test_remediate_content_never_deletes_original_text():
    content = "# Doc\n\nOriginal important sentence.\n\n```\ncode\n```\n"
    findings = [{"class": "fence_missing_language", "line": 5, "warning": "..."}]
    remediated = core.remediate_content(content, findings)
    assert "Original important sentence." in remediated


# ---------------------------------------------------------------------------
# Remediation planning
# ---------------------------------------------------------------------------

def test_plan_remediation_noop_when_no_warnings():
    plan = core.plan_remediation({"record_id": "DOC-1", "compliance_warnings": []})
    assert plan["action"] == "noop"


def test_plan_remediation_agent_review_when_all_ambiguous():
    plan = core.plan_remediation({
        "record_id": "DOC-2",
        "compliance_warnings": ["Document is empty."],
    })
    assert plan["action"] == "agent_review"
    assert plan["ambiguous_warnings"] == ["Document is empty."]


def test_plan_remediation_full_remediate_when_all_deterministic():
    plan = core.plan_remediation({
        "record_id": "DOC-3",
        "compliance_warnings": [
            "Code fence at line 2 should include a language identifier.",
        ],
    })
    assert plan["action"] == "remediate"
    assert len(plan["deterministic_findings"]) == 1


def test_plan_remediation_partial_when_mixed():
    plan = core.plan_remediation({
        "record_id": "DOC-4",
        "compliance_warnings": [
            "Code fence at line 2 should include a language identifier.",
            "Document is empty.",
        ],
    })
    assert plan["action"] == "partial_remediate"
    assert len(plan["deterministic_findings"]) == 1
    assert len(plan["ambiguous_warnings"]) == 1


# ---------------------------------------------------------------------------
# Idempotency guard (AC-4)
# ---------------------------------------------------------------------------

def test_already_compliant_maturity_is_idempotent_noop():
    doc = {"document_maturity_state": "compliant", "compliance_warnings": ["stale warning"]}
    assert core.is_already_compliant(doc) is True


def test_zero_warnings_is_idempotent_noop_even_if_raw():
    doc = {"document_maturity_state": "raw", "compliance_warnings": []}
    assert core.is_already_compliant(doc) is True


def test_raw_with_warnings_is_not_idempotent_noop():
    doc = {"document_maturity_state": "raw", "compliance_warnings": ["Document is empty."]}
    assert core.is_already_compliant(doc) is False


# ---------------------------------------------------------------------------
# io-approval ramp (FTR-106 AC-4 pattern reuse)
# ---------------------------------------------------------------------------

def test_io_approval_ramp_active_below_threshold():
    assert core.io_approval_ramp_active(0) is True
    assert core.io_approval_ramp_active(2) is True


def test_io_approval_ramp_inactive_at_threshold():
    assert core.io_approval_ramp_active(3) is False
    assert core.io_approval_ramp_active(4) is False


def test_mutation_never_allowed_during_dry_run():
    assert core.mutation_allowed(run_count=10, dry_run=True, mutation_enabled=True) is False


def test_mutation_never_allowed_when_mutation_disabled():
    assert core.mutation_allowed(run_count=10, dry_run=False, mutation_enabled=False) is False


def test_mutation_blocked_during_ramp_even_if_enabled():
    assert core.mutation_allowed(run_count=1, dry_run=False, mutation_enabled=True) is False


def test_mutation_allowed_after_ramp_when_enabled_and_not_dry_run():
    assert core.mutation_allowed(run_count=3, dry_run=False, mutation_enabled=True) is True


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------

def test_hard_disabled_true_variants():
    for val in ("1", "true", "True", "YES", "yes"):
        assert core.is_hard_disabled({"CEE_GDMP_HARD_DISABLED": val}) is True


def test_hard_disabled_false_when_unset_or_zero():
    assert core.is_hard_disabled({}) is False
    assert core.is_hard_disabled({"CEE_GDMP_HARD_DISABLED": "0"}) is False


# ---------------------------------------------------------------------------
# Handler-level tests (mock HTTP + S3, never touch AWS/network)
# ---------------------------------------------------------------------------

class _FakeS3:
    def __init__(self, initial_counter=None):
        self._store = {}
        if initial_counter is not None:
            self._store["gdmp-remediation-state/run_counter.json"] = json.dumps(
                {"run_count": initial_counter}
            ).encode("utf-8")

    def get_object(self, Bucket, Key):
        if Key not in self._store:
            raise KeyError(Key)
        import io
        return {"Body": io.BytesIO(self._store[Key])}

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self._store[Key] = Body if isinstance(Body, bytes) else Body.encode("utf-8")


def test_handler_gdmp_hard_disabled_reports_but_never_mutates(monkeypatch):
    """ENC-TSK-L91: CEE_GDMP_HARD_DISABLED gates MUTATION only. Even with the
    ramp cleared + dry_run off + mutation enabled (i.e. it WOULD mutate), the
    disarm must block every _patch_document, must NOT advance the io-approval
    ramp counter, yet must still run the candidate scan and persist the per-run
    breakdown so the soak is auditable."""
    monkeypatch.setenv("CEE_GDMP_HARD_DISABLED", "1")
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)

    import gdmp_remediation_core as gcore
    monkeypatch.setattr(gcore, "GDMP_DRY_RUN", False)
    monkeypatch.setattr(gcore, "GDMP_MUTATION_ENABLED", True)
    monkeypatch.setattr(mod, "is_dry_run", lambda event=None: False)
    monkeypatch.setattr(mod, "mutation_allowed", lambda **kw: gcore.mutation_allowed(
        run_count=kw["run_count"], dry_run=False, mutation_enabled=True
    ))
    monkeypatch.setattr(mod, "_fetch_documents", lambda: [
        {
            "record_id": "DOC-RAW-DISARM",
            "compliance_score": 40,
            "document_maturity_state": "raw",
            "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        },
    ])

    def _boom_patch(*args, **kwargs):
        raise AssertionError("must not PATCH while CEE_GDMP_HARD_DISABLED=1")

    def _boom_counter(*args, **kwargs):
        raise AssertionError("must not advance io-approval ramp while disarmed")

    monkeypatch.setattr(mod, "_patch_document", _boom_patch)
    monkeypatch.setattr(mod, "_save_run_counter", _boom_counter)
    monkeypatch.setattr(mod, "GDMP_STATE_BUCKET", "fake-bucket")
    fake = _FakeS3(initial_counter=3)  # ramp already cleared -> would mutate if armed
    monkeypatch.setattr(mod, "_get_s3", lambda: fake)

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["mutation_hard_disabled"] is True
    assert body["mutation_allowed"] is False
    assert body["remediated_count"] == 0
    assert body["candidate_count"] == 1  # scan still ran
    assert body["breakdown_ref"] is not None
    assert body["breakdown_totals"]["candidates"] == 1
    # breakdown persisted to S3 (timestamped record + stable latest.json)
    assert any(k.endswith("breakdowns/latest.json") for k in fake._store)
    assert any("/breakdowns/run-" in k for k in fake._store)
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)


def test_handler_shared_cee_hard_disabled_short_circuits(monkeypatch):
    """The shared engine-wide CEE_HARD_DISABLED cost kill switch (ISS-465) still
    fully short-circuits the run: no document fetch, no scan, skipped=True."""
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)
    monkeypatch.setenv("CEE_HARD_DISABLED", "1")

    def _boom(*args, **kwargs):
        raise AssertionError("must not fetch when CEE_HARD_DISABLED is set")

    monkeypatch.setattr(mod, "_fetch_documents", _boom)
    result = mod.lambda_handler({}, None)

    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["skipped"] is True
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)


def test_concurrency_recompute_skips_when_fresh_doc_findings_differ(monkeypatch):
    """ENC-TSK-L91 optimistic-concurrency guard: the queued plan (from the
    run-start scan) had a deterministic auto-fixable warning, but the pre-PATCH
    fresh GET shows the doc now carries only an AMBIGUOUS warning (a concurrent
    human edit changed it). The handler must recompute from the fresh doc and
    SKIP -- never apply the stale deterministic fix onto the changed content."""
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)
    monkeypatch.delenv("CEE_HARD_DISABLED", raising=False)
    import gdmp_remediation_core as gcore
    monkeypatch.setattr(gcore, "GDMP_DRY_RUN", False)
    monkeypatch.setattr(gcore, "GDMP_MUTATION_ENABLED", True)
    monkeypatch.setattr(mod, "is_dry_run", lambda event=None: False)
    monkeypatch.setattr(mod, "mutation_allowed", lambda **kw: gcore.mutation_allowed(
        run_count=kw["run_count"], dry_run=False, mutation_enabled=True))
    # Stale scan: deterministic (auto-fixable) fence warning -> plan=remediate.
    monkeypatch.setattr(mod, "_fetch_documents", lambda: [
        {
            "record_id": "DOC-RACE",
            "compliance_score": 40,
            "document_maturity_state": "raw",
            "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        },
    ])
    # Fresh pre-PATCH GET: still raw + still non-compliant (so the idempotency
    # guard does NOT short-circuit), but the warning is now ambiguous-only, so a
    # fresh plan yields NO deterministic findings.
    monkeypatch.setattr(mod, "_fetch_document_with_content", lambda doc_id: {
        "record_id": doc_id,
        "document_maturity_state": "raw",
        "compliance_score": 45,
        "compliance_warnings": ["Document appears to be empty or contains only whitespace."],
        "content": "# Doc\n\nedited by a human mid-run\n",
    })

    def _boom_patch(*args, **kwargs):
        raise AssertionError("must not apply stale deterministic fix to fresh content")

    monkeypatch.setattr(mod, "_patch_document", _boom_patch)
    monkeypatch.setattr(mod, "GDMP_STATE_BUCKET", "fake-bucket")
    monkeypatch.setattr(mod, "_get_s3", lambda: _FakeS3(initial_counter=3))

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["remediated_count"] == 0
    assert body["skipped_idempotent_count"] == 1


def test_handler_dry_run_default_never_patches(monkeypatch):
    """Dry-run default-on (AC-3): the handler must never call _patch_document
    even when deterministic candidates exist, unless dry_run is explicitly off
    AND mutation_enabled AND the io-approval ramp has cleared."""
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)
    monkeypatch.setattr(mod, "_fetch_documents", lambda: [
        {
            "record_id": "DOC-RAW1",
            "compliance_score": 40,
            "document_maturity_state": "raw",
            "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        },
    ])

    def _boom_patch(*args, **kwargs):
        raise AssertionError("must not PATCH during dry-run")

    monkeypatch.setattr(mod, "_patch_document", _boom_patch)
    monkeypatch.setattr(mod, "_get_s3", lambda: _FakeS3())

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["dry_run"] is True
    assert body["mutation_allowed"] is False
    assert body["remediated_count"] == 0
    assert body["candidate_count"] == 1


def test_handler_remediates_when_ramp_cleared_and_mutation_enabled(monkeypatch):
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)

    # GDMP_DRY_RUN / GDMP_MUTATION_ENABLED are read once at gdmp_remediation_core
    # import time, so patch the already-imported module's constants directly
    # (and the handler's imported references to is_dry_run/mutation_allowed)
    # rather than relying on env vars + a re-import.
    import gdmp_remediation_core as gcore
    monkeypatch.setattr(gcore, "GDMP_DRY_RUN", False)
    monkeypatch.setattr(gcore, "GDMP_MUTATION_ENABLED", True)
    monkeypatch.setattr(mod, "is_dry_run", lambda event=None: False)
    monkeypatch.setattr(mod, "mutation_allowed", lambda **kw: gcore.mutation_allowed(
        run_count=kw["run_count"], dry_run=False, mutation_enabled=True
    ))

    monkeypatch.setattr(mod, "_fetch_documents", lambda: [
        {
            "record_id": "DOC-RAW2",
            "compliance_score": 40,
            "document_maturity_state": "raw",
            "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        },
    ])
    monkeypatch.setattr(mod, "_fetch_document_with_content", lambda doc_id: {
        "record_id": doc_id,
        "document_maturity_state": "raw",
        "compliance_score": 40,
        "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        "content": "# Doc\n\n```\ncode\n```\n",
    })

    patch_calls = []

    def _fake_patch(document_id, body):
        patch_calls.append((document_id, body))
        if "content" in body:
            return {
                "success": True,
                "document": {
                    "compliance_score": 100,
                    "compliance_warnings": [],
                },
            }
        return {"success": True, "document": {"document_maturity_state": "compliant"}}

    monkeypatch.setattr(mod, "_patch_document", _fake_patch)
    monkeypatch.setattr(mod, "GDMP_STATE_BUCKET", "fake-bucket")
    monkeypatch.setattr(mod, "_get_s3", lambda: _FakeS3(initial_counter=3))

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["remediated_count"] == 1
    assert body["applied"][0]["after_compliance_score"] == 100
    assert body["applied"][0]["advanced_to_compliant"] is True
    # Two PATCH calls: one for content, one for document_maturity_state.
    assert len(patch_calls) == 2
    assert patch_calls[0][1] == {"content": "# Doc\n\n```text\ncode\n```\n"}
    assert patch_calls[1][1] == {"document_maturity_state": "compliant"}


def test_handler_idempotent_skip_when_already_compliant(monkeypatch):
    """AC-4: re-running Stage-1 on an already-compliant document is a no-op."""
    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)
    monkeypatch.setattr(mod, "_fetch_documents", lambda: [
        {
            "record_id": "DOC-RAW3",
            "compliance_score": 40,
            "document_maturity_state": "raw",
            "compliance_warnings": ["Code fence at line 2 should include a language identifier."],
        },
    ])
    # Simulate the document having *already* been remediated by a concurrent
    # run by the time this run fetches full content (maturity flipped).
    monkeypatch.setattr(mod, "_fetch_document_with_content", lambda doc_id: {
        "record_id": doc_id,
        "document_maturity_state": "compliant",
        "compliance_score": 100,
        "compliance_warnings": [],
        "content": "# Doc\n\n```text\ncode\n```\n",
    })

    def _boom_patch(*args, **kwargs):
        raise AssertionError("must not PATCH an already-compliant document")

    monkeypatch.setattr(mod, "_patch_document", _boom_patch)
    monkeypatch.setattr(mod, "mutation_allowed", lambda **kw: True)
    monkeypatch.setattr(mod, "_get_s3", lambda: _FakeS3(initial_counter=5))

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["remediated_count"] == 0
    assert body["skipped_idempotent_count"] == 1


def test_handler_returns_500_on_unexpected_exception(monkeypatch):
    def _boom():
        raise RuntimeError("document api down")

    monkeypatch.delenv("CEE_GDMP_HARD_DISABLED", raising=False)
    monkeypatch.setattr(mod, "_fetch_documents", _boom)

    result = mod.lambda_handler({}, None)
    assert result["statusCode"] == 500
    body = json.loads(result["body"])
    assert body["success"] is False


def test_http_request_get_uses_get_method(monkeypatch):
    seen_methods = []

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"success": true, "documents": []}'

    def _fake_urlopen(req, timeout=30):
        seen_methods.append(req.get_method())
        return _FakeResp()

    monkeypatch.setattr(mod.urllib.request, "urlopen", _fake_urlopen)
    mod._http_request("https://example.invalid/api/v1/documents/search", method="GET")
    assert seen_methods == ["GET"]


def test_http_request_patch_uses_patch_method(monkeypatch):
    seen_methods = []

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"success": true}'

    def _fake_urlopen(req, timeout=30):
        seen_methods.append(req.get_method())
        return _FakeResp()

    monkeypatch.setattr(mod.urllib.request, "urlopen", _fake_urlopen)
    mod._http_request(
        "https://example.invalid/api/v1/documents/DOC-1", method="PATCH", body={"content": "x"}
    )
    assert seen_methods == ["PATCH"]
