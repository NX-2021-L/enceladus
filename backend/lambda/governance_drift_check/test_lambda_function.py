"""Tests for governance_drift_check Lambda — ENC-TSK-I32 / ENC-FTR-116.

Covers:
  - No drift when the canonical record agrees with live S3
  - Drift on bundle-hash mismatch (per-file checksum change)
  - Drift when the canonical record is missing (fail-closed)
  - Drift when the recompute from live S3 fails (fail-closed)
  - The metric + SNS alert fire only on drift
  - Read-only: handler never writes DDB or S3
  - §4.3 bundle-hash contract pinned to the spec value (kept in sync with
    recompute_governance)
"""

import hashlib

import lambda_function as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _live(hash_="h_live", revision="2026-06-27.01", files=None):
    if files is None:
        files = [
            {
                "uri": "governance://agents.md",
                "s3_key": "governance/live/agents.md",
                "s3_version_id": "v1",
                "checksum_sha256_hex": "aabbcc",
            }
        ]
    return {"governance_hash": hash_, "governance_revision": revision, "files": files}


def _record(hash_="h_live", revision="2026-06-27.01", generation=1, files=None):
    if files is None:
        files = [
            {
                "uri": "governance://agents.md",
                "s3_key": "governance/live/agents.md",
                "s3_version_id": "v1",
                "checksum_sha256_hex": "aabbcc",
            }
        ]
    return {
        "governance_hash": hash_,
        "governance_revision": revision,
        "generation": generation,
        "files": files,
    }


def _patch_emit(monkeypatch):
    """Capture metric + alert emissions instead of calling AWS."""
    emitted = {"metric": [], "alerts": []}
    monkeypatch.setattr(mod, "_emit_metric", lambda drift: emitted["metric"].append(drift))
    monkeypatch.setattr(mod, "_publish_alert", lambda result: emitted["alerts"].append(result))
    return emitted


# ---------------------------------------------------------------------------
# detect_drift
# ---------------------------------------------------------------------------

def test_no_drift_when_record_agrees(monkeypatch):
    monkeypatch.setattr(mod, "_recompute_live_state", lambda: _live())
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: _record())

    result = mod.detect_drift()

    assert result["drift"] is False
    assert result["reason"] == "agree"
    assert result["hash_agrees"] is True
    assert result["mismatched_files"] == []


def test_drift_on_hash_mismatch(monkeypatch):
    live_files = [
        {
            "uri": "governance://agents.md",
            "s3_key": "governance/live/agents.md",
            "s3_version_id": "v2",
            "checksum_sha256_hex": "NEWSUM",
        }
    ]
    monkeypatch.setattr(mod, "_recompute_live_state", lambda: _live(hash_="h_new", files=live_files))
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: _record(hash_="h_old"))

    result = mod.detect_drift()

    assert result["drift"] is True
    assert result["reason"] == "hash_mismatch"
    assert result["hash_agrees"] is False
    assert "governance://agents.md" in result["mismatched_files"]


def test_drift_when_record_missing(monkeypatch):
    monkeypatch.setattr(mod, "_recompute_live_state", lambda: _live())
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: None)

    result = mod.detect_drift()

    assert result["drift"] is True
    assert result["reason"] == "record_missing"


def test_drift_when_recompute_fails(monkeypatch):
    def _boom():
        raise RuntimeError("S3 unavailable")

    monkeypatch.setattr(mod, "_recompute_live_state", _boom)
    # _read_canonical_record must not even be needed
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: (_ for _ in ()).throw(AssertionError))

    result = mod.detect_drift()

    assert result["drift"] is True
    assert result["reason"] == "recompute_failure"


def test_revision_bump_without_byte_change_is_not_silent(monkeypatch):
    """A revision change with identical bytes keeps hash agreement but is flagged."""
    monkeypatch.setattr(mod, "_recompute_live_state", lambda: _live(revision="2026-06-27.02"))
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: _record(revision="2026-06-27.01"))

    result = mod.detect_drift()

    # Hash still agrees (same checksums) so it is not hard drift, but the
    # revision disagreement is reported for the §4.6 dual-signal discipline.
    assert result["revision_agrees"] is False
    assert result["hash_agrees"] is True


# ---------------------------------------------------------------------------
# handler emissions
# ---------------------------------------------------------------------------

def test_handler_emits_metric_zero_and_no_alert_on_agreement(monkeypatch):
    emitted = _patch_emit(monkeypatch)
    monkeypatch.setattr(mod, "detect_drift", lambda: {"drift": False, "reason": "agree", "generation": 1, "record_governance_hash": "h"})

    mod.handler({}, None)

    assert emitted["metric"] == [False]
    assert emitted["alerts"] == []


def test_handler_emits_metric_one_and_alert_on_drift(monkeypatch):
    emitted = _patch_emit(monkeypatch)
    monkeypatch.setattr(
        mod, "detect_drift",
        lambda: {"drift": True, "reason": "hash_mismatch", "message": "boom"},
    )

    result = mod.handler({}, None)

    assert emitted["metric"] == [True]
    assert len(emitted["alerts"]) == 1
    assert result["reason"] == "hash_mismatch"


def test_handler_is_read_only(monkeypatch):
    """Handler must never write DDB or S3."""
    monkeypatch.setattr(mod, "_recompute_live_state", lambda: _live())
    monkeypatch.setattr(mod, "_read_canonical_record", lambda: _record())

    metric_calls = []

    class SafeCW:
        def put_metric_data(self, **kwargs):
            metric_calls.append(kwargs)

    class ForbiddenDDB:
        def put_item(self, **kwargs):
            raise AssertionError("drift check must not write DDB")

        def update_item(self, **kwargs):
            raise AssertionError("drift check must not write DDB")

    class ForbiddenS3:
        def put_object(self, **kwargs):
            raise AssertionError("drift check must not write S3")

    monkeypatch.setattr(mod, "_cw_client", SafeCW())
    monkeypatch.setattr(mod, "_ddb_client", ForbiddenDDB())
    monkeypatch.setattr(mod, "_s3_client", ForbiddenS3())
    monkeypatch.setattr(mod, "_publish_alert", lambda result: None)

    mod.handler({}, None)

    assert metric_calls and metric_calls[0]["MetricData"][0]["Value"] == 0.0


# ---------------------------------------------------------------------------
# §4.3 contract pin (must match recompute_governance byte-for-byte)
# ---------------------------------------------------------------------------

def test_bundle_hash_matches_spec():
    entries = [
        {"uri": "governance://agents.md", "checksum_sha256_hex": "aabbcc"},
        {"uri": "governance://agents/plan.md", "checksum_sha256_hex": "112233"},
    ]
    h = hashlib.sha256()
    for e in entries:
        h.update(e["uri"].encode())
        h.update(b"\n")
        h.update(e["checksum_sha256_hex"].encode())
        h.update(b"\n")
    assert mod._compute_bundle_hash(entries) == h.hexdigest()
