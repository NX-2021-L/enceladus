"""Tests for recompute_governance Lambda — ENC-TSK-I27.

Covers:
  - One generation increment per qualifying change
  - Idempotency: same sequencer yields no DDB write
  - CAS concurrent-write safety: lost race returns without error
  - Recursion-safety: handler never calls S3 PutObject
  - Non-canonical key is silently skipped
"""

import json

import lambda_function as mod


def _make_s3_event(key: str, sequencer: str = "AAAA", version_id: str = "v1") -> dict:
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": mod.S3_BUCKET},
                    "object": {
                        "key": key,
                        "versionId": version_id,
                        "sequencer": sequencer,
                    },
                },
            }
        ]
    }


def _make_sns_wrapped_event(key: str, sequencer: str = "AAAA", version_id: str = "v1") -> dict:
    """S3 -> SNS -> Lambda delivery: the S3 event is a JSON string in Sns.Message.

    This is the real cross-region relay shape (governance bucket us-west-1, Lambda
    us-west-2). ENC-ISS-390 e2e.
    """
    inner = _make_s3_event(key, sequencer=sequencer, version_id=version_id)
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {
                    "Type": "Notification",
                    "Message": json.dumps(inner),
                },
            }
        ]
    }


def _stub_canonical(monkeypatch, files=None):
    """Monkeypatch _list_canonical_files + _get_file_checksum + _read_governance_revision."""
    if files is None:
        files = [("governance://agents.md", "governance/live/agents.md")]

    monkeypatch.setattr(mod, "_list_canonical_files", lambda: files)

    checksums = {s3_key: (f"deadbeef{i:056x}", f"vid-{i}") for i, (_, s3_key) in enumerate(files)}
    monkeypatch.setattr(mod, "_get_file_checksum", lambda key: checksums[key])
    monkeypatch.setattr(mod, "_read_governance_revision", lambda key: "2026-06-27.01")


def test_first_write_increments_to_generation_1(monkeypatch):
    _stub_canonical(monkeypatch)

    written = {}

    monkeypatch.setattr(mod, "_read_current_record", lambda: None)
    monkeypatch.setattr(
        mod,
        "_cas_write",
        lambda *, governance_revision, governance_hash, generation, file_entries, source_event, expected_cas: (
            written.update({"generation": generation, "expected_cas": expected_cas}) or True
        ),
    )

    mod.handler(_make_s3_event("governance/live/agents.md", sequencer="SEQ1"), None)

    assert written["generation"] == 1
    assert written["expected_cas"] is None


def test_generation_increments_on_each_change(monkeypatch):
    _stub_canonical(monkeypatch)

    monkeypatch.setattr(
        mod,
        "_read_current_record",
        lambda: {"generation": 5, "cas_version": 5, "source_event": {"s3_sequencer": "OLDSEQ"}},
    )

    written = {}
    monkeypatch.setattr(
        mod,
        "_cas_write",
        lambda *, governance_revision, governance_hash, generation, file_entries, source_event, expected_cas: (
            written.update({"generation": generation, "expected_cas": expected_cas}) or True
        ),
    )

    mod.handler(_make_s3_event("governance/live/agents.md", sequencer="NEWSEQ"), None)

    assert written["generation"] == 6
    assert written["expected_cas"] == 5


def test_same_sequencer_is_idempotent(monkeypatch):
    _stub_canonical(monkeypatch)

    monkeypatch.setattr(
        mod,
        "_read_current_record",
        lambda: {"generation": 3, "cas_version": 3, "source_event": {"s3_sequencer": "DUPSEQ"}},
    )

    cas_write_calls = []
    monkeypatch.setattr(
        mod, "_cas_write",
        lambda **kwargs: cas_write_calls.append(kwargs) or True,
    )

    mod.handler(_make_s3_event("governance/live/agents.md", sequencer="DUPSEQ"), None)

    assert not cas_write_calls, "No DDB write expected for duplicate sequencer"


def test_cas_race_does_not_raise(monkeypatch):
    _stub_canonical(monkeypatch)

    monkeypatch.setattr(
        mod,
        "_read_current_record",
        lambda: {"generation": 10, "cas_version": 10, "source_event": {"s3_sequencer": "OLD"}},
    )
    monkeypatch.setattr(mod, "_cas_write", lambda **kwargs: False)

    # Must not raise even when CAS write returns False (lost race)
    mod.handler(_make_s3_event("governance/live/agents.md", sequencer="NEW"), None)


def test_non_canonical_key_skipped(monkeypatch):
    _stub_canonical(monkeypatch)

    read_calls = []
    monkeypatch.setattr(mod, "_read_current_record", lambda: read_calls.append(1) or None)

    mod.handler(_make_s3_event("governance/live/other/file.md", sequencer="SEQ"), None)

    assert not read_calls, "Non-canonical key should bail before touching DDB"


def test_recursion_safety_no_s3_putobject(monkeypatch):
    """Handler must never call _get_s3().put_object — recursion guard."""
    _stub_canonical(monkeypatch)
    monkeypatch.setattr(mod, "_read_current_record", lambda: None)
    monkeypatch.setattr(mod, "_cas_write", lambda **kwargs: True)

    put_calls = []

    class SafeS3:
        def put_object(self, **kwargs):
            put_calls.append(kwargs)

        def head_object(self, **kwargs):
            return {}

        def get_object(self, **kwargs):
            from io import BytesIO
            return {"Body": BytesIO(b"governance_revision: 2026-06-27.01\n")}

        def get_object_attributes(self, **kwargs):
            return {"Checksum": {"ChecksumSHA256": "AAEC="}, "VersionId": "v1"}

        def get_paginator(self, name):
            class Pager:
                def paginate(self, **kwargs):
                    return iter([{"Contents": []}])
            return Pager()

    monkeypatch.setattr(mod, "_s3_client", SafeS3())

    mod.handler(_make_s3_event("governance/live/agents.md", sequencer="RECUR"), None)

    assert not put_calls, "Lambda must never write back to S3 (recursion guard)"


def test_bundle_hash_matches_spec():
    """§4.3: sha256 over URI+\\n+hex+\\n per file in lex order."""
    import hashlib

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
    expected = h.hexdigest()

    assert mod._compute_bundle_hash(entries) == expected


def test_sns_wrapped_event_is_unwrapped_and_processed(monkeypatch):
    """S3 -> SNS -> Lambda: the wrapped S3 event must be unwrapped and written."""
    _stub_canonical(monkeypatch)
    monkeypatch.setattr(mod, "_read_current_record", lambda: None)

    written = {}
    monkeypatch.setattr(
        mod,
        "_cas_write",
        lambda *, governance_revision, governance_hash, generation, file_entries, source_event, expected_cas: (
            written.update({"generation": generation, "seq": source_event.get("s3_sequencer")}) or True
        ),
    )

    mod.handler(_make_sns_wrapped_event("governance/live/agents.md", sequencer="SNSSEQ1"), None)

    assert written["generation"] == 1
    assert written["seq"] == "SNSSEQ1"


def test_malformed_sns_message_returns_without_write(monkeypatch):
    """A non-JSON / Records-less SNS message is handled gracefully (no crash, no write)."""
    _stub_canonical(monkeypatch)

    cas_calls = []
    monkeypatch.setattr(mod, "_cas_write", lambda **kwargs: cas_calls.append(kwargs) or True)
    monkeypatch.setattr(mod, "_read_current_record", lambda: None)

    bad = {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": "not-json"}}]}
    mod.handler(bad, None)  # must not raise

    empty = {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": json.dumps({"Records": []})}}]}
    mod.handler(empty, None)  # must not raise

    assert not cas_calls, "malformed/empty SNS messages must not produce a DDB write"
