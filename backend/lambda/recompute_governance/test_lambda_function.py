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
    """Wrap a raw S3 event in an SNS Notification envelope (the real gamma delivery shape)."""
    s3_event = _make_s3_event(key, sequencer=sequencer, version_id=version_id)
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "EventVersion": "1.0",
                "Sns": {
                    "Type": "Notification",
                    "MessageId": "msg-1",
                    "TopicArn": "arn:aws:sns:us-west-1:356364570033:enceladus-governance-live-relay-gamma",
                    "Message": json.dumps(s3_event),
                },
            }
        ]
    }


def _make_sns_test_event() -> dict:
    """An s3:TestEvent relayed via SNS — Message has no S3 Records."""
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {"Type": "Notification", "Message": json.dumps({"Service": "Amazon S3", "Event": "s3:TestEvent"})},
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


# ---------------------------------------------------------------------------
# ENC-TSK-I53: SNS-relay envelope unwrapping (real gamma delivery topology)
# ---------------------------------------------------------------------------

def test_extract_s3_record_handles_raw_and_sns():
    raw = _make_s3_event("governance/live/agents.md", sequencer="R1")
    rec_raw = mod._extract_s3_record(raw)
    assert rec_raw["s3"]["object"]["sequencer"] == "R1"

    wrapped = _make_sns_wrapped_event("governance/live/agents.md", sequencer="S1")
    rec_sns = mod._extract_s3_record(wrapped)
    assert rec_sns["s3"]["object"]["sequencer"] == "S1"
    assert rec_sns["s3"]["object"]["key"] == "governance/live/agents.md"


def test_sns_wrapped_event_increments_like_raw(monkeypatch):
    """A real SNS-delivered governance/live/* event must recompute (regression for the KeyError 's3' defect)."""
    _stub_canonical(monkeypatch)
    monkeypatch.setattr(mod, "_read_current_record", lambda: None)

    written = {}
    monkeypatch.setattr(
        mod,
        "_cas_write",
        lambda *, governance_revision, governance_hash, generation, file_entries, source_event, expected_cas: (
            written.update({"generation": generation, "expected_cas": expected_cas, "seq": source_event["s3_sequencer"]}) or True
        ),
    )

    mod.handler(_make_sns_wrapped_event("governance/live/agents.md", sequencer="SNSSEQ1"), None)

    assert written["generation"] == 1
    assert written["expected_cas"] is None
    assert written["seq"] == "SNSSEQ1"


def test_sns_test_event_skipped(monkeypatch):
    """s3:TestEvent relayed through SNS carries no S3 Records and must be a no-op."""
    read_calls = []
    monkeypatch.setattr(mod, "_read_current_record", lambda: read_calls.append(1) or None)

    mod.handler(_make_sns_test_event(), None)

    assert not read_calls, "s3:TestEvent should bail before touching DDB"


def test_malformed_sns_message_does_not_raise(monkeypatch):
    """A non-JSON SNS Message must be skipped gracefully, not crash the handler."""
    read_calls = []
    monkeypatch.setattr(mod, "_read_current_record", lambda: read_calls.append(1) or None)

    event = {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": "not-json{{"}}]}
    mod.handler(event, None)  # must not raise

    assert not read_calls


# ---------------------------------------------------------------------------
# DVP-TSK-B44: EventBridge "Object Created" from the PROD content bucket (shared governance corpus)
# ---------------------------------------------------------------------------

def _make_eventbridge_event(key: str, sequencer: str = "EB-SEQ1", version_id: str = "v1",
                            detail_type: str = "Object Created") -> dict:
    """The real shape: aws.s3 / Object Created, key RAW (not URL-encoded), version-id hyphenated."""
    return {
        "version": "0",
        "id": "17793124-05d4-b198-2fde-7ededc63b103",
        "detail-type": detail_type,
        "source": "aws.s3",
        "account": "356364570033",
        "time": "2026-10-13T20:00:00Z",
        "region": "us-west-2",
        "resources": ["arn:aws:s3:::enceladus-content-356364570033-us-west-2"],
        "detail": {
            "version": "0",
            "bucket": {"name": "enceladus-content-356364570033-us-west-2"},
            "object": {"key": key, "size": 5, "etag": "abc", "version-id": version_id, "sequencer": sequencer},
            "request-id": "N4N7GDK58NMKJ12R",
            "requester": "356364570033",
            "source-ip-address": "1.2.3.4",
            "reason": "PutObject",
        },
    }


def test_extract_s3_record_handles_eventbridge():
    rec = mod._extract_s3_record(_make_eventbridge_event("governance/live/agents/x y.md", sequencer="E1", version_id="V9"))
    assert rec["s3"]["object"] == {"key": "governance/live/agents/x y.md", "sequencer": "E1", "versionId": "V9"}


def test_eventbridge_event_triggers_a_recompute(monkeypatch):
    _stub_canonical(monkeypatch)
    monkeypatch.setattr(mod, "_read_current_record", lambda: None)

    written = {}
    monkeypatch.setattr(
        mod,
        "_cas_write",
        lambda *, governance_revision, governance_hash, generation, file_entries, source_event, expected_cas: (
            written.update({"generation": generation, "source_event": source_event}) or True
        ),
    )

    mod.handler(_make_eventbridge_event("governance/live/agents.md", sequencer="EBSEQ1", version_id="vEB"), None)

    assert written["generation"] == 1
    assert written["source_event"] == {
        "s3_sequencer": "EBSEQ1", "trigger_s3_key": "governance/live/agents.md", "trigger_version_id": "vEB",
    }


def test_eventbridge_same_sequencer_dedups(monkeypatch):
    _stub_canonical(monkeypatch)
    monkeypatch.setattr(
        mod, "_read_current_record",
        lambda: {"generation": 3, "cas_version": 3, "source_event": {"s3_sequencer": "EBSEQ1"}},
    )
    writes = []
    monkeypatch.setattr(mod, "_cas_write", lambda **kw: writes.append(kw) or True)

    mod.handler(_make_eventbridge_event("governance/live/agents.md", sequencer="EBSEQ1"), None)

    assert not writes


def test_eventbridge_non_canonical_key_and_other_detail_types_are_skipped(monkeypatch):
    read_calls = []
    monkeypatch.setattr(mod, "_read_current_record", lambda: read_calls.append(1) or None)

    mod.handler(_make_eventbridge_event("governance/live/other.json"), None)
    mod.handler(_make_eventbridge_event("governance/live/agents.md", detail_type="Object Deleted"), None)
    mod.handler({"source": "aws.s3", "detail-type": "Object Created", "detail": {"object": {}}}, None)

    assert not read_calls


def test_other_event_shapes_still_win_over_the_eventbridge_branch():
    """The backstop's synthetic Records input has no top-level 'source', so it keeps the original path."""
    backstop = {"Records": [{"eventSource": "aws:scheduled-backstop",
                             "s3": {"object": {"key": "governance/live/agents.md", "sequencer": "", "versionId": ""}}}]}
    assert mod._extract_s3_record(backstop)["s3"]["object"]["key"] == "governance/live/agents.md"
    assert mod._eventbridge_s3_record(backstop) is None
