"""Unit tests for the appsync_feed_publisher Lambda (ENC-TSK-K20).

Covers: payload shape (B67 AC-10 field set + AC-23 size budget), actorType
inference, action derivation, uuid7 monotonic-ish ordering, cursor monotonicity,
and the ReportBatchItemFailures partial-batch contract.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from unittest.mock import patch

# Set env BEFORE importing so module-level config resolves for DRY_RUN unit runs.
os.environ.setdefault("APPSYNC_EVENTS_HTTP_ENDPOINT", "example.appsync-api.us-west-2.amazonaws.com")
os.environ.setdefault("APPSYNC_EVENTS_API_KEY", "test-key")
os.environ.setdefault("DRY_RUN", "true")

sys.path.insert(0, os.path.dirname(__file__))

_SPEC = importlib.util.spec_from_file_location(
    "appsync_feed_publisher_lambda",
    os.path.join(os.path.dirname(__file__), "lambda_function.py"),
)
mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(mod)


def _stream_record(
    *,
    event_name: str = "MODIFY",
    new_image: dict | None = None,
    old_image: dict | None = None,
    keys: dict | None = None,
    seq: str = "seq-1",
    approx_secs: float | None = 1_700_000_000.0,
) -> dict:
    def _typed(image: dict | None) -> dict:
        out = {}
        for k, v in (image or {}).items():
            if isinstance(v, bool):
                out[k] = {"BOOL": v}
            elif isinstance(v, (int, float)):
                out[k] = {"N": str(v)}
            elif isinstance(v, dict):
                out[k] = {"M": _typed(v)}
            elif isinstance(v, list):
                out[k] = {"L": [_typed({"_": x})["_"] for x in v]}
            else:
                out[k] = {"S": str(v)}
        return out

    ddb: dict = {"SequenceNumber": seq}
    if approx_secs is not None:
        ddb["ApproximateCreationDateTime"] = approx_secs
    if new_image is not None:
        ddb["NewImage"] = _typed(new_image)
    if old_image is not None:
        ddb["OldImage"] = _typed(old_image)
    if keys is not None:
        ddb["Keys"] = _typed(keys)
    return {"eventName": event_name, "eventID": seq, "dynamodb": ddb}


# ---------------------------------------------------------------------------
# Payload shape (AC-10) + size budget (AC-23)
# ---------------------------------------------------------------------------


def test_payload_has_exact_ac10_field_set():
    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "ENC-TSK-K20",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "AppSync FeedPublisher",
        },
    )
    payload = mod.build_event_payload(rec, 0)
    assert payload is not None
    assert set(payload.keys()) == {
        "eventId",
        "recordId",
        "record_type",
        "action",
        "actorType",
        "actorId",
        "summary",
        "cursor",
        "channels",
    }
    assert payload["recordId"] == "ENC-TSK-K20"
    assert payload["record_type"] == "task"
    assert payload["channels"] == [
        "/feed/updates",
        "/records/ENC-TSK-K20",
        "/projects/enceladus",
    ]


def test_payload_median_size_under_500_bytes():
    sizes = []
    for i in range(11):
        rec = _stream_record(
            event_name="MODIFY",
            new_image={
                "record_id": f"ENC-TSK-{i:03d}",
                "record_type": "task",
                "project_id": "enceladus",
                "title": "A reasonably descriptive task title here",
                "status": "in-progress",
                "write_source": {"provider": "ENC-SES-00P", "channel": "mcp_server"},
            },
        )
        payload = mod.build_event_payload(rec, i)
        sizes.append(len(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
    sizes.sort()
    median = sizes[len(sizes) // 2]
    assert median <= 500, f"median payload {median} bytes exceeds 500-byte budget"


def test_payload_does_not_inline_raw_item_image():
    rec = _stream_record(
        event_name="MODIFY",
        new_image={"record_id": "ENC-ISS-1", "record_type": "issue", "project_id": "enceladus"},
    )
    payload = mod.build_event_payload(rec, 0)
    # No raw DynamoDB typed attributes leak through.
    blob = json.dumps(payload)
    assert '"NewImage"' not in blob and '"S":' not in blob


def test_record_without_record_id_is_skipped():
    rec = _stream_record(event_name="MODIFY", new_image={"record_type": "task"})
    assert mod.build_event_payload(rec, 0) is None


# ---------------------------------------------------------------------------
# actorType inference
# ---------------------------------------------------------------------------


def test_actor_type_agent_from_session_provider():
    assert mod.infer_actor({"write_source": {"provider": "ENC-SES-00P", "channel": "mutation_api"}}) == (
        "agent",
        "ENC-SES-00P",
    )


def test_actor_type_agent_from_mcp_channel():
    at, aid = mod.infer_actor({"write_source": {"provider": "", "channel": "mcp_server"}})
    assert at == "agent"


def test_actor_type_agent_from_arc_walker_channel():
    at, _ = mod.infer_actor({"write_source": {"provider": "system:arc-walker", "channel": "arc-walker"}})
    assert at == "agent"


def test_actor_type_human_from_cognito_provider():
    at, aid = mod.infer_actor({"write_source": {"provider": "jreese", "channel": "mutation_api"}})
    assert at == "human"
    assert aid == "jreese"


def test_actor_type_defaults_to_agent():
    at, aid = mod.infer_actor({})
    assert at == "agent"
    assert aid == "unknown"


# ---------------------------------------------------------------------------
# action derivation
# ---------------------------------------------------------------------------


def test_action_created_on_insert():
    assert mod.derive_action("INSERT", {"status": "open"}, {}) == "created"


def test_action_removed_on_remove():
    assert mod.derive_action("REMOVE", {}, {"status": "open"}) == "removed"


def test_action_closed_on_terminal_transition():
    assert mod.derive_action("MODIFY", {"status": "closed"}, {"status": "in-progress"}) == "closed"
    assert mod.derive_action("MODIFY", {"status": "deploy-success"}, {"status": "pr"}) == "closed"


def test_action_updated_when_not_terminal():
    assert mod.derive_action("MODIFY", {"status": "in-progress"}, {"status": "open"}) == "updated"
    # Already terminal, no transition => still 'updated' (no re-close).
    assert mod.derive_action("MODIFY", {"status": "closed"}, {"status": "closed"}) == "updated"


# ---------------------------------------------------------------------------
# uuid7 monotonic-ish
# ---------------------------------------------------------------------------


def test_uuid7_is_valid_v7_and_time_ordered():
    a = mod.uuid7(1_700_000_000_000)
    b = mod.uuid7(1_700_000_000_001)
    # version nibble is 7
    assert a[14] == "7" and b[14] == "7"
    # variant nibble in {8,9,a,b}
    assert a[19].lower() in "89ab"
    # Later timestamp sorts lexically after earlier one.
    assert a < b


def test_uuid7_monotonic_within_same_millisecond():
    ts = 1_700_000_000_500
    ids = [mod.uuid7(ts) for _ in range(50)]
    assert ids == sorted(ids), "uuid7 not monotonic within a single millisecond"
    assert len(set(ids)) == len(ids), "uuid7 collided within a millisecond"


# ---------------------------------------------------------------------------
# cursor monotonicity
# ---------------------------------------------------------------------------


def test_cursor_monotonic_across_batch_counter():
    ms = 1_700_000_000_000
    cursors = [mod.derive_cursor(ms, i) for i in range(5)]
    assert cursors == sorted(cursors)
    assert len(set(cursors)) == len(cursors)


def test_cursor_orders_by_time_over_counter():
    earlier = mod.derive_cursor(1_700_000_000_000, 999)
    later = mod.derive_cursor(1_700_000_000_001, 0)
    assert later > earlier


# ---------------------------------------------------------------------------
# handler / partial-batch failure
# ---------------------------------------------------------------------------


def test_handler_dry_run_publishes_all_and_returns_empty():
    event = {
        "Records": [
            _stream_record(
                event_name="INSERT",
                new_image={"record_id": "ENC-TSK-1", "record_type": "task", "project_id": "enceladus"},
                seq="s1",
            ),
            _stream_record(
                event_name="MODIFY",
                new_image={"record_id": "ENC-TSK-2", "record_type": "task", "project_id": "enceladus", "status": "closed"},
                old_image={"status": "open"},
                seq="s2",
            ),
        ]
    }
    with patch.object(mod, "DRY_RUN", True):
        result = mod.handler(event, None)
    assert result == {}


def test_handler_reports_batch_item_failure_on_publish_error():
    event = {
        "Records": [
            _stream_record(
                event_name="INSERT",
                new_image={"record_id": "ENC-TSK-1", "record_type": "task", "project_id": "enceladus"},
                seq="bad-seq",
            ),
        ]
    }
    with patch.object(mod, "DRY_RUN", False), patch.object(
        mod, "publish_to_appsync", side_effect=RuntimeError("boom")
    ):
        result = mod.handler(event, None)
    assert result == {"batchItemFailures": [{"itemIdentifier": "bad-seq"}]}


def test_handler_skips_unresolvable_record_without_failing():
    event = {"Records": [_stream_record(event_name="MODIFY", new_image={"record_type": "task"}, seq="s9")]}
    with patch.object(mod, "DRY_RUN", True):
        result = mod.handler(event, None)
    assert result == {}


# ---------------------------------------------------------------------------
# ENC-TSK-K74 regression: composite record_id must never leak '#' into the
# per-record channel (AppSync rejects it: 400 Invalid Channel Format —
# verified live during K56 gamma provisioning), nor into recordId/summary.
# Real tracker rows carry composite record_id ("task#ENC-TSK-004") plus a
# bare item_id attribute; the original fixture above used a bare record_id,
# which is why this bug escaped the suite.
# ---------------------------------------------------------------------------


def test_composite_record_id_uses_bare_item_id_everywhere():
    rec = _stream_record(
        event_name="MODIFY",
        new_image={
            "record_id": "task#ENC-TSK-004",
            "item_id": "ENC-TSK-004",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "Composite id row",
        },
        old_image={
            "record_id": "task#ENC-TSK-004",
            "item_id": "ENC-TSK-004",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "Composite id row",
            "status": "open",
        },
    )
    payload = mod.build_event_payload(rec, 0)
    assert payload is not None
    assert payload["recordId"] == "ENC-TSK-004"
    assert payload["channels"] == [
        "/feed/updates",
        "/records/ENC-TSK-004",
        "/projects/enceladus",
    ]
    assert "#" not in payload["summary"]
    for channel in payload["channels"]:
        assert "#" not in channel


def test_composite_record_id_without_item_id_falls_back_to_suffix():
    # Older rows may lack the bare item_id attribute — the suffix after the
    # last '#' is the bare id.
    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "lesson#ENC-LSN-057",
            "record_type": "lesson",
            "project_id": "enceladus",
            "title": "No item_id attribute",
        },
    )
    payload = mod.build_event_payload(rec, 0)
    assert payload is not None
    assert payload["recordId"] == "ENC-LSN-057"
    assert "/records/ENC-LSN-057" in payload["channels"]


# ---------------------------------------------------------------------------
# ENC-TSK-L29: full record body on /records/{recordId} only (not /feed/updates
# or /projects/{id}), so the client's Tier-1/Tier-2 mirror (ENC-TSK-L24) can
# upsert directly with no follow-up fetch.
# ---------------------------------------------------------------------------


def test_build_full_record_body_returns_new_image_for_insert():
    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "task#ENC-TSK-L29T",
            "item_id": "ENC-TSK-L29T",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "Full body row",
            "status": "open",
        },
    )
    full_body = mod.build_full_record_body(rec)
    assert full_body is not None
    assert full_body["item_id"] == "ENC-TSK-L29T"
    assert full_body["title"] == "Full body row"
    assert full_body["status"] == "open"


def test_build_full_record_body_returns_new_image_for_modify():
    rec = _stream_record(
        event_name="MODIFY",
        new_image={"record_id": "task#ENC-TSK-L29T", "item_id": "ENC-TSK-L29T", "status": "closed"},
        old_image={"record_id": "task#ENC-TSK-L29T", "item_id": "ENC-TSK-L29T", "status": "open"},
    )
    full_body = mod.build_full_record_body(rec)
    assert full_body is not None
    assert full_body["status"] == "closed"


def test_build_full_record_body_returns_none_for_remove():
    rec = _stream_record(
        event_name="REMOVE",
        old_image={"record_id": "task#ENC-TSK-L29T", "item_id": "ENC-TSK-L29T", "status": "open"},
    )
    full_body = mod.build_full_record_body(rec)
    assert full_body is None


class _FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_publish_to_appsync_attaches_record_only_to_records_channel():
    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "task#ENC-TSK-L29T",
            "item_id": "ENC-TSK-L29T",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "Full body row",
        },
    )
    payload = mod.build_event_payload(rec, 0)
    full_body = mod.build_full_record_body(rec)
    assert payload is not None and full_body is not None

    sent_bodies = {}

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        body = json.loads(req.data.decode("utf-8"))
        sent_bodies[body["channel"]] = json.loads(body["events"][0])
        return _FakeResponse(200)

    with patch.object(mod.urllib.request, "urlopen", side_effect=_fake_urlopen):
        mod.publish_to_appsync(payload, full_body)

    assert set(sent_bodies.keys()) == {"/feed/updates", "/records/ENC-TSK-L29T", "/projects/enceladus"}
    assert "record" not in sent_bodies["/feed/updates"]
    assert "record" not in sent_bodies["/projects/enceladus"]
    assert sent_bodies["/records/ENC-TSK-L29T"]["record"] == full_body
    # AC-23: the lightweight channels must stay exactly as small as before —
    # no accidental leakage of the full body onto the fixed-budget channels.
    assert sent_bodies["/feed/updates"] == payload


def test_publish_to_appsync_without_full_body_is_unchanged():
    rec = _stream_record(
        event_name="REMOVE",
        old_image={
            "record_id": "task#ENC-TSK-L29T",
            "item_id": "ENC-TSK-L29T",
            "record_type": "task",
            "project_id": "enceladus",
        },
    )
    payload = mod.build_event_payload(rec, 0)
    assert payload is not None

    sent_bodies = {}

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        body = json.loads(req.data.decode("utf-8"))
        sent_bodies[body["channel"]] = json.loads(body["events"][0])
        return _FakeResponse(200)

    with patch.object(mod.urllib.request, "urlopen", side_effect=_fake_urlopen):
        mod.publish_to_appsync(payload)

    for body in sent_bodies.values():
        assert "record" not in body


# ---------------------------------------------------------------------------
# ENC-TSK-M69: Decimal-safe JSON serialization
#
# DynamoDB Stream Number (N) attributes deserialize to Decimal
# (boto3.dynamodb.types.TypeDeserializer); json.dumps has no native Decimal
# support. Covers both the lightweight payload and the /records/{recordId}
# full_body payload (ENC-TSK-L29) since full_body can carry Decimal at any
# depth (top-level and nested inside M/L attributes).
# ---------------------------------------------------------------------------


def test_json_default_converts_integral_decimal_to_int():
    from decimal import Decimal

    assert mod._json_default(Decimal("3")) == 3
    assert isinstance(mod._json_default(Decimal("3")), int)


def test_json_default_converts_non_integral_decimal_to_float():
    from decimal import Decimal

    assert mod._json_default(Decimal("4.5")) == 4.5
    assert isinstance(mod._json_default(Decimal("4.5")), float)


def test_json_default_reraises_typeerror_for_unsupported_types():
    class _Unserializable:
        pass

    try:
        mod._json_default(_Unserializable())
        assert False, "expected TypeError"
    except TypeError:
        pass


def test_build_full_record_body_deserializes_number_attribute_as_decimal():
    from decimal import Decimal

    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "task#ENC-TSK-M69T",
            "item_id": "ENC-TSK-M69T",
            "sync_version": 3,
        },
    )
    full_body = mod.build_full_record_body(rec)
    assert isinstance(full_body["sync_version"], Decimal)


def test_publish_to_appsync_serializes_decimal_in_full_body_top_level_and_nested():
    rec = _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "task#ENC-TSK-M69T",
            "item_id": "ENC-TSK-M69T",
            "record_type": "task",
            "project_id": "enceladus",
            "sync_version": 7,
            "checkout_count": 2.5,
            "ontology": {"earned_points": 45, "max_points": 70},
        },
    )
    payload = mod.build_event_payload(rec, 0)
    full_body = mod.build_full_record_body(rec)
    assert payload is not None and full_body is not None

    sent_bodies = {}

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        body = json.loads(req.data.decode("utf-8"))
        sent_bodies[body["channel"]] = json.loads(body["events"][0])
        return _FakeResponse(200)

    with patch.object(mod.urllib.request, "urlopen", side_effect=_fake_urlopen):
        mod.publish_to_appsync(payload, full_body)  # must not raise

    record = sent_bodies["/records/ENC-TSK-M69T"]["record"]
    # Integral Decimal -> int (record ids/counts/versions must not drift to float)
    assert record["sync_version"] == 7
    assert isinstance(record["sync_version"], int)
    # Non-integral Decimal -> float
    assert record["checkout_count"] == 2.5
    assert isinstance(record["checkout_count"], float)
    # Nested Decimal (inside an M-typed sub-map) also serializes cleanly
    assert record["ontology"]["earned_points"] == 45
    assert isinstance(record["ontology"]["earned_points"], int)

    # AC-23: lightweight channels are unaffected and still exclude "record"
    assert "record" not in sent_bodies["/feed/updates"]
    assert "record" not in sent_bodies["/projects/enceladus"]
