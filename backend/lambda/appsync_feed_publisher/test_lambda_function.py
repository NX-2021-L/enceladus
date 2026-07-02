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
        return {k: {"S": str(v)} for k, v in (image or {}).items()}

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
