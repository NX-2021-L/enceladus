"""Unit tests for the appsync_feed_publisher Lambda (ENC-TSK-K20).

Covers: payload shape (B67 AC-10 field set + AC-23 size budget), actorType
inference, action derivation, uuid7 monotonic-ish ordering, cursor monotonicity,
and the ReportBatchItemFailures partial-batch contract.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import urllib.error
from unittest.mock import MagicMock, patch

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
        # ENC-TSK-R54-0C v2 additions (status/priority/updated_at absent from this image)
        "schemaVersion",
        "recordTitle",
        "recordUpdatedAt",
    }
    assert payload["recordId"] == "ENC-TSK-K20"
    assert payload["record_type"] == "task"
    assert payload["channels"] == [
        "/feed/updates",
        "/records/ENC-TSK-K20",
        "/projects/enceladus",
    ]


def test_payload_median_size_under_v2_budget():
    # v1 budget was 500 B (B67 AC-23); v2 adds ~5 display keys (ENC-TSK-R53-0C) => 700 B.
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
                "priority": "P1",
                "updated_at": "2026-10-27T01:02:03Z",
                "version_seq": 123456,
                "write_source": {"provider": "ENC-SES-00P", "channel": "mcp_server"},
            },
        )
        payload = mod.build_event_payload(rec, i)
        sizes.append(len(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
    sizes.sort()
    median = sizes[len(sizes) // 2]
    assert median <= 700, f"median payload {median} bytes exceeds 700-byte v2 budget"


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


def test_id_allocator_counter_row_is_skipped():
    # ENC-ISS-876: every create also bumps COUNTER-<TYPE>; publishing it sent a titleless,
    # statusless v2 event that made the client heal once per create.
    for name in ("MODIFY", "INSERT"):
        rec = _stream_record(
            event_name=name,
            new_image={"record_id": "COUNTER-ISSUE", "record_type": "counter", "project_id": "enceladus"},
        )
        assert mod.build_event_payload(rec, 0) is None
    real = _stream_record(
        event_name="INSERT",
        new_image={"record_id": "ENC-ISS-877", "record_type": "issue", "project_id": "enceladus", "title": "t", "status": "open"},
    )
    assert mod.build_event_payload(real, 0) is not None


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


# ---------------------------------------------------------------------------
# ENC-ISS-531: permanent-error classification, poison-record skip + metric,
# and response-body logging. BatchSize=1 + indefinite DynamoDB Streams retry
# means a record AppSync will NEVER accept must be skipped, not retried
# forever (which silently blocks its whole shard).
# ---------------------------------------------------------------------------


def _http_error(code, body=b"Bad Request detail"):
    return urllib.error.HTTPError(
        url="https://example.appsync-api.us-west-2.amazonaws.com/event",
        code=code,
        msg="Bad Request",
        hdrs=None,
        fp=io.BytesIO(body),
    )


def test_is_permanent_publish_error_classifies_4xx_except_429():
    assert mod._is_permanent_publish_error(_http_error(400)) is True
    assert mod._is_permanent_publish_error(_http_error(403)) is True
    assert mod._is_permanent_publish_error(_http_error(404)) is True
    # 429 is transient (rate limit) -- must keep retrying, not poison-skip
    assert mod._is_permanent_publish_error(_http_error(429)) is False
    assert mod._is_permanent_publish_error(_http_error(500)) is False
    assert mod._is_permanent_publish_error(RuntimeError("boom")) is False


def test_publish_to_appsync_logs_response_body_and_reraises_on_http_error():
    rec = _stream_record(
        event_name="INSERT",
        new_image={"record_id": "task#ENC-TSK-P1", "item_id": "ENC-TSK-P1", "project_id": "enceladus"},
    )
    payload = mod.build_event_payload(rec, 0)

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        raise _http_error(400, body=b'{"errors":[{"message":"invalid channel"}]}')

    with patch.object(mod.urllib.request, "urlopen", side_effect=_fake_urlopen), patch.object(
        mod.logger, "error"
    ) as mock_log_error:
        try:
            mod.publish_to_appsync(payload)
            assert False, "expected HTTPError to propagate"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400

    # The response body must have been read and logged, not just the bare
    # "HTTP Error 400" exception string.
    logged = " ".join(str(c) for c in mock_log_error.call_args.args)
    assert "invalid channel" in logged


def test_handler_skips_poison_record_and_emits_metric_without_retrying():
    event = {
        "Records": [
            _stream_record(
                event_name="INSERT",
                new_image={"record_id": "task#ENC-TSK-P2", "item_id": "ENC-TSK-P2", "project_id": "enceladus"},
                seq="poison-seq",
            ),
        ]
    }
    fake_cloudwatch = MagicMock()
    with patch.object(mod, "DRY_RUN", False), patch.object(
        mod, "publish_to_appsync", side_effect=_http_error(400)
    ), patch.object(mod, "_cloudwatch", fake_cloudwatch):
        result = mod.handler(event, None)

    # NOT reported as a batch failure -- DynamoDB Streams must advance past
    # a record that can never succeed, not retry it forever.
    assert result == {}
    fake_cloudwatch.put_metric_data.assert_called_once()
    call_kwargs = fake_cloudwatch.put_metric_data.call_args.kwargs
    assert call_kwargs["Namespace"] == mod.POISON_METRIC_NAMESPACE
    assert call_kwargs["MetricData"][0]["MetricName"] == "PoisonRecordSkipped"


def test_handler_still_retries_transient_5xx_without_emitting_metric():
    event = {
        "Records": [
            _stream_record(
                event_name="INSERT",
                new_image={"record_id": "task#ENC-TSK-P3", "item_id": "ENC-TSK-P3", "project_id": "enceladus"},
                seq="transient-seq",
            ),
        ]
    }
    fake_cloudwatch = MagicMock()
    with patch.object(mod, "DRY_RUN", False), patch.object(
        mod, "publish_to_appsync", side_effect=_http_error(503)
    ), patch.object(mod, "_cloudwatch", fake_cloudwatch):
        result = mod.handler(event, None)

    # Unchanged existing behavior: transient errors ARE retried.
    assert result == {"batchItemFailures": [{"itemIdentifier": "transient-seq"}]}
    fake_cloudwatch.put_metric_data.assert_not_called()


def test_emit_poison_metric_failure_does_not_raise():
    fake_cloudwatch = MagicMock()
    fake_cloudwatch.put_metric_data.side_effect = RuntimeError("cloudwatch unavailable")
    with patch.object(mod, "_cloudwatch", fake_cloudwatch):
        mod._emit_poison_metric("seq-x", 400)  # must not raise


# ---------------------------------------------------------------------------
# ENC-ISS-532: internal sentinel-project rows (version_seq counter /
# feed_tombstone, project_id="__feed__") must never construct a channel --
# AppSync permanently rejects /projects/__feed__ (ENC-ISS-531/ENC-TSK-M71
# poison-skips it, but filtering upstream avoids relying on that backstop
# for a fully predictable, non-project record shape).
# ---------------------------------------------------------------------------


def test_is_real_project_id_rejects_dunder_sentinels_and_empty():
    assert mod._is_real_project_id("__feed__") is False
    assert mod._is_real_project_id("") is False
    assert mod._is_real_project_id("enceladus") is True
    assert mod._is_real_project_id("chosen-family") is True
    # A leading/trailing single underscore is NOT the dunder-sentinel shape.
    assert mod._is_real_project_id("_enceladus") is True


def test_build_event_payload_returns_none_for_sentinel_project_id():
    rec = _stream_record(
        event_name="MODIFY",
        new_image={
            "project_id": "__feed__",
            "record_id": "counter#version_seq",
            "version_seq": 42,
        },
        keys={"project_id": "__feed__", "record_id": "counter#version_seq"},
    )
    assert mod.build_event_payload(rec, 0) is None


def test_build_event_payload_unchanged_for_normal_record():
    rec = _stream_record(
        event_name="INSERT",
        new_image={"record_id": "task#ENC-TSK-Z1", "item_id": "ENC-TSK-Z1", "project_id": "enceladus"},
    )
    payload = mod.build_event_payload(rec, 0)
    assert payload is not None
    assert payload["channels"] == ["/feed/updates", "/records/ENC-TSK-Z1", "/projects/enceladus"]


def test_handler_filters_sentinel_project_row_without_publishing():
    event = {
        "Records": [
            _stream_record(
                event_name="MODIFY",
                new_image={"project_id": "__feed__", "record_id": "counter#version_seq", "version_seq": 1},
                keys={"project_id": "__feed__", "record_id": "counter#version_seq"},
                seq="counter-seq",
            ),
        ]
    }
    fake_cloudwatch = MagicMock()
    with patch.object(mod, "DRY_RUN", False), patch.object(
        mod, "publish_to_appsync"
    ) as mock_publish, patch.object(mod, "_cloudwatch", fake_cloudwatch):
        result = mod.handler(event, None)

    # Filtered upstream -- not a failure, not retried, and AppSync is never called.
    assert result == {}
    mock_publish.assert_not_called()
    fake_cloudwatch.put_metric_data.assert_called_once()
    call_kwargs = fake_cloudwatch.put_metric_data.call_args.kwargs
    assert call_kwargs["MetricData"][0]["MetricName"] == "NonProjectRecordFiltered"


# ---------------------------------------------------------------------------
# DVP-TSK-928: Cognito-namespace dual-publish
# ---------------------------------------------------------------------------


def _authed_rec():
    return _stream_record(
        event_name="INSERT",
        new_image={
            "record_id": "task#ENC-TSK-928",
            "item_id": "ENC-TSK-928",
            "record_type": "task",
            "project_id": "enceladus",
            "title": "Cognito realtime",
        },
    )


def _capture_posts(authed_error=None, legacy_error=None):
    """Patch urlopen + the SigV4 signer; return the list of (channel, headers, events) actually POSTed."""
    posts = []

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        body = json.loads(req.data.decode("utf-8"))
        channel = body["channel"]
        posts.append((channel, {k.lower(): v for k, v in req.header_items()}, body["events"]))
        if authed_error is not None and channel.startswith("/authed/"):
            raise authed_error
        if legacy_error is not None and not channel.startswith("/authed/"):
            raise legacy_error
        return _FakeResponse(200)

    return posts, _fake_urlopen


def test_dual_publish_mirrors_every_channel_into_the_cognito_namespace_with_sigv4():
    rec = _authed_rec()
    payload = mod.build_event_payload(rec, 0)
    full_body = mod.build_full_record_body(rec)
    posts, fake = _capture_posts()

    with patch.object(mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"), patch.object(
        mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig", "host": "h"}
    ) as sigv4, patch.object(mod.urllib.request, "urlopen", side_effect=fake):
        mod.publish_to_appsync(payload, full_body)

    by_channel = {channel: (headers, events) for channel, headers, events in posts}
    legacy = {"/feed/updates", "/records/ENC-TSK-928", "/projects/enceladus"}
    assert set(by_channel) == legacy | {f"/authed{c}" for c in legacy}
    # Legacy channels keep the API key; the authed namespace is IAM-only and must never carry it.
    for channel in legacy:
        assert by_channel[channel][0].get("x-api-key") == "test-key"
        assert by_channel[f"/authed{channel}"][0].get("x-api-key") is None
        assert by_channel[f"/authed{channel}"][0]["authorization"].startswith("AWS4-HMAC-SHA256")
    assert sigv4.call_count == 3
    # Same payload contract per channel: full body only on the record channel, identical event ids.
    assert json.loads(by_channel["/authed/records/ENC-TSK-928"][1][0])["record"] == full_body
    assert "record" not in json.loads(by_channel["/authed/feed/updates"][1][0])
    assert by_channel["/authed/feed/updates"][1] == by_channel["/feed/updates"][1]
    assert by_channel["/authed/records/ENC-TSK-928"][1] == by_channel["/records/ENC-TSK-928"][1]


def test_dual_publish_is_off_when_no_namespace_is_configured():
    payload = mod.build_event_payload(_authed_rec(), 0)
    posts, fake = _capture_posts()
    with patch.object(mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", ""), patch.object(
        mod, "_sigv4_headers"
    ) as sigv4, patch.object(mod.urllib.request, "urlopen", side_effect=fake):
        mod.publish_to_appsync(payload)
    assert [c for c, _h, _e in posts] == ["/feed/updates", "/records/ENC-TSK-928", "/projects/enceladus"]
    sigv4.assert_not_called()


def test_authed_failure_never_fails_the_record_and_is_counted():
    payload = mod.build_event_payload(_authed_rec(), 0)
    posts, fake = _capture_posts(authed_error=_http_error(403, b"Unauthorized"))
    with patch.object(mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"), patch.object(
        mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}
    ), patch.object(mod.urllib.request, "urlopen", side_effect=fake), patch.object(
        mod, "_cloudwatch"
    ) as cw:
        mod.publish_to_appsync(payload)  # must not raise: legacy channels already succeeded

    assert {c for c, _h, _e in posts if not c.startswith("/authed/")} == {
        "/feed/updates",
        "/records/ENC-TSK-928",
        "/projects/enceladus",
    }
    metrics = [call.kwargs["MetricData"][0]["MetricName"] for call in cw.put_metric_data.call_args_list]
    assert metrics == ["AuthedPublishFailed"] * 3


def test_handler_does_not_report_a_batch_failure_for_an_authed_only_failure():
    rec = _authed_rec()
    posts, fake = _capture_posts(authed_error=_http_error(503, b"unavailable"))
    with patch.object(mod, "DRY_RUN", False), patch.object(mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"), patch.object(
        mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}
    ), patch.object(mod.urllib.request, "urlopen", side_effect=fake), patch.object(mod, "_cloudwatch"):
        result = mod.handler({"Records": [rec]}, None)
    assert result == {}


def test_legacy_failure_still_raises_before_the_authed_mirror_is_attempted():
    payload = mod.build_event_payload(_authed_rec(), 0)
    posts, fake = _capture_posts(legacy_error=_http_error(503, b"unavailable"))
    with patch.object(mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"), patch.object(
        mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}
    ), patch.object(mod.urllib.request, "urlopen", side_effect=fake):
        try:
            mod.publish_to_appsync(payload)
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
        else:  # pragma: no cover
            raise AssertionError("legacy publish failure must propagate")
    assert not any(c.startswith("/authed/") for c, _h, _e in posts)


def test_sigv4_headers_sign_for_the_appsync_service_in_the_publish_region():
    from botocore.credentials import Credentials

    session = MagicMock()
    session.get_credentials.return_value = Credentials("AKIATEST", "secret", "session-token")
    with patch.object(mod.boto3, "Session", return_value=session), patch.object(
        mod, "APPSYNC_EVENTS_REGION", "us-west-2"
    ):
        headers = mod._sigv4_headers(b'{"channel":"/authed/feed/updates","events":["{}"]}', "example.appsync-api.us-west-2.amazonaws.com")
    auth = {k.lower(): v for k, v in headers.items()}
    assert auth["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIATEST/")
    assert "/us-west-2/appsync/aws4_request" in auth["authorization"]
    assert auth["x-amz-security-token"] == "session-token"


def test_cognito_only_plane_publishes_to_the_authed_namespace_alone_with_sigv4():
    rec = _authed_rec()
    payload = mod.build_event_payload(rec, 0)
    full_body = mod.build_full_record_body(rec)
    posts, fake = _capture_posts()
    with patch.object(mod, "APPSYNC_EVENTS_LEGACY_PUBLISH", False), patch.object(
        mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"
    ), patch.object(mod, "APPSYNC_EVENTS_API_KEY", ""), patch.object(
        mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}
    ) as sigv4, patch.object(mod.urllib.request, "urlopen", side_effect=fake):
        mod.publish_to_appsync(payload, full_body)

    assert sorted(c for c, _h, _e in posts) == [
        "/authed/feed/updates",
        "/authed/projects/enceladus",
        "/authed/records/ENC-TSK-928",
    ]
    assert all("x-api-key" not in h for _c, h, _e in posts)
    assert sigv4.call_count == 3
    by_channel = {c: e for c, _h, e in posts}
    assert json.loads(by_channel["/authed/records/ENC-TSK-928"][0])["record"] == full_body


def test_cognito_only_plane_is_fail_closed_unlike_the_gamma_mirror():
    payload = mod.build_event_payload(_authed_rec(), 0)
    posts, fake = _capture_posts(authed_error=_http_error(503, b"unavailable"))
    with patch.object(mod, "APPSYNC_EVENTS_LEGACY_PUBLISH", False), patch.object(
        mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"
    ), patch.object(mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}), patch.object(
        mod.urllib.request, "urlopen", side_effect=fake
    ):
        try:
            mod.publish_to_appsync(payload)
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
        else:  # pragma: no cover
            raise AssertionError("authed publish failure must propagate on the Cognito-only plane")


def test_cognito_only_plane_without_a_namespace_is_a_loud_misconfiguration():
    payload = mod.build_event_payload(_authed_rec(), 0)
    with patch.object(mod, "APPSYNC_EVENTS_LEGACY_PUBLISH", False), patch.object(
        mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", ""
    ):
        try:
            mod.publish_to_appsync(payload)
        except RuntimeError as exc:
            assert "APPSYNC_EVENTS_AUTHED_NAMESPACE" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected RuntimeError")


def test_cognito_only_permanent_rejection_is_poison_skipped_by_the_handler():
    rec = _authed_rec()
    posts, fake = _capture_posts(authed_error=_http_error(403, b"Unauthorized"))
    with patch.object(mod, "DRY_RUN", False), patch.object(mod, "APPSYNC_EVENTS_LEGACY_PUBLISH", False), patch.object(
        mod, "APPSYNC_EVENTS_AUTHED_NAMESPACE", "authed"
    ), patch.object(mod, "_sigv4_headers", return_value={"Authorization": "AWS4-HMAC-SHA256 sig"}), patch.object(
        mod.urllib.request, "urlopen", side_effect=fake
    ), patch.object(mod, "_cloudwatch") as cw:
        result = mod.handler({"Records": [rec]}, None)
    assert result == {}
    assert cw.put_metric_data.call_args.kwargs["MetricData"][0]["MetricName"] == "PoisonRecordSkipped"


# ---------------------------------------------------------------------------
# ENC-TSK-R54-0C: live-event payload v2 (ENC-TSK-R53-0C contract)
# ---------------------------------------------------------------------------

_V1_KEYS = {
    "eventId", "recordId", "record_type", "action", "actorType", "actorId",
    "summary", "cursor", "channels",
}


def _v2_image(**over) -> dict:
    img = {
        "record_id": "task#ENC-TSK-R1",
        "item_id": "ENC-TSK-R1",
        "record_type": "task",
        "project_id": "enceladus",
        "title": "Ship payload v2",
        "status": "in-progress",
        "priority": "P1",
        "updated_at": "2026-10-27T01:02:03Z",
        "version_seq": 4242,
        "write_source": {"provider": "ENC-SES-0NW", "channel": "mcp_server"},
    }
    img.update(over)
    return img


def test_v2_payload_for_create_event_carries_display_fields():
    rec = _stream_record(event_name="INSERT", new_image=_v2_image(status="open"))
    p = mod.build_event_payload(rec, 0)
    assert p["action"] == "created"
    assert p["schemaVersion"] == 2
    assert p["recordTitle"] == "Ship payload v2"
    assert p["recordStatus"] == "open"
    assert p["recordPriority"] == "P1"
    assert p["recordUpdatedAt"] == "2026-10-27T01:02:03Z"
    assert p["recordVersionSeq"] == 4242 and isinstance(p["recordVersionSeq"], int)
    assert set(p) == _V1_KEYS | {
        "schemaVersion", "recordTitle", "recordStatus", "recordPriority",
        "recordUpdatedAt", "recordVersionSeq",
    }


def test_v2_payload_for_update_event_reflects_new_image():
    rec = _stream_record(
        event_name="MODIFY",
        new_image=_v2_image(status="pr", updated_at="2026-10-27T02:00:00Z", version_seq=4243),
        old_image=_v2_image(status="in-progress"),
    )
    p = mod.build_event_payload(rec, 1)
    assert p["action"] == "updated"
    assert p["recordStatus"] == "pr"
    assert p["recordUpdatedAt"] == "2026-10-27T02:00:00Z"
    assert p["recordVersionSeq"] == 4243


def test_v2_payload_for_remove_event_uses_old_image():
    rec = _stream_record(event_name="REMOVE", old_image=_v2_image())
    p = mod.build_event_payload(rec, 0)
    assert p["action"] == "removed"
    assert p["recordStatus"] == "in-progress"
    assert p["recordTitle"] == "Ship payload v2"
    assert p["recordUpdatedAt"] == "2026-10-27T01:02:03Z"


def test_v2_optional_fields_omitted_when_row_lacks_them():
    rec = _stream_record(
        event_name="INSERT",
        new_image={"record_id": "LES-1", "record_type": "lesson", "project_id": "enceladus", "name": "A lesson"},
    )
    p = mod.build_event_payload(rec, 0)
    assert p["schemaVersion"] == 2
    assert p["recordTitle"] == "A lesson"  # falls back to name
    assert "recordStatus" not in p and "recordPriority" not in p and "recordVersionSeq" not in p


def test_v2_title_truncated_to_160_chars_but_summary_keeps_v1_form():
    long_title = "x" * 400
    rec = _stream_record(event_name="INSERT", new_image=_v2_image(title=long_title))
    p = mod.build_event_payload(rec, 0)
    assert len(p["recordTitle"]) == 160
    assert p["summary"].endswith(": " + long_title)
    assert len(json.dumps(p, separators=(",", ":")).encode()) < 1200


def test_v2_non_integral_version_seq_is_dropped():
    rec = _stream_record(event_name="INSERT", new_image=_v2_image(version_seq=1.5))
    assert "recordVersionSeq" not in mod.build_event_payload(rec, 0)


def test_v1_keys_preserved_with_unchanged_values():
    rec = _stream_record(event_name="MODIFY", new_image=_v2_image())
    p = mod.build_event_payload(rec, 3)
    assert _V1_KEYS <= set(p)
    assert p["recordId"] == "ENC-TSK-R1"
    assert p["record_type"] == "task"
    assert p["actorType"] == "agent" and p["actorId"] == "ENC-SES-0NW"
    assert p["summary"] == "ENC-SES-0NW updated task ENC-TSK-R1: Ship payload v2"
    assert p["channels"] == ["/feed/updates", "/records/ENC-TSK-R1", "/projects/enceladus"]
    assert isinstance(p["cursor"], int)


# actorId inference for MCP tracker.log writes (empty write_source.provider)


def test_actor_id_from_last_update_note_provider_marker():
    at, aid = mod.infer_actor({
        "write_source": {"provider": "", "channel": "mcp_server"},
        "last_update_note": "Created via tracker API [provider=ENC-SES-0NW, dispatch=D1]: x",
        "owner": "someone",
    })
    assert (at, aid) == ("agent", "ENC-SES-0NW")


def test_actor_id_from_last_history_entry_structured_then_description_marker():
    base = {"write_source": {"provider": "", "channel": "mcp_server"}}
    assert mod.infer_actor({**base, "history": [
        {"status": "worklog", "description": "old [provider=ENC-SES-OLD]"},
        {"status": "worklog", "provider": "ENC-SES-0AB", "description": "new"},
    ]}) == ("agent", "ENC-SES-0AB")
    assert mod.infer_actor({**base, "history": [
        {"status": "worklog", "description": "note [provider=ENC-SES-0CD]"},
    ]}) == ("agent", "ENC-SES-0CD")


def test_actor_id_from_checkout_holder_when_nothing_else_names_the_actor():
    assert mod.infer_actor({
        "write_source": {"provider": "", "channel": "mcp_server"},
        "history": [{"status": "worklog", "description": "plain text"}],
        "active_agent_session_id": "ENC-SES-0EF",
        "owner": "someone",
    }) == ("agent", "ENC-SES-0EF")


def test_actor_id_precedence_provider_beats_derived_and_legacy_fallbacks_kept():
    # write_source.provider wins over note/history/checkout.
    assert mod.infer_actor({
        "write_source": {"provider": "jreese", "channel": "mutation_api"},
        "last_update_note": "[provider=ENC-SES-X]",
        "active_agent_session_id": "ENC-SES-Y",
    }) == ("human", "jreese")
    # Existing precedence for non-session writes: updated_by/owner/assignee, then unknown.
    assert mod.infer_actor({"write_source": {"provider": ""}, "updated_by": "u", "owner": "o"})[1] == "u"
    assert mod.infer_actor({"owner": "o", "assignee": "a"})[1] == "o"
    assert mod.infer_actor({"assignee": "a"})[1] == "a"
    assert mod.infer_actor({"write_source": {"provider": "", "channel": "mcp_server"}})[1] == "unknown"


def test_tracker_log_update_event_resolves_actor_from_record_image_not_unknown():
    rec = _stream_record(
        event_name="MODIFY",
        new_image=_v2_image(
            write_source={"provider": "", "channel": "mcp_server"},
            last_update_note="worklog text",
            history=[{"status": "worklog", "description": "did a thing [provider=ENC-SES-0NW]"}],
        ),
    )
    p = mod.build_event_payload(rec, 0)
    assert p["actorId"] == "ENC-SES-0NW" and p["actorType"] == "agent"
    assert p["summary"].startswith("ENC-SES-0NW updated task")


# ---------------------------------------------------------------------------
# ENC-TSK-R55-0B: documents-table stream source, document-shaped v2 payload
# ---------------------------------------------------------------------------

_DOCS_ARN = "arn:aws:dynamodb:us-west-2:356364570033:table/documents-gamma/stream/2026-10-27T00:00:00.000"
_TRACKER_ARN = "arn:aws:dynamodb:us-west-2:356364570033:table/devops-project-tracker-gamma/stream/2026-10-27T00:00:00.000"


def _doc_record(event_name="MODIFY", arn=_DOCS_ARN, new=None, old=None, keys=None):
    rec = _stream_record(event_name=event_name, new_image=new, old_image=old, keys=keys)
    if arn:
        rec["eventSourceARN"] = arn
    return rec


def _doc_image(**over):
    img = {
        "document_id": "DOC-56AA3C4F96BF",
        "project_id": "enceladus",
        "title": "A governed document",
        "status": "active",
        "document_subtype": "design",
        "updated_at": "2026-10-27T01:00:00Z",
        "created_at": "2026-10-26T01:00:00Z",
        "version_seq": 77,
        "keywords": ["a", "b"],
    }
    img.update(over)
    return img


def test_is_documents_record_by_arn_and_by_shape():
    assert mod.is_documents_record(_doc_record(new=_doc_image()))
    assert not mod.is_documents_record(_doc_record(arn=_TRACKER_ARN, new=_v2_image()))
    # no ARN: fall back to image shape
    assert mod.is_documents_record(_doc_record(arn=None, new=_doc_image()))
    assert not mod.is_documents_record(_doc_record(arn=None, new=_v2_image()))


def test_document_create_event_payload_v2():
    p = mod.build_event_payload(_doc_record("INSERT", new=_doc_image()), 0)
    assert p["recordId"] == "DOC-56AA3C4F96BF"
    assert p["record_type"] == "document"
    assert p["action"] == "created"
    assert p["schemaVersion"] == 2
    assert p["recordTitle"] == "A governed document"
    assert p["recordStatus"] == "active"
    assert p["recordUpdatedAt"] == "2026-10-27T01:00:00Z"
    assert p["recordVersionSeq"] == 77
    assert p["documentSubtype"] == "design"
    assert "recordPriority" not in p
    assert p["channels"] == ["/feed/updates", "/records/DOC-56AA3C4F96BF", "/projects/enceladus"]
    assert _V1_KEYS <= set(p)
    assert "keywords" not in p  # tags are not carried (size)


def test_document_update_event_and_defaults():
    p = mod.build_event_payload(
        _doc_record(new=_doc_image(status="", title="", updated_at="", title_x=1), old=_doc_image()), 1
    )
    assert p["action"] == "updated"
    assert p["recordStatus"] == "active"            # default
    assert p["recordTitle"] == "DOC-56AA3C4F96BF"   # title falls back to the id
    assert p["recordUpdatedAt"] == "2026-10-26T01:00:00Z"  # falls back to created_at


def test_document_removed_on_remove_and_on_deleted_or_archived_status():
    rem = mod.build_event_payload(_doc_record("REMOVE", old=_doc_image()), 0)
    assert rem["action"] == "removed" and rem["recordTitle"] == "A governed document"
    for st in ("deleted", "archived"):
        p = mod.build_event_payload(_doc_record(new=_doc_image(status=st), old=_doc_image()), 0)
        assert p["action"] == "removed" and p["recordStatus"] == st


def test_document_counter_row_is_skipped():
    rec = _doc_record(new={"document_id": "__COUNTER__VERSION_SEQ__", "project_id": "__feed__", "version_seq": 9})
    assert mod.build_event_payload(rec, 0) is None
    rec = _doc_record(new={"document_id": "DOC-X", "record_type": "counter"})
    assert mod.build_event_payload(rec, 0) is None


def test_document_title_truncated_and_payload_small():
    p = mod.build_event_payload(_doc_record("INSERT", new=_doc_image(title="t" * 500)), 0)
    assert len(p["recordTitle"]) == 160
    assert len(json.dumps(p, separators=(",", ":")).encode()) < 1200


def test_document_event_has_no_full_record_body():
    assert mod.build_full_record_body(_doc_record(new=_doc_image())) is None
    # tracker behaviour unchanged
    assert mod.build_full_record_body(_stream_record(new_image=_v2_image())) is not None


def test_tracker_record_with_tracker_arn_unchanged_by_document_branch():
    rec = _stream_record(event_name="INSERT", new_image=_v2_image())
    rec["eventSourceARN"] = _TRACKER_ARN
    p = mod.build_event_payload(rec, 0)
    assert p["record_type"] == "task" and p["recordId"] == "ENC-TSK-R1"
    assert "documentSubtype" not in p


def test_handler_publishes_document_event_dry_run_and_skips_counter():
    event = {"Records": [
        _doc_record("INSERT", new=_doc_image()),
        _doc_record("MODIFY", new={"document_id": "__COUNTER__VERSION_SEQ__", "version_seq": 3}),
    ]}
    assert mod.handler(event, None) == {}
