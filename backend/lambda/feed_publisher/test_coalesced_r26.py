"""ENC-TSK-R26 (ENC-PLN-100 C2.1): MARK/SWEEP trailing-edge coalescing of the feed publish.

State-table behavior is exercised against moto's DynamoDB so the real UpdateExpression /
ConditionExpression strings run (reserved words, REMOVE+SET mixing, conditional failures), not a
hand-rolled fake. The property under test is the one ENC-ISS-543 taught us to protect: the
coalescer must never drop the LAST write (a closed task must not present as open).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

_SPEC = importlib.util.spec_from_file_location(
    "feed_publisher_lambda_r26", os.path.join(HERE, "lambda_function.py")
)
fp = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(fp)

import feed_utils  # noqa: E402  (bundled alongside the lambda)

TABLE = "enceladus-feed-publish-state"


def _sqs_record(project_id, message_id, *, event_name="MODIFY", image="NewImage", updated_at=None):
    img = {"project_id": {"S": project_id}}
    if updated_at:
        img["updated_at"] = {"S": updated_at}
    return {
        "messageId": message_id,
        "body": json.dumps(
            {"eventName": event_name, "dynamodb": {"Keys": {"record_id": {"S": "task#X"}}, image: img}}
        ),
    }


class Clock:
    """Controllable microsecond clock patched over fp._now_us."""

    def __init__(self, start=1_800_000_000_000_000):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += int(seconds * 1_000_000)


class SpyClient:
    """Delegating DynamoDB client that records calls and can inject failures."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = []
        self.fail_for = {}  # project_id -> error code

    def update_item(self, **kwargs):
        self.calls.append(("update_item", kwargs))
        pid = kwargs["Key"]["project_id"]["S"]
        code = self.fail_for.get(pid)
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "injected"}}, "UpdateItem")
        return self.inner.update_item(**kwargs)

    def scan(self, **kwargs):
        self.calls.append(("scan", kwargs))
        return self.inner.scan(**kwargs)

    def get_item(self, **kwargs):
        return self.inner.get_item(**kwargs)


@pytest.fixture
def state(monkeypatch):
    for k, v in {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_DEFAULT_REGION": "us-west-2",
    }.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        client.create_table(
            TableName=TABLE,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "project_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "project_id", "KeyType": "HASH"}],
        )
        spy = SpyClient(client)
        clock = Clock()
        with patch.object(fp, "_ddb_client", return_value=spy), patch.object(
            fp, "_now_us", clock
        ), patch.object(fp, "FEED_PUBLISH_MODE", fp.FEED_PUBLISH_MODE_COALESCED), patch.object(
            fp, "FEED_PUBLISH_STATE_TABLE", TABLE
        ), patch.object(fp, "FEED_CLAIM_GRACE_SECONDS", 5.0), patch.object(
            fp, "_record_project_activity", MagicMock(return_value=0)
        ):
            yield client, spy, clock


def _item(client, project_id):
    return client.get_item(TableName=TABLE, Key={"project_id": {"S": project_id}}).get("Item")


def _is_dirty(client, project_id):
    item = _item(client, project_id)
    return bool(item and item.get("dirty", {}).get("BOOL"))


def _publish_result(generated_at="2026-10-19T00:00:00Z", degraded=(), global_degraded=False):
    return fp.PublishResult(generated_at, set(degraded), global_degraded)


# ---------------------------------------------------------------------------
# MARK
# ---------------------------------------------------------------------------


def test_mark_issues_one_update_item_per_project_and_never_publishes(state):
    client, spy, clock = state
    event = {
        "Records": [
            _sqs_record("enceladus", "m1"),
            _sqs_record("enceladus", "m2"),
            _sqs_record("enceladus", "m3"),
            _sqs_record("devops", "m4"),
            _sqs_record("devops", "m5", event_name="REMOVE", image="OldImage"),
        ]
    }
    with patch.object(fp, "_publish_all", side_effect=AssertionError("MARK must not publish")):
        out = fp.handler(event, None)

    assert out == {}  # every record consumed: queue delivery stays 100%
    updates = [c for c in spy.calls if c[0] == "update_item"]
    assert len(updates) == 2  # one per distinct project_id, not per record
    assert {c[1]["Key"]["project_id"]["S"] for c in updates} == {"enceladus", "devops"}
    assert all(c[1]["TableName"] == TABLE for c in updates)
    assert _is_dirty(client, "enceladus") and _is_dirty(client, "devops")
    assert "last_write_at" in _item(client, "enceladus")
    fp._record_project_activity.assert_called_once()  # A83 stamp keeps running on the MARK path


def test_mark_remove_event_alone_marks_dirty(state):
    client, _spy, _clock = state
    out = fp.handler({"Records": [_sqs_record("enceladus", "m1", event_name="REMOVE", image="OldImage")]}, None)
    assert out == {}
    assert _is_dirty(client, "enceladus")


def test_mark_last_write_at_is_monotonic(state):
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": ["a"], "event_ts": None}})
    first = int(_item(client, "enceladus")["last_write_at"]["N"])
    clock.now -= 10_000_000  # an out-of-order MARK computed an older timestamp
    failed = fp._mark_projects_dirty({"enceladus": {"message_ids": ["b"], "event_ts": None}})
    assert failed == []  # condition failure == a newer mark already stored; not an error
    assert int(_item(client, "enceladus")["last_write_at"]["N"]) == first
    assert _is_dirty(client, "enceladus")


def test_mark_event_timestamp_is_clamped_not_trusted(state):
    client, _spy, clock = state
    far_future = "2099-01-01T00:00:00Z"
    fp._mark_projects_dirty({"enceladus": {"message_ids": ["a"], "event_ts": far_future}})
    stored = int(_item(client, "enceladus")["last_write_at"]["N"])
    assert stored == clock.now + fp._FUTURE_EVENT_CLAMP_US


def test_mark_failure_returns_only_that_projects_messages_to_the_queue(state):
    client, spy, _clock = state
    spy.fail_for["devops"] = "ProvisionedThroughputExceededException"
    event = {
        "Records": [
            _sqs_record("enceladus", "m1"),
            _sqs_record("devops", "m2"),
            _sqs_record("devops", "m3"),
        ]
    }
    out = fp.handler(event, None)
    assert out == {"batchItemFailures": [{"itemIdentifier": "m2"}, {"itemIdentifier": "m3"}]}
    assert _is_dirty(client, "enceladus")
    assert not _is_dirty(client, "devops")


def test_mark_unresolvable_record_is_returned_not_swallowed(state):
    out = fp.handler(
        {"Records": [{"messageId": "bad", "body": "not-json"}, _sqs_record("enceladus", "ok")]}, None
    )
    assert out == {"batchItemFailures": [{"itemIdentifier": "bad"}]}


# ---------------------------------------------------------------------------
# SWEEP
# ---------------------------------------------------------------------------


def test_sweep_with_no_dirty_projects_is_one_scan_and_nothing_else(state):
    _client, spy, _clock = state
    with patch.object(fp, "_publish_all", side_effect=AssertionError("idle sweep must not publish")):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["status"] == "idle"
    assert [c[0] for c in spy.calls] == ["scan"]  # no lease write, no claim


def test_sweep_skips_when_lease_is_held(state):
    client, spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": ["a"], "event_ts": None}})
    client.put_item(
        TableName=TABLE,
        Item={
            "project_id": {"S": fp._LEASE_KEY},
            "lease_expires_at": {"N": str(clock.now + 120_000_000)},
            "lease_owner": {"S": "other-sweep"},
        },
    )
    with patch.object(fp, "_publish_all", side_effect=AssertionError("must not double-publish")):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out == {"status": "skipped", "reason": "lease_held"}
    assert _is_dirty(client, "enceladus")
    assert _item(client, fp._LEASE_KEY)["lease_owner"]["S"] == "other-sweep"  # not stolen, not released


def test_sweep_takes_over_an_expired_lease_and_releases_its_own(state):
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": ["a"], "event_ts": None}})
    client.put_item(
        TableName=TABLE,
        Item={
            "project_id": {"S": fp._LEASE_KEY},
            "lease_expires_at": {"N": str(clock.now - 1)},
            "lease_owner": {"S": "dead-sweep"},
        },
    )
    clock.advance(60)  # the mark is older than the claim
    with patch.object(fp, "_publish_all", return_value=_publish_result()) as pub:
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["status"] == "published"
    pub.assert_called_once()
    lease = _item(client, fp._LEASE_KEY)
    assert "lease_owner" not in lease and "lease_expires_at" not in lease  # released


def test_sweep_publishes_once_for_all_dirty_projects_then_clears_each(state):
    client, spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    fp._mark_projects_dirty({"devops": {"message_ids": [], "event_ts": None}})
    clock.advance(60)
    with patch.object(fp, "_publish_all", return_value=_publish_result()) as pub:
        out = fp.handler({"action": "feed_sweep"}, None)
    pub.assert_called_once_with({"enceladus", "devops"})  # ONE full publish, not one per project
    assert sorted(out["cleared"]) == ["devops", "enceladus"] and out["retained"] == []
    assert not _is_dirty(client, "enceladus") and not _is_dirty(client, "devops")
    item = _item(client, "enceladus")
    assert item["last_published_at"]["S"] == "2026-10-19T00:00:00Z"
    assert "claimed_at" in item and "dirty_since" not in item


def test_write_during_publish_keeps_the_project_dirty(state):
    """The trailing-edge property: a MARK that lands while the publish runs must survive."""
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    clock.advance(60)

    def publish_while_a_write_lands(_affected):
        clock.advance(20)  # the publish is slow...
        fp._mark_projects_dirty({"enceladus": {"message_ids": ["late"], "event_ts": None}})
        clock.advance(5)
        return _publish_result()

    with patch.object(fp, "_publish_all", side_effect=publish_while_a_write_lands):
        out = fp.handler({"action": "feed_sweep"}, None)

    assert out["cleared"] == [] and out["retained"] == ["enceladus"]
    assert _is_dirty(client, "enceladus")  # the late write is still owed a publish
    # ...and the next sweep picks it up and clears it.
    clock.advance(300)
    with patch.object(fp, "_publish_all", return_value=_publish_result()) as pub:
        out2 = fp.handler({"action": "feed_sweep"}, None)
    pub.assert_called_once()
    assert out2["cleared"] == ["enceladus"] and not _is_dirty(client, "enceladus")


def test_write_inside_the_claim_grace_window_keeps_the_project_dirty(state):
    """A MARK just before the claim may belong to a write the (eventually consistent) GSI read
    has not seen yet, so it must not be cleared by this sweep."""
    client, _spy, clock = state
    clock.advance(100)
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    clock.advance(2)  # claim happens 2s after the mark, inside the 5s grace
    with patch.object(fp, "_publish_all", return_value=_publish_result()):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["retained"] == ["enceladus"] and _is_dirty(client, "enceladus")


def test_project_marked_after_the_scan_is_left_for_the_next_sweep(state):
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    clock.advance(60)

    def publish_while_new_project_appears(_affected):
        fp._mark_projects_dirty({"newproj": {"message_ids": [], "event_ts": None}})
        return _publish_result()

    with patch.object(fp, "_publish_all", side_effect=publish_while_new_project_appears):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["cleared"] == ["enceladus"]
    assert _is_dirty(client, "newproj")  # untouched: never claimed, never cleared


def test_failed_publish_leaves_everything_dirty_and_releases_the_lease(state):
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    clock.advance(60)
    with patch.object(fp, "_publish_all", side_effect=RuntimeError("s3 down")):
        with pytest.raises(RuntimeError):
            fp.handler({"action": "feed_sweep"}, None)
    assert _is_dirty(client, "enceladus")
    assert "lease_owner" not in _item(client, fp._LEASE_KEY)  # next sweep is not blocked


def test_degraded_publish_does_not_clear_dirty(state):
    client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    fp._mark_projects_dirty({"devops": {"message_ids": [], "event_ts": None}})
    clock.advance(60)
    # enceladus's tracker read failed: an EMPTY feed was published for it. Must stay dirty.
    with patch.object(fp, "_publish_all", return_value=_publish_result(degraded={"enceladus"})):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["cleared"] == ["devops"] and out["retained"] == ["enceladus"]
    assert _is_dirty(client, "enceladus") and not _is_dirty(client, "devops")

    clock.advance(300)
    with patch.object(fp, "_publish_all", return_value=_publish_result(global_degraded=True)):
        out = fp.handler({"action": "feed_sweep"}, None)
    assert out["cleared"] == [] and _is_dirty(client, "enceladus")


def test_sweep_refreshes_the_projects_cache_before_publishing(state):
    _client, _spy, clock = state
    fp._mark_projects_dirty({"enceladus": {"message_ids": [], "event_ts": None}})
    clock.advance(60)
    fp._projects_cache = [{"name": "stale"}]
    fp._projects_cache_at = 1e18
    seen = {}

    def capture(_affected):
        seen["cache"] = fp._projects_cache
        return _publish_result()

    with patch.object(fp, "_publish_all", side_effect=capture):
        fp.handler({"action": "feed_sweep"}, None)
    assert seen["cache"] is None  # a project registered since the cache fill cannot be missed


# ---------------------------------------------------------------------------
# per_batch is unchanged; flags
# ---------------------------------------------------------------------------


def test_per_batch_sqs_path_still_publishes_and_never_touches_the_state_table():
    client = MagicMock()
    event = {"Records": [_sqs_record("enceladus", "m1")]}
    with patch.object(fp, "FEED_PUBLISH_MODE", fp.FEED_PUBLISH_MODE_PER_BATCH), patch.object(
        fp, "_ddb_client", return_value=client
    ), patch.object(fp, "_record_project_activity", MagicMock()), patch.object(
        fp, "_publish_all", return_value=_publish_result()
    ) as pub:
        out = fp.handler(event, None)
    assert out == {}
    pub.assert_called_once_with({"enceladus"})
    client.update_item.assert_not_called()


def test_sweep_event_is_inert_in_per_batch_mode():
    with patch.object(fp, "FEED_PUBLISH_MODE", fp.FEED_PUBLISH_MODE_PER_BATCH), patch.object(
        fp, "_ddb_client", side_effect=AssertionError("per_batch sweep must not open the state table")
    ):
        assert fp.handler({"action": "feed_sweep"}, None) == {
            "status": "skipped",
            "reason": "per_batch_mode",
        }


def test_publish_mode_normalization_fails_safe_to_per_batch():
    assert fp._normalize_publish_mode(None) == "per_batch"
    assert fp._normalize_publish_mode("") == "per_batch"
    assert fp._normalize_publish_mode("per_batch") == "per_batch"
    assert fp._normalize_publish_mode("typo") == "per_batch"
    assert fp._normalize_publish_mode(" Coalesced ") == "coalesced"


def _run_full_publish(*, mode, invalidate):
    s3 = MagicMock(return_value=["k"])
    cf = MagicMock(return_value="INV-1")
    with patch.object(fp, "FEED_PUBLISH_MODE", mode), patch.object(fp, "FEED_INVALIDATE", invalidate), patch.object(
        fp, "FEED_S3_PUBLISH_ENABLED", True
    ), patch.object(fp, "_all_project_entries", return_value=[]), patch.object(
        fp, "_ddb_client", return_value=MagicMock()
    ), patch.object(fp, "generate_mobile_feeds"), patch.object(fp, "generate_documents_feed"), patch.object(
        fp, "_generate_deploy_pending_feed"
    ), patch.object(fp, "check_freshness_sla"), patch.object(
        fp, "generate_reference_docs_from_s3"
    ), patch.object(fp, "publish_mobile_feeds_to_s3", s3), patch.object(
        fp, "invalidate_mobile_cf", cf
    ), patch.object(fp, "write_analytics_sync_stage", return_value={}), patch.object(
        fp.boto3, "client", return_value=MagicMock()
    ):
        fp._publish_all(set())
    return s3, cf


def test_invalidate_flag_true_keeps_todays_invalidation():
    _s3, cf = _run_full_publish(mode="per_batch", invalidate=True)
    cf.assert_called_once()


def test_invalidate_flag_false_drops_createinvalidation_but_still_publishes():
    s3, cf = _run_full_publish(mode="coalesced", invalidate=False)
    s3.assert_called_once()
    cf.assert_not_called()


def test_cache_control_override_only_in_coalesced_mode():
    s3, _cf = _run_full_publish(mode="coalesced", invalidate=False)
    assert s3.call_args.kwargs["cache_control"] == "max-age=60"
    s3b, _cfb = _run_full_publish(mode="per_batch", invalidate=True)
    assert "cache_control" not in s3b.call_args.kwargs  # byte-identical call


def test_feed_utils_cache_control_default_and_override():
    with tempfile.TemporaryDirectory() as tmp:
        feed_dir = Path(tmp)
        (feed_dir / "tasks.json").write_text("{}")
        store = MagicMock()
        with patch.object(feed_utils, "_feed_content_store", return_value=store), patch.object(
            feed_utils.boto3, "client", return_value=MagicMock()
        ):
            feed_utils.publish_mobile_feeds_to_s3(feed_dir, bucket="b", s3_prefix="mobile/v1")
            default_extra = store.upload_file.call_args.args[2]
            feed_utils.publish_mobile_feeds_to_s3(
                feed_dir, bucket="b", s3_prefix="mobile/v1", cache_control="max-age=60"
            )
            override_extra = store.upload_file.call_args.args[2]
    assert default_extra["CacheControl"] == "max-age=0, s-maxage=30, must-revalidate"
    assert override_extra["CacheControl"] == "max-age=60"
    assert "stale-while-revalidate" not in override_extra["CacheControl"]  # ruling A3
