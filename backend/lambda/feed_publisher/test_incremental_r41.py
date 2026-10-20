"""ENC-TSK-R41 (ENC-PLN-100 C4.1, FR-22, ruling P100-R28): incremental tracker re-read.

Runs the real MARK / SWEEP / _publish_all / _build_project_model code against moto DynamoDB (state
table + tracker table with the real key schema and project-type-index) and moto S3 (the snapshot
bucket), so the actual UpdateExpression / ConditionExpression strings, string-set ADD / DELETE and
BatchGetItem run. The properties under test are the ones a missed delete or a late write would break:
  * a delta merge reproduces what a full re-read would (update, insert, REMOVE);
  * the change ids / read_watermark / last_full_reread_at only move after a successful publish;
  * an id a MARK adds during a publish survives the clear and dirty stays set;
  * overflow, a missing / old snapshot and any merge error all self-heal with a full re-read;
  * FEED_INCREMENTAL off is today's behavior.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

_SPEC = importlib.util.spec_from_file_location("feed_publisher_lambda_r41", os.path.join(HERE, "lambda_function.py"))
fp = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(fp)

import feed_utils  # noqa: E402

STATE = "enceladus-feed-publish-state"
TRACKER = "devops-project-tracker"
BUCKET = "enc-content-test"
PROJECT = "enceladus"
CTX = SimpleNamespace(aws_request_id="req-1", get_remaining_time_in_millis=lambda: 60_000)


class Clock:
    def __init__(self, start=1_800_000_000_000_000):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += int(seconds * 1_000_000)


class Spy:
    """Delegating DynamoDB client recording update_item calls."""

    def __init__(self, inner):
        self.inner = inner
        self.updates = []

    def update_item(self, **kw):
        self.updates.append(kw)
        return self.inner.update_item(**kw)

    def __getattr__(self, name):
        return getattr(self.inner, name)


def _tracker_item(rid, title="t", status="open", project=PROJECT, rtype=None):
    rtype = rtype or rid.split("#", 1)[0]
    return {
        "project_id": {"S": project}, "record_id": {"S": rid}, "record_type": {"S": rtype},
        "item_id": {"S": rid.split("#", 1)[1]}, "title": {"S": title}, "status": {"S": status},
        "updated_at": {"S": "2026-10-19T00:00:00Z"},
    }


def _rec(rid, event="MODIFY", project=PROJECT, keys=True):
    img = {"project_id": {"S": project}}
    dyn = {("OldImage" if event == "REMOVE" else "NewImage"): img}
    if keys:
        dyn["Keys"] = {"project_id": {"S": project}, "record_id": {"S": rid}}
    return {"messageId": f"m-{rid}-{event}", "body": json.dumps({"eventName": event, "dynamodb": dyn})}


@pytest.fixture
def env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-west-2"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ddb = boto3.client("dynamodb", region_name="us-west-2")
        ddb.create_table(
            TableName=STATE, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "project_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "project_id", "KeyType": "HASH"}],
        )
        ddb.create_table(
            TableName=TRACKER, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": "project_id", "AttributeType": "S"},
                {"AttributeName": "record_id", "AttributeType": "S"},
                {"AttributeName": "record_type", "AttributeType": "S"},
            ],
            KeySchema=[{"AttributeName": "project_id", "KeyType": "HASH"}, {"AttributeName": "record_id", "KeyType": "RANGE"}],
            GlobalSecondaryIndexes=[{
                "IndexName": "project-type-index",
                "KeySchema": [{"AttributeName": "project_id", "KeyType": "HASH"}, {"AttributeName": "record_type", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )
        s3 = boto3.client("s3", region_name="us-west-2")
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "us-west-2"})
        spy, clock = Spy(ddb), Clock()
        with contextlib.ExitStack() as stack:
            for p in (
                patch.object(fp, "_ddb_client", return_value=spy),
                patch.object(fp, "_now_us", clock),
                patch.object(fp, "FEED_PUBLISH_MODE", fp.FEED_PUBLISH_MODE_COALESCED),
                patch.object(fp, "FEED_INCREMENTAL", True),
                patch.object(fp, "FEED_INCREMENTAL_MAX_IDS", 1000),
                patch.object(fp, "FEED_FULL_REREAD_SECONDS", 86400.0),
                patch.object(fp, "SNAPSHOT_BUCKET", BUCKET),
                patch.object(fp, "FEED_PUBLISH_STATE_TABLE", STATE),
                patch.object(fp, "TRACKER_TABLE", TRACKER),
                patch.object(fp, "TRACKER_REGION", "us-west-2"),
                patch.object(fp, "FEED_CLAIM_GRACE_SECONDS", 5.0),
                patch.object(fp, "FEED_S3_PUBLISH_ENABLED", False),
                patch.object(fp, "_record_project_activity", MagicMock(return_value=0)),
                patch.object(fp, "_all_project_entries", return_value=[SimpleNamespace(name=PROJECT)]),
                patch.object(fp, "fetch_documents_from_dynamodb", return_value=[]),
                patch.object(fp, "generate_documents_feed"),
                patch.object(fp, "_generate_deploy_pending_feed"),
                patch.object(fp, "check_freshness_sla"),
                patch.object(fp, "generate_reference_docs_from_s3"),
                patch.object(fp, "write_analytics_sync_stage", return_value={}),
                patch.object(fp, "publish_sync_message"),
                patch.object(fp, "publish_eventbridge_event"),
                patch.object(fp, "invalidate_mobile_cf", return_value="inv"),
            ):
                stack.enter_context(p)
            yield SimpleNamespace(ddb=ddb, spy=spy, clock=clock, s3=s3, published=[])


def _row(env, project=PROJECT):
    return env.ddb.get_item(TableName=STATE, Key={"project_id": {"S": project}}, ConsistentRead=True).get("Item") or {}


def _ss(env, attr, project=PROJECT):
    return set((_row(env, project).get(attr) or {}).get("SS") or [])


def _dirty(env):
    return bool(_row(env).get("dirty", {}).get("BOOL"))


def _put(env, *items):
    for it in items:
        env.ddb.put_item(TableName=TRACKER, Item=it)


def _sweep(env, tmp, *, during_publish=None, gen_error=None):
    """Run one real SWEEP; env.published collects the task ids generate_mobile_feeds received."""

    def gen(entries, data, generated_at, out, **kw):
        if during_publish:
            during_publish()
        if gen_error:
            raise gen_error
        env.published.append(sorted(t["id"] for d in data.values() for t in d["tasks"]))

    with patch.object(fp, "generate_mobile_feeds", side_effect=gen), patch.object(fp, "FEED_TEMP_DIR", Path(tmp)):
        return fp._handle_sweep(CTX)


def _mark(env, *records):
    return fp._handle_mark({"Records": list(records)})


# ---------------------------------------------------------------------------
# MARK
# ---------------------------------------------------------------------------


def test_mark_adds_ids_in_the_same_single_update_item(env):
    resp = _mark(env, _rec("task#A"), _rec("task#B", "REMOVE"), _rec("issue#C"))
    assert not resp.get("batchItemFailures")
    state_updates = [u for u in env.spy.updates if u["TableName"] == STATE]
    assert len(state_updates) == 1, "one conditional UpdateItem per project per batch"
    u = state_updates[0]
    assert "ADD changed_ids :ids, removed_ids :rids" in u["UpdateExpression"] and "ConditionExpression" in u
    assert _dirty(env)
    assert _ss(env, "changed_ids") == {"task#A", "task#B", "issue#C"}
    assert _ss(env, "removed_ids") == {"task#B"}
    assert "full_reread" not in _row(env)


def test_mark_flag_off_is_the_pre_r41_update(env):
    with patch.object(fp, "FEED_INCREMENTAL", False):
        _mark(env, _rec("task#A"))
    u = [u for u in env.spy.updates if u["TableName"] == STATE][0]
    assert u["UpdateExpression"] == fp._MARK_UPDATE and "ReturnValues" not in u
    assert _dirty(env) and "changed_ids" not in _row(env)


def test_mark_batch_over_the_cap_sets_full_reread_instead_of_ids(env):
    with patch.object(fp, "FEED_INCREMENTAL_MAX_IDS", 3):
        _mark(env, *[_rec(f"task#{i}") for i in range(5)])
    row = _row(env)
    assert row["full_reread"]["BOOL"] is True and "changed_ids" not in row and _dirty(env)


def test_mark_set_growing_past_the_cap_across_batches_flips_to_full_reread(env):
    with patch.object(fp, "FEED_INCREMENTAL_MAX_IDS", 3):
        _mark(env, _rec("task#1"), _rec("task#2"))
        assert _ss(env, "changed_ids") == {"task#1", "task#2"} and "full_reread" not in _row(env)
        env.clock.advance(1)
        _mark(env, _rec("task#3"), _rec("task#4"))
    row = _row(env)
    assert row["full_reread"]["BOOL"] is True and "changed_ids" not in row and _dirty(env)


def test_mark_with_unreadable_stream_key_forces_full_reread(env):
    _mark(env, _rec("task#A", keys=False))  # no Keys, and the image has no record_id
    assert _row(env)["full_reread"]["BOOL"] is True


def test_mark_for_a_documents_row_adds_no_id_and_no_full_reread(env):
    rec = {"messageId": "d1", "body": json.dumps({"eventName": "MODIFY", "dynamodb": {
        "Keys": {"document_id": {"S": "DOC-1"}}, "NewImage": {"project_id": {"S": PROJECT}, "document_id": {"S": "DOC-1"}}}})}
    _mark(env, rec)
    row = _row(env)
    assert _dirty(env) and "changed_ids" not in row and "full_reread" not in row


def test_out_of_order_mark_still_lands_its_ids(env):
    # MARK 1 carries a future event time (clamped to now+60s) -> last_write_at runs ahead of "now".
    future = "2027-01-01T00:00:00Z"
    r1 = _rec("task#A")
    body = json.loads(r1["body"])
    body["dynamodb"]["NewImage"]["updated_at"] = {"S": future}
    r1["body"] = json.dumps(body)
    _mark(env, r1)
    first = int(_row(env)["last_write_at"]["N"])
    _mark(env, _rec("task#B"))  # processing-time ts is older than last_write_at -> condition fails -> fallback
    assert int(_row(env)["last_write_at"]["N"]) == first, "last_write_at must never move backwards"
    assert _ss(env, "changed_ids") == {"task#A", "task#B"} and _dirty(env)


def test_stream_record_key_classification():
    key = fp._stream_record_key
    assert key({"eventName": "REMOVE"}, {"Keys": {"record_id": {"S": "task#A"}}, "OldImage": {"x": {"S": "1"}}}) == ("task#A", True)
    assert key({}, {"NewImage": {"record_id": {"S": "task#A"}}}) == ("task#A", False)
    assert key({}, {"Keys": {"document_id": {"S": "DOC-1"}}}) == ("", False)
    assert key({}, {"NewImage": {"project_id": {"S": "p"}}}) == (None, False)


# ---------------------------------------------------------------------------
# SWEEP: delta merge
# ---------------------------------------------------------------------------


def _first_full_publish(env, tmp):
    _put(env, _tracker_item("task#A", "a"), _tracker_item("task#B", "b"), _tracker_item("issue#I1", "i"))
    _mark(env, _rec("task#A"), _rec("task#B"), _rec("issue#I1"))
    env.clock.advance(60)
    out = _sweep(env, tmp)
    assert out["status"] == "published" and out["cleared"] == [PROJECT]
    return out


def test_first_sweep_is_a_full_read_that_saves_a_snapshot_and_clears_ids(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        assert env.published[-1] == ["A", "B"]
        snap = fp._load_snapshot(PROJECT)
        assert set(snap["items"]) == {"task#A", "task#B", "issue#I1"}
        row = _row(env)
        assert "dirty" not in row and "changed_ids" not in row and "removed_ids" not in row
        assert "last_full_reread_at" in row and "read_watermark" in row and "last_published_at" in row


def test_delta_merge_update_insert_and_remove(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        # update A, insert C, delete B
        _put(env, _tracker_item("task#A", "a2", status="closed"), _tracker_item("task#C", "c"))
        env.ddb.delete_item(TableName=TRACKER, Key={"project_id": {"S": PROJECT}, "record_id": {"S": "task#B"}})
        env.clock.advance(60)
        _mark(env, _rec("task#A"), _rec("task#C"), _rec("task#B", "REMOVE"))
        env.clock.advance(60)
        calls = []
        real_batch = fp.batch_get_tracker_items
        with patch.object(fp, "query_project_items", side_effect=AssertionError("incremental must not re-query the project")), \
                patch.object(fp, "batch_get_tracker_items", side_effect=lambda *a, **k: (calls.append(a[1]), real_batch(*a, **k))[1]):
            out = _sweep(env, tmp)
        assert out["status"] == "published" and out["cleared"] == [PROJECT]
        assert calls == [["task#A", "task#B", "task#C"]], "BatchGet exactly the changed ids"
        assert env.published[-1] == ["A", "C"], "B (REMOVE) is dropped, C inserted"
        snap = fp._load_snapshot(PROJECT)
        assert set(snap["items"]) == {"task#A", "task#C", "issue#I1"}
        assert snap["items"]["task#A"]["title"]["S"] == "a2"
        assert "changed_ids" not in _row(env) and "removed_ids" not in _row(env) and not _dirty(env)


def test_incremental_equals_full_reread(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _put(env, _tracker_item("task#Z", "z"), _tracker_item("task#A", "a3"))
        _mark(env, _rec("task#Z"), _rec("task#A"))
        env.clock.advance(60)
        _sweep(env, tmp)
        incremental = fp._load_snapshot(PROJECT)["items"]
        assert incremental == feed_utils.query_project_items(PROJECT, TRACKER, "us-west-2")


def test_removed_then_recreated_record_is_kept(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        # B was removed and re-created inside the window: it is in BOTH sets but exists -> kept.
        _put(env, _tracker_item("task#B", "b-reborn"))
        _mark(env, _rec("task#B", "REMOVE"), _rec("task#B", "INSERT"))
        env.clock.advance(60)
        _sweep(env, tmp)
        assert env.published[-1] == ["A", "B"]
        assert fp._load_snapshot(PROJECT)["items"]["task#B"]["title"]["S"] == "b-reborn"


def test_unchanged_clean_projects_reuse_the_snapshot_without_any_tracker_read(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _mark(env, _rec("task#A"))
        env.clock.advance(60)
        with patch.object(fp, "query_project_items", side_effect=AssertionError("no full read")):
            _sweep(env, tmp)
        assert env.published[-1] == ["A", "B"]


# ---------------------------------------------------------------------------
# SWEEP: watermark, reconciliation, overflow, errors
# ---------------------------------------------------------------------------


def test_nothing_advances_when_the_publish_fails_then_it_does_on_success(env):
    with tempfile.TemporaryDirectory() as tmp:
        _put(env, _tracker_item("task#A", "a"))
        _mark(env, _rec("task#A"))
        env.clock.advance(60)
        with pytest.raises(RuntimeError):
            _sweep(env, tmp, gen_error=RuntimeError("publish down"))
        row = _row(env)
        assert _dirty(env) and _ss(env, "changed_ids") == {"task#A"}
        assert "read_watermark" not in row and "last_published_at" not in row and "last_full_reread_at" not in row
        assert fp._load_snapshot(PROJECT) is None, "snapshot is only saved after the publish step"
        env.clock.advance(60)
        out = _sweep(env, tmp)
        assert out["cleared"] == [PROJECT]
        assert "read_watermark" in _row(env) and not _dirty(env)


def test_failed_snapshot_save_keeps_the_project_dirty_with_its_ids(env):
    with tempfile.TemporaryDirectory() as tmp:
        _put(env, _tracker_item("task#A", "a"))
        _mark(env, _rec("task#A"))
        env.clock.advance(60)
        with patch.object(fp, "_save_snapshot", return_value=False):
            out = _sweep(env, tmp)
        assert out["retained"] == [PROJECT] and out["cleared"] == []
        assert _dirty(env) and _ss(env, "changed_ids") == {"task#A"}


def test_snapshot_older_than_24h_forces_a_full_reread_and_resets_the_clock(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        snap = fp._load_snapshot(PROJECT)
        assert fp._save_snapshot(PROJECT, snap["items"], time.time() - 90_000)  # > 24 h old
        _put(env, _tracker_item("task#N", "n"))
        _mark(env, _rec("task#N"))
        env.clock.advance(60)
        with patch.object(fp, "batch_get_tracker_items", side_effect=AssertionError("must reconcile with a full read")) as bg, \
                patch.object(fp, "query_project_items", wraps=fp.query_project_items) as q:
            # the strong overlay also uses batch_get; allow it to fail softly (it is best effort)
            bg.side_effect = RuntimeError("overlay unavailable")
            _sweep(env, tmp)
        assert q.call_count == 1
        assert env.published[-1] == ["A", "B", "N"]
        assert time.time() - fp._load_snapshot(PROJECT)["full_read_at"] < 60
        assert int(_row(env)["last_full_reread_at"]["N"]) > time.time() - 60


def test_full_reread_flag_overrides_a_fresh_snapshot_and_is_cleared_when_honored(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _put(env, _tracker_item("task#N", "n"))
        with patch.object(fp, "FEED_INCREMENTAL_MAX_IDS", 1):
            _mark(env, _rec("task#N"), _rec("task#A"))  # 2 ids > cap 1 -> full_reread
        assert _row(env)["full_reread"]["BOOL"] is True
        env.clock.advance(60)
        with patch.object(fp, "query_project_items", wraps=fp.query_project_items) as q:
            _sweep(env, tmp)
        assert q.call_count == 1 and env.published[-1] == ["A", "B", "N"]
        assert "full_reread" not in _row(env) and not _dirty(env)


def test_merge_error_self_heals_with_a_full_reread(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _put(env, _tracker_item("task#N", "n"))
        _mark(env, _rec("task#N"))
        env.clock.advance(60)
        with patch.object(fp, "batch_get_tracker_items", side_effect=RuntimeError("throttled")), \
                patch.object(fp, "query_project_items", wraps=fp.query_project_items) as q:
            out = _sweep(env, tmp)
        assert out["cleared"] == [PROJECT] and q.call_count == 1
        assert env.published[-1] == ["A", "B", "N"]


def test_unprocessed_keys_are_retried(monkeypatch):
    calls = []

    class FakeDdb:
        def batch_get_item(self, RequestItems, ReturnConsumedCapacity):
            calls.append(RequestItems)
            keys = RequestItems[TRACKER]["Keys"]
            assert RequestItems[TRACKER]["ConsistentRead"] is True
            if len(calls) == 1:
                return {"Responses": {TRACKER: [_tracker_item(keys[0]["record_id"]["S"])]},
                        "UnprocessedKeys": {TRACKER: {"Keys": keys[1:], "ConsistentRead": True}},
                        "ConsumedCapacity": [{"TableName": TRACKER, "CapacityUnits": 1.5}]}
            return {"Responses": {TRACKER: [_tracker_item(k["record_id"]["S"]) for k in keys]}, "UnprocessedKeys": {},
                    "ConsumedCapacity": [{"TableName": TRACKER, "CapacityUnits": 2.0}]}

    monkeypatch.setattr(feed_utils.boto3, "client", lambda *a, **k: FakeDdb())
    feed_utils.reset_read_units()
    got = feed_utils.batch_get_tracker_items(PROJECT, [f"task#{i}" for i in range(3)], TRACKER, "us-west-2", sleep=lambda s: None)
    assert set(got) == {"task#0", "task#1", "task#2"} and len(calls) == 2
    assert feed_utils.read_units_total() == pytest.approx(3.5)


def test_batch_get_chunks_of_100(monkeypatch):
    sizes = []

    class FakeDdb:
        def batch_get_item(self, RequestItems, ReturnConsumedCapacity):
            keys = RequestItems[TRACKER]["Keys"]
            sizes.append(len(keys))
            return {"Responses": {TRACKER: []}, "UnprocessedKeys": {}}

    monkeypatch.setattr(feed_utils.boto3, "client", lambda *a, **k: FakeDdb())
    feed_utils.batch_get_tracker_items(PROJECT, [f"task#{i:04d}" for i in range(250)], TRACKER, "us-west-2")
    assert sizes == [100, 100, 50]


# ---------------------------------------------------------------------------
# R26 invariant: a write during the publish keeps its id and dirty
# ---------------------------------------------------------------------------


def test_mark_during_publish_keeps_its_id_and_dirty_then_next_sweep_picks_it_up(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _put(env, _tracker_item("task#A", "a2"))
        _mark(env, _rec("task#A"))
        env.clock.advance(60)

        def write_lands_mid_publish():
            env.clock.advance(1)
            _put(env, _tracker_item("task#LATE", "late"))
            _mark(env, _rec("task#LATE"))

        out = _sweep(env, tmp, during_publish=write_lands_mid_publish)
        assert out["retained"] == [PROJECT] and out["cleared"] == []
        assert _dirty(env), "trailing edge: a MARK after the claim keeps the project dirty"
        assert "task#LATE" in _ss(env, "changed_ids")
        env.clock.advance(60)
        out2 = _sweep(env, tmp)
        assert out2["cleared"] == [PROJECT]
        assert env.published[-1] == ["A", "B", "LATE"]
        assert not _dirty(env) and "changed_ids" not in _row(env)


def test_clear_deletes_only_processed_ids_and_redirties_on_leftovers(env):
    """A late MARK whose last_write_at predates the cutoff (the condition still passes) must not lose its id."""
    _mark(env, _rec("task#A"))
    claimed_at = int(_row(env)["last_write_at"]["N"]) + 10_000_000
    plan = {"mode": "incremental", "processed_changed": {"task#A"}, "processed_removed": set(), "full_honored": False,
            "full_read_at": time.time()}
    env.ddb.update_item(TableName=STATE, Key={"project_id": {"S": PROJECT}},
                        UpdateExpression="ADD changed_ids :x", ExpressionAttributeValues={":x": {"SS": ["task#LATE"]}})
    ok = fp._clear_with_ids(env.spy, PROJECT, claimed_at, 5_000_000, "2026-10-19T00:00:00Z", plan)
    assert ok is False and _dirty(env) and _ss(env, "changed_ids") == {"task#LATE"}


# ---------------------------------------------------------------------------
# Flag off, metrics
# ---------------------------------------------------------------------------


def test_flag_off_sweep_is_unchanged_no_snapshot_no_id_clear(env, capsys):
    with tempfile.TemporaryDirectory() as tmp, patch.object(fp, "FEED_INCREMENTAL", False), \
            patch.object(fp, "fetch_from_dynamodb", side_effect=lambda e, **kw: {"tasks": [{"id": "A"}], "issues": [], "features": []}) as f, \
            patch.object(fp, "_build_project_model", side_effect=AssertionError("flag off must not use the model builder")):
        _mark(env, _rec("task#A"))
        env.clock.advance(60)
        out = _sweep(env, tmp)
        assert out["cleared"] == [PROJECT] and f.call_count == 1
        row = _row(env)
        assert "dirty" not in row and "read_watermark" not in row and "last_full_reread_at" not in row
        assert "changed_ids" not in row
        claim = [u for u in env.spy.updates if u["UpdateExpression"] == fp._CLAIM_UPDATE][0]
        assert "ReturnValues" not in claim, "flag off: claim call is unchanged"
        s3_keys = env.s3.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0)
        assert s3_keys == 0
    metrics = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith('{"_aws"')]
    assert len(metrics) == 1 and metrics[0]["Mode"] == "full"


def test_sweep_emits_one_emf_record_with_the_three_metrics(env, capsys):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        capsys.readouterr()
        _put(env, _tracker_item("task#N", "n"))
        _mark(env, _rec("task#N"))
        env.clock.advance(60)
        _sweep(env, tmp)
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith('{"_aws"')]
    assert len(lines) == 1
    rec = lines[0]
    declared = {m["Name"] for m in rec["_aws"]["CloudWatchMetrics"][0]["Metrics"]}
    assert declared == {"FeedPublishBytes", "FeedPublishReadUnits", "FeedPublishMode"}
    assert rec["Mode"] == "incremental" and rec["FeedPublishMode"] == 1
    assert isinstance(rec["FeedPublishBytes"], int) and rec["FeedPublishReadUnits"] >= 0
    assert rec["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "Enceladus/FeedPublisher"
    assert rec["ProjectModes"] == {PROJECT: "incremental"}


def test_uploaded_bytes_prefers_stored_bytes_and_tolerates_missing_files(tmp_path):
    (tmp_path / "a.json").write_bytes(b"x" * 10)
    n = fp._uploaded_bytes(tmp_path, "mobile/v1", ["mobile/v1/a.json", "mobile/v1/gone.json", "mobile/v1/z.json"],
                           {"stored_bytes": {"mobile/v1/z.json": 7}})
    assert n == 17


def test_snapshot_roundtrip_and_rejects_foreign_project():
    blob = feed_utils.snapshot_encode("p1", {"task#A": _tracker_item("task#A")}, 10.0, 11.0)
    assert feed_utils.snapshot_decode(blob, "p1")["items"]["task#A"]["title"]["S"] == "t"
    assert feed_utils.snapshot_decode(blob, "p2") is None
    assert feed_utils.snapshot_decode(b"not gzip", "p1") is None
    with pytest.raises(TypeError):
        feed_utils.snapshot_encode("p1", {"task#A": {"blob": {"B": b"\x00"}}}, 1.0, 1.0)


# ---------------------------------------------------------------------------
# Snapshot staleness: a publish that did not refresh the snapshot forces a full re-read
# ---------------------------------------------------------------------------


def _age_snapshot(seconds):
    snap = fp._load_snapshot(PROJECT)
    blob = feed_utils.snapshot_encode(PROJECT, snap["items"], snap["full_read_at"], snap["saved_at"] - seconds)
    fp._snapshot_s3().put_object(Bucket=BUCKET, Key=fp._snapshot_key(PROJECT), Body=blob)


def test_flag_toggled_off_publish_then_on_forces_a_full_reread(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _age_snapshot(60)  # time passes: the flag-off publish below happens after the snapshot was saved
        # flag OFF: a change is published without ids and without refreshing the snapshot
        _put(env, _tracker_item("task#A", "a-while-off"))
        with patch.object(fp, "FEED_INCREMENTAL", False), patch.object(
            fp, "fetch_from_dynamodb", side_effect=lambda e, **kw: {"tasks": [{"id": "A"}], "issues": [], "features": []}
        ):
            _mark(env, _rec("task#A"))
            assert "changed_ids" not in _row(env)
            env.clock.advance(60)
            assert _sweep(env, tmp)["cleared"] == [PROJECT]
        assert fp._load_snapshot(PROJECT)["items"]["task#A"]["title"]["S"] == "a", "snapshot is stale now"
        # flag back ON: a different id arrives; the incremental path would merge only it and keep A stale
        _put(env, _tracker_item("task#N", "n"))
        _mark(env, _rec("task#N"))
        env.clock.advance(60)
        with patch.object(fp, "query_project_items", wraps=fp.query_project_items) as q:
            _sweep(env, tmp)
        assert q.call_count == 1, "snapshot older than last_published_at -> full re-read"
        assert env.published[-1] == ["A", "B", "N"]
        assert fp._load_snapshot(PROJECT)["items"]["task#A"]["title"]["S"] == "a-while-off"


def test_unreadable_last_published_stamp_means_no_snapshot_is_trusted(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        _mark(env, _rec("task#A"))
        env.clock.advance(60)
        with patch.object(fp, "_scan_last_published", return_value=None), patch.object(
            fp, "query_project_items", wraps=fp.query_project_items
        ) as q:
            _sweep(env, tmp)
        assert q.call_count == 1


def test_back_to_back_incremental_sweeps_do_not_false_positive_the_staleness_check(env):
    with tempfile.TemporaryDirectory() as tmp:
        _first_full_publish(env, tmp)
        with patch.object(fp, "query_project_items", side_effect=AssertionError("must stay incremental")):
            for i in range(3):
                _put(env, _tracker_item(f"task#S{i}", f"s{i}"))
                _mark(env, _rec(f"task#S{i}"))
                env.clock.advance(60)
                assert _sweep(env, tmp)["cleared"] == [PROJECT]
            # a MARK whose record is unchanged: merge mutates nothing, snapshot must still be refreshed
            _mark(env, _rec("task#A"))
            env.clock.advance(60)
            before = fp._load_snapshot(PROJECT)["saved_at"]
            assert _sweep(env, tmp)["cleared"] == [PROJECT]
            assert fp._load_snapshot(PROJECT)["saved_at"] >= before
            _mark(env, _rec("task#B"))
            env.clock.advance(60)
            assert _sweep(env, tmp)["cleared"] == [PROJECT]
        assert env.published[-1] == ["A", "B", "S0", "S1", "S2"]
