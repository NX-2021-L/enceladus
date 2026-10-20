"""ENC-TSK-R34 (ENC-PLN-100 C3.1, BRD FR-20 + FR-21, ruling A7): feed content-hash diffing and gzip payloads.

The properties protected: an unchanged object is never re-PUT (and a changed one always is), a failed or
partial publish never records a hash it did not earn, a gzipped object always carries
Content-Encoding: gzip and round-trips, every S3-API reader decodes it, and with the flags off (or in
per_batch mode) the publisher is byte-identical to before.
"""

from __future__ import annotations

import contextlib
import gzip
import importlib.util
import io
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "shared_layer", "python"))

_SPEC = importlib.util.spec_from_file_location("feed_publisher_lambda_r34", os.path.join(HERE, "lambda_function.py"))
fp = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(fp)

import feed_utils  # noqa: E402
from enceladus_shared import content_store as shared_content_store  # noqa: E402

TABLE = "enceladus-feed-publish-state"


class FakeStore:
    """Records uploads; for gzip objects also records the DECODED body read from the staged file."""

    def __init__(self, fail_on=None):
        self.uploads = []
        self.fail_on = fail_on

    def upload_file(self, local_path, key, extra_args):
        if self.fail_on and key.endswith(self.fail_on):
            raise RuntimeError("put failed")
        raw = Path(local_path).read_bytes()
        body = gzip.decompress(raw) if extra_args.get("ContentEncoding") == "gzip" else raw
        self.uploads.append({"key": key, "extra": dict(extra_args), "stored": raw, "body": body})

    def keys(self):
        return [u["key"] for u in self.uploads]


def _feed_dir(tmp, tasks=None, generated_at="2026-10-19T00:00:00Z"):
    d = Path(tmp)
    feed_utils.write_json(d / "tasks.json", {"generated_at": generated_at, "version": "1", "tasks": tasks or [{"id": "T1"}]})
    feed_utils.write_json(d / "features.json", {"generated_at": generated_at, "version": "1", "features": [{"id": "F1"}]})
    (d / "deploy-pending.json").write_text(
        json.dumps({"generated_at": generated_at, "version": "1.0", "pending_count": 0}, separators=(",", ":"))
    )
    (d / "reference").mkdir(exist_ok=True)
    (d / "reference" / "enceladus.md").write_text("# ref\n")
    return d


def _publish(feed_dir, store, **kw):
    with patch.object(feed_utils, "_feed_content_store", return_value=store), patch.object(
        feed_utils.boto3, "client", return_value=MagicMock()
    ):
        return feed_utils.publish_mobile_feeds_to_s3(feed_dir, bucket="b", s3_prefix="mobile/v1", **kw)


# ---------------------------------------------------------------------------
# FR-20: digest
# ---------------------------------------------------------------------------


def test_digest_ignores_generated_at_wherever_it_sorts_and_in_compact_json():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        da, db = _feed_dir(a, generated_at="2026-10-19T00:00:00Z"), _feed_dir(b, generated_at="2026-10-19T09:09:09Z")
        for name in ("tasks.json", "features.json", "deploy-pending.json"):  # features: generated_at sorts AFTER its array
            assert feed_utils.object_content_digest(da / name) == feed_utils.object_content_digest(db / name), name


def test_digest_changes_with_content_and_raw_md_is_hashed_whole():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        da = _feed_dir(a)
        db = _feed_dir(b, tasks=[{"id": "T1", "status": "closed"}])
        assert feed_utils.object_content_digest(da / "tasks.json") != feed_utils.object_content_digest(db / "tasks.json")
        (db / "reference" / "enceladus.md").write_text("# ref v2\n")
        assert feed_utils.object_content_digest(da / "reference" / "enceladus.md") != feed_utils.object_content_digest(
            db / "reference" / "enceladus.md"
        )


def test_digest_does_not_confuse_a_nested_generated_at_with_the_stamp():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        feed_utils.write_json(Path(a) / "tasks.json", {"generated_at": "t1", "tasks": [{"generated_at": "x"}]})
        feed_utils.write_json(Path(b) / "tasks.json", {"generated_at": "t1", "tasks": [{"generated_at": "y"}]})
        assert feed_utils.object_content_digest(Path(a) / "tasks.json") != feed_utils.object_content_digest(Path(b) / "tasks.json")


# ---------------------------------------------------------------------------
# FR-20: publish diffing
# ---------------------------------------------------------------------------


def test_unchanged_objects_are_not_put_and_changed_ones_are():
    with tempfile.TemporaryDirectory() as t1:
        report1 = {}
        s1 = FakeStore()
        _publish(_feed_dir(t1), s1, previous_hashes={}, report=report1)
        assert sorted(s1.keys()) == sorted(
            ["mobile/v1/tasks.json", "mobile/v1/features.json", "mobile/v1/deploy-pending.json", "mobile/v1/reference/enceladus.md"]
        )
        hashes = report1["hashes"]
    # Same content, newer generated_at -> nothing is written.
    with tempfile.TemporaryDirectory() as t2:
        s2, report2 = FakeStore(), {}
        uploaded = _publish(_feed_dir(t2, generated_at="2026-10-19T05:00:00Z"), s2, previous_hashes=hashes, report=report2)
        assert uploaded == [] and s2.uploads == []
        assert len(report2["skipped"]) == 4 and report2["hashes"] == hashes
    # One task changed -> exactly tasks.json is written.
    with tempfile.TemporaryDirectory() as t3:
        s3, report3 = FakeStore(), {}
        _publish(_feed_dir(t3, tasks=[{"id": "T1", "status": "closed"}], generated_at="2026-10-19T06:00:00Z"), s3,
                 previous_hashes=hashes, report=report3)
        assert s3.keys() == ["mobile/v1/tasks.json"]
        assert report3["hashes"]["mobile/v1/tasks.json"] != hashes["mobile/v1/tasks.json"]
        # the object that IS written carries the new generated_at
        assert b"2026-10-19T06:00:00Z" in s3.uploads[0]["body"]


def test_failed_put_records_no_hash_for_it_so_the_next_sweep_retries():
    with tempfile.TemporaryDirectory() as t:
        store, report = FakeStore(fail_on="tasks.json"), {}
        with pytest.raises(RuntimeError):
            _publish(_feed_dir(t), store, previous_hashes={}, report=report)
        assert "mobile/v1/tasks.json" not in report["hashes"]
        assert all(k != "mobile/v1/tasks.json" for k in report["hashes"])


def test_no_previous_hashes_means_no_diffing_and_identical_call():
    with tempfile.TemporaryDirectory() as t:
        store = FakeStore()
        d = _feed_dir(t)
        _publish(d, store)
        first = store.keys()
        _publish(d, store)
        assert store.keys() == first + first  # everything re-put, as before R34
        assert all("ContentEncoding" not in u["extra"] for u in store.uploads)


# ---------------------------------------------------------------------------
# FR-21: gzip
# ---------------------------------------------------------------------------


def test_gzip_json_sets_content_encoding_round_trips_and_leaves_markdown_alone():
    with tempfile.TemporaryDirectory() as t:
        d = _feed_dir(t)
        original = (d / "tasks.json").read_bytes()
        store, report = FakeStore(), {}
        _publish(d, store, gzip_json=True, report=report)
        by_key = {u["key"]: u for u in store.uploads}
        tasks = by_key["mobile/v1/tasks.json"]
        assert tasks["extra"]["ContentEncoding"] == "gzip" and tasks["extra"]["ContentType"] == "application/json"
        assert tasks["stored"][:2] == b"\x1f\x8b" and tasks["body"] == original
        md = by_key["mobile/v1/reference/enceladus.md"]
        assert "ContentEncoding" not in md["extra"] and md["stored"] == b"# ref\n"
        assert report["gzip"]["mobile/v1/tasks.json"]["raw_bytes"] == len(original)
        assert report["split_required"] == []


def test_gzip_staging_dir_is_removed_even_when_a_put_fails():
    before = set(Path(tempfile.gettempdir()).glob("feed-gz-*"))
    with tempfile.TemporaryDirectory() as t:
        with pytest.raises(RuntimeError):
            _publish(_feed_dir(t), FakeStore(fail_on="features.json"), gzip_json=True)
    assert set(Path(tempfile.gettempdir()).glob("feed-gz-*")) == before


def test_split_threshold_is_reported_not_silently_ignored():
    with tempfile.TemporaryDirectory() as t:
        d = _feed_dir(t, tasks=[{"id": f"T{i}", "n": random.Random(i).random()} for i in range(2000)])
        report = {}
        with patch.object(feed_utils, "FEED_GZIP_SPLIT_THRESHOLD_BYTES", 1024):
            _publish(d, FakeStore(), gzip_json=True, report=report)
        assert "mobile/v1/tasks.json" in report["split_required"]


def test_real_generator_payload_compresses_at_least_5x_and_stays_under_the_split_threshold():
    rng = random.Random(34)
    words = [f"w{rng.randrange(4000)}" for _ in range(4000)]

    def rec(i):
        return {
            "task_id": f"ENC-TSK-{i:05d}", "project_id": "enceladus", "title": " ".join(rng.choices(words, k=9)),
            "description": " ".join(rng.choices(words, k=120)), "status": rng.choice(["open", "closed", "in-progress"]),
            "priority": rng.choice(["P0", "P1", "P2", "P3"]), "created_at": f"2026-0{rng.randrange(1, 9)}-1{rng.randrange(0, 9)}T10:00:00Z",
            "updated_at": "2026-10-19T00:00:00Z", "history": [{"status": "open", "timestamp": "2026-01-01T00:00:00Z",
                                                             "description": " ".join(rng.choices(words, k=20))}] * 3,
            "acceptance_criteria": [{"description": " ".join(rng.choices(words, k=25))}] * 2,
        }

    entry = feed_utils.FeedProjectEntry(name="enceladus", prefix="ENC", path=Path("."), status="active", metadata={})
    with tempfile.TemporaryDirectory() as t:
        feed_utils.generate_mobile_feeds([entry], {"enceladus": {"tasks": [rec(i) for i in range(3000)]}}, "2026-10-19T00:00:00Z", Path(t))
        raw = (Path(t) / "tasks.json").stat().st_size
        report = {}
        _publish(Path(t), FakeStore(), gzip_json=True, report=report)
        stored = report["gzip"]["mobile/v1/tasks.json"]["stored_bytes"]
    assert raw / stored >= 5, (raw, stored)
    assert stored < feed_utils.FEED_GZIP_SPLIT_THRESHOLD_BYTES


# ---------------------------------------------------------------------------
# FR-21 gate: every S3-API reader decodes
# ---------------------------------------------------------------------------


def _resp(body: bytes, encoding=None):
    r = {"Body": io.BytesIO(body)}
    if encoding:
        r["ContentEncoding"] = encoding
    return r


def test_reader_helpers_gunzip_on_content_encoding_and_pass_identity_through():
    payload = b'{"tasks": []}'
    gz = gzip.compress(payload)
    assert feed_utils.read_s3_object_bytes(_resp(gz, "gzip")) == payload
    assert feed_utils.read_s3_object_bytes(_resp(payload)) == payload
    assert feed_utils.decode_s3_body(gz, "GZIP") == payload
    assert shared_content_store.decode_body(_resp(gz, "gzip")) == payload
    assert shared_content_store.decode_body(_resp(payload)) == payload


def test_content_store_read_bytes_decodes_a_gzip_object_from_real_s3():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="feed-test-bucket")
        body = json.dumps({"tasks": [{"id": "T1"}]}).encode()
        s3.put_object(Bucket="feed-test-bucket", Key="mobile/v1/tasks.json", Body=gzip.compress(body), ContentEncoding="gzip",
                      ContentType="application/json")
        store = shared_content_store.ContentStore(s3, mode="legacy", legacy_bucket="feed-test-bucket")
        assert store.read_bytes("mobile/v1/tasks.json") == body
        raw = s3.get_object(Bucket="feed-test-bucket", Key="mobile/v1/tasks.json")
        assert raw["ContentEncoding"] == "gzip" and raw["Body"].read()[:2] == b"\x1f\x8b"  # boto3 does not decode


def test_generate_reference_docs_from_s3_decodes_a_gzip_encoded_object():
    ddb = MagicMock()
    ddb.get_item.return_value = {"Item": {"project_id": {"S": "p"}, "record_id": {"S": "reference#p"},
                                          "s3_key": {"S": "k.md"}, "s3_bucket": {"S": "other-bucket"}}}
    s3 = MagicMock()
    s3.get_object.return_value = _resp(gzip.compress(b"# hi\n"), "gzip")
    entry = feed_utils.FeedProjectEntry(name="p", prefix="P", path=Path("."), status="active", metadata={})
    with tempfile.TemporaryDirectory() as t, patch.object(feed_utils, "_feed_content_store", return_value=MagicMock()):
        feed_utils.generate_reference_docs_from_s3([entry], Path(t), ddb, table="tbl", s3_client=s3)
        assert (Path(t) / "reference" / "p.md").read_bytes() == b"# hi\n"


# ---------------------------------------------------------------------------
# Lambda wiring: flags, hash map on the state table, sync-stage skipping
# ---------------------------------------------------------------------------


@pytest.fixture
def state(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-west-2"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-west-2")
        client.create_table(
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "project_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "project_id", "KeyType": "HASH"}],
        )
        yield client


def _run_publish(client, tmp, *, tasks_by_project, mode="coalesced", diff=True, gz=False, store=None, publish_enabled=True):
    entries = [SimpleNamespace(name=n) for n in tasks_by_project]
    store = store or FakeStore()
    stage = MagicMock(side_effect=lambda **kw: {"tasks": f"s3://a/{kw['project_name']}/"})
    sns, eb = MagicMock(), MagicMock()

    def gen(entries_, data, generated_at, out, **kw):
        feed_utils.write_json(Path(out) / "tasks.json", {"generated_at": generated_at, "version": "1",
                                                          "tasks": [t for d in data.values() for t in d["tasks"]]},
                              minify=kw.get("minify", False))

    gen_mock = MagicMock(side_effect=gen)
    store.gen = gen_mock

    patches = [
        patch.object(fp, "FEED_PUBLISH_MODE", mode),
        patch.object(fp, "FEED_CONTENT_DIFF", diff),
        patch.object(fp, "FEED_GZIP", gz),
        patch.object(fp, "FEED_S3_PUBLISH_ENABLED", publish_enabled),
        patch.object(fp, "FEED_INVALIDATE", False),
        patch.object(fp, "FEED_PUBLISH_STATE_TABLE", TABLE),
        patch.object(fp, "FEED_TEMP_DIR", Path(tmp)),
        patch.object(fp, "_all_project_entries", return_value=entries),
        patch.object(fp, "_ddb_client", return_value=client),
        patch.object(
            fp, "fetch_from_dynamodb", side_effect=lambda e, **kw: {"tasks": tasks_by_project[e.name], "issues": [], "features": []}
        ),
        patch.object(fp, "fetch_documents_from_dynamodb", return_value=[]),
        patch.object(fp, "generate_mobile_feeds", gen_mock),
        patch.object(fp, "generate_documents_feed"),
        patch.object(fp, "_generate_deploy_pending_feed"),
        patch.object(fp, "check_freshness_sla"),
        patch.object(fp, "generate_reference_docs_from_s3"),
        patch.object(fp, "write_analytics_sync_stage", stage),
        patch.object(fp, "publish_sync_message", sns),
        patch.object(fp, "publish_eventbridge_event", eb),
        patch.object(feed_utils, "_feed_content_store", return_value=store),
        patch.object(fp.boto3, "client", return_value=MagicMock()),
        patch.object(feed_utils.boto3, "client", return_value=MagicMock()),
    ]
    with contextlib.ExitStack() as stack:
        for p_ in patches:
            stack.enter_context(p_)
        fp._publish_all(set())
    return store, stage, sns, eb


def test_sweep_second_publish_with_no_change_writes_nothing_and_signals_nothing(state):
    with tempfile.TemporaryDirectory() as t:
        data = {"p1": [{"id": "T1"}], "p2": [{"id": "T2"}]}
        store, stage, sns, eb = _run_publish(state, t, tasks_by_project=data)
        assert store.keys() == ["mobile/v1/tasks.json"] and stage.call_count == 2 and eb.call_count == 2
        item = state.get_item(TableName=TABLE, Key={"project_id": {"S": fp.OBJECT_HASHES_KEY}})["Item"]
        assert set(item["hashes"]["M"]) == {"mobile/v1/tasks.json"} and set(item["stage_hashes"]["M"]) == {"p1", "p2"}

        store, stage, sns, eb = _run_publish(state, t, tasks_by_project=data)
        assert store.uploads == [] and stage.call_count == 0 and sns.call_count == 0 and eb.call_count == 0


def test_sweep_after_one_task_change_rewrites_tasks_and_only_that_projects_stage(state):
    with tempfile.TemporaryDirectory() as t:
        _run_publish(state, t, tasks_by_project={"p1": [{"id": "T1"}], "p2": [{"id": "T2"}]})
        store, stage, sns, eb = _run_publish(state, t, tasks_by_project={"p1": [{"id": "T1", "status": "closed"}], "p2": [{"id": "T2"}]})
        assert store.keys() == ["mobile/v1/tasks.json"]
        assert [c.kwargs["project_name"] for c in stage.call_args_list] == ["p1"]
        assert [c.kwargs["project_name"] for c in sns.call_args_list] == ["p1"]
        assert eb.call_count == 1


def test_changed_publish_target_or_gzip_flag_forces_a_full_republish(state):
    with tempfile.TemporaryDirectory() as t:
        data = {"p1": [{"id": "T1"}]}
        _run_publish(state, t, tasks_by_project=data, gz=False)
        store, *_ = _run_publish(state, t, tasks_by_project=data, gz=True)  # encoding changed
        assert store.keys() == ["mobile/v1/tasks.json"] and store.uploads[0]["extra"]["ContentEncoding"] == "gzip"


def test_daily_full_refresh_republishes_even_when_hashes_match(state):
    with tempfile.TemporaryDirectory() as t:
        data = {"p1": [{"id": "T1"}]}
        _run_publish(state, t, tasks_by_project=data)
        with patch.object(fp.time, "time", return_value=time.time() + fp.FEED_DIFF_REFRESH_SECONDS + 5):
            store, stage, *_ = _run_publish(state, t, tasks_by_project=data)
        assert store.keys() == ["mobile/v1/tasks.json"] and stage.call_count == 1


def test_unreadable_hash_map_degrades_to_a_full_publish(state):
    with tempfile.TemporaryDirectory() as t:
        data = {"p1": [{"id": "T1"}]}
        _run_publish(state, t, tasks_by_project=data)
        broken = MagicMock(wraps=state)
        broken.get_item.side_effect = RuntimeError("ddb down")
        store, stage, *_ = _run_publish(broken, t, tasks_by_project=data)
        assert store.keys() == ["mobile/v1/tasks.json"] and stage.call_count == 1


def test_gamma_shape_publish_disabled_still_skips_unchanged_sync_stage(state):
    with tempfile.TemporaryDirectory() as t:
        data = {"p1": [{"id": "T1"}]}
        _run_publish(state, t, tasks_by_project=data, publish_enabled=False)
        store, stage, sns, eb = _run_publish(state, t, tasks_by_project=data, publish_enabled=False)
        assert store.uploads == [] and stage.call_count == 0 and sns.call_count == 0


def test_flags_off_or_per_batch_mode_is_byte_identical_and_touches_no_state(state):
    for kwargs in ({"diff": False, "gz": False}, {"mode": "per_batch", "diff": True, "gz": True}):
        with tempfile.TemporaryDirectory() as t:
            spy = MagicMock(wraps=state)
            data = {"p1": [{"id": "T1"}]}
            store, stage, sns, eb = _run_publish(spy, t, tasks_by_project=data, **kwargs)
            store2, stage2, sns2, eb2 = _run_publish(spy, t, tasks_by_project=data, **kwargs)
            assert store2.keys() == ["mobile/v1/tasks.json"] and stage2.call_count == 1  # nothing skipped
            assert all("ContentEncoding" not in u["extra"] for u in store2.uploads)
            assert spy.update_item.call_count == 0 and spy.get_item.call_count == 0
            assert state.get_item(TableName=TABLE, Key={"project_id": {"S": fp.OBJECT_HASHES_KEY}}).get("Item") is None


def test_default_flags_are_off():
    assert fp._env_true("FEED_R34_UNSET_FLAG") is False
    assert fp.FEED_CONTENT_DIFF is False and fp.FEED_GZIP is False
    assert fp._content_diff_active() is False and fp._gzip_active() is False


def test_hash_item_is_invisible_to_the_dirty_scan(state):
    fp._save_hash_state(state, hashes={"k": "h"}, fingerprint="f", refreshed_at=1.0)
    with patch.object(fp, "FEED_PUBLISH_STATE_TABLE", TABLE):
        assert fp._scan_dirty_projects(state) == []


def test_gzip_flag_minifies_and_splits_but_per_batch_and_flags_off_call_the_generator_unchanged(state):
    with tempfile.TemporaryDirectory() as t:
        store, *_ = _run_publish(state, t, tasks_by_project={"p1": [{"id": "T1"}]}, gz=True)
        assert store.gen.call_args.kwargs == {"minify": True, "split_tasks": True, "key_prefix": fp.FEED_PREFIX}
    for kwargs in ({"gz": False}, {"mode": "per_batch", "gz": True}):
        with tempfile.TemporaryDirectory() as t:
            store, *_ = _run_publish(state, t, tasks_by_project={"p1": [{"id": "T1"}]}, **kwargs)
            assert store.gen.call_args.kwargs == {} and len(store.gen.call_args.args) == 4  # pre-R34 call


# ---------------------------------------------------------------------------
# FR-21 / ruling A7: minified + split tasks.json behind an index manifest
# ---------------------------------------------------------------------------

ENTRIES = [feed_utils.FeedProjectEntry(name=n, prefix=n[:3].upper(), path=Path("."), status="active", metadata={})
           for n in ("alpha", "beta", "gamma")]


def _split_dir(tmp, data, generated_at="2026-10-19T00:00:00Z"):
    feed_utils.generate_mobile_feeds(ENTRIES, {n: {"tasks": ts} for n, ts in data.items()}, generated_at, Path(tmp),
                                     minify=True, split_tasks=True, key_prefix="mobile/v1")
    return Path(tmp)


def _task(i, **kw):
    return {"id": f"ENC-TSK-{i}", "title": f"task {i}", "status": "open", **kw}


DATA = {"alpha": [_task(1), _task(2)], "beta": [_task(3)], "gamma": []}


def test_split_writes_one_minified_file_per_project_and_an_index_manifest():
    with tempfile.TemporaryDirectory() as t:
        d = _split_dir(t, DATA)
        manifest_raw = (d / "tasks.json").read_text()
        manifest = json.loads(manifest_raw)
        assert manifest_raw.startswith('{"generated_at":"2026-10-19T00:00:00Z",') and "\n" not in manifest_raw
        assert set(manifest) == {"generated_at", "version", "split", "projects"} and manifest["split"] is True
        assert [p["project_id"] for p in manifest["projects"]] == ["alpha", "beta", "gamma"]
        for p in manifest["projects"]:
            f = d / "tasks" / f"{p['project_id']}.json"
            assert set(p) == {"project_id", "key", "count", "sha256", "bytes"}
            assert p["key"] == f"mobile/v1/tasks/{p['project_id']}.json"
            assert p["bytes"] == f.stat().st_size and p["sha256"] == feed_utils.object_content_digest(f)
            doc = json.loads(f.read_text())
            assert doc["project_id"] == p["project_id"] and len(doc["tasks"]) == p["count"] == len(DATA[p["project_id"]])
        # the other feeds are minified too, and generated_at leads (digest never parses a big file)
        assert (d / "issues.json").read_text().startswith('{"generated_at":')
        assert not (d / "tasks.json").read_text().count("  ")


def test_split_publish_puts_project_files_before_the_manifest_all_gzip_encoded():
    with tempfile.TemporaryDirectory() as t:
        store, report = FakeStore(), {}
        _publish(_split_dir(t, DATA), store, previous_hashes={}, gzip_json=True, report=report)
        keys = store.keys()
        assert keys[-1] == "mobile/v1/tasks.json"  # manifest last
        assert {"mobile/v1/tasks/alpha.json", "mobile/v1/tasks/beta.json", "mobile/v1/tasks/gamma.json"} <= set(keys)
        assert all(u["extra"]["ContentEncoding"] == "gzip" for u in store.uploads)
        by_key = {u["key"]: u for u in store.uploads}
        assert json.loads(by_key["mobile/v1/tasks.json"]["body"])["split"] is True
        assert json.loads(by_key["mobile/v1/tasks/alpha.json"]["body"])["tasks"][0]["task_id"] == "ENC-TSK-1"


def test_split_unchanged_projects_are_not_put_and_a_changed_one_puts_only_itself_and_the_manifest():
    with tempfile.TemporaryDirectory() as t1:
        report1 = {}
        _publish(_split_dir(t1, DATA), FakeStore(), previous_hashes={}, gzip_json=True, report=report1)
        hashes = report1["hashes"]
    with tempfile.TemporaryDirectory() as t2:  # nothing changed, newer generated_at: zero PUTs (manifest too)
        s2 = FakeStore()
        _publish(_split_dir(t2, DATA, generated_at="2026-10-19T09:00:00Z"), s2, previous_hashes=hashes, gzip_json=True)
        assert s2.uploads == []
    with tempfile.TemporaryDirectory() as t3:
        changed = {**DATA, "beta": [_task(3, title="renamed")]}  # title only: the projects.json summary is unaffected
        s3 = FakeStore()
        _publish(_split_dir(t3, changed, generated_at="2026-10-19T10:00:00Z"), s3, previous_hashes=hashes, gzip_json=True)
        assert s3.keys() == ["mobile/v1/tasks/beta.json", "mobile/v1/tasks.json"]
        manifest = json.loads(s3.uploads[-1]["body"])
        by_id = {p["project_id"]: p["sha256"] for p in manifest["projects"]}
        assert by_id["beta"] == feed_utils.object_content_digest(Path(t3) / "tasks" / "beta.json")
        assert by_id["alpha"] == hashes["mobile/v1/tasks/alpha.json"]  # untouched project keeps its digest
        assert manifest["generated_at"] == "2026-10-19T10:00:00Z"


def test_load_tasks_feed_reads_both_shapes_through_the_gzip_decoders():
    with tempfile.TemporaryDirectory() as t:
        store = FakeStore()
        _publish(_split_dir(t, DATA), store, gzip_json=True)
        stored = {u["key"]: (u["stored"], "gzip") for u in store.uploads}

    def read_split(key):
        data, enc = stored[key]
        return feed_utils.decode_s3_body(data, enc)

    split = feed_utils.load_tasks_feed(read_split, "mobile/v1/tasks.json")
    assert [x["task_id"] for x in split["tasks"]] == ["ENC-TSK-1", "ENC-TSK-2", "ENC-TSK-3"]
    mono = {"generated_at": "t", "version": "1", "tasks": [{"task_id": "X"}]}
    gz_mono = gzip.compress(json.dumps(mono).encode())
    assert feed_utils.load_tasks_feed(lambda k: feed_utils.decode_s3_body(gz_mono, "gzip"), "k") == mono


def test_minified_digest_excludes_generated_at_and_tracks_content():
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        fa, fb = Path(a) / "x.json", Path(b) / "x.json"
        feed_utils.write_json(fa, {"generated_at": "t1", "version": "1", "tasks": [1]}, minify=True)
        feed_utils.write_json(fb, {"generated_at": "t2", "version": "1", "tasks": [1]}, minify=True)
        assert fa.read_text() == '{"generated_at":"t1","tasks":[1],"version":"1"}'
        assert feed_utils.object_content_digest(fa) == feed_utils.object_content_digest(fb)
        feed_utils.write_json(fb, {"generated_at": "t2", "version": "1", "tasks": [2]}, minify=True)
        assert feed_utils.object_content_digest(fa) != feed_utils.object_content_digest(fb)
        feed_utils.write_json(fb, {"generated_at": "t2"}, minify=True)
        assert fb.read_text() == '{"generated_at":"t2"}'
        assert feed_utils.object_content_digest(fb) == feed_utils.object_content_digest(fb)
