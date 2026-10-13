"""DVP-TSK-B20 (isolation W4g): graph_query_api pathway-telemetry/ goes through content_store (no AWS).

Env under test: CONTENT_STORE_MODE=dual with CONTENT_STORE_READ=legacy (writes in both buckets, reads legacy only), and
CONTENT_STORE_READ unset (the later flip: content first, legacy on a miss). In gamma the legacy key carries the gamma/ env
prefix (PATHWAY_TELEMETRY_PREFIX = gamma/pathway-telemetry) and the content-bucket key does not.
"""

import datetime as dt
import json
import logging
import os
import sys

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))  # enceladus_shared.content_store

import flow_weight_refresh as fwr  # noqa: E402
import lambda_function as lf  # noqa: E402
from test_flow_weight_refresh_j02 import _FakeDriver  # noqa: E402

LEGACY = "enceladus-shared-356364570033"
CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
PREFIX = "gamma/pathway-telemetry"
T0 = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)


class _NoSuchKey(ClientError):
    """Like boto3's modeled s3.exceptions.NoSuchKey: a ClientError subclass named NoSuchKey, code NoSuchKey."""

    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")


_NoSuchKey.__name__ = "NoSuchKey"


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _FakeS3:
    """objects: {(bucket, key): (bytes, LastModified)}. Records every call."""

    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self, objects=None, put_fail=None):
        self.objects = dict(objects or {})
        self.put_fail = put_fail
        self.puts, self.gets, self.lists = [], [], []

    def put_object(self, Bucket, Key, Body, **kw):
        if self.put_fail is not None:
            raise self.put_fail
        self.puts.append((Bucket, Key, Body, kw))
        self.objects[(Bucket, Key)] = (Body, T0)
        return {"ETag": "x"}

    def get_object(self, Bucket, Key, **kw):
        self.gets.append((Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)][0])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.lists.append((Bucket, Prefix))
        yield {"Contents": [{"Key": k, "LastModified": lm, "Size": len(b)}
                            for (bkt, k), (b, lm) in sorted(self.objects.items()) if bkt == Bucket and k.startswith(Prefix)]}


def _hit(edge_id, count):
    return json.dumps({"edge_participation": [{"edge_id": edge_id, "traversal_count": count, "retrieval_outcome": "hit"}]}).encode()


@pytest.fixture
def env(monkeypatch):
    def _set(read="legacy", bucket=LEGACY):
        monkeypatch.setenv("CONTENT_STORE_MODE", "dual")
        monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
        monkeypatch.setenv("S3_ENV_PREFIX", "gamma/")
        if read is None:
            monkeypatch.delenv("CONTENT_STORE_READ", raising=False)
        else:
            monkeypatch.setenv("CONTENT_STORE_READ", read)
        monkeypatch.setattr(lf, "PATHWAY_TELEMETRY_BUCKET", bucket)
        monkeypatch.setattr(lf, "PATHWAY_TELEMETRY_PREFIX", PREFIX)
        monkeypatch.setattr(lf, "_CONTENT_STORE", None)
    return _set


def _use(monkeypatch, s3):
    monkeypatch.setattr(lf, "_get_s3", lambda: s3)
    return s3


# -- writer -------------------------------------------------------------------------------------------------------
def test_telemetry_put_lands_in_both_buckets_with_gamma_key_mapping(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _FakeS3())
    lf._emit_pathway_telemetry({"wave_id": "W1", "outcome": {"result_count": 3}})
    assert [b for b, *_ in s3.puts] == [CONTENT, LEGACY]  # content first, then legacy
    (_, ckey, cbody, ckw), (_, lkey, lbody, lkw) = s3.puts
    assert lkey.startswith("gamma/pathway-telemetry/wave_id=W1/") and lkey.endswith(".jsonl")
    assert ckey == lkey[len("gamma/"):] and ckey.startswith("pathway-telemetry/wave_id=W1/")
    assert cbody == lbody and json.loads(lbody)["wave_id"] == "W1"
    assert ckw == lkw == {"ContentType": "application/x-ndjson"}


def test_unset_bucket_writes_nothing_and_logs(env, monkeypatch, caplog):
    env(bucket="")
    s3 = _use(monkeypatch, _FakeS3())
    with caplog.at_level(logging.INFO):
        lf._emit_pathway_telemetry({"wave_id": "W1"})
    assert s3.puts == []
    assert any("PATHWAY_TELEMETRY " in r.getMessage() for r in caplog.records)


def test_put_failure_degrades_to_the_log_line(env, monkeypatch, caplog):
    env()
    _use(monkeypatch, _FakeS3(put_fail=RuntimeError("boom")))
    with caplog.at_level(logging.INFO):
        lf._emit_pathway_telemetry({"wave_id": "W1"})  # never raises into the request path
    assert any("PATHWAY_TELEMETRY " in r.getMessage() for r in caplog.records)


# -- flow_weight_refresh reader (legacy-pinned) --------------------------------------------------------------------
def _seed():
    return {
        (LEGACY, f"{PREFIX}/wave_id=W1/a.jsonl"): (_hit("e1", 2), T0),
        (LEGACY, f"{PREFIX}/wave_id=W1/b.jsonl"): (_hit("e1", 3), T0 + dt.timedelta(seconds=5)),
        (LEGACY, "gamma/other/c.jsonl"): (_hit("zz", 9), T0),
        # a content copy that disagrees: proves a legacy-pinned read never looks here
        (CONTENT, "pathway-telemetry/wave_id=W1/a.jsonl"): (_hit("e1", 100), T0 + dt.timedelta(days=1)),
    }


def test_refresh_legacy_pin_lists_and_reads_legacy_only_same_result_as_raw(env, monkeypatch):
    env(read="legacy")
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    store = lf._content_store(s3)
    via_store = fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100, store=store)
    flow_store = fwr._aggregate_hit_flow(s3, LEGACY, via_store, store=store)
    assert s3.lists == [(LEGACY, PREFIX + "/")] and {b for b, _ in s3.gets} == {LEGACY}
    raw = fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100)
    assert via_store == raw and len(raw) == 2
    assert flow_store == fwr._aggregate_hit_flow(s3, LEGACY, raw) == {"e1": 5}


def test_run_refresh_uses_the_store_for_the_configured_bucket(env, monkeypatch):
    env(read="legacy")
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    driver = _FakeDriver(watermark_response=None)
    result = fwr.run_refresh(driver, s3, {})
    assert result["ok"] and result["applied"] and result["edges_reinforced"] == 1
    assert s3.lists == [(LEGACY, PREFIX + "/")] and {b for b, _ in s3.gets} == {LEGACY}


def test_explicit_other_bucket_stays_a_raw_legacy_read(env, monkeypatch):
    env(read=None)  # even with content-first reads configured, a foreign bucket is not the content store's business
    s3 = _use(monkeypatch, _FakeS3({("other-bucket", "p/x.jsonl"): (_hit("e9", 1), T0)}))
    result = fwr.run_refresh(_FakeDriver(watermark_response=None), s3, {"bucket": "other-bucket", "prefix": "p"})
    assert result["applied"] and s3.lists == [("other-bucket", "p/")]
    assert {b for b, _ in s3.gets} == {"other-bucket"}


# -- close_wave reader (legacy-pinned) -----------------------------------------------------------------------------
def test_close_wave_reader_is_legacy_pinned(env, monkeypatch):
    env(read="legacy")
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    records, seen, failed = lf._iter_wave_pathway_telemetry_records("W1")
    assert (seen, failed) == (2, 0) and len(records) == 2
    assert s3.lists == [(LEGACY, f"{PREFIX}/wave_id=W1/")] and {b for b, _ in s3.gets} == {LEGACY}


# -- the later flip is an env change -------------------------------------------------------------------------------
def test_read_unset_content_hit_is_read_from_content_and_a_miss_falls_back_to_legacy(env, monkeypatch):
    env(read=None)
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    store = lf._content_store(s3)
    objs = fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100, store=store)
    keys = [k for k, _ in objs]
    # both buckets listed; legacy-form keys; the content copy of a.jsonl does not duplicate it
    assert sorted(keys) == [f"{PREFIX}/wave_id=W1/a.jsonl", f"{PREFIX}/wave_id=W1/b.jsonl"]
    assert [b for b, _ in s3.lists] == [CONTENT, LEGACY]
    # a.jsonl keeps the OLDER (legacy) stamp, so the W3-style re-stamped content copy does not re-trigger the watermark
    assert dict(objs)[f"{PREFIX}/wave_id=W1/a.jsonl"] == int(T0.timestamp() * 1000)
    s3.gets.clear()
    flow = fwr._aggregate_hit_flow(s3, LEGACY, objs, store=store)
    assert flow == {"e1": 100 + 3}  # a from content (100), b missing in content -> legacy (3)
    assert (CONTENT, "pathway-telemetry/wave_id=W1/a.jsonl") in s3.gets
    assert s3.gets.count((LEGACY, f"{PREFIX}/wave_id=W1/a.jsonl")) == 0
    assert (CONTENT, "pathway-telemetry/wave_id=W1/b.jsonl") in s3.gets and (LEGACY, f"{PREFIX}/wave_id=W1/b.jsonl") in s3.gets


# -- DVP-TSK-B45 (DVP-ISS-149): the list prefix carries a trailing slash (IAM allows only <prefix>/*) -----------------
@pytest.mark.parametrize("configured", ["pathway-telemetry", "pathway-telemetry/", "gamma/pathway-telemetry", "gamma/pathway-telemetry/"])
def test_raw_list_prefix_has_exactly_one_trailing_slash(configured):
    s3 = _FakeS3({(LEGACY, f"{configured.rstrip('/')}/wave_id=W1/a.jsonl"): (_hit("e1", 1), T0)})
    assert [k for k, _ in fwr._list_new_telemetry_objects(s3, LEGACY, configured, 0, 100)] == [
        f"{configured.rstrip('/')}/wave_id=W1/a.jsonl"]
    assert s3.lists == [(LEGACY, configured.rstrip("/") + "/")]


def test_prod_list_prefix_is_pathway_telemetry_slash_on_both_paths(env, monkeypatch):
    env(read="legacy")
    monkeypatch.setattr(lf, "PATHWAY_TELEMETRY_PREFIX", "pathway-telemetry")
    monkeypatch.setenv("S3_ENV_PREFIX", "")
    s3 = _use(monkeypatch, _FakeS3({(LEGACY, "pathway-telemetry/wave_id=W1/a.jsonl"): (_hit("e1", 1), T0)}))
    raw = fwr._list_new_telemetry_objects(s3, LEGACY, "pathway-telemetry", 0, 100)
    via_store = fwr._list_new_telemetry_objects(s3, LEGACY, "pathway-telemetry", 0, 100, store=lf._content_store(s3))
    assert raw == via_store and len(raw) == 1
    assert s3.lists == [(LEGACY, "pathway-telemetry/")] * 2


def test_gamma_list_prefix_is_gamma_pathway_telemetry_slash_on_both_paths(env, monkeypatch):
    env(read="legacy")  # PREFIX == gamma/pathway-telemetry, S3_ENV_PREFIX == gamma/
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100)
    fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100, store=lf._content_store(s3))
    assert s3.lists == [(LEGACY, "gamma/pathway-telemetry/")] * 2


def test_gamma_content_first_lists_the_unprefixed_content_key_with_the_slash(env, monkeypatch):
    env(read=None)
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    fwr._list_new_telemetry_objects(s3, LEGACY, PREFIX, 0, 100, store=lf._content_store(s3))
    assert s3.lists == [(CONTENT, "pathway-telemetry/"), (LEGACY, "gamma/pathway-telemetry/")]


def test_run_refresh_lists_with_the_slash(env, monkeypatch):
    env(read="legacy")
    s3 = _use(monkeypatch, _FakeS3(_seed()))
    fwr.run_refresh(_FakeDriver(watermark_response=None), s3, {})
    assert s3.lists == [(LEGACY, "gamma/pathway-telemetry/")]
