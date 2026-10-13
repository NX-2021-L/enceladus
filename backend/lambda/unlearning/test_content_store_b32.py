"""DVP-TSK-B32 (isolation W4j): unlearning-tombstones/ and unlearning-state/ go through content_store (no AWS).

Env under test: CONTENT_STORE_MODE=dual with CONTENT_STORE_READ=legacy (writes and deletes in both buckets; the run
counter read and the expired-tombstone list/get on legacy only), then CONTENT_STORE_READ unset (the later flip). The
function is gamma-only, so legacy keys carry gamma/ and content keys do not.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))  # enceladus_shared.content_store

import lambda_function as lf  # noqa: E402

LEGACY = "jreese-net"
CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
TOMB = "gamma/unlearning-tombstones"
STATE = "gamma/unlearning-state"


class _NoSuchKey(ClientError):
    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _FakeS3:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.calls = []

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = Body

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key, kw))
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)])}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Bucket, Key, {}))
        self.objects.pop((Bucket, Key), None)

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.calls.append(("list", Bucket, Prefix, {}))
        yield {"Contents": [{"Key": k} for (b, k) in sorted(self.objects) if b == Bucket and k.startswith(Prefix)]}

    def touched(self, op):
        return [(c[1], c[2]) for c in self.calls if c[0] == op]


@pytest.fixture
def env(monkeypatch):
    def _set(read="legacy", s3=None):
        monkeypatch.setenv("CONTENT_STORE_MODE", "dual")
        monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
        monkeypatch.setenv("S3_ENV_PREFIX", "gamma/")
        if read is None:
            monkeypatch.delenv("CONTENT_STORE_READ", raising=False)
        else:
            monkeypatch.setenv("CONTENT_STORE_READ", read)
        monkeypatch.setattr(lf, "UNLEARNING_BUCKET", LEGACY)
        monkeypatch.setattr(lf, "UNLEARNING_PREFIX", TOMB)
        monkeypatch.setattr(lf, "STATE_PREFIX", STATE)
        monkeypatch.setattr(lf, "_CONTENT_STORE", None)
        s3 = s3 or _FakeS3()
        monkeypatch.setattr(lf, "_get_s3", lambda: s3)
        return s3
    return _set


def _tomb(days):
    until = datetime.now(timezone.utc) + timedelta(days=days)
    return json.dumps({"recover_until": until.isoformat().replace("+00:00", "Z")}).encode()


def test_run_counter_writes_both_and_reads_legacy_only(env):
    s3 = env()
    lf._save_run_counter(4)
    assert s3.touched("put") == [(CONTENT, "unlearning-state/run_counter.json"), (LEGACY, f"{STATE}/run_counter.json")]
    s3.objects[(CONTENT, "unlearning-state/run_counter.json")] = b'{"run_count": 99}'  # a stale content copy is never read
    assert lf._load_run_counter() == 4
    assert s3.touched("get") == [(LEGACY, f"{STATE}/run_counter.json")]


def test_tombstone_lands_in_both_buckets_with_gamma_key_mapping(env):
    s3 = env()
    key = lf._write_tombstone("DOC-1", {"status": "active"})
    assert key.startswith(f"{TOMB}/DOC-1/")
    (cb, ck), (lb, lk) = s3.touched("put")
    assert (cb, lb) == (CONTENT, LEGACY) and lk == key and ck == key[len("gamma/"):]
    assert s3.objects[(cb, ck)] == s3.objects[(lb, lk)]
    assert all(c[3] == {"ContentType": "application/json"} for c in s3.calls)


def test_expired_sweep_lists_and_reads_legacy_and_deletes_both(env):
    s3 = env(s3=_FakeS3({
        (LEGACY, f"{TOMB}/DOC-1/old.json"): _tomb(-1),
        (CONTENT, "unlearning-tombstones/DOC-1/old.json"): _tomb(-1),
        (LEGACY, f"{TOMB}/DOC-2/new.json"): _tomb(5),
    }))
    assert lf._hard_delete_expired_tombstones(dry_run=False) == [f"{TOMB}/DOC-1/old.json"]
    assert s3.touched("list") == [(LEGACY, TOMB)]
    assert {b for b, _ in s3.touched("get")} == {LEGACY}
    assert s3.touched("delete") == [(CONTENT, "unlearning-tombstones/DOC-1/old.json"), (LEGACY, f"{TOMB}/DOC-1/old.json")]


def test_dry_run_sweep_deletes_nothing(env):
    s3 = env(s3=_FakeS3({(LEGACY, f"{TOMB}/DOC-1/old.json"): _tomb(-1)}))
    assert lf._hard_delete_expired_tombstones(dry_run=True) == [f"{TOMB}/DOC-1/old.json"]
    assert s3.touched("delete") == []


def test_legacy_mode_is_a_raw_legacy_call(env, monkeypatch):
    s3 = env()
    monkeypatch.setenv("CONTENT_STORE_MODE", "legacy")
    lf._save_run_counter(1)
    assert s3.touched("put") == [(LEGACY, f"{STATE}/run_counter.json")]


def test_after_the_flip_the_sweep_merges_both_listings_and_reads_content_first(env):
    s3 = env(read=None, s3=_FakeS3({
        (LEGACY, f"{TOMB}/DOC-1/old.json"): _tomb(-1),
        (CONTENT, "unlearning-tombstones/DOC-1/old.json"): _tomb(-1),
        (LEGACY, f"{TOMB}/DOC-3/pre.json"): _tomb(-2),  # not yet copied by the delta: legacy fallback
    }))
    assert sorted(lf._hard_delete_expired_tombstones(dry_run=True)) == [f"{TOMB}/DOC-1/old.json", f"{TOMB}/DOC-3/pre.json"]
    assert [b for b, _ in s3.touched("list")] == [CONTENT, LEGACY]
    assert (LEGACY, f"{TOMB}/DOC-1/old.json") not in s3.touched("get")
    assert s3.touched("get")[-2:] == [(CONTENT, "unlearning-tombstones/DOC-3/pre.json"), (LEGACY, f"{TOMB}/DOC-3/pre.json")]


def test_cloudformation_env_is_writer_first():
    path = os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml")
    text = open(path, encoding="utf-8").read()
    m = re.search(r"(?ms)^  UnlearningFunction:\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
    assert m
    fn = m.group(1)
    for line in ("CONTENT_STORE_MODE: dual", "CONTENT_STORE_READ: legacy", "S3_ENV_PREFIX: !Ref S3EnvPrefix",
                 'CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"'):
        assert line in fn
