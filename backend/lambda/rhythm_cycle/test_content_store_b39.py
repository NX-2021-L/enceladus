"""DVP-TSK-B39 (isolation W4k): rhythm-cycle/ goes through content_store (no AWS).

Writers: rhythm_cycle (beat artifacts via artifact_store, stanzas via tenant_invoker.write_completion_stanza) and the
six heavy-beat tenants' _write_rhythm_stanza. With CONTENT_STORE_MODE=dual and CONTENT_STORE_READ=legacy every write
lands in the content bucket (key without the gamma/ env prefix) and the legacy bucket, while read_latest and the
stanza list/get stay on legacy. rhythm-cycle/ is gamma-only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone

import boto3
import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
LAMBDA = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(LAMBDA))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(LAMBDA, "shared_layer", "python"))  # enceladus_shared.content_store

import artifact_store  # noqa: E402
import tenant_invoker  # noqa: E402

LEGACY = "jreese-net"
CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
TENANTS = ("memory_consolidation", "handoff_consolidation_engine", "graph_health_metrics", "percolation_monitor",
           "corpus_entropy_engine", "titan_embedding_backfill")


class _NoSuchKey(ClientError):
    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _FakeS3:
    class exceptions:
        NoSuchKey = _NoSuchKey

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
    def _set(read="legacy", mode="dual"):
        monkeypatch.setenv("CONTENT_STORE_MODE", mode)
        monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
        monkeypatch.setenv("S3_ENV_PREFIX", "gamma/")
        if read is None:
            monkeypatch.delenv("CONTENT_STORE_READ", raising=False)
        else:
            monkeypatch.setenv("CONTENT_STORE_READ", read)
        monkeypatch.setattr(artifact_store, "S3_BUCKET", LEGACY)
        monkeypatch.setattr(artifact_store, "_tier_base", lambda tier: f"gamma/rhythm-cycle/{tier}")
        monkeypatch.setattr(artifact_store, "_STORE", None)
        s3 = _FakeS3()
        monkeypatch.setattr(artifact_store, "_s3", s3)
        monkeypatch.setattr(tenant_invoker, "_s3", s3)
        return s3
    return _set


# -- rhythm_cycle ---------------------------------------------------------------------------------------------------
def test_beat_artifact_and_latest_land_in_both_buckets(env):
    s3 = env()
    out = artifact_store.write_artifact("sense", {"n": 1}, datetime(2026, 10, 13, 1, 2, 3, tzinfo=timezone.utc))
    assert out["timestamped_key"] == "gamma/rhythm-cycle/sense/2026/10/13/010203.json"
    assert s3.touched("put") == [
        (CONTENT, "rhythm-cycle/sense/2026/10/13/010203.json"), (LEGACY, "gamma/rhythm-cycle/sense/2026/10/13/010203.json"),
        (CONTENT, "rhythm-cycle/sense/latest.json"), (LEGACY, "gamma/rhythm-cycle/sense/latest.json"),
    ]
    assert all(c[3] == {"ContentType": "application/json"} for c in s3.calls)


def test_read_latest_is_legacy_pinned(env):
    s3 = env()
    s3.objects[(LEGACY, "gamma/rhythm-cycle/decide/latest.json")] = b'{"src": "legacy"}'
    s3.objects[(CONTENT, "rhythm-cycle/decide/latest.json")] = b'{"src": "content"}'
    assert artifact_store.read_latest("decide") == {"src": "legacy"}
    assert s3.touched("get") == [(LEGACY, "gamma/rhythm-cycle/decide/latest.json")]
    s3.calls.clear()
    assert artifact_store.read_latest("coherence") is None  # a legacy miss is still None


def test_stanza_write_both_and_list_get_legacy_only(env):
    s3 = env()
    prefix = "gamma/rhythm-cycle/heavy_integrate/tenant-results/20261013-010203"
    tenant_invoker.write_completion_stanza(f"{prefix}/alpha.json", "alpha", "completed", output_count=1)
    assert s3.touched("put") == [(CONTENT, prefix[len("gamma/"):] + "/alpha.json"), (LEGACY, f"{prefix}/alpha.json")]
    s3.objects[(CONTENT, prefix[len("gamma/"):] + "/ghost.json")] = b"{}"  # content-only key: never listed while pinned
    assert tenant_invoker._list_stanza_tenants(prefix) == ["alpha"]
    assert tenant_invoker._read_stanza(prefix, "alpha")["did_work"] is True
    assert {b for b, _ in s3.touched("list") + s3.touched("get")} == {LEGACY}


def test_after_the_flip_reads_go_content_first(env):
    s3 = env(read=None)
    s3.objects[(CONTENT, "rhythm-cycle/sense/latest.json")] = b'{"src": "content"}'
    s3.objects[(LEGACY, "gamma/rhythm-cycle/light_integrate/latest.json")] = b'{"src": "legacy"}'
    assert artifact_store.read_latest("sense") == {"src": "content"}
    assert artifact_store.read_latest("light_integrate") == {"src": "legacy"}  # content miss -> legacy
    assert s3.touched("get") == [
        (CONTENT, "rhythm-cycle/sense/latest.json"),
        (CONTENT, "rhythm-cycle/light_integrate/latest.json"), (LEGACY, "gamma/rhythm-cycle/light_integrate/latest.json"),
    ]


def test_legacy_mode_is_a_raw_legacy_put(env):
    s3 = env(read=None, mode="legacy")
    artifact_store.write_artifact("sense", {"n": 1})
    assert {b for b, _ in s3.touched("put")} == {LEGACY}


# -- heavy-beat tenants -----------------------------------------------------------------------------------------------
def _load_tenant(name):
    d = os.path.join(LAMBDA, name)
    extra = [d, os.path.join(LAMBDA, "document_api"), os.path.join(LAMBDA, "graph_query_api"),
             os.path.join(LAMBDA, "graph_sync")]
    saved = list(sys.path)
    sys.path[:0] = extra
    try:
        spec = importlib.util.spec_from_file_location(f"b39_tenant_{name}", os.path.join(d, "lambda_function.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path[:] = saved
    return mod


@pytest.mark.parametrize("name", TENANTS)
def test_tenant_stanza_lands_in_both_buckets(name, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    mod = _load_tenant(name)
    s3 = _FakeS3()
    monkeypatch.setattr(boto3, "client", lambda *a, **kw: s3)
    monkeypatch.setattr(mod, "RHYTHM_RESULTS_BUCKET", LEGACY)
    monkeypatch.setenv("CONTENT_STORE_MODE", "dual")
    monkeypatch.setenv("CONTENT_STORE_READ", "legacy")
    monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
    monkeypatch.setenv("S3_ENV_PREFIX", "gamma/")
    key = f"gamma/rhythm-cycle/heavy_integrate/tenant-results/20261013-010203/{name}.json"
    assert mod._write_rhythm_stanza({"result_key": key}, "completed", {}, output_count=2) is True
    assert s3.touched("put") == [(CONTENT, key[len("gamma/"):]), (LEGACY, key)]
    assert s3.objects[(CONTENT, key[len("gamma/"):])] == s3.objects[(LEGACY, key)]
    assert json.loads(s3.objects[(LEGACY, key)])["output_count"] == 2
    # unset mode (titan_embedding_backfill until its env is set out of band) is the raw legacy put
    s3.calls.clear()
    monkeypatch.delenv("CONTENT_STORE_MODE")
    assert mod._write_rhythm_stanza({"result_key": key}, "skipped") is True
    assert s3.touched("put") == [(LEGACY, key)]


# -- infrastructure ---------------------------------------------------------------------------------------------------
def _block(text, name):
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n|\Z)", text)
    assert m, name
    return m.group(1)


def test_cloudformation_env_is_writer_first_for_every_rhythm_writer():
    with open(os.path.join(REPO, "infrastructure", "cloudformation", "02-compute.yaml"), encoding="utf-8") as fh:
        text = fh.read()
    content = 'CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"'
    for fn in ("RhythmCycleFunction", "HandoffConsolidationEngineFunction", "GraphHealthMetricsFunction",
               "PercolationMonitorFunction", "MemoryConsolidationFunction"):
        b = _block(text, fn)
        assert "CONTENT_STORE_MODE: dual" in b and "CONTENT_STORE_READ: legacy" in b and content in b, fn
        assert "S3_ENV_PREFIX: !Ref S3EnvPrefix" in b, fn
        assert b.count("S3_ENV_PREFIX:") == 1 and b.count("CONTENT_STORE_MODE:") == 1, fn
    cee = _block(text, "CorpusEntropyEngineFunction")  # already dual (B17, content-first reads; its stanza is a write)
    assert "CONTENT_STORE_MODE: dual" in cee and content in cee


def test_gamma_content_bucket_expires_rhythm_artifacts_after_7_days():
    with open(os.path.join(REPO, "infrastructure", "cloudformation", "isolation", "w2-content-storage.yaml"),
              encoding="utf-8") as fh:
        text = fh.read()
    for tier in ("sense", "light_integrate", "decide", "heavy_integrate", "coherence"):
        m = re.search(r"- !If\n\s+- IsProduction\n\s+- !Ref AWS::NoValue\n\s+- Id: RhythmArtifact-" + tier +
                      r"\n\s+Status: Enabled\n\s+Prefix: rhythm-cycle/" + tier + r"/\n\s+ExpirationInDays: 7\n", text)
        assert m, tier
