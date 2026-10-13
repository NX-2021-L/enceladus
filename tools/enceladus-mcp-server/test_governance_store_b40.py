"""DVP-TSK-B40 (isolation W4i): the MCP server and dispatch_plan_generator read governance/live through the governance
store (no AWS).

governance/ is ONE shared corpus held only in the PROD content bucket on both planes (unprefixed keys). Without
GOVERNANCE_CONTENT_BUCKET (local stdio, MCP Lambdas outside CloudFormation) the reads are the raw legacy calls; with
coordination_api's dual + CONTENT_STORE_READ=legacy they stay legacy; after the flip they go to the prod bucket first.
Docstore-fallback catalog entries (agent-documents/ keys in their own bucket) never go through the governance store.
"""

import importlib.util
import io
import os
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


server = _load("enceladus_server_b40", "server.py")
dpg = _load("enceladus_dpg_b40", "dispatch_plan_generator.py")

LEGACY = server.S3_BUCKET
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
PREFIX = server.S3_GOVERNANCE_PREFIX.rstrip("/")


class _S3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.calls = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.calls.append(("list", Bucket, Prefix))
        yield {"Contents": [{"Key": k, "LastModified": "2026-10-13T00:00:00Z"}
                            for (b, k) in sorted(self.objects) if b == Bucket and k.startswith(Prefix)]}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def buckets(self, op):
        return {c[1] for c in self.calls if c[0] == op}


def _objects(content=True):
    objs = {(LEGACY, f"{PREFIX}/agents.md"): b"# legacy agents", (LEGACY, f"{PREFIX}/agents/a.md"): b"# a"}
    if content:
        objs[(PROD_CONTENT, f"{PREFIX}/agents.md")] = b"# legacy agents"
        objs[(PROD_CONTENT, f"{PREFIX}/agents/a.md")] = b"# a"
    return objs


@pytest.fixture
def env(monkeypatch):
    def _set(vals, s3):
        for k in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET", "CONTENT_BUCKET", "S3_ENV_PREFIX"):
            monkeypatch.delenv(k, raising=False)
        for k, v in vals.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(server, "_get_s3", lambda: s3)
        monkeypatch.setattr(dpg, "_get_s3", lambda: s3)
        server._governance_resource_body_cache.clear()
        return s3
    return _set


PINNED = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
FLIPPED = {"CONTENT_STORE_MODE": "dual", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT, "S3_ENV_PREFIX": "gamma/"}


@pytest.mark.parametrize("vals", [{}, {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": "per-env"}, PINNED])
def test_server_catalog_and_body_stay_on_legacy(env, vals):
    s3 = env(vals, _S3(_objects()))
    catalog = server._governance_catalog_from_s3()
    assert set(catalog) == {"governance://agents.md", "governance://agents/a.md"}
    assert all(e["s3_bucket"] == LEGACY for e in catalog.values())
    meta = catalog["governance://agents.md"]
    assert server._read_governance_text_cached(uri="governance://agents.md", bucket=meta["s3_bucket"],
                                               key=meta["s3_key"], force_refresh=True) == "# legacy agents"
    assert s3.buckets("list") == {LEGACY} and s3.buckets("get") == {LEGACY}


def test_server_after_the_flip_reads_the_shared_prod_bucket_unprefixed(env):
    s3 = env(FLIPPED, _S3(_objects()))
    catalog = server._governance_catalog_from_s3()
    assert set(catalog) == {"governance://agents.md", "governance://agents/a.md"}
    assert catalog["governance://agents.md"]["s3_key"] == f"{PREFIX}/agents.md"  # legacy-form key, no gamma/
    server._read_governance_text_cached(uri="governance://agents.md", bucket=LEGACY, key=f"{PREFIX}/agents.md",
                                        force_refresh=True)
    assert ("get", PROD_CONTENT, f"{PREFIX}/agents.md") in s3.calls
    assert ("list", PROD_CONTENT, f"{PREFIX}/") in s3.calls


def test_server_docstore_fallback_entries_are_never_routed_through_the_governance_store(env):
    s3 = env(FLIPPED, _S3({("docstore-bucket", "agent-documents/enceladus/DOC-1.md"): b"# doc"}))
    text = server._read_governance_text_cached(uri="governance://agents.md", bucket="docstore-bucket",
                                               key="agent-documents/enceladus/DOC-1.md", force_refresh=True)
    assert text == "# doc" and s3.calls == [("get", "docstore-bucket", "agent-documents/enceladus/DOC-1.md")]


def test_dispatch_plan_catalog_hash_is_identical_pinned_and_flipped(env):
    pinned_s3 = env(PINNED, _S3(_objects()))
    pinned = dpg._governance_catalog_from_s3()
    assert pinned_s3.buckets("get") == {LEGACY}
    flipped_s3 = env(FLIPPED, _S3(_objects()))
    flipped = dpg._governance_catalog_from_s3()
    assert flipped == pinned and set(pinned) == {"governance://agents.md", "governance://agents/a.md"}
    assert flipped_s3.buckets("get") == {PROD_CONTENT}


def test_dispatch_plan_flip_falls_back_to_legacy_for_a_file_not_yet_copied(env):
    s3 = env(FLIPPED, _S3(_objects(content=False)))
    assert set(dpg._governance_catalog_from_s3()) == {"governance://agents.md", "governance://agents/a.md"}
    assert ("get", LEGACY, f"{PREFIX}/agents/a.md") in s3.calls


def test_content_store_loads_from_the_vendored_copy_when_nothing_else_is_on_the_path(monkeypatch):
    for name in ("content_store", "enceladus_shared", "enceladus_shared.content_store"):
        monkeypatch.setitem(sys.modules, name, None)  # import of either name raises ImportError
    cls = server._load_content_store_cls()
    assert cls.__name__ == "ContentStore" and hasattr(cls, "governance_from_env")
    assert os.path.isfile(HERE / "content_store.py")
