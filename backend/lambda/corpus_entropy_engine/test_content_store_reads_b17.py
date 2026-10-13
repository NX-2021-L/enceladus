"""DVP-TSK-B17 (isolation W4e): corpus_entropy_engine docstore reads go through content_store (no AWS).

Env under test: CONTENT_STORE_MODE=dual. The legacy bucket is DOCSTORE_S3_BUCKET; in gamma the legacy key carries
the gamma/ env prefix (DOCSTORE_S3_PREFIX) and the content-bucket key does not.
"""

import logging
import os
import re
import sys

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "document_api"))  # outline.py, as in test_lambda_function.py
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))  # enceladus_shared.content_store

import lambda_function as mod  # noqa: E402

CONTENT = "enceladus-content-gamma-356364570033-us-west-2"


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
    class exceptions:
        NoSuchKey = _NoSuchKey

    def __init__(self, objects=None, fail=None):
        self.objects = dict(objects or {})
        self.fail = fail  # an exception raised for every get_object
        self.calls = []

    def get_object(self, Bucket, Key, **kw):
        self.calls.append((Bucket, Key))
        if self.fail is not None:
            raise self.fail
        if (Bucket, Key) not in self.objects:
            raise _NoSuchKey()
        return {"Body": _Body(self.objects[(Bucket, Key)])}


@pytest.fixture
def env(monkeypatch):
    def _set(prefix="", docstore_prefix="agent-documents"):
        monkeypatch.setenv("CONTENT_STORE_MODE", "dual")
        monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
        monkeypatch.setenv("S3_ENV_PREFIX", prefix)
        monkeypatch.delenv("CONTENT_STORE_READ", raising=False)
        monkeypatch.setattr(mod, "DOCSTORE_S3_PREFIX", docstore_prefix)
        monkeypatch.setattr(mod, "_CONTENT_STORE", None)
    return _set


def _use(monkeypatch, s3):
    monkeypatch.setattr(mod, "_get_s3", lambda: s3)
    return s3


def test_content_hit_never_touches_legacy(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _FakeS3({
        (CONTENT, "agent-documents/p/D.md"): b"content-body",
        (mod.DOCSTORE_S3_BUCKET, "agent-documents/p/D.md"): b"legacy-body",
    }))
    assert mod._fetch_s3_text("agent-documents/p/D.md") == "content-body"
    assert s3.calls == [(CONTENT, "agent-documents/p/D.md")]


def test_content_miss_falls_back_to_legacy(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _FakeS3({(mod.DOCSTORE_S3_BUCKET, "agent-documents/p/D.md"): b"legacy-body"}))
    assert mod._fetch_s3_text("agent-documents/p/D.md") == "legacy-body"
    assert s3.calls == [(CONTENT, "agent-documents/p/D.md"), (mod.DOCSTORE_S3_BUCKET, "agent-documents/p/D.md")]


def test_missing_in_both_buckets_is_none(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _FakeS3())
    assert mod._fetch_s3_text("agent-documents/p/D.md") is None
    assert [b for b, _k in s3.calls] == [CONTENT, mod.DOCSTORE_S3_BUCKET]


def test_a_non_nosuchkey_error_is_logged_and_returns_none(env, monkeypatch, caplog):
    env()
    s3 = _use(monkeypatch, _FakeS3(fail=RuntimeError("AccessDenied boom")))
    with caplog.at_level(logging.WARNING):
        assert mod._fetch_s3_text("agent-documents/p/D.md") is None
    assert "docstore S3 get failed key=agent-documents/p/D.md" in caplog.text
    assert "AccessDenied boom" in caplog.text
    assert len(s3.calls) == 1  # a non-miss error never triggers the legacy fallback


def test_gamma_key_maps_to_the_unprefixed_content_key(env, monkeypatch):
    env(prefix="gamma/", docstore_prefix="gamma/agent-documents")
    s3 = _use(monkeypatch, _FakeS3({(CONTENT, "agent-documents/p/D.md"): b"gamma-content"}))
    key = mod._docstore_s3_key("p", "D")
    assert key == "gamma/agent-documents/p/D.md"
    assert mod._fetch_s3_text(key) == "gamma-content"
    assert s3.calls == [(CONTENT, "agent-documents/p/D.md")]


def test_gamma_content_miss_reads_the_prefixed_legacy_key(env, monkeypatch):
    env(prefix="gamma/", docstore_prefix="gamma/agent-documents")
    s3 = _use(monkeypatch, _FakeS3({(mod.DOCSTORE_S3_BUCKET, "gamma/agent-documents/p/versions/D/2.md"): b"v2"}))
    assert mod._fetch_s3_text(mod._docstore_version_s3_key("p", "D", 2)) == "v2"
    assert s3.calls == [(CONTENT, "agent-documents/p/versions/D/2.md"),
                        (mod.DOCSTORE_S3_BUCKET, "gamma/agent-documents/p/versions/D/2.md")]


def test_legacy_mode_is_a_plain_legacy_get(env, monkeypatch):
    env()
    monkeypatch.setenv("CONTENT_STORE_MODE", "legacy")
    s3 = _use(monkeypatch, _FakeS3({(mod.DOCSTORE_S3_BUCKET, "agent-documents/p/D.md"): b"legacy-body"}))
    assert mod._fetch_s3_text("agent-documents/p/D.md") == "legacy-body"
    assert s3.calls == [(mod.DOCSTORE_S3_BUCKET, "agent-documents/p/D.md")]


def test_the_store_is_rebuilt_when_the_client_changes(env, monkeypatch):
    env()
    a = _use(monkeypatch, _FakeS3({(CONTENT, "agent-documents/p/D.md"): b"x"}))
    assert mod._fetch_s3_text("agent-documents/p/D.md") == "x"
    b = _use(monkeypatch, _FakeS3({(CONTENT, "agent-documents/p/D.md"): b"y"}))
    assert mod._fetch_s3_text("agent-documents/p/D.md") == "y"
    assert len(a.calls) == 1 and len(b.calls) == 1


def _compute_text():
    path = os.path.abspath(os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml"))
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _block(text, name):
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
    assert m, name
    return m.group(1)


def test_cloudformation_env_and_iam_for_the_gamma_function():
    text = _compute_text()
    fn = _block(text, "CorpusEntropyEngineFunction")
    assert "CONTENT_STORE_MODE: dual" in fn
    assert 'CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"' in fn
    assert "S3_ENV_PREFIX: !Ref S3EnvPrefix" in fn
    assert 'DOCSTORE_S3_PREFIX: !Sub "${S3EnvPrefix}agent-documents"' in fn
    assert "CONTENT_STORE_READ" not in fn
    role = _block(text, "CorpusEntropyEngineRole")
    assert 'arn:aws:s3:::jreese-net/${S3EnvPrefix}agent-documents/*' in role
    assert 'arn:aws:s3:::enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}/agent-documents/*' in role
    assert "s3:GetObject" in role
    # ListBucket on the content bucket ARN: without it a missing key is a 403, the legacy fallback never fires.
    assert re.search(r"s3:ListBucket\n\s+Resource:\n\s+- !Sub \"arn:aws:s3:::enceladus-content\$\{EnvironmentSuffix\}-\$\{AWS::AccountId\}-\$\{AWS::Region\}\"\n", role)


def test_build_extras_ships_content_store_and_keeps_outline():
    with open(os.path.join(HERE, ".build_extras"), encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    assert lines == ["backend/lambda/document_api/outline.py",
                     "backend/lambda/shared_layer/python/enceladus_shared/content_store.py"]
