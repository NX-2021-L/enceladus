"""DVP-TSK-B40 (isolation W4i): governance_drift_check reads governance/live through the governance store (no AWS).

Same contract as recompute_governance (whose test carries the full matrix): no GOVERNANCE_CONTENT_BUCKET is the raw
legacy path, CONTENT_STORE_READ=legacy keeps dual reads on legacy, and the flip reads the shared PROD content bucket
with unprefixed keys.
"""

import base64
import hashlib
import io
import os
import sys

from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))

import lambda_function as mod  # noqa: E402

LEGACY = "jreese-net"
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
FILES = {"governance/live/agents.md": b"governance_revision: r1\n", "governance/live/agents/a.md": b"a\n"}


class _S3:
    def __init__(self):
        self.objects = {(b, k): v for b in (LEGACY, PROD_CONTENT) for k, v in FILES.items()}
        self.calls = []

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(Bucket)
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(Bucket)
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def get_object_attributes(self, Bucket, Key, **kw):
        self.calls.append(Bucket)
        return {"Checksum": {"ChecksumSHA256": base64.b64encode(hashlib.sha256(self.objects[(Bucket, Key)]).digest()).decode()},
                "VersionId": "v"}

    def get_paginator(self, name):
        return self

    def paginate(self, Bucket, Prefix):
        self.calls.append(Bucket)
        yield {"Contents": [{"Key": k} for (b, k) in sorted(self.objects) if b == Bucket and k.startswith(Prefix)]}


def _read_all(monkeypatch, env):
    for k in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    s3 = _S3()
    monkeypatch.setattr(mod, "_s3_client", s3)
    files = mod._list_canonical_files()
    sums = [mod._get_file_checksum(key)[0] for _, key in files]
    rev = mod._read_governance_revision("governance/live/agents.md")
    return s3, [u for u, _ in files], sums, rev


def test_legacy_without_governance_bucket_and_with_the_read_pin(monkeypatch):
    for env in ({}, {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}):
        s3, uris, sums, rev = _read_all(monkeypatch, env)
        assert set(s3.calls) == {LEGACY} and uris == ["governance://agents.md", "governance://agents/a.md"]
        assert rev == "r1" and sums[1] == hashlib.sha256(b"a\n").hexdigest()


def test_after_the_flip_reads_the_shared_prod_bucket_with_identical_results(monkeypatch):
    _, uris0, sums0, rev0 = _read_all(monkeypatch, {})
    s3, uris, sums, rev = _read_all(monkeypatch, {"CONTENT_STORE_MODE": "dual", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT})
    assert (uris, sums, rev) == (uris0, sums0, rev0)
    assert PROD_CONTENT in s3.calls
