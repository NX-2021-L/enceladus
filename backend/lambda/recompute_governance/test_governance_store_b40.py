"""DVP-TSK-B40 (isolation W4i): recompute_governance reads governance/live through the governance store (no AWS).

governance/ is ONE shared corpus held only in the PROD content bucket on both planes (unprefixed keys). Without
GOVERNANCE_CONTENT_BUCKET the reads are the same raw calls on jreese-net as before; with it, CONTENT_STORE_READ=legacy
keeps them there; after the flip they go content-first. The bundle hash must be identical in all three cases when the
content bucket holds byte-identical copies (the W3 delta's guarantee).
"""

import base64
import hashlib
import os
import re
import sys

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))

import lambda_function as mod  # noqa: E402

LEGACY = "jreese-net"
PROD_CONTENT = "enceladus-content-356364570033-us-west-2"
FILES = {
    "governance/live/agents.md": b"# agents\ngovernance_revision: 2026-10-13.01\n",
    "governance/live/agents/lifecycle-primer.md": b"# primer\n",
    "governance/live/agents/zeta.md": b"# zeta\n",
}


class _S3:
    def __init__(self, objects):
        self.objects = dict(objects)
        self.calls = []

    def _miss(self, op):
        return ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, op)

    def head_object(self, Bucket, Key, **kw):
        self.calls.append(("head", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {}

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise self._miss("GetObject")
        import io
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def get_object_attributes(self, Bucket, Key, ObjectAttributes, **kw):
        self.calls.append(("attrs", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            raise self._miss("GetObjectAttributes")
        digest = base64.b64encode(hashlib.sha256(self.objects[(Bucket, Key)]).digest()).decode()
        return {"Checksum": {"ChecksumSHA256": digest}, "VersionId": f"v-{Bucket}"}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        self.calls.append(("list", Bucket, Prefix))
        yield {"Contents": [{"Key": k} for (b, k) in sorted(self.objects) if b == Bucket and k.startswith(Prefix)]}

    def buckets(self):
        return {c[1] for c in self.calls}


def _both_buckets():
    objs = {(LEGACY, k): v for k, v in FILES.items()}
    objs.update({(PROD_CONTENT, k): v for k, v in FILES.items()})
    return objs


def _bundle(monkeypatch, s3, env):
    for k in ("CONTENT_STORE_MODE", "CONTENT_STORE_READ", "GOVERNANCE_CONTENT_BUCKET", "CONTENT_BUCKET", "S3_ENV_PREFIX"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(mod, "_s3_client", s3)
    files = mod._list_canonical_files()
    entries = [{"uri": uri, "checksum_sha256_hex": mod._get_file_checksum(key)[0]} for uri, key in files]
    return mod._compute_bundle_hash(entries), [u for u, _ in files], mod._read_governance_revision(
        "governance/live/agents.md")


def _expected_hash():
    h = hashlib.sha256()
    for key in sorted(FILES, key=lambda k: "governance://" + k[len("governance/live/"):]):
        h.update(("governance://" + key[len("governance/live/"):]).encode() + b"\n")
        h.update(hashlib.sha256(FILES[key]).hexdigest().encode() + b"\n")
    return h.hexdigest()


def test_no_governance_bucket_is_the_raw_legacy_path(monkeypatch):
    s3 = _S3(_both_buckets())
    digest, uris, rev = _bundle(monkeypatch, s3, {"CONTENT_STORE_MODE": "dual", "CONTENT_BUCKET": "per-env-bucket"})
    assert digest == _expected_hash() and rev == "2026-10-13.01"
    assert s3.buckets() == {LEGACY}
    assert uris == ["governance://agents.md", "governance://agents/lifecycle-primer.md", "governance://agents/zeta.md"]


def test_dual_with_the_read_pin_stays_on_legacy(monkeypatch):
    s3 = _S3(_both_buckets())
    env = {"CONTENT_STORE_MODE": "dual", "CONTENT_STORE_READ": "legacy", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
    assert _bundle(monkeypatch, s3, env)[0] == _expected_hash()
    assert s3.buckets() == {LEGACY}


def test_after_the_flip_the_hash_is_unchanged_and_read_from_the_shared_prod_bucket(monkeypatch):
    s3 = _S3(_both_buckets())
    env = {"CONTENT_STORE_MODE": "dual", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT, "S3_ENV_PREFIX": "gamma/"}
    digest, uris, _ = _bundle(monkeypatch, s3, env)
    assert digest == _expected_hash() and len(uris) == 3
    assert all(c[1] == PROD_CONTENT for c in s3.calls if c[0] in ("head", "attrs", "get"))
    assert all(not c[2].startswith("gamma/") for c in s3.calls)  # the shared corpus is never env-prefixed


def test_after_the_flip_a_file_missing_from_content_falls_back_without_changing_the_hash(monkeypatch):
    objs = _both_buckets()
    del objs[(PROD_CONTENT, "governance/live/agents/zeta.md")]  # e.g. written to legacy before B22 and not yet copied
    s3 = _S3(objs)
    env = {"CONTENT_STORE_MODE": "dual", "GOVERNANCE_CONTENT_BUCKET": PROD_CONTENT}
    assert _bundle(monkeypatch, s3, env)[0] == _expected_hash()
    assert ("attrs", LEGACY, "governance/live/agents/zeta.md") in s3.calls


def _block(text, name):
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n|\Z)", text)
    assert m, name
    return m.group(1)


@pytest.mark.parametrize("role", ["RecomputeGovernanceRole", "GovernanceDriftCheckRole"])
def test_roles_can_read_the_shared_prod_bucket_on_both_planes(role):
    with open(os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml"),
              encoding="utf-8") as fh:
        b = _block(fh.read(), role)
    read = b.split("Sid: ReadGovernanceLiveSharedProdContent", 1)[1].split("- Sid:", 1)[0]
    assert "s3:GetObject" in read and "s3:GetObjectAttributes" in read
    assert '!Sub "arn:aws:s3:::enceladus-content-${AWS::AccountId}-${AWS::Region}/governance/live/*"' in read
    lst = b.split("Sid: ListGovernanceSharedProdContent", 1)[1].split("- PolicyName:", 1)[0]
    assert "s3:ListBucket" in lst and "Condition" not in lst  # a content miss must answer 404, not 403


@pytest.mark.parametrize("fn", ["recompute_governance", "governance_drift_check"])
def test_build_extras_ship_content_store(fn):
    with open(os.path.join(HERE, "..", fn, ".build_extras"), encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    assert "backend/lambda/shared_layer/python/enceladus_shared/content_store.py" in lines
