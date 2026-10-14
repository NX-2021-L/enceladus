"""DVP-TSK-B32 (isolation W4j): gdmp-remediation-state/ goes through content_store (no AWS).

The run counter is read-modify-write (the io-approval ramp), so its read stays on legacy while CONTENT_STORE_READ=legacy;
the counter and the run breakdowns are written to both buckets. The function is gamma-only: legacy keys carry gamma/,
content keys do not.
"""

import os
import re
import sys

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(HERE, "..", "corpus_entropy_engine"))
sys.path.append(os.path.join(HERE, "..", "shared_layer", "python"))

import lambda_function as mod  # noqa: E402

LEGACY = "jreese-net"
CONTENT = "enceladus-content-gamma-356364570033-us-west-2"
PREFIX = "gamma/gdmp-remediation-state"


class _Body:
    def __init__(self, data):
        self._d = data

    def read(self):
        return self._d


class _FakeS3:
    def __init__(self, objects=None, deny_content_miss=False):
        self.objects = dict(objects or {})
        self.calls = []
        self.deny_content_miss = deny_content_miss

    def put_object(self, Bucket, Key, Body, **kw):
        self.calls.append(("put", Bucket, Key, kw))
        self.objects[(Bucket, Key)] = Body

    def get_object(self, Bucket, Key, **kw):
        self.calls.append(("get", Bucket, Key))
        if (Bucket, Key) not in self.objects:
            code = "AccessDenied" if (self.deny_content_miss and Bucket == CONTENT) else "NoSuchKey"
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "GetObject")
        return {"Body": _Body(self.objects[(Bucket, Key)])}

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
        monkeypatch.setattr(mod, "GDMP_STATE_BUCKET", LEGACY)
        monkeypatch.setattr(mod, "GDMP_STATE_PREFIX", PREFIX)
        monkeypatch.setattr(mod, "_CONTENT_STORE", None)
        s3 = s3 or _FakeS3()
        monkeypatch.setattr(mod, "_get_s3", lambda: s3)
        return s3
    return _set


def test_run_counter_writes_both_and_reads_legacy_only(env):
    s3 = env()
    mod._save_run_counter(2)
    assert s3.touched("put") == [(CONTENT, "gdmp-remediation-state/run_counter.json"), (LEGACY, f"{PREFIX}/run_counter.json")]
    s3.objects[(CONTENT, "gdmp-remediation-state/run_counter.json")] = b'{"run_count": 99}'
    assert mod._load_run_counter() == 2
    assert s3.touched("get") == [(LEGACY, f"{PREFIX}/run_counter.json")]


def test_breakdown_and_latest_land_in_both_buckets(env):
    s3 = env()
    ref = mod._persist_run_breakdown({"scanned_at": "2026-10-13T01:02:03Z", "run_count": 1})
    puts = s3.touched("put")
    assert ref == f"s3://{LEGACY}/{PREFIX}/breakdowns/run-20261013T010203Z-n1.json"
    assert puts == [
        (CONTENT, "gdmp-remediation-state/breakdowns/run-20261013T010203Z-n1.json"),
        (LEGACY, f"{PREFIX}/breakdowns/run-20261013T010203Z-n1.json"),
        (CONTENT, "gdmp-remediation-state/breakdowns/latest.json"),
        (LEGACY, f"{PREFIX}/breakdowns/latest.json"),
    ]
    assert all(c[3] == {"ContentType": "application/json"} for c in s3.calls)


def test_after_the_flip_a_content_miss_falls_back_to_the_legacy_counter(env):
    s3 = env(read=None, s3=_FakeS3({(LEGACY, f"{PREFIX}/run_counter.json"): b'{"run_count": 3}'}))
    assert mod._load_run_counter() == 3
    assert s3.touched("get") == [(CONTENT, "gdmp-remediation-state/run_counter.json"), (LEGACY, f"{PREFIX}/run_counter.json")]


def test_without_content_list_bucket_a_flipped_read_would_restart_the_ramp(env):
    # Why GdmpRampStateListContentBucket exists: a 403 content miss skips the legacy fallback and the counter reads 0.
    env(read=None, s3=_FakeS3({(LEGACY, f"{PREFIX}/run_counter.json"): b'{"run_count": 3}'}, deny_content_miss=True))
    assert mod._load_run_counter() == 0


def test_cloudformation_env_and_list_grant():
    path = os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml")
    text = open(path, encoding="utf-8").read()

    def block(name):
        m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
        assert m, name
        return m.group(1)

    fn = block("CorpusEntropyGdmpRemediationFunction")
    for line in ("CONTENT_STORE_MODE: dual", "S3_ENV_PREFIX: !Ref S3EnvPrefix",
                 'CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"'):
        assert line in fn
    assert "CONTENT_STORE_READ: " not in fn  # DVP-TSK-B53: reads go content-first after the W3 delta
    role = block("CorpusEntropyGdmpRemediationRole")
    grant = role.split("Sid: GdmpRampStateListContentBucket", 1)[1].split("- PolicyName:", 1)[0]
    assert "s3:ListBucket" in grant
    assert 'arn:aws:s3:::enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"' in grant
