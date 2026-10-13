"""DVP-TSK-B31 (isolation W4g read flip): pathway-telemetry/ readers go content-first (no AWS).

B20 made every pathway-telemetry/ access go through content_store with CONTENT_STORE_READ=legacy. B31 drops that pin in
02-compute, so close_wave and flow_weight_refresh list both buckets and read content first, legacy on a miss. The flip
is safe only after the W3 delta for the prefix: a content miss on this role may answer 403 (prefix-conditioned
ListBucket, DVP-ISS-149), and 403 never falls back to legacy.
"""

import os
import re
import sys

import pytest
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import lambda_function as lf  # noqa: E402
from test_content_store_pathway_b20 import CONTENT, LEGACY, PREFIX, T0, _FakeS3, _hit, _use  # noqa: E402

COMPUTE_YAML = os.path.abspath(os.path.join(HERE, "..", "..", "..", "infrastructure", "cloudformation", "02-compute.yaml"))


@pytest.fixture
def env(monkeypatch):
    def _set(read=None):
        monkeypatch.setenv("CONTENT_STORE_MODE", "dual")
        monkeypatch.setenv("CONTENT_BUCKET", CONTENT)
        monkeypatch.setenv("S3_ENV_PREFIX", "gamma/")
        if read is None:
            monkeypatch.delenv("CONTENT_STORE_READ", raising=False)
        else:
            monkeypatch.setenv("CONTENT_STORE_READ", read)
        monkeypatch.setattr(lf, "PATHWAY_TELEMETRY_BUCKET", LEGACY)
        monkeypatch.setattr(lf, "PATHWAY_TELEMETRY_PREFIX", PREFIX)
        monkeypatch.setattr(lf, "_CONTENT_STORE", None)
    return _set


def _block(text, name):
    m = re.search(r"(?ms)^  " + name + r":\n(.*?)(?=^  [A-Za-z0-9]+:\n)", text)
    assert m, name
    return m.group(1)


def test_cloudformation_drops_the_read_pin_for_graph_query_api_only():
    with open(COMPUTE_YAML, encoding="utf-8") as fh:
        text = fh.read()
    fn = _block(text, "GraphQueryApiFunction")
    assert "CONTENT_STORE_MODE: dual" in fn
    assert "CONTENT_STORE_READ: " not in fn
    assert 'CONTENT_BUCKET: !Sub "enceladus-content${EnvironmentSuffix}-${AWS::AccountId}-${AWS::Region}"' in fn
    assert "S3_ENV_PREFIX: !Ref S3EnvPrefix" in fn
    # DVP-ISS-149 stays an io decision: the content ListBucket condition is unchanged by the flip
    role = _block(text, "GraphQueryApiRole")
    content_list = role.split("Sid: PathwayTelemetryListContentBucket", 1)[1].split("- PolicyName:", 1)[0]
    assert '- "pathway-telemetry/*"' in content_list and '- "pathway-telemetry"\n' not in content_list


def _wave_seed():
    return {
        # written after B20 went dual: in both buckets
        (LEGACY, f"{PREFIX}/wave_id=W1/a.jsonl"): (_hit("e1", 2), T0),
        (CONTENT, "pathway-telemetry/wave_id=W1/a.jsonl"): (_hit("e1", 2), T0),
        # pre-B20 object the delta has not copied yet: legacy only
        (LEGACY, f"{PREFIX}/wave_id=W1/b.jsonl"): (_hit("e1", 3), T0),
    }


def test_close_wave_reads_content_first_and_falls_back_on_a_404_miss(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _FakeS3(_wave_seed()))
    records, seen, failed = lf._iter_wave_pathway_telemetry_records("W1")
    assert (seen, failed) == (2, 0) and len(records) == 2
    assert [b for b, _ in s3.lists] == [CONTENT, LEGACY]  # merged listing, legacy-form keys, no duplicate for a.jsonl
    assert s3.gets.count((LEGACY, f"{PREFIX}/wave_id=W1/a.jsonl")) == 0  # a content hit never touches legacy
    assert s3.gets[-2:] == [(CONTENT, "pathway-telemetry/wave_id=W1/b.jsonl"), (LEGACY, f"{PREFIX}/wave_id=W1/b.jsonl")]


class _AccessDeniedOnContentMiss(_FakeS3):
    """What the role sees on a content miss when its content ListBucket is prefix-conditioned: 403, not 404."""

    def get_object(self, Bucket, Key, **kw):
        if Bucket == CONTENT and (Bucket, Key) not in self.objects:
            self.gets.append((Bucket, Key))
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetObject")
        return super().get_object(Bucket, Key, **kw)


def test_without_the_delta_a_legacy_only_key_is_a_counted_failure_not_a_crash(env, monkeypatch):
    env()
    s3 = _use(monkeypatch, _AccessDeniedOnContentMiss(_wave_seed()))
    records, seen, failed = lf._iter_wave_pathway_telemetry_records("W1")
    assert (seen, failed) == (2, 1) and len(records) == 1  # why the W3 delta must run before this deploy
    assert (LEGACY, f"{PREFIX}/wave_id=W1/b.jsonl") not in s3.gets
