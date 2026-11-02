"""ENC-TSK-R83-0B (ENC-FTR-150 AC-9): MENTIONS drift adapter on the anomaly primitive."""
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test")

import lambda_function as lf  # noqa: E402
import mentions_drift_adapter as md  # noqa: E402
import source_adapters as sa  # noqa: E402
from test_sns_anomaly_responder import FakeTracker  # noqa: E402


def _msg(mismatch=33, sample=96, missing=True, extra=False, breached=True, run_at="2026-11-02T10:00:00Z", n=5):
    div = [{"record_id": f"ENC-TSK-{i}", "record_type": "task",
            "missing": [f"ENC-TSK-{i + 100}"] if missing else [], "extra": ["ENC-FTR-1"] if extra else []}
           for i in range(n)]
    return json.dumps({"audit": "mentions_drift_audit", "run_at": run_at, "sample_size": sample,
                       "mismatch_count": mismatch, "ratio": round(mismatch / sample, 4), "threshold": 0.01,
                       "threshold_breached": breached, "has_missing": missing, "has_extra": extra,
                       "divergent": div})


def _event(message):
    return {"Records": [{"Sns": {"Message": message,
            "MessageAttributes": {"anomaly_source": {"Type": "String", "Value": "mentions-drift"}}}}]}


def test_registered_and_contract_valid():
    assert "mentions-drift" in sa.REGISTRY.sources()
    out = sa.parse_message(md, _msg())
    assert len(out) == 1 and out[0]["source"] == "mentions-drift" and out[0]["project_id"] == "enceladus"
    assert f"[mentions-drift:{out[0]['anomaly_id']}]" in out[0]["title"]
    assert out[0]["evidence"][0]["source_key"] == f"mentions-drift:{out[0]['anomaly_id']}"


def test_id_stable_across_counts_ordering_and_time_but_not_direction():
    a = md.parse(_msg(mismatch=33, run_at="2026-11-02T10:00:00Z", n=5))[0]["anomaly_id"]
    b = md.parse(_msg(mismatch=70, sample=90, run_at="2026-11-03T10:00:00Z", n=9))[0]["anomaly_id"]
    c = md.parse(_msg(missing=False, extra=True))[0]["anomaly_id"]
    d = md.parse(_msg(missing=True, extra=True))[0]["anomaly_id"]
    assert a == b and len({a, c, d}) == 3


def test_not_breached_or_malformed_yield_nothing():
    assert md.parse(_msg(breached=False)) == []
    assert md.parse("not json") == []
    assert md.parse(_msg(missing=False, extra=False)) == []


def test_three_consecutive_runs_one_issue_zero_duplicates(monkeypatch):
    monkeypatch.delenv("ANOMALY_SOURCE", raising=False)  # per-record attribute selects the adapter
    tracker = FakeTracker()
    for i, (mm, ts) in enumerate([(33, "T1"), (41, "T2"), (29, "T3")]):
        res = lf.lambda_handler(_event(_msg(mismatch=mm, run_at=ts)), None, client=tracker)
        assert res["summary"]["errors"] == 0
    assert tracker.creates == 1
    assert len(tracker.issues) == 1
    assert len(tracker.logs) == 2  # runs 2 and 3 replayed onto the same issue


def test_cad_default_unaffected_without_attribute():
    snap = {"Records": [{"Sns": {"TopicArn": "x", "Message": "{}"}}]}
    assert lf._select_adapter(snap["Records"][0]["Sns"]).SOURCE == "aws-cad"
