"""ENC-TSK-R83-0A: async fail-open Bedrock enrichment -- advisory fields only."""
import io
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test")

import enrichment as en  # noqa: E402
import lambda_function as lf  # noqa: E402
import test_sns_anomaly_responder as base  # noqa: E402

NORM = {"source": "aws-cad", "anomaly_id": "A1", "project": "devops", "title": "t [aws-cad:A1]",
        "impact": {"total_impact_usd": 12.5}, "evidence": [{"source_key": "aws-cad:A1"}]}
REQ = {"norm": NORM, "key": "aws-cad:A1", "project": "devops", "issue_id": "DVP-ISS-901"}
MODEL_REPLY = {"hypothesis": "NAT spike", "technical_notes": "check NAT bytes", "location_hint": "vpc",
               "suggested_priority": "P1", "suggested_project": "enceladus", "evil_field": "x"}


class Tracker(base.FakeTracker):
    def __init__(self):
        super().__init__()
        self.gets = []

    def get_issue(self, project, issue_id):
        self.gets.append(issue_id)
        return {"record": dict(self.issues.get(issue_id, {}))}


class FakeBedrock:
    def __init__(self, reply=None, exc=None):
        self.calls, self.reply, self.exc = 0, reply, exc

    def invoke_model(self, **kw):
        self.calls += 1
        if self.exc:
            raise self.exc
        body = {"content": [{"type": "text", "text": json.dumps(self.reply)}]}
        return {"body": io.BytesIO(json.dumps(body).encode())}


def _setup(monkeypatch, bedrock, enabled=True):
    monkeypatch.setenv("ANOMALY_ENRICHMENT_ENABLED", "true" if enabled else "false")
    monkeypatch.setattr(en, "get_bedrock_runtime", lambda: bedrock)
    monkeypatch.setattr(en, "read_cost_digest", lambda: {"settled": False, "settled_day": "2026-10-30"})
    t = Tracker()
    t.issues["DVP-ISS-901"] = {"item_id": "DVP-ISS-901", "status": "open", "title": "x", "evidence": []}
    return t


def test_writes_only_advisory_fields_and_stamps(monkeypatch):
    b = FakeBedrock(MODEL_REPLY)
    t = _setup(monkeypatch, b)
    r = en.enrich(REQ, t)
    assert r["status"] == "enriched" and b.calls == 1
    written = {f for _, f in t.sets}
    assert written == {"hypothesis", "technical_notes", "location_hint"} <= set(en.ADVISORY_FIELDS)
    notes = t.issues["DVP-ISS-901"]["technical_notes"]
    assert "model=" in notes
    assert "enceladus" in notes and "P1" in notes and en.version_marker("aws-cad:A1", NORM) in notes
    assert "priority" not in written and "project" not in written and "evil_field" not in written


def test_bedrock_error_is_logged_and_fail_open(monkeypatch):
    t = _setup(monkeypatch, FakeBedrock(exc=RuntimeError("throttled")))
    r = en.enrich(REQ, t)
    assert r["status"] == "failed_open" and t.sets == []
    assert any("[ERROR] Bedrock enrichment failed" in d for _, d in t.logs)


def test_disabled_flag_makes_no_bedrock_call(monkeypatch):
    b = FakeBedrock(MODEL_REPLY)
    t = _setup(monkeypatch, b, enabled=False)
    assert en.enrich(REQ, t) == {"status": "disabled"}
    assert b.calls == 0 and t.sets == [] and t.gets == []
    assert en.dispatch_async("fn", REQ) is False


def test_idempotent_per_anomaly_version(monkeypatch):
    b = FakeBedrock(MODEL_REPLY)
    t = _setup(monkeypatch, b)
    en.enrich(REQ, t)
    assert en.enrich(REQ, t)["status"] == "skipped_idempotent" and b.calls == 1
    bumped = dict(REQ, norm=dict(NORM, impact={"total_impact_usd": 99}))
    assert en.enrich(bumped, t)["status"] == "enriched" and b.calls == 2


def test_unparseable_reply_fail_open(monkeypatch):
    b = FakeBedrock("not json at all")
    t = _setup(monkeypatch, b)
    assert en.enrich(REQ, t)["status"] == "failed_open" and t.sets == []


def test_dispatch_failure_does_not_fail_intake(monkeypatch):
    monkeypatch.setenv("ANOMALY_ENRICHMENT_ENABLED", "true")
    import boto3

    def boom(*a, **k):
        raise RuntimeError("no lambda")
    monkeypatch.setattr(boto3, "client", boom)
    assert en.dispatch_async("fn", REQ) is False


def test_handler_intake_succeeds_when_enrichment_dispatch_raises(monkeypatch):
    monkeypatch.setattr(lf.enrichment, "dispatch_async", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(lf.source_adapters, "parse_message", lambda a, m: [dict(NORM)])
    t = Tracker()
    out = lf.lambda_handler({"Records": [{"Sns": {"Message": "{}", "TopicArn": "arn"}}]}, None, client=t)
    assert t.creates == 1 and out["summary"]["errors"] == 0


def test_handler_enrichment_leg_delegates(monkeypatch):
    seen = []
    monkeypatch.setattr(lf.enrichment, "enrich", lambda req, c: seen.append(req) or {"status": "enriched"})
    out = lf.lambda_handler({"enrichment_request": REQ}, None, client=Tracker())
    assert out == {"enrichment": {"status": "enriched"}} and seen == [REQ]
