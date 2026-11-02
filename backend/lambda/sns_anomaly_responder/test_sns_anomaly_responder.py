"""ENC-TSK-R81-0B unit tests: deterministic normalize + idempotent create (3 replays -> 1 create).
The SnapStart fixture is a reconstruction of the 2026-04-22 SEV1 shape (FTR-100 AC-6)."""
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test")

import aws_cad_adapter as cad  # noqa: E402
import lambda_function as lf  # noqa: E402

FIXTURE = (HERE / "fixtures" / "snapstart_spike_2026_04_22.json").read_text()


class FakeTracker:
    def __init__(self):
        self.issues = {}
        self.creates = 0
        self.sets = []
        self.logs = []

    def list_issues(self, project, status, cursor=""):
        return {"records": [r for r in self.issues.values() if r["status"] == status], "next_cursor": ""}

    def create_issue(self, project, body):
        self.creates += 1
        iid = f"DVP-ISS-{900 + self.creates}"
        self.issues[iid] = {"item_id": iid, "status": "open", "title": body["title"],
                            "evidence": body["evidence"], "body": body}
        return {"success": True, "record_id": iid}

    def set_field(self, project, issue_id, field, value):
        self.sets.append((issue_id, field))
        self.issues[issue_id][field] = value

    def log(self, project, issue_id, description):
        self.logs.append((issue_id, description))


def _event(message=FIXTURE):
    return {"Records": [{"Sns": {"TopicArn": "arn:aws:sns:us-west-2:1:enceladus-cost-anomaly-events-gamma", "Message": message}}]}


def test_normalize_shape_and_breakdown():
    norm = cad.parse(FIXTURE)[0]
    assert set(["source", "anomaly_id", "project", "title", "evidence"]) <= set(norm)
    assert norm["source"] == "aws-cad" and norm["project"] == "devops"
    assert "[aws-cad:a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d]" in norm["title"]
    ev = norm["evidence"][0]
    assert ev["description"] and isinstance(ev["steps_to_duplicate"], list) and ev["steps_to_duplicate"]
    usage = {r["usage_type"] for r in ev["breakdown"]}  # FTR-100 AC-3 per-service/per-usage-type
    assert usage == {"USW2-Lambda-SnapStart-Restore-Duration", "USW2-Lambda-SnapStart-Cache-GB-Second"}
    assert all(r["service"] == "AWS Lambda" for r in ev["breakdown"])


def test_threshold_floor_and_pct(monkeypatch):
    small = json.loads(FIXTURE)
    small["impact"].update(totalImpact=0.40, totalImpactPercentage=900.0)
    assert cad.parse(json.dumps(small)) == []  # under the $1 floor
    monkeypatch.setenv("CAD_MIN_IMPACT_USD", "0.25")
    assert len(cad.parse(json.dumps(small))) == 1  # configurable without code change
    small["impact"].update(totalImpact=3.0, totalImpactPercentage=10.0)
    assert cad.parse(json.dumps(small)) == []  # under 35% gate
    monkeypatch.setenv("CAD_MIN_IMPACT_PCT", "0")
    assert len(cad.parse(json.dumps(small))) == 1


def test_non_cad_and_garbage_are_ignored():
    assert cad.parse("not json") == [] and cad.parse(json.dumps({"hello": 1})) == []


def test_replay_x3_yields_one_create_and_evidence_worklog_on_replays():
    t = FakeTracker()
    for _ in range(3):
        out = lf.lambda_handler(_event(), None, client=t)
    assert t.creates == 1 and len(t.issues) == 1
    issue = next(iter(t.issues.values()))
    assert issue["body"]["idempotency_key"] == "aws-cad:a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    assert [r["action"] for r in out["results"]] == ["replayed"]
    assert len(t.logs) == 2  # worklog on each replay, none on first create
    assert t.sets == []  # identical impact -> evidence unchanged


def test_replay_with_new_impact_refreshes_evidence():
    t = FakeTracker()
    lf.lambda_handler(_event(), None, client=t)
    bigger = json.loads(FIXTURE)
    bigger["impact"].update(totalImpact=31.5, maxImpact=31.5)
    lf.lambda_handler(_event(json.dumps(bigger)), None, client=t)
    assert t.creates == 1 and t.sets and t.sets[0][1] == "evidence"
    assert len(next(iter(t.issues.values()))["evidence"]) == 2 and "31.5" in t.logs[-1][1]


def test_closed_issue_is_not_duplicated():
    t = FakeTracker()
    lf.lambda_handler(_event(), None, client=t)
    next(iter(t.issues.values()))["status"] = "closed"
    lf.lambda_handler(_event(), None, client=t)
    assert t.creates == 1


def test_lookup_failure_does_not_blind_create():
    class Boom(FakeTracker):
        def list_issues(self, *a, **k):
            raise lf.TrackerError("down")
    t = Boom()
    try:
        lf.lambda_handler(_event(), None, client=t)
        assert False, "should raise so SNS retries"
    except RuntimeError:
        pass
    assert t.creates == 0


def test_second_adapter_stub_needs_no_primitive_change():  # AC-8 seam
    class Stub:
        SOURCE = "stub"
        @staticmethod
        def parse(message):
            return [{"source": "stub", "anomaly_id": "x1", "project": "devops", "title": "t [stub:x1]",
                     "evidence": [{"description": "d", "steps_to_duplicate": ["s"], "impact": {}}], "impact": {}}]
    lf.ADAPTERS["stub"] = Stub
    try:
        os.environ["ANOMALY_SOURCE"] = "stub"
        t = FakeTracker()
        for _ in range(3):
            lf.lambda_handler(_event("{}"), None, client=t)
        assert t.creates == 1
    finally:
        os.environ.pop("ANOMALY_SOURCE", None)
        lf.ADAPTERS.pop("stub", None)
