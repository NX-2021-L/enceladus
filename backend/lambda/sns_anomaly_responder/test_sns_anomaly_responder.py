"""ENC-TSK-R81-0B unit tests: deterministic normalize + idempotent create (3 replays -> 1 create).
The SnapStart fixture is a reconstruction of the 2026-04-22 SEV1 shape (FTR-100 AC-6)."""
import json
import os
import pathlib
import pytest
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
    assert t.sets == [(issue["item_id"], "evidence")] * 2  # ENC-TSK-R91: every replay appends an evidence entry
    assert len(issue["evidence"]) == 3


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


# --- ENC-TSK-R82-0A: identity (FTR-150 AC-2) + notify on first create (AC-4) -------------------

class FakeApi:
    """Scripted internal-key HTTP: records every call, answers governance/register/claim/mutations."""
    def __init__(self, register_error=None, type_error=False):
        self.type_error = type_error
        self.calls = []
        self.register_error = register_error
        self.issues = {}

    def __call__(self, method, url, body=None):
        self.calls.append((method, url, body))
        if url.endswith("/governance/hash"):
            return {"governance_hash": "g" * 64}
        if url.endswith("/agents/types") and method == "POST":
            if self.type_error:
                raise lf.TrackerError("POST types -> HTTP 422")
            return {"agent_type": {"agent_type_id": "ENC-AGT-00R"}, "created": False}
        if url.endswith("/agents/sessions") and method == "POST":
            if self.register_error:
                raise lf.TrackerError("POST register -> HTTP 422: agent-type-not-active")
            return {"session": {"session_id": "ENC-SES-0ZZ"}}
        if url.endswith("/agents/sessions/claim"):
            return {"sci": "SCI-" + "a" * 32}
        if url.endswith("/retire"):
            return {}
        if "?type=issue" in url:
            status = url.split("status=")[1].split("&")[0]
            return {"records": [r for r in self.issues.values() if r["status"] == status], "next_cursor": ""}
        if method == "POST" and url.endswith("/issue"):
            self.issues["DVP-ISS-950"] = {"item_id": "DVP-ISS-950", "status": "open", "title": body["title"],
                                          "evidence": body["evidence"]}
            return {"record_id": "DVP-ISS-950"}
        return {}


def _run_api(monkeypatch, api, event=None):
    monkeypatch.setattr(lf, "_http", api)
    monkeypatch.setattr(lf.acquire_identity, "__defaults__", (api,))
    monkeypatch.setattr(lf.retire_identity, "__defaults__", (api,))
    return lf.lambda_handler(event or _event(), None)


def test_identity_fail_closed_register_claim_then_stamped_mutations(monkeypatch):
    api = FakeApi()
    out = _run_api(monkeypatch, api)
    reg = [c for c in api.calls if c[1].endswith("/agents/sessions") and c[0] == "POST"][0]
    assert reg[2]["agent_type_id"] == "ENC-AGT-00R" and reg[2]["runtime"] == "aws_lambda"
    claim = [c for c in api.calls if c[1].endswith("/claim")][0]
    assert claim[2] == {"session_id": "ENC-SES-0ZZ", "expected_agent_type_id": "ENC-AGT-00R"}
    mutations = [c for c in api.calls if c[0] in ("POST", "PATCH") and "/tracker/" in c[1]]
    assert mutations
    for _m, _u, body in mutations:
        assert body["write_source"] == {"provider": "ENC-SES-0ZZ"}
        assert body["sci"] == "SCI-" + "a" * 32 and body["governance_hash"] == "g" * 64
    # governance hash is fetched BEFORE register (same invocation), session retired at the end
    urls = [c[1] for c in api.calls]
    assert urls[0].endswith("/governance/hash") and urls[-1].endswith("/ENC-SES-0ZZ/retire")
    assert out["results"][0]["action"] == "created"


def test_register_rejection_aborts_before_any_mutation(monkeypatch):
    api = FakeApi(register_error=True)
    try:
        _run_api(monkeypatch, api)
        assert False, "must fail closed"
    except lf.TrackerError:
        pass
    assert not [c for c in api.calls if "/tracker/" in c[1]]


def test_unstamped_client_refuses_mutations():
    c = lf.TrackerClient()
    for fn in (lambda: c.create_issue("devops", {}), lambda: c.set_field("devops", "X", "f", 1),
               lambda: c.log("devops", "X", "d")):
        try:
            fn()
            assert False
        except lf.TrackerError:
            pass


def test_push_on_first_create_only_with_issue_service_impact_even_if_enrichment_off(monkeypatch):
    monkeypatch.setenv("ANOMALY_ENRICHMENT_ENABLED", "0")
    api = FakeApi()
    _run_api(monkeypatch, api)
    pushes = [c for c in api.calls if c[1].endswith("/coordination/notifications/anomaly")]
    assert len(pushes) == 1
    body = pushes[0][2]
    assert body["issue_id"] == "DVP-ISS-950" and body["project_id"] == "devops"
    assert body["service"] == "AWS Lambda" and body["total_impact_usd"]
    _run_api(monkeypatch, api)  # replay: no second push
    assert len([c for c in api.calls if c[1].endswith("/notifications/anomaly")]) == 1


def test_push_failure_does_not_fail_intake():
    class NoPush(FakeTracker):
        def notify_anomaly(self, *a):
            raise lf.TrackerError("push down")
    t = NoPush()
    out = lf.lambda_handler(_event(), None, client=t)
    assert out["results"][0] == {**out["results"][0], "action": "created", "notified": False} and t.creates == 1
# ---- ENC-TSK-R82-0C: update-push thresholds + anomaly-closed worklog + runtime config ----
class PushTracker(FakeTracker):
    def __init__(self):
        super().__init__()
        self.updates = []

    def notify_anomaly_update(self, project, issue_id, norm, prior_usd):
        self.updates.append((issue_id, prior_usd, norm["impact"]["total_impact_usd"]))
        return {}


def _msg(total, **extra):
    body = json.loads(FIXTURE)
    body["impact"]["totalImpact"] = total
    body.update(extra)
    return json.dumps(body)


def _seed(total=10.0):
    t = PushTracker()
    lf.lambda_handler(_event(_msg(total)), None, client=t)
    return t


def test_update_below_threshold_no_push(monkeypatch):
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_RATIO", raising=False)
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_ABS_USD", raising=False)
    t = _seed(10.0)
    r = lf.lambda_handler(_event(_msg(12.0)), None, client=t)["results"][0]
    assert r["action"] == "replayed" and r["notified"] is False and t.updates == []
    assert "no push" in t.logs[-1][1]


def test_update_absolute_and_ratio_cross_push(monkeypatch):
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_RATIO", raising=False)
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_ABS_USD", raising=False)
    t = _seed(10.0)
    assert lf.lambda_handler(_event(_msg(15.5)), None, client=t)["results"][0]["notified"] is True  # +5.5 abs
    assert t.updates == [("DVP-ISS-901", 10.0, 15.5)]
    # baseline is now the last PUSH (15.5): +2 is below, 2x(15.5)=31 is the ratio gate
    assert lf.lambda_handler(_event(_msg(17.5)), None, client=t)["results"][0]["notified"] is False
    assert lf.lambda_handler(_event(_msg(31.0)), None, client=t)["results"][0]["notified"] is True


def test_creep_cannot_escape_threshold(monkeypatch):
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_RATIO", raising=False)
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_ABS_USD", raising=False)
    t = _seed(100.0)
    pushed = [lf.lambda_handler(_event(_msg(v)), None, client=t)["results"][0]["notified"]
              for v in (102.0, 104.0, 106.0)]  # each +2 over previous delivery, +6 over last push
    assert pushed == [False, False, True]


def test_threshold_configurable_without_code_change(monkeypatch):
    monkeypatch.setenv("ANOMALY_UPDATE_PUSH_ABS_USD", "1")
    monkeypatch.setenv("ANOMALY_UPDATE_PUSH_RATIO", "10")
    t = _seed(10.0)
    assert lf.lambda_handler(_event(_msg(11.5)), None, client=t)["results"][0]["notified"] is True
    monkeypatch.setenv("ANOMALY_UPDATE_PUSH_ABS_USD", "junk")  # invalid -> default $5
    assert lf.update_push_thresholds()["abs_usd"] == 5.0


def test_closed_signal_logs_and_does_not_close(monkeypatch):
    t = _seed(10.0)
    r = lf.lambda_handler(_event(_msg(10.0, anomalyStatus="CLOSED")), None, client=t)["results"][0]
    assert r["action"] == "closed_logged" and t.creates == 1
    assert t.issues["DVP-ISS-901"]["status"] == "open" and "CLOSED by source" in t.logs[-1][1]
    assert t.updates == []


def test_closed_signal_without_issue_creates_nothing():
    t = PushTracker()
    r = lf.lambda_handler(_event(_msg(0.1, anomalyStatus="CLOSED")), None, client=t)["results"][0]
    assert r["action"] == "closed_signal_unmatched" and t.creates == 0


def test_type_resolution_env_override_wins(monkeypatch):
    monkeypatch.setenv("ANOMALY_AGENT_TYPE_ID", "ENC-AGT-ZZZ")
    monkeypatch.setattr(lf, "_TYPE_ID_CACHE", {})
    api = FakeApi()
    assert lf.resolve_agent_type_id(api) == "ENC-AGT-ZZZ"
    assert api.calls == []


def test_type_resolution_once_per_container(monkeypatch):
    monkeypatch.delenv("ANOMALY_AGENT_TYPE_ID", raising=False)
    monkeypatch.setattr(lf, "_TYPE_ID_CACHE", {})
    api = FakeApi()
    assert lf.resolve_agent_type_id(api) == "ENC-AGT-00R"
    assert lf.resolve_agent_type_id(api) == "ENC-AGT-00R"
    posts = [c for c in api.calls if c[1].endswith("/agents/types")]
    assert len(posts) == 1
    assert posts[0][2] == {"surface": "sns-anomaly-responder", "model": "deterministic-no-llm", "cost_tier": "low"}


def test_type_resolution_failure_fails_closed(monkeypatch):
    monkeypatch.delenv("ANOMALY_AGENT_TYPE_ID", raising=False)
    monkeypatch.setattr(lf, "_TYPE_ID_CACHE", {})
    api = FakeApi(type_error=True)
    with pytest.raises(lf.TrackerError):
        lf.acquire_identity(api)
    assert not any(c[1].endswith("/agents/sessions") for c in api.calls)


# ---- ENC-TSK-R91: gamma E2E defects (compact list, truthful pushed, handler context) ----
class CompactListTracker(PushTracker):
    """Mirrors the real tracker: list rows are COMPACT (no evidence); get_issue returns the full record."""
    def __init__(self, push_ok=True):
        super().__init__()
        self.push_ok = push_ok
        self.create_pushes = 0

    def list_issues(self, project, status, cursor=""):
        rows = [{k: v for k, v in r.items() if k not in ("evidence", "body")}
                for r in self.issues.values() if r["status"] == status]
        return {"records": rows, "next_cursor": ""}

    def get_issue(self, project, issue_id):
        return {"record": self.issues[issue_id]}

    def notify_anomaly(self, project, issue_id, norm):
        self.create_pushes += 1
        if not self.push_ok:
            raise lf.TrackerError("HTTP 404")
        return {}

    def notify_anomaly_update(self, project, issue_id, norm, prior_usd):
        if not self.push_ok:
            raise lf.TrackerError("HTTP 404")
        return super().notify_anomaly_update(project, issue_id, norm, prior_usd)


def _clear_thresholds(monkeypatch):
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_RATIO", raising=False)
    monkeypatch.delenv("ANOMALY_UPDATE_PUSH_ABS_USD", raising=False)


def test_replays_append_entries_and_baseline_survives_compact_list(monkeypatch):
    _clear_thresholds(monkeypatch)
    t = CompactListTracker()
    lf.lambda_handler(_event(_msg(10.0)), None, client=t)
    rs = [lf.lambda_handler(_event(_msg(v)), None, client=t)["results"][0] for v in (10.0, 12.0, 20.0)]
    assert [r["notified"] for r in rs] == [False, False, True]  # replays below threshold do not push
    assert t.updates == [("DVP-ISS-901", 10.0, 20.0)]  # baseline came from the stored evidence, not None
    ev = next(iter(t.issues.values()))["evidence"]
    assert len(ev) == 4  # create + one entry per replay
    assert [e.get("pushed") for e in ev[1:]] == [False, False, True]
    assert [e["total_impact_usd"] for e in ev[1:]] == [10.0, 12.0, 20.0]
    assert lf.push_baseline(ev) == 20.0  # next replay compares against the last PUSHED impact


def test_failed_update_push_is_not_flagged_pushed(monkeypatch):
    _clear_thresholds(monkeypatch)
    t = CompactListTracker(push_ok=False)
    lf.lambda_handler(_event(_msg(10.0)), None, client=t)
    r = lf.lambda_handler(_event(_msg(30.0)), None, client=t)["results"][0]
    assert r["notified"] is False
    ev = next(iter(t.issues.values()))["evidence"]
    assert ev[-1]["pushed"] is False and ev[-1]["total_impact_usd"] == 30.0
    assert lf.push_baseline(ev) == 10.0  # failed push never moves the baseline
    assert "push FAILED" in t.logs[-1][1]


def test_unknown_evidence_never_overwrites_or_pushes(monkeypatch):
    _clear_thresholds(monkeypatch)
    t = CompactListTracker()
    lf.lambda_handler(_event(_msg(10.0)), None, client=t)
    sets_before = len([x for x in t.sets if x[1] == "evidence"])  # create's pushed-flag write

    def boom(project, issue_id):
        raise lf.TrackerError("down")
    t.get_issue = boom
    r = lf.lambda_handler(_event(_msg(50.0)), None, client=t)["results"][0]
    assert r["notified"] is False and t.updates == []
    assert len([x for x in t.sets if x[1] == "evidence"]) == sets_before  # stored evidence untouched


def test_lambda_handler_passes_context_to_enrichment_dispatch(monkeypatch):
    import types
    calls = []
    monkeypatch.setattr(lf.enrichment, "dispatch_async", lambda fn, payload: calls.append((fn, payload)))
    t = FakeTracker()
    ctx = types.SimpleNamespace(function_name="enceladus-sns-anomaly-responder-gamma")
    out = lf.lambda_handler(_event(), ctx, client=t)
    assert out["results"][0]["action"] == "created" and len(calls) == 1
    fn, payload = calls[0]
    assert fn == "enceladus-sns-anomaly-responder-gamma"
    assert payload["issue_id"] == out["results"][0]["issue_id"] and payload["project"] == "devops"


# ---- ENC-TSK-R91 follow-up: create-time baseline + enrichment only after create ----
def test_identical_replay_after_2xx_create_push_does_not_push(monkeypatch):
    _clear_thresholds(monkeypatch)
    t = CompactListTracker()
    lf.lambda_handler(_event(_msg(24.71)), None, client=t)
    first = next(iter(t.issues.values()))["evidence"][0]
    assert first["total_impact_usd"] == 24.71 and first["pushed"] is True
    r = lf.lambda_handler(_event(_msg(24.71)), None, client=t)["results"][0]
    assert r["notified"] is False and t.updates == []  # baseline = create push, not None
    assert "prior pushed impact=None" not in " ".join(d for _, d in t.logs)


def test_failed_create_push_is_not_flagged_pushed(monkeypatch):
    _clear_thresholds(monkeypatch)
    t = CompactListTracker(push_ok=False)
    lf.lambda_handler(_event(_msg(24.71)), None, client=t)
    first = next(iter(t.issues.values()))["evidence"][0]
    assert first["total_impact_usd"] == 24.71 and "pushed" not in first


def test_enrichment_dispatched_once_across_create_replay_and_closed(monkeypatch):
    import types
    _clear_thresholds(monkeypatch)
    calls = []
    monkeypatch.setattr(lf.enrichment, "dispatch_async", lambda fn, payload: calls.append(payload))
    t = CompactListTracker()
    ctx = types.SimpleNamespace(function_name="fn")
    lf.lambda_handler(_event(_msg(24.71)), ctx, client=t)
    lf.lambda_handler(_event(_msg(24.71)), ctx, client=t)
    lf.lambda_handler(_event(_msg(60.0)), ctx, client=t)
    r = lf.lambda_handler(_event(_msg(24.71, anomalyStatus="CLOSED")), ctx, client=t)["results"][0]
    assert r["action"] == "closed_logged"
    assert len(calls) == 1 and calls[0]["issue_id"] == "DVP-ISS-901"
