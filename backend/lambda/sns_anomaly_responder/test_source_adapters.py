"""ENC-TSK-R82-0D: source-adapter boundary + stub adapter proof (ENC-FTR-150 AC-8).
The primitive (lambda_function) is exercised with a second source and is never modified."""
import json
import os
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("COORDINATION_INTERNAL_API_KEY", "test")

import aws_cad_adapter as cad  # noqa: E402
import lambda_function as lf  # noqa: E402
import source_adapters as sa  # noqa: E402
import stub_adapter  # noqa: E402
from test_sns_anomaly_responder import FIXTURE, FakeTracker, _event  # noqa: E402


@pytest.fixture
def stub_registered(monkeypatch):
    sa.REGISTRY.register(stub_adapter)
    monkeypatch.setenv("ANOMALY_SOURCE", "stub")
    yield
    sa.REGISTRY.pop("stub", None)


def _stub_msg(*ids, project=None):
    sigs = [{"id": i, "title": f"drift {i}", "magnitude": 3, **({"project": project} if project else {})} for i in ids]
    return json.dumps({"signals": sigs})


def test_default_registry_is_aws_cad_only_and_handler_uses_it():
    assert lf.ADAPTERS is sa.REGISTRY
    assert sa.REGISTRY.sources() == ["aws-cad"]
    assert isinstance(cad, sa.SourceAdapter)


def test_aws_cad_output_satisfies_contract():
    anomalies = sa.parse_message(cad, FIXTURE)
    assert len(anomalies) == 1
    n = anomalies[0]
    assert n["project_id"] == n["project"] == "devops"
    assert n["source"] == "aws-cad" and n["breakdown"] and n["severity"] == "medium"


def test_stub_adapter_conforms_and_is_deterministic():
    assert isinstance(stub_adapter, sa.SourceAdapter)
    a = sa.parse_message(stub_adapter, _stub_msg("sig-1", "sig-2"))
    b = sa.parse_message(stub_adapter, _stub_msg("sig-1", "sig-2"))
    strip = lambda xs: [{k: v for k, v in x.items()} for x in xs]
    assert [x["anomaly_id"] for x in a] == ["sig-1", "sig-2"]
    assert strip(a) == strip(b)  # no clock/ordering dependence in identity fields
    assert all(x["evidence"][0]["source_key"] == f"stub:{x['anomaly_id']}" for x in a)


def test_stub_garbage_yields_nothing():
    assert stub_adapter.parse("not json") == []
    assert stub_adapter.parse(json.dumps({"signals": [{"title": "no id"}, "x"]})) == []


def test_stub_through_unmodified_primitive_replay_x3_one_create(stub_registered):
    t = FakeTracker()
    for _ in range(3):
        res = lf.lambda_handler(_event(_stub_msg("sig-1")), None, client=t)
    assert t.creates == 1
    assert len(t.logs) == 2  # replays append a worklog, no new create
    issue = next(iter(t.issues.values()))
    assert "[stub:sig-1]" in issue["title"]
    assert issue["body"]["idempotency_key"] == "stub:sig-1"
    assert res["results"][0]["action"] == "replayed"


def test_project_routing_hook(stub_registered):
    seen = []

    class Spy(FakeTracker):
        def create_issue(self, project, body):
            seen.append(project)
            return super().create_issue(project, body)

    lf.lambda_handler(_event(_stub_msg("a")), None, client=Spy())
    lf.lambda_handler(_event(_stub_msg("b", project="enceladus")), None, client=Spy())
    assert seen == ["devops", "enceladus"]


def test_sources_do_not_collide_on_same_anomaly_id(monkeypatch):
    sa.REGISTRY.register(stub_adapter)
    try:
        t = FakeTracker()
        cad_id = json.loads(FIXTURE)["anomalyId"]
        lf.lambda_handler(_event(FIXTURE), None, client=t)
        monkeypatch.setenv("ANOMALY_SOURCE", "stub")
        lf.lambda_handler(_event(_stub_msg(cad_id)), None, client=t)
        assert t.creates == 2
    finally:
        sa.REGISTRY.pop("stub", None)


def test_unknown_source_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("ANOMALY_SOURCE", "nope")
    assert lf._select_adapter("") is cad


@pytest.mark.parametrize("bad", [
    {"source": "x", "anomaly_id": "", "project": "p", "title": "t", "evidence": [{}]},
    {"source": "x", "anomaly_id": "1", "project": "p", "title": "t", "evidence": []},
    {"source": "other", "anomaly_id": "1", "project": "p", "title": "t", "evidence": [{}]},
    {"source": "x", "anomaly_id": "1", "title": "t", "evidence": [{}]},
    "not-a-dict",
])
def test_validate_rejects_contract_violations(bad):
    with pytest.raises(sa.AdapterContractError):
        sa.validate_normalized(bad, "x")


def test_contract_violation_fails_invocation_so_sns_retries(monkeypatch):
    class Bad:
        SOURCE = "bad"
        @staticmethod
        def parse(message):
            return [{"source": "bad", "anomaly_id": "", "project": "p", "title": "t", "evidence": [{}]}]
    sa.REGISTRY.register(Bad)
    monkeypatch.setenv("ANOMALY_SOURCE", "bad")
    t = FakeTracker()
    try:
        with pytest.raises(RuntimeError):
            lf.lambda_handler(_event("{}"), None, client=t)
        assert t.creates == 0
    finally:
        sa.REGISTRY.pop("bad", None)


def test_register_rejects_bad_adapters():
    reg = sa.AdapterRegistry()
    class NoParse:
        SOURCE = "ok"
    class BadName:
        SOURCE = "Bad:Name"
        parse = staticmethod(lambda m: [])
    for a in (NoParse, BadName):
        with pytest.raises(sa.AdapterContractError):
            reg.register(a)
