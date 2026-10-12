"""DVP-TSK-968 follow-up (E4-R24): the validator and runner accept the RP-0 s4 step and binding grammar natively."""
import copy
import json
from pathlib import Path

import pytest

import recipe_run_service as rrs
import recipe_service as rs
import test_recipe_run_service as base

KIT = Path(__file__).resolve().parent / "fixtures" / "recipes" / "kit"
KIT_FILES = sorted(KIT.glob("*.json"))


def _kit(name):
    return json.loads((KIT / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry():
    reg = rs.load_registry()
    assert reg, "the bundled recipe_caps must load"
    return reg


def test_there_are_five_kit_fixtures():
    assert [p.stem for p in KIT_FILES] == ["governance-arc", "idea-to-brd", "lesson-capture", "statement-ingest", "trip-ledger-close"]


@pytest.mark.parametrize("path", KIT_FILES, ids=lambda p: p.stem)
def test_every_kit_fixture_validates_with_zero_errors_against_the_bundled_caps(path, registry):
    fx = json.loads(path.read_text(encoding="utf-8"))
    assert set(fx) >= {"name", "version", "content_hash", "definition"}
    assert rs.validate_definition(fx["definition"], registry) == []


@pytest.mark.parametrize("path", KIT_FILES, ids=lambda p: p.stem)
def test_normalizing_never_rewrites_the_stored_definition_or_its_hash(path):
    fx = json.loads(path.read_text(encoding="utf-8"))
    before = copy.deepcopy(fx["definition"])
    norm = rs.normalize_definition(fx["definition"])
    assert fx["definition"] == before                                            # input untouched
    assert rs.compute_content_hash(fx["name"], fx["version"], fx["definition"]) == rs.compute_content_hash(fx["name"], fx["version"], before)
    assert all(not isinstance(s.get("gate"), str) for s in norm["steps"])         # normalized copy is the internal form
    assert [s["id"] for s in norm["steps"]] == [s["id"] for s in before["steps"]]


def test_the_internal_gate_form_still_validates_and_both_forms_normalize_alike(registry):
    rp0 = {"id": "g", "gate": "human", "prompt": "ok?", "inputs": {"type": "object", "properties": {"n": {"type": "string"}}},
           "timeout": {"seconds": 60}, "on_reject": "cancelled", "sensitive": True, "approvers": ["io"]}
    internal = {"id": "g", "type": "gate", "gate": {k: v for k, v in rp0.items() if k not in ("id", "gate")}}
    assert rs.normalize_step(rp0) == internal
    assert rs.normalize_step(internal) == internal


@pytest.mark.parametrize("mut,code", [
    (lambda st: st.pop("timeout"), "SHAPE"),
    (lambda st: st.update(gate="robot"), "GATE_REQUIRED"),
    (lambda st: st.update(on_reject="exploded"), "SHAPE"),
    (lambda st: st.update(action="tracker.create"), "SHAPE"),
    (lambda st: st.update(bogus=1), "UNKNOWN_KEY"),
    (lambda st: st.update(approvers="io"), "SHAPE"),
])
def test_a_malformed_rp0_gate_step_is_rejected(mut, code):
    st = {"id": "g", "gate": "human", "prompt": "ok?", "timeout": {"seconds": 60}}
    mut(st)
    got = {e["code"] for e in rs.validate_definition({"tools": [], "steps": [st]}, None)}
    assert code in got


def test_run_binding_root_is_a_valid_static_ref_but_only_for_its_fields():
    def codes(ref):
        d = {"tools": ["x.y"], "steps": [{"id": "a", "action": "x.y", "arguments": {"v": ref}, "on_error": "abort"}]}
        return {e["code"] for e in rs.validate_definition(d, {"enceladus": {"x.y"}})}
    for f in rs.RUN_FIELDS:
        assert codes(f"$run.{f}") == set()
    assert "BINDING_UNRESOLVED" in codes("$run.nope") and "BINDING_UNRESOLVED" in codes("$run")


def test_index_alias_must_point_backwards_and_literal_escapes_a_dollar():
    def codes(args, more=()):
        d = {"tools": ["x.y"], "steps": [{"id": "a", "action": "x.y", "arguments": {}, "on_error": "abort"},
                                         {"id": "b", "action": "x.y", "arguments": args, "on_error": "abort"}, *more]}
        return {e["code"] for e in rs.validate_definition(d, {"enceladus": {"x.y"}})}
    assert codes({"v": "$0.id"}) == set()
    assert "FORWARD_REFERENCE" in codes({"v": "$1.id"}) or "UNKNOWN_BINDING_ROOT" in codes({"v": "$7.id"})
    assert codes({"v": {"$literal": "$ghost.x"}}) == set()


class ArcWorld(base.World):
    def execute(self, batch):
        self.batches.append(copy.deepcopy(batch))
        return rrs.run_batch_locally(batch, lambda call, dry: {"ok": True, "result": {"record_id": "DVP-TSK-100", "commit_complete_id": "CCI-1"}})


ARC_INPUTS = {"project_id": "devops", "title": "t", "components": ["comp-x"]}


def test_runner_drives_the_governance_arc_kit_fixture_to_its_first_rp0_gate():
    fx = _kit("governance-arc")
    w = ArcWorld(definition=fx["definition"])
    code, body = w.start({"inputs": ARC_INPUTS})
    assert code == 201 and body["status"] == "awaiting_gate"
    assert [s["status"] for s in body["steps"]][:4] == ["ok", "ok", "ok", "awaiting"]
    assert len(w.batches) == 1 and len(w.batches[0]["calls"]) == 3                 # one execute per segment
    checkout = body["steps"][2]["resolved_call"]["arguments"]
    assert checkout["active_agent_session_id"] == base.STARTER and checkout["record_id"] == {"$ref": "create", "path": ["record_id"]}   # $run.started_by; in-segment refs resolve in the executor
    req = w.escalations[0]
    assert req["kind"] == "acceptance" and req["justification"] == "Code is complete. Provide the commit sha."
    assert req["inputs_schema"]["required"] == ["commit_sha"] and req["expiresAt"] == "2026-10-12T12:00:00Z"
    assert req["subject"]["step_id"] == "code_gate" and "distinct_from" not in req
    assert body["gate"]["kind"] == "acceptance" and body["resume_token"].startswith("rrt_")
    stored = w.items[(base.PROJECT, rs.version_key(base.REC, "1.0.0"))]["definition"]
    assert stored == fx["definition"]                                                 # stored definition never rewritten


def test_rp0_sensitive_gate_files_distinct_from_and_approvers():
    d = {"tools": ["tracker.create_task"], "inputs": {"type": "object", "properties": {}},
         "steps": [{"id": "mk", "action": "tracker.create_task", "arguments": {}, "on_error": "abort"},
                   {"id": "ok", "gate": "human", "prompt": "Approve?", "inputs": {"type": "object", "properties": {}},
                    "timeout": {"seconds": 120}, "on_reject": "cancelled", "on_expire": "failed", "sensitive": True,
                    "approvers": ["io", "ops"], "escalation_kind": "security"}]}
    w = ArcWorld(definition=d)
    code, body = w.start({"inputs": {}})
    assert code == 201 and body["status"] == "awaiting_gate"
    req = w.escalations[0]
    assert req["distinct_from"] == [base.STARTER] and req["approvers"] == ["io", "ops"] and req["kind"] == "security"
    assert req["expiresAt"] == "2026-10-11T12:02:00Z"


def test_rp0_on_reject_cancelled_routes_the_run_to_cancelled():
    d = {"tools": ["tracker.create_task"], "inputs": {"type": "object", "properties": {}},
         "steps": [{"id": "mk", "action": "tracker.create_task", "arguments": {}, "on_error": "abort"},
                   {"id": "ok", "gate": "human", "prompt": "Approve?", "inputs": {"type": "object", "properties": {}},
                    "timeout": {"seconds": 120}, "on_reject": "cancelled"}]}
    w = ArcWorld(definition=d)
    run_id = w.start({"inputs": {}})[1]["run_id"]
    w.decide("DVP-ESC-001", status="denied")
    rrs.sweep(w.ctx, base.PROJECT, {}, "io")
    _c, body = rrs.get(w.ctx, base.PROJECT, run_id)
    assert body["status"] == "cancelled" and body["error"]["code"] == "CANCELLED"
