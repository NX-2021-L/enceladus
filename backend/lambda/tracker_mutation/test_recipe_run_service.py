"""DVP-TSK-968 part B: recipe run lifecycle and runner (in-memory store, mocked hub producer)."""
import copy
import itertools

import pytest

import recipe_run_service as rrs
import recipe_service as rs

PROJECT, REC, STARTER = "devops", "DVP-REC-001", "agent-a"


def _defn(sensitive=False, on_reject="failed", on_expire=None, surface=None):
    gate = {"prompt": "Approve the close?", "timeout": {"seconds": 3600}, "sensitive": sensitive, "on_reject": on_reject,
            "inputs": {"type": "object", "required": ["note"], "properties": {"note": {"type": "string"}}}}
    if on_expire:
        gate["on_expire"] = on_expire
    first = {"id": "mk", "type": "action", "action": "tracker.create_task", "arguments": {"title": "$inputs.title"},
             "compensate": {"action": "tracker.close_task", "arguments": {"task_id": "$mk.task_id"}}}
    if surface:
        first["surface"] = surface
    return {"inputs": {"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}},
            "steps": [first,
                      {"id": "approve", "type": "gate", "gate": gate},
                      {"id": "tag", "type": "action", "action": "tracker.update_task",
                       "arguments": {"task_id": "$mk.task_id", "note": "$approve.inputs.note"}}],
            "outputs": {"schema": {"type": "object", "required": ["task_id"]},
                        "from": {"task_id": "$mk.task_id", "decision": "$approve.decision"}}}


class World:
    def __init__(self, definition=None, status="published", ready=None, fail=()):
        self.items, self.puts, self.minted = {}, 0, 0
        self.batches, self.escalations, self.escs, self.withdrawn = [], [], {}, []
        self.clock, self.hash, self.fail, self.n = "2026-10-11T12:00:00Z", "gh1", set(fail), itertools.count(1)
        definition = definition or _defn()
        chash = rs.compute_content_hash("daily-close", "1.0.0", definition)
        self.items[(PROJECT, rs.head_key(REC))] = {"record_id": rs.head_key(REC), "recipe_id": REC, "latest_published": "1.0.0",
                                                    "project_ids": [PROJECT], "owner": "io", "name": "daily-close"}
        self.items[(PROJECT, rs.version_key(REC, "1.0.0"))] = {
            "record_id": rs.version_key(REC, "1.0.0"), "recipe_id": REC, "name": "daily-close", "version": "1.0.0",
            "status": status, "definition": definition, "content_hash": chash}
        self.ctx = rrs.RunContext(get=self.get, put=self.put, query=self.query, mint=self.mint, now=lambda: self.clock,
                                  escalate=self.escalate, escalation=lambda p, e: copy.deepcopy(self.escs.get(e)),
                                  execute=self.execute, governance_hash=lambda: self.hash,
                                  surface_ready=ready or (lambda s: s == "enceladus"),
                                  withdraw=lambda p, e, r: self.withdrawn.append(e) or True)

    def get(self, project, sk):
        return copy.deepcopy(self.items.get((project, sk)))

    def put(self, project, item, if_absent=False, expect=None):
        key, cur = (project, item["record_id"]), self.items.get((project, item["record_id"]))
        if if_absent and cur is not None:
            return False
        if expect and (cur is None or cur.get(expect[0]) != expect[1]):
            return False
        self.items[key] = copy.deepcopy(dict(item, project_id=project))
        self.puts += 1
        return True

    def query(self, project, prefix):
        return [copy.deepcopy(v) for (p, k), v in self.items.items() if p == project and k.startswith(prefix)]

    def mint(self, project):
        self.minted += 1
        return f"DVP-RUN-{self.minted:03d}"

    def escalate(self, project, request):
        self.escalations.append(request)
        eid = f"DVP-ESC-{len(self.escalations):03d}"
        self.escs[eid] = {"escalation_id": eid, "status": "pending", "subject": request["subject"], "sourcePrincipal": "recipe-runner"}
        return 201, {"escalation_id": eid}

    def execute(self, batch):
        self.batches.append(copy.deepcopy(batch))

        def call_one(call, dry_run):
            if call["action"] in self.fail:
                return {"ok": False, "error": {"code": "BOOM", "message": f"{call['action']} failed"}}
            return {"ok": True, "result": {"task_id": f"DVP-TSK-{next(self.n):03d}", "dry_run": dry_run, "args": call["arguments"]}}
        return rrs.run_batch_locally(batch, call_one)

    def decide(self, eid, status="approved", inputs=None, by="io@example.com"):
        self.escs[eid].update(status=status, approved_by={"email": by}, decision={"inputs": inputs or {}})

    def start(self, body=None, **kw):
        base = {"recipe_id": REC, "inputs": {"title": "close"}, "idempotency_key": "k1", "governance_hash": "gh1"}
        return rrs.start(self.ctx, PROJECT, dict(base, **(body or {})), STARTER, **kw)

    def stored(self, run_id):
        return self.items[(PROJECT, rrs.run_key(run_id))]


def test_start_stops_at_first_gate_and_opens_a_hub_escalation():
    w = World()
    code, body = w.start()
    assert code == 201 and body["run_id"] == "DVP-RUN-001" and body["status"] == "awaiting_gate"
    assert [s["status"] for s in body["steps"]] == ["ok", "awaiting", "pending"]
    assert len(w.batches) == 1 and len(w.batches[0]["calls"]) == 1          # one execute call per segment
    req = w.escalations[0]
    assert req["source_principal"] == "recipe-runner" and req["kind"] == "acceptance"
    assert req["subject"]["type"] == "recipe_run_step" and req["subject"]["record_id"] == "DVP-RUN-001" and req["subject"]["step_id"] == "approve"
    assert req["inputs_schema"]["required"] == ["note"] and req["expiresAt"] == "2026-10-11T13:00:00Z" and "distinct_from" not in req
    assert body["gate"]["escalation_id"] == "DVP-ESC-001" and body["resume_token"].startswith("rrt_")
    assert body["recipe_ref"]["content_hash"].startswith("sha256:")
    stored = w.stored("DVP-RUN-001")
    assert body["resume_token"] not in str(stored)                              # only the hash is stored
    code, read = rrs.get(w.ctx, PROJECT, "DVP-RUN-001")                         # one read answers completion
    assert code == 200 and read["complete"] is False and read["terminal"] is False and read["progress"] == "1/3"
    assert "resume_token" not in read and "token_hash" not in str(read["gate"])
    assert read["steps"][0]["receipt"] == {"task_id": "DVP-TSK-001"}


def test_approve_applier_binds_gate_inputs_and_completes_then_replay_is_a_noop():
    w = World()
    run_id = w.start()[1]["run_id"]
    w.decide("DVP-ESC-001", inputs={"note": "fine"})
    code, body = rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001", "decider": "io@example.com"}, "io")
    assert code == 200 and body["status"] == "completed" and body["complete"] is True
    assert body["outputs"] == {"task_id": "DVP-TSK-001", "decision": "approve"}
    assert len(w.batches) == 2 and w.batches[1]["calls"][0]["arguments"] == {"task_id": "DVP-TSK-001", "note": "fine"}
    assert w.ctx.get(PROJECT, rrs.run_key(run_id))["telemetry"]["gates_opened"] == 1
    before = (len(w.batches), w.puts)
    code, again = rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001"}, "io")
    assert code == 200 and again["replayed"] is True and (len(w.batches), w.puts) == before


@pytest.mark.parametrize("on_reject,status,code", [("failed", "failed", "GATE_REJECTED"), ("cancelled", "cancelled", "CANCELLED")])
def test_deny_follows_on_reject_and_failed_compensates_first(on_reject, status, code):
    w = World(_defn(on_reject=on_reject))
    run_id = w.start()[1]["run_id"]
    w.decide("DVP-ESC-001", status="denied")
    run = w.ctx.get(PROJECT, rrs.run_key(run_id))
    code_, body = rrs.sweep(w.ctx, PROJECT, {}, "io")
    assert body["observed"] == 1
    _c, body = rrs.get(w.ctx, PROJECT, run_id)
    assert body["status"] == status and body["error"]["code"] == code and body["steps"][2]["status"] == "skipped"
    assert len(w.batches) == (2 if on_reject == "failed" else 1)
    if on_reject == "failed":
        assert w.batches[1]["calls"][0]["action"] == "tracker.close_task" and body["compensation"] == "done"
        assert w.batches[1]["calls"][0]["arguments"] == {"task_id": "DVP-TSK-001"}
    assert run["gate"] is not None and w.stored(run_id)["gate"] is None


def test_resume_token_is_validated_first_consumed_once_and_replay_executes_nothing():
    w = World()
    token = w.start()[1]["resume_token"]
    snap = (w.puts, len(w.batches))
    assert rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": "rrt_wrong"}, STARTER)[0] == 403
    assert rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER)[1]["error_code"] == "GATE_PENDING"
    w.decide("DVP-ESC-001", inputs={"note": 5})                                    # wrong type -> 422 before any state change
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER)
    assert code == 422 and body["error_code"] == "INPUTS_INVALID" and (w.puts, len(w.batches)) == snap
    assert w.stored("DVP-RUN-001").get("consumed_tokens") in (None, [])
    assert rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER, dry_run=True)[0] == 422
    w.decide("DVP-ESC-001", inputs={"note": "ok"})
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token, "dry_run": True}, STARTER, dry_run=True)
    assert code == 200 and body["dry_run"] is True and (w.puts, len(w.batches)) == snap
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER)
    assert code == 200 and body["status"] == "completed" and len(w.batches) == 2
    done = (w.puts, len(w.batches))
    code, again = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER)
    assert code == 200 and again["replayed"] is True and again["executed"] == 0 and (w.puts, len(w.batches)) == done


def test_governance_drift_blocks_resume_and_keeps_the_token():
    w = World()
    token = w.start()[1]["resume_token"]
    w.decide("DVP-ESC-001", inputs={"note": "ok"})
    w.hash = "gh2"
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token}, STARTER)
    assert code == 409 and body["error_code"] == "GOVERNANCE_DRIFT" and body["diff"]["governance_hash"] == {"was": "gh1", "now": "gh2"}
    run = w.stored("DVP-RUN-001")
    assert run["status"] == "awaiting_gate" and run["blocked"]["code"] == "GOVERNANCE_DRIFT" and not run.get("consumed_tokens") and len(w.batches) == 1
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": token, "accept_governance_drift": True}, STARTER)
    assert code == 200 and body["status"] == "completed" and body["governance_hash_last"] == "gh2"


def test_abort_runs_only_declared_compensates_in_reverse():
    steps = [{"id": sid, "type": "action", "action": f"tracker.do_{sid}", "arguments": {"n": sid},
              **({"compensate": {"action": f"tracker.undo_{sid}", "arguments": {"id": f"${sid}.task_id"}}} if sid != "b2" else {})}
             for sid in ("a", "b", "b2", "c", "d")]
    w = World({"steps": steps}, fail=("tracker.do_c",))
    code, body = w.start()
    assert code == 201 and body["status"] == "failed" and body["error"] == {"code": "STEP_ERROR", "message": "c: tracker.do_c failed", "step_id": "c"}
    assert [s["status"] for s in body["steps"]] == ["ok", "ok", "ok", "error", "skipped"]
    assert [c["action"] for c in w.batches[1]["calls"]] == ["tracker.undo_b", "tracker.undo_a"]     # reverse, declared only
    assert body["compensation"] == "done" and [c["ok"] for c in body["compensations"]] == [True, True]


def test_on_error_continue_marks_the_step_skipped_and_the_run_goes_on():
    steps = [{"id": "a", "type": "action", "action": "tracker.do_a", "on_error": "continue", "arguments": {}},
             {"id": "b", "type": "action", "action": "tracker.do_b", "arguments": {}}]
    w = World({"steps": steps}, fail=("tracker.do_a",))
    body = w.start()[1]
    assert body["status"] == "completed" and [s["status"] for s in body["steps"]] == ["skipped", "ok"]
    assert body["steps"][0]["error"]["code"] == "BOOM"


def test_dry_run_all_writes_nothing_and_types_unresolved_placeholders():
    w = World()
    code, body = w.start({"mode": "dry_run", "idempotency_key": ""})
    assert code == 200 and body["run_id"] is None and body["dry_run"] is True and body["writes"] == 0
    assert (w.puts, w.minted, len(w.batches), len(w.escalations)) == (0, 0, 0, 0)
    mk, gate, tag = body["planned"]
    assert mk["arguments"] == {"title": "close"} and mk["status"] == "planned"
    assert gate["status"] == "gate" and gate["prompt"] == "Approve the close?"
    assert tag["status"] == "planned (unresolved)"
    assert tag["arguments"]["task_id"] == {"$unresolved": "$mk.task_id", "type": "unknown"} or tag["arguments"]["task_id"]["$unresolved"] == "$mk.task_id"
    assert tag["arguments"]["note"]["$unresolved"] == "$approve.inputs.note" and body["unresolved"] is True
    assert w.start(dry_run=True)[1]["run_id"] is None and w.puts == 0


def test_external_surface_without_credentials_runs_dry_and_flags_fixture_mode():
    w = World(_defn(surface="io-finance"))
    body = w.start()[1]
    call = w.batches[0]["calls"][0]
    assert call["surface"] == "io-finance" and call["dry_run"] is True
    assert body["fixture_mode"] is True and body["steps"][0]["fixture"] is True and body["telemetry"]["writes"] == 0
    ready = World(_defn(surface="io-finance"), ready=lambda s: True)
    assert ready.start()[1]["fixture_mode"] is False and ready.batches[0]["calls"][0]["dry_run"] is False


def test_sensitive_gate_refuses_the_starter_and_files_distinct_from():
    w = World(_defn(sensitive=True))
    run_id = w.start()[1]["run_id"]
    assert w.escalations[0]["distinct_from"] == [STARTER]
    w.decide("DVP-ESC-001", inputs={"note": "ok"}, by=STARTER)
    snap = (w.puts, len(w.batches))
    code, body = rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001", "decider": STARTER}, "io")
    assert code == 403 and body["error_code"] == "SELF_REVIEW" and (w.puts, len(w.batches)) == snap
    assert w.stored(run_id)["status"] == "awaiting_gate"
    w.decide("DVP-ESC-001", inputs={"note": "ok"}, by="io@example.com")
    assert rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001", "decider": "io@example.com"}, "io")[1]["status"] == "completed"


def test_apply_refuses_foreign_escalations_and_undecided_gates():
    w = World()
    run_id = w.start()[1]["run_id"]
    assert rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001"}, "io")[0] == 409        # still pending
    assert rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-999"}, "io")[0] == 403        # not the bound gate
    w.escs["DVP-ESC-001"]["sourcePrincipal"] = "someone-else"
    w.decide("DVP-ESC-001", inputs={"note": "ok"})
    assert rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001"}, "io")[0] == 403


def test_start_is_idempotent_validates_inputs_first_and_pins_a_published_version():
    w = World()
    first = w.start()[1]
    code, again = w.start()
    assert code == 200 and again["run_id"] == first["run_id"] and again["idempotent"] is True and len(w.batches) == 1 and w.minted == 1
    assert w.start({"inputs": {"title": "other"}})[1]["error_code"] == "IDEMPOTENCY_CONFLICT"
    bad = World()
    code, body = bad.start({"inputs": {}})
    assert code == 422 and body["error_code"] == "INPUTS_INVALID" and (bad.puts, bad.minted) == (0, 0)
    assert World(status="validated").start()[1]["error_code"] == "NOT_PUBLISHED"
    assert w.start({"idempotency_key": "k2", "content_hash": "sha256:" + "0" * 64})[1]["error_code"] == "PIN_MISMATCH"
    assert rrs.start(w.ctx, PROJECT, {"recipe_id": REC, "inputs": {"title": "x"}, "governance_hash": "gh1"}, STARTER)[0] == 400


def test_cancel_by_starter_withdraws_the_gate_and_later_approval_executes_nothing():
    w = World()
    run_id = w.start()[1]["run_id"]
    assert rrs.cancel(w.ctx, PROJECT, run_id, {"reason": "nope"}, "stranger")[0] == 403
    assert rrs.cancel(w.ctx, PROJECT, run_id, {}, STARTER, dry_run=True)[1]["dry_run"] is True and w.stored(run_id)["status"] == "awaiting_gate"
    code, body = rrs.cancel(w.ctx, PROJECT, run_id, {"reason": "nope"}, STARTER)
    assert code == 200 and body["status"] == "cancelled" and body["error"]["code"] == "CANCELLED" and body["escalation_withdrawn"] is True
    assert w.withdrawn == ["DVP-ESC-001"]
    w.decide("DVP-ESC-001", inputs={"note": "ok"})
    code, body = rrs.apply_gate(w.ctx, PROJECT, run_id, {"escalation_id": "DVP-ESC-001"}, "io")
    assert code == 200 and body["replayed"] is True and body["status"] == "cancelled" and len(w.batches) == 1


def test_sweeper_expires_an_undecided_gate_fail_closed_and_lists_runs():
    w = World()
    run_id = w.start()[1]["run_id"]
    w.clock = "2026-10-11T14:00:00Z"
    assert rrs.sweep(w.ctx, PROJECT, {}, "io")[1]["observed"] == 1
    body = rrs.get(w.ctx, PROJECT, run_id)[1]
    assert body["status"] == "expired" and body["error"]["code"] == "GATE_EXPIRED" and len(w.batches) == 1
    items = rrs.list_runs(w.ctx, PROJECT, {"status": "expired"})[1]["items"]
    assert [i["run_id"] for i in items] == [run_id] and rrs.list_runs(w.ctx, PROJECT, {"status": "running"})[1]["count"] == 0


def test_hub_failure_leaves_awaiting_gate_and_resume_refiles_with_the_same_key():
    w = World()
    w.ctx.escalate = lambda p, r: (503, {"error": "down"})
    code, body = w.start()
    assert code == 502 and body["error_code"] == "GATE_FAILED" and w.stored("DVP-RUN-001")["status"] == "awaiting_gate"
    w.ctx.escalate = w.escalate
    code, body = rrs.resume(w.ctx, PROJECT, "DVP-RUN-001", {"resume_token": body["resume_token"]}, STARTER)
    assert code == 202 and body["refiled"] is True and body["gate"]["escalation_id"] == "DVP-ESC-001"
    assert w.escalations[0]["idempotency_key"] == "DVP-RUN-001:approve:1"
