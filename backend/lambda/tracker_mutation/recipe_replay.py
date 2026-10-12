"""DVP-TSK-976 (DVP-PLN-013 E4-W4.1): deterministic replay of a recorded recipe run (the recipes parity test).

A fixture is a recorded run transcript:
  {recipe: {recipe_id, name, version, content_hash, definition}, project_id, run_id, started_by, governance_hash,
   inputs, segments: [{calls: [...], results: [...]}], gates: [{step_id, decision: approve|deny, inputs, decider}],
   expected: {final_state, step_statuses, receipts, step_results (optional), outputs}}

The replay drives recipe_run_service with no network and no agent: a fake executor asserts that each segment plans
exactly the recorded calls (order-sensitive) and answers with the recorded results; a fake hub records the gate
escalations and applies the recorded decisions through recipe_run_service.apply_gate (the recipe_run_step applier
path).  Sensitive gates are also probed with the starter as decider and must refuse (SELF_REVIEW).

CLI: python3 recipe_replay.py <fixture.json | dir> ... [--md FILE]   (exit 1 on any FAIL or when no fixture is found)
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import recipe_run_service as rrs  # noqa: E402
import recipe_service as rs  # noqa: E402

FIXTURE_SUFFIX = ".run.json"
CLOCK = "2026-10-11T12:00:00Z"


class ReplayWorld:
    """In-memory store + fake hub + recorded executor.  Subclass and override execute() to record a transcript."""

    def __init__(self, fixture: Dict[str, Any]):
        self.fx = fixture
        recipe = fixture["recipe"]
        self.project = fixture.get("project_id") or "devops"
        self.rec_id = recipe.get("recipe_id") or "DVP-REC-001"
        self.starter = fixture.get("started_by") or "agent-a"
        self.gh = fixture.get("governance_hash") or "gh-replay"
        self.run_id = fixture.get("run_id") or "DVP-RUN-001"
        self.segments: List[Dict[str, Any]] = fixture.get("segments") or []
        self.items: Dict[Any, Dict[str, Any]] = {}
        self.escalations: List[Dict[str, Any]] = []
        self.escs: Dict[str, Dict[str, Any]] = {}
        self.failures: List[str] = []
        self.seg = 0
        self.captured: List[Dict[str, Any]] = []
        self.items[(self.project, rs.head_key(self.rec_id))] = {
            "record_id": rs.head_key(self.rec_id), "recipe_id": self.rec_id, "latest_published": recipe["version"],
            "project_ids": [self.project], "owner": "io", "name": recipe["name"]}
        self.items[(self.project, rs.version_key(self.rec_id, recipe["version"]))] = {
            "record_id": rs.version_key(self.rec_id, recipe["version"]), "recipe_id": self.rec_id, "name": recipe["name"],
            "version": recipe["version"], "status": "published", "definition": copy.deepcopy(recipe["definition"]),
            "content_hash": recipe["content_hash"]}
        self.ctx = rrs.RunContext(
            get=self.get, put=self.put, query=self.query, mint=lambda project: self.run_id, now=lambda: fixture.get("clock") or CLOCK,
            escalate=self.escalate, escalation=lambda project, eid: copy.deepcopy(self.escs.get(eid)),
            execute=self.execute, governance_hash=lambda: self.gh, surface_ready=lambda surface: True)

    # -- store
    def get(self, project: str, sk: str) -> Optional[Dict[str, Any]]:
        return copy.deepcopy(self.items.get((project, sk)))

    def put(self, project: str, item: Dict[str, Any], if_absent: bool = False, expect: Any = None) -> bool:
        key, cur = (project, item["record_id"]), self.items.get((project, item["record_id"]))
        if (if_absent and cur is not None) or (expect and (cur is None or cur.get(expect[0]) != expect[1])):
            return False
        self.items[key] = copy.deepcopy(dict(item, project_id=project))
        return True

    def query(self, project: str, prefix: str) -> List[Dict[str, Any]]:
        return [copy.deepcopy(v) for (p, k), v in self.items.items() if p == project and k.startswith(prefix)]

    # -- hub
    def escalate(self, project: str, request: Dict[str, Any]):
        self.escalations.append(copy.deepcopy(request))
        eid = f"ESC-REPLAY-{len(self.escalations):03d}"
        self.escs[eid] = {"escalation_id": eid, "status": "pending", "subject": request["subject"], "sourcePrincipal": rrs.SOURCE_PRINCIPAL}
        return 201, {"escalation_id": eid}

    def decide(self, eid: str, verdict: str, inputs: Dict[str, Any], decider: str) -> None:
        self.escs[eid].update(status="approved" if verdict == "approve" else "denied", approved_by={"email": decider},
                              decision={"inputs": inputs or {}})

    # -- executor: assert the planned calls equal the recorded calls, answer with the recorded results
    def execute(self, batch: Dict[str, Any]) -> Dict[str, Any]:
        idx, self.seg = self.seg, self.seg + 1
        if idx >= len(self.segments):
            self.failures.append(f"segment {idx} was planned but the fixture records only {len(self.segments)} segment(s)")
            return {"results": []}
        seg = self.segments[idx]
        if json.loads(json.dumps(batch["calls"])) != seg.get("calls"):
            planned = [c.get("step_id") for c in batch["calls"]]
            recorded = [c.get("step_id") for c in seg.get("calls") or []]
            self.failures.append(f"segment {idx}: planned calls differ from the recorded calls (planned {planned}, recorded {recorded})")
        results = copy.deepcopy(seg.get("results") or [])
        for pos, (call, res) in enumerate(zip(batch["calls"], results)):
            if isinstance(res, dict) and res.get("step_id") not in (None, call.get("step_id")):
                self.failures.append(f"segment {idx}: recorded result {pos} belongs to {res.get('step_id')!r} but call {pos} is {call.get('step_id')!r}")
        return {"results": results}

    # -- drive
    def drive(self) -> Dict[str, Any]:
        fx, gates = self.fx, self.fx.get("gates") or []
        body: Dict[str, Any] = {}
        code, body = rrs.start(self.ctx, self.project, {
            "recipe_id": self.rec_id, "inputs": fx.get("inputs") or {}, "idempotency_key": "replay:" + fx["recipe"]["name"],
            "governance_hash": self.gh}, self.starter)
        applied, refused = 0, []
        while code < 300 and body.get("status") == "awaiting_gate" and applied < len(gates):
            g, gate = gates[applied], body.get("gate") or {}
            if g.get("step_id") != gate.get("step_id"):
                self.failures.append(f"gate order: run opened {gate.get('step_id')!r}, fixture decides {g.get('step_id')!r}")
                break
            eid, req = gate["escalation_id"], self.escalations[-1]
            decider, inputs, verdict = g.get("decider") or "io@example.com", g.get("inputs") or {}, g.get("decision") or "approve"
            if gate.get("sensitive"):
                if req.get("distinct_from") != [self.starter]:
                    self.failures.append(f"gate {gate['step_id']}: sensitive gate did not file distinct_from [{self.starter}]")
                self.decide(eid, "approve", inputs, self.starter)               # probe: the starter must be refused
                pcode, pbody = rrs.apply_gate(self.ctx, self.project, self.run_id, {"escalation_id": eid, "decider": self.starter}, "replay")
                if pcode == 403 and pbody.get("error_code") == "SELF_REVIEW":
                    refused.append(gate["step_id"])
                else:
                    self.failures.append(f"gate {gate['step_id']}: the starter was not refused ({pcode} {pbody.get('error_code')})")
            self.decide(eid, verdict, inputs, decider)
            code, body = rrs.apply_gate(self.ctx, self.project, self.run_id, {"escalation_id": eid, "decider": decider}, "replay")
            applied += 1
        if code >= 300:
            self.failures.append(f"runner error {code} {body.get('error_code')}: {str(body.get('message') or '')[:160]}")
        _, read = rrs.get(self.ctx, self.project, self.run_id)
        if not isinstance(read, dict) or "steps" not in read:
            read = {"status": "unstarted", "steps": [], "outputs": None, "telemetry": {}}
        return self.verdict(read, applied, refused)

    def verdict(self, read: Dict[str, Any], applied: int, refused: List[str]) -> Dict[str, Any]:
        exp, fails = self.fx.get("expected") or {}, list(self.failures)
        statuses = {s["id"]: s["status"] for s in read.get("steps") or []}
        receipts = {s["id"]: s["receipt"] for s in read.get("steps") or [] if s.get("receipt")}
        agent_calls = int((read.get("telemetry") or {}).get("agent_calls") or 0)
        step_results = {s["id"]: s["result"] for s in read.get("steps") or [] if s.get("result") is not None and s.get("type") != "gate"}
        for key, got in (("final_state", read.get("status")), ("step_statuses", statuses), ("receipts", receipts),
                         ("step_results", step_results), ("outputs", read.get("outputs"))):
            if key in exp and exp[key] != got:
                fails.append(f"{key}: expected {json.dumps(exp[key], sort_keys=True)} got {json.dumps(got, sort_keys=True)}")
        if agent_calls != 0:
            fails.append(f"agent_calls must be 0, got {agent_calls}")
        if self.seg != len(self.segments):
            fails.append(f"executed {self.seg} segment(s), the fixture records {len(self.segments)}")
        if applied != len(self.fx.get("gates") or []):
            fails.append(f"applied {applied} gate decision(s), the fixture records {len(self.fx.get('gates') or [])}")
        name, ok = self.fx["recipe"]["name"], not fails
        line = (f"recipes parity: {name} replay {'PASS' if ok else 'FAIL'} "
                f"({self.seg} segments, {applied} gates, agent_calls={agent_calls})")
        return {"name": name, "ok": ok, "status": read.get("status"), "summary": line, "failures": fails, "segments": self.seg,
                "gates": applied, "agent_calls": agent_calls, "starter_refused": refused, "synthetic": bool(self.fx.get("synthetic")),
                "run_id": read.get("run_id")}


def replay(fixture: Dict[str, Any]) -> Dict[str, Any]:
    return ReplayWorld(fixture).drive()


def find_fixtures(paths: List[str]) -> List[Path]:
    found: List[Path] = []
    for raw in paths:
        p = Path(raw)
        found.extend(sorted(p.rglob("*" + FIXTURE_SUFFIX)) if p.is_dir() else [p])
    return found


def main(argv: List[str]) -> int:
    md: List[str] = []
    args = list(argv)
    while "--md" in args:
        i = args.index("--md")
        md.append(args[i + 1])
        del args[i:i + 2]
    files = find_fixtures(args)
    if not files:
        print("recipes parity: no fixtures found; refusing to pass an empty parity test")
        return 1
    lines, bad = [], 0
    for path in files:
        try:
            res = replay(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            res = {"ok": False, "summary": f"recipes parity: {path.name} replay FAIL (0 segments, 0 gates, agent_calls=0)",
                   "failures": [f"fixture unreadable or replay crashed: {type(exc).__name__}: {exc}"], "synthetic": False}
        bad += 0 if res["ok"] else 1
        lines.append(res["summary"])
        lines.extend("  - " + f for f in res["failures"])
        if res.get("synthetic"):
            lines.append("  - note: synthetic fixture; replace it with the recorded RUN-* transcript")
    print("\n".join(lines))
    for target in md:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write("### Recipes parity (recorded-run replay)\n\n" + "\n".join(
                ("- " + ln if ln.startswith("recipes parity") else ln) for ln in lines) + "\n\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
