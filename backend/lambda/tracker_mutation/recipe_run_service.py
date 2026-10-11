"""DVP-TSK-968 part B (DVP-PLN-013 E4-W2.2, DVP-FTR-106): the recipe run primitive and runner.

Storage-agnostic like recipe_service: every function takes a RunContext of injected callables, so the
Lambda wires DynamoDB and the tests wire an in-memory store.  Runs live at record_id recipe_run#<RUN>
(deliberately outside the recipe# prefix); the start idempotency marker lives at recipe-run-idem#<hash>.

Runner v1 (architect ruling E4-R15, RP-0 s4):
  * server-side, keyed by run_id; a segment is the steps from the cursor to the next gate.
  * one ctx.execute call per segment; the cursor is advanced by a conditional (rev) write; a claim write
    (queued -> running, segment_started) precedes the call so a concurrent or crashed driver can never
    execute a segment twice, and an at_most_once step is never auto-retried.
  * governance_hash is re-fetched at each segment start; drift blocks (GOVERNANCE_DRIFT), never continues.
  * on_error abort -> remaining steps skipped, only DECLARED compensate steps run, in reverse order.
    on_error continue marks the step skipped and the run goes on.
  * external surfaces without credentials run with dry_run=true and flag the run fixture_mode=true.
  * dry_run_all computes the whole plan with typed {"$unresolved": ...} placeholders and writes nothing.
  * gates open a hub escalation as the producer principal recipe-runner (subject recipe_run_step); the
    plaintext resume token is shown once (in the response that opened the gate) and stored hashed; it is
    validated BEFORE any state change, consumed once, and a replay executes nothing.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import recipe_service as rs

Result = rs.Result
_ok = rs._ok
_err = rs._err

SOURCE_PRINCIPAL = rs.SOURCE_PRINCIPAL
RUN_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,11}-RUN-[0-9]{3,}$")
RUN_PREFIX = "recipe_run#"
IDEM_PREFIX = "recipe-run-idem#"
TERMINAL = ("completed", "failed", "cancelled", "expired")
MODES = ("dry_run", "to_next_gate")
DEFAULT_TTL_SECONDS = 7 * 86400
DEFAULT_GATE_SECONDS = 86400
APPROVED = rs.APPROVED_ESCALATION_STATUSES
PENDING = rs.PENDING_ESCALATION_STATUSES
DENIED = {"denied", "rejected", "declined", "deny"}
EXPIRED = {"expired"}
REJECT_WORDS = {"deny", "denied", "reject", "rejected", "decline", "declined"}
MAX_LIST = 200


@dataclass
class RunContext:
    get: Callable[[str, str], Optional[Dict[str, Any]]]
    put: Callable[..., bool]                                   # (project, item, if_absent=False, expect=None) -> ok
    query: Callable[[str, str], List[Dict[str, Any]]]
    mint: Callable[[str], str]                                 # project -> new RUN id (server-minted)
    now: Callable[[], str]
    escalate: Callable[[str, Dict[str, Any]], Tuple[int, Dict[str, Any]]]
    escalation: Callable[[str, str], Optional[Dict[str, Any]]]
    execute: Callable[[Dict[str, Any]], Dict[str, Any]]        # ONE call per segment: {"calls": [...]} -> {"results": [...]}
    governance_hash: Callable[[], Optional[str]] = lambda: None
    surface_ready: Callable[[str], bool] = lambda surface: surface == "enceladus"
    withdraw: Callable[[str, str, str], bool] = lambda project, esc_id, reason: False


# ----------------------------------------------------------------------------- helpers

def run_key(run_id: str) -> str:
    return RUN_PREFIX + run_id


def idem_item_key(key: str) -> str:
    return IDEM_PREFIX + hashlib.sha256(key.encode("utf-8")).hexdigest()[:48]


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_ts(value: Any) -> datetime:
    return datetime.strptime(str(value)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def _plus(now: str, seconds: int) -> str:
    return (_parse_ts(now) + timedelta(seconds=int(seconds))).strftime("%Y-%m-%dT%H:%M:%SZ")


def _past(ts: Any, now: str) -> bool:
    return bool(ts) and _parse_ts(ts) <= _parse_ts(now)


def _is_action(step: Dict[str, Any]) -> bool:
    return step.get("type", "action") == "action"


class Unresolved(Exception):
    def __init__(self, pointer: str):
        super().__init__(pointer)
        self.pointer = pointer


def _walk(value: Any, segs: List[str]) -> Any:
    cur = value
    for seg in segs:
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            raise KeyError(seg)
    return cur


def _placeholder(pointer: str) -> Dict[str, Any]:
    last = pointer.replace("/", ".").rstrip(".").split(".")[-1]
    typ = "string" if (last == "id" or last.endswith("_id") or last.endswith("Id")) else "unknown"
    return {"$unresolved": pointer, "type": typ}


def resolve(value: Any, scope: Dict[str, Any], pending: Tuple[str, ...] = (), lenient: bool = False) -> Any:
    """Resolve whole-value bindings ($root.a.b). Roots in `pending` become {"$ref": root, "path": [...]}
    for the executor to resolve inside the segment; lenient (dry_run_all) yields typed placeholders."""
    if isinstance(value, str):
        if not value.startswith("$"):
            return value
        if value.startswith("$$"):
            return value[1:]
        parsed = rs.parse_binding(value)
        if parsed:
            root, segs = parsed
            if root in pending:
                return {"$ref": root, "path": list(segs)}
            if root in scope:
                try:
                    return _walk(scope[root], segs)
                except (KeyError, TypeError):
                    pass
        if lenient:
            return _placeholder(value)
        raise Unresolved(value)
    if isinstance(value, dict):
        if set(value) == {"$literal"}:
            return value["$literal"]
        return {k: resolve(v, scope, pending, lenient) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, scope, pending, lenient) for v in value]
    return value


def resolve_refs(value: Any, results: Dict[str, Any]) -> Any:
    """Executor side: replace {"$ref","path"} markers with the earlier in-segment step result."""
    if isinstance(value, dict):
        if set(value) == {"$ref", "path"}:
            return _walk(results[value["$ref"]], value["path"])
        return {k: resolve_refs(v, results) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_refs(v, results) for v in value]
    return value


def receipt_of(result: Any) -> Dict[str, Any]:
    """x-io-minted ids found at the top of a step result (the step receipt)."""
    if not isinstance(result, dict):
        return {}
    return {k: v for k, v in result.items() if k.endswith("_id") and isinstance(v, str) and v}


def run_batch_locally(batch: Dict[str, Any], call_one: Callable[[Dict[str, Any], bool], Dict[str, Any]]) -> Dict[str, Any]:
    """Reference executor: run a segment's calls in order, resolving in-segment $ref markers.
    call_one(call, dry_run) -> {"ok", "result", "error", "receipt"}. Stops at the first error unless
    batch["continue_on_error"] (compensation)."""
    results: Dict[str, Any] = {}
    out: List[Dict[str, Any]] = []
    for call in batch.get("calls", []):
        try:
            args = resolve_refs(call.get("arguments", {}), results)
        except (KeyError, TypeError) as exc:
            out.append({"step_id": call["step_id"], "ok": False, "error": {"code": "BINDING_FAILED", "message": f"unresolved in-segment binding: {exc}"}})
            if batch.get("continue_on_error") or call.get("on_error") == "continue":
                continue
            break
        res = call_one(dict(call, arguments=args), bool(call.get("dry_run") or batch.get("dry_run")))
        res = dict(res, step_id=call["step_id"])
        out.append(res)
        if res.get("ok"):
            results[call["step_id"]] = res.get("result")
        elif not (batch.get("continue_on_error") or call.get("on_error") == "continue"):
            break
    return {"results": out}


# ----------------------------------------------------------------------------- JSON Schema subset

def _type_ok(value: Any, typ: str) -> bool:
    return {"string": isinstance(value, str), "boolean": isinstance(value, bool), "object": isinstance(value, dict),
            "array": isinstance(value, list), "null": value is None,
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool)}.get(typ, True)


def validate_schema(value: Any, schema: Any, path: str = "") -> List[str]:
    """Small JSON Schema subset (type, enum, const, required, properties, additionalProperties:false,
    items, min/max length, min/max, pattern, min/max items). Returns a list of problems."""
    if not isinstance(schema, dict):
        return []
    here = path or "/"
    typ = schema.get("type")
    if typ is not None:
        types = typ if isinstance(typ, list) else [typ]
        if not any(_type_ok(value, t) for t in types):
            return [f"{here}: expected type {types}"]
    errs: List[str] = []
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{here}: must be one of {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        errs.append(f"{here}: must equal {schema['const']!r}")
    if isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errs.append(f"{here}: shorter than {schema['minLength']}")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errs.append(f"{here}: longer than {schema['maxLength']}")
        if isinstance(schema.get("pattern"), str) and not re.search(schema["pattern"], value):
            errs.append(f"{here}: does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            errs.append(f"{here}: below minimum {schema['minimum']}")
        if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
            errs.append(f"{here}: above maximum {schema['maximum']}")
    if isinstance(value, dict):
        for name in schema.get("required") or []:
            if name not in value:
                errs.append(f"{path}/{name}: required")
        props = schema.get("properties") or {}
        for name, sub in props.items():
            if name in value:
                errs.extend(validate_schema(value[name], sub, f"{path}/{name}"))
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in props:
                    errs.append(f"{path}/{name}: unknown property")
    if isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            errs.append(f"{here}: fewer than {schema['minItems']} items")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            errs.append(f"{here}: more than {schema['maxItems']} items")
        if isinstance(schema.get("items"), dict):
            for idx, entry in enumerate(value):
                errs.extend(validate_schema(entry, schema["items"], f"{path}/{idx}"))
    return errs


# ----------------------------------------------------------------------------- views and persistence

def _has_unresolved(value: Any) -> bool:
    if isinstance(value, dict):
        return "$unresolved" in value or any(_has_unresolved(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_unresolved(v) for v in value)
    return False


def view(run: Dict[str, Any], token: Optional[str] = None) -> Dict[str, Any]:
    """The one-read answer to 'was it completed'."""
    steps = run.get("steps") or []
    done = sum(1 for s in steps if s.get("status") in ("ok", "skipped"))
    gate = run.get("gate")
    out = {
        "run_id": run.get("run_id"), "project_id": run.get("project_id"), "recipe_ref": run.get("recipe_ref"),
        "status": run.get("status"), "complete": run.get("status") == "completed",
        "terminal": run.get("status") in TERMINAL, "progress": f"{done}/{len(steps)}",
        "cursor": run.get("cursor"), "inputs": run.get("inputs"),
        "steps": [{k: s.get(k) for k in ("id", "type", "status", "resolved_call", "result", "error", "receipt", "fixture")
                   if s.get(k) is not None or k in ("id", "status")} for s in steps],
        "gate": ({k: v for k, v in gate.items() if k != "token_hash"} if isinstance(gate, dict) else None),
        "gate_history": run.get("gate_history") or [], "outputs": run.get("outputs"), "error": run.get("error"),
        "compensation": run.get("compensation") or "none", "compensations": run.get("compensations") or [],
        "blocked": run.get("blocked"), "fixture_mode": bool(run.get("fixture_mode")),
        "started_by": run.get("started_by"), "idempotency_key": run.get("idempotency_key"),
        "governance_hash_start": run.get("governance_hash_start"), "governance_hash_last": run.get("governance_hash_last"),
        "telemetry": run.get("telemetry"), "expires_at": run.get("expires_at"), "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"), "completed_at": run.get("completed_at"), "rev": run.get("rev"),
    }
    if token:
        out["resume_token"] = token
        out["resume_token_note"] = "Shown once; single-use; needs the hub decision before it advances the run."
    return out


def _save(ctx: RunContext, project_id: str, run: Dict[str, Any]) -> bool:
    """Conditional write on rev (idempotent advance): False when another writer got there first."""
    expect = int(run.get("rev") or 0)
    new = dict(run, rev=expect + 1, updated_at=ctx.now())
    if not ctx.put(project_id, new, expect=("rev", expect)):
        return False
    run["rev"], run["updated_at"] = new["rev"], new["updated_at"]
    return True


def _conflict(run_id: str) -> Result:
    return _err(409, "CONFLICT", f"{run_id} changed concurrently; re-read it with recipe_run.get and retry.")


def _load(ctx: RunContext, project_id: str, run_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Result]]:
    if not RUN_ID_RE.match(run_id or ""):
        return None, _err(400, "VALIDATION_FAILED", "run_id is malformed.")
    run = ctx.get(project_id, run_key(run_id))
    if not run:
        return None, _err(404, "NOT_FOUND", f"Run not found: {run_id}")
    run["cursor"] = int(run.get("cursor") or 0)
    run["rev"] = int(run.get("rev") or 0)
    run.setdefault("telemetry", {"steps_total": len(run.get("steps") or []), "gates_opened": 0, "writes": 0, "agent_calls": 0})
    return run, None


def _load_def(ctx: RunContext, project_id: str, run: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Result]]:
    ref = run.get("recipe_ref") or {}
    item = ctx.get(project_id, rs.version_key(ref.get("recipe_id", ""), ref.get("version", "")))
    if not item:
        return None, _err(404, "NOT_FOUND", f"Pinned recipe version not found: {ref.get('recipe_id')}@{ref.get('version')}")
    if item.get("content_hash") != ref.get("content_hash") or not rs._hash_ok(item):
        return None, _err(409, "PIN_MISMATCH", "The pinned recipe version no longer matches its content_hash; the run is blocked.")
    return item["definition"], None


def _scope(run: Dict[str, Any]) -> Dict[str, Any]:
    scope: Dict[str, Any] = {"inputs": run.get("inputs") or {},
                             "run": {"run_id": run.get("run_id"), "started_by": run.get("started_by"), "project_id": run.get("project_id")}}
    for rec in run.get("steps") or []:
        if rec.get("status") == "ok":
            scope[rec["id"]] = rec.get("result")
    return scope


# ----------------------------------------------------------------------------- dry_run_all

def plan(definition: Dict[str, Any], inputs: Dict[str, Any], meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    scope = {"inputs": inputs, "run": meta}
    planned: List[Dict[str, Any]] = []
    for step in definition.get("steps") or []:
        if not _is_action(step):
            gate = step.get("gate") or {}
            planned.append({"id": step.get("id"), "type": "gate", "status": "gate", "prompt": gate.get("prompt"),
                            "kind": gate.get("escalation_kind", "acceptance"), "sensitive": bool(gate.get("sensitive")),
                            "inputs_schema": gate.get("inputs"), "timeout": gate.get("timeout")})
            continue
        args = resolve(step.get("arguments", {}), scope, lenient=True)
        planned.append({"id": step.get("id"), "type": "action", "surface": step.get("surface") or "enceladus",
                        "action": step.get("action"), "arguments": args, "dry_run": True,
                        "status": "planned (unresolved)" if _has_unresolved(args) else "planned"})
    return planned


# ----------------------------------------------------------------------------- the runner

def _close_gate(run: Dict[str, Any], verdict: str, decider: str, now: str) -> None:
    gate = run.get("gate")
    if isinstance(gate, dict):
        run["consumed_tokens"] = list(run.get("consumed_tokens") or []) + ([gate["token_hash"]] if gate.get("token_hash") else [])
        run["gate_history"] = list(run.get("gate_history") or []) + [
            {"step_id": gate.get("step_id"), "escalation_id": gate.get("escalation_id"), "attempt": gate.get("attempt"),
             "opened_at": gate.get("opened_at"), "verdict": verdict, "decided_by": decider or None, "closed_at": now}]
    run["gate"] = None


def _block_drift(ctx: RunContext, project_id: str, run: Dict[str, Any], expected: str, actual: str) -> Result:
    msg = "governance_hash changed since the previous segment; resume is blocked until a human accepts the drift."
    run["blocked"] = {"code": "GOVERNANCE_DRIFT", "message": msg, "expected": expected, "actual": actual, "at": ctx.now()}
    _save(ctx, project_id, run)
    return _err(409, "GOVERNANCE_DRIFT", msg, expected=expected, actual=actual, diff={"governance_hash": {"was": expected, "now": actual}})


def _compensate(ctx: RunContext, project_id: str, run: Dict[str, Any], steps: List[Dict[str, Any]]) -> None:
    """Declared compensate steps only, in reverse order, for steps that actually wrote."""
    scope = _scope(run)
    calls: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []
    for i in range(len(run["steps"]) - 1, -1, -1):
        rec, step = run["steps"][i], steps[i]
        comp = step.get("compensate")
        if rec.get("status") != "ok" or not comp or rec.get("fixture"):
            continue
        try:
            args = resolve(comp.get("arguments", {}), scope)
        except Unresolved as exc:
            failed.append({"step_id": rec["id"], "ok": False, "error": {"code": "BINDING_FAILED", "message": exc.pointer}})
            continue
        calls.append({"step_id": rec["id"], "surface": comp.get("surface") or step.get("surface") or "enceladus",
                      "action": comp.get("action"), "arguments": args, "dry_run": False,
                      "idempotency_key": f"{run['run_id']}:{rec['id']}:compensate"})
    if not calls and not failed:
        run["compensation"] = "none"
        return
    results: List[Dict[str, Any]] = list(failed)
    if calls:
        try:
            resp = ctx.execute({"run_id": run["run_id"], "project_id": project_id, "calls": calls, "dry_run": False,
                                "continue_on_error": True, "compensation": True, "principal": SOURCE_PRINCIPAL}) or {}
            results.extend(resp.get("results") or [])
        except Exception as exc:  # noqa: BLE001
            results.extend({"step_id": c["step_id"], "ok": False, "error": {"code": "EXECUTE_FAILED", "message": str(exc)[:300]}} for c in calls)
    run["compensations"] = [{"step_id": r.get("step_id"), "ok": bool(r.get("ok")), "error": r.get("error"), "receipt": r.get("receipt")} for r in results]
    run["compensation"] = "done" if results and all(r.get("ok") for r in results) and len(results) >= len(calls) else "partial"


def _terminate(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any], status: str,
               code: str, message: str, step_id: Optional[str], compensate: bool = True) -> Optional[Result]:
    if compensate:
        _compensate(ctx, project_id, run, definition["steps"])
    for rec in run["steps"]:
        if rec.get("status") in ("pending", "awaiting"):
            rec["status"] = "skipped"
    run.update(status=status, error={"code": code, "message": message[:500], "step_id": step_id}, completed_at=ctx.now())
    return None if _save(ctx, project_id, run) else _conflict(run["run_id"])


def _file_escalation(ctx: RunContext, project_id: str, run: Dict[str, Any], step: Dict[str, Any]) -> Tuple[Optional[str], Optional[Result]]:
    gate, g, rid, sid = run["gate"], step["gate"], run["run_id"], step["id"]
    call = {"capability": "recipe_run.resume", "mcpTool": "recipe_run_resume", "method": "POST",
            "path": f"/api/v1/tracker/{project_id}/recipe-run/{rid}/apply",
            "args": {"step_id": sid, "gate_attempt": gate["attempt"]},
            "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
            "ifMatch": (run.get("recipe_ref") or {}).get("content_hash")}
    call["callHash"] = hashlib.sha256(rs.canonical(call).encode("utf-8")).hexdigest()
    ref = run.get("recipe_ref") or {}
    request: Dict[str, Any] = {
        "source_principal": SOURCE_PRINCIPAL, "kind": g.get("escalation_kind") or "acceptance",
        "title": f"Recipe run {rid}: gate {sid} ({ref.get('recipe_id')}@{ref.get('version')})",
        "justification": g.get("prompt"), "summary": g.get("prompt"),
        "subject": {"type": "recipe_run_step", "record_id": rid, "step_id": sid,
                    "recipe_id": ref.get("recipe_id"), "version": ref.get("version")},
        "inputs_schema": g.get("inputs"), "expiresAt": gate["expires_at"],
        "idempotency_key": f"{rid}:{sid}:{gate['attempt']}", "proposedCalls": [call]}
    if g.get("sensitive"):
        request["distinct_from"] = [run.get("started_by")]
    code, resp = ctx.escalate(project_id, request)
    esc_id = (resp or {}).get("escalation_id")
    if code >= 300 or not esc_id:
        return None, _err(502, "GATE_FAILED", f"The hub refused the gate ({code}): {(resp or {}).get('error', 'no escalation id')}. "
                          "The run stays awaiting_gate; recipe_run.resume re-files it with the same idempotency key.")
    return esc_id, None


def _open_gate(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any], ctl: Dict[str, Any]) -> Optional[Result]:
    step = definition["steps"][run["cursor"]]
    g = step["gate"]
    now = ctx.now()
    seconds = int((g.get("timeout") or {}).get("seconds") or DEFAULT_GATE_SECONDS)
    token = "rrt_" + secrets.token_urlsafe(24)
    attempt = int(run.get("gate_attempt") or 0) + 1
    run.update(status="awaiting_gate", gate_attempt=attempt, gate={
        "step_id": step["id"], "escalation_id": None, "opened_at": now, "expires_at": _plus(now, seconds),
        "attempt": attempt, "token_hash": token_hash(token), "sensitive": bool(g.get("sensitive")),
        "kind": g.get("escalation_kind") or "acceptance"})
    run["steps"][run["cursor"]]["status"] = "awaiting"
    run["telemetry"]["gates_opened"] = int(run["telemetry"].get("gates_opened") or 0) + 1
    if not _save(ctx, project_id, run):                       # 1. conditional write -> awaiting_gate
        return _conflict(run["run_id"])
    esc_id, err = _file_escalation(ctx, project_id, run, step)  # 2. hub producer call
    if err:
        err[1]["resume_token"] = token                            # lets the starter re-file the gate via recipe_run.resume
        return err
    run["gate"]["escalation_id"] = esc_id                     # 3. store gate.escalation_id
    if not _save(ctx, project_id, run):
        return _conflict(run["run_id"])
    ctl["token"] = token
    return None


def _complete(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any]) -> Optional[Result]:
    outs = definition.get("outputs")
    value = None
    if isinstance(outs, dict):
        if "from" in outs:
            try:
                value = resolve(outs["from"], _scope(run))
            except Unresolved as exc:
                return _terminate(ctx, project_id, run, definition, "failed", "STEP_ERROR", f"outputs binding {exc.pointer} did not resolve", None)
        problems = validate_schema(value, outs.get("schema")) if outs.get("schema") else []
        if problems:
            return _terminate(ctx, project_id, run, definition, "failed", "STEP_ERROR", "outputs do not match outputs.schema: " + "; ".join(problems[:5]), None)
    run.update(status="completed", outputs=value, completed_at=ctx.now())
    return None if _save(ctx, project_id, run) else _conflict(run["run_id"])


def _segment(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any],
             start: int, end: int, ctl: Dict[str, Any]) -> Optional[Result]:
    steps = definition["steps"]
    gh = ctl.get("governance_hash") or ctx.governance_hash()       # re-fetched at every segment start
    last = run.get("governance_hash_last")
    if gh and last and gh != last and not ctl.get("accept_drift"):
        return _block_drift(ctx, project_id, run, last, gh)
    if gh:
        run["governance_hash_last"] = gh
    at_most = [steps[i]["id"] for i in range(start, end) if steps[i].get("idempotency") == "at_most_once"]
    if int(run.get("segment_started", -1)) == start and at_most:
        return _terminate(ctx, project_id, run, definition, "failed", "STEP_ERROR",
                          f"the segment at step {start} was already claimed and at_most_once step(s) {at_most} are never auto-retried.", at_most[0])
    run.update(segment_started=start, status="running", blocked=None)
    if not _save(ctx, project_id, run):                              # claim (queued -> running)
        return _conflict(run["run_id"])
    scope, pending, calls = _scope(run), [], []
    for i in range(start, end):
        step = steps[i]
        try:
            args = resolve(step.get("arguments", {}), scope, tuple(pending))
        except Unresolved as exc:
            return _terminate(ctx, project_id, run, definition, "failed", "STEP_ERROR", f"binding {exc.pointer} could not be resolved", step["id"])
        surface = step.get("surface") or "enceladus"
        fixture = not ctx.surface_ready(surface)
        if fixture:
            run["fixture_mode"] = True
        calls.append({"step_id": step["id"], "surface": surface, "action": step.get("action"), "arguments": args,
                      "dry_run": fixture, "idempotency_key": f"{run['run_id']}:{step['id']}",
                      "idempotency": step.get("idempotency", "at_least_once"), "on_error": step.get("on_error", "abort")})
        pending.append(step["id"])
    batch = {"run_id": run["run_id"], "project_id": project_id, "segment": [start, end], "governance_hash": gh or last,
             "dry_run": False, "principal": SOURCE_PRINCIPAL, "calls": calls}
    try:
        resp = ctx.execute(batch) or {}                              # ONE execute call per segment
    except Exception as exc:  # noqa: BLE001
        resp = {"results": [{"step_id": calls[0]["step_id"], "ok": False, "error": {"code": "EXECUTE_FAILED", "message": str(exc)[:300]}}]}
    results = resp.get("results") or []
    failure: Optional[Tuple[str, Dict[str, Any]]] = None
    for idx, call in enumerate(calls):
        rec, step = run["steps"][start + idx], steps[start + idx]
        if failure is not None:
            rec["status"] = "skipped"
            continue
        r = results[idx] if idx < len(results) and isinstance(results[idx], dict) else \
            {"ok": False, "error": {"code": "NO_RESULT", "message": "execute returned no result for this step"}}
        rec["resolved_call"] = {k: call[k] for k in ("surface", "action", "arguments", "dry_run")}
        if r.get("ok"):
            rec.update(status="ok", result=r.get("result"), receipt=r.get("receipt") or receipt_of(r.get("result")),
                       fixture=bool(call["dry_run"]), error=None)
            if not call["dry_run"]:
                run["telemetry"]["writes"] = int(run["telemetry"].get("writes") or 0) + 1
        else:
            error = r.get("error") if isinstance(r.get("error"), dict) else {"code": "STEP_ERROR", "message": str(r.get("error") or "step failed")}
            rec["error"] = {"code": str(error.get("code") or "STEP_ERROR"), "message": str(error.get("message") or "step failed")[:500]}
            if step.get("on_error") == "continue":
                rec["status"] = "skipped"
            else:
                rec["status"] = "error"
                failure = (step["id"], rec["error"])
    if failure:
        return _terminate(ctx, project_id, run, definition, "failed", "STEP_ERROR", f"{failure[0]}: {failure[1]['message']}", failure[0])
    run["cursor"] = end
    return None if _save(ctx, project_id, run) else _conflict(run["run_id"])   # cursor advance, conditional


def _drive(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any], ctl: Dict[str, Any]) -> Optional[Result]:
    steps = definition["steps"]
    while run["status"] not in TERMINAL:
        cur = run["cursor"]
        if cur >= len(steps):
            return _complete(ctx, project_id, run, definition)
        if not _is_action(steps[cur]):
            return _open_gate(ctx, project_id, run, definition, ctl)
        end = cur
        while end < len(steps) and _is_action(steps[end]):
            end += 1
        err = _segment(ctx, project_id, run, definition, cur, end, ctl)
        if err is not None:
            return err
    return None


def _finish(run: Dict[str, Any], ctl: Dict[str, Any], res: Optional[Result], status: int = 200, **extra: Any) -> Result:
    if res is not None:
        return res
    body = view(run, ctl.get("token"))
    body.update(extra)
    return _ok(body, 202 if status == 200 and run.get("status") == "awaiting_gate" else status)


# ----------------------------------------------------------------------------- start / get / list

def start(ctx: RunContext, project_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    rec = str(body.get("recipe_id") or "").strip()
    if not rs.REC_ID_RE.match(rec):
        return _err(400, "VALIDATION_FAILED", "recipe_id (for example DVP-REC-001) is required.")
    mode = str(body.get("mode") or "to_next_gate")
    if mode not in MODES:
        return _err(400, "VALIDATION_FAILED", f"mode must be one of {list(MODES)}.")
    plan_only = bool(dry_run) or mode == "dry_run"
    inputs = body.get("inputs") if body.get("inputs") is not None else {}
    if not isinstance(inputs, dict):
        return _err(400, "VALIDATION_FAILED", "inputs must be an object.")
    key = str(body.get("idempotency_key") or "").strip()
    gh = str(body.get("governance_hash") or "").strip() or (ctx.governance_hash() or "")
    if not plan_only:
        if not key:
            return _err(400, "VALIDATION_FAILED", "idempotency_key is required to start a run.")
        if not gh:
            return _err(400, "VALIDATION_FAILED", "governance_hash is required to start a run.")
    head = ctx.get(project_id, rs.head_key(rec))
    if not head:
        return _err(404, "NOT_FOUND", f"Recipe not found: {rec}")
    version = str(body.get("version") or head.get("latest_published") or "").strip()
    if not version:
        return _err(409, "NOT_PUBLISHED", f"{rec} has no published version; only published versions can run.")
    item = ctx.get(project_id, rs.version_key(rec, version))
    if not item:
        return _err(404, "NOT_FOUND", f"Recipe version not found: {rec}@{version}")
    if item.get("status") != "published" and not (item.get("status") == "deprecated" and body.get("allow_deprecated") is True):
        return _err(409, "NOT_PUBLISHED", f"{rec}@{version} is {item.get('status')}; only published versions run (deprecated needs allow_deprecated).")
    if not rs._hash_ok(item):
        return _err(409, "PIN_MISMATCH", f"{rec}@{version} does not match its content_hash.")
    if body.get("content_hash") and body["content_hash"] != item["content_hash"]:
        return _err(409, "PIN_MISMATCH", "The supplied content_hash does not match the published version.")
    served = head.get("project_ids") or item.get("project_ids") or []
    if served and project_id not in served:
        return _err(422, "PROJECT_NOT_SERVED", f"{project_id} is not in the recipe project_ids {served}.")
    definition = item["definition"]
    problems = validate_schema(inputs, definition.get("inputs") or {})
    if problems:
        return _err(422, "INPUTS_INVALID", "inputs do not match the recipe inputs schema.", errors=problems[:20])
    ref = {"recipe_id": rec, "version": version, "content_hash": item["content_hash"]}
    if plan_only:                                    # dry_run_all: nothing is minted, stored, filed or executed
        planned = plan(definition, inputs, {"project_id": project_id, "started_by": actor})
        fixture = any(_is_action(s) and not ctx.surface_ready(s.get("surface") or "enceladus") for s in definition.get("steps") or [])
        return _ok({"mode": "dry_run", "dry_run": True, "run_id": None, "recipe_ref": ref, "planned": planned,
                    "fixture_mode": fixture, "unresolved": any(p.get("status") == "planned (unresolved)" for p in planned),
                    "writes": 0})
    inputs_hash = hashlib.sha256(rs.canonical(inputs).encode("utf-8")).hexdigest()
    marker_key = idem_item_key(key)
    marker = ctx.get(project_id, marker_key)
    if marker is None:
        marker = {"record_id": marker_key, "record_kind": "run_idem", "run_id": ctx.mint(project_id),
                  "inputs_hash": inputs_hash, "recipe_id": rec, "version": version, "created_at": ctx.now()}
        if not ctx.put(project_id, marker, if_absent=True):
            marker = ctx.get(project_id, marker_key) or marker
    if marker.get("inputs_hash") != inputs_hash or marker.get("recipe_id") != rec:
        return _err(409, "IDEMPOTENCY_CONFLICT", "That idempotency_key was already used with different inputs or a different recipe.")
    run_id = marker["run_id"]
    existing = ctx.get(project_id, run_key(run_id))
    if existing:
        return _ok(dict(view(existing), idempotent=True))
    now = ctx.now()
    steps = definition.get("steps") or []
    run: Dict[str, Any] = {
        "record_id": run_key(run_id), "record_kind": "run", "run_id": run_id, "project_id": project_id, "recipe_ref": ref,
        "inputs": inputs, "status": "queued", "cursor": 0, "started_by": actor, "idempotency_key": key,
        "steps": [{"id": s.get("id"), "type": s.get("type", "action"), "status": "pending", "resolved_call": None,
                   "result": None, "error": None, "receipt": None} for s in steps],
        "gate": None, "outputs": None, "error": None, "compensation": "none", "fixture_mode": False,
        "governance_hash_start": gh, "governance_hash_last": gh, "created_at": now, "updated_at": now,
        "expires_at": _plus(now, DEFAULT_TTL_SECONDS), "rev": 0,
        "telemetry": {"steps_total": len(steps), "gates_opened": 0, "writes": 0, "agent_calls": 0}}
    if not ctx.put(project_id, run, if_absent=True):
        existing = ctx.get(project_id, run_key(run_id))
        return _ok(dict(view(existing), idempotent=True)) if existing else _conflict(run_id)
    ctl = {"governance_hash": gh}
    return _finish(run, ctl, _drive(ctx, project_id, run, definition, ctl), 201)


def get(ctx: RunContext, project_id: str, run_id: str) -> Result:
    run, err = _load(ctx, project_id, run_id)
    return err if err else _ok(view(run))


def list_runs(ctx: RunContext, project_id: str, query: Dict[str, Any]) -> Result:
    items = [r for r in ctx.query(project_id, RUN_PREFIX) if r.get("record_kind", "run") == "run"]
    for field, key in (("status", "status"), ("recipe_id", "recipe_id")):
        want = str((query or {}).get(field) or "").strip()
        if want:
            items = [r for r in items if (r.get(key) if key == "status" else (r.get("recipe_ref") or {}).get(key)) == want]
    items.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    try:
        limit = max(1, min(int((query or {}).get("limit") or 50), MAX_LIST))
    except (TypeError, ValueError):
        limit = 50
    out = [{k: v for k, v in view(r).items() if k in ("run_id", "recipe_ref", "status", "complete", "progress", "gate", "error",
                                                       "started_by", "fixture_mode", "created_at", "updated_at", "completed_at")}
           for r in items[:limit]]
    return _ok({"items": out, "count": len(out), "total": len(items)})


# ----------------------------------------------------------------------------- gate decisions

def _esc_verdict(esc: Optional[Dict[str, Any]]) -> Optional[str]:
    if not esc:
        return None
    status = str(esc.get("status") or "").lower()
    if status in DENIED:
        return "reject"
    if status in EXPIRED:
        return "expire"
    if status in APPROVED:
        decision = esc.get("decision") if isinstance(esc.get("decision"), dict) else {}
        return "reject" if str(decision.get("verdict") or "").lower() in REJECT_WORDS else "approve"
    return None


def _esc_decider(esc: Dict[str, Any]) -> str:
    who = esc.get("approved_by") or esc.get("decided_by") or ""
    if isinstance(who, str) and who.startswith("{"):
        try:
            who = json.loads(who)
        except ValueError:
            pass
    if isinstance(who, dict):
        return str(who.get("email") or who.get("sub") or "")
    return str(who)


def _decide(ctx: RunContext, project_id: str, run: Dict[str, Any], definition: Dict[str, Any], verdict: str,
            inputs: Dict[str, Any], decider: str, ctl: Dict[str, Any], dry_run: bool = False) -> Optional[Result]:
    cur = run["cursor"]
    step, rec = definition["steps"][cur], run["steps"][cur]
    g, now = step["gate"], ctx.now()
    if verdict == "approve":
        if g.get("sensitive") and decider and decider == run.get("started_by"):
            return _err(403, "SELF_REVIEW", "A sensitive gate cannot be approved by the principal that started the run.")
        problems = validate_schema(inputs, g.get("inputs") or {})            # validated BEFORE any state change
        if problems:
            return _err(422, "INPUTS_INVALID", "gate inputs do not match the gate inputs schema.", errors=problems[:20])
        gh = ctl.get("governance_hash") or ctx.governance_hash()
        last = run.get("governance_hash_last")
        if gh and last and gh != last and not ctl.get("accept_drift"):
            if dry_run:
                return _err(409, "GOVERNANCE_DRIFT", "governance_hash changed; resume would be blocked.", expected=last, actual=gh)
            return _block_drift(ctx, project_id, run, last, gh)
        if dry_run:
            return _ok({"run_id": run["run_id"], "dry_run": True, "writes": 0, "executed": 0,
                        "would_do": {"consume_token": True, "bind": [f"${step['id']}.inputs", f"${step['id']}.decision"], "continue_from": cur + 1}})
        _close_gate(run, "approve", decider, now)
        rec.update(status="ok", result={"inputs": inputs, "decision": "approve"}, error=None)
        run.update(cursor=cur + 1, status="running", blocked=None, governance_hash_last=gh or last)
        if not _save(ctx, project_id, run):
            return _conflict(run["run_id"])
        return _drive(ctx, project_id, run, definition, ctl)
    # reject / expire never execute anything but declared compensation
    if verdict == "reject":
        route, code, label = g.get("on_reject", "failed"), "GATE_REJECTED", "rejected in the hub"
    else:
        route, code, label = g.get("on_expire", "expired"), "GATE_EXPIRED", "expired in the hub (fail-closed)"
    if dry_run:
        return _ok({"run_id": run["run_id"], "dry_run": True, "writes": 0, "executed": 0, "would_do": {"run_status": route, "code": code}})
    _close_gate(run, verdict, decider, now)
    rec.update(status="error", error={"code": code, "message": f"gate {step['id']} {label}"})
    message = f"gate {step['id']} {label}"
    if route == "cancelled":
        return _terminate(ctx, project_id, run, definition, "cancelled", "CANCELLED", message, step["id"], compensate=False)
    return _terminate(ctx, project_id, run, definition, route, code, message, step["id"], compensate=route == "failed")


def resume(ctx: RunContext, project_id: str, run_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    token = str(body.get("resume_token") or "").strip()
    if not token:
        return _err(400, "VALIDATION_FAILED", "resume_token is required.")
    run, err = _load(ctx, project_id, run_id)
    if err:
        return err
    th = token_hash(token)
    if th in (run.get("consumed_tokens") or []):               # replay: nothing is executed, nothing is written
        return _ok(dict(view(run), replayed=True, executed=0, writes=0))
    if run["status"] in TERMINAL:
        return _err(409, "RUN_TERMINAL", f"{run_id} is {run['status']}; nothing to resume.")
    gate = run.get("gate")
    if run["status"] != "awaiting_gate" or not isinstance(gate, dict):
        return _err(409, "NOT_AWAITING_GATE", f"{run_id} is {run['status']}, not awaiting a gate.")
    if th != gate.get("token_hash"):
        return _err(403, "INVALID_RESUME_TOKEN", "resume_token does not match the open gate.")
    definition, derr = _load_def(ctx, project_id, run)
    if derr:
        return derr
    ctl = {"governance_hash": str(body.get("governance_hash") or "").strip() or None,
           "accept_drift": body.get("accept_governance_drift") is True}
    if not gate.get("escalation_id"):                          # the hub call failed earlier: re-file, same idempotency key
        if dry_run:
            return _ok({"run_id": run_id, "dry_run": True, "writes": 0, "would_do": {"refile_gate_escalation": gate.get("step_id")}})
        esc_id, ferr = _file_escalation(ctx, project_id, run, definition["steps"][run["cursor"]])
        if ferr:
            return ferr
        gate["escalation_id"] = esc_id
        return _conflict(run_id) if not _save(ctx, project_id, run) else _ok(dict(view(run), refiled=True), 202)
    esc = ctx.escalation(project_id, gate["escalation_id"])
    verdict = _esc_verdict(esc)
    if verdict is None:
        return _err(409, "GATE_PENDING", f"Escalation {gate['escalation_id']} has no decision yet; nothing was consumed.",
                    escalation_id=gate["escalation_id"], expires_at=gate.get("expires_at"))
    decision = esc.get("decision") if isinstance(esc.get("decision"), dict) else {}
    inputs = body.get("inputs") if isinstance(body.get("inputs"), dict) else decision.get("inputs")
    inputs = inputs if isinstance(inputs, dict) else {}
    decider = str(body.get("decider") or _esc_decider(esc))
    return _finish(run, ctl, _decide(ctx, project_id, run, definition, verdict, inputs, decider, ctl, dry_run))


def apply_gate(ctx: RunContext, project_id: str, run_id: str, body: Dict[str, Any], actor: str) -> Result:
    """Hub applier hook for subject recipe_run_step: runs ONLY from an approved escalation that names this
    run, gate step and the escalation bound to the open gate. Replays are idempotent no-ops."""
    esc_id = str(body.get("escalation_id") or "").strip()
    if not esc_id:
        return _err(400, "VALIDATION_FAILED", "escalation_id is required.")
    run, err = _load(ctx, project_id, run_id)
    if err:
        return err
    if any(h.get("escalation_id") == esc_id for h in run.get("gate_history") or []):
        return _ok(dict(view(run), idempotent=True, replayed=True, executed=0))
    gate = run.get("gate")
    if run["status"] != "awaiting_gate" or not isinstance(gate, dict):
        return _err(409, "NOT_AWAITING_GATE", f"{run_id} is {run['status']}; nothing is applied.")
    if gate.get("escalation_id") != esc_id:
        return _err(403, "NOT_AUTHORIZED", f"{esc_id} is not the escalation bound to the open gate of {run_id}.")
    esc = ctx.escalation(project_id, esc_id)
    if not esc:
        return _err(404, "NOT_FOUND", f"Escalation not found: {esc_id}")
    subject = esc.get("subject") if isinstance(esc.get("subject"), dict) else {}
    if subject.get("type") != "recipe_run_step" or subject.get("record_id") != run_id or subject.get("step_id") != gate.get("step_id"):
        return _err(403, "NOT_AUTHORIZED", "The escalation does not name this run and gate step.")
    if str(esc.get("sourcePrincipal") or esc.get("source_principal") or "") != SOURCE_PRINCIPAL:
        return _err(403, "NOT_AUTHORIZED", "The escalation was not filed by the recipe runner.")
    verdict = _esc_verdict(esc)
    if verdict is None:
        return _err(409, "NOT_AUTHORIZED", f"Escalation {esc_id} is {esc.get('status')!r}, not decided; nothing is applied.")
    definition, derr = _load_def(ctx, project_id, run)
    if derr:
        return derr
    decision = esc.get("decision") if isinstance(esc.get("decision"), dict) else {}
    inputs = body.get("inputs") if isinstance(body.get("inputs"), dict) else decision.get("inputs")
    inputs = inputs if isinstance(inputs, dict) else {}
    decider = str(body.get("decider") or _esc_decider(esc))
    ctl = {"governance_hash": str(body.get("governance_hash") or "").strip() or None, "accept_drift": False}
    return _finish(run, ctl, _decide(ctx, project_id, run, definition, verdict, inputs, decider, ctl))


# ----------------------------------------------------------------------------- cancel / sweep

def cancel(ctx: RunContext, project_id: str, run_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    run, err = _load(ctx, project_id, run_id)
    if err:
        return err
    if run["status"] == "cancelled":
        return _ok(dict(view(run), idempotent=True))
    if run["status"] in TERMINAL:
        return _err(409, "RUN_TERMINAL", f"{run_id} is {run['status']}; cannot cancel.")
    head = ctx.get(project_id, rs.head_key((run.get("recipe_ref") or {}).get("recipe_id", ""))) or {}
    if not (actor and (actor == run.get("started_by") or actor == head.get("owner"))) and not rs._is_io(actor):
        return _err(403, "NOT_AUTHORIZED", "Only the run starter, the recipe owner or io can cancel a run.")
    reason = str(body.get("reason") or "cancelled by request")[:300]
    gate = run.get("gate") if isinstance(run.get("gate"), dict) else None
    if dry_run:
        return _ok({"run_id": run_id, "dry_run": True, "writes": 0, "would_do": {"status": "cancelled", "withdraw_escalation": (gate or {}).get("escalation_id")}})
    now = ctx.now()
    esc_id = (gate or {}).get("escalation_id")
    if gate:
        _close_gate(run, "cancel", actor, now)
    for rec in run["steps"]:
        if rec.get("status") in ("pending", "awaiting"):
            rec["status"] = "skipped"
    run.update(status="cancelled", error={"code": "CANCELLED", "message": reason, "step_id": None}, completed_at=now)
    if not _save(ctx, project_id, run):
        return _conflict(run_id)
    withdrawn = None
    if esc_id:                                       # state first, then the hub, so a lost race never withdraws a live gate
        try:
            withdrawn = bool(ctx.withdraw(project_id, esc_id, reason))
        except Exception:  # noqa: BLE001
            withdrawn = False
    return _ok(dict(view(run), escalation_withdrawn=withdrawn))


def sweep(ctx: RunContext, project_id: str, body: Dict[str, Any], actor: str) -> Result:
    """Runner sweeper: expire stale non-terminal runs and observe decided/expired gates (the fallback to the
    hub event and the recipe_run.resume kick)."""
    now = ctx.now()
    counts = {"expired": 0, "observed": 0, "errors": 0}
    for raw in ctx.query(project_id, RUN_PREFIX):
        if raw.get("record_kind", "run") != "run" or raw.get("status") in TERMINAL:
            continue
        run, err = _load(ctx, project_id, str(raw.get("run_id") or ""))
        if err:
            counts["errors"] += 1
            continue
        definition, derr = _load_def(ctx, project_id, run)
        if derr:
            counts["errors"] += 1
            continue
        gate = run.get("gate") if isinstance(run.get("gate"), dict) else None
        if run["status"] == "awaiting_gate" and gate and gate.get("escalation_id"):
            esc = ctx.escalation(project_id, gate["escalation_id"])
            verdict = _esc_verdict(esc)
            if verdict is None and _past(gate.get("expires_at"), now):
                verdict = "expire"
            if verdict:
                decision = (esc or {}).get("decision") if isinstance((esc or {}).get("decision"), dict) else {}
                inputs = decision.get("inputs") if isinstance(decision.get("inputs"), dict) else {}
                res = _decide(ctx, project_id, run, definition, verdict, inputs, _esc_decider(esc or {}), {"accept_drift": False})
                counts["observed" if res is None else "errors"] += 1
                continue
        if _past(run.get("expires_at"), now):
            if gate:
                _close_gate(run, "expire", actor, now)
            res = _terminate(ctx, project_id, run, definition, "expired", "STEP_ERROR", "run TTL elapsed", None, compensate=False)
            counts["expired" if res is None else "errors"] += 1
    return _ok(dict(counts, swept_at=now))
