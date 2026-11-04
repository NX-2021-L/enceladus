"""Code-mode `execute` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09).

ENC-TSK-S29-0A (BRD DOC-E32D0ED08473 B4/W3.3, ruling D4):
  * every step is validated before the first write (422 problem, nothing written);
  * steps may declare ``id`` / ``depends_on``; a declared graph runs on a pool of
    ``EXECUTE_POOL_SIZE`` (legacy batches stay strictly serial);
  * each step reports started_ms / duration_ms / status / error; the response carries
    execute_total_ms, critical_path_ms and committed_prefix;
  * fail-closed governance rotation: the governance hash is re-read immediately before each
    step's commit; on a mismatch that step and every not-yet-started step abort
    (``governance_hash_stale``), committed steps stand.  No action in the registry declares an
    inverse, so no compensation runs; resume = a new execute with the remaining steps and a new
    idempotency key.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from mcp.types import TextContent

from mcp_server.meta_support import (
    meta_tool_error,
    meta_tool_success,
    raw_call_summary,
)
from mcp_server.runtime import EXECUTE_STEP_INDEX, RUNTIME

logger = logging.getLogger(__name__)

EXECUTE_ACTIONS: Dict[str, Dict[str, Any]] | None = None

# ---------------------------------------------------------------------------
# DVP-TSK-892 (DVP-PLN-010 E2-W1.7, candidate C-5): ResolvedCall v1, RFC 9457
# problem details with errors[].pointer, and Idempotency-Key replay.
# Everything here is ADDITIVE: no existing response field changes shape.
# ---------------------------------------------------------------------------
SURFACE_ID = "enceladus"
PROBLEM_TYPE_PREFIX = "urn:enceladus:problem:"
IDEMPOTENCY_KEY_ARGS = ("idempotency_key", "Idempotency-Key", "idempotencyKey")
SCHEMA_HASH_ARGS = ("schema_hash", "schemaHash")
# OD-7 (header name and TTL) is undecided in the spec; 24h mirrors the common
# idempotency-key window and the store is bounded.
IDEMPOTENCY_TTL_S = 24 * 3600
IDEMPOTENCY_MAX_ENTRIES = 512

_CONTRACTS: Optional[Dict[tuple, Dict[str, Any]]] = None
_IDEM_LOCK = threading.Lock()
# key -> {"fingerprint": str, "payload": dict, "expires": float}
# In-memory (per warm Lambda container / server process): a replay on a cold or
# different container re-executes.  Documented limitation; a durable store is a
# follow-on (needs infra, out of scope for this change).
_IDEM_STORE: Dict[str, Dict[str, Any]] = {}
_IDEM_INFLIGHT: set = set()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def problem_details(
    status: int,
    title: str,
    detail: str,
    *,
    slug: str = "validation",
    errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """RFC 9457 problem details; ``errors[].pointer`` is an RFC 6901 pointer into the step arguments."""
    problem: Dict[str, Any] = {
        "type": PROBLEM_TYPE_PREFIX + slug,
        "title": title,
        "status": status,
        "detail": detail,
    }
    if errors:
        problem["errors"] = errors
    return problem


def _pointer(path: Any) -> str:
    parts = [str(p).replace("~", "~0").replace("/", "~1") for p in path]
    return "/" + "/".join(parts) if parts else ""


def _action_contract(action: str, via: str = "execute") -> Optional[Dict[str, Any]]:
    """Per-action contract (inputSchema/outputSchema/annotations) from the unwrapped registry."""
    global _CONTRACTS
    if _CONTRACTS is None:
        catalog = RUNTIME.action_catalog() if RUNTIME.action_catalog is not None else []
        _CONTRACTS = {(item.get("via"), item["name"]): item for item in catalog}
    return _CONTRACTS.get((via, action))


def schema_hash_for(contract: Optional[Dict[str, Any]], entry: Dict[str, Any]) -> str:
    if contract is not None:
        basis = {
            "inputSchema": contract.get("inputSchema"),
            "outputSchema": contract.get("outputSchema"),
            "annotations": contract.get("annotations"),
            "requiresGovernanceHash": contract.get("requiresGovernanceHash"),
        }
    else:
        basis = {"tool": entry.get("tool"), "annotations": entry.get("annotations")}
    return _sha256(basis)


def validate_step_arguments(contract: Optional[Dict[str, Any]], step_args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate step arguments against the action inputSchema; one error per offending field."""
    schema = (contract or {}).get("inputSchema")
    if not isinstance(schema, dict):
        return []
    try:
        import jsonschema

        validator = jsonschema.Draft202012Validator(schema)
        raw_errors = sorted(validator.iter_errors(step_args), key=lambda e: [str(p) for p in e.absolute_path])
    except Exception as exc:  # a broken declaration must never block the call
        logger.warning("execute: schema validation skipped: %s", exc)
        return []
    errors: List[Dict[str, Any]] = []
    for err in raw_errors:
        path = list(err.absolute_path)
        if err.validator == "required":
            missing = (err.validator_value or [])
            for name in missing:
                if name not in step_args:
                    errors.append({"pointer": _pointer(path + [name]), "detail": f"'{name}' is a required property", "code": "required"})
            continue
        detail = err.message
        if err.validator == "not" and isinstance(err.schema, dict) and err.schema.get("description"):
            # A forbidden property (``"not": {}``) explains itself in its description.
            detail = err.schema["description"]
        errors.append({"pointer": _pointer(path), "detail": detail, "code": str(err.validator)})
    return errors


def _side_effects(annotations: Dict[str, Any]) -> Dict[str, Any]:
    if annotations.get("readOnlyHint"):
        return {"writeCount": 0, "kinds": []}
    if annotations.get("destructiveHint"):
        return {"writeCount": 1, "kinds": ["destructive-write"]}
    if annotations.get("idempotentHint"):
        return {"writeCount": 1, "kinds": ["additive-write"]}
    return {"writeCount": 1, "kinds": ["write"]}


def _placeholders(contract: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    out_schema = (contract or {}).get("outputSchema")
    props = out_schema.get("properties") if isinstance(out_schema, dict) else None
    result: List[Dict[str, str]] = []
    if isinstance(props, dict):
        for name, spec in props.items():
            if isinstance(spec, dict) and spec.get("x-io-minted"):
                result.append({"pointer": _pointer([name]), "label": f"<new {name}>"})
    return result


def _principal(step_args: Dict[str, Any]) -> Optional[str]:
    for candidate in (
        os.environ.get("ENCELADUS_MCP_PRINCIPAL"),
        step_args.get("principal"),
        step_args.get("provider"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def resolve_call(
    action: str,
    entry: Dict[str, Any],
    step_args: Dict[str, Any],
    *,
    idempotency_key: str,
    schema_hash: str,
    contract: Optional[Dict[str, Any]],
    warnings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a ResolvedCall v1 (DOC-3724FD572867 s1.3) for one execute step. Zero writes."""
    annotations = dict(entry.get("annotations") or (contract or {}).get("annotations") or {})
    side_effects = _side_effects(annotations)
    title = str(entry.get("title") or (contract or {}).get("title") or action)
    call: Dict[str, Any] = {
        "v": 1,
        "surface": SURFACE_ID,
        "action": action,
        "arguments": step_args,
        "schemaHash": schema_hash,
        # Enceladus actions resolve to MCP tool handlers (which call the HTTP APIs); the
        # handler name is the stable route-level identifier, there is no single HTTP path.
        "underlying": [{"handler": entry["tool"], "method": "TOOL", "path": f"mcp://{SURFACE_ID}/tools/{entry['tool']}", "body": step_args}],
        "sideEffects": side_effects,
        "sentence": f"{title} ({'read-only' if not side_effects['writeCount'] else 'writes ' + side_effects['kinds'][0]}) via {entry['tool']}",
        "placeholders": _placeholders(contract),
        "annotations": annotations,
        "idempotencyKey": idempotency_key,
        "source": "server-dry-run",
    }
    gov = step_args.get("governance_hash")
    if isinstance(gov, str) and gov.strip():
        call["governanceHash"] = gov.strip()
    principal = _principal(step_args)
    if principal:
        call["principal"] = principal
    if warnings:
        call["warnings"] = list(warnings)
    return call


def _first_arg(args: Dict[str, Any], names: tuple) -> str:
    for name in names:
        value = args.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _with_problem(result: list, problem: Dict[str, Any]) -> list:
    """Attach an RFC 9457 ``problem`` member to a serialized meta-tool payload."""
    try:
        payload = json.loads(result[0].text)
        payload["problem"] = problem
        return RUNTIME.result_text(payload)
    except Exception:
        return result


def _idem_purge(now: float) -> None:
    for key in [k for k, v in _IDEM_STORE.items() if v["expires"] <= now]:
        _IDEM_STORE.pop(key, None)
    while len(_IDEM_STORE) > IDEMPOTENCY_MAX_ENTRIES:
        _IDEM_STORE.pop(next(iter(_IDEM_STORE)), None)



def _truthy_dry_run(value: Any) -> bool:
    """Fail-safe dry_run coercion: only an explicit false-like value is non-dry."""
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off", "none", "null")
    return bool(value)


def register_actions(actions: Dict[str, Dict[str, Any]]) -> None:
    global EXECUTE_ACTIONS
    EXECUTE_ACTIONS = actions


async def execute(args: dict) -> list[TextContent]:
    """Entry point: Idempotency-Key handling around the step runner (DVP-TSK-892)."""
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return _with_problem(
            meta_tool_error("execute", code="invalid_input", message="steps must be a non-empty array"),
            problem_details(
                422, "Invalid execute request", "steps must be a non-empty array",
                errors=[{"pointer": "/steps", "detail": "steps must be a non-empty array", "code": "invalid_input"}],
            ),
        )

    key = _first_arg(args, IDEMPOTENCY_KEY_ARGS)
    if not key or bool(args.get("dry_run", False)):
        # No key, or a dry run (zero writes, so nothing to deduplicate): run as before.
        return await _execute_steps(args, key)

    fingerprint = _sha256({"steps": steps, "dry_run": False})
    now = time.time()
    with _IDEM_LOCK:
        _idem_purge(now)
        stored = _IDEM_STORE.get(key)
        if stored is not None:
            if stored["fingerprint"] != fingerprint:
                conflict = problem_details(
                    422, "Idempotency-Key reused with a different request",
                    "This Idempotency-Key was already used for a different set of steps.",
                    slug="idempotency-key-reuse",
                    errors=[{"pointer": "/idempotency_key", "detail": "key bound to a different request", "code": "idempotency_key_reuse"}],
                )
                return _with_problem(
                    meta_tool_error("execute", code="idempotency_key_reuse", message=conflict["detail"]), conflict
                )
            replay = dict(stored["payload"])
            replay["idempotent_replay"] = True
            replay["idempotency_key"] = key
            return RUNTIME.result_text(replay)
        if key in _IDEM_INFLIGHT:
            busy = problem_details(
                409, "Request in progress", "A request with this Idempotency-Key is still executing.",
                slug="idempotency-in-flight",
                errors=[{"pointer": "/idempotency_key", "detail": "request in flight", "code": "idempotency_in_flight"}],
            )
            return _with_problem(meta_tool_error("execute", code="idempotency_in_flight", message=busy["detail"]), busy)
        _IDEM_INFLIGHT.add(key)

    try:
        result = await _execute_steps(args, key)
        try:
            payload = json.loads(result[0].text)
        except Exception:
            payload = None
        # Only a fully successful receipt is stored: a failed or partial run stays retryable.
        if isinstance(payload, dict) and payload.get("success") is True:
            with _IDEM_LOCK:
                _IDEM_STORE[key] = {"fingerprint": fingerprint, "payload": payload, "expires": time.time() + IDEMPOTENCY_TTL_S}
        return result
    finally:
        with _IDEM_LOCK:
            _IDEM_INFLIGHT.discard(key)




# ---------------------------------------------------------------------------
# ENC-TSK-S29-0A: pre-validation, dependency graph, pooled scheduler, timings, D4 rotation.
# ---------------------------------------------------------------------------
EXECUTE_POOL_SIZE = 8
_OK_STATUSES = ("success", "dry_run")


def _with_fields(result: list, fields: Dict[str, Any]) -> list:
    """Merge top-level members into a serialized meta-tool payload."""
    try:
        payload = json.loads(result[0].text)
        payload.update(fields)
        return RUNTIME.result_text(payload)
    except Exception:
        return result


def _prepare_step(
    index: int,
    raw_step: Any,
    *,
    overall_dry_run: bool,
    top_schema_hash: str,
    idempotency_key: str,
    request_fingerprint: str,
) -> Dict[str, Any]:
    """Validate one step with zero side effects.

    Returns ``{"ok": True, ...}`` (a runnable step; for a dry step ``result`` is final) or
    ``{"ok": False, "result", "failed", "errors", "summary", "problem_status"}``.
    """

    def bad(result, failed, errors, summary=None, problem_status=422):
        return {
            "ok": False, "index": index, "action": result.get("action", ""), "result": result,
            "failed": failed, "errors": errors, "summary": summary, "problem_status": problem_status,
        }

    if not isinstance(raw_step, dict):
        return bad(
            {
                "step": index, "status": "invalid", "error": "step must be an object",
                "problem": problem_details(
                    422, "Invalid step", "step must be an object",
                    errors=[{"pointer": "", "detail": "step must be an object", "code": "type"}],
                ),
            },
            {"step": index, "error": "step must be an object"},
            [{"step": index, "pointer": "", "detail": "step must be an object", "code": "type"}],
        )

    action = str(raw_step.get("action") or "").strip()
    on_error = str(raw_step.get("on_error") or "abort").strip().lower()
    entry = (EXECUTE_ACTIONS or {}).get(action)
    if not action or entry is None:
        error_message = f"Unknown execute action '{action}'" if action else "step action is required"
        return bad(
            {
                "step": index, "action": action, "status": "invalid", "error": error_message,
                "problem": problem_details(
                    422, "Unknown execute action", error_message,
                    errors=[{"pointer": "/action", "detail": error_message, "code": "unknown_action"}],
                ),
            },
            {"step": index, "action": action, "error": error_message},
            [{"step": index, "pointer": "/action", "detail": error_message, "code": "unknown_action"}],
        )

    step_args: Dict[str, Any] = {}
    if isinstance(raw_step.get("arguments"), dict):
        step_args.update(raw_step["arguments"])
    # ENC-ISS-755: a client may send dry_run inside ``arguments`` instead of on the step.
    # No governed handler implements it, so honoring it here is the only safe reading: a
    # truthy value (fail-safe for "true"/"1" strings) makes this a dry step and is never
    # forwarded. A falsy value is left in place (the default) and forwarded unchanged.
    arguments_dry_run = _truthy_dry_run(step_args.get("dry_run")) if "dry_run" in step_args else False
    if arguments_dry_run:
        step_args.pop("dry_run", None)
    # ENC-ISS-855: server-fixed argument values (plan.create -> record_type=plan).
    inject_errors = [
        {"pointer": _pointer([key]), "detail": f"'{action}' fixes {key} to {value!r}; got {step_args[key]!r}", "code": "const"}
        for key, value in (entry.get("inject") or {}).items()
        if key in step_args and step_args[key] != value
    ]
    if inject_errors:
        error_message = f"Arguments for action '{action}' failed validation"
        summary = {"tool": entry["tool"], "arguments": step_args, "status": "invalid", "error_code": "validation_failed"}
        return bad(
            {
                "step": index, "action": action, "status": "invalid", "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(422, "Validation failed", error_message, errors=inject_errors),
            },
            {"step": index, "action": action, "error": error_message, "error_code": "validation_failed"},
            [{"step": index, **e} for e in inject_errors], summary,
        )
    step_args.update(entry.get("inject") or {})
    step_dry_run = overall_dry_run or _truthy_dry_run(raw_step.get("dry_run", False)) or arguments_dry_run
    summary = {"tool": entry["tool"], "arguments": step_args, "status": "dry_run" if step_dry_run else "pending"}

    if entry.get("requires_governance_hash") and not step_args.get("governance_hash"):
        error_message = f"Action '{action}' requires governance_hash"
        summary["status"] = "blocked"
        summary["error_code"] = "governance_hash_missing"
        gov_error = {"pointer": "/governance_hash", "detail": error_message, "code": "governance_hash_missing"}
        return bad(
            {
                "step": index, "action": action, "status": "blocked", "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(422, "Missing governance_hash", error_message, errors=[gov_error]),
            },
            {"step": index, "action": action, "error": error_message},
            [{"step": index, **gov_error}], summary,
        )

    allowed = RUNTIME.raw_tool_allowed
    if allowed is None or not allowed(entry["tool"]):
        error_message = f"Raw tool '{entry['tool']}' is outside the current session boundary"
        summary["status"] = "blocked"
        summary["error_code"] = "boundary_denied"
        return bad(
            {
                "step": index, "action": action, "status": "blocked", "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(
                    403, "Outside session boundary", error_message, slug="boundary-denied",
                    errors=[{"pointer": "/action", "detail": error_message, "code": "boundary_denied"}],
                ),
            },
            {"step": index, "action": action, "error": error_message},
            [{"step": index, "pointer": "/action", "detail": error_message, "code": "boundary_denied"}],
            summary, 403,
        )

    contract = _action_contract(action)
    live_hash = schema_hash_for(contract, entry)
    if step_dry_run:
        sent_hash = str(raw_step.get("schema_hash") or raw_step.get("schemaHash") or top_schema_hash or "").strip()
        if sent_hash and sent_hash != live_hash:
            # Spec 1.3: schemaHash mismatch -> problem 409 so the client re-fetches the registry.
            error_message = f"schemaHash for action '{action}' does not match the live registry"
            summary["status"] = "blocked"
            summary["error_code"] = "schema_hash_mismatch"
            hash_error = {"pointer": "/schemaHash", "detail": error_message, "code": "schema_hash_mismatch"}
            return bad(
                {
                    "step": index, "action": action, "status": "blocked", "error": error_message,
                    "resolved_calls": [summary],
                    "problem": problem_details(409, "Schema hash mismatch", error_message, slug="schema-hash-mismatch", errors=[hash_error]),
                },
                {"step": index, "action": action, "error": error_message, "error_code": "schema_hash_mismatch"},
                [{"step": index, **hash_error}], summary, 409,
            )

    # S29-0A: argument shape is checked for real steps too, before any write happens.
    field_errors = validate_step_arguments(contract, step_args)
    if field_errors:
        error_message = f"Arguments for action '{action}' failed validation"
        summary["status"] = "invalid"
        summary["error_code"] = "validation_failed"
        return bad(
            {
                "step": index, "action": action, "status": "invalid", "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(422, "Validation failed", error_message, errors=field_errors),
            },
            {"step": index, "action": action, "error": error_message, "error_code": "validation_failed"},
            [{"step": index, **e} for e in field_errors], summary,
        )

    prepared: Dict[str, Any] = {
        "ok": True, "index": index, "action": action, "entry": entry, "step_args": step_args,
        "on_error": on_error, "dry_run": step_dry_run, "summary": summary,
    }
    if step_dry_run:
        warnings: List[str] = []
        if not idempotency_key:
            warnings.append("no Idempotency-Key supplied; idempotencyKey is derived from the request and is not a replay guard")
        resolved = resolve_call(
            action, entry, step_args,
            idempotency_key=idempotency_key or f"dry-{request_fingerprint[:32]}",
            schema_hash=live_hash, contract=contract, warnings=warnings,
        )
        prepared["result"] = {
            "step": index, "action": action, "status": "dry_run",
            "resolved_calls": [summary], "resolved_call": resolved,
        }
    return prepared


def _graph_dependencies(steps: List[Any]) -> tuple:
    """Parse ``id`` / ``depends_on``.  Returns (declared, deps, errors, order).

    ``deps[i]`` is the sorted list of zero-based dependency indexes of step i; ``errors`` maps a
    zero-based step index to RFC 6901 pointer errors (relative to the step object); ``order`` is a
    topological order (index order when no graph is declared or the graph is invalid).
    """
    n = len(steps)
    errors: Dict[int, List[Dict[str, Any]]] = {}

    def err(i: int, pointer: str, detail: str, code: str) -> None:
        errors.setdefault(i, []).append({"pointer": pointer, "detail": detail, "code": code})

    ids: Dict[str, int] = {}
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or "id" not in step:
            continue
        sid = step["id"]
        if not isinstance(sid, str) or not sid.strip():
            err(i, "/id", "id must be a non-empty string", "type")
        elif sid in ids:
            err(i, "/id", f"duplicate step id '{sid}' (also step {ids[sid] + 1})", "duplicate_id")
        else:
            ids[sid] = i

    deps: List[List[int]] = [[] for _ in range(n)]
    declared = False
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or step.get("depends_on") is None:
            continue
        raw = step["depends_on"]
        if not isinstance(raw, list):
            err(i, "/depends_on", "depends_on must be an array of step ids or zero-based indexes", "type")
            continue
        declared = True  # an explicit (even empty) depends_on opts the batch into the DAG schedule
        seen = set()
        for j, ref in enumerate(raw):
            target: Optional[int] = None
            if isinstance(ref, bool) or not isinstance(ref, (str, int)):
                err(i, f"/depends_on/{j}", "dependency must be a step id (string) or zero-based index (integer)", "type")
            elif isinstance(ref, int):
                if 0 <= ref < n:
                    target = ref
                else:
                    err(i, f"/depends_on/{j}", f"dependency index {ref} is out of range (0..{n - 1})", "unknown_dependency")
            elif ref in ids:
                target = ids[ref]
            else:
                err(i, f"/depends_on/{j}", f"unknown step id '{ref}'", "unknown_dependency")
            if target is not None and target not in seen:
                seen.add(target)
                deps[i].append(target)
        deps[i].sort()

    order: List[int] = []
    if declared:
        indegree = [len(d) for d in deps]
        children: Dict[int, List[int]] = {}
        for i, d in enumerate(deps):
            for t in d:
                children.setdefault(t, []).append(i)
        ready = [i for i in range(n) if indegree[i] == 0]
        while ready:
            node = ready.pop(0)
            order.append(node)
            for child in children.get(node, []):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
        if len(order) != n:
            for i in range(n):
                if i not in order:
                    err(i, "/depends_on", "step is part of a dependency cycle", "dependency_cycle")
            order = list(range(n))
    else:
        order = list(range(n))
    return declared, deps, errors, order


def _critical_path_ms(order: List[int], deps: List[List[int]], durations: List[int], serial: bool) -> int:
    """Longest dependency chain by summed duration; the implicit chain in serial mode."""
    if serial:
        return int(sum(durations))
    best = [0] * len(durations)
    longest = 0
    for i in order:
        best[i] = durations[i] + max((best[d] for d in deps[i]), default=0)
        longest = max(longest, best[i])
    return int(longest)


def _governance_check(step_args: Dict[str, Any], batch_wall_start: float) -> Optional[Dict[str, str]]:
    """Ruling D4: re-read the current hash immediately before a step commits.

    Cost: the probe serves the 60 s TTL cache when the cached value is no older than the batch
    (zero hops); otherwise it refreshes once and the rest of the batch reads the cache.
    """
    probe = RUNTIME.current_governance_hash
    provided = str(step_args.get("governance_hash") or "").strip()
    if probe is None or not provided:
        return None
    try:
        current = str(probe(max(0.0, time.time() - batch_wall_start)) or "").strip()
    except Exception as exc:  # fail closed: an unreadable current hash must not commit
        return {"code": "governance_hash_unverifiable", "message": f"current governance hash could not be read: {exc}"}
    if not current:
        return None  # probe disabled
    if current != provided:
        return {
            "code": "governance_hash_stale",
            "message": "GOVERNANCE_STALE: governance rotated during the batch; this step's governance_hash no longer matches the current bundle",
        }
    return None


async def _execute_steps(args: dict, idempotency_key: str = "") -> list[TextContent]:
    steps = args.get("steps")
    overall_dry_run = bool(args.get("dry_run", False))
    top_schema_hash = _first_arg(args, SCHEMA_HASH_ARGS)
    request_fingerprint = _sha256({"steps": steps, "dry_run": overall_dry_run})
    t0 = time.perf_counter()
    wall0 = time.time()

    def now_ms() -> int:
        return int(round((time.perf_counter() - t0) * 1000))

    # ---- Phase 1: validate every step (and the dependency graph) before any write. ----
    prepared = [
        _prepare_step(
            i, raw, overall_dry_run=overall_dry_run, top_schema_hash=top_schema_hash,
            idempotency_key=idempotency_key, request_fingerprint=request_fingerprint,
        )
        for i, raw in enumerate(steps, start=1)
    ]
    declared, deps, graph_errors, order = _graph_dependencies(steps)
    problem_status = 422
    problem_errors: List[Dict[str, Any]] = []
    failed_steps: List[Dict[str, Any]] = []
    invalid_found = False
    for p in prepared:
        gerrs = graph_errors.get(p["index"] - 1)
        if gerrs and p["ok"]:
            message = f"Step {p['index']} has an invalid dependency declaration"
            p.update({
                "ok": False, "summary": None, "problem_status": 422,
                "failed": {"step": p["index"], "action": p["action"], "error": message, "error_code": "dependency_invalid"},
                "errors": [{"step": p["index"], **e} for e in gerrs],
                "result": {
                    "step": p["index"], "action": p["action"], "status": "invalid", "error": message,
                    "problem": problem_details(422, "Invalid dependency graph", message, errors=gerrs),
                },
            })
        elif gerrs:
            p["errors"] = p["errors"] + [{"step": p["index"], **e} for e in gerrs]
            p["result"]["problem"]["errors"] = list(p["result"]["problem"].get("errors", [])) + gerrs
        if not p["ok"]:
            invalid_found = True
            failed_steps.append(p["failed"])
            problem_errors.extend(p["errors"])
            if p["problem_status"] != 422:
                problem_status = p["problem_status"]

    results: Dict[int, Dict[str, Any]] = {}
    underlying: Dict[int, Dict[str, Any]] = {}
    committed: List[int] = []

    def stamp(result: Dict[str, Any], started: int, duration: int) -> Dict[str, Any]:
        result.setdefault("error", None)
        result["started_ms"] = started
        result["duration_ms"] = duration
        return result

    if invalid_found:
        for p in prepared:
            idx = p["index"]
            if not p["ok"]:
                results[idx] = stamp(dict(p["result"]), 0, 0)
                if p["summary"] is not None:
                    underlying[idx] = p["summary"]
            elif p["dry_run"]:
                results[idx] = stamp(dict(p["result"]), 0, 0)
                underlying[idx] = p["summary"]
            else:
                results[idx] = stamp({
                    "step": idx, "action": p["action"], "status": "skipped",
                    "error": "not executed: the batch failed pre-validation; nothing was written",
                }, 0, 0)
        return _finalize(
            overall_dry_run, idempotency_key, prepared, results, underlying, failed_steps, problem_errors,
            problem_status, committed, order, deps, declared, now_ms(), None,
        )

    # ---- Phase 2: execute (serial legacy order, or a pooled topological schedule). ----
    abort: Dict[str, Any] = {}
    semaphore = asyncio.Semaphore(EXECUTE_POOL_SIZE)
    done = {p["index"]: asyncio.Event() for p in prepared}
    by_index = {p["index"]: p for p in prepared}

    def aborted_result(p: Dict[str, Any]) -> Dict[str, Any]:
        return stamp({
            "step": p["index"], "action": p["action"], "status": "aborted",
            "error": abort["message"], "error_code": abort["code"],
        }, now_ms(), 0)

    def set_abort(code: str, message: str, step: int) -> None:
        if not abort:
            abort.update({"code": code, "message": message, "step": step})

    async def run_one(p: Dict[str, Any]) -> None:
        idx = p["index"]
        try:
            if p["dry_run"]:
                results[idx] = stamp(dict(p["result"]), now_ms(), 0)
                underlying[idx] = p["summary"]
                return
            if declared:
                failed_dep = None
                for d in deps[idx - 1]:
                    await done[d + 1].wait()
                    if failed_dep is None and results[d + 1]["status"] not in _OK_STATUSES:
                        failed_dep = d + 1
            else:
                failed_dep = None
            async with (semaphore if declared else contextlib.nullcontext()):
                if abort:
                    results[idx] = aborted_result(p)
                    return
                if failed_dep is not None:
                    results[idx] = stamp({
                        "step": idx, "action": p["action"], "status": "skipped",
                        "error": f"skipped: dependency step {failed_dep} did not succeed",
                    }, now_ms(), 0)
                    return
                started = now_ms()
                t_step = time.perf_counter()

                def duration() -> int:
                    return int(round((time.perf_counter() - t_step) * 1000))

                stale = _governance_check(p["step_args"], wall0)
                if stale is not None:
                    set_abort(stale["code"], stale["message"], idx)
                    failed_steps.append({"step": idx, "action": p["action"], "error": stale["message"], "error_code": stale["code"]})
                    problem_errors.append({"step": idx, "pointer": "/governance_hash", "detail": stale["message"], "code": stale["code"]})
                    results[idx] = stamp({
                        "step": idx, "action": p["action"], "status": "aborted",
                        "error": stale["message"], "error_code": stale["code"],
                    }, started, duration())
                    return
                summary = p["summary"]
                try:
                    token = EXECUTE_STEP_INDEX.set(idx)
                    try:
                        raw_call = await RUNTIME.invoke_raw_tool(p["entry"]["tool"], p["step_args"])
                    finally:
                        EXECUTE_STEP_INDEX.reset(token)
                except Exception as exc:
                    error_message = str(exc)
                    failed_steps.append({"step": idx, "action": p["action"], "error": error_message})
                    summary["status"] = "error"
                    summary["error_code"] = "tool_resolution_failed"
                    underlying[idx] = summary
                    results[idx] = stamp({
                        "step": idx, "action": p["action"], "status": "error", "error": error_message,
                        "resolved_calls": [summary],
                    }, started, duration())
                    if p["on_error"] != "continue":
                        set_abort("step_aborted", f"aborted: step {idx} failed (on_error=abort)", idx)
                    return
                call_summary = raw_call_summary(raw_call)
                underlying[idx] = call_summary
                if raw_call["status"] != "success":
                    error_message = f"Underlying tool '{p['entry']['tool']}' returned an error"
                    failed_steps.append({
                        "step": idx, "action": p["action"], "error": error_message,
                        "error_code": raw_call.get("error_code") or "tool_error",
                    })
                    results[idx] = stamp({
                        "step": idx, "action": p["action"], "status": "error", "error": error_message,
                        "result": raw_call["payload"], "resolved_calls": [call_summary],
                    }, started, duration())
                    if p["on_error"] != "continue":
                        set_abort("step_aborted", f"aborted: step {idx} failed (on_error=abort)", idx)
                    return
                committed.append(idx)
                results[idx] = stamp({
                    "step": idx, "action": p["action"], "status": "success",
                    "result": raw_call["payload"], "resolved_calls": [call_summary],
                }, started, duration())
        finally:
            done[idx].set()

    if declared:
        await asyncio.gather(*(run_one(by_index[i + 1]) for i in range(len(prepared))))
    else:
        for p in prepared:
            if abort:
                results[p["index"]] = aborted_result(p)
                done[p["index"]].set()
                continue
            await run_one(p)

    return _finalize(
        overall_dry_run, idempotency_key, prepared, results, underlying, failed_steps, problem_errors,
        problem_status, committed, order, deps, declared, now_ms(), abort,
    )


def _finalize(
    overall_dry_run: bool,
    idempotency_key: str,
    prepared: List[Dict[str, Any]],
    results: Dict[int, Dict[str, Any]],
    underlying: Dict[int, Dict[str, Any]],
    failed_steps: List[Dict[str, Any]],
    problem_errors: List[Dict[str, Any]],
    problem_status: int,
    committed: List[int],
    order: List[int],
    deps: List[List[int]],
    declared: bool,
    total_ms: int,
    abort: Optional[Dict[str, Any]],
) -> list[TextContent]:
    indexes = [p["index"] for p in prepared]
    step_results = [results[i] for i in indexes]
    underlying_calls = [underlying[i] for i in indexes if i in underlying]
    durations = [int(results[i].get("duration_ms") or 0) for i in indexes]
    timing = {
        "execute_total_ms": total_ms,
        "critical_path_ms": _critical_path_ms(order, deps, durations, serial=not declared),
        "committed_prefix": list(committed),
        "execution_mode": "dag" if declared else "serial",
    }
    if declared:
        timing["pool_size"] = EXECUTE_POOL_SIZE

    if failed_steps:
        stale = bool(abort) and abort.get("code") in ("governance_hash_stale", "governance_hash_unverifiable")
        if stale:
            problem_status = 409
        error_code = abort["code"] if stale else "step_failed"
        error_message = abort["message"] if stale else "One or more execute steps failed"
        if stale:
            slug = "governance-hash-stale"
        else:
            slug = "schema-hash-mismatch" if problem_status == 409 else ("boundary-denied" if problem_status == 403 else "validation")
        return RUNTIME.result_text({
            "success": False,
            "interface_mode": RUNTIME.interface_mode,
            "tool": "execute",
            "dry_run": overall_dry_run,
            "partial": any(step.get("status") == "success" for step in step_results),
            "step_results": step_results,
            "underlying_calls": underlying_calls,
            "error": {
                "code": error_code,
                "message": error_message,
                "details": {"failed_steps": failed_steps},
            },
            # DVP-TSK-892: RFC 9457 problem details (additive). Present for argument/boundary
            # failures detected by execute itself; tool-level failures keep their step payload.
            **(
                {"problem": problem_details(
                    problem_status, "Execute request failed",
                    error_message if stale else "One or more execute steps failed",
                    slug=slug, errors=problem_errors,
                )}
                if problem_errors
                else {}
            ),
            **({"idempotency_key": idempotency_key} if idempotency_key else {}),
            **timing,
        })

    metadata: Dict[str, Any] = {"step_count": len(step_results)}
    if idempotency_key:
        metadata["idempotency_key"] = idempotency_key
    return _with_fields(
        meta_tool_success(
            "execute",
            steps=step_results,
            underlying_calls=underlying_calls,
            dry_run=overall_dry_run,
            metadata=metadata,
        ),
        timing,
    )
