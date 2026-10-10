"""Code-mode `execute` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09)."""
from __future__ import annotations

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
from mcp_server.runtime import RUNTIME

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

_CONTRACTS: Optional[Dict[str, Dict[str, Any]]] = None
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


def _action_contract(action: str) -> Optional[Dict[str, Any]]:
    """Per-action contract (inputSchema/outputSchema/annotations) from the unwrapped registry."""
    global _CONTRACTS
    if _CONTRACTS is None:
        catalog = RUNTIME.action_catalog() if RUNTIME.action_catalog is not None else []
        _CONTRACTS = {item["name"]: item for item in catalog if item.get("via") == "execute"}
    return _CONTRACTS.get(action)


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
        errors.append({"pointer": _pointer(path), "detail": err.message, "code": str(err.validator)})
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


async def _execute_steps(args: dict, idempotency_key: str = "") -> list[TextContent]:
    steps = args.get("steps")
    overall_dry_run = bool(args.get("dry_run", False))
    top_schema_hash = _first_arg(args, SCHEMA_HASH_ARGS)
    request_fingerprint = _sha256({"steps": steps, "dry_run": overall_dry_run})
    problem_errors: List[Dict[str, Any]] = []
    problem_status = 422
    step_results: List[Dict[str, Any]] = []
    underlying_calls: List[Dict[str, Any]] = []
    failed_steps: List[Dict[str, Any]] = []

    for index, raw_step in enumerate(steps, start=1):
        if not isinstance(raw_step, dict):
            failed_steps.append({"step": index, "error": "step must be an object"})
            step_results.append({
                "step": index,
                "status": "invalid",
                "error": "step must be an object",
                "problem": problem_details(
                    422, "Invalid step", "step must be an object",
                    errors=[{"pointer": "", "detail": "step must be an object", "code": "type"}],
                ),
            })
            problem_errors.append({"step": index, "pointer": "", "detail": "step must be an object", "code": "type"})
            break

        action = str(raw_step.get("action") or "").strip()
        on_error = str(raw_step.get("on_error") or "abort").strip().lower()
        entry = (EXECUTE_ACTIONS or {}).get(action)
        if not action or entry is None:
            error_message = f"Unknown execute action '{action}'" if action else "step action is required"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            unknown = problem_details(
                422, "Unknown execute action", error_message,
                errors=[{"pointer": "/action", "detail": error_message, "code": "unknown_action"}],
            )
            step_results.append({"step": index, "action": action, "status": "invalid", "error": error_message, "problem": unknown})
            problem_errors.append({"step": index, "pointer": "/action", "detail": error_message, "code": "unknown_action"})
            if on_error != "continue":
                break
            continue

        step_args = {}
        if isinstance(raw_step.get("arguments"), dict):
            step_args.update(raw_step["arguments"])
        step_dry_run = overall_dry_run or bool(raw_step.get("dry_run", False))
        summary = {
            "tool": entry["tool"],
            "arguments": step_args,
            "status": "dry_run" if step_dry_run else "pending",
        }

        if entry.get("requires_governance_hash") and not step_args.get("governance_hash"):
            error_message = f"Action '{action}' requires governance_hash"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "blocked"
            summary["error_code"] = "governance_hash_missing"
            underlying_calls.append(summary)
            gov_error = {"pointer": "/governance_hash", "detail": error_message, "code": "governance_hash_missing"}
            step_results.append({
                "step": index,
                "action": action,
                "status": "blocked",
                "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(422, "Missing governance_hash", error_message, errors=[gov_error]),
            })
            problem_errors.append({"step": index, **gov_error})
            if on_error != "continue":
                break
            continue

        allowed = RUNTIME.raw_tool_allowed
        if allowed is None or not allowed(entry["tool"]):
            error_message = f"Raw tool '{entry['tool']}' is outside the current session boundary"
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "blocked"
            summary["error_code"] = "boundary_denied"
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "blocked",
                "error": error_message,
                "resolved_calls": [summary],
                "problem": problem_details(
                    403, "Outside session boundary", error_message, slug="boundary-denied",
                    errors=[{"pointer": "/action", "detail": error_message, "code": "boundary_denied"}],
                ),
            })
            problem_errors.append({"step": index, "pointer": "/action", "detail": error_message, "code": "boundary_denied"})
            problem_status = 403
            if on_error != "continue":
                break
            continue

        if step_dry_run:
            contract = _action_contract(action)
            live_hash = schema_hash_for(contract, entry)
            sent_hash = str(raw_step.get("schema_hash") or raw_step.get("schemaHash") or top_schema_hash or "").strip()
            if sent_hash and sent_hash != live_hash:
                # Spec 1.3: schemaHash mismatch -> problem 409 so the client re-fetches the registry.
                error_message = f"schemaHash for action '{action}' does not match the live registry"
                failed_steps.append({"step": index, "action": action, "error": error_message, "error_code": "schema_hash_mismatch"})
                summary["status"] = "blocked"
                summary["error_code"] = "schema_hash_mismatch"
                underlying_calls.append(summary)
                hash_error = {"pointer": "/schemaHash", "detail": error_message, "code": "schema_hash_mismatch"}
                step_results.append({
                    "step": index,
                    "action": action,
                    "status": "blocked",
                    "error": error_message,
                    "resolved_calls": [summary],
                    "problem": problem_details(409, "Schema hash mismatch", error_message, slug="schema-hash-mismatch", errors=[hash_error]),
                })
                problem_errors.append({"step": index, **hash_error})
                problem_status = 409
                if on_error != "continue":
                    break
                continue

            field_errors = validate_step_arguments(contract, step_args)
            if field_errors:
                error_message = f"Arguments for action '{action}' failed validation"
                failed_steps.append({"step": index, "action": action, "error": error_message, "error_code": "validation_failed"})
                summary["status"] = "invalid"
                summary["error_code"] = "validation_failed"
                underlying_calls.append(summary)
                step_results.append({
                    "step": index,
                    "action": action,
                    "status": "invalid",
                    "error": error_message,
                    "resolved_calls": [summary],
                    "problem": problem_details(422, "Validation failed", error_message, errors=field_errors),
                })
                problem_errors.extend({"step": index, **e} for e in field_errors)
                if on_error != "continue":
                    break
                continue

            warnings: List[str] = []
            if not idempotency_key:
                warnings.append("no Idempotency-Key supplied; idempotencyKey is derived from the request and is not a replay guard")
            resolved = resolve_call(
                action,
                entry,
                step_args,
                idempotency_key=idempotency_key or f"dry-{request_fingerprint[:32]}",
                schema_hash=live_hash,
                contract=contract,
                warnings=warnings,
            )
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "dry_run",
                "resolved_calls": [summary],
                "resolved_call": resolved,
            })
            continue

        try:
            raw_call = await RUNTIME.invoke_raw_tool(entry["tool"], step_args)
        except Exception as exc:
            error_message = str(exc)
            failed_steps.append({"step": index, "action": action, "error": error_message})
            summary["status"] = "error"
            summary["error_code"] = "tool_resolution_failed"
            underlying_calls.append(summary)
            step_results.append({
                "step": index,
                "action": action,
                "status": "error",
                "error": error_message,
                "resolved_calls": [summary],
            })
            if on_error != "continue":
                break
            continue

        call_summary = raw_call_summary(raw_call)
        underlying_calls.append(call_summary)
        if raw_call["status"] != "success":
            error_message = f"Underlying tool '{entry['tool']}' returned an error"
            failed_steps.append({
                "step": index,
                "action": action,
                "error": error_message,
                "error_code": raw_call.get("error_code") or "tool_error",
            })
            step_results.append({
                "step": index,
                "action": action,
                "status": "error",
                "error": error_message,
                "result": raw_call["payload"],
                "resolved_calls": [call_summary],
            })
            if on_error != "continue":
                break
            continue

        step_results.append({
            "step": index,
            "action": action,
            "status": "success",
            "result": raw_call["payload"],
            "resolved_calls": [call_summary],
        })

    if failed_steps:
        return RUNTIME.result_text({
            "success": False,
            "interface_mode": RUNTIME.interface_mode,
            "tool": "execute",
            "dry_run": overall_dry_run,
            "partial": any(step.get("status") == "success" for step in step_results),
            "step_results": step_results,
            "underlying_calls": underlying_calls,
            "error": {
                "code": "step_failed",
                "message": "One or more execute steps failed",
                "details": {"failed_steps": failed_steps},
            },
            # DVP-TSK-892: RFC 9457 problem details (additive). Present for argument/boundary
            # failures detected by execute itself; tool-level failures keep their step payload.
            **(
                {
                    "problem": problem_details(
                        problem_status,
                        "Execute request failed",
                        "One or more execute steps failed",
                        slug="schema-hash-mismatch" if problem_status == 409 else ("boundary-denied" if problem_status == 403 else "validation"),
                        errors=problem_errors,
                    )
                }
                if problem_errors
                else {}
            ),
            **({"idempotency_key": idempotency_key} if idempotency_key else {}),
        })

    metadata: Dict[str, Any] = {"step_count": len(step_results)}
    if idempotency_key:
        metadata["idempotency_key"] = idempotency_key
    return meta_tool_success(
        "execute",
        steps=step_results,
        underlying_calls=underlying_calls,
        dry_run=overall_dry_run,
        metadata=metadata,
    )
