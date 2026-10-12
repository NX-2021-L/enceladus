"""DVP-TSK-968 part A (DVP-PLN-013 E4-W2.2, DVP-FTR-106): the recipe primitive.

A recipe is a governed, versioned, immutable-once-published definition (not a work
record: no checkout, no acceptance criteria, not escalatable). This module is the
storage-agnostic service: every function takes a RecipeContext of injected callables
(get/put/query/mint/escalate/...), so the Lambda wires DynamoDB and the tests wire an
in-memory store. Nothing here talks to AWS.

Item keys (table keyed by project_id + record_id):
  recipe#<REC>              head item          (record_kind=head)
  recipe#<REC>@<semver>     version item       (record_kind=version, definition lives here)
  recipe-name#<name>        name-uniqueness marker (written if-absent; maps name -> REC)
  (part B)  recipe_run#<RUN> run items, deliberately outside the recipe# prefix.

Definition lifecycle (spec s6): draft -> validated (recipe.validate, static) ->
published (IO GATE, hub acceptance escalation decided by a Cognito human-admin, applied
through the registered recipe_version applier) -> deprecated -> retired (IO GATE).

Binding grammar (whole-value only, no interpolation): a string value that starts with
'$' is a binding: $<root>.<a>.<b> or $<root>/<a>/<b> (RFC 6901 pointer after the root,
~0 ~1 escapes). root is 'inputs' or an EARLIER step id; '$$' escapes a literal '$'.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

Result = Tuple[int, Dict[str, Any]]

SOURCE_PRINCIPAL = "recipe-runner"
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REC_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,11}-REC-[0-9]{3,}$")
STEP_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")      # RP-0 s4 id grammar (the stricter lowercase form is a subset)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BINDING_RE = re.compile(r"^\$(?P<root>[A-Za-z0-9_][A-Za-z0-9_-]*)(?P<rest>(?:[./]\S*)?)$")

STATUSES = ("draft", "validated", "published", "deprecated", "retired")
SURFACES = ("enceladus", "io-finance", "io-travel", "io-graph")
GATE_KINDS = ("escalation", "tool_call", "stale_lock", "reconciliation", "acceptance", "limit", "security")
JSON_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}
DEF_KEYS = {"execution", "description", "inputs", "outputs", "steps", "tools", "surfaces"}
STEP_KEYS = {"id", "type", "description", "action", "surface", "arguments", "compensate", "on_error", "gate", "idempotency"}
# RP-0 s4 GateStep is flat: {id, gate: human, prompt, inputs, approvers?, sensitive?, timeout, on_reject, on_expire?, escalation_kind?}
RP0_GATE_STEP_KEYS = {"id", "gate", "prompt", "inputs", "approvers", "sensitive", "timeout", "on_reject", "on_expire", "escalation_kind", "description"}
RUN_FIELDS = ("run_id", "started_by", "project_id", "recipe_id", "version")        # $run.<field> binding root
GATE_KEYS = {"prompt", "inputs", "sensitive", "escalation_kind", "timeout", "on_reject", "on_expire", "approvers"}
MAX_DEFINITION_BYTES = 256 * 1024
MAX_STEPS = 50
HISTORY_CAP = 200
PENDING_ESCALATION_STATUSES = {"requested", "pending", "open", "snoozed"}
APPROVED_ESCALATION_STATUSES = {"approved", "decided", "executing", "applied", "executed"}


@dataclass
class RecipeContext:
    get: Callable[[str, str], Optional[Dict[str, Any]]]
    put: Callable[..., bool]                                   # (project, item, if_absent=False, expect=None) -> ok
    query: Callable[[str, str], List[Dict[str, Any]]]          # (project, sk_prefix) -> items
    mint: Callable[[str], str]                                 # project -> new REC id (server-minted)
    now: Callable[[], str]
    registry: Callable[[], Optional[Dict[str, Set[str]]]]
    escalate: Callable[[str, Dict[str, Any]], Tuple[int, Dict[str, Any]]]
    escalation: Callable[[str, str], Optional[Dict[str, Any]]]
    active_runs: Callable[[str, str, str], int] = lambda project, rec, version: 0


# ----------------------------------------------------------------------------- helpers

def head_key(rec: str) -> str:
    return f"recipe#{rec}"


def version_key(rec: str, version: str) -> str:
    return f"recipe#{rec}@{version}"


def name_key(name: str) -> str:
    return f"recipe-name#{name}"


def canonical(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact, no ASCII escaping (JCS-equivalent for our types)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_content_hash(name: str, version: str, definition: Any) -> str:
    """sha256 over canonical {definition, name, version}; head metadata and status excluded."""
    body = canonical({"definition": definition, "name": name, "version": version})
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def parse_semver(value: Any) -> Optional[Tuple[int, int, int]]:
    m = SEMVER_RE.match(str(value or ""))
    return tuple(int(g) for g in m.groups()) if m else None  # type: ignore[return-value]


def _err(status: int, code: str, message: str, **extra: Any) -> Result:
    return status, {"success": False, "error": message, "error_code": code, **extra}


def _ok(body: Dict[str, Any], status: int = 200) -> Result:
    return status, {"success": True, **body}


def _is_io(actor: str) -> bool:
    return str(actor or "").lower().startswith("io")


def _append_history(head: Dict[str, Any], actor: str, action: str, version: Optional[str], at: str) -> None:
    hist = list(head.get("history") or [])
    hist.append({"actor": actor, "action": action, "version": version, "at": at})
    head["history"] = hist[-HISTORY_CAP:]


def is_rp0_gate(step: Any) -> bool:
    """True for the RP-0 s4 flat GateStep ({id, gate: "human", prompt, ...}); the internal form has a gate object."""
    return isinstance(step, dict) and isinstance(step.get("gate"), str)


def normalize_step(step: Any) -> Any:
    """Internal form of one step, as a copy: the RP-0 s4 GateStep becomes {id, type: gate, gate: {...}}.
    Used at validation and run time only; the stored definition (and its content_hash) is never rewritten."""
    if not is_rp0_gate(step):
        return copy.deepcopy(step)
    out: Dict[str, Any] = {"id": step.get("id"), "type": "gate",
                           "gate": {k: copy.deepcopy(step[k]) for k in GATE_KEYS if k in step}}
    if "description" in step:
        out["description"] = step["description"]
    return out


def normalize_definition(definition: Any) -> Any:
    if not isinstance(definition, dict) or not isinstance(definition.get("steps"), list):
        return copy.deepcopy(definition)
    out = {k: copy.deepcopy(v) for k, v in definition.items() if k != "steps"}
    out["steps"] = [normalize_step(st) for st in definition["steps"]]
    return out


def derive_tools(definition: Dict[str, Any]) -> List[str]:
    tools: Set[str] = set()
    for step in definition.get("steps") or []:
        if not isinstance(step, dict):
            continue
        if isinstance(step.get("action"), str) and step.get("type", "action") == "action":
            tools.add(step["action"])
        comp = step.get("compensate")
        if isinstance(comp, dict) and isinstance(comp.get("action"), str):
            tools.add(comp["action"])
    return sorted(tools)


def edges_for(head: Dict[str, Any], definition: Dict[str, Any], rec: Optional[str]) -> List[Dict[str, Any]]:
    src = rec
    edges = [{"type": "recipe-serves-project", "from": src, "to": p} for p in head.get("project_ids") or []]
    edges += [{"type": "recipe-implements-feature", "from": src, "to": f} for f in head.get("related_feature_ids") or []]
    edges += [{"type": "recipe-uses-tool", "from": src, "to": t} for t in derive_tools(definition or {})]
    return edges


def _head_status(versions: List[Dict[str, Any]], head: Dict[str, Any]) -> str:
    latest = head.get("latest_published")
    if latest:
        return "published"
    if not versions:
        return "draft"
    ordered = sorted(versions, key=lambda v: parse_semver(v.get("version")) or (0, 0, 0))
    return str(ordered[-1].get("status") or "draft")


def _recompute_latest_published(versions: List[Dict[str, Any]]) -> Optional[str]:
    pub = [v["version"] for v in versions if v.get("status") == "published" and parse_semver(v.get("version"))]
    return max(pub, key=parse_semver) if pub else None  # type: ignore[arg-type]


def classify_bump(old: Dict[str, Any], new: Dict[str, Any]) -> str:
    """major = step removed/renamed or required-input/output change; minor = additive; else patch."""
    def step_ids(d):
        return {s.get("id") for s in (d.get("steps") or []) if isinstance(s, dict)}

    def required(d):
        return set(((d.get("inputs") or {}).get("required")) or [])

    def out_req(d):
        return set((((d.get("outputs") or {}).get("schema") or {}).get("required")) or [])

    if step_ids(old) - step_ids(new) or required(old) != required(new) or out_req(old) != out_req(new):
        return "major"
    if step_ids(new) - step_ids(old) or set(((new.get("inputs") or {}).get("properties")) or {}) - \
            set(((old.get("inputs") or {}).get("properties")) or {}):
        return "minor"
    return "patch"


def bump(version: str, kind: str) -> str:
    major, minor, patch = parse_semver(version) or (0, 0, 0)
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


# ----------------------------------------------------------------------------- registry

def load_registry(search_dirs: Optional[List[Path]] = None) -> Optional[Dict[str, Set[str]]]:
    """surface -> action ids from caps.json snapshots; None when the enceladus caps are absent.

    Search order: RECIPE_CAPS_DIR, <module>/recipe_caps, <repo>/tools/enceladus-mcp-server/parity.
    enceladus = <dir>/caps.json; other surfaces = <dir>/surfaces/<surface>.caps.json or <dir>/<surface>.caps.json.
    """
    here = Path(__file__).resolve().parent
    dirs: List[Path] = list(search_dirs or [])
    if not dirs:
        if os.environ.get("RECIPE_CAPS_DIR"):
            dirs.append(Path(os.environ["RECIPE_CAPS_DIR"]))
        dirs.append(here / "recipe_caps")
        dirs.append(here.parent.parent.parent / "tools" / "enceladus-mcp-server" / "parity")
    for base in dirs:
        enc = base / "caps.json"
        if not enc.is_file():
            continue
        registry: Dict[str, Set[str]] = {}
        try:
            registry["enceladus"] = _caps_ids(json.loads(enc.read_text("utf-8")))
        except (OSError, ValueError):
            continue
        for surface in SURFACES[1:]:
            for cand in (base / "surfaces" / f"{surface}.caps.json", base / f"{surface}.caps.json"):
                if cand.is_file():
                    try:
                        registry[surface] = _caps_ids(json.loads(cand.read_text("utf-8")))
                    except (OSError, ValueError):
                        pass
                    break
        return registry
    return None


def _caps_ids(doc: Any) -> Set[str]:
    actions = doc.get("actions") if isinstance(doc, dict) else doc
    ids: Set[str] = set()
    if isinstance(actions, dict):
        return {str(k) for k in actions}
    for a in actions or []:
        if isinstance(a, dict):
            ident = a.get("name") or a.get("id") or a.get("action")
            if ident:
                ids.add(str(ident))
        elif isinstance(a, str):
            ids.add(a)
    return ids


def registry_version(registry: Dict[str, Set[str]]) -> str:
    digest = hashlib.sha256(canonical({s: sorted(v) for s, v in sorted(registry.items())}).encode()).hexdigest()
    return f"sha256:{digest[:16]}"


# ----------------------------------------------------------------------------- bindings

def parse_binding(value: str) -> Optional[Tuple[str, List[str]]]:
    """(root, segments) for a binding string; None when malformed. Caller checks startswith('$')."""
    m = BINDING_RE.match(value)
    if not m:
        return None
    root, rest = m.group("root"), m.group("rest")
    if not rest:
        return root, []
    if rest[0] == ".":
        segs = rest[1:].split(".")
        if any(not s or "/" in s for s in segs):
            return None
        return root, segs
    segs = [s.replace("~1", "/").replace("~0", "~") for s in rest.split("/")[1:]]
    return root, segs


def iter_values(value: Any, path: str) -> Iterator[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict) and set(value) == {"$literal"}:
        return                                   # escape hatch: contents are data, not bindings
    if isinstance(value, dict):
        for k, v in value.items():
            yield from iter_values(v, f"{path}/{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from iter_values(v, f"{path}/{i}")


def _check_bindings(value: Any, path: str, scope: Dict[str, Any], err: Callable[..., None]) -> None:
    for p, v in iter_values(value, path):
        if not isinstance(v, str) or not v.startswith("$") or v.startswith("$$"):
            continue
        parsed = parse_binding(v)
        if parsed is None:
            err(p, "BINDING_MALFORMED", f"'{v}' is not a whole-value binding ($root.path or $root/pointer).")
            continue
        root, segs = parsed
        visible = scope["visible"]
        if root.isdigit():                                       # RP-0 N index alias: 0-based position in steps
            order = scope.get("order") or []
            if int(root) >= len(order) or not order[int(root)]:
                err(p, "UNKNOWN_BINDING_ROOT", f"'{v}': index alias {root} is outside the {len(order)} steps.")
                continue
            root = order[int(root)]
        if root == "run":
            if not segs or segs[0] not in RUN_FIELDS:
                err(p, "BINDING_UNRESOLVED", f"'{v}': $run exposes only {list(RUN_FIELDS)}.")
        elif root == "inputs":
            props = scope["input_props"]
            if segs and props is not None and segs[0] not in props:
                err(p, "UNKNOWN_INPUT", f"'{v}' references input '{segs[0]}' that inputs.properties does not declare.")
        elif root in visible:
            info = visible[root]
            if info["type"] == "gate":
                if not segs or segs[0] not in ("inputs", "decision"):
                    err(p, "BINDING_UNRESOLVED", f"'{v}': a gate exposes only .inputs.* and .decision.")
                elif segs[0] == "inputs":
                    gprops = info["gate_props"]
                    if gprops is None:
                        err(p, "BINDING_UNRESOLVED", f"'{v}': gate '{root}' declares no inputs schema.")
                    elif len(segs) > 1 and segs[1] not in gprops:
                        err(p, "BINDING_UNRESOLVED", f"'{v}': gate '{root}' declares no input '{segs[1]}'.")
        elif root == scope.get("self_id") and scope.get("allow_self"):
            continue
        elif root in scope["all_ids"]:
            err(p, "FORWARD_REFERENCE", f"'{v}' references step '{root}' which does not run before it.")
        else:
            err(p, "UNKNOWN_BINDING_ROOT", f"'{v}': '{root}' is neither 'inputs' nor an earlier step id.")


# ----------------------------------------------------------------------------- static validation

def _check_json_schema_object(schema: Any, path: str, err: Callable[..., None]) -> Optional[Set[str]]:
    """Light JSONSchema7 object check; returns the property-name set (None when schema is absent)."""
    if schema is None:
        return None
    if not isinstance(schema, dict) or schema.get("type") != "object":
        err(path, "SCHEMA_INVALID", "must be a JSON Schema object with type 'object'.")
        return None
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        err(f"{path}/properties", "SCHEMA_INVALID", "properties must be an object.")
        return set()
    for name, sub in props.items():
        if not isinstance(sub, dict):
            err(f"{path}/properties/{name}", "SCHEMA_INVALID", "each property needs its own schema object.")
            continue
        typ = sub.get("type")
        types = typ if isinstance(typ, list) else [typ] if typ is not None else []
        if any(t not in JSON_TYPES for t in types):
            err(f"{path}/properties/{name}/type", "SCHEMA_INVALID", f"unknown JSON Schema type {typ!r}.")
        if isinstance(sub.get("pattern"), str):
            try:
                re.compile(sub["pattern"])
            except re.error as exc:
                err(f"{path}/properties/{name}/pattern", "SCHEMA_INVALID", f"invalid pattern: {exc}.")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(r not in props for r in required):
        err(f"{path}/required", "SCHEMA_INVALID", "required[] must list declared properties only.")
    return set(props)


def _check_action_ref(action: Any, surface: Any, path: str, surfaces: Optional[List[str]],
                      registry: Optional[Dict[str, Set[str]]], err: Callable[..., None]) -> None:
    if not isinstance(action, str) or not action.strip():
        err(f"{path}/action", "ACTION_REQUIRED", "action must be a non-empty capability id.")
        return
    if registry is None:
        err(f"{path}/action", "REGISTRY_UNAVAILABLE", "the capability registry is not loaded; cannot validate.")
        return
    if surface is not None and surface not in SURFACES:
        err(f"{path}/surface", "UNKNOWN_SURFACE", f"surface must be one of {list(SURFACES)}.")
        return
    candidates = [surface] if surface else list(surfaces or registry.keys())
    if any(action in registry.get(s, ()) for s in candidates):
        return
    unloaded = [s for s in candidates if s not in registry]
    hint = f" (registry not loaded for {unloaded})" if unloaded else ""
    err(f"{path}/action", "UNKNOWN_ACTION", f"'{action}' is not a registered capability on {candidates}{hint}.")


def validate_definition(definition: Any, registry: Optional[Dict[str, Set[str]]]) -> List[Dict[str, str]]:
    """Static validation (spec s6 draft>validated). Returns [] when the definition is valid."""
    errors: List[Dict[str, str]] = []

    def err(path: str, code: str, message: str) -> None:
        errors.append({"path": path or "/", "code": code, "message": message})

    if not isinstance(definition, dict):
        err("", "SHAPE", "definition must be an object.")
        return errors
    for key in definition:
        if key not in DEF_KEYS:
            err(f"/{key}", "UNKNOWN_KEY", f"unknown definition key '{key}'.")
    if definition.get("execution", "deterministic") != "deterministic":
        err("/execution", "EXECUTION_NOT_SUPPORTED", "only 'deterministic' execution is supported in v1 (delegated is reserved).")
    if "description" in definition and not isinstance(definition["description"], str):
        err("/description", "SHAPE", "description must be a string.")
    surfaces = definition.get("surfaces")
    if surfaces is not None:
        if not isinstance(surfaces, list) or any(s not in SURFACES for s in surfaces):
            err("/surfaces", "UNKNOWN_SURFACE", f"surfaces must be a subset of {list(SURFACES)}.")
            surfaces = None

    input_props = _check_json_schema_object(definition.get("inputs"), "/inputs", err)
    steps = definition.get("steps")
    if not isinstance(steps, list) or not steps:
        err("/steps", "STEPS_REQUIRED", "steps must be a non-empty array.")
        return errors
    if len(steps) > MAX_STEPS:
        err("/steps", "TOO_MANY_STEPS", f"at most {MAX_STEPS} steps.")

    all_ids = [s.get("id") for s in steps if isinstance(s, dict) and isinstance(s.get("id"), str)]
    order = [st.get("id") if isinstance(st, dict) and isinstance(st.get("id"), str) else None for st in steps]
    visible: Dict[str, Dict[str, Any]] = {}
    seen: Set[str] = set()
    for i, step in enumerate(steps):
        path = f"/steps/{i}"
        if not isinstance(step, dict):
            err(path, "SHAPE", "a step must be an object.")
            continue
        rp0 = is_rp0_gate(step)
        for key in step:
            if key not in (RP0_GATE_STEP_KEYS if rp0 else STEP_KEYS):
                err(f"{path}/{key}", "UNKNOWN_KEY", f"unknown step key '{key}'.")
        sid = step.get("id")
        if not isinstance(sid, str) or not STEP_ID_RE.match(sid) or sid in ("inputs", "decision", "run"):
            err(f"{path}/id", "STEP_ID_INVALID", "step id must match ^[a-z][a-z0-9_-]{0,62}$ and not be 'inputs'.")
            sid = None
        elif sid in seen:
            err(f"{path}/id", "STEP_ID_DUPLICATE", f"step id '{sid}' is used twice.")
        scope = {"visible": visible, "all_ids": set(all_ids), "input_props": input_props,
                 "self_id": sid, "allow_self": False, "order": order}
        stype = "gate" if rp0 else step.get("type", "action")
        if stype == "action":
            if "gate" in step:
                err(f"{path}/gate", "SHAPE", "exactly one of action or gate.")
            if "idempotency" in step and step["idempotency"] not in ("at_least_once", "at_most_once"):
                err(f"{path}/idempotency", "SHAPE", "idempotency must be at_least_once or at_most_once.")
            _check_action_ref(step.get("action"), step.get("surface"), path, surfaces, registry, err)
            args = step.get("arguments", {})
            if not isinstance(args, dict):
                err(f"{path}/arguments", "SHAPE", "arguments must be an object.")
            else:
                _check_bindings(args, f"{path}/arguments", scope, err)
            if step.get("on_error", "abort") not in ("abort", "continue"):
                err(f"{path}/on_error", "ON_ERROR_UNSUPPORTED", "on_error must be abort (reverse compensate) or continue.")
            comp = step.get("compensate")
            if comp is not None:
                if not isinstance(comp, dict) or set(comp) - {"action", "surface", "arguments"}:
                    err(f"{path}/compensate", "SHAPE", "compensate must be {action, arguments?, surface?}.")
                else:
                    _check_action_ref(comp.get("action"), comp.get("surface"), f"{path}/compensate", surfaces, registry, err)
                    cscope = dict(scope, allow_self=True)
                    cargs = comp.get("arguments", {})
                    if not isinstance(cargs, dict):
                        err(f"{path}/compensate/arguments", "SHAPE", "arguments must be an object.")
                    else:
                        _check_bindings(cargs, f"{path}/compensate/arguments", cscope, err)
            if sid:
                visible[sid] = {"type": "action", "gate_props": None}
        elif stype == "gate":
            gate = step if rp0 else step.get("gate")
            gpath = path if rp0 else f"{path}/gate"
            gprops: Optional[Set[str]] = None
            if not isinstance(gate, dict):
                err(gpath, "GATE_REQUIRED", "a gate step needs a gate object.")
            else:
                if rp0 and step.get("gate") != "human":
                    err(f"{path}/gate", "GATE_REQUIRED", "a gate step is {gate: human, prompt, ...}.")
                for key in ([] if rp0 else gate):
                    if key not in GATE_KEYS:
                        err(f"{gpath}/{key}", "UNKNOWN_KEY", f"unknown gate key '{key}'.")
                if not (isinstance(gate.get("prompt"), str) and gate["prompt"].strip()):
                    err(f"{gpath}/prompt", "GATE_PROMPT_REQUIRED", "gate.prompt must be a non-empty string.")
                if gate.get("escalation_kind", "acceptance") not in GATE_KINDS:
                    err(f"{gpath}/escalation_kind", "GATE_KIND_INVALID", f"escalation_kind must be one of {list(GATE_KINDS)}.")
                if "sensitive" in gate and not isinstance(gate["sensitive"], bool):
                    err(f"{gpath}/sensitive", "SHAPE", "sensitive must be a boolean.")
                tmo = gate.get("timeout")
                if tmo is not None and not (isinstance(tmo, dict) and isinstance(tmo.get("seconds"), int)
                                            and not isinstance(tmo.get("seconds"), bool) and 1 <= tmo["seconds"] <= 2592000):
                    err(f"{gpath}/timeout", "SHAPE", "timeout must be {seconds: 1..2592000}.")
                if gate.get("on_reject", "failed") not in ("failed", "cancelled"):
                    err(f"{gpath}/on_reject", "SHAPE", "on_reject must be failed or cancelled.")
                if gate.get("on_expire", "expired") not in ("expired", "failed", "cancelled"):
                    err(f"{gpath}/on_expire", "SHAPE", "on_expire must be expired, failed or cancelled.")
                if rp0 and tmo is None:
                    err(f"{gpath}/timeout", "SHAPE", "timeout {seconds} is required on a gate step.")
                apv = gate.get("approvers")
                if apv is not None and not (isinstance(apv, list) and all(isinstance(x, str) and x for x in apv)):
                    err(f"{gpath}/approvers", "SHAPE", "approvers must be an array of principals.")
                gprops = _check_json_schema_object(gate.get("inputs"), f"{gpath}/inputs", err)
            for forbidden in ("action", "arguments", "compensate", "on_error", "idempotency"):
                if forbidden in step:
                    err(f"{path}/{forbidden}", "SHAPE", f"a gate step cannot carry '{forbidden}'.")
            if sid:
                visible[sid] = {"type": "gate", "gate_props": gprops}
        else:
            err(f"{path}/type", "STEP_TYPE_INVALID", "step type must be 'action' or 'gate'.")
        if sid:
            seen.add(sid)

    derived = derive_tools(definition)
    tools = definition.get("tools")
    if not isinstance(tools, list) or any(not isinstance(t, str) for t in tools):
        err("/tools", "TOOLS_MISMATCH", f"tools must equal the derived set {derived}.")
    elif set(tools) != set(derived) or len(tools) != len(set(tools)):
        missing = sorted(set(derived) - set(tools))
        extra = sorted(set(tools) - set(derived))
        err("/tools", "TOOLS_MISMATCH", f"tools must equal the set derived from step and compensate actions (missing {missing}, extra {extra}).")

    outputs = definition.get("outputs")
    if outputs is not None:
        if not isinstance(outputs, dict) or set(outputs) - {"schema", "from"}:
            err("/outputs", "SHAPE", "outputs must be {schema, from}.")
        else:
            oprops = _check_json_schema_object(outputs.get("schema"), "/outputs/schema", err)
            frm = outputs.get("from", {})
            if not isinstance(frm, dict):
                err("/outputs/from", "SHAPE", "from must map output fields to bindings.")
                frm = {}
            for field, binding in frm.items():
                if not (isinstance(binding, str) and binding.startswith("$") and not binding.startswith("$$")):
                    err(f"/outputs/from/{field}", "BINDING_REQUIRED", "an output binding must be a whole-value '$...' reference.")
                if oprops is not None and field not in oprops:
                    err(f"/outputs/from/{field}", "SCHEMA_INVALID", f"'{field}' is not a declared output property.")
            for req in ((outputs.get("schema") or {}).get("required") or []):
                if req not in frm:
                    err(f"/outputs/from/{req}", "OUTPUT_UNBOUND", f"required output '{req}' has no binding.")
            oscope = {"visible": visible, "all_ids": set(all_ids), "input_props": input_props, "self_id": None, "allow_self": False}
            _check_bindings(frm, "/outputs/from", oscope, err)
    return errors


# ----------------------------------------------------------------------------- loaders

def _load_version(ctx: RecipeContext, project_id: str, body: Dict[str, Any]):
    rec = str(body.get("recipe_id") or "").strip()
    ver = str(body.get("version") or "").strip()
    if not REC_ID_RE.match(rec):
        return None, None, None, _err(400, "VALIDATION_FAILED", "recipe_id is required (for example DVP-REC-001).")
    if not parse_semver(ver):
        return None, None, None, _err(400, "VALIDATION_FAILED", "version is required and must be semver (x.y.z).")
    item = ctx.get(project_id, version_key(rec, ver))
    if not item:
        return None, None, None, _err(404, "NOT_FOUND", f"Recipe version not found: {rec}@{ver}")
    return rec, ver, item, None


def _versions(ctx: RecipeContext, project_id: str, rec: str) -> List[Dict[str, Any]]:
    items = [i for i in ctx.query(project_id, f"recipe#{rec}@") if i.get("record_kind") == "version"]
    return sorted(items, key=lambda v: parse_semver(v.get("version")) or (0, 0, 0))


def _save(ctx: RecipeContext, project_id: str, item: Dict[str, Any]) -> bool:
    rev = int(item.get("rev") or 0)
    new = dict(item, rev=rev + 1, updated_at=ctx.now())
    ok = ctx.put(project_id, new, expect=("rev", rev) if rev else None)
    if ok:
        item.update(new)
    return ok


def _hash_ok(item: Dict[str, Any]) -> bool:
    return compute_content_hash(item.get("name"), item.get("version"), item.get("definition")) == item.get("content_hash")


# ----------------------------------------------------------------------------- create

def create(ctx: RecipeContext, project_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    name = str(body.get("name") or "").strip()
    definition = body.get("definition")
    problems: List[str] = []
    if not NAME_RE.match(name):
        problems.append("name must match ^[a-z][a-z0-9-]{2,62}$")
    if not isinstance(definition, dict) or not definition:
        problems.append("definition must be a non-empty object")
    elif len(canonical(definition).encode("utf-8")) > MAX_DEFINITION_BYTES:
        problems.append(f"definition exceeds {MAX_DEFINITION_BYTES} bytes")
    for field in ("tags", "project_ids", "related_feature_ids"):
        val = body.get(field)
        if val is not None and (not isinstance(val, list) or any(not isinstance(x, str) or not x.strip() for x in val)):
            problems.append(f"{field} must be an array of non-empty strings")
    if not body.get("project_ids"):
        problems.append("project_ids is required (projects served; the home project is added)")
    if body.get("version") is not None and not parse_semver(body["version"]):
        problems.append("version must be semver (x.y.z)")
    if problems:
        return _err(400, "VALIDATION_FAILED", "; ".join(problems), errors=problems)

    now = ctx.now()
    project_ids = list(dict.fromkeys([project_id] + [p.strip() for p in body.get("project_ids") or []]))
    rec = str(body.get("recipe_id") or "").strip()
    if rec and not REC_ID_RE.match(rec):
        return _err(400, "VALIDATION_FAILED", "recipe_id is malformed.")

    # ---- new recipe -------------------------------------------------------------------
    if not rec:
        version = str(body.get("version") or "1.0.0")
        if ctx.get(project_id, name_key(name)):
            return _err(409, "VALIDATION_FAILED", f"A recipe named '{name}' already exists in this project.", field="name")
        chash = compute_content_hash(name, version, definition)
        head = {"record_id": None, "item_id": None, "record_type": "recipe", "record_kind": "head", "recipe_id": None,
                "name": name, "owner": str(body.get("owner") or actor), "tags": list(body.get("tags") or []),
                "project_ids": project_ids, "related_feature_ids": list(body.get("related_feature_ids") or []),
                "latest_published": None, "status": "draft", "history": [], "rev": 1,
                "created_at": now, "updated_at": now, "created_by": actor}
        if dry_run:
            return _ok({"recipe_id": None, "version": version, "status": "draft", "content_hash": chash, "name": name,
                        "dry_run": True,
                        "would_do": {"mint": "recipe", "puts": [name_key(name), "recipe#<minted>", "recipe#<minted>@" + version],
                                     "edges": edges_for(head, definition, None)}})
        rec = ctx.mint(project_id)
        head.update(recipe_id=rec, item_id=rec, record_id=head_key(rec))
        _append_history(head, actor, "create", version, now)
        if not ctx.put(project_id, {"record_id": name_key(name), "item_id": name_key(name), "record_type": "recipe",
                                    "record_kind": "name", "recipe_id": rec, "name": name, "created_at": now}, if_absent=True):
            return _err(409, "VALIDATION_FAILED", f"A recipe named '{name}' already exists in this project.", field="name")
        ctx.put(project_id, head, if_absent=True)
        ver_item = _new_version_item(rec, name, version, definition, chash, None, now, actor)
        ctx.put(project_id, ver_item, if_absent=True)
        return _ok({"recipe_id": rec, "version": version, "status": "draft", "content_hash": chash, "name": name,
                    "created": True}, 201)

    # ---- existing recipe: replace a draft or add a version -----------------------------
    head = ctx.get(project_id, head_key(rec))
    if not head:
        return _err(404, "NOT_FOUND", f"Recipe not found: {rec}")
    if name != head.get("name"):
        return _err(400, "VALIDATION_FAILED", "name is immutable.", field="name")
    versions = _versions(ctx, project_id, rec)
    existing = {v["version"]: v for v in versions}
    owner = str(body.get("owner") or head.get("owner") or actor)
    if owner != head.get("owner") and not (actor == head.get("owner") or _is_io(actor)):
        return _err(403, "NOT_AUTHORIZED", "Only the owner or io may change the owner.")

    version = str(body.get("version") or "")
    if not version:
        open_drafts = [v for v in versions if v["status"] in ("draft", "validated")]
        if open_drafts:
            version = open_drafts[-1]["version"]
        else:
            base = versions[-1] if versions else {"version": "0.0.0", "definition": {}}
            version = bump(base["version"], classify_bump(base.get("definition") or {}, definition))
    chash = compute_content_hash(name, version, definition)
    target = existing.get(version)
    if target is not None:
        if target["status"] not in ("draft", "validated"):
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{version} is {target['status']} and immutable; create a new version.")
        if target["status"] == "validated" and not (actor == head.get("owner") or _is_io(actor)):
            return _err(403, "NOT_AUTHORIZED", "Editing a validated version is limited to the owner or io.")
        supersedes = target.get("supersedes")
    else:
        newest = versions[-1]["version"] if versions else None
        if newest and parse_semver(version) <= parse_semver(newest):  # type: ignore[operator]
            return _err(409, "ILLEGAL_TRANSITION", f"version {version} must be greater than the newest version {newest}.")
        supersedes = head.get("latest_published") or newest
    if dry_run:
        return _ok({"recipe_id": rec, "version": version, "status": "draft", "content_hash": chash, "name": name,
                    "dry_run": True, "replaces_draft": target is not None,
                    "would_do": {"puts": [head_key(rec), version_key(rec, version)],
                                 "edges": edges_for(dict(head, project_ids=project_ids), definition, rec)}})

    ver_item = _new_version_item(rec, name, version, definition, chash, supersedes, now, actor)
    if target is not None:
        ver_item.update(created_at=target.get("created_at", now), created_by=target.get("created_by", actor),
                        rev=int(target.get("rev") or 0))
        if not _save(ctx, project_id, ver_item):
            return _err(409, "CONFLICT", f"{rec}@{version} changed concurrently; retry.")
    else:
        if not ctx.put(project_id, ver_item, if_absent=True):
            return _err(409, "CONFLICT", f"{rec}@{version} already exists.")
    head.update(owner=owner, project_ids=project_ids if body.get("project_ids") else head.get("project_ids"),
                tags=list(body["tags"]) if body.get("tags") is not None else head.get("tags", []),
                related_feature_ids=(list(body["related_feature_ids"]) if body.get("related_feature_ids") is not None
                                     else head.get("related_feature_ids", [])))
    _append_history(head, actor, "replace_draft" if target is not None else "new_version", version, now)
    head["status"] = _head_status(_versions(ctx, project_id, rec), head)
    if not _save(ctx, project_id, head):
        return _err(409, "CONFLICT", f"Recipe {rec} changed concurrently; retry.")
    return _ok({"recipe_id": rec, "version": version, "status": "draft", "content_hash": chash, "name": name,
                "created": target is None, "replaced_draft": target is not None}, 201 if target is None else 200)


def _new_version_item(rec, name, version, definition, chash, supersedes, now, actor) -> Dict[str, Any]:
    return {"record_id": version_key(rec, version), "item_id": f"{rec}@{version}", "record_type": "recipe",
            "record_kind": "version", "recipe_id": rec, "name": name, "version": version, "status": "draft",
            "content_hash": chash, "supersedes": supersedes, "validation": None, "publish_escalation_id": None,
            "deprecation": None, "definition": definition, "rev": 1, "created_at": now, "updated_at": now,
            "created_by": actor}


# ----------------------------------------------------------------------------- get / list

def get(ctx: RecipeContext, project_id: str, rec: str, version: Optional[str] = None) -> Result:
    if not REC_ID_RE.match(rec or ""):
        return _err(400, "VALIDATION_FAILED", "recipe_id is malformed.")
    head = ctx.get(project_id, head_key(rec))
    if not head:
        return _err(404, "NOT_FOUND", f"Recipe not found: {rec}")
    versions = _versions(ctx, project_id, rec)
    chosen = None
    if version:
        if not parse_semver(version):
            return _err(400, "VALIDATION_FAILED", "version must be semver (x.y.z).")
        chosen = next((v for v in versions if v["version"] == version), None)
        if chosen is None:
            return _err(404, "NOT_FOUND", f"Recipe version not found: {rec}@{version}")
    elif head.get("latest_published"):
        chosen = next((v for v in versions if v["version"] == head["latest_published"]), None)
    return _ok({"head": head, "version": chosen,
                "resolved": "version" if version else ("latest_published" if chosen else "none"),
                "versions": [{"version": v["version"], "status": v["status"], "content_hash": v["content_hash"]} for v in versions]})


def list_recipes(ctx: RecipeContext, project_id: str, query: Dict[str, Any]) -> Result:
    try:
        limit = max(1, min(200, int(query.get("limit") or 50)))
    except (TypeError, ValueError):
        return _err(400, "VALIDATION_FAILED", "limit must be an integer.")
    items = ctx.query(project_id, "recipe#")
    heads = [i for i in items if i.get("record_kind") == "head"]
    by_rec: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        if it.get("record_kind") == "version":
            by_rec.setdefault(it["recipe_id"], []).append(it)
    serves = str(query.get("serves_project_id") or "").strip()
    status = str(query.get("status") or "").strip()
    tag = str(query.get("tag") or "").strip()
    text = str(query.get("query") or "").strip().lower()
    out = []
    for h in sorted(heads, key=lambda x: x.get("recipe_id", "")):
        vs = by_rec.get(h["recipe_id"], [])
        if serves and serves not in (h.get("project_ids") or []):
            continue
        if status and status != h.get("status") and status not in {v.get("status") for v in vs}:
            continue
        if tag and tag not in (h.get("tags") or []):
            continue
        if text and text not in " ".join([h.get("name", ""), h.get("recipe_id", "")] + list(h.get("tags") or [])).lower():
            continue
        out.append({"recipe_id": h["recipe_id"], "name": h.get("name"), "owner": h.get("owner"), "status": h.get("status"),
                    "tags": h.get("tags") or [], "project_ids": h.get("project_ids") or [],
                    "latest_published": h.get("latest_published"), "version_count": len(vs),
                    "updated_at": h.get("updated_at")})
    return _ok({"items": out[:limit], "count": min(len(out), limit), "truncated": len(out) > limit})


# ----------------------------------------------------------------------------- validate

def validate(ctx: RecipeContext, project_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    rec, ver, item, error = _load_version(ctx, project_id, body)
    if error:
        return error
    if not _hash_ok(item):
        return _err(409, "PIN_MISMATCH", "content_hash does not match the stored definition.", recipe_id=rec, version=ver)
    registry = ctx.registry()
    errors = validate_definition(item.get("definition"), registry)
    if registry is None and not any(e["code"] == "REGISTRY_UNAVAILABLE" for e in errors):
        errors.append({"path": "/", "code": "REGISTRY_UNAVAILABLE", "message": "the capability registry is not loaded."})
    ok = not errors
    status = item["status"]
    validation = {"registry_version": registry_version(registry) if registry else None,
                  "governance_hash": str(body.get("governance_hash") or ""), "validated_at": ctx.now(), "errors": errors}
    if status in ("draft", "validated"):
        status = "validated" if ok else "draft"
    result = {"ok": ok, "errors": errors, "status": status, "recipe_id": rec, "version": ver,
              "content_hash": item["content_hash"], "validation": validation}
    if dry_run:
        return _ok(dict(result, dry_run=True, would_do={"puts": [version_key(rec, ver)], "status": status}))
    if item["status"] in ("draft", "validated"):
        item["status"] = status
        item["validation"] = validation
        if not _save(ctx, project_id, item):
            return _err(409, "CONFLICT", f"{rec}@{ver} changed concurrently; retry.")
        head = ctx.get(project_id, head_key(rec))
        if head:
            _append_history(head, actor, "validate_ok" if ok else "validate_failed", ver, validation["validated_at"])
            head["status"] = _head_status(_versions(ctx, project_id, rec), head)
            _save(ctx, project_id, head)
    return _ok(result)


# ----------------------------------------------------------------------------- hub gate

def _gate_request(project_id: str, rec: str, item: Dict[str, Any], target: str, rationale: str) -> Dict[str, Any]:
    call = {"capability": f"recipe.{'publish' if target == 'published' else 'retire'}",
            "mcpTool": "recipe_publish_request" if target == "published" else "recipe_deprecate",
            "method": "POST", "path": f"/api/v1/tracker/{project_id}/recipe/{rec}/apply",
            "args": {"version": item["version"], "target": target, "content_hash": item["content_hash"]},
            "annotations": {"readOnlyHint": False, "destructiveHint": target == "retired", "idempotentHint": True},
            "ifMatch": item["content_hash"]}
    call["callHash"] = hashlib.sha256(canonical(call).encode("utf-8")).hexdigest()
    verb = "Publish" if target == "published" else "Retire"
    return {"source_principal": SOURCE_PRINCIPAL, "kind": "acceptance",
            "title": f"{verb} recipe {item.get('name')} ({rec}@{item['version']})",
            "justification": rationale,
            "subject": {"type": "recipe_version", "record_id": rec, "version": item["version"], "target": target,
                        "content_hash": item["content_hash"]},
            "proposedCalls": [call]}


def _file_gate(ctx: RecipeContext, project_id: str, rec: str, item: Dict[str, Any], target: str,
               rationale: str, field: str, actor: str, dry_run: bool) -> Result:
    existing = item.get(field)
    if existing:
        esc = ctx.escalation(project_id, existing)
        if esc and str(esc.get("status") or "").lower() in PENDING_ESCALATION_STATUSES:
            return _ok({"escalation_id": existing, "status": "pending", "recipe_id": rec, "version": item["version"],
                        "target": target, "reused": True})
    request = _gate_request(project_id, rec, item, target, rationale)
    if dry_run:
        return _ok({"escalation_id": None, "status": "pending", "recipe_id": rec, "version": item["version"],
                    "target": target, "dry_run": True, "would_do": {"escalation": request}})
    code, resp = ctx.escalate(project_id, request)
    esc_id = (resp or {}).get("escalation_id")
    if code >= 300 or not esc_id:
        return _err(502, "GATE_FAILED", f"The hub refused the request ({code}): {(resp or {}).get('error', 'no escalation id')}")
    item[field] = esc_id
    if not _save(ctx, project_id, item):
        return _err(409, "CONFLICT", f"{rec}@{item['version']} changed concurrently; escalation {esc_id} was filed, retry to bind it.")
    head = ctx.get(project_id, head_key(rec))
    if head:
        _append_history(head, actor, f"{target}_requested", item["version"], ctx.now())
        _save(ctx, project_id, head)
    return _ok({"escalation_id": esc_id, "status": "pending", "recipe_id": rec, "version": item["version"], "target": target}, 202)


def publish_request(ctx: RecipeContext, project_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    rec, ver, item, error = _load_version(ctx, project_id, body)
    if error:
        return error
    rationale = str(body.get("rationale") or "").strip()
    if not rationale:
        return _err(400, "VALIDATION_FAILED", "rationale is required.")
    if item["status"] != "validated":
        return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} is {item['status']}; only a validated version can be published.")
    if not _hash_ok(item):
        return _err(409, "PIN_MISMATCH", "content_hash does not match the stored definition.")
    if body.get("content_hash") and body["content_hash"] != item["content_hash"]:
        return _err(409, "PIN_MISMATCH", "content_hash does not match the pinned hash.")
    return _file_gate(ctx, project_id, rec, item, "published", rationale, "publish_escalation_id", actor, dry_run)


# ----------------------------------------------------------------------------- deprecate

def deprecate(ctx: RecipeContext, project_id: str, body: Dict[str, Any], actor: str, dry_run: bool = False) -> Result:
    rec, ver, item, error = _load_version(ctx, project_id, body)
    if error:
        return error
    reason = str(body.get("reason") or "").strip()
    if not reason:
        return _err(400, "VALIDATION_FAILED", "reason is required.")
    target = str(body.get("target") or "deprecated")
    if target not in ("deprecated", "retired"):
        return _err(400, "VALIDATION_FAILED", "target must be 'deprecated' or 'retired'.")
    if target == "retired":
        if item["status"] not in ("published", "deprecated"):
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} is {item['status']}; only published or deprecated can be retired.")
        if ctx.active_runs(project_id, rec, ver):
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} has non-terminal pinned runs; retirement requires zero.")
        res = _file_gate(ctx, project_id, rec, item, "retired", reason, "retire_escalation_id", actor, dry_run)
        if res[0] < 300:
            res[1]["status"] = item["status"]
        return res
    if item["status"] != "published":
        return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} is {item['status']}; only a published version can be deprecated.")
    replaced_by = body.get("replaced_by")
    if dry_run:
        return _ok({"status": "deprecated", "recipe_id": rec, "version": ver, "escalation_id": None, "dry_run": True,
                    "would_do": {"puts": [version_key(rec, ver), head_key(rec)], "recompute": "latest_published"}})
    now = ctx.now()
    item["status"] = "deprecated"
    item["deprecation"] = {"reason": reason, "replaced_by": replaced_by, "at": now, "by": actor}
    if not _save(ctx, project_id, item):
        return _err(409, "CONFLICT", f"{rec}@{ver} changed concurrently; retry.")
    _refresh_head(ctx, project_id, rec, actor, "deprecate", ver)
    return _ok({"status": "deprecated", "recipe_id": rec, "version": ver})


def _refresh_head(ctx: RecipeContext, project_id: str, rec: str, actor: str, action: str, version: str) -> None:
    head = ctx.get(project_id, head_key(rec))
    if not head:
        return
    versions = _versions(ctx, project_id, rec)
    head["latest_published"] = _recompute_latest_published(versions)
    head["status"] = _head_status(versions, head)
    _append_history(head, actor, action, version, ctx.now())
    _save(ctx, project_id, head)


# ----------------------------------------------------------------------------- applier hook

def apply_decision(ctx: RecipeContext, project_id: str, rec: str, body: Dict[str, Any], actor: str) -> Result:
    """Recipe-service apply hook behind the hub's recipe_version applier.

    Moves a version validated->published or published|deprecated->retired ONLY from an
    approved hub escalation whose subject names this exact record, version and hash.
    """
    esc_id = str(body.get("escalation_id") or "").strip()
    if not esc_id or not REC_ID_RE.match(rec or ""):
        return _err(400, "VALIDATION_FAILED", "recipe_id and escalation_id are required.")
    esc = ctx.escalation(project_id, esc_id)
    if not esc:
        return _err(404, "NOT_FOUND", f"Escalation not found: {esc_id}")
    subject = esc.get("subject") if isinstance(esc.get("subject"), dict) else {}
    if subject.get("type") != "recipe_version" or subject.get("record_id") != rec:
        return _err(403, "NOT_AUTHORIZED", "The escalation does not name this recipe.")
    if str(esc.get("sourcePrincipal") or esc.get("source_principal") or "") != SOURCE_PRINCIPAL:
        return _err(403, "NOT_AUTHORIZED", "The escalation was not filed by the recipe service.")
    if str(esc.get("status") or "").lower() not in APPROVED_ESCALATION_STATUSES:
        return _err(409, "NOT_AUTHORIZED", f"Escalation {esc_id} is {esc.get('status')!r}, not approved; nothing is applied.")
    ver = str(subject.get("version") or "")
    target = str(subject.get("target") or "")
    if target not in ("published", "retired") or not parse_semver(ver):
        return _err(400, "VALIDATION_FAILED", "The escalation subject has no valid version/target.")
    item = ctx.get(project_id, version_key(rec, ver))
    if not item:
        return _err(404, "NOT_FOUND", f"Recipe version not found: {rec}@{ver}")
    if not _hash_ok(item) or subject.get("content_hash") != item["content_hash"]:
        return _err(409, "PIN_MISMATCH", "The approved content_hash no longer matches the version.")
    field = "publish_escalation_id" if target == "published" else "retire_escalation_id"
    if item.get(field) != esc_id:
        return _err(403, "NOT_AUTHORIZED", f"{esc_id} is not the escalation bound to {rec}@{ver}.")
    if item["status"] == target:
        return _ok({"status": target, "recipe_id": rec, "version": ver, "idempotent": True})
    now = ctx.now()
    if target == "published":
        if item["status"] != "validated":
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} is {item['status']}; only validated can be published.")
        item.update(status="published", published_at=now, approved_by=str(body.get("decider") or actor))
    else:
        if item["status"] not in ("published", "deprecated"):
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} is {item['status']}; cannot retire.")
        if ctx.active_runs(project_id, rec, ver):
            return _err(409, "ILLEGAL_TRANSITION", f"{rec}@{ver} has non-terminal pinned runs; retirement requires zero.")
        item.update(status="retired", retired_at=now, approved_by=str(body.get("decider") or actor))
    if not _save(ctx, project_id, item):
        return _err(409, "CONFLICT", f"{rec}@{ver} changed concurrently; retry.")
    _refresh_head(ctx, project_id, rec, actor, "published" if target == "published" else "retired", ver)
    return _ok({"status": target, "recipe_id": rec, "version": ver})
