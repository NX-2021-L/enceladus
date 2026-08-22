#!/usr/bin/env python3
"""elr_validate.py -- ELR three-layer pre-flight validation gate.

Implements DOC-F2CF625B7556 section 4a. Simulates, in local code, the dry
run an agent currently performs mentally before calling MCP -- so a
missing required field or a bad enum value costs a local refusal instead
of a rejected governed round trip.

Three layers, cheapest first:

  Layer 1 -- Live governance dictionary (DOC-65129AF350D0), pulled fresh
             each process via a dedicated scoped read-only key (or the
             session's internal-key fallback), never hardcoded. Validates
             enum membership, type conformance, constraints (min_length,
             min_items, pattern, required_keys), and the nested
             transition_evidence.<x>.required_fields shapes that ARE
             dictionary-encoded.

  Layer 2 -- Empirical contract overlay (elr_contracts.json). Applied
             ONLY where Layer 1 is silent (Layer 1 precedence). Entries
             flagged dictionary_derivable are logged as redundant, not
             re-enforced, once Layer 1 already covers the same ground.

  Layer 3 -- Structured error-envelope learning (`learn` subcommand).
             Parses a platform api.error_envelope / document_api
             error_envelope verbatim and emits a proposed_overlay_entry
             for io/agent review. Never auto-writes into
             elr_contracts.json.

HARD REFUSAL RULE: if the dictionary cannot be pulled, or inputs are
missing/invalid, ELR refuses -- digest {ok: false, refusal: {...}}
mirroring the platform's own error envelope shape. The call is never
described as forwardable. An unavailable OVERLAY file is NOT a refusal
condition: elr-validate proceeds Layer-1-only with an
"overlay-unavailable" anomaly (spec: overlay gaps never block).

Python 3.11 standard library only -- no pip dependencies. Nothing here
imports server.py; ELR must run standalone on any workstation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Allow running this file directly without tools/elr already on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from elr_lib import config as elr_config  # noqa: E402
from elr_lib import transport as elr_transport  # noqa: E402
from elr_lib.digest import content_digest  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_OVERLAY_PATH = Path(__file__).resolve().parent / "elr_contracts.json"

DICT_KEY_FILE = Path.home() / ".enceladus" / "elr" / "dict-key.json"
SESSION_CACHE_DIR = Path.home() / ".enceladus" / "elr" / "session-cache"
SESSION_CACHE_FILE = SESSION_CACHE_DIR / "governance_data_dictionary.json"

# Route confirmed by reading tools/enceladus-mcp-server/server.py:
# _governance_dictionary() (the MCP tool) queries /dictionary?entity=...
# for a SINGLE entity's schema or a compact index with no args; it never
# returns the whole 121-entity bundle in one call. The full bundled file
# -- the one elr-validate needs cached whole so any entity can be looked
# up offline for the rest of the process -- is retrieved the same way
# _governance_get() retrieves it for file_name="governance_data_dictionary.json":
# GET {GOVERNANCE_API_BASE}/governance_data_dictionary.json via the
# governance API's internal-key auth (X-Coordination-Internal-Key),
# where GOVERNANCE_API_BASE defaults to https://jreese.net/api/v1/governance.
# elr_lib.config's "governance" API entry mirrors this base/key chain
# verbatim, so InternalClient(api="governance") reproduces the same route.
DICTIONARY_FILE_PATH = "/governance_data_dictionary.json"

# Data types elr-validate actually checks. Anything else declared on a
# dictionary field (e.g. "execute_action" -- operation metadata embedded
# on an entity, not a payload data field) is skipped entirely: it is not
# a shape a payload could conform to or violate.
_KNOWN_SCALAR_TYPES = {"string", "boolean", "integer", "number", "object", "array", "enum"}

_PY_TYPE_FOR = {
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "object": dict,
    "array": list,
}

# Dictionary field definitions occasionally document a nested required_fields
# entry that the SERVICE stamps, not the caller (e.g.
# tracker.task.transition_evidence.properties.code_on_main_evidence
# .required_fields.github_verified: "Do not set manually -- the service
# stamps this field."). Flagging those as a caller-side missing-field
# refusal would be a false positive baked out of the live dictionary
# itself, so any required_fields entry whose own definition text matches
# this phrase is treated as informational, not caller-required.
_SERVER_STAMPED_MARKER = "stamps this field"


# ---------------------------------------------------------------------------
# Refusal digest shape (mirrors the platform's api.error_envelope: code,
# message, details.missing_required_fields / allowed_values -- see
# backend/lambda/tracker_mutation/lambda_function.py's
# _tracker_create_validation_error / _error helpers).
# ---------------------------------------------------------------------------


def _refusal_digest(
    operation: str,
    reason: str,
    *,
    missing_fields: Optional[List[str]] = None,
    violations: Optional[List[Dict[str, Any]]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    digest: Dict[str, Any] = {
        "operation": operation,
        "ok": False,
        "refusal": {
            "reason": reason,
            "missing_fields": list(missing_fields or []),
            "violations": list(violations or []),
        },
    }
    digest.update(extra)
    return digest


# ---------------------------------------------------------------------------
# Layer 1 -- live dictionary retrieval
# ---------------------------------------------------------------------------


def resolve_dictionary_auth() -> Tuple[str, str, Optional[str]]:
    """Resolve which credential to attach to the dictionary pull.

    Auth order per section 4a: (a) the dedicated scoped read-only key
    file ~/.enceladus/elr/dict-key.json ({token, token_id, scope}) if it
    exists and parses; (b) fallback to the session's internal-key path
    (elr_lib.config's normal "governance" key chain -- the same
    dedicated-env-var-then-common-chain resolution InternalProfileConfig
    already performs for every other ELR call).

    Returns (token, auth_path, error). token is "" when nothing resolved
    (auth_path is then "no-auth-available"); error is set only for a
    key file that exists but fails to parse/validate, so the caller can
    surface it as an anomaly without hard-failing on it (fallback still
    applies).
    """
    key_file_error: Optional[str] = None
    if DICT_KEY_FILE.exists():
        try:
            raw = DICT_KEY_FILE.read_text(encoding="utf-8")
            data = json.loads(raw)
            token = str(data.get("token") or "").strip()
            if token:
                return token, "dedicated-key", None
            key_file_error = "dict-key.json present but has no non-empty 'token' field"
        except (OSError, json.JSONDecodeError) as exc:
            key_file_error = f"dict-key.json present but unreadable/invalid: {exc}"

    profile = elr_config.InternalProfileConfig()
    fallback_token = profile.key_for("governance")
    if fallback_token:
        return fallback_token, "fallback-internal-key", key_file_error
    return "", "no-auth-available", key_file_error


def fetch_dictionary(*, timeout: int = 20) -> Dict[str, Any]:
    """Pull governance_data_dictionary.json fresh and cache it for this
    process only (plus an on-disk session-cache file for cross-call
    reuse within one ELR session -- content is never baked into code).

    Returns a result dict:
      ok (bool), auth_path (str), status (int), source_route (str),
      dictionary (dict|None) -- the parsed {"entities": {...}, ...} body,
      version (str|None), entity_count (int|None), size_bytes (int|None),
      content_hash (str|None), error (str|None), anomalies (list[str]).
    """
    token, auth_path, key_file_error = resolve_dictionary_auth()
    anomalies: List[str] = []
    if key_file_error:
        anomalies.append(f"dict_key_file_error: {key_file_error}")

    profile = elr_config.InternalProfileConfig()
    if token:
        # Attach whichever token auth resolved to -- the dedicated key
        # file's token if present and valid, else the fallback chain's
        # value profile.key_for("governance") already picked. Either way
        # the same X-Coordination-Internal-Key header convention applies
        # (server.py:_governance_api_request), so InternalClient is reused
        # unmodified; only the credential value attached to the
        # "governance" API slot differs.
        profile._keys["governance"] = token  # noqa: SLF001 -- same-package reuse, not a foreign API

    client = elr_transport.InternalClient(profile, timeout=timeout)
    source_route = f"{profile.base_url('governance')}{DICTIONARY_FILE_PATH}"
    status, body = client.request("GET", "governance", DICTIONARY_FILE_PATH)

    ok = 200 <= status < 300 and isinstance(body, dict) and not body.get("error")
    if not ok:
        error = None
        if isinstance(body, dict):
            error = body.get("error") or body.get("message")
        return {
            "ok": False,
            "auth_path": auth_path,
            "status": status,
            "source_route": source_route,
            "dictionary": None,
            "version": None,
            "entity_count": None,
            "size_bytes": None,
            "content_hash": None,
            "error": error or f"dictionary pull failed with HTTP {status}",
            "anomalies": anomalies,
        }

    content = body.get("content")
    try:
        dictionary = json.loads(content) if isinstance(content, str) else content
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "auth_path": auth_path,
            "status": status,
            "source_route": source_route,
            "dictionary": None,
            "version": None,
            "entity_count": None,
            "size_bytes": None,
            "content_hash": None,
            "error": f"dictionary body did not parse as JSON: {exc}",
            "anomalies": anomalies,
        }

    if not isinstance(dictionary, dict) or "entities" not in dictionary:
        return {
            "ok": False,
            "auth_path": auth_path,
            "status": status,
            "source_route": source_route,
            "dictionary": None,
            "version": None,
            "entity_count": None,
            "size_bytes": None,
            "content_hash": None,
            "error": "dictionary body missing 'entities' -- unexpected shape",
            "anomalies": anomalies,
        }

    raw_bytes = (content if isinstance(content, str) else json.dumps(content)).encode("utf-8")
    digest = content_digest(raw_bytes)

    _write_session_cache(dictionary)

    return {
        "ok": True,
        "auth_path": auth_path,
        "status": status,
        "source_route": source_route,
        "dictionary": dictionary,
        "version": dictionary.get("version"),
        "entity_count": len(dictionary.get("entities") or {}),
        "size_bytes": digest["size_bytes"],
        "content_hash": digest["content_hash"],
        "error": None,
        "anomalies": anomalies,
    }


def _write_session_cache(dictionary: Dict[str, Any]) -> None:
    """Best-effort in-process-lifetime cache file. Never raises -- a
    cache write failure (e.g. read-only home dir) must not turn into a
    hard refusal; the pull already succeeded.
    """
    try:
        SESSION_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        SESSION_CACHE_FILE.write_text(json.dumps(dictionary), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Layer 1 -- payload validation against a pulled dictionary
# ---------------------------------------------------------------------------


def _check_scalar(field_def: Dict[str, Any], value: Any, path: str) -> List[Dict[str, Any]]:
    """Type/enum/constraint check for one scalar-ish value against one
    dictionary field definition. Returns a list of violation dicts
    (empty when clean).
    """
    violations: List[Dict[str, Any]] = []
    declared_type = field_def.get("type")

    if declared_type not in _KNOWN_SCALAR_TYPES:
        # e.g. "execute_action" metadata fields -- not a data shape.
        return violations

    if declared_type == "enum":
        if not isinstance(value, str):
            violations.append(
                {"path": path, "kind": "type_mismatch", "reason": f"expected string (enum), got {type(value).__name__}"}
            )
        enum_values = field_def.get("enum") or []
        if enum_values and value not in enum_values:
            violations.append(
                {
                    "path": path,
                    "kind": "enum_violation",
                    "reason": f"{value!r} not in allowed enum values",
                    "allowed_values": enum_values,
                }
            )
        return violations

    py_type = _PY_TYPE_FOR.get(declared_type)
    if py_type is not None and not isinstance(value, py_type):
        violations.append(
            {"path": path, "kind": "type_mismatch", "reason": f"expected type {declared_type}, got {type(value).__name__}"}
        )
        return violations  # further constraint checks would be meaningless on a type mismatch

    constraints = field_def.get("constraints") or {}

    enum_values = constraints.get("enum")
    if enum_values and value not in enum_values:
        violations.append(
            {
                "path": path,
                "kind": "enum_violation",
                "reason": f"{value!r} not in allowed constraint values",
                "allowed_values": enum_values,
            }
        )

    if isinstance(value, str):
        min_length = constraints.get("min_length")
        if isinstance(min_length, int) and len(value) < min_length:
            violations.append(
                {"path": path, "kind": "constraint_violation", "reason": f"length {len(value)} below min_length {min_length}"}
            )
        pattern = constraints.get("pattern")
        if pattern and not re.search(pattern, value):
            violations.append(
                {"path": path, "kind": "constraint_violation", "reason": f"value does not match required pattern {pattern!r}"}
            )
        fmt = str(constraints.get("format") or "")
        if fmt.lower().startswith("iso 8601") and "T" not in value:
            violations.append(
                {"path": path, "kind": "constraint_violation", "reason": "ISO 8601 datetime requires a 'T' separator"}
            )

    if isinstance(value, list):
        min_items = constraints.get("min_items")
        if isinstance(min_items, int) and len(value) < min_items:
            violations.append(
                {"path": path, "kind": "constraint_violation", "reason": f"{len(value)} item(s) below min_items {min_items}"}
            )
        item_type = field_def.get("item_type")
        allowed_item_types = [t.strip() for t in str(item_type).split("|")] if item_type else []
        items_def = field_def.get("items")
        required_keys = constraints.get("required_keys") or []
        for idx, item in enumerate(value):
            if allowed_item_types:
                ok_type = any(
                    (t == "object" and isinstance(item, dict))
                    or (t == "string" and isinstance(item, str))
                    for t in allowed_item_types
                )
                if not ok_type:
                    violations.append(
                        {
                            "path": f"{path}[{idx}]",
                            "kind": "type_mismatch",
                            "reason": f"expected one of item types {allowed_item_types}",
                        }
                    )
            if isinstance(items_def, dict) and items_def.get("type") == "string" and not isinstance(item, str):
                violations.append({"path": f"{path}[{idx}]", "kind": "type_mismatch", "reason": "expected string item"})
            if required_keys and isinstance(item, dict):
                for req_key in required_keys:
                    if req_key not in item or (isinstance(item.get(req_key), str) and not item[req_key].strip()):
                        violations.append(
                            {
                                "path": f"{path}[{idx}].{req_key}",
                                "kind": "missing_required",
                                "reason": "required item key missing/empty",
                            }
                        )

    return violations


def layer1_validate(
    entities: Dict[str, Any], entity_id: str, payload: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Validate payload against the live dictionary's field definitions
    for one entity.

    Returns (violations, required_fields_checked, unknown_field_names).
    required_fields_checked lists the field names Layer 1 itself
    encodes a hard requirement for (constraints.required == true) --
    used to give Layer 1 precedence over Layer 2 for those exact fields.
    """
    entity_def = entities.get(entity_id)
    if entity_def is None:
        raise KeyError(entity_id)

    fields = entity_def.get("fields") or {}
    violations: List[Dict[str, Any]] = []
    required_fields_checked: List[str] = []
    unknown_fields: List[str] = []

    for field_name, field_def in fields.items():
        constraints = field_def.get("constraints") or {}
        is_required = constraints.get("required") is True
        if is_required:
            required_fields_checked.append(field_name)

        if field_name not in payload:
            if is_required:
                violations.append(
                    {"path": field_name, "kind": "missing_required", "reason": "required field missing (dictionary-encoded)"}
                )
            continue

        value = payload[field_name]
        violations.extend(_check_scalar(field_def, value, field_name))

        declared_type = field_def.get("type")
        properties = field_def.get("properties")
        if declared_type == "object" and isinstance(properties, dict) and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                sub_schema = properties.get(sub_key)
                if not isinstance(sub_schema, dict):
                    continue
                required_shape = sub_schema.get("required_fields")
                if not isinstance(required_shape, dict):
                    continue
                if not isinstance(sub_value, dict):
                    violations.append(
                        {
                            "path": f"{field_name}.{sub_key}",
                            "kind": "type_mismatch",
                            "reason": "expected an object per nested required_fields shape",
                        }
                    )
                    continue
                for req_name, req_def in required_shape.items():
                    if not isinstance(req_def, dict):
                        continue
                    if _SERVER_STAMPED_MARKER in str(req_def.get("definition", "")).lower():
                        continue  # service-stamped, not caller-required
                    nested_path = f"{field_name}.{sub_key}.{req_name}"
                    if req_name not in sub_value:
                        violations.append(
                            {
                                "path": nested_path,
                                "kind": "missing_required",
                                "reason": "required nested field missing (dictionary-encoded)",
                            }
                        )
                        continue
                    violations.extend(_check_scalar(req_def, sub_value[req_name], nested_path))

    for field_name in payload:
        if field_name not in fields:
            unknown_fields.append(field_name)

    return violations, required_fields_checked, unknown_fields


# ---------------------------------------------------------------------------
# Layer 2 -- empirical contract overlay
# ---------------------------------------------------------------------------


def load_overlay(path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Load elr_contracts.json. Never raises and never refuses on a
    missing/corrupt overlay -- per the design tenet ("overlay gaps never
    block"), the caller proceeds Layer-1-only with anomaly
    "overlay-unavailable".

    Returns (entries, anomaly).
    """
    overlay_path = path or DEFAULT_OVERLAY_PATH
    try:
        raw = overlay_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        entries = data.get("entries")
        if not isinstance(entries, list):
            return [], "overlay-unavailable"
        return entries, None
    except (OSError, json.JSONDecodeError):
        return [], "overlay-unavailable"


def _dictionary_derivable_tristate(flag: Any) -> str:
    """An overlay entry's dictionary_derivable is prose ("false",
    "true (...)", "partial (...)"), preserved verbatim from the spec.
    This extracts the leading true/partial/false intent.

    Only "true" means Layer 1 already fully covers this entry -- those
    are logged as genuinely redundant. "partial" means Layer 1 covers
    PART of the ground (e.g. the enums on tracker.create feature) but
    NOT the specific requirement this entry exists to enforce (e.g.
    user_story required-ness) -- so a "partial" entry still does real
    work and must never be lumped in with "redundant".
    """
    normalized = str(flag).strip().lower()
    if normalized.startswith("true"):
        return "true"
    if normalized.startswith("partial"):
        return "partial"
    return "false"


def layer2_validate(
    entries: List[Dict[str, Any]],
    entity_id: str,
    op: Optional[str],
    payload: Dict[str, Any],
    layer1_required_fields: List[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply overlay entries applicable to (entity_id, op), but ONLY
    where Layer 1 is silent for the specific field/shape in question
    (Layer 1 precedence). Entries whose dictionary_derivable flag says
    Layer 1 already covers this ground are logged as redundant rather
    than re-enforced.

    Returns (violations, redundant_entries). redundant_entries lists
    ONLY entries flagged fully dictionary_derivable ("true"); "partial"
    entries still enforce their un-derivable half and are never counted
    as redundant.
    """
    violations: List[Dict[str, Any]] = []
    redundant: List[Dict[str, Any]] = []

    for entry in entries:
        entry_entity = entry.get("entity")
        entry_op = entry.get("op")

        if entry_entity is not None and entry_entity != entity_id:
            continue
        if entry_entity is None:
            # Entity-agnostic entries (checkout.task, escalation.request, ...)
            # only match when the caller told us which op it's validating.
            if not op or entry_op != op:
                continue
        elif op and entry_op and entry_op != op:
            continue

        derivable = _dictionary_derivable_tristate(entry.get("dictionary_derivable"))
        if derivable == "true":
            redundant.append({"id": entry.get("id"), "operation": entry.get("operation")})
            # Fully dictionary_derivable entries are logged, not skipped --
            # Layer 1 precedence means we only skip enforcing a specific
            # field/shape Layer 1 already checked, not the whole entry, so
            # this can still catch something Layer 1's type/enum pass on
            # THIS payload didn't (e.g. a completely absent nested object).

        missing_field = entry.get("missing_field")
        if missing_field and missing_field not in layer1_required_fields:
            value = payload.get(missing_field)
            if missing_field not in payload or (isinstance(value, str) and not value.strip()):
                violations.append(
                    {
                        "source": "layer2",
                        "kind": "missing_required",
                        "entry_id": entry.get("id"),
                        "path": missing_field,
                        "reason": entry.get("requirement"),
                    }
                )

        for req_field in entry.get("required_fields") or []:
            if req_field in layer1_required_fields:
                continue
            if req_field not in payload:
                violations.append(
                    {
                        "source": "layer2",
                        "kind": "missing_required",
                        "entry_id": entry.get("id"),
                        "path": req_field,
                        "reason": entry.get("requirement"),
                    }
                )

        for rejected_field in entry.get("rejected_fields") or []:
            if rejected_field in payload:
                violations.append(
                    {
                        "source": "layer2",
                        "kind": "rejected_present",
                        "entry_id": entry.get("id"),
                        "path": rejected_field,
                        "reason": f"{rejected_field!r} is rejected by the live validator; {entry.get('requirement')}",
                    }
                )

    return violations, redundant


# ---------------------------------------------------------------------------
# Layer 3 -- structured error-envelope learning
# ---------------------------------------------------------------------------


def _first_present(envelope: Dict[str, Any], *paths: List[str]) -> Any:
    """Return the first non-None value found by walking each dotted
    path (a list of keys) into envelope, trying paths in order.
    """
    for path in paths:
        node: Any = envelope
        found = True
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                found = False
                break
        if found and node is not None:
            return node
    return None


def learn_from_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Layer 3: parse a platform error envelope (api.error_envelope /
    document_api.error_envelope shape) and surface its fields VERBATIM,
    plus a proposed_overlay_entry for io/agent review. This never
    writes elr_contracts.json -- only the CLI/caller can decide to.

    Tolerates both known real shapes observed live:
      - tracker_mutation's flattened body: {error, error_envelope:
        {code, message, retryable, details: {...}}, <details keys
        also flattened onto the top level>} where details carries
        missing_required_fields / allowed_values / example_fix /
        record_type / governed_rules.
      - document_api's error_envelope.details: {required_fields,
        optional_fields, dictionary_entity, document_subtype,
        example_fix, edge_density_requirements, format_constraint}.
    """
    code = _first_present(envelope, ["error_envelope", "code"], ["code"])
    message = _first_present(envelope, ["error_envelope", "message"], ["message"], ["error"])
    retryable = _first_present(envelope, ["error_envelope", "retryable"], ["retryable"])
    failure_classification = _first_present(
        envelope, ["error_envelope", "failure_classification"], ["failure_classification"]
    )
    missing_required_fields = _first_present(
        envelope,
        ["error_envelope", "details", "missing_required_fields"],
        ["missing_required_fields"],
    )
    required_fields = _first_present(
        envelope,
        ["error_envelope", "details", "required_fields"],
        ["required_fields"],
    )
    allowed_values = _first_present(
        envelope,
        ["error_envelope", "details", "allowed_values"],
        ["allowed_values"],
    )
    example_fix = _first_present(
        envelope,
        ["error_envelope", "details", "example_fix"],
        ["example_fix"],
    )
    record_type = _first_present(envelope, ["error_envelope", "details", "record_type"], ["record_type"])
    dictionary_entity = _first_present(
        envelope, ["error_envelope", "details", "dictionary_entity"], ["dictionary_entity"]
    )

    parsed = {
        "code": code,
        "message": message,
        "retryable": retryable,
        "failure_classification": failure_classification,
        "missing_required_fields": missing_required_fields,
        "required_fields": required_fields,
        "allowed_values": allowed_values,
        "example_fix": example_fix,
        "record_type": record_type,
        "dictionary_entity": dictionary_entity,
    }

    fields_learned = list(missing_required_fields or []) + list(required_fields or [])
    op = None
    if isinstance(example_fix, dict):
        op = example_fix.get("tool")

    operation_label = op or dictionary_entity or record_type or "unknown-operation"
    proposed_entry = {
        "operation": operation_label,
        "requirement": (
            f"{message or 'server rejected the call'}"
            + (f" -- missing field(s): {', '.join(fields_learned)}" if fields_learned else "")
        ),
        "dictionary_derivable": "false",
        "entity": (f"tracker.{record_type}" if record_type else dictionary_entity),
        "op": op,
        "required_fields": fields_learned or None,
        "verified": {"date": None, "session": None, "status": "PROPOSED -- review before adding to elr_contracts.json"},
    }

    return {
        "operation": "elr_validate.learn",
        "ok": True,
        "parsed": parsed,
        "proposed_overlay_entry": proposed_entry,
    }


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


def validate_entity_payload(
    entity_id: str,
    payload: Dict[str, Any],
    op: Optional[str],
    dictionary: Dict[str, Any],
    overlay_entries: List[Dict[str, Any]],
    overlay_anomaly: Optional[str],
) -> Dict[str, Any]:
    """Run Layer 1 then Layer 2 against an already-pulled dictionary and
    an already-loaded overlay. Pure function -- fully offline-testable.
    """
    operation = f"elr_validate.validate:{entity_id}"
    entities = dictionary.get("entities") or {}

    if entity_id not in entities:
        return _refusal_digest(
            operation,
            "unknown_entity",
            missing_fields=[],
            violations=[{"path": "entity", "reason": f"{entity_id!r} not found in live dictionary"}],
            dictionary_version=dictionary.get("version"),
            known_entity_count=len(entities),
        )

    try:
        layer1_violations, layer1_required, unknown_fields = layer1_validate(entities, entity_id, payload)
    except KeyError:
        return _refusal_digest(
            operation,
            "unknown_entity",
            violations=[{"path": "entity", "reason": f"{entity_id!r} not found in live dictionary"}],
        )

    layer2_violations, redundant_entries = layer2_validate(overlay_entries, entity_id, op, payload, layer1_required)

    all_violations = layer1_violations + layer2_violations
    anomalies: List[str] = []
    if overlay_anomaly:
        anomalies.append(overlay_anomaly)
    if unknown_fields:
        anomalies.append(f"fields_not_in_dictionary: {sorted(unknown_fields)}")
    if redundant_entries:
        anomalies.append(f"redundant_overlay_entries: {[e['id'] for e in redundant_entries]}")

    if all_violations:
        missing_fields = sorted({v["path"] for v in all_violations if v.get("kind") == "missing_required"})
        return _refusal_digest(
            operation,
            "validation_failed",
            missing_fields=missing_fields,
            violations=all_violations,
            entity=entity_id,
            op=op,
            dictionary_version=dictionary.get("version"),
            anomalies=anomalies,
        )

    return {
        "operation": operation,
        "ok": True,
        "entity": entity_id,
        "op": op,
        "dictionary_version": dictionary.get("version"),
        "layer1_required_fields_checked": sorted(layer1_required),
        "anomalies": anomalies,
    }


def cmd_validate(args: argparse.Namespace) -> Dict[str, Any]:
    dict_result = fetch_dictionary(timeout=args.timeout)
    if not dict_result["ok"]:
        return _refusal_digest(
            f"elr_validate.validate:{args.entity}",
            "dictionary_unreachable",
            violations=[{"path": "dictionary", "reason": dict_result["error"]}],
            auth_path=dict_result["auth_path"],
            source_route=dict_result["source_route"],
            status=dict_result["status"],
            anomalies=dict_result["anomalies"],
        )

    try:
        payload_raw = _read_source(args.payload)
        payload = json.loads(payload_raw)
    except (OSError, json.JSONDecodeError) as exc:
        return _refusal_digest(
            f"elr_validate.validate:{args.entity}",
            "invalid_payload_input",
            violations=[{"path": "payload", "reason": str(exc)}],
            auth_path=dict_result["auth_path"],
        )

    if not isinstance(payload, dict):
        return _refusal_digest(
            f"elr_validate.validate:{args.entity}",
            "invalid_payload_input",
            violations=[{"path": "payload", "reason": "payload must be a JSON object"}],
            auth_path=dict_result["auth_path"],
        )

    overlay_entries, overlay_anomaly = load_overlay(Path(args.overlay) if args.overlay else None)

    digest = validate_entity_payload(
        args.entity, payload, args.op, dict_result["dictionary"], overlay_entries, overlay_anomaly
    )
    digest["auth_path"] = dict_result["auth_path"]
    digest["source_route"] = dict_result["source_route"]
    digest["dictionary_content_hash"] = dict_result["content_hash"]
    return digest


def cmd_learn(args: argparse.Namespace) -> Dict[str, Any]:
    try:
        raw = _read_source(args.envelope)
        envelope = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return _refusal_digest(
            "elr_validate.learn",
            "invalid_envelope_input",
            violations=[{"path": "envelope", "reason": str(exc)}],
        )
    if not isinstance(envelope, dict):
        return _refusal_digest(
            "elr_validate.learn",
            "invalid_envelope_input",
            violations=[{"path": "envelope", "reason": "envelope must be a JSON object"}],
        )
    return learn_from_envelope(envelope)


def _read_source(spec: str) -> str:
    if spec == "-":
        return sys.stdin.read()
    return Path(spec).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False everywhere in ELR -- A.8's argparse prefix trap
    # (a flag silently abbreviation-bound to a different, longer flag).
    parser = argparse.ArgumentParser(
        prog="elr_validate",
        description="ELR three-layer pre-flight validation gate (DOC-F2CF625B7556 section 4a). JSON digests only.",
        allow_abbrev=False,
    )
    parser.add_argument("--json", action="store_true", default=True, help="Emit digest as JSON (always on; flag kept for explicit invocation).")
    parser.add_argument("--timeout", type=int, default=20, help="Dictionary pull timeout in seconds (default: 20).")

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate a payload against the live dictionary + overlay.", allow_abbrev=False
    )
    validate_parser.add_argument("--entity", required=True, help="Dictionary entity id, e.g. tracker.feature")
    validate_parser.add_argument("--payload", required=True, help="Payload JSON file path, or '-' for stdin.")
    validate_parser.add_argument("--op", default=None, help="Operation key for overlay matching, e.g. tracker.create")
    validate_parser.add_argument("--overlay", default=None, help="Override path to elr_contracts.json.")

    learn_parser = subparsers.add_parser(
        "learn", help="Parse a server error envelope and propose an overlay entry.", allow_abbrev=False
    )
    learn_parser.add_argument("--envelope", required=True, help="Error envelope JSON file path, or '-' for stdin.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate":
        digest = cmd_validate(args)
    elif args.command == "learn":
        digest = cmd_learn(args)
    else:  # pragma: no cover -- argparse enforces choices via subparsers
        parser.error(f"unknown command {args.command!r}")
        return 2

    print(json.dumps(digest, sort_keys=True))
    return 0 if digest.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
