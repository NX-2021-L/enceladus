"""DVP-TSK-843: unwrapped action registry -- coverage, discovery and drift guards.

Run (from the repository root):
  PYTHONPATH=backend/lambda/shared_layer/python \
    python3 -m pytest tools/enceladus-mcp-server/test_action_registry_parity.py -q
"""
import asyncio
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import uuid
from collections import defaultdict
from unittest.mock import patch

import jsonschema
import pytest

SERVER_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SERVER_DIR.parent.parent
sys.path.insert(0, str(SERVER_DIR))
sys.path.insert(0, str(REPO_ROOT / "backend" / "lambda" / "shared_layer" / "python"))

from mcp_server.action_schemas import (  # noqa: E402
    ACTION_INPUT_SCHEMAS,
    ALIAS_REQUIRED_TOOLS,
    PASSTHROUGH_TOOLS,
)
from mcp_server.actions import ActionFeatureFlags, build_action_registries  # noqa: E402
from mcp_server.runtime import RUNTIME, bind_runtime  # noqa: E402
from parity import emit_caps  # noqa: E402
from parity.args_introspect import handler_arg_reads  # noqa: E402

ALL_FLAGS_ENV = {
    "ENABLE_TYPED_RELATIONSHIPS": "true",
    "ENABLE_LESSON_PRIMITIVE": "true",
    "ENABLE_HANDOFF_PRIMITIVE": "true",
    "ENABLE_COMPONENT_PROPOSAL": "true",
}
ALL_FLAGS = ActionFeatureFlags(True, True, True, True, True)
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint")


def _run(coro):
    # Not asyncio.run(): it clears the thread's current event loop, which breaks sibling
    # test modules that still use asyncio.get_event_loop().
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _load_server(**env):
    name = f"enceladus_server_parity_{uuid.uuid4().hex}"
    env = {"ENCELADUS_COMPACT_CONTEXT_ROUTE": "off", **env}
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location(name, SERVER_DIR / "server.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module


@pytest.fixture(scope="module")
def server():
    return _load_server(ENCELADUS_MCP_INTERFACE_MODE="code", **ALL_FLAGS_ENV)


@pytest.fixture(scope="module")
def raw_server():
    return _load_server(ENCELADUS_MCP_INTERFACE_MODE="raw", **ALL_FLAGS_ENV)


@pytest.fixture(scope="module")
def registries():
    return build_action_registries(ALL_FLAGS)


@pytest.fixture(scope="module")
def catalog(server):
    return server._action_catalog()


def _all_entries(registries):
    for via, registry in zip(("search", "coordination", "execute"), registries):
        for name, entry in registry.items():
            yield via, name, entry


def _search(module, **args):
    # RUNTIME is process-global and rebinds on every server import; point it at this module.
    bind_runtime(
        interface_mode=module.INTERFACE_MODE,
        invoke_raw_tool=module._invoke_raw_tool,
        raw_tool_allowed=module._raw_tool_allowed,
        result_text=module._result_text,
        error_payload=module._error_payload,
        action_catalog=module._action_catalog,
    )
    result = _run(module.search({"action": "actions.schemas", **args}))
    return json.loads(result[0].text)


# --------------------------------------------------------------------------- coverage


def test_every_registered_action_has_title_and_annotations(registries):
    missing = []
    for via, name, entry in _all_entries(registries):
        ann = entry.get("annotations")
        if not entry.get("title") or not isinstance(ann, dict):
            missing.append(f"{via}:{name}")
            continue
        if set(ann) != set(HINTS) or not all(isinstance(ann[h], bool) for h in HINTS):
            missing.append(f"{via}:{name} (annotations {ann!r})")
    assert not missing, f"actions without title/annotations: {missing}"


def test_every_registered_action_has_an_input_schema(catalog):
    missing = [a["name"] for a in catalog if not isinstance(a["inputSchema"], dict)]
    assert not missing, f"actions without inputSchema: {missing}"
    for action in catalog:
        assert action["inputSchema"].get("type") == "object", action["name"]


def test_annotation_coverage_is_100_percent_for_actions_and_tools(catalog, server, raw_server):
    assert catalog, "empty catalog"
    covered = [a for a in catalog if all(isinstance(a["annotations"].get(h), bool) for h in HINTS)]
    assert len(covered) == len(catalog)
    for module in (server, raw_server):
        tools = _run(module.list_tools())
        unannotated = [t.name for t in tools if t.annotations is None]
        assert not unannotated, f"first-party tools without annotations: {unannotated}"
        for tool in tools:
            dumped = tool.annotations.model_dump(exclude_none=True)
            assert set(HINTS) <= set(dumped), (tool.name, dumped)


def test_raw_and_meta_tool_set_is_fully_covered(raw_server):
    """No first-party tool slips through: every raw handler is listed or behind an action."""
    listed = {t.name for t in _run(raw_server.list_tools())}
    behind_actions = {
        entry["tool"]
        for _via, _name, entry in _all_entries(
            (raw_server._SEARCH_ACTIONS, raw_server._COORDINATION_ACTIONS, raw_server._EXECUTE_ACTIONS)
        )
        if not entry.get("builtin")
    }
    assert set(raw_server._TOOL_HANDLERS) <= listed | behind_actions


def test_actions_sharing_a_tool_carry_identical_annotations(registries):
    by_tool = defaultdict(list)
    for via, name, entry in _all_entries(registries):
        by_tool[entry["tool"]].append((name, entry["annotations"]))
    for tool, items in by_tool.items():
        first = items[0][1]
        assert all(ann == first for _n, ann in items), (tool, items)


def test_annotation_invariants(catalog):
    for action in catalog:
        ann, name = action["annotations"], action["name"]
        if ann["readOnlyHint"]:
            assert not ann["destructiveHint"], name
            assert ann["idempotentHint"], name
            assert not action["requiresGovernanceHash"], name
        if action["requiresGovernanceHash"]:
            assert not ann["readOnlyHint"], name
            assert "governance_hash" in action["inputSchema"]["properties"], name
            assert "governance_hash" in action["inputSchema"]["required"], name
        if action["via"] == "search":
            assert ann["readOnlyHint"], f"search action {name} must be read-only"
        if action["via"] == "execute" and ann["readOnlyHint"]:
            assert name == "documents.check_policy", name
    for action in catalog:
        if action["name"] == "get_compact_context":
            assert action["via"] == "top-level"


# ------------------------------------------------------------------------ minted ids


def test_minted_id_fields_are_marked_on_creation_actions(catalog):
    by_name = {a["name"]: a for a in catalog}
    expected = {
        "tracker.create": {"record_id"},
        "plan.create": {"record_id"},
        "tracker.create_lesson": {"record_id"},
        "documents.put": {"document_id"},
        "document.create_note": {"document_id"},
        "document.create_handoff": {"document_id"},
        "document.create_coe": {"document_id"},
        "document.create_wave": {"document_id"},
        "agent.register": {"session_id"},
        "agent.claim": {"sci"},
        "agent.type.register": {"agent_type_id"},
        "escalation.request": {"escalation_id"},
        "deploy.submit": {"request_id"},
        "checkout.advance": {"commit_approval_id", "commit_complete_id"},
    }
    for name, fields in expected.items():
        out = by_name[name]["outputSchema"]
        assert out and out["type"] == "object", name
        for field in fields:
            assert out["properties"][field]["x-io-minted"] is True, (name, field)
    for action in catalog:
        out = action["outputSchema"]
        if out:
            assert all(p.get("x-io-minted") is True for p in out["properties"].values()), action["name"]


# ---------------------------------------------------------------------------- discovery


@pytest.mark.parametrize("mode_fixture", ["server", "raw_server"])
def test_discovery_count_equals_registry_size(mode_fixture, request):
    module = request.getfixturevalue(mode_fixture)
    payload = _search(module)
    assert payload["success"] is True and payload["action"] == "actions.schemas"
    result = payload["result"]
    registry_size = (
        len(module._SEARCH_ACTIONS) + len(module._COORDINATION_ACTIONS) + len(module._EXECUTE_ACTIONS)
        + 1  # get_compact_context (top-level)
    )
    assert result["count"] == len(result["actions"]) == result["registry_size"] == registry_size
    names = {a["name"] for a in result["actions"]}
    assert len(names) == registry_size
    expected = (
        set(module._SEARCH_ACTIONS) | set(module._COORDINATION_ACTIONS) | set(module._EXECUTE_ACTIONS)
        | {"get_compact_context"}
    )
    assert names == expected
    assert "actions.schemas" in names


def test_discovery_shape_and_filters(server):
    result = _search(server)["result"]
    for action in result["actions"]:
        assert set(action) >= {"name", "title", "inputSchema", "outputSchema", "annotations",
                               "requiresGovernanceHash", "via"}, action["name"]
        assert action["via"] in ("top-level", "search", "coordination", "execute")
    only_exec = _search(server, arguments={"via": "execute"})["result"]
    assert {a["via"] for a in only_exec["actions"]} == {"execute"}
    assert only_exec["count"] == len(server._EXECUTE_ACTIONS)
    assert only_exec["registry_size"] == result["registry_size"]
    named = _search(server, arguments={"names": ["tracker.get", "plan.create"]})["result"]
    assert [a["name"] for a in named["actions"]] == ["tracker.get", "plan.create"]
    bad = _search(server, arguments={"via": "nope"})
    assert bad["success"] is False and bad["error"]["code"] == "invalid_input"


def test_discovery_does_not_call_any_underlying_tool(server):
    async def boom(*_a, **_k):
        raise AssertionError("actions.schemas must not invoke a raw tool")

    with patch.object(RUNTIME, "invoke_raw_tool", boom):
        assert _search(server)["success"] is True


def test_feature_flags_off_shrink_the_catalog_but_keep_it_consistent():
    module = _load_server(
        ENCELADUS_MCP_INTERFACE_MODE="code",
        ENABLE_TYPED_RELATIONSHIPS="false", ENABLE_LESSON_PRIMITIVE="false",
        ENABLE_HANDOFF_PRIMITIVE="false", ENABLE_COMPONENT_PROPOSAL="false",
    )
    result = _search(module)["result"]
    assert result["count"] == result["registry_size"]
    assert not any(a.get("flag") in {
        "enable_typed_relationships", "enable_lesson_primitive",
        "enable_handoff_primitive", "enable_component_proposal",
    } for a in result["actions"])
    assert all(a["inputSchema"] for a in result["actions"])


# ------------------------------------------------------- the 55 declared input schemas


def _tools_without_raw_definition(server, registries):
    raw = {t.name for t in server._raw_tool_definitions()} | {t.name for t in server._code_mode_tool_catalog()}
    return {
        entry["tool"]
        for _via, _name, entry in _all_entries(registries)
        if not entry.get("builtin") and entry["tool"] not in raw
    }


def test_declared_schemas_cover_exactly_the_tools_without_a_raw_definition(server, registries):
    undeclared = _tools_without_raw_definition(server, registries)
    assert undeclared == set(ACTION_INPUT_SCHEMAS), (
        sorted(undeclared - set(ACTION_INPUT_SCHEMAS)), sorted(set(ACTION_INPUT_SCHEMAS) - undeclared),
    )
    assert len(undeclared) == 55


def test_declared_schemas_are_well_formed():
    for tool, schema in ACTION_INPUT_SCHEMAS.items():
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["type"] == "object", tool
        props = schema["properties"]
        for key in schema.get("required", []):
            assert key in props, (tool, key)
            assert props[key].get("x-io-required-by") is None, (tool, key)
        for key, prop in props.items():
            assert prop.get("description"), (tool, key)
        if tool in ALIAS_REQUIRED_TOOLS:
            assert "required" not in schema and schema["anyOf"], tool


def test_declared_schemas_match_what_the_handlers_actually_read(server):
    """Drift guard: handler source (AST) vs the single declaration."""
    problems = []
    for tool, schema in ACTION_INPUT_SCHEMAS.items():
        handler = server._TOOL_HANDLERS[tool]
        reads = handler_arg_reads(SERVER_DIR / "server.py", handler.__name__)
        declared = set(schema["properties"])
        if tool in PASSTHROUGH_TOOLS:
            if not reads.opaque:
                problems.append(f"{tool}: marked passthrough but handler no longer forwards its whole argument dict")
            missing = reads.keys - declared
        else:
            if reads.opaque:
                problems.append(f"{tool}: handler forwards arguments opaquely ({reads.opaque}); add to PASSTHROUGH_TOOLS")
            missing = reads.keys - declared
            extra = declared - reads.keys
            if extra:
                problems.append(f"{tool}: declared but never read by {handler.__name__}: {sorted(extra)}")
        if missing:
            problems.append(f"{tool}: read by {handler.__name__} but not declared: {sorted(missing)}")
    assert not problems, "\n".join(problems)


class _Reached(Exception):
    pass


NETWORK_HELPERS = (
    "_tracker_api_request", "_coordination_api_request", "_document_api_request",
    "_checkout_api_request", "_graph_query_api_request", "_projects_api_request",
    "_deploy_api_request", "_governance_api_request", "_manifest_fetch_record",
)


def _placeholder(tool, key, prop):
    if key == "governance_hash":
        return "gh-test"
    if key in {"record_id", "source_id", "target_id", "objective_task_id", "task_id", "source_record_id"}:
        if key == "record_id" and tool.startswith("plan_"):
            return "DVP-PLN-001"
        if key == "record_id" and tool == "tracker_extend_lesson":
            return "DVP-LSN-001"
        if key == "target_id":
            return "DVP-TSK-002"  # tracker.relate rejects source == target
        return "DVP-TSK-001"
    if key == "agent_layer":
        return "supervisor"
    if key == "document_subtype":
        return "doc"
    typ = prop.get("type")
    if "enum" in prop:
        return prop["enum"][0]
    if typ == "array":
        item_type = (prop.get("items") or {}).get("type")
        return [0] if item_type == "integer" else ["DVP-TSK-001"]
    if typ == "integer":
        return 1
    if typ == "number":
        return 1.0
    if typ == "boolean":
        return True
    if typ == "object":
        return {"k": "v"}
    if "anyOf" in prop:
        return "DVP-TSK-001"
    return f"x-{key}"


@pytest.fixture()
def tripwired(server, monkeypatch):
    reached = []

    def make(name):
        def helper(*_a, **_k):
            reached.append(name)
            return {}
        return helper

    for name in NETWORK_HELPERS:
        monkeypatch.setattr(server, name, make(name))
    # Hermetic: accept the governance hash, resolve any prefix, skip the storage-policy lookup.
    monkeypatch.setattr(server, "_current_governance_hash_for_validation", lambda provided: provided)
    monkeypatch.setattr(server, "_resolve_prefix", lambda _p: "devops")
    monkeypatch.setattr(server, "_enforce_document_storage_policy", lambda **_k: None)
    return reached


def _invoke(server, tool, args):
    try:
        _run(server._TOOL_HANDLERS[tool](dict(args)))
    except Exception:  # a handler raising (KeyError, ValueError, ...) is a rejection, not a network call
        pass


def test_required_keys_are_enforced_by_the_handler_before_any_io(server, tripwired):
    """For every declared `required` key: full args reach the backend; dropping the key does not."""
    checked = 0
    problems = []
    for tool, schema in ACTION_INPUT_SCHEMAS.items():
        props = schema["properties"]
        if tool in ALIAS_REQUIRED_TOOLS:
            continue
        full = {k: _placeholder(tool, k, props[k]) for k in schema.get("required", [])}
        # Positive control: with every required key present the handler must get as far as
        # the backend, otherwise "dropping a key stops it" proves nothing.
        tripwired.clear()
        _invoke(server, tool, full)
        if schema.get("required") and not tripwired:
            problems.append(f"{tool}: positive control failed -- full required args never reached the backend")
            continue
        for key in schema.get("required", []):
            tripwired.clear()
            partial = {k: v for k, v in full.items() if k != key}
            _invoke(server, tool, partial)
            if tripwired:
                problems.append(f"{tool}: '{key}' is declared required but the handler reached {tripwired[0]} without it")
            checked += 1
    assert not problems, "\n".join(problems)
    assert checked >= 60  # guard against the loop silently checking nothing


def test_alias_required_tool_rejects_when_both_aliases_missing(server, tripwired):
    tripwired.clear()
    result = _run(server._TOOL_HANDLERS["telemetry_rank"]({"project_id": "devops"}))
    assert not tripwired
    assert "attribute_name is required" in result[0].text


# --------------------------------------------------------------------- caps.json emitter


def test_bundled_schema_is_the_pinned_contract_copy():
    source = json.loads((SERVER_DIR / "parity" / "schema" / "SOURCE.json").read_text())
    digest = hashlib.sha256((SERVER_DIR / "parity" / "schema" / "caps.schema.json").read_bytes()).hexdigest()
    assert digest == source["sha256"]
    assert source["schemaVersion"] == "1.0.0"
    assert source["source"]["repo"] == "NX-2021-L/devops"


def test_emitted_caps_validate_against_the_bundled_schema(server):
    caps = emit_caps.build_caps("all", server=server)
    assert caps["schemaVersion"] == "1.0.0" and caps["surface"] == "enceladus"
    emit_caps.validate_caps(caps)
    names = [a["name"] for a in caps["actions"]]
    assert len(names) == len(set(names)) == 106
    flagged = [a for a in caps["actions"] if "flag" in a]
    assert len(flagged) == 24


def test_schema_rejects_an_action_missing_annotations(server):
    caps = emit_caps.build_caps("all", server=server)
    broken = json.loads(json.dumps(caps))
    del broken["actions"][0]["annotations"]
    with pytest.raises(jsonschema.ValidationError):
        emit_caps.validate_caps(broken)
    broken = json.loads(json.dumps(caps))
    broken["schemaVersion"] = "2.0.0"
    with pytest.raises(jsonschema.ValidationError):
        emit_caps.validate_caps(broken)


def test_committed_snapshot_is_current(server):
    committed = json.loads((SERVER_DIR / "parity" / "caps.json").read_text())
    emit_caps.validate_caps(committed)
    fresh = emit_caps.build_caps("all", server=server, generated_at=committed["generatedAt"])
    assert committed == fresh, "parity/caps.json is stale: run python3 tools/enceladus-mcp-server/parity/emit_caps.py"


def test_emitted_caps_match_live_discovery(server, catalog):
    caps = emit_caps.build_caps("all", server=server)
    assert {a["name"]: a for a in caps["actions"]} == {a["name"]: a for a in catalog}
