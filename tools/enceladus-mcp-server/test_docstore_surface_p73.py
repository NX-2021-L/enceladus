"""ENC-TSK-P73 (FR-B3-1..6): documents.patch_section / manifest / history /
diff MCP registration, denylist passthrough, deferred tool-loading
classification, and connection_health docstore_capabilities.
"""
import json
import os
from unittest.mock import patch

from test_code_mode import _load_server, _run, _tool_dump


def test_registry_contains_the_five_actions_with_right_kinds():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    assert server._EXECUTE_ACTIONS["documents.patch_section"]["tool"] == "documents_patch_section"
    assert server._EXECUTE_ACTIONS["documents.patch_section"]["requires_governance_hash"] is True
    for action, tool in (
        ("documents.manifest", "documents_manifest"),
        ("documents.history", "documents_history"),
        ("documents.diff", "documents_diff"),
        ("projects.prefix_map", "projects_prefix_map"),
    ):
        assert server._SEARCH_ACTIONS[action]["tool"] == tool
        assert action not in server._EXECUTE_ACTIONS
        assert tool in server._TOOL_HANDLERS
    assert "documents_patch_section" in server._TOOL_HANDLERS


def test_patch_section_rejects_missing_governance_hash_at_execute_step_level():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    with patch.dict(
        os.environ, {"COORDINATION_ALLOWED_RAW_TOOLS": "documents_patch_section"}, clear=False
    ):
        payload = json.loads(
            _run(
                server.call_tool(
                    "execute",
                    {
                        "steps": [
                            {
                                "action": "documents.patch_section",
                                "arguments": {
                                    "document_id": "DOC-P73-UNIT",
                                    "anchor": {"block_id": "b1"},
                                    "op": "replace",
                                    "body": "new text",
                                    "if_match": "a" * 64,
                                },
                            }
                        ]
                    },
                )
            )[0].text
        )

    assert payload["success"] is False
    failed = payload["error"]["details"]["failed_steps"][0]
    assert failed["error"] == "Action 'documents.patch_section' requires governance_hash"


def test_patch_section_handler_rejects_missing_governance_hash_directly():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    result = _run(server._documents_patch_section({"document_id": "DOC-P73-UNIT"}))
    payload = json.loads(result[0].text)
    assert payload["error"]["code"] == "PERMISSION_DENIED"


def test_patch_section_denylist_forwards_body_and_copies_if_match_header():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")

    captured = {}

    def _fake_request(method, path="", payload=None, query=None, extra_headers=None):
        captured.update(method=method, path=path, payload=payload, query=query, extra_headers=extra_headers)
        return {"success": True, "document_id": "DOC-P73-UNIT"}

    args = {
        "document_id": "DOC-P73-UNIT",
        "project_id": "enceladus",
        "anchor": {"block_id": "b1"},
        "op": "replace",
        "body": "new text",
        "if_match": "a" * 64,
        "include_heading": True,
        "rebase_headings": False,
        "idempotency_key": "idem-1",
        "caused_by": "ENC-TSK-P73",
        "dry_run": False,
        "governance_hash": server._compute_governance_hash(),
    }

    with patch.object(server, "_document_api_request", _fake_request):
        result = _run(server._documents_patch_section(args))
    payload = json.loads(result[0].text)

    assert payload["success"] is True
    assert captured["method"] == "POST"
    assert captured["path"] == "/DOC-P73-UNIT/sections"
    assert captured["extra_headers"] == {"If-Match": "a" * 64}
    body = captured["payload"]
    # document_id / governance_hash are denylisted out of the body; every
    # other field forwards untouched with no per-field whitelist edit.
    assert "document_id" not in body
    assert "governance_hash" not in body
    for key in (
        "project_id", "anchor", "op", "body", "if_match", "include_heading",
        "rebase_headings", "idempotency_key", "caused_by",
    ):
        assert body[key] == args[key]
    assert body["dry_run"] is False


def test_manifest_history_diff_query_passthrough():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    captured = {}

    def _fake_request(method, path="", payload=None, query=None, extra_headers=None):
        captured.update(method=method, path=path, query=query)
        return {"success": True}

    with patch.object(server, "_document_api_request", _fake_request):
        _run(server._documents_manifest({"document_id": "DOC-1", "digest_only": True}))
        assert captured["path"] == "/DOC-1/manifest"
        assert captured["query"] == {"digest_only": "true"}

        _run(server._documents_history({
            "document_id": "DOC-1", "since": "2026-01-01", "page_size": 25, "cursor": "c1",
        }))
        assert captured["path"] == "/DOC-1/history"
        assert captured["query"] == {"since": "2026-01-01", "page_size": 25, "cursor": "c1"}

        _run(server._documents_diff({"document_id": "DOC-1", "from": "v1", "to": "v2"}))
        assert captured["path"] == "/DOC-1/diff"
        assert captured["query"] == {"from": "v1", "to": "v2"}


def test_documents_get_gains_digest_only_and_time_travel_passthrough():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    captured = {}

    def _fake_request(method, path="", payload=None, query=None, extra_headers=None):
        captured.update(query=query)
        return {"success": True}

    with patch.object(server, "_document_api_request", _fake_request):
        _run(server._documents_get({
            "document_id": "DOC-1", "digest_only": True, "at_version": 3, "at_event": "evt-1",
        }))

    assert captured["query"] == {
        "include_content": "true", "digest_only": "true", "at_version": 3, "at_event": "evt-1",
    }


def test_read_actions_are_deferred_not_eager_loaded():
    """ENC-TSK-G15: the four new read actions/tools must not appear in
    EAGER_LOAD_TOOLS -- reachable only via 'search' (deferred by default),
    matching the ENC-TSK-P74 projects.prefix_map precedent."""
    from tool_defer_loading import EAGER_LOAD_TOOLS

    for name in (
        "documents_manifest", "documents.manifest",
        "documents_history", "documents.history",
        "documents_diff", "documents.diff",
        "projects_prefix_map", "projects.prefix_map",
    ):
        assert name not in EAGER_LOAD_TOOLS


def test_execute_core_byte_growth_bounded_by_patch_section_definition_only():
    """ENC-TSK-G15 (P73 AC-2): documents.patch_section is named in the core
    (always-loaded) 'execute' tool description -- 'core' -- while
    documents.manifest/history/diff and projects.prefix_map are not named
    anywhere in the core code-mode catalog, so the per-turn core
    tool-definition byte count grows by exactly the patch_section fragment
    and by none of the deferred read actions' text."""
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    catalog = server._code_mode_tool_catalog()
    dumped = [_tool_dump(t) for t in catalog]
    catalog_text = json.dumps(dumped, sort_keys=True)

    execute_tool = next(t for t in dumped if t["name"] == "execute")
    description = json.dumps(execute_tool["inputSchema"])
    added_fragment = "documents.patch_section, "
    assert added_fragment in description

    before_description = description.replace(added_fragment, "", 1)
    growth = len(description.encode("utf-8")) - len(before_description.encode("utf-8"))
    assert growth == len(added_fragment.encode("utf-8"))

    for deferred_action in ("documents.manifest", "documents.history", "documents.diff", "projects.prefix_map"):
        assert deferred_action not in catalog_text


def test_connection_health_docstore_capabilities_computed_from_registry():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    with patch.object(server, "_health_api_request", return_value={"dynamodb": "ok", "s3": "ok"}), \
            patch.object(server, "_graph_health_check", return_value={"status": "ok"}):
        payload = json.loads(_run(server._connection_health({}))[0].text)
    assert payload["docstore_capabilities"] == {
        "patch_section": True, "manifest": True, "history": True, "prefix_map": True,
    }


def test_connection_health_docstore_capabilities_reflects_missing_action():
    server = _load_server(ENCELADUS_MCP_INTERFACE_MODE="code")
    search_actions_without_history = {
        k: v for k, v in server._SEARCH_ACTIONS.items() if k != "documents.history"
    }
    with patch.object(server, "_health_api_request", return_value={"dynamodb": "ok", "s3": "ok"}), \
            patch.object(server, "_graph_health_check", return_value={"status": "ok"}), \
            patch.object(server, "_SEARCH_ACTIONS", search_actions_without_history):
        payload = json.loads(_run(server._connection_health({}))[0].text)
    assert payload["docstore_capabilities"]["history"] is False
    assert payload["docstore_capabilities"]["manifest"] is True
