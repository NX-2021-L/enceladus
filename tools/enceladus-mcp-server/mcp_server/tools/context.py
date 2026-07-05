"""Code-mode `get_compact_context` meta-tool handler (ENC-FTR-044 / ENC-TSK-L09)."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from mcp.types import TextContent

from mcp_server.meta_support import (
    RECORD_CONTEXT_MODES,
    best_effort_raw_tool,
    meta_tool_error,
    meta_tool_success,
    raw_call_summary,
)
from mcp_server.runtime import RUNTIME

logger = logging.getLogger(__name__)

async def get_compact_context_meta(args: dict) -> list[TextContent]:
    mode = str(args.get("mode") or "").strip().lower()
    if not mode:
        if args.get("record_id"):
            mode = "record"
        elif args.get("document_id"):
            mode = "document"
        elif args.get("query"):
            mode = "topic"
        elif args.get("project_id"):
            mode = "project"
    if not mode:
        return meta_tool_error(
            "get_compact_context",
            code="invalid_input",
            message="mode is required (or provide record_id, document_id, query, or project_id)",
        )

    warnings: List[str] = []
    underlying_calls: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}
    include_code_map = args.get("include_code_map", True) is not False
    include_related_documents = args.get("include_related_documents", True) is not False
    include_governance = args.get("include_governance", True) is not False

    if mode in RECORD_CONTEXT_MODES:
        record_id = str(args.get("record_id") or "").strip()
        if not record_id:
            return meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="record_id is required for record-oriented context modes",
                mode=mode,
            )

        raw_args = {
            "record_id": record_id,
            "include_components": args.get("include_components", True),
            "include_architecture": args.get("include_architecture", True),
            "include_recent_history": args.get("include_recent_history", True),
            "history_limit": args.get("history_limit", 10),
            "max_tokens": args.get("max_tokens", 2500),
        }
        try:
            record_call = await RUNTIME.invoke_raw_tool("get_issue_context", raw_args)
        except PermissionError as exc:
            return meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )

        underlying_calls.append(raw_call_summary(record_call))
        if record_call["status"] != "success":
            return meta_tool_error(
                "get_compact_context",
                code=record_call.get("error_code") or "tool_error",
                message="Underlying issue-context assembly failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": record_call["payload"]},
            )

        context["record_context"] = record_call["payload"]
        project_id = str(
            args.get("project_id")
            or ((record_call["payload"] or {}).get("project_id") if isinstance(record_call["payload"], dict) else "")
        ).strip()
        if not project_id:
            try:
                project_id, _record_type, _rid = RUNTIME.parse_record_id(record_id)
            except ValueError:
                project_id = ""

        if project_id:
            project_payload = await best_effort_raw_tool(
                "projects_get",
                {"project_name": project_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project lookup failed",
            )
            if project_payload is not None:
                context["project"] = project_payload

        if include_code_map and project_id:
            code_map_payload = await best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if include_related_documents:
            related_docs = await best_effort_raw_tool(
                "documents_search",
                {"project_id": project_id, "related": record_id} if project_id else {"related": record_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="related document lookup failed",
            )
            if related_docs is not None:
                context["related_documents"] = related_docs

        if include_governance:
            governance_entity = str(args.get("governance_entity") or "").strip()
            if not governance_entity:
                try:
                    _project_id, record_type, _rid = RUNTIME.parse_record_id(record_id)
                    governance_entity = f"tracker.{record_type}"
                except ValueError:
                    governance_entity = ""
            if governance_entity:
                governance_payload = await best_effort_raw_tool(
                    "governance_dictionary",
                    {"entity": governance_entity},
                    underlying_calls=underlying_calls,
                    warnings=warnings,
                    warning_label="governance lookup failed",
                )
                if governance_payload is not None:
                    context["governance"] = governance_payload

    elif mode == "project":
        project_id = str(args.get("project_id") or "").strip()
        if not project_id:
            return meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="project_id is required for project mode",
                mode=mode,
            )
        try:
            project_call = await RUNTIME.invoke_raw_tool("projects_get", {"project_name": project_id})
        except PermissionError as exc:
            return meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )
        underlying_calls.append(raw_call_summary(project_call))
        if project_call["status"] != "success":
            return meta_tool_error(
                "get_compact_context",
                code=project_call.get("error_code") or "tool_error",
                message="Project lookup failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": project_call["payload"]},
            )
        context["project"] = project_call["payload"]

        if include_code_map:
            code_map_payload = await best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if include_related_documents:
            docs_payload = await best_effort_raw_tool(
                "documents_list",
                {"project_id": project_id, "page_size": args.get("page_size", 10)},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project document lookup failed",
            )
            if docs_payload is not None:
                context["documents"] = docs_payload

        if args.get("domains"):
            arch_payload = await best_effort_raw_tool(
                "get_architecture_excerpts",
                {
                    "project_id": project_id,
                    "domains": args.get("domains"),
                    "max_excerpt_tokens": args.get("max_excerpt_tokens", 1200),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="architecture excerpts unavailable",
            )
            if arch_payload is not None:
                context["architecture"] = arch_payload

        governance_entity = str(args.get("governance_entity") or "").strip()
        if include_governance and governance_entity:
            governance_payload = await best_effort_raw_tool(
                "governance_dictionary",
                {"entity": governance_entity},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="governance lookup failed",
            )
            if governance_payload is not None:
                context["governance"] = governance_payload

    elif mode == "document":
        document_id = str(args.get("document_id") or "").strip()
        if not document_id:
            return meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="document_id is required for document mode",
                mode=mode,
            )
        try:
            document_call = await RUNTIME.invoke_raw_tool("documents_get", {"document_id": document_id, "include_content": True})
        except PermissionError as exc:
            return meta_tool_error(
                "get_compact_context",
                code="boundary_denied",
                message=str(exc),
                mode=mode,
            )
        except Exception as exc:
            return meta_tool_error(
                "get_compact_context",
                code="tool_resolution_failed",
                message=str(exc),
                mode=mode,
            )
        underlying_calls.append(raw_call_summary(document_call))
        if document_call["status"] != "success":
            return meta_tool_error(
                "get_compact_context",
                code=document_call.get("error_code") or "tool_error",
                message="Document lookup failed",
                mode=mode,
                underlying_calls=underlying_calls,
                details={"result": document_call["payload"]},
            )
        context["document"] = document_call["payload"]

        document_payload = document_call["payload"] if isinstance(document_call["payload"], dict) else {}
        document_record = document_payload.get("document") if isinstance(document_payload.get("document"), dict) else {}
        project_id = str(args.get("project_id") or document_record.get("project_id") or "").strip()
        if include_code_map and project_id:
            code_map_payload = await best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        related_items = document_record.get("related_items") if isinstance(document_record, dict) else None
        if include_related_documents and related_items:
            context["related_items"] = related_items

    elif mode == "topic":
        query = str(args.get("query") or "").strip()
        project_id = str(args.get("project_id") or "").strip()
        if not query and not project_id:
            return meta_tool_error(
                "get_compact_context",
                code="invalid_input",
                message="topic mode requires query or project_id",
                mode=mode,
            )

        if project_id:
            project_payload = await best_effort_raw_tool(
                "projects_get",
                {"project_name": project_id},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="project lookup failed",
            )
            if project_payload is not None:
                context["project"] = project_payload

        document_search_args: Dict[str, Any] = {}
        if project_id:
            document_search_args["project_id"] = project_id
        if args.get("keyword"):
            document_search_args["keyword"] = args.get("keyword")
        if args.get("title"):
            document_search_args["title"] = args.get("title")
        elif query:
            document_search_args["title"] = query
        if args.get("related"):
            document_search_args["related"] = args.get("related")
        docs_payload = await best_effort_raw_tool(
            "documents_search",
            document_search_args,
            underlying_calls=underlying_calls,
            warnings=warnings,
            warning_label="document topic search failed",
        )
        if docs_payload is not None:
            context["documents"] = docs_payload

        if project_id and query:
            reference_payload = await best_effort_raw_tool(
                "reference_search",
                {
                    "project_id": project_id,
                    "query": query,
                    "context_lines": args.get("context_lines", 2),
                    "max_results": args.get("max_results", 10),
                    **({"section": args.get("section")} if args.get("section") else {}),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="reference search failed",
            )
            if reference_payload is not None:
                context["reference"] = reference_payload

        if include_code_map and project_id:
            code_map_payload = await best_effort_raw_tool(
                "get_code_map",
                {"project_id": project_id, **({"domain": args.get("domain")} if args.get("domain") else {})},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="code map unavailable",
            )
            if code_map_payload is not None:
                context["code_map"] = code_map_payload

        if project_id and args.get("domains"):
            arch_payload = await best_effort_raw_tool(
                "get_architecture_excerpts",
                {
                    "project_id": project_id,
                    "domains": args.get("domains"),
                    "max_excerpt_tokens": args.get("max_excerpt_tokens", 1200),
                },
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="architecture excerpts unavailable",
            )
            if arch_payload is not None:
                context["architecture"] = arch_payload

        governance_entity = str(args.get("governance_entity") or "").strip()
        if include_governance and governance_entity:
            governance_payload = await best_effort_raw_tool(
                "governance_dictionary",
                {"entity": governance_entity},
                underlying_calls=underlying_calls,
                warnings=warnings,
                warning_label="governance lookup failed",
            )
            if governance_payload is not None:
                context["governance"] = governance_payload
    else:
        return meta_tool_error(
            "get_compact_context",
            code="unknown_mode",
            message=f"Unknown context mode '{mode}'",
            mode=mode,
        )

    # ENC-TSK-B92 Phase 1: three-signal hybrid retrieval.
    # Opt-in by passing `query` and/or `anchor_record_id`. Backward-compat:
    # callers who do not pass either receive exactly the legacy context shape.
    include_hybrid_retrieval = args.get("include_hybrid_retrieval")
    query_text = str(args.get("query") or "").strip()
    anchor_id = str(args.get("anchor_record_id") or "").strip()
    # Default anchor for record-oriented modes: use the primary record_id.
    if not anchor_id and mode in RECORD_CONTEXT_MODES:
        anchor_id = str(args.get("record_id") or "").strip()
    # Infer project_id from args first, then from the assembled context.
    hybrid_project_id = str(args.get("project_id") or "").strip()
    if not hybrid_project_id and isinstance(context.get("record_context"), dict):
        rc = context["record_context"]
        hybrid_project_id = str((rc or {}).get("project_id") or "").strip()
    if not hybrid_project_id and anchor_id:
        try:
            hybrid_project_id, _rt, _rid = RUNTIME.parse_record_id(anchor_id)
        except Exception:
            hybrid_project_id = ""

    # Auto-enable when the caller provided a query or anchor and did not
    # explicitly opt out. Explicit True is honored regardless.
    should_invoke_hybrid = (
        include_hybrid_retrieval is True
        or (include_hybrid_retrieval is not False and (query_text or anchor_id))
    )
    if should_invoke_hybrid and hybrid_project_id and (query_text or anchor_id):
        try:
            hybrid_resp = RUNTIME.invoke_hybrid_retrieval(
                project_id=hybrid_project_id,
                query_text=query_text or None,
                anchor_record_id=anchor_id or None,
                record_type_filter=args.get("record_type"),
                top_n=args.get("top_n"),
                include_below_threshold=bool(args.get("include_below_threshold", False)),
            )
            underlying_calls.append({
                "tool": "graph_query_api.hybrid",
                "status": "success" if hybrid_resp.get("success") else "error",
                "arguments": {
                    "project_id": hybrid_project_id,
                    "query": query_text,
                    "anchor_record_id": anchor_id,
                    "record_type": args.get("record_type"),
                    "top_n": args.get("top_n"),
                    "include_below_threshold": bool(args.get("include_below_threshold", False)),
                },
            })
            if hybrid_resp.get("error"):
                warnings.append(
                    "hybrid retrieval unavailable: " + str(hybrid_resp.get("error"))
                )
            else:
                context["hybrid_retrieval"] = {
                    "nodes": hybrid_resp.get("nodes", []),
                    "summary": hybrid_resp.get("summary", ""),
                    "signal_availability": hybrid_resp.get("signal_availability", {}),
                    "graph_algorithm": hybrid_resp.get("graph_algorithm"),
                    "rrf_k": hybrid_resp.get("rrf_k"),
                    "embedding_coverage_sample": hybrid_resp.get("embedding_coverage_sample", {}),
                    "per_node_fusion": hybrid_resp.get("per_node_fusion", {}),
                    "fsrs_t3_threshold": hybrid_resp.get("fsrs_t3_threshold"),
                    "include_below_threshold": hybrid_resp.get("include_below_threshold"),
                    "duration_ms": hybrid_resp.get("duration_ms"),
                }
        except Exception as exc:
            warnings.append(f"hybrid retrieval failed: {exc}")

    # ENC-FTR-050: Context Node assembly manifest (flagged off by default)
    if RUNTIME.enable_context_nodes and args.get("max_tokens"):
        try:
            import importlib
            _scoring = importlib.import_module("context_node_scoring")
            token_budget = int(args.get("max_tokens", 2500))
            record_id = str(args.get("record_id") or args.get("query") or "")
            # Build candidate list from context sections
            _candidates = []
            for section_key, section_val in context.items():
                if isinstance(section_val, dict):
                    _est_tokens = len(json.dumps(section_val, default=str)) // 4
                    _candidates.append({
                        "record_id": section_key,
                        "title": section_key,
                        "token_cost": _est_tokens,
                        "record_type": "task",
                        "updated_at": section_val.get("updated_at", "2026-01-01T00:00:00Z"),
                    })
            if _candidates:
                _inc, _exc, _manifest = _scoring.score_candidates(
                    _candidates, query=record_id, seed_record_id=record_id,
                    budget=token_budget, graph_healthy=False,
                )
                context["context_assembly_manifest"] = {
                    "enabled": True,
                    "token_budget": token_budget,
                    **_manifest,
                    "included_sections": [i.get("record_id", "") for i in _inc],
                    "excluded_sections": [e.get("record_id", "") for e in _exc],
                }
                # AC9: Telemetry logging
                logger.info(
                    "[CONTEXT_NODE_TELEMETRY] mode=%s budget=%d used=%d efficiency=%.4f "
                    "included=%d excluded=%d",
                    mode, token_budget, _manifest.get("tokens_used", 0),
                    _manifest.get("packing_efficiency", 0),
                    _manifest.get("items_included", 0),
                    _manifest.get("items_excluded", 0),
                )
        except Exception as _cn_err:
            warnings.append(f"context_node_scoring unavailable: {_cn_err}")

    return meta_tool_success(
        "get_compact_context",
        mode=mode,
        result=context,
        underlying_calls=underlying_calls,
        warnings=warnings,
        metadata={"section_count": len(context)},
        partial=bool(warnings),
    )
