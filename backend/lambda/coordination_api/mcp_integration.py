"""mcp_integration.py — MCP server module loading, tool calls, governance hash computation.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import logging
import os
import pathlib
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    from mcp_client import CoordinationMcpClient
except ModuleNotFoundError:
    import importlib.util as _ilu
    _MCP_MODULE_PATH = pathlib.Path(__file__).with_name("mcp_client.py")
    _MCP_SPEC = _ilu.spec_from_file_location("coordination_mcp_client", _MCP_MODULE_PATH)
    if _MCP_SPEC is None or _MCP_SPEC.loader is None:
        raise
    _MCP_MODULE = _ilu.module_from_spec(_MCP_SPEC)
    _MCP_SPEC.loader.exec_module(_MCP_MODULE)
    CoordinationMcpClient = _MCP_MODULE.CoordinationMcpClient

from config import (
    DOCUMENTS_TABLE,
    ENCELADUS_MCP_SERVER_PATH,
    GOVERNANCE_KEYWORD,
    GOVERNANCE_PROJECT_ID,
    MCP_AUDIT_CALLER_IDENTITY,
    MCP_SERVER_LOG_GROUP,
    logger,
)
from serialization import _classify_mcp_error, _deserialize, _emit_cloudwatch_json, _emit_structured_observability, _now_z
from aws_clients import _get_ddb
from project_utils import _ENCELADUS_MCP_SERVER_MODULE

__all__ = [
    "_call_mcp_tool",
    "_compute_governance_hash_local",
    "_load_mcp_server_module",
    "_parse_mcp_result",
    "_resolve_mcp_server_path",
]

# ---------------------------------------------------------------------------
# Tracker record helpers
# ---------------------------------------------------------------------------


def _resolve_mcp_server_path() -> str:
    candidates = [ENCELADUS_MCP_SERVER_PATH]
    cwd = pathlib.Path.cwd()
    candidates.extend(
        [
            str(cwd / "tools/enceladus-mcp-server/server.py"),
            str(cwd / "projects/enceladus/tools/enceladus-mcp-server/server.py"),
            str(cwd / "projects/devops/tools/enceladus-mcp-server/server.py"),
            str(pathlib.Path(__file__).resolve().parents[3] / "enceladus-mcp-server/server.py"),
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError(
        "Enceladus MCP server module not found; set ENCELADUS_MCP_SERVER_PATH to server.py"
    )


def _load_mcp_server_module():
    global _ENCELADUS_MCP_SERVER_MODULE
    if _ENCELADUS_MCP_SERVER_MODULE is not None:
        return _ENCELADUS_MCP_SERVER_MODULE

    module_path = _resolve_mcp_server_path()
    spec = importlib.util.spec_from_file_location("enceladus_mcp_server_runtime", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load MCP server module from {module_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _ENCELADUS_MCP_SERVER_MODULE = module
    return _ENCELADUS_MCP_SERVER_MODULE


def _parse_mcp_result(result: Any) -> Dict[str, Any]:
    if not isinstance(result, list) or not result:
        raise RuntimeError("MCP tool returned no content")
    payload = result[0]
    text = getattr(payload, "text", None)
    if text is None and isinstance(payload, dict):
        text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("MCP tool returned empty text payload")
    if text.startswith("ERROR:"):
        raise RuntimeError(text.replace("ERROR:", "", 1).strip())
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"MCP tool returned non-JSON payload: {text[:200]}") from exc
    if isinstance(data, dict):
        if data.get("error"):
            raise RuntimeError(str(data.get("error")))
        return data
    return {"result": data}


def _call_mcp_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    module = _load_mcp_server_module()
    invocation_id = f"mcpi-{uuid.uuid4().hex[:20]}"
    sanitized_args = {k: v for k, v in arguments.items() if v is not None}
    sanitized_args.setdefault("invocation_id", invocation_id)
    sanitized_args.setdefault("caller_identity", MCP_AUDIT_CALLER_IDENTITY)
    input_hash = hashlib.sha256(
        json.dumps(sanitized_args, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    started = time.perf_counter()
    status = "error"
    error_code = ""

    try:
        result = asyncio.run(module.call_tool(name, sanitized_args))
        parsed = _parse_mcp_result(result)
        status = "success"
    except Exception as exc:
        error_code = _classify_mcp_error(exc)
        raise
    finally:
        latency_ms = int((time.perf_counter() - started) * 1000)
        request_id = str(
            sanitized_args.get("coordination_request_id")
            or sanitized_args.get("request_id")
            or ""
        )
        dispatch_id = str(sanitized_args.get("dispatch_id") or "")
        caller_identity = str(sanitized_args.get("caller_identity") or MCP_AUDIT_CALLER_IDENTITY)
        audit_payload = {
            "invocation_id": invocation_id,
            "caller_identity": caller_identity,
            "request_id": request_id,
            "dispatch_id": dispatch_id,
            "tool_name": name,
            "input_hash": input_hash,
            "result_status": status,
            "latency_ms": latency_ms,
            "error_code": error_code,
            "timestamp": _now_z(),
        }
        logger.info("[AUDIT] %s", json.dumps(audit_payload, sort_keys=True))
        _emit_cloudwatch_json(MCP_SERVER_LOG_GROUP, audit_payload, stream_name="mcp-tool-audit")
        _emit_structured_observability(
            component="mcp_server",
            event="tool_invocation",
            request_id=request_id,
            dispatch_id=dispatch_id,
            tool_name=name,
            latency_ms=latency_ms,
            error_code=error_code,
            extra={
                "invocation_id": invocation_id,
                "caller_identity": caller_identity,
                "input_hash": input_hash,
                "result_status": status,
            },
            mirror_log_group=MCP_SERVER_LOG_GROUP,
        )

    return parsed


def _compute_governance_hash_local() -> str:
    """Compute hash from MCP governance source (S3-backed) with fallback."""
    try:
        module = _load_mcp_server_module()
        compute = getattr(module, "_compute_governance_hash", None)
        if callable(compute):
            try:
                value = compute(force_refresh=True)
            except TypeError:
                value = compute()
            text = str(value or "").strip()
            if text:
                return text
    except Exception as exc:
        logger.warning("MCP-backed governance hash failed; falling back to docstore: %s", exc)

    return _compute_governance_hash_docstore_fallback()


def _compute_governance_hash_docstore_fallback() -> str:
    ddb = _get_ddb()
    resp = ddb.query(
        TableName=DOCUMENTS_TABLE,
        IndexName="project-updated-index",
        KeyConditionExpression="project_id = :pid",
        ExpressionAttributeValues={":pid": {"S": str(GOVERNANCE_PROJECT_ID)}},
        ScanIndexForward=False,
    )
    items = list(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = ddb.query(
            TableName=DOCUMENTS_TABLE,
            IndexName="project-updated-index",
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": str(GOVERNANCE_PROJECT_ID)}},
            ScanIndexForward=False,
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))

    def _uri_from_file_name(name: str) -> Optional[str]:
        fn = str(name or "").strip()
        if fn == "agents.md":
            return "governance://agents.md"
        if fn.startswith("agents/"):
            return f"governance://{fn}"
        return None

    selected: Dict[str, Dict[str, Any]] = {}
    for raw in items:
        doc = _deserialize(raw)
        if str(doc.get("status") or "").lower() != "active":
            continue
        keywords = [str(k).strip().lower() for k in doc.get("keywords") or [] if str(k).strip()]
        if GOVERNANCE_KEYWORD and GOVERNANCE_KEYWORD.lower() not in keywords:
            continue
        uri = _uri_from_file_name(str(doc.get("file_name") or ""))
        if not uri:
            continue
        existing = selected.get(uri)
        if existing and str(existing.get("updated_at") or "") >= str(doc.get("updated_at") or ""):
            continue
        selected[uri] = doc

    h = hashlib.sha256()
    if not selected:
        h.update(b"enceladus-governance-docstore-empty")
        return h.hexdigest()

    for uri in sorted(selected.keys()):
        doc = selected[uri]
        content_hash = str(doc.get("content_hash") or "").strip()
        if not content_hash:
            content_hash = hashlib.sha256(
                str(doc.get("document_id") or "").encode("utf-8")
            ).hexdigest()
        h.update(uri.encode("utf-8"))
        h.update(b"\n")
        h.update(content_hash.encode("utf-8"))
        h.update(b"\n")

    return h.hexdigest()

