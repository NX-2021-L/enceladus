"""Coordination MCP client boundary for DVP-TSK-244.

This module provides a deterministic adapter that translates coordination API
lifecyle operations into MCP capability calls and normalizes the returned
payload into the coordination state machine.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import boto3
    from botocore.config import Config
except Exception:  # pragma: no cover - boto3 unavailable in some local unit contexts
    boto3 = None
    Config = None


_WRITE_CAPABILITIES = {
    "coordination.request.create",
    "coordination.request.dispatch",
    "coordination.request.callback",
}

_STATE_BY_CAPABILITY = {
    "coordination.request.create": "intake_received",
    "coordination.request.dispatch": "running",
}
_DOCUMENTS_TABLE = os.environ.get("DOCUMENTS_TABLE", "documents")
_DYNAMODB_REGION = os.environ.get("DYNAMODB_REGION", "us-west-2")
_GOVERNANCE_PROJECT_ID = os.environ.get("GOVERNANCE_PROJECT_ID", "devops")
_GOVERNANCE_KEYWORD = os.environ.get("GOVERNANCE_KEYWORD", "governance-file")


def _now_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_governance_hash(workspace_root: Optional[str] = None) -> str:
    if boto3 is not None and Config is not None:
        try:
            ddb = boto3.client(
                "dynamodb",
                region_name=_DYNAMODB_REGION,
                config=Config(retries={"max_attempts": 3, "mode": "standard"}),
            )
            resp = ddb.query(
                TableName=_DOCUMENTS_TABLE,
                IndexName="project-updated-index",
                KeyConditionExpression="project_id = :pid",
                ExpressionAttributeValues={":pid": {"S": _GOVERNANCE_PROJECT_ID}},
                ScanIndexForward=False,
            )
            items = list(resp.get("Items", []))
            while resp.get("LastEvaluatedKey"):
                resp = ddb.query(
                    TableName=_DOCUMENTS_TABLE,
                    IndexName="project-updated-index",
                    KeyConditionExpression="project_id = :pid",
                    ExpressionAttributeValues={":pid": {"S": _GOVERNANCE_PROJECT_ID}},
                    ScanIndexForward=False,
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                )
                items.extend(resp.get("Items", []))

            def _deser(v: Dict[str, Any]) -> Any:
                if "S" in v:
                    return v["S"]
                if "N" in v:
                    n = v["N"]
                    return int(n) if "." not in n else float(n)
                if "L" in v:
                    return [_deser(i) for i in v["L"]]
                if "M" in v:
                    return {k: _deser(val) for k, val in v["M"].items()}
                return None

            def _deser_item(item: Dict[str, Any]) -> Dict[str, Any]:
                return {k: _deser(val) for k, val in item.items()}

            def _uri_from_file_name(name: str) -> Optional[str]:
                fn = str(name or "").strip()
                if fn == "agents.md":
                    return "governance://agents.md"
                if fn.startswith("agents/"):
                    return f"governance://{fn}"
                return None

            selected: Dict[str, Dict[str, Any]] = {}
            for raw in items:
                doc = _deser_item(raw)
                if str(doc.get("status") or "").lower() != "active":
                    continue
                keywords = [str(k).strip().lower() for k in doc.get("keywords") or [] if str(k).strip()]
                if _GOVERNANCE_KEYWORD and _GOVERNANCE_KEYWORD.lower() not in keywords:
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
                content_hash = str(selected[uri].get("content_hash") or "").strip()
                if not content_hash:
                    content_hash = hashlib.sha256(
                        str(selected[uri].get("document_id") or "").encode("utf-8")
                    ).hexdigest()
                h.update(uri.encode("utf-8"))
                h.update(b"\n")
                h.update(content_hash.encode("utf-8"))
                h.update(b"\n")
            return h.hexdigest()
        except Exception:
            pass

    # Compatibility fallback for local/offline contexts where AWS is unavailable.
    root = Path(workspace_root or os.environ.get("ENCELADUS_WORKSPACE_ROOT", "/Users/jreese/agents-dev"))
    agents_md = root / "agents.md"
    agents_dir = root / "agents"

    h = hashlib.sha256()
    files = []
    if agents_md.exists():
        files.append(agents_md)
    if agents_dir.is_dir():
        for fp in sorted(agents_dir.iterdir()):
            if fp.is_file() and not fp.name.startswith("."):
                files.append(fp)

    for fp in files:
        try:
            h.update(fp.read_bytes())
        except OSError:
            continue
    return h.hexdigest()


class CoordinationMcpClient:
    """Lightweight MCP capability adapter used by coordination API handlers."""

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = workspace_root

    def _call_tool(self, capability: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        out = {
            "capability": capability,
            "invoked_at": _now_z(),
            "payload": payload,
        }
        if capability in _WRITE_CAPABILITIES:
            out["governance_hash"] = compute_governance_hash(self.workspace_root)

        normalized_state = payload.get("state")
        if normalized_state is None:
            normalized_state = _STATE_BY_CAPABILITY.get(capability)
        if normalized_state:
            out["normalized_state"] = str(normalized_state)
        return out

    def coordination_request_create(self, *, request_id: str, project_id: str, state: str, requestor_session_id: str) -> Dict[str, Any]:
        payload = {
            "request_id": request_id,
            "project_id": project_id,
            "requestor_session_id": requestor_session_id,
            "state": state,
        }
        return self._call_tool("coordination.request.create", payload)

    def coordination_request_dispatch(
        self,
        *,
        request_id: str,
        execution_mode: str,
        provider_session: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "request_id": request_id,
            "execution_mode": execution_mode,
            "provider_session": provider_session,
            "state": "running",
        }
        return self._call_tool("coordination.request.dispatch", payload)

    def coordination_request_callback(
        self,
        *,
        request_id: str,
        state: str,
        provider: str,
        execution_id: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "request_id": request_id,
            "state": state,
            "provider": provider,
            "execution_id": execution_id,
            "details": details,
        }
        return self._call_tool("coordination.request.callback", payload)

    def coordination_request_get(self, *, request_id: str) -> Dict[str, Any]:
        return self._call_tool("coordination.request.get", {"request_id": request_id})

    def codex_session_initialize(self, *, request_id: str) -> Dict[str, Any]:
        return {
            "request_id": request_id,
            "provider": "openai_codex",
            "stage": "initialize",
            "initialized_at": _now_z(),
        }

    def codex_session_start(self, *, request_id: str, thread_id: str, fork_from_thread_id: str, model: str) -> Dict[str, Any]:
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"coordination:{request_id}")
        effective_thread = thread_id or fork_from_thread_id or f"thread_{namespace.hex[:16]}"
        provider_session_id = f"psn_{uuid.uuid5(namespace, effective_thread).hex[:20]}"
        turn_id = f"turn_{uuid.uuid5(namespace, effective_thread + ':turn').hex[:20]}"

        return {
            "provider": "openai_codex",
            "provider_session_id": provider_session_id,
            "thread_id": effective_thread,
            "fork_from_thread_id": fork_from_thread_id or None,
            "turn_id": turn_id,
            "turn_status": "started",
            "model": model or None,
            "started_at": _now_z(),
        }

    def codex_turn_complete(
        self,
        *,
        request_id: str,
        command_id: str,
        provider_result: Dict[str, Any],
        existing_provider_session: Dict[str, Any],
    ) -> Dict[str, Any]:
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"coordination:{request_id}")
        thread_id = str(provider_result.get("thread_id") or existing_provider_session.get("thread_id") or f"thread_{namespace.hex[:16]}")
        turn_id = str(provider_result.get("turn_id") or existing_provider_session.get("turn_id") or f"turn_{uuid.uuid5(namespace, thread_id + ':turn').hex[:20]}")
        provider_session_id = str(
            provider_result.get("provider_session_id")
            or existing_provider_session.get("provider_session_id")
            or f"psn_{uuid.uuid5(namespace, thread_id).hex[:20]}"
        )
        execution_id = str(provider_result.get("execution_id") or command_id or f"exe_{uuid.uuid5(namespace, turn_id).hex[:20]}")
        turn_status = str(provider_result.get("turn_status") or "completed")

        return {
            "provider": "openai_codex",
            "provider_session_id": provider_session_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "turn_status": turn_status,
            "execution_id": execution_id,
            "completed_at": str(provider_result.get("completed_at") or _now_z()),
            "model": provider_result.get("model") or existing_provider_session.get("model"),
            "raw_result": json.dumps(provider_result, sort_keys=True),
        }
