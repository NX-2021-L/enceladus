"""Shared OpenSearch records indexing helpers (ENC-TSK-L41 / L42).

Used by devops-opensearch-indexer (CDC stream path) and
devops-opensearch-backfill (full-corpus scan path). Keeps document shape,
stable _id, and external-version idempotency identical across both paths.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3

SKIP_RECORD_TYPES = frozenset({"reference", "relationship"})
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT", "").rstrip("/")
OPENSEARCH_SECRET_NAME = os.environ.get("OPENSEARCH_SECRET_NAME", "")
SECRETS_REGION = os.environ.get("SECRETS_REGION", os.environ.get("AWS_REGION", "us-west-2"))

_admin_password: Optional[str] = None
_secrets_client = None


def _get_secrets_client():
    global _secrets_client
    if _secrets_client is None:
        _secrets_client = boto3.client("secretsmanager", region_name=SECRETS_REGION)
    return _secrets_client


def _get_admin_password() -> str:
    global _admin_password
    if _admin_password is not None:
        return _admin_password
    override = os.environ.get("OPENSEARCH_ADMIN_PASSWORD")
    if override:
        _admin_password = override
        return _admin_password
    if not OPENSEARCH_SECRET_NAME:
        raise RuntimeError("OPENSEARCH_SECRET_NAME is not configured")
    resp = _get_secrets_client().get_secret_value(SecretId=OPENSEARCH_SECRET_NAME)
    payload = json.loads(resp["SecretString"])
    password = payload.get("password") or payload.get("admin_password")
    if not password:
        raise RuntimeError(f"Secret {OPENSEARCH_SECRET_NAME} missing password key")
    _admin_password = str(password)
    return _admin_password


def _deser_value(ddb_val: Dict[str, Any]) -> Any:
    if "S" in ddb_val:
        return ddb_val["S"]
    if "N" in ddb_val:
        return ddb_val["N"]
    if "BOOL" in ddb_val:
        return ddb_val["BOOL"]
    if "NULL" in ddb_val:
        return None
    if "L" in ddb_val:
        return [_deser_value(v) for v in ddb_val["L"]]
    if "M" in ddb_val:
        return {k: _deser_value(v) for k, v in ddb_val["M"].items()}
    if "SS" in ddb_val:
        return list(ddb_val["SS"])
    return str(ddb_val)


def _deser_image(image: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _deser_value(v) for k, v in image.items()}


def _normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(record or {})
    record_type = str(normalized.get("record_type") or "").strip()
    if not record_type and normalized.get("document_id"):
        record_type = "document"
        normalized["record_type"] = record_type
    if record_type == "document" and not normalized.get("record_id"):
        normalized["record_id"] = normalized.get("document_id", "")
    return normalized


def _bare_record_id(record_id: str) -> str:
    record_id = str(record_id or "").strip()
    return record_id.split("#", 1)[-1] if "#" in record_id else record_id


def _parse_epoch_ms(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return 0


def _stable_doc_id(project_id: str, record_type: str, record_id: str) -> str:
    return f"{project_id}#{record_type}#{_bare_record_id(record_id)}"


def _build_search_document(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    record = _normalize_record(record)
    project_id = str(record.get("project_id") or "").strip()
    record_type = str(record.get("record_type") or "").strip()
    record_id = str(record.get("record_id") or "").strip()
    if not project_id or not record_type or not record_id:
        return None
    if record_type in SKIP_RECORD_TYPES:
        return None

    title = str(record.get("title") or "").strip()
    description = str(record.get("description") or "").strip()
    body = str(record.get("body") or record.get("full_description") or record.get("content") or "").strip()
    if record_type == "document" and not description:
        description = title

    updated_at = record.get("updated_at") or record.get("created_at")
    created_at = record.get("created_at") or updated_at
    version_ms = _parse_epoch_ms(updated_at)

    tags = record.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    elif not isinstance(tags, list):
        tags = []

    doc = {
        "project_id": project_id,
        "record_type": record_type,
        "status": str(record.get("status") or "").strip(),
        "priority": str(record.get("priority") or "").strip(),
        "tags": [str(t) for t in tags if t],
        "title": title,
        "description": description,
        "body": body,
        "created_at": created_at,
        "updated_at": updated_at,
        "version_seq": version_ms,
    }
    return doc


def build_index_action(record: Dict[str, Any], write_index: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Return ('index', meta+doc) for a DynamoDB item, or None to skip."""
    record = _normalize_record(record)
    search_doc = _build_search_document(record)
    if not search_doc:
        return None
    doc_id = _stable_doc_id(
        search_doc["project_id"],
        search_doc["record_type"],
        record.get("record_id", ""),
    )
    version_ms = search_doc["version_seq"]
    meta = {
        "index": {
            "_index": write_index,
            "_id": doc_id,
            "version": version_ms,
            "version_type": "external",
        }
    }
    return ("index", {"meta": meta, "doc": search_doc})


def _opensearch_request(method: str, path: str, body: Optional[Any] = None) -> Tuple[int, Any]:
    if not OPENSEARCH_ENDPOINT:
        raise RuntimeError("OPENSEARCH_ENDPOINT is not configured")
    url = f"{OPENSEARCH_ENDPOINT}{path}"
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8") if not isinstance(body, (bytes, bytearray)) else body
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    auth = base64.b64encode(f"admin:{_get_admin_password()}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, context=SSL_CONTEXT, timeout=30) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        parsed = json.loads(raw) if raw else {}
        return exc.code, parsed


def bulk_execute(actions: List[Tuple[str, Dict[str, Any]]], write_index: str) -> List[Tuple[int, Dict[str, Any]]]:
    if not actions:
        return []
    lines: List[str] = []
    for _kind, payload in actions:
        lines.append(json.dumps(payload["meta"]))
        if "doc" in payload:
            lines.append(json.dumps(payload["doc"]))
    body = "\n".join(lines) + "\n"
    status, resp = _opensearch_request("POST", f"/{write_index}/_bulk", body.encode("utf-8"))
    if status != 200:
        raise RuntimeError(f"Bulk request failed: status={status} resp={resp}")
    items = resp.get("items") or []
    results: List[Tuple[int, Dict[str, Any]]] = []
    for item in items:
        op_result = item.get("index") or item.get("delete") or {}
        results.append((op_result.get("status", 500), op_result))
    if len(results) != len(actions):
        raise RuntimeError(
            f"Bulk item count mismatch: expected {len(actions)} got {len(results)}"
        )
    return results


def is_success_status(status: int) -> bool:
    if 200 <= status < 300:
        return True
    if status == 409:
        return True
    return False
