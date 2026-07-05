#!/usr/bin/env python3
"""devops-opensearch-indexer — CDC indexer for B67 Search2.0 (ENC-TSK-L41).

Consumes DynamoDB stream records from a dedicated SQS FIFO queue fed by
TrackerToSearchIndexPipe + DocumentsToSearchIndexPipe. Bulk-upserts tracker and
document mutations into OpenSearch via the records_write alias; REMOVE deletes
by stable natural key.

Idempotency (interim until ENC-TSK-L27 version_seq):
  _id = {project_id}#{record_type}#{bare_record_id}
  external version = updated_at epoch milliseconds (version_seq field)
"""
from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

WRITE_ALIAS = os.environ.get("OPENSEARCH_WRITE_ALIAS", "records_write")
OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT", "").rstrip("/")
OPENSEARCH_SECRET_NAME = os.environ.get("OPENSEARCH_SECRET_NAME", "")
SECRETS_REGION = os.environ.get("SECRETS_REGION", os.environ.get("AWS_REGION", "us-west-2"))

SKIP_RECORD_TYPES = frozenset({"reference", "relationship"})
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

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


def _extract_remove_record_id(keys: Dict[str, Any], old_record: Dict[str, Any]) -> str:
    for key_name in ("record_id", "document_id"):
        typed = keys.get(key_name) or {}
        value = str(typed.get("S") or "").strip()
        if value:
            return value
    for key_name in ("record_id", "document_id"):
        value = str(old_record.get(key_name) or "").strip()
        if value:
            return value
    return ""


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


def _extract_stream_record(sqs_body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if isinstance(sqs_body, str):
        try:
            sqs_body = json.loads(sqs_body)
        except json.JSONDecodeError:
            return None
    if "dynamodb" in sqs_body:
        return sqs_body
    return sqs_body


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


def _stream_record_to_action(stream_record: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Return ('index', meta+doc) or ('delete', meta) or None to skip."""
    event_name = stream_record.get("eventName", "")
    dynamodb = stream_record.get("dynamodb", {})

    if event_name in ("INSERT", "MODIFY"):
        new_image = dynamodb.get("NewImage", {})
        if not new_image:
            return None
        record = _normalize_record(_deser_image(new_image))
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
                "_index": WRITE_ALIAS,
                "_id": doc_id,
                "version": version_ms,
                "version_type": "external",
            }
        }
        return ("index", {"meta": meta, "doc": search_doc})

    if event_name == "REMOVE":
        old_image = dynamodb.get("OldImage", {})
        old_record = _normalize_record(_deser_image(old_image)) if old_image else {}
        raw_id = _extract_remove_record_id(dynamodb.get("Keys", {}), old_record)
        if not raw_id:
            return None
        record_type = str(old_record.get("record_type") or "").strip()
        if not record_type and old_record.get("document_id"):
            record_type = "document"
        if record_type in SKIP_RECORD_TYPES:
            return None
        project_id = str(old_record.get("project_id") or "").strip()
        if not project_id or not record_type:
            return None
        doc_id = _stable_doc_id(project_id, record_type, raw_id)
        meta = {"delete": {"_index": WRITE_ALIAS, "_id": doc_id}}
        return ("delete", {"meta": meta})

    return None


def _bulk_execute(actions: List[Tuple[str, Dict[str, Any]]]) -> List[Tuple[int, Dict[str, Any]]]:
    if not actions:
        return []
    lines: List[str] = []
    for _kind, payload in actions:
        lines.append(json.dumps(payload["meta"]))
        if "doc" in payload:
            lines.append(json.dumps(payload["doc"]))
    body = "\n".join(lines) + "\n"
    status, resp = _opensearch_request("POST", f"/{WRITE_ALIAS}/_bulk", body.encode("utf-8"))
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


def _is_success_status(status: int) -> bool:
    if 200 <= status < 300:
        return True
    # External version conflict: stale write is idempotent success.
    if status == 409:
        return True
    return False


def _batch_failure_response(message_ids: List[str]) -> Dict[str, Any]:
    failures = []
    seen = set()
    for message_id in message_ids:
        if not message_id or message_id in seen:
            continue
        seen.add(message_id)
        failures.append({"itemIdentifier": message_id})
    if not failures:
        return {}
    return {"batchItemFailures": failures}


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    records = event.get("Records") or []
    if not records:
        return {}

    parsed: List[Tuple[str, Optional[Tuple[str, Dict[str, Any]]]]] = []
    failed_message_ids: List[str] = []
    bulk_actions: List[Tuple[str, Dict[str, Any]]] = []
    bulk_message_indexes: List[int] = []

    for idx, sqs_record in enumerate(records):
        message_id = sqs_record.get("messageId") or sqs_record.get("messageID")
        try:
            body_raw = sqs_record.get("body", "{}")
            body = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
            stream_record = _extract_stream_record(body)
            if not stream_record or "dynamodb" not in stream_record:
                parsed.append((message_id, None))
                continue
            action = _stream_record_to_action(stream_record)
            parsed.append((message_id, action))
            if action is not None:
                bulk_message_indexes.append(idx)
                bulk_actions.append(action)
        except Exception:
            logger.exception("[ERROR] Failed to parse SQS record messageId=%s", message_id)
            if message_id:
                failed_message_ids.append(message_id)

    if bulk_actions:
        try:
            bulk_results = _bulk_execute(bulk_actions)
            for bulk_idx, (status, _result) in enumerate(bulk_results):
                if _is_success_status(status):
                    continue
                msg_idx = bulk_message_indexes[bulk_idx]
                message_id = records[msg_idx].get("messageId") or records[msg_idx].get("messageID")
                if message_id:
                    failed_message_ids.append(message_id)
        except Exception:
            logger.exception("[ERROR] OpenSearch bulk execute failed")
            for msg_idx in bulk_message_indexes:
                message_id = records[msg_idx].get("messageId") or records[msg_idx].get("messageID")
                if message_id:
                    failed_message_ids.append(message_id)

    logger.info(
        "[INFO] Batch complete: total=%d bulk=%d failures=%d",
        len(records),
        len(bulk_actions),
        len(failed_message_ids),
    )
    return _batch_failure_response(failed_message_ids)
