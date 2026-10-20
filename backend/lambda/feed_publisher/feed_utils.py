#!/usr/bin/env python3
"""feed_utils.py — Shared mobile feed generation and publication utilities.

Extracted from project_json_sync.py so the same logic can be used by:
  - project_json_sync.py (local manual runs / emergency override)
  - devops-feed-publisher Lambda (event-driven cloud feed publisher)

Contains:
  - DynamoDB read: fetch_from_dynamodb(), fetch_documents_from_dynamodb()
  - Mobile feed generation: generate_mobile_feeds(), generate_documents_feed(), generate_reference_docs()
  - S3 publication: publish_mobile_feeds_to_s3()
  - CloudFront invalidation: invalidate_mobile_cf()
  - Downstream signals: publish_sync_message(), publish_eventbridge_event()
  - Supporting transform/normalize functions

This module is intentionally standalone with no dependency on project_json_sync.py.
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

try:
    import boto3
    from boto3.session import Session
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    from boto3.dynamodb.types import TypeDeserializer as _DdbDeserializer
except ImportError:
    boto3 = None  # type: ignore[assignment]
    Session = None  # type: ignore[assignment]
    Config = None  # type: ignore[assignment]
    BotoCoreError = ClientError = Exception  # type: ignore[assignment,misc]
    _DdbDeserializer = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_REF_DIRNAME = "agent-reference"

LOG_PREFIX = "feed_utils"
MOBILE_FEED_VERSION = "1.0"
DEFAULT_MOBILE_FEED_DIR = REPO_ROOT / "mobile-feeds" / "v1"
DEFAULT_MOBILE_S3_BUCKET = "jreese-net"
DEFAULT_MOBILE_S3_PREFIX = "mobile/v1"
DEFAULT_MOBILE_CF_DISTRIBUTION = "E2BOQXCW1TA6Y4"
DEFAULT_TRACKER_TABLE = "devops-project-tracker"
DEFAULT_TRACKER_REGION = "us-west-2"
TRACKER_GSI_PROJECT_TYPE = "project-type-index"
DEFAULT_DOCUMENTS_TABLE = "documents"
DOCUMENTS_GSI = "project-updated-index"
MOBILE_CF_INVALIDATION_PATHS = ["/mobile/v1/*"]
DEFAULT_SNS_TOPIC = "arn:aws:sns:us-west-2:356364570033:devops-project-json-sync"
DEFAULT_EVENT_BUS = "default"
EVENT_SOURCE = "devops.json-sync"
EVENT_DETAIL_TYPE = "project-json-sync"

# Analytics / Trino pipeline constants
ANALYTICS_S3_BUCKET = "devops-agentcli-compute"
ANALYTICS_BASE_PREFIX = "projects"
ANALYTICS_STAGE_SUBPATH = "sync-stage"
ANALYTICS_ARTIFACTS = ("tasks", "issues", "features")
SYNC_TS_FORMAT = "%Y%m%d%H%M"
SYNC_TIMEZONE = ZoneInfo("America/Los_Angeles")

_MOBILE_FEED_CACHE_CONTROL = "max-age=0, s-maxage=30, must-revalidate"

# Payload size budget thresholds (bytes)
FEED_SIZE_WARN_BYTES = 500 * 1024   # 500 KB — log WARNING
FEED_SIZE_ERROR_BYTES = 1024 * 1024  # 1 MB — log ERROR

# Closed-item age limit: items in closed/complete status older than this are
# excluded from mobile feeds to prevent unbounded payload growth.
# Items remain in DynamoDB and YAML exports — only mobile feeds are trimmed.
CLOSED_ITEM_MAX_AGE_DAYS = 90

# Freshness SLA: if the delta between generated_at and the most recent
# source record updated_at exceeds this threshold, emit a WARNING.
FRESHNESS_SLA_SECONDS = 600  # 10 minutes

# Mobile feed status normalization maps
# ENC-FTR-035: 'deployed' replaced by deploy-init / deploy-success + coding-updates re-entry arc.
# Legacy 'deployed' kept as a passthrough until TSK-704 migration completes.
_STATUS_TASK = {
    "open": "open",
    "in-progress": "in-progress", "in_progress": "in-progress", "in progress": "in-progress",
    "coding-complete": "coding-complete", "coding_complete": "coding-complete",
    "committed": "committed",
    "pushed": "pushed",
    "merged-main": "merged-main", "merged_main": "merged-main",
    "deploy-init": "deploy-init", "deploy_init": "deploy-init",
    "deploy-success": "deploy-success", "deploy_success": "deploy-success",
    "coding-updates": "coding-updates", "coding_updates": "coding-updates",
    "deployed": "deployed",  # legacy — present until TSK-704 migration; harmless after
    "closed": "closed",
}
_STATUS_FEATURE = {
    "planned": "planned",
    "in-progress": "in-progress", "in_progress": "in-progress", "in progress": "in-progress",
    "complete": "completed", "completed": "completed",
    "production": "production",
    "deprecated": "deprecated",
    "closed": "closed",
}
_STATUS_ISSUE = {
    "open": "open",
    "in-progress": "in-progress", "in_progress": "in-progress", "in progress": "in-progress",
    "closed": "closed",
}
_VALID_PRIORITIES = {"P0", "P1", "P2", "P3"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def log(tag: str, message: str) -> None:
    """Emit structured log lines with consistent tags."""
    print(f"[{tag}] {message}")


# ---------------------------------------------------------------------------
# Project entry (lightweight dataclass — no dependency on project_json_sync)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FeedProjectEntry:
    """Minimal project descriptor consumed by feed generation functions."""
    name: str
    prefix: str
    path: Path
    status: str
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# JSON output helper
# ---------------------------------------------------------------------------


def write_json(path: Path, payload: Any, minify: bool = False) -> None:
    """Write payload to JSON with deterministic formatting.

    ``minify`` (ENC-TSK-R34, FEED_GZIP path only) writes the compact form with ``generated_at`` FIRST
    (see dumps_minified); the default is the indent=2 layout every other caller has always got."""
    if minify:
        path.write_text(dumps_minified(payload), encoding="utf-8")
        return
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def dumps_minified(payload: Any) -> str:
    """Compact, sorted-key JSON (ensure_ascii as everywhere else) with a top-level ``generated_at``
    moved to the very front, so object_content_digest can exclude it with a prefix match instead of
    parsing a 25 MB document inside a 512 MB Lambda."""
    if not isinstance(payload, dict) or "generated_at" not in payload:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    rest = {k: v for k, v in payload.items() if k != "generated_at"}
    body = json.dumps(rest, sort_keys=True, separators=(",", ":"))
    stamp = json.dumps(payload["generated_at"])
    return '{"generated_at":' + stamp + ("," + body[1:] if rest else "}")


def require_boto3() -> None:
    """Ensure boto3 is available for S3/SNS/CF operations."""
    if boto3 is None or Config is None:
        raise SystemExit(
            "boto3 is required for cloud operations. Install via: pip install boto3"
        )


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------


def _ddb_deserialize_item(raw: Dict) -> Dict:
    """Convert DynamoDB typed format to plain Python dict using TypeDeserializer."""
    if _DdbDeserializer is None:
        raise RuntimeError("boto3 TypeDeserializer not available; install boto3.")
    deser = _DdbDeserializer()
    return {k: deser.deserialize(v) for k, v in raw.items()}


def _looks_char_split(value: Any) -> bool:
    if not isinstance(value, list) or len(value) < 6:
        return False
    return all(isinstance(x, str) and len(x) == 1 for x in value)


def _coerce_id_list(value: Any) -> List[str]:
    """Best-effort normalization of relation IDs for feed generation."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text[:1] == "[" and text[-1:] == "]":
            try:
                return _coerce_id_list(json.loads(text))
            except json.JSONDecodeError:
                pass
        return [part.strip().upper() for part in text.split(",") if part.strip()]
    if isinstance(value, list):
        if _looks_char_split(value):
            return _coerce_id_list("".join(value))
        out: List[str] = []
        for item in value:
            if isinstance(item, str):
                text = item.strip()
                if text:
                    out.extend(part.strip().upper() for part in text.split(",") if part.strip())
        return out
    return []


def _coerce_depends_on(value: Any) -> List[Any]:
    """Best-effort normalization of depends_on entries for feed generation."""
    def _id_to_type(record_id: str) -> Optional[str]:
        parts = record_id.split("-")
        if len(parts) >= 3:
            return {"TSK": "task", "ISS": "issue", "FTR": "feature"}.get(parts[1])
        return None

    def _group(ids: List[str]) -> List[Any]:
        grouped: Dict[str, List[str]] = {"task": [], "issue": [], "feature": []}
        unknown: List[str] = []
        for rid in ids:
            rtype = _id_to_type(rid)
            if rtype:
                grouped[rtype].append(rid)
            else:
                unknown.append(rid)
        out_local: List[Any] = []
        for rtype in ("task", "issue", "feature"):
            if grouped[rtype]:
                out_local.append({"type": rtype, "ids": grouped[rtype]})
        out_local.extend(unknown)
        return out_local

    if value is None:
        return []
    if isinstance(value, str):
        ids = _coerce_id_list(value)
        if not ids:
            return []
        return _group(ids)
    if isinstance(value, list):
        if _looks_char_split(value):
            return _coerce_depends_on("".join(value))
        out: List[Any] = []
        for item in value:
            if isinstance(item, dict):
                dep_type = str(item.get("type", "")).strip().lower()
                ids = _coerce_id_list(item.get("ids"))
                if dep_type and ids:
                    out.append({"type": dep_type, "ids": ids})
            elif isinstance(item, str):
                ids = _coerce_id_list(item)
                if ids:
                    out.extend(_group(ids))
        return out
    return []


def _ddb_item_to_yaml_record(item: Dict) -> Dict:
    """Convert a deserialized DynamoDB tracker item to the YAML-compatible dict format.

    The result looks identical to what read_yaml_file() would return for the same record,
    so it can be fed directly into _transform_task / _transform_issue / _transform_feature.
    The `update` field (async PWA queue) is intentionally excluded — it should never
    appear in mobile feeds.
    """
    out: Dict[str, Any] = {}
    # item_id → id (matches YAML "id:" field)
    if "item_id" in item:
        out["id"] = item["item_id"]
    # Pass-through scalar fields
    for f in ("title", "description", "status", "priority", "severity",
              "hypothesis", "assigned_to", "last_update_note",
              "created_at", "updated_at", "parent",
              # Ontology fields (ENC-FTR-012)
              "user_story", "category", "intent", "blocked_by",
              "active_agent_session_id",
              # Coordination metadata (ENC-TSK-465)
              "coordination_request_id",
              # Execution link (ENC-TSK-460 §5.5)
              "primary_task"):
        if f in item and item[f] is not None:
            out[f] = item[f]
    # Boolean fields
    for f in ("active_agent_session", "active_agent_session_parent", "coordination"):
        if f in item:
            out[f] = item[f]
    # List fields
    for f in ("owners", "success_metrics", "technical_notes", "checklist",
              "acceptance_criteria"):
        if f in item and item[f]:
            out[f] = list(item[f])
    # Structured evidence (issue ontology)
    if "evidence" in item and item["evidence"]:
        out["evidence"] = item["evidence"]
    # Reconstruct `related` list from flat DynamoDB fields
    related_list = []
    for rtype, field in (("task", "related_task_ids"),
                         ("issue", "related_issue_ids"),
                         ("feature", "related_feature_ids")):
        ids = _coerce_id_list(item.get(field))
        if ids:
            related_list.append({"type": rtype, "ids": ids})
    if related_list:
        out["related"] = related_list
    if "depends_on" in item and item["depends_on"]:
        depends_on = _coerce_depends_on(item["depends_on"])
        if depends_on:
            out["depends_on"] = depends_on
    # History
    history = item.get("history")
    if history and isinstance(history, list):
        out["history"] = [
            {k: str(v) for k, v in h.items()} if isinstance(h, dict) else {}
            for h in history
        ]
    return out


# ---------------------------------------------------------------------------
# ENC-TSK-R41 (ENC-PLN-100 C4.1, FR-22): incremental tracker re-read building blocks.
#
# The SWEEP keeps a per-project snapshot of the RAW DynamoDB items (lossless: no Decimal/set
# round-trip) in S3 and, instead of re-querying the whole project, strongly-consistently BatchGets
# only the record keys the DynamoDB stream reported changed, then merges them in. A key that comes
# back absent is a deletion. Everything here is pure mechanics; the policy (when to trust a snapshot,
# how ids are tracked and cleared) lives in lambda_function.py.
# ---------------------------------------------------------------------------

_READ_UNITS: Dict[str, float] = {"total": 0.0}
SNAPSHOT_VERSION = 1
BATCH_GET_CHUNK = 100
BATCH_GET_MAX_ATTEMPTS = 6


def _note_consumed(resp: Any) -> None:
    """Accumulate ConsumedCapacity from a Query page / BatchGetItem response (best effort)."""
    try:
        cc = resp.get("ConsumedCapacity") if isinstance(resp, dict) else None
        if cc is None:
            return
        for entry in cc if isinstance(cc, list) else [cc]:
            _READ_UNITS["total"] += float(entry.get("CapacityUnits") or 0.0)
    except Exception:  # noqa: BLE001 - metrics must never break a publish
        pass


def reset_read_units() -> None:
    _READ_UNITS["total"] = 0.0


def read_units_total() -> float:
    return float(_READ_UNITS["total"])


def group_project_items(raw_items: List[Dict]) -> Dict[str, Any]:
    """Raw DynamoDB items of one project -> the artifact_payloads dict fetch_from_dynamodb returns.
    Reference rows (and any unknown record_type) are skipped - they are metadata only."""
    grouped: Dict[str, List[Dict]] = {"task": [], "issue": [], "feature": [], "lesson": [], "plan": []}
    for raw in raw_items:
        item = _ddb_deserialize_item(raw)
        rtype = item.get("record_type")
        if rtype in grouped:
            if rtype in ("task", "issue", "feature"):
                grouped[rtype].append(_ddb_item_to_yaml_record(item))
            else:
                # lessons and plans: store raw deserialized item directly
                grouped[rtype].append(item)
    return {
        "tasks": grouped["task"],
        "issues": grouped["issue"],
        "features": grouped["feature"],
        "lessons": grouped["lesson"],
        "plans": grouped["plan"],
    }


def query_project_items(project_name: str, table: str, region: str) -> Dict[str, Dict]:
    """Full per-project read of the tracker table as {record_id: raw item}. Unlike
    fetch_from_dynamodb this RAISES on a failed read: a snapshot must never be built from a partial or
    empty read."""
    require_boto3()
    ddb = boto3.client("dynamodb", region_name=region, config=Config(retries={"max_attempts": 3, "mode": "standard"}))
    items: Dict[str, Dict] = {}
    for page in ddb.get_paginator("query").paginate(
        TableName=table,
        IndexName=TRACKER_GSI_PROJECT_TYPE,
        KeyConditionExpression="project_id = :pid",
        ExpressionAttributeValues={":pid": {"S": project_name}},
        ReturnConsumedCapacity="TOTAL",
    ):
        _note_consumed(page)
        for raw in page.get("Items", []):
            rid = (raw.get("record_id") or {}).get("S")
            if rid:
                items[rid] = raw
    return items


def batch_get_tracker_items(
    project_name: str,
    record_ids: List[str],
    table: str,
    region: str,
    sleep: Any = time.sleep,
) -> Dict[str, Dict]:
    """Strongly consistent BatchGetItem of exactly ``record_ids`` (chunks of 100, UnprocessedKeys
    retried with backoff). Returns {record_id: raw item} for the keys that EXIST; a missing key is
    absent from the result. Raises if keys are still unprocessed after the retries (the caller falls
    back to a full re-read)."""
    require_boto3()
    ddb = boto3.client("dynamodb", region_name=region, config=Config(retries={"max_attempts": 3, "mode": "standard"}))
    found: Dict[str, Dict] = {}
    ordered = sorted(set(record_ids))
    for start in range(0, len(ordered), BATCH_GET_CHUNK):
        pending = {table: {
            "Keys": [{"project_id": {"S": project_name}, "record_id": {"S": rid}} for rid in ordered[start:start + BATCH_GET_CHUNK]],
            "ConsistentRead": True,
        }}
        for attempt in range(BATCH_GET_MAX_ATTEMPTS):
            resp = ddb.batch_get_item(RequestItems=pending, ReturnConsumedCapacity="TOTAL")
            _note_consumed(resp)
            for raw in (resp.get("Responses") or {}).get(table, []):
                rid = (raw.get("record_id") or {}).get("S")
                if rid:
                    found[rid] = raw
            pending = resp.get("UnprocessedKeys") or {}
            if not pending:
                break
            sleep(min(2.0, 0.05 * (2 ** attempt)))
        else:
            raise RuntimeError(f"BatchGetItem left unprocessed keys for project={project_name}")
    return found


def snapshot_encode(project: str, items: Dict[str, Dict], full_read_at: float, saved_at: float) -> bytes:
    """gzip JSON of the raw items. Raises (TypeError) on a non-JSON attribute (e.g. binary): the
    caller then simply has no snapshot and keeps doing full re-reads."""
    payload = {
        "v": SNAPSHOT_VERSION, "project": project, "full_read_at": float(full_read_at),
        "saved_at": float(saved_at), "items": items,
    }
    return gzip.compress(json.dumps(payload, separators=(",", ":")).encode("utf-8"), compresslevel=6)


def snapshot_decode(blob: bytes, project: str) -> Optional[Dict[str, Any]]:
    """Inverse of snapshot_encode; None for anything that is not a valid snapshot of ``project``."""
    try:
        payload = json.loads(gzip.decompress(blob).decode("utf-8"))
        if payload.get("v") != SNAPSHOT_VERSION or payload.get("project") != project:
            return None
        if not isinstance(payload.get("items"), dict):
            return None
        return {
            "items": payload["items"],
            "full_read_at": float(payload.get("full_read_at") or 0.0),
            "saved_at": float(payload.get("saved_at") or 0.0),
        }
    except Exception:  # noqa: BLE001
        return None


def fetch_from_dynamodb(
    project_entry: FeedProjectEntry,
    table: str = DEFAULT_TRACKER_TABLE,
    region: str = DEFAULT_TRACKER_REGION,
) -> Dict[str, Any]:
    """Read all records for a project from DynamoDB and return artifact_payloads dict.

    Returns the same structure expected by generate_mobile_feeds():
        {"tasks": [...], "issues": [...], "features": [...]}

    The `update` field is intentionally excluded from all returned records.
    Reference-type rows are also excluded (those are metadata only).
    """
    require_boto3()
    ddb = boto3.client(
        "dynamodb",
        region_name=region,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )

    log("INFO", f"{LOG_PREFIX}: fetching project={project_entry.name} from DynamoDB table={table}")

    # Query project-type-index GSI: PK=project_id fetches all record types for the project
    paginator = ddb.get_paginator("query")
    raw_items: List[Dict] = []
    try:
        for page in paginator.paginate(
            TableName=table,
            IndexName=TRACKER_GSI_PROJECT_TYPE,
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": project_entry.name}},
            ReturnConsumedCapacity="TOTAL",
        ):
            raw_items.extend(page.get("Items", []))
            _note_consumed(page)
    except (BotoCoreError, ClientError) as exc:  # type: ignore[misc]
        log("ERROR", f"{LOG_PREFIX}: DynamoDB query failed for project={project_entry.name}: {exc}")
        return {"tasks": [], "issues": [], "features": []}

    artifact_payloads = group_project_items(raw_items)
    grouped = {
        "task": artifact_payloads["tasks"], "issue": artifact_payloads["issues"],
        "feature": artifact_payloads["features"], "lesson": artifact_payloads["lessons"],
        "plan": artifact_payloads["plans"],
    }

    log(
        "INFO",
        f"{LOG_PREFIX}: DynamoDB read project={project_entry.name}: "
        f"tasks={len(grouped['task'])} issues={len(grouped['issue'])} "
        f"features={len(grouped['feature'])} lessons={len(grouped['lesson'])} "
        f"plans={len(grouped['plan'])}",
    )
    return artifact_payloads


def fetch_documents_from_dynamodb(
    project_entry: FeedProjectEntry,
    table: str = DEFAULT_DOCUMENTS_TABLE,
    region: str = DEFAULT_TRACKER_REGION,
) -> List[Dict[str, Any]]:
    """Read all document metadata records for a project from the documents table.

    Queries the ``project-updated-index`` GSI on the *documents* DynamoDB table.
    Returns a list of deserialized document dicts (content is NOT included — it
    lives in S3 and is fetched on-demand for detail views).
    """
    require_boto3()
    ddb = boto3.client(
        "dynamodb",
        region_name=region,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )

    log("INFO", f"{LOG_PREFIX}: fetching documents for project={project_entry.name} from table={table}")

    paginator = ddb.get_paginator("query")
    raw_items: List[Dict] = []
    try:
        for page in paginator.paginate(
            TableName=table,
            IndexName=DOCUMENTS_GSI,
            KeyConditionExpression="project_id = :pid",
            ExpressionAttributeValues={":pid": {"S": project_entry.name}},
            ScanIndexForward=False,  # newest first
            ReturnConsumedCapacity="TOTAL",
        ):
            raw_items.extend(page.get("Items", []))
            _note_consumed(page)
    except (BotoCoreError, ClientError) as exc:  # type: ignore[misc]
        log("ERROR", f"{LOG_PREFIX}: DynamoDB documents query failed for project={project_entry.name}: {exc}")
        return []

    documents = [_ddb_deserialize_item(raw) for raw in raw_items]

    log(
        "INFO",
        f"{LOG_PREFIX}: DynamoDB documents read project={project_entry.name}: "
        f"documents={len(documents)}",
    )
    return documents


# ---------------------------------------------------------------------------
# Normalization / transform helpers
# ---------------------------------------------------------------------------


def _normalize_status(raw: Optional[str], mapping: Dict[str, str], default: str) -> str:
    if not raw:
        return default
    return mapping.get(raw.strip().lower(), default)


def _normalize_priority(raw: Optional[str]) -> str:
    if not raw:
        return "P3"
    val = raw.strip().upper()
    return val if val in _VALID_PRIORITIES else "P3"


def _normalize_severity(raw: Optional[str]) -> str:
    if not raw:
        return "medium"
    val = raw.strip().lower()
    return val if val in _VALID_SEVERITIES else "medium"


def _truncate(text: Optional[str], max_len: int) -> Optional[str]:
    if text is None:
        return None
    s = str(text).strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _extract_history(history: Any) -> tuple:
    """Return (created_at, updated_at, last_update_note, full_history) from a history list."""
    if not isinstance(history, list) or not history:
        return (None, None, None, [])
    first = history[0] if isinstance(history[0], dict) else {}
    last = history[-1] if isinstance(history[-1], dict) else {}
    created_at = str(first.get("timestamp", "")) or None
    updated_at = str(last.get("timestamp", "")) or None
    last_note = str(last.get("description", "")).strip() or None
    full_history: List[Dict[str, str]] = []
    for entry in history:
        if isinstance(entry, dict):
            full_history.append({
                "timestamp": str(entry.get("timestamp", "")),
                "status": str(entry.get("status", "")),
                "description": str(entry.get("description", "")),
            })
    return (created_at, updated_at, last_note, full_history)


def _flatten_related_ids(related: Any, target_type: str) -> List[str]:
    if not isinstance(related, list):
        return []
    ids: List[str] = []
    for entry in related:
        if isinstance(entry, dict) and entry.get("type") == target_type:
            raw_ids = entry.get("ids", [])
            if isinstance(raw_ids, list):
                ids.extend(str(i) for i in raw_ids)
    return ids


def _count_checklist(checklist: Any) -> tuple:
    if not isinstance(checklist, list):
        return (0, 0, [])
    total = len(checklist)
    done = sum(1 for item in checklist if isinstance(item, str) and item.strip().upper().startswith("DONE"))
    items = [str(item).strip() for item in checklist]
    return (total, done, items)


def _transform_task(task: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    created_at, updated_at, last_note, full_history = _extract_history(task.get("history"))
    cl_total, cl_done, cl_items = _count_checklist(task.get("checklist"))
    result = {
        "task_id": task.get("id", ""),
        "project_id": project_id,
        "title": task.get("title", ""),
        "description": str(task.get("description", "")).strip(),
        "status": _normalize_status(task.get("status"), _STATUS_TASK, "open"),
        "priority": _normalize_priority(task.get("priority")),
        "assigned_to": task.get("assigned_to") or None,
        "related_feature_ids": _flatten_related_ids(task.get("related"), "feature"),
        "related_task_ids": _flatten_related_ids(task.get("related"), "task"),
        "related_issue_ids": _flatten_related_ids(task.get("related"), "issue"),
        "checklist_total": cl_total,
        "checklist_done": cl_done,
        "checklist": cl_items,
        "history": full_history,
        "updated_at": updated_at,
        "last_update_note": last_note,
        "created_at": created_at,
        "parent": task.get("parent") or None,
        # Ontology fields (ENC-FTR-012)
        "active_agent_session": task.get("active_agent_session", False),
        "active_agent_session_parent": task.get("active_agent_session_parent", False),
        "category": task.get("category") or None,
        "intent": task.get("intent") or None,
        "blocked_by": task.get("blocked_by") or None,
        "coordination": bool(task.get("coordination", False)),
        "coordination_request_id": task.get("coordination_request_id") or None,
    }
    if task.get("active_agent_session_id"):
        result["active_agent_session_id"] = task["active_agent_session_id"]
    if task.get("acceptance_criteria"):
        result["acceptance_criteria"] = list(task["acceptance_criteria"])
    return result


def _transform_issue(issue: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    created_at, updated_at, last_note, full_history = _extract_history(issue.get("history"))
    result = {
        "issue_id": issue.get("id", ""),
        "project_id": project_id,
        "title": issue.get("title", ""),
        "description": str(issue.get("description", "")).strip(),
        "status": _normalize_status(issue.get("status"), _STATUS_ISSUE, "open"),
        "priority": _normalize_priority(issue.get("priority")),
        "severity": _normalize_severity(issue.get("severity")),
        "hypothesis": str(issue.get("hypothesis", "")).strip() or None,
        "related_feature_ids": _flatten_related_ids(issue.get("related"), "feature"),
        "related_task_ids": _flatten_related_ids(issue.get("related"), "task"),
        "related_issue_ids": _flatten_related_ids(issue.get("related"), "issue"),
        "history": full_history,
        "updated_at": updated_at,
        "last_update_note": last_note,
        "created_at": created_at,
        "parent": issue.get("parent") or None,
        # Ontology fields (ENC-FTR-012)
        "category": issue.get("category") or None,
        "intent": issue.get("intent") or None,
        "blocked_by": issue.get("blocked_by") or None,
        # Execution link (ENC-TSK-460 §5.5)
        "primary_task": issue.get("primary_task") or None,
        "coordination": bool(issue.get("coordination", False)),
        "coordination_request_id": issue.get("coordination_request_id") or None,
    }
    if issue.get("evidence"):
        result["evidence"] = issue["evidence"]
    return result


def _transform_feature(feat: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    created_at, updated_at, last_note, full_history = _extract_history(feat.get("history"))
    owners_raw = feat.get("owners")
    owners = list(owners_raw) if isinstance(owners_raw, list) else []
    metrics = feat.get("success_metrics")
    metrics_list = [str(m).strip() for m in metrics] if isinstance(metrics, list) else []
    metrics_count = len(metrics_list)
    ac_raw = feat.get("acceptance_criteria")
    # Handle both structured (dict) and legacy (string) acceptance criteria
    ac_list: list = []
    if isinstance(ac_raw, list):
        for c in ac_raw:
            if isinstance(c, dict):
                ac_list.append({
                    "description": str(c.get("description", "")).strip(),
                    "evidence": str(c.get("evidence", "")).strip(),
                    "evidence_acceptance": bool(c.get("evidence_acceptance", False)),
                })
            else:
                # Legacy plain string — wrap as structured with no evidence
                ac_list.append({
                    "description": str(c).strip(),
                    "evidence": "",
                    "evidence_acceptance": False,
                })
    return {
        "feature_id": feat.get("id", ""),
        "project_id": project_id,
        "title": feat.get("title", ""),
        "description": str(feat.get("description", "")).strip(),
        "status": _normalize_status(feat.get("status"), _STATUS_FEATURE, "planned"),
        "owners": owners,
        "success_metrics_count": metrics_count,
        "success_metrics": metrics_list,
        "related_task_ids": _flatten_related_ids(feat.get("related"), "task"),
        "related_feature_ids": _flatten_related_ids(feat.get("related"), "feature"),
        "related_issue_ids": _flatten_related_ids(feat.get("related"), "issue"),
        "history": full_history,
        "updated_at": updated_at,
        "last_update_note": last_note,
        "created_at": created_at,
        "parent": feat.get("parent") or None,
        # Ontology fields (ENC-FTR-012)
        "user_story": feat.get("user_story") or None,
        "acceptance_criteria": ac_list,
        "category": feat.get("category") or None,
        "intent": feat.get("intent") or None,
        "blocked_by": feat.get("blocked_by") or None,
        # Execution link (ENC-TSK-460 §5.5)
        "primary_task": feat.get("primary_task") or None,
        "coordination": bool(feat.get("coordination", False)),
        "coordination_request_id": feat.get("coordination_request_id") or None,
    }


def _transform_lesson(lesson: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """Transform a raw deserialized DynamoDB lesson record into the mobile feed shape."""
    def _to_float(v: Any) -> float:
        try:
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    history = lesson.get("history") or []
    full_history: List[Dict[str, str]] = []
    if isinstance(history, list):
        for h in history:
            if isinstance(h, dict):
                full_history.append({
                    "timestamp": str(h.get("timestamp", "")),
                    "status": str(h.get("status", "")),
                    "description": str(h.get("description", "")),
                })

    created_at = full_history[0].get("timestamp") if full_history else None
    updated_at = full_history[-1].get("timestamp") if full_history else None
    last_note = str(full_history[-1].get("description", "")).strip() or None if full_history else None
    if lesson.get("updated_at"):
        updated_at = lesson["updated_at"]
    if lesson.get("created_at"):
        created_at = lesson["created_at"]

    evidence_chain = lesson.get("evidence_chain") or []
    if not isinstance(evidence_chain, list):
        evidence_chain = []

    pillar_scores = lesson.get("pillar_scores") or {}
    if isinstance(pillar_scores, dict):
        pillar_scores = {k: _to_float(v) for k, v in pillar_scores.items()}
    else:
        pillar_scores = {}

    extensions = lesson.get("extensions") or []
    if isinstance(extensions, list):
        extensions = [
            {
                "description": str(e.get("description", "")),
                "timestamp": str(e.get("timestamp", "")),
                "provider": e.get("provider") or None,
            }
            for e in extensions if isinstance(e, dict)
        ]
    else:
        extensions = []

    return {
        "lesson_id": lesson.get("item_id", ""),
        "project_id": project_id,
        "title": lesson.get("title", ""),
        "observation": str(lesson.get("observation", "")).strip(),
        "insight": str(lesson.get("insight", "")).strip(),
        "evidence_chain": [str(e) for e in evidence_chain],
        "provenance": str(lesson.get("provenance", "")).strip(),
        "confidence": _to_float(lesson.get("confidence", 0)),
        "pillar_scores": pillar_scores,
        "resonance_score": _to_float(lesson.get("resonance_score", 0)),
        "pillar_composite": _to_float(lesson.get("pillar_composite", 0)),
        "extensions": extensions,
        "category": lesson.get("category") or None,
        "status": str(lesson.get("status", "active")).strip(),
        "lesson_version": int(lesson.get("lesson_version", 1) or 1),
        "analysis_reference": lesson.get("analysis_reference") or None,
        "governance_proposal": lesson.get("governance_proposal") or None,
        "related_task_ids": _coerce_id_list(lesson.get("related_task_ids")),
        "related_issue_ids": _coerce_id_list(lesson.get("related_issue_ids")),
        "related_feature_ids": _coerce_id_list(lesson.get("related_feature_ids")),
        "history": full_history,
        "updated_at": updated_at,
        "last_update_note": last_note,
        "created_at": created_at,
    }


def _transform_plan(plan: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """Transform a raw deserialized DynamoDB plan record into the mobile feed shape."""
    history = plan.get("history") or []
    full_history: List[Dict[str, str]] = []
    if isinstance(history, list):
        for h in history:
            if isinstance(h, dict):
                full_history.append({
                    "timestamp": str(h.get("timestamp", "")),
                    "status": str(h.get("status", "")),
                    "description": str(h.get("description", "")),
                })

    created_at = full_history[0].get("timestamp") if full_history else None
    updated_at = full_history[-1].get("timestamp") if full_history else None
    last_note = str(full_history[-1].get("description", "")).strip() or None if full_history else None
    if plan.get("updated_at"):
        updated_at = plan["updated_at"]
    if plan.get("created_at"):
        created_at = plan["created_at"]

    objectives_set = plan.get("objectives_set") or plan.get("subtask_ids") or []
    if not isinstance(objectives_set, list):
        objectives_set = []

    attached_documents = plan.get("attached_documents") or []
    if not isinstance(attached_documents, list):
        attached_documents = []

    return {
        "plan_id": plan.get("item_id", ""),
        "project_id": project_id,
        "title": plan.get("title", ""),
        "description": str(plan.get("description", "")).strip(),
        "status": str(plan.get("status", "drafted")).strip(),
        "priority": _normalize_priority(plan.get("priority")),
        "category": plan.get("category") or None,
        "objectives_set": [str(o) for o in objectives_set],
        "attached_documents": [str(d) for d in attached_documents],
        "related_feature_id": plan.get("related_feature_id") or None,
        "checkout_state": plan.get("checkout_state") or None,
        "checked_out_by": plan.get("checked_out_by") or None,
        "checked_out_at": plan.get("checked_out_at") or None,
        "related_task_ids": _coerce_id_list(plan.get("related_task_ids")),
        "related_issue_ids": _coerce_id_list(plan.get("related_issue_ids")),
        "related_feature_ids": _coerce_id_list(plan.get("related_feature_ids")),
        "history": full_history,
        "updated_at": updated_at,
        "last_update_note": last_note,
        "created_at": created_at,
    }


def _transform_document(doc: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """Transform a deserialized document record into the mobile feed shape.

    ``content`` is intentionally excluded — it lives in S3 and is only fetched
    on-demand for document detail views.
    """
    keywords = doc.get("keywords", [])
    if isinstance(keywords, set):
        keywords = sorted(keywords)
    elif not isinstance(keywords, list):
        keywords = []
    related_items = doc.get("related_items", [])
    if isinstance(related_items, set):
        related_items = sorted(related_items)
    elif not isinstance(related_items, list):
        related_items = []
    return {
        "document_id": doc.get("document_id", ""),
        "project_id": project_id,
        "title": doc.get("title", ""),
        "description": str(doc.get("description", "")).strip(),
        "file_name": doc.get("file_name", ""),
        "content_type": doc.get("content_type", ""),
        "content_hash": doc.get("content_hash", ""),
        "size_bytes": int(doc.get("size_bytes", 0) or 0),
        "keywords": keywords,
        "related_items": related_items,
        "status": doc.get("status", "active"),
        "created_by": doc.get("created_by", ""),
        "created_at": doc.get("created_at") or None,
        "updated_at": doc.get("updated_at") or None,
        "version": int(doc.get("version", 1) or 1),
    }


def _compute_children_ids(
    items: List[Dict[str, Any]],
    item_id_key: str,
) -> Dict[str, List[str]]:
    """Compute children_ids for each item by finding all items where parent == item_id.

    Args:
        items: List of transformed items (tasks, issues, or features)
        item_id_key: The key containing the item ID (e.g., 'task_id', 'issue_id', 'feature_id')

    Returns:
        Dict mapping parent_item_id -> list of child item IDs
    """
    children_map: Dict[str, List[str]] = {}

    for item in items:
        parent = item.get("parent")
        if parent:
            if parent not in children_map:
                children_map[parent] = []
            item_id = item.get(item_id_key)
            if item_id:
                children_map[parent].append(item_id)

    return children_map


def _add_children_ids_to_items(
    items: List[Dict[str, Any]],
    children_map: Dict[str, List[str]],
    item_id_key: str,
) -> None:
    """Add children_ids field to each item in-place.

    Args:
        items: List of transformed items
        children_map: Dict mapping item_id -> list of child IDs
        item_id_key: The key containing the item ID
    """
    for item in items:
        item_id = item.get(item_id_key)
        if item_id and item_id in children_map:
            item["children_ids"] = children_map[item_id]


def _find_latest_timestamp(items: List[Dict[str, Any]]) -> Optional[str]:
    """Find the most recent updated_at across a list of mobile-transformed items."""
    timestamps = [item.get("updated_at") for item in items if item.get("updated_at")]
    if not timestamps:
        return None
    return max(timestamps)


def _build_project_summary(
    entry: FeedProjectEntry,
    tasks: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
    features: List[Dict[str, Any]],
) -> Dict[str, Any]:
    open_tasks = sum(1 for t in tasks if t["status"] == "open")
    planned_tasks = sum(1 for t in tasks if t["status"] == "planned")
    closed_tasks = sum(1 for t in tasks if t["status"] == "closed")
    open_issues = sum(1 for i in issues if i["status"] != "closed")
    closed_issues = sum(1 for i in issues if i["status"] == "closed")
    in_progress_features = sum(1 for f in features if f["status"] == "in-progress")
    completed_features = sum(1 for f in features if f["status"] == "completed")

    all_items = tasks + issues + features
    latest_ts = _find_latest_timestamp(all_items)
    latest_note = None
    if latest_ts:
        for item in all_items:
            if item.get("updated_at") == latest_ts and item.get("last_update_note"):
                latest_note = item["last_update_note"]
                break

    return {
        "project_id": entry.name,
        "name": entry.name,
        "prefix": entry.prefix,
        "status": entry.status,
        "summary": _truncate(entry.metadata.get("summary"), 200) or "",
        "last_sprint": entry.metadata.get("last_sprint") or "",
        "open_tasks": open_tasks,
        "planned_tasks": planned_tasks,
        "closed_tasks": closed_tasks,
        "total_tasks": len(tasks),
        "open_issues": open_issues,
        "closed_issues": closed_issues,
        "total_issues": len(issues),
        "in_progress_features": in_progress_features,
        "completed_features": completed_features,
        "total_features": len(features),
        "updated_at": latest_ts,
        "last_update_note": latest_note,
    }


# ---------------------------------------------------------------------------
# Closed-item age filter
# ---------------------------------------------------------------------------


def _is_stale_closed_item(record: Dict[str, Any], cutoff: dt.datetime) -> bool:
    """Return True if the record is in a closed/complete status AND its most recent
    history timestamp is older than *cutoff*.  Records without parseable timestamps
    are kept (safe default).
    """
    status = str(record.get("status", "")).strip().lower()
    if status not in ("closed", "complete", "completed"):
        return False
    # Use updated_at first, fall back to last history entry timestamp
    ts_str = record.get("updated_at") or ""
    if not ts_str:
        history = record.get("history")
        if isinstance(history, list) and history:
            last = history[-1]
            if isinstance(last, dict):
                ts_str = str(last.get("timestamp", ""))
    if not ts_str:
        return False  # no timestamp — keep the item
    try:
        item_ts = dt.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return item_ts < cutoff
    except (ValueError, TypeError):
        return False  # unparseable — keep the item


def _filter_stale_closed(
    records: List[Dict[str, Any]],
    max_age_days: int = CLOSED_ITEM_MAX_AGE_DAYS,
) -> tuple:
    """Filter out closed items older than max_age_days.

    Returns (kept, pruned_count) so callers can log the pruning.
    """
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max_age_days)
    kept = [r for r in records if not _is_stale_closed_item(r, cutoff)]
    return kept, len(records) - len(kept)


# ---------------------------------------------------------------------------
# Feed generation
# ---------------------------------------------------------------------------


def _write_split_tasks(
    tasks_by_project: List[tuple],
    generated_at: str,
    output_dir: Path,
    key_prefix: str,
    minify: bool,
) -> Dict[str, Any]:
    """Write tasks/<project_id>.json for every project; return the tasks.json index manifest payload."""
    tasks_dir = output_dir / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    projects: List[Dict[str, Any]] = []
    for project_id, tasks in tasks_by_project:
        name = urllib.parse.quote(str(project_id), safe="")
        rel = f"tasks/{name}.json"
        path = output_dir / rel
        write_json(
            path,
            {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "project_id": project_id, "tasks": tasks},
            minify=minify,
        )
        projects.append({
            "project_id": project_id,
            "key": f"{key_prefix.rstrip('/')}/{rel}" if key_prefix else rel,
            "count": len(tasks),
            "sha256": object_content_digest(path),
            "bytes": path.stat().st_size,
        })
    return {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "split": True, "projects": projects}


def load_tasks_feed(read_bytes: Any, tasks_key: str) -> Dict[str, Any]:
    """Reader helper for BOTH tasks.json shapes (ENC-TSK-R34 / FR-21).

    ``read_bytes(key) -> bytes`` must return DECODED bytes (ContentStore.read_bytes, or
    read_s3_object_bytes over a get_object response). A monolithic tasks.json is returned as is; a split
    manifest is expanded by reading every ``projects[].key`` and concatenating the tasks, so callers
    always get ``{"generated_at", "version", "tasks": [...]}``."""
    doc = json.loads(read_bytes(tasks_key))
    if not (isinstance(doc, dict) and doc.get("split") is True):
        return doc
    tasks: List[Any] = []
    for project in doc.get("projects", []):
        tasks.extend(json.loads(read_bytes(project["key"])).get("tasks", []))
    return {"generated_at": doc.get("generated_at"), "version": doc.get("version"), "tasks": tasks}


def generate_mobile_feeds(
    project_entries: List[FeedProjectEntry],
    all_project_data: Dict[str, Dict[str, Any]],
    generated_at: str,
    output_dir: Path,
    minify: bool = False,
    split_tasks: bool = False,
    key_prefix: str = "",
) -> Dict[str, Path]:
    """Generate aggregated mobile-optimized JSON feeds across all projects.

    ENC-TSK-R34 (FEED_GZIP path only; the defaults are today's output):
      * ``minify`` - compact JSON (see write_json).
      * ``split_tasks`` - BRD FR-21 / ruling A7: the full tasks.json compressed above 5 MB, so write
        ``tasks/<project_id>.json`` per project and make ``tasks.json`` an index manifest
        ``{generated_at, version, split: true, projects: [{project_id, key, count, sha256, bytes}]}``.
        ``key`` is ``<key_prefix>/tasks/<project_id>.json``; ``sha256`` is object_content_digest of that
        file (generated_at excluded) and ``bytes`` its size, so the manifest only changes when a project does.

    Args:
        project_entries: List of FeedProjectEntry for all projects to include.
        all_project_data: Dict mapping project name → {"tasks": [...], "issues": [...], "features": [...]}.
        generated_at: ISO-8601 timestamp string for the feed's generated_at field.
        output_dir: Local directory to write JSON files into.

    Returns:
        Dict mapping feed name → Path of written JSON file.
    """
    log("START", f"{LOG_PREFIX}: generating mobile feeds -> {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_tasks: List[Dict[str, Any]] = []
    tasks_by_project: List[tuple] = []
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []
    all_lessons: List[Dict[str, Any]] = []
    all_plans: List[Dict[str, Any]] = []
    project_summaries: List[Dict[str, Any]] = []

    total_pruned = 0
    for entry in project_entries:
        proj_data = all_project_data.get(entry.name, {})
        raw_tasks = proj_data.get("tasks", [])
        raw_issues = proj_data.get("issues", [])
        raw_features = proj_data.get("features", [])
        raw_lessons = proj_data.get("lessons", [])
        raw_plans = proj_data.get("plans", [])

        # Filter out closed items older than CLOSED_ITEM_MAX_AGE_DAYS
        raw_tasks, pruned_t = _filter_stale_closed(raw_tasks)
        raw_issues, pruned_i = _filter_stale_closed(raw_issues)
        raw_features, pruned_f = _filter_stale_closed(raw_features)
        raw_lessons, pruned_l = _filter_stale_closed(raw_lessons)
        raw_plans, pruned_p = _filter_stale_closed(raw_plans)
        pruned = pruned_t + pruned_i + pruned_f + pruned_l + pruned_p
        if pruned:
            log("INFO", f"{LOG_PREFIX}: pruned {pruned} stale closed items from {entry.name} (tasks={pruned_t} issues={pruned_i} features={pruned_f} lessons={pruned_l} plans={pruned_p})")
            total_pruned += pruned

        tasks = [_transform_task(t, entry.name) for t in raw_tasks if isinstance(t, dict)]
        issues = [_transform_issue(i, entry.name) for i in raw_issues if isinstance(i, dict)]
        features = [_transform_feature(f, entry.name) for f in raw_features if isinstance(f, dict)]
        lessons = [_transform_lesson(l, entry.name) for l in raw_lessons if isinstance(l, dict)]
        plans = [_transform_plan(p, entry.name) for p in raw_plans if isinstance(p, dict)]

        # Compute and add children_ids for hierarchy queries
        task_children = _compute_children_ids(tasks, "task_id")
        issue_children = _compute_children_ids(issues, "issue_id")
        feature_children = _compute_children_ids(features, "feature_id")

        _add_children_ids_to_items(tasks, task_children, "task_id")
        _add_children_ids_to_items(issues, issue_children, "issue_id")
        _add_children_ids_to_items(features, feature_children, "feature_id")

        all_tasks.extend(tasks)
        tasks_by_project.append((entry.name, tasks))
        all_issues.extend(issues)
        all_features.extend(features)
        all_lessons.extend(lessons)
        all_plans.extend(plans)
        project_summaries.append(_build_project_summary(entry, tasks, issues, features))

    if total_pruned:
        log("INFO", f"{LOG_PREFIX}: total stale closed items pruned from feeds: {total_pruned} (max_age={CLOSED_ITEM_MAX_AGE_DAYS}d)")

    feeds = {
        "projects": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "projects": project_summaries},
        "tasks": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "tasks": all_tasks},
        "issues": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "issues": all_issues},
        "features": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "features": all_features},
        "lessons": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "lessons": all_lessons},
        "plans": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "plans": all_plans},
    }

    output_paths: Dict[str, Path] = {}
    if split_tasks:
        feeds["tasks"] = _write_split_tasks(tasks_by_project, generated_at, output_dir, key_prefix, minify)
    for feed_name, payload in feeds.items():
        out_path = output_dir / f"{feed_name}.json"
        write_json(out_path, payload, minify=minify)
        item_count = len(payload["projects"]) if (split_tasks and feed_name == "tasks") else len(payload[feed_name])
        feed_bytes = out_path.stat().st_size
        feed_kb = feed_bytes / 1024
        log("INFO", f"{LOG_PREFIX}: wrote mobile feed {feed_name}.json ({item_count} items, {feed_kb:.1f}KB) -> {out_path}")
        if feed_bytes > FEED_SIZE_ERROR_BYTES:
            log("ERROR", f"{LOG_PREFIX}: PAYLOAD BUDGET EXCEEDED {feed_name}.json={feed_kb:.1f}KB > {FEED_SIZE_ERROR_BYTES // 1024}KB limit")
        elif feed_bytes > FEED_SIZE_WARN_BYTES:
            log("WARNING", f"{LOG_PREFIX}: payload budget warning {feed_name}.json={feed_kb:.1f}KB > {FEED_SIZE_WARN_BYTES // 1024}KB threshold")
        output_paths[feed_name] = out_path

    log("SUCCESS", f"{LOG_PREFIX}: mobile feeds complete ({len(project_entries)} projects)")
    return output_paths


def _is_stale_archived_document(doc: Dict[str, Any], cutoff: dt.datetime) -> bool:
    """Return True if the document is archived AND its updated_at is older than *cutoff*."""
    status = str(doc.get("status", "")).strip().lower()
    if status != "archived":
        return False
    ts_str = doc.get("updated_at") or doc.get("created_at") or ""
    if not ts_str:
        return False  # no timestamp — keep the item
    try:
        item_ts = dt.datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        return item_ts < cutoff
    except (ValueError, TypeError):
        return False  # unparseable — keep the item


def generate_documents_feed(
    project_entries: List[FeedProjectEntry],
    all_documents_data: Dict[str, List[Dict[str, Any]]],
    generated_at: str,
    output_dir: Path,
    minify: bool = False,
) -> Path:
    """Generate a ``documents.json`` mobile feed from pre-fetched document data.

    Mirrors the ``generate_mobile_feeds()`` pattern: transforms document records,
    filters stale archived docs, and writes a single aggregated JSON file.

    Args:
        project_entries: List of FeedProjectEntry for all projects to include.
        all_documents_data: Dict mapping project name → list of deserialized document dicts.
        generated_at: ISO-8601 timestamp string for the feed's generated_at field.
        output_dir: Local directory to write ``documents.json`` into.

    Returns:
        Path to the written ``documents.json`` file.
    """
    log("START", f"{LOG_PREFIX}: generating documents feed -> {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_documents: List[Dict[str, Any]] = []
    total_pruned = 0
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=CLOSED_ITEM_MAX_AGE_DAYS)

    for entry in project_entries:
        raw_docs = all_documents_data.get(entry.name, [])
        # Filter stale archived documents (same pattern as stale closed tracker items)
        kept = [d for d in raw_docs if not _is_stale_archived_document(d, cutoff)]
        pruned = len(raw_docs) - len(kept)
        if pruned:
            log("INFO", f"{LOG_PREFIX}: pruned {pruned} stale archived documents from {entry.name}")
            total_pruned += pruned

        documents = [_transform_document(d, entry.name) for d in kept if isinstance(d, dict)]
        all_documents.extend(documents)

    if total_pruned:
        log("INFO", f"{LOG_PREFIX}: total stale archived documents pruned: {total_pruned} (max_age={CLOSED_ITEM_MAX_AGE_DAYS}d)")

    payload = {
        "generated_at": generated_at,
        "version": MOBILE_FEED_VERSION,
        "documents": all_documents,
    }

    out_path = output_dir / "documents.json"
    write_json(out_path, payload, minify=minify)
    feed_bytes = out_path.stat().st_size
    feed_kb = feed_bytes / 1024
    log("INFO", f"{LOG_PREFIX}: wrote documents feed documents.json ({len(all_documents)} items, {feed_kb:.1f}KB) -> {out_path}")
    if feed_bytes > FEED_SIZE_ERROR_BYTES:
        log("ERROR", f"{LOG_PREFIX}: PAYLOAD BUDGET EXCEEDED documents.json={feed_kb:.1f}KB > {FEED_SIZE_ERROR_BYTES // 1024}KB limit")
    elif feed_bytes > FEED_SIZE_WARN_BYTES:
        log("WARNING", f"{LOG_PREFIX}: payload budget warning documents.json={feed_kb:.1f}KB > {FEED_SIZE_WARN_BYTES // 1024}KB threshold")

    log("SUCCESS", f"{LOG_PREFIX}: documents feed complete ({len(project_entries)} projects, {len(all_documents)} documents)")
    return out_path


def check_freshness_sla(
    generated_at: str,
    all_project_data: Dict[str, Dict[str, Any]],
    sla_seconds: int = FRESHNESS_SLA_SECONDS,
) -> bool:
    """Compare generated_at against the most recent updated_at across all source records.

    Emits a WARNING if the feed lags behind the newest source record by more than
    sla_seconds. Returns True if within SLA, False if stale.
    """
    try:
        gen_ts = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        log("WARNING", f"{LOG_PREFIX}: cannot parse generated_at={generated_at} for freshness check")
        return True  # can't check — assume OK

    newest_source: Optional[dt.datetime] = None
    for proj_data in all_project_data.values():
        for record_list in proj_data.values():
            if not isinstance(record_list, list):
                continue
            for record in record_list:
                if not isinstance(record, dict):
                    continue
                ts_str = record.get("updated_at") or ""
                if not ts_str:
                    history = record.get("history")
                    if isinstance(history, list) and history:
                        last = history[-1]
                        if isinstance(last, dict):
                            ts_str = str(last.get("timestamp", ""))
                if not ts_str:
                    continue
                try:
                    item_ts = dt.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if newest_source is None or item_ts > newest_source:
                        newest_source = item_ts
                except (ValueError, TypeError):
                    continue

    if newest_source is None:
        return True  # no source timestamps — nothing to compare

    delta = (gen_ts - newest_source).total_seconds()
    # If generated_at is *before* the newest source record, that's also stale
    if delta < 0:
        delta = abs(delta)

    if delta > sla_seconds:
        log(
            "WARNING",
            f"{LOG_PREFIX}: FRESHNESS SLA BREACH — feed generated_at={generated_at} "
            f"lags newest source record by {delta:.0f}s (SLA={sla_seconds}s)",
        )
        return False

    log("INFO", f"{LOG_PREFIX}: freshness SLA OK — delta={delta:.0f}s (SLA={sla_seconds}s)")
    return True


def generate_reference_docs(
    project_entries: List[FeedProjectEntry],
    output_dir: Path,
) -> Dict[str, Path]:
    """Copy each project's *-reference.md into output_dir/reference/{project_id}.md.

    NOTE: In the cloud Lambda context, this function reads reference docs from S3
    (using the DynamoDB reference metadata row) rather than from the local filesystem.
    In local context, this copies from the local agent-reference/ directory.
    This local-filesystem version is used by project_json_sync.py.
    """
    ref_dir = output_dir / "reference"
    ref_dir.mkdir(parents=True, exist_ok=True)
    output_paths: Dict[str, Path] = {}
    for entry in project_entries:
        agent_ref_dir = entry.path / AGENT_REF_DIRNAME
        if not agent_ref_dir.exists():
            continue
        md_candidates = sorted(agent_ref_dir.glob("*-reference.md"))
        if not md_candidates:
            log("WARNING", f"{LOG_PREFIX}: no *-reference.md found for project={entry.name}")
            continue
        src_md = md_candidates[0]
        dest_md = ref_dir / f"{entry.name}.md"
        dest_md.write_bytes(src_md.read_bytes())
        log("INFO", f"{LOG_PREFIX}: wrote reference doc {entry.name}.md -> {dest_md}")
        output_paths[entry.name] = dest_md
    log("SUCCESS", f"{LOG_PREFIX}: reference docs copied ({len(output_paths)} projects)")
    return output_paths


# ---------------------------------------------------------------------------
# ENC-TSK-R34 (ENC-PLN-100 C3.1, BRD FR-20 / FR-21): content-hash diffing + gzip payloads
# ---------------------------------------------------------------------------

# BRD FR-21 / ruling A7: gzip first, split tasks.json by project (with an index manifest) ONLY if it is
# still larger than this when compressed. Measured against a real-generator fixture: not needed
# (see test_content_diff_r34); the publisher logs a WARNING and reports ``split_required`` if it ever is.
FEED_GZIP_SPLIT_THRESHOLD_BYTES = 5 * 1024 * 1024
_GZIP_LEVEL = 6
# write_json() emits indent=2 with sorted keys, so the top-level ``generated_at`` is the only key that
# begins a line with exactly two spaces. Nested keys sit at >= 4 spaces, and a raw newline can never occur
# inside a JSON string, so this needle cannot match anything else.
_GENERATED_AT_NEEDLE = b'\n  "generated_at": "'
_COMPACT_PARSE_LIMIT_BYTES = 1024 * 1024
_MINIFIED_STAMP = re.compile(rb'\{"generated_at":"[^"]*",?')


def object_content_digest(path: Path) -> str:
    """SHA-256 of an object's CONTENT, ignoring the per-run ``generated_at`` stamp.

    Every feed JSON carries a top-level ``generated_at`` that changes on every publish, so a raw hash
    would never match and FR-20 would never skip anything. For the indent=2 JSON that write_json()
    produces the ``generated_at`` line is excluded from the hash without parsing (the 25 MB tasks.json
    must not be parsed inside a 512 MB Lambda); small compact JSON (deploy-pending.json) is parsed and
    re-dumped canonically; anything else (reference/*.md) is hashed raw."""
    raw = path.read_bytes()
    h = hashlib.sha256()
    if path.suffix.lower() == ".json":
        m = _MINIFIED_STAMP.match(raw)
        if m:  # dumps_minified layout: the stamp is the first member
            h.update(b"{")
            h.update(memoryview(raw)[m.end():])
            return h.hexdigest()
        start = raw.find(_GENERATED_AT_NEEDLE)
        if start >= 0:
            end = raw.find(b"\n", start + 1)
            end = len(raw) if end < 0 else end
            view = memoryview(raw)
            h.update(view[: start + 1])
            h.update(view[end + 1:])
            return h.hexdigest()
        if len(raw) <= _COMPACT_PARSE_LIMIT_BYTES:
            try:
                doc = json.loads(raw)
            except ValueError:
                doc = None
            if isinstance(doc, dict):
                doc.pop("generated_at", None)
                h.update(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                return h.hexdigest()
    h.update(raw)
    return h.hexdigest()


def gzip_file(src: Path, dst: Path, level: int = _GZIP_LEVEL) -> int:
    """Stream-compress ``src`` to ``dst`` (mtime=0 -> deterministic bytes). Returns the stored size."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, dst.open("wb") as raw_out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, compresslevel=level, mtime=0) as gz:
            shutil.copyfileobj(fin, gz, 1024 * 1024)
    return dst.stat().st_size


def decode_s3_body(body: bytes, content_encoding: Optional[str]) -> bytes:
    """gunzip ``body`` when the object carries ``Content-Encoding: gzip`` (boto3 does NOT do this)."""
    if content_encoding and "gzip" in str(content_encoding).lower():
        return gzip.decompress(body)
    return body


def read_s3_object_bytes(resp: Dict[str, Any]) -> bytes:
    """The decoded bytes of a ``get_object`` response: honors ``ContentEncoding`` (ENC-TSK-R34 / FR-21).

    Every S3-API reader of a feed object must read through this (or ContentStore.read_bytes, which
    applies the same rule) once FEED_GZIP stores the JSON objects gzip-encoded."""
    return decode_s3_body(resp["Body"].read(), resp.get("ContentEncoding"))



def generate_reference_docs_from_s3(
    project_entries: List[FeedProjectEntry],
    output_dir: Path,
    ddb,
    table: str = DEFAULT_TRACKER_TABLE,
    s3_client=None,
) -> Dict[str, Path]:
    """Cloud variant: read reference docs from S3 using DynamoDB metadata rows.

    Used by the cloud Lambda feed publisher where no local filesystem has the
    reference docs. For each project, reads the reference#{project} DynamoDB row
    to get the s3_key, then downloads from S3 and writes to output_dir/reference/.

    DVP-TSK-B53 (isolation W4n): a row naming the legacy feed bucket (FEED_BUCKET) is read through the feed
    ContentStore (content-first, legacy fallback on a miss); a row naming any other bucket is read raw.
    """
    require_boto3()
    s3 = s3_client or boto3.client("s3", region_name="us-east-1")
    legacy_bucket = (os.environ.get("FEED_BUCKET") or DEFAULT_MOBILE_S3_BUCKET).strip()
    store = _feed_content_store(s3, legacy_bucket)
    ref_dir = output_dir / "reference"
    ref_dir.mkdir(parents=True, exist_ok=True)
    output_paths: Dict[str, Path] = {}

    for entry in project_entries:
        sk = f"reference#{entry.name}"
        key_typed = {"project_id": {"S": entry.name}, "record_id": {"S": sk}}
        try:
            resp = ddb.get_item(TableName=table, Key=key_typed, ConsistentRead=True)
        except (BotoCoreError, ClientError) as exc:  # type: ignore[misc]
            log("WARN", f"{LOG_PREFIX}: DynamoDB get_item reference#{entry.name} failed: {exc}")
            continue

        item_raw = resp.get("Item")
        if not item_raw:
            log("INFO", f"{LOG_PREFIX}: no reference metadata for project={entry.name}, skipping")
            continue

        meta = _ddb_deserialize_item(item_raw)
        s3_key = meta.get("s3_key", "")
        s3_bucket = meta.get("s3_bucket", "jreese-net")
        if not s3_key:
            log("WARN", f"{LOG_PREFIX}: reference row for {entry.name} has no s3_key, skipping")
            continue

        try:
            if s3_bucket == legacy_bucket:
                s3_resp = store.get_object(s3_key)
            else:
                s3_resp = s3.get_object(Bucket=s3_bucket, Key=s3_key)
            body = read_s3_object_bytes(s3_resp)  # ENC-TSK-R34: honors Content-Encoding: gzip
        except Exception as exc:
            log("ERROR", f"{LOG_PREFIX}: S3 download failed for {entry.name}: {exc}")
            continue

        dest_md = ref_dir / f"{entry.name}.md"
        dest_md.write_bytes(body)
        log("INFO", f"{LOG_PREFIX}: downloaded reference {entry.name}.md from s3://{s3_bucket}/{s3_key}")
        output_paths[entry.name] = dest_md

    log("SUCCESS", f"{LOG_PREFIX}: reference docs from S3 ({len(output_paths)} projects)")
    return output_paths


# ---------------------------------------------------------------------------
# S3 publication
# ---------------------------------------------------------------------------


def _feed_content_store(s3_client: Any, legacy_bucket: str) -> Any:
    """DVP-TSK-B09 (isolation W4): the store that decides which bucket(s) feed uploads land in.

    CONTENT_STORE_MODE=legacy (default) uploads to ``legacy_bucket`` exactly as before; dual also uploads to
    CONTENT_BUCKET (S3_ENV_PREFIX stripped). CONTENT_STORE_READ=legacy keeps every read on the legacy bucket.
    """
    try:
        from content_store import ContentStore  # shipped to the function root by .build_extras
    except ImportError:  # local tests: the canonical shared-layer copy
        from enceladus_shared.content_store import ContentStore
    return ContentStore(
        s3_client,
        mode=(os.environ.get("CONTENT_STORE_MODE") or "legacy").strip().lower(),
        content_bucket=(os.environ.get("CONTENT_BUCKET") or "").strip(),
        legacy_bucket=legacy_bucket,
        legacy_key_prefix=os.environ.get("S3_ENV_PREFIX", ""),
        read_mode=(os.environ.get("CONTENT_STORE_READ") or "auto").strip().lower(),
    )


def publish_mobile_feeds_to_s3(
    feed_dir: Path,
    bucket: str = DEFAULT_MOBILE_S3_BUCKET,
    s3_prefix: str = DEFAULT_MOBILE_S3_PREFIX,
    dry_run: bool = False,
    cache_control: Optional[str] = None,
    previous_hashes: Optional[Dict[str, str]] = None,
    gzip_json: bool = False,
    report: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Upload mobile feed JSON/MD files from feed_dir to s3://bucket/s3_prefix/.

    S3 objects are tagged with Cache-Control: max-age=0, s-maxage=30, must-revalidate.
    Browsers always revalidate (max-age=0) while CloudFront edge caches serve the
    object for up to 30 seconds (s-maxage=30), reduced from 300s to improve feed
    freshness SLA. Returns the list of S3 keys uploaded.

    ENC-TSK-R26: ``cache_control`` overrides that header (the coalesced publisher passes
    "max-age=60" so freshness rides a 60 s TTL instead of a CloudFront invalidation).
    None keeps the header above, byte-identical to before.

    ENC-TSK-R34 (all three default to today's behavior):
      * ``previous_hashes`` (FR-20) - the {s3_key: content digest} map of the last publish. When given,
        an object whose digest (generated_at excluded) is unchanged is NOT put; the returned list is only
        the keys actually written. None = no diffing, every object is put.
      * ``gzip_json`` (FR-21) - JSON objects are stored gzip-compressed with ``Content-Encoding: gzip``;
        reference/*.md are never compressed.
      * ``report`` - filled in place: ``hashes`` (the new map, only objects confirmed written or
        confirmed unchanged - safe to persist even when a later put raises), ``changed``, ``skipped``,
        ``raw_bytes``/``stored_bytes`` per gzipped key and ``split_required`` (compressed > 5 MB).
    """
    object_cache_control = cache_control or _MOBILE_FEED_CACHE_CONTROL
    require_boto3()
    s3_client = boto3.client("s3", region_name="us-east-1")
    store = _feed_content_store(s3_client, bucket)

    uploaded: List[str] = []
    diffing = previous_hashes is not None
    new_hashes: Dict[str, str] = {}
    skipped: List[str] = []
    gz_sizes: Dict[str, Dict[str, int]] = {}
    split_required: List[str] = []
    gz_dir: Optional[Path] = None
    if report is not None:
        report.update(hashes=new_hashes, changed=uploaded, skipped=skipped, gzip=gz_sizes, split_required=split_required)
    # Walk the feed directory recursively to catch reference/*.md too
    try:
        # A split index manifest (tasks.json beside a tasks/ dir) goes LAST, so a reader never sees a
        # manifest that points at a project file which has not been written yet (ENC-TSK-R34).
        ordered = sorted(feed_dir.rglob("*"))
        ordered.sort(key=lambda q: q.suffix.lower() == ".json" and q.is_file() and (q.parent / q.stem).is_dir())
        for local_path in ordered:
            if not local_path.is_file():
                continue
            rel = local_path.relative_to(feed_dir)
            s3_key = f"{s3_prefix}/{rel.as_posix()}"
            suffix = local_path.suffix.lower()

            if suffix == ".json":
                content_type = "application/json"
            elif suffix == ".md":
                content_type = "text/markdown; charset=utf-8"
            else:
                log("INFO", f"{LOG_PREFIX}: skipping non-feed file {rel}")
                continue

            digest: Optional[str] = None
            if diffing:
                digest = object_content_digest(local_path)
                if previous_hashes.get(s3_key) == digest:
                    new_hashes[s3_key] = digest
                    skipped.append(s3_key)
                    continue

            if dry_run:
                log("INFO", f"{LOG_PREFIX}: [DRY-RUN] s3 upload {local_path.name} -> s3://{bucket}/{s3_key}")
                uploaded.append(s3_key)
                continue

            extra_args: Dict[str, Any] = {
                "CacheControl": object_cache_control,
                "ContentType": content_type,
            }
            upload_path = local_path
            if gzip_json and suffix == ".json":
                if gz_dir is None:
                    gz_dir = Path(tempfile.mkdtemp(prefix="feed-gz-"))
                upload_path = gz_dir / (rel.as_posix().replace("/", "__") + ".gz")
                raw_size = local_path.stat().st_size
                stored_size = gzip_file(local_path, upload_path)
                extra_args["ContentEncoding"] = "gzip"
                gz_sizes[s3_key] = {"raw_bytes": raw_size, "stored_bytes": stored_size}
                log("INFO", f"{LOG_PREFIX}: gzip {rel} {raw_size} -> {stored_size} bytes")
                if stored_size > FEED_GZIP_SPLIT_THRESHOLD_BYTES:
                    split_required.append(s3_key)
                    log(
                        "WARNING",
                        f"{LOG_PREFIX}: {rel} is {stored_size} bytes gzipped (> {FEED_GZIP_SPLIT_THRESHOLD_BYTES}); "
                        "BRD FR-21 / ruling A7 requires splitting it by project with an index manifest",
                    )

            store.upload_file(str(upload_path), s3_key, extra_args)
            log("INFO", f"{LOG_PREFIX}: uploaded {rel} -> s3://{bucket}/{s3_key}")
            uploaded.append(s3_key)
            if upload_path is not local_path:
                try:
                    upload_path.unlink()
                except OSError:
                    pass
            if digest is not None:
                new_hashes[s3_key] = digest  # recorded only after the put returned
    finally:
        if gz_dir is not None:
            shutil.rmtree(gz_dir, ignore_errors=True)

    log(
        "SUCCESS",
        f"{LOG_PREFIX}: mobile feed publish complete ({len(uploaded)} files -> s3://{bucket}/{s3_prefix}/)",
    )
    return uploaded


# ---------------------------------------------------------------------------
# CloudFront invalidation
# ---------------------------------------------------------------------------


def invalidate_mobile_cf(
    distribution_id: str = DEFAULT_MOBILE_CF_DISTRIBUTION,
    paths: Optional[List[str]] = None,
    dry_run: bool = False,
) -> Optional[str]:
    """Create a CloudFront invalidation for the mobile feed paths.

    Returns the invalidation ID, or None on dry-run / error.
    """
    require_boto3()
    cf_paths = paths or MOBILE_CF_INVALIDATION_PATHS
    caller_ref = dt.datetime.now(tz=dt.timezone.utc).strftime("sync-%Y%m%d%H%M%S")

    if dry_run:
        log(
            "INFO",
            f"{LOG_PREFIX}: [DRY-RUN] CloudFront invalidation distribution={distribution_id} paths={cf_paths}",
        )
        return None

    cf_client = boto3.client("cloudfront", region_name="us-east-1")
    resp = cf_client.create_invalidation(
        DistributionId=distribution_id,
        InvalidationBatch={
            "Paths": {"Quantity": len(cf_paths), "Items": cf_paths},
            "CallerReference": caller_ref,
        },
    )
    inv_id = resp["Invalidation"]["Id"]
    log(
        "SUCCESS",
        f"{LOG_PREFIX}: CloudFront invalidation created id={inv_id} "
        f"distribution={distribution_id} paths={cf_paths}",
    )
    return inv_id


# ---------------------------------------------------------------------------
# SNS + EventBridge signals
# ---------------------------------------------------------------------------


def publish_sync_message(
    project_name: str,
    sync_date: dt.date,
    artifact_names: List[str],
    sns_topic: str = DEFAULT_SNS_TOPIC,
    sns_region: Optional[str] = None,
    sync_run_id: Optional[str] = None,
    dry_run: bool = False,
) -> None:
    """Publish a structured SNS message describing the sync results.

    Simplified signature vs. project_json_sync.py — accepts project_name and
    artifact_names directly rather than the full ProjectEntry + output paths.
    """
    if not sns_topic:
        return

    run_id = sync_run_id or dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%d%H%M")
    message = {
        "project": project_name,
        "sync_date": sync_date.isoformat(),
        "artifacts": artifact_names,
        "sync_run_id": run_id,
    }

    if dry_run:
        log(
            "INFO",
            f"{LOG_PREFIX}: [DRY-RUN] sns publish project={project_name} "
            f"topic={sns_topic} payload={json.dumps(message)}",
        )
        return

    require_boto3()
    sns_client = (
        boto3.client("sns", region_name=sns_region)
        if sns_region
        else boto3.client("sns")
    )

    try:
        sns_client.publish(TopicArn=sns_topic, Message=json.dumps(message))
        log(
            "INFO",
            f"{LOG_PREFIX}: published SNS message project={project_name} topic={sns_topic}",
        )
    except (BotoCoreError, ClientError) as exc:  # type: ignore[misc]
        log(
            "ERROR",
            f"{LOG_PREFIX}: failed SNS publish project={project_name} topic={sns_topic}: {exc}",
        )
        raise


def publish_eventbridge_event(
    message: Dict[str, Any],
    bus_name: str = DEFAULT_EVENT_BUS,
    dry_run: bool = False,
) -> None:
    """Publish a detail event to EventBridge for Trino/Superset pipeline."""
    if dry_run:
        log(
            "INFO",
            f"{LOG_PREFIX}: [DRY-RUN] eventbridge put_event bus={bus_name} "
            f"detail={json.dumps(message)}",
        )
        return

    if boto3 is None:
        log("WARNING", f"{LOG_PREFIX}: boto3 unavailable, skipping EventBridge publish")
        return

    events_client = boto3.client("events")
    response = events_client.put_events(
        Entries=[
            {
                "Source": EVENT_SOURCE,
                "DetailType": EVENT_DETAIL_TYPE,
                "Detail": json.dumps(message),
                "EventBusName": bus_name,
            }
        ]
    )
    if response.get("FailedEntryCount"):
        raise SystemExit(f"EventBridge put_events failed: {response}")
    log(
        "INFO",
        f"{LOG_PREFIX}: published EventBridge event bus={bus_name} source={EVENT_SOURCE}",
    )


def write_analytics_sync_stage(
    project_name: str,
    project_data: Dict[str, Any],
    bucket: str = ANALYTICS_S3_BUCKET,
    region: str = DEFAULT_TRACKER_REGION,
    dry_run: bool = False,
) -> Dict[str, str]:
    """Write per-artifact JSON to the analytics sync-stage S3 path.

    Mirrors the S3 path convention used by project_json_sync.py so the
    downstream devops-json-to-parquet-transformer Lambda can locate and
    convert the files without any changes.

    Path: s3://{bucket}/{base}/sync-stage/{artifact}/project={project}/ingest_ts={ts}/{artifact}.json

    Returns a stage_prefixes dict mapping artifact names to their S3 URI
    prefixes, suitable for inclusion in an EventBridge payload consumed by
    the transformer's expand_message().
    """
    now_pst = dt.datetime.now(tz=SYNC_TIMEZONE)
    sync_suffix = now_pst.strftime(SYNC_TS_FORMAT)

    stage_prefixes: Dict[str, str] = {}

    for artifact in ANALYTICS_ARTIFACTS:
        records = project_data.get(artifact, [])
        dir_key = "/".join([
            ANALYTICS_BASE_PREFIX,
            ANALYTICS_STAGE_SUBPATH,
            artifact,
            f"project={project_name}",
            f"ingest_ts={sync_suffix}",
        ])
        s3_key = f"{dir_key}/{artifact}.json"
        s3_prefix_uri = f"s3://{bucket}/{dir_key}/"

        if dry_run:
            log(
                "INFO",
                f"{LOG_PREFIX}: [DRY-RUN] analytics sync-stage "
                f"project={project_name} artifact={artifact} key={s3_key} records={len(records)}",
            )
            stage_prefixes[artifact] = s3_prefix_uri
            continue

        require_boto3()
        s3_client = boto3.client("s3", region_name=region)
        s3_client.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=json.dumps(records, indent=2, sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        log(
            "INFO",
            f"{LOG_PREFIX}: wrote analytics sync-stage "
            f"project={project_name} artifact={artifact} key=s3://{bucket}/{s3_key} records={len(records)}",
        )
        stage_prefixes[artifact] = s3_prefix_uri

    return stage_prefixes
