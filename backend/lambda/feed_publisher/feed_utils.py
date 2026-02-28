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
import json
import sys
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
_STATUS_TASK = {
    "open": "open", "closed": "closed",
    "in-progress": "in_progress", "in_progress": "in_progress",
    "in progress": "in_progress", "planned": "planned",
}
_STATUS_FEATURE = {
    "planned": "planned", "in-progress": "in_progress",
    "in_progress": "in_progress", "in progress": "in_progress",
    "complete": "completed", "completed": "completed",
    "closed": "closed",
}
_STATUS_ISSUE = {
    "open": "open", "closed": "closed",
    "in-progress": "in_progress", "in_progress": "in_progress",
    "in progress": "in_progress",
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


def write_json(path: Path, payload: Any) -> None:
    """Write payload to JSON with deterministic formatting."""
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


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
        ):
            raw_items.extend(page.get("Items", []))
    except (BotoCoreError, ClientError) as exc:  # type: ignore[misc]
        log("ERROR", f"{LOG_PREFIX}: DynamoDB query failed for project={project_entry.name}: {exc}")
        return {"tasks": [], "issues": [], "features": []}

    # Group by record_type (skip reference rows — those are metadata only)
    grouped: Dict[str, List[Dict]] = {"task": [], "issue": [], "feature": []}
    for raw in raw_items:
        item = _ddb_deserialize_item(raw)
        rtype = item.get("record_type")
        if rtype in grouped:
            grouped[rtype].append(_ddb_item_to_yaml_record(item))

    artifact_payloads: Dict[str, Any] = {
        "tasks": grouped["task"],
        "issues": grouped["issue"],
        "features": grouped["feature"],
    }

    log(
        "INFO",
        f"{LOG_PREFIX}: DynamoDB read project={project_entry.name}: "
        f"tasks={len(grouped['task'])} issues={len(grouped['issue'])} "
        f"features={len(grouped['feature'])}",
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
        ):
            raw_items.extend(page.get("Items", []))
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
    in_progress_features = sum(1 for f in features if f["status"] == "in_progress")
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


def generate_mobile_feeds(
    project_entries: List[FeedProjectEntry],
    all_project_data: Dict[str, Dict[str, Any]],
    generated_at: str,
    output_dir: Path,
) -> Dict[str, Path]:
    """Generate aggregated mobile-optimized JSON feeds across all projects.

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
    all_issues: List[Dict[str, Any]] = []
    all_features: List[Dict[str, Any]] = []
    project_summaries: List[Dict[str, Any]] = []

    total_pruned = 0
    for entry in project_entries:
        proj_data = all_project_data.get(entry.name, {})
        raw_tasks = proj_data.get("tasks", [])
        raw_issues = proj_data.get("issues", [])
        raw_features = proj_data.get("features", [])

        # Filter out closed items older than CLOSED_ITEM_MAX_AGE_DAYS
        raw_tasks, pruned_t = _filter_stale_closed(raw_tasks)
        raw_issues, pruned_i = _filter_stale_closed(raw_issues)
        raw_features, pruned_f = _filter_stale_closed(raw_features)
        pruned = pruned_t + pruned_i + pruned_f
        if pruned:
            log("INFO", f"{LOG_PREFIX}: pruned {pruned} stale closed items from {entry.name} (tasks={pruned_t} issues={pruned_i} features={pruned_f})")
            total_pruned += pruned

        tasks = [_transform_task(t, entry.name) for t in raw_tasks if isinstance(t, dict)]
        issues = [_transform_issue(i, entry.name) for i in raw_issues if isinstance(i, dict)]
        features = [_transform_feature(f, entry.name) for f in raw_features if isinstance(f, dict)]

        # Compute and add children_ids for hierarchy queries
        task_children = _compute_children_ids(tasks, "task_id")
        issue_children = _compute_children_ids(issues, "issue_id")
        feature_children = _compute_children_ids(features, "feature_id")

        _add_children_ids_to_items(tasks, task_children, "task_id")
        _add_children_ids_to_items(issues, issue_children, "issue_id")
        _add_children_ids_to_items(features, feature_children, "feature_id")

        all_tasks.extend(tasks)
        all_issues.extend(issues)
        all_features.extend(features)
        project_summaries.append(_build_project_summary(entry, tasks, issues, features))

    if total_pruned:
        log("INFO", f"{LOG_PREFIX}: total stale closed items pruned from feeds: {total_pruned} (max_age={CLOSED_ITEM_MAX_AGE_DAYS}d)")

    feeds = {
        "projects": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "projects": project_summaries},
        "tasks": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "tasks": all_tasks},
        "issues": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "issues": all_issues},
        "features": {"generated_at": generated_at, "version": MOBILE_FEED_VERSION, "features": all_features},
    }

    output_paths: Dict[str, Path] = {}
    for feed_name, payload in feeds.items():
        out_path = output_dir / f"{feed_name}.json"
        write_json(out_path, payload)
        item_count = len(payload[feed_name])
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
    write_json(out_path, payload)
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
    """
    require_boto3()
    s3 = s3_client or boto3.client("s3", region_name="us-east-1")
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
            s3_resp = s3.get_object(Bucket=s3_bucket, Key=s3_key)
            body = s3_resp["Body"].read()
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


def publish_mobile_feeds_to_s3(
    feed_dir: Path,
    bucket: str = DEFAULT_MOBILE_S3_BUCKET,
    s3_prefix: str = DEFAULT_MOBILE_S3_PREFIX,
    dry_run: bool = False,
) -> List[str]:
    """Upload mobile feed JSON/MD files from feed_dir to s3://bucket/s3_prefix/.

    S3 objects are tagged with Cache-Control: max-age=0, s-maxage=300, must-revalidate.
    Browsers always revalidate (max-age=0) while CloudFront edge caches serve the
    object for up to 5 minutes (s-maxage=300), aligned with the SQS FIFO debounce
    window. Returns the list of S3 keys uploaded.
    """
    require_boto3()
    s3_client = boto3.client("s3", region_name="us-east-1")

    uploaded: List[str] = []
    # Walk the feed directory recursively to catch reference/*.md too
    for local_path in sorted(feed_dir.rglob("*")):
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

        if dry_run:
            log("INFO", f"{LOG_PREFIX}: [DRY-RUN] s3 upload {local_path.name} -> s3://{bucket}/{s3_key}")
            uploaded.append(s3_key)
            continue

        s3_client.upload_file(
            str(local_path),
            bucket,
            s3_key,
            ExtraArgs={
                "CacheControl": _MOBILE_FEED_CACHE_CONTROL,
                "ContentType": content_type,
            },
        )
        log("INFO", f"{LOG_PREFIX}: uploaded {rel} -> s3://{bucket}/{s3_key}")
        uploaded.append(s3_key)

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
