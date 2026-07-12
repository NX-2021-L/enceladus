"""Sense beat — cheap reads only (ENC-TSK-K80)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr

from artifact_store import read_latest, write_artifact
from config import AGENT_SESSIONS_TABLE, PROJECTS_TABLE, PROJECT_ID, TRACKER_API_BASE
from http_client import get_json

logger = logging.getLogger(__name__)
_ddb = boto3.resource("dynamodb")


def _session_census() -> List[Dict[str, Any]]:
    table = _ddb.Table(AGENT_SESSIONS_TABLE)
    sessions: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("status").is_in(["allocated", "claimed"]),
    }
    while True:
        resp = table.scan(**scan_kwargs)
        sessions.extend(resp.get("Items", []))
        token = resp.get("LastEvaluatedKey")
        if not token:
            break
        scan_kwargs["ExclusiveStartKey"] = token
    return [
        {
            "session_id": s.get("session_id"),
            "status": s.get("status"),
            "agent_type_id": s.get("agent_type_id"),
            "claimed_at": s.get("claimed_at"),
            "last_activity_at": s.get("last_activity_at"),
        }
        for s in sessions
    ]


def _checkout_census() -> List[Dict[str, Any]]:
    table = _ddb.Table(PROJECTS_TABLE)
    hits: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("checkout_state").eq("checked_out"),
    }
    while True:
        resp = table.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            components = item.get("components") or item.get("task", {}).get("components") or []
            hits.append(
                {
                    "record_id": item.get("item_id") or item.get("record_id"),
                    "checked_out_by": item.get("checked_out_by"),
                    "components": components,
                }
            )
        token = resp.get("LastEvaluatedKey")
        if not token:
            break
        scan_kwargs["ExclusiveStartKey"] = token
    return hits


def _open_task_count() -> int:
    if not TRACKER_API_BASE:
        return 0
    # ENC-TSK-N28: gamma tracker API serves /records?project_id=... (the
    # /{project_id}/records path shape 404s).
    url = f"{TRACKER_API_BASE}/records"
    data = get_json(url, {"project_id": PROJECT_ID, "status": "open", "record_type": "task", "page_size": 1})
    return int(data.get("total") or data.get("count") or 0)


def run_sense() -> Dict[str, Any]:
    prior = read_latest("sense") or {}
    prior_open = int(prior.get("open_task_count") or 0)

    sessions = _session_census()
    checkouts = _checkout_census()
    open_count = _open_task_count()
    delta = open_count - prior_open

    snapshot = {
        "beat_type": "sense",
        "session_census": sessions,
        "active_checkouts": checkouts,
        "open_task_count": open_count,
        "open_task_delta": delta,
        "queue_depth": open_count,
        "constraints": {"embeddings": False, "graph_writes": False, "llm_calls": False},
    }
    keys = write_artifact("sense", snapshot, datetime.now(timezone.utc))
    snapshot.update(keys)
    return snapshot
