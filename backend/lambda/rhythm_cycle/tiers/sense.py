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



# ENC-ISS-557 / BRD §4.4 (C4): defensive cap on pagination depth, mirroring
# decide.py's _open_leaf_tasks guard. Never loop unbounded against the
# tracker API; if this is hit the count is marked truncated rather than
# silently presented as exact.
_MAX_PAGES = 50


def _open_task_count() -> Dict[str, Any]:
    """Cursor-exhausted paginated count of the open task backlog.

    ENC-ISS-557: the prior implementation (ENC-ISS-553 fix) issued a single
    page_size=200 request and returned "count" (items in that one page) as
    if it were the true total -- silently plateauing at 200 forever once the
    real backlog passed that size. This version pages via `next_cursor`
    until the tracker API exhausts it, or the `_MAX_PAGES` guard is hit, same
    pattern as decide.py's `_open_leaf_tasks`. sense stays within its
    cheap-reads-only mandate: this is still plain HTTP pagination, no
    embeddings/graph writes/LLM calls, just more of the same call.

    Returns {count, truncated, page_count, cursor_terminus}. truncated=True
    means _MAX_PAGES was hit before the cursor naturally emptied, so `count`
    is a floor, not an exact total.
    """
    if not TRACKER_API_BASE:
        return {"count": 0, "truncated": False, "page_count": 0, "cursor_terminus": None}

    # ENC-ISS-553: N28's /records?project_id=... shape (#1016) live-probed a
    # 200 response but never checked the payload -- tracker_mutation's
    # _RE_PROJECT regex matches the literal "records" segment as {projectId},
    # so it silently queried a nonexistent project and always returned
    # {"records": [], "count": 0}. The real route is {TRACKER_API_BASE}/
    # {PROJECT_ID} with query param "type" (the handler reads "type", not
    # "record_type" -- confirmed live).
    url = f"{TRACKER_API_BASE}/{PROJECT_ID}"
    count = 0
    cursor = ""
    page_count = 0
    truncated = False

    for _ in range(_MAX_PAGES):
        params: Dict[str, Any] = {"status": "open", "type": "task", "page_size": 200}
        if cursor:
            params["next_cursor"] = cursor
        data = get_json(url, params)
        page_count += 1
        count += int(data.get("count") or 0)
        cursor = data.get("next_cursor") or ""
        if not cursor:
            break
    else:
        truncated = bool(cursor)

    return {
        "count": count,
        "truncated": truncated,
        "page_count": page_count,
        "cursor_terminus": cursor or None,
    }


def run_sense() -> Dict[str, Any]:
    prior = read_latest("sense") or {}
    prior_open = int(prior.get("open_task_count") or 0)

    sessions = _session_census()
    checkouts = _checkout_census()
    task_count = _open_task_count()
    open_count = task_count["count"]
    delta = open_count - prior_open

    snapshot = {
        "beat_type": "sense",
        "session_census": sessions,
        "active_checkouts": checkouts,
        "open_task_count": open_count,
        "open_task_count_truncated": task_count["truncated"],
        "open_task_delta": delta,
        "queue_depth": open_count,
        "constraints": {"embeddings": False, "graph_writes": False, "llm_calls": False},
    }
    keys = write_artifact("sense", snapshot, datetime.now(timezone.utc))
    snapshot.update(keys)
    return snapshot
