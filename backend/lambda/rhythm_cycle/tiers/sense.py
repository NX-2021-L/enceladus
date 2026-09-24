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



def _open_task_count() -> Dict[str, Any]:
    """Open task backlog count via the tracker's census route (ENC-PLN-093 O5.2).

    ENC-ISS-557: the prior implementation (ENC-ISS-553 fix) issued a single
    page_size=200 request and returned "count" (items in that one page) as
    if it were the true total -- silently plateauing at 200 forever once the
    real backlog passed that size. A follow-up fix paged via `next_cursor`
    until the tracker API's cursor exhausted, trading that bug for one HTTP
    round trip per 200 open tasks. This version issues a single
    `mode=census` request instead -- the tracker route performs its own
    server-side walk and hands back a true (or honestly floored) count in
    one call, so sense gets an accurate total without paginating itself.
    sense stays within its cheap-reads-only mandate: this is still plain
    HTTP, no embeddings/graph writes/LLM calls, just one call instead of many.

    Returns {count, truncated, page_count, cursor_terminus}. Under the
    census contract there is only ever one call, so page_count is always 1
    and cursor_terminus is always None -- both are kept in the return shape
    for compatibility with existing callers. truncated=True mirrors the
    census route's own `count_truncated`: the server walk hit its own
    budget, so `count` is a floor, not an exact total.
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
    params = {"status": "open", "type": "task", "mode": "census", "page_size": 100}
    data = get_json(f"{TRACKER_API_BASE}/{PROJECT_ID}", params)
    return {
        "count": int(data.get("count") or 0),
        "truncated": bool(data.get("count_truncated")),
        "page_count": 1,
        "cursor_terminus": None,
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
        # ENC-PLN-093 O5.2 (AC-1): telemetry field name the census migration
        # is graded on. Mirrors open_task_count_truncated so existing
        # consumers of that field keep working unchanged.
        "open_count_truncated": task_count["truncated"],
        "open_task_delta": delta,
        "queue_depth": open_count,
        "constraints": {"embeddings": False, "graph_writes": False, "llm_calls": False},
    }
    keys = write_artifact("sense", snapshot, datetime.now(timezone.utc))
    snapshot.update(keys)
    return snapshot
