"""Decide beat — ADE evaluation + escalations (ENC-TSK-K83/K84/K85)."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3

from artifact_store import read_latest, write_artifact
from config import (
    COORDINATION_API_BASE,
    PROJECT_ID,
    SNS_TOPIC_ARN,
    TRACKER_API_BASE,
    pre_approved_scopes,
)
from http_client import get_json, post_json
from identity import resolve_identity
from metrics import publish_lyapunov

logger = logging.getLogger(__name__)
_sns = boto3.client("sns")

# ENC-TSK-N20 / BRD DOC-44230223DD1C §4.4 (C4): defensive cap on pagination
# depth. Never loop unbounded against the tracker API; if this is hit the
# read is marked truncated in the decide artifact rather than silently
# returning a partial count as if it were complete.
_MAX_PAGES = 50


def _open_leaf_tasks() -> Dict[str, Any]:
    """Cursor-exhausted paginated read of the open task backlog.

    ENC-TSK-N20 / BRD §4.4 (C4): the prior implementation (ENC-ISS-542) issued
    a single page_size=100 request with no cursor follow-through and filtered
    leaves using the legacy `orphan` flag heuristic — silently truncating the
    backlog on any project with more than 100 open tasks, and undercounting
    whenever the orphan flag lagged reality. This version pages until the
    tracker API's cursor (`next_cursor`) is exhausted, or the `_MAX_PAGES`
    guard above is hit, and defines a leaf as a record with no `parent` field
    set at all (explicit parent-absence) rather than the orphan flag.

    Returns a dict: {leaves, page_count, cursor_terminus, truncated}.
    cursor_terminus is the final outstanding next_cursor value if pagination
    was cut short by the max_pages guard, else None (natural exhaustion) —
    this is what makes the metric's completeness auditable from the decide
    artifact (BRD §4.4).
    """
    if not TRACKER_API_BASE:
        return {"leaves": [], "page_count": 0, "cursor_terminus": None, "truncated": False}

    # ENC-TSK-N28: gamma tracker API serves /records?project_id=... (the
    # /{project_id}/records path shape 404s).
    url = f"{TRACKER_API_BASE}/records"
    leaves: List[Dict[str, Any]] = []
    cursor = ""
    page_count = 0
    truncated = False

    for _ in range(_MAX_PAGES):
        params: Dict[str, Any] = {
            "project_id": PROJECT_ID,
            "status": "open",
            "record_type": "task",
            "page_size": 100,
        }
        if cursor:
            params["next_cursor"] = cursor
        data = get_json(url, params)
        page_count += 1
        records = data.get("records") or []
        leaves.extend(r for r in records if not r.get("parent"))
        cursor = data.get("next_cursor") or ""
        if not cursor:
            break
    else:
        # Loop ran out of iterations without the cursor naturally emptying —
        # more pages remain beyond the defensive cap.
        truncated = bool(cursor)

    return {
        "leaves": leaves,
        "page_count": page_count,
        "cursor_terminus": cursor or None,
        "truncated": truncated,
    }


def _dispatch_plan_dry_run(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not COORDINATION_API_BASE:
        return {"dry_run": True, "dispatches": [], "reason": "coordination_api_unconfigured"}
    # ENC-TSK-N28: COORDINATION_API_BASE already ends in /api/v1 — do not re-prefix.
    url = f"{COORDINATION_API_BASE}/coordination/dispatch-plan/dry-run"
    try:
        return post_json(url, {"project_id": PROJECT_ID, "sense_snapshot": snapshot})
    except Exception as exc:
        logger.warning("dispatch dry-run failed: %s", exc)
        return {"dry_run": True, "error": str(exc), "dispatches": []}


def _in_preapproved_scope(record_id: str, scopes: List[str]) -> bool:
    rid = (record_id or "").strip()
    for scope in scopes:
        if rid == scope or rid.startswith(scope):
            return True
    return False


def _create_escalation(target_record_id: str, summary: str) -> Dict[str, Any]:
    # TODO(ENC-TSK-N28 follow-up): escalation route shape unverified on gamma APIGW.
    # tracker_mutation's _RE_ESCALATION accepts /{project}/escalation (optional
    # /api/v1/tracker prefix), but no explicit RouteKey exists in
    # infrastructure/cloudformation — orchestrator ENC-SES-09B to confirm live shape.
    url = f"{TRACKER_API_BASE}/{PROJECT_ID}/escalation"

    # ENC-TSK-N21 / BRD §4.3: the prior hardcoded requested_by_session=
    # "rhythm-decide-beat" never resolved to a real governed session and could
    # never carry a Session Claim ID (sci) — any beat-originated escalation
    # would fail closed once the FTR-122 SCI gate tightens past its
    # grandfather window. identity.resolve_identity() resolves-or-mints (and
    # caches across beats) a real ENC-SES session + sci for the rhythm's own
    # identity; tracker_mutation's escalation.request handler reads the
    # session id from requested_by.session_id (falling back to
    # write_source.provider) and records requested_by.sci_present. When
    # identity resolution is degraded (RHYTHM_AGENT_TYPE_ID unset or the
    # coordination API unreachable) this falls back to the exact pre-N21
    # pseudo-identity string, preserving prior behavior rather than raising.
    identity = resolve_identity()
    session_id = str(identity.get("session_id") or "") or "rhythm-decide-beat"
    body: Dict[str, Any] = {
        "mutation_type": "deploy_arc_change",
        "target_record_id": target_record_id,
        "summary": summary,
        "requested_by_session": session_id,
        "requested_by": {
            "session_id": session_id,
            "agent_type_id": str(identity.get("agent_type_id") or ""),
            "sci_present": bool(identity.get("sci")),
        },
    }
    if identity.get("sci"):
        body["sci"] = identity["sci"]
    return post_json(url, body)


def _notify_beat(proposals: List[Dict[str, Any]], escalations: List[str]) -> None:
    if not SNS_TOPIC_ARN:
        return
    body = {
        "beat": "decide",
        "pending_escalations": escalations,
        "proposal_count": len(proposals),
        "at": datetime.now(timezone.utc).isoformat(),
    }
    _sns.publish(TopicArn=SNS_TOPIC_ARN, Subject="Rhythm Decide beat summary", Message=json.dumps(body))


def run_decide() -> Dict[str, Any]:
    sense = read_latest("sense") or {}
    prior_decide = read_latest("decide") or {}
    prior_leaves = int(prior_decide.get("backlog_open_leaves") or 0)

    backlog = _open_leaf_tasks()
    leaves = backlog["leaves"]
    leaf_count = len(leaves)
    delta = leaf_count - prior_leaves
    grooming = bool(os.environ.get("RHYTHM_GROOMING_EVENT", "").lower() in ("1", "true", "yes"))

    publish_lyapunov(leaf_count, delta, grooming=grooming)

    plan = _dispatch_plan_dry_run(sense)
    proposals = plan.get("dispatches") or plan.get("proposals") or []
    scopes = pre_approved_scopes()

    dispatched: List[str] = []
    escalated: List[str] = []
    for prop in proposals:
        rid = str(prop.get("record_id") or prop.get("target_record_id") or "")
        if not rid:
            continue
        if _in_preapproved_scope(rid, scopes):
            dispatched.append(rid)
        else:
            try:
                esc = _create_escalation(rid, f"Rhythm decide beat proposal for {rid}")
                escalated.append(str(esc.get("escalation_id") or esc.get("item_id") or rid))
            except Exception as exc:
                logger.warning("escalation create failed for %s: %s", rid, exc)
                escalated.append(rid)

    artifact = {
        "beat_type": "decide",
        "sense_snapshot_key": sense.get("latest_key"),
        "dispatch_plan": plan,
        "pre_approved_scopes": scopes,
        "dispatched_in_scope": dispatched,
        "escalation_ids": escalated,
        "backlog_open_leaves": leaf_count,
        "backlog_open_leaves_delta": delta,
        # ENC-TSK-N20 / BRD §4.4: page count + cursor terminus make the
        # completeness of the Lyapunov read auditable from the artifact
        # itself, rather than assumed.
        "backlog_page_count": backlog["page_count"],
        "backlog_cursor_terminus": backlog["cursor_terminus"],
        "backlog_pagination_truncated": backlog["truncated"],
        "grooming": grooming,
    }
    keys = write_artifact("decide", artifact, datetime.now(timezone.utc))
    artifact.update(keys)
    _notify_beat(proposals, escalated)
    return artifact
