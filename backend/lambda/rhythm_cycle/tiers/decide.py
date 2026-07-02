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
from metrics import publish_lyapunov

logger = logging.getLogger(__name__)
_sns = boto3.client("sns")


def _open_leaf_tasks() -> List[Dict[str, Any]]:
    if not TRACKER_API_BASE:
        return []
    url = f"{TRACKER_API_BASE}/{PROJECT_ID}/records"
    data = get_json(url, {"status": "open", "record_type": "task", "page_size": 100})
    records = data.get("records") or []
    return [r for r in records if not r.get("parent") and r.get("orphan")]


def _dispatch_plan_dry_run(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not COORDINATION_API_BASE:
        return {"dry_run": True, "dispatches": [], "reason": "coordination_api_unconfigured"}
    url = f"{COORDINATION_API_BASE}/api/v1/coordination/dispatch-plan/dry-run"
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
    url = f"{TRACKER_API_BASE}/{PROJECT_ID}/escalation"
    return post_json(
        url,
        {
            "mutation_type": "deploy_arc_change",
            "target_record_id": target_record_id,
            "summary": summary,
            "requested_by_session": "rhythm-decide-beat",
        },
    )


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

    leaves = _open_leaf_tasks()
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
        "grooming": grooming,
    }
    keys = write_artifact("decide", artifact, datetime.now(timezone.utc))
    artifact.update(keys)
    _notify_beat(proposals, escalated)
    return artifact
