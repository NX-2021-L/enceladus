"""intake_dedup.py — Intake debounce queue — record-ID dedup + merge (v0.3 contract §6.1.1).

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from config import (
    COORDINATION_GSI_PROJECT,
    COORDINATION_TABLE,
    DEBOUNCE_WINDOW_SECONDS,
    HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL,
    HOST_V2_FLEET_ENABLED,
    HOST_V2_FLEET_FALLBACK_TO_STATIC,
    HOST_V2_FLEET_INSTANCE_TTL_SECONDS,
    HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
    HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
    HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES,
    HOST_V2_FLEET_NAME_PREFIX,
    HOST_V2_FLEET_READINESS_POLL_SECONDS,
    HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS,
    HOST_V2_FLEET_SWEEP_GRACE_SECONDS,
    HOST_V2_FLEET_SWEEP_ON_DISPATCH,
    HOST_V2_FLEET_TAG_MANAGED_BY_VALUE,
    HOST_V2_INSTANCE_ID,
    HOST_V2_TIMEOUT_SECONDS,
    MAX_TITLE_LENGTH,
    _STATE_INTAKE_RECEIVED,
    _STATE_QUEUED,
    logger,
)
from serialization import _deserialize, _now_z, _serialize, _unix_now
from aws_clients import _get_ddb, _get_ec2, _get_ssm
from project_utils import _load_project_meta
from mcp_integration import _compute_governance_hash_local
from tracker_ops import _append_tracker_history, _create_tracker_record_auto
from persistence import _append_state_transition, _update_request

__all__ = [
    "_active_host_dispatches",
    "_cleanup_dispatch_host",
    "_count_active_host_dispatches",
    "_decompose_and_create_tracker_artifacts",
    "_dispatch_uses_host_runtime",
    "_extract_record_ids_from_body",
    "_extract_record_ids_from_request",
    "_find_active_host_dispatch",
    "_find_dedup_match",
    "_find_intake_candidates",
    "_fleet_launch_ready",
    "_launch_fleet_instance",
    "_merge_requests",
    "_promote_expired_intake_requests",
    "_resolve_host_dispatch_target",
    "_sweep_orphan_fleet_hosts",
    "_wait_for_fleet_instance_readiness",
]

# ---------------------------------------------------------------------------
# Intake debounce queue — record-ID dedup + merge (v0.3 contract §6.1.1)
# ---------------------------------------------------------------------------


def _extract_record_ids_from_body(request_body: Dict[str, Any]) -> set:
    """Extract all tracker record IDs referenced anywhere in an incoming request body."""
    ids: set = set()
    _ID_PATTERN = re.compile(r"\b[A-Z]{3}-(?:TSK|ISS|FTR)-\d{3}(?:-[0-9][A-Z])?\b")

    for rid in request_body.get("related_record_ids") or []:
        if isinstance(rid, str) and rid.strip():
            ids.add(rid.strip().upper())

    for outcome in request_body.get("outcomes") or []:
        if isinstance(outcome, str):
            ids.update(_ID_PATTERN.findall(outcome.upper()))

    constraints = request_body.get("constraints")
    if constraints:
        ids.update(_ID_PATTERN.findall(json.dumps(constraints).upper()))

    return ids


def _extract_record_ids_from_request(request: Dict[str, Any]) -> set:
    """Extract record IDs from a persisted coordination request item."""
    ids: set = set()
    _ID_PATTERN = re.compile(r"\b[A-Z]{3}-(?:TSK|ISS|FTR)-\d{3}(?:-[0-9][A-Z])?\b")

    for rid in request.get("related_record_ids") or []:
        if isinstance(rid, str) and rid.strip():
            ids.add(rid.strip().upper())

    for outcome in request.get("outcomes") or []:
        if isinstance(outcome, str):
            ids.update(_ID_PATTERN.findall(outcome.upper()))

    constraints = request.get("constraints")
    if constraints:
        ids.update(_ID_PATTERN.findall(json.dumps(constraints).upper()))

    fid = request.get("feature_id")
    if fid:
        ids.add(fid.upper())
    for tid in request.get("task_ids") or []:
        ids.add(tid.upper())
    for iid in request.get("issue_ids") or []:
        ids.add(iid.upper())

    return ids


def _find_intake_candidates(project_id: str, now_epoch: int) -> List[Dict[str, Any]]:
    """Find all coordination requests in intake_received state within debounce window."""
    ddb = _get_ddb()
    candidates: List[Dict[str, Any]] = []

    try:
        resp = ddb.query(
            TableName=COORDINATION_TABLE,
            IndexName=COORDINATION_GSI_PROJECT,
            KeyConditionExpression="project_id = :pid AND updated_epoch >= :min_epoch",
            FilterExpression="#s = :intake_state",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":pid": _serialize(project_id),
                ":min_epoch": _serialize(now_epoch - DEBOUNCE_WINDOW_SECONDS - 60),
                ":intake_state": _serialize(_STATE_INTAKE_RECEIVED),
            },
            ScanIndexForward=False,
        )
        for raw in resp.get("Items", []):
            item = _deserialize(raw)
            expires = int(item.get("debounce_window_expires_epoch") or 0)
            if expires > now_epoch:
                candidates.append(item)
    except (BotoCoreError, ClientError) as exc:
        logger.warning("intake candidate lookup skipped: %s", exc)

    return candidates


def _dispatch_uses_host_runtime(execution_mode: str) -> bool:
    mode = str(execution_mode or "").strip().lower()
    return mode not in {"claude_agent_sdk", "codex_app_server", "codex_full_auto"}


def _fleet_launch_ready() -> bool:
    return bool(HOST_V2_FLEET_ENABLED and HOST_V2_FLEET_LAUNCH_TEMPLATE_ID)


def _active_host_dispatches(
    project_id: str,
    *,
    current_request_id: str = "",
    instance_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    ddb = _get_ddb()
    now_epoch = _unix_now()
    cutoff = now_epoch - max(HOST_V2_TIMEOUT_SECONDS, 600) - 600
    active: List[Dict[str, Any]] = []
    last_evaluated_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "TableName": COORDINATION_TABLE,
            "IndexName": COORDINATION_GSI_PROJECT,
            "KeyConditionExpression": "project_id = :pid AND updated_epoch >= :cutoff",
            "ExpressionAttributeValues": {
                ":pid": _serialize(project_id),
                ":cutoff": _serialize(cutoff),
            },
            "ScanIndexForward": False,
            "Limit": 50,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key
        resp = ddb.query(**kwargs)
        for raw in resp.get("Items", []):
            item = _deserialize(raw)
            rid = str(item.get("request_id") or "")
            if not rid or rid == current_request_id:
                continue
            state = str(item.get("state") or "")
            if state not in {"dispatching", "running"}:
                continue
            execution_mode = str(item.get("execution_mode") or "")
            if not _dispatch_uses_host_runtime(execution_mode):
                continue
            lock_expires_epoch = int(item.get("lock_expires_epoch") or 0)
            if lock_expires_epoch and lock_expires_epoch < now_epoch:
                continue
            dispatch = item.get("dispatch") or {}
            candidate_instance_id = str(dispatch.get("instance_id") or HOST_V2_INSTANCE_ID)
            if instance_id and candidate_instance_id != instance_id:
                continue
            active.append(
                {
                    "request_id": rid,
                    "state": state,
                    "dispatch_id": str(dispatch.get("dispatch_id") or ""),
                    "command_id": str(dispatch.get("command_id") or ""),
                    "instance_id": candidate_instance_id,
                    "lock_expires_epoch": lock_expires_epoch,
                    "execution_mode": execution_mode,
                    "host_kind": str(dispatch.get("host_kind") or "static"),
                }
            )
        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    return active


def _count_active_host_dispatches(project_id: str, *, current_request_id: str = "") -> int:
    return len(_active_host_dispatches(project_id, current_request_id=current_request_id))


def _find_active_host_dispatch(
    project_id: str,
    current_request_id: str,
    *,
    instance_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    active = _active_host_dispatches(
        project_id,
        current_request_id=current_request_id,
        instance_id=instance_id or HOST_V2_INSTANCE_ID,
    )
    return active[0] if active else None


def _launch_fleet_instance(project_id: str, request_id: str, dispatch_id: str) -> Dict[str, Any]:
    ec2 = _get_ec2()
    name_suffix = dispatch_id.lower().replace("dsp-", "")[:12]
    instance_name = f"{HOST_V2_FLEET_NAME_PREFIX}-{name_suffix}"
    tags = [
        {"Key": "Name", "Value": instance_name},
        {"Key": "enceladus:managed-by", "Value": HOST_V2_FLEET_TAG_MANAGED_BY_VALUE},
        {"Key": "enceladus:project", "Value": str(project_id)},
        {"Key": "enceladus:coordination-request-id", "Value": str(request_id)},
        {"Key": "enceladus:dispatch-id", "Value": str(dispatch_id)},
        {"Key": "enceladus:fleet-node", "Value": "true"},
    ]
    response = ec2.run_instances(
        MinCount=1,
        MaxCount=1,
        LaunchTemplate={
            "LaunchTemplateId": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
            "Version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
        },
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
        InstanceInitiatedShutdownBehavior="terminate",
    )
    instances = response.get("Instances") or []
    if not instances:
        raise RuntimeError("Fleet launch failed: run_instances returned no instances")
    instance = instances[0]
    instance_id = str(instance.get("InstanceId") or "")
    if not instance_id:
        raise RuntimeError("Fleet launch failed: missing InstanceId")
    return {
        "instance_id": instance_id,
        "launch_template_id": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
        "launch_template_version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
        "launched_at": _now_z(),
        "dispatch_id": dispatch_id,
        "project_id": project_id,
    }


def _wait_for_fleet_instance_readiness(instance_id: str) -> Dict[str, Any]:
    deadline = time.time() + max(30, HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS)
    poll_seconds = max(3, HOST_V2_FLEET_READINESS_POLL_SECONDS)
    ec2 = _get_ec2()
    ssm = _get_ssm()
    last_state = "unknown"

    while time.time() < deadline:
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            if code == "InvalidInstanceID.NotFound":
                time.sleep(poll_seconds)
                continue
            raise

        reservations = response.get("Reservations") or []
        if not reservations or not (reservations[0].get("Instances") or []):
            time.sleep(poll_seconds)
            continue
        instance = (reservations[0].get("Instances") or [])[0]
        last_state = str(((instance.get("State") or {}).get("Name") or "unknown")).lower()
        if last_state in {"terminated", "shutting-down", "stopping", "stopped"}:
            raise RuntimeError(f"Fleet instance {instance_id} entered terminal state '{last_state}' before readiness")
        if last_state != "running":
            time.sleep(poll_seconds)
            continue

        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}],
            MaxResults=1,
        )
        details = info.get("InstanceInformationList") or []
        if details and str(details[0].get("PingStatus") or "").lower() == "online":
            return {
                "instance_id": instance_id,
                "state": last_state,
                "ssm_ping_status": "Online",
                "ready_at": _now_z(),
            }
        time.sleep(poll_seconds)

    raise RuntimeError(
        f"Fleet instance {instance_id} readiness timeout after {HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS}s "
        f"(last_state={last_state})"
    )


def _cleanup_dispatch_host(request: Dict[str, Any], reason: str) -> Dict[str, Any]:
    dispatch = dict(request.get("dispatch") or {})
    if str(dispatch.get("host_kind") or "").lower() != "fleet":
        return request
    if not HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL:
        dispatch["host_cleanup_state"] = "skipped_by_config"
        dispatch["host_cleanup_reason"] = reason
        dispatch["host_cleanup_at"] = _now_z()
        request["dispatch"] = dispatch
        return request

    cleanup_state = str(dispatch.get("host_cleanup_state") or "")
    if cleanup_state in {"terminated", "already_terminated"}:
        return request

    instance_id = str(dispatch.get("instance_id") or "")
    if not instance_id:
        return request

    try:
        _get_ec2().terminate_instances(InstanceIds=[instance_id])
        dispatch["host_cleanup_state"] = "terminated"
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        if code == "InvalidInstanceID.NotFound":
            dispatch["host_cleanup_state"] = "already_terminated"
        else:
            dispatch["host_cleanup_state"] = "termination_failed"
            dispatch["host_cleanup_error"] = str(exc)
    dispatch["host_cleanup_reason"] = reason
    dispatch["host_cleanup_at"] = _now_z()
    request["dispatch"] = dispatch
    return request


def _sweep_orphan_fleet_hosts(project_id: str) -> Dict[str, Any]:
    if not _fleet_launch_ready():
        return {"enabled": False, "scanned": 0, "terminated": 0, "kept": 0}

    try:
        active_dispatches = _active_host_dispatches(project_id)
    except Exception as exc:
        logger.warning("fleet sweep skipped: unable to read active dispatches (%s)", exc)
        return {"enabled": True, "error": str(exc), "scanned": 0, "terminated": 0, "kept": 0}

    active_instance_ids = {str(item.get("instance_id") or "") for item in active_dispatches if item.get("instance_id")}
    max_age = max(300, HOST_V2_FLEET_INSTANCE_TTL_SECONDS + HOST_V2_FLEET_SWEEP_GRACE_SECONDS)
    now_epoch = _unix_now()
    filters = [
        {"Name": "tag:enceladus:managed-by", "Values": [HOST_V2_FLEET_TAG_MANAGED_BY_VALUE]},
        {"Name": "tag:enceladus:project", "Values": [project_id]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ]

    scanned = 0
    kept = 0
    terminate_ids: List[str] = []
    try:
        paginator = _get_ec2().get_paginator("describe_instances")
        for page in paginator.paginate(Filters=filters):
            for reservation in page.get("Reservations") or []:
                for instance in reservation.get("Instances") or []:
                    scanned += 1
                    iid = str(instance.get("InstanceId") or "")
                    if not iid:
                        continue
                    if iid in active_instance_ids:
                        kept += 1
                        continue
                    launched_at = instance.get("LaunchTime")
                    launched_epoch = int(launched_at.timestamp()) if hasattr(launched_at, "timestamp") else now_epoch
                    age_seconds = max(0, now_epoch - launched_epoch)
                    if age_seconds >= max_age:
                        terminate_ids.append(iid)
                    else:
                        kept += 1
    except Exception as exc:
        logger.warning("fleet sweep describe_instances failed: %s", exc)
        return {
            "enabled": True,
            "error": str(exc),
            "scanned": scanned,
            "terminated": 0,
            "kept": kept,
            "active_dispatches": len(active_dispatches),
        }

    terminated = 0
    if terminate_ids:
        try:
            for i in range(0, len(terminate_ids), 50):
                batch = terminate_ids[i : i + 50]
                _get_ec2().terminate_instances(InstanceIds=batch)
                terminated += len(batch)
        except Exception as exc:
            logger.warning("fleet sweep terminate failed: %s", exc)
            return {
                "enabled": True,
                "error": str(exc),
                "scanned": scanned,
                "terminated": terminated,
                "kept": kept,
                "active_dispatches": len(active_dispatches),
            }

    return {
        "enabled": True,
        "scanned": scanned,
        "terminated": terminated,
        "kept": kept,
        "active_dispatches": len(active_dispatches),
    }


def _resolve_host_dispatch_target(
    request: Dict[str, Any],
    execution_mode: str,
    dispatch_id: str,
    *,
    host_allocation: str = "auto",
) -> Dict[str, Any]:
    if not _dispatch_uses_host_runtime(execution_mode):
        return {
            "instance_id": HOST_V2_INSTANCE_ID,
            "host_kind": "managed_session",
            "host_allocation": "managed",
            "host_source": "provider_api",
        }

    allocation = str(host_allocation or "auto").strip().lower()
    if allocation not in {"auto", "static", "fleet"}:
        raise ValueError(f"Unsupported host_allocation '{host_allocation}'")

    if allocation == "static":
        return {
            "instance_id": HOST_V2_INSTANCE_ID,
            "host_kind": "static",
            "host_allocation": "static",
            "host_source": "host_v2",
        }

    fleet_available = _fleet_launch_ready()
    if (allocation == "fleet" or (allocation == "auto" and fleet_available)) and fleet_available:
        project_id = str(request.get("project_id") or "")
        request_id = str(request.get("request_id") or "")
        if HOST_V2_FLEET_SWEEP_ON_DISPATCH:
            sweep_result = _sweep_orphan_fleet_hosts(project_id)
            logger.info("[INFO] fleet orphan sweep result: %s", json.dumps(sweep_result, sort_keys=True))
        active_dispatches = _count_active_host_dispatches(project_id, current_request_id=request_id)
        if HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES > 0 and active_dispatches >= HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES:
            raise RuntimeError(
                "host_fleet_capacity_exceeded:"
                f" active={active_dispatches} max={HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES}"
            )

        launch = _launch_fleet_instance(project_id, request_id, dispatch_id)
        instance_id = launch["instance_id"]
        try:
            readiness = _wait_for_fleet_instance_readiness(instance_id)
        except Exception:
            try:
                _get_ec2().terminate_instances(InstanceIds=[instance_id])
            except Exception:
                logger.warning("failed terminating fleet instance after readiness error: %s", instance_id)
            raise

        return {
            "instance_id": instance_id,
            "host_kind": "fleet",
            "host_allocation": "fleet",
            "host_source": "launch_template",
            "launch_template_id": HOST_V2_FLEET_LAUNCH_TEMPLATE_ID,
            "launch_template_version": HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION,
            "launched_at": launch.get("launched_at"),
            "ready_at": readiness.get("ready_at"),
            "instance_ttl_seconds": HOST_V2_FLEET_INSTANCE_TTL_SECONDS,
        }

    if allocation == "fleet":
        if HOST_V2_FLEET_FALLBACK_TO_STATIC:
            return {
                "instance_id": HOST_V2_INSTANCE_ID,
                "host_kind": "static",
                "host_allocation": "fleet-fallback-static",
                "host_source": "host_v2",
            }
        raise RuntimeError("host_fleet_unavailable: launch template not configured")

    return {
        "instance_id": HOST_V2_INSTANCE_ID,
        "host_kind": "static",
        "host_allocation": "auto-static",
        "host_source": "host_v2",
    }


def _find_dedup_match(
    project_id: str,
    incoming_record_ids: set,
    now_epoch: int,
) -> Optional[Dict[str, Any]]:
    """Find an existing intake_received request whose record IDs overlap with incoming."""
    if not incoming_record_ids:
        return None

    candidates = _find_intake_candidates(project_id, now_epoch)
    for candidate in candidates:
        existing_ids = _extract_record_ids_from_request(candidate)
        if incoming_record_ids & existing_ids:
            return candidate

    return None


def _merge_requests(
    existing: Dict[str, Any],
    new_body: Dict[str, Any],
    new_requestor_session_id: str,
) -> Dict[str, Any]:
    """Merge a new request body into an existing intake_received request.

    v0.3 contract section 6.1.1 merge rules:
    - initiative_title: concatenated with ' + ' or kept if identical
    - outcomes: union deduplicated by exact string match
    - constraints: deep-merged, later overrides
    - related_record_ids: union set
    - source_sessions: array of all contributing session IDs
    - source_requests: array of original request IDs that were merged
    """
    now = _now_z()
    now_epoch = _unix_now()

    existing_title = existing.get("initiative_title", "")
    new_title = str(new_body.get("initiative_title") or "").strip()
    if new_title and new_title != existing_title:
        merged_title = f"{existing_title} + {new_title}"
        if len(merged_title) > MAX_TITLE_LENGTH * 2:
            merged_title = merged_title[: MAX_TITLE_LENGTH * 2]
    else:
        merged_title = existing_title
    existing["initiative_title"] = merged_title

    existing_outcomes = list(existing.get("outcomes") or [])
    new_outcomes = list(new_body.get("outcomes") or [])
    seen = set(existing_outcomes)
    for outcome in new_outcomes:
        if outcome not in seen:
            existing_outcomes.append(outcome)
            seen.add(outcome)
    existing["outcomes"] = existing_outcomes

    existing_constraints = dict(existing.get("constraints") or {})
    new_constraints = dict(new_body.get("constraints") or {})
    existing_constraints.update(new_constraints)
    existing["constraints"] = existing_constraints

    existing_related = set(existing.get("related_record_ids") or [])
    new_related = set(new_body.get("related_record_ids") or [])
    existing["related_record_ids"] = sorted(existing_related | new_related)

    sessions = list(existing.get("source_sessions") or [])
    original_session = existing.get("requestor_session_id")
    if original_session and original_session not in sessions:
        sessions.append(original_session)
    if new_requestor_session_id and new_requestor_session_id not in sessions:
        sessions.append(new_requestor_session_id)
    existing["source_sessions"] = sessions

    source_requests = list(existing.get("source_requests") or [])
    own_id = existing.get("request_id")
    if own_id and own_id not in source_requests:
        source_requests.append(own_id)
    existing["source_requests"] = source_requests

    existing["debounce_window_expires_epoch"] = now_epoch + DEBOUNCE_WINDOW_SECONDS
    existing["debounce_window_expires"] = (
        dt.datetime.fromtimestamp(
            now_epoch + DEBOUNCE_WINDOW_SECONDS, tz=dt.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    history = list(existing.get("state_history") or [])
    history.append({
        "timestamp": now,
        "from": _STATE_INTAKE_RECEIVED,
        "to": _STATE_INTAKE_RECEIVED,
        "reason": f"Merged with incoming request (session={new_requestor_session_id})",
        "meta": {
            "merged_title": new_title,
            "merged_outcomes_count": len(new_outcomes),
            "merged_related_count": len(new_related),
        },
    })
    existing["state_history"] = history

    existing["updated_at"] = now
    existing["updated_epoch"] = now_epoch
    existing["sync_version"] = int(existing.get("sync_version", 0)) + 1
    existing["last_merge_at"] = now

    return existing


def _promote_expired_intake_requests(project_id: str) -> List[str]:
    """Promote intake_received requests whose debounce window has expired to queued.

    On-read promotion pattern: called during create/get to avoid separate scheduler.
    """
    now_epoch = _unix_now()
    promoted: List[str] = []

    try:
        ddb = _get_ddb()
        resp = ddb.query(
            TableName=COORDINATION_TABLE,
            IndexName=COORDINATION_GSI_PROJECT,
            KeyConditionExpression="project_id = :pid AND updated_epoch >= :min_epoch",
            FilterExpression="#s = :intake_state",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={
                ":pid": _serialize(project_id),
                ":min_epoch": _serialize(now_epoch - DEBOUNCE_WINDOW_SECONDS - 300),
                ":intake_state": _serialize(_STATE_INTAKE_RECEIVED),
            },
            ScanIndexForward=False,
        )
    except (BotoCoreError, ClientError) as exc:
        logger.warning("intake promotion scan skipped: %s", exc)
        return promoted

    for raw in resp.get("Items", []):
        item = _deserialize(raw)
        expires = int(item.get("debounce_window_expires_epoch") or 0)
        if expires > 0 and expires <= now_epoch:
            try:
                _append_state_transition(
                    item,
                    _STATE_QUEUED,
                    "Debounce window expired — promoted to queued",
                    extra={"debounce_expires_epoch": expires, "promoted_at_epoch": now_epoch},
                )
                _update_request(item)
                promoted.append(item["request_id"])
                logger.info("[INFO] promoted intake_received -> queued: %s", item["request_id"])
            except Exception as exc:
                logger.warning("failed to promote request %s: %s", item.get("request_id"), exc)

    return promoted


def _decompose_and_create_tracker_artifacts(
    project_id: str,
    initiative_title: str,
    outcomes: Sequence[str],
    request_id: str,
    assigned_to: str,
    dispatch_id: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    meta = _load_project_meta(project_id)
    governance_hash = _compute_governance_hash_local()
    if not governance_hash:
        raise RuntimeError("Missing governance hash")

    acceptance_criteria = [
        f"Outcome {idx}: {outcome}" for idx, outcome in enumerate(outcomes, start=1)
    ]
    invocation_meta = {
        "governance_hash": governance_hash,
        "coordination_request_id": request_id,
        "dispatch_id": dispatch_id or "",
        "provider": provider or "",
        "timestamp": _now_z(),
    }
    meta_json = json.dumps(invocation_meta, sort_keys=True)

    feature_description = (
        f"Coordination decomposition for request {request_id}. "
        f"Initiative: {initiative_title}. "
        f"Invocation metadata: {meta_json}"
    )

    feature_id = _create_tracker_record_auto(
        project_id=project_id,
        prefix=meta.prefix,
        record_type="feature",
        title=f"{initiative_title[:120]} (coordination request)",
        description=feature_description,
        priority="P1",
        assigned_to=assigned_to,
        success_metrics=acceptance_criteria,
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )
    _append_tracker_history(
        feature_id,
        "worklog",
        f"MCP_INVOCATION: {meta_json}",
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )

    task_ids: List[str] = []
    issue_ids: List[str] = []

    for idx, outcome in enumerate(outcomes, start=1):
        task_id = _create_tracker_record_auto(
            project_id=project_id,
            prefix=meta.prefix,
            record_type="task",
            title=f"Execute outcome {idx}: {outcome[:90]}",
            description=(
                f"Generated by coordination request {request_id}. "
                f"Outcome: {outcome}. Invocation metadata: {meta_json}"
            ),
            priority="P1",
            assigned_to=assigned_to,
            related_ids=[feature_id],
            acceptance_criteria=[f"Outcome {idx}: {outcome}"],
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )
        task_ids.append(task_id)
        _append_tracker_history(
            task_id,
            "worklog",
            f"MCP_INVOCATION: {meta_json}",
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )

    issue_ids.append(
        _create_tracker_record_auto(
            project_id=project_id,
            prefix=meta.prefix,
            record_type="issue",
            title=f"Coordination risk tracking for {initiative_title[:80]}",
            description=(
                f"Generated for request {request_id} to track dispatch/callback "
                f"orchestration failures. Invocation metadata: {meta_json}"
            ),
            priority="P1",
            assigned_to=assigned_to,
            severity="high",
            hypothesis=(
                "Asynchronous worker execution may fail or return non-deterministic "
                "completion signals without explicit request-state transitions."
            ),
            related_ids=[feature_id, *task_ids],
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )
    )
    _append_tracker_history(
        issue_ids[0],
        "worklog",
        f"MCP_INVOCATION: {meta_json}",
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )

    _append_tracker_history(
        feature_id,
        "worklog",
        (
            f"Coordination request {request_id} decomposed into {len(task_ids)} tasks "
            f"and {len(issue_ids)} issue(s)."
        ),
        governance_hash=governance_hash,
        coordination_request_id=request_id,
        dispatch_id=dispatch_id,
        provider=provider,
    )
    for criterion in acceptance_criteria:
        _append_tracker_history(
            feature_id,
            "worklog",
            f"ACCEPTANCE CRITERIA: {criterion} | metadata={meta_json}",
            governance_hash=governance_hash,
            coordination_request_id=request_id,
            dispatch_id=dispatch_id,
            provider=provider,
        )

    return {
        "feature_id": feature_id,
        "task_ids": task_ids,
        "issue_ids": issue_ids,
        "acceptance_criteria": acceptance_criteria,
        "governance_hash": governance_hash,
    }


