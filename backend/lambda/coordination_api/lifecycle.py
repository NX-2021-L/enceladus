"""lifecycle.py — Tracker lifecycle updates, callback adapters, plan status, event emission.

Part of coordination_api modularization (ENC-TSK-527).
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from config import (
    CALLBACK_EVENTBRIDGE_BUS,
    CALLBACK_EVENT_DETAIL_TYPE,
    CALLBACK_EVENT_SOURCE,
    FEED_PUSH_DEFAULT_EVENT_BUS,
    FEED_PUSH_HTTP_TIMEOUT_SECONDS,
    FEED_SUBSCRIPTIONS_TABLE,
    _VALID_TERMINAL_STATES,
    logger,
)
from serialization import _deserialize, _now_z, _serialize
from aws_clients import _feed_subscriptions_enabled, _get_ddb, _get_eb
from tracker_ops import _append_tracker_history, _set_tracker_status

__all__ = [
    "_cancel_coordination_linked_subscriptions",
    "_compute_plan_status",
    "_deliver_feed_push_event",
    "_emit_callback_event",
    "_evaluate_plan_terminal_state",
    "_finalize_tracker_from_request",
    "_normalize_aws_native_callback",
    "_normalize_callback_body",
    "_normalize_claude_sdk_callback",
    "_normalize_codex_callback",
    "_publish_feed_push_updates",
    "_safe_json_dict",
    "_subscription_scope_matches",
    "_update_dispatch_outcome",
    "_update_provider_session_from_callback",
]

# ---------------------------------------------------------------------------
# Tracker lifecycle updates tied to coordination request state
# ---------------------------------------------------------------------------


def _finalize_tracker_from_request(request: Dict[str, Any]) -> None:
    state = request.get("state")
    rid = request["request_id"]
    task_ids = list(request.get("task_ids") or [])
    issue_ids = list(request.get("issue_ids") or [])
    feature_id = request.get("feature_id")
    provider = (
        str((request.get("provider_session") or {}).get("provider") or "")
        or str(request.get("execution_provider") or "")
    )
    dispatch_id = str((request.get("dispatch") or {}).get("dispatch_id") or "")
    governance_hash = str(request.get("governance_hash") or "")

    if state in {"succeeded", "failed", "cancelled", "dead_letter"}:
        try:
            _cancel_coordination_linked_subscriptions(rid, terminal_state=state)
        except Exception as exc:
            logger.warning("Failed cancelling coordination-linked subscriptions for %s: %s", rid, exc)

    if state == "succeeded":
        for tid in task_ids:
            _set_tracker_status(
                tid,
                "closed",
                f"Coordination request {rid} completed successfully.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        if feature_id:
            _set_tracker_status(
                feature_id,
                "completed",
                f"Coordination request {rid} completed successfully.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for iid in issue_ids:
            _append_tracker_history(
                iid,
                "worklog",
                f"Coordination request {rid} succeeded; issue retained for audit trail.",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        return

    if state in {"failed", "cancelled", "dead_letter"}:
        detail = request.get("result", {}).get("summary") or f"Request ended in state {state}."
        if feature_id:
            _append_tracker_history(
                feature_id,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for tid in task_ids:
            _append_tracker_history(
                tid,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )
        for iid in issue_ids:
            _append_tracker_history(
                iid,
                "worklog",
                f"Coordination request {rid} {state}: {detail}",
                governance_hash=governance_hash,
                coordination_request_id=rid,
                dispatch_id=dispatch_id,
                provider=provider,
            )


def _safe_json_dict(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _subscription_scope_matches(
    subscription: Dict[str, Any],
    *,
    project_id: str,
    item_ids: Sequence[str],
    coordination_request_id: str,
) -> bool:
    if str(subscription.get("state") or "").lower() != "active":
        return False
    if str(subscription.get("delivery_mode") or "").lower() != "push":
        return False

    sub_coord = str(subscription.get("coordination_request_id") or "")
    if sub_coord and sub_coord != coordination_request_id:
        return False

    scope = _safe_json_dict(subscription.get("scope_json"))
    scope_project = str(scope.get("project_id") or "").strip()
    if scope_project and scope_project != project_id:
        return False

    scope_record_ids = {
        str(record_id).strip()
        for record_id in (scope.get("record_ids") or [])
        if str(record_id).strip()
    }
    if scope_record_ids:
        return bool(scope_record_ids & set(item_ids))

    return True


def _deliver_feed_push_event(
    *,
    subscription_id: str,
    push_config: Dict[str, Any],
    payload: Dict[str, Any],
) -> None:
    detail_type = str(push_config.get("detail_type") or "feed.update")
    endpoint = str(push_config.get("endpoint") or "").strip()
    event_bus = str(push_config.get("event_bus") or "").strip()

    if endpoint.startswith("arn:aws:events:"):
        event_bus = endpoint.split(":event-bus/")[-1] if ":event-bus/" in endpoint else endpoint

    if event_bus or endpoint.startswith("arn:aws:events:"):
        _get_eb().put_events(
            Entries=[
                {
                    "Source": "enceladus.feed",
                    "DetailType": detail_type,
                    "Detail": json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    "EventBusName": event_bus or FEED_PUSH_DEFAULT_EVENT_BUS,
                }
            ]
        )
        return

    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        req_headers = {"Content-Type": "application/json"}
        token = str(push_config.get("token") or "").strip()
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        user_headers = push_config.get("headers") or {}
        if isinstance(user_headers, dict):
            req_headers.update({str(k): str(v) for k, v in user_headers.items() if str(k).strip()})
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=req_headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=FEED_PUSH_HTTP_TIMEOUT_SECONDS) as resp:
            _ = resp.read()
        return

    logger.warning("Push subscription %s has unsupported endpoint/event_bus config", subscription_id)


def _publish_feed_push_updates(
    *,
    project_id: str,
    coordination_request_id: str,
    state: str,
    summary: str,
    item_ids: Sequence[str],
) -> None:
    if not item_ids:
        return
    if not _feed_subscriptions_enabled():
        return

    try:
        now = _now_z()
        ddb = _get_ddb()
        expr_names = {"#state": "state"}
        expr_values = {
            ":active": _serialize("active"),
            ":push": _serialize("push"),
        }
        filter_expr = "#state = :active AND delivery_mode = :push"
        last_key = None
        delivered = 0

        while True:
            kwargs: Dict[str, Any] = {
                "TableName": FEED_SUBSCRIPTIONS_TABLE,
                "FilterExpression": filter_expr,
                "ExpressionAttributeNames": expr_names,
                "ExpressionAttributeValues": expr_values,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            page = ddb.scan(**kwargs)
            for raw_item in page.get("Items", []):
                sub = _deserialize(raw_item)
                if not _subscription_scope_matches(
                    sub,
                    project_id=project_id,
                    item_ids=item_ids,
                    coordination_request_id=coordination_request_id,
                ):
                    continue

                push_config = _safe_json_dict(sub.get("push_config_json"))
                payload = {
                    "subscription_id": sub.get("subscription_id"),
                    "project_id": project_id,
                    "coordination_request_id": coordination_request_id,
                    "state": state,
                    "summary": summary,
                    "items_modified": list(item_ids),
                    "delivered_at": now,
                }
                try:
                    _deliver_feed_push_event(
                        subscription_id=str(sub.get("subscription_id") or ""),
                        push_config=push_config,
                        payload=payload,
                    )
                    delivered += 1
                except Exception as exc:
                    logger.warning(
                        "Failed delivering push update for subscription=%s: %s",
                        sub.get("subscription_id"),
                        exc,
                    )
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                break

        if delivered:
            logger.info(
                "[INFO] Delivered feed push updates for coordination=%s subscriptions=%d items=%d",
                coordination_request_id,
                delivered,
                len(item_ids),
            )
    except Exception as exc:
        logger.warning("Skipping feed push publish due to subscription lookup error: %s", exc)


def _cancel_coordination_linked_subscriptions(
    coordination_request_id: str,
    *,
    terminal_state: str,
) -> int:
    if not coordination_request_id:
        return 0
    if not _feed_subscriptions_enabled():
        return 0

    ddb = _get_ddb()
    now = _now_z()
    cancelled = 0
    expr_names = {"#state": "state"}
    expr_values = {
        ":rid": _serialize(coordination_request_id),
        ":active": _serialize("active"),
    }
    filter_expr = "coordination_request_id = :rid AND #state = :active"
    last_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "TableName": FEED_SUBSCRIPTIONS_TABLE,
            "FilterExpression": filter_expr,
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_values,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        page = ddb.scan(**kwargs)
        for raw_item in page.get("Items", []):
            sub = _deserialize(raw_item)
            sub_id = str(sub.get("subscription_id") or "")
            if not sub_id:
                continue
            try:
                ddb.update_item(
                    TableName=FEED_SUBSCRIPTIONS_TABLE,
                    Key={"subscription_id": _serialize(sub_id)},
                    ConditionExpression="attribute_exists(subscription_id) AND #state = :active",
                    UpdateExpression=(
                        "SET #state = :cancelled, cancelled_at = :ts, updated_at = :ts, "
                        "cancelled_reason = :reason"
                    ),
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={
                        ":active": _serialize("active"),
                        ":cancelled": _serialize("cancelled"),
                        ":ts": _serialize(now),
                        ":reason": _serialize(
                            f"coordination_terminal:{terminal_state}:{coordination_request_id}"
                        ),
                    },
                )
                cancelled += 1
            except ddb.exceptions.ConditionalCheckFailedException:
                continue
            except Exception as exc:
                logger.warning("Failed cancelling subscription %s: %s", sub_id, exc)
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            break

    if cancelled:
        logger.info(
            "[INFO] Auto-cancelled %d feed subscriptions for coordination=%s state=%s",
            cancelled,
            coordination_request_id,
            terminal_state,
        )
    return cancelled


# ---------------------------------------------------------------------------
# v0.3 Multi-provider callback adapters
# ---------------------------------------------------------------------------


def _normalize_callback_body(body: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Normalize provider-specific callback payload into canonical v0.3 schema.

    Each provider may send completion events in different formats. This
    adapter normalizes them into the standard callback contract:
        {state, dispatch_id, summary, execution_id, provider, details, feed_updates}
    """
    if provider == "claude_agent_sdk":
        return _normalize_claude_sdk_callback(body)
    elif provider == "openai_codex":
        return _normalize_codex_callback(body)
    elif provider == "aws_native":
        return _normalize_aws_native_callback(body)
    # Fallback: treat as already-normalized generic callback
    return body


def _normalize_claude_sdk_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize Claude Agent SDK completion event.

    Claude Agent SDK callbacks may arrive as structured completion events
    with fields: result, session_id, model, usage, stop_reason, output.
    """
    normalized: Dict[str, Any] = {
        "provider": "claude_agent_sdk",
    }

    # Map SDK completion status to coordination state
    stop_reason = str(body.get("stop_reason") or body.get("status") or "").lower()
    if stop_reason in ("end_turn", "tool_use", "completed", "succeeded"):
        normalized["state"] = "succeeded"
    elif stop_reason in ("max_tokens", "timeout", "error", "failed"):
        normalized["state"] = "failed"
    elif stop_reason in ("cancelled", "canceled"):
        normalized["state"] = "cancelled"
    else:
        # If 'state' is passed directly (generic callback), use it
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(body.get("dispatch_id") or "")
    normalized["execution_id"] = str(
        body.get("execution_id") or body.get("session_id") or ""
    )

    # Build summary from SDK output
    sdk_output = body.get("output") or body.get("result")
    if isinstance(sdk_output, str):
        normalized["summary"] = sdk_output[:2000]
    elif isinstance(sdk_output, dict):
        normalized["summary"] = str(sdk_output.get("summary") or sdk_output.get("text") or "")[:2000]
    else:
        normalized["summary"] = str(body.get("summary") or "")[:2000]

    # Preserve SDK-specific details
    details: Dict[str, Any] = {}
    for sdk_field in (
        "model",
        "usage",
        "stop_reason",
        "session_id",
        "fork_from_session_id",
        "permission_mode",
        "allowed_tools",
    ):
        if body.get(sdk_field) is not None:
            details[sdk_field] = body[sdk_field]
    if body.get("details") and isinstance(body["details"], dict):
        details.update(body["details"])
    normalized["details"] = details

    normalized["feed_updates"] = body.get("feed_updates") or {}

    return normalized


def _normalize_codex_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize OpenAI Codex completion event.

    Codex callbacks may arrive from SSM command output or from Codex App
    Server JSON-RPC responses with fields: thread_id, turn_id, turn_status,
    completed_at, output.
    """
    normalized: Dict[str, Any] = {
        "provider": "openai_codex",
    }

    # Map Codex turn status to coordination state
    turn_status = str(body.get("turn_status") or body.get("status") or "").lower()
    if turn_status in ("completed", "succeeded", "success"):
        normalized["state"] = "succeeded"
    elif turn_status in ("failed", "error", "errored"):
        normalized["state"] = "failed"
    elif turn_status in ("cancelled", "canceled", "stopped"):
        normalized["state"] = "cancelled"
    else:
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(body.get("dispatch_id") or "")
    normalized["execution_id"] = str(
        body.get("execution_id") or body.get("thread_id") or ""
    )
    normalized["summary"] = str(body.get("summary") or body.get("output") or "")[:2000]

    details: Dict[str, Any] = {}
    for codex_field in (
        "provider_session_id",
        "thread_id",
        "turn_id",
        "turn_status",
        "completed_at",
        "model",
    ):
        if body.get(codex_field) is not None:
            details[codex_field] = body[codex_field]
    if body.get("details") and isinstance(body["details"], dict):
        details.update(body["details"])
    normalized["details"] = details

    normalized["feed_updates"] = body.get("feed_updates") or {}

    return normalized


def _update_provider_session_from_callback(
    request: Dict[str, Any],
    *,
    provider: str,
    execution_id: str,
    details: Dict[str, Any],
) -> None:
    existing = dict(request.get("provider_session") or {})
    merged = dict(existing)
    merged["provider"] = provider

    if execution_id:
        merged["execution_id"] = execution_id

    if provider == "openai_codex":
        for field in (
            "provider_session_id",
            "thread_id",
            "turn_id",
            "turn_status",
            "completed_at",
            "model",
        ):
            value = details.get(field)
            if value is not None and value != "":
                merged[field] = value
    elif provider == "claude_agent_sdk":
        for field in (
            "session_id",
            "fork_from_session_id",
            "permission_mode",
            "allowed_tools",
            "completed_at",
            "model",
        ):
            value = details.get(field)
            if value is not None and value != "":
                merged[field] = value

    request["provider_session"] = merged


def _normalize_aws_native_callback(body: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize AWS-native callback (EventBridge event or SQS message).

    AWS-native callbacks come from Step Functions, Lambda, or CodeBuild
    completion events. The detail payload may include status, output,
    execution_arn, and state_machine fields.
    """
    normalized: Dict[str, Any] = {
        "provider": "aws_native",
    }

    # EventBridge detail may nest the actual payload
    detail = body.get("detail") if isinstance(body.get("detail"), dict) else body

    status = str(detail.get("status") or detail.get("state") or "").lower()
    if status in ("succeeded", "completed", "success"):
        normalized["state"] = "succeeded"
    elif status in ("failed", "aborted", "timed_out", "timeout"):
        normalized["state"] = "failed"
    elif status in ("cancelled", "canceled"):
        normalized["state"] = "cancelled"
    else:
        raw_state = str(body.get("state") or "").strip().lower()
        if raw_state in _VALID_TERMINAL_STATES:
            normalized["state"] = raw_state
        else:
            normalized["state"] = "failed"

    normalized["dispatch_id"] = str(
        detail.get("dispatch_id") or body.get("dispatch_id") or ""
    )
    normalized["execution_id"] = str(
        detail.get("execution_id")
        or detail.get("executionArn")
        or detail.get("command_id")
        or ""
    )
    normalized["summary"] = str(
        detail.get("summary") or detail.get("output") or detail.get("cause") or ""
    )[:2000]

    details: Dict[str, Any] = {}
    for aws_field in ("executionArn", "stateMachineArn", "command_id", "build_id",
                       "build_status", "source", "detail-type"):
        val = body.get(aws_field) or detail.get(aws_field)
        if val is not None:
            details[aws_field] = val
    if detail.get("details") and isinstance(detail["details"], dict):
        details.update(detail["details"])
    normalized["details"] = details

    normalized["feed_updates"] = detail.get("feed_updates") or body.get("feed_updates") or {}

    return normalized


# ---------------------------------------------------------------------------
# v0.3 Dispatch-level plan status tracking
# ---------------------------------------------------------------------------


def _compute_plan_status(request: Dict[str, Any]) -> Dict[str, Any]:
    """Compute plan-level status from individual dispatch outcomes.

    For requests with a dispatch_plan, each dispatch can independently reach
    a terminal state. This returns a summary of completion progress.
    """
    dispatch_plan = request.get("dispatch_plan") or {}
    dispatches = dispatch_plan.get("dispatches") or []

    if not dispatches:
        # Legacy single-dispatch request — derive from request state
        state = request.get("state", "")
        if state in _VALID_TERMINAL_STATES:
            return {"completed": 1, "pending": 0, "failed": 1 if state == "failed" else 0, "total": 1}
        return {"completed": 0, "pending": 1, "failed": 0, "total": 1}

    dispatch_outcomes = request.get("dispatch_outcomes") or {}
    completed = 0
    failed = 0
    pending = 0

    for d in dispatches:
        did = d.get("dispatch_id", "")
        outcome = dispatch_outcomes.get(did, {})
        d_state = outcome.get("state", "pending")
        if d_state == "succeeded":
            completed += 1
        elif d_state == "failed":
            failed += 1
            completed += 1  # failed is terminal, counts as "done"
        elif d_state == "cancelled":
            completed += 1
        else:
            pending += 1

    return {
        "completed": completed,
        "pending": pending,
        "failed": failed,
        "total": len(dispatches),
    }


def _update_dispatch_outcome(
    request: Dict[str, Any],
    dispatch_id: str,
    state: str,
    summary: str,
    execution_id: str,
    provider: str,
    details: Dict[str, Any],
) -> Dict[str, Any]:
    """Record a dispatch-level outcome within the request.

    For multi-dispatch plans, each dispatch reports independently.
    Returns the updated request.
    """
    outcomes = dict(request.get("dispatch_outcomes") or {})
    outcomes[dispatch_id] = {
        "state": state,
        "summary": summary[:2000],
        "execution_id": execution_id,
        "provider": provider,
        "details": details,
        "completed_at": _now_z(),
    }
    request["dispatch_outcomes"] = outcomes
    return request


def _evaluate_plan_terminal_state(request: Dict[str, Any]) -> Optional[str]:
    """Determine if all dispatches have completed and what the overall state should be.

    Returns the terminal state string if the plan is complete, or None if
    dispatches are still pending.
    """
    plan_status = _compute_plan_status(request)
    if plan_status["pending"] > 0:
        return None

    if plan_status["failed"] == 0:
        return "succeeded"

    rollback_policy = (request.get("dispatch_plan") or {}).get("rollback_policy") or {}
    on_partial = rollback_policy.get("on_partial_failure", "continue")

    if plan_status["failed"] == plan_status["total"]:
        return "failed"

    # Partial failure — depends on policy
    if on_partial == "halt_remaining":
        return "failed"
    elif on_partial == "rollback_completed":
        return "failed"
    else:
        # "continue" — if any succeeded, the plan succeeded with partial failures
        return "succeeded" if (plan_status["completed"] - plan_status["failed"]) > 0 else "failed"


# ---------------------------------------------------------------------------
# v0.3 EventBridge / SQS callback emit helpers
# ---------------------------------------------------------------------------


def _emit_callback_event(request: Dict[str, Any], callback_body: Dict[str, Any]) -> None:
    """Emit an EventBridge event for callback observability.

    Published on every callback receipt so downstream systems can react
    to coordination completion events.
    """
    try:
        eb = _get_eb()
        eb.put_events(
            Entries=[
                {
                    "Source": CALLBACK_EVENT_SOURCE,
                    "DetailType": CALLBACK_EVENT_DETAIL_TYPE,
                    "EventBusName": CALLBACK_EVENTBRIDGE_BUS,
                    "Detail": json.dumps({
                        "request_id": request["request_id"],
                        "project_id": request.get("project_id"),
                        "state": callback_body.get("state"),
                        "dispatch_id": callback_body.get("dispatch_id"),
                        "provider": callback_body.get("provider"),
                        "execution_id": callback_body.get("execution_id"),
                        "summary": (callback_body.get("summary") or "")[:500],
                        "plan_status": _compute_plan_status(request),
                        "timestamp": _now_z(),
                    }),
                }
            ]
        )
    except Exception as exc:
        logger.warning("Failed emitting callback EventBridge event: %s", exc)


