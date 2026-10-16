"""ENC-TSK-Q83 notify v2: per-device escalation web push (contracts/notify/v2).

Routes, storage (PUSHDEV#<principal>/<device_id>) and the SNS-fed sender live
here; lambda_function.py keeps only single-line router hooks. To avoid a
circular import the hosting module is injected: every hook passes it as
``host`` and ``d`` below refers to it (late-bound, so tests may patch the host's
helpers such as _get_ddb or _load_escalation_approver_allowlist).
"""
import hashlib
import json
import os
import re
from typing import Any, Dict, Optional, Tuple

d: Any = None  # the hosting lambda_function module, bound by handle()/handle_escalation_push_sns()


def handle(host: Any, method: str, path: str, event: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    global d
    d = host
    return _handle_notifications(method, path, event, claims)


PUSH_SUBSCRIPTIONS_TABLE = os.environ.get("PUSH_SUBSCRIPTIONS_TABLE", "enceladus-push-subscriptions")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://enceladus.jreese.net/")
PUSH_TTL_SECONDS = 24 * 3600
_NOTIFY_RISKS = ("low", "medium", "high", "critical")
_NOTIFY_KIND_RE = re.compile(r"^[a-z0-9_\-]{1,40}$")
_NOTIFY_MAX_KINDS = 32
_NOTIFY_PATH_PREFIX = "/api/v1/coordination/notifications/"
_NOTIFY_DETAILS = ("detailed", "generic")
_NOTIFY_PLATFORMS = ("ios", "macos", "other")
_NOTIFY_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{8,128}$")
_NOTIFY_GENERIC_BODY = "New escalation awaiting your decision"


def _notify_default_prefs() -> Dict[str, Any]:
    """ES-R1: a new device receives nothing until it opts in per type (absent type == disabled)."""
    return {"types": {}, "detail": "detailed"}


def _notify_normalize_prefs(raw: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    """Validate a v2 devicePreferences body; returns (prefs, '') or (None, reason)."""
    if not isinstance(raw, dict):
        return None, "A JSON object body is required."
    if set(raw) - {"types", "detail"}:
        return None, "Only types and detail are allowed."
    types = raw.get("types")
    if not isinstance(types, dict) or len(types) > _NOTIFY_MAX_KINDS:
        return None, "types must be an object of at most 32 kinds."
    out_types: Dict[str, Any] = {}
    for kind, cfg in types.items():
        if not isinstance(kind, str) or not _NOTIFY_KIND_RE.match(kind) or not isinstance(cfg, dict):
            return None, f"Invalid type entry {kind!r}."
        if set(cfg) != {"enabled", "min_risk"}:
            return None, f"types.{kind} requires exactly enabled and min_risk."
        if not isinstance(cfg["enabled"], bool):
            return None, f"types.{kind}.enabled must be a boolean."
        if cfg["min_risk"] not in _NOTIFY_RISKS:
            return None, f"types.{kind}.min_risk must be one of {list(_NOTIFY_RISKS)}."
        out_types[kind] = {"enabled": cfg["enabled"], "min_risk": cfg["min_risk"]}
    if raw.get("detail") not in _NOTIFY_DETAILS:
        return None, f"detail must be one of {list(_NOTIFY_DETAILS)}."
    return {"types": out_types, "detail": raw["detail"]}, ""


def _notify_vapid() -> Dict[str, str]:
    key = os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    if not key:
        key = next(iter(sorted(d.COORDINATION_INTERNAL_API_KEYS)), "") if d.COORDINATION_INTERNAL_API_KEYS else ""
    return d._webpush.derive_vapid(key, os.environ.get("VAPID_SUBJECT") or "https://jreese.net")


def _notify_pk(email: str) -> str:
    return f"PUSHDEV#{email}"


def _notify_subscription_from_body(body: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    sub = body.get("subscription") if isinstance(body, dict) else None
    if not isinstance(sub, dict):
        return None, "A JSON push subscription is required."
    endpoint = sub.get("endpoint")
    keys = sub.get("keys") if isinstance(sub.get("keys"), dict) else {}
    if d._webpush is None or not d._webpush.endpoint_allowed(endpoint):
        return None, "endpoint must be an https URL on a known push service."
    p256dh, auth = keys.get("p256dh"), keys.get("auth")
    try:
        if (not isinstance(p256dh, str) or not isinstance(auth, str)
                or len(d._webpush.b64u_decode(p256dh)) != 65 or not d._webpush.b64u_decode(auth)):
            raise ValueError("bad keys")
    except Exception:  # noqa: BLE001
        return None, "keys.p256dh and keys.auth are required (base64url)."
    return {"endpoint": endpoint, "p256dh": p256dh, "auth": auth}, ""


def _notify_device_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Wire `device` (no endpoint/keys/prefs ever leave the server)."""
    return {
        "device_id": item["device_id"]["S"], "label": item["label"]["S"],
        "platform": item["platform"]["S"], "created_at": item["created_at"]["S"],
        "last_sent_at": (item.get("last_sent_at") or {}).get("S") or None,
    }


def _notify_prefs_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    try:
        prefs, _why = _notify_normalize_prefs(json.loads(item["prefs"]["S"]))
        if prefs is not None:
            return prefs
    except (ValueError, TypeError, KeyError):
        pass
    return _notify_default_prefs()


def _purge_legacy_push_rows(email: str) -> int:
    """Idempotent: delete this principal's v1 PUSHSUB#/PUSHPREF# rows. Returns rows deleted."""
    ddb, deleted = d._get_ddb(), 0
    for prefix in ("PUSHSUB#", "PUSHPREF#"):
        items = ddb.query(
            TableName=PUSH_SUBSCRIPTIONS_TABLE, KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": f"{prefix}{email}"}}).get("Items", [])
        for it in items:
            ddb.delete_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": it["pk"], "sk": it["sk"]})
            deleted += 1
    return deleted


def _notify_send_raw(item: Dict[str, Any], payload: Dict[str, Any], topic: str) -> int:
    endpoint = item["endpoint"]["S"]
    keys = item["keys"]["M"]
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = d._webpush.encrypt_aes128gcm(data, keys["p256dh"]["S"], keys["auth"]["S"])
    headers = {**d._webpush.vapid_headers(endpoint, _notify_vapid()),
               "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
               "TTL": str(PUSH_TTL_SECONDS), "Urgency": "high", "Topic": topic[:32]}
    return int(d._webpush.http_send(endpoint, body, headers))


def _notify_mark_sent(item: Dict[str, Any]) -> None:
    d._get_ddb().update_item(
        TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET last_sent_at = :t", ExpressionAttributeValues={":t": {"S": d._gate_fmt(d._gate_now())}})


def _handle_notifications(method: str, path: str, event: Dict[str, Any], claims: Dict[str, Any]) -> Dict[str, Any]:
    """Notify v2 routes (contracts/notify/v2). Approver allow-list only; fails closed."""
    if d._webpush is None:
        return d._error(503, "Web push is unavailable.")
    if (not d._is_cognito_session(claims) or not d._is_human_cognito_principal(claims)
            or not d._is_allowlisted_escalation_decider(claims)):
        return d._error(403, "Notifications require an allow-listed escalation approver.")
    email = str(claims.get("email") or "").strip().lower()
    rest = path[len(_NOTIFY_PATH_PREFIX):].strip("/") if path.startswith(_NOTIFY_PATH_PREFIX) else ""
    parts = rest.split("/") if rest else []
    if parts == ["vapid-public-key"]:
        if method != "GET":
            return d._error(405, "Method not allowed.")
        try:
            public_key = _notify_vapid()["public"]
        except Exception as exc:  # noqa: BLE001
            d.logger.error("vapid derivation failed: %s", exc)
            return d._error(503, "Web push key unavailable.")
        return d._response(200, {"public_key": public_key})
    # v1 principal-level routes are removed (x-removed).
    if parts == ["preferences"] or (parts == ["subscribe"] and method == "DELETE"):
        return d._error(410, "Removed in notify v2: use /notifications/devices and "
                           "/notifications/devices/{device_id}/preferences.", code="GONE")
    ddb = d._get_ddb()
    pk = _notify_pk(email)

    def _body() -> Any:
        try:
            return d._json_body(event)
        except Exception:  # noqa: BLE001
            return None

    if parts == ["subscribe"]:
        if method != "POST":
            return d._error(405, "Method not allowed.")
        body = _body()
        if not isinstance(body, dict):
            return d._error(400, "A JSON object body is required.")
        device_id = body.get("device_id")
        if not isinstance(device_id, str) or not _NOTIFY_DEVICE_ID_RE.match(device_id):
            return d._error(400, "device_id is required (8-128 chars).")
        label, platform = body.get("label"), body.get("platform")
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 64:
            return d._error(400, "label is required (1-64 chars).")
        if platform not in _NOTIFY_PLATFORMS:
            return d._error(400, f"platform must be one of {list(_NOTIFY_PLATFORMS)}.")
        sub, why = _notify_subscription_from_body(body)
        if sub is None:
            return d._error(400, why)
        try:
            try:
                _purge_legacy_push_rows(email)
            except Exception as exc:  # noqa: BLE001 -- purge is best-effort and retried next subscribe
                d.logger.warning("legacy push purge failed: %s", exc)
            existing = ddb.get_item(TableName=PUSH_SUBSCRIPTIONS_TABLE,
                                    Key={"pk": {"S": pk}, "sk": {"S": device_id}}).get("Item")
            item = dict(existing) if existing else {
                "pk": {"S": pk}, "sk": {"S": device_id}, "device_id": {"S": device_id},
                "label": {"S": label.strip()}, "created_at": {"S": d._gate_fmt(d._gate_now())},
                "prefs": {"S": json.dumps(_notify_default_prefs(), separators=(",", ":"))}}
            # Re-subscribe replaces endpoint/keys (and platform); keeps prefs, label, created_at.
            item.update({
                "platform": {"S": platform}, "endpoint": {"S": sub["endpoint"]},
                "keys": {"M": {"p256dh": {"S": sub["p256dh"]}, "auth": {"S": sub["auth"]}}},
                "endpoint_hash": {"S": hashlib.sha256(sub["endpoint"].encode("utf-8")).hexdigest()}})
            ddb.put_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Item=item)
        except Exception as exc:  # noqa: BLE001
            d.logger.error("push device write failed: %s", exc)
            return d._error(500, "Failed to save device.")
        return d._response(200, _notify_device_from_item(item))

    if parts == ["devices"]:
        if method != "GET":
            return d._error(405, "Method not allowed.")
        try:
            items = ddb.query(TableName=PUSH_SUBSCRIPTIONS_TABLE, KeyConditionExpression="pk = :pk",
                              ExpressionAttributeValues={":pk": {"S": pk}}).get("Items", [])
        except Exception as exc:  # noqa: BLE001
            d.logger.error("push device list failed: %s", exc)
            return d._error(500, "Failed to list devices.")
        return d._response(200, {"devices": [_notify_device_from_item(i) for i in items]})

    if len(parts) >= 2 and parts[0] == "devices" and (len(parts) == 2 or parts[2:] in (["preferences"], ["test"])):
        device_id, sub_route = parts[1], (parts[2] if len(parts) == 3 else "")
        try:
            item = ddb.get_item(TableName=PUSH_SUBSCRIPTIONS_TABLE,
                                Key={"pk": {"S": pk}, "sk": {"S": device_id}}).get("Item")
        except Exception as exc:  # noqa: BLE001
            d.logger.error("push device read failed: %s", exc)
            return d._error(500, "Failed to read device.")
        if not item:
            return d._error(404, "Device not found.")
        try:
            if sub_route == "preferences":
                if method == "GET":
                    return d._response(200, _notify_prefs_from_item(item))
                if method == "PUT":
                    prefs, why = _notify_normalize_prefs(_body())
                    if prefs is None:
                        return d._error(400, why)
                    ddb.update_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]},
                                    UpdateExpression="SET prefs = :p",
                                    ExpressionAttributeValues={":p": {"S": json.dumps(prefs, separators=(",", ":"))}})
                    return d._response(200, prefs)
                return d._error(405, "Method not allowed.")
            if sub_route == "test":
                if method != "POST":
                    return d._error(405, "Method not allowed.")
                payload = {"web_push": 8030, "notification": {
                    "title": "Enceladus test notification",
                    "body": "Notifications are working on this device.",
                    "navigate": APP_BASE_URL}}
                try:
                    status = _notify_send_raw(item, payload, "test")
                except Exception as exc:  # noqa: BLE001
                    d.logger.warning("test push failed device-hash=%s: %s",
                                   hashlib.sha256(device_id.encode()).hexdigest()[:8], exc)
                    return d._response(200, {"sent": False, "status_code": None})
                if status in (404, 410):
                    ddb.delete_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]})
                ok = 200 <= status < 300
                if ok:
                    _notify_mark_sent(item)
                return d._response(200, {"sent": ok, "status_code": status})
            if method == "PATCH":
                body = _body()
                label = body.get("label") if isinstance(body, dict) else None
                if (not isinstance(body, dict) or set(body) != {"label"} or not isinstance(label, str)
                        or not 1 <= len(label.strip()) <= 64):
                    return d._error(400, "label is required (1-64 chars).")
                item["label"] = {"S": label.strip()}
                ddb.update_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]},
                                UpdateExpression="SET #l = :l", ExpressionAttributeNames={"#l": "label"},
                                ExpressionAttributeValues={":l": item["label"]})
                return d._response(200, _notify_device_from_item(item))
            if method == "DELETE":
                ddb.delete_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]})
                resp = d._response(204, None)
                resp["body"] = ""
                return resp
        except Exception as exc:  # noqa: BLE001
            d.logger.error("push device operation failed: %s", exc)
            return d._error(500, "Device operation failed.")
        return d._error(405, "Method not allowed.")
    return d._error(404, "Not found.")


def _notify_pending_count(project_id: str) -> Optional[int]:
    """Pending (requested) escalation count for the badge; None when not cheap."""
    try:
        out = d._get_ddb().query(
            TableName=d.TRACKER_TABLE,
            KeyConditionExpression="project_id = :pid AND begins_with(record_id, :prefix)",
            FilterExpression="#st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":pid": d._serialize(project_id), ":prefix": d._serialize("escalation#"),
                                       ":st": d._serialize("requested")},
            Select="COUNT")
        return int(out.get("Count", 0))
    except Exception as exc:  # noqa: BLE001
        d.logger.warning("push badge count unavailable: %s", exc)
        return None


def _notify_render(escalation: Dict[str, Any], escalation_id: str, level: int,
                   badge: Optional[int]) -> Dict[str, Any]:
    risk = str(escalation.get("risk") or "medium")
    kind = str(escalation.get("kind") or "escalation")
    if level == 0:
        body = _NOTIFY_GENERIC_BODY
    else:
        payload = escalation.get("payload") if isinstance(escalation.get("payload"), dict) else {}
        summary = str(escalation.get("justification") or escalation.get("title")
                      or payload.get("justification") or payload.get("title")
                      or escalation.get("mutation_type") or "").strip()
        summary = " ".join(summary.split())
        if len(summary) > 120:
            summary = summary[:119].rstrip() + "…"
        body = f"{escalation.get('project_id') or ''}: {kind} — {summary}".strip()
    notification: Dict[str, Any] = {
        "title": f"Escalation · {risk}" if level else "Escalation", "body": body,
        "navigate": f"{APP_BASE_URL.rstrip('/')}/escalations/{escalation_id}",
    }  # no "tag": DeclarativePushPayload (notify v2) forbids extra keys
    if badge is not None:
        notification["app_badge"] = badge
    return {"web_push": 8030, "notification": notification}


def _notify_push_one(escalation_id: str, project_id: str) -> int:
    """Send the push for one new escalation, per approver device. Returns the number accepted.

    Attribute mapping (notify v2): the notification "type" is the escalation
    record's ``kind`` and its "risk" is the record's ``risk`` (default medium),
    both read from the escalation item the SNS message points at. A device
    receives the push only if ``prefs.types[kind].enabled`` and
    ``risk >= prefs.types[kind].min_risk``; a missing type is disabled (ES-R1).
    ``prefs.detail`` selects detailed vs generic text. Legacy PUSHSUB#/PUSHPREF#
    rows are never read.
    """
    escalation = d._read_escalation_item(project_id, escalation_id)
    if not escalation or str(escalation.get("status") or "requested") != "requested":
        return 0
    d._escalation_gate_view(escalation)
    escalation.setdefault("project_id", project_id)
    kind, risk = str(escalation.get("kind") or "escalation"), str(escalation.get("risk") or "medium")
    risk_rank = _NOTIFY_RISKS.index(risk) if risk in _NOTIFY_RISKS else 1
    ddb = d._get_ddb()
    badge = _notify_pending_count(project_id)
    sent = 0
    for email in sorted(d._load_escalation_approver_allowlist()):
        try:
            devices = ddb.query(
                TableName=PUSH_SUBSCRIPTIONS_TABLE, KeyConditionExpression="pk = :pk",
                ExpressionAttributeValues={":pk": {"S": _notify_pk(email)}}).get("Items", [])
        except Exception as exc:  # noqa: BLE001 -- one approver never stops the rest
            d.logger.warning("push prepare failed approver-hash=%s: %s",
                           hashlib.sha256(email.encode()).hexdigest()[:8], exc)
            continue
        for item in devices:
            try:
                prefs = _notify_prefs_from_item(item)
                cfg = prefs["types"].get(kind)
                if not cfg or not cfg.get("enabled"):
                    continue
                if risk_rank < _NOTIFY_RISKS.index(cfg.get("min_risk", "low")):
                    continue
                payload = _notify_render(escalation, escalation_id, 1 if prefs["detail"] == "detailed" else 0, badge)
                status = _notify_send_raw(item, payload, escalation_id)
                if status in (404, 410):
                    ddb.delete_item(TableName=PUSH_SUBSCRIPTIONS_TABLE, Key={"pk": item["pk"], "sk": item["sk"]})
                elif 200 <= status < 300:
                    sent += 1
                    try:
                        _notify_mark_sent(item)
                    except Exception as exc:  # noqa: BLE001
                        d.logger.warning("push last_sent_at update failed: %s", exc)
                else:
                    d.logger.warning("push rejected status=%s device-hash=%s", status,
                                   hashlib.sha256(item["sk"]["S"].encode()).hexdigest()[:8])
            except Exception as exc:  # noqa: BLE001 -- one device never stops the rest
                d.logger.warning("push send failed device-hash=%s: %s",
                               hashlib.sha256(str(item.get("sk", {}).get("S", "")).encode()).hexdigest()[:8], exc)
    return sent


def _handle_escalation_push_sns(event: Dict[str, Any]) -> Dict[str, Any]:
    """SNS entry (devops-feed-alerts, filter category=escalation): only 'requested' sends."""
    sent = 0
    try:
        for record in event.get("Records") or []:
            try:
                attrs = (record.get("Sns") or {}).get("MessageAttributes") or {}

                def _attr(name: str) -> str:
                    return str((attrs.get(name) or {}).get("Value") or "").strip()

                if _attr("escalation_event") != "requested":
                    continue
                escalation_id, project_id = _attr("escalation_id"), _attr("project_id")
                if not escalation_id or not project_id:
                    d.logger.warning("escalation push skipped: missing id/project attributes")
                    continue
                sent += _notify_push_one(escalation_id, project_id)
            except Exception as exc:  # noqa: BLE001
                d.logger.error("escalation push record failed: %s", exc)
    except Exception as exc:  # noqa: BLE001 -- the handler never raises (J72 s5.8)
        d.logger.error("escalation push handler failed: %s", exc)
    return {"success": True, "sent": sent}


def handle_escalation_push_sns(host: Any, event: Dict[str, Any]) -> Dict[str, Any]:
    global d
    d = host
    return _handle_escalation_push_sns(event)
