#!/usr/bin/env python3
"""Pure payload-construction helpers for the real-time FeedPublisher.

This module is deliberately dependency-free (stdlib only) so the full
lightweight-event contract required by ENC-TSK-B67 (AC-2, AC-10, AC-22, AC-23)
can be unit-tested without AWS, boto3, or a DynamoDB Streams event source.

North Star contract (DOC-E470AC8CE9A8 §6.4): the FeedPublisher computes
*everything* the client needs to render — the pre-rendered summary string, the
derived action, the actor attribution, and the per-record context-node scores.
The browser performs zero text generation, zero aggregation, and zero diffing;
it only ``JSON.parse()`` and renders.

Event payload shape (AC-10 / AC-23) — exactly these keys:

    eventId       UUID v7 (timestamp-sortable, globally unique)
    recordId      the mutated record id
    record_type   task | issue | feature | plan | lesson | document | ...
    action        created | updated | closed | status_changed | ... (pre-derived)
    actorType     "human" | "agent"
    actorId       actor identifier string
    summary       pre-rendered human-readable display string
    cursor        monotonically increasing integer
    context_node  {freshness_score, structural_importance,
                   information_density, access_frequency}  (AC-22)

``occurred_at`` and ``channel`` are carried as transport metadata for latency
instrumentation (AC-3) and routing (AC-1); they are not part of the AC-10 core
model the client renders.
"""

from __future__ import annotations

import math
import os
import secrets
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Versioning / constants
# ---------------------------------------------------------------------------

PAYLOAD_VERSION = "2.0"

# Relationship fields the publisher can see on a tracker record. The count of
# populated edges across these fields is the basis for the *absolute* degree
# centrality used as structural_importance (DOC-310B93107B60 §4 — explicitly
# NOT the query-relative seed-PPR metric).
EDGE_FIELDS: Tuple[str, ...] = (
    "parent",
    "subtask_ids",
    "related_task_ids",
    "related_issue_ids",
    "related_feature_ids",
    "related_lesson_ids",
    "related_document_ids",
    "related_items",
    "components",
    "superseded_by",
)

# Degree saturation constant: degree/(degree+K) maps an unbounded edge count
# into (0, 1). K=8 means a record with 8 edges scores 0.5.
_DEGREE_SATURATION_K = 8.0

# Freshness exponential-decay half-life in days.
_FRESHNESS_HALFLIFE_DAYS = 7.0

# Text fields used for the information-density (Shannon entropy) signal.
_DENSITY_TEXT_FIELDS: Tuple[str, ...] = (
    "title",
    "description",
    "intent",
    "summary",
    "content",
    "update",
)


# ---------------------------------------------------------------------------
# UUID v7 (RFC 9562) — timestamp-sortable, globally unique
# ---------------------------------------------------------------------------


def uuid7(ts_ms: Optional[int] = None) -> str:
    """Return an RFC 9562 UUID v7 string.

    The first 48 bits encode a Unix millisecond timestamp, making the value
    lexicographically and chronologically sortable (the property AC-9/AC-10
    rely on for dedup + ordering). The remaining bits are random.
    """
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    ts_ms &= (1 << 48) - 1

    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    # Assemble the 128-bit integer.
    value = ts_ms << 80
    value |= 0x7 << 76  # version 7
    value |= rand_a << 64
    value |= 0x2 << 62  # variant (10xx)
    value |= rand_b

    hex_str = f"{value:032x}"
    return (
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


# ---------------------------------------------------------------------------
# Cursor — monotonically increasing integer (AC-9 layer 3, AC-5.4 gap recovery)
# ---------------------------------------------------------------------------


def cursor_from_timestamp(ts_ms: Optional[int] = None) -> int:
    """Derive a monotonically increasing cursor from a millisecond timestamp.

    Using the DynamoDB-Streams approximate event time (ms since epoch) yields a
    globally increasing integer without a shared counter. The client uses it for
    cursor pagination and ``gap_too_large`` detection on reconnect.
    """
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    return int(ts_ms)


# ---------------------------------------------------------------------------
# Actor attribution (AC-2, AC-10, AC-22)
# ---------------------------------------------------------------------------


def derive_actor(new_image: Dict[str, Any], old_image: Dict[str, Any]) -> Tuple[str, str]:
    """Return ``(actorType, actorId)`` for a mutation.

    A mutation is attributed to an *agent* when an agent session owns the
    record's checkout or stamped the last write; otherwise it is a *human*
    (PWA / Cognito) write. This is the source-agnostic attribution required by
    AC-2 (both PWA and MCP agent mutations flow through the same trigger).
    """
    img = new_image or old_image or {}

    session_id = (
        img.get("active_agent_session_id")
        or img.get("last_write_session_id")
        or ""
    )
    if isinstance(session_id, str) and session_id.startswith("ENC-SES-"):
        return "agent", session_id

    write_source = img.get("write_source")
    if isinstance(write_source, dict):
        provider = str(write_source.get("provider", ""))
        channel = str(write_source.get("channel", ""))
        if "agent" in provider.lower() or "agent" in channel.lower() or provider.startswith("ENC-SES-"):
            return "agent", provider or channel or "agent"
        if provider:
            return "human", provider

    # last_update_note convention: "[USER-INITIATED] ..." → human override.
    note = str(img.get("last_update_note", ""))
    if "[USER-INITIATED]" in note:
        return "human", str(img.get("initiated_by", "user"))

    initiated_by = img.get("initiated_by")
    if isinstance(initiated_by, str) and initiated_by:
        return "human", initiated_by

    return "human", "io"


# ---------------------------------------------------------------------------
# Action derivation (AC-10)
# ---------------------------------------------------------------------------


def derive_action(
    event_name: str,
    new_image: Dict[str, Any],
    old_image: Dict[str, Any],
) -> str:
    """Derive the operation string the client renders, server-side.

    ``event_name`` is the DynamoDB Streams event name (INSERT/MODIFY/REMOVE).
    """
    event_name = (event_name or "").upper()
    if event_name == "INSERT":
        return "created"
    if event_name == "REMOVE":
        return "removed"

    old_status = (old_image or {}).get("status")
    new_status = (new_image or {}).get("status")
    if old_status != new_status and new_status is not None:
        if new_status == "closed":
            return "closed"
        return "status_changed"

    # Worklog / history append heuristic.
    old_hist = _history_len(old_image)
    new_hist = _history_len(new_image)
    if new_hist > old_hist:
        return "worklog_appended"

    # Relationship edge added → create_relationship feed event (AC-22).
    if _edge_count(new_image) > _edge_count(old_image):
        return "create_relationship"

    return "updated"


def _history_len(image: Dict[str, Any]) -> int:
    for key in ("worklog", "history", "update_history"):
        val = (image or {}).get(key)
        if isinstance(val, list):
            return len(val)
    return 0


# ---------------------------------------------------------------------------
# Pre-rendered summary (AC-10, AC-23 — backend computes the display string)
# ---------------------------------------------------------------------------


def render_summary(
    record_id: str,
    record_type: str,
    action: str,
    actor_type: str,
    actor_id: str,
    new_image: Dict[str, Any],
    old_image: Dict[str, Any],
) -> str:
    """Build the human-readable, ready-to-render summary string.

    The client renders this verbatim; it performs no text generation (AC-10).
    """
    img = new_image or old_image or {}
    title = str(img.get("title") or img.get("name") or record_id)
    rtype = (record_type or "record").lower()
    actor = "an agent" if actor_type == "agent" else "a human"
    if actor_id and actor_id not in ("io", "user", "agent"):
        actor = f"{actor_type} {actor_id}"

    if action == "created":
        return f"{actor} created {rtype} {record_id}: {title}"
    if action == "closed":
        return f"{actor} closed {rtype} {record_id}: {title}"
    if action == "status_changed":
        old_status = (old_image or {}).get("status", "?")
        new_status = (new_image or {}).get("status", "?")
        return (
            f"{actor} moved {rtype} {record_id} from {old_status} to "
            f"{new_status}: {title}"
        )
    if action == "worklog_appended":
        return f"{actor} appended a worklog entry to {rtype} {record_id}: {title}"
    if action == "create_relationship":
        return f"{actor} added a relationship on {rtype} {record_id}: {title}"
    if action == "removed":
        return f"{actor} removed {rtype} {record_id}: {title}"
    return f"{actor} updated {rtype} {record_id}: {title}"


# ---------------------------------------------------------------------------
# Context-node scoring (AC-22) — absolute, intrinsic, per-record signals
# ---------------------------------------------------------------------------


def _edge_count(image: Dict[str, Any]) -> int:
    """Count populated relationship edges on a record (degree centrality)."""
    if not image:
        return 0
    degree = 0
    for field in EDGE_FIELDS:
        val = image.get(field)
        if val is None or val == "":
            continue
        if isinstance(val, (list, tuple, set)):
            degree += len([v for v in val if v])
        else:
            degree += 1
    return degree


def compute_freshness(updated_at_ms: Optional[int], now_ms: Optional[int] = None) -> float:
    """Exponential-decay freshness in [0, 1] from a last-update timestamp."""
    if not updated_at_ms:
        return 0.0
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    age_days = max(0.0, (now_ms - updated_at_ms) / 86_400_000.0)
    score = math.exp(-math.log(2) * age_days / _FRESHNESS_HALFLIFE_DAYS)
    return round(_clamp01(score), 4)


def compute_structural_importance(image: Dict[str, Any]) -> float:
    """Absolute degree-centrality importance in [0, 1].

    DOC-310B93107B60 §4 decision: ``structural_importance`` is redefined as an
    ABSOLUTE metric (degree centrality, saturating), NOT the query-relative
    seed-PPR value (which was stubbed to 0.5 in v3 and is ill-defined as a
    fixed badge / edge label).
    """
    degree = _edge_count(image)
    score = degree / (degree + _DEGREE_SATURATION_K)
    return round(_clamp01(score), 4)


def compute_information_density(image: Dict[str, Any]) -> float:
    """Normalized Shannon entropy of the record's text content in [0, 1]."""
    parts: List[str] = []
    for field in _DENSITY_TEXT_FIELDS:
        val = (image or {}).get(field)
        if isinstance(val, str) and val:
            parts.append(val)
        elif isinstance(val, list):
            parts.extend(str(v) for v in val if isinstance(v, str))
    text = " ".join(parts).strip()
    if not text:
        return 0.0

    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)

    # Normalize by the max entropy for the observed alphabet size, then weight
    # by a length factor so a 3-char title does not score the same as a rich
    # description. Both factors are absolute and intrinsic to the record.
    alphabet = len(counts)
    max_entropy = math.log2(alphabet) if alphabet > 1 else 1.0
    norm_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
    length_factor = min(1.0, total / 400.0)
    return round(_clamp01(norm_entropy * length_factor), 4)


def compute_context_node(
    image: Dict[str, Any],
    updated_at_ms: Optional[int],
    now_ms: Optional[int] = None,
) -> Dict[str, float]:
    """Assemble the four absolute context-node scores (AC-22)."""
    access_frequency = 0
    raw_af = (image or {}).get("access_frequency")
    if isinstance(raw_af, (int, float)):
        access_frequency = int(raw_af)
    return {
        "freshness_score": compute_freshness(updated_at_ms, now_ms),
        "structural_importance": compute_structural_importance(image),
        "information_density": compute_information_density(image),
        "access_frequency": access_frequency,
    }


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# ---------------------------------------------------------------------------
# Timestamp extraction
# ---------------------------------------------------------------------------


def _parse_iso_ms(value: Any) -> Optional[int]:
    """Parse an ISO-8601 string into ms since epoch, tolerantly."""
    if not isinstance(value, str) or not value:
        return None
    import datetime as _dt

    raw = value.strip().replace("Z", "+00:00")
    try:
        dt = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return int(dt.timestamp() * 1000)


def updated_at_ms_from_image(image: Dict[str, Any]) -> Optional[int]:
    return _parse_iso_ms((image or {}).get("updated_at"))


# ---------------------------------------------------------------------------
# Top-level payload builder (AC-2, AC-10, AC-22, AC-23)
# ---------------------------------------------------------------------------


def build_event_payload(
    *,
    event_name: str,
    new_image: Dict[str, Any],
    old_image: Dict[str, Any],
    approx_creation_ms: Optional[int] = None,
    now_ms: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Build the lightweight feed-event payload for one stream record.

    Returns ``None`` when no renderable record id can be resolved (the record
    is then skipped, contributing no feed noise).
    """
    img = new_image or old_image or {}
    record_id = (
        img.get("record_id")
        or img.get("item_id")
        or img.get("id")
        or img.get("document_id")
    )
    if not record_id:
        return None
    record_id = str(record_id)

    record_type = str(
        img.get("record_type") or img.get("type") or _infer_type(record_id)
    )
    project_id = str(img.get("project_id") or "")

    actor_type, actor_id = derive_actor(new_image, old_image)
    action = derive_action(event_name, new_image, old_image)
    summary = render_summary(
        record_id, record_type, action, actor_type, actor_id, new_image, old_image
    )

    ts_ms = approx_creation_ms or int(time.time() * 1000)
    updated_ms = updated_at_ms_from_image(img) or ts_ms
    context_node = compute_context_node(img, updated_ms, now_ms)

    import datetime as _dt

    occurred_at = (
        _dt.datetime.fromtimestamp(ts_ms / 1000, tz=_dt.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )

    return {
        "eventId": uuid7(ts_ms),
        "recordId": record_id,
        "record_type": record_type,
        "action": action,
        "actorType": actor_type,
        "actorId": actor_id,
        "summary": summary,
        "cursor": cursor_from_timestamp(ts_ms),
        "context_node": context_node,
        # transport metadata (not part of the AC-10 core render model)
        "projectId": project_id,
        "occurred_at": occurred_at,
        "version": PAYLOAD_VERSION,
    }


def channels_for_event(payload: Dict[str, Any]) -> List[str]:
    """Return the AppSync Events channels a payload should be published to.

    Maps the event onto the AC-1 channel model:
      /feed/updates            global activity feed
      /records/{recordId}      record-detail subscriptions
      /projects/{projectId}    project-scoped events
    """
    channels = ["/feed/updates"]
    rid = payload.get("recordId")
    if rid:
        channels.append(f"/records/{rid}")
    pid = payload.get("projectId")
    if pid:
        channels.append(f"/projects/{pid}")
    return channels


def _infer_type(record_id: str) -> str:
    seg = record_id.split("-")
    if len(seg) >= 2:
        code = seg[1].upper()
        return {
            "TSK": "task",
            "ISS": "issue",
            "FTR": "feature",
            "PLN": "plan",
            "LSN": "lesson",
        }.get(code, "record")
    if record_id.startswith("DOC-"):
        return "document"
    return "record"


def payload_size_bytes(payload: Dict[str, Any]) -> int:
    """Serialized JSON size in bytes — used to assert the AC-23 ≤500B budget."""
    import json

    return len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def appsync_endpoint() -> Optional[str]:
    return os.environ.get("APPSYNC_EVENTS_HTTP_ENDPOINT")
