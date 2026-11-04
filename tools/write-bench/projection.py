"""Projection-lag read-back and burst-cell helpers (ENC-TSK-S46-0B; BRD DOC-735D82EA6E0E 7.2 / 9.2).

After a governed write acks, poll the touched record(s) through the MCP read surface
(search tracker.get) every POLL_INTERVAL_S until projection_status == "projected" or
CAP_S elapses. projection_lag_ms = t_projected - t_ack, both ms epoch, where t_ack comes
from the write response and t_projected is the receipt time of the first poll that saw
"projected". A non-success read counts as "not yet projected" (ENC-ISS-893: gamma reads of
ZNC-* ids fail until ENC-TSK-S42); when every poll failed the result carries
blocked_reason="read_unavailable". Stdlib only; polling runs outside the timed write.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import wire

POLL_INTERVAL_S = 0.1
CAP_S = 60.0
PROJECTED = "projected"
BURST_OP = "execute_20_independent_burst"
BURST_SIZE = 20

# read_fn(record_id) -> (ok, payload, t_receipt_ms)
ReadFn = Callable[[str], Tuple[bool, Any, float]]


def lag_applies(op: str) -> bool:
    """Default-on for tracker_* and execute_* cells; off for documents_*."""
    return op.startswith("tracker_") or op.startswith("execute_")


def parse_t_ack_ms(value: Any) -> Optional[float]:
    """Accept ms epoch, s epoch, or ISO-8601; return ms epoch or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if value > 1e11 else float(value) * 1000.0
    if isinstance(value, str) and value:
        try:
            return parse_t_ack_ms(float(value))
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000.0
        except ValueError:
            return None
    return None


def extract_t_ack_ms(payload: Any, fallback_ms: float) -> Tuple[float, str]:
    t = parse_t_ack_ms(wire.find_key(payload, "t_ack"))
    return (t, "response") if t is not None else (fallback_ms, "client_end_fallback")


def record_ids_for(tool: str, arguments: Dict[str, Any], payload: Any) -> List[str]:
    """Distinct record ids a write touched: tracker.set args, or the created record id."""
    ids: List[str] = []
    for s in arguments.get("steps", []) if isinstance(arguments, dict) else []:
        a = s.get("arguments", {})
        if s.get("action") == "tracker.set" and a.get("record_id"):
            ids.append(a["record_id"])
    if not ids:
        rid = wire.find_key(payload, "record_id")
        if isinstance(rid, str):
            ids.append(rid)
    return list(dict.fromkeys(ids))


def step_failures(payload: Any) -> List[str]:
    """Tool-level failure messages from an execute payload (top-level or per step)."""
    msgs: List[str] = []
    if isinstance(payload, dict):
        for key in ("results", "steps"):
            seq = payload.get(key)
            if isinstance(seq, list):
                for i, item in enumerate(seq):
                    if isinstance(item, dict) and (item.get("success") is False or item.get("error")):
                        msgs.append(f"step {i}: {str(item.get('error') or item.get('message') or 'failed')[:160]}")
        if payload.get("success") is False and not msgs:
            msgs.append(str(payload.get("error") or payload.get("message") or "success=false")[:160])
    elif isinstance(payload, str) and payload:
        msgs.append(payload[:160])
    return msgs


def is_projected(payload: Any) -> bool:
    return wire.find_key(payload, "projection_status") == PROJECTED


def poll_projection(read_fn: ReadFn, record_ids: List[str], t_ack_ms: float,
                    interval_s: float = POLL_INTERVAL_S, cap_s: float = CAP_S,
                    sleep: Callable[[float], None] = time.sleep,
                    monotonic: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """Poll all ids each round until each is projected or cap_s elapses.
    projection_lag_ms is the MAX per-record lag (the burst is only 'landed' when its last record is)."""
    start = monotonic()
    pending = list(record_ids)
    per_record: Dict[str, Optional[float]] = {r: None for r in record_ids}
    polls = ok_polls = 0
    while pending:
        for rid in list(pending):
            ok, payload, t_rcv = read_fn(rid)
            polls += 1
            if ok:
                ok_polls += 1
                if is_projected(payload):
                    per_record[rid] = max(0.0, t_rcv - t_ack_ms)
                    pending.remove(rid)
        if not pending or monotonic() - start >= cap_s:
            break
        sleep(interval_s)
    timed_out = bool(pending)
    out: Dict[str, Any] = {
        "projection_polls": polls, "projection_timed_out": timed_out,
        "projection_lag_ms": None if timed_out else (max(per_record.values()) if per_record else None),
        "projection_lag_per_record_ms": per_record, "projection_blocked_reason": None,
    }
    if polls and ok_polls == 0:
        out["projection_blocked_reason"] = "read_unavailable"
    return out


def make_read_fn(session: Any) -> ReadFn:
    """Read via search tracker.get on a long-lived session (outside the timed write)."""
    def read(record_id: str) -> Tuple[bool, Any, float]:
        rec = session.call("search", {"action": "tracker.get", "arguments": {"record_id": record_id}}, str(uuid.uuid4()))
        return bool(rec.get("ok")), rec.get("payload"), float(rec["t_client_end"]) * 1000.0
    return read


def annotate_call(rec: Dict[str, Any], op: str, tool: str, arguments: Dict[str, Any],
                  read_fn: Optional[ReadFn], interval_s: float = POLL_INTERVAL_S, cap_s: float = CAP_S,
                  sleep: Callable[[float], None] = time.sleep) -> None:
    """Burst blocked detection + projection read-back. Mutates rec (payload must still be present)."""
    payload = rec.get("payload")
    if op == BURST_OP:
        fails = [] if rec.get("ok") else (step_failures(payload) or [str(rec.get("error") or "call_failed")[:160]])
        if rec.get("ok"):
            fails = step_failures(payload)
        if fails:
            rec["ok"] = False  # never counted as latency
            rec["status"] = "blocked"
            rec["blocked_reason"] = "tool_failure: " + "; ".join(fails[:3])
            return
    if read_fn is None or not lag_applies(op) or not rec.get("ok"):
        return
    ids = record_ids_for(tool, arguments, payload)
    if not ids:
        return
    t_ack, src = extract_t_ack_ms(payload, float(rec.get("t_client_end") or time.time()) * 1000.0)
    rec["t_ack_ms"], rec["t_ack_source"] = t_ack, src
    rec.update(poll_projection(read_fn, ids, t_ack, interval_s, cap_s, sleep))


def summarize_lag(calls: List[dict], resamples: int = 10_000) -> Dict[str, Dict[str, Any]]:
    """Per-cell projection_lag_ms summary (p50/p95 + bootstrap CIs) plus poll/timeout/blocked counts."""
    import stats  # noqa: PLC0415
    cells: Dict[str, List[dict]] = {}
    for c in calls:
        if c.get("warmup") or not ("projection_polls" in c or c.get("status") == "blocked"):
            continue
        cells.setdefault(stats.cell_key(c["operation"], c["arm"], c["series"]), []).append(c)
    samples = stats.group_samples(calls, "projection_lag_ms")
    out: Dict[str, Dict[str, Any]] = {}
    for key, cs in sorted(cells.items()):
        blocked = [c for c in cs if c.get("status") == "blocked"]
        polled = [c for c in cs if "projection_polls" in c]
        entry: Dict[str, Any] = {"calls": len(cs), "timed_out": sum(1 for c in polled if c["projection_timed_out"]),
                                 "polls_total": sum(c["projection_polls"] for c in polled)}
        if blocked and len(blocked) == len(cs):
            entry.update(status="blocked", blocked_reason=blocked[0]["blocked_reason"])
        elif polled and all(c.get("projection_blocked_reason") == "read_unavailable" for c in polled):
            entry.update(status="blocked", blocked_reason="read_unavailable")
        if key in samples:
            entry.update(stats.summarize(samples[key], key + ":projection_lag_ms", resamples))
        out[key] = entry
    return out
