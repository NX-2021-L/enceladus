"""ENC-TSK-S96-0D (ENC-PLN-108 W1.4) -- the lifecycle-stamp history extractor.

Pure and stdlib-only on purpose: no boto3, no environment, no I/O. The same module
is imported by the tracker_mutation Lambda (which derives the stamps SERVER-SIDE
from the record it reads itself) and by tools/backfill_task_lifecycle_stamps.py
(which runs the identical derivation for the dry-run report), so the report an
operator reads and the write the Lambda performs cannot disagree.

What it derives, from one task's stored ``history`` array (entry shape
``{timestamp, status, description}``):

  first_checked_out_at  the timestamp of the FIRST "Agent session checkout by"
                        entry (tracker_mutation checkout note).
  closed_at             the timestamp of the LAST transition into ``closed``,
                        recognised under every writer that ever wrote a close.

The rule that governs everything here is ruling D-21 (DOC-5E1E205FA664, after the
tenets of ENC-FTR-121): THE EXTRACTOR NEVER GUESSES. A closed task whose history
does not PROVE a close time yields no ``closed_at`` and an explicit
``closed_at_unknown`` marker saying why. Concretely it refuses to answer when

  * no entry in the history is a recognised close note,
  * the last recognised close carries a timestamp that cannot be parsed,
  * a status write by a writer this module does not know follows the last
    recognised close (the real last close may be that later write), or
  * a recognised NON-closed transition follows the last recognised close while
    the task is nevertheless closed now (it was re-closed by a write that left no
    recognisable note).

It also never falls back to ``updated_at`` -- the mart's extractor does, and that
is exactly the inference D-21 forbids.

The close notes below were extracted from the writers' own format strings, not
guessed; each carries the file it came from so a future change to a writer can be
matched against this table. ``tracker_mutation/test_lifecycle_backfill_s96_0d.py``
pins each skeleton to the writer's source text, so editing a writer's note without
updating this table fails a test instead of silently turning proven closes into
unknown ones.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

EXTRACTOR_VERSION = "1"

# The governing rulings, stamped into every closed_at_unknown marker so the record
# explains itself without a trip to the idea doc.
BACKFILL_BASIS = "DOC-5E1E205FA664 ruling D-21 (the backfill never guesses a close time)"

CHECKOUT_NOTE_PREFIX = "Agent session checkout by "

_TS_OUT = "%Y-%m-%dT%H:%M:%SZ"
_TS_RE = re.compile(
    r"^(?P<d>\d{4}-\d{2}-\d{2})[T ](?P<t>\d{2}:\d{2}:\d{2})(?:\.\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2})$"
)

# --------------------------------------------------------------------------
# The writers. Each regex is anchored at the START of the history description;
# the mart's extractor uses an unanchored search, which also fires on prose that
# merely quotes a note ("... Field 'status' set to 'closed' ...") -- a false
# proof is worse than an unknown here.
# --------------------------------------------------------------------------

# writer id -> (source sites, human description). The sites are file:line of the
# format string at the base this was written against (b548665e); the skeleton test
# asserts the literal text still appears in the file, so a line drift is harmless.
CLOSE_WRITERS: Dict[str, Dict[str, Any]] = {
    "tracker_mutation.generic_patch": {
        "sites": ["backend/lambda/tracker_mutation/lambda_function.py:7244"],
        "skeleton": "Field 'status' set to 'closed'[ [provider=...]][ [evidence: ...]]",
    },
    "tracker_mutation.pwa_close": {
        "sites": ["backend/lambda/tracker_mutation/lambda_function.py:7540"],
        "skeleton": "Closed via Enceladus PWA   (history status 'close_audit')",
    },
    "tracker_mutation.escalation_override": {
        "sites": ["backend/lambda/tracker_mutation/lambda_function.py:697"],
        "skeleton": "[ESCALATION-APPLIED] <id> (direct_state_override) ... after={\"status\": \"closed\", ...}",
    },
    "tracker_mutation.arc_walker": {
        "sites": ["backend/lambda/tracker_mutation/lambda_function.py:3229"],
        "skeleton": "[ARC-WALKER][AUTO-ADVANCE] <from> -> closed (gate_class=...",
    },
    "tracker_mutation.human_override": {
        "sites": ["backend/lambda/tracker_mutation/lambda_function.py:6057"],
        "skeleton": "[USER-INITIATED] Status changed to 'closed' by <user>. Note: <note>",
    },
    "coordination_api._set_tracker_status": {
        "sites": [
            "backend/lambda/coordination_api/lambda_function.py:7572",
            "backend/lambda/coordination_api/lifecycle.py:79",
        ],
        # Two copies of _set_tracker_status (lambda_function.py and tracker_ops.py)
        # are called from two copies of _finalize_tracker_from_request
        # (lambda_function.py and lifecycle.py); the note is the caller's, and both
        # callers pass the same string, so the two writers emit ONE skeleton.
        "skeleton": "Coordination request <request_id> completed successfully.",
    },
}

# A writer that no longer exists but whose closes are still in the stored history.
# bedrock_agent_actions stopped writing the tracker in ENC-TSK-T04 (ENC-ISS-909,
# ENC-ISS-911) so it is NOT a live close writer and W1.1/W1.2 do not stamp from it
# (ruling D-24); but every close it made before that is real history, and the idea
# doc counts it among the seven notes the extractor must know. Dropping it would
# turn proven historical closes into unknowns.
RETIRED_CLOSE_WRITERS: Dict[str, Dict[str, Any]] = {
    "bedrock_agent_actions._handle_tracker_status": {
        "sites": ["backend/lambda/bedrock_agent_actions/lambda_function.py (removed by 87822d84)"],
        "skeleton": "Status changed to 'closed' by bedrock agent   (unquoted before ENC-TSK-S94)",
    },
}

_STATUS = r"(?P<to>[A-Za-z0-9_\- ]+?)"

# (writer id, compiled regex over the description). `to` is the target status.
_TRANSITION_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("tracker_mutation.generic_patch",
     re.compile(r"^Field 'status' set to '" + _STATUS + r"'(?=$|\s)", re.IGNORECASE)),
    ("tracker_mutation.human_override",
     re.compile(r"^\[USER-INITIATED\] Status changed to '" + _STATUS + r"' by ", re.IGNORECASE)),
    ("tracker_mutation.arc_walker",
     re.compile(r"^\[ARC-WALKER\]\[AUTO-ADVANCE\] \S+ -> (?P<to>[A-Za-z0-9_\-]+) \(gate_class=")),
    ("tracker_mutation.escalation_override",
     re.compile(r"^\[ESCALATION-APPLIED\] \S+ \(direct_state_override\) .*?after=\{\"status\": \""
                r"(?P<to>[A-Za-z0-9_\-]+)\"", re.DOTALL)),
    ("bedrock_agent_actions._handle_tracker_status",
     re.compile(r"^Status changed to '?" + _STATUS + r"'? by bedrock agent$", re.IGNORECASE)),
)

_COORD_CLOSE_RE = re.compile(r"^Coordination request \S+ completed successfully\.$")
_COORD_RUNNING_RE = re.compile(r"^Coordination request \S+ running via SSM$")
_PWA_CLOSE_DESC = "Closed via Enceladus PWA"
_PWA_REOPEN_DESC = "Reopened via Enceladus PWA"

# Any OTHER status write whose writer we cannot attribute: the mart's legacy
# "Status changed to '<x>'" shape. It never counts as proof, but it does stop a
# proof that precedes it (see derive_closed_at).
_UNATTRIBUTED_STATUS_RE = re.compile(
    r"^(?:Field 'status' set to|Status changed to) '(?P<to>[A-Za-z0-9_\- ]+)'", re.IGNORECASE)

CLOSED = "closed"


def _norm_status(raw: str) -> str:
    return raw.strip().replace("_", "-").lower()


def normalise_timestamp(raw: Any) -> Optional[str]:
    """Return the instant as ``YYYY-MM-DDTHH:MM:SSZ`` (UTC), or None if it cannot be proven.

    A timestamp with no zone designator is refused rather than assumed to be UTC.
    """
    if not isinstance(raw, str):
        return None
    m = _TS_RE.match(raw.strip())
    if not m:
        return None
    tz = m.group("tz")
    try:
        naive = _dt.datetime.strptime(f"{m.group('d')}T{m.group('t')}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        naive -= sign * _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return naive.strftime(_TS_OUT)


class Transition:
    """One history entry read as a status write by a known (or unattributed) writer."""

    __slots__ = ("index", "writer", "to_status", "timestamp", "recognised")

    def __init__(self, index: int, writer: str, to_status: str, timestamp: Optional[str], recognised: bool):
        self.index = index
        self.writer = writer
        self.to_status = to_status
        self.timestamp = timestamp
        self.recognised = recognised

    def as_dict(self) -> Dict[str, Any]:
        return {"index": self.index, "writer": self.writer, "to_status": self.to_status,
                "timestamp": self.timestamp, "recognised": self.recognised}


def parse_status_write(entry: Mapping[str, Any], index: int = 0) -> Optional[Transition]:
    """Read ONE history entry as a status write, or return None if it is not one."""
    if not isinstance(entry, Mapping):
        return None
    desc = entry.get("description")
    desc = desc.strip() if isinstance(desc, str) else ""
    entry_status = _norm_status(entry.get("status") or "") if isinstance(entry.get("status"), str) else ""
    ts = normalise_timestamp(entry.get("timestamp"))

    # Legacy PWA close / reopen: identified by the exact description (and carries
    # status close_audit / reopened, which we do not require).
    if desc == _PWA_CLOSE_DESC:
        return Transition(index, "tracker_mutation.pwa_close", CLOSED, ts, True)
    if desc == _PWA_REOPEN_DESC:
        return Transition(index, "tracker_mutation.pwa_close", "open", ts, True)
    if _COORD_CLOSE_RE.match(desc):
        return Transition(index, "coordination_api._set_tracker_status", CLOSED, ts, True)
    if _COORD_RUNNING_RE.match(desc):
        return Transition(index, "coordination_api._set_tracker_status", "in-progress", ts, True)
    for writer, rx in _TRANSITION_PATTERNS:
        m = rx.match(desc)
        if m:
            return Transition(index, writer, _norm_status(m.group("to")), ts, True)
    m = _UNATTRIBUTED_STATUS_RE.match(desc)
    if m:
        return Transition(index, "unattributed", _norm_status(m.group("to")), ts, False)
    # An entry whose own status column says closed but whose note we cannot read is
    # a close we cannot attribute (never proof, but it blocks an earlier proof).
    if entry_status == CLOSED:
        return Transition(index, "unattributed", CLOSED, ts, False)
    return None


def _history(record: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    hist = record.get("history")
    return [e for e in hist if isinstance(e, Mapping)] if isinstance(hist, Sequence) and not isinstance(hist, (str, bytes)) else []


def first_checkout(record: Mapping[str, Any]) -> Tuple[Optional[str], Optional[int], str]:
    """(timestamp, history index, state) for the first checkout note.

    state: ``found`` | ``none`` | ``unparsable_timestamp``
    """
    for idx, entry in enumerate(_history(record)):
        desc = entry.get("description")
        if isinstance(desc, str) and desc.startswith(CHECKOUT_NOTE_PREFIX):
            ts = normalise_timestamp(entry.get("timestamp"))
            return (ts, idx, "found") if ts else (None, idx, "unparsable_timestamp")
    return None, None, "none"


def derive_closed_at(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Derive the close time for a record whose current status is closed.

    Returns ``{"state": "proven", "closed_at", "writer", "index"}`` or
    ``{"state": "unknown", "reason": <code>, "detail": <text>}``. Callers must
    have established that the record is closed; this function does not look at
    ``status`` itself.
    """
    writes = [t for t in (parse_status_write(e, i) for i, e in enumerate(_history(record))) if t is not None]
    closes = [t for t in writes if t.recognised and t.to_status == CLOSED]
    if not closes:
        stray = [t for t in writes if t.to_status == CLOSED]
        if stray:
            return {"state": "unknown", "reason": "close_by_unrecognised_writer",
                    "detail": f"{len(stray)} history entr{'y' if len(stray) == 1 else 'ies'} record a close "
                              f"in a shape none of the known close writers produces"}
        return {"state": "unknown", "reason": "no_recognised_close_note",
                "detail": "the history holds no close note from any known writer"}
    last = closes[-1]  # history is append-only, so position is write order
    n_closes = len(closes)
    if last.timestamp is None:
        return {"state": "unknown", "reason": "close_note_timestamp_unparsable", "recognised_closes": n_closes,
                "detail": f"history[{last.index}] is a close by {last.writer} but its timestamp cannot be parsed"}
    for later in writes:
        if later.index <= last.index:
            continue
        if not later.recognised:
            return {"state": "unknown", "reason": "later_unrecognised_status_write", "recognised_closes": n_closes,
                    "detail": f"history[{later.index}] is a status write to '{later.to_status}' by an "
                              f"unattributed writer after the last recognised close at history[{last.index}]"}
        if later.to_status != CLOSED:
            return {"state": "unknown", "reason": "reopened_after_last_close", "recognised_closes": n_closes,
                    "detail": f"history[{later.index}] moves the task to '{later.to_status}' after the last "
                              f"recognised close at history[{last.index}], yet the task is closed now"}
    return {"state": "proven", "closed_at": last.timestamp, "writer": last.writer, "index": last.index,
            "recognised_closes": n_closes}


def _count(raw: Any) -> Optional[int]:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def plan_lifecycle_stamps(record: Mapping[str, Any]) -> Dict[str, Any]:
    """The full derivation for one task record -- what to stamp, what to leave, and why.

    ``set`` holds ONLY attributes that are absent on the record and that history
    proves (or, for the waiver, that history fails to prove). It never contains an
    attribute the record already carries: the write is set-if-absent, and an
    existing value (including one io set through an escalation, ruling D-21) is
    never replaced.

    ``checkout_class`` / ``close_class`` are the dry-run report's buckets.
    """
    status = _norm_status(record.get("status") or "") if isinstance(record.get("status"), str) else ""
    count = _count(record.get("checkout_count"))
    never_checked_out = not count or count <= 0
    out: Dict[str, Any] = {
        "status": status,
        "checkout_count": count or 0,
        "checked_out": not never_checked_out,
        "set": {},
        "flags": [],
    }

    # ---- first_checked_out_at --------------------------------------------
    # io ruling 2026-11-19 (D-31, "history wins"): HISTORY decides whether a task was
    # ever checked out; checkout_count is corroboration, never a gate. The first gamma
    # dry run found 782 tasks carrying a recognisable checkout note while their
    # checkout_count was 0, because the counter arrived with ENC-TSK-F41 and was never
    # backfilled -- on a pre-F41 record a zero count is an ABSENT counter, not a claim
    # that no checkout happened. Gating on it discarded proof the extractor already
    # held. Ruling D-21 still binds in full: nothing is guessed, and a task whose
    # history proves no first checkout is still left unstamped.
    note_ts, note_idx, note_state = first_checkout(record)
    if record.get("first_checked_out_at"):
        out["checkout_class"] = "already_set"
    elif note_state == "found":
        out["checkout_class"] = "stamped"
        out["set"]["first_checked_out_at"] = note_ts
        out["first_checked_out_at_index"] = note_idx
        if never_checked_out:
            # Stamped from history, and the disagreement with the counter is still
            # reported rather than hidden -- it is the audit trail for D-31.
            out["flags"].append("checkout_note_but_count_zero")
    elif note_state == "unparsable_timestamp":
        out["checkout_class"] = "checked_out_unprovable"
        out["flags"].append("first_checkout_timestamp_unparsable")
    elif never_checked_out:
        out["checkout_class"] = "never_checked_out"
    else:
        out["checkout_class"] = "checked_out_unprovable"
        out["flags"].append("checkout_count_positive_but_no_checkout_note")

    # ---- closed_at / closed_at_unknown -----------------------------------
    if status != CLOSED:
        out["close_class"] = "not_closed"
        return out
    closed_count = _count(record.get("closed_count"))
    if record.get("closed_at"):
        out["close_class"] = "already_set"
        return out
    d = derive_closed_at(record)
    if closed_count is not None and closed_count > d.get("recognised_closes", 0):
        # Informational only: closed_count rose by more than the recognised close
        # notes explain. Older writers added no closed_count, so the reverse is
        # normal; this direction hints at a close that left no recognisable note.
        out["flags"].append("closed_count_exceeds_recognised_closes")
    if d["state"] == "proven":
        if record.get("closed_at_unknown"):
            out["close_class"] = "proven_but_unknown_marker_present"
            out["flags"].append("closed_at_unknown_marker_present_not_replaced")
        else:
            out["close_class"] = "proven"
            out["set"]["closed_at"] = d["closed_at"]
            out["close_writer"] = d["writer"]
    else:
        if record.get("closed_at_unknown"):
            out["close_class"] = "already_unknown"
        else:
            out["close_class"] = "unknown"
            out["unknown_reason"] = d["reason"]
            out["unknown_detail"] = d["detail"]
            out["set"]["closed_at_unknown"] = {"reason": d["reason"], "detail": d["detail"]}
    return out


def marker_value(unknown: Mapping[str, Any], run_id: str, recorded_at: str) -> Dict[str, Any]:
    """The full ``closed_at_unknown`` map: that the time is unknown, why, and when the backfill ran."""
    return {
        "reason": str(unknown.get("reason") or ""),
        "detail": str(unknown.get("detail") or ""),
        "basis": BACKFILL_BASIS,
        "backfill_run_id": run_id,
        "recorded_at": recorded_at,
        "extractor_version": EXTRACTOR_VERSION,
    }
