"""Manifest Primitive v1 projection helpers (ENC-FTR-097, ENC-TSK-G27).

Pure functions that transform a tracker record (as returned by the
tracker API GET endpoint) into the manifest, AC-body, and worklog
projections defined in DOC-59D2295AA7FD section 7.1. No I/O.

Source of truth: DOC-59D2295AA7FD section 7.1.1 through 7.1.6.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


_AC_STATUS_COMPLETE = "complete"
_AC_STATUS_INCOMPLETE = "incomplete"

# Stable subset used to compute content_hash. Excludes ephemeral metadata
# (sync_version, write_source, history) so the hash is identical across
# reads of a record that has not changed.
_HASH_FIELDS: Tuple[str, ...] = (
    "record_id",
    "item_id",
    "project_id",
    "record_type",
    "title",
    "description",
    "status",
    "priority",
    "category",
    "intent",
    "transition_type",
    "components",
    "parent",
    "subtask_ids",
    "acceptance_criteria",
    "related_task_ids",
    "related_issue_ids",
    "related_feature_ids",
    "user_story",
    "commit_sha",
    "deploy_evidence",
    "transition_evidence",
    "updated_at",
)

_AC_TOUCH_RE = re.compile(
    r"^Acceptance criterion \[(?P<idx>\d+)\] evidence (accepted|updated)"
)
_STATUS_TRANSITION_RE = re.compile(
    r"^Field 'status' set to '(?P<to>[^']+)'"
)


def compute_content_hash(record: Dict[str, Any]) -> str:
    """Stable SHA-256 hex digest over the canonical subset of ``record``.

    The hash is the read-side freshness token used by ``tracker.get_acs``
    and ``tracker.worklogs`` (DOC-59D2295AA7FD section 7.1.6). Two reads of
    an unchanged record return identical digests.
    """
    canonical: Dict[str, Any] = {}
    for key in _HASH_FIELDS:
        if key in record and record[key] is not None:
            canonical[key] = record[key]
    serialized = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def short_title(text: Any, max_len: int = 80) -> str:
    """First clause / first ``max_len`` chars of ``text``."""
    if text is None:
        return ""
    s = str(text).strip()
    if not s:
        return ""
    for stop in (". ", "; ", "\n"):
        idx = s.find(stop)
        if 0 < idx < max_len:
            return s[:idx].strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"


def _ac_dict(ac: Any) -> Dict[str, Any]:
    """Normalize a structured-or-string AC entry to a dict."""
    if isinstance(ac, dict):
        return ac
    return {
        "description": str(ac) if ac is not None else "",
        "evidence": "",
        "evidence_acceptance": False,
    }


def _ac_status(ac: Dict[str, Any]) -> str:
    return _AC_STATUS_COMPLETE if ac.get("evidence_acceptance") else _AC_STATUS_INCOMPLETE


def _ac_evidence_ref(ac: Dict[str, Any], max_len: int = 200) -> str:
    """Compact evidence pointer; full body is on tracker.get_acs."""
    ev = ac.get("evidence")
    if ev is None:
        return ""
    s = str(ev).strip()
    if not s:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"


def _ac_last_touched(
    history: Optional[List[Dict[str, Any]]], idx: int, fallback: str
) -> str:
    """Most recent set_acceptance_evidence timestamp for AC ``idx``.

    Falls back to ``fallback`` (record updated_at) when no AC-touch entry
    is found in the history index.
    """
    if not history:
        return fallback or ""
    for entry in reversed(history):
        desc = str(entry.get("description") or "")
        match = _AC_TOUCH_RE.match(desc)
        if match and int(match.group("idx")) == idx:
            return str(entry.get("timestamp") or fallback or "")
    return fallback or ""


def project_ac_manifest(
    ac: Any,
    idx: int,
    history: Optional[List[Dict[str, Any]]],
    fallback_timestamp: str,
) -> Dict[str, Any]:
    """Per-AC manifest projection (DOC-59D2295AA7FD section 7.1.1)."""
    norm = _ac_dict(ac)
    return {
        "ac_index": idx,
        "short_title": short_title(norm.get("description", "")),
        "status": _ac_status(norm),
        "evidence_ref": _ac_evidence_ref(norm),
        "last_touched": _ac_last_touched(history, idx, fallback_timestamp),
    }


def project_ac_body(ac: Any, idx: int) -> Dict[str, Any]:
    """Full-body AC projection (DOC-59D2295AA7FD section 7.1.2)."""
    norm = _ac_dict(ac)
    return {
        "ac_index": idx,
        "body": str(norm.get("description") or ""),
        "status": _ac_status(norm),
        "evidence_ref": _ac_evidence_ref(norm, max_len=2000),
    }


def _normalize_fields(fields: Optional[Iterable[Any]]) -> Optional[set]:
    if fields is None:
        return None
    norm = {str(f).strip() for f in fields if str(f).strip()}
    return norm or None


# Identity / freshness fields are always retained even when ``fields``
# narrows the projection — without them the manifest is unidentifiable.
_REQUIRED_MANIFEST_FIELDS = frozenset({"record_id", "content_hash", "updated_at"})


def project_record_manifest(
    record: Dict[str, Any], fields: Optional[Iterable[Any]] = None
) -> Dict[str, Any]:
    """Per-record manifest with optional projection narrowing.

    Used by both ``tracker.manifest`` (DOC-59D2295AA7FD section 7.1.1)
    and ``tracker.manifest_bulk`` (section 7.1.5).
    """
    history = record.get("history") if isinstance(record.get("history"), list) else []
    updated_at = str(record.get("updated_at") or "")
    acs = [
        project_ac_manifest(ac, idx, history, updated_at)
        for idx, ac in enumerate(record.get("acceptance_criteria") or [])
    ]
    full: Dict[str, Any] = {
        "record_id": str(record.get("item_id") or record.get("record_id") or ""),
        "title": str(record.get("title") or ""),
        "record_type": str(record.get("record_type") or ""),
        "status": str(record.get("status") or ""),
        "priority": str(record.get("priority") or ""),
        "transition_type": str(record.get("transition_type") or ""),
        "updated_at": updated_at,
        "acs": acs,
        "ac_count": len(acs),
        "content_hash": compute_content_hash(record),
    }
    allowed = _normalize_fields(fields)
    if allowed is None:
        return full
    return {
        k: v
        for k, v in full.items()
        if k in allowed or k in _REQUIRED_MANIFEST_FIELDS
    }


def parse_transition(description: str) -> Optional[Dict[str, Any]]:
    """Pull a {to: <new_status>} fragment out of a status-write history line."""
    if not description:
        return None
    match = _STATUS_TRANSITION_RE.match(str(description).strip())
    if not match:
        return None
    return {"to": match.group("to")}


def worklog_id(idx: int) -> str:
    """Position-based deterministic worklog ID."""
    return f"wl-{idx:04d}"


def project_worklog_metadata(entry: Dict[str, Any], idx: int) -> Dict[str, Any]:
    """Per-entry metadata projection (DOC-59D2295AA7FD section 7.1.3)."""
    desc = str(entry.get("description") or "")
    transition = parse_transition(desc)
    out: Dict[str, Any] = {
        "worklog_id": worklog_id(idx),
        "timestamp": str(entry.get("timestamp") or ""),
        "author": str(
            entry.get("provider") or entry.get("author") or "system"
        ),
        "size_bytes": len(desc.encode("utf-8")),
    }
    if transition:
        out["transition"] = transition
    return out


def project_worklog_body(entry: Dict[str, Any], idx: int) -> Dict[str, Any]:
    """Full-body worklog projection (DOC-59D2295AA7FD section 7.1.4)."""
    base = project_worklog_metadata(entry, idx)
    base["body"] = str(entry.get("description") or "")
    base["status"] = str(entry.get("status") or "worklog")
    return base


def filter_worklogs(
    history: Optional[List[Dict[str, Any]]],
    since: Optional[str] = None,
    until: Optional[str] = None,
    ids: Optional[Iterable[str]] = None,
) -> List[Tuple[int, Dict[str, Any]]]:
    """Filter and order worklogs by timestamp ascending.

    ``since`` / ``until`` are ISO-8601 strings; lexicographic comparison is
    correct for normalized UTC timestamps (the tracker store always writes
    Zulu suffix). ``ids`` is a set of synthesized worklog IDs (``wl-NNNN``).
    """
    if not history:
        return []
    indexed = list(enumerate(history))
    indexed.sort(key=lambda pair: str(pair[1].get("timestamp") or ""))
    id_set = {str(i).strip() for i in ids} if ids else None
    out: List[Tuple[int, Dict[str, Any]]] = []
    for idx, entry in indexed:
        ts = str(entry.get("timestamp") or "")
        if since and ts < str(since):
            continue
        if until and ts > str(until):
            continue
        if id_set is not None and worklog_id(idx) not in id_set:
            continue
        out.append((idx, entry))
    return out


# --- Freshness contract -----------------------------------------------------

# Structured staleness response code — referenced in governance dictionary.
STALE_ERROR_CODE = "STALE_CONTENT_HASH"
BULK_LIMIT_ERROR_CODE = "BULK_SIZE_EXCEEDED"
INDEX_OUT_OF_RANGE_ERROR_CODE = "AC_INDEX_OUT_OF_RANGE"


def staleness_envelope(
    record_id: str, current_hash: str, supplied_hash: str
) -> Dict[str, Any]:
    """Structured rejection body for a stale content_hash."""
    return {
        "error": True,
        "error_code": STALE_ERROR_CODE,
        "record_id": record_id,
        "current_content_hash": current_hash,
        "supplied_content_hash": supplied_hash,
        "retry_guidance": (
            "Refresh the manifest via tracker.manifest (single record) or "
            "tracker.manifest_bulk (set), then retry the selective fetch with "
            "the new content_hash."
        ),
    }


def coerce_indices(value: Any) -> List[int]:
    """Coerce caller-supplied AC indices into a sorted list of unique non-negative ints."""
    if value is None:
        return []
    if isinstance(value, (int, str)):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"indices must be a list of integers, got {type(value).__name__}")
    out: List[int] = []
    for raw in value:
        try:
            i = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"index {raw!r} is not an integer") from exc
        if i < 0:
            raise ValueError(f"index {i} must be non-negative")
        out.append(i)
    return sorted(set(out))
