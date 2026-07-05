"""Feed corpus pagination for GET /api/v1/feed/corpus (ENC-TSK-L23 / FTR-127)."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
VALID_SORTS = {
    "updated_at_desc",
    "record_id_asc",
    "title_asc",
    "status_asc",
    "priority_asc",
}

_FACET_FIELDS = ("record_type", "status", "priority", "project_id")


def _clamp_limit(raw: Any) -> int:
    try:
        value = int(str(raw or DEFAULT_LIMIT))
    except (TypeError, ValueError):
        value = DEFAULT_LIMIT
    return max(1, min(MAX_LIMIT, value))


def _split_csv(raw: Any) -> List[str]:
    if raw is None:
        return []
    return [part.strip().lower() for part in str(raw).split(",") if part.strip()]


def parse_corpus_query(qs: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "limit": _clamp_limit(qs.get("limit")),
        "cursor": str(qs.get("cursor") or "").strip(),
        "sort": str(qs.get("sort") or "updated_at_desc").strip().lower(),
        "q": str(qs.get("q") or "").strip().lower(),
        "record_type": _split_csv(qs.get("record_type")),
        "status": _split_csv(qs.get("status")),
        "project_id": _split_csv(qs.get("project_id")),
        "priority": _split_csv(qs.get("priority")),
    }


def encode_cursor(sort_value: str, record_key: str) -> str:
    payload = {"sort_value": sort_value, "record_key": record_key}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(raw: str) -> Optional[Tuple[str, str]]:
    if not raw:
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        sort_value = str(payload.get("sort_value") or "")
        record_key = str(payload.get("record_key") or "")
        if not sort_value or not record_key:
            return None
        return sort_value, record_key
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        return None


def _sort_key(entry: Mapping[str, Any], sort: str) -> Tuple:
    if sort == "record_id_asc":
        primary = str(entry.get("record_id") or "").lower()
    elif sort == "title_asc":
        primary = str(entry.get("title") or "").lower()
    elif sort == "status_asc":
        primary = str((entry.get("attrs") or {}).get("status") or "").lower()
    elif sort == "priority_asc":
        primary = str((entry.get("attrs") or {}).get("priority") or "").lower()
    else:
        primary = str(entry.get("updated_at") or "")
        sort = "updated_at_desc"
    record_key = str(entry.get("record_key") or "")
    if sort == "updated_at_desc":
        return (primary, record_key)
    return (primary, record_key)


def sort_entries(entries: Sequence[Mapping[str, Any]], sort: str) -> List[Dict[str, Any]]:
    normalized_sort = sort if sort in VALID_SORTS else "updated_at_desc"
    if normalized_sort == "updated_at_desc":
        ordered = sorted(
            entries,
            key=lambda entry: (
                str(entry.get("updated_at") or ""),
                str(entry.get("record_key") or ""),
            ),
            reverse=True,
        )
    else:
        ordered = sorted(entries, key=lambda entry: _sort_key(entry, normalized_sort))
    result: List[Dict[str, Any]] = []
    for entry in ordered:
        row = dict(entry)
        row["sort_value"] = _sort_key(row, normalized_sort)[0]
        result.append(row)
    return result


def _matches_filters(entry: Mapping[str, Any], query: Mapping[str, Any]) -> bool:
    needle = str(query.get("q") or "")
    if needle:
        hay = f"{entry.get('record_id', '')} {entry.get('title', '')}".lower()
        if needle not in hay:
            return False

    attrs = entry.get("attrs") or {}
    for field, values in (
        ("record_type", query.get("record_type")),
        ("status", query.get("status")),
        ("project_id", query.get("project_id")),
        ("priority", query.get("priority")),
    ):
        selected = values or []
        if not selected:
            continue
        actual = str(entry.get(field if field != "priority" else "record_type") or "")
        if field == "status":
            actual = str(attrs.get("status") or "").lower()
        elif field == "priority":
            actual = str(attrs.get("priority") or "").lower()
        elif field == "record_type":
            actual = str(entry.get("record_type") or "").lower()
        elif field == "project_id":
            actual = str(entry.get("project_id") or "").lower()
        if actual not in selected:
            return False
    return True


def compute_facets(entries: Iterable[Mapping[str, Any]]) -> Dict[str, Dict[str, int]]:
    facets: Dict[str, Dict[str, int]] = {field: {} for field in _FACET_FIELDS}
    for entry in entries:
        attrs = entry.get("attrs") or {}
        pairs = {
            "record_type": str(entry.get("record_type") or "unknown"),
            "status": str(attrs.get("status") or "unknown"),
            "priority": str(attrs.get("priority") or "unknown"),
            "project_id": str(entry.get("project_id") or "unknown"),
        }
        for field, value in pairs.items():
            bucket = facets[field]
            bucket[value] = bucket.get(value, 0) + 1
    return facets


def paginate_corpus(
    entries: Sequence[Mapping[str, Any]],
    query: Mapping[str, Any],
) -> Dict[str, Any]:
    sort = str(query.get("sort") or "updated_at_desc")
    if sort not in VALID_SORTS:
        sort = "updated_at_desc"

    filtered = [dict(entry) for entry in entries if _matches_filters(entry, query)]
    sorted_rows = sort_entries(filtered, sort)
    facets = compute_facets(sorted_rows)

    cursor = decode_cursor(str(query.get("cursor") or ""))
    start_index = 0
    if cursor is not None:
        _cursor_sort, cursor_key = cursor
        for idx, row in enumerate(sorted_rows):
            if str(row.get("record_key") or "") == cursor_key:
                start_index = idx + 1
                break

    limit = int(query.get("limit") or DEFAULT_LIMIT)
    page = sorted_rows[start_index : start_index + limit]
    next_cursor = None
    if start_index + limit < len(sorted_rows) and page:
        last = page[-1]
        next_cursor = encode_cursor(str(last.get("sort_value") or ""), str(last.get("record_key") or ""))

    public_items = []
    for row in page:
        public_items.append(
            {
                "record_id": row.get("record_id"),
                "record_type": row.get("record_type"),
                "project_id": row.get("project_id"),
                "title": row.get("title"),
                "updated_at": row.get("updated_at"),
                "source": row.get("source"),
                "record_key": row.get("record_key"),
                "attrs": row.get("attrs") or {},
            }
        )

    return {
        "items": public_items,
        "next_cursor": next_cursor,
        "facets": facets,
        "total_matches": len(sorted_rows),
        "sort": sort,
    }


def tracker_record_key(project_id: str, record_id: str) -> str:
    return f"tracker:{project_id}:{record_id}"


def document_record_key(document_id: str) -> str:
    return f"document::{document_id}"


def build_tracker_entry(
    record_type: str,
    record_id: str,
    project_id: str,
    title: str,
    updated_at: Optional[str],
    attrs: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "record_id": record_id,
        "record_type": record_type,
        "project_id": project_id,
        "title": title or record_id,
        "updated_at": updated_at,
        "source": "tracker",
        "record_key": tracker_record_key(project_id, record_id),
        "attrs": dict(attrs),
    }


def build_document_entry(item: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    document_id = str(item.get("document_id") or "").strip()
    if not document_id:
        return None
    status = str(item.get("status") or "active").lower()
    if status in {"deleted", "archived"}:
        return None
    keywords = item.get("keywords") or []
    tags = [str(tag).strip() for tag in keywords if str(tag).strip()]
    attrs = {
        "status": status,
        "tags": tags,
        "document_subtype": str(item.get("document_subtype") or "general"),
    }
    subtypepattern = str(item.get("subtypepattern") or "").strip()
    if subtypepattern:
        attrs["subtypepattern"] = subtypepattern
    return {
        "record_id": document_id,
        "record_type": "document",
        "project_id": str(item.get("project_id") or ""),
        "title": str(item.get("title") or document_id),
        "updated_at": item.get("updated_at") or item.get("created_at"),
        "source": "document",
        "record_key": document_record_key(document_id),
        "attrs": attrs,
    }


def build_tracker_entries_from_records(
    tasks: Sequence[Mapping[str, Any]],
    issues: Sequence[Mapping[str, Any]],
    features: Sequence[Mapping[str, Any]],
    lessons: Sequence[Mapping[str, Any]],
    plans: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def append_many(records: Sequence[Mapping[str, Any]], record_type: str, id_key: str) -> None:
        for record in records:
            record_id = str(record.get(id_key) or "")
            if not record_id:
                continue
            attrs = {
                "status": record.get("status"),
                "priority": record.get("priority"),
                "category": record.get("category"),
            }
            if record_type == "issue":
                attrs["severity"] = record.get("severity")
            entries.append(
                build_tracker_entry(
                    record_type,
                    record_id,
                    str(record.get("project_id") or ""),
                    str(record.get("title") or record_id),
                    record.get("updated_at"),
                    attrs,
                )
            )

    append_many(tasks, "task", "task_id")
    append_many(issues, "issue", "issue_id")
    append_many(features, "feature", "feature_id")
    append_many(lessons, "lesson", "lesson_id")
    append_many(plans, "plan", "plan_id")
    return entries
