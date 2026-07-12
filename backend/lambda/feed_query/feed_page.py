"""Server-side page cap + cursor continuation for GET /api/v1/feed (ENC-TSK-M74).

The bare full-refresh response is a single synchronous Lambda payload composed of
five typed arrays (tasks/issues/features/lessons/plans). Left uncapped it grew to
~919 records (697 tasks with full history), and that hydration volume + multi-MB
serialization on a 256MB Lambda was the measured dominant term in feed p95
(~4.90s vs a <500ms bar). No consumer reads 919 records in a feed view, so this
module caps the page to ``MAX_FEED_PAGE_RECORDS`` records TOTAL across the five
arrays and hands back a continuation cursor.

The cursor field name (``next_cursor``) and its opaque-base64 semantics are
byte-compatible with the corpus endpoint (``corpus.encode_cursor`` /
``corpus.decode_cursor``, ENC-TSK-L23) that the client already loops on in
``corpusSeed.ts`` (B67 AC-9's getNextPageParam contract) -- so a direct/legacy
consumer of bare /feed can page through with the exact same pattern.

Ordering preserves the ``feed_source=opensearch`` selection intent: OpenSearch
selects the top-N most-recently-updated keys per (project, record_type); the
honest cross-type merge is a single global sort by (updated_at DESC,
record_key ASC). Per-record output is byte-identical: this module only truncates
the set and never mutates a record dict.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from corpus import decode_cursor, encode_cursor, tracker_record_key

DEFAULT_MAX_FEED_PAGE_RECORDS = 75

# (array-attribute-name, id-key) in the fixed order the response arrays appear.
_ARRAY_SPECS: Tuple[Tuple[str, str], ...] = (
    ("tasks", "task_id"),
    ("issues", "issue_id"),
    ("features", "feature_id"),
    ("lessons", "lesson_id"),
    ("plans", "plan_id"),
)


def _record_key(record: Dict[str, Any], id_key: str) -> str:
    return tracker_record_key(
        str(record.get("project_id") or ""),
        str(record.get(id_key) or ""),
    )


def _flatten_ordered(
    arrays: Dict[str, List[Dict[str, Any]]]
) -> List[Tuple[str, str, str, Dict[str, Any]]]:
    """Flatten the five typed arrays into one globally ordered list.

    Each element is ``(updated_at, record_key, array_name, record)``. Ordering is
    a stable two-pass sort producing (updated_at DESC, record_key ASC): records
    sharing an updated_at keep record_key ascending; records with an empty
    updated_at sort last (they are the first dropped when the cap bites).
    """
    flat: List[Tuple[str, str, str, Dict[str, Any]]] = []
    for array_name, id_key in _ARRAY_SPECS:
        for record in arrays.get(array_name, []) or []:
            updated_at = str(record.get("updated_at") or "")
            flat.append((updated_at, _record_key(record, id_key), array_name, record))
    # Stable: secondary key first (record_key asc), then primary (updated_at desc).
    flat.sort(key=lambda t: t[1])
    flat.sort(key=lambda t: t[0], reverse=True)
    return flat


def _resplit(
    window: List[Tuple[str, str, str, Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {name: [] for name, _ in _ARRAY_SPECS}
    for _updated_at, _key, array_name, record in window:
        out[array_name].append(record)
    return out


def apply_page_cap(
    tasks: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
    features: List[Dict[str, Any]],
    lessons: List[Dict[str, Any]],
    plans: List[Dict[str, Any]],
    *,
    cursor: Optional[str] = None,
    cap: int = DEFAULT_MAX_FEED_PAGE_RECORDS,
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Optional[str],
]:
    """Cap the full-refresh page and compute a continuation cursor.

    Returns ``(tasks, issues, features, lessons, plans, next_cursor)`` where the
    five arrays together hold at most ``cap`` records (the globally most-recent
    window after any ``cursor``), and ``next_cursor`` is an opaque token when more
    records remain past the window, else ``None``.

    A malformed/undecodable ``cursor`` is treated as no cursor (start from the
    top) -- the caller validates and 400s explicitly before reaching here, so
    this is a defensive fallback only.
    """
    arrays = {
        "tasks": tasks,
        "issues": issues,
        "features": features,
        "lessons": lessons,
        "plans": plans,
    }
    ordered = _flatten_ordered(arrays)

    start_index = 0
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded is not None:
            _sort_value, cursor_key = decoded
            for idx, (_updated_at, record_key, _name, _record) in enumerate(ordered):
                if record_key == cursor_key:
                    start_index = idx + 1
                    break

    if cap <= 0:
        window = ordered[start_index:]
    else:
        window = ordered[start_index : start_index + cap]

    next_cursor: Optional[str] = None
    if cap > 0 and window and (start_index + cap) < len(ordered):
        last_updated_at, last_key, _name, _record = window[-1]
        next_cursor = encode_cursor(last_updated_at, last_key)

    split = _resplit(window)
    return (
        split["tasks"],
        split["issues"],
        split["features"],
        split["lessons"],
        split["plans"],
        next_cursor,
    )
