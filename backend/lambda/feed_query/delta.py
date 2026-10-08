"""Version-seq incremental feed delta for GET /api/v1/feed/delta (ENC-TSK-L27)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from enceladus_shared.version_seq import FEED_SCOPE, FEED_TOMBSTONE_RECORD_TYPE
except ImportError:  # pragma: no cover - local tests without layer
    FEED_SCOPE = "global"
    FEED_TOMBSTONE_RECORD_TYPE = "feed_tombstone"

VERSION_SEQ_INDEX = "version-seq-index"
MAX_DELTA_ITEMS = 500


def parse_since_version(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        value = int(text)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return value


def _ddb_str(item: Mapping[str, Any], key: str) -> str:
    field = item.get(key) or {}
    if "S" in field:
        return str(field["S"])
    if "N" in field:
        return str(field["N"])
    return ""


def query_version_delta(
    ddb: Any,
    table_name: str,
    since: int,
    *,
    is_stale_closed: Callable[[Mapping[str, Any], Any], bool],
    transform_record: Callable[[Mapping[str, Any], str], Optional[Dict[str, Any]]],
    cutoff: Any,
    max_items: int = MAX_DELTA_ITEMS,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, bool]:
    """Return (items, tombstones, latest_version_seq, truncated).

    ENC-TSK-Q34 (AC-3): at most ``max_items`` index rows are consumed per
    response. The query walks version_seq ascending, so when the window fills
    ``latest_version_seq`` is the seq of the last row consumed and
    ``truncated`` is True; the caller resumes with since=latest.
    """
    changed_keys: List[Dict[str, Dict[str, str]]] = []
    tombstones: List[Dict[str, Any]] = []
    latest = since
    consumed = 0
    truncated = False
    cap = max(1, int(max_items))

    paginator = ddb.get_paginator("query")
    for page in paginator.paginate(
        TableName=table_name,
        IndexName=VERSION_SEQ_INDEX,
        KeyConditionExpression="feed_scope = :scope AND version_seq > :since",
        ExpressionAttributeValues={
            ":scope": {"S": FEED_SCOPE},
            ":since": {"N": str(int(since))},
        },
        ProjectionExpression="project_id, record_id, record_type, item_id, version_seq, "
        "target_project_id, target_record_id, target_record_type, updated_at",
        ScanIndexForward=True,
        Limit=cap,
    ):
        for item in page.get("Items", []):
            seq_raw = _ddb_str(item, "version_seq")
            try:
                seq = int(seq_raw)
            except (TypeError, ValueError):
                continue
            if consumed >= cap:
                truncated = True
                break
            consumed += 1
            latest = max(latest, seq)
            record_type = _ddb_str(item, "record_type")
            if record_type == FEED_TOMBSTONE_RECORD_TYPE:
                target_project = _ddb_str(item, "target_project_id")
                target_record = _ddb_str(item, "target_record_id")
                target_type = _ddb_str(item, "target_record_type")
                item_id = _ddb_str(item, "item_id") or target_record.split("#", 1)[-1]
                record_key = (
                    f"document::{item_id}"
                    if target_type == "document"
                    else f"tracker:{target_project}:{item_id}"
                )
                tombstones.append(
                    {
                        "record_key": record_key,
                        "record_id": item_id,
                        "record_type": target_type or "task",
                        "project_id": target_project,
                        "version_seq": seq,
                    }
                )
                continue
            pid = _ddb_str(item, "project_id")
            rid = _ddb_str(item, "record_id")
            if pid and rid:
                changed_keys.append(
                    {"project_id": {"S": pid}, "record_id": {"S": rid}}
                )
        if truncated:
            break

    if not changed_keys and not tombstones:
        return [], [], latest, truncated

    items: List[Dict[str, Any]] = []
    for batch_start in range(0, len(changed_keys), 100):
        batch = changed_keys[batch_start : batch_start + 100]
        resp = ddb.batch_get_item(
            RequestItems={table_name: {"Keys": batch, "ConsistentRead": False}}
        )
        raw_items = resp.get("Responses", {}).get(table_name, [])
        unprocessed = (
            resp.get("UnprocessedKeys", {}).get(table_name, {}).get("Keys", [])
        )
        if unprocessed:
            resp2 = ddb.batch_get_item(
                RequestItems={table_name: {"Keys": unprocessed, "ConsistentRead": False}}
            )
            raw_items.extend(resp2.get("Responses", {}).get(table_name, []))

        for raw_item in raw_items:
            record_type = _ddb_str(raw_item, "record_type")
            pid = _ddb_str(raw_item, "project_id")
            item_id = _ddb_str(raw_item, "item_id")
            seq_raw = _ddb_str(raw_item, "version_seq")
            try:
                seq = int(seq_raw)
            except (TypeError, ValueError):
                seq = latest
            if is_stale_closed(raw_item, cutoff):
                record_key = f"tracker:{pid}:{item_id}" if item_id else ""
                if record_key:
                    tombstones.append(
                        {
                            "record_key": record_key,
                            "record_id": item_id,
                            "record_type": record_type,
                            "project_id": pid,
                            "version_seq": seq,
                        }
                    )
                continue
            transformed = transform_record(raw_item, pid)
            if transformed is None:
                continue
            transformed["version_seq"] = seq
            items.append(transformed)

    return items, tombstones, latest, truncated


def query_document_delta(
    documents: Sequence[Mapping[str, Any]],
    since: int,
    *,
    build_entry: Callable[[Mapping[str, Any]], Optional[Dict[str, Any]]],
    is_counter_row: Callable[[Mapping[str, Any]], bool],
    max_items: int = MAX_DELTA_ITEMS,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, bool]:
    """Document half of the delta (ENC-TSK-Q34 AC-1 / ENC-ISS-765).

    document_api stamps every document write with a version_seq drawn from its
    own DOCUMENTS_TABLE counter, a sequence space independent of the tracker
    counter, so documents travel on their own cursor (``doc_since``) and are
    never compared with tracker seqs. Documents are soft-deleted by status, so
    an archived/deleted row at a newer seq becomes a tombstone. Rows written
    before ENC-TSK-P72 carry no version_seq; they reach clients through the
    corpus seed and get a seq on their next write.

    Return shape matches query_version_delta: (items, tombstones, latest, truncated).
    """
    cap = max(1, int(max_items))
    changed: List[Tuple[int, Mapping[str, Any]]] = []
    for document in documents:
        if is_counter_row(document):
            continue
        try:
            seq = int(document.get("version_seq") or 0)
        except (TypeError, ValueError):
            continue
        if seq > since:
            changed.append((seq, document))
    changed.sort(key=lambda pair: pair[0])
    truncated = len(changed) > cap
    window = changed[:cap]

    items: List[Dict[str, Any]] = []
    tombstones: List[Dict[str, Any]] = []
    latest = since
    for seq, document in window:
        latest = max(latest, seq)
        document_id = str(document.get("document_id") or "").strip()
        if not document_id:
            continue
        status = str(document.get("status") or "active").strip().lower()
        if status in {"deleted", "archived"}:
            tombstones.append(
                {
                    "record_key": f"document::{document_id}",
                    "record_id": document_id,
                    "record_type": "document",
                    "project_id": str(document.get("project_id") or ""),
                    "version_seq": seq,
                }
            )
            continue
        entry = build_entry(document)
        if entry is None:
            continue
        entry["version_seq"] = seq
        items.append(entry)
    return items, tombstones, latest, truncated
